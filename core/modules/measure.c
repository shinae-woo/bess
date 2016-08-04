#include <rte_tcp.h>
#include <string.h>

#include "../module.h"
#include "../utils/histogram.h"
#include "../time.h"

#define MAX_SNAPSHOTS 8

/* XXX: currently doesn't support multiple workers */
struct measure_priv {
	struct histogram curr;
	struct histogram snapshots[MAX_SNAPSHOTS];

	uint64_t start_time;
	int warmup;		/* second */

	uint64_t pkt_cnt;
	uint64_t bytes_cnt;
	uint64_t total_latency;
};

static struct snobj *measure_init(struct module *m, struct snobj *arg)
{
	struct measure_priv *priv = get_priv(m);
	int ret;

	if (arg)
		priv->warmup = snobj_eval_int(arg, "warmup");

	ret = init_hist(&priv->curr);
	if (ret < 0)
		return snobj_errno(-ret);

	return NULL;
}

static void measure_deinit(struct module *m)
{
	struct measure_priv *priv = get_priv(m);

	deinit_hist(&priv->curr);
	
	for (int i = 0; i < MAX_SNAPSHOTS; i++)
		if (priv->snapshots[i].arr == NULL)
	
	for (int i = 0; i < MAX_SNAPSHOTS; i++) {
		if (priv->snapshots[i].arr != NULL)
			deinit_hist(&priv->snapshots[i]);
	}
}

struct snobj *
command_measure_latency_clear(struct module *m, const char *cmd, 
		struct snobj *arg)
{
	struct measure_priv *priv = get_priv(m);
	clear_hist(&priv->curr);

	return NULL;
}

static inline int get_measure_packet(struct snbuf* pkt, uint64_t* time)
{
	uint8_t *avail = (uint8_t*)((uint8_t*)snb_head_data(pkt) +
			sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr)) +
		sizeof(struct tcp_hdr);
	uint64_t *ts = (uint64_t*)(avail + 1);
	uint8_t available = *avail;
	*time = *ts;
	return available;
}

static void measure_process_batch(struct module *m, struct pkt_batch *batch)
{
	struct measure_priv *priv = get_priv(m);

	uint64_t time = ctx.current_ns;

	if (priv->start_time == 0)
		priv->start_time = ctx.current_ns;

	if ((time - priv->start_time) / 1e9 < priv->warmup)
		goto skip;

	priv->pkt_cnt += batch->cnt;

	for (int i = 0; i < batch->cnt; i++) {
		uint64_t pkt_time;
		if (get_measure_packet(batch->pkts[i], &pkt_time)) {
			uint64_t diff;
			
			if (time >= pkt_time)
				diff = time - pkt_time;
			else
				continue;

			priv->bytes_cnt += batch->pkts[i]->mbuf.pkt_len;
			priv->total_latency += diff;

			record_latency(&priv->curr, diff);
		}
	}

skip:
	run_next_module(m, batch);
}

struct snobj *
command_get_summary(struct module *m, const char *cmd, struct snobj *arg)
{
	struct measure_priv *priv = get_priv(m);

	uint64_t pkt_total = priv->pkt_cnt;
	uint64_t byte_total = priv->bytes_cnt;
	uint64_t bits = (byte_total + pkt_total * 24) * 8;

	struct snobj *r = snobj_map();

	snobj_map_set(r, "timestamp", snobj_double(get_epoch_time()));
	snobj_map_set(r, "packets", snobj_uint(pkt_total));
	snobj_map_set(r, "bits", snobj_uint(bits));
	snobj_map_set(r, "total_latency_ns", 
			snobj_uint(priv->total_latency * 100));

	return r;
}

struct snobj *
command_save_snapshot(struct module *m, const char *cmd, struct snobj *arg)
{
	struct measure_priv *priv = get_priv(m);

	if (snobj_type(arg) != TYPE_MAP)
		return snobj_err(EINVAL, "argument must be an map");

	if (!snobj_eval_exists(arg, "index"))
		return snobj_err(EINVAL, "'index' must be specified");

	int idx = snobj_eval_int(arg, "index");
	if (idx >= MAX_SNAPSHOTS || idx < 0)
		return snobj_err(EINVAL, "index must be 0 - %d", MAX_SNAPSHOTS);

	int ret = save_snapshot(&priv->curr, &priv->snapshots[idx]);
	if (ret < 0)
		return snobj_err(EINVAL, "fail to save snapshot");

	return NULL;
}

struct snobj *
command_get_ptile(struct module *m, const char *cmd, struct snobj *arg)
{
	struct measure_priv *priv = get_priv(m);

	if (snobj_type(arg) != TYPE_MAP) 
		return snobj_err(EINVAL, "argument must be a map");
	
	if (!snobj_eval_exists(arg, "index"))
		return snobj_err(EINVAL, "'index' must be specified");
	
	if (!snobj_eval_exists(arg, "plist"))
		return snobj_err(EINVAL, "'plist' must be specified");

	int idx = snobj_eval_int(arg, "index");
	if (priv->snapshots[idx].arr == NULL)
		return snobj_err(EINVAL, "idx %d: no saved snapshot", idx);

	struct snobj *list= snobj_eval(arg, "plist");
	if (snobj_type(list) != TYPE_LIST) 
		return snobj_err(EINVAL, "'plist' must be a list");

	double in_arr[list->size];
	double out_arr[list->size];
	for (int i = 0; i < list->size; i++) {
		struct snobj *elem = snobj_list_get(list, i);
		if (snobj_type(elem) == TYPE_INT)
			in_arr[i] = snobj_int_get(elem);
		else if (snobj_type(elem) == TYPE_DOUBLE)
			in_arr[i] = snobj_double_get(elem);
		else 
			return snobj_err(EINVAL, "idx %d: not a number", i);

		if (in_arr[i] < 0 || in_arr[i] > 100)
			return snobj_err(EINVAL, "idx %d: must be 0 - 100", i);
	}

	get_ptile(&priv->snapshots[idx], &priv->curr, list->size, in_arr, out_arr);

	struct snobj *out = snobj_list();
	for (int i = 0; i < list->size; i++) 
		snobj_list_add(out, snobj_double(out_arr[i]));

	return out;
}

static const struct mclass measure = {
	.name 		= "Measure",
	.help		= 
		"measures packet latency (paired with Timestamp module)",
	.num_igates	= 1,
	.num_ogates	= 1,
	.priv_size	= sizeof(struct measure_priv),
	.init 		= measure_init,
	.deinit 		= measure_deinit,
	.process_batch 	= measure_process_batch,
	.commands	 = {
		{"get_summary", command_get_summary, .mt_safe=1},
		{"measure_latency_clear", command_measure_latency_clear, .mt_safe=1},
		{"save_snapshot", command_save_snapshot, .mt_safe=1},
		{"get_ptile", command_get_ptile, .mt_safe=1}
	}
};

ADD_MCLASS(measure)
