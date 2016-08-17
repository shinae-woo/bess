#include <rte_common.h>
#include <rte_config.h>
#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_tcp.h>

#include "../module.h"
#include "md5.h"

/* XXX: currently doesn't support multiple workers */

/* ngates: number of lb clients 
 * gates[0] ~ ngates[ngates-1]: ports for lb clients
 */

#define MAX_LB_GATES 100

#define MAX_BUCKETS 100
struct lb_priv {
	gate_idx_t gates[MAX_LB_GATES];
	struct {
		uint16_t offset;
		uint32_t size;
	} rule;
	uint32_t ngates;

#ifdef CHASHING
	uint32_t nbuckets;
	uint32_t hash_points[MAX_LB_GATES][MAX_BUCKETS];
#endif
};

#ifdef CHASHING
static uint32_t _hash(int a, int b) 
{
	uint32_t hash = 0;
	unsigned char result[16];

	MD5_CTX ctx;
	MD5_Init(&ctx);
	MD5_Update(&ctx, &a, 4);
	MD5_Update(&ctx, &b, 4);
	MD5_Final(result, &ctx);

	hash = result[1] +
		(result[3] << 4) +
		(result[7] << 8) +
		(result[11] << 16);

	return hash % UINT32_MAX;
}
#endif

static struct snobj *
command_set_rule(struct module *m, const char *cmd, struct snobj *arg)
{
	struct lb_priv* priv = get_priv(m);
	
	if (snobj_type(arg) != TYPE_MAP) 
		return snobj_err(EINVAL, "Argument must be a map");

	struct snobj *_offset = snobj_map_get(arg, "offset");
	struct snobj *_size = snobj_map_get(arg, "size");

	if (!_offset || snobj_type(_offset) != TYPE_INT)
		return snobj_err(EINVAL, "Rule map must contain offset"
					"as a integer");
	
	if (!_size || snobj_type(_size) != TYPE_INT)
		return snobj_err(EINVAL, "Rule map must contain size"
					"as a integer");

	priv->rule.offset = snobj_int_get(_offset);
	priv->rule.size = snobj_int_get(_size);

	return NULL;
}

static struct snobj *
command_set_num_gates(struct module *m, const char *cmd, struct snobj *arg)
{
	struct lb_priv* priv = get_priv(m);
	
	if (snobj_type(arg) == TYPE_INT) {
		int gates = snobj_int_get(arg);

		if (gates < 0 || gates > MAX_LB_GATES || gates > MAX_GATES)
			return snobj_err(EINVAL, "No more than %d gates", 
					MIN(MAX_LB_GATES, MAX_GATES));

		priv->ngates = gates;
		for (int i = 0; i < gates; i++)
			priv->gates[i] = i;

	} else
		return snobj_err(EINVAL, "Must specify gates to load balancer");

	return NULL;	
}

/** NOT YET BE TESTED **/
static struct snobj *
command_set_chashing(struct module *m, const char *cmd, struct snobj *arg)
{
#ifdef CHASHING	
	int i, j;
	if (snobj_eval_exists(arg, "buckets") &&
			snobj_eval(arg, "buckets")->type == TYPE_INT) {
		int nbuckets = snobj_eval_int(arg, "buckets");
		if (nbuckets > MAX_BUCKETS || nbuckets < 0)
			return snobj_err(EINVAL, "No more than %d gates or "
					"no less than 0 gates", MAX_LB_GATES-1);
		priv->nbuckets = nbuckets;
	} else {
		priv->nbuckets = 1;
	}

	for (i = 0; i < priv->ngates; ++i) {
		for (j = 0; j < priv->nbuckets; ++j) {
			priv->hash_points[i][j] = _hash(i, j); 
		}
	}
	
	return NULL;
#endif
	
	return snobj_err(EINVAL, "Not yet be provided functionality");
}

static struct snobj *
lb_init(struct module *m, struct snobj *arg)
{	
	struct lb_priv* priv = get_priv(m);

	/* default rule is load balancing based on 'src_ip' and 'dst_ip' */
	priv->rule.offset = 26;
	priv->rule.size = 8;

	if (arg)
		return command_set_num_gates(m, NULL, arg);
	else
		return snobj_err(EINVAL, "Must specify a number of gates "
				"to split into");
}

static inline int 
load_balance_pkt(uint32_t ngates, uint32_t offset, uint32_t size, 
		struct snbuf *snb) 
{
	char *head = snb_head_data(snb);
	uint32_t hash = 0;
	for (int i = 0; i < size; ++i) {
		hash += *(uint8_t *)(head + offset + i);
		hash += (hash << 10);
		hash ^= (hash << 6);
	}

	hash += (hash << 3);
	hash ^= (hash >> 11);
	hash += (hash << 15);

	return hash % ngates;
}

static void
lb_process_batch(struct module *m, struct pkt_batch *batch)
{
	struct lb_priv* priv = get_priv(m);
	gate_idx_t ogates[MAX_PKT_BURST];

	for (int i = 0; i < batch->cnt; i++) {
		int gate_id = load_balance_pkt(priv->ngates, priv->rule.offset, 
				priv->rule.size, batch->pkts[i]);
		ogates[i] = priv->gates[gate_id];
	}
	run_split(m, ogates, batch);
}

static const struct mclass lb = {
	.name 		= "LoadBalance",
	.help		= "Load balancing packets by modular hashing",
	.num_igates	= 1,
	.num_ogates = MAX_LB_GATES,
	.priv_size	= sizeof(struct lb_priv),
	.init 		= lb_init,
	.process_batch 	= lb_process_batch,
	.commands =	{
		{"set_rule", command_set_rule},
		{"set_num_gates", command_set_num_gates},
		{"set_chashing", command_set_chashing},
	}
};

ADD_MCLASS(lb)
