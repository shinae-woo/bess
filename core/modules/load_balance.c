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

#define MAX_BUCKETS 100
struct lb_priv {
	gate_t gates[MAX_OUTPUT_GATES];
	struct {
		uint16_t offset;
		uint32_t size;
	} rule;
	uint32_t ngates;

#ifdef CHASHING
	uint32_t nbuckets;
	uint32_t hash_points[MAX_OUTPUT_GATES][MAX_BUCKETS];
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

static struct snobj *lb_init(struct module *m, struct snobj *arg)
{	
	struct lb_priv* priv = get_priv(m);
	if (!arg)
		return snobj_err(EINVAL, "Must specify arguments");

	if (snobj_eval_exists(arg, "gates") &&
	      snobj_eval(arg, "gates")->type == TYPE_INT) {
		int gate = snobj_eval_int(arg, "gates");
		if (gate > MAX_OUTPUT_GATES || gate < 0)
			return snobj_err(EINVAL, "No more than %d gates or "
					"no less than 0 gates", 
					MAX_OUTPUT_GATES);
		priv->ngates = gate;
		for (int i = 0; i < gate; i++) {
			priv->gates[i] = i;
		}
	} else if (snobj_eval_exists(arg, "gates") &&
		   snobj_eval(arg, "gates")->type == TYPE_LIST) {
		struct snobj *gates = snobj_eval(arg, "gates");
		if (gates->size > MAX_OUTPUT_GATES)
			return snobj_err(EINVAL, "No more than %d gates", 
					MAX_OUTPUT_GATES);

		priv->ngates = gates->size;

		for (int i = 0; i < gates->size; i++) {
			priv->gates[i] = 
				snobj_int_get(snobj_list_get(gates, i));
			if (priv->gates[i] > MAX_OUTPUT_GATES)
				return snobj_err(EINVAL, "Invalid gate %d",
						priv->gates[i]);
		}
	} else {
		return snobj_err(EINVAL, "Must specify gates to load balancer");
	}

	if (snobj_eval_exists(arg, "rule") &&
			snobj_eval(arg, "rule")->type == TYPE_MAP) {
		struct snobj *rule = snobj_eval(arg, "rule");

		priv->rule.offset = snobj_eval_int(rule, "offset");
		priv->rule.size = snobj_eval_int(rule, "size");

	} else {
		return snobj_err(EINVAL, "Must specify rules to load balancer");
	}

#ifdef CHASHING	
	int i, j;
	if (snobj_eval_exists(arg, "buckets") &&
			snobj_eval(arg, "buckets")->type == TYPE_INT) {
		int nbuckets = snobj_eval_int(arg, "buckets");
		if (nbuckets > MAX_BUCKETS || nbuckets < 0)
			return snobj_err(EINVAL, "No more than %d gates or "
					"no less than 0 gates", MAX_OUTPUT_GATES-1);
		priv->nbuckets = nbuckets;
	} else {
		priv->nbuckets = 1;
	}

	for (i = 0; i < priv->ngates; ++i) {
		for (j = 0; j < priv->nbuckets; ++j) {
			priv->hash_points[i][j] = _hash(i, j); 
		}
	}
	
#endif

	return NULL;
	
}

static struct snobj *lb_query(struct module *m, struct snobj *arg)
{
	struct lb_priv* priv = get_priv(m);

	if (snobj_eval_exists(arg, "gates") &&
			snobj_eval(arg, "gates")->type == TYPE_INT) {
		int gate = snobj_eval_int(arg, "gates");
		if (gate >= MAX_OUTPUT_GATES)
			return snobj_err(EINVAL, "No more than %d gates", 
					MAX_OUTPUT_GATES);
		priv->ngates = gate;
		for (int i = 0; i < gate; i++) {
			priv->gates[i] = i;
		}
	} else if (snobj_eval_exists(arg, "gates") &&
			snobj_eval(arg, "gates")->type == TYPE_LIST) {
		struct snobj *gates = snobj_eval(arg, "gates");
		if (gates->size > MAX_OUTPUT_GATES)
			return snobj_err(EINVAL, "No more than %d gates", 
					MAX_OUTPUT_GATES);

		priv->ngates = gates->size;

		for (int i = 0; i < gates->size; i++) {
			priv->gates[i] = 
				snobj_int_get(snobj_list_get(gates, i));
			if (priv->gates[i] > MAX_OUTPUT_GATES)
				return snobj_err(EINVAL, "Invalid gate %d",
						priv->gates[i]);
		}
	} else {
		return snobj_err(EINVAL, "Must specify gates to load balancer");
	}

	return NULL;	
}

static inline int load_balance_pkt(uint32_t ngates, 
		uint32_t offset, uint32_t size, struct snbuf *snb) 
{
	char *head = snb_head_data(snb);
	uint32_t hash = 0;
	for (int i = 0; i < size; ++i) {
		hash += *(head + offset + i);
		hash += (hash << 10);
		hash ^= (hash << 6);
	}

	hash += (hash << 3);
	hash ^= (hash >> 11);
	hash += (hash << 15);

	// no consistent hashing
	return hash % ngates;
}

static void
lb_process_batch(struct module *m, struct pkt_batch *batch)
{
	struct lb_priv* priv = get_priv(m);
	gate_t ogates[MAX_PKT_BURST];

	for (int i = 0; i < batch->cnt; i++) {
		int gate_id = load_balance_pkt(priv->ngates, priv->rule.offset, 
				priv->rule.size, batch->pkts[i]);
		if (gate_id < 0 || gate_id > priv->ngates)
			ogates[i] = priv->gates[priv->ngates];
		else
			ogates[i] = priv->gates[gate_id];
	}
	run_split(m, ogates, batch);
}

static const struct mclass lb = {
	.name 		= "LoadBalance",
	.priv_size	= sizeof(struct lb_priv),
	.init 		= lb_init,
	.process_batch 	= lb_process_batch,
	.query		= lb_query,
};

ADD_MCLASS(lb)
