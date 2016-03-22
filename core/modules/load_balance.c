#include <rte_common.h>
#include <rte_config.h>
#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_tcp.h>

#include "../module.h"

/* XXX: currently doesn't support multiple workers */

/* ngates: number of lb clients 
 * gates[0] ~ ngates[ngates-1]: ports for lb clients
 */
struct lb_priv {
	gate_t gates[MAX_OUTPUT_GATES];
	struct {
		uint16_t offset;
		uint32_t mask;
	} rule;
	uint32_t ngates;
};

static struct snobj *lb_init(struct module *m, struct snobj *arg)
{	
	struct lb_priv* priv = get_priv(m);
	if (!arg)
		return snobj_err(EINVAL, "Must specify arguments");

	if (snobj_eval_exists(arg, "gates") &&
	      snobj_eval(arg, "gates")->type == TYPE_INT) {
		int gate = snobj_eval_int(arg, "gates");
		if (gate > MAX_OUTPUT_GATES)
			return snobj_err(EINVAL, "No more than %d gates", 
					MAX_OUTPUT_GATES-1);
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
		switch(snobj_eval_int(rule, "size")) {
		case 1:
			priv->rule.mask = 0x000000ff;
			break;
		case 2:
			priv->rule.mask = 0x0000ffff;
			break;
		case 4:
			priv->rule.mask = 0xffffffff;
			break;
		default:
			return snobj_err(EINVAL, "'size' must be 1, 2, or 4");
		}

	} else {
		return snobj_err(EINVAL, "Must specify rules to load balancer");
	}
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
		uint32_t offset, uint32_t mask, struct snbuf *snb) 
{
	char *head = snb_head_data(snb);
	uint32_t p = *(uint32_t *)(head + offset);
	uint32_t range_per_gate = mask/ngates;
#if 0
	FILE *file = fopen("/home/shinae/log", "a");
	fprintf(file, "%08x %02x %02x %02x %02x %08x %08x %d\n", mask, 
			*(head+offset), *(head+offset+1), 
			*(head+offset+2), *(head+offset+3), 
			p, p & mask, (p & mask) / range_per_gate);
	fclose(file);
#endif
	return (p & mask) / range_per_gate;
}

static void
lb_process_batch(struct module *m, struct pkt_batch *batch)
{
	struct lb_priv* priv = get_priv(m);
	gate_t ogates[MAX_PKT_BURST];

	for (int i = 0; i < batch->cnt; i++) {
		int gate_id = load_balance_pkt(priv->ngates, priv->rule.offset, 
				priv->rule.mask, batch->pkts[i]);
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
