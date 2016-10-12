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

/* load balancer split input traffic to a number of output traffic
 * each igate split into n ogates (specified in split_ogate)
 * e.g., igate 0 split into 0, 1, 2 ogates, and igate 1 split into 3, 4, 5 ogates.
 */

#define MAX_LB_GATES 100

#define HASHING_UNIDIRT		1
#define HASHING_BIDIRT		2	
#define CHASHING_UNIDIRT	3	
#define CHASHING_BIDIRT		4	

struct split_ogate {
	gate_idx_t start_idx;
	uint32_t ngates;
};

struct lb_priv {
	gate_idx_t gates[MAX_LB_GATES];
	struct split_ogate split[MAX_LB_GATES];
	uint32_t num_split;
	
	uint16_t lb_method;
	struct {
		uint16_t offset;
		uint32_t size;
	} rule;

	int (*load_balance_pkt)(uint32_t, uint32_t, uint32_t, struct snbuf *);
};

static int 
load_balance_pkt_directional(uint32_t ngates, uint32_t offset, uint32_t size, 
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

static int 
load_balance_pkt_bidirectional(uint32_t ngates, uint32_t offset, uint32_t size, 
		struct snbuf *snb) 
{
	char *head = snb_head_data(snb);
	uint32_t hash = 0;
	for (int i = 0; i < size; ++i) {
		hash += *(uint8_t *)(head + offset + i);
	}

	return hash % ngates;
}

static struct snobj *
command_set_num_gates(struct module *m, const char *cmd, struct snobj *arg)
{
	struct lb_priv* priv = get_priv(m);
	
	if (snobj_type(arg) == TYPE_INT) {
		int gates = snobj_int_get(arg);

		if (gates < 0 || gates > MAX_LB_GATES || gates > MAX_GATES)
			return snobj_err(EINVAL, "No more than %d gates or less than one", 
					MIN(MAX_LB_GATES, MAX_GATES));

		priv->num_split = 1;
		priv->split[0].start_idx = 0;
		priv->split[0].ngates = gates;
		for (int i = 0; i < gates; i++)
			priv->gates[i] = i;

	} else if (snobj_type(arg) == TYPE_LIST) {
		uint32_t total_ogates = 0;

		if (arg->size > MAX_LB_GATES)
			return snobj_err(EINVAL, "no more than %d gates ",
					MIN(MAX_LB_GATES, MAX_GATES));
	
		priv->num_split = arg->size;
		for (int i = 0; i < arg->size; i++) {
			struct snobj *elem = snobj_list_get(arg, i);

			if (snobj_type(elem) != TYPE_INT)
				return snobj_err(EINVAL,
						"'ogates' must be a list of integers");

			priv->split[i].start_idx = total_ogates;
			priv->split[i].ngates = snobj_int_get(elem);
			total_ogates += priv->split[i].ngates;
		}
		
		if (total_ogates < 0 || total_ogates > MAX_LB_GATES 
				|| total_ogates > MAX_GATES)
			return snobj_err(EINVAL, "No more than %d gates or less than one", 
					MIN(MAX_LB_GATES, MAX_GATES));

		for (int i = 0; i < total_ogates; i++)
			priv->gates[i] = i;
	
	} else
		return snobj_err(EINVAL, "Rule map must contain size "
					"as a integer or a list");
	
	return NULL;	
}

static struct snobj *
command_set_rule(struct module *m, const char *cmd, struct snobj *arg)
{
	struct lb_priv* priv = get_priv(m);

	/* set load balancing rules */
	if (snobj_type(arg) != TYPE_MAP) 
		return snobj_err(EINVAL, "Argument must be a map");

	struct snobj *_offset = snobj_map_get(arg, "offset");
	struct snobj *_size = snobj_map_get(arg, "size");

	if (!_offset || snobj_type(_offset) != TYPE_INT)
		return snobj_err(EINVAL, "Rule map must contain offset "
					"as a integer");
	priv->rule.offset = snobj_int_get(_offset);
	
	if (!_size || snobj_type(_size) != TYPE_INT)
		return snobj_err(EINVAL, "Rule map must contain size "
					"as a integer");
	priv->rule.size = snobj_int_get(_size);
	
	/* set appropriate load balancing methods */
	struct snobj *_method = snobj_map_get(arg, "method");
	struct snobj *_direction = snobj_map_get(arg, "direction");
	
	if (strcmp(snobj_str_get(_method), "hashing") == 0) {
		if (strcmp(snobj_str_get(_direction), "unidirectional") == 0)
			priv->lb_method = HASHING_UNIDIRT;
		else if (strcmp(snobj_str_get(_direction), "bidirectional") == 0)
			priv->lb_method = HASHING_BIDIRT;
		else
			return snobj_err(EINVAL, "Unknown 'direction'");

	} else if (strcmp(snobj_str_get(_method), "chashing") == 0) {
		if (strcmp(snobj_str_get(_direction), "unidirectional") == 0)
			priv->lb_method = HASHING_UNIDIRT;
		else if (strcmp(snobj_str_get(_direction), "bidirectional") == 0)
			priv->lb_method = HASHING_BIDIRT;
		else
			return snobj_err(EINVAL, "Unknown 'direction'");

	} else
		return snobj_err(EINVAL, "Unknown 'method'");

	switch (priv->lb_method) {

		case HASHING_UNIDIRT:
			priv->load_balance_pkt = load_balance_pkt_directional;
			break;

		case HASHING_BIDIRT:
			priv->load_balance_pkt = load_balance_pkt_bidirectional;
			break;

		default:
			return snobj_err(EINVAL, "Not support lb method");
	}
	
	/* set output gates */
	struct snobj *_ogates = snobj_map_get(arg, "ogates");
	if (!_ogates)
		return snobj_err(EINVAL, "Rule map must contain ogates "
					"as a integer or a list");
	return command_set_num_gates(m, cmd, _ogates);
}

static struct snobj *
lb_init(struct module *m, struct snobj *arg)
{	
	struct lb_priv* priv = get_priv(m);

	/* default rule is load balancing based on 'src_ip' and 'dst_ip' */
	priv->lb_method = HASHING_UNIDIRT;
	priv->rule.offset = 26;
	priv->rule.size = 8;

	if (!arg)
		return snobj_err(EINVAL, "Must specify a number of gates "
				"to split into");

	return command_set_rule(m, NULL, arg);
}

static void
lb_process_batch(struct module *m, struct pkt_batch *batch)
{
	struct lb_priv* priv = get_priv(m);
	gate_idx_t ogates[MAX_PKT_BURST];
	gate_idx_t igate = get_igate();

	if (priv->split[igate].ngates == 0)
		return;

	for (int i = 0; i < batch->cnt; i++) {
		int gate_id = priv->load_balance_pkt(priv->split[igate].ngates, 
				priv->rule.offset, priv->rule.size, batch->pkts[i]);
		ogates[i] = priv->gates[gate_id + priv->split[igate].start_idx];
	}
	run_split(m, ogates, batch);
}

static const struct mclass lb = {
	.name 		= "LoadBalance",
	.help		= "Load balancing packets by modular hashing",
	.num_igates	= MAX_LB_GATES,
	.num_ogates = MAX_LB_GATES,
	.priv_size	= sizeof(struct lb_priv),
	.init 		= lb_init,
	.process_batch 	= lb_process_batch,
	.commands =	{
		{"set_num_gates", command_set_num_gates},
	}
};

ADD_MCLASS(lb)
