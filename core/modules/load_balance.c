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
 * gates[n]: default port for packets not be load-balanced
 */
struct lb_priv {
	gate_t gates[MAX_OUTPUT_GATES];
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
		if (gate >= MAX_OUTPUT_GATES)
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
	return NULL;
	
}

static struct snobj *lb_query(struct module *m, struct snobj *arg)
{
	struct lb_priv* priv = get_priv(m);

	if (snobj_eval_exists(arg, "gates")) {
		int gate = snobj_eval_int(arg, "gates");
		if (gate > MAX_OUTPUT_GATES)
			return snobj_err(EINVAL, "No more than %d gates", 
					MAX_OUTPUT_GATES);
		priv->ngates = gate;
		for (int i = 0; i < gate; i++) {
			priv->gates[i] = i;
		}
	} else if (snobj_eval_exists(arg, "gate_list")) {
		struct snobj *gates = snobj_eval(arg, "gate_list");
		if (gates->size > MAX_OUTPUT_GATES)
			return snobj_err(EINVAL, "No more than %d gates", 
					MAX_OUTPUT_GATES);

		for (int i = 0; i < gates->size; i++) {
			priv->gates[i] = 
				snobj_int_get(snobj_list_get(gates, i));
			if (priv->gates[i] > MAX_OUTPUT_GATES)
				return snobj_err(EINVAL, "Invalid gate %d",
						priv->gates[i]);
		}
	}

	return NULL;	
}

static inline int load_balance_flow(uint32_t ngates, 
		uint32_t src_ip, uint32_t dst_ip,
		uint16_t src_port, uint16_t dst_port)
{
	static uint32_t count = 0;
	static  FILE *fp;
	fp = fopen("log","a");
	
	if (count ++ < 100)
		fprintf(fp, "%0x -> %d\n", src_ip, src_ip % ngates);

	fclose(fp);
	return src_ip % ngates;
}

static inline int load_balance_pkt(uint32_t ngates, struct rte_mbuf *mbuf) 
{
	struct ether_hdr *ethh = rte_pktmbuf_mtod(mbuf, struct ether_hdr *);

	if (ethh->ether_type != rte_be_to_cpu_16(ETHER_TYPE_IPv4)) 
		return -1;
	
	struct ipv4_hdr* iph = (struct ipv4_hdr *)rte_pktmbuf_adj(mbuf, 
			sizeof(struct ether_hdr));

	if (iph->next_proto_id == IPPROTO_UDP) {
		struct udp_hdr* udph = (struct udp_hdr *) ((u_char *)iph +
				((iph->version_ihl & IPV4_HDR_IHL_MASK) << 2));
		return load_balance_flow(ngates, iph->src_addr, iph->dst_addr, 
				udph->src_port, udph->dst_port);

	} else if (iph->next_proto_id == IPPROTO_TCP) {
		struct tcp_hdr* tcph = (struct tcp_hdr *) ((u_char *)iph +
				((iph->version_ihl & IPV4_HDR_IHL_MASK) << 2));
		return load_balance_flow(ngates, iph->src_addr, iph->dst_addr, 
				tcph->src_port, tcph->dst_port);
	}
	
	return -1;
}

static void
lb_process_batch(struct module *m, struct pkt_batch *batch)
{
	struct lb_priv* priv = get_priv(m);
	gate_t ogates[MAX_PKT_BURST];

	for (int i = 0; i < batch->cnt; i++) {
		int gate_id = load_balance_pkt(priv->ngates, 
				(struct rte_mbuf *) batch->pkts[i]);
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
