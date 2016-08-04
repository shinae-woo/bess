#include "../module.h"
#include "../time.h"

#define MAX_VARS		16

struct supdate_priv {
	int num_vars;
	struct var {
		uint32_t mask;		/* bits with 1 won't be updated */
		uint32_t min;
		uint32_t range;		/* == max - min + 1 */
		int16_t offset;
		uint64_t idx;
	} vars[MAX_VARS];
};

static struct snobj *
command_add(struct module *m, const char *cmd, struct snobj *arg)
{
	struct supdate_priv *priv = get_priv(m);

	int curr = priv->num_vars;

	if (snobj_type(arg) != TYPE_LIST)
		return snobj_err(EINVAL, "argument must be a list of maps");

	if (curr + arg->size > MAX_VARS)
		return snobj_err(EINVAL, "max %d variables " \
				"can be specified", MAX_VARS);

	for (int i = 0; i < arg->size; i++) {
		struct snobj *var = snobj_list_get(arg, i);

		uint8_t size;
		int16_t offset;
		uint32_t mask;
		uint32_t min;
		uint32_t max;

		if (var->type != TYPE_MAP)
			return snobj_err(EINVAL, 
					"argument must be a list of maps");

		offset = snobj_eval_int(var, "offset");
		size = snobj_eval_uint(var, "size");
		min = snobj_eval_uint(var, "min");
		max = snobj_eval_uint(var, "max");

		if (offset < 0)
			return snobj_err(EINVAL, "too small 'offset'");

		switch (size) {
		case 1:
			offset -= 3;
			mask = rte_cpu_to_be_32(0xffffff00);
			min = MIN(min, 0xff);
			max = MIN(max, 0xff);
			break;

		case 2:
			offset -= 2;
			mask = rte_cpu_to_be_32(0xffff0000);
			min = MIN(min, 0xffff);
			max = MIN(max, 0xffff);
			break;

		case 4:
			mask = rte_cpu_to_be_32(0x00000000);
			min = MIN(min, 0xffffffffu);
			max = MIN(max, 0xffffffffu);
			break;

		default:
			return snobj_err(EINVAL, "'size' must be 1, 2, or 4");
		}

		if (offset + 4 > SNBUF_DATA)
			return snobj_err(EINVAL, "too large 'offset'");

		if (min > max)
			return snobj_err(EINVAL, "'min' should not be " \
					"greater than 'max'");

		priv->vars[curr + i].offset = offset;
		priv->vars[curr + i].mask = mask;
		priv->vars[curr + i].min = min;
		priv->vars[curr + i].idx = 0;

		/* avoid modulo 0 */
		priv->vars[curr + i].range = (max - min + 1) ? : 0xffffffff;
	}

	priv->num_vars = curr + arg->size;


	return NULL;
}

static struct snobj *
command_clear(struct module *m, const char *cmd, struct snobj *arg)
{
	struct supdate_priv *priv = get_priv(m);

	priv->num_vars = 0;

	return NULL;
}

static struct snobj *supdate_init(struct module *m, struct snobj *arg)
{
	struct supdate_priv *priv = get_priv(m);

	for (int i = 0; i < priv->num_vars; i++) {
		struct var *var = &priv->vars[i];
		var->idx = 0;
	}

	if (arg)
		return command_add(m, NULL, arg);
	else
		return NULL;
}

static void supdate_process_batch(struct module *m, struct pkt_batch *batch)
{
	struct supdate_priv *priv = get_priv(m);

	int cnt = batch->cnt;

	for (int i = 0; i < priv->num_vars; i++) {
		struct var *var = &priv->vars[i];

		uint32_t mask = var->mask;
		uint32_t min = var->min;
		uint32_t range = var->range;
		int16_t offset = var->offset;
		uint32_t idx = var->idx;
			
		for (int j = 0; j < cnt; j++) {
			struct snbuf *snb = batch->pkts[j];
			char *head = snb_head_data(snb);

			uint32_t * restrict p;
			uint32_t updated_val = idx;

			p = (uint32_t *)(head + offset);
			*p = (*p & mask) | rte_cpu_to_be_32(min + updated_val);
		}
		
		var->idx++;
		if (var->idx == range)
			var->idx = 0;
	}

	run_next_module(m, batch);
}

static const struct mclass supdate = {
	.name 			= "SequentialUpdate",
	.help			= "updates packet data sequentially in range",
	.def_module_name	= "supdate",
	.num_igates		= 1,
	.num_ogates		= 1,
	.priv_size		= sizeof(struct supdate_priv),
	.init 			= supdate_init,
	.process_batch 		= supdate_process_batch,
	.commands		= {
		{"add", 	command_add},
		{"clear", 	command_clear},
	}
};

ADD_MCLASS(supdate)
