#ifndef __HISTOGRAM_H__
#define __HISTOGRAM_H__

#include <rte_cycles.h>
#include <math.h>

#include "../mem_alloc.h"

#define HISTO_BASE_UNIT (100lu) // minimum unit starts from 10^2 ns
#define HISTO_MAX_UNIT	(8)		// from 10^2 ns to 10^10 ns (10 s)
#define HISTO_BUCKETS	(1000)	// significant digit is 3

typedef uint64_t histo_count_t;
struct histogram {
	histo_count_t *arr[HISTO_MAX_UNIT];
	histo_count_t above_threshold;
};

static inline void record_latency(struct histogram* hist, uint64_t latency) 
{
	static float slot_unit = (float) HISTO_BASE_UNIT * 10 / HISTO_BUCKETS;

	int latency_base = (int) latency/HISTO_BASE_UNIT;

	int unit_id = 0;
	int slot_id = 0;

	if (latency_base > 0) {
		unit_id = (int) log10(latency_base);
		slot_id = (int) (latency / (pow(10, unit_id) * slot_unit));
	} else {
		slot_id = (int) (latency / (pow(10, unit_id) * slot_unit));
	}

	if (unit_id < 0 || slot_id < 0 || slot_id >= HISTO_BUCKETS) {
		log_err("cannot put latency into histogram: %lu "
				"unit_id: %d slot_id: %d\n", latency, unit_id, slot_id);
		return;
	}

	if (unit_id >= HISTO_MAX_UNIT) {
		hist->above_threshold++;
		return;
	}

	hist->arr[unit_id][slot_id]++;
}

static void get_ptile(const struct histogram *curr, 
		int arr_size, const double *in_arr, double *out_arr)
{
	static float slot_unit = (float) HISTO_BASE_UNIT * 10 / HISTO_BUCKETS;

	uint64_t total_cnt = 0;
	int min_unit = 0;
	int min_bucket = 0;
	int max_unit = 0;
	int max_bucket = 0;
	
	static histo_count_t cumm[HISTO_MAX_UNIT][HISTO_BUCKETS];

	for (int i = 0; i < HISTO_MAX_UNIT; i++) {
		for (int j = 0; j < HISTO_BUCKETS; j++) {
			
			if (curr->arr[i][j] > 0) {
				if (min_unit == 0 && min_bucket == 0) {
					min_unit = i;
					min_bucket = j;
				}

				max_unit = i;
				max_bucket = j;
			}

			total_cnt += curr->arr[i][j];
			cumm[i][j] = total_cnt;
		}
	}
	
	if (total_cnt == 0) {
		for (int k = 0; k < arr_size; k++) {
			out_arr[k] = 0;
		}
		return;
	}

	int pcount[arr_size];
	for (int k = 0; k < arr_size; k++) {
		pcount[k] = total_cnt * in_arr[k] / 100;
		out_arr[k] = min_bucket * pow(10, min_unit) * slot_unit;
	}

	for (int i = 0; i <= max_unit; i++) {
		for (int j = 0; j <= max_bucket; j++) {
			if (curr->arr[i][j] <= 0)
				continue;
			
			uint64_t latency = j * pow(10, i) * slot_unit;
			for (int k = 0; k < arr_size; k++) {
				if (cumm[i][j] < pcount[k])
					out_arr[k] = latency;
			}
		}
	}
}

static void get_diff_ptile(const struct histogram *prev, const struct histogram *curr, 
		int arr_size, const double *in_arr, double *out_arr)
{
	static float slot_unit = (float) HISTO_BASE_UNIT * 10 / HISTO_BUCKETS;

	uint64_t total_cnt = 0;
	int min_unit = 0;
	int min_bucket = 0;
	int max_unit = 0;
	int max_bucket = 0;
	
	static histo_count_t cumm[HISTO_MAX_UNIT][HISTO_BUCKETS];
	static histo_count_t diff[HISTO_MAX_UNIT][HISTO_BUCKETS];

	for (int i = 0; i < HISTO_MAX_UNIT; i++) {
		for (int j = 0; j < HISTO_BUCKETS; j++) {
			diff[i][j] = curr->arr[i][j] - prev->arr[i][j];
			
			if (diff[i][j] > 0) {
				if (min_unit == 0 && min_bucket == 0) {
					min_unit = i;
					min_bucket = j;
				}

				max_unit = i;
				max_bucket = j;
			}

			total_cnt += diff[i][j];
			cumm[i][j] = total_cnt;
		}
	}
	
	if (total_cnt == 0) {
		for (int k = 0; k < arr_size; k++) {
			out_arr[k] = 0;
		}
		return;
	}

	int pcount[arr_size];
	for (int k = 0; k < arr_size; k++) {
		pcount[k] = total_cnt * in_arr[k] / 100;
		out_arr[k] = min_bucket * pow(10, min_unit) * slot_unit;
	}

	for (int i = 0; i <= max_unit; i++) {
		for (int j = 0; j <= max_bucket; j++) {
			if (diff[i][j] <= 0)
				continue;
			
			uint64_t latency = j * pow(10, i) * slot_unit;
			for (int k = 0; k < arr_size; k++) {
				if (cumm[i][j] < pcount[k])
					out_arr[k] = latency;
			}
		}
	}
}

static int init_hist(struct histogram* hist) 
{
	for (int i = 0; i < HISTO_MAX_UNIT; i++) {
		hist->arr[i] = mem_alloc(HISTO_BUCKETS * sizeof(histo_count_t));
		if (!hist->arr[i])
			return -ENOMEM;
	}
	return 0;
}

static void deinit_hist(struct histogram* hist) 
{
	for (int i = 0; i < HISTO_MAX_UNIT; i++) {
		if (hist->arr[i]) {
			mem_free(hist->arr[i]);
			hist->arr[i] = NULL;
		}
	}
}

static void clear_hist(struct histogram* hist) {
	for (int i = 0; i < HISTO_MAX_UNIT; i++)
		memset(hist->arr[i], 0, HISTO_BUCKETS * sizeof(histo_count_t));
}

static int save_snapshot(const struct histogram* from, struct histogram* to)
{
	if (to->arr[0] == NULL) {
		int ret = init_hist(to);
		if (ret < 0)
			return ret;
	}

	for (int i = 0; i < HISTO_MAX_UNIT; i++)
		memcpy(to->arr[i], from->arr[i], 
				HISTO_BUCKETS * sizeof(histo_count_t));

	return 0;
}

#endif
