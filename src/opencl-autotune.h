/*
 * Developed by Claudio André <claudioandre.br at gmail.com> in 2012
 *
 *
 * Copyright (c) 2012-2015 Claudio André <claudioandre.br at gmail.com>
 * This program comes with ABSOLUTELY NO WARRANTY; express or implied.
 *
 * This is free software, and you are welcome to redistribute it
 * under certain conditions; as expressed here
 * http://www.gnu.org/licenses/gpl-2.0.html
 */

#ifndef _COMMON_TUNE_H
#define _COMMON_TUNE_H

#include "common-opencl.h"

/* Step size for work size enumeration. Zero will double. */
#ifndef STEP
#define STEP	0
#endif

/* Start size for GWS enumeration */
#ifndef SEED
#define SEED	128
#endif

//Necessary definitions. Each format have to have each one of them.
static size_t get_task_max_work_group_size();
static void create_clobj(size_t gws, struct fmt_main * self);
static void release_clobj(void);

/* Keeps track of whether we already tuned */
static int autotuned;

/* ------- Externals ------- */
/* Can be used to select a 'good' default gws size */
size_t autotune_get_task_max_size(int multiplier, int keys_per_core_cpu,
	int keys_per_core_gpu, cl_kernel crypt_kernel);

/* Can be used to select a 'good' default lws size */
size_t autotune_get_task_max_work_group_size(int use_local_memory,
	int local_memory_size, cl_kernel crypt_kernel);

/* --
  This function could be used to calculated the best num
  of keys per crypt for the given format
-- */
void autotune_find_best_gws(int sequential_id, unsigned int rounds, int step,
	unsigned long long int max_run_time, int have_lws);

/* --
  This function could be used to calculated the best local
  group size for the given format
-- */
void autotune_find_best_lws(size_t group_size_limit,
	int sequential_id, cl_kernel crypt_kernel);

/* ------- Try to find the best configuration ------- */
/* --
  This function could be used to calculated the best num
  for the workgroup
  Work-items that make up a work-group (also referred to
  as the size of the work-group)
-- */
static void find_best_lws(struct fmt_main * self, int sequential_id)
{
	//Call the default function.
	autotune_find_best_lws(
		get_task_max_work_group_size(), sequential_id, crypt_kernel
	);
}

/* --
  This function could be used to calculated the best num
  of keys per crypt for the given format
-- */
static void find_best_gws(struct fmt_main * self, int sequential_id, unsigned int rounds,
	unsigned long long int max_run_time, int have_lws)
{
	//Call the common function.
	autotune_find_best_gws(
		sequential_id, rounds, STEP, max_run_time, have_lws
	);

	create_clobj(global_work_size, self);
}

#define get_power_of_two(v)	\
{				\
	v--;			\
	v |= v >> 1;		\
	v |= v >> 2;		\
	v |= v >> 4;		\
	v |= v >> 8;		\
	v |= v >> 16;		\
	v |= v >> 32;		\
	v++;			\
}

/* --
  This function does the common part of auto-tune adjustments,
  preparation and execution. It is shared code to be inserted
  in each format file.
-- */
static void autotune_run_extra(struct fmt_main * self, unsigned int rounds,
	size_t gws_limit, unsigned long long int max_run_time, cl_uint lws_is_power_of_two)
{
	int need_best_lws, need_best_gws;

	/* Read LWS/GWS prefs from config or environment */
	opencl_get_user_preferences(FORMAT_LABEL);

	if (!global_work_size && !getenv("GWS"))
		global_work_size = 0;

	need_best_lws = !local_work_size && !getenv("LWS");
	if (need_best_lws)
		local_work_size = 0;

	if (gws_limit && (global_work_size > gws_limit))
		global_work_size = gws_limit;

	/* Adjust, if necessary */
	if (!local_work_size)
		global_work_size = GET_MULTIPLE_OR_ZERO(global_work_size, 64);
	else if (global_work_size)
		global_work_size = GET_MULTIPLE_OR_ZERO(global_work_size, local_work_size);

	if (lws_is_power_of_two && local_work_size & (local_work_size - 1))
		  get_power_of_two(local_work_size);

	/* Ensure local_work_size is not oversized */
	if (local_work_size > get_task_max_work_group_size())
		local_work_size = get_task_max_work_group_size();

	/* Enumerate GWS using *LWS=NULL (unless it was set explicitly) */
	need_best_gws = !global_work_size;
	if (need_best_gws) {
		unsigned long long int max_run_time1;
		int have_lws = !(!local_work_size || need_best_lws);
		if (have_lws) {
			max_run_time1 = max_run_time;
			need_best_gws = 0;
		} else {
			max_run_time1 = (max_run_time + 1) / 2;
		}
		find_best_gws(self, gpu_id, rounds, max_run_time1, have_lws);
	} else {
		create_clobj(global_work_size, self);
	}

	if (!local_work_size || need_best_lws)
		find_best_lws(self, gpu_id);

	if (need_best_gws)
		find_best_gws(self, gpu_id, rounds, max_run_time, 1);

	/* Adjust to the final configuration */
	release_clobj();
	global_work_size = GET_EXACT_MULTIPLE(global_work_size, local_work_size);
	create_clobj(global_work_size, self);

	if (options.verbosity > 3 && !(options.flags & FLG_SHOW_CHK))
		fprintf(stderr,
		        "Local worksize (LWS) "Zu", global worksize (GWS) "Zu"\n",
		        local_work_size, global_work_size);

	self->params.min_keys_per_crypt = local_work_size * opencl_v_width;
	self->params.max_keys_per_crypt = global_work_size * opencl_v_width;

	autotuned++;
}

static void autotune_run(struct fmt_main * self, unsigned int rounds,
	size_t gws_limit, unsigned long long int max_run_time)
{
	return autotune_run_extra(self, rounds, gws_limit, max_run_time, CL_FALSE);
}


#undef get_power_of_two
#endif  /* _COMMON_TUNE_H */
