/*
 * Developed by Claudio André <claudio.andre at correios.net.br> in 2012
 *
 * Copyright (c) 2012 Claudio André <claudio.andre at correios.net.br>
 * This program comes with ABSOLUTELY NO WARRANTY; express or implied.
 *
 * This is free software, and you are welcome to redistribute it
 * under certain conditions; as expressed here
 * http://www.gnu.org/licenses/gpl-2.0.html
 */

#include "common-opencl.h"
#include "opencl_sha2_common.h"

/* Allow the developer to select configurable step size for gws. */
int common_get_next_gws_size(size_t num, int step, int startup, int default_value) {

    if (startup) {

        if (step == 0)
            return GET_MULTIPLE(default_value, local_work_size);
        else
            return GET_MULTIPLE(step, local_work_size);
    }

    if (step < 1)
        return num * 2;

    return num + step;
}

/* Can be used to select a 'good' default lws size */
size_t common_get_task_max_work_group_size(int use_local_memory,
	int local_memory_size, cl_kernel crypt_kernel) {

	size_t max_available;

	if (use_local_memory)
		max_available = get_local_memory_size(ocl_gpu_id) /
				(local_memory_size);
	else
		max_available = get_max_work_group_size(ocl_gpu_id);

	if (max_available > get_current_work_group_size(ocl_gpu_id, crypt_kernel))
		return get_current_work_group_size(ocl_gpu_id, crypt_kernel);

	return max_available;
}

/* Can be used to select a 'good' default gws size */
size_t common_get_task_max_size(int multiplier, int keys_per_core_cpu,
	int keys_per_core_gpu, cl_kernel crypt_kernel) {

	size_t max_available;
	max_available = get_max_compute_units(ocl_gpu_id);

	if (cpu(device_info[ocl_gpu_id]))
		return max_available * keys_per_core_cpu;

	else
		return max_available * multiplier * keys_per_core_gpu *
				get_current_work_group_size(ocl_gpu_id, crypt_kernel);
}

/*
 * Public domain hash function by DJ Bernstein
 * We are hashing almost the entire struct
 */
int common_salt_hash(void * salt, int salt_size, int salt_hash_size) {
	unsigned char *s = salt;
	unsigned int hash = 5381;
	unsigned int i;

	for (i = 0; i < salt_size; i++)
		hash = ((hash << 5) + hash) ^ s[i];

	return hash & (salt_hash_size - 1);
}

/* --
  This function could be used to calculated the best local
  group size for the given format
-- */
void common_find_best_lws(size_t group_size_limit,
	unsigned int sequential_id, cl_kernel crypt_kernel) {

	int show_details = 0;

	if (getenv("DETAILS"))
		show_details = 1;

	//Call the default function.
	opencl_find_best_lws(
		show_details, group_size_limit, sequential_id, crypt_kernel
	);
}

/* --
  This function could be used to calculated the best num
  of keys per crypt for the given format
-- */
void common_find_best_gws(int sequential_id, unsigned int rounds, int step,
	unsigned long long int max_run_time) {

	int show_speed = 0, show_details = 0;
	char *tmp_value;

	if (getenv("DETAILS")) {
		show_details = 1;
	}

	if ((tmp_value = getenv("STEP"))) {
		step = atoi(tmp_value);
		show_speed = 1;
	}
	step = GET_MULTIPLE(step, local_work_size);

	//Call the default function.
	opencl_find_best_gws(
		step, show_speed, show_details, max_run_time, sequential_id, rounds);
}
