/*
 * This software is Copyright (c) 2015 Sayantan Datta <std2048 at gmail dot com>
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification, are permitted.
 * Based on Solar Designer implementation of DES_bs_b.c in jtr-v1.7.9
 */

#ifdef HAVE_OPENCL

#include <assert.h>
#include <string.h>
#include <sys/time.h>

#include "options.h"
#include "opencl_lm.h"
#include "opencl_lm_hst_dev_shared.h"
#include "bt_interface.h"
#include "memdbg.h"

#define PADDING 	2048
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

static cl_kernel **krnl = NULL;
static cl_int err;
static cl_mem buffer_lm_key_idx, buffer_raw_keys, buffer_lm_keys, buffer_hash_ids, buffer_bitmap_dupe, buffer_hash_table, buffer_offset_table;
static int *loaded_hashes = NULL;
static unsigned int num_loaded_hashes, *hash_ids = NULL, *zero_buffer = NULL;
static size_t current_gws = 0;

static OFFSET_TABLE_WORD *offset_table = NULL;
static unsigned int hash_table_size, offset_table_size;

static int lm_crypt(int *pcount, struct db_salt *salt);

static void create_buffer_gws(size_t gws)
{
	unsigned int i;

	opencl_lm_all = (opencl_lm_combined*) mem_alloc ((gws + PADDING)* sizeof(opencl_lm_combined));
	opencl_lm_keys = (opencl_lm_transfer*) mem_alloc ((gws + PADDING)* sizeof(opencl_lm_transfer));

	buffer_raw_keys = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, (gws + PADDING) * sizeof(opencl_lm_transfer), NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Failed creating buffer_raw_keys.");

	buffer_lm_keys = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE, (gws + PADDING) * sizeof(lm_vector) * 56, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Failed creating buffer_lm_keys.");

	for (i = 0; i < (gws + PADDING); i++)
		opencl_lm_init(i);
}

static void set_kernel_args_gws()
{
	HANDLE_CLERROR(clSetKernelArg(krnl[gpu_id][1], 0, sizeof(cl_mem), &buffer_raw_keys), "Failed setting kernel argument 0, kernel 1.");
	HANDLE_CLERROR(clSetKernelArg(krnl[gpu_id][1], 1, sizeof(cl_mem), &buffer_lm_keys), "Failed setting kernel argument 1, kernel 1.");

	HANDLE_CLERROR(clSetKernelArg(krnl[gpu_id][0], 1, sizeof(cl_mem), &buffer_lm_keys), "Failed setting kernel argument 1, kernel 0.");
}

static void release_buffer_gws()
{
	if (opencl_lm_all) {
		MEM_FREE(opencl_lm_all);
		MEM_FREE(opencl_lm_keys);
		HANDLE_CLERROR(clReleaseMemObject(buffer_raw_keys), "Error releasing buffer_raw_keys.");
		HANDLE_CLERROR(clReleaseMemObject(buffer_lm_keys), "Error releasing buffer_lm_keys.");
		opencl_lm_all = 0;
	}
}

static void create_buffer(unsigned int num_loaded_hashes, unsigned int ot_size, unsigned int ht_size)
{
	hash_ids     = (unsigned int *) mem_calloc (3 * num_loaded_hashes + 1, sizeof(unsigned int));
	zero_buffer = (unsigned int *) mem_calloc (((ht_size - 1) / 32 + 1), sizeof(unsigned int));

	opencl_lm_init_index();

	buffer_lm_key_idx = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, 768 * sizeof(unsigned int), opencl_lm_index768, &ret_code);
	HANDLE_CLERROR(ret_code, "Failed creating buffer_lm_key_idx.");

	buffer_offset_table = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, ot_size * sizeof(OFFSET_TABLE_WORD), offset_table, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating buffer argument buffer_offset_table.");

	buffer_hash_table = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, ht_size * sizeof(unsigned int) * 2, hash_table_64, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating buffer argument buffer_hash_table.");

	buffer_hash_ids = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE, (3 * num_loaded_hashes + 1) * sizeof(unsigned int), NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Failed creating buffer_hash_ids.");

	buffer_bitmap_dupe = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE | CL_MEM_COPY_HOST_PTR, ((ht_size - 1) / 32 + 1) * sizeof(unsigned int), zero_buffer, &ret_code);
	HANDLE_CLERROR(err, "Failed creating buffer_bitmap_dupe.");

	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], buffer_hash_ids, CL_TRUE, 0, sizeof(cl_uint), zero_buffer, 0, NULL, NULL), "failed in clEnqueueWriteBuffer buffer_hash_ids.");
}

static void set_kernel_args()
{
	HANDLE_CLERROR(clSetKernelArg(krnl[gpu_id][0], 0, sizeof(cl_mem), &buffer_lm_key_idx), "Failed setting kernel argument 0, kernel 0.");
	HANDLE_CLERROR(clSetKernelArg(krnl[gpu_id][0], 2, sizeof(cl_mem), &buffer_offset_table), "Failed setting kernel argument 2, kernel 0.");
	HANDLE_CLERROR(clSetKernelArg(krnl[gpu_id][0], 3, sizeof(cl_mem), &buffer_hash_table), "Failed setting kernel argument 3, kernel 0.");
	HANDLE_CLERROR(clSetKernelArg(krnl[gpu_id][0], 4, sizeof(cl_mem), &buffer_hash_ids), "Failed setting kernel argument 4, kernel 0.");
	HANDLE_CLERROR(clSetKernelArg(krnl[gpu_id][0], 5, sizeof(cl_mem), &buffer_bitmap_dupe), "Failed setting kernel argument 5, kernel 0.");
}

static void release_buffer()
{
	if (buffer_bitmap_dupe) {
		MEM_FREE(loaded_hashes);
		MEM_FREE(hash_ids);
		MEM_FREE(zero_buffer);
		HANDLE_CLERROR(clReleaseMemObject(buffer_lm_key_idx), "Error releasing buffer_lm_key_idx");
		HANDLE_CLERROR(clReleaseMemObject(buffer_hash_ids), "Error releasing buffer_hash_ids.");
		HANDLE_CLERROR(clReleaseMemObject(buffer_bitmap_dupe), "Error releasing buffer_bitmap_dupe.");
		buffer_bitmap_dupe = 0;
	}
}

static void init_kernels(unsigned int num_loaded_hashes, size_t s_mem_lws, unsigned int use_local_mem)
{
	static char build_opts[500];

	sprintf (build_opts, "-D NUM_LOADED_HASHES=%u -D USE_LOCAL_MEM=%u -D WORK_GROUP_SIZE=%zu"
		 " -D OFFSET_TABLE_SIZE=%u -D HASH_TABLE_SIZE=%u" ,
		 num_loaded_hashes, use_local_mem, s_mem_lws, offset_table_size,  hash_table_size);

	opencl_read_source("$JOHN/kernels/lm_kernel.cl");
	opencl_build(gpu_id, build_opts, 0, NULL);

	krnl[gpu_id][0] = clCreateKernel(program[gpu_id], "lm_bs", &ret_code);
	HANDLE_CLERROR(ret_code, "Failed creating kernel lm_bs.");

	opencl_read_source("$JOHN/kernels/lm_finalize_keys_kernel.cl");
	opencl_build(gpu_id, build_opts, 0, NULL);

	krnl[gpu_id][1] = clCreateKernel(program[gpu_id], "lm_bs_finalize_keys", &ret_code);
	HANDLE_CLERROR(ret_code, "Failed creating kernel lm_bs_finalize_keys.");
}

static void release_kernels()
{
	if (krnl[gpu_id][0]) {
		HANDLE_CLERROR(clReleaseKernel(krnl[gpu_id][0]), "Error releasing kernel 0");
		HANDLE_CLERROR(clReleaseKernel(krnl[gpu_id][1]), "Error releasing kernel 1");
		krnl[gpu_id][0] = 0;
	}
}

static void clean_all_buffers()
{
	int i;
	release_buffer_gws();
	release_buffer();
	release_kernels();
	HANDLE_CLERROR(clReleaseProgram(program[gpu_id]),
	               "Error releasing Program");
	for (i = 0; i < MAX_PLATFORMS * MAX_DEVICES_PER_PLATFORM; i++)
		MEM_FREE(krnl[i]);
	MEM_FREE(krnl);
}

/* if returns 0x800000, means there is no restriction on lws due to local memory limitations.*/
/* if returns 0, means local memory shouldn't be allocated.*/
static size_t find_smem_lws_limit(unsigned int full_unroll, unsigned int use_local_mem, unsigned int force_global_keys)
{
	cl_ulong s_mem_sz = get_local_memory_size(gpu_id);
	size_t expected_lws_limit;
	cl_uint warp_size;

	if (force_global_keys) {
		if (s_mem_sz > 768 * sizeof(cl_short))
			return 0x800000;
		else
			return 0;
	}

	if (!s_mem_sz)
		return 0;

	if (gpu_amd(device_info[gpu_id])) {
		if (clGetDeviceInfo(devices[gpu_id], CL_DEVICE_WAVEFRONT_WIDTH_AMD,
		                    sizeof(cl_uint), &warp_size, 0) != CL_SUCCESS)
			warp_size = 64;
	}
	else if (gpu_nvidia(device_info[gpu_id])) {
		if (clGetDeviceInfo(devices[gpu_id], CL_DEVICE_WARP_SIZE_NV,
		                    sizeof(cl_uint), &warp_size, 0) != CL_SUCCESS)
			warp_size = 32;
	}
	else
		return 0;

	if (full_unroll || !use_local_mem) {
		expected_lws_limit = s_mem_sz /
				(sizeof(lm_vector) * 56);
		if (!expected_lws_limit)
			return 0;
		expected_lws_limit = GET_MULTIPLE_OR_ZERO(
				expected_lws_limit, warp_size);
	}
	else {
		if (s_mem_sz > 768 * sizeof(cl_short)) {
			s_mem_sz -= 768 * sizeof(cl_short);
			expected_lws_limit = s_mem_sz /
					(sizeof(lm_vector) * 56);
			if (!expected_lws_limit)
				return 0x800000;
			expected_lws_limit = GET_MULTIPLE_OR_ZERO(
				expected_lws_limit, warp_size);
		}
		else
			return 0;
	}

	if (warp_size == 1 && expected_lws_limit & (expected_lws_limit - 1)) {
		get_power_of_two(expected_lws_limit);
		expected_lws_limit >>= 1;
	}
	return expected_lws_limit;
}

#define calc_ms(start, end)	\
		((long double)(end.tv_sec - start.tv_sec) * 1000.000 + \
			(long double)(end.tv_usec - start.tv_usec) / 1000.000)

/* Sets global_work_size and max_keys_per_crypt. */
static void gws_tune(size_t gws_init, long double kernel_run_ms, int gws_tune_flag)
{
	unsigned int i;
	char key[PLAINTEXT_LENGTH + 1] = "alterit";

	struct timeval startc, endc;
	long double time_ms = 0;
	int pcount;

	size_t gws_limit = get_max_mem_alloc_size(gpu_id) / sizeof(opencl_lm_transfer);
	if (gws_limit > PADDING)
		gws_limit -= PADDING;

	if (gws_limit & (gws_limit - 1)) {
		get_power_of_two(gws_limit);
		gws_limit >>= 1;
	}
	assert(gws_limit > PADDING);
	assert(!(gws_limit & (gws_limit - 1)));

	if (gws_tune_flag)
		global_work_size = gws_init;

	if (global_work_size > gws_limit)
		global_work_size = gws_limit;

	if (gws_tune_flag) {
		release_buffer_gws();
		create_buffer_gws(global_work_size);
		set_kernel_args_gws();

		for (i = 0; i < (global_work_size << LM_LOG_DEPTH); i++) {
			key[i & 3] = i & 255;
			key[(i & 3) + 3] = i ^ 0x3E;
			opencl_lm_set_key(key, i);
		}

		gettimeofday(&startc, NULL);
		pcount = (int)(global_work_size << LM_LOG_DEPTH);
		lm_crypt((int *)&pcount, NULL);
		gettimeofday(&endc, NULL);

		time_ms = calc_ms(startc, endc);
		global_work_size = (size_t)((kernel_run_ms / time_ms) * (long double)global_work_size);
	}

	get_power_of_two(global_work_size);

	if (global_work_size > gws_limit)
		global_work_size = gws_limit;

	release_buffer_gws();
	create_buffer_gws(global_work_size);
	set_kernel_args_gws();

	/* for hash_ids[3*x + 1], 27 bits for storing gid and 5 bits for bs depth. */
	assert(global_work_size <= ((1U << 28) - 1));
	fmt_opencl_lm.params.max_keys_per_crypt = global_work_size << LM_LOG_DEPTH;
	fmt_opencl_lm.params.min_keys_per_crypt = LM_DEPTH;
}

static void auto_tune_all(unsigned int num_loaded_hashes, long double kernel_run_ms)
{
	unsigned int full_unroll = 0;
	unsigned int use_local_mem = 1;
	unsigned int force_global_keys = 1;
	unsigned int gws_tune_flag = 1;
	unsigned int lws_tune_flag = 1;

	size_t s_mem_limited_lws;

	struct timeval startc, endc;
	long double time_ms = 0;

	char key[PLAINTEXT_LENGTH + 1] = "alterit";

	if (cpu(device_info[gpu_id])) {
		force_global_keys = 1;
		use_local_mem = 0;
		full_unroll = 0;
		kernel_run_ms = 5;
	}
	else if (gpu(device_info[gpu_id])) {
		force_global_keys = 0;
		use_local_mem = 1;
		full_unroll = 0;
	}
	else {
		force_global_keys = 1;
		use_local_mem = 0;
		full_unroll = 0;
		kernel_run_ms = 40;
	}

	local_work_size = 0;
	global_work_size = 0;
	gws_tune_flag = 1;
	lws_tune_flag = 1;
	opencl_get_user_preferences(FORMAT_LABEL);
	if (global_work_size)
		gws_tune_flag = 0;
	if (local_work_size) {
		lws_tune_flag = 0;
		if (local_work_size & (local_work_size - 1)) {
			get_power_of_two(local_work_size);
		}
	}

	s_mem_limited_lws = find_smem_lws_limit(
			full_unroll, use_local_mem, force_global_keys);
#if 0
	fprintf(stdout, "Limit_smem:%zu, Full_unroll_flag:%u,"
		"Use_local_mem:%u, Force_global_keys:%u\n",
 		s_mem_limited_lws, full_unroll, use_local_mem,
		force_global_keys);
#endif

	if (s_mem_limited_lws == 0x800000 || !s_mem_limited_lws) {
		long double best_time_ms;
		size_t best_lws, lws_limit;

		release_kernels();
		init_kernels(num_loaded_hashes, 0, use_local_mem && s_mem_limited_lws);
		set_kernel_args();

		gws_tune(1024, 2 * kernel_run_ms, gws_tune_flag);
		gws_tune(global_work_size, kernel_run_ms, gws_tune_flag);

		lws_limit = get_kernel_max_lws(gpu_id, krnl[gpu_id][0]);

		if (lws_tune_flag) {
			if (gpu(device_info[gpu_id]) && lws_limit >= 32)
				local_work_size = 32;
			else
				local_work_size = get_kernel_preferred_multiple(gpu_id, krnl[gpu_id][0]);
		}
		if (local_work_size > lws_limit)
			local_work_size = lws_limit;

		assert(local_work_size <= lws_limit);

		if (lws_tune_flag) {
			time_ms = 0;
			best_time_ms = 999999.00;
			best_lws = local_work_size;
			while (local_work_size <= lws_limit) {
				int pcount, i;
				for (i = 0; i < (global_work_size << LM_LOG_DEPTH); i++) {
					key[i & 3] = i & 255;
					key[(i & 3) + 3] = i ^ 0x3F;
					opencl_lm_set_key(key, i);
				}
				gettimeofday(&startc, NULL);
				pcount = (int)(global_work_size << LM_LOG_DEPTH);
				lm_crypt((int *)&pcount, NULL);
				gettimeofday(&endc, NULL);

				time_ms = calc_ms(startc, endc);

				if (time_ms < best_time_ms) {
					best_lws = local_work_size;
					best_time_ms = time_ms;
				}
#if 0
	fprintf(stdout, "GWS: %zu, LWS: %zu, Limit_smem:%zu, Limit_kernel:%zu,"
		"Current time:%Lf, Best time:%Lf\n",
 		global_work_size, local_work_size, s_mem_limited_lws,
		get_kernel_max_lws(gpu_id, krnl[gpu_id][0]), time_ms,
		best_time_ms);
#endif
				local_work_size *= 2;
			}
			local_work_size = best_lws;
			gws_tune(global_work_size, kernel_run_ms, gws_tune_flag);
		}
	}

	else {
		long double best_time_ms;
		size_t best_lws;
		cl_uint warp_size;

		if (gpu_amd(device_info[gpu_id])) {
			if (clGetDeviceInfo(devices[gpu_id], CL_DEVICE_WAVEFRONT_WIDTH_AMD,
			                    sizeof(cl_uint), &warp_size, 0) != CL_SUCCESS)
				warp_size = 64;
		}
		else if (gpu_nvidia(device_info[gpu_id])) {
			if (clGetDeviceInfo(devices[gpu_id], CL_DEVICE_WARP_SIZE_NV,
			                    sizeof(cl_uint), &warp_size, 0) != CL_SUCCESS)
				warp_size = 32;
		}
		else {
			warp_size = 1;
			fprintf(stderr, "Possible auto_tune fail!!.\n");
		}
		if (lws_tune_flag)
			local_work_size = warp_size;
		if (local_work_size > s_mem_limited_lws)
			local_work_size = s_mem_limited_lws;

		release_kernels();
		init_kernels(num_loaded_hashes, local_work_size, use_local_mem);

		if (local_work_size > get_kernel_max_lws(gpu_id, krnl[gpu_id][0])) {
			local_work_size = get_kernel_max_lws(gpu_id, krnl[gpu_id][0]);
			release_kernels();
			init_kernels(num_loaded_hashes, local_work_size, use_local_mem);
		}

		set_kernel_args();
		gws_tune(1024, 2 * kernel_run_ms, gws_tune_flag);
		gws_tune(global_work_size, kernel_run_ms, gws_tune_flag);

		if (lws_tune_flag) {
			best_time_ms = 999999.00;
			best_lws = local_work_size;
			while (local_work_size <= s_mem_limited_lws) {
				int pcount, i;
				release_kernels();
				init_kernels(num_loaded_hashes, local_work_size, use_local_mem);
				set_kernel_args();
				set_kernel_args_gws();

				for (i = 0; i < (global_work_size << LM_LOG_DEPTH); i++) {
					key[i & 3] = i & 255;
					key[(i & 3) + 3] = i ^ 0x3E;
					opencl_lm_set_key(key, i);
				}

				gettimeofday(&startc, NULL);
				pcount = (int)(global_work_size << LM_LOG_DEPTH);
				lm_crypt((int *)&pcount, NULL);
				gettimeofday(&endc, NULL);
				time_ms = calc_ms(startc, endc);

				if (time_ms < best_time_ms &&
				  local_work_size <= get_kernel_max_lws(
				    gpu_id, krnl[gpu_id][0])) {
					best_lws = local_work_size;
					best_time_ms = time_ms;
				}
#if 0
	fprintf(stdout, "GWS: %zu, LWS: %zu, Limit_smem:%zu, Limit_kernel:%zu,"
		"Current time:%Lf, Best time:%Lf\n",
 		global_work_size, local_work_size, s_mem_limited_lws,
		get_kernel_max_lws(gpu_id, krnl[gpu_id][0]), time_ms,
		best_time_ms);
#endif
				if (gpu(device_info[gpu_id])) {
					if (local_work_size < 16)
						local_work_size = 16;
					else if (local_work_size < 32)
						local_work_size = 32;
					else if (local_work_size < 64)
						local_work_size = 64;
					else if (local_work_size < 96)
						local_work_size = 96;
					else if (local_work_size < 128)
						local_work_size = 128;
					else
						local_work_size += warp_size;
				}
				else
					local_work_size *= 2;
			}
			local_work_size = best_lws;
			release_kernels();
			init_kernels(num_loaded_hashes, local_work_size, use_local_mem);
			set_kernel_args();
			gws_tune(global_work_size, kernel_run_ms, gws_tune_flag);
		}
	}
	if (options.verbosity > 3)
	fprintf(stdout, "GWS: %zu, LWS: %zu\n",
		global_work_size, local_work_size);
}

static void prepare_table(struct db_salt *salt) {
	int *bin, i;
	struct db_password *pw;

	MEM_FREE(loaded_hashes);

	num_loaded_hashes = salt->count;
	loaded_hashes = (int *)mem_alloc(num_loaded_hashes * sizeof(int) * 2);

	pw = salt -> list;
	i = 0;
	do {
		bin = (int *)pw -> binary;
		// Potential segfault if removed
		if(bin != NULL) {
			loaded_hashes[2 * i] = bin[0];
			loaded_hashes[2 * i + 1] = bin[1];
			i++ ;
		}
	} while ((pw = pw -> next)) ;

	if(i != (salt->count)) {
		fprintf(stderr,
			"Something went wrong while preparing hashes..Exiting..\n");
		error();
	}

	num_loaded_hashes = create_perfect_hash_table(64, (void *)loaded_hashes,
				num_loaded_hashes,
			        &offset_table,
			        &offset_table_size,
			        &hash_table_size, 0);

	if (!num_loaded_hashes) {
		MEM_FREE(hash_table_64);
		MEM_FREE(offset_table);
		fprintf(stderr, "Failed to create Hash Table for cracking.\n");
		error();
	}
}

static void reset(struct db_main *db)
{
	static int initialized;

	if (initialized) {
		struct db_salt *salt;

		release_buffer();
		release_buffer_gws();
		release_kernels();

		salt = db->salts;
		prepare_table(salt);
		create_buffer(num_loaded_hashes, offset_table_size, hash_table_size);

		auto_tune_all(num_loaded_hashes, 300);
	}
	else {
		int i, *binary;
		char *ciphertext;

		num_loaded_hashes = 0;
		while (fmt_opencl_lm.params.tests[num_loaded_hashes].ciphertext) num_loaded_hashes++;

		loaded_hashes = (int *) mem_alloc (num_loaded_hashes * sizeof(int) * 2);

		i = 0;
		while (fmt_opencl_lm.params.tests[i].ciphertext) {
			char **fields = fmt_opencl_lm.params.tests[i].fields;
			if (!fields[1])
				fields[1] = fmt_opencl_lm.params.tests[i].ciphertext;
			ciphertext = fmt_opencl_lm.methods.split(fmt_opencl_lm.methods.prepare(fields, &fmt_opencl_lm), 0, &fmt_opencl_lm);
			binary = (int *)fmt_opencl_lm.methods.binary(ciphertext);
			loaded_hashes[2 * i] = binary[0];
			loaded_hashes[2 * i + 1] = binary[1];
			i++;
			//fprintf(stderr, "C:%s B:%d %d %d\n", ciphertext, binary[0], binary[1], i == num_loaded_hashes );
		}

		num_loaded_hashes = create_perfect_hash_table(64, (void *)loaded_hashes,
				num_loaded_hashes,
			        &offset_table,
			        &offset_table_size,
			        &hash_table_size, 0);

		if (!num_loaded_hashes) {
			MEM_FREE(hash_table_64);
			MEM_FREE(offset_table);
			fprintf(stderr, "Failed to create Hash Table for self test.\n");
			error();
		}

		create_buffer(num_loaded_hashes, offset_table_size, hash_table_size);
		auto_tune_all(num_loaded_hashes, 300);

		hash_ids[0] = 0;
		initialized++;
	}
}

static void init_global_variables()
{
	int i;

	krnl = (cl_kernel **) mem_calloc(MAX_PLATFORMS * MAX_DEVICES_PER_PLATFORM, sizeof(cl_kernel *));
	for (i = 0; i < MAX_PLATFORMS * MAX_DEVICES_PER_PLATFORM; i++)
		krnl[i] = (cl_kernel *) mem_calloc(2, sizeof(cl_kernel));
}

static char *get_key(int index)
{
      get_key_body();
}

static int lm_crypt(int *pcount, struct db_salt *salt)
{
	cl_event evnt;
	const int count = (*pcount + LM_DEPTH - 1) >> LM_LOG_DEPTH;
	size_t *lws = local_work_size ? &local_work_size : NULL;
	current_gws = local_work_size ? (count + local_work_size - 1) / local_work_size * local_work_size : count;

	assert(current_gws <= global_work_size + PADDING);
	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], buffer_raw_keys, CL_TRUE, 0, current_gws * sizeof(opencl_lm_transfer), opencl_lm_keys, 0, NULL, NULL ), "Failed Copy data to gpu");
	err = clEnqueueNDRangeKernel(queue[gpu_id], krnl[gpu_id][1], 1, NULL, &current_gws, lws, 0, NULL, &evnt);
	HANDLE_CLERROR(err, "Enque Kernel Failed");
	clWaitForEvents(1, &evnt);
	clReleaseEvent(evnt);

	err = clEnqueueNDRangeKernel(queue[gpu_id], krnl[gpu_id][0], 1, NULL, &current_gws, lws, 0, NULL, &evnt);
	HANDLE_CLERROR(err, "Enque Kernel Failed");

	clWaitForEvents(1, &evnt);
	clReleaseEvent(evnt);

	HANDLE_CLERROR(clEnqueueReadBuffer(queue[gpu_id], buffer_hash_ids, CL_TRUE, 0, sizeof(unsigned int), hash_ids, 0, NULL, NULL), "Write FAILED\n");

	if (hash_ids[0] > num_loaded_hashes) {
		fprintf(stderr, "Error, crypt_all kernel.\n");
		error();
	}

	if (hash_ids[0]) {
		HANDLE_CLERROR(clEnqueueReadBuffer(queue[gpu_id], buffer_hash_ids, CL_TRUE, 0, (3 * hash_ids[0] + 1) * sizeof(unsigned int), hash_ids, 0, NULL, NULL), "Write FAILED\n");
		HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], buffer_bitmap_dupe, CL_TRUE, 0, ((hash_table_size - 1)/32 + 1) * sizeof(cl_uint), zero_buffer, 0, NULL, NULL), "failed in clEnqueueWriteBuffer buffer_bitmap_dupe.");
		HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], buffer_hash_ids, CL_TRUE, 0, sizeof(cl_uint), zero_buffer, 0, NULL, NULL), "failed in clEnqueueWriteBuffer buffer_hash_ids.");
	}

	return hash_ids[0];
}

int opencl_lm_get_hash_0(int index)
{
	return hash_table_64[hash_ids[3 + 3 * index]] & 0xf;
}

int opencl_lm_get_hash_1(int index)
{
	return hash_table_64[hash_ids[3 + 3 * index]] & 0xff;
}

int opencl_lm_get_hash_2(int index)
{
	return hash_table_64[hash_ids[3 + 3 * index]] & 0xfff;
}

int opencl_lm_get_hash_3(int index)
{
	return hash_table_64[hash_ids[3 + 3 * index]] & 0xffff;
}

int opencl_lm_get_hash_4(int index)
{
	return hash_table_64[hash_ids[3 + 3 * index]] & 0xfffff;
}

int opencl_lm_get_hash_5(int index)
{
	return hash_table_64[hash_ids[3 + 3 * index]] & 0xffffff;
}

int opencl_lm_get_hash_6(int index)
{
	return hash_table_64[hash_ids[3 + 3 * index]] & 0x7ffffff;
}

static int cmp_one(void *binary, int index)
{
	if (((int *)binary)[0] == hash_table_64[hash_ids[3 + 3 * index]])
		return 1;
	return 0;
}

static int cmp_exact(char *source, int index)
{
	int *binary = opencl_lm_get_binary(source + 4);

	if (binary[1] == hash_table_64[hash_ids[3 + 3 * index] + hash_table_size])
		return 1;
	return 0;
}

void opencl_lm_b_register_functions(struct fmt_main *fmt)
{
	fmt->methods.done = &clean_all_buffers;
	fmt->methods.reset = &reset;
	fmt->methods.get_key = &get_key;
	fmt->methods.crypt_all = &lm_crypt;
	fmt->methods.cmp_exact = cmp_exact;
	fmt->methods.cmp_one = cmp_one;
	opencl_lm_init_global_variables = &init_global_variables;
}
#endif /* HAVE_OPENCL */
