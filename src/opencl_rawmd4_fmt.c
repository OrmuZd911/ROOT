/*
 * MD4 OpenCL code is based on Alain Espinosa's OpenCL patches.
 *
 * This software is Copyright (c) 2010, Dhiru Kholia <dhiru.kholia at gmail.com>
 * and Copyright (c) 2012, magnum
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#include <string.h>

#include "arch.h"
#include "params.h"
#include "path.h"
#include "common.h"
#include "formats.h"
#include "common-opencl.h"
#include "config.h"
#include "options.h"

#define PLAINTEXT_LENGTH    55 /* Max. is 55 with current kernel */
#define BUFSIZE             ((PLAINTEXT_LENGTH+3)/4*4)
#define FORMAT_LABEL        "raw-md4-opencl"
#define FORMAT_NAME         "Raw MD4"
#define ALGORITHM_NAME      "OpenCL (inefficient, development use only)"
#define BENCHMARK_COMMENT   ""
#define BENCHMARK_LENGTH    -1
#define CIPHERTEXT_LENGTH   32
#define DIGEST_SIZE         16
#define BINARY_SIZE         4
#define SALT_SIZE           0

#define FORMAT_TAG          "$MD4$"
#define TAG_LENGTH          (sizeof(FORMAT_TAG) - 1)

cl_command_queue queue_prof;
cl_mem pinned_saved_keys, pinned_saved_idx, pinned_partial_hashes;
cl_mem buffer_keys, buffer_idx, buffer_out;
static cl_uint *partial_hashes;
static cl_uint *res_hashes;
static unsigned int *saved_plain, *saved_idx;
static unsigned int key_idx = 0;

#define MIN(a, b)               (((a) > (b)) ? (b) : (a))
#define MAX(a, b)               (((a) > (b)) ? (a) : (b))

#define MIN_KEYS_PER_CRYPT      1024
#define MAX_KEYS_PER_CRYPT      (1024 * 2048)

#define CONFIG_NAME             "rawmd4"
#define STEP                    65536

static int have_full_hashes;

static const char * warn[] = {
	"pass xfer: "  ,  ", crypt: "    ,  ", result xfer: "
};

extern void common_find_best_lws(size_t group_size_limit,
        unsigned int sequential_id, cl_kernel crypt_kernel);
extern void common_find_best_gws(int sequential_id, unsigned int rounds, int step,
        unsigned long long int max_run_time);

static int crypt_all(int *pcount, struct db_salt *_salt);
static int crypt_all_benchmark(int *pcount, struct db_salt *_salt);

static struct fmt_tests tests[] = {
	{"$MD4$6d78785c44ea8dfa178748b245d8c3ae", "magnum" },
	{"$MD4$31d6cfe0d16ae931b73c59d7e0c089c0", "" },
	{"$MD4$cafbb81fb64d9dd286bc851c4c6e0d21", "lolcode" },
	{"$MD4$585028aa0f794af812ee3be8804eb14a", "123456" },
	{"$MD4$23580e2a459f7ea40f9efa148b63cafb", "12345" },
	{"$MD4$bf75555ca19051f694224f2f5e0b219d", "1234567" },
	{"$MD4$41f92cf74e3d2c3ba79183629a929915", "rockyou" },
	{"$MD4$0ceb1fd260c35bd50005341532748de6", "abc123" },
	{NULL}
};

static void create_clobj(int kpc, struct fmt_main * self)
{
	self->params.min_keys_per_crypt = self->params.max_keys_per_crypt = kpc;

	pinned_saved_keys = clCreateBuffer(context[ocl_gpu_id], CL_MEM_READ_ONLY | CL_MEM_ALLOC_HOST_PTR, BUFSIZE * kpc, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating page-locked memory pinned_saved_keys");
	saved_plain = clEnqueueMapBuffer(queue[ocl_gpu_id], pinned_saved_keys, CL_TRUE, CL_MAP_READ | CL_MAP_WRITE, 0, BUFSIZE * kpc, 0, NULL, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping page-locked memory saved_plain");

	pinned_saved_idx = clCreateBuffer(context[ocl_gpu_id], CL_MEM_READ_ONLY | CL_MEM_ALLOC_HOST_PTR, 4 * kpc, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating page-locked memory pinned_saved_idx");
	saved_idx = clEnqueueMapBuffer(queue[ocl_gpu_id], pinned_saved_idx, CL_TRUE, CL_MAP_READ | CL_MAP_WRITE, 0, 4 * kpc, 0, NULL, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping page-locked memory saved_idx");

	res_hashes = malloc(sizeof(cl_uint) * 3 * kpc);

	pinned_partial_hashes = clCreateBuffer(context[ocl_gpu_id], CL_MEM_WRITE_ONLY | CL_MEM_ALLOC_HOST_PTR, 4 * kpc, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating page-locked memory pinned_partial_hashes");
	partial_hashes = (cl_uint *) clEnqueueMapBuffer(queue[ocl_gpu_id], pinned_partial_hashes, CL_TRUE, CL_MAP_READ, 0, 4 * kpc, 0, NULL, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping page-locked memory partial_hashes");

	// create and set arguments
	buffer_keys = clCreateBuffer(context[ocl_gpu_id], CL_MEM_READ_ONLY, BUFSIZE * kpc, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating buffer argument buffer_keys");

	buffer_idx = clCreateBuffer(context[ocl_gpu_id], CL_MEM_READ_ONLY, 4 * kpc, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating buffer argument buffer_idx");

	buffer_out = clCreateBuffer(context[ocl_gpu_id], CL_MEM_WRITE_ONLY, DIGEST_SIZE * kpc, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating buffer argument buffer_out");

	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 0, sizeof(buffer_keys), (void *) &buffer_keys), "Error setting argument 1");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 1, sizeof(buffer_idx), (void *) &buffer_idx), "Error setting argument 2");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 2, sizeof(buffer_out), (void *) &buffer_out), "Error setting argument 3");

	global_work_size = kpc;
}

static void release_clobj(void)
{
	HANDLE_CLERROR(clEnqueueUnmapMemObject(queue[ocl_gpu_id], pinned_partial_hashes, partial_hashes, 0,NULL,NULL), "Error Unmapping partial_hashes");
	HANDLE_CLERROR(clEnqueueUnmapMemObject(queue[ocl_gpu_id], pinned_saved_keys, saved_plain, 0, NULL, NULL), "Error Unmapping saved_plain");
	HANDLE_CLERROR(clEnqueueUnmapMemObject(queue[ocl_gpu_id], pinned_saved_idx, saved_idx, 0, NULL, NULL), "Error Unmapping saved_idx");

	HANDLE_CLERROR(clReleaseMemObject(buffer_keys), "Error Releasing buffer_keys");
	HANDLE_CLERROR(clReleaseMemObject(buffer_idx), "Error Releasing buffer_idx");
	HANDLE_CLERROR(clReleaseMemObject(buffer_out), "Error Releasing buffer_out");
	HANDLE_CLERROR(clReleaseMemObject(pinned_saved_keys), "Error Releasing pinned_saved_keys");
	HANDLE_CLERROR(clReleaseMemObject(pinned_partial_hashes), "Error Releasing pinned_partial_hashes");
	MEM_FREE(res_hashes);
}

static void done(void)
{
	release_clobj();

	HANDLE_CLERROR(clReleaseKernel(crypt_kernel), "Release kernel");
	HANDLE_CLERROR(clReleaseProgram(program[ocl_gpu_id]), "Release Program");
}

/* ------- Try to find the best configuration ------- */
/* --
   This function could be used to calculated the best num
   for the workgroup
   Work-items that make up a work-group (also referred to
   as the size of the work-group)
   -- */
static void find_best_lws(struct fmt_main * self, int sequential_id) {

	// Call the default function.
	common_find_best_lws(
		get_current_work_group_size(ocl_gpu_id, crypt_kernel),
		sequential_id, crypt_kernel
		);
}

/* --
   This function could be used to calculated the best num
   of keys per crypt for the given format
   -- */
static void find_best_gws(struct fmt_main * self, int sequential_id) {

	// Call the common function.
	common_find_best_gws(
		sequential_id, 1, 0,
		(cpu(device_info[ocl_gpu_id]) ? 500000000ULL : 1000000000ULL)
		);

	create_clobj(global_work_size, self);
}

static void init(struct fmt_main *self)
{
	size_t selected_gws, max_mem;

	opencl_init("$JOHN/kernels/md4_kernel.cl", ocl_gpu_id);
	crypt_kernel = clCreateKernel(program[ocl_gpu_id], "md4", &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating kernel. Double-check kernel name?");

	local_work_size = global_work_size = 0;
	opencl_get_user_preferences(CONFIG_NAME);

	// Initialize openCL tuning (library) for this format.
	opencl_init_auto_setup(STEP, 0, 3, NULL, warn,
	        &multi_profilingEvent[1], self, create_clobj,
	        release_clobj, BUFSIZE, 0);
	self->methods.crypt_all = crypt_all_benchmark;

	self->params.max_keys_per_crypt = (global_work_size ?
	        global_work_size : MAX_KEYS_PER_CRYPT);
	selected_gws = global_work_size;

	if (!local_work_size) {
		create_clobj(self->params.max_keys_per_crypt, self);
		find_best_lws(self, ocl_gpu_id);
		release_clobj();
	}
	global_work_size = selected_gws;

	// Obey device limits
	if (local_work_size > get_current_work_group_size(ocl_gpu_id, crypt_kernel))
		local_work_size = get_current_work_group_size(ocl_gpu_id, crypt_kernel);
	clGetDeviceInfo(devices[ocl_gpu_id], CL_DEVICE_MAX_MEM_ALLOC_SIZE,
	        sizeof(max_mem), &max_mem, NULL);
	while (global_work_size > MIN((1<<26)*4/56, max_mem / BUFSIZE))
		global_work_size -= local_work_size;

	if (global_work_size)
		create_clobj(global_work_size, self);
	else {
		find_best_gws(self, ocl_gpu_id);
	}
	fprintf(stderr, "Local worksize (LWS) %zd, global worksize (GWS) %zd\n",
	        local_work_size, global_work_size);
	self->params.min_keys_per_crypt = local_work_size;
	self->params.max_keys_per_crypt = global_work_size;
	self->methods.crypt_all = crypt_all;
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *p, *q;

	p = ciphertext;
	if (!strncmp(p, FORMAT_TAG, TAG_LENGTH))
		p += TAG_LENGTH;

	q = p;
	while (atoi16[ARCH_INDEX(*q)] != 0x7F) {
		if (*q >= 'A' && *q <= 'F') /* support lowercase only */
			return 0;
		q++;
	}
	return !*q && q - p == CIPHERTEXT_LENGTH;
}

static char *split(char *ciphertext, int index, struct fmt_main *self)
{
	static char out[TAG_LENGTH + CIPHERTEXT_LENGTH + 1];

	if (!strncmp(ciphertext, FORMAT_TAG, TAG_LENGTH))
		return ciphertext;

	memcpy(out, FORMAT_TAG, TAG_LENGTH);
	memcpy(out + TAG_LENGTH, ciphertext, CIPHERTEXT_LENGTH + 1);
	return out;
}

static void *get_binary(char *ciphertext)
{
	static unsigned char out[DIGEST_SIZE];
	char *p;
	int i;
	p = ciphertext + TAG_LENGTH;
	for (i = 0; i < sizeof(out); i++) {
		out[i] = (atoi16[ARCH_INDEX(*p)] << 4) | atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}
	return out;
}
static int binary_hash_0(void *binary) { return *(ARCH_WORD_32 *) binary & 0xF; }
static int binary_hash_1(void *binary) { return *(ARCH_WORD_32 *) binary & 0xFF; }
static int binary_hash_2(void *binary) { return *(ARCH_WORD_32 *) binary & 0xFFF; }
static int binary_hash_3(void *binary) { return *(ARCH_WORD_32 *) binary & 0xFFFF; }
static int binary_hash_4(void *binary) { return *(ARCH_WORD_32 *) binary & 0xFFFFF; }
static int binary_hash_5(void *binary) { return *(ARCH_WORD_32 *) binary & 0xFFFFFF; }
static int binary_hash_6(void *binary) { return *(ARCH_WORD_32 *) binary & 0x7FFFFFF; }

static int get_hash_0(int index) { return partial_hashes[index] & 0xF; }
static int get_hash_1(int index) { return partial_hashes[index] & 0xFF; }
static int get_hash_2(int index) { return partial_hashes[index] & 0xFFF; }
static int get_hash_3(int index) { return partial_hashes[index] & 0xFFFF; }
static int get_hash_4(int index) { return partial_hashes[index] & 0xFFFFF; }
static int get_hash_5(int index) { return partial_hashes[index] & 0xFFFFFF; }
static int get_hash_6(int index) { return partial_hashes[index] & 0x7FFFFFF; }

static void clear_keys(void)
{
	key_idx = 0;
}

static void set_key(char *_key, int index)
{
	const ARCH_WORD_32 *key = (ARCH_WORD_32*)_key;
	int len = strlen(_key);

	saved_idx[index] = (key_idx << 6) | len;

	while (len > 4) {
		saved_plain[key_idx++] = *key++;
		len -= 4;
	}
	if (len)
		saved_plain[key_idx++] = *key & (0xffffffffU >> (32 - (len << 3)));
}

static char *get_key(int index)
{
	static char out[PLAINTEXT_LENGTH + 1];
	int i, len = saved_idx[index] & 63;
	char *key = (char*)&saved_plain[saved_idx[index] >> 6];

	for (i = 0; i < len; i++)
		out[i] = *key++;
	out[i] = 0;
	return out;
}

static int crypt_all_benchmark(int *pcount, struct db_salt *salt)
{
	int count = *pcount;

	global_work_size = (count + local_work_size - 1) / local_work_size * local_work_size;

	// copy keys to the device
	BENCH_CLERROR(clEnqueueWriteBuffer(queue[ocl_gpu_id], buffer_keys, CL_TRUE, 0, 4 * key_idx, saved_plain, 0, NULL, &multi_profilingEvent[0]), "failed in clEnqueueWriteBuffer buffer_keys");
	BENCH_CLERROR(clEnqueueWriteBuffer(queue[ocl_gpu_id], buffer_idx, CL_TRUE, 0, 4 * global_work_size, saved_idx, 0, NULL, &multi_profilingEvent[0]), "failed in clEnqueueWriteBuffer buffer_idx");

	BENCH_CLERROR(clEnqueueNDRangeKernel(queue[ocl_gpu_id], crypt_kernel, 1, NULL, &global_work_size, &local_work_size, 0, NULL, &multi_profilingEvent[1]), "failed in clEnqueueNDRangeKernel");

	// read back partial hashes
	BENCH_CLERROR(clEnqueueReadBuffer(queue[ocl_gpu_id], buffer_out, CL_TRUE, 0, sizeof(cl_uint) * global_work_size, partial_hashes, 0, NULL, &multi_profilingEvent[2]), "failed in reading data back");
	have_full_hashes = 0;

	return count;
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	int count = *pcount;

	global_work_size = (count + local_work_size - 1) / local_work_size * local_work_size;

	// copy keys to the device
	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[ocl_gpu_id], buffer_keys, CL_TRUE, 0, 4 * key_idx, saved_plain, 0, NULL, NULL), "failed in clEnqueueWriteBuffer buffer_keys");
	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[ocl_gpu_id], buffer_idx, CL_TRUE, 0, 4 * global_work_size, saved_idx, 0, NULL, NULL), "failed in clEnqueueWriteBuffer buffer_idx");

	HANDLE_CLERROR(clEnqueueNDRangeKernel(queue[ocl_gpu_id], crypt_kernel, 1, NULL, &global_work_size, &local_work_size, 0, NULL, NULL), "failed in clEnqueueNDRangeKernel");

	// read back partial hashes
	HANDLE_CLERROR(clEnqueueReadBuffer(queue[ocl_gpu_id], buffer_out, CL_TRUE, 0, sizeof(cl_uint) * global_work_size, partial_hashes, 0, NULL, NULL), "failed in reading data back");
	have_full_hashes = 0;

	return count;
}

static int cmp_all(void *binary, int count)
{
	unsigned int i;
	unsigned int b = ((unsigned int *) binary)[0];

	for (i = 0; i < count; i++)
		if (b == partial_hashes[i])
			return 1;
	return 0;
}

static int cmp_one(void *binary, int index)
{
	return (((unsigned int*)binary)[0] == partial_hashes[index]);
}

static int cmp_exact(char *source, int index)
{
	unsigned int *t = (unsigned int *) get_binary(source);

	if (!have_full_hashes) {
		clEnqueueReadBuffer(queue[ocl_gpu_id], buffer_out, CL_TRUE,
		        sizeof(cl_uint) * (global_work_size),
		        sizeof(cl_uint) * 3 * global_work_size,
		        res_hashes, 0, NULL, NULL);
		have_full_hashes = 1;
	}

	if (t[1]!=res_hashes[index])
		return 0;
	if (t[2]!=res_hashes[1*global_work_size+index])
		return 0;
	if (t[3]!=res_hashes[2*global_work_size+index])
		return 0;
	return 1;
}

struct fmt_main fmt_opencl_rawMD4 = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
		DEFAULT_ALIGN,
		SALT_SIZE,
		DEFAULT_ALIGN,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT,
		tests
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
		split,
		get_binary,
		fmt_default_salt,
		fmt_default_source,
		{
			binary_hash_0,
			binary_hash_1,
			binary_hash_2,
			binary_hash_3,
			binary_hash_4,
			binary_hash_5,
			binary_hash_6
		},
		fmt_default_salt_hash,
		fmt_default_set_salt,
		set_key,
		get_key,
		clear_keys,
		crypt_all,
		{
			get_hash_0,
			get_hash_1,
			get_hash_2,
			get_hash_3,
			get_hash_4,
			get_hash_5,
			get_hash_6
		},
		cmp_all,
		cmp_one,
		cmp_exact
	}
};
