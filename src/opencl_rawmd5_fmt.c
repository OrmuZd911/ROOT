/*
 * MD5 OpenCL code is based on Alain Espinosa's OpenCL patches.
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

#define PLAINTEXT_LENGTH    32 /* Max. is 56 with current kernel */
#define FORMAT_LABEL        "raw-md5-opencl"
#define FORMAT_NAME         "Raw MD5"
#define ALGORITHM_NAME      "OpenCL (inefficient, development use only)"
#define BENCHMARK_COMMENT   ""
#define BENCHMARK_LENGTH    -1
#define CIPHERTEXT_LENGTH   32
#define DIGEST_SIZE         16
#define BINARY_SIZE         4
#define SALT_SIZE           0

#define FORMAT_TAG          "$dynamic_0$"
#define TAG_LENGTH          (sizeof(FORMAT_TAG) - 1)

cl_command_queue queue_prof;
cl_mem pinned_saved_keys, pinned_partial_hashes, buffer_out, buffer_keys;
static cl_uint *partial_hashes;
static cl_uint *res_hashes;
static char *saved_plain;
static int keybuf_size = PLAINTEXT_LENGTH;

#define MIN(a, b)		(((a) > (b)) ? (b) : (a))
#define MAX(a, b)		(((a) > (b)) ? (a) : (b))

#define MIN_KEYS_PER_CRYPT      2048
#define MAX_KEYS_PER_CRYPT      (1024 * 2048)

#define CONFIG_NAME		"rawmd5"
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
	{"098f6bcd4621d373cade4e832627b4f6", "test"},
	{"d41d8cd98f00b204e9800998ecf8427e", ""},
	{NULL}
};

static void create_clobj(int kpc, struct fmt_main * self)
{
	self->params.min_keys_per_crypt = self->params.max_keys_per_crypt = kpc;

	pinned_saved_keys = clCreateBuffer(context[ocl_gpu_id], CL_MEM_READ_ONLY | CL_MEM_ALLOC_HOST_PTR, keybuf_size * kpc, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating page-locked memory pinned_saved_keys");
	saved_plain = (char *) clEnqueueMapBuffer(queue[ocl_gpu_id], pinned_saved_keys, CL_TRUE, CL_MAP_READ | CL_MAP_WRITE, 0, keybuf_size * kpc, 0, NULL, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping page-locked memory saved_plain");

	res_hashes = malloc(sizeof(cl_uint) * 3 * kpc);

	pinned_partial_hashes = clCreateBuffer(context[ocl_gpu_id], CL_MEM_WRITE_ONLY | CL_MEM_ALLOC_HOST_PTR, 4 * kpc, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating page-locked memory pinned_partial_hashes");
	partial_hashes = (cl_uint *) clEnqueueMapBuffer(queue[ocl_gpu_id], pinned_partial_hashes, CL_TRUE, CL_MAP_READ, 0, 4 * kpc, 0, NULL, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping page-locked memory partial_hashes");

	// create and set arguments
	buffer_keys = clCreateBuffer(context[ocl_gpu_id], CL_MEM_READ_ONLY, keybuf_size * kpc, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating buffer argument buffer_keys");

	buffer_out = clCreateBuffer(context[ocl_gpu_id], CL_MEM_WRITE_ONLY, DIGEST_SIZE * kpc, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating buffer argument buffer_out");

	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 0, sizeof(buffer_keys), (void *) &buffer_keys), "Error setting argument 1");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 1, sizeof(buffer_out), (void *) &buffer_out), "Error setting argument 2");

	global_work_size = kpc;
}

static void release_clobj(void)
{
	HANDLE_CLERROR(clEnqueueUnmapMemObject(queue[ocl_gpu_id], pinned_partial_hashes, partial_hashes, 0,NULL,NULL), "Error Unmapping partial_hashes");
	HANDLE_CLERROR(clEnqueueUnmapMemObject(queue[ocl_gpu_id], pinned_saved_keys, saved_plain, 0, NULL, NULL), "Error Unmapping saved_plain");

	HANDLE_CLERROR(clReleaseMemObject(buffer_keys), "Error Releasing buffer_keys");
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

	//Call the default function.
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

	//Call the common function.
	common_find_best_gws(
		sequential_id, 1, 0,
		(cpu(device_info[ocl_gpu_id]) ? 500000000ULL : 1000000000ULL)
	);

	create_clobj(global_work_size, self);
}

static void init(struct fmt_main *self)
{
	char build_opts[64];
	size_t selected_gws;

	/* Reduced length can give a significant boost.
	   This kernel need a multiple of 4 (eg. 32, 16 or 12). */
	if (options.force_maxlength && options.force_maxlength < PLAINTEXT_LENGTH - 3) {
		keybuf_size = MAX((options.force_maxlength + 3) / 4 * 4, 8);
		self->params.benchmark_comment = mem_alloc_tiny(20, MEM_ALIGN_NONE);
		sprintf(self->params.benchmark_comment, " (max length %d)",
		        keybuf_size);
	}
	snprintf(build_opts, sizeof(build_opts),
	         "-DKEY_LENGTH=%d", keybuf_size);
	opencl_init_opt("$JOHN/kernels/md5_kernel.cl", ocl_gpu_id, build_opts);
	crypt_kernel = clCreateKernel(program[ocl_gpu_id], "md5", &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating kernel. Double-check kernel name?");

	local_work_size = global_work_size = 0;
	opencl_get_user_preferences(CONFIG_NAME);

	//Initialize openCL tuning (library) for this format.
	opencl_init_auto_setup(STEP, 0, 3, NULL,
		warn, &multi_profilingEvent[1], self, create_clobj, release_clobj,
		keybuf_size);

	self->methods.crypt_all = crypt_all_benchmark;
	self->params.max_keys_per_crypt = (global_work_size ? global_work_size: MAX_KEYS_PER_CRYPT);
	selected_gws = global_work_size;

	if (!local_work_size) {
		create_clobj(self->params.max_keys_per_crypt, self);
		find_best_lws(self, ocl_gpu_id);
		release_clobj();
	}
	global_work_size = selected_gws;

	if (local_work_size > get_current_work_group_size(ocl_gpu_id, crypt_kernel))
		local_work_size = get_current_work_group_size(ocl_gpu_id, crypt_kernel);

	if (global_work_size)
		create_clobj(global_work_size, self);

	else {
		//user chose to die of boredom
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
	memset(saved_plain, 0, keybuf_size * global_work_size);
}

static void set_key(char *key, int index)
{
	char *dst = (char*)&saved_plain[index * keybuf_size];

	while (*key)
		*dst++ = *key++;
}

static char *get_key(int index)
{
	int length = 0;
	static char out[PLAINTEXT_LENGTH + 1];
	char *key = &saved_plain[index * keybuf_size];

	while (length < keybuf_size && *key)
		out[length++] = *key++;
	out[length] = 0;
	return out;
}

static int crypt_all_benchmark(int *pcount, struct db_salt *salt)
{
	int count = *pcount;

	global_work_size = (count + local_work_size - 1) / local_work_size * local_work_size;

	// copy keys to the device
	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[ocl_gpu_id], buffer_keys, CL_TRUE, 0,
		keybuf_size * global_work_size, saved_plain, 0, NULL, &multi_profilingEvent[0]),
		"failed in clEnqueueWriteBuffer buffer_keys");

	HANDLE_CLERROR(clEnqueueNDRangeKernel(queue[ocl_gpu_id], crypt_kernel, 1, NULL,
		&global_work_size, &local_work_size, 0, NULL, &multi_profilingEvent[1]),
		"failed in clEnqueueNDRangeKernel");

	// read back partial hashes
	HANDLE_CLERROR(clEnqueueReadBuffer(queue[ocl_gpu_id], buffer_out, CL_TRUE, 0,
		sizeof(cl_uint) * global_work_size, partial_hashes, 0, NULL, &multi_profilingEvent[2]),
		"failed in reading data back");
	have_full_hashes = 0;

	return count;
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	int count = *pcount;

	global_work_size = (count + local_work_size - 1) / local_work_size * local_work_size;

	// copy keys to the device
	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[ocl_gpu_id], buffer_keys, CL_TRUE, 0, keybuf_size * global_work_size, saved_plain, 0, NULL, NULL), "failed in clEnqueueWriteBuffer buffer_keys");

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

struct fmt_main fmt_opencl_rawMD5 = {
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