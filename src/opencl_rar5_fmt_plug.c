/*
 * This software is Copyright (c) 2013 Lukas Odzioba <ukasz at openwall dot net>,
 * Copyright (c) 2013 Dhiru Kholia and
 * Copyright (c) 2014 magnum
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification, are permitted.
 *
 * http://www.rarlab.com/technote.htm
 *
 * $rar5$<salt_len>$<salt>$<iter_log2>$<iv>$<pswcheck_len>$<pswcheck>
 */
#ifdef HAVE_OPENCL

#if FMT_EXTERNS_H
extern struct fmt_main fmt_ocl_rar5;
#elif FMT_REGISTERS_H
john_register_one(&fmt_ocl_rar5);
#else

#include <ctype.h>
#include <string.h>
#include <assert.h>

//#define DEBUG

#include "misc.h"
#include "arch.h"
#include "base64.h"
#include "common.h"
#include "formats.h"
#include "options.h"
#include "common-opencl.h"
#include "rar5_common.h"
#include "memdbg.h"

#define SIZE_SALT50 16
#define SIZE_PSWCHECK 8
#define SIZE_PSWCHECK_CSUM 4
#define SIZE_INITV 16

#define FORMAT_LABEL		"RAR5-opencl"
#define FORMAT_NAME		""
#define FORMAT_TAG  		"$rar5$"
#define TAG_LENGTH  		6
#define ALGORITHM_NAME		"PBKDF2-SHA256 OpenCL"

#define BENCHMARK_COMMENT	""
#define BENCHMARK_LENGTH	-1
#define DEFAULT_LWS		64
#define DEFAULT_GWS		1024
#define STEP			0
#define SEED			1024

#define BINARY_ALIGN		4
#define SALT_ALIGN		1

#define uint8_t			unsigned char
#define uint32_t		unsigned int

#define PLAINTEXT_LENGTH	55
#define BINARY_SIZE		SIZE_PSWCHECK
#define SALT_SIZE		sizeof(struct custom_salt)

#define KERNEL_NAME		"pbkdf2_sha256_kernel"
#define SPLIT_KERNEL_NAME	"pbkdf2_sha256_loop"
#define OCL_CONFIG		"rar5"

#define MIN(a, b)		(((a) < (b)) ? (a) : (b))
#define MAX(a, b)		(((a) > (b)) ? (a) : (b))
#define HASH_LOOPS		(3*13*29) // factors 3, 13, 29, 29
#define ITERATIONS		(32800 - 1)

typedef struct {
	uint8_t length;
	uint8_t v[PLAINTEXT_LENGTH];
} pass_t;

typedef struct {
	uint32_t hash[8];
} crack_t;

typedef struct {
	uint8_t length;
	uint8_t salt[64];
	uint32_t rounds;
} salt_t;

typedef struct {
	uint32_t ipad[8];
	uint32_t opad[8];
	uint32_t hash[8];
	uint32_t W[8];
	uint32_t rounds;
} state_t;

static pass_t *host_pass;			      /** plain ciphertexts **/
static salt_t *host_salt;			      /** salt **/
static crack_t *host_crack;			      /** hash**/
static cl_int cl_error;
static cl_mem mem_in, mem_out, mem_salt, mem_state;
static cl_kernel split_kernel;

static const char * warn[] = {
        "P xfer: "  ,  ", S xfer: "   , ", init: " , ", crypt: ",
        ", res xfer: "
};

static int split_events[] = { 3, -1, -1 };

static int crypt_all(int *pcount, struct db_salt *_salt);
static int crypt_all_benchmark(int *pcount, struct db_salt *_salt);

//This file contains auto-tuning routine(s). Has to be included after formats definitions.
#include "opencl_autotune.h"

static void create_clobj(size_t kpc, struct fmt_main *self)
{
#define CL_RO CL_MEM_READ_ONLY
#define CL_WO CL_MEM_WRITE_ONLY
#define CL_RW CL_MEM_READ_WRITE

#define CLCREATEBUFFER(_flags, _size, _string)\
	clCreateBuffer(context[gpu_id], _flags, _size, NULL, &cl_error);\
	HANDLE_CLERROR(cl_error, _string);

#define CLKERNELARG(kernel, id, arg, msg)\
	HANDLE_CLERROR(clSetKernelArg(kernel, id, sizeof(arg), &arg), msg);

	host_pass = mem_calloc(kpc * sizeof(pass_t));
	host_crack = mem_calloc(kpc * sizeof(crack_t));
	host_salt = mem_calloc(sizeof(salt_t));

	mem_in =
		CLCREATEBUFFER(CL_RO, kpc * sizeof(pass_t),
		"Cannot allocate mem in");
	mem_salt =
		CLCREATEBUFFER(CL_RO, sizeof(salt_t), "Cannot allocate mem salt");
	mem_out =
		CLCREATEBUFFER(CL_WO, kpc * sizeof(crack_t),
		"Cannot allocate mem out");
	mem_state =
		CLCREATEBUFFER(CL_RW, kpc * sizeof(state_t),
		"Cannot allocate mem state");

	crypt_out = mem_alloc(sizeof(*crypt_out) * kpc);

	CLKERNELARG(crypt_kernel, 0, mem_in, "Error while setting mem_in");
	CLKERNELARG(crypt_kernel, 1, mem_salt, "Error while setting mem_salt");
	CLKERNELARG(crypt_kernel, 2, mem_state, "Error while setting mem_state");

	CLKERNELARG(split_kernel, 0, mem_state, "Error while setting mem_state");
	CLKERNELARG(split_kernel, 1 ,mem_out, "Error while setting mem_out");
}

/* ------- Helper functions ------- */
static size_t get_task_max_work_group_size()
{
	size_t s;

	s = common_get_task_max_work_group_size(FALSE, 0, crypt_kernel);
	s = MIN(s, common_get_task_max_work_group_size(FALSE, 0, split_kernel));
	return s;
}

static size_t get_task_max_size()
{
	return 0;
}

static size_t get_default_workgroup()
{
	if (cpu(device_info[gpu_id]))
		return 1;
	else
		return 128;
}

static void release_clobj(void)
{
	HANDLE_CLERROR(clReleaseMemObject(mem_in), "Release mem in");
	HANDLE_CLERROR(clReleaseMemObject(mem_salt), "Release mem salt");
	HANDLE_CLERROR(clReleaseMemObject(mem_out), "Release mem out");
	HANDLE_CLERROR(clReleaseMemObject(mem_state), "Release mem state");

	MEM_FREE(host_pass);
	MEM_FREE(host_salt);
	MEM_FREE(host_crack);
}

static void init(struct fmt_main *self)
{
	char build_opts[64];

        snprintf(build_opts, sizeof(build_opts), "-DHASH_LOOPS=%u", HASH_LOOPS);
        opencl_init("$JOHN/kernels/pbkdf2_hmac_sha256_kernel.cl",
            gpu_id, build_opts);

	crypt_kernel =
	    clCreateKernel(program[gpu_id], KERNEL_NAME, &cl_error);
	HANDLE_CLERROR(cl_error, "Error creating crypt kernel");

	split_kernel =
	    clCreateKernel(program[gpu_id], SPLIT_KERNEL_NAME, &cl_error);
	HANDLE_CLERROR(cl_error, "Error creating split kernel");

	//Initialize openCL tuning (library) for this format.
	opencl_init_auto_setup(SEED, HASH_LOOPS, split_events,
		warn, 3, self, create_clobj, release_clobj,
		sizeof(state_t), 0);

	//Auto tune execution from shared/included code.
	self->methods.crypt_all = crypt_all_benchmark;
	common_run_auto_tune(self, ITERATIONS, 0,
		(cpu(device_info[gpu_id]) ? 1000000000 : 10000000000ULL));
	self->methods.crypt_all = crypt_all;
}

static void done(void)
{
	MEM_FREE(crypt_out);
	release_clobj();
	HANDLE_CLERROR(clReleaseKernel(crypt_kernel), "Release kernel 1");
	HANDLE_CLERROR(clReleaseKernel(split_kernel), "Release kernel 2");
	HANDLE_CLERROR(clReleaseProgram(program[gpu_id]),
	    "Release Program");
}

static void set_salt(void *salt)
{
	cur_salt = (struct custom_salt *)salt;

	host_salt->rounds = cur_salt->iterations + 32; // We only need PswCheck
	host_salt->length = cur_salt->saltlen;
	memcpy(host_salt->salt, cur_salt->salt, cur_salt->saltlen);
#ifdef DEBUG
	fprintf(stderr, "Setting salt iter %d len %d ", host_salt->rounds, host_salt->length);
	dump_stuff(host_salt->salt, SIZE_SALT50);
#endif
}

static void opencl_limit_gws(int count)
{
	global_work_size =
	    (count + local_work_size - 1) / local_work_size * local_work_size;
}

static int crypt_all_benchmark(int *pcount, struct db_salt *salt)
{
	int i, count = *pcount;
	size_t gws;
	size_t *lws = local_work_size ? &local_work_size : NULL;

	gws = GET_MULTIPLE_OR_BIGGER(count, local_work_size);

#ifdef DEBUG
	printf("crypt_all(%d)\n", count);
	printf("LWS = %d, GWS = %d\n", (int)local_work_size, (int)gws);
#endif

	/// Copy data to gpu
	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], mem_in,
		CL_FALSE, 0, gws * sizeof(pass_t), host_pass, 0,
		NULL, multi_profilingEvent[0]), "Copy data to gpu");
	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], mem_salt,
		CL_FALSE, 0, sizeof(salt_t), host_salt, 0, NULL, multi_profilingEvent[1]),
	    "Copy salt to gpu");

	/// Run kernel
	HANDLE_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], crypt_kernel,
		1, NULL, &gws, lws, 0, NULL,
		multi_profilingEvent[2]), "Run kernel");
	HANDLE_CLERROR(clFinish(queue[gpu_id]), "clFinish");

	for(i = 0; i < 1; i++) {
		HANDLE_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], split_kernel,
			1, NULL, &gws, lws, 0, NULL,
			multi_profilingEvent[3]), "Run split kernel");
		HANDLE_CLERROR(clFinish(queue[gpu_id]), "clFinish");
		opencl_process_event();
	}
	/// Read the result back
	HANDLE_CLERROR(clEnqueueReadBuffer(queue[gpu_id], mem_out,
		CL_FALSE, 0, gws * sizeof(crack_t), host_crack, 0,
		NULL, multi_profilingEvent[4]), "Copy result back");

	/// Await completion of all the above
	HANDLE_CLERROR(clFinish(queue[gpu_id]), "clFinish");

	return count;
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	int i, count = *pcount;
	int loops = host_salt->rounds / HASH_LOOPS;

	loops += host_salt->rounds % HASH_LOOPS > 0;
	opencl_limit_gws(count);

#ifdef DEBUG
	printf("crypt_all(%d)\n", count);
	printf("LWS = %d, GWS = %d\n", (int)local_work_size, (int)global_work_size);
#endif

	/// Copy data to gpu
	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], mem_in,
		CL_FALSE, 0, global_work_size * sizeof(pass_t), host_pass, 0,
		NULL, NULL), "Copy data to gpu");
	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], mem_salt,
		CL_FALSE, 0, sizeof(salt_t), host_salt, 0, NULL, NULL),
	    "Copy salt to gpu");

	/// Run kernel
	HANDLE_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], crypt_kernel,
		1, NULL, &global_work_size, &local_work_size, 0, NULL,
		profilingEvent), "Run kernel");
	HANDLE_CLERROR(clFinish(queue[gpu_id]), "clFinish");


	for(i = 0; i < loops; i++) {
		HANDLE_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], split_kernel,
			1, NULL, &global_work_size, &local_work_size, 0, NULL,
			profilingEvent), "Run split kernel");
		HANDLE_CLERROR(clFinish(queue[gpu_id]), "clFinish");
		opencl_process_event();
	}
	/// Read the result back
	HANDLE_CLERROR(clEnqueueReadBuffer(queue[gpu_id], mem_out,
		CL_FALSE, 0, global_work_size * sizeof(crack_t), host_crack, 0,
		NULL, NULL), "Copy result back");

	/// Await completion of all the above
	HANDLE_CLERROR(clFinish(queue[gpu_id]), "clFinish");

	// special wtf processing [SIC]
	for (i = 0; i < count; i++) {
		crypt_out[i][0] = host_crack[i].hash[0];
		crypt_out[i][1] = host_crack[i].hash[1];
		crypt_out[i][0] ^= host_crack[i].hash[2];
		crypt_out[i][1] ^= host_crack[i].hash[3];
		crypt_out[i][0] ^= host_crack[i].hash[4];
		crypt_out[i][1] ^= host_crack[i].hash[5];
		crypt_out[i][0] ^= host_crack[i].hash[6];
		crypt_out[i][1] ^= host_crack[i].hash[7];
	}

	return count;
}

static void set_key(char *key, int index)
{
	int saved_key_length = MIN(strlen(key), PLAINTEXT_LENGTH);

	memcpy(host_pass[index].v, key, saved_key_length);
	host_pass[index].length = saved_key_length;
#ifdef DEBUG
	fprintf(stderr, "%s(%s)\n", __FUNCTION__, key);
#endif
}

static char *get_key(int index)
{
	static char ret[PLAINTEXT_LENGTH + 1];
	memcpy(ret, host_pass[index].v, PLAINTEXT_LENGTH);
	ret[MIN(host_pass[index].length, PLAINTEXT_LENGTH)] = 0;
	return ret;
}

#if FMT_MAIN_VERSION > 11
static unsigned int iteration_count(void *salt)
{
	salt_t *my_salt;

	my_salt = salt;
	return (unsigned int)my_salt->rounds;
}
#endif

struct fmt_main fmt_ocl_rar5 = {
{
	FORMAT_LABEL,
	FORMAT_NAME,
	ALGORITHM_NAME,
	BENCHMARK_COMMENT,
	BENCHMARK_LENGTH,
	PLAINTEXT_LENGTH,
	BINARY_SIZE,
	BINARY_ALIGN,
	SALT_SIZE,
	SALT_ALIGN,
	1,
	1,
	FMT_CASE | FMT_8_BIT,
#if FMT_MAIN_VERSION > 11
	{
		"iteration count",
	},
#endif
	tests
}, {
	init,
	done,
	fmt_default_reset,
	fmt_default_prepare,
	valid,
	fmt_default_split,
	get_binary,
	get_salt,
#if FMT_MAIN_VERSION > 11
	{
		iteration_count,
	},
#endif
	fmt_default_source,
	{
		fmt_default_binary_hash_0,
		fmt_default_binary_hash_1,
		fmt_default_binary_hash_2,
		fmt_default_binary_hash_3,
		fmt_default_binary_hash_4,
		fmt_default_binary_hash_5,
		fmt_default_binary_hash_6
	},
	fmt_default_salt_hash,
	set_salt,
	set_key,
	get_key,
	fmt_default_clear_keys,
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
}};

#endif /* plugin stanza */

#endif /* HAVE_OPENCL */
