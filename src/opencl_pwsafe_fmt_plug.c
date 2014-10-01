/* Password Safe cracker patch for JtR. Hacked together during May of
 * 2012 by Dhiru Kholia <dhiru.kholia at gmail.com>.
 *
 * OpenCL port by Lukas Odzioba <ukasz at openwall.net>
 * Split kernel implemented and plaintext extension by Brian Wallace <brian.wallace9809 at gmail.com>
 *
 * This software is Copyright (c) 2012-2013, Dhiru Kholia <dhiru.kholia at gmail.com> and Brian Wallace <brian.wallace9809 at gmail.com>,
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted. */

#ifdef HAVE_OPENCL

#if FMT_EXTERNS_H
extern struct fmt_main fmt_opencl_pwsafe;
#elif FMT_REGISTERS_H
john_register_one(&fmt_opencl_pwsafe);
#else

#include <string.h>
#include <assert.h>
#include <errno.h>

#include "arch.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "params.h"
#include "options.h"
#include "base64.h"
#include "common-opencl.h"
#include "memory.h"
#include "memdbg.h"

#define uint8_t                         unsigned char
#define uint32_t                        unsigned int
#define MIN(a,b) (((a)<(b))?(a):(b))

#define FORMAT_LABEL            "pwsafe-opencl"
#define FORMAT_NAME             "Password Safe"
#define ALGORITHM_NAME          "SHA256 OpenCL"
#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        0
#define PLAINTEXT_LENGTH        87
#define BINARY_SIZE             0
#define KERNEL_INIT_NAME	"pwsafe_init"
#define KERNEL_RUN_NAME   	"pwsafe_iter"
#define KERNEL_FINISH_NAME	"pwsafe_check"
#define MIN_KEYS_PER_CRYPT      (512*112)
#define MAX_KEYS_PER_CRYPT      MIN_KEYS_PER_CRYPT

#define OCL_CONFIG		"pwsafe"
#define STEP                    0
#define SEED                    256
#define ROUNDS_DEFAULT          2048

static const char * warn[] = {
	"pass xfer: "  ,  ", init: "    ,  ", crypt: ",
	" ("           ,  "/"              ,  "), final: "  ,  ", result xfer: "
};

#include "opencl_autotune.h"

cl_kernel init_kernel;
cl_kernel finish_kernel;

/* ------- Helper functions ------- */
static size_t get_task_max_work_group_size()
{
	return MIN(
		MIN(common_get_task_max_work_group_size(FALSE, 0, init_kernel),
		    common_get_task_max_work_group_size(FALSE, 0, crypt_kernel)),
		common_get_task_max_work_group_size(FALSE, 0, finish_kernel));
}

static size_t get_task_max_size()
{
	return 0;
}

static size_t get_default_workgroup()
{
	return 0;
}

# define SWAP32(n) \
    (((n) << 24) | (((n) & 0xff00) << 8) | (((n) >> 8) & 0xff00) | ((n) >> 24))

static int split_events[3] = { 2, 3, 4 };

static int crypt_all(int *pcount, struct db_salt *_salt);
static int crypt_all_benchmark(int *pcount, struct db_salt *_salt);

static struct fmt_tests pwsafe_tests[] = {
	{"$pwsafe$*3*fefc1172093344c9d5577b25f5b4b6e5d2942c94f9fc24c21733e28ae6527521*2048*88cbaf7d8668c1a98263f5dce7cb39c3304c49a3e0d76a7ea475dc02ab2f97a7", "12345678"},
	{"$pwsafe$*3*581cd1135b9b993ccb0f6b01c1fcfacd799c69960496c96286f94fe1400c1b25*2048*4ab3c2d3af251e94eb2f753fdf30fb9da074bec6bac0fa9d9d152b95fc5795c6", "openwall"},
	{"$pwsafe$*3*34ba0066d0fc594c126b60b9db98b6024e1cf585901b81b5b005ce386f173d4c*2048*cc86f1a5d930ff19b3602770a86586b5d9dea7bb657012aca875aa2a7dc71dc0", "12345678901234567890123"},
	{"$pwsafe$*3*a42431191707895fb8d1121a3a6e255e33892d8eecb50fc616adab6185b5affb*2048*0f71d12df2b7c5394ae90771f6475a7ad0437007a8eeb5d9b58e35d8fd57c827", "123456789012345678901234567"},
	{"$pwsafe$*3*c380dee0dbb536f5454f78603b020be76b33e294e9c2a0e047f43b9c61669fc8*2048*e88ed54a85e419d555be219d200563ae3ba864e24442826f412867fc0403917d", "this is an 87 character password to test the max bound of pwsafe-opencl................"},
	{NULL}
};

//Also acts as the hash state
typedef struct {
	uint8_t v[87];
	uint32_t length;
} pwsafe_pass;

typedef struct {
	uint32_t cracked;	///cracked or not
} pwsafe_hash;

typedef struct {
	int version;
	uint32_t iterations;
	uint8_t hash[32];
	uint8_t salt[32];
} pwsafe_salt;
#define SALT_SIZE               sizeof(pwsafe_salt)

static cl_mem mem_in, mem_out, mem_salt;

#define insize (sizeof(pwsafe_pass) * global_work_size)
#define outsize (sizeof(pwsafe_hash) * global_work_size)
#define saltsize (sizeof(pwsafe_salt))

static pwsafe_pass *host_pass;				/** binary ciphertexts **/
static pwsafe_salt *host_salt;				/** salt **/
static pwsafe_hash *host_hash;				/** calculated hashes **/

static void release_clobj(void)
{
	HANDLE_CLERROR(clReleaseMemObject(mem_in), "Release mem in");
	HANDLE_CLERROR(clReleaseMemObject(mem_salt), "Release mem salt");
	HANDLE_CLERROR(clReleaseMemObject(mem_out), "Release mem out");

	MEM_FREE(host_pass);
	MEM_FREE(host_hash);
	MEM_FREE(host_salt);
}

static void done(void)
{
	release_clobj();

	HANDLE_CLERROR(clReleaseKernel(init_kernel), "Release kernel");
	HANDLE_CLERROR(clReleaseKernel(crypt_kernel), "Release kernel");
	HANDLE_CLERROR(clReleaseKernel(finish_kernel), "Release kernel");
	HANDLE_CLERROR(clReleaseProgram(program[gpu_id]), "Release Program");
}

static void pwsafe_set_key(char *key, int index)
{
	int saved_key_length = MIN(strlen(key), PLAINTEXT_LENGTH);
	memcpy(host_pass[index].v, key, saved_key_length);
	host_pass[index].length = saved_key_length;
}

/* ------- Create and destroy necessary objects ------- */
static void create_clobj(size_t gws, struct fmt_main * self)
{
	size_t in_size = (sizeof(pwsafe_pass) * gws);
	size_t out_size = (sizeof(pwsafe_hash) * gws);

	self->params.min_keys_per_crypt = self->params.max_keys_per_crypt = gws;

	host_pass = mem_calloc(gws * sizeof(pwsafe_pass));
	host_hash = mem_calloc(gws * sizeof(pwsafe_hash));
	host_salt = mem_calloc(sizeof(pwsafe_salt));

	///Allocate memory on the GPU

	mem_salt =
	    clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, saltsize, NULL,
	    &ret_code);
	HANDLE_CLERROR(ret_code, "Error while allocating memory for salt");
	mem_in =
	    clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, in_size, NULL,
	    &ret_code);
	HANDLE_CLERROR(ret_code, "Error while allocating memory for passwords");
	mem_out =
	    clCreateBuffer(context[gpu_id], CL_MEM_WRITE_ONLY, out_size, NULL,
	    &ret_code);
	HANDLE_CLERROR(ret_code, "Error while allocating memory for hashes");
	///Assign kernel parameters
	clSetKernelArg(init_kernel, 0, sizeof(mem_in), &mem_in);
	clSetKernelArg(init_kernel, 1, sizeof(mem_salt), &mem_salt);
	clSetKernelArg(crypt_kernel, 0, sizeof(mem_in), &mem_in);
	clSetKernelArg(finish_kernel, 0, sizeof(mem_in), &mem_in);
	clSetKernelArg(finish_kernel, 1, sizeof(mem_out), &mem_out);
	clSetKernelArg(finish_kernel, 2, sizeof(mem_salt), &mem_salt);

	self->params.min_keys_per_crypt = local_work_size;
	self->params.max_keys_per_crypt = gws;
	global_work_size = gws;
}

static void init(struct fmt_main *self)
{
	opencl_init("$JOHN/kernels/pwsafe_kernel.cl", gpu_id, NULL);

	init_kernel = clCreateKernel(program[gpu_id], KERNEL_INIT_NAME, &ret_code);
	HANDLE_CLERROR(ret_code, "Error while creating init kernel");

	crypt_kernel = clCreateKernel(program[gpu_id], KERNEL_RUN_NAME, &ret_code);
	HANDLE_CLERROR(ret_code, "Error while creating crypt kernel");

	finish_kernel = clCreateKernel(program[gpu_id], KERNEL_FINISH_NAME, &ret_code);
	HANDLE_CLERROR(ret_code, "Error while creating finish kernel");

	//Initialize openCL tuning (library) for this format.
	self->methods.crypt_all = crypt_all_benchmark;
	opencl_init_auto_setup(SEED, ROUNDS_DEFAULT/8, split_events,
		warn, 3, self, create_clobj,
	        release_clobj, sizeof(pwsafe_pass), 0);

	//Auto tune execution from shared/included code.
	common_run_auto_tune(self, ROUNDS_DEFAULT, 0,
		(cpu(device_info[gpu_id]) ? 500000000ULL : 1000000000ULL));
	self->methods.crypt_all = crypt_all;
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	// format $pwsafe$version*salt*iterations*hash
	char *p;
	char *ctcopy;
	char *keeptr;
	if (strncmp(ciphertext, "$pwsafe$*", 9) != 0)
		return 0;
	ctcopy = strdup(ciphertext);
	keeptr = ctcopy;
	ctcopy += 9;		/* skip over "$pwsafe$*" */
	if ((p = strtok(ctcopy, "*")) == NULL)	/* version */
		goto err;
	if (atoi(p) == 0)
		goto err;
	if ((p = strtok(NULL, "*")) == NULL)	/* salt */
		goto err;
	if (strlen(p) < 64)
		goto err;
	if ((p = strtok(NULL, "*")) == NULL)	/* iterations */
		goto err;
	if (atoi(p) == 0)
		goto err;
	if ((p = strtok(NULL, "*")) == NULL)	/* hash */
		goto err;
	if (strlen(p) != 64)
		goto err;
	MEM_FREE(keeptr);
	return 1;
err:
	MEM_FREE(keeptr);
	return 0;
}

static void *get_salt(char *ciphertext)
{
	char *ctcopy = strdup(ciphertext);
	char *keeptr = ctcopy;
	char *p;
	int i;
	pwsafe_salt *salt_struct =
	    mem_alloc_tiny(sizeof(pwsafe_salt), MEM_ALIGN_WORD);
	ctcopy += 9;		/* skip over "$pwsafe$*" */
	p = strtok(ctcopy, "*");
	salt_struct->version = atoi(p);
	p = strtok(NULL, "*");
	for (i = 0; i < 32; i++)
		salt_struct->salt[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
		    + atoi16[ARCH_INDEX(p[i * 2 + 1])];
	p = strtok(NULL, "*");
	salt_struct->iterations = (unsigned int) atoi(p);
	p = strtok(NULL, "*");
	for (i = 0; i < 32; i++)
		salt_struct->hash[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
		    + atoi16[ARCH_INDEX(p[i * 2 + 1])];

	MEM_FREE(keeptr);
        alter_endianity(salt_struct->hash, 32);
	return (void *) salt_struct;
}


static void set_salt(void *salt)
{
	memcpy(host_salt, salt, SALT_SIZE);
	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], mem_salt,
	        CL_FALSE, 0, saltsize, host_salt, 0, NULL, NULL),
	        "Copy memsalt");
}

static int crypt_all_benchmark(int *pcount, struct db_salt *salt)
{
	int count = *pcount;
	int i;
	size_t *lws = local_work_size ? &local_work_size : NULL;

	BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], mem_in, CL_FALSE,
		0, insize, host_pass, 0, NULL, multi_profilingEvent[0]), "Copy memin");

	///Run the init kernel
	BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], init_kernel, 1,
		NULL, &global_work_size, lws,
		0, NULL, multi_profilingEvent[1]), "Set ND range");

	///Run split kernel
	for(i = 0; i < 3; i++)
	{
		BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], crypt_kernel, 1,
			NULL, &global_work_size, lws,
			0, NULL, multi_profilingEvent[split_events[i]]), "Set ND range");  // 2, 3, 4
		BENCH_CLERROR(clFinish(queue[gpu_id]), "Error running loop kernel");
		opencl_process_event();
	}

	///Run the finish kernel
	BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], finish_kernel, 1,
		NULL, &global_work_size, lws,
		0, NULL, multi_profilingEvent[5]), "Set ND range");

	BENCH_CLERROR(clEnqueueReadBuffer(queue[gpu_id], mem_out, CL_FALSE, 0,
		outsize, host_hash, 0, NULL, multi_profilingEvent[6]),
	    "Copy data back");

	///Await completion of all the above
	BENCH_CLERROR(clFinish(queue[gpu_id]), "clFinish error");

	return count;
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	int count = *pcount;
	int i = 0;

	global_work_size = (count + local_work_size - 1) / local_work_size * local_work_size;

	///Copy data to GPU memory
		HANDLE_CLERROR(clEnqueueWriteBuffer
			(queue[gpu_id], mem_in, CL_FALSE, 0, insize, host_pass, 0, NULL,
			NULL), "Copy memin");

	HANDLE_CLERROR(clEnqueueNDRangeKernel
	    (queue[gpu_id], init_kernel, 1, NULL, &global_work_size, &local_work_size,
		0, NULL, NULL), "Set ND range");

	///Run kernel
	for(i = 0; i < 8; i++)
	{
		HANDLE_CLERROR(clEnqueueNDRangeKernel
			(queue[gpu_id], crypt_kernel, 1, NULL, &global_work_size, &local_work_size,
			0, NULL, NULL), "Set ND range");
		HANDLE_CLERROR(clFinish(queue[gpu_id]), "Error running loop kernel");
		opencl_process_event();
	}

	HANDLE_CLERROR(clEnqueueNDRangeKernel
	    (queue[gpu_id], finish_kernel, 1, NULL, &global_work_size, &local_work_size,
		0, NULL, NULL), "Set ND range");

	HANDLE_CLERROR(clEnqueueReadBuffer(queue[gpu_id], mem_out, CL_FALSE, 0,
		outsize, host_hash, 0, NULL, NULL),
	    "Copy data back");

	///Await completion of all the above
	HANDLE_CLERROR(clFinish(queue[gpu_id]), "clFinish error");

	return count;
}

static int cmp_all(void *binary, int count)
{
	int i;

	for (i = 0; i < count; i++)
		if (host_hash[i].cracked == 1)
			return 1;
	return 0;
}

static int cmp_one(void *binary, int index)
{
	return host_hash[index].cracked;
}

static int cmp_exact(char *source, int index)
{
	return host_hash[index].cracked;
}


static char *get_key(int index)
{
	static char ret[PLAINTEXT_LENGTH + 1];
	memcpy(ret, host_pass[index].v, PLAINTEXT_LENGTH);
	ret[MIN(host_pass[index].length, PLAINTEXT_LENGTH)] = 0;
	return ret;
}

struct fmt_main fmt_opencl_pwsafe = {
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
#if FMT_MAIN_VERSION > 11
		{ NULL },
#endif
		pwsafe_tests
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		fmt_default_binary,
		get_salt,
#if FMT_MAIN_VERSION > 11
		{ NULL },
#endif
		fmt_default_source,
		{
			fmt_default_binary_hash
		},
		fmt_default_salt_hash,
		set_salt,
		pwsafe_set_key,
		get_key,
		fmt_default_clear_keys,
		crypt_all,
		{
			fmt_default_get_hash
		},
		cmp_all,
		cmp_one,
		cmp_exact
	}
};

#endif /* plugin stanza */

#endif /* HAVE_OPENCL */
