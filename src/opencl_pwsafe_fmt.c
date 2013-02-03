/* Password Safe cracker patch for JtR. Hacked together during May of
 * 2012 by Dhiru Kholia <dhiru.kholia at gmail.com>.
 *
 * OpenCL port by Lukas Odzioba <ukasz at openwall.net>
 *
 * This software is Copyright (c) 2012, Dhiru Kholia <dhiru.kholia at gmail.com>,
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted. */

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

#define uint8_t                         unsigned char
#define uint32_t                        unsigned int
#define MIN(a,b) (((a)<(b))?(a):(b))

#define FORMAT_LABEL            "pwsafe-opencl"
#define FORMAT_NAME             "Password Safe SHA-256"
#define ALGORITHM_NAME          "OpenCL"
#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        0
#define PLAINTEXT_LENGTH        15
#define BINARY_SIZE             0
#define KERNEL_NAME             "pwsafe"
#define MIN_KEYS_PER_CRYPT      (512*112)
#define MAX_KEYS_PER_CRYPT      MIN_KEYS_PER_CRYPT

#define CONFIG_NAME		"pwsafe"
#define STEP                    1024
#define ROUNDS_DEFAULT          2048

static const char * warn[] = {
        "pass xfer: "  ,  ", salt xfer: "  ,  ", crypt: "    ,  ", result xfer: "
};

extern void common_find_best_lws(size_t group_size_limit,
	unsigned int sequential_id, cl_kernel crypt_kernel);
extern void common_find_best_gws(int sequential_id, unsigned int rounds, int step,
	unsigned long long int max_run_time);

# define SWAP32(n) \
    (((n) << 24) | (((n) & 0xff00) << 8) | (((n) >> 8) & 0xff00) | ((n) >> 24))

static int new_keys;
static int crypt_all(int *pcount, struct db_salt *_salt);
static int crypt_all_benchmark(int *pcount, struct db_salt *_salt);

static struct fmt_tests pwsafe_tests[] = {
	{"$pwsafe$*3*fefc1172093344c9d5577b25f5b4b6e5d2942c94f9fc24c21733e28ae6527521*2048*88cbaf7d8668c1a98263f5dce7cb39c3304c49a3e0d76a7ea475dc02ab2f97a7", "12345678"},
	{"$pwsafe$*3*581cd1135b9b993ccb0f6b01c1fcfacd799c69960496c96286f94fe1400c1b25*2048*4ab3c2d3af251e94eb2f753fdf30fb9da074bec6bac0fa9d9d152b95fc5795c6", "openwall"},
	{NULL}
};

typedef struct {
	uint8_t v[15];
	uint8_t length;
} pwsafe_pass;

typedef struct {
	uint32_t cracked;	///cracked or not
} pwsafe_hash;

typedef struct {
	int version;
	uint32_t iterations;
	uint8_t hash[32];
//        uint8_t length;
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

	HANDLE_CLERROR(clReleaseKernel(crypt_kernel), "Release kernel");
	HANDLE_CLERROR(clReleaseProgram(program[ocl_gpu_id]), "Release Program");
}

static void pwsafe_set_key(char *key, int index)
{
	int saved_key_length = MIN(strlen(key), PLAINTEXT_LENGTH);
	memcpy(host_pass[index].v, key, saved_key_length);
	host_pass[index].length = saved_key_length;
	new_keys = 1;
}

/* ------- Create and destroy necessary objects ------- */
static void create_clobj(int gws, struct fmt_main * self)
{
	int in_size = (sizeof(pwsafe_pass) * gws);
	int out_size = (sizeof(pwsafe_hash) * gws);

	self->params.min_keys_per_crypt = self->params.max_keys_per_crypt = gws;

	host_pass = mem_calloc(gws * sizeof(pwsafe_pass));
	host_hash = mem_calloc(gws * sizeof(pwsafe_hash));
	host_salt = mem_calloc(sizeof(pwsafe_salt));

	///Allocate memory on the GPU

	mem_salt =
	    clCreateBuffer(context[ocl_gpu_id], CL_MEM_READ_ONLY, saltsize, NULL,
	    &ret_code);
	HANDLE_CLERROR(ret_code, "Error while allocating memory for salt");
	mem_in =
	    clCreateBuffer(context[ocl_gpu_id], CL_MEM_READ_ONLY, in_size, NULL,
	    &ret_code);
	HANDLE_CLERROR(ret_code, "Error while allocating memory for passwords");
	mem_out =
	    clCreateBuffer(context[ocl_gpu_id], CL_MEM_WRITE_ONLY, out_size, NULL,
	    &ret_code);
	HANDLE_CLERROR(ret_code, "Error while allocating memory for hashes");
	///Assign kernel parameters
	clSetKernelArg(crypt_kernel, 0, sizeof(mem_in), &mem_in);
	clSetKernelArg(crypt_kernel, 1, sizeof(mem_out), &mem_out);
	clSetKernelArg(crypt_kernel, 2, sizeof(mem_salt), &mem_salt);
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
		sequential_id, ROUNDS_DEFAULT, 0,
		(cpu(device_info[ocl_gpu_id]) ? 500000000ULL : 2400000000ULL)
	);

	create_clobj(global_work_size, self);
}

static void init(struct fmt_main *self)
{
	cl_ulong maxsize;
	size_t selected_gws;

	opencl_init_opt("$JOHN/kernels/pwsafe_kernel.cl", ocl_gpu_id, NULL);

	crypt_kernel = clCreateKernel(program[ocl_gpu_id], KERNEL_NAME, &ret_code);
	HANDLE_CLERROR(ret_code, "Error while creating kernel");

	local_work_size = cpu(device_info[ocl_gpu_id]) ? 1 : 64;
	global_work_size = 0;
	opencl_get_user_preferences(CONFIG_NAME);

	//Initialize openCL tuning (library) for this format.
	opencl_init_auto_setup(STEP, 0, 4, NULL,
		warn, &multi_profilingEvent[2], self, create_clobj, release_clobj,
		sizeof(pwsafe_pass));

	self->methods.crypt_all = crypt_all_benchmark;

	selected_gws = global_work_size;
	/* Note: we ask for the kernels' max sizes, not the device's! */
	maxsize = get_current_work_group_size(ocl_gpu_id, crypt_kernel);

	while (local_work_size > maxsize)
		local_work_size >>= 1;

	self->params.max_keys_per_crypt = (global_work_size ? global_work_size: MAX_KEYS_PER_CRYPT);

	if (!local_work_size) {
		create_clobj(self->params.max_keys_per_crypt, self);
		find_best_lws(self, ocl_gpu_id);
		release_clobj();
	}
	global_work_size = selected_gws;

	if (global_work_size)
		create_clobj(global_work_size, self);
	else
		//user chose to die of boredom
		find_best_gws(self, ocl_gpu_id);

	self->params.min_keys_per_crypt = local_work_size;
	self->params.max_keys_per_crypt = global_work_size;
	self->methods.crypt_all = crypt_all;

	fprintf(stderr, "Local worksize (LWS) %d, Global worksize (GWS) %d\n", (int)local_work_size, (int)global_work_size);
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	// format $pwsafe$version*salt*iterations*hash
	char *p;
	char *ctcopy = strdup(ciphertext);
	char *keeptr = ctcopy;
	if (strncmp(ciphertext, "$pwsafe$", 8) != 0)
		return 0;
	ctcopy += 9;		/* skip over "$pwsafe$*" */
	if ((p = strtok(ctcopy, "*")) == NULL)	/* version */
		return 0;
	if (atoi(p) == 0)
		return 0;
	if ((p = strtok(NULL, "*")) == NULL)	/* salt */
		return 0;
	if (strlen(p) < 64)
		return 0;
	if ((p = strtok(NULL, "*")) == NULL)	/* iterations */
		return 0;
	if (atoi(p) == 0)
		return 0;
	if ((p = strtok(NULL, "*")) == NULL)	/* hash */
		return 0;
	if (strlen(p) != 64)
		return 0;
	MEM_FREE(keeptr);
	return 1;
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
}

static int crypt_all_benchmark(int *pcount, struct db_salt *salt)
{
	int count = *pcount;

	global_work_size = (count + local_work_size - 1) / local_work_size * local_work_size;

	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[ocl_gpu_id], mem_in, CL_FALSE,
		0, insize, host_pass, 0, NULL, &multi_profilingEvent[0]), "Copy memin");
	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[ocl_gpu_id], mem_salt, CL_FALSE,
		0, saltsize, host_salt, 0, NULL, &multi_profilingEvent[1]), "Copy memsalt");

	///Run kernel
	HANDLE_CLERROR(clEnqueueNDRangeKernel(queue[ocl_gpu_id], crypt_kernel, 1,
		NULL, &global_work_size, &local_work_size,
		0, NULL, &multi_profilingEvent[2]), "Set ND range");
	HANDLE_CLERROR(clEnqueueReadBuffer(queue[ocl_gpu_id], mem_out, CL_FALSE, 0,
		outsize, host_hash, 0, NULL, &multi_profilingEvent[3]),
	    "Copy data back");

	///Await completion of all the above
	HANDLE_CLERROR(clFinish(queue[ocl_gpu_id]), "clFinish error");

	return count;
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	int count = *pcount;

	global_work_size = (count + local_work_size - 1) / local_work_size * local_work_size;

	///Copy data to GPU memory
	if (new_keys)
		HANDLE_CLERROR(clEnqueueWriteBuffer
			(queue[ocl_gpu_id], mem_in, CL_FALSE, 0, insize, host_pass, 0, NULL,
			NULL), "Copy memin");

	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[ocl_gpu_id], mem_salt, CL_FALSE,
		0, saltsize, host_salt, 0, NULL, NULL), "Copy memsalt");

	///Run kernel
	HANDLE_CLERROR(clEnqueueNDRangeKernel
	    (queue[ocl_gpu_id], crypt_kernel, 1, NULL, &global_work_size, &local_work_size,
		0, NULL, profilingEvent), "Set ND range");
	HANDLE_CLERROR(clEnqueueReadBuffer(queue[ocl_gpu_id], mem_out, CL_FALSE, 0,
		outsize, host_hash, 0, NULL, NULL),
	    "Copy data back");

	///Await completion of all the above
	HANDLE_CLERROR(clFinish(queue[ocl_gpu_id]), "clFinish error");
	new_keys = 0;

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