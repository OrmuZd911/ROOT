/*
 * This software is Copyright (c) 2015 magnum
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#ifdef HAVE_OPENCL

#if FMT_EXTERNS_H
extern struct fmt_main fmt_ocl_pbkdf2_md4;
#elif FMT_REGISTERS_H
john_register_one(&fmt_ocl_pbkdf2_md4);
#else

#include <ctype.h>
#include <string.h>

#include "common-opencl.h"
#include "arch.h"
#include "misc.h"
#include "common.h"
#include "stdint.h"
#include "formats.h"
#include "base64_convert.h"
#include "stdint.h"
#include "options.h"
#define OUTLEN 16
#include "opencl_pbkdf2_hmac_md4.h"
#define OPENCL_FORMAT
#define PBKDF2_HMAC_MD4_ALSO_INCLUDE_CTX 1
#include "pbkdf2_hmac_md4.h"

//#define DEBUG
#define dump_stuff_msg(a, b, c)	dump_stuff_msg((void*)a, b, c)

#define FORMAT_LABEL		"PBKDF2-HMAC-MD4-opencl"
#define FORMAT_NAME		""
#define ALGORITHM_NAME		"PBKDF2-MD4 OpenCL"
#define BENCHMARK_COMMENT	""
#define BENCHMARK_LENGTH	-1
#define MIN_KEYS_PER_CRYPT	1
#define MAX_KEYS_PER_CRYPT	1

#define BINARY_SIZE		16
#define BINARY_ALIGN		sizeof(uint32_t)
#define MAX_BINARY_SIZE         (4 * BINARY_SIZE)
#define PLAINTEXT_LENGTH	64
#define SALT_SIZE		sizeof(pbkdf2_salt)
#define SALT_ALIGN		sizeof(int)
#define MAX_SALT_SIZE           52
#define MAX_CIPHERTEXT_LENGTH   (TAG_LEN + 6 + 1 + 2*MAX_SALT_SIZE + 1 + 2*MAX_BINARY_SIZE)

#define FORMAT_TAG              "$pbkdf2-hmac-md4$"
#define TAG_LEN                 (sizeof(FORMAT_TAG) - 1)

/* This handles all widths */
#define GETPOS(i, index)	(((index) % v_width) * 4 + ((i) & ~3U) * v_width + ((i) & 3) + ((index) / v_width) * PLAINTEXT_LENGTH * v_width)

/*
 * HASH_LOOPS is ideally made by factors of (iteration count - 1) and should
 * be chosen for a kernel duration of not more than 200 ms
 */
#define HASH_LOOPS		333

#define LOOP_COUNT		(((cur_salt->iterations - 1 + HASH_LOOPS - 1)) / HASH_LOOPS)
#define STEP			0
#define SEED			256

static const char * warn[] = {
	"P xfer: "  ,  ", init: "   , ", loop: " , ", final: ", ", res xfer: "
};

static int split_events[] = { 2, -1, -1 };

static cl_kernel pbkdf2_init, pbkdf2_loop, pbkdf2_final;
static int crypt_all(int *pcount, struct db_salt *_salt);
static int crypt_all_benchmark(int *pcount, struct db_salt *_salt);

//This file contains auto-tuning routine(s). Has to be included after formats definitions.
#include "opencl-autotune.h"
#include "memdbg.h"

/* ------- Helper functions ------- */
static size_t get_task_max_work_group_size()
{
	size_t s;

	s = autotune_get_task_max_work_group_size(FALSE, 0, pbkdf2_init);
	s = MIN(s, autotune_get_task_max_work_group_size(FALSE, 0, pbkdf2_loop));
	s = MIN(s, autotune_get_task_max_work_group_size(FALSE, 0, pbkdf2_final));
	return s;
}

static struct fmt_tests tests[] = {
	{"$pbkdf2-hmac-md4$1000$6d61676e756d$32ebfcea201e61cc498948916a213459", "magnum"},
	{"$pbkdf2-hmac-md4$1000$6d61676e756d$32ebfcea201e61cc498948916a213459c259c7b0a8ce9473368665f0808dcde1", "magnum"},
	{"$pbkdf2-hmac-md4$1$73616c74$1857f69412150bca4542581d0f9e7fd1", "password"},
	{NULL}
};

static size_t key_buf_size;
static unsigned int *inbuffer;
static pbkdf2_out *output;
static pbkdf2_salt *cur_salt;
static cl_mem mem_in, mem_out, mem_salt, mem_state;
static unsigned int v_width = 1;	/* Vector width of kernel */
static int new_keys;
static struct fmt_main *self;

static void create_clobj(size_t gws, struct fmt_main *self)
{
	gws *= v_width;
	key_buf_size = PLAINTEXT_LENGTH * gws;

	/// Allocate memory
	inbuffer = mem_calloc(1, key_buf_size);
	output = mem_alloc(sizeof(pbkdf2_out) * gws);

	mem_in = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, key_buf_size, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error allocating mem in");
	mem_salt = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, sizeof(pbkdf2_salt), NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error allocating mem salt");
	mem_out = clCreateBuffer(context[gpu_id], CL_MEM_WRITE_ONLY, sizeof(pbkdf2_out) * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error allocating mem out");
	mem_state = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE, sizeof(pbkdf2_state) * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error allocating mem_state");

	HANDLE_CLERROR(clSetKernelArg(pbkdf2_init, 0, sizeof(mem_in), &mem_in), "Error while setting mem_in kernel argument");
	HANDLE_CLERROR(clSetKernelArg(pbkdf2_init, 1, sizeof(mem_salt), &mem_salt), "Error while setting mem_salt kernel argument");
	HANDLE_CLERROR(clSetKernelArg(pbkdf2_init, 2, sizeof(mem_state), &mem_state), "Error while setting mem_state kernel argument");

	HANDLE_CLERROR(clSetKernelArg(pbkdf2_loop, 0, sizeof(mem_state), &mem_state), "Error while setting mem_state kernel argument");

	HANDLE_CLERROR(clSetKernelArg(pbkdf2_final, 0, sizeof(mem_salt), &mem_salt), "Error while setting mem_salt kernel argument");
	HANDLE_CLERROR(clSetKernelArg(pbkdf2_final, 1, sizeof(mem_out), &mem_out), "Error while setting mem_out kernel argument");
	HANDLE_CLERROR(clSetKernelArg(pbkdf2_final, 2, sizeof(mem_state), &mem_state), "Error while setting mem_state kernel argument");
}

static void release_clobj(void)
{
	if (inbuffer) {
		HANDLE_CLERROR(clReleaseMemObject(mem_state), "Release mem state");
		HANDLE_CLERROR(clReleaseMemObject(mem_out), "Release mem out");
		HANDLE_CLERROR(clReleaseMemObject(mem_salt), "Release mem setting");
		HANDLE_CLERROR(clReleaseMemObject(mem_in), "Release mem in");

		MEM_FREE(output);
		MEM_FREE(inbuffer);
	}
}

static void done(void)
{
	if (autotuned) {
		release_clobj();

		HANDLE_CLERROR(clReleaseKernel(pbkdf2_init), "Release kernel");
		HANDLE_CLERROR(clReleaseKernel(pbkdf2_loop), "Release kernel");
		HANDLE_CLERROR(clReleaseKernel(pbkdf2_final), "Release kernel");
		HANDLE_CLERROR(clReleaseProgram(program[gpu_id]), "Release Program");

		autotuned--;
	}
}

static void init(struct fmt_main *_self)
{
	static char valgo[sizeof(ALGORITHM_NAME) + 8] = "";

	self = _self;

	opencl_prepare_dev(gpu_id);
	/* Nvidia Kepler benefits from 2x interleaved code */
	if (!options.v_width && nvidia_sm_3x(device_info[gpu_id]))
		v_width = 2;
	else
	/* VLIW5 does better with just 2x vectors due to GPR pressure */
	if (!options.v_width && amd_vliw5(device_info[gpu_id]))
		v_width = 2;
	else
		v_width = opencl_get_vector_width(gpu_id, sizeof(cl_int));

	if (v_width > 1) {
		/* Run vectorized kernel */
		snprintf(valgo, sizeof(valgo),
		         ALGORITHM_NAME " %ux", v_width);
		self->params.algorithm_name = valgo;
	}
}

static void reset(struct db_main *db)
{
	if (!autotuned) {
		char build_opts[64];

		snprintf(build_opts, sizeof(build_opts),
		         "-DHASH_LOOPS=%u -DOUTLEN=%u "
		         "-DPLAINTEXT_LENGTH=%u -DV_WIDTH=%u",
		         HASH_LOOPS, OUTLEN, PLAINTEXT_LENGTH, v_width);
		opencl_init("$JOHN/kernels/pbkdf2_hmac_md4_kernel.cl", gpu_id, build_opts);

		pbkdf2_init = clCreateKernel(program[gpu_id], "pbkdf2_init", &ret_code);
		HANDLE_CLERROR(ret_code, "Error creating kernel");
		crypt_kernel = pbkdf2_loop = clCreateKernel(program[gpu_id], "pbkdf2_loop", &ret_code);
		HANDLE_CLERROR(ret_code, "Error creating kernel");
		pbkdf2_final = clCreateKernel(program[gpu_id], "pbkdf2_final", &ret_code);
		HANDLE_CLERROR(ret_code, "Error creating kernel");

		//Initialize openCL tuning (library) for this format.
		opencl_init_auto_setup(SEED, 2*HASH_LOOPS, split_events, warn,
		                       2, self, create_clobj, release_clobj,
		                       v_width * sizeof(pbkdf2_state), 0);

		//Auto tune execution from shared/included code.
		self->methods.crypt_all = crypt_all_benchmark;
		autotune_run(self, 2*999+4, 0,
		             (cpu(device_info[gpu_id]) ?
		              1000000000 : 5000000000ULL));
		self->methods.crypt_all = crypt_all;
	}
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *ptr, *ctcopy, *keeptr;
	size_t len;
	char *delim;

	if (strncmp(ciphertext, FORMAT_TAG, TAG_LEN))
		return 0;

	if (strlen(ciphertext) > MAX_CIPHERTEXT_LENGTH)
		return 0;

	ciphertext += TAG_LEN;

	delim = strchr(ciphertext, '.') ? "." : "$";

	if (!(ctcopy = strdup(ciphertext)))
		return 0;
	keeptr = ctcopy;
	if (!(ptr = strtokm(ctcopy, delim)))
		goto error;
	if (!atoi(ptr))
		goto error;
	if (!(ptr = strtokm(NULL, delim)))
		goto error;
	len = strlen(ptr); // salt hex length
	if (len > 2 * MAX_SALT_SIZE || len & 1)
		goto error;
	if (!ishex(ptr))
		goto error;
	if (!(ptr = strtokm(NULL, delim)))
		goto error;
	len = strlen(ptr); // binary hex length
	if (len < BINARY_SIZE || len > MAX_BINARY_SIZE || len & 1)
		goto error;
	if (!ishex(ptr))
		goto error;
	MEM_FREE(keeptr);
	return 1;
error:
	MEM_FREE(keeptr);
	return 0;
}

static char *split(char *ciphertext, int index, struct fmt_main *self)
{
	static char out[MAX_CIPHERTEXT_LENGTH + 1];

	strnzcpy(out, ciphertext, sizeof(out));
	strlwr(out);
	return out;
}

static void *get_salt(char *ciphertext)
{
	static pbkdf2_salt cs;
	char *p;
	int saltlen;
	char delim;

	if (!strncmp(ciphertext, FORMAT_TAG, sizeof(FORMAT_TAG) - 1))
		ciphertext += sizeof(FORMAT_TAG) - 1;
	cs.iterations = atoi(ciphertext);
	delim = strchr(ciphertext, '.') ? '.' : '$';
	ciphertext = strchr(ciphertext, delim) + 1;
	p = strchr(ciphertext, delim);
	saltlen = 0;
	memset(cs.salt, 0, sizeof(cs.salt));
	while (ciphertext < p) {        /** extract salt **/
		cs.salt[saltlen++] =
			atoi16[ARCH_INDEX(ciphertext[0])] * 16 +
			atoi16[ARCH_INDEX(ciphertext[1])];
		ciphertext += 2;
	}
	cs.length = saltlen;
	cs.outlen = BINARY_SIZE;

	return (void*)&cs;
}

static void *get_binary(char *ciphertext)
{
	static union {
		unsigned char c[MAX_BINARY_SIZE];
		uint32_t dummy;
	} buf;
	unsigned char *out = buf.c;
	char *p;
	int i, len;
	char delim;

	delim = strchr(ciphertext, '.') ? '.' : '$';
	p = strrchr(ciphertext, delim) + 1;
	len = strlen(p) / 2;
	for (i = 0; i < len && *p; i++) {
		out[i] =
			(atoi16[ARCH_INDEX(*p)] << 4) |
			atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}
#if 0
	dump_stuff_msg(__FUNCTION__, out, BINARY_SIZE);
#endif
	return out;
}

static void set_salt(void *salt)
{
	cur_salt = (pbkdf2_salt*)salt;
	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], mem_salt, CL_FALSE, 0, sizeof(pbkdf2_salt), cur_salt, 0, NULL, NULL), "Copy salt to gpu");
#if 0
	fprintf(stderr, "\n%s(%.*s) len %u iter %u\n", __FUNCTION__, cur_salt->length, cur_salt->salt, cur_salt->length, cur_salt->iterations);
	dump_stuff_msg("salt", cur_salt->salt, cur_salt->length);
#endif
}

static void clear_keys(void)
{
	memset(inbuffer, 0, key_buf_size);
}

static void set_key(char *key, int index)
{
	int i;
	int length = strlen(key);

	for (i = 0; i < length; i++)
		((char*)inbuffer)[GETPOS(i, index)] = key[i];

	new_keys = 1;
	//fprintf(stderr, "%s(%s)\n", __FUNCTION__, key);
}

static char* get_key(int index)
{
	static char ret[PLAINTEXT_LENGTH + 1];
	int i = 0;

	while (i < PLAINTEXT_LENGTH &&
	       (ret[i] = ((char*)inbuffer)[GETPOS(i, index)]))
		i++;
	ret[i] = 0;

	//fprintf(stderr, "%s(%s)\n", __FUNCTION__, ret);
	return ret;
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int i;
	size_t scalar_gws;

	global_work_size = ((count + (v_width * local_work_size - 1)) / (v_width * local_work_size)) * local_work_size;
	scalar_gws = global_work_size * v_width;

	/// Copy data to gpu
	if (new_keys) {
		HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], mem_in, CL_FALSE, 0, key_buf_size, inbuffer, 0, NULL, NULL), "Copy data to gpu");
		new_keys = 0;
	}

	/// Run kernels
	HANDLE_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], pbkdf2_init, 1, NULL, &global_work_size, &local_work_size, 0, NULL, NULL), "Run initial kernel");

	for (i = 0; i < LOOP_COUNT; i++) {
		HANDLE_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], pbkdf2_loop, 1, NULL, &global_work_size, &local_work_size, 0, NULL, NULL), "Run loop kernel");
		HANDLE_CLERROR(clFinish(queue[gpu_id]), "Error running loop kernel");
		opencl_process_event();
	}

	HANDLE_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], pbkdf2_final, 1, NULL, &global_work_size, &local_work_size, 0, NULL, NULL), "Run intermediate kernel");

	/// Read the result back
	HANDLE_CLERROR(clEnqueueReadBuffer(queue[gpu_id], mem_out, CL_TRUE, 0, sizeof(pbkdf2_out) * scalar_gws, output, 0, NULL, NULL), "Copy result back");

	return count;
}

static int crypt_all_benchmark(int *pcount, struct db_salt *salt)
{
	size_t scalar_gws;
	size_t *lws = local_work_size ? &local_work_size : NULL;

	global_work_size = local_work_size ? ((*pcount + (v_width * local_work_size - 1)) / (v_width * local_work_size)) * local_work_size : *pcount / v_width;
	scalar_gws = global_work_size * v_width;

#if 0
	fprintf(stderr, "%s(%d) lws "Zu" gws "Zu" sgws "Zu" kpc %d/%d\n", __FUNCTION__, *pcount, local_work_size, global_work_size, scalar_gws, me->params.min_keys_per_crypt, me->params.max_keys_per_crypt);
#endif

	/// Copy data to gpu
	BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], mem_in, CL_FALSE, 0, key_buf_size, inbuffer, 0, NULL, multi_profilingEvent[0]), "Copy data to gpu");

	/// Run kernels
	BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], pbkdf2_init, 1, NULL, &global_work_size, lws, 0, NULL, multi_profilingEvent[1]), "Run initial kernel");

	BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], pbkdf2_loop, 1, NULL, &global_work_size, lws, 0, NULL, NULL), "Run loop kernel");
	BENCH_CLERROR(clFinish(queue[gpu_id]), "Error running loop kernel");
	BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], pbkdf2_loop, 1, NULL, &global_work_size, lws, 0, NULL, multi_profilingEvent[2]), "Run loop kernel");
	BENCH_CLERROR(clFinish(queue[gpu_id]), "Error running loop kernel");

	BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], pbkdf2_final, 1, NULL, &global_work_size, lws, 0, NULL, multi_profilingEvent[3]), "Run intermediate kernel");

	/// Read the result back
	BENCH_CLERROR(clEnqueueReadBuffer(queue[gpu_id], mem_out, CL_TRUE, 0, sizeof(pbkdf2_out) * scalar_gws, output, 0, NULL, multi_profilingEvent[4]), "Copy result back");

	return *pcount;
}

static int binary_hash_0(void *binary)
{
#if 0
	dump_stuff_msg(__FUNCTION__, binary, BINARY_SIZE);
#endif
	return (((uint32_t *) binary)[0] & 0xf);
}

static int get_hash_0(int index)
{
#if 0
	dump_stuff_msg(__FUNCTION__, output[index].dk, BINARY_SIZE);
#endif
	return *(uint32_t*)output[index].dk & 0xf;
}
static int get_hash_1(int index) { return *(uint32_t*)output[index].dk & 0xff; }
static int get_hash_2(int index) { return *(uint32_t*)output[index].dk & 0xfff; }
static int get_hash_3(int index) { return *(uint32_t*)output[index].dk & 0xffff; }
static int get_hash_4(int index) { return *(uint32_t*)output[index].dk & 0xfffff; }
static int get_hash_5(int index) { return *(uint32_t*)output[index].dk & 0xffffff; }
static int get_hash_6(int index) { return *(uint32_t*)output[index].dk & 0x7ffffff; }

static int cmp_all(void *binary, int count)
{
	int index;

	for (index = 0; index < count; index++)
		if (*(uint32_t*)binary == *(uint32_t*)output[index].dk)
			return 1;
#if 0
	dump_stuff_msg(__FUNCTION__, output[count - 1].dk, BINARY_SIZE);
#endif
	return 0;
}

static int cmp_one(void *binary, int index)
{
	return !memcmp(binary, output[index].dk, BINARY_SIZE);
}

/* Check the FULL binary, just for good measure. There is not a chance we'll
   have a false positive here but this function is not performance critical. */
static int cmp_exact(char *source, int index)
{
	int i = 0, len, result;
	char *p, *key = get_key(index);
	char delim;
	unsigned char *binary, *crypt;

	delim = strchr(source, '.') ? '.' : '$';
	p = strrchr(source, delim) + 1;
	len = strlen(p) / 2;

	if (len == BINARY_SIZE) return 1;

	binary = mem_alloc(len);
	crypt = mem_alloc(len);

	while (*p) {
		binary[i++] = (atoi16[ARCH_INDEX(*p)] << 4) |
			atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}
	pbkdf2_md4((const unsigned char*)key,
	            strlen(key),
	            cur_salt->salt, cur_salt->length,
	            cur_salt->iterations, crypt, len, 0);
	result = !memcmp(binary, crypt, len);
#if 0
	dump_stuff_msg("hash binary", binary, len);
	dump_stuff_msg("calc binary", crypt, len);
#endif
	MEM_FREE(binary);
	MEM_FREE(crypt);
	if (!result)
		fprintf(stderr, "\n%s: Warning: Partial match for '%s'.\n"
		        "This is a bug or a malformed input line of:\n%s\n",
		        FORMAT_LABEL, key, source);
	return result;
}

static int salt_hash(void *salt)
{
	unsigned char *s = (unsigned char*)salt;
	unsigned int hash = 5381;
	int len = SALT_SIZE;

	while (len--)
		hash = ((hash << 5) + hash) ^ *s++;

	return hash & (SALT_HASH_SIZE - 1);
}

static unsigned int iteration_count(void *salt)
{
	return ((pbkdf2_salt*)salt)->iterations;
}

struct fmt_main fmt_ocl_pbkdf2_md4 = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		0,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
		BINARY_ALIGN,
		SALT_SIZE,
		SALT_ALIGN,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT | FMT_SPLIT_UNIFIES_CASE,
		{
			"iterations",
		},
		tests
	}, {
		init,
		done,
		reset,
		fmt_default_prepare,
		valid,
		split,
		get_binary,
		get_salt,
		{
			iteration_count,
		},
		fmt_default_source,
		{
			binary_hash_0,
			fmt_default_binary_hash_1,
			fmt_default_binary_hash_2,
			fmt_default_binary_hash_3,
			fmt_default_binary_hash_4,
			fmt_default_binary_hash_5,
			fmt_default_binary_hash_6
		},
		salt_hash,
		NULL,
		set_salt,
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

#endif /* plugin stanza */

#endif /* HAVE_OPENCL */
