/*
 * This software is Copyright (c) 2014 magnum
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#ifdef HAVE_OPENCL

#if FMT_EXTERNS_H
extern struct fmt_main fmt_ocl_pbkdf2_sha1;
#elif FMT_REGISTERS_H
john_register_one(&fmt_ocl_pbkdf2_sha1);
#else

#include <ctype.h>
#include <string.h>

#include "common-opencl.h"
#include "arch.h"
#include "misc.h"
#include "common.h"
#include "stdint.h"
#include "formats.h"
#include "johnswap.h"
#include "base64_convert.h"
#include "stdint.h"
#include "options.h"
#define OUTLEN 20
#include "opencl_pbkdf2_hmac_sha1.h"
#define OPENCL_FORMAT
#define PBKDF2_HMAC_SHA1_ALSO_INCLUDE_CTX 1
#include "pbkdf2_hmac_sha1.h"

//#define DEBUG
#define dump_stuff_msg(a, b, c)	dump_stuff_msg((void*)a, b, c)

#define FORMAT_LABEL		"PBKDF2-HMAC-SHA1-opencl"
#define FORMAT_NAME		""
#define ALGORITHM_NAME		"PBKDF2-SHA1 OpenCL"
#define BENCHMARK_COMMENT	""
#define BENCHMARK_LENGTH	-1
#define MIN_KEYS_PER_CRYPT	1
#define MAX_KEYS_PER_CRYPT	1

#define BINARY_SIZE		20
#define BINARY_ALIGN		sizeof(uint32_t)
#define MAX_BINARY_SIZE         (4 * BINARY_SIZE)
#define PLAINTEXT_LENGTH	64
#define SALT_SIZE		sizeof(pbkdf2_salt)
#define SALT_ALIGN		sizeof(int)
#define MAX_SALT_SIZE           52
#define MAX_CIPHERTEXT_LENGTH   (TAG_LEN + 6 + 1 + 2*MAX_SALT_SIZE + 1 + 2*MAX_BINARY_SIZE)

#define FORMAT_TAG              "$pbkdf2-hmac-sha1$"
#define PKCS5S2_TAG             "{PKCS5S2}"
#define PK5K2_TAG               "$p5k2$"
#define TAG_LEN                 (sizeof(FORMAT_TAG) - 1)

/* This handles all widths */
#define GETPOS(i, index)	(((index) % ocl_v_width) * 4 + ((i) & ~3U) * ocl_v_width + (((i) & 3) ^ 3) + ((index) / ocl_v_width) * PLAINTEXT_LENGTH * ocl_v_width)

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
	{"$pbkdf2-hmac-sha1$1000.fd11cde0.27de197171e6d49fc5f55c9ef06c0d8751cd7250", "3956"},
	{"$pbkdf2-hmac-sha1$1000.6926d45e.231c561018a4cee662df7cd4a8206701c5806af9", "1234"},
	{"$pbkdf2-hmac-sha1$1000.98fcb0db.37082711ff503c2d2dea9a5cf7853437c274d32e", "5490"},
	// WPA-PSK DK (raw key as stored by some routers):
	// iterations is always 4096.
	// ESSID was "Harkonen" - converted to hex 4861726b6f6e656e.
	// Only first 20 bytes (40 hex chars) of key is required but if
	// you supply all 32 (64) of them, they will be double checked
	// without sacrificing speed.
	// Please also note that you should run such hashes with --min-len=8,
	// because WPAPSK passwords can't be shorter than that.
	{"$pbkdf2-hmac-sha1$4096$4861726b6f6e656e$ee51883793a6f68e9615fe73c80a3aa6f2dd0ea537bce627b929183cc6e57925", "12345678"},
	// these get converted in prepare()
	// http://pythonhosted.org/passlib/lib/passlib.hash.atlassian_pbkdf2_sha1.html
	{"{PKCS5S2}DQIXJU038u4P7FdsuFTY/+35bm41kfjZa57UrdxHp2Mu3qF2uy+ooD+jF5t1tb8J", "password"},
	// http://pythonhosted.org/passlib/lib/passlib.hash.cta_pbkdf2_sha1.html
	{"$p5k2$2710$oX9ZZOcNgYoAsYL-8bqxKg==$AU2JLf2rNxWoZxWxRCluY0u6h6c=", "password" },
	{NULL}
};

static size_t key_buf_size;
static unsigned int *inbuffer;
static pbkdf2_out *output;
static pbkdf2_salt *cur_salt;
static cl_mem mem_in, mem_out, mem_salt, mem_state;
static int new_keys;
static struct fmt_main *self;

static void create_clobj(size_t gws, struct fmt_main *self)
{
	gws *= ocl_v_width;
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
	/* VLIW5 does better with just 2x vectors due to GPR pressure */
	if (!options.v_width && amd_vliw5(device_info[gpu_id]))
		ocl_v_width = 2;
	else
		ocl_v_width = opencl_get_vector_width(gpu_id, sizeof(cl_int));

	if (ocl_v_width > 1) {
		/* Run vectorized kernel */
		snprintf(valgo, sizeof(valgo),
		         ALGORITHM_NAME " %ux", ocl_v_width);
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
		         HASH_LOOPS, OUTLEN, PLAINTEXT_LENGTH, ocl_v_width);
		opencl_init("$JOHN/kernels/pbkdf2_hmac_sha1_kernel.cl", gpu_id, build_opts);

		pbkdf2_init = clCreateKernel(program[gpu_id], "pbkdf2_init", &ret_code);
		HANDLE_CLERROR(ret_code, "Error creating kernel");
		crypt_kernel = pbkdf2_loop = clCreateKernel(program[gpu_id], "pbkdf2_loop", &ret_code);
		HANDLE_CLERROR(ret_code, "Error creating kernel");
		pbkdf2_final = clCreateKernel(program[gpu_id], "pbkdf2_final", &ret_code);
		HANDLE_CLERROR(ret_code, "Error creating kernel");

		//Initialize openCL tuning (library) for this format.
		opencl_init_auto_setup(SEED, 2*HASH_LOOPS, split_events, warn,
		                       2, self, create_clobj, release_clobj,
		                       ocl_v_width * sizeof(pbkdf2_state), 0);

		//Auto tune execution from shared/included code.
		autotune_run(self, 2*999+4, 0,
		             (cpu(device_info[gpu_id]) ?
		              1000000000 : 5000000000ULL));
	}
}

static char *prepare(char *fields[10], struct fmt_main *self)
{
	static char Buf[256];
	if (strncmp(fields[1], PKCS5S2_TAG, 9) != 0 && strncmp(fields[1], PK5K2_TAG, 6))
		return fields[1];
	if (!strncmp(fields[1], PKCS5S2_TAG, 9)) {
		char tmp[120+4];
		if (strlen(fields[1]) > 75) return fields[1];
		//{"{PKCS5S2}DQIXJU038u4P7FdsuFTY/+35bm41kfjZa57UrdxHp2Mu3qF2uy+ooD+jF5t1tb8J", "password"},
		//{"$pbkdf2-hmac-sha1$10000.0d0217254d37f2ee0fec576cb854d8ff.edf96e6e3591f8d96b9ed4addc47a7632edea176bb2fa8a03fa3179b75b5bf09", "password"},
		base64_convert(&(fields[1][9]), e_b64_mime, strlen(&(fields[1][9])), tmp, e_b64_hex, sizeof(tmp), 0);
		sprintf(Buf, "$pbkdf2-hmac-sha1$10000.%32.32s.%s", tmp, &tmp[32]);
		return Buf;
	}
	if (!strncmp(fields[1], PK5K2_TAG, 6)) {
		char tmps[160+4], tmph[160+4], *cp, *cp2;
		unsigned iter=0;
		// salt was listed as 1024 bytes max. But our max salt size is 64 bytes (~90 base64 bytes).
		if (strlen(fields[1]) > 128) return fields[1];
		//{"$p5k2$2710$oX9ZZOcNgYoAsYL-8bqxKg==$AU2JLf2rNxWoZxWxRCluY0u6h6c=", "password" },
		//{"$pbkdf2-hmac-sha1$10000.a17f5964e70d818a00b182fef1bab12a.014d892dfdab3715a86715b144296e634bba87a7", "password"},
		cp = fields[1];
		cp += 6;
		while (*cp && *cp != '$') {
			iter *= 0x10;
			if (atoi16[ARCH_INDEX(*cp)] == 0x7f) return fields[1];
			iter += atoi16[ARCH_INDEX(*cp)];
			++cp;
		}
		if (*cp != '$') return fields[1];
		++cp;
		cp2 = strchr(cp, '$');
		if (!cp2) return fields[1];
		base64_convert(cp, e_b64_mime, cp2-cp, tmps, e_b64_hex, sizeof(tmps), flg_Base64_MIME_DASH_UNDER);
		if (strlen(tmps) > 64) return fields[1];
		++cp2;
		base64_convert(cp2, e_b64_mime, strlen(cp2), tmph, e_b64_hex, sizeof(tmph), flg_Base64_MIME_DASH_UNDER);
		if (strlen(tmph) != 40) return fields[1];
		sprintf(Buf, "$pbkdf2-hmac-sha1$%d.%s.%s", iter, tmps, tmph);
		return Buf;
	}
	return fields[1];
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
#if !ARCH_LITTLE_ENDIAN
	for (i = 0; i < len/sizeof(uint32_t); ++i) {
		((uint32_t*)out)[i] = JOHNSWAP(((uint32_t*)out)[i]);
	}
#endif
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
}

static char* get_key(int index)
{
	static char ret[PLAINTEXT_LENGTH + 1];
	int i = 0;

	while (i < PLAINTEXT_LENGTH &&
	       (ret[i] = ((char*)inbuffer)[GETPOS(i, index)]))
		i++;
	ret[i] = 0;

	return ret;
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int i;
	size_t scalar_gws;
	size_t *lws = local_work_size ? &local_work_size : NULL;

	global_work_size = GET_MULTIPLE_OR_BIGGER_VW(count, local_work_size);
	scalar_gws = global_work_size * ocl_v_width;

	/// Copy data to gpu
	if (ocl_autotune_running || new_keys) {
		BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], mem_in, CL_FALSE, 0, key_buf_size, inbuffer, 0, NULL, multi_profilingEvent[0]), "Copy data to gpu");
		new_keys = 0;
	}

	/// Run kernels
	BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], pbkdf2_init, 1, NULL, &global_work_size, lws, 0, NULL, multi_profilingEvent[1]), "Run initial kernel");

	for (i = 0; i < (ocl_autotune_running ? 1 : LOOP_COUNT); i++) {
		BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], pbkdf2_loop, 1, NULL, &global_work_size, lws, 0, NULL, multi_profilingEvent[2]), "Run loop kernel");
		BENCH_CLERROR(clFinish(queue[gpu_id]), "Error running loop kernel");
		opencl_process_event();
	}

	BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], pbkdf2_final, 1, NULL, &global_work_size, lws, 0, NULL, multi_profilingEvent[3]), "Run intermediate kernel");

	/// Read the result back
	BENCH_CLERROR(clEnqueueReadBuffer(queue[gpu_id], mem_out, CL_TRUE, 0, sizeof(pbkdf2_out) * scalar_gws, output, 0, NULL, multi_profilingEvent[4]), "Copy result back");

	return count;
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
static int get_hash_6(int index) { return *(uint32_t*)output[index].dk & PH_MASK_6; }

static int cmp_all(void *binary, int count)
{
	int index;

	for (index = 0; index < count; index++)
		if (*(uint32_t*)binary == *(uint32_t*)output[index].dk)
			return 1;
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
#if !ARCH_LITTLE_ENDIAN
	for (i = 0; i < len/sizeof(uint32_t); ++i) {
		((uint32_t*)binary)[i] = JOHNSWAP(((uint32_t*)binary)[i]);
	}
#endif
	pbkdf2_sha1((const unsigned char*)key,
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

struct fmt_main fmt_ocl_pbkdf2_sha1 = {
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
		prepare,
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
