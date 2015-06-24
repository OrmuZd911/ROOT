/* NTLM patch for john (performance improvement and OpenCL 1.0 conformant)
 *
 * Written by Alain Espinosa <alainesp at gmail.com> in 2010 and modified
 * by Samuele Giovanni Tonon in 2011.  No copyright is claimed, and
 * the software is hereby placed in the public domain.
 * In case this attempt to disclaim copyright and place the software in the
 * public domain is deemed null and void, then the software is
 * Copyright (c) 2010 Alain Espinosa
 * Copyright (c) 2011 Samuele Giovanni Tonon
 * and it is hereby released to the general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 *
 * (This is a heavily cut-down "BSD license".)
 */

#ifdef HAVE_OPENCL

#if FMT_EXTERNS_H
extern struct fmt_main fmt_opencl_NT;
#elif FMT_REGISTERS_H
john_register_one(&fmt_opencl_NT);
#else

#include <string.h>

#include "arch.h"
#include "misc.h"
#include "options.h"
#include "memory.h"
#include "common.h"
#include "formats.h"
#include "path.h"
#include "common-opencl.h"

#define FORMAT_LABEL		"nt-opencl"
#define FORMAT_NAME		"NT"
#define ALGORITHM_NAME		"MD4 OpenCL (inefficient, development use only)"
#define BENCHMARK_COMMENT	""
#define BENCHMARK_LENGTH	-1
#define PLAINTEXT_LENGTH	23
#define CIPHERTEXT_LENGTH	32
#define BINARY_SIZE		16
#define BINARY_ALIGN		MEM_ALIGN_WORD
#define SALT_SIZE		0
#define SALT_ALIGN		1

#define MIN_KEYS_PER_CRYPT	1
#define MAX_KEYS_PER_CRYPT	1

static struct fmt_tests tests[] = {
	{"b7e4b9022cd45f275334bbdb83bb5be5", "John the Ripper"},
	{"$NT$8bd6e4fb88e01009818749c5443ea712", "\xFC"},         // German u-diaeresis in ISO-8859-1
	{"$NT$cc1260adb6985ca749f150c7e0b22063", "\xFC\xFC"},     // Two of the above
	{"$NT$7a21990fcd3d759941e45c490f143d5f", "12345"},
	{"$NT$f9e37e83b83c47a93c2f09f66408631b", "abc123"},
	{"$NT$8846f7eaee8fb117ad06bdd830b7586c", "password"},
	{"$NT$2b2ac2d1c7c8fda6cea80b5fad7563aa", "computer"},
	{"$NT$32ed87bdb5fdc5e9cba88547376818d4", "123456"},
	{"$NT$b7e0ea9fbffcf6dd83086e905089effd", "tigger"},
	{"$NT$7ce21f17c0aee7fb9ceba532d0546ad6", "1234"},
	{"$NT$b23a90d0aad9da3615fafc27a1b8baeb", "a1b2c3"},
	{"$NT$2d20d252a479f485cdf5e171d93985bf", "qwerty"},
	{"$NT$3dbde697d71690a769204beb12283678", "123"},
	{"$NT$c889c75b7c1aae1f7150c5681136e70e", "xxx"},
	{"$NT$d5173c778e0f56d9fc47e3b3c829aca7", "money"},
	{"$NT$0cb6948805f797bf2a82807973b89537", "test"},
	{"$NT$0569fcf2b14b9c7f3d3b5f080cbd85e5", "carmen"},
	{"$NT$f09ab1733a528f430353834152c8a90e", "mickey"},
	{"$NT$878d8014606cda29677a44efa1353fc7", "secret"},
	{"$NT$85ac333bbfcbaa62ba9f8afb76f06268", "summer"},
	{"$NT$5962cc080506d90be8943118f968e164", "internet"},
	{"$NT$f07206c3869bda5acd38a3d923a95d2a", "service"},
	{"$NT$31d6cfe0d16ae931b73c59d7e0c089c0", ""},
	{"$NT$d0dfc65e8f286ef82f6b172789a0ae1c", "canada"},
	{"$NT$066ddfd4ef0e9cd7c256fe77191ef43c", "hello"},
	{"$NT$39b8620e745b8aa4d1108e22f74f29e2", "ranger"},
	{"$NT$8d4ef8654a9adc66d4f628e94f66e31b", "shadow"},
	{"$NT$320a78179516c385e35a93ffa0b1c4ac", "baseball"},
	{"$NT$e533d171ac592a4e70498a58b854717c", "donald"},
	{"$NT$5eee54ce19b97c11fd02e531dd268b4c", "harley"},
	{"$NT$6241f038703cbfb7cc837e3ee04f0f6b", "hockey"},
	{"$NT$becedb42ec3c5c7f965255338be4453c", "letmein"},
	{"$NT$ec2c9f3346af1fb8e4ee94f286bac5ad", "maggie"},
	{"$NT$f5794cbd75cf43d1eb21fad565c7e21c", "mike"},
	{"$NT$74ed32086b1317b742c3a92148df1019", "mustang"},
	{"$NT$63af6e1f1dd9ecd82f17d37881cb92e6", "snoopy"},
	{"$NT$58def5844fe58e8f26a65fff9deb3827", "buster"},
	{"$NT$f7eb9c06fafaa23c4bcf22ba6781c1e2", "dragon"},
	{"$NT$dd555241a4321657e8b827a40b67dd4a", "jordan"},
	{"$NT$bb53a477af18526ada697ce2e51f76b3", "michael"},
	{"$NT$92b7b06bb313bf666640c5a1e75e0c18", "michelle"},
	{NULL}
};

//Init values
#define INIT_A 0x67452301
#define INIT_B 0xefcdab89
#define INIT_C 0x98badcfe
#define INIT_D 0x10325476

#define SQRT_2 0x5a827999
#define SQRT_3 0x6ed9eba1

static int have_full_hashes;

static cl_uint *bbbs;
static cl_uint *res_hashes;
static char *saved_plain;
static int max_key_length = 0;
static char get_key_saved[PLAINTEXT_LENGTH+1];
static struct fmt_main *self;

//OpenCL variables
static cl_mem pinned_saved_keys, pinned_bbbs, buffer_out, buffer_keys;

#define STEP			0
#define SEED			(128*1024)

// This file contains auto-tuning routine(s). Has to be included after formats definitions.
#include "opencl-autotune.h"
#include "memdbg.h"

static const char * warn[] = {
	"xfer: ",  ", crypt: ",  ", xfer: "
};

/* ------- Helper functions ------- */
static size_t get_task_max_work_group_size()
{
	return autotune_get_task_max_work_group_size(FALSE, 0, crypt_kernel);
}

static size_t get_task_max_size()
{
	return 0;
}

static size_t get_default_workgroup()
{
	if (cpu(device_info[gpu_id]))
		return get_platform_vendor_id(platform_id) == DEV_INTEL ?
			8 : 1;
	else
		return 64;
}

static void create_clobj(size_t gws, struct fmt_main *self)
{
	int argIndex = 0;

	pinned_saved_keys = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE | CL_MEM_ALLOC_HOST_PTR, (PLAINTEXT_LENGTH+1)*gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code,"Error creating page-locked memory");
	pinned_bbbs = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE | CL_MEM_ALLOC_HOST_PTR,4*gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code,"Error creating page-locked memory");

	res_hashes = mem_alloc(sizeof(cl_uint) * 3 * gws);
	saved_plain = (char*) clEnqueueMapBuffer(queue[gpu_id], pinned_saved_keys, CL_TRUE, CL_MAP_WRITE | CL_MAP_READ, 0, (PLAINTEXT_LENGTH+1)*gws, 0, NULL, NULL, &ret_code);
	HANDLE_CLERROR(ret_code,"Error mapping page-locked memory");
	bbbs = (cl_uint*)clEnqueueMapBuffer(queue[gpu_id], pinned_bbbs , CL_TRUE, CL_MAP_READ, 0, 4*gws, 0, NULL, NULL, &ret_code);
	HANDLE_CLERROR(ret_code,"Error mapping page-locked memory");

	// Create and set arguments
	buffer_keys = clCreateBuffer( context[gpu_id], CL_MEM_READ_ONLY,(PLAINTEXT_LENGTH+1)*gws, NULL, &ret_code );
	HANDLE_CLERROR(ret_code,"Error creating buffer argument");
	buffer_out  = clCreateBuffer( context[gpu_id], CL_MEM_WRITE_ONLY , 4*4*gws, NULL, &ret_code );
	HANDLE_CLERROR(ret_code,"Error creating buffer argument");

	argIndex = 0;

	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, argIndex++, sizeof(buffer_keys), (void*) &buffer_keys),
		"Error setting argument 0");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, argIndex++, sizeof(buffer_out ), (void*) &buffer_out ),
		"Error setting argument 1");

	global_work_size = gws;
}

static void release_clobj(void)
{
	if (res_hashes) {
		clEnqueueUnmapMemObject(queue[gpu_id], pinned_bbbs, bbbs, 0, NULL, NULL);
		clEnqueueUnmapMemObject(queue[gpu_id], pinned_saved_keys, saved_plain, 0, NULL, NULL);
		HANDLE_CLERROR(clFinish(queue[gpu_id]), "Error releasing memory mappings");

		HANDLE_CLERROR(clReleaseMemObject(buffer_keys), "Release mem in");
		HANDLE_CLERROR(clReleaseMemObject(buffer_out), "Release mem setting");
		HANDLE_CLERROR(clReleaseMemObject(pinned_bbbs), "Release mem out");
		HANDLE_CLERROR(clReleaseMemObject(pinned_saved_keys), "Release mem out");

		MEM_FREE(res_hashes);
	}
}

static void done(void)
{
	release_clobj();

	HANDLE_CLERROR(clReleaseKernel(crypt_kernel), "Release kernel");
	HANDLE_CLERROR(clReleaseProgram(program[gpu_id]), "Release Program");
}

static void init(struct fmt_main *_self)
{
	self = _self;

	opencl_init("$JOHN/kernels/nt_kernel.cl", gpu_id, NULL);

	crypt_kernel = clCreateKernel( program[gpu_id], "nt_crypt", &ret_code );
	HANDLE_CLERROR(ret_code,"Error creating kernel");
}

static void reset(struct db_main *db)
{
	if (!db) {
		// Initialize openCL tuning (library) for this format.
		opencl_init_auto_setup(SEED, 0, NULL, warn, 1, self,
		                       create_clobj, release_clobj,
		                       2 * 2 * (PLAINTEXT_LENGTH + 1), 0);

		// Auto tune execution from shared/included code.
		autotune_run(self, 1, 0, 200);
	}
}

// TODO: Use concurrent memory copy & execute
static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int key_length_mul_4 = (((max_key_length+1) + 3)/4)*4;
	size_t *lws = local_work_size ? &local_work_size : NULL;

	// Fill params. Copy only necessary data
	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], buffer_keys,
		CL_TRUE, 0, key_length_mul_4 * global_work_size, saved_plain,
		0, NULL, multi_profilingEvent[0]),
		"failed in clEnqueWriteBuffer buffer_keys");

	// Execute method
	clEnqueueNDRangeKernel( queue[gpu_id], crypt_kernel, 1, NULL,
		&global_work_size, lws, 0, NULL,
		multi_profilingEvent[1]);

	// Read partial result
	clEnqueueReadBuffer(queue[gpu_id], buffer_out, CL_TRUE, 0,
		sizeof(cl_uint)*global_work_size, bbbs, 0, NULL,
		multi_profilingEvent[2]);

	max_key_length = 0;
	have_full_hashes = 0;

	return count;
}

static char *split(char *ciphertext, int index, struct fmt_main *self)
{
	static char out[CIPHERTEXT_LENGTH + 4 + 1];

	if (!strncmp(ciphertext, "$NT$", 4))
		ciphertext += 4;

	out[0] = '$';
	out[1] = 'N';
	out[2] = 'T';
	out[3] = '$';

	memcpy(&out[4], ciphertext, 32);
	out[36] = 0;

	strlwr(&out[4]);

	return out;
}

static int valid(char *ciphertext, struct fmt_main *self)
{
        char *pos;

	if (!strncmp(ciphertext, "$NT$", 4))
		ciphertext += 4;

        for (pos = ciphertext; atoi16[ARCH_INDEX(*pos)] != 0x7F; pos++);

        if (!*pos && pos - ciphertext == CIPHERTEXT_LENGTH)
		return 1;
        else
	return 0;

}

// here to 'handle' the pwdump files:  user:uid:lmhash:ntlmhash:::
// Note, we address the user id inside loader.
static char *prepare(char *split_fields[10], struct fmt_main *self)
{
	static char out[33+5];

	if (!valid(split_fields[1], self)) {
		if (split_fields[3] && strlen(split_fields[3]) == 32) {
			sprintf(out, "$NT$%s", split_fields[3]);
			if (valid(out,self))
				return out;
		}
	}
	return split_fields[1];
}

static void *get_binary(char *ciphertext)
{
	static unsigned int out[4];
	unsigned int i=0;
	unsigned int temp;

	ciphertext+=4;
	for (; i<4; i++){
		temp  = (atoi16[ARCH_INDEX(ciphertext[i*8+0])])<<4;
		temp |= (atoi16[ARCH_INDEX(ciphertext[i*8+1])]);

		temp |= (atoi16[ARCH_INDEX(ciphertext[i*8+2])])<<12;
		temp |= (atoi16[ARCH_INDEX(ciphertext[i*8+3])])<<8;

		temp |= (atoi16[ARCH_INDEX(ciphertext[i*8+4])])<<20;
		temp |= (atoi16[ARCH_INDEX(ciphertext[i*8+5])])<<16;

		temp |= (atoi16[ARCH_INDEX(ciphertext[i*8+6])])<<28;
		temp |= (atoi16[ARCH_INDEX(ciphertext[i*8+7])])<<24;

		out[i]=temp;
	}

	out[0] -= INIT_A;
	out[1] -= INIT_B;
	out[2] -= INIT_C;
	out[3] -= INIT_D;

	out[1]  = (out[1] >> 15) | (out[1] << 17);
	out[1] -= SQRT_3 + (out[2] ^ out[3] ^ out[0]);
	out[1]  = (out[1] >> 15) | (out[1] << 17);
	out[1] -= SQRT_3;

	return out;
}

static int binary_hash_0(void *binary) { return ((unsigned int *)binary)[1] & 0xF; }
static int binary_hash_1(void *binary) { return ((unsigned int *)binary)[1] & 0xFF; }
static int binary_hash_2(void *binary) { return ((unsigned int *)binary)[1] & 0xFFF; }
static int binary_hash_3(void *binary) { return ((unsigned int *)binary)[1] & 0xFFFF; }
static int binary_hash_4(void *binary) { return ((unsigned int *)binary)[1] & 0xFFFFF; }
static int binary_hash_5(void *binary) { return ((unsigned int *)binary)[1] & 0xFFFFFF; }
static int binary_hash_6(void *binary) { return ((unsigned int *)binary)[1] & 0x7FFFFFF; }

static int get_hash_0(int index) { return bbbs[index] & 0xF; }
static int get_hash_1(int index) { return bbbs[index] & 0xFF; }
static int get_hash_2(int index) { return bbbs[index] & 0xFFF; }
static int get_hash_3(int index) { return bbbs[index] & 0xFFFF; }
static int get_hash_4(int index) { return bbbs[index] & 0xFFFFF; }
static int get_hash_5(int index) { return bbbs[index] & 0xFFFFFF; }
static int get_hash_6(int index) { return bbbs[index] & 0x7FFFFFF; }

static int cmp_all(void *binary, int count) {
	unsigned int i=0;
	unsigned int b=((unsigned int *)binary)[1];

	for(;i<count;i++)
		if(b==bbbs[i])
			return 1;
	return 0;
}

static int cmp_one(void * binary, int index)
{
	unsigned int *t=(unsigned int *)binary;
	if (t[1]==bbbs[index])
		return 1;
	return 0;
}

static int cmp_exact(char *source, int index)
{
	unsigned int *t = (unsigned int *) get_binary(source);

	if (!have_full_hashes){
		clEnqueueReadBuffer(queue[gpu_id], buffer_out, CL_TRUE,
			sizeof(cl_uint) * (global_work_size),
			sizeof(cl_uint) * 3 * global_work_size, res_hashes, 0,
			NULL, NULL);
		have_full_hashes = 1;
	}

	if (t[0]!=res_hashes[index])
		return 0;
	if (t[1]!=bbbs[index])
		return 0;
	if (t[2]!=res_hashes[1*global_work_size+index])
		return 0;
	if (t[3]!=res_hashes[2*global_work_size+index])
		return 0;
	return 1;
}

static void set_key(char *key, int index)
{
	int length = -1;

	do {
		length++;
		//Save keys in a coalescing friendly way
		saved_plain[(length/4)*global_work_size*4+index*4+length%4] = key[length];
	}
	while(key[length]);
	//Calculate max key length of this chunk
	if (length > max_key_length)
		max_key_length = length;
}
static char *get_key(int index)
{
	int length = -1;

	do
	{
		length++;
		//Decode saved key
		get_key_saved[length] = saved_plain[(length/4)*global_work_size*4+index*4+length%4];
	}
	while(get_key_saved[length]);

	return get_key_saved;
}

struct fmt_main fmt_opencl_NT = {
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
		FMT_CASE | FMT_8_BIT | FMT_SPLIT_UNIFIES_CASE | FMT_UNICODE,
#if FMT_MAIN_VERSION > 11
		{ NULL },
#endif
		tests
	}, {
		init,
		done,
		reset,
		prepare,
		valid,
		split,
		get_binary,
		fmt_default_salt,
#if FMT_MAIN_VERSION > 11
		{ NULL },
#endif
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
		NULL,
		fmt_default_set_salt,
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
	}
};

#endif /* plugin stanza */

#endif /* HAVE_OPENCL */
