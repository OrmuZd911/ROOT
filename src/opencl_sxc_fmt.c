/*
 * Modified by Dhiru Kholia <dhiru at openwall.com> for Keychain format.
 *
 * This software is Copyright (c) 2012 Lukas Odzioba <ukasz@openwall.net>
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted. */

#include <string.h>
#include "arch.h"
#include "formats.h"
#include "common.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "common-opencl.h"
#include <openssl/sha.h>
#include <openssl/blowfish.h>
#include <openssl/aes.h>
#ifdef _OPENMP
#include <omp.h>
#endif

#define FORMAT_LABEL		"sxc-opencl"
#define FORMAT_NAME		"SXC SHA-1 Blowfish"
#define ALGORITHM_NAME		"OpenCL"
#define BENCHMARK_COMMENT	""
#define BENCHMARK_LENGTH	-1
#define MIN_KEYS_PER_CRYPT	4096*9
#define MAX_KEYS_PER_CRYPT	MIN_KEYS_PER_CRYPT
#define BINARY_SIZE		20
#define PLAINTEXT_LENGTH	64
#define SALT_SIZE		sizeof(sxc_cpu_salt)

#define uint8_t			unsigned char
#define uint16_t		unsigned short
#define uint32_t		unsigned int

typedef struct {
	uint32_t length;
	uint8_t v[20];	// hash of password
} sxc_password;

typedef struct {
	uint32_t v[16/4];
} sxc_hash;

typedef struct {
	uint8_t length;
	uint8_t salt[32];
	uint32_t iterations;
	uint32_t outlen;
} sxc_salt;

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static ARCH_WORD_32 (*crypt_out)[32 / sizeof(ARCH_WORD_32)];

typedef struct {
	int cipher_type;
	int checksum_type;
	int iterations;
	int key_size;
	int iv_length;
	int salt_length;
	int original_length;
	int length;
	unsigned char iv[16];
	unsigned char salt[32];
	unsigned char content[1024];
} sxc_cpu_salt;

static sxc_cpu_salt *cur_salt;

static struct fmt_tests sxc_tests[] = {
	{"$sxc$*0*0*1024*16*4448359828281a1e6842c31453473abfeae584fb*8*dc0248bea0c7508c*16*1d53770002fe9d8016064e5ef9423174*860*864*f00399ab17b9899cd517758ecf918d4da78099ccd3557aef5e22e137fd5b81f732fc7c167c4de0cf263b4f82b50e3d6abc65da613a36b0025d89e1a09adeb4106da28040d1019bb4b36630fc8bc94fe5b515504bf8a92ea630bb95ace074868e7c10743ec970c89895f44b975a30b6ca032354f3e73ec86b2cc7a4f7a185884026d971b37b1e0e650376a2552e27ba955c700f8903a82a6df11f6cc2ecf63290f02ffdd278f890d1db75f9e8bd0f437c4ec613d3c6dcb421bbd1067be633593ba9bd58f77ef08e0cca64c732f892567d20de8d4c444fa9c1c1adc5e4657ef9740cb69ce55c8f9e6b1cfed0739ef002f1e1c1e54a5df50a759d92354f78eb90a9d9378f36df7d1edd8002ea0d637604fcd2408494c2d42b1771e2a2a20b55044836f76db4ed71e8a53f55a04f9437946603e7246c2d2d70caf6be0de82e8977fab4de84ca3783baedac041195d8b51166b502ff80c17db78f63d3632df1d5ef5b14d8d5553fc40b072030f9e3374c93e929a490c6cfb170f04433fc46f43b9c7d27f3f8c4ed759d4a20c2e53a0701b7c3d9201390a9b5597ce8ba35bd765b662e2242b9821bbb63b6be502d2150fff37e4b7f2a6b592fd0e319a7349df320e7fe7da600a2a05628dc00e04d480c085417f676bd0518bc39d9a9be34fc0cb192d5fa5e0c657cdf7c1ad265a2e81b90ac8b28d326f98b8f33c123df83edc964d2c17a904d0df8bd9ecbf629929d6e48cadc97f49a8941ada3d219e8c0f04f37cecc9a50cc5307fd2a488c34829b05cd1615ae0d1ef0ce450529aa755f9ae38332187ffe4144990de3265afaacb9f0f0fb9c67f6210369f7a0cc5bb346412db08e0f4732f91aa8d4b32fe6eece4fba118f118f6df2fb6c53fa9bc164c9ab7a9d414d33281eb0c3cd02abe0a4dd1c170e41c1c960a8f12a48a7b5e1f748c08e1b150a4e389c110ea3368bc6c6ef2bee98dc92c6825cbf6aee20e690e116c0e6cf48d49b38035f6a9b0cd6053b9f5b9f8360024c9c608cbba3fe5e7966b656fa08dec3e3ce3178a0c0007b7d177c7c44e6a68f4c7325cb98264b1e0f391c75a6a8fd3691581fb68ef459458830f2138d0fd743631efd92b742dfeb62c5ea8502515eb65af414bf805992f9272a7b1b745970fd54e128751f8f6c0a4d5bc7872bc09c04037e1e91dc7192d68f780cdb0f7ef6b282ea883be462ffeffb7b396e30303030", "openwall"},
	{NULL}
};

static sxc_password *inbuffer;
static sxc_hash *outbuffer;
static sxc_salt currentsalt;
static cl_mem mem_in, mem_out, mem_setting;

#define insize (sizeof(sxc_password) * global_work_size)
#define outsize (sizeof(sxc_hash) * global_work_size)
#define settingsize sizeof(sxc_salt)

static void release_clobj(void)
{
	HANDLE_CLERROR(clReleaseMemObject(mem_in), "Release mem in");
	HANDLE_CLERROR(clReleaseMemObject(mem_setting), "Release mem setting");
	HANDLE_CLERROR(clReleaseMemObject(mem_out), "Release mem out");

	MEM_FREE(inbuffer);
	MEM_FREE(outbuffer);
	MEM_FREE(saved_key);
	MEM_FREE(crypt_out);
}

static void done(void)
{
	release_clobj();

	HANDLE_CLERROR(clReleaseKernel(crypt_kernel), "Release kernel");
	HANDLE_CLERROR(clReleaseProgram(program[ocl_gpu_id]), "Release Program");
}

static void init(struct fmt_main *self)
{
	cl_int cl_error;
	char build_opts[64];
	char *temp;
	cl_ulong maxsize;

	snprintf(build_opts, sizeof(build_opts),
	         "-DKEYLEN=%d -DSALTLEN=%d -DOUTLEN=%d",
	         (int)sizeof(inbuffer->v),
	         (int)sizeof(currentsalt.salt),
	         (int)sizeof(outbuffer->v));
	opencl_init_opt("$JOHN/kernels/pbkdf2_hmac_sha1_unsplit_kernel.cl",
	                ocl_gpu_id, build_opts);

	if ((temp = getenv("LWS")))
		local_work_size = atoi(temp);
	else
		local_work_size = cpu(device_info[ocl_gpu_id]) ? 1 : 64;

	if ((temp = getenv("GWS")))
		global_work_size = atoi(temp);
	else
		global_work_size = MAX_KEYS_PER_CRYPT;

	crypt_kernel = clCreateKernel(program[ocl_gpu_id], "derive_key", &cl_error);
	HANDLE_CLERROR(cl_error, "Error creating kernel");

	/* Note: we ask for the kernels' max sizes, not the device's! */
	HANDLE_CLERROR(clGetKernelWorkGroupInfo(crypt_kernel, devices[ocl_gpu_id], CL_KERNEL_WORK_GROUP_SIZE, sizeof(maxsize), &maxsize, NULL), "Query max workgroup size");

	while (local_work_size > maxsize)
		local_work_size >>= 1;

	inbuffer =
		(sxc_password *) mem_calloc(sizeof(sxc_password) *
		                        global_work_size);
	outbuffer =
		(sxc_hash *) mem_alloc(sizeof(sxc_hash) * global_work_size);

	saved_key = mem_calloc(sizeof(*saved_key) * global_work_size);

	crypt_out = mem_calloc(sizeof(*crypt_out) * global_work_size);

	/// Allocate memory
	mem_in =
	    clCreateBuffer(context[ocl_gpu_id], CL_MEM_READ_ONLY, insize, NULL,
	    &cl_error);
	HANDLE_CLERROR(cl_error, "Error allocating mem in");
	mem_setting =
	    clCreateBuffer(context[ocl_gpu_id], CL_MEM_READ_ONLY, settingsize,
	    NULL, &cl_error);
	HANDLE_CLERROR(cl_error, "Error allocating mem setting");
	mem_out =
	    clCreateBuffer(context[ocl_gpu_id], CL_MEM_WRITE_ONLY, outsize, NULL,
	    &cl_error);
	HANDLE_CLERROR(cl_error, "Error allocating mem out");

	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 0, sizeof(mem_in),
		&mem_in), "Error while setting mem_in kernel argument");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 1, sizeof(mem_out),
		&mem_out), "Error while setting mem_out kernel argument");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 2, sizeof(mem_setting),
		&mem_setting), "Error while setting mem_salt kernel argument");

	self->params.max_keys_per_crypt = global_work_size;
	if (!local_work_size)
		opencl_find_best_workgroup(self);

	self->params.min_keys_per_crypt = local_work_size;

	fprintf(stderr, "Local worksize (LWS) %d, Global worksize (GWS) %d\n", (int)local_work_size, (int)global_work_size);
}

static int ishex(char *q)
{
	while (atoi16[ARCH_INDEX(*q)] != 0x7F)
		q++;
	return !*q;
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *ctcopy;
	char *keeptr;
	char *p;
	int res;
	if (strncmp(ciphertext, "$sxc$", 5))
		return 0;
	ctcopy = strdup(ciphertext);
	keeptr = ctcopy;
	ctcopy += 6;
	if ((p = strtok(ctcopy, "*")) == NULL)	/* cipher type */
		goto err;
	res = atoi(p);
	if (res != 0 && res != 1)
		goto err;
	if ((p = strtok(NULL, "*")) == NULL)	/* checksum type */
		goto err;
	res = atoi(p);
	if (res != 0 && res != 1)
		goto err;
	if ((p = strtok(NULL, "*")) == NULL)	/* iterations */
		goto err;
	if ((p = strtok(NULL, "*")) == NULL)	/* key size */
		goto err;
	if ((p = strtok(NULL, "*")) == NULL)	/* checksum field (skipped) */
		goto err;
	if ((p = strtok(NULL, "*")) == NULL)	/* iv length */
		goto err;
	res = atoi(p);
	if ((p = strtok(NULL, "*")) == NULL)	/* iv */
		goto err;
	if (strlen(p) != res * 2)
		goto err;
	if (!ishex(p))
		goto err;
	if ((p = strtok(NULL, "*")) == NULL)	/* salt length */
		goto err;
	res = atoi(p);
	if ((p = strtok(NULL, "*")) == NULL)	/* salt */
		goto err;
	if (strlen(p) != res * 2)
		goto err;
	if (!ishex(p))
		goto err;
	if ((p = strtok(NULL, "*")) == NULL)	/* original length */
		goto err;
	if ((p = strtok(NULL, "*")) == NULL)	/* length */
		goto err;
	res = atoi(p);
	if ((p = strtok(NULL, "*")) == NULL)	/* content */
		goto err;
	if (strlen(p) != res * 2)
		goto err;
	if (!ishex(p))
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
	int i;
	char *p;
	static sxc_cpu_salt cs;
	ctcopy += 6;	/* skip over "$sxc$*" */
	p = strtok(ctcopy, "*");
	cs.cipher_type = atoi(p);
	p = strtok(NULL, "*");
	cs.checksum_type = atoi(p);
	p = strtok(NULL, "*");
	cs.iterations = atoi(p);
	p = strtok(NULL, "*");
	cs.key_size = atoi(p);
	p = strtok(NULL, "*");
	/* skip checksum field */
	p = strtok(NULL, "*");
	cs.iv_length = atoi(p);
	p = strtok(NULL, "*");
	for (i = 0; i < cs.iv_length; i++)
		cs.iv[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	p = strtok(NULL, "*");
	cs.salt_length = atoi(p);
	p = strtok(NULL, "*");
	for (i = 0; i < cs.salt_length; i++)
		cs.salt[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	p = strtok(NULL, "*");
	cs.original_length = atoi(p);
	p = strtok(NULL, "*");
	cs.length = atoi(p);
	p = strtok(NULL, "*");
	for (i = 0; i < cs.length; i++)
		cs.content[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	MEM_FREE(keeptr);
	return (void *)&cs;
}

static void *get_binary(char *ciphertext)
{
	static union {
		unsigned char c[BINARY_SIZE+1];
		ARCH_WORD dummy;
	} buf;
	unsigned char *out = buf.c;
	char *p;
	int i;
	char *ctcopy = strdup(ciphertext);
	char *keeptr = ctcopy;
	ctcopy += 6;	/* skip over "$sxc$*" */
	p = strtok(ctcopy, "*");
	p = strtok(NULL, "*");
	p = strtok(NULL, "*");
	p = strtok(NULL, "*");
	p = strtok(NULL, "*");
	for (i = 0; i < BINARY_SIZE; i++) {
		out[i] =
			(atoi16[ARCH_INDEX(*p)] << 4) |
			atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}
	MEM_FREE(keeptr);
	return out;
}

static void set_salt(void *salt)
{
	cur_salt = (sxc_cpu_salt*)salt;
	memcpy((char*)currentsalt.salt, cur_salt->salt, cur_salt->salt_length);
	currentsalt.length = cur_salt->salt_length;
	currentsalt.iterations = cur_salt->iterations;
	currentsalt.outlen = cur_salt->key_size;
}

static int binary_hash_0(void *binary) { return *(ARCH_WORD_32 *)binary & 0xf; }
static int binary_hash_1(void *binary) { return *(ARCH_WORD_32 *)binary & 0xff; }
static int binary_hash_2(void *binary) { return *(ARCH_WORD_32 *)binary & 0xfff; }
static int binary_hash_3(void *binary) { return *(ARCH_WORD_32 *)binary & 0xffff; }
static int binary_hash_4(void *binary) { return *(ARCH_WORD_32 *)binary & 0xfffff; }
static int binary_hash_5(void *binary) { return *(ARCH_WORD_32 *)binary & 0xffffff; }
static int binary_hash_6(void *binary) { return *(ARCH_WORD_32 *)binary & 0x7ffffff; }

static int get_hash_0(int index) { return crypt_out[index][0] & 0xf; }
static int get_hash_1(int index) { return crypt_out[index][0] & 0xff; }
static int get_hash_2(int index) { return crypt_out[index][0] & 0xfff; }
static int get_hash_3(int index) { return crypt_out[index][0] & 0xffff; }
static int get_hash_4(int index) { return crypt_out[index][0] & 0xfffff; }
static int get_hash_5(int index) { return crypt_out[index][0] & 0xffffff; }
static int get_hash_6(int index) { return crypt_out[index][0] & 0x7ffffff; }

#undef set_key
static void set_key(char *key, int index)
{
	int saved_key_length = strlen(key);
	if (saved_key_length > PLAINTEXT_LENGTH)
		saved_key_length = PLAINTEXT_LENGTH;
	memcpy(saved_key[index], key, saved_key_length);
	saved_key[index][saved_key_length] = 0;
}

static char *get_key(int index)
{
	return saved_key[index];
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	int count = *pcount;
	int index;

	global_work_size = (count + local_work_size - 1) / local_work_size * local_work_size;

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for(index = 0; index < count; index++)
	{
		unsigned char hash[20];
		SHA_CTX ctx;

		SHA1_Init(&ctx);
		SHA1_Update(&ctx, (unsigned char *)saved_key[index], strlen(saved_key[index]));
		SHA1_Final((unsigned char *)hash, &ctx);
		memcpy(inbuffer[index].v, hash, 20);
		inbuffer[index].length = 20;
	}

	/// Copy data to gpu
	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[ocl_gpu_id], mem_in, CL_FALSE, 0,
		insize, inbuffer, 0, NULL, NULL), "Copy data to gpu");
	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[ocl_gpu_id], mem_setting,
		CL_FALSE, 0, settingsize, &currentsalt, 0, NULL, NULL),
	    "Copy setting to gpu");

	/// Run kernel
	HANDLE_CLERROR(clEnqueueNDRangeKernel(queue[ocl_gpu_id], crypt_kernel, 1,
		NULL, &global_work_size, &local_work_size, 0, NULL, profilingEvent),
	    "Run kernel");
	HANDLE_CLERROR(clFinish(queue[ocl_gpu_id]), "clFinish");

	/// Read the result back
	HANDLE_CLERROR(clEnqueueReadBuffer(queue[ocl_gpu_id], mem_out, CL_FALSE, 0,
		outsize, outbuffer, 0, NULL, NULL), "Copy result back");

	/// Await completion of all the above
	HANDLE_CLERROR(clFinish(queue[ocl_gpu_id]), "clFinish");

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for(index = 0; index < count; index++)
	{
		BF_KEY bf_key;
		SHA_CTX ctx;
		int bf_ivec_pos;
		unsigned char ivec[8];
		unsigned char output[1024];

		bf_ivec_pos = 0;
		memcpy(ivec, cur_salt->iv, 8);
		BF_set_key(&bf_key, cur_salt->key_size, (const unsigned char*)outbuffer[index].v);
		BF_cfb64_encrypt(cur_salt->content, output, cur_salt->length, &bf_key, ivec, &bf_ivec_pos, 0);
		SHA1_Init(&ctx);
		SHA1_Update(&ctx, output, cur_salt->original_length);
		SHA1_Final((unsigned char*)crypt_out[index], &ctx);
	 }
	return count;
}

static int cmp_all(void *binary, int count)
{
	int index = 0;
	for (; index < count; index++)
		if (!memcmp(binary, crypt_out[index], BINARY_SIZE))
			return 1;
	return 0;
}

static int cmp_one(void *binary, int index)
{
	return !memcmp(binary, crypt_out[index], BINARY_SIZE);
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

struct fmt_main fmt_opencl_sxc = {
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
		FMT_CASE | FMT_8_BIT | FMT_OMP,
		sxc_tests
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		get_binary,
		get_salt,
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
	}
};
