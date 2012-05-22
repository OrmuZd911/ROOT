/*
 * SHA-512 hashing, OpenCL interface.
 * Please note that in current comparison function, we use computed a77
 * compares with ciphertext d80. For more details, refer to:
 * http://www.openwall.com/lists/john-dev/2012/04/11/13
 *
 * Copyright (c) 2012 myrice (interfacing to CUDA)
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 */


#include <openssl/opensslv.h>
#if OPENSSL_VERSION_NUMBER >= 0x00908000

#include <string.h>
#include <openssl/sha.h>


#include "common-opencl.h"
#include "arch.h"
#include "params.h"
#include "common.h"
#include "formats.h"

#define FORMAT_LABEL			"raw-sha512-opencl"
#define FORMAT_NAME			"SHA-512"
#define ALGORITHM_NAME			"OpenCL"

#define BENCHMARK_COMMENT		""
#define BENCHMARK_LENGTH		-1

#define KERNEL_NAME "kernel_sha512"
#define CMP_KERNEL_NAME "kernel_cmp"

#define uint8_t  unsigned char
#define uint32_t unsigned int
#define uint64_t unsigned long long int

#define KEYS_PER_CRYPT (1024*512)
#define ITERATIONS 1

#define MIN_KEYS_PER_CRYPT	(KEYS_PER_CRYPT)
#define MAX_KEYS_PER_CRYPT	(ITERATIONS*KEYS_PER_CRYPT)
#define hash_addr(j,idx) (((j)*(MAX_KEYS_PER_CRYPT))+(idx))

#define SWAP64(n) \
  (((n) << 56)					\
   | (((n) & 0xff00) << 40)			\
   | (((n) & 0xff0000) << 24)			\
   | (((n) & 0xff000000) << 8)			\
   | (((n) >> 8) & 0xff000000)			\
   | (((n) >> 24) & 0xff0000)			\
   | (((n) >> 40) & 0xff00)			\
   | ((n) >> 56))


#define SALT_SIZE 0

#define BINARY_SIZE 8
#define FULL_BINARY_SIZE 64


#define PLAINTEXT_LENGTH 12 //For one iteration, maximum is 107
#define CIPHERTEXT_LENGTH 128

typedef struct { // notice memory align problem
	uint64_t H[8];
	uint32_t buffer[32];	//1024 bits
	uint32_t buflen;
} sha512_ctx;

typedef struct {
    uint8_t length;
    char v[PLAINTEXT_LENGTH+1];
} sha512_key;



typedef struct {
    uint64_t v[BINARY_SIZE / 8]; // up to 512 bits
} sha512_hash;


static struct fmt_tests tests[] = {
	{"b109f3bbbc244eb82441917ed06d618b9008dd09b3befd1b5e07394c706a8bb980b1d7785e5976ec049b46df5f1326af5a2ea6d103fd07c95385ffab0cacbc86", "password"},
	{"2c80f4c2b3db6b677d328775be4d38c8d8cd9a4464c3b6273644fb148f855e3db51bc33b54f3f6fa1f5f52060509f0e4d350bb0c7f51947728303999c6eff446", "john-user"},
	{NULL}
};


static sha512_key gkey[MAX_KEYS_PER_CRYPT];
static sha512_hash ghash[MAX_KEYS_PER_CRYPT];
uint8_t sha512_key_changed;

static uint64_t H[8] = {
	0x6a09e667f3bcc908LL,
	0xbb67ae8584caa73bLL,
	0x3c6ef372fe94f82bLL,
	0xa54ff53a5f1d36f1LL,
	0x510e527fade682d1LL,
	0x9b05688c2b3e6c1fLL,
	0x1f83d9abfb41bd6bLL,
	0x5be0cd19137e2179LL
};

//OpenCL variables:
static cl_mem mem_in, mem_out, mem_binary, mem_cmp;
static size_t insize = sizeof(sha512_key) * MAX_KEYS_PER_CRYPT;
static size_t outsize = sizeof(sha512_hash) * MAX_KEYS_PER_CRYPT;
static size_t global_work_size = MAX_KEYS_PER_CRYPT;
cl_kernel cmp_kernel;

static void release_all(void)
{
	HANDLE_CLERROR(clReleaseKernel(crypt_kernel), "Release kernel");
	HANDLE_CLERROR(clReleaseMemObject(mem_in), "Release memin");
	HANDLE_CLERROR(clReleaseMemObject(mem_out), "Release memout");
	HANDLE_CLERROR(clReleaseCommandQueue(queue[gpu_id]), "Release Queue");
}

static void set_key(char *key, int index)
{
	int length = strlen(key);
	if (length > PLAINTEXT_LENGTH)
		length = PLAINTEXT_LENGTH;
	gkey[index].length = length;
	memcpy(gkey[index].v, key, length);
	sha512_key_changed = 1;
}

static char *get_key(int index)
{
	gkey[index].v[gkey[index].length] = 0;
	return gkey[index].v;
}

static void find_best_workgroup()
{
	cl_event myEvent;
	cl_ulong startTime, endTime, kernelExecTimeNs = CL_ULONG_MAX;
	cl_ulong sumStartTime, sumEndTime;
	size_t my_work_group = 1;
	cl_int ret_code;
	int i;
	size_t max_group_size;
	size_t work_size = KEYS_PER_CRYPT;
    HANDLE_CLERROR(clGetKernelWorkGroupInfo(crypt_kernel, devices[gpu_id], 
		CL_KERNEL_WORK_GROUP_SIZE,sizeof (max_group_size), &max_group_size, 
		NULL), "Error querying CL_DEVICE_MAX_WORK_GROUP_SIZE");
	
	cl_command_queue queue_prof =
	    clCreateCommandQueue(context[gpu_id], devices[gpu_id],
	    CL_QUEUE_PROFILING_ENABLE,
	    &ret_code);
	HANDLE_CLERROR(ret_code, "Error while creating command queue");
	
	/// Set keys
	char *pass = "password";
	for (i = 0; i < MAX_KEYS_PER_CRYPT; i++) {
		set_key(pass, i);
	}
	

	///Copy data to GPU
	HANDLE_CLERROR(clEnqueueWriteBuffer(queue_prof, mem_in, CL_FALSE, 0,
		insize, gkey, 0, NULL, NULL), "Copy data to gpu");

	my_work_group = 1;
	if (get_device_type(gpu_id) == CL_DEVICE_TYPE_GPU) 
		my_work_group = 32;

	///Find best local work size
	for (; (int) my_work_group <= (int) max_group_size; my_work_group *= 2) {
		sumStartTime = 0;
		sumEndTime = 0;
		for (i = 0; i < 10; ++i) {
			HANDLE_CLERROR(clEnqueueNDRangeKernel(queue_prof, crypt_kernel,
				1, NULL, &work_size, &my_work_group, 0, NULL,
				&myEvent), "Run kernel");
			HANDLE_CLERROR(clFinish(queue_prof), "clFinish error");
			
			clGetEventProfilingInfo(myEvent, CL_PROFILING_COMMAND_SUBMIT,
			    sizeof(cl_ulong), &startTime, NULL);
			clGetEventProfilingInfo(myEvent, CL_PROFILING_COMMAND_END,
			    sizeof(cl_ulong), &endTime, NULL);
			sumStartTime += startTime;
			sumEndTime += endTime;
		}
		if ((sumEndTime - sumStartTime) < kernelExecTimeNs) {
			kernelExecTimeNs = sumEndTime - sumStartTime;
			local_work_size = my_work_group;
		}
		//printf("%d time=%lld\n",(int) my_work_group, endTime-startTime);
	}
	printf("Optimal Group work Size = %d\n", (int) local_work_size);
	clReleaseCommandQueue(queue_prof);
}


static void init(struct fmt_main *pFmt)
{
	opencl_init("$JOHN/sha512_kernel.cl", gpu_id, platform_id);

	///Alocate memory on the GPU
	mem_in =
		clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, insize, NULL,
		&ret_code);
	HANDLE_CLERROR(ret_code,"Error while alocating memory for passwords");
	mem_out =
		clCreateBuffer(context[gpu_id], CL_MEM_WRITE_ONLY, outsize, NULL,
		&ret_code);
	HANDLE_CLERROR(ret_code,"Error while alocating memory for hashes");
	mem_binary =
		clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, sizeof(uint64_t), NULL,
		&ret_code);
	HANDLE_CLERROR(ret_code,"Error while alocating memory for binary");
	mem_cmp =
		clCreateBuffer(context[gpu_id], CL_MEM_WRITE_ONLY, sizeof(uint32_t), NULL,
		&ret_code);
	HANDLE_CLERROR(ret_code,"Error while alocating memory for cmp_all result");

	///Assign crypt kernel parameters 
	crypt_kernel = clCreateKernel(program[gpu_id], KERNEL_NAME, &ret_code);
	HANDLE_CLERROR(ret_code,"Error while creating crypt_kernel");
	clSetKernelArg(crypt_kernel, 0, sizeof(mem_in), &mem_in);
	clSetKernelArg(crypt_kernel, 1, sizeof(mem_out), &mem_out);

	///Assign cmp kernel parameters 
	cmp_kernel = clCreateKernel(program[gpu_id], CMP_KERNEL_NAME, &ret_code);
	HANDLE_CLERROR(ret_code,"Error while creating cmp_kernel");
	clSetKernelArg(cmp_kernel, 0, sizeof(mem_binary), &mem_binary);
	clSetKernelArg(cmp_kernel, 1, sizeof(mem_out), &mem_out);
	clSetKernelArg(cmp_kernel, 2, sizeof(mem_cmp), &mem_cmp);

	find_best_workgroup();

	printf("Global work size = %lld\n",(long long)global_work_size);
	atexit(release_all);

}

static int valid(char *ciphertext, struct fmt_main *pFmt)
{
	char *pos;

	/* Require lowercase hex digits (assume ASCII) */
	pos = ciphertext;
	while (atoi16[ARCH_INDEX(*pos)] != 0x7F && (*pos <= '9' || *pos >= 'a'))
		pos++;
	return !*pos && pos - ciphertext == CIPHERTEXT_LENGTH;

}

static void *get_binary(char *ciphertext)
{
	static unsigned char out[FULL_BINARY_SIZE];
	char *p;
	int i;

	p = ciphertext;
	for (i = 0; i < sizeof(out); i++) {
		out[i] =
		    (atoi16[ARCH_INDEX(*p)] << 4) |
		    atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}
	uint64_t *b = (uint64_t*)out;
	for (i = 0; i < 8; i++) {
		uint64_t t = SWAP64(b[i])-H[i];
		b[i] = SWAP64(t);
	}
	return out;

}

static int binary_hash_0(void *binary)
{
	return *((ARCH_WORD_32 *)binary+6) & 0xF;
}

static int binary_hash_1(void *binary)
{
	return *((ARCH_WORD_32 *)binary+6) & 0xFF;
}

static int binary_hash_2(void *binary)
{
	return *((ARCH_WORD_32 *)binary+6) & 0xFFF;
}

static int binary_hash_3(void *binary)
{
	return *((ARCH_WORD_32 *)binary+6) & 0xFFFF;
}

static int binary_hash_4(void *binary)
{
	return *((ARCH_WORD_32 *)binary+6) & 0xFFFFF;
}

static int binary_hash_5(void *binary)
{
	return *((ARCH_WORD_32 *)binary+6) & 0xFFFFFF;
}

static int binary_hash_6(void *binary)
{
	return *((ARCH_WORD_32 *)binary+6) & 0x7FFFFFF;
}

static int get_hash_0(int index)
{
	HANDLE_CLERROR(clEnqueueReadBuffer(queue[gpu_id], mem_out, CL_FALSE, 0,
		outsize, ghash, 0, NULL, NULL), "Copy data back");
	HANDLE_CLERROR(clFinish(queue[gpu_id]), "clFinish error");
	return ((uint64_t*)ghash)[index] & 0xF;
}

static int get_hash_1(int index)
{	
	HANDLE_CLERROR(clEnqueueReadBuffer(queue[gpu_id], mem_out, CL_FALSE, 0,
		outsize, ghash, 0, NULL, NULL), "Copy data back");
	HANDLE_CLERROR(clFinish(queue[gpu_id]), "clFinish error");
	return ((uint64_t*)ghash)[index] & 0xFF;
}

static int get_hash_2(int index)
{
	HANDLE_CLERROR(clEnqueueReadBuffer(queue[gpu_id], mem_out, CL_FALSE, 0,
		outsize, ghash, 0, NULL, NULL), "Copy data back");
	HANDLE_CLERROR(clFinish(queue[gpu_id]), "clFinish error");

	return ((uint64_t*)ghash)[hash_addr(0, index)] & 0xFFF;
}

static int get_hash_3(int index)
{
	HANDLE_CLERROR(clEnqueueReadBuffer(queue[gpu_id], mem_out, CL_FALSE, 0,
		outsize, ghash, 0, NULL, NULL), "Copy data back");
	HANDLE_CLERROR(clFinish(queue[gpu_id]), "clFinish error");

	return ((uint64_t*)ghash)[hash_addr(0, index)] & 0xFFFF;
}

static int get_hash_4(int index)
{
	HANDLE_CLERROR(clEnqueueReadBuffer(queue[gpu_id], mem_out, CL_FALSE, 0,
		outsize, ghash, 0, NULL, NULL), "Copy data back");
	HANDLE_CLERROR(clFinish(queue[gpu_id]), "clFinish error");

	return ((uint64_t*)ghash)[hash_addr(0, index)] & 0xFFFFF;
}

static int get_hash_5(int index)
{
	HANDLE_CLERROR(clEnqueueReadBuffer(queue[gpu_id], mem_out, CL_FALSE, 0,
		outsize, ghash, 0, NULL, NULL), "Copy data back");
	HANDLE_CLERROR(clFinish(queue[gpu_id]), "clFinish error");

	return ((uint64_t*)ghash)[hash_addr(0, index)] & 0xFFFFFF;
}

static int get_hash_6(int index)
{
	HANDLE_CLERROR(clEnqueueReadBuffer(queue[gpu_id], mem_out, CL_FALSE, 0,
		outsize, ghash, 0, NULL, NULL), "Copy data back");
	HANDLE_CLERROR(clFinish(queue[gpu_id]), "clFinish error");

	return ((uint64_t*)ghash)[hash_addr(0, index)] & 0x7FFFFFF;
}

static void crypt_all(int count)
{
	///Copy data to GPU memory
	if (sha512_key_changed) {
		HANDLE_CLERROR(clEnqueueWriteBuffer
		    (queue[gpu_id], mem_in, CL_FALSE, 0, insize, gkey, 0, NULL,
			NULL), "Copy memin");
	}

	///Run kernel
	size_t worksize = KEYS_PER_CRYPT;
	size_t localworksize = local_work_size;
	HANDLE_CLERROR(clEnqueueNDRangeKernel
	    (queue[gpu_id], crypt_kernel, 1, NULL, &worksize, &localworksize,
		0, NULL, NULL), "Set ND range");

	///Await completion of all the above
	HANDLE_CLERROR(clFinish(queue[gpu_id]), "clFinish error");

	/// Reset key to unchanged
	sha512_key_changed = 0;
}

static int cmp_all(void *binary, int count)
{
	///Copy binary to GPU memory
	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], mem_binary, CL_FALSE,
		0, sizeof(uint64_t), ((uint64_t*)binary)+3, 0, NULL, NULL), "Copy mem_binary");

	///Run kernel
	size_t worksize = KEYS_PER_CRYPT;
	size_t localworksize = local_work_size;
	HANDLE_CLERROR(clEnqueueNDRangeKernel
	    (queue[gpu_id], cmp_kernel, 1, NULL, &worksize, &localworksize,
		0, NULL, NULL), "Set ND range");

	uint32_t result;
	/// Copy result out
	HANDLE_CLERROR(clEnqueueReadBuffer(queue[gpu_id], mem_cmp, CL_FALSE, 0,
		sizeof(uint32_t), &result, 0, NULL, NULL), "Copy data back");

	///Await completion of all the above
	HANDLE_CLERROR(clFinish(queue[gpu_id]), "clFinish error");
	return result;
	
}

static int cmp_one(void *binary, int index)
{
	HANDLE_CLERROR(clEnqueueReadBuffer(queue[gpu_id], mem_out, CL_FALSE, 0,
		outsize, ghash, 0, NULL, NULL), "Copy data back");
	HANDLE_CLERROR(clFinish(queue[gpu_id]), "clFinish error");

	uint64_t *b = (uint64_t *) binary;
	uint64_t *t = (uint64_t *)ghash;
	if (b[3] != t[hash_addr(0, index)])
		return 0;
	return 1;
}

static int cmp_exact(char *source, int index)
{
	SHA512_CTX ctx;
	uint64_t crypt_out[8];
	
	SHA512_Init(&ctx);
	SHA512_Update(&ctx, gkey[index].v, gkey[index].length);
	SHA512_Final((unsigned char *)(crypt_out), &ctx);	

	int i;
	uint64_t *b = (uint64_t *)get_binary(source);
	uint64_t *c = (uint64_t *)crypt_out;

	for (i = 0; i < 8; i++) {
		uint64_t t = SWAP64(c[i])-H[i];
		c[i] = SWAP64(t);
	}

	
	for (i = 0; i < FULL_BINARY_SIZE / 8; i++) { //examin 512bits
		if (b[i] != c[i])
			return 0;
	}
	return 1;

}

struct fmt_main fmt_opencl_rawsha512 = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
		SALT_SIZE,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT,
		tests
	}, {
		init,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		get_binary,
		fmt_default_salt,
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
#else
#ifdef __GNUC__
#warning Note: Mac OS X Lion format disabled - it needs OpenSSL 0.9.8 or above
#endif
#endif


