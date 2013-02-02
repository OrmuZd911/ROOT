/*
 * Developed by Claudio André <claudio.andre at correios.net.br> in 2012
 * Based on source code provided by Samuele Giovanni Tonon
 *
 * More information at http://openwall.info/wiki/john/OpenCL-RAWSHA-256
 *
 * Copyright (c) 2011 Samuele Giovanni Tonon <samu at linuxasylum dot net>
 * Copyright (c) 2012 Claudio André <claudio.andre at correios.net.br>
 * This program comes with ABSOLUTELY NO WARRANTY; express or implied .
 * This is free software, and you are welcome to redistribute it
 * under certain conditions; as expressed here
 * http://www.gnu.org/licenses/gpl-2.0.html
 */

#include <string.h>
#include "sha.h"
#include "sha2.h"
#include "common-opencl.h"
#include "config.h"
#include "opencl_rawsha256.h"

#define FORMAT_LABEL			"raw-sha256-opencl"
#define FORMAT_NAME			"Raw SHA-256 (pwlen < " PLAINTEXT_TEXT ")"
#define ALGORITHM_NAME			"OpenCL (inefficient, development use mostly)"

#define BENCHMARK_COMMENT		""
#define BENCHMARK_LENGTH		-1

#define CONFIG_NAME			"rawsha256"

static sha256_password			* plaintext;			// plaintext ciphertexts
static uint32_t				* calculated_hash;		// calculated (partial) hashes

static cl_mem pass_buffer;		//Plaintext buffer.
static cl_mem hash_buffer;		//Partial hash keys (output).
static cl_mem p_binary_buffer;		//To compare partial binary ([3]).
static cl_mem result_buffer;		//To get the if a hash was found.
static cl_mem pinned_saved_keys, pinned_partial_hashes;

static cl_kernel cmp_kernel;

static int hash_found;

static int crypt_all(int *pcount, struct db_salt *_salt);
static int crypt_all_benchmark(int *pcount, struct db_salt *_salt);

static struct fmt_tests tests[] = {
	{"5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8", "password"},
	{"$SHA256$ef797c8118f02dfb649607dd5d3f8c7623048c9c063d532cc95c5ed7a898a64f", "12345678"},
	{"$SHA256$e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", ""},
#ifdef DEBUG //Special test cases.
	{"a49c2c9d0c006c8cb55a9a7a38822b83e0cd442614cb416af952fa50156761dc", "openwall"},
#endif
	{NULL}
};

/* ------- Helper functions ------- */
static size_t get_task_max_work_group_size(){

	return common_get_task_max_work_group_size(FALSE, 0, crypt_kernel);
}

static size_t get_task_max_size(){

	return common_get_task_max_size(1,
		KEYS_PER_CORE_CPU, KEYS_PER_CORE_GPU, crypt_kernel);
}

static size_t get_default_workgroup(){

	if (cpu(device_info[ocl_gpu_id]))
		return 1;
	else
		return 128;
}

static void crypt_one(int index, sha256_hash * hash) {
	SHA256_CTX ctx;

	SHA256_Init(&ctx);
	SHA256_Update(&ctx, plaintext[index].pass, plaintext[index].length);
	SHA256_Final((unsigned char *) (hash), &ctx);
}

/* ------- Create and destroy necessary objects ------- */
static void create_clobj(int gws, struct fmt_main * self) {
	self->params.min_keys_per_crypt = self->params.max_keys_per_crypt = gws;

	pinned_saved_keys = clCreateBuffer(context[ocl_gpu_id],
			CL_MEM_READ_WRITE | CL_MEM_ALLOC_HOST_PTR,
			sizeof(sha256_password) * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating page-locked memory pinned_saved_keys");

	plaintext = (sha256_password *) clEnqueueMapBuffer(queue[ocl_gpu_id],
			pinned_saved_keys, CL_TRUE, CL_MAP_WRITE | CL_MAP_READ, 0,
			sizeof(sha256_password) * gws, 0, NULL, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping page-locked memory saved_plain");

	pinned_partial_hashes = clCreateBuffer(context[ocl_gpu_id],
			CL_MEM_READ_WRITE | CL_MEM_ALLOC_HOST_PTR,
			sizeof(uint32_t) * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating page-locked memory pinned_partial_hashes");

	calculated_hash = (uint32_t *) clEnqueueMapBuffer(queue[ocl_gpu_id],
			pinned_partial_hashes, CL_TRUE, CL_MAP_READ, 0,
			sizeof(uint32_t) * gws, 0, NULL, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping page-locked memory out_hashes");

	// create arguments (buffers)
	pass_buffer = clCreateBuffer(context[ocl_gpu_id], CL_MEM_READ_ONLY,
			sizeof(sha256_password) * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating buffer argument buffer_keys");

	hash_buffer = clCreateBuffer(context[ocl_gpu_id], CL_MEM_WRITE_ONLY,
			sizeof(uint32_t) * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating buffer argument hash_buffer");

	p_binary_buffer = clCreateBuffer(context[ocl_gpu_id], CL_MEM_READ_ONLY,
			sizeof(uint32_t), NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating buffer argument p_binary_buffer");

	result_buffer = clCreateBuffer(context[ocl_gpu_id], CL_MEM_READ_ONLY,
			sizeof(int), NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating buffer argument result_buffer");

	//Set kernel arguments
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 0, sizeof(cl_mem),
			(void *) &pass_buffer), "Error setting argument 0");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 1, sizeof(cl_mem),
			(void *) &hash_buffer), "Error setting argument 1");

	HANDLE_CLERROR(clSetKernelArg(cmp_kernel, 0, sizeof(cl_mem),
			(void *) &hash_buffer), "Error setting argument 0");
	HANDLE_CLERROR(clSetKernelArg(cmp_kernel, 1, sizeof(cl_mem),
			(void *) &p_binary_buffer), "Error setting argument 1");
	HANDLE_CLERROR(clSetKernelArg(cmp_kernel, 2, sizeof(cl_mem),
			(void *) &result_buffer), "Error setting argument 2");

	memset(plaintext, '\0', sizeof(sha256_password) * gws);
}

static void release_clobj(void) {
	cl_int ret_code;

	ret_code = clEnqueueUnmapMemObject(queue[ocl_gpu_id], pinned_saved_keys,
			plaintext, 0, NULL, NULL);
	HANDLE_CLERROR(ret_code, "Error Unmapping saved_plain");

	ret_code = clReleaseMemObject(pass_buffer);
	HANDLE_CLERROR(ret_code, "Error Releasing buffer_keys");
	ret_code = clReleaseMemObject(hash_buffer);
	HANDLE_CLERROR(ret_code, "Error Releasing hash_buffer");

	ret_code = clReleaseMemObject(p_binary_buffer);
	HANDLE_CLERROR(ret_code, "Error Releasing p_binary_buffer");
	ret_code = clReleaseMemObject(result_buffer);
	HANDLE_CLERROR(ret_code, "Error Releasing result_buffer");

	ret_code = clReleaseMemObject(pinned_saved_keys);
	HANDLE_CLERROR(ret_code, "Error Releasing pinned_saved_keys");
	ret_code = clReleaseMemObject(pinned_partial_hashes);
	HANDLE_CLERROR(ret_code, "Error Releasing pinned_partial_hashes");
}

/* ------- Key functions ------- */
static void set_key(char * key, int index) {
	int len;

	//Assure buffer has no "trash data".
	memset(plaintext[index].pass, '\0', PLAINTEXT_LENGTH);
	len = strlen(key);

	//Put the tranfered key on password buffer.
	memcpy(plaintext[index].pass, key, len);
	plaintext[index].length = len ;

	/* Prepare for GPU */
	plaintext[index].pass->mem_08[len] = 0x80;
}

static char * get_key(int index) {
	static char ret[PLAINTEXT_LENGTH + 1];
	memcpy(ret, plaintext[index].pass, PLAINTEXT_LENGTH);
	ret[plaintext[index].length] = '\0';
	return ret;
}

/* ------- Try to find the best configuration ------- */
/* --
  This function could be used to calculated the best num
  for the workgroup
  Work-items that make up a work-group (also referred to
  as the size of the work-group)

  For formats using __local
  LWS should never be a big number since every work-item
  uses about 400 bytes of local memory. Local memory
  is usually 32 KB.
-- */
static void find_best_lws(struct fmt_main * self, int sequential_id) {

	//Call the default function.
	common_find_best_lws(
		get_task_max_work_group_size(), sequential_id, crypt_kernel
	);
}

/* --
  This function could be used to calculated the best num
  of keys per crypt for the given format
-- */
static void find_best_gws(struct fmt_main * self, int sequential_id) {

	//Call the common function.
	common_find_best_gws(
		sequential_id, 1, STEP,
		(cpu(device_info[ocl_gpu_id]) ? 500000000ULL : 1000000000ULL)
	);

	create_clobj(global_work_size, self);
}

/* ------- Initialization  ------- */
static void init(struct fmt_main * self) {
	char * task = "$JOHN/kernels/sha256_kernel.cl";

	opencl_init_dev(ocl_gpu_id);
	opencl_build_kernel_save(task, ocl_gpu_id, NULL, 1, 1);

	// create kernel(s) to execute
	crypt_kernel = clCreateKernel(program[ocl_gpu_id], "kernel_crypt", &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating kernel. Double-check kernel name?");
	cmp_kernel = clCreateKernel(program[ocl_gpu_id], "kernel_cmp", &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating kernel_cmp. Double-check kernel name?");

	global_work_size = get_task_max_size();
	local_work_size = get_default_workgroup();
	opencl_get_user_preferences(CONFIG_NAME);

	//Initialize openCL tuning (library) for this format.
	opencl_init_auto_setup(STEP, 0, 3, NULL,
		warn, &multi_profilingEvent[1], self, create_clobj, release_clobj,
		sizeof(sha256_password));

	self->methods.crypt_all = crypt_all_benchmark;

	//Check if local_work_size is a valid number.
	if (local_work_size > get_task_max_work_group_size()){
		fprintf(stderr, "Error: invalid local worksize (LWS). Max value allowed is: %zd\n" ,
			   get_task_max_work_group_size());
		local_work_size = 0; //Force find a valid number.
	}
	self->params.max_keys_per_crypt = (global_work_size ? global_work_size: get_task_max_size());

	if (!local_work_size) {
		create_clobj(self->params.max_keys_per_crypt, self);
		find_best_lws(self, ocl_gpu_id);
		release_clobj();
	}

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

static void done(void) {
	release_clobj();

	HANDLE_CLERROR(clReleaseKernel(crypt_kernel), "Release kernel");
	HANDLE_CLERROR(clReleaseKernel(cmp_kernel), "Release kernel");
	HANDLE_CLERROR(clReleaseProgram(program[ocl_gpu_id]), "Release Program");
}

/* ------- Check if the ciphertext if a valid SHA-256 ------- */
static int valid(char * ciphertext, struct fmt_main * self) {
	char *p, *q;

	p = ciphertext;
	if (!strncmp(p, "$SHA256$", 8))
		p += 8;

	q = p;
	while (atoi16[ARCH_INDEX(*q)] != 0x7F)
		q++;
	return !*q && q - p == CIPHERTEXT_LENGTH;
}

static char *split(char *ciphertext, int index, struct fmt_main *pFmt) {

	static char out[8 + CIPHERTEXT_LENGTH + 1];

	if (!strncmp(ciphertext, "$SHA256$", 8))
		return ciphertext;

	memcpy(out, "$SHA256$", 8);
	memcpy(out + 8, ciphertext, CIPHERTEXT_LENGTH + 1);
	strlwr(out + 8);
	return out;
}

/* ------- To binary functions ------- */
static void * get_binary(char *ciphertext) {
	static unsigned char *out;
	uint32_t * b;
	char *p;
	int i;

	if (!out) out = mem_alloc_tiny(FULL_BINARY_SIZE, MEM_ALIGN_WORD);

	p = ciphertext + 8;
	for (i = 0; i < (FULL_BINARY_SIZE / 2); i++) {
		out[i] =
				(atoi16[ARCH_INDEX(*p)] << 4) |
				 atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}
	b = (uint32_t *) out;
	b[0] = SWAP32(b[3]) - H3;

	return out;
}

static void * get_full_binary(char *ciphertext) {
	static unsigned char *out;
	char *p;
	int i;

	if (!out) out = mem_alloc_tiny(FULL_BINARY_SIZE, MEM_ALIGN_WORD);

	p = ciphertext + 8;
	for (i = 0; i < FULL_BINARY_SIZE; i++) {
		out[i] =
				(atoi16[ARCH_INDEX(*p)] << 4) |
				 atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}

	return out;
}

/* ------- Crypt function ------- */
static int crypt_all_benchmark(int *pcount, struct db_salt *_salt) {
	int count = *pcount;
	size_t gws;

	gws = GET_MULTIPLE_BIGGER(count, local_work_size);

	//Send data to device.
	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[ocl_gpu_id], pass_buffer, CL_FALSE, 0,
				sizeof(sha256_password) * gws, plaintext, 0, NULL, &multi_profilingEvent[0]),
				"failed in clEnqueueWriteBuffer pass_buffer");

	//Enqueue the kernel
	HANDLE_CLERROR(clEnqueueNDRangeKernel(queue[ocl_gpu_id], crypt_kernel, 1, NULL,
			&gws, &local_work_size, 0, NULL, &multi_profilingEvent[1]),
			"failed in clEnqueueNDRangeKernel");

	//Read back hashes
	HANDLE_CLERROR(clEnqueueReadBuffer(queue[ocl_gpu_id], hash_buffer, CL_FALSE, 0,
			sizeof(uint32_t) * gws, calculated_hash, 0, NULL, &multi_profilingEvent[2]),
			"failed in reading data back");

	//Do the work
	HANDLE_CLERROR(clFinish(queue[ocl_gpu_id]), "failed in clFinish");

	return count;
}

static int crypt_all(int *pcount, struct db_salt *_salt) {
	int count = *pcount;
	size_t gws;

	gws = GET_MULTIPLE_BIGGER(count, local_work_size);

	//Send data to device.
	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[ocl_gpu_id], pass_buffer, CL_FALSE, 0,
				sizeof(sha256_password) * gws, plaintext, 0, NULL, NULL),
				"failed in clEnqueueWriteBuffer pass_buffer");

	//Enqueue the kernel
	HANDLE_CLERROR(clEnqueueNDRangeKernel(queue[ocl_gpu_id], crypt_kernel, 1, NULL,
			&gws, &local_work_size, 0, NULL, NULL),
			"failed in clEnqueueNDRangeKernel");

	//Read back hashes
	HANDLE_CLERROR(clEnqueueReadBuffer(queue[ocl_gpu_id], hash_buffer, CL_FALSE, 0,
			sizeof(uint32_t) * gws, calculated_hash, 0, NULL, NULL),
			"failed in reading data back");

	//Do the work
	HANDLE_CLERROR(clFinish(queue[ocl_gpu_id]), "failed in clFinish");

	return count;
}

/* ------- Compare functins ------- */
static int cmp_all(void * binary, int count) {
	uint32_t partial_binary;
	size_t gws;

	gws = GET_MULTIPLE_BIGGER(count, local_work_size);
	partial_binary = ((uint32_t *) binary)[0];
	hash_found = 0;

	//Send data to device.
	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[ocl_gpu_id], p_binary_buffer, CL_FALSE, 0,
			sizeof(uint32_t), &partial_binary, 0, NULL, NULL),
			"failed in clEnqueueWriteBuffer p_binary_buffer");
	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[ocl_gpu_id], result_buffer, CL_FALSE, 0,
			sizeof(int), &hash_found, 0, NULL, NULL),
			"failed in clEnqueueWriteBuffer p_binary_buffer");

	//Enqueue the kernel
	HANDLE_CLERROR(clEnqueueNDRangeKernel(queue[ocl_gpu_id], cmp_kernel, 1, NULL,
			&gws, &local_work_size, 0, NULL, NULL),
			"failed in clEnqueueNDRangeKernel");

	//Read results back.
	HANDLE_CLERROR(clEnqueueReadBuffer(queue[ocl_gpu_id], result_buffer, CL_FALSE, 0,
			sizeof(int), &hash_found, 0, NULL, NULL),
			"failed in reading data back");

	//Do the work
	HANDLE_CLERROR(clFinish(queue[ocl_gpu_id]), "failed in clFinish");

	return hash_found;
}

static int cmp_one(void *binary, int index) {
	return (calculated_hash[index] == ((uint32_t *) binary)[0]);
}

static int cmp_exact(char *source, int index) {
	//I don't know why, but this is called and i have to recheck.
	//If i skip this final test i get:
	//form=raw-sha512-ng-opencl	 guesses: 1468 time: 0:00:00:02 : Expected count(s) (1500)  [!!!FAILED!!!]
	//.pot CHK:raw-sha512-ng-opencl	 guesses: 1452 time: 0:00:00:02 : Expected count(s) (1500)  [!!!FAILED!!!]

	uint32_t * binary;
	sha256_hash full_hash;

	crypt_one(index, &full_hash);

	binary = (uint32_t *) get_full_binary(source);
	return !memcmp(binary, (void *) &full_hash, FULL_BINARY_SIZE);
}

/* ------- Binary Hash functions group ------- */
#ifdef DEBUG
static void print_binary(void * binary) {
	uint32_t *bin = binary;
	int i;

	for (i = 0; i < 8; i++)
		fprintf(stderr, "%08x ", bin[i]);
	puts("(Ok)");
}

static void print_hash(int index) {
	fprintf(stderr, "\n");
	fprintf(stderr, "%08x ", calculated_hash[index]);
	puts("");
}
#endif

static int binary_hash_0(void * binary) {
#ifdef DEBUG
	print_binary(binary);
#endif
	return *(ARCH_WORD_32 *) binary & 0xF;
}
static int binary_hash_1(void * binary) { return *(ARCH_WORD_32 *) binary & 0xFF; }
static int binary_hash_2(void * binary) { return *(ARCH_WORD_32 *) binary & 0xFFF; }
static int binary_hash_3(void * binary) { return *(ARCH_WORD_32 *) binary & 0xFFFF; }
static int binary_hash_4(void * binary) { return *(ARCH_WORD_32 *) binary & 0xFFFFF; }
static int binary_hash_5(void * binary) { return *(ARCH_WORD_32 *) binary & 0xFFFFFF; }
static int binary_hash_6(void * binary) { return *(ARCH_WORD_32 *) binary & 0x7FFFFFF; }

//Get Hash functions group.
static int get_hash_0(int index) {
#ifdef DEBUG
	print_hash(index);
#endif
	return calculated_hash[index] & 0xF;
}
static int get_hash_1(int index) { return calculated_hash[index] & 0xFF; }
static int get_hash_2(int index) { return calculated_hash[index] & 0xFFF; }
static int get_hash_3(int index) { return calculated_hash[index] & 0xFFFF; }
static int get_hash_4(int index) { return calculated_hash[index] & 0xFFFFF; }
static int get_hash_5(int index) { return calculated_hash[index] & 0xFFFFFF; }
static int get_hash_6(int index) { return calculated_hash[index] & 0x7FFFFFF; }

/* ------- Format structure ------- */
struct fmt_main fmt_opencl_rawsha256 = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		PLAINTEXT_LENGTH - 1,
		BINARY_SIZE,
		BINARY_ALIGN,
		SALT_SIZE,
		SALT_ALIGN,
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