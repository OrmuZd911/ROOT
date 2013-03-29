/*
 * Developed by Claudio André <claudio.andre at correios.net.br> in 2012
 * Based on source code provided by Samuele Giovanni Tonon
 *
 * More information at http://openwall.info/wiki/john/OpenCL-RAWSHA-512
 * More information at http://openwall.info/wiki/john/OpenCL-XSHA-512
 *
 * Note: using myrice idea.
 * Please note that in current comparison function, we use computed a77
 * compares with ciphertext d80. For more details, refer to:
 * http://www.openwall.com/lists/john-dev/2012/04/11/13
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
#include "opencl_rawsha512-ng.h"

#define RAW_FORMAT_LABEL		"raw-sha512-ng-opencl"
#define RAW_FORMAT_NAME			"Raw SHA-512 (pwlen < " PLAINTEXT_TEXT ")"
#define X_FORMAT_LABEL			"xsha512-ng-opencl"
#define X_FORMAT_NAME			"Mac OS X 10.7+ salted SHA-512 (pwlen < " PLAINTEXT_TEXT ")"

#define ALGORITHM_NAME			"OpenCL (inefficient, development use mostly)"

#define BENCHMARK_COMMENT		""
#define RAW_BENCHMARK_LENGTH		-1
#define X_BENCHMARK_LENGTH		0

#define CONFIG_NAME			"rawsha512"

static sha512_salt			* salt;
static uint32_t				* plaintext, * saved_idx;	// plaintext ciphertexts
static uint32_t				* calculated_hash;		// calculated (partial) hashes

static cl_mem salt_buffer;		//Salt information.
static cl_mem pass_buffer;		//Plaintext buffer.
static cl_mem hash_buffer;		//Partial hash keys (output).
static cl_mem idx_buffer;		//Sizes and offsets buffer.
static cl_mem p_binary_buffer;		//To compare partial binary ([3]).
static cl_mem result_buffer;		//To get the if a hash was found.
static cl_mem pinned_saved_keys, pinned_saved_idx, pinned_partial_hashes;

static cl_kernel cmp_kernel;
static int new_keys, hash_found, salted_format = 0;
static uint32_t key_idx = 0;
static size_t offset = 0, offset_idx = 0;

static int crypt_all(int *pcount, struct db_salt *_salt);
static int crypt_all_benchmark(int *pcount, struct db_salt *_salt);

static struct fmt_tests raw_tests[] = {
	{"b109f3bbbc244eb82441917ed06d618b9008dd09b3befd1b5e07394c706a8bb980b1d7785e5976ec049b46df5f1326af5a2ea6d103fd07c95385ffab0cacbc86", "password"},
	{"$SHA512$fa585d89c851dd338a70dcf535aa2a92fee7836dd6aff1226583e88e0996293f16bc009c652826e0fc5c706695a03cddce372f139eff4d13959da6f1f5d3eabe", "12345678"},
	{"$SHA512$cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e", ""},
#ifdef DEBUG //Special test cases.
	{"2c80f4c2b3db6b677d328775be4d38c8d8cd9a4464c3b6273644fb148f855e3db51bc33b54f3f6fa1f5f52060509f0e4d350bb0c7f51947728303999c6eff446", "john-user"},
	{"12b03226a6d8be9c6e8cd5e55dc6c7920caaa39df14aab92d5e3ea9340d1c8a4d3d0b8e4314f1f6ef131ba4bf1ceb9186ab87c801af0d5c95b1befb8cedae2b9", "1234567890"},
	{"aa3b7bdd98ec44af1f395bbd5f7f27a5cd9569d794d032747323bf4b1521fbe7725875a68b440abdf0559de5015baf873bb9c01cae63ecea93ad547a7397416e", "12345678901234567890"},
	{"eba392e2f2094d7ffe55a23dffc29c412abd47057a0823c6c149c9c759423afde56f0eef73ade8f79bc1d16a99cbc5e4995afd8c14adb49410ecd957aecc8d02", "123456789012345678901234567890"},
	{"3a8529d8f0c7b1ad2fa54c944952829b718d5beb4ff9ba8f4a849e02fe9a272daf59ae3bd06dde6f01df863d87c8ba4ab016ac576b59a19078c26d8dbe63f79e", "1234567890123456789012345678901234567890"},
	{"49c1faba580a55d6473f427174b62d8aa68f49958d70268eb8c7f258ba5bb089b7515891079451819aa4f8bf75b784dc156e7400ab0a04dfd2b75e46ef0a943e", "12345678901234567890123456789012345678901234567890"},
	{"8c5b51368ec88e1b1c4a67aa9de0aa0919447e142a9c245d75db07bbd4d00962b19112adb9f2b52c0a7b29fe2de661a872f095b6a1670098e5c7fde4a3503896", "123456789012345678901234567890123456789012345678901"},
	{"35ea7bc1d848db0f7ff49178392bf58acfae94bf74d77ae2d7e978df52aac250ff2560f9b98dc7726f0b8e05b25e5132074b470eb461c4ebb7b4d8bf9ef0d93f", "1234567890123456789012345678901234567890123456789012345"},
#endif
	{NULL}
};

static struct fmt_tests x_tests[] = {
	{"$LION$bb0489df7b073e715f19f83fd52d08ede24243554450f7159dd65c100298a5820525b55320f48182491b72b4c4ba50d7b0e281c1d98e06591a5e9c6167f42a742f0359c7", "password"},
	{"$LION$74911f723bd2f66a3255e0af4b85c639776d510b63f0b939c432ab6e082286c47586f19b4e2f3aab74229ae124ccb11e916a7a1c9b29c64bd6b0fd6cbd22e7b1f0ba1673", "hello"},
	{"5e3ab14c8bd0f210eddafbe3c57c0003147d376bf4caf75dbffa65d1891e39b82c383d19da392d3fcc64ea16bf8203b1fc3f2b14ab82c095141bb6643de507e18ebe7489", "boobies"},
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
		return 64;
}

static void crypt_one(int index, sha512_hash * hash) {
	SHA512_CTX ctx;

	int len = saved_idx[index] & 63;
	char * key = (char *) &plaintext[saved_idx[index] >> 6];

	SHA512_Init(&ctx);
	SHA512_Update(&ctx, key, len);
	SHA512_Final((unsigned char *) (hash), &ctx);
}

static void crypt_one_x(int index, sha512_hash * hash) {
	SHA512_CTX ctx;

	int len = saved_idx[index] & 63;
	char * key = (char *) &plaintext[saved_idx[index] >> 6];

	SHA512_Init(&ctx);
	SHA512_Update(&ctx, (char *) &salt->salt, SALT_SIZE_X);
	SHA512_Update(&ctx, key, len);
	SHA512_Final((unsigned char *) (hash), &ctx);
}

/* ------- Create and destroy necessary objects ------- */
static void create_clobj(int gws, struct fmt_main * self) {
	int position = 0;

	self->params.min_keys_per_crypt = self->params.max_keys_per_crypt = gws;

	pinned_saved_keys = clCreateBuffer(context[ocl_gpu_id],
			CL_MEM_READ_ONLY | CL_MEM_ALLOC_HOST_PTR,
			BUFFER_SIZE * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating page-locked memory pinned_saved_keys");

	plaintext = (uint32_t *) clEnqueueMapBuffer(queue[ocl_gpu_id],
			pinned_saved_keys, CL_TRUE, CL_MAP_WRITE, 0,
			BUFFER_SIZE * gws, 0, NULL, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping page-locked memory plaintext");

	pinned_saved_idx = clCreateBuffer(context[ocl_gpu_id],
			CL_MEM_READ_ONLY | CL_MEM_ALLOC_HOST_PTR,
			sizeof(uint32_t) * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating page-locked memory pinned_saved_idx");

	saved_idx = (uint32_t *) clEnqueueMapBuffer(queue[ocl_gpu_id],
			pinned_saved_idx, CL_TRUE, CL_MAP_WRITE, 0,
			sizeof(uint32_t) * gws, 0, NULL, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping page-locked memory saved_idx");

	pinned_partial_hashes = clCreateBuffer(context[ocl_gpu_id],
			CL_MEM_WRITE_ONLY | CL_MEM_ALLOC_HOST_PTR,
			sizeof(uint32_t) * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating page-locked memory pinned_partial_hashes");

	calculated_hash = (uint32_t *) clEnqueueMapBuffer(queue[ocl_gpu_id],
			pinned_partial_hashes, CL_TRUE, CL_MAP_READ, 0,
			sizeof(uint32_t) * gws, 0, NULL, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping page-locked memory out_hashes");

	// create arguments (buffers)
	salt_buffer = clCreateBuffer(context[ocl_gpu_id], CL_MEM_READ_ONLY,
			sizeof(sha512_salt), NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating salt_buffer out argument");

	pass_buffer = clCreateBuffer(context[ocl_gpu_id], CL_MEM_READ_ONLY,
			BUFFER_SIZE * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating buffer argument pass_buffer");

	idx_buffer = clCreateBuffer(context[ocl_gpu_id], CL_MEM_READ_ONLY,
		sizeof(uint32_t) * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating buffer argument idx_buffer");

	hash_buffer = clCreateBuffer(context[ocl_gpu_id], CL_MEM_WRITE_ONLY,
			sizeof(uint32_t) * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating buffer argument hash_buffer");

	p_binary_buffer = clCreateBuffer(context[ocl_gpu_id], CL_MEM_READ_ONLY,
			sizeof(uint32_t), NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating buffer argument p_binary_buffer");

	result_buffer = clCreateBuffer(context[ocl_gpu_id], CL_MEM_READ_WRITE,
			sizeof(int), NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating buffer argument result_buffer");

	//Set kernel arguments
	if (salted_format) {
		HANDLE_CLERROR(clSetKernelArg(crypt_kernel, position++, sizeof(cl_mem),
			(void *) &salt_buffer), "Error setting argument 0");
	}
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, position++, sizeof(cl_mem),
			(void *) &pass_buffer), "Error setting argument p0");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, position++, sizeof(cl_mem),
			(void *) &idx_buffer), "Error setting argument p1");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, position++, sizeof(cl_mem),
			(void *) &hash_buffer), "Error setting argument p2");

	HANDLE_CLERROR(clSetKernelArg(cmp_kernel, 0, sizeof(cl_mem),
			(void *) &hash_buffer), "Error setting argument 0");
	HANDLE_CLERROR(clSetKernelArg(cmp_kernel, 1, sizeof(cl_mem),
			(void *) &p_binary_buffer), "Error setting argument 1");
	HANDLE_CLERROR(clSetKernelArg(cmp_kernel, 2, sizeof(cl_mem),
			(void *) &result_buffer), "Error setting argument 2");

	memset(plaintext, '\0', BUFFER_SIZE * gws);
	memset(saved_idx, '\0', sizeof(uint32_t) * gws);
}

static void release_clobj(void) {
	cl_int ret_code;

	ret_code = clEnqueueUnmapMemObject(queue[ocl_gpu_id], pinned_saved_keys,
			plaintext, 0, NULL, NULL);
	HANDLE_CLERROR(ret_code, "Error Unmapping keys");
	ret_code = clEnqueueUnmapMemObject(queue[ocl_gpu_id], pinned_saved_idx,
			saved_idx, 0, NULL, NULL);
	HANDLE_CLERROR(ret_code, "Error Unmapping indexes");
	ret_code = clEnqueueUnmapMemObject(queue[ocl_gpu_id], pinned_partial_hashes,
			calculated_hash, 0, NULL, NULL);
	HANDLE_CLERROR(ret_code, "Error Unmapping partial hashes");

	ret_code = clReleaseMemObject(salt_buffer);
	HANDLE_CLERROR(ret_code, "Error Releasing salt_buffer");
	ret_code = clReleaseMemObject(pass_buffer);
	HANDLE_CLERROR(ret_code, "Error Releasing buffer_keys");
	ret_code = clReleaseMemObject(hash_buffer);
	HANDLE_CLERROR(ret_code, "Error Releasing hash_buffer");
	ret_code = clReleaseMemObject(idx_buffer);
	HANDLE_CLERROR(ret_code, "Error Releasing idx_buffer");

	ret_code = clReleaseMemObject(p_binary_buffer);
	HANDLE_CLERROR(ret_code, "Error Releasing p_binary_buffer");
	ret_code = clReleaseMemObject(result_buffer);
	HANDLE_CLERROR(ret_code, "Error Releasing result_buffer");

	ret_code = clReleaseMemObject(pinned_saved_keys);
	HANDLE_CLERROR(ret_code, "Error Releasing pinned_saved_keys");
	ret_code = clReleaseMemObject(pinned_saved_idx);
	HANDLE_CLERROR(ret_code, "Error Releasing pinned_saved_idx");
	ret_code = clReleaseMemObject(pinned_partial_hashes);
	HANDLE_CLERROR(ret_code, "Error Releasing pinned_partial_hashes");
}

/* ------- Salt functions ------- */
static void * get_salt(char *ciphertext) {
	static unsigned char out[SALT_SIZE_X];
	char *p;
	int i;

	ciphertext += 6;
	p = ciphertext;
	for (i = 0; i < sizeof (out); i++) {
		out[i] =
				(atoi16[ARCH_INDEX(*p)] << 4) |
				atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}

	return out;
}

static void set_salt(void * salt_info) {

	salt = salt_info;

	//Send salt information to GPU.
	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[ocl_gpu_id], salt_buffer, CL_FALSE, 0,
		sizeof(sha512_salt), salt, 0, NULL, NULL),
		"failed in clEnqueueWriteBuffer salt_buffer");
	HANDLE_CLERROR(clFlush(queue[ocl_gpu_id]), "failed in clFlush");
}

static int salt_hash(void * salt) {

	return common_salt_hash(salt, SALT_SIZE_X, SALT_HASH_SIZE);
}

/* ------- Key functions ------- */
static void clear_keys(void) {
	offset = 0;
	offset_idx = 0;
	key_idx = 0;
}

static void set_key(char * _key, int index) {
	int len = 0;

	const uint32_t * key = (uint32_t *) _key;

	while (*(_key++))
		len++;

	saved_idx[index] = (key_idx << 6) | len;

	while (len > 4) {
		plaintext[key_idx++] = *key++;
		len -= 4;
	}

	if (len)
		plaintext[key_idx++] = *key;

	//Batch transfers to GPU.
	if ((index % TRANSFER_SIZE) == 0 && (index > 0)) {
	    	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[ocl_gpu_id], pass_buffer,
			CL_FALSE, sizeof(uint32_t) * offset,
			sizeof(uint32_t) * TRANSFER_SIZE,
			plaintext + offset, 0, NULL, NULL),
			"failed in clEnqueueWriteBuffer pass_buffer");
	    	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[ocl_gpu_id], idx_buffer,
			CL_FALSE, sizeof(uint32_t) * offset,
			sizeof(uint32_t) * TRANSFER_SIZE,
			saved_idx + offset, 0, NULL, NULL),
			"failed in clEnqueueWriteBuffer idx_buffer");

		HANDLE_CLERROR(clFlush(queue[ocl_gpu_id]), "failed in clFlush");
		offset += TRANSFER_SIZE;
		offset_idx = key_idx;
	}
	new_keys = 1;
}

static char * get_key(int index) {
	static char ret[PLAINTEXT_LENGTH + 1];
	int len = saved_idx[index] & 63;
	char * key = (char *) &plaintext[saved_idx[index] >> 6];

	memcpy(ret, key, PLAINTEXT_LENGTH);
	ret[len] = '\0';

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
	char * task = "$JOHN/kernels/sha512-ng_kernel.cl";
	size_t gws_limit;

	opencl_init_dev(ocl_gpu_id);
	opencl_build_kernel_save(task, ocl_gpu_id, NULL, 1, 1);

	// create kernel(s) to execute
	if (salted_format)
		crypt_kernel = clCreateKernel(program[ocl_gpu_id], "kernel_crypt_xsha", &ret_code);
	else
		crypt_kernel = clCreateKernel(program[ocl_gpu_id], "kernel_crypt_raw", &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating kernel. Double-check kernel name?");
	cmp_kernel = clCreateKernel(program[ocl_gpu_id], "kernel_cmp", &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating kernel_cmp. Double-check kernel name?");

	global_work_size = get_task_max_size();
	local_work_size = get_default_workgroup();
	opencl_get_user_preferences(CONFIG_NAME);

	gws_limit = MIN((0xf << 22) * 4 / BUFFER_SIZE,
			get_max_mem_alloc_size(ocl_gpu_id) / BUFFER_SIZE);

	//Initialize openCL tuning (library) for this format.
	opencl_init_auto_setup(STEP, 0, 4, NULL,
		warn, &multi_profilingEvent[1], self, create_clobj, release_clobj,
		BUFFER_SIZE, gws_limit);

	self->methods.crypt_all = crypt_all_benchmark;

	//Check if local_work_size is a valid number.
	if (local_work_size > get_task_max_work_group_size()){
		fprintf(stderr, "Error: invalid local worksize (LWS). Max value allowed is: %zd\n" ,
			   get_task_max_work_group_size());
		local_work_size = 0; //Force find a valid number.
	}
	self->params.max_keys_per_crypt = (global_work_size ? global_work_size: get_task_max_size());

	if (!local_work_size) {
		local_work_size = get_task_max_work_group_size();
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
	//Limit worksize using index limitation.
	while (global_work_size > gws_limit)
		global_work_size -= local_work_size;

	fprintf(stderr, "Local worksize (LWS) %zd, global worksize (GWS) %zd\n",
		   local_work_size, global_work_size);
	self->params.min_keys_per_crypt = local_work_size;
	self->params.max_keys_per_crypt = global_work_size;
	self->methods.crypt_all = crypt_all;
}

static void init_x(struct fmt_main * self) {
	salted_format = 1;
	init(self);
}

static void done(void) {
	release_clobj();

	HANDLE_CLERROR(clReleaseKernel(crypt_kernel), "Release kernel");
	HANDLE_CLERROR(clReleaseKernel(cmp_kernel), "Release kernel");
	HANDLE_CLERROR(clReleaseProgram(program[ocl_gpu_id]), "Release Program");
}

/* ------- Check if the ciphertext if a valid SHA-512 ------- */
static int valid(char * ciphertext, struct fmt_main * self) {
	char *p, *q;

	p = ciphertext;
	if (!strncmp(p, "$SHA512$", 8))
		p += 8;

	q = p;
	while (atoi16[ARCH_INDEX(*q)] != 0x7F)
		q++;
	return !*q && q - p == CIPHERTEXT_LENGTH_RAW;
}

static char *split(char *ciphertext, int index, struct fmt_main *pFmt) {

	static char out[8 + CIPHERTEXT_LENGTH_RAW + 1];

	if (!strncmp(ciphertext, "$SHA512$", 8))
		return ciphertext;

	memcpy(out, "$SHA512$", 8);
	memcpy(out + 8, ciphertext, CIPHERTEXT_LENGTH_RAW + 1);
	strlwr(out + 8);
	return out;
}

static int valid_x(char * ciphertext, struct fmt_main * self) {
	char *p, *q;

	p = ciphertext;
	if (!strncmp(p, "$LION$", 6))
		p += 6;

	q = p;
	while (atoi16[ARCH_INDEX(*q)] != 0x7F)
		q++;
	return !*q && q - p == CIPHERTEXT_LENGTH_X;
}

static char *split_x(char *ciphertext, int index, struct fmt_main *pFmt) {
	static char out[8 + CIPHERTEXT_LENGTH_X + 1];

	if (!strncmp(ciphertext, "$LION$", 6))
		return ciphertext;

	memcpy(out, "$LION$", 6);
	memcpy(out + 6, ciphertext, CIPHERTEXT_LENGTH_X + 1);
	strlwr(out + 6);
	return out;
}

/* ------- To binary functions ------- */
static void * get_binary(char *ciphertext) {
	static unsigned char *out;
	uint64_t * b;
	char *p;
	int i;

	if (!out) out = mem_alloc_tiny(FULL_BINARY_SIZE, MEM_ALIGN_WORD);

	if (salted_format)
		ciphertext += 6;

	p = ciphertext + 8;
	for (i = 0; i < FULL_BINARY_SIZE; i++) {
		out[i] =
				(atoi16[ARCH_INDEX(*p)] << 4) |
				 atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}
	b = (uint64_t *) out;
	b[0] = SWAP64((unsigned long long) b[3]) - H3;

	return out;
}

static void * get_full_binary(char *ciphertext) {
	static unsigned char *out;
	char *p;
	int i;

	if (!out) out = mem_alloc_tiny(FULL_BINARY_SIZE, MEM_ALIGN_WORD);

	if (salted_format)
		ciphertext += 6;

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
	if (new_keys)
		BENCH_CLERROR(clEnqueueWriteBuffer(queue[ocl_gpu_id], pass_buffer, CL_FALSE,
			sizeof(uint32_t) * offset,
			sizeof(uint32_t) * (key_idx - offset),
			plaintext + offset, 0, NULL, &multi_profilingEvent[0]),
			"failed in clEnqueueWriteBuffer pass_buffer");

	BENCH_CLERROR(clEnqueueWriteBuffer(queue[ocl_gpu_id], idx_buffer, CL_FALSE,
		sizeof(uint32_t) * offset,
		sizeof(uint32_t) * (gws - offset),
		saved_idx + offset, 0, NULL, &multi_profilingEvent[3]),
		"failed in clEnqueueWriteBuffer idx_buffer");

	//Enqueue the kernel
	BENCH_CLERROR(clEnqueueNDRangeKernel(queue[ocl_gpu_id], crypt_kernel, 1, NULL,
			&gws, &local_work_size, 0, NULL, &multi_profilingEvent[1]),
			"failed in clEnqueueNDRangeKernel");

	//Read back hashes
	BENCH_CLERROR(clEnqueueReadBuffer(queue[ocl_gpu_id], hash_buffer, CL_FALSE, 0,
			sizeof(uint32_t) * gws, calculated_hash, 0, NULL, &multi_profilingEvent[2]),
			"failed in reading data back");

	//Do the work
	BENCH_CLERROR(clFinish(queue[ocl_gpu_id]), "failed in clFinish");
	new_keys = 0;

	return count;
}

static int crypt_all(int *pcount, struct db_salt *_salt) {
	int count = *pcount;
	size_t gws;

	gws = GET_MULTIPLE_BIGGER(count, local_work_size);

	//Send data to device.
	if (new_keys)
		HANDLE_CLERROR(clEnqueueWriteBuffer(queue[ocl_gpu_id], pass_buffer, CL_FALSE,
			sizeof(uint32_t) * offset,
			sizeof(uint32_t) * (key_idx - offset),
			plaintext + offset, 0, NULL, NULL),
			"failed in clEnqueueWriteBuffer pass_buffer");

	BENCH_CLERROR(clEnqueueWriteBuffer(queue[ocl_gpu_id], idx_buffer, CL_FALSE,
		sizeof(uint32_t) * offset,
		sizeof(uint32_t) * (gws - offset),
		saved_idx + offset, 0, NULL, NULL),
		"failed in clEnqueueWriteBuffer idx_buffer");

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
	new_keys = 0;

	return count;
}

/* ------- Compare functins ------- */
static int cmp_all(void * binary, int count) {
	uint32_t partial_binary;
	size_t gws;

	gws = GET_MULTIPLE_BIGGER(count, local_work_size);
	partial_binary = (int) ((uint64_t *) binary)[0];
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
	return (calculated_hash[index] == (int) ((uint64_t *) binary)[0]);
}

static int cmp_exact(char *source, int index) {
	//I don't know why, but this is called and i have to recheck.
	//If i skip this final test i get:
	//form=raw-sha512-ng-opencl	 guesses: 1468 time: 0:00:00:02 : Expected count(s) (1500)  [!!!FAILED!!!]
	//.pot CHK:raw-sha512-ng-opencl	 guesses: 1452 time: 0:00:00:02 : Expected count(s) (1500)  [!!!FAILED!!!]

	uint64_t * binary;
	sha512_hash full_hash;

	crypt_one(index, &full_hash);

	binary = (uint64_t *) get_full_binary(source);
	return !memcmp(binary, (void *) &full_hash, FULL_BINARY_SIZE);
}

static int cmp_exact_x(char *source, int index) {
	//I don't know why, but this is called and i have to recheck.
	//If i skip this final test i get:
	//form=raw-sha512-ng-opencl		 guesses: 1468 time: 0:00:00:02 : Expected count(s) (1500)  [!!!FAILED!!!]
	//.pot CHK:raw-sha512-ng-opencl	 guesses: 1452 time: 0:00:00:02 : Expected count(s) (1500)  [!!!FAILED!!!]

	uint64_t * binary;
	sha512_hash full_hash;

	crypt_one_x(index, &full_hash);

	binary = (uint64_t *) get_full_binary(source);
	return !memcmp(binary, (void *) &full_hash, FULL_BINARY_SIZE);
}

/* ------- Binary Hash functions group ------- */
#ifdef DEBUG
static void print_binary(void * binary) {
	uint64_t *bin = binary;
	uint64_t tmp = bin[0] + H3;
	tmp = SWAP64(tmp);

	fprintf(stderr, "%016lx ", bin[0]);
	fprintf(stderr, "%016lx \n", tmp);
	puts("(Ok)");
}

static void print_hash(int index) {
	int i;
	sha512_hash hash;
	crypt_one(index, &hash);

	fprintf(stderr, "\n");
	for (i = 0; i < 8; i++)
		fprintf(stderr, "%016lx ", hash.v[i]);
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
struct fmt_main fmt_opencl_rawsha512_ng = {
	{
		RAW_FORMAT_LABEL,
		RAW_FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		RAW_BENCHMARK_LENGTH,
		PLAINTEXT_LENGTH - 1,
		BINARY_SIZE,
		BINARY_ALIGN,
		SALT_SIZE_RAW,
		SALT_ALIGN_RAW,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT | FMT_SPLIT_UNIFIES_CASE,
		raw_tests
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

struct fmt_main fmt_opencl_xsha512_ng = {
	{
		X_FORMAT_LABEL,
		X_FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		X_BENCHMARK_LENGTH,
		PLAINTEXT_LENGTH - 1,
		BINARY_SIZE,
		BINARY_ALIGN,
		SALT_SIZE_X,
		SALT_ALIGN_X,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT | FMT_SPLIT_UNIFIES_CASE,
		x_tests
	}, {
		init_x,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		valid_x,
		split_x,
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
		salt_hash,
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
		cmp_exact_x
	}
};