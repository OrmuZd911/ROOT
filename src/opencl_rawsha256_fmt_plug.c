/*
 * Developed by Claudio André <claudioandre.br at gmail.com> in 2012
 * Based on source code provided by Samuele Giovanni Tonon
 *
 * More information at http://openwall.info/wiki/john/OpenCL-RAWSHA-256
 * More information at http://openwall.info/wiki/john/OpenCL-CISCO4
 *
 * Copyright (c) 2011 Samuele Giovanni Tonon <samu at linuxasylum dot net>
 * Copyright (c) 2012-2015 Claudio André <claudioandre.br at gmail.com>
 * This program comes with ABSOLUTELY NO WARRANTY; express or implied .
 * This is free software, and you are welcome to redistribute it
 * under certain conditions; as expressed here
 * http://www.gnu.org/licenses/gpl-2.0.html
 */

#ifdef HAVE_OPENCL

#if FMT_EXTERNS_H
extern struct fmt_main fmt_opencl_rawsha256;
#elif FMT_REGISTERS_H
john_register_one(&fmt_opencl_rawsha256);
#else

#include <string.h>

#include "common-opencl.h"
#include "config.h"
#include "options.h"
#include "opencl_rawsha256.h"
#include "rawSHA256_common.h"
#include "mask_ext.h"
#include "opencl_mask_extras.h"

#define FORMAT_LABEL			"Raw-SHA256-opencl"
#define FORMAT_NAME			""

#define ALGORITHM_NAME			"SHA256 OpenCL"

//plaintext: keys to compute the hash function
//saved_idx: offset and length of each plaintext (data is sent using chunks)
static uint32_t				* plaintext, * saved_idx;

static cl_mem pass_buffer;		//Plaintext buffer.
static cl_mem idx_buffer;		//Sizes and offsets buffer.

//Pinned buffers
static cl_mem pinned_plaintext, pinned_saved_idx, pinned_int_key_loc;

//Reference to self
static struct fmt_main *self;

//Device (GPU) buffers
//int_keys: mask to apply
//loaded_hashes: buffer of binary hashes transfered/loaded to GPU
//hash_ids: information about how recover the cracked password
//bitmap: a bitmap memory space.
//int_key_loc: the position of the mask to apply.
static cl_mem buffer_int_keys, buffer_loaded_hashes, buffer_hash_ids,
	buffer_bitmap, buffer_int_key_loc;

//Host buffers
//saved_int_key_loc: the position of the mask to apply
//num_loaded_hashes: number of binary hashes transfered/loaded to GPU
//loaded_hashes: buffer of binary hashes transfered/loaded to GPU
//hash_ids: information about how recover the cracked password
static uint32_t * saved_int_key_loc, num_loaded_hashes,
	* loaded_hashes = NULL, * hash_ids = NULL;

//ref_counter: a reference counter of the openCL objetcts (expect to be 0 or 1)
static unsigned ref_counter = 0;

//Used to control partial key transfers.
static uint32_t key_idx = 0;
static size_t offset = 0, offset_idx = 0;

static int crypt_all(int *pcount, struct db_salt *_salt);
static void load_hash(const struct db_salt *salt);

//This file contains auto-tuning routine(s). Has to be included after formats definitions.
#include "opencl-autotune.h"
#include "memdbg.h"

/* ------- Helper functions ------- */
static size_t get_task_max_work_group_size()
{
	size_t s;

	s = autotune_get_task_max_work_group_size(FALSE, 0, crypt_kernel);
	return MIN(s, 512);
}

static size_t get_task_max_size()
{
	return 0;
}

static size_t get_default_workgroup()
{
	return 0;
}

/* ------- Create and destroy necessary objects ------- */
static void create_mask_buffers()
{
	if (loaded_hashes)
		MEM_FREE(loaded_hashes);

	if (hash_ids)
		 MEM_FREE(hash_ids);

	loaded_hashes = (cl_uint *) mem_alloc(BINARY_SIZE * num_loaded_hashes);
	hash_ids = (cl_uint *) mem_alloc((num_loaded_hashes + 1) * 3 * sizeof(uint32_t));
}

static void create_clobj(size_t gws, struct fmt_main *self)
{
	pinned_plaintext = clCreateBuffer(context[gpu_id],
			CL_MEM_READ_ONLY | CL_MEM_ALLOC_HOST_PTR,
			BUFFER_SIZE * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating page-locked memory pinned_plaintext");

	plaintext = (uint32_t *) clEnqueueMapBuffer(queue[gpu_id],
			pinned_plaintext, CL_TRUE, CL_MAP_WRITE, 0,
			BUFFER_SIZE * gws, 0, NULL, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping page-locked memory plaintext");

	pinned_saved_idx = clCreateBuffer(context[gpu_id],
			CL_MEM_READ_ONLY | CL_MEM_ALLOC_HOST_PTR,
			sizeof(uint32_t) * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating page-locked memory pinned_saved_idx");

	saved_idx = (uint32_t *) clEnqueueMapBuffer(queue[gpu_id],
			pinned_saved_idx, CL_TRUE, CL_MAP_WRITE, 0,
			sizeof(uint32_t) * gws, 0, NULL, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping page-locked memory saved_idx");

	pinned_int_key_loc = clCreateBuffer(context[gpu_id],
			CL_MEM_READ_ONLY | CL_MEM_ALLOC_HOST_PTR,
			sizeof(uint32_t) * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating page-locked memory pinned_int_key_loc");

	saved_int_key_loc = (uint32_t *) clEnqueueMapBuffer(queue[gpu_id],
			pinned_int_key_loc, CL_TRUE, CL_MAP_WRITE, 0,
			sizeof(uint32_t) * gws, 0, NULL, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping page-locked memory saved_int_key_loc");

	// create arguments (buffers)
	pass_buffer = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY,
		BUFFER_SIZE * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating buffer argument pass_buffer");

	idx_buffer = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY,
		sizeof(uint32_t) * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating buffer argument idx_buffer");

	//Mask mode
	buffer_loaded_hashes = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY,
		BINARY_SIZE * num_loaded_hashes, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating buffer argument buffer_loaded_hashes");

	buffer_hash_ids = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE,
		(num_loaded_hashes + 1) * 3 * sizeof(uint32_t), NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating buffer argument buffer_buffer_hash_ids");

	buffer_bitmap = clCreateBuffer(context[gpu_id], CL_MEM_WRITE_ONLY,
		GET_MULTIPLE_OR_BIGGER(num_loaded_hashes/32 + 1, 32),
		NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating buffer argument buffer_bitmap");

	buffer_int_key_loc = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY,
		sizeof(uint32_t) * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating buffer argument buffer_int_key_loc");

	buffer_int_keys = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY,
		4 * mask_int_cand.num_int_cand, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating buffer argument buffer_int_keys");

	//Set kernel arguments
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 0, sizeof(cl_mem),
		(void *) &pass_buffer), "Error setting argument 0");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 1, sizeof(cl_mem),
		(void *) &idx_buffer), "Error setting argument 1");

	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 2, sizeof(buffer_int_key_loc),
		(void *) &buffer_int_key_loc), "Error setting argument 2");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 3, sizeof(buffer_int_keys),
		(void *) &buffer_int_keys), "Error setting argument 3");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 4, sizeof(cl_uint),
		(void *) &(mask_int_cand.num_int_cand)), "Error setting argument 4");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 5, sizeof(cl_uint),
		(void *) &num_loaded_hashes), "Error setting argument 5");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 6, sizeof(buffer_loaded_hashes),
		(void *) &buffer_loaded_hashes), "Error setting argument 6");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 7, sizeof(buffer_hash_ids),
		(void *) &buffer_hash_ids), "Error setting argument 7");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 8, sizeof(buffer_bitmap),
		(void *) &buffer_bitmap), "Error setting argument 8");

	//Indicates that the OpenCL objetcs are initialized.
	ref_counter++;

	//Assure buffers have no "trash data".
	memset(plaintext, '\0', BUFFER_SIZE * gws);
	memset(saved_idx, '\0', sizeof(uint32_t) * gws);
	memset(saved_int_key_loc, '\0', sizeof(uint32_t) * gws);
}

static void release_clobj(void)
{
	cl_int ret_code;

	ret_code = clEnqueueUnmapMemObject(queue[gpu_id], pinned_plaintext,
			plaintext, 0, NULL, NULL);
	HANDLE_CLERROR(ret_code, "Error Unmapping keys");
	ret_code = clEnqueueUnmapMemObject(queue[gpu_id], pinned_saved_idx,
			saved_idx, 0, NULL, NULL);
	HANDLE_CLERROR(ret_code, "Error Unmapping indexes");
	ret_code = clEnqueueUnmapMemObject(queue[gpu_id], pinned_int_key_loc,
			saved_int_key_loc, 0, NULL, NULL);
	HANDLE_CLERROR(ret_code, "Error Unmapping key locations");
	HANDLE_CLERROR(clFinish(queue[gpu_id]),
	               "Error releasing memory mappings");

	ret_code = clReleaseMemObject(pass_buffer);
	HANDLE_CLERROR(ret_code, "Error Releasing pass_buffer");
	ret_code = clReleaseMemObject(idx_buffer);
	HANDLE_CLERROR(ret_code, "Error Releasing idx_buffer");

	ret_code = clReleaseMemObject(buffer_loaded_hashes);
	HANDLE_CLERROR(ret_code, "Error Releasing buffer_loaded_hashes");
	ret_code = clReleaseMemObject(buffer_hash_ids);
	HANDLE_CLERROR(ret_code, "Error Releasing buffer_hash_ids");
	ret_code = clReleaseMemObject(buffer_bitmap);
	HANDLE_CLERROR(ret_code, "Error Releasing buffer_bitmap");
	ret_code = clReleaseMemObject(buffer_int_key_loc);
	HANDLE_CLERROR(ret_code, "Error Releasing buffer_int_key_loc");
	ret_code = clReleaseMemObject(buffer_int_keys);
	HANDLE_CLERROR(ret_code, "Error Releasing buffer_int_keys");
	ret_code = clReleaseMemObject(pinned_plaintext);
	HANDLE_CLERROR(ret_code, "Error Releasing pinned_plaintext");
	ret_code = clReleaseMemObject(pinned_saved_idx);
	HANDLE_CLERROR(ret_code, "Error Releasing pinned_saved_idx");
	ret_code = clReleaseMemObject(pinned_int_key_loc);
	HANDLE_CLERROR(ret_code, "Error Releasing pinned_int_key_loc");

	ref_counter--;
}

/* ------- Key functions ------- */
static void reset(struct db_main *db)
{
	offset = 0;
	offset_idx = 0;
	key_idx = 0;

	if (db) {
	       	num_loaded_hashes = db->salts->count;

		//Cracking
		if (ref_counter > 0)
			release_clobj();

		create_mask_buffers();
		create_clobj(global_work_size, self);
		load_hash(db->salts);

	} else {
	    	size_t gws_limit;
		unsigned int flag;

	    	// Auto-tune / Benckmark / Self-test.
		gws_limit = MIN((0xf << 22) * 4 / BUFFER_SIZE,
				get_max_mem_alloc_size(gpu_id) / BUFFER_SIZE);

		//Mask initialization
		flag = (options.flags & FLG_MASK_CHK) && !global_work_size;

		for (num_loaded_hashes = 0; tests[num_loaded_hashes].ciphertext;)
			num_loaded_hashes++;
		create_mask_buffers();

		//Initialize openCL tuning (library) for this format.
		opencl_init_auto_setup(SEED, 0, NULL,
			warn, 1, self, create_clobj, release_clobj,
			2 * BUFFER_SIZE, gws_limit);

		//Auto tune execution from shared/included code.
		autotune_run(self, 1, gws_limit,
			(cpu(device_info[gpu_id]) ? 500000000ULL : 1000000000ULL));

		load_hash(NULL);

		if (options.flags & FLG_MASK_CHK) {
			fprintf(stdout,
				"Using Mask Mode with internal candidate generation%s",
				flag ? "" : "\n");

			if (flag) {
				self->params.max_keys_per_crypt /= 256;

				if (self->params.max_keys_per_crypt < 1)
					self->params.max_keys_per_crypt = 1;

					fprintf(stdout, ", global worksize(GWS) set to %d\n",
						self->params.max_keys_per_crypt);
			}
		}
	}
}

/* ------- Key functions ------- */
static void clear_keys(void)
{
	offset = 0;
	offset_idx = 0;
	key_idx = 0;
}

static void set_key(char * _key, int index)
{
	const ARCH_WORD_32 * key = (ARCH_WORD_32 *) _key;
	int len = strlen(_key);

	saved_idx[index] = (key_idx << 6) | len;

	while (len > 4) {
		plaintext[key_idx++] = *key++;
		len -= 4;
	}

	if (len > 0)
		plaintext[key_idx++] = *key;

	//Mask Mode ranges setup
	if (mask_int_cand.num_int_cand > 1) {
		int i;
		saved_int_key_loc[index] = 0;

		for (i = 0; i < MASK_FMT_INT_PLHDR; i++) {

			if (mask_skip_ranges[i] != -1)  {
				saved_int_key_loc[index] |=
				    ((mask_int_cand.int_cpu_mask_ctx->ranges[mask_skip_ranges[i]].offset +
				      mask_int_cand.int_cpu_mask_ctx->ranges[mask_skip_ranges[i]].pos) & 0xff)
				      << (i << 3);
			} else
				saved_int_key_loc[index] |= 0x80 << (i << 3);
		}
	}

	//Batch transfers to GPU.
	if ((index % TRANSFER_SIZE) == 0 && (index > 0)) {
		HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], pass_buffer,
			CL_FALSE, sizeof(uint32_t) * offset,
			sizeof(uint32_t) * TRANSFER_SIZE,
			plaintext + offset, 0, NULL, NULL),
			"failed in clEnqueueWriteBuffer pass_buffer");
		HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], idx_buffer,
			CL_FALSE, sizeof(uint32_t) * offset,
			sizeof(uint32_t) * TRANSFER_SIZE,
			saved_idx + offset, 0, NULL, NULL),
			"failed in clEnqueueWriteBuffer idx_buffer");

		HANDLE_CLERROR(clFlush(queue[gpu_id]), "failed in clFlush");
		offset += TRANSFER_SIZE;
		offset_idx = key_idx;
	}
}

static char * get_key(int index)
{
	static char * ret;
	int int_index, t, i;

	if (!ret) ret = mem_alloc_tiny(PLAINTEXT_LENGTH + 1, MEM_ALIGN_WORD);

	//TODO: FIXME: Why does it happen?
	//../run/john ~/testhashes -form=raw-sha256-opencl --mask=clau?a?l?l?d?d?d -dev=0 --skip
	//if (hash_ids[0] == 0 && index > global_work_size)
	//	return "";

	//Mask Mode plaintext recovery
	if (hash_ids == NULL || hash_ids[0] == 0 ||
	    index > hash_ids[0] || hash_ids[0] > num_loaded_hashes) {
		t = index;
		int_index = 0;

	} else  {
		t = hash_ids[1 + 3 * index];
		int_index = hash_ids[2 + 3 * index];
	}

	//Mask Mode plaintext recovery.
	//TODO: ### remove me.
	if (t > global_work_size) {
		fprintf(stderr,
			"Get key error! t: %d gws: %zd index: %d int_index: %d\n",
			t, global_work_size, index, int_index);
		t = 0;
	}
	memcpy(ret, ((char *) &plaintext[saved_idx[t] >> 6]), PLAINTEXT_LENGTH);
	ret[saved_idx[t] & 63] = '\0';

	if (mask_int_cand.num_int_cand > 1) {

		for (i = 0; i < MASK_FMT_INT_PLHDR && mask_skip_ranges[i] != -1; i++)
			ret[(saved_int_key_loc[t]& (0xff << (i * 8))) >> (i * 8)] =
				mask_int_cand.int_cand[int_index].x[i];
	}

	return ret;
}

/* ------- Initialization  ------- */
static void init(struct fmt_main *_self)
{
	char * task = "$JOHN/kernels/sha256_kernel.cl";

	self = _self;

	opencl_prepare_dev(gpu_id);
	opencl_build_kernel(task, gpu_id, NULL, 1);

	/* Read LWS/GWS prefs from config or environment */
	opencl_get_user_preferences(FORMAT_LABEL);

	// create kernel(s) to execute
	crypt_kernel = clCreateKernel(program[gpu_id], "kernel_crypt", &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating kernel. Double-check kernel name?");

	mask_int_cand_target = 10000;
}

static void done(void)
{
	release_clobj();

	HANDLE_CLERROR(clReleaseKernel(crypt_kernel), "Release kernel");
	HANDLE_CLERROR(clReleaseProgram(program[gpu_id]), "Release Program");

	if (loaded_hashes)
		MEM_FREE(loaded_hashes);

	if (hash_ids)
		MEM_FREE(hash_ids);
}

/* ------- Send hashes to crack (binary) to GPU ------- */
static void load_hash(const struct db_salt *salt)
{
	uint32_t * binary, i = 0, more;
	struct db_password * pw;

	if (salt) {
		num_loaded_hashes = salt->count;
		pw = salt->list;
	} else
		pw = NULL;

	do {

		if (salt)
			binary = (uint32_t *) pw->binary;
		else {
		    	char * ciphertext;
		    	char **fields = tests[i].fields;

			if (!fields[1])
				fields[1] = tests[i].ciphertext;

			ciphertext = raw_sha256_common_split(
				raw_sha256_common_prepare(fields, self), 0, self);
			binary = (uint32_t *) raw_sha256_common_binary(ciphertext);
		}

		// Skip cracked hashes (segfault if removed).
		if (binary) {
			//It is not better to handle (only) part of binary on GPU
			loaded_hashes[HASH_PARTS * i] = binary[0];
			loaded_hashes[HASH_PARTS * i + 1] = binary[1];
			loaded_hashes[HASH_PARTS * i + 2] = binary[2];
			loaded_hashes[HASH_PARTS * i + 3] = binary[3];
			loaded_hashes[HASH_PARTS * i + 4] = binary[4];
			loaded_hashes[HASH_PARTS * i + 5] = binary[5];
			loaded_hashes[HASH_PARTS * i + 6] = binary[6];
			loaded_hashes[HASH_PARTS * i + 7] = binary[7];
		}
		i++ ;

		if (salt) {
			pw = pw->next;
			more = (pw != NULL);
		} else
		    more = (tests[i].ciphertext != NULL);

	} while (more);

	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], buffer_loaded_hashes,
		CL_TRUE, 0, BINARY_SIZE * num_loaded_hashes,
		loaded_hashes, 0, NULL, NULL),
		"failed in clEnqueueWriteBuffer num_loaded_hashes");

	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 4, sizeof(cl_uint),
		(void *) &(mask_int_cand.num_int_cand)), "Error setting argument 4");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 5, sizeof(cl_uint),
		(void *) &num_loaded_hashes), "Error setting argument 5");

	HANDLE_CLERROR(clFinish(queue[gpu_id]), "failed in clFinish");
}

/* ------- Crypt function ------- */
static int crypt_all(int *pcount, struct db_salt *_salt)
{
	const int count = *pcount;
	const struct db_salt * salt = _salt;
	size_t gws, initial = 128;
	size_t *lws = local_work_size ? &local_work_size : &initial;

	gws = GET_MULTIPLE_OR_BIGGER(count, local_work_size);

	//Check if any password was cracked and reload (if necessary)
	if (salt && num_loaded_hashes != salt->count)
		load_hash(salt);

	//Send data to device.
	if (key_idx > offset)
		HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], pass_buffer, CL_FALSE,
		    sizeof(uint32_t) * offset,
		    sizeof(uint32_t) * (key_idx - offset),
		    plaintext + offset, 0, NULL, multi_profilingEvent[0]),
		    "failed in clEnqueueWriteBuffer pass_buffer");

	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], idx_buffer, CL_FALSE,
		sizeof(uint32_t) * offset,
		sizeof(uint32_t) * (gws - offset),
		saved_idx + offset, 0, NULL, multi_profilingEvent[3]),
		"failed in clEnqueueWriteBuffer idx_buffer");

	if (mask_int_cand.num_int_cand > 1) {
		HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], buffer_int_key_loc, CL_FALSE,
			0, 4 * gws, saved_int_key_loc, 0, NULL, multi_profilingEvent[4]),
			"failed in clEnqueueWriteBuffer buffer_int_key_loc");

		HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], buffer_int_keys, CL_FALSE,
			0, 4 * mask_int_cand.num_int_cand, mask_int_cand.int_cand,
			0, NULL, multi_profilingEvent[5]),
			"failed in clEnqueueWriteBuffer buffer_int_keys");
	}

	//Enqueue the kernel
	HANDLE_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], crypt_kernel, 1, NULL,
			&gws, lws, 0, NULL, multi_profilingEvent[1]),
			"failed in clEnqueueNDRangeKernel");

	//Found hashes
	HANDLE_CLERROR(clEnqueueReadBuffer(queue[gpu_id], buffer_hash_ids, CL_FALSE,
		0, (num_loaded_hashes + 1) * 3 * sizeof(uint32_t), hash_ids,
		0, NULL, multi_profilingEvent[2]),
		"failed in reading data back buffer_hash_ids");

	//Do the work
	HANDLE_CLERROR(clFinish(queue[gpu_id]), "failed in clFinish");

	if (hash_ids[0] > num_loaded_hashes) {
		fprintf(stderr, "Error, crypt_all kernel.\n");
		error();
	}
	*pcount *= mask_int_cand.num_int_cand;
	return hash_ids[0];
}

/* ------- Compare functins ------- */
static int cmp_all(void * binary, int count)
{
	return (count > 0);
}

static int cmp_one(void *binary, int index)
{
	return (loaded_hashes[HASH_PARTS * hash_ids[3 + 3 * index]] == ((uint32_t *) binary)[0]);
}

static int cmp_exact(char *source, int index)
{
	uint32_t * binary = (uint32_t *) raw_sha256_common_binary(source);

	if (binary[1] != loaded_hashes[HASH_PARTS * hash_ids[3 + 3 * index] + 1])
		return 0;
	if (binary[2] != loaded_hashes[HASH_PARTS * hash_ids[3 + 3 * index] + 2])
		return 0;
	if (binary[3] != loaded_hashes[HASH_PARTS * hash_ids[3 + 3 * index] + 3])
		return 0;
	if (binary[4] != loaded_hashes[HASH_PARTS * hash_ids[3 + 3 * index] + 4])
		return 0;
	if (binary[5] != loaded_hashes[HASH_PARTS * hash_ids[3 + 3 * index] + 5])
		return 0;
	if (binary[6] != loaded_hashes[HASH_PARTS * hash_ids[3 + 3 * index] + 6])
		return 0;
	if (binary[7] != loaded_hashes[HASH_PARTS * hash_ids[3 + 3 * index] + 7])
		return 0;
	return 1;
}

static int get_hash_0(int index) { return loaded_hashes[HASH_PARTS * hash_ids[3 + 3 * index]] & 0xf; }
static int get_hash_1(int index) { return loaded_hashes[HASH_PARTS * hash_ids[3 + 3 * index]] & 0xff; }
static int get_hash_2(int index) { return loaded_hashes[HASH_PARTS * hash_ids[3 + 3 * index]] & 0xfff; }
static int get_hash_3(int index) { return loaded_hashes[HASH_PARTS * hash_ids[3 + 3 * index]] & 0xffff; }
static int get_hash_4(int index) { return loaded_hashes[HASH_PARTS * hash_ids[3 + 3 * index]] & 0xfffff; }
static int get_hash_5(int index) { return loaded_hashes[HASH_PARTS * hash_ids[3 + 3 * index]] & 0xffffff; }
static int get_hash_6(int index) { return loaded_hashes[HASH_PARTS * hash_ids[3 + 3 * index]] & 0x7ffffff; }

/* ------- Format structure ------- */
struct fmt_main fmt_opencl_rawsha256 = {
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
		{ NULL },
		tests
	}, {
		init,
		done,
		reset,
		raw_sha256_common_prepare,
		raw_sha256_common_valid,
		raw_sha256_common_split,
		raw_sha256_common_binary,
		fmt_default_salt,
		{ NULL },
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
		NULL,
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

#endif /* plugin stanza */

#endif /* HAVE_OPENCL */
