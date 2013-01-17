/*
* This software is Copyright (c) 2012 Lukas Odzioba <lukas dot odzioba at gmail dot com>
* and it is hereby released to the general public under the following terms:
* Redistribution and use in source and binary forms, with or without modification, are permitted.
*/
#include <string.h>
#include "arch.h"
#include <assert.h>
#include "formats.h"
#include "common.h"
#include "misc.h"
#include "cuda_wpapsk.h"
#include "cuda_common.h"

#define FORMAT_LABEL		"wpapsk-cuda"
#define FORMAT_NAME		"WPA-PSK PBKDF2-HMAC-SHA-1"
#define ALGORITHM_NAME		"CUDA"

#define BENCHMARK_COMMENT	""
#define BENCHMARK_LENGTH	-1

///#define WPAPSK_DEBUG
extern wpapsk_password *inbuffer;
extern wpapsk_hash *outbuffer;
extern wpapsk_salt currentsalt;
extern hccap_t hccap;
extern mic_t *mic;
extern void wpapsk_gpu(wpapsk_password *, wpapsk_hash *, wpapsk_salt *);

extern void *salt(char *ciphertext);

/** testcase from http://wiki.wireshark.org/SampleCaptures = wpa-Induction.pcap **/
static struct fmt_tests wpapsk_tests[] = {
	{"$WPAPSK$Coherer#..l/Uf7J..qHUXMunTE3nfbMWSwxv27Ua0XutIOrfRSuv9gOCIugIVGlosMyXdNxfBZUAYmgKqeb6GBPxLiIZr56NtWTGR/Cp5ldAk61.5I0.Ec.2...........nTE3nfbMWSwxv27Ua0XutIOrfRSuv9gOCIugIVGlosM.................................................................3X.I.E..1uk0.E..1uk2.E..1uk0....................................................................................................................................................................................../t.....U...8FWdk8OpPckhewBwt4MXYI", "Induction"},
	{NULL}
};


static void done()
{
	MEM_FREE(inbuffer);
	MEM_FREE(outbuffer);
	MEM_FREE(mic);
}

static void init(struct fmt_main *self)
{
	assert(sizeof(hccap_t) == HCCAP_SIZE);
	///Allocate memory for hashes and passwords
	inbuffer =
	    (wpapsk_password *) mem_calloc(MAX_KEYS_PER_CRYPT *
	      sizeof(wpapsk_password));
	outbuffer =
	    (wpapsk_hash *) mem_alloc(MAX_KEYS_PER_CRYPT * sizeof(wpapsk_hash));
	check_mem_allocation(inbuffer, outbuffer);
	mic = (mic_t *) mem_alloc(MAX_KEYS_PER_CRYPT * sizeof(mic_t));
	///Initialize CUDA
	cuda_init(cuda_gpu_id);
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	wpapsk_gpu(inbuffer, outbuffer, &currentsalt);
	wpapsk_postprocess(KEYS_PER_CRYPT);
        return *pcount;
}

struct fmt_main fmt_cuda_wpapsk = {
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
		wpapsk_tests
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		binary,
		salt,
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
