/* Cracker for RIPv2 MD5 authentication hashes.
 *
 * This software is Copyright (c) 2013, Dhiru Kholia <dhiru [at] openwall.com>,
 * and it is hereby released to the general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#include "md5.h"
#include <string.h>
#include "arch.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "params.h"
#include "options.h"

#ifdef _OPENMP
#include <omp.h>
#define OMP_SCALE 2048 // XXX
#endif

#define FORMAT_LABEL            "net-md5"
#define FORMAT_NAME             "\"Keyed MD5\" RIPv2, OSPF, BGP, SNMPv2"
#define FORMAT_TAG              "$netmd5$"
#define FORMAT_TAG_2            "$netmd5b$"
#define TAG_LENGTH              (sizeof(FORMAT_TAG) - 1)
#define TAG_LENGTH_2            (sizeof(FORMAT_TAG_2) - 1)
#define ALGORITHM_NAME          "MD5 32/" ARCH_BITS_STR
#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        -1

// Linux Kernel says "#define TCP_MD5SIG_MAXKEYLEN 80"
#define PLAINTEXT_LENGTH        80

#define BINARY_SIZE             16
#define BINARY_ALIGN            sizeof(ARCH_WORD_32)
#define SALT_SIZE               sizeof(struct custom_salt)
#define SALT_ALIGN              MEM_ALIGN_NONE
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      1
#define HEXCHARS                "0123456789abcdef"

static struct fmt_tests tests[] = {
	/* RIPv2 MD5 authentication hashes */
	{FORMAT_TAG "02020000ffff0003002c01145267d48d000000000000000000020000ac100100ffffff000000000000000001ffff0001$1e372a8a233c6556253a0909bc3dcce6", "quagga"},
	{FORMAT_TAG "02020000ffff0003002c01145267d48f000000000000000000020000ac100100ffffff000000000000000001ffff0001$ed9f940c3276afcc06d15babe8a1b61b", "quagga"},
	{FORMAT_TAG "02020000ffff0003002c01145267d490000000000000000000020000ac100100ffffff000000000000000001ffff0001$c9f7763f80fcfcc2bbbca073be1f5df7", "quagga"},
	{FORMAT_TAG "02020000ffff0003002c01145267d49a000000000000000000020000ac100200ffffff000000000000000001ffff0001$3f6a72deeda200806230298af0797997", "quagga"},
	{FORMAT_TAG "02020000ffff0003002c01145267d49b000000000000000000020000ac100200ffffff000000000000000001ffff0001$b69184bacccc752cadf78cac455bd0de", "quagga"},
	{FORMAT_TAG "02020000ffff0003002c01145267d49d000000000000000000020000ac100100ffffff000000000000000001ffff0001$6442669c577e7662188865a54c105d0e", "quagga"},
	{FORMAT_TAG "02020000ffff0003002c01145267e076000000000000000000020000ac100200ffffff000000000000000001ffff0001$4afe22cf1750d9af8775b25bcf9cfb8c", "abcdefghijklmnop"},
	{FORMAT_TAG "02020000ffff0003002c01145267e077000000000000000000020000ac100200ffffff000000000000000001ffff0001$326b12f6da03048a655ea4d8f7e3e123", "abcdefghijklmnop"},
	{FORMAT_TAG "02020000ffff0003002c01145267e2ab000000000000000000020000ac100100ffffff000000000000000001ffff0001$ad76c40e70383f6993f54b4ba6492a26", "abcdefghijklmnop"},
	/* OSPFv2 MD5 authentication hashes */
	{"$netmd5$0201002cac1001010000000000000002000001105267ff8fffffff00000a0201000000280000000000000000$445ecbb27272bd791a757a6c85856150", "abcdefghijklmnop"},
	{FORMAT_TAG "0201002cac1001010000000000000002000001105267ff98ffffff00000a0201000000280000000000000000$d4c248b417b8cb1490e02c5e99eb0ad1", "abcdefghijklmnop"},
	{FORMAT_TAG "0201002cac1001010000000000000002000001105267ffa2ffffff00000a0201000000280000000000000000$528d9bf98be8213482af7295307625bf", "abcdefghijklmnop"},
	/* BGP TCP_MD5SIG hashes */
	{"$netmd5b$c0a83814c0a838280006002800b3d10515f72762291b6878a010007300000000$eaf8d1f1da3f03c90b42709e9508fc73", "lolcats"},
	{NULL}
};

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static ARCH_WORD_32 (*crypt_out)[BINARY_SIZE / sizeof(ARCH_WORD_32)];

static struct custom_salt {
	int length;
	int type;  /* 1 implies BGP hashes */
	unsigned char salt[1024]; // XXX but should be OK
} *cur_salt;

static void init(struct fmt_main *self)
{
#ifdef _OPENMP
	int omp_t = omp_get_num_threads();

	self->params.min_keys_per_crypt *= omp_t;
	omp_t *= OMP_SCALE;
	self->params.max_keys_per_crypt *= omp_t;
#endif
	saved_key = mem_calloc_tiny(sizeof(*saved_key) *
		self->params.max_keys_per_crypt, MEM_ALIGN_WORD);
	crypt_out = mem_calloc_tiny(sizeof(*crypt_out) * self->params.max_keys_per_crypt, MEM_ALIGN_WORD);
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *p, *q = NULL;
	int len;

	p = ciphertext;

	if (!strncmp(p, FORMAT_TAG_2, TAG_LENGTH_2))
		p += TAG_LENGTH_2;

	else if (!strncmp(p, FORMAT_TAG, TAG_LENGTH))
		p += TAG_LENGTH;

	q = strrchr(ciphertext, '$');
	if (!q)
		return 0;
	q = q + 1;
	if ((q - p - 1) > SALT_SIZE * 2)
		return 0;

	len = strspn(q, HEXCHARS);
	if (len != BINARY_SIZE * 2 || len != strlen(q))
		return 0;

	if (strspn(p, HEXCHARS) != q - p - 1)
		return 0;

	return 1;
}

static void *get_salt(char *ciphertext)
{
	static struct custom_salt cs;
	int i, len;
	memset(&cs, 0, SALT_SIZE);

	if (!strncmp(ciphertext, FORMAT_TAG_2, TAG_LENGTH_2)) {
		ciphertext += TAG_LENGTH_2;
		cs.type = 1;
	}

	else if (!strncmp(ciphertext, FORMAT_TAG, TAG_LENGTH))
		ciphertext += TAG_LENGTH;

	len = (strrchr(ciphertext, '$') - ciphertext) / 2;

	for (i = 0; i < len; i++)
		cs.salt[i] = (atoi16[ARCH_INDEX(ciphertext[2 * i])] << 4) |
			atoi16[ARCH_INDEX(ciphertext[2 * i + 1])];

	cs.length = len;
	return &cs;
}

static void *get_binary(char *ciphertext)
{
	static union {
		unsigned char c[BINARY_SIZE];
		ARCH_WORD dummy;
	} buf;
	unsigned char *out = buf.c;
	char *p;
	int i;
	p = strrchr(ciphertext, '$') + 1;
	for (i = 0; i < BINARY_SIZE; i++) {
		out[i] =
		    (atoi16[ARCH_INDEX(*p)] << 4) |
		    atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}

	return out;
}

static int get_hash_0(int index) { return crypt_out[index][0] & 0xf; }
static int get_hash_1(int index) { return crypt_out[index][0] & 0xff; }
static int get_hash_2(int index) { return crypt_out[index][0] & 0xfff; }
static int get_hash_3(int index) { return crypt_out[index][0] & 0xffff; }
static int get_hash_4(int index) { return crypt_out[index][0] & 0xfffff; }
static int get_hash_5(int index) { return crypt_out[index][0] & 0xffffff; }
static int get_hash_6(int index) { return crypt_out[index][0] & 0x7ffffff; }

static void set_salt(void *salt)
{
	cur_salt = (struct custom_salt *)salt;
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	int count = *pcount;
	int index = 0;
#ifdef _OPENMP
#pragma omp parallel for
	for (index = 0; index < count; index++)
#endif
	{
		MD5_CTX ctx;

		MD5_Init(&ctx);
		MD5_Update(&ctx, cur_salt->salt, cur_salt->length);

		if (cur_salt->type == 1) /* handle BGP hashes */
			MD5_Update(&ctx, saved_key[index], strlen(saved_key[index]));
		else {
			// RIPv2 truncates (or null pads) passwords to length 16
			MD5_Update(&ctx, saved_key[index], 16);
		}
		MD5_Final((unsigned char*)crypt_out[index], &ctx);
	}
	return count;
}

static int cmp_all(void *binary, int count)
{
	int index = 0;
#ifdef _OPENMP
	for (; index < count; index++)
#endif
		if (((ARCH_WORD_32*)binary)[0] == crypt_out[index][0])
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

static void netmd5_set_key(char *key, int index)
{
	/* strncpy will pad with zeros, which is needed */
	strncpy(saved_key[index], key, sizeof(saved_key[0]));
}

static char *get_key(int index)
{
	return saved_key[index];
}

struct fmt_main fmt_netmd5 = {
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
		0,
		FMT_CASE | FMT_8_BIT | FMT_OMP,
		tests
	}, {
		init,
		fmt_default_done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		get_binary,
		get_salt,
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
		set_salt,
		netmd5_set_key,
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
