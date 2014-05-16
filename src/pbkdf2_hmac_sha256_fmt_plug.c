/* This software is Copyright (c) 2012 Lukas Odzioba <ukasz@openwall.net>
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * Based on hmac-sha512 by magnum
 *
 * Minor fixes, format unification and OMP support done by Dhiru Kholia
 * <dhiru@openwall.com>
 *
 * Fixed for supporting $ml$ "dave" format as well as GRUB native format by
 * magnum 2013. Note: We support a binary size of >512 bits (64 bytes / 128
 * chars of hex) but we currently do not calculate it even in cmp_exact(). The
 * chance for a 512-bit hash collision should be pretty dang slim.
 *
 * the pbkdf2_sha256_hmac was so messed up, I simply copied sha512 over the top
 * of it, replacing the code in totality.  JimF.
 */

#include <ctype.h>
#include <string.h>
#include <assert.h>

#include "misc.h"
#include "arch.h"
#include "common.h"
#include "formats.h"
#include "base64.h"
#include "sha2.h"
#include "johnswap.h"
#include "stdint.h"
#include "pbkdf2_hmac_sha256.h"

#define FORMAT_LABEL            "PBKDF2-HMAC-SHA256"
#define FORMAT_NAME		""

#define BENCHMARK_COMMENT	", rounds=12000"

#ifdef MMX_COEF_SHA256
#define ALGORITHM_NAME		"PBKDF2-SHA256 " SHA256_ALGORITHM_NAME
#else
#if ARCH_BITS >= 64
#define ALGORITHM_NAME          "PBKDF2-SHA256 64/" ARCH_BITS_STR " " SHA2_LIB
#else
#define ALGORITHM_NAME          "PBKDF2-SHA256 32/" ARCH_BITS_STR " " SHA2_LIB
#endif
#endif

#define BINARY_SIZE             32
#define MAX_CIPHERTEXT_LENGTH   1024 /* Bump this and code will adopt */
#define MAX_BINARY_SIZE         (4*32) /* Bump this and code will adopt */
#define MAX_SALT_SIZE           128 /* Bump this and code will adopt */
#define SALT_SIZE               sizeof(struct custom_salt)
#define FMT_PREFIX		"$pbkdf2-sha256$"
#ifdef MMX_COEF_SHA256
#define MIN_KEYS_PER_CRYPT	SSE_GROUP_SZ_SHA256
#define MAX_KEYS_PER_CRYPT	SSE_GROUP_SZ_SHA256
#else
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      1
#endif
#define BENCHMARK_LENGTH        -1
#ifdef _OPENMP
static int omp_t = 1;
#include <omp.h>
#define OMP_SCALE               4
#endif

#include "memdbg.h"

#define PAD_SIZE                128
#define PLAINTEXT_LENGTH        125

#define MIN(a,b)                (((a)<(b))?(a):(b))
#define MAX(a,b)                (((a)>(b))?(a):(b))

static struct fmt_tests tests[] = {
	{"$pbkdf2-sha256$12000$2NtbSwkhRChF6D3nvJfSGg$OEWLc4keep8Vx3S/WnXgsfalb9q0RQdS1s05LfalSG4", ""},
	{"$pbkdf2-sha256$12000$fK8VAoDQuvees5ayVkpp7Q$xfzKAoBR/Iaa68tjn.O8KfGxV.zdidcqEeDoTFvDz2A", "1"},
	{"$pbkdf2-sha256$12000$GoMQYsxZ6/0fo5QyhtAaAw$xQ9L6toKn0q245SIZKoYjCu/Fy15hwGme9.08hBde1w", "12"},
	{"$pbkdf2-sha256$12000$6r3XWgvh/D/HeA/hXAshJA$11YY39OaSkJuwb.ONKVy5ebCZ00i5f8Qpcgwfe3d5kY", "123"},
	{"$pbkdf2-sha256$12000$09q711rLmbMWYgwBIGRMqQ$kHdAHlnQ1i1FHKBCPLV0sA20ai2xtYA1Ev8ODfIkiQg", "1234"},
	{"$pbkdf2-sha256$12000$Nebce08pJcT43zuHUMo5Rw$bMW/EsVqy8tMaDecFwuZNEPVfQbXBclwN78okLrxJoA", "openwall"},
	{"$pbkdf2-sha256$12000$mtP6/39PSQlhzBmDsJZS6g$zUXxf/9XBGrkedXVwhpC9wLLwwKSvHX39QRz7MeojYE", "password"},
	{"$pbkdf2-sha256$12000$35tzjhGi9J5TSilF6L0XAg$MiJA1gPN1nkuaKPVzSJMUL7ucH4bWIQetzX/JrXRYpw", "pbkdf2-sha256"},
	{"$pbkdf2-sha256$12000$sxbCeE8pxVjL2ds7hxBizA$uIiwKdo9DbPiiaLi1y3Ljv.r9G1tzxLRdlkD1uIOwKM", " 15 characters "},
	{"$pbkdf2-sha256$12000$CUGI8V7rHeP8nzMmhJDyXg$qjq3rBcsUgahqSO/W4B1bvsuWnrmmC4IW8WKMc5bKYE", " 16 characters__"},
	{"$pbkdf2-sha256$12000$FmIM4VxLaY1xLuWc8z6n1A$OVe6U1d5dJzYFKlJsZrW1NzUrfgiTpb9R5cAfn96WCk", " 20 characters______"},
	{"$pbkdf2-sha256$12000$fA8BAMAY41wrRQihdO4dow$I9BSCuV6UjG55LktTKbV.bIXtyqKKNvT3uL7JQwMLp8", " 24 characters______1234"},
	{"$pbkdf2-sha256$12000$/j8npJTSOmdMKcWYszYGgA$PbhiSNRzrELfAavXEsLI1FfitlVjv9NIB.jU1HHRdC8", " 28 characters______12345678"},
	{"$pbkdf2-sha256$12000$xfj/f6/1PkcIoXROCeE8Bw$ci.FEcPOKKKhX5b3JwzSDo6TGuYjgj1jKfCTZ9UpDM0", " 32 characters______123456789012"},
	{"$pbkdf2-sha256$12000$6f3fW8tZq7WWUmptzfmfEw$GDm/yhq1TnNR1MVGy73UngeOg9QJ7DtW4BnmV2F065s", " 40 characters______12345678901234567890"},
	{"$pbkdf2-sha256$12000$dU5p7T2ndM7535tzjpGyVg$ILbppLkipmonlfH1I2W3/vFMyr2xvCI8QhksH8DWn/M", " 55 characters______________________________________end"},
	{"$pbkdf2-sha256$12000$iDFmDCHE2FtrDaGUEmKMEaL0Xqv1/t/b.x.DcC6lFEI$tUdEcw3csCnsfiYbFdXH6nvbftH8rzvBDl1nABeN0nE", "salt length = 32"},
	{"$pbkdf2-sha256$12000$0zoHwNgbIwSAkDImZGwNQUjpHcNYa43xPqd0DuH8H0OIUWqttfY.h5DynvPeG.O8N.Y$.XK4LNIeewI7w9QF5g9p5/NOYMYrApW03bcv/MaD6YQ", "salt length = 50"},
	{"$pbkdf2-sha256$12000$HGPMeS9lTAkhROhd653Tuvc.ZyxFSOk9x5gTYgyBEAIAgND6PwfAmA$WdCipc7O/9tTgbpZvcz.mAkIDkdrebVKBUgGbncvoNw", "salt length = 40"},
	{NULL}
};

static struct custom_salt {
	uint8_t length;
	uint8_t salt[MAX_SALT_SIZE];
	uint32_t rounds;
} *cur_salt;

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static ARCH_WORD_32 (*crypt_out)[BINARY_SIZE / sizeof(ARCH_WORD_32)];

static void init(struct fmt_main *self)
{
#ifdef _OPENMP
	omp_t = omp_get_max_threads();
	self->params.min_keys_per_crypt *= omp_t;
	omp_t *= OMP_SCALE;
	self->params.max_keys_per_crypt *= omp_t;
#endif
	saved_key = mem_calloc_tiny(sizeof(*saved_key) *
	        self->params.max_keys_per_crypt, MEM_ALIGN_WORD);
	crypt_out = mem_calloc_tiny(sizeof(*crypt_out) *
	        self->params.max_keys_per_crypt, MEM_ALIGN_WORD);
}

static int isabase64(char a)
{
	int ret = 0;
	if (a >= 'a' && a <= 'z')
		ret = 1;
	if (a >= 'A' && a <= 'Z')
		ret = 1;
	if (a >= '0' && a <= '9')
		ret = 1;
	if (a == '.' || a == '/')
		ret = 1;
	return ret;
}

static int valid(char *ciphertext, struct fmt_main *pFmt)
{
	int saltlen = 0;
	char *p, *c = ciphertext;
	if (strncmp(ciphertext, FMT_PREFIX, strlen(FMT_PREFIX) != 0))
		return 0;
	if (strlen(ciphertext) < 44 + strlen(FMT_PREFIX))
		return 0;
	c += strlen(FMT_PREFIX);
	if (strtol(c, NULL, 10) == 0)
		return 0;
	c = strchr(c, '$');
	if (c == NULL)
		return 0;
	c++;
	p = strchr(c, '$');
	if (p == NULL)
		return 0;
	while (c < p) {
		if (!isabase64(*c++))
			return 0;
		saltlen++;
	}
	saltlen = saltlen * 3 / 4;
	if (saltlen > MAX_SALT_SIZE)
		return 0;
	c++;
	if (strlen(c) != 43)
		return 0;
	while (*c)
		if (!isabase64(*c++))
			return 0;
	return 1;
}

/* adapted base64 encoding used by passlib - s/./+/ and trim padding */
static void abase64_decode(const char *in, int length, char *out)
{
	int i;
	static char hash[70 + 1];
#ifdef DEBUG
	assert(length <= 70);
	assert(length % 4 != 1);
#endif
	memset(hash, '=', 70);
	memcpy(hash, in, length);
	for (i = 0; i < length; i++)
		if (hash[i] == '.')
			hash[i] = '+';
	switch (length % 4) {
	case 2:
		length += 2;
		break;
	case 3:
		length++;
		break;
	}
	hash[length] = 0;
	base64_decode(hash, length, out);
}

static void *get_salt(char *ciphertext)
{
	static struct custom_salt salt;
	char *p, *c = ciphertext, *oc;
	c += strlen(FMT_PREFIX);
	salt.rounds = strtol(c, NULL, 10);
	c = strchr(c, '$') + 1;
	p = strchr(c, '$');
	salt.length = 0;
	oc = c;
	while (c++ < p)
		salt.length++;
	abase64_decode(oc, salt.length, (char *)salt.salt);
	salt.length = salt.length * 3 / 4;
	//memcpy(salt.hash, (char *)binary(ciphertext), BINARY_SIZE);
	return (void *)&salt;
}

static void *get_binary(char *ciphertext)
{
	static union {
		char c[BINARY_SIZE];
		ARCH_WORD dummy;
	} buf;
	char *ret = buf.c;
	char *c = ciphertext;
#if !ARCH_LITTLE_ENDIAN
	int i;
#endif
	c += strlen(FMT_PREFIX) + 1;
	c = strchr(c, '$') + 1;
	c = strchr(c, '$') + 1;
#ifdef DEBUG
	assert(strlen(c) == 43);
#endif
	abase64_decode(c, 43, ret);
#if !ARCH_LITTLE_ENDIAN
	for (i = 0; i < BINARY_SIZE/4; ++i) {
		((ARCH_WORD_32*)ret)[i] = JOHNSWAP(((ARCH_WORD_32*)ret)[i]);
	}
#endif
	return ret;
}

static void set_salt(void *salt)
{
	cur_salt = (struct custom_salt *)salt;
}

static int get_hash_0(int index) { return crypt_out[index][0] & 0xf; }
static int get_hash_1(int index) { return crypt_out[index][0] & 0xff; }
static int get_hash_2(int index) { return crypt_out[index][0] & 0xfff; }
static int get_hash_3(int index) { return crypt_out[index][0] & 0xffff; }
static int get_hash_4(int index) { return crypt_out[index][0] & 0xfffff; }
static int get_hash_5(int index) { return crypt_out[index][0] & 0xffffff; }
static int get_hash_6(int index) { return crypt_out[index][0] & 0x7ffffff; }

static int crypt_all(int *pcount, struct db_salt *salt)
{
	int count = *pcount;
	int index = 0;

#ifdef _OPENMP
#pragma omp parallel for
#endif
#if defined(_OPENMP) || MAX_KEYS_PER_CRYPT > 1
#endif
	for (index = 0; index < count; index += MAX_KEYS_PER_CRYPT)
	{
#ifdef SSE_GROUP_SZ_SHA256
		int lens[SSE_GROUP_SZ_SHA256], i;
		unsigned char *pin[SSE_GROUP_SZ_SHA256];
		ARCH_WORD_32 *pout[SSE_GROUP_SZ_SHA256];
		for (i = 0; i < SSE_GROUP_SZ_SHA256; ++i) {
			lens[i] = strlen(saved_key[index+i]);
			pin[i] = (unsigned char*)saved_key[index+i];
			pout[i] = crypt_out[index+i];
		}
		pbkdf2_sha256_sse((const unsigned char **)pin, lens, cur_salt->salt, cur_salt->length, cur_salt->rounds, (unsigned char**)pout, BINARY_SIZE, 0);
#else
		pbkdf2_sha256((const unsigned char*)(saved_key[index]), strlen(saved_key[index]),
			cur_salt->salt, cur_salt->length,
			cur_salt->rounds, (unsigned char*)crypt_out[index], BINARY_SIZE, 0);
#endif
	}
	return count;
}

static int cmp_all(void *binary, int count)
{
	int index = 0;
#if defined(_OPENMP) || MAX_KEYS_PER_CRYPT > 1
	for (; index < count; index++)
#endif
		if (!memcmp(binary, crypt_out[index], ARCH_SIZE))
			return 1;
	return 0;
}

static int cmp_one(void *binary, int index)
{
	return !memcmp(binary, crypt_out[index], BINARY_SIZE);
}

/* Check the FULL binary, just for good measure. There is no chance we'll
   have a false positive here but this function is not performance sensitive.
   
   This function not done linke pbkdf2_hmac_sha512. Simply return 1.
   */
static int cmp_exact(char *source, int index)
{
	return 1;
}

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

struct fmt_main fmt_pbkdf2_hmac_sha256 = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
		sizeof(ARCH_WORD_32),
		SALT_SIZE,
		sizeof(ARCH_WORD),
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT | FMT_OMP,
#if FMT_MAIN_VERSION > 11
		{ NULL },
#endif
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
#if FMT_MAIN_VERSION > 11
		{ NULL },
#endif
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
