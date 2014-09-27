/* GNOME Keyring cracker patch for JtR. Hacked together during Monsoon of
 * 2012 by Dhiru Kholia <dhiru.kholia at gmail.com>.
 *
 * This software is Copyright (c) 2012, Dhiru Kholia <dhiru.kholia at gmail.com>,
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted. */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_keyring;
#elif FMT_REGISTERS_H
john_register_one(&fmt_keyring);
#else

#include <string.h>
#include <assert.h>
#include <errno.h>
#ifdef _OPENMP
#include <omp.h>
#define OMP_SCALE               64
#endif

#include "arch.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "params.h"
#include "options.h"
#include "md5.h"
#include "sha2.h"
#include <openssl/aes.h>
#include "memdbg.h"

#define FORMAT_LABEL		"keyring"
#define FORMAT_NAME		"GNOME Keyring"
#define ALGORITHM_NAME		"SHA256 AES 32/" ARCH_BITS_STR " " SHA2_LIB
#define BENCHMARK_COMMENT	""
#define BENCHMARK_LENGTH	-1
#define PLAINTEXT_LENGTH	15
#define BINARY_SIZE		0
#define SALT_SIZE		sizeof(*cur_salt)
#define MIN_KEYS_PER_CRYPT	1
#define MAX_KEYS_PER_CRYPT	1

#define SALTLEN 8
typedef unsigned char guchar;
typedef unsigned int guint;
typedef int gint;

static struct fmt_tests keyring_tests[] = {
	{"$keyring$db1b562e453a0764*3221*16*0*02b5c084e4802369c42507300f2e5e56", "openwall"},
	{"$keyring$4f3f1557a7da17f5*2439*144*0*12215fabcff6782aa23605ab2cd843f7be9477b172b615eaa9130836f189d32ffda2e666747378f09c6e76ad817154daae83a36c0a0a35f991d40bcfcba3b7807ef57a0ce4c7f835bf34c6e358f0d66aa048d73dacaaaf6d7fa4b3510add6b88cc237000ff13cb4dbd132db33be3ea113bedeba80606f86662cc226af0dad789c703a7df5ad8700542e0f7a5e1f10cf0", "password"},
	{NULL}
};

static struct custom_salt {
	unsigned int iterations;
	unsigned char salt[SALTLEN];
	unsigned int crypto_size;
	unsigned int inlined;
	unsigned char ct[LINE_BUFFER_SIZE / 2]; /* after hex conversion */
} *cur_salt;

unsigned char (*input)[sizeof(cur_salt->ct)];
static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static int *cracked;
static int any_cracked;
static size_t cracked_size;

static void init(struct fmt_main *self)
{

#if defined (_OPENMP)
	int omp_t;

	omp_t = omp_get_max_threads();
	self->params.min_keys_per_crypt *= omp_t;
	self->params.max_keys_per_crypt *= omp_t * OMP_SCALE;
	input = mem_alloc_tiny(sizeof(*input) * omp_t, MEM_ALIGN_WORD);
#else
	input = mem_alloc_tiny(sizeof(*input), MEM_ALIGN_WORD);
#endif
	saved_key = mem_calloc_tiny(sizeof(*saved_key) *
			self->params.max_keys_per_crypt, MEM_ALIGN_WORD);
	any_cracked = 0;
	cracked_size = sizeof(*cracked) * self->params.max_keys_per_crypt;
	cracked = mem_calloc_tiny(cracked_size, MEM_ALIGN_WORD);
}

static int looks_like_nice_int(char *p)
{
	// reasonability check + avoids atoi's UB
	if (strlen(p) > 9)
		return 0;
	for (; *p; p++)
		if (*p < '0' || *p > '9')
			return 0;
	return 1;
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *ctcopy, *keeptr, *p;
	int ctlen;
	if (strncmp(ciphertext, "$keyring$", 9) != 0)
		return 0;
	ctcopy = strdup(ciphertext);
	keeptr = ctcopy;
	if (keeptr == NULL)
		goto err;
	ctcopy += 9;
	if ((p = strtok(ctcopy, "*")) == NULL)	/* salt */
		goto err;
	if (strlen(p) != SALTLEN * 2)
		goto err;
	while (*p)
		if (atoi16[ARCH_INDEX(*p++)] == 0x7f)
			goto err;
	if ((p = strtok(NULL, "*")) == NULL)	/* iterations */
		goto err;
	if (!looks_like_nice_int(p))
		goto err;
	if ((p = strtok(NULL, "*")) == NULL)	/* crypto size */
		goto err;
	if (!looks_like_nice_int(p))
		goto err;
	ctlen = atoi(p);
	if ((p = strtok(NULL, "*")) == NULL)	/* inlined - unused? TODO */
		goto err;
	if (!looks_like_nice_int(p))
		goto err;
	if ((p = strtok(NULL, "*")) == NULL)	/* ciphertext */
		goto err;
	if (ctlen > LINE_BUFFER_SIZE)
		goto err;
	if (strlen(p) != ctlen * 2)
		goto err;
	if (strlen(p) < 32)	/* this shouldn't happen for valid hashes */
		goto err;
	while (*p)
		if (atoi16[ARCH_INDEX(*p++)] == 0x7f)
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
	static struct custom_salt cs;
	memset(&cs, 0, sizeof(cs));
	ctcopy += 9;	/* skip over "$keyring$" */
	cur_salt = mem_alloc_tiny(sizeof(struct custom_salt), MEM_ALIGN_WORD);
	p = strtok(ctcopy, "*");
	for (i = 0; i < SALTLEN; i++)
		cs.salt[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	p = strtok(NULL, "*");
	cs.iterations = atoi(p);
	p = strtok(NULL, "*");
	cs.crypto_size = atoi(p);
	p = strtok(NULL, "*");
	cs.inlined = atoi(p);
	p = strtok(NULL, "*");
	assert(strlen(p) == 2 * cs.crypto_size);
	for (i = 0; i < cs.crypto_size; i++)
		cs.ct[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	MEM_FREE(keeptr);
	return (void *)&cs;
}


static void set_salt(void *salt)
{
	cur_salt = (struct custom_salt *)salt;
}

static void symkey_generate_simple(const char *password, int n_password, unsigned char *salt, int n_salt, int iterations, unsigned char *key, unsigned char *iv)
{

	SHA256_CTX ctx;
	guchar digest[64];
	guint n_digest;
	gint pass, i;
	gint needed_iv, needed_key;
	guchar *at_iv, *at_key;

	at_key = key;
	at_iv = iv;

	needed_key = 16;
	needed_iv = 16;
	n_digest = 32;		/* SHA256 digest size */

	for (pass = 0;; ++pass) {
		SHA256_Init(&ctx);

		/* Hash in the previous buffer on later passes */
		if (pass > 0) {
			SHA256_Update(&ctx, digest, n_digest);
		}

		if (password) {
			SHA256_Update(&ctx, password, n_password);

		}
		if (salt && n_salt) {
			SHA256_Update(&ctx, salt, n_salt);
		}
		SHA256_Final(digest, &ctx);

		for (i = 1; i < iterations; ++i) {
			SHA256_Init(&ctx);
			SHA256_Update(&ctx, digest, n_digest);
			SHA256_Final(digest, &ctx);
		}
		/* Copy as much as possible into the destinations */
		i = 0;
		while (needed_key && i < n_digest) {
			*(at_key++) = digest[i];
			needed_key--;
			i++;
		}
		while (needed_iv && i < n_digest) {
			if (at_iv)
				*(at_iv++) = digest[i];
			needed_iv--;
			i++;
		}

		if (needed_key == 0 && needed_iv == 0)
			break;

	}
}

static void decrypt_buffer(unsigned char *buffer, unsigned int len,
    unsigned char *salt, int iterations, char *password)
{
	unsigned char key[32];
	unsigned char iv[32];
	AES_KEY akey;
	int n_password = strlen(password);

	symkey_generate_simple(password, n_password, salt, 8, iterations, key, iv);

	memset(&akey, 0, sizeof(AES_KEY));
	if (AES_set_decrypt_key(key, 128, &akey) < 0) {
		fprintf(stderr, "AES_set_decrypt_key failed!\n");
	}
	AES_cbc_encrypt(buffer, buffer, len, &akey, iv, AES_DECRYPT);
}

static int verify_decrypted_buffer(unsigned char *buffer, int len)
{
	guchar digest[16];
	MD5_CTX ctx;
	MD5_Init(&ctx);
	MD5_Update(&ctx, buffer + 16, len - 16);
	MD5_Final(digest, &ctx);
	return memcmp(buffer, digest, 16) == 0;
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	int count = *pcount;
	int index = 0;

	if (any_cracked) {
		memset(cracked, 0, cracked_size);
		any_cracked = 0;
	}

#ifdef _OPENMP
#pragma omp parallel for
	for (index = 0; index < count; index++)
#endif
	{
#ifdef _OPENMP
		int t = omp_get_thread_num();
#else
		const int t = 0;
#endif
		memcpy(input[t], cur_salt->ct, cur_salt->crypto_size);
		decrypt_buffer(input[t], cur_salt->crypto_size, cur_salt->salt, cur_salt->iterations, saved_key[index]);
		if (verify_decrypted_buffer(input[t], cur_salt->crypto_size))
#ifdef _OPENMP
#pragma omp critical
#endif
			any_cracked = cracked[index] = 1;
	}
	return count;
}

static int cmp_all(void *binary, int count)
{
	return any_cracked;
}

static int cmp_one(void *binary, int index)
{
	return cracked[index];
}

static int cmp_exact(char *source, int index)
{
	return cracked[index];
}

static void keyring_set_key(char *key, int index)
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

#if FMT_MAIN_VERSION > 11
static unsigned int iteration_count(void *salt)
{
	struct custom_salt *my_salt;

	my_salt = salt;
	return my_salt->iterations;
}
#endif

struct fmt_main fmt_keyring = {
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
#if FMT_MAIN_VERSION > 11
		{
			"iteration count",
		},
#endif
		keyring_tests
	}, {
		init,
		fmt_default_done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		fmt_default_binary,
		get_salt,
#if FMT_MAIN_VERSION > 11
		{
			iteration_count,
		},
#endif
		fmt_default_source,
		{
			fmt_default_binary_hash
		},
		fmt_default_salt_hash,
		set_salt,
		keyring_set_key,
		get_key,
		fmt_default_clear_keys,
		crypt_all,
		{
			fmt_default_get_hash
		},
		cmp_all,
		cmp_one,
		cmp_exact
	}
};

#endif /* plugin stanza */
