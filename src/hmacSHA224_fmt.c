/*
 * This  software is Copyright © 2012 magnum, and it is hereby released to the
 * general public under the following terms:  Redistribution and use in source
 * and binary forms, with or without modification, are permitted.
 *
 * Based on hmac-md5 by Bartavelle
 */

#include <string.h>

#include "arch.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include <openssl/sha.h>

#define FORMAT_LABEL			"hmac-sha224"
#define FORMAT_NAME			"HMAC SHA224"

#define ALGORITHM_NAME			"32/" ARCH_BITS_STR

#define BENCHMARK_COMMENT		""
#define BENCHMARK_LENGTH		-1

#define PLAINTEXT_LENGTH		64

#define BINARY_SIZE			(224/8)
#define SALT_SIZE			64

#define BLOCK_SIZE			64

#define MIN_KEYS_PER_CRYPT		1
#define MAX_KEYS_PER_CRYPT		1

static struct fmt_tests tests[] = {
	{"what do ya want for nothing?#a30e01098bc6dbbf45690f3a7e9e6d0f8bbea2a39e6148008fd05e44", "Jefe"},
	{NULL}
};

static char crypt_key[BINARY_SIZE+1];
static unsigned char opad[BLOCK_SIZE];
static unsigned char ipad[BLOCK_SIZE];
static unsigned char cursalt[SALT_SIZE];
static unsigned char out[PLAINTEXT_LENGTH + 1];

static int valid(char *ciphertext, struct fmt_main *pFmt)
{
	int pos, i;

	for(i=0;(i<strlen(ciphertext)) && (ciphertext[i]!='#');i++) ;
	if(i==strlen(ciphertext))
		return 0;
	pos = i+1;
	if (strlen(ciphertext+pos) != BINARY_SIZE*2) return 0;
	for (i = pos; i < BINARY_SIZE*2+pos; i++) {
		if (!(  (('0' <= ciphertext[i])&&(ciphertext[i] <= '9')) ||
		        (('a' <= ciphertext[i])&&(ciphertext[i] <= 'f'))
		        || (('A' <= ciphertext[i])&&(ciphertext[i] <= 'F'))))
			return 0;
	}
	return 1;
}

static void set_salt(void *salt)
{
	memcpy(cursalt, salt, SALT_SIZE);
}

static void set_key(char *key, int index)
{
	int i;
	int len;

	len = strlen(key);

	memset(ipad, 0x36, BLOCK_SIZE);
	memset(opad, 0x5C, BLOCK_SIZE);

	for(i=0;i<len;i++)
	{
		ipad[i] ^= key[i];
		opad[i] ^= key[i];
	}
}

static char *get_key(int index)
{
	unsigned int i;
	for(i=0;i<PLAINTEXT_LENGTH;i++)
		out[i] = ipad[ i ] ^ 0x36;
	out[i] = 0;
	return (char*) out;
}

static int cmp_all(void *binary, int count)
{
	return !memcmp(binary, crypt_key, BINARY_SIZE);
}

static int cmp_exact(char *source, int count)
{
	return (1);
}

static int cmp_one(void *binary, int index)
{
	return !memcmp(binary, crypt_key, BINARY_SIZE);
}

static void crypt_all(int count)
{
	SHA256_CTX ctx;

	SHA224_Init( &ctx );
	SHA224_Update( &ctx, ipad, BLOCK_SIZE );
	SHA224_Update( &ctx, cursalt, strlen( (char*) cursalt) );
	SHA224_Final( (unsigned char*) crypt_key, &ctx);

	SHA224_Init( &ctx );
	SHA224_Update( &ctx, opad, BLOCK_SIZE );
	SHA224_Update( &ctx, crypt_key, BINARY_SIZE);
	SHA224_Final( (unsigned char*) crypt_key, &ctx);
}

static void *binary(char *ciphertext)
{
	static unsigned char realcipher[BINARY_SIZE];
	int i,pos;

	for(i=0;ciphertext[i]!='#';i++);
	pos=i+1;
	for(i=0;i<BINARY_SIZE;i++)
		realcipher[i] = atoi16[ARCH_INDEX(ciphertext[i*2+pos])]*16 + atoi16[ARCH_INDEX(ciphertext[i*2+1+pos])];

	return (void*)realcipher;
}

static void *salt(char *ciphertext)
{
	static unsigned char salt[SALT_SIZE];
	int i=0;
	memset(salt, 0, sizeof(salt));
	while(ciphertext[i]!='#')
	{
		salt[i] = ciphertext[i];
		i++;
	}
	return salt;
}

struct fmt_main fmt_hmacSHA224 = {
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
		fmt_default_init,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		binary,
		salt,
		{
			fmt_default_binary_hash,
			fmt_default_binary_hash,
			fmt_default_binary_hash,
			fmt_default_binary_hash,
			fmt_default_binary_hash
		},
		fmt_default_salt_hash,
		set_salt,
		set_key,
		get_key,
		fmt_default_clear_keys,
		crypt_all,
		{
			fmt_default_get_hash,
			fmt_default_get_hash,
			fmt_default_get_hash,
			fmt_default_get_hash,
			fmt_default_get_hash
		},
		cmp_all,
		cmp_one,
		cmp_exact
	}
};
