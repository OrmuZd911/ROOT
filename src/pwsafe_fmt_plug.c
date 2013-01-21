/* Password Safe and Password Gorilla cracker patch for JtR. Hacked together
 * during May of 2012 by Dhiru Kholia <dhiru.kholia at gmail.com>.
 *
 * This software is Copyright (c) 2012, Dhiru Kholia <dhiru.kholia at gmail.com>,
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted. */

#include "sha2.h"

#include <string.h>
#include <assert.h>
#include <errno.h>
#include "arch.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "params.h"
#include "options.h"
#include "base64.h"
#ifdef _OPENMP
static int omp_t = 1;
#include <omp.h>
#define OMP_SCALE               64
#endif

#define FORMAT_LABEL		"pwsafe"
#define FORMAT_NAME		"Password Safe SHA-256"
#define ALGORITHM_NAME		"32/" ARCH_BITS_STR
#define BENCHMARK_COMMENT	""
#define BENCHMARK_LENGTH	-1
#define PLAINTEXT_LENGTH	32
#define BINARY_SIZE		32
#define SALT_SIZE		sizeof(struct custom_salt)
#define MIN_KEYS_PER_CRYPT	1
#define MAX_KEYS_PER_CRYPT	1

static struct fmt_tests pwsafe_tests[] = {
	{"$pwsafe$*3*fefc1172093344c9d5577b25f5b4b6e5d2942c94f9fc24c21733e28ae6527521*2048*88cbaf7d8668c1a98263f5dce7cb39c3304c49a3e0d76a7ea475dc02ab2f97a7", "12345678"},
	{"$pwsafe$*3*581cd1135b9b993ccb0f6b01c1fcfacd799c69960496c96286f94fe1400c1b25*2048*4ab3c2d3af251e94eb2f753fdf30fb9da074bec6bac0fa9d9d152b95fc5795c6", "openwall"},
	{NULL}
};



static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static ARCH_WORD_32 (*crypt_out)[BINARY_SIZE / sizeof(ARCH_WORD_32)];

static struct custom_salt {
	int version;
	unsigned int iterations;
	char unsigned salt[32];
} *cur_salt;

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
	crypt_out = mem_calloc_tiny(sizeof(*crypt_out) * self->params.max_keys_per_crypt, MEM_ALIGN_WORD);
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	// format $pwsafe$version*salt*iterations*hash
	char *p;
	char *ctcopy;
	char *keeptr;
	if (strncmp(ciphertext, "$pwsafe$", 8) != 0)
		return 0;
	ctcopy = strdup(ciphertext);
	keeptr = ctcopy;
	ctcopy += 9;		/* skip over "$pwsafe$*" */
	if ((p = strtok(ctcopy, "*")) == NULL)	/* version */
		return 0;
	if (atoi(p) == 0)
		return 0;
	if ((p = strtok(NULL, "*")) == NULL)	/* salt */
		return 0;
	if (strlen(p) < 64)
		return 0;
	if ((p = strtok(NULL, "*")) == NULL)	/* iterations */
		return 0;
	if (atoi(p) == 0)
		return 0;
	if ((p = strtok(NULL, "*")) == NULL)	/* hash */
		return 0;
	if (strlen(p) != 64)
		return 0;
	MEM_FREE(keeptr);
	return 1;
}

static void *get_salt(char *ciphertext)
{
	char *ctcopy = strdup(ciphertext);
	char *keeptr = ctcopy;
	char *p;
	int i;
	static struct custom_salt cs;
	ctcopy += 9;	/* skip over "$pwsafe$*" */
	p = strtok(ctcopy, "*");
	cs.version = atoi(p);
	p = strtok(NULL, "*");
	for (i = 0; i < 32; i++)
		cs.salt[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	p = strtok(NULL, "*");
	cs.iterations = (unsigned int)atoi(p);
	MEM_FREE(keeptr);
	return (void *)&cs;
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
	p = strrchr(ciphertext, '*') + 1;
	for (i = 0; i < BINARY_SIZE; i++) {
		out[i] =
		    (atoi16[ARCH_INDEX(*p)] << 4) |
		    atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}

	return out;
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

static void set_salt(void *salt)
{
	cur_salt = (struct custom_salt *)salt;
}

#define rotl(x,y) ( x<<y | x>>(32-y) )
#define rotr(x,y) ( x>>y | x<<(32-y) )
#define CHOICE(x,y,z) ( z ^ (x & ( y ^ z)) )
#define MAJORITY(x,y,z) ( (x & y) | (z & (x | y)) )
#define ROTXOR1(x) (rotr(x,2) ^ rotr(x,13) ^ rotr(x,22))
#define ROTXOR2(x) (rotr(x,6) ^ rotr(x,11) ^ rotr(x,25))
#define ROTXOR3(x) (rotr(x,7) ^ rotr(x,18) ^ (x>>3))
#define ROTXOR4(x) (rotr(x,17) ^ rotr(x,19) ^ (x>>10))
#define bytereverse(x) ( ((x) << 24) | (((x) << 8) & 0x00ff0000) | (((x) >> 8) & 0x0000ff00) | ((x) >> 24) )

static void pwsafe_sha256_iterate(unsigned int * state, unsigned int iterations)
{
	unsigned int word00,word01,word02,word03,word04,word05,word06,word07;
	unsigned int word08,word09,word10,word11,word12,word13,word14,word15;
	unsigned int temp0, temp1, temp2, temp3, temp4, temp5, temp6, temp7;
	iterations++;
	word00 = state[0];
	word01 = state[1];
	word02 = state[2];
	word03 = state[3];
	word04 = state[4];
	word05 = state[5];
	word06 = state[6];
	word07 = state[7];
	while(iterations)
	{
		iterations--;
		temp0 = 0x6a09e667UL;
		temp1 = 0xbb67ae85UL;
		temp2 = 0x3c6ef372UL;
		temp3 = 0xa54ff53aUL;
		temp4 = 0x510e527fUL;
		temp5 = 0x9b05688cUL;
		temp6 = 0x1f83d9abUL;
		temp7 = 0x5be0cd19UL;

		temp7 += ROTXOR2( temp4 ) + CHOICE( temp4, temp5, temp6 ) + 0x428a2f98 + (word00);
		temp3 += temp7;
		temp7 += ROTXOR1( temp0 ) + MAJORITY( temp0, temp1, temp2 );

		temp6 += ROTXOR2( temp3 ) + CHOICE( temp3, temp4, temp5 ) + 0x71374491 + (word01);
		temp2 += temp6;
		temp6 += ROTXOR1( temp7 ) + MAJORITY( temp7, temp0, temp1 );

		temp5 += ROTXOR2( temp2 ) + CHOICE( temp2, temp3, temp4 ) + 0xb5c0fbcf + (word02);
		temp1 += temp5;
		temp5 += ROTXOR1( temp6 ) + MAJORITY( temp6, temp7, temp0 );

		temp4 += ROTXOR2( temp1 ) + CHOICE( temp1, temp2, temp3 ) + 0xe9b5dba5 + (word03);
		temp0 += temp4;
		temp4 += ROTXOR1( temp5 ) + MAJORITY( temp5, temp6, temp7 );

		temp3 += ROTXOR2( temp0 ) + CHOICE( temp0, temp1, temp2 ) + 0x3956c25b + (word04);
		temp7 += temp3;
		temp3 += ROTXOR1( temp4 ) + MAJORITY( temp4, temp5, temp6 );

		temp2 += ROTXOR2( temp7 ) + CHOICE( temp7, temp0, temp1 ) + 0x59f111f1 + (word05);
		temp6 += temp2;
		temp2 += ROTXOR1( temp3 ) + MAJORITY( temp3, temp4, temp5 );

		temp1 += ROTXOR2( temp6 ) + CHOICE( temp6, temp7, temp0 ) + 0x923f82a4 + (word06);
		temp5 += temp1;
		temp1 += ROTXOR1( temp2 ) + MAJORITY( temp2, temp3, temp4 );

		temp0 += ROTXOR2( temp5 ) + CHOICE( temp5, temp6, temp7 ) + 0xab1c5ed5 + (word07);
		temp4 += temp0;
		temp0 += ROTXOR1( temp1 ) + MAJORITY( temp1, temp2, temp3 );

		temp7 += ROTXOR2( temp4 ) + CHOICE( temp4, temp5, temp6 ) + 0xd807aa98 + ( (word08 = 0x80000000U) );
		temp3 += temp7;
		temp7 += ROTXOR1( temp0 ) + MAJORITY( temp0, temp1, temp2 );

		temp6 += ROTXOR2( temp3 ) + CHOICE( temp3, temp4, temp5 ) + 0x12835b01 + ( (word09 = 0) );
		temp2 += temp6;
		temp6 += ROTXOR1( temp7 ) + MAJORITY( temp7, temp0, temp1 );

		temp5 += ROTXOR2( temp2 ) + CHOICE( temp2, temp3, temp4 ) + 0x243185be + ( (word10 = 0) );
		temp1 += temp5;
		temp5 += ROTXOR1( temp6 ) + MAJORITY( temp6, temp7, temp0 );

		temp4 += ROTXOR2( temp1 ) + CHOICE( temp1, temp2, temp3 ) + 0x550c7dc3 + ( (word11 = 0) );
		temp0 += temp4;
		temp4 += ROTXOR1( temp5 ) + MAJORITY( temp5, temp6, temp7 );

		temp3 += ROTXOR2( temp0 ) + CHOICE( temp0, temp1, temp2 ) + 0x72be5d74 + ( (word12 = 0) );
		temp7 += temp3;
		temp3 += ROTXOR1( temp4 ) + MAJORITY( temp4, temp5, temp6 );

		temp2 += ROTXOR2( temp7 ) + CHOICE( temp7, temp0, temp1 ) + 0x80deb1fe + ( (word13 = 0) );
		temp6 += temp2;
		temp2 += ROTXOR1( temp3 ) + MAJORITY( temp3, temp4, temp5 );

		temp1 += ROTXOR2( temp6 ) + CHOICE( temp6, temp7, temp0 ) + 0x9bdc06a7 + ( (word14 = 0) );
		temp5 += temp1;
		temp1 += ROTXOR1( temp2 ) + MAJORITY( temp2, temp3, temp4 );

		temp0 += ROTXOR2( temp5 ) + CHOICE( temp5, temp6, temp7 ) + 0xc19bf174 + ( (word15 = 256) );
		temp4 += temp0;
		temp0 += ROTXOR1( temp1 ) + MAJORITY( temp1, temp2, temp3 );



		temp7 += ROTXOR2( temp4 ) + CHOICE( temp4, temp5, temp6 ) + 0xe49b69c1 + ( (word00 += ROTXOR4( word14 ) + word09 + ROTXOR3( word01 ) ) );
		temp3 += temp7;
		temp7 += ROTXOR1( temp0 ) + MAJORITY( temp0, temp1, temp2 );

		temp6 += ROTXOR2( temp3 ) + CHOICE( temp3, temp4, temp5 ) + 0xefbe4786 + ( (word01 += ROTXOR4( word15 ) + word10 + ROTXOR3( word02 ) ) );
		temp2 += temp6;
		temp6 += ROTXOR1( temp7 ) + MAJORITY( temp7, temp0, temp1 );

		temp5 += ROTXOR2( temp2 ) + CHOICE( temp2, temp3, temp4 ) + 0x0fc19dc6 + ( (word02 += ROTXOR4( word00 ) + word11 + ROTXOR3( word03 ) ) );
		temp1 += temp5;
		temp5 += ROTXOR1( temp6 ) + MAJORITY( temp6, temp7, temp0 );

		temp4 += ROTXOR2( temp1 ) + CHOICE( temp1, temp2, temp3 ) + 0x240ca1cc + ( (word03 += ROTXOR4( word01 ) + word12 + ROTXOR3( word04 ) ) );
		temp0 += temp4;
		temp4 += ROTXOR1( temp5 ) + MAJORITY( temp5, temp6, temp7 );

		temp3 += ROTXOR2( temp0 ) + CHOICE( temp0, temp1, temp2 ) + 0x2de92c6f + ( (word04 += ROTXOR4( word02 ) + word13 + ROTXOR3( word05 ) ) );
		temp7 += temp3;
		temp3 += ROTXOR1( temp4 ) + MAJORITY( temp4, temp5, temp6 );

		temp2 += ROTXOR2( temp7 ) + CHOICE( temp7, temp0, temp1 ) + 0x4a7484aa + ( (word05 += ROTXOR4( word03 ) + word14 + ROTXOR3( word06 ) ) );
		temp6 += temp2;
		temp2 += ROTXOR1( temp3 ) + MAJORITY( temp3, temp4, temp5 );

		temp1 += ROTXOR2( temp6 ) + CHOICE( temp6, temp7, temp0 ) + 0x5cb0a9dc + ( (word06 += ROTXOR4( word04 ) + word15 + ROTXOR3( word07 ) ) );
		temp5 += temp1;
		temp1 += ROTXOR1( temp2 ) + MAJORITY( temp2, temp3, temp4 );

		temp0 += ROTXOR2( temp5 ) + CHOICE( temp5, temp6, temp7 ) + 0x76f988da + ( (word07 += ROTXOR4( word05 ) + word00 + ROTXOR3( word08 ) ) );
		temp4 += temp0;
		temp0 += ROTXOR1( temp1 ) + MAJORITY( temp1, temp2, temp3 );

		temp7 += ROTXOR2( temp4 ) + CHOICE( temp4, temp5, temp6 ) + 0x983e5152 + ( (word08 += ROTXOR4( word06 ) + word01 + ROTXOR3( word09 ) ) );
		temp3 += temp7;
		temp7 += ROTXOR1( temp0 ) + MAJORITY( temp0, temp1, temp2 );

		temp6 += ROTXOR2( temp3 ) + CHOICE( temp3, temp4, temp5 ) + 0xa831c66d + ( (word09 += ROTXOR4( word07 ) + word02 + ROTXOR3( word10 ) ) );
		temp2 += temp6;
		temp6 += ROTXOR1( temp7 ) + MAJORITY( temp7, temp0, temp1 );

		temp5 += ROTXOR2( temp2 ) + CHOICE( temp2, temp3, temp4 ) + 0xb00327c8 + ( (word10 += ROTXOR4( word08 ) + word03 + ROTXOR3( word11 ) ) );
		temp1 += temp5;
		temp5 += ROTXOR1( temp6 ) + MAJORITY( temp6, temp7, temp0 );

		temp4 += ROTXOR2( temp1 ) + CHOICE( temp1, temp2, temp3 ) + 0xbf597fc7 + ( (word11 += ROTXOR4( word09 ) + word04 + ROTXOR3( word12 ) ) );
		temp0 += temp4;
		temp4 += ROTXOR1( temp5 ) + MAJORITY( temp5, temp6, temp7 );

		temp3 += ROTXOR2( temp0 ) + CHOICE( temp0, temp1, temp2 ) + 0xc6e00bf3 + ( (word12 += ROTXOR4( word10 ) + word05 + ROTXOR3( word13 ) ) );
		temp7 += temp3;
		temp3 += ROTXOR1( temp4 ) + MAJORITY( temp4, temp5, temp6 );

		temp2 += ROTXOR2( temp7 ) + CHOICE( temp7, temp0, temp1 ) + 0xd5a79147 + ( (word13 += ROTXOR4( word11 ) + word06 + ROTXOR3( word14 ) ) );
		temp6 += temp2;
		temp2 += ROTXOR1( temp3 ) + MAJORITY( temp3, temp4, temp5 );

		temp1 += ROTXOR2( temp6 ) + CHOICE( temp6, temp7, temp0 ) + 0x06ca6351 + ( (word14 += ROTXOR4( word12 ) + word07 + ROTXOR3( word15 ) ) );
		temp5 += temp1;
		temp1 += ROTXOR1( temp2 ) + MAJORITY( temp2, temp3, temp4 );

		temp0 += ROTXOR2( temp5 ) + CHOICE( temp5, temp6, temp7 ) + 0x14292967 + ( (word15 += ROTXOR4( word13 ) + word08 + ROTXOR3( word00 ) ) );
		temp4 += temp0;
		temp0 += ROTXOR1( temp1 ) + MAJORITY( temp1, temp2, temp3 );




		temp7 += ROTXOR2( temp4 ) + CHOICE( temp4, temp5, temp6 ) + 0x27b70a85 + ( (word00 += ROTXOR4( word14 ) + word09 + ROTXOR3( word01 ) ) );
		temp3 += temp7;
		temp7 += ROTXOR1( temp0 ) + MAJORITY( temp0, temp1, temp2 );

		temp6 += ROTXOR2( temp3 ) + CHOICE( temp3, temp4, temp5 ) + 0x2e1b2138 + ( (word01 += ROTXOR4( word15 ) + word10 + ROTXOR3( word02 ) ) );
		temp2 += temp6;
		temp6 += ROTXOR1( temp7 ) + MAJORITY( temp7, temp0, temp1 );

		temp5 += ROTXOR2( temp2 ) + CHOICE( temp2, temp3, temp4 ) + 0x4d2c6dfc + ( (word02 += ROTXOR4( word00 ) + word11 + ROTXOR3( word03 ) ) );
		temp1 += temp5;
		temp5 += ROTXOR1( temp6 ) + MAJORITY( temp6, temp7, temp0 );

		temp4 += ROTXOR2( temp1 ) + CHOICE( temp1, temp2, temp3 ) + 0x53380d13 + ( (word03 += ROTXOR4( word01 ) + word12 + ROTXOR3( word04 ) ) );
		temp0 += temp4;
		temp4 += ROTXOR1( temp5 ) + MAJORITY( temp5, temp6, temp7 );

		temp3 += ROTXOR2( temp0 ) + CHOICE( temp0, temp1, temp2 ) + 0x650a7354 + ( (word04 += ROTXOR4( word02 ) + word13 + ROTXOR3( word05 ) ) );
		temp7 += temp3;
		temp3 += ROTXOR1( temp4 ) + MAJORITY( temp4, temp5, temp6 );

		temp2 += ROTXOR2( temp7 ) + CHOICE( temp7, temp0, temp1 ) + 0x766a0abb + ( (word05 += ROTXOR4( word03 ) + word14 + ROTXOR3( word06 ) ) );
		temp6 += temp2;
		temp2 += ROTXOR1( temp3 ) + MAJORITY( temp3, temp4, temp5 );

		temp1 += ROTXOR2( temp6 ) + CHOICE( temp6, temp7, temp0 ) + 0x81c2c92e + ( (word06 += ROTXOR4( word04 ) + word15 + ROTXOR3( word07 ) ) );
		temp5 += temp1;
		temp1 += ROTXOR1( temp2 ) + MAJORITY( temp2, temp3, temp4 );

		temp0 += ROTXOR2( temp5 ) + CHOICE( temp5, temp6, temp7 ) + 0x92722c85 + ( (word07 += ROTXOR4( word05 ) + word00 + ROTXOR3( word08 ) ) );
		temp4 += temp0;
		temp0 += ROTXOR1( temp1 ) + MAJORITY( temp1, temp2, temp3 );

		temp7 += ROTXOR2( temp4 ) + CHOICE( temp4, temp5, temp6 ) + 0xa2bfe8a1 + ( (word08 += ROTXOR4( word06 ) + word01 + ROTXOR3( word09 ) ) );
		temp3 += temp7;
		temp7 += ROTXOR1( temp0 ) + MAJORITY( temp0, temp1, temp2 );

		temp6 += ROTXOR2( temp3 ) + CHOICE( temp3, temp4, temp5 ) + 0xa81a664b + ( (word09 += ROTXOR4( word07 ) + word02 + ROTXOR3( word10 ) ) );
		temp2 += temp6;
		temp6 += ROTXOR1( temp7 ) + MAJORITY( temp7, temp0, temp1 );

		temp5 += ROTXOR2( temp2 ) + CHOICE( temp2, temp3, temp4 ) + 0xc24b8b70 + ( (word10 += ROTXOR4( word08 ) + word03 + ROTXOR3( word11 ) ) );
		temp1 += temp5;
		temp5 += ROTXOR1( temp6 ) + MAJORITY( temp6, temp7, temp0 );

		temp4 += ROTXOR2( temp1 ) + CHOICE( temp1, temp2, temp3 ) + 0xc76c51a3 + ( (word11 += ROTXOR4( word09 ) + word04 + ROTXOR3( word12 ) ) );
		temp0 += temp4;
		temp4 += ROTXOR1( temp5 ) + MAJORITY( temp5, temp6, temp7 );

		temp3 += ROTXOR2( temp0 ) + CHOICE( temp0, temp1, temp2 ) + 0xd192e819 + ( (word12 += ROTXOR4( word10 ) + word05 + ROTXOR3( word13 ) ) );
		temp7 += temp3;
		temp3 += ROTXOR1( temp4 ) + MAJORITY( temp4, temp5, temp6 );

		temp2 += ROTXOR2( temp7 ) + CHOICE( temp7, temp0, temp1 ) + 0xd6990624 + ( (word13 += ROTXOR4( word11 ) + word06 + ROTXOR3( word14 ) ) );
		temp6 += temp2;
		temp2 += ROTXOR1( temp3 ) + MAJORITY( temp3, temp4, temp5 );

		temp1 += ROTXOR2( temp6 ) + CHOICE( temp6, temp7, temp0 ) + 0xf40e3585 + ( (word14 += ROTXOR4( word12 ) + word07 + ROTXOR3( word15 ) ) );
		temp5 += temp1;
		temp1 += ROTXOR1( temp2 ) + MAJORITY( temp2, temp3, temp4 );

		temp0 += ROTXOR2( temp5 ) + CHOICE( temp5, temp6, temp7 ) + 0x106aa070 + ( (word15 += ROTXOR4( word13 ) + word08 + ROTXOR3( word00 ) ) );
		temp4 += temp0;
		temp0 += ROTXOR1( temp1 ) + MAJORITY( temp1, temp2, temp3 );




		temp7 += ROTXOR2( temp4 ) + CHOICE( temp4, temp5, temp6 ) + 0x19a4c116 + ( (word00 += ROTXOR4( word14 ) + word09 + ROTXOR3( word01 ) ) );
		temp3 += temp7;
		temp7 += ROTXOR1( temp0 ) + MAJORITY( temp0, temp1, temp2 );

		temp6 += ROTXOR2( temp3 ) + CHOICE( temp3, temp4, temp5 ) + 0x1e376c08 + ( (word01 += ROTXOR4( word15 ) + word10 + ROTXOR3( word02 ) ) );
		temp2 += temp6;
		temp6 += ROTXOR1( temp7 ) + MAJORITY( temp7, temp0, temp1 );

		temp5 += ROTXOR2( temp2 ) + CHOICE( temp2, temp3, temp4 ) + 0x2748774c + ( (word02 += ROTXOR4( word00 ) + word11 + ROTXOR3( word03 ) ) );
		temp1 += temp5;
		temp5 += ROTXOR1( temp6 ) + MAJORITY( temp6, temp7, temp0 );

		temp4 += ROTXOR2( temp1 ) + CHOICE( temp1, temp2, temp3 ) + 0x34b0bcb5 + ( (word03 += ROTXOR4( word01 ) + word12 + ROTXOR3( word04 ) ) );
		temp0 += temp4;
		temp4 += ROTXOR1( temp5 ) + MAJORITY( temp5, temp6, temp7 );

		temp3 += ROTXOR2( temp0 ) + CHOICE( temp0, temp1, temp2 ) + 0x391c0cb3 + ( (word04 += ROTXOR4( word02 ) + word13 + ROTXOR3( word05 ) ) );
		temp7 += temp3;
		temp3 += ROTXOR1( temp4 ) + MAJORITY( temp4, temp5, temp6 );

		temp2 += ROTXOR2( temp7 ) + CHOICE( temp7, temp0, temp1 ) + 0x4ed8aa4a + ( (word05 += ROTXOR4( word03 ) + word14 + ROTXOR3( word06 ) ) );
		temp6 += temp2;
		temp2 += ROTXOR1( temp3 ) + MAJORITY( temp3, temp4, temp5 );

		temp1 += ROTXOR2( temp6 ) + CHOICE( temp6, temp7, temp0 ) + 0x5b9cca4f + ( (word06 += ROTXOR4( word04 ) + word15 + ROTXOR3( word07 ) ) );
		temp5 += temp1;
		temp1 += ROTXOR1( temp2 ) + MAJORITY( temp2, temp3, temp4 );

		temp0 += ROTXOR2( temp5 ) + CHOICE( temp5, temp6, temp7 ) + 0x682e6ff3 + ( (word07 += ROTXOR4( word05 ) + word00 + ROTXOR3( word08 ) ) );
		temp4 += temp0;
		temp0 += ROTXOR1( temp1 ) + MAJORITY( temp1, temp2, temp3 );

		temp7 += ROTXOR2( temp4 ) + CHOICE( temp4, temp5, temp6 ) + 0x748f82ee + ( (word08 += ROTXOR4( word06 ) + word01 + ROTXOR3( word09 ) ) );
		temp3 += temp7;
		temp7 += ROTXOR1( temp0 ) + MAJORITY( temp0, temp1, temp2 );

		temp6 += ROTXOR2( temp3 ) + CHOICE( temp3, temp4, temp5 ) + 0x78a5636f + ( (word09 += ROTXOR4( word07 ) + word02 + ROTXOR3( word10 ) ) );
		temp2 += temp6;
		temp6 += ROTXOR1( temp7 ) + MAJORITY( temp7, temp0, temp1 );

		temp5 += ROTXOR2( temp2 ) + CHOICE( temp2, temp3, temp4 ) + 0x84c87814 + ( (word10 += ROTXOR4( word08 ) + word03 + ROTXOR3( word11 ) ) );
		temp1 += temp5;
		temp5 += ROTXOR1( temp6 ) + MAJORITY( temp6, temp7, temp0 );

		temp4 += ROTXOR2( temp1 ) + CHOICE( temp1, temp2, temp3 ) + 0x8cc70208 + ( (word11 += ROTXOR4( word09 ) + word04 + ROTXOR3( word12 ) ) );
		temp0 += temp4;
		temp4 += ROTXOR1( temp5 ) + MAJORITY( temp5, temp6, temp7 );

		temp3 += ROTXOR2( temp0 ) + CHOICE( temp0, temp1, temp2 ) + 0x90befffa + ( (word12 += ROTXOR4( word10 ) + word05 + ROTXOR3( word13 ) ) );
		temp7 += temp3;
		temp3 += ROTXOR1( temp4 ) + MAJORITY( temp4, temp5, temp6 );

		temp2 += ROTXOR2( temp7 ) + CHOICE( temp7, temp0, temp1 ) + 0xa4506ceb + ( (word13 += ROTXOR4( word11 ) + word06 + ROTXOR3( word14 ) ) );
		temp6 += temp2;
		temp2 += ROTXOR1( temp3 ) + MAJORITY( temp3, temp4, temp5 );

		temp1 += ROTXOR2( temp6 ) + CHOICE( temp6, temp7, temp0 ) + 0xbef9a3f7 + ( (word14 += ROTXOR4( word12 ) + word07 + ROTXOR3( word15 ) ) );
		temp5 += temp1;
		temp1 += ROTXOR1( temp2 ) + MAJORITY( temp2, temp3, temp4 );

		temp0 += ROTXOR2( temp5 ) + CHOICE( temp5, temp6, temp7 ) + 0xc67178f2 + ( (word15 += ROTXOR4( word13 ) + word08 + ROTXOR3( word00 ) ) );
		temp4 += temp0;
		temp0 += ROTXOR1( temp1 ) + MAJORITY( temp1, temp2, temp3 );

		word00 = 0x6a09e667UL + temp0;
		word01 = 0xbb67ae85UL + temp1;
		word02 = 0x3c6ef372UL + temp2;
		word03 = 0xa54ff53aUL + temp3;
		word04 = 0x510e527fUL + temp4;
		word05 = 0x9b05688cUL + temp5;
		word06 = 0x1f83d9abUL + temp6;
		word07 = 0x5be0cd19UL + temp7;
	}
	state[0] = bytereverse(word00);
	state[1] = bytereverse(word01);
	state[2] = bytereverse(word02);
	state[3] = bytereverse(word03);
	state[4] = bytereverse(word04);
	state[5] = bytereverse(word05);
	state[6] = bytereverse(word06);
	state[7] = bytereverse(word07);
}

static void crypt_all(int count)
{
	int index = 0;
#ifdef _OPENMP
#pragma omp parallel for
	for (index = 0; index < count; index++)
#endif
	{
		SHA256_CTX ctx;
		SHA256_Init(&ctx);
		SHA256_Update(&ctx, saved_key[index], strlen(saved_key[index]));
		SHA256_Update(&ctx, cur_salt->salt, 32);
		SHA256_Final((unsigned char*)crypt_out[index], &ctx);
		pwsafe_sha256_iterate(ctx.h, cur_salt->iterations);
		memcpy(crypt_out[index], ctx.h, 32);
	}
}

static int cmp_all(void *binary, int count)
{
	int index = 0;
#ifdef _OPENMP
	for (; index < count; index++)
#endif
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

static void pwsafe_set_key(char *key, int index)
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

struct fmt_main fmt_pwsafe = {
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
		FMT_CASE | FMT_8_BIT | FMT_OMP,
		pwsafe_tests
	}, {
		init,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		get_binary,
		get_salt,
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
		pwsafe_set_key,
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
