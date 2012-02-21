/*
* This software is Copyright (c) 2011 Lukas Odzioba <lukas dot odzioba at gmail dot com> 
* and it is hereby released to the general public under the following terms:
* Redistribution and use in source and binary forms, with or without modification, are permitted.
* Based on S3nf implementation http://openwall.info/wiki/john/MSCash2
*/

#include <stdio.h>
#include "../cuda_mscash2.h"
#include "cuda_common.cuh"
extern "C" void mscash2_gpu(mscash2_password *, mscash2_hash *, mscash2_salt *);

__constant__ mscash2_salt cuda_salt[1];

__host__ void md4_crypt(uint32_t * buffer, uint32_t * hash)
{
	uint32_t a;
	uint32_t b;
	uint32_t c;
	uint32_t d;

	a = 0xFFFFFFFF + buffer[0];
	a = (a << 3) | (a >> 29);
	d = INIT_D + (INIT_C ^ (a & 0x77777777)) + buffer[1];
	d = (d << 7) | (d >> 25);
	c = INIT_C + (INIT_B ^ (d & (a ^ INIT_B))) + buffer[2];
	c = (c << 11) | (c >> 21);
	b = INIT_B + (a ^ (c & (d ^ a))) + buffer[3];
	b = (b << 19) | (b >> 13);

	a += (d ^ (b & (c ^ d))) + buffer[4];
	a = (a << 3) | (a >> 29);
	d += (c ^ (a & (b ^ c))) + buffer[5];
	d = (d << 7) | (d >> 25);
	c += (b ^ (d & (a ^ b))) + buffer[6];
	c = (c << 11) | (c >> 21);
	b += (a ^ (c & (d ^ a))) + buffer[7];
	b = (b << 19) | (b >> 13);

	a += (d ^ (b & (c ^ d))) + buffer[8];
	a = (a << 3) | (a >> 29);
	d += (c ^ (a & (b ^ c))) + buffer[9];
	d = (d << 7) | (d >> 25);
	c += (b ^ (d & (a ^ b))) + buffer[10];
	c = (c << 11) | (c >> 21);
	b += (a ^ (c & (d ^ a))) + buffer[11];
	b = (b << 19) | (b >> 13);

	a += (d ^ (b & (c ^ d))) + buffer[12];
	a = (a << 3) | (a >> 29);
	d += (c ^ (a & (b ^ c))) + buffer[13];
	d = (d << 7) | (d >> 25);
	c += (b ^ (d & (a ^ b))) + buffer[14];
	c = (c << 11) | (c >> 21);
	b += (a ^ (c & (d ^ a))) + buffer[15];
	b = (b << 19) | (b >> 13);

	a += ((b & (c | d)) | (c & d)) + buffer[0] + SQRT_2;
	a = (a << 3) | (a >> 29);
	d += ((a & (b | c)) | (b & c)) + buffer[4] + SQRT_2;
	d = (d << 5) | (d >> 27);
	c += ((d & (a | b)) | (a & b)) + buffer[8] + SQRT_2;
	c = (c << 9) | (c >> 23);
	b += ((c & (d | a)) | (d & a)) + buffer[12] + SQRT_2;
	b = (b << 13) | (b >> 19);

	a += ((b & (c | d)) | (c & d)) + buffer[1] + SQRT_2;
	a = (a << 3) | (a >> 29);
	d += ((a & (b | c)) | (b & c)) + buffer[5] + SQRT_2;
	d = (d << 5) | (d >> 27);
	c += ((d & (a | b)) | (a & b)) + buffer[9] + SQRT_2;
	c = (c << 9) | (c >> 23);
	b += ((c & (d | a)) | (d & a)) + buffer[13] + SQRT_2;
	b = (b << 13) | (b >> 19);

	a += ((b & (c | d)) | (c & d)) + buffer[2] + SQRT_2;
	a = (a << 3) | (a >> 29);
	d += ((a & (b | c)) | (b & c)) + buffer[6] + SQRT_2;
	d = (d << 5) | (d >> 27);
	c += ((d & (a | b)) | (a & b)) + buffer[10] + SQRT_2;
	c = (c << 9) | (c >> 23);
	b += ((c & (d | a)) | (d & a)) + buffer[14] + SQRT_2;
	b = (b << 13) | (b >> 19);

	a += ((b & (c | d)) | (c & d)) + buffer[3] + SQRT_2;
	a = (a << 3) | (a >> 29);
	d += ((a & (b | c)) | (b & c)) + buffer[7] + SQRT_2;
	d = (d << 5) | (d >> 27);
	c += ((d & (a | b)) | (a & b)) + buffer[11] + SQRT_2;
	c = (c << 9) | (c >> 23);
	b += ((c & (d | a)) | (d & a)) + buffer[15] + SQRT_2;
	b = (b << 13) | (b >> 19);

	a += (d ^ c ^ b) + buffer[0] + SQRT_3;
	a = (a << 3) | (a >> 29);
	d += (c ^ b ^ a) + buffer[8] + SQRT_3;
	d = (d << 9) | (d >> 23);
	c += (b ^ a ^ d) + buffer[4] + SQRT_3;
	c = (c << 11) | (c >> 21);
	b += (a ^ d ^ c) + buffer[12] + SQRT_3;
	b = (b << 15) | (b >> 17);

	a += (d ^ c ^ b) + buffer[2] + SQRT_3;
	a = (a << 3) | (a >> 29);
	d += (c ^ b ^ a) + buffer[10] + SQRT_3;
	d = (d << 9) | (d >> 23);
	c += (b ^ a ^ d) + buffer[6] + SQRT_3;
	c = (c << 11) | (c >> 21);
	b += (a ^ d ^ c) + buffer[14] + SQRT_3;
	b = (b << 15) | (b >> 17);

	a += (d ^ c ^ b) + buffer[1] + SQRT_3;
	a = (a << 3) | (a >> 29);
	d += (c ^ b ^ a) + buffer[9] + SQRT_3;
	d = (d << 9) | (d >> 23);
	c += (b ^ a ^ d) + buffer[5] + SQRT_3;
	c = (c << 11) | (c >> 21);
	b += (a ^ d ^ c) + buffer[13] + SQRT_3;
	b = (b << 15) | (b >> 17);

	a += (d ^ c ^ b) + buffer[3] + SQRT_3;
	a = (a << 3) | (a >> 29);

	d += (c ^ b ^ a) + buffer[11] + SQRT_3;
	d = (d << 9) | (d >> 23);
	c += (b ^ a ^ d) + buffer[7] + SQRT_3;
	c = (c << 11) | (c >> 21);
	b += (a ^ d ^ c) + buffer[15] + SQRT_3;
	b = (b << 15) | (b >> 17);

	hash[0] = a + INIT_A;
	hash[1] = b + INIT_B;
	hash[2] = c + INIT_C;
	hash[3] = d + INIT_D;
}

__device__ __host__ void preproc(const uint8_t * key, uint32_t keylen,
    uint32_t * state, uint8_t var)
{
	int i;
	uint32_t W[16], temp;
	uint8_t ipad[64];

	for (i = 0; i < 64; i++)
		ipad[i] = var;

	for (i = 0; i < keylen; i++)
		ipad[i] = ipad[i] ^ key[i];

#pragma unroll 16
	for (i = 0; i < 16; i++)
		GET_WORD_32_BE(W[i], ipad, i * 4);
	
	uint32_t A = INIT_A;
	uint32_t B = INIT_B;
	uint32_t C = INIT_C;
	uint32_t D = INIT_D;
	uint32_t E = INIT_E;

	SHA1(A, B, C, D, E, W);

	state[0] = A + INIT_A;
	state[1] = B + INIT_B;
	state[2] = C + INIT_C;
	state[3] = D + INIT_D;
	state[4] = E + INIT_E;

}

__device__ void hmac_sha1(const uint8_t * key, uint32_t keylen,
    const uint8_t * input, uint32_t inputlen, uint8_t * output,
    uint32_t * ipad_state, uint32_t * opad_state)
{
	int i;
	uint32_t temp, W[16];
	uint32_t A, B, C, D, E;
	uint32_t state_A,state_B,state_C,state_D,state_E;
	uint8_t buf[64];
	uint32_t *src=(uint32_t*)buf;
	i=64/4;
	while(i--)
	  *src++=0;

	memcpy(buf, input, inputlen);
	buf[inputlen] = 0x80;
	PUT_WORD_32_BE((64 + inputlen) << 3, buf, 60);

	A = ipad_state[0];
	B = ipad_state[1];
	C = ipad_state[2];
	D = ipad_state[3];
	E = ipad_state[4];
	
	state_A=A;
	state_B=B;
	state_C=C;
	state_D=D;
	state_E=E;

	for (i = 0; i < 16; i++)
		GET_WORD_32_BE(W[i], buf, i * 4);

	SHA1(A, B, C, D, E, W);

	A += state_A;
	B += state_B;
	C += state_C;
	D += state_D;
	E += state_E;

	PUT_WORD_32_BE(A, buf, 0);
	PUT_WORD_32_BE(B, buf, 4);
	PUT_WORD_32_BE(C, buf, 8);
	PUT_WORD_32_BE(D, buf, 12);
	PUT_WORD_32_BE(E, buf, 16);

	buf[20] = 0x80;
	PUT_WORD_32_BE(0x2A0, buf, 60);

	A = opad_state[0];
	B = opad_state[1];
	C = opad_state[2];
	D = opad_state[3];
	E = opad_state[4];
	
	state_A=A;
	state_B=B;
	state_C=C;
	state_D=D;
	state_E=E;

	for (i = 0; i < 16; i++)
		GET_WORD_32_BE(W[i], buf, i * 4);

	SHA1(A, B, C, D, E, W);

	A += state_A;
	B += state_B;
	C += state_C;
	D += state_D;
	E += state_E;

	PUT_WORD_32_BE(A, output, 0);
	PUT_WORD_32_BE(B, output, 4);
	PUT_WORD_32_BE(C, output, 8);
	PUT_WORD_32_BE(D, output, 12);
	PUT_WORD_32_BE(E, output, 16);
}

__device__ void pbkdf2(const uint8_t * pass, const uint8_t * salt,
    int saltlen, uint8_t * out)
{
	uint8_t temp[SHA1_DIGEST_LENGTH];
	__shared__ uint8_t sbuf[THREADS][48];
	uint8_t* buf=sbuf[threadIdx.x];
	uint32_t ipad_state[5];
	uint32_t opad_state[5];
	int i, j;
	uint8_t tmp_out[16];

	i=48/4;
	uint32_t *src=(uint32_t*)buf;
	while(i--)
	  *src++=0;

	memcpy(buf, salt, saltlen);
	buf[saltlen + 3] = 0x01;

	preproc(pass, 16, ipad_state, 0x36);
	preproc(pass, 16, opad_state, 0x5c);

	hmac_sha1(pass, 16, buf, saltlen + 4, temp, ipad_state, opad_state);

	memcpy(tmp_out, temp, 20);

	for (i = 1; i < ITERATIONS; i++) {
		hmac_sha1(pass, 16, temp, SHA1_DIGEST_LENGTH, temp, ipad_state,
		    opad_state);

#pragma unroll 16
		for (j = 0; j < 16; j++)
			tmp_out[j] ^= temp[j];
	}
	memcpy(out, tmp_out, 20);
}


__global__ void pbkdf2_kernel(mscash2_password * inbuffer,
    mscash2_hash * outbuffer)
{
	uint32_t idx = blockIdx.x * blockDim.x + threadIdx.x;

	uint32_t username_len = (uint32_t) cuda_salt[0].length;

	pbkdf2((uint8_t *) inbuffer[idx].dcc_hash,
	    cuda_salt[0].unicode_salt, username_len << 1,
	    (uint8_t *) outbuffer[idx].v);

}

__host__ void mscash_cpu(mscash2_password * inbuffer, mscash2_hash * outbuffer,
    mscash2_salt * host_salt)
    {
      
      int i,idx = 0;
	uint32_t buffer[16];
	uint32_t nt_hash[16];
	uint8_t salt[64];
	memset(salt,0,64);
	uint8_t *username = host_salt->salt;
	uint32_t username_len = (uint32_t) host_salt->length;
	

	for (i = 0; i < (username_len >> 1) + 1; i++)
		((uint32_t *) salt)[i] =
		    username[2 * i] | (username[2 * i + 1] << 16);
	memcpy(host_salt->unicode_salt, salt, 64);



	for (idx = 0; idx < KEYS_PER_CRYPT; idx++) {

		uint8_t *password = inbuffer[idx].v;
		uint32_t password_len = inbuffer[idx].length;
		memset(nt_hash, 0, 64);
		memset(buffer, 0, 64);

		for (i = 0; i < password_len >> 1; i++)
			buffer[i] =
			    password[2 * i] | (password[2 * i + 1] << 16);

		if (password_len % 2 == 1)
			buffer[i] = password[password_len - 1] | 0x800000;
		else
			buffer[i] = 0x80;

		buffer[14] = password_len << 4;

		md4_crypt(buffer, nt_hash);

		memcpy((uint8_t *) nt_hash + 16, salt, username_len << 1);

		i = username_len + 8;

		if (username_len % 2 == 1)
			nt_hash[i >> 1] =
			    username[username_len - 1] | 0x800000;
		else
			nt_hash[i >> 1] = 0x80;

		nt_hash[14] = i << 4;

		md4_crypt(nt_hash, inbuffer[idx].dcc_hash);

	}

      
    }
__host__ void mscash2_gpu(mscash2_password * inbuffer, mscash2_hash * outbuffer,
    mscash2_salt * host_salt)
{
	
	mscash_cpu(inbuffer,outbuffer,host_salt);
	mscash2_password *cuda_inbuffer;
	mscash2_hash *cuda_outbuffer;
	size_t insize = sizeof(mscash2_password) * KEYS_PER_CRYPT;
	size_t outsize = sizeof(mscash2_hash) * KEYS_PER_CRYPT;
	
	HANDLE_ERROR(cudaMemcpyToSymbol(cuda_salt, host_salt,
		sizeof(mscash2_salt)));
	
	HANDLE_ERROR(cudaMalloc(&cuda_inbuffer, insize));
	HANDLE_ERROR(cudaMalloc(&cuda_outbuffer, outsize));

	HANDLE_ERROR(cudaMemcpy(cuda_inbuffer, inbuffer, insize,
		cudaMemcpyHostToDevice));

	pbkdf2_kernel <<< BLOCKS, THREADS >>> (cuda_inbuffer, cuda_outbuffer);

	HANDLE_ERROR(cudaMemcpy(outbuffer, cuda_outbuffer, outsize,
		cudaMemcpyDeviceToHost));

	HANDLE_ERROR(cudaFree(cuda_inbuffer));
	HANDLE_ERROR(cudaFree(cuda_outbuffer));

}
