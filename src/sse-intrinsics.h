/*
 * This software is Copyright (c) 2010 bartavelle, <bartavelle at bandecon.com>, and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification, are permitted.
 *
 * Some modifications, Jim Fougeron, 2013.  Licensing rights listed in accompanying sse-intrinsics.c file.
 */

#include "common.h"
#include "sse-intrinsics-load-flags.h"

#ifndef _EMMINTRIN_H_INCLUDED
#define __m128i void
#endif

#define STRINGIZE2(s) #s
#define STRINGIZE(s) STRINGIZE2(s)

#if defined(__XOP__)
#define SSE_type			"XOP intrinsics"
#elif defined(__AVX__)
#define SSE_type			"AVX intrinsics"
#elif defined(MMX_COEF) && MMX_COEF == 2
#define SSE_type			"MMX"
#else
#define SSE_type			"SSE2 intrinsics"
#endif

#ifdef MD5_SSE_PARA
void md5cryptsse(unsigned char * buf, unsigned char * salt, char * out, int md5_type);
void SSEmd5body(__m128i* data, unsigned int * out, int init);
#define MD5_SSE_type			SSE_type
#define MD5_ALGORITHM_NAME		"128/128 " MD5_SSE_type " " MD5_N_STR
#elif defined(MMX_COEF) && MMX_COEF == 4
#define MD5_SSE_type			"SSE2"
#define MD5_ALGORITHM_NAME		"128/128 " MD5_SSE_type " 4x"
#elif defined(MMX_COEF) && MMX_COEF == 2
#define MD5_SSE_type			"MMX"
#define MD5_ALGORITHM_NAME		"64/64 " MD5_SSE_type " 2x"
#elif defined(MMX_COEF)
#define MD5_SSE_type			"?"
#define MD5_ALGORITHM_NAME		MD5_SSE_type
#else
#define MD5_SSE_type			"1x"
#define MD5_ALGORITHM_NAME		"32/" ARCH_BITS_STR
#endif

#ifdef MD4_SSE_PARA
void SSEmd4body(__m128i* data, unsigned int * out, int init);
#define MD4_SSE_type			SSE_type
#define MD4_ALGORITHM_NAME		"128/128 " MD4_SSE_type " " MD4_N_STR
#elif defined(MMX_COEF) && MMX_COEF == 4
#define MD4_SSE_type			"SSE2"
#define MD4_ALGORITHM_NAME		"128/128 " MD4_SSE_type " 4x"
#elif defined(MMX_COEF) && MMX_COEF == 2
#define MD4_SSE_type			"MMX"
#define MD4_ALGORITHM_NAME		"64/64 " MD4_SSE_type " 2x"
#elif defined(MMX_COEF)
#define MD4_SSE_type			"?"
#define MD4_ALGORITHM_NAME		MD4_SSE_type
#else
#define MD4_SSE_type			"1x"
#define MD4_ALGORITHM_NAME		"32/" ARCH_BITS_STR
#endif

#ifdef SHA1_SSE_PARA
void SSESHA1body(__m128i* data, unsigned int * out, unsigned int * reload_state, int input_layout_output); // if reload_state null, then 'normal' init performed.
#define SHA1_SSE_type			SSE_type
#define SHA1_ALGORITHM_NAME		"128/128 " SHA1_SSE_type " " SHA1_N_STR
#elif defined(MMX_COEF) && MMX_COEF == 4
#define SHA1_SSE_type			"SSE2"
#define SHA1_ALGORITHM_NAME		"128/128 " SHA1_SSE_type " 4x"
#elif defined(MMX_COEF) && MMX_COEF == 2
#define SHA1_SSE_type			"MMX"
#define SHA1_ALGORITHM_NAME		"64/64 " SHA1_SSE_type " 2x"
#elif defined(MMX_COEF)
#define SHA1_SSE_type			"?"
#define SHA1_ALGORITHM_NAME		SHA1_SSE_type
#else
#define SHA1_SSE_type			"1x"
#define SHA1_ALGORITHM_NAME		"32/" ARCH_BITS_STR
#endif

// code for SHA256 and SHA512 (from rawSHA256_ng_fmt.c and rawSHA512_ng_fmt.c)

#if defined __XOP__
#define SIMD_TYPE                 "XOP"
#elif defined __SSE4_1__
#define SIMD_TYPE                 "SSE4.1"
#elif defined __SSSE3__
#define SIMD_TYPE                 "SSSE3"
#else
#define SIMD_TYPE                 "SSE2"
#endif

#ifdef MMX_COEF_SHA256
#define SHA256_ALGORITHM_NAME	"128/128 " SIMD_TYPE " intrinsics " STRINGIZE(MMX_COEF_SHA256)"x"
void SSESHA256body(__m128i* data, ARCH_WORD_32 *out, int sha256_flags);
#endif

#ifdef MMX_COEF_SHA512
#define SHA512_ALGORITHM_NAME	"128/128 " SIMD_TYPE " intrinsics " STRINGIZE(MMX_COEF_SHA512)"x"
void SSESHA512body(__m128i* data, ARCH_WORD_32 *out, int init);
#endif
