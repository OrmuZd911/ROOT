/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-2002,2005,2006,2008,2010,2011,2013 by Solar Designer
 *
 * ...with changes in the jumbo patch for mingw and MSC, by JimF.
 * ...and introduction of MMX_TYPE and MMX_COEF by Simon Marechal.
 * ...and NT_SSE2 by Alain Espinosa.
 * ...and various little things by magnum
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 */

/*
 * Architecture specific parameters for x86 with SSE2 asm or intrinsics.
 */

#ifndef _JOHN_ARCH_H
#define _JOHN_ARCH_H

#if AC_BUILT
#include "autoconfig.h"
#else
#if defined (_MSC_VER) && !defined (_OPENMP)
#define __SSE2__
//#define __SSSE3__
//#define __SSE4_1__
//#define __XOP__
//#define __AVX__
#endif
#define ARCH_WORD			long
#define ARCH_SIZE			4
#define ARCH_BITS			32
#define ARCH_BITS_LOG			5
#define ARCH_BITS_STR			"32"
#define ARCH_LITTLE_ENDIAN		1
#define ARCH_INT_GT_32			0
#define ARCH_ALLOWS_UNALIGNED		1
#endif

#define ARCH_INDEX(x)			((unsigned int)(unsigned char)(x))

#define CPU_DETECT			1
#define CPU_REQ				1
#define CPU_NAME			"SSE2"
#ifndef CPU_FALLBACK
#define CPU_FALLBACK			0
#endif
#if CPU_FALLBACK && !defined(CPU_FALLBACK_BINARY)
#define CPU_FALLBACK_BINARY		"john-non-sse"
#define CPU_FALLBACK_BINARY_DEFAULT
#endif

#ifdef __XOP__
#define JOHN_XOP
#endif
#if defined(__AVX__) || defined(JOHN_XOP)
#define JOHN_AVX
#endif

#ifdef __SSSE3__
#undef CPU_NAME
#define CPU_NAME		"SSSE3"
#endif
#ifdef __SSE4_1__
#undef CPU_NAME
#define CPU_NAME		"SSE4.1"
#endif

#define DES_ASM				1
#define DES_128K			0
#define DES_X2				1
#define DES_MASK			1
#define DES_SCALE			0
#define DES_EXTB			0
#define DES_COPY			1
#define DES_STD_ALGORITHM_NAME		"DES 48/64 4K MMX"
#define DES_BS				1
#if defined(JOHN_AVX) && (defined(__GNUC__) || defined(_OPENMP))
/*
 * Require gcc for AVX/XOP because DES_bs_all is aligned in a gcc-specific way,
 * except in OpenMP-enabled builds, where it's aligned by different means.
 */
#define CPU_REQ_AVX
#undef CPU_NAME
#define CPU_NAME			"AVX"
#ifdef CPU_FALLBACK_BINARY_DEFAULT
#undef CPU_FALLBACK_BINARY
#define CPU_FALLBACK_BINARY		"john-non-avx"
#endif
#define DES_BS_ASM			0
#if 1
#define DES_BS_VECTOR			8
#if defined(JOHN_XOP) && defined(__GNUC__)
/* Require gcc for 256-bit XOP because of __builtin_ia32_vpcmov_v8sf256() */
#define CPU_REQ_XOP
#undef CPU_NAME
#define CPU_NAME			"XOP"
#ifdef CPU_FALLBACK_BINARY_DEFAULT
#undef CPU_FALLBACK_BINARY
#define CPU_FALLBACK_BINARY		"john-non-xop"
#endif
#undef DES_BS
#define DES_BS				3
#define DES_BS_ALGORITHM_NAME		"DES 256/256 XOP"
#else
#define DES_BS_ALGORITHM_NAME		"DES 256/256 AVX"
#endif
#else
#define DES_BS_VECTOR			4
#ifdef JOHN_XOP
#undef DES_BS
#define DES_BS				3
#define DES_BS_ALGORITHM_NAME		"DES 128/128 XOP"
#else
#define DES_BS_ALGORITHM_NAME		"DES 128/128 AVX"
#endif
#endif
#elif defined(__SSE2__) && defined(_OPENMP)
#define DES_BS_ASM			0
#if 1
#define DES_BS_VECTOR			4
#define DES_BS_ALGORITHM_NAME		"DES 128/128 SSE2"
#elif 0
#define DES_BS_VECTOR			6
#define DES_BS_VECTOR_SIZE		8
#define DES_BS_ALGORITHM_NAME		"DES 128/128 SSE2 + 64/64 MMX"
#elif 0
#define DES_BS_VECTOR			5
#define DES_BS_VECTOR_SIZE		8
#define DES_BS_ALGORITHM_NAME		"DES 128/128 SSE2 + 32/32"
#else
#define DES_BS_VECTOR			7
#define DES_BS_VECTOR_SIZE		8
#define DES_BS_ALGORITHM_NAME		"DES 128/128 SSE2 + 64/64 MMX + 32/32"
#endif
#else
#define DES_BS_ASM			1
#define DES_BS_VECTOR			4
#define DES_BS_ALGORITHM_NAME		"DES 128/128 SSE2"
#endif
#define DES_BS_EXPAND			1

#ifdef _OPENMP
#define MD5_ASM				0
#define MD5_X2				1
#else
// NOTE, for some newer gcc compiliers, setting MD5_ASM to 2 and MD5_X2 to 1 is faster.
#define MD5_ASM				1
#define MD5_X2				0
#endif
// Also, for some compiliers, and possibly CPU's, MD5_IMM 0 would be faster.
// MORE testing needs done for these 3 items, OR
#define MD5_IMM				1

#if defined(_OPENMP) || defined(_MSC_VER) || \
    (defined(__GNUC__) && \
    (__GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 2)))
#define BF_ASM				0
#define BF_X2				1
#else
#define BF_ASM				1
#define BF_X2				0
#endif
#define BF_SCALE			1

#ifndef JOHN_DISABLE_INTRINSICS
#ifdef __GNUC__
#define GCC_VERSION			(__GNUC__ * 10000 \
			 + __GNUC_MINOR__ * 100 \
			 + __GNUC_PATCHLEVEL__)
#endif

#ifndef MD5_SSE_PARA
#if defined(__INTEL_COMPILER) || defined(USING_ICC_S_FILE)
#define MD5_SSE_PARA			3
#define MD5_N_STR			"12x"
#elif defined(__clang__)
#define MD5_SSE_PARA			4
#define MD5_N_STR			"16x"
#elif defined (_MSC_VER)
#define MD5_SSE_PARA			1
#define MD5_N_STR			"4x"
#elif defined(__GNUC__) && GCC_VERSION < 30406	// 3.4.6
#undef MD5_SSE_PARA
#undef MD5_N_STR
#elif defined(__GNUC__) && GCC_VERSION < 40405	// 4.4.5
#define MD5_SSE_PARA			1
#define MD5_N_STR			"4x"
#elif defined(__GNUC__)
#define MD5_SSE_PARA			3
#define MD5_N_STR			"12x"
#else
#define MD5_SSE_PARA			2
#define MD5_N_STR			"8x"
#endif
#endif /* MD5_SSE_PARA */

#ifndef MD4_SSE_PARA
#if defined(__INTEL_COMPILER) || defined(USING_ICC_S_FILE)
#define MD4_SSE_PARA			3
#define MD4_N_STR			"12x"
#elif defined(__clang__)
#define MD4_SSE_PARA			3
#define MD4_N_STR			"12x"
#elif defined (_MSC_VER)
#define MD4_SSE_PARA			1
#define MD4_N_STR			"4x"
#elif defined(__GNUC__) && GCC_VERSION < 30406	// 3.4.6
#undef MD4_SSE_PARA
#undef MD4_N_STR
#elif defined(__GNUC__) && GCC_VERSION < 40405	// 4.4.5
#define MD4_SSE_PARA			1
#define MD4_N_STR			"4x"
#elif defined(__GNUC__) && GCC_VERSION < 40500	// 4.5
#define MD4_SSE_PARA			2
#define MD4_N_STR			"8x"
#elif defined(__GNUC__)
#define MD4_SSE_PARA			3
#define MD4_N_STR			"12x"
#else
#define MD4_SSE_PARA			2
#define MD4_N_STR			"8x"
#endif
#endif /* MD4_SSE_PARA */

#ifndef SHA1_SSE_PARA
//#ifdef _OPENMP // The asm version is faster but not thread-safe
#if defined(__INTEL_COMPILER) || defined(USING_ICC_S_FILE)
#define SHA1_SSE_PARA			1
#define SHA1_N_STR			"4x"
#elif defined(__clang__)
#define SHA1_SSE_PARA			3
#define SHA1_N_STR			"12x"
#elif defined (_MSC_VER)
#define SHA1_SSE_PARA			1
#define SHA1_N_STR			"4x"
#elif defined(__GNUC__) && GCC_VERSION < 30406	// 3.4.6
#undef SHA1_SSE_PARA
#undef SHA1_N_STR
#elif defined(__GNUC__) && GCC_VERSION > 40600 // 4.6
#define SHA1_SSE_PARA			2
#define SHA1_N_STR			"8x"
#elif defined(__GNUC__)
#define SHA1_SSE_PARA			1
#define SHA1_N_STR			"4x"
#else
#define SHA1_SSE_PARA			1
#define SHA1_N_STR			"4x"
#endif
//#endif /* _OPENMP */
#endif /* SHA1_SSE_PARA */

#define STR_VALUE(arg)			#arg
#define PARA_TO_N(n)			"4x" STR_VALUE(n)

#ifndef MD4_N_STR
#if defined(MD4_SSE_PARA)
#define MD4_N_STR			PARA_TO_N(MD4_SSE_PARA)
#else
#define MD4_N_STR			"4x"
#endif
#endif
#ifndef MD5_N_STR
#if defined(MD5_SSE_PARA)
#define MD5_N_STR			PARA_TO_N(MD5_SSE_PARA)
#else
#define MD5_N_STR			"4x"
#endif
#endif
#ifndef SHA1_N_STR
#if defined(SHA1_SSE_PARA)
#define SHA1_N_STR			PARA_TO_N(SHA1_SSE_PARA)
#else
#define SHA1_N_STR			"4x"
#endif
#endif

#endif /* JOHN_DISABLE_INTRINSICS */

#ifndef SHA_BUF_SIZ
#ifdef SHA1_SSE_PARA
// This can be 80 (old code) or 16 (new code)
#define SHA_BUF_SIZ			16
#else
// This must be 80
#define SHA_BUF_SIZ			80
#endif
#endif

#define MMX_TYPE			" SSE2"
#define MMX_COEF			4

#define NT_SSE2

#define MMX_COEF_SHA256 4
#define MMX_COEF_SHA512 2

#endif
