/*
 * Developed by Claudio André <claudio.andre at correios.net.br> in 2012
 *
 * More information at http://openwall.info/wiki/john/OpenCL-RAWSHA-512
 *
 * Copyright (c) 2012 Claudio André <claudio.andre at correios.net.br>
 * This program comes with ABSOLUTELY NO WARRANTY; express or implied.
 *
 * This is free software, and you are welcome to redistribute it
 * under certain conditions; as expressed here
 * http://www.gnu.org/licenses/gpl-2.0.html
 */

#ifndef _RAWSHA512_NG_H
#define _RAWSHA512_NG_H

//Copied from common-opencl.h
#define UNKNOWN                 0
#define CPU                     1
#define GPU                     2
#define ACCELERATOR             4
#define AMD                     64
#define NVIDIA                  128
#define INTEL                   256
#define AMD_GCN                 1024
#define AMD_VLIW4               2048
#define AMD_VLIW5               4096
#define NO_BYTE_ADDRESSABLE     8192

#define cpu(n)                  ((n & CPU) == (CPU))
#define gpu(n)                  ((n & GPU) == (GPU))
#define gpu_amd(n)              ((n & AMD) && gpu(n))
#define gpu_nvidia(n)           ((n & NVIDIA) && gpu(n))
#define gpu_intel(n)            ((n & INTEL) && gpu(n))
#define cpu_amd(n)              ((n & AMD) && cpu(n))
#define amd_gcn(n)              ((n & AMD_GCN) && gpu_amd(n))
#define amd_vliw4(n)            ((n & AMD_VLIW4) && gpu_amd(n))
#define amd_vliw5(n)            ((n & AMD_VLIW5) && gpu_amd(n))
#define no_byte_addressable(n)  (n & NO_BYTE_ADDRESSABLE)

//Type names definition.
#define uint8_t  unsigned char
#define uint16_t unsigned short
#define uint32_t unsigned int
#define uint64_t unsigned long  //Tip: unsigned long long int failed on compile (AMD).

//Functions.
#define MAX(x,y)                ((x) > (y) ? (x) : (y))
#define MIN(x,y)                ((x) < (y) ? (x) : (y))

//Constants.
#define PLAINTEXT_LENGTH        32
#define PLAINTEXT_TEXT          "32"
#define CIPHERTEXT_LENGTH       128
#define PLAINTEXT_ARRAY         (PLAINTEXT_LENGTH / 8)
#define BINARY_SIZE             8
#define FULL_BINARY_SIZE        64
#define SALT_SIZE               0
#define STEP                    65536

#define KEYS_PER_CORE_CPU       65536
#define KEYS_PER_CORE_GPU       512
#define MIN_KEYS_PER_CRYPT      1024
#define MAX_KEYS_PER_CRYPT      2048*2048*4+1

//Macros.
#define SWAP(n) \
            (((n) << 56)                      \
          | (((n) & 0xff00) << 40)            \
          | (((n) & 0xff0000) << 24)          \
          | (((n) & 0xff000000) << 8)         \
          | (((n) >> 8) & 0xff000000)         \
          | (((n) >> 24) & 0xff0000)          \
          | (((n) >> 40) & 0xff00)            \
          | ((n) >> 56))

#define SWAP64_V(n)             SWAP(n)

#if gpu_amd(DEVICE_INFO)
        #define Ch(x,y,z)       bitselect(z, y, x)
        #define Maj(x,y,z)      bitselect(x, y, z ^ x)
        #define ror(x, n)       rotate(x, (uint64_t) 64-n)
        #define SWAP64(n)       (as_ulong(as_uchar8(n).s76543210))
#else
        #if gpu_nvidia(DEVICE_INFO)
            #pragma OPENCL EXTENSION cl_nv_pragma_unroll : enable
        #endif
        #define Ch(x,y,z)       ((x & y) ^ ( (~x) & z))
        #define Maj(x,y,z)      ((x & y) ^ (x & z) ^ (y & z))
        #define ror(x, n)       ((x >> n) | (x << (64-n)))
        #define SWAP64(n)       SWAP(n)
#endif
#define Sigma0(x)               ((ror(x,28)) ^ (ror(x,34)) ^ (ror(x,39)))
#define Sigma1(x)               ((ror(x,14)) ^ (ror(x,18)) ^ (ror(x,41)))
#define sigma0(x)               ((ror(x,1))  ^ (ror(x,8))  ^ (x>>7))
#define sigma1(x)               ((ror(x,19)) ^ (ror(x,61)) ^ (x>>6))

/* Macros for reading/writing chars from int32's (from rar_kernel.cl) */
#define GETCHAR(buf, index) ((buf)[(index)])
#define ATTRIB(buf, index, val) (buf)[(index)] = val
#define PUTCHAR(buf, index, val) (buf)[(index)>>2] = ((buf)[(index)>>2] & ~(0xffU << (((index) & 3) << 3))) + ((val) << (((index) & 3) << 3))

//Data types.
typedef union {
    uint8_t                     mem_08[8];
    uint16_t                    mem_16[4];
    uint32_t                    mem_32[2];
    uint64_t                    mem_64[1];
} buffer_64;

typedef struct {
    uint32_t                    length;
    buffer_64                   pass[PLAINTEXT_ARRAY];
} sha512_password;

typedef struct {
    uint64_t                    v[8];           //512 bits
} sha512_hash;

typedef struct {
    uint64_t                    H[8];           //512 bits
    uint32_t                    buflen;
    buffer_64                   buffer[16];     //1024bits
} sha512_ctx;
#endif
