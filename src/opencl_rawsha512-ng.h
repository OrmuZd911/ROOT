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

#include "opencl_device_info.h"
#include "opencl_sha512.h"

//Constants.
#define PLAINTEXT_LENGTH        32      /* 31 characters + 0x80 */
#define PLAINTEXT_TEXT          "32"
#define CIPHERTEXT_LENGTH       128
#define PLAINTEXT_ARRAY         (PLAINTEXT_LENGTH / 8)
#define BINARY_SIZE             4
#define FULL_BINARY_SIZE        64
#define BINARY_ALIGN            4
#define SALT_SIZE               0
#define SALT_ALIGN              1
#define STEP                    65536

#define KEYS_PER_CORE_CPU       65536
#define KEYS_PER_CORE_GPU       512

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

typedef struct {
    uint64_t                    H[8];           //512 bits
} sha512_ctx_H;

typedef struct {
    uint32_t                    buflen;
    buffer_64                   buffer[16];     //1024bits
} sha512_ctx_buffer;

#ifndef _OPENCL_COMPILER
    static const char * warn[] = {
        "pass xfer: "  ,  ", crypt: "    ,  ", result xfer: "
};
#endif

#endif  /* _RAWSHA512_NG_H */