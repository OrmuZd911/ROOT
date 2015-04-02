/*
 * Developed by Claudio André <claudioandre.br at gmail.com> in 2012
 *
 * More information at http://openwall.info/wiki/john/OpenCL-RAWSHA-512
 * More information at http://openwall.info/wiki/john/OpenCL-XSHA-512
 *
 * Copyright (c) 2012-2015 Claudio André <claudioandre.br at gmail.com>
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
#define PLAINTEXT_LENGTH        55

#define BUFFER_SIZE             56      /* PLAINTEXT_LENGTH multiple of 4 */
#define SHORT_BINARY_SIZE	 4
#define SALT_SIZE_RAW           0
#define SALT_SIZE_X             4
#define SALT_ALIGN_RAW          1
#define SALT_ALIGN_X            4
#define STEP			0
#define SEED			1024

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
    uint32_t                    salt;
} sha512_salt;

typedef struct {
    uint64_t                    v[8];           //512 bits
} sha512_hash;

typedef struct {
    uint32_t                    buflen;
    buffer_64                   buffer[16];     //1024bits
} sha512_ctx;

#ifndef _OPENCL_COMPILER
    static const char * warn[] = {
        "pass xfer: "  ,  ", crypt: "    ,  ", result xfer: ",  ", index xfer: "
};
#endif

#endif  /* _RAWSHA512_NG_H */
