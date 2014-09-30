/*
 * Developed by Claudio André <claudio.andre at correios.net.br> in 2012
 *
 * More information at http://openwall.info/wiki/john/OpenCL-SHA-512
 *
 * Copyright (c) 2012 Claudio André <claudio.andre at correios.net.br>
 * This program comes with ABSOLUTELY NO WARRANTY; express or implied.
 *
 * This is free software, and you are welcome to redistribute it
 * under certain conditions; as expressed here
 * http://www.gnu.org/licenses/gpl-2.0.html
 */

#include "opencl_cryptsha512.h"

#if gpu(DEVICE_INFO) && !amd_gcn(DEVICE_INFO)
    #define VECTOR_USAGE
#endif

///	    *** UNROLL ***
///AMD: sometimes a bad thing(?).
///NVIDIA: GTX 570 don't allow full unroll.
#if amd_gcn(DEVICE_INFO)
    #define WEAK_UNROLL		1
#elif gpu_amd(DEVICE_INFO)
    #define STRONG_UNROLL	1
#elif cpu(DEVICE_INFO)
    #define STRONG_UNROLL	1
#elif (nvidia_sm_2x(DEVICE_INFO) || nvidia_sm_3x(DEVICE_INFO))
    #define MEDIUM_UNROLL	1
#elif nvidia_sm_5x(DEVICE_INFO)
    #define STRONG_UNROLL	1
#endif

/************************** helper **************************/
inline void init_ctx(sha512_ctx * ctx) {
    ctx->H[0] = H0;
    ctx->H[1] = H1;
    ctx->H[2] = H2;
    ctx->H[3] = H3;
    ctx->H[4] = H4;
    ctx->H[5] = H5;
    ctx->H[6] = H6;
    ctx->H[7] = H7;

    ctx->total = 0;
    ctx->buflen = 0;
}

inline void clear_ctx_buffer(sha512_ctx * ctx) {

    ctx->buffer[0].mem_64[0] = 0;
    ctx->buffer[1].mem_64[0] = 0;
    ctx->buffer[2].mem_64[0] = 0;
    ctx->buffer[3].mem_64[0] = 0;
    ctx->buffer[4].mem_64[0] = 0;
    ctx->buffer[5].mem_64[0] = 0;
    ctx->buffer[6].mem_64[0] = 0;
    ctx->buffer[7].mem_64[0] = 0;
    ctx->buffer[8].mem_64[0] = 0;
    ctx->buffer[9].mem_64[0] = 0;
    ctx->buffer[10].mem_64[0] = 0;
    ctx->buffer[11].mem_64[0] = 0;
    ctx->buffer[12].mem_64[0] = 0;
    ctx->buffer[13].mem_64[0] = 0;
    ctx->buffer[14].mem_64[0] = 0;
    ctx->buffer[15].mem_64[0] = 0;

    ctx->buflen = 0;
}

/************************** prepare **************************/
inline void clear_buffer(uint64_t     * destination,
                         const uint32_t len,
                         const uint32_t limit) {

    uint32_t length;

    CLEAR_BUFFER_64(destination, len);

    uint64_t * l = destination + length;

    while (length < limit) {
        *l++ = 0;
        length++;
    }
}

inline void sha512_block(sha512_ctx * ctx) {
    uint64_t a = ctx->H[0];
    uint64_t b = ctx->H[1];
    uint64_t c = ctx->H[2];
    uint64_t d = ctx->H[3];
    uint64_t e = ctx->H[4];
    uint64_t f = ctx->H[5];
    uint64_t g = ctx->H[6];
    uint64_t h = ctx->H[7];
    uint64_t t;
    uint64_t w[16];

#ifdef VECTOR_USAGE
    ulong16  w_vector;
    w_vector = vload16(0, ctx->buffer->mem_64);
    w_vector = SWAP64_V(w_vector);
    vstore16(w_vector, 0, w);
#else
    for (int i = 0; i < 16; i++)
        w[i] = SWAP64(ctx->buffer[i].mem_64[0]);
#endif

    for (int i = 0; i < 16; i++) {
        t = k[i] + w[i] + h + Sigma1(e) + Ch(e, f, g);

        h = g;
        g = f;
        f = e;
        e = d + t;
        t = t + Maj(a, b, c) + Sigma0(a);
        d = c;
        c = b;
        b = a;
        a = t;
    }

#ifdef AMD_STUPID_BUG_1
    #pragma unroll 16
#endif
    for (int i = 16; i < 80; i++) {
        w[i & 15] = sigma1(w[(i - 2) & 15]) + sigma0(w[(i - 15) & 15]) + w[(i - 16) & 15] + w[(i - 7) & 15];
        t = k[i] + w[i & 15] + h + Sigma1(e) + Ch(e, f, g);

        h = g;
        g = f;
        f = e;
        e = d + t;
        t = t + Maj(a, b, c) + Sigma0(a);
        d = c;
        c = b;
        b = a;
        a = t;
    }
    /* Put checksum in context given as argument. */
    ctx->H[0] += a;
    ctx->H[1] += b;
    ctx->H[2] += c;
    ctx->H[3] += d;
    ctx->H[4] += e;
    ctx->H[5] += f;
    ctx->H[6] += g;
    ctx->H[7] += h;
}

inline void insert_to_buffer_R(sha512_ctx    * ctx,
                               const uint8_t * string,
                               const uint32_t len) {

    uint64_t * s = (uint64_t *) string;
    uint32_t tmp, pos;
    tmp = ((ctx->buflen & 7) << 3);
    pos = (ctx->buflen >> 3);

    for (uint32_t i = 0; i < len; i+=8, s++) {
	APPEND_BUFFER_F(ctx->buffer->mem_64, s[0]);
    }
    ctx->buflen += len;

    //A fast clean should be possible.
    clear_buffer(ctx->buffer->mem_64, ctx->buflen, 16);
}

inline void insert_to_buffer_G(         sha512_ctx    * ctx,
                               __global const uint8_t * string,
                               const uint32_t len) {

    __global uint64_t * s = (__global uint64_t *) string;
    uint32_t tmp, pos;
    tmp = ((ctx->buflen & 7) << 3);
    pos = (ctx->buflen >> 3);

    for (uint32_t i = 0; i < len; i+=8, s++) {
	APPEND_BUFFER_F(ctx->buffer->mem_64, s[0]);
    }
    ctx->buflen += len;
    tmp = (ctx->buflen & 7);

    if (tmp) {
	pos = (ctx->buflen >> 3);
	ctx->buffer[pos].mem_64[0] = ctx->buffer[pos].mem_64[0] & clear_mask[tmp];
    }
}

inline void ctx_update_R(sha512_ctx * ctx,
                         uint8_t    * string,
                         const uint32_t len) {

    ctx->total += len;
    uint32_t startpos = ctx->buflen;

    insert_to_buffer_R(ctx, string, (startpos + len <= 128 ? len : 128 - startpos));

    if (ctx->buflen == 128) {  //Branching.
        uint32_t offset = 128 - startpos;
        sha512_block(ctx);
        ctx->buflen = len - offset;

        //Unaligned memory acess.
	for (uint32_t i = 0; i < ctx->buflen; i++)
	    PUT(BUFFER, i, (string + offset)[i]);

	clear_buffer(ctx->buffer->mem_64, ctx->buflen, 16);
    }
}

inline void ctx_update_G(         sha512_ctx * ctx,
                         __global uint8_t    * string, uint32_t len) {

    ctx->total += len;
    uint32_t startpos = ctx->buflen;

    insert_to_buffer_G(ctx, string, (startpos + len <= 128 ? len : 128 - startpos));

    if (ctx->buflen == 128) {  //Branching.
        uint32_t offset = 128 - startpos;
        sha512_block(ctx);
        ctx->buflen = len - offset;

        //Unaligned memory acess.
	for (uint32_t i = 0; i < ctx->buflen; i++)
	    PUT(BUFFER, i, (string + offset)[i]);

	clear_buffer(ctx->buffer->mem_64, ctx->buflen, 16);
    }
}

inline void ctx_append_1(sha512_ctx * ctx) {

    uint32_t length;
    PUT(BUFFER, ctx->buflen, 0x80);

    CLEAR_BUFFER_64(ctx->buffer->mem_64, ctx->buflen + 1);

    uint64_t * l = ctx->buffer->mem_64 + length;

    while (length < 16) {
        *l++ = 0;
        length++;
    }
}

inline void ctx_add_length(sha512_ctx * ctx) {

    ctx->buffer[15].mem_64[0] = SWAP64((uint64_t) (ctx->total * 8));
}

inline void finish_ctx(sha512_ctx * ctx) {

    ctx_append_1(ctx);
    ctx_add_length(ctx);
    ctx->buflen = 0;
}

inline void sha512_digest(sha512_ctx * ctx,
                          uint64_t   * result,
                          const int size) {

    if (ctx->buflen <= 111) { //data+0x80+datasize fits in one 1024bit block
        finish_ctx(ctx);

    } else {
        bool moved = true;

        if (ctx->buflen < 128) { //data and 0x80 fits in one block
            ctx_append_1(ctx);
            moved = false;
        }
        sha512_block(ctx);
        clear_ctx_buffer(ctx);

        if (moved) //append 1,the rest is already clean
            PUT(BUFFER, 0, 0x80);
        ctx_add_length(ctx);
    }
    sha512_block(ctx);

    for (int i = 0; i < size; i++)
        result[i] = SWAP64(ctx->H[i]);
}

inline void sha512_prepare(__global   sha512_salt     * salt_data,
                           __global   sha512_password * keys_data,
                                      sha512_buffers  * fast_buffers,
                                      sha512_ctx      * ctx) {

#define pass        keys_data->pass->mem_08
#define passlen     keys_data->length
#define salt        salt_data->salt->mem_08
#define saltlen     salt_data->length
#define alt_result  fast_buffers->alt_result
#define temp_result fast_buffers->temp_result
#define p_sequence  fast_buffers->p_sequence

    init_ctx(ctx);
    clear_ctx_buffer(ctx);

    ctx_update_G(ctx, pass, passlen);
    ctx_update_G(ctx, salt, saltlen);
    ctx_update_G(ctx, pass, passlen);

    sha512_digest(ctx, alt_result->mem_64, BUFFER_ARRAY);
    init_ctx(ctx);
    clear_ctx_buffer(ctx);

    ctx_update_G(ctx, pass, passlen);
    ctx_update_G(ctx, salt, saltlen);
    ctx_update_R(ctx, alt_result->mem_08, passlen);

    for (uint32_t i = passlen; i > 0; i >>= 1) {

        if (i & 1)
            ctx_update_R(ctx, alt_result->mem_08, 64U);
        else
            ctx_update_G(ctx, pass, passlen);
    }
    sha512_digest(ctx, alt_result->mem_64, BUFFER_ARRAY);
    init_ctx(ctx);
    clear_ctx_buffer(ctx);

    for (uint32_t i = 0; i < passlen; i++)
        ctx_update_G(ctx, pass, passlen);

    sha512_digest(ctx, p_sequence->mem_64, PLAINTEXT_ARRAY);
    init_ctx(ctx);
    clear_ctx_buffer(ctx);

    /* For every character in the password add the entire password. */
    for (uint32_t i = 0; i < 16U + alt_result->mem_08[0]; i++)
        ctx_update_G(ctx, salt, saltlen);

    /* Finish the digest. */
    sha512_digest(ctx, temp_result->mem_64, SALT_ARRAY);

    /* SWAP temp buffers. */
    clear_buffer(p_sequence->mem_64, passlen, PLAINTEXT_ARRAY);
    clear_buffer(temp_result->mem_64, saltlen, SALT_ARRAY);
}
#undef salt
#undef pass
#undef saltlen
#undef passlen
#undef alt_result
#undef temp_result
#undef p_sequence

__kernel
void kernel_prepare(__global   sha512_salt     * salt,
                    __global   sha512_password * keys_buffer,
                    __global   buffer_64       * global_alt_result,
		    __global   uint64_t	       * work_memory) {

    //Compute buffers (on Nvidia, better private)
    sha512_buffers fast_buffers;
    sha512_ctx     ctx_data;

    //Get the task to be done
    size_t gid = get_global_id(0);

    //Get temp alt_result pointer.
    __global buffer_64 * alt_result = &global_alt_result[(gid * 8)];

    //Do the job
    sha512_prepare(salt, &keys_buffer[gid], &fast_buffers, &ctx_data);

    //Save results.
    for (int i = 0; i < 8; i++)
        alt_result[i].mem_64[0] = SWAP64(fast_buffers.alt_result[i].mem_64[0]);

    for (int i = 0; i < SALT_ARRAY; i++)
        fast_buffers.temp_result[i].mem_64[0] = SWAP64(fast_buffers.temp_result[i].mem_64[0]);

    for (int i = 0; i < PLAINTEXT_ARRAY; i++)
        fast_buffers.p_sequence[i].mem_64[0] = SWAP64(fast_buffers.p_sequence[i].mem_64[0]);

    //Preload and prepare the temp buffer.
    for (int i = 0; i < 8; i++) {
	uint32_t total = 0;
	uint32_t j = generator_index[i];

	for (int k = 0; k < 8; k++)
	   work_memory[OFFSET(i, k)] = 0;

        if (j & 1) {
	    work_memory[OFFSET(i, 0)] = fast_buffers.p_sequence[0].mem_64[0];
	    work_memory[OFFSET(i, 1)] = fast_buffers.p_sequence[1].mem_64[0];
	    work_memory[OFFSET(i, 2)] = fast_buffers.p_sequence[2].mem_64[0];
            total += keys_buffer[gid].length;
        }

        if (j % 3) {
	    APPEND_BE_SPECIAL(work_memory, fast_buffers.temp_result[0].mem_64[0],
		i, total);
	    APPEND_BE_SPECIAL(work_memory, fast_buffers.temp_result[1].mem_64[0],
		i, total + 8);
            total += salt->length;
        }

        if (j % 7) {
	    APPEND_BE_SPECIAL(work_memory, fast_buffers.p_sequence[0].mem_64[0],
		i, total);
	    APPEND_BE_SPECIAL(work_memory, fast_buffers.p_sequence[1].mem_64[0],
		i, total + 8);
	    APPEND_BE_SPECIAL(work_memory, fast_buffers.p_sequence[2].mem_64[0],
		i, total + 16);
            total += keys_buffer[gid].length;
        }

        if (! (j & 1)) {
	    APPEND_BE_SPECIAL(work_memory, fast_buffers.p_sequence[0].mem_64[0],
		i, total);
	    APPEND_BE_SPECIAL(work_memory, fast_buffers.p_sequence[1].mem_64[0],
		i, total + 8);
	    APPEND_BE_SPECIAL(work_memory, fast_buffers.p_sequence[2].mem_64[0],
		i, total + 16);
            total += keys_buffer[gid].length;
        }
	work_memory[OFFSET(i, 8)] = total;
    }
}

/************************** hashing **************************/
inline void sha512_block_be(uint64_t * buffer, uint64_t * H) {
    uint64_t t;
    uint64_t a = H[0];
    uint64_t b = H[1];
    uint64_t c = H[2];
    uint64_t d = H[3];
    uint64_t e = H[4];
    uint64_t f = H[5];
    uint64_t g = H[6];
    uint64_t h = H[7];
    uint64_t w[16];

#ifdef VECTOR_USAGE
    ulong16  w_vector = vload16(0, buffer);
    vstore16(w_vector, 0, w);
#else
    #pragma unroll
    for (int i = 0; i < 16; i++)
        w[i] = buffer[i];
#endif

#ifdef STRONG_UNROLL
    #pragma unroll
#endif
    for (int i = 0; i < 16; i++) {
        t = k[i] + w[i] + h + Sigma1(e) + Ch(e, f, g);

        h = g;
        g = f;
        f = e;
	e = d + t;
	t = t + Maj(a, b, c) + Sigma0(a);
        d = c;
        c = b;
        b = a;
        a = t;
    }

#ifdef STRONG_UNROLL
    #pragma unroll
#elif MEDIUM_UNROLL
    #pragma unroll 16
#elif WEAK_UNROLL
    #pragma unroll 8
#endif
    for (int i = 16; i < 80; i++) {
        w[i & 15] = sigma1(w[(i - 2) & 15]) + sigma0(w[(i - 15) & 15]) + w[(i - 16) & 15] + w[(i - 7) & 15];
        t = k[i] + w[i & 15] + h + Sigma1(e) + Ch(e, f, g);

        h = g;
        g = f;
        f = e;
	e = d + t;
	t = t + Maj(a, b, c) + Sigma0(a);
        d = c;
        c = b;
        b = a;
        a = t;
    }
    /* Put checksum in context given as argument. */
    H[0] += a;
    H[1] += b;
    H[2] += c;
    H[3] += d;
    H[4] += e;
    H[5] += f;
    H[6] += g;
    H[7] += h;
}

inline void sha512_crypt(const uint32_t saltlen, const uint32_t passlen,
                         const uint32_t initial, const uint32_t rounds,
			 __global	buffer_64      * alt_result,
			 __global	uint64_t       * work_memory) {

    //To compute buffers.
    int		    total;
    uint64_t	    w[16];
    uint64_t	    H[8];

    //Transfer host global data to a faster memory space.
    #pragma unroll
    for (int i = 0; i < 8; i++)
        H[i] = alt_result[i].mem_64[0];

    /* Repeatedly run the collected hash value through SHA512 to burn cycles. */
    for (int i = 0; i < rounds; i++) {

	#pragma unroll
	for (int j = 8; j < 16; j++)
	   w[j] = 0;

        if (i & 1) {
            w[0] = work_memory[OFFSET(loop_index[i], 0)];
            w[1] = work_memory[OFFSET(loop_index[i], 1)];
            w[2] = work_memory[OFFSET(loop_index[i], 2)];
            w[3] = work_memory[OFFSET(loop_index[i], 3)];
            w[4] = work_memory[OFFSET(loop_index[i], 4)];
            w[5] = work_memory[OFFSET(loop_index[i], 5)];
            w[6] = work_memory[OFFSET(loop_index[i], 6)];
            w[7] = work_memory[OFFSET(loop_index[i], 7)];
            total = work_memory[OFFSET(loop_index[i], 8)];

	    {
		uint32_t tmp, pos;
		tmp = ((total & 7) << 3);
		pos = (total >> 3);

		APPEND_BE_BUFFER(w, H[0]);
		APPEND_BE_BUFFER(w, H[1]);
		APPEND_BE_BUFFER(w, H[2]);
		APPEND_BE_BUFFER(w, H[3]);
		APPEND_BE_BUFFER(w, H[4]);
		APPEND_BE_BUFFER(w, H[5]);
		APPEND_BE_BUFFER(w, H[6]);
		APPEND_BE_BUFFER_F(w, H[7]);
	    }
            total += 64;

        } else {
            w[0] = H[0];
            w[1] = H[1];
            w[2] = H[2];
            w[3] = H[3];
            w[4] = H[4];
            w[5] = H[5];
            w[6] = H[6];
            w[7] = H[7];
	    w[8] = work_memory[OFFSET(loop_index[i], 0)];
	    w[9] = work_memory[OFFSET(loop_index[i], 1)];
	    w[10] = work_memory[OFFSET(loop_index[i], 2)];
	    w[11] = work_memory[OFFSET(loop_index[i], 3)];
	    w[12] = work_memory[OFFSET(loop_index[i], 4)];
	    w[13] = work_memory[OFFSET(loop_index[i], 5)];
	    w[14] = work_memory[OFFSET(loop_index[i], 6)];
	    w[15] = work_memory[OFFSET(loop_index[i], 7)];
            total = 64 + work_memory[OFFSET(loop_index[i], 8)];
        }
        //Initialize CTX.
	H[0] = H0;
	H[1] = H1;
	H[2] = H2;
	H[3] = H3;
	H[4] = H4;
	H[5] = H5;
	H[6] = H6;
	H[7] = H7;

        //Do the sha512_digest(ctx);
	APPEND_BE_SINGLE(w, 0x8000000000000000UL, total);

	if (total < 112) { //data+0x80+datasize fits in one 1024bit block
	    w[15] = (total * 8);

	} else {
	    sha512_block_be(w, H);

	    #pragma unroll
	    for (int i = 0; i < 15; i++)
	       w[i] = 0;
	    w[15] = (total * 8);
	}
	sha512_block_be(w, H);
    }
    //Push results back to global memory.
    #pragma unroll
    for (int i = 0; i < 8; i++)
        alt_result[i].mem_64[0] = H[i];
}

__kernel
void kernel_crypt(__constant sha512_salt     * salt,
                  __global   sha512_password * keys_buffer,
                  __global   sha512_hash     * out_buffer,
                  __global   buffer_64       * global_alt_result,
		  __global   uint64_t	     * work_memory) {

    //Get the task to be done
    size_t gid = get_global_id(0);

    //Get temp alt_result pointer.
    __global buffer_64 * alt_result = &global_alt_result[(gid * 8)];

    //Do the job
    sha512_crypt(salt->length, keys_buffer[gid].length, 0, HASH_LOOPS,
		 alt_result, work_memory);
}

__kernel
void kernel_final(__constant sha512_salt     * salt,
                  __global   sha512_password * keys_buffer,
                  __global   sha512_hash     * out_buffer,
                  __global   buffer_64       * global_alt_result,
		  __global   uint64_t	     * work_memory) {

    //Get the task to be done
    size_t gid = get_global_id(0);

    //Get temp alt_result pointer.
    __global buffer_64 * alt_result = &global_alt_result[(gid * 8)];

    //Do the job
    sha512_crypt(salt->length, keys_buffer[gid].length, 0,
		 MIN(salt->final,  HASH_LOOPS),
		 alt_result, work_memory);

    //SWAP results and put it as hash data.
    //Unlikely, but if avoided, could became an optimization.
    for (int i = 0; i < 8; i++)
        out_buffer[gid].v[i] = SWAP64(alt_result[i].mem_64[0]);
}
