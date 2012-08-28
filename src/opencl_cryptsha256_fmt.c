/*
 * Developed by Claudio André <claudio.andre at correios.net.br> in 2012
 *
 * More information at http://openwall.info/wiki/john/OpenCL-SHA-256
 *
 * Copyright (c) 2012 Claudio André <claudio.andre at correios.net.br>
 * This program comes with ABSOLUTELY NO WARRANTY; express or implied.
 *
 * This is free software, and you are welcome to redistribute it
 * under certain conditions; as expressed here
 * http://www.gnu.org/licenses/gpl-2.0.html
 */

#include <string.h>
#include "common-opencl.h"
#include "config.h"
#include "opencl_cryptsha256.h"
#include <time.h>

#define FORMAT_LABEL			"sha256crypt-opencl"
#define FORMAT_NAME			"sha256crypt"
#define ALGORITHM_NAME			"OpenCL"

#define BENCHMARK_COMMENT		" (rounds=5000)"
#define BENCHMARK_LENGTH		-1

#define LWS_CONFIG			"sha256crypt_LWS"
#define GWS_CONFIG			"sha256crypt_GWS"

static sha256_salt         * salt;
static sha256_password     * plaintext;             // plaintext ciphertexts
static sha256_hash         * calculated_hash;       // calculated hashes
static int                 fast_mode = FALSE;

cl_mem salt_buffer;        //Salt information.
cl_mem pass_buffer;        //Plaintext buffer.
cl_mem hash_buffer;        //Hash keys (output).
cl_mem pinned_saved_keys, pinned_partial_hashes;

cl_command_queue queue_prof;
cl_kernel crypt_kernel;
static int new_keys, new_salt;

static struct fmt_tests tests[] = {
    {"$5$LKO/Ute40T3FNF95$U0prpBQd4PloSGU0pnpM4z9wKn4vZ1.jsrzQfPqxph9", "U*U*U*U*"},
    {"$5$LKO/Ute40T3FNF95$fdgfoJEBoMajNxCv3Ru9LyQ0xZgv0OBMQoq80LQ/Qd.", "U*U***U"},
    {"$5$LKO/Ute40T3FNF95$8Ry82xGnnPI/6HtFYnvPBTYgOL23sdMXn8C29aO.x/A", "U*U***U*"},
    {"$5$9mx1HkCz7G1xho50$O7V7YgleJKLUhcfk9pgzdh3RapEaWqMtEp9UUBAKIPA", "*U*U*U*U"},
    {"$5$kc7lRD1fpYg0g.IP$d7CMTcEqJyTXyeq8hTdu/jB/I6DGkoo62NXbHIR7S43", ""},
    {NULL}
};

/* ------- Helper functions ------- */
static unsigned int get_multiple(unsigned int dividend, unsigned int divisor){

    return (dividend / divisor) * divisor;
}

static size_t get_task_max_work_group_size(){
    size_t max_available;

    if (gpu_amd(device_info[gpu_id]))
        max_available = get_local_memory_size(gpu_id) /
                (sizeof(sha256_password) + sizeof(sha256_ctx) +
                 sizeof(sha256_buffers));
    else if (gpu_nvidia(device_info[gpu_id]))
        max_available = get_local_memory_size(gpu_id) /
                sizeof(sha256_password);
    else
        max_available = get_max_work_group_size(gpu_id);

    if (max_available > get_current_work_group_size(gpu_id, crypt_kernel))
        return get_current_work_group_size(gpu_id, crypt_kernel);

    return max_available;
}

static size_t get_task_max_size(){
    size_t max_available;
    max_available = get_max_compute_units(gpu_id);

    if (cpu(device_info[gpu_id]))
        return max_available * KEYS_PER_CORE_CPU;

    else
        return max_available * get_current_work_group_size(gpu_id, crypt_kernel);
}

static size_t get_safe_workgroup(){

    if (cpu(device_info[gpu_id]))
        return 1;

    else
        return 32;
}

static size_t get_default_workgroup(){
    size_t max_available;
    max_available = get_task_max_work_group_size();

    if (gpu_nvidia(device_info[gpu_id]) ||
       (!cpu(device_info[gpu_id]) && fast_mode)) {
        global_work_size = get_multiple(global_work_size, max_available);
        return max_available;

    } else
        return get_safe_workgroup();
}

/* ------- Create and destroy necessary objects ------- */
static void create_clobj(int gws) {
    pinned_saved_keys = clCreateBuffer(context[gpu_id],
            CL_MEM_READ_WRITE | CL_MEM_ALLOC_HOST_PTR,
            sizeof(sha256_password) * gws, NULL, &ret_code);
    HANDLE_CLERROR(ret_code, "Error creating page-locked memory pinned_saved_keys");

    plaintext = (sha256_password *) clEnqueueMapBuffer(queue[gpu_id],
            pinned_saved_keys, CL_TRUE, CL_MAP_WRITE | CL_MAP_READ, 0,
            sizeof(sha256_password) * gws, 0, NULL, NULL, &ret_code);
    HANDLE_CLERROR(ret_code, "Error mapping page-locked memory saved_plain");

    pinned_partial_hashes = clCreateBuffer(context[gpu_id],
            CL_MEM_READ_WRITE | CL_MEM_ALLOC_HOST_PTR,
            sizeof(sha256_hash) * gws, NULL, &ret_code);
    HANDLE_CLERROR(ret_code, "Error creating page-locked memory pinned_partial_hashes");

    calculated_hash = (sha256_hash *) clEnqueueMapBuffer(queue[gpu_id],
            pinned_partial_hashes, CL_TRUE, CL_MAP_READ, 0,
            sizeof(sha256_hash) * gws, 0, NULL, NULL, &ret_code);
    HANDLE_CLERROR(ret_code, "Error mapping page-locked memory out_hashes");

    // create arguments (buffers)
    salt_buffer = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY,
            sizeof(sha256_salt), NULL, &ret_code);
    HANDLE_CLERROR(ret_code, "Error creating salt_buffer out argument");

    pass_buffer = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY,
            sizeof(sha256_password) * gws, NULL, &ret_code);
    HANDLE_CLERROR(ret_code, "Error creating buffer argument buffer_keys");

    hash_buffer = clCreateBuffer(context[gpu_id], CL_MEM_WRITE_ONLY,
            sizeof(sha256_hash) * gws, NULL, &ret_code);
    HANDLE_CLERROR(ret_code, "Error creating buffer argument buffer_out");

    //Set kernel arguments
    HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 0, sizeof(cl_mem),
            (void *) &salt_buffer), "Error setting argument 0");
    HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 1, sizeof(cl_mem),
            (void *) &pass_buffer), "Error setting argument 1");
    HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 2, sizeof(cl_mem),
            (void *) &hash_buffer), "Error setting argument 2");

    if (gpu_amd(device_info[gpu_id])) {
        //Fast working memory.
        HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 3,
           sizeof(sha256_password) * local_work_size,
           NULL), "Error setting argument 3");
        HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 4,
           sizeof(sha256_buffers) * local_work_size,
           NULL), "Error setting argument 4");
        HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 5,
           sizeof(sha256_ctx) * local_work_size,
           NULL), "Error setting argument 5");

    } else if (gpu_nvidia(device_info[gpu_id])) {
        //Fast working memory.
        HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 3,
           sizeof(sha256_password) * local_work_size,
           NULL), "Error setting argument 3");
    }
    memset(plaintext, '\0', sizeof(sha256_password) * gws);
    global_work_size = gws;
}

static void release_clobj(void) {
    cl_int ret_code;

    ret_code = clEnqueueUnmapMemObject(queue[gpu_id], pinned_partial_hashes,
            calculated_hash, 0, NULL, NULL);
    HANDLE_CLERROR(ret_code, "Error Ummapping out_hashes");
    ret_code = clEnqueueUnmapMemObject(queue[gpu_id], pinned_saved_keys,
            plaintext, 0, NULL, NULL);
    HANDLE_CLERROR(ret_code, "Error Ummapping saved_plain");

    ret_code = clReleaseMemObject(salt_buffer);
    HANDLE_CLERROR(ret_code, "Error Releasing data_info");
    ret_code = clReleaseMemObject(pass_buffer);
    HANDLE_CLERROR(ret_code, "Error Releasing buffer_keys");
    ret_code = clReleaseMemObject(hash_buffer);
    HANDLE_CLERROR(ret_code, "Error Releasing buffer_out");

    ret_code = clReleaseMemObject(pinned_saved_keys);
    HANDLE_CLERROR(ret_code, "Error Releasing pinned_saved_keys");
    ret_code = clReleaseMemObject(pinned_partial_hashes);
    HANDLE_CLERROR(ret_code, "Error Releasing pinned_partial_hashes");
}

/* ------- Salt functions ------- */
static void * get_salt(char * ciphertext) {
    static sha256_salt out;
    int len;

    out.rounds = ROUNDS_DEFAULT;
    ciphertext += 3;
    if (!strncmp(ciphertext, ROUNDS_PREFIX,
            sizeof(ROUNDS_PREFIX) - 1)) {
        const char *num = ciphertext + sizeof(ROUNDS_PREFIX) - 1;
        char *endp;
        unsigned long int srounds = strtoul(num, &endp, 10);
        if (*endp == '$') {
            ciphertext = endp + 1;
            out.rounds = srounds < ROUNDS_MIN ?
                    ROUNDS_MIN : srounds;
            out.rounds = srounds > ROUNDS_MAX ?
                    ROUNDS_MAX : srounds;
        }
    }

    for (len = 0; ciphertext[len] != '$'; len++);

    //Assure buffer has no "trash data".
    memset(out.salt, '\0', SALT_LENGTH);
    len = (len > SALT_LENGTH ? SALT_LENGTH : len);

    //Put the tranfered salt on salt buffer.
    memcpy(out.salt, ciphertext, len);
    out.length = len;
    return &out;
}

static void set_salt(void * salt_info) {

    salt = salt_info;
    new_salt = 1;
}

/* ------- Key functions ------- */
static void set_key(char * key, int index) {
    int len;

    //Assure buffer has no "trash data".
    memset(plaintext[index].pass, '\0', PLAINTEXT_LENGTH);
    len = strlen(key);
    len = (len > PLAINTEXT_LENGTH ? PLAINTEXT_LENGTH : len);

    //Put the tranfered key on password buffer.
    memcpy(plaintext[index].pass, key, len);
    plaintext[index].length = len ;
    new_keys = 1;
}

static char * get_key(int index) {
    static char ret[PLAINTEXT_LENGTH + 1];
    memcpy(ret, plaintext[index].pass, PLAINTEXT_LENGTH);
    ret[plaintext[index].length] = '\0';
    return ret;
}

/* ------- Try to find the best configuration ------- */
/* --
  This function could be used to calculated the best num
  for the workgroup
  Work-items that make up a work-group (also referred to
  as the size of the work-group)
  LWS should never be a big number since every work-item
  uses about 400 bytes of local memory. Local memory
  is usually 32 KB
-- */
static void find_best_workgroup(struct fmt_main *self) {

    size_t max_group_size;

    max_group_size = get_task_max_work_group_size();
    fprintf(stderr, "Max local work size %d, ", (int) max_group_size);

    //Call the default function.
    opencl_find_best_workgroup_limit(self, max_group_size);

    fprintf(stderr, "Optimal local work size %d\n", (int) local_work_size);
    fprintf(stderr, "(to avoid this test on next run, put \""
        LWS_CONFIG " = %d\" in john.conf, section [" SECTION_OPTIONS
        SUBSECTION_OPENCL "])\n", (int)local_work_size);
}

//Allow me to have a configurable step size.
static int get_step(size_t num, int step, int startup){

    if (startup) {

        if (step == 0)
            return STEP;
        else
            return step;
    }

    if (step < 1)
        return num * 2;

    return num + step;
}

/* --
  This function could be used to calculated the best num
  of keys per crypt for the given format
-- */
static void find_best_gws(void) {
    size_t num;
    cl_event myEvent;
    cl_ulong startTime, endTime, run_time, min_time = CL_ULONG_MAX;
    cl_int ret_code;
    cl_uint *tmpbuffer;
    int optimal_gws = MIN_KEYS_PER_CRYPT, i, step = STEP;
    int do_benchmark = 0;
    unsigned int SHAspeed, bestSHAspeed = 0;
    char *tmp_value;

    fprintf(stderr, "Calculating best global work size, this will take a while\n");

    if ((tmp_value = getenv("STEP"))){
        step = atoi(tmp_value);
        step = get_multiple(step, local_work_size);
        do_benchmark = 1;
    }

    for (num = get_step(num, step, 1); num < MAX_KEYS_PER_CRYPT;
         num = get_step(num, step, 0)) {
        release_clobj();
        create_clobj(num);

        if (! do_benchmark)
            advance_cursor();

        tmpbuffer = mem_alloc(sizeof(sha256_hash) * num);

        if (tmpbuffer == NULL) {
            fprintf (stderr, "Malloc failure in find_best_gws\n");
            exit (EXIT_FAILURE);
        }

        queue_prof = clCreateCommandQueue(context[gpu_id], devices[gpu_id],
                CL_QUEUE_PROFILING_ENABLE, &ret_code);
        HANDLE_CLERROR(ret_code, "Failed in clCreateCommandQueue");

        // Set salt.
        set_salt(get_salt("$5$saltstring$"));

        // Set keys
        for (i = 0; i < num; i++) {
            set_key("aaabaabaaa", i);
        }
        HANDLE_CLERROR(clEnqueueWriteBuffer(queue_prof, salt_buffer, CL_FALSE, 0,
                sizeof(sha256_salt), salt, 0, NULL, NULL),
                "Failed in clEnqueueWriteBuffer I");
        HANDLE_CLERROR(clEnqueueWriteBuffer(queue_prof, pass_buffer, CL_FALSE, 0,
                sizeof(sha256_password) * num, plaintext, 0, NULL, NULL),
                "Failed in clEnqueueWriteBuffer II");
        ret_code = clEnqueueNDRangeKernel(queue_prof, crypt_kernel,
                1, NULL, &num, &local_work_size, 0, NULL, &myEvent);
        HANDLE_CLERROR(clEnqueueReadBuffer(queue_prof, hash_buffer, CL_FALSE, 0,
                sizeof(sha256_hash) * num, tmpbuffer, 0, NULL, NULL),
                "Failed in clEnqueueReadBuffer");
        HANDLE_CLERROR(clFinish(queue_prof), "Failed in clFinish");

        if (ret_code != CL_SUCCESS) {
            fprintf(stderr, "Error %d\n", ret_code);
            continue;
        }
        HANDLE_CLERROR(clGetEventProfilingInfo(myEvent, CL_PROFILING_COMMAND_SUBMIT,
                sizeof(cl_ulong), &startTime, NULL),
                "Failed in clGetEventProfilingInfo I");
        HANDLE_CLERROR(clGetEventProfilingInfo(myEvent, CL_PROFILING_COMMAND_END,
                sizeof(cl_ulong), &endTime, NULL),
                "Failed in clGetEventProfilingInfo II");

        MEM_FREE(tmpbuffer);
        HANDLE_CLERROR(clReleaseCommandQueue(queue_prof),
            "Failed in clReleaseCommandQueue");
        HANDLE_CLERROR(clReleaseEvent(myEvent), "Failed in clReleaseEvent");

        run_time = endTime - startTime;
	SHAspeed = 5000 * num / (run_time / 1000000000.);

        if (run_time < min_time)
            min_time = run_time;

        if (do_benchmark) {
            fprintf(stderr, "gws: %6zu\t%6lu c/s%10u rounds/s%8.3f sec per crypt_all()",
                    num, (long) (num / (run_time / 1000000000.)), SHAspeed,
                    (float) run_time / 1000000000.);

            if (run_time > 10000000000ULL) {
                fprintf(stderr, " - too slow\n");
                break;
            }
        } else {
            if (run_time > min_time * 10 || run_time > 10000000000ULL)
                break;
        }
        if (SHAspeed > (1.01 * bestSHAspeed)) {
            if (do_benchmark)
                fprintf(stderr, "+");
            bestSHAspeed = SHAspeed;
            optimal_gws = num;
        }
        if (do_benchmark)
            fprintf(stderr, "\n");
    }
    fprintf(stderr, "Optimal global work size %d\n", optimal_gws);
    fprintf(stderr, "(to avoid this test on next run, put \""
        GWS_CONFIG " = %d\" in john.conf, section [" SECTION_OPTIONS
        SUBSECTION_OPENCL "])\n", optimal_gws);
    global_work_size = optimal_gws;
    release_clobj();
    create_clobj(optimal_gws);
}

/* ------- Initialization  ------- */
static void init(struct fmt_main *self) {
    int source_in_use;
    char * tmp_value;
    char * task = "$JOHN/cryptsha256_kernel_DEFAULT.cl";
    uint64_t startTime, runtime;

    opencl_init_dev(gpu_id, platform_id);
    startTime = (unsigned long) time(NULL);
    source_in_use = device_info[gpu_id];

    if ((tmp_value = getenv("_TYPE")))
        source_in_use = atoi(tmp_value);

    if ((tmp_value = getenv("_FAST")))
        fast_mode = TRUE;

    if (! cpu(source_in_use)) {
        fprintf(stderr, "Building the kernel, this could take a while\n");

        if (! no_byte_addressable(source_in_use)) {

            if (gpu_nvidia(source_in_use))
                task = "$JOHN/cryptsha256_kernel_NVIDIA.cl";
            else if (gpu_amd(source_in_use))
                task = "$JOHN/cryptsha256_kernel_AMD.cl";
        }
    }
    fflush(stdout);
    opencl_build_kernel(task, gpu_id);

    if ((runtime = (unsigned long) (time(NULL) - startTime)) > 2UL)
        fprintf(stderr, "Elapsed time: %lu seconds\n", runtime);
    fflush(stdout);

    // create kernel(s) to execute
    crypt_kernel = clCreateKernel(program[gpu_id], "kernel_crypt", &ret_code);
    HANDLE_CLERROR(ret_code, "Error creating kernel. Double-check kernel name?");

    global_work_size = get_task_max_size();
    local_work_size = get_default_workgroup();

    if (source_in_use != device_info[gpu_id]) {
        device_info[gpu_id] = source_in_use;
        fprintf(stderr, "Selected runtime id %d, source (%s)\n", source_in_use, task);
    }

    if ((tmp_value = cfg_get_param(SECTION_OPTIONS,
                                   SUBSECTION_OPENCL, LWS_CONFIG)))
        local_work_size = atoi(tmp_value);

    if ((tmp_value = getenv("LWS")))
        local_work_size = atoi(tmp_value);

    //Check if local_work_size is a valid number.
    if (local_work_size > get_task_max_work_group_size()){
        fprintf(stderr, "Error: invalid local work size (LWS). Max value allowed is: %Zd\n" ,
               get_task_max_work_group_size());
        local_work_size = 0; //Force find a valid number.
    }
    self->params.max_keys_per_crypt = global_work_size;

    if (!local_work_size) {
        local_work_size = get_task_max_work_group_size();
        create_clobj(global_work_size);
        find_best_workgroup(self);
        release_clobj();
    }

    if ((tmp_value = cfg_get_param(SECTION_OPTIONS,
                                   SUBSECTION_OPENCL, GWS_CONFIG)))
        global_work_size = atoi(tmp_value);

    if ((tmp_value = getenv("GWS")))
        global_work_size = atoi(tmp_value);

    if (global_work_size)
        create_clobj(global_work_size);

    else {
        //user chose to die of boredom
        global_work_size = get_task_max_size();
        create_clobj(global_work_size);
        find_best_gws();
    }
    fprintf(stderr, "Local work size (LWS) %Zd, global work size (GWS) %Zd\n",
           local_work_size, global_work_size);
    self->params.max_keys_per_crypt = global_work_size;
}

/* ------- Check if the ciphertext if a valid SHA-256 crypt ------- */
static int valid(char *ciphertext, struct fmt_main *self) {
    char *pos, *start;

    if (strncmp(ciphertext, "$5$", 3))
        return 0;

    ciphertext += 3;

    if (!strncmp(ciphertext, ROUNDS_PREFIX,
            sizeof(ROUNDS_PREFIX) - 1)) {
        const char *num = ciphertext + sizeof(ROUNDS_PREFIX) - 1;
        char *endp;
        if (!strtoul(num, &endp, 10))
            return 0;
        if (*endp == '$')
            ciphertext = endp + 1;
    }

    for (pos = ciphertext; *pos && *pos != '$'; pos++);
    if (!*pos || pos < ciphertext || pos > &ciphertext[SALT_LENGTH]) return 0;

    start = ++pos;
    while (atoi64[ARCH_INDEX(*pos)] != 0x7F) pos++;
    if (*pos || pos - start != CIPHERTEXT_LENGTH) return 0;

    return 1;
}

/* ------- To binary functions ------- */
#define TO_BINARY(b1, b2, b3) \
    value = (ARCH_WORD_32)atoi64[ARCH_INDEX(pos[0])] | \
           ((ARCH_WORD_32)atoi64[ARCH_INDEX(pos[1])] << 6) | \
           ((ARCH_WORD_32)atoi64[ARCH_INDEX(pos[2])] << 12) | \
           ((ARCH_WORD_32)atoi64[ARCH_INDEX(pos[3])] << 18); \
        pos += 4; \
        out[b1] = value >> 16; \
        out[b2] = value >> 8; \
        out[b3] = value;

static void * get_binary(char *ciphertext) {
    static ARCH_WORD_32 outbuf[BINARY_SIZE / 4];
    ARCH_WORD_32 value;
    char *pos;
    unsigned char *out = (unsigned char*) outbuf;

    pos = strrchr(ciphertext, '$') + 1;

    TO_BINARY(0, 10, 20);
    TO_BINARY(21, 1, 11);
    TO_BINARY(12, 22, 2);
    TO_BINARY(3, 13, 23);
    TO_BINARY(24, 4, 14);
    TO_BINARY(15, 25, 5);
    TO_BINARY(6, 16, 26);
    TO_BINARY(27, 7, 17);
    TO_BINARY(18, 28, 8);
    TO_BINARY(9, 19, 29);
    value = (ARCH_WORD_32) atoi64[ARCH_INDEX(pos[0])] |
           ((ARCH_WORD_32) atoi64[ARCH_INDEX(pos[1])] << 6) |
           ((ARCH_WORD_32) atoi64[ARCH_INDEX(pos[2])] << 12);
    out[31] = value >> 8; \
	out[30] = value; \
	return (void *) out;
}

/* ------- Compare functins ------- */
static int cmp_all(void * binary, int count) {
    uint32_t i;
    uint32_t b = ((uint32_t *) binary)[0];

    for (i = 0; i < count; i++)
        if (b == calculated_hash[i].v[0])
            return 1;
    return 0;
}

static int cmp_one(void * binary, int index) {
    return !memcmp(binary, (void *) &calculated_hash[index], BINARY_SIZE);
}

static int cmp_exact(char *source, int count) {
    return 1;
}

/* ------- Crypt function ------- */
static void crypt_all(int count) {
    //Send data to device.
    if (new_salt)
        HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], salt_buffer, CL_FALSE, 0,
            sizeof(sha256_salt), salt, 0, NULL, NULL),
            "failed in clEnqueueWriteBuffer salt_buffer");

    if (new_keys)
        HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], pass_buffer, CL_FALSE, 0,
                sizeof(sha256_password) * global_work_size, plaintext, 0, NULL, NULL),
                "failed in clEnqueueWriteBuffer pass_buffer");

    //Enqueue the kernel
    HANDLE_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], crypt_kernel, 1, NULL,
            &global_work_size, &local_work_size, 0, NULL, NULL),
            "failed in clEnqueueNDRangeKernel");

    //Read back hashes
    HANDLE_CLERROR(clEnqueueReadBuffer(queue[gpu_id], hash_buffer, CL_FALSE, 0,
            sizeof(sha256_hash) * global_work_size, calculated_hash, 0, NULL, NULL),
            "failed in reading data back");

    //Do the workx
    HANDLE_CLERROR(clFinish(queue[gpu_id]), "failed in clFinish");
    new_keys = 0;
    new_salt = 0;
}

/* ------- Binary Hash functions group ------- */
#ifdef DEBUG
static void print_binary(void * binary) {
    uint32_t *bin = binary;
    int i;

    for (i = 0; i < 8; i++)
        fprintf(stderr, "%016x ", bin[i]);
    puts("(Ok)");
}

static void print_hash() {
    int i;

    for (i = 0; i < global_work_size; i++)
        if (calculated_hash[i].v[0] == 12)
            fprintf(stderr, "Value: %u, %d\n ", calculated_hash[i].v[0], i);

    fprintf(stderr, "\n");
    for (i = 0; i < 8; i++)
        fprintf(stderr, "%016x ", calculated_hash[0].v[i]);
    puts("");
}
#endif

static int binary_hash_0(void * binary) {
#ifdef DEBUG
    print_binary(binary);
#endif
    return *(ARCH_WORD_32 *) binary & 0xF;
}
static int binary_hash_1(void * binary) { return *(ARCH_WORD_32 *) binary & 0xFF; }
static int binary_hash_2(void * binary) { return *(ARCH_WORD_32 *) binary & 0xFFF; }
static int binary_hash_3(void * binary) { return *(ARCH_WORD_32 *) binary & 0xFFFF; }
static int binary_hash_4(void * binary) { return *(ARCH_WORD_32 *) binary & 0xFFFFF; }
static int binary_hash_5(void * binary) { return *(ARCH_WORD_32 *) binary & 0xFFFFFF; }
static int binary_hash_6(void * binary) { return *(ARCH_WORD_32 *) binary & 0x7FFFFFF; }

//Get Hash functions group.
static int get_hash_0(int index) {
#ifdef DEBUG
    print_hash(index);
#endif
    return calculated_hash[index].v[0] & 0xF;
}
static int get_hash_1(int index) { return calculated_hash[index].v[0] & 0xFF; }
static int get_hash_2(int index) { return calculated_hash[index].v[0] & 0xFFF; }
static int get_hash_3(int index) { return calculated_hash[index].v[0] & 0xFFFF; }
static int get_hash_4(int index) { return calculated_hash[index].v[0] & 0xFFFFF; }
static int get_hash_5(int index) { return calculated_hash[index].v[0] & 0xFFFFFF; }
static int get_hash_6(int index) { return calculated_hash[index].v[0] & 0x7FFFFFF; }

/* ------- Format structure ------- */
struct fmt_main fmt_opencl_cryptsha256 = {
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
    },
    {
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
        set_key,
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