/*
 * This software is Copyright (c) 2012 Sayantan Datta <std2048 at gmail dot com>
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification, are permitted.
 * Based on Solar Designer implementation of DES_bs_b.c in jtr-v1.7.9
 */


#include "opencl_DES_bs.h"
#include <assert.h>
#include <string.h>
#include <sys/time.h>

#define LOG_SIZE 1024*16

typedef unsigned WORD vtype;

opencl_DES_bs_transfer *opencl_DES_bs_data;
DES_bs_vector *B;

static cl_kernel krnl[MAX_PLATFORMS * MAX_DEVICES_PER_PLATFORM][4096];
static cl_int err;
static cl_mem index768_gpu,index96_gpu,opencl_DES_bs_data_gpu,B_gpu;
static int set_salt = 0;
static   WORD current_salt;
static size_t DES_local_work_size = WORK_GROUP_SIZE;

void DES_opencl_clean_all_buffer()
{
	int i;
	const char* errMsg = "Release Memory Object :Failed";
	MEM_FREE(opencl_DES_bs_all);
	MEM_FREE(opencl_DES_bs_data);
	MEM_FREE(B);
	HANDLE_CLERROR(clReleaseMemObject(index768_gpu),errMsg);
	HANDLE_CLERROR(clReleaseMemObject(index96_gpu), errMsg);
	HANDLE_CLERROR(clReleaseMemObject(opencl_DES_bs_data_gpu), errMsg);
	HANDLE_CLERROR(clReleaseMemObject(B_gpu), errMsg);
	for( i = 0; i < 4096; i++)
		clReleaseKernel(krnl[ocl_gpu_id][i]);
}

void opencl_DES_bs_init_global_variables() {

	opencl_DES_bs_all = (opencl_DES_bs_combined*) mem_alloc (MULTIPLIER * sizeof(opencl_DES_bs_combined));
	opencl_DES_bs_data = (opencl_DES_bs_transfer*) mem_alloc (MULTIPLIER * sizeof(opencl_DES_bs_transfer));
	B = (DES_bs_vector*) mem_alloc (MULTIPLIER * 64 * sizeof(DES_bs_vector));
}

static void find_best_gws(struct fmt_main *fmt)
{
	struct timeval start, end;
	double savetime;
	long int count = 64;
	double speed = 999999, diff;
	int ccount;

	gettimeofday(&start, NULL);
	ccount = count * WORK_GROUP_SIZE * DES_BS_DEPTH;
	opencl_DES_bs_crypt_25(&ccount, NULL);
	gettimeofday(&end, NULL);
	savetime = (end.tv_sec - start.tv_sec) + (double)(end.tv_usec - start.tv_usec) / 1000000.000;
	speed = ((double)count) / savetime;
	do {
		count *= 2;
		if ((count * WORK_GROUP_SIZE) > MULTIPLIER) {
			count = count >> 1; 
			break; 
		  
		}
		gettimeofday(&start, NULL);
		ccount = count * WORK_GROUP_SIZE * DES_BS_DEPTH;
		opencl_DES_bs_crypt_25(&ccount, NULL);
		gettimeofday(&end, NULL);
		savetime = (end.tv_sec - start.tv_sec) + (double)(end.tv_usec - start.tv_usec) / 1000000.000;
		diff = (((double)count) / savetime) / speed;
		if (diff < 1) {
			count = count >> 1;
			break; 
		}
		diff = diff - 1;
		diff = (diff < 0) ? (-diff) : diff;
		speed = ((double)count) / savetime;
	} while(diff > 0.01);
	
	fprintf(stderr, "Optimal Global Work Size:%ld\n", count * WORK_GROUP_SIZE * DES_BS_DEPTH);
	
	fmt -> params.max_keys_per_crypt = count * WORK_GROUP_SIZE * DES_BS_DEPTH;
	fmt -> params.min_keys_per_crypt = WORK_GROUP_SIZE * DES_BS_DEPTH;
}

#if (HARDCODE_SALT)

	static WORD stored_salt[4096]= {0x7fffffff};

	//static char *kernel_source;

	//static int kernel_loaded;

	//static size_t program_size;
/*
static char *include_source(char *pathname, int dev_id, char *options)
{
	static char include[PATH_BUFFER_SIZE];

	sprintf(include, "-I %s %s %s%d %s %s", path_expand(pathname),
	        get_device_type(ocl_gpu_id) == CL_DEVICE_TYPE_CPU ?
	        "-DDEVICE_IS_CPU" : "",
	        "-DDEVICE_INFO=", device_info[ocl_gpu_id],
#ifdef __APPLE__
	        "-DAPPLE",
#else
	        gpu_nvidia(device_info[ocl_gpu_id]) ? "-cl-nv-verbose" : "",
#endif
	        OPENCLBUILDOPTIONS);

	if (options) {
		strcat(include, " ");
		strcat(include, options);
	}

	//fprintf(stderr, "Options used: %s\n", include);
	return include;
}

static void read_kernel_source(char *kernel_filename)
{
	char *kernel_path = path_expand(kernel_filename);
	FILE *fp = fopen(kernel_path, "r");
	size_t source_size, read_size;

	if (!fp)
		fp = fopen(kernel_path, "rb");

	if (!fp)
		HANDLE_CLERROR(!CL_SUCCESS, "Source kernel not found!");

	fseek(fp, 0, SEEK_END);
	source_size = ftell(fp);
	fseek(fp, 0, SEEK_SET);
	MEM_FREE(kernel_source);
	kernel_source = mem_calloc(source_size + 1);
	read_size = fread(kernel_source, sizeof(char), source_size, fp);
	if (read_size != source_size)
		fprintf(stderr,
		    "Error reading source: expected %zu, got %zu bytes.\n",
		    source_size, read_size);
	fclose(fp);
	program_size = source_size;
	kernel_loaded = 1;
}
*/
/*
static void build_kernel_exp(int dev_id, char *options)
{
	//cl_int build_code;
        //char * build_log; size_t log_size;
	const char *srcptr[] = { kernel_source };
	assert(kernel_loaded);
	program[ocl_gpu_id] =
	    clCreateProgramWithSource(context[ocl_gpu_id], 1, srcptr, NULL,
	    &ret_code);

	HANDLE_CLERROR(ret_code, "Error while creating program");

	if(gpu_nvidia(device_info[ocl_gpu_id]))
	   options = "";

	//build_code =
	clBuildProgram(program[ocl_gpu_id], 0, NULL,
		include_source("$JOHN/kernels/", ocl_gpu_id, options), NULL, NULL);
*/
	/*
        HANDLE_CLERROR(clGetProgramBuildInfo(program[ocl_gpu_id], devices[ocl_gpu_id],
                CL_PROGRAM_BUILD_LOG, 0, NULL,
                &log_size), "Error while getting build info I");
        build_log = (char *) mem_alloc((log_size + 1));

	HANDLE_CLERROR(clGetProgramBuildInfo(program[ocl_gpu_id], devices[ocl_gpu_id],
		CL_PROGRAM_BUILD_LOG, log_size + 1, (void *) build_log,
		NULL), "Error while getting build info");

	///Report build errors and warnings
	if (build_code != CL_SUCCESS) {
		//Give us much info about error and exit
		fprintf(stderr, "Compilation log: %s\n", build_log);
		fprintf(stderr, "Error building kernel. Returned build code: %d. DEVICE_INFO=%d\n", build_code, device_info[ocl_gpu_id]);
		HANDLE_CLERROR (build_code, "clBuildProgram failed.");
	}
#ifdef REPORT_OPENCL_WARNINGS
	else if (strlen(build_log) > 1) // Nvidia may return a single '\n' which is not that interesting
		fprintf(stderr, "Compilation log: %s\n", build_log);
#endif
        MEM_FREE(build_log);
#if 0
	FILE *file;
	size_t source_size;
	char *source;

	HANDLE_CLERROR(clGetProgramInfo(program[ocl_gpu_id],
		CL_PROGRAM_BINARY_SIZES,
		sizeof(size_t), &source_size, NULL), "error");
	fprintf(stderr, "source size %zu\n", source_size);
	source = mem_alloc(source_size);

	HANDLE_CLERROR(clGetProgramInfo(program[ocl_gpu_id],
		CL_PROGRAM_BINARIES, sizeof(char *), &source, NULL), "error");

	file = fopen("program.bin", "w");
	if (file == NULL)
		fprintf(stderr, "Error opening binary file\n");
	else if (fwrite(source, source_size, 1, file) != 1)
		fprintf(stderr, "error writing binary\n");
	fclose(file);
	MEM_FREE(source);
#endif
*/
//}

static void init_dev()
{
	opencl_init_dev(ocl_gpu_id);
	
	opencl_DES_bs_data_gpu = clCreateBuffer(context[ocl_gpu_id], CL_MEM_READ_WRITE, MULTIPLIER * sizeof(opencl_DES_bs_transfer), NULL, &err);
	if(opencl_DES_bs_data_gpu == (cl_mem)0) 
		HANDLE_CLERROR(err, "Create Buffer FAILED\n"); 

	index768_gpu = clCreateBuffer(context[ocl_gpu_id], CL_MEM_READ_WRITE, 768 * sizeof(unsigned int), NULL, &err);
	if(index768_gpu == (cl_mem)0) 
		HANDLE_CLERROR(err, "Create Buffer FAILED\n"); 

	index96_gpu = clCreateBuffer(context[ocl_gpu_id], CL_MEM_READ_WRITE, 96 * sizeof(unsigned int), NULL, &err);
	if(index96_gpu == (cl_mem)0) 
		HANDLE_CLERROR(err, "Create Buffer FAILED\n");

	B_gpu = clCreateBuffer(context[ocl_gpu_id], CL_MEM_READ_WRITE, 64 * MULTIPLIER * sizeof(DES_bs_vector), NULL, &err);
	if(B_gpu == (cl_mem)0) 
		HANDLE_CLERROR(err, "Create Buffer FAILED\n"); 

	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[ocl_gpu_id], index768_gpu, CL_TRUE, 0, 768 * sizeof(unsigned int), index768, 0, NULL, NULL ), "Failed Copy data to gpu");

	read_kernel_source("$JOHN/kernels/DES_bs_kernel.cl") ;
}

void modify_src() {

	  int i = 55, j = 1, tmp;
	  static char digits[10] = {'0','1','2','3','4','5','6','7','8','9'} ;
	  static unsigned int  index[48]  = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,
					     24,25,26,27,28,29,30,31,32,33,34,35,
					     48,49,50,51,52,53,54,55,56,57,58,59,
					     72,73,74,75,76,77,78,79,80,81,82,83 } ;
	  for (j = 1; j <= 48; j++) {
		tmp = index96[index[j - 1]] / 10;
		if (tmp == 0) 
			kernel_source[i + j * 17] = ' ' ;
		else
			kernel_source[i + j * 17] = digits[tmp];
		tmp = index96[index[j - 1]] % 10;
	     ++i;
	     kernel_source[i + j * 17 ] = digits[tmp];
	     ++i;
	  }
}

void DES_bs_select_device(struct fmt_main *fmt)
{
	init_dev();
	if(!global_work_size)
		find_best_gws(fmt);
	else {
		fprintf(stderr, "Global worksize (GWS) forced to %zu\n", global_work_size);
		fmt -> params.max_keys_per_crypt = global_work_size;
		fmt -> params.min_keys_per_crypt = WORK_GROUP_SIZE * DES_BS_DEPTH ;
	}
}
#else

void DES_bs_select_device(struct fmt_main *fmt)
{
	//char *env;
	size_t max_lws;
	const char *errMsg;

	opencl_init_opt("$JOHN/kernels/DES_bs_kernel.cl", ocl_gpu_id, NULL);
	
	krnl[ocl_gpu_id][0] = clCreateKernel(program[ocl_gpu_id], "DES_bs_25_b", &err) ;
	if (err) {
		fprintf(stderr, "Create Kernel DES_bs_25_b FAILED\n"); 
		return ;
	}
	//cmdq[platform_no][dev_no] = queue[ocl_gpu_id];

	/* Honour this for testing and --test=0 */
	//if ((env = getenv("LWS")))
	//	DES_local_work_size = atoi(env);

	/* Cap LWS at device limit... */
	HANDLE_CLERROR(clGetKernelWorkGroupInfo(krnl[ocl_gpu_id][0], devices[ocl_gpu_id], CL_KERNEL_WORK_GROUP_SIZE, sizeof(max_lws), &max_lws, NULL), "Query max work group size");

	/* ...but ensure GWS is still a multiple of LWS */
	while (DES_local_work_size > max_lws)
		DES_local_work_size >>= 1;
	//fprintf(stderr, "Using LWS %zu\n", DES_local_work_size);
		
	errMsg = "Create Buffer FAILED."; 
	opencl_DES_bs_data_gpu = clCreateBuffer(context[ocl_gpu_id], CL_MEM_READ_WRITE, MULTIPLIER * sizeof(opencl_DES_bs_transfer), NULL, &err);
	if (opencl_DES_bs_data_gpu == (cl_mem)0)  
		HANDLE_CLERROR(err, errMsg); 

	index768_gpu = clCreateBuffer(context[ocl_gpu_id], CL_MEM_READ_WRITE, 768 * sizeof(unsigned int), NULL, &err);
	if (index768_gpu == (cl_mem)0)  
		HANDLE_CLERROR(err, errMsg); 

	index96_gpu = clCreateBuffer(context[ocl_gpu_id], CL_MEM_READ_WRITE, 96 * sizeof(unsigned int), NULL, &err);
	if (index96_gpu == (cl_mem)0) 
		HANDLE_CLERROR(err, errMsg); 

	B_gpu = clCreateBuffer(context[ocl_gpu_id], CL_MEM_READ_WRITE, 64 * MULTIPLIER * sizeof(DES_bs_vector), NULL, &err);
	if (B_gpu == (cl_mem)0) 
		HANDLE_CLERROR(err, errMsg); 

	HANDLE_CLERROR(clSetKernelArg(krnl[ocl_gpu_id][0], 0, sizeof(cl_mem), &index768_gpu), "Set Kernel Arg FAILED arg0\n");
	HANDLE_CLERROR(clSetKernelArg(krnl[ocl_gpu_id][0], 1, sizeof(cl_mem), &index96_gpu), "Set Kernel Arg FAILED arg1\n");
	HANDLE_CLERROR(clSetKernelArg(krnl[ocl_gpu_id][0], 2, sizeof(cl_mem), &opencl_DES_bs_data_gpu), "Set Kernel Arg FAILED arg2\n");
	HANDLE_CLERROR(clSetKernelArg(krnl[ocl_gpu_id][0], 3, sizeof(cl_mem),&B_gpu), "Set Kernel Arg FAILED arg4\n");

	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[ocl_gpu_id], index768_gpu, CL_TRUE, 0, 768*sizeof(unsigned int), index768, 0, NULL, NULL ), "Failed Copy data to gpu");

	if (!global_work_size)
		find_best_gws(fmt);
	else {
		fprintf(stderr, "Global worksize (GWS) forced to %zu\n", global_work_size);
		fmt -> params.max_keys_per_crypt = global_work_size;
		fmt -> params.min_keys_per_crypt = WORK_GROUP_SIZE*DES_BS_DEPTH ;
	}
}
#endif

void opencl_DES_bs_set_salt(WORD salt)
{
	unsigned int new = salt,section=0;
	unsigned int old;
	int dst;

	for (section = 0; section < MAX_KEYS_PER_CRYPT / DES_BS_DEPTH; section++) {
	new = salt;
	old = opencl_DES_bs_all[section].salt;
	opencl_DES_bs_all[section].salt = new;
	}
	section=0;
	current_salt = salt ;
	for (dst = 0; dst < 24; dst++) {
		if ((new ^ old) & 1) {
			DES_bs_vector *sp1, *sp2;
			int src1 = dst;
			int src2 = dst + 24;
			if (new & 1) {
				src1 = src2;
				src2 = dst;
			}
			sp1 = opencl_DES_bs_all[section].Ens[src1];
			sp2 = opencl_DES_bs_all[section].Ens[src2];

			index96[dst] = (WORD *)sp1 - (WORD *)B;
			index96[dst + 24] = (WORD *)sp2 - (WORD *)B;
			index96[dst + 48] = (WORD *)(sp1 + 32) - (WORD *)B;
			index96[dst + 72] = (WORD *)(sp2 + 32) - (WORD *)B;
		}
		new >>= 1;
		old >>= 1;
		if (new == old)
			break;
	}

	set_salt = 1;
}

#if HARDCODE_SALT

int opencl_DES_bs_crypt_25(int *pcount, struct db_salt *salt)
{
	int keys_count = *pcount;
	unsigned int section = 0, keys_count_multiple;
	static unsigned int pos ;
	cl_event evnt;
	size_t N,M;

	if (keys_count%DES_BS_DEPTH == 0) 
		keys_count_multiple = keys_count;
	else 
		keys_count_multiple = (keys_count / DES_BS_DEPTH + 1) * DES_BS_DEPTH;

	section = keys_count_multiple / DES_BS_DEPTH;

	M = DES_local_work_size;

	if (section % DES_local_work_size != 0)
		N = (section / DES_local_work_size + 1) * DES_local_work_size ;
	else
		N = section;

	if (set_salt == 1) {
		unsigned int found = 0;
		if (stored_salt[current_salt] == current_salt) {
			found = 1;
			pos = current_salt;
		}

		if (found == 0) {
			pos = current_salt;
			modify_src();
			clReleaseProgram(program[ocl_gpu_id]);
			//build_kernel( ocl_gpu_id, "-fno-bin-amdil -fno-bin-source -fbin-exe") ;
			opencl_build(ocl_gpu_id, "-fno-bin-amdil -fno-bin-source -fbin-exe", 0, NULL, 1);
			krnl[ocl_gpu_id][pos] = clCreateKernel(program[ocl_gpu_id], "DES_bs_25", &err) ;
			
			if (err) {
				fprintf(stderr, "Create Kernel DES_bs_25 FAILED\n"); 
				return 0;
			}
			
			HANDLE_CLERROR(clSetKernelArg(krnl[ocl_gpu_id][pos], 0, sizeof(cl_mem), &index768_gpu), "Set Kernel Arg FAILED arg0\n");
			HANDLE_CLERROR(clSetKernelArg(krnl[ocl_gpu_id][pos], 1, sizeof(cl_mem), &index96_gpu), "Set Kernel Arg FAILED arg1\n");
			HANDLE_CLERROR(clSetKernelArg(krnl[ocl_gpu_id][pos], 2, sizeof(cl_mem), &opencl_DES_bs_data_gpu), "Set Kernel Arg FAILED arg2\n");
			HANDLE_CLERROR(clSetKernelArg(krnl[ocl_gpu_id][pos], 3, sizeof(cl_mem),&B_gpu), "Set Kernel Arg FAILED arg4\n");
			stored_salt[current_salt] = current_salt;
		}
		//HANDLE_CLERROR(clEnqueueWriteBuffer(queue[ocl_gpu_id],index96_gpu,CL_TRUE,0,96*sizeof(unsigned int),index96,0,NULL,NULL ), "Failed Copy data to gpu");
		set_salt = 0;
	}

	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[ocl_gpu_id],opencl_DES_bs_data_gpu,CL_TRUE,0,MULTIPLIER*sizeof(opencl_DES_bs_transfer),opencl_DES_bs_data,0,NULL,NULL ), "Failed Copy data to gpu");

	err=clEnqueueNDRangeKernel(queue[ocl_gpu_id],krnl[ocl_gpu_id][pos],1,NULL,&N,&M,0,NULL,&evnt);
	HANDLE_CLERROR(err,"Enque Kernel Failed");

	clWaitForEvents(1,&evnt);

	HANDLE_CLERROR(clEnqueueReadBuffer(queue[ocl_gpu_id],B_gpu,CL_TRUE,0,MULTIPLIER*64*sizeof(DES_bs_vector),B, 0, NULL, NULL),"Write FAILED\n");

	clFinish(queue[ocl_gpu_id]);

	return keys_count;
}

#else

int opencl_DES_bs_crypt_25(int *pcount, struct db_salt *salt)
{
	int keys_count = *pcount;
	unsigned int section = 0, keys_count_multiple;
	cl_event evnt;
	size_t N, M;

	if (keys_count % DES_BS_DEPTH == 0)
		keys_count_multiple = keys_count;
	else 
		keys_count_multiple = (keys_count/DES_BS_DEPTH + 1) * DES_BS_DEPTH;

	section = keys_count_multiple / DES_BS_DEPTH;
	M = DES_local_work_size;

	if (section % DES_local_work_size !=0)
		N = (section / DES_local_work_size +1) * DES_local_work_size ;
	else
		N = section;

	if (set_salt == 1) {
		HANDLE_CLERROR(clEnqueueWriteBuffer(queue[ocl_gpu_id], index96_gpu, CL_TRUE, 0, 96 * sizeof(unsigned int), index96, 0, NULL, NULL ), "Failed Copy data to gpu");
		set_salt = 0;
	}

	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[ocl_gpu_id], opencl_DES_bs_data_gpu, CL_TRUE, 0, MULTIPLIER * sizeof(opencl_DES_bs_transfer), opencl_DES_bs_data, 0, NULL, NULL ), "Failed Copy data to gpu");

	err = clEnqueueNDRangeKernel(queue[ocl_gpu_id], krnl[ocl_gpu_id][0], 1, NULL, &N, &M, 0, NULL, &evnt);
	HANDLE_CLERROR(err, "Enque Kernel Failed");

	clWaitForEvents(1, &evnt);

	HANDLE_CLERROR(clEnqueueReadBuffer(queue[ocl_gpu_id], B_gpu, CL_TRUE, 0, MULTIPLIER * 64 * sizeof(DES_bs_vector), B, 0, NULL, NULL), "Copy data from Device :Failed");

	clFinish(queue[ocl_gpu_id]);

	return keys_count;
}
#endif
