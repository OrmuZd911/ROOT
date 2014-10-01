/*
 * This file is part of John the Ripper password cracker.
 *
 * Common OpenCL functions go in this file.
 *
 * This software is
 * Copyright (c) 2010-2012 Samuele Giovanni Tonon <samu at linuxasylum dot net>
 * Copyright (c) 2010-2013 Lukas Odzioba <ukasz@openwall.net>
 * Copyright (c) 2010-2013 magnum
 * Copyright (c) 2012-2013 Claudio André <claudio.andre at correios.net.br>
 * and is hereby released to the general public under the following terms:
 *    Redistribution and use in source and binary forms, with or without
 *    modifications, are permitted.
 */

#define _BSD_SOURCE // setenv()
#define NEED_OS_TIMER
#include "os.h"

#include <assert.h>
#include <string.h>
#include <ctype.h>
#include <sys/stat.h>
#include <time.h>
#include <signal.h>
#include <stdlib.h>

#include "options.h"
#include "config.h"
#include "common-opencl.h"
#include "signals.h"
#include "recovery.h"
#include "status.h"
#include "john.h"
#ifdef HAVE_MPI
#include "john-mpi.h"
#endif
#include "memdbg.h"

#define LOG_SIZE 1024*16

#define MIN(a, b)		(((a) > (b)) ? (b) : (a))
#define MAX(a, b)		(((a) > (b)) ? (a) : (b))

// If we are a release build, only output OpenCL build log if
// there was a fatal error (or --verbosity was increased).
#ifdef JTR_RELEASE_BUILD
#define LOG_VERB 4
#else
#define LOG_VERB 3
#endif

/* Common OpenCL variables */
int platform_id;
int default_gpu_selected = 0;

static char opencl_log[LOG_SIZE];
static int kernel_loaded;
static size_t program_size;
static int opencl_initialized;

extern volatile int bench_running;
static void opencl_get_dev_info(int sequential_id);
static void find_valid_opencl_device(int *dev_id, int *platform_id);

// Used by auto-tuning to decide how GWS should changed between trials.
extern int common_get_next_gws_size(size_t num, int step, int startup,
	int default_value);

// Settings to use for auto-tuning.
static int buffer_size;
static int default_value;
static int hash_loops;
static unsigned long long int duration_time = 0;
static const char **warnings;
static int *split_events;
static int main_opencl_event;
static struct fmt_main *self;
static void (*create_clobj)(size_t gws, struct fmt_main *self);
static void (*release_clobj)(void);
static const char *config_name;
static size_t gws_limit;

cl_device_id devices[MAX_GPU_DEVICES];
cl_context context[MAX_GPU_DEVICES];
cl_program program[MAX_GPU_DEVICES];
cl_command_queue queue[MAX_GPU_DEVICES];
cl_int ret_code;
cl_kernel crypt_kernel;
size_t local_work_size;
size_t global_work_size;
size_t max_group_size;
unsigned int opencl_v_width = 1;

char *kernel_source;
static char *kernel_source_file;

cl_event *profilingEvent, *firstEvent, *lastEvent;
cl_event *multi_profilingEvent[MAX_EVENTS];

int device_info[MAX_GPU_DEVICES];
static ocl_device_detais ocl_device_list[MAX_GPU_DEVICES];

void opencl_process_event(void)
{
	if (!bench_running) {
#if !OS_TIMER
		sig_timer_emu_tick();
#endif
		if (event_pending) {

			event_pending = event_abort;

			if (event_save) {
				event_save = 0;
				rec_save();
			}

			if (event_status) {
				event_status = 0;
				status_print();
			}

			if (event_ticksafety) {
				event_ticksafety = 0;
				status_ticks_overflow_safety();
			}
		}
	}
}

void handle_clerror(cl_int cl_error, const char *message, const char *file,
		    int line)
{
	if (cl_error != CL_SUCCESS) {
		fprintf(stderr,
			"OpenCL error (%s) in file (%s) at line (%d) - (%s)\n",
			get_error_name(cl_error), file, line, message);
		exit(EXIT_FAILURE);
	}
}

int get_number_of_available_platforms()
{
	int i = 0;

	while (platforms[i++].platform);

	return --i;
}

int get_number_of_available_devices()
{
	int total = 0, i = 0;

	while (platforms[i].platform)
		total += platforms[i++].num_devices;

	return total;
}

int get_number_of_devices_in_use()
{
	int i = 0;

	while (gpu_device_list[i++] != -1);

	return --i;
}

int get_platform_id(int sequential_id)
{
	int pos = 0, i = 0;

	while (platforms[i].platform) {
		pos += platforms[i].num_devices;

		if (sequential_id < pos)
			break;
		i++;
	}
	return (platforms[i].platform ? i : -1);
}

int get_device_id(int sequential_id)
{
	int pos = sequential_id, i = 0;

	while (platforms[i].platform && pos >= platforms[i].num_devices) {
		pos -= platforms[i].num_devices;
		i++;
	}
	return (platforms[i].platform ? pos : -1);
}

int get_sequential_id(unsigned int dev_id, unsigned int platform_id)
{
	int pos = 0, i = 0;

	while (platforms[i].platform && i < platform_id)
		pos += platforms[i++].num_devices;

	if (i == platform_id && dev_id >= platforms[i].num_devices)
		return -1;

	return (platforms[i].platform ? pos + dev_id : -1);
}

static int get_if_device_is_in_use(int sequential_id)
{
	int i = 0, found = 0;

	if (sequential_id >= get_number_of_available_devices()) {
		return -1;
	}

	for (i = 0; i < get_number_of_devices_in_use() && !found; i++) {
		if (sequential_id == gpu_device_list[i])
			found = 1;
	}
	return found;
}

static void start_opencl_environment()
{
	cl_platform_id platform_list[MAX_PLATFORMS];
	char opencl_data[LOG_SIZE];
	cl_uint num_platforms, device_num, device_pos = 0;
	int i;

	/* Find OpenCL enabled devices. We ignore error here, in case
	 * there is no platform and we'd like to run a non-OpenCL format. */
	clGetPlatformIDs(MAX_PLATFORMS, platform_list, &num_platforms);

	for (i = 0; i < num_platforms; i++) {
		platforms[i].platform = platform_list[i];

		HANDLE_CLERROR(clGetPlatformInfo(platforms[i].platform,
		    CL_PLATFORM_NAME, sizeof(opencl_data), opencl_data, NULL),
		    "Error querying PLATFORM_NAME");
		HANDLE_CLERROR(clGetDeviceIDs(platforms[i].platform,
		    CL_DEVICE_TYPE_ALL, MAX_GPU_DEVICES, &devices[device_pos],
		    &device_num), "No OpenCL device of that type exist");

		// Save platform and devices information
		platforms[i].num_devices = device_num;

		// Point to the end of the list
		device_pos += device_num;

#ifdef DEBUG
		fprintf(stderr, "OpenCL platform %d: %s, %d device(s).\n",
			i, opencl_data, device_num);
#endif
	}
	// Set NULL to the final buffer position.
	platforms[i].platform = NULL;
	devices[device_pos] = NULL;
}

static cl_int get_pci_info(int sequential_id, hw_bus * hardware_info) {

	cl_int ret;
	hardware_info->bus = -1;
	hardware_info->device = -1;
	memset(hardware_info->busId, '\0', sizeof(hardware_info->busId));

#if defined(CL_DEVICE_TOPOLOGY_AMD) && CL_DEVICE_TOPOLOGY_TYPE_PCIE_AMD == 1

	if (gpu_amd(device_info[sequential_id]) || cpu(device_info[sequential_id])) {
		cl_device_topology_amd topo;

		ret = clGetDeviceInfo(devices[sequential_id],
			CL_DEVICE_TOPOLOGY_AMD, sizeof(topo), &topo, NULL);

		if (ret == CL_SUCCESS) {
			hardware_info->bus = topo.pcie.bus & 0xff;
			hardware_info->device = topo.pcie.device & 0xff;
			hardware_info->function = topo.pcie.function & 0xff;
		} else
			if (cpu_intel(device_info[sequential_id]))
				return CL_SUCCESS;
			else
				return ret;
	}
#endif

#ifdef CL_DEVICE_REGISTERS_PER_BLOCK_NV

	if (gpu_nvidia(device_info[sequential_id])) {
		cl_uint entries;

		ret = clGetDeviceInfo(
			devices[sequential_id], CL_DEVICE_PCI_BUS_ID_NV,
			sizeof(cl_uint), &entries, NULL);

		if (ret == CL_SUCCESS)
			hardware_info->bus = entries;
		else
		    return ret;

		ret = clGetDeviceInfo(
			devices[sequential_id],CL_DEVICE_PCI_SLOT_ID_NV,
			sizeof(cl_uint), &entries, NULL);

		if (ret == CL_SUCCESS) {
			hardware_info->device = entries >> 3;
			hardware_info->function = entries & 7;

		} else
		    return ret;
	}
#endif
	sprintf(hardware_info->busId, "%02x:%02x.%x", hardware_info->bus,
		hardware_info->device, hardware_info->function);
	return CL_SUCCESS;
}

static int start_opencl_device(int sequential_id, int *err_type)
{
	cl_context_properties properties[3];
	char opencl_data[LOG_SIZE];
	static int amd = 0, nvidia = 0;

	// Get the detailed information about the device.
	opencl_get_dev_info(sequential_id);

	// Map temp monitoring function to device id
	if (gpu_nvidia(device_info[sequential_id])) {
		temp_dev_id[sequential_id] = nvidia++;
		dev_get_temp[sequential_id] = nvml_lib ? nvidia_get_temp : NULL;
	} else if (gpu_amd(device_info[sequential_id])) {
		temp_dev_id[sequential_id] = amd++;
		dev_get_temp[sequential_id] = adl_lib ? amd_get_temp : NULL;
	} else {
		temp_dev_id[sequential_id] = sequential_id;
		dev_get_temp[sequential_id] = NULL;
	}
	//Get harware bus/pcie information.
	HANDLE_CLERROR(
		get_pci_info(sequential_id,
		&ocl_device_list[sequential_id].pci_info),
	    "Error querying BUS INFORMATION");

	HANDLE_CLERROR(clGetDeviceInfo(devices[sequential_id], CL_DEVICE_NAME,
	    sizeof(opencl_data), opencl_data, NULL),
	    "Error querying DEVICE_NAME");

	max_group_size = get_device_max_lws(sequential_id);

	// Get the platform properties
	properties[0] = CL_CONTEXT_PLATFORM;
	properties[1] = (cl_context_properties)
		platforms[get_platform_id(sequential_id)].platform;
	properties[2] = 0;

	// Setup context and queue
	context[sequential_id] = clCreateContext(properties, 1,
		&devices[sequential_id], NULL, NULL, &ret_code);
	if (ret_code != CL_SUCCESS) {
#ifdef DEBUG
		fprintf(stderr, "Error creating context for device %d "
			"(%d:%d): %s\n", sequential_id,
			get_platform_id(sequential_id),
			get_device_id(sequential_id),
			get_error_name(ret_code));
#endif
		platforms[get_platform_id(sequential_id)].num_devices--;
		*err_type = 1;
		return 0;
	}
	queue[sequential_id] = clCreateCommandQueue(context[sequential_id],
		devices[sequential_id], 0, &ret_code);
	if (ret_code != CL_SUCCESS) {
#ifdef DEBUG
		fprintf(stderr, "Error creating command queue for "
			"device %d (%d:%d): %s\n", sequential_id,
			get_platform_id(sequential_id),
			get_device_id(sequential_id),
			get_error_name(ret_code));
#endif
		platforms[get_platform_id(sequential_id)].num_devices--;
		HANDLE_CLERROR(clReleaseContext(context[sequential_id]),
				"Release Context");
		*err_type = 2;
		return 0;
	}
#ifdef DEBUG
	fprintf(stderr, "  Device %d: %s\n", sequential_id, opencl_data);
#endif
	// Success.
	return 1;
}

static void add_device_to_list(int sequential_id)
{
	int i = 0, found;

	found = get_if_device_is_in_use(sequential_id);

	if (found < 0) {
		fprintf(stderr, "Invalid OpenCL device id %d\n", sequential_id);
		exit(EXIT_FAILURE);
	}

	if (found == 0) {
		// Only requested and working devices should be started.
		if (start_opencl_device(sequential_id, &i)) {
			gpu_device_list[get_number_of_devices_in_use() + 1] = -1;
			gpu_device_list[get_number_of_devices_in_use()] = sequential_id;
		} else
			fprintf(stderr, "Device id %d not working correctly,"
				" skipping.\n", sequential_id);
	}
}

static void add_device_type(cl_ulong device_type)
{
	int i, j, sequence_nr = 0;
	cl_uint device_num;
	cl_ulong long_entries;
	cl_device_id devices[MAX_GPU_DEVICES];

	for (i = 0; platforms[i].platform; i++) {
		// Get all devices of informed type.
		HANDLE_CLERROR(clGetDeviceIDs(platforms[i].platform,
			CL_DEVICE_TYPE_ALL, MAX_GPU_DEVICES, devices, &device_num),
			"No OpenCL device of that type exist");

		for (j = 0; j < device_num; j++, sequence_nr++) {
			clGetDeviceInfo(devices[j], CL_DEVICE_TYPE,
					sizeof(cl_ulong), &long_entries, NULL);
			if (long_entries & device_type)
				add_device_to_list(sequence_nr);
		}
	}
}

static void build_device_list(char *device_list[MAX_GPU_DEVICES])
{
	int n = 0;

	while (device_list[n] && n < MAX_GPU_DEVICES) {
		int len = MAX(strlen(device_list[n]), 3);
		if (!strcmp(device_list[n], "all"))
			add_device_type(CL_DEVICE_TYPE_ALL);
		else if (!strcmp(device_list[n], "cpu"))
			add_device_type(CL_DEVICE_TYPE_CPU);
		else if (!strcmp(device_list[n], "gpu"))
			add_device_type(CL_DEVICE_TYPE_GPU);
		else if (!strncmp(device_list[n], "accelerator", len))
			add_device_type(CL_DEVICE_TYPE_ACCELERATOR);
		else if (!isdigit(device_list[n][0])) {
			fprintf(stderr, "Error: --device must be numerical, "
				"or one of \"all\", \"cpu\", \"gpu\" and\n"
				"\"accelerator\".\n");
			exit(1);
		}
		else
			add_device_to_list(atoi(device_list[n]));
		n++;
	}
}

void opencl_preinit(void)
{
	char *device_list[MAX_GPU_DEVICES], string[10];
	int n = 0;
	char *env;

	// Prefer COMPUTE over DISPLAY and lacking both, assume :0
	env = getenv("COMPUTE");
	if (env && *env)
		setenv("DISPLAY", env, 1);
	else {
		// We assume that 10 dot something is X11
		// forwarding so we override that too.
		env = getenv("DISPLAY");
		if (!env || !*env || strstr(env, ":10."))
			setenv("DISPLAY", ":0", 1);
	}

	if (!opencl_initialized) {
		nvidia_probe();
		amd_probe();
		device_list[0] = NULL;

		gpu_device_list[0] = -1;
		gpu_device_list[1] = -1;
		start_opencl_environment();

		if (options.ocl_platform) {
			struct list_entry *current;

			platform_id = atoi(options.ocl_platform);

			if (platform_id >= get_number_of_available_platforms())
			{
				fprintf(stderr, "Invalid OpenCL platform %d\n",
					platform_id);
				exit(1);
			}

			/* Legacy syntax --platform + --device */
			if ((current = options.gpu_devices->head)) {
				if (current->next) {
					fprintf(stderr, "Only one OpenCL device"
						" supported with --platform "
						"syntax.\n");
					exit(1);
				}
				if (!strcmp(current->data, "all") ||
				    !strcmp(current->data, "cpu") ||
				    !strcmp(current->data, "gpu")) {
					fprintf(stderr, "Only a single "
						"numerical --device allowed "
						"when using legacy --platform "
						"syntax.\n");
					exit(1);
				}
				if (!isdigit(ARCH_INDEX(current->data[0]))) {
					fprintf(stderr, "Invalid OpenCL device"
						" id %s\n", current->data);
					exit(1);
				}
				gpu_id = get_sequential_id(
					atoi(current->data), platform_id);

				if (gpu_id < 0) {
					fprintf(stderr, "Invalid OpenCL device"
						" id %s\n", current->data);
					exit(1);
				}
			} else
				gpu_id = get_sequential_id(0, platform_id);
		} else {
			struct list_entry *current;

			/* New syntax, sequential --device */
			if ((current = options.gpu_devices->head)) {
				do {
					device_list[n++] = current->data;
				} while ((current = current->next));

				device_list[n] = NULL;
			} else {
				gpu_id = -1;
				platform_id = -1;
			}
		}

		// Use configuration file only if JtR knows nothing about
		// the environment.
		if (!options.ocl_platform && platform_id < 0) {
			char *devcfg;

			if ((devcfg = cfg_get_param(SECTION_OPTIONS,
						    SUBSECTION_OPENCL,
						    "Platform")))
				platform_id = atoi(devcfg);
		}

		if (!options.gpu_devices->head && gpu_id < 0) {
			char *devcfg;

			if ((devcfg = cfg_get_param(SECTION_OPTIONS,
						    SUBSECTION_OPENCL,
						    "Device"))) {
				gpu_id = atoi(devcfg);
				gpu_device_list[0] = gpu_id;
			}
		}

		if (platform_id == -1 || gpu_id == -1) {
			find_valid_opencl_device(&gpu_id, &platform_id);
			gpu_id = get_sequential_id(gpu_id, platform_id);
			default_gpu_selected = 1;
		}

		if (!device_list[0]) {
			sprintf(string, "%d", gpu_id);
			device_list[0] = string;
			device_list[1] = NULL;
		}

		build_device_list(device_list);

		if (get_number_of_devices_in_use() == 0) {
			fprintf(stderr, "No OpenCL devices found\n");
			exit(1);
		}
#ifdef HAVE_MPI
		// Poor man's multi-device support
		if (mpi_p > 1) {
			// Pick device to use for this node
			gpu_id =
				gpu_device_list[mpi_id % get_number_of_devices_in_use()];

			// Hide any other devices from list
			gpu_device_list[0] = gpu_id;
			gpu_device_list[1] = -1;
		} else
#endif
			gpu_id = gpu_device_list[0];
		platform_id = get_platform_id(gpu_id);

		opencl_initialized = 1;
	}
}

unsigned int opencl_get_vector_width(int sequential_id, int size)
{
	/* --force-scalar option, or john.conf ForceScalar boolean */
	if (options.flags & FLG_SCALAR)
		options.v_width = 1;

	/* --force-vector-width=N */
	if (options.v_width) {
		opencl_v_width = options.v_width;
	} else {
		cl_uint v_width = 0;

		/* OK, we supply the real figure */
		opencl_preinit();
		switch(size) {
		case sizeof(cl_char):
			HANDLE_CLERROR(clGetDeviceInfo(devices[gpu_id],
				CL_DEVICE_PREFERRED_VECTOR_WIDTH_CHAR,
				sizeof(v_width), &v_width, NULL),
				"Error asking for char vector width");
			break;
		case sizeof(cl_short):
			HANDLE_CLERROR(clGetDeviceInfo(devices[gpu_id],
				CL_DEVICE_PREFERRED_VECTOR_WIDTH_SHORT,
				sizeof(v_width), &v_width, NULL),
				"Error asking for long vector width");
			break;
		case sizeof(cl_int):
			HANDLE_CLERROR(clGetDeviceInfo(devices[gpu_id],
				CL_DEVICE_PREFERRED_VECTOR_WIDTH_INT,
				sizeof(v_width), &v_width, NULL),
				"Error asking for int vector width");
			break;
		case sizeof(cl_long):
			HANDLE_CLERROR(clGetDeviceInfo(devices[gpu_id],
				CL_DEVICE_PREFERRED_VECTOR_WIDTH_LONG,
				sizeof(v_width), &v_width, NULL),
				"Error asking for long vector width");
			break;
		default:
			fprintf(stderr, "%s() called with unknown type\n",
				__FUNCTION__);
			error();
		}
		opencl_v_width = v_width;
	}
	return opencl_v_width;
}

/* Called by core after calling format's done() */
void opencl_done()
{
	int i;

	if (!opencl_initialized)
		return;

	for (i = 0; i < get_number_of_devices_in_use(); i++) {
		if (queue[gpu_device_list[i]])
			HANDLE_CLERROR(clReleaseCommandQueue(
					       queue[gpu_device_list[i]]),
				       "Release Queue");
		queue[gpu_device_list[i]] = NULL;
		if (context[gpu_device_list[i]])
			HANDLE_CLERROR(clReleaseContext(
					       context[gpu_device_list[i]]),
				       "Release Context");
		context[gpu_device_list[i]] = NULL;
	}
	if (kernel_source) libc_free(kernel_source);
	kernel_source = NULL;

	/* Reset in case we load another format after this */
	local_work_size = global_work_size = duration_time = 0;
	opencl_v_width = 1;

	opencl_initialized = 0;
}

static char *opencl_get_config_name(char *format, char *config_name)
{
	static char full_name[128];

	full_name[0] = '\0';
	strcat(full_name, format);
	strcat(full_name, config_name);

	return full_name;
}

void opencl_get_user_preferences(char *format)
{
	char *tmp_value;

	if (format)
	if ((tmp_value = cfg_get_param(SECTION_OPTIONS, SUBSECTION_OPENCL,
		opencl_get_config_name(format, LWS_CONFIG_NAME))))
		local_work_size = atoi(tmp_value);

	if ((tmp_value = getenv("LWS")))
		local_work_size = atoi(tmp_value);

	if (format)
	if ((tmp_value = cfg_get_param(SECTION_OPTIONS, SUBSECTION_OPENCL,
		opencl_get_config_name(format, GWS_CONFIG_NAME))))
		global_work_size = atoi(tmp_value);

	if ((tmp_value = getenv("GWS")))
		global_work_size = atoi(tmp_value);

	if (local_work_size)
		// Ensure a valid multiple is used.
		global_work_size = GET_MULTIPLE_OR_ZERO(global_work_size,
						local_work_size);

	if (format)
	if ((tmp_value = cfg_get_param(SECTION_OPTIONS, SUBSECTION_OPENCL,
		opencl_get_config_name(format, DUR_CONFIG_NAME))))
		duration_time = atoi(tmp_value) * 1000000000ULL;

	// Save the format config string.
	config_name = format;
}

static void dev_init(int sequential_id)
{
	char device_name[MAX_OCLINFO_STRING_LEN];
#ifdef CL_DEVICE_BOARD_NAME_AMD
	cl_int ret_code;
	int len;
#endif
	HANDLE_CLERROR(clGetDeviceInfo(devices[sequential_id], CL_DEVICE_NAME,
		sizeof(device_name), device_name, NULL),
		"Error querying DEVICE_NAME");

#ifdef CL_DEVICE_BOARD_NAME_AMD
	ret_code = clGetDeviceInfo(devices[sequential_id],
				   CL_DEVICE_BOARD_NAME_AMD,
				   sizeof(opencl_log), opencl_log, NULL);

	if (ret_code == CL_SUCCESS && (len = strlen(opencl_log))) {
		while (len > 0 && isspace(ARCH_INDEX(opencl_log[len - 1])))
			len--;
		opencl_log[len] = '\0';

		if (options.verbosity >= 2)
			fprintf(stderr, "Device %d: %s (%s)\n",
				sequential_id, device_name, opencl_log);
	} else
#endif
	{
		if (options.verbosity >= 2)
			fprintf(stderr, "Device %d: %s\n",
				sequential_id, device_name);
	}
}

static char *include_source(char *pathname, int sequential_id, char *opts)
{
	static char include[PATH_BUFFER_SIZE];

	sprintf(include, "-I %s %s %s%s%s%d %s %s", path_expand(pathname),
		OPENCLBUILDOPTIONS,
#ifdef __APPLE__
		"-DAPPLE ",
#else
		gpu_nvidia(device_info[sequential_id]) ? "-cl-nv-verbose " : "",
#endif
		get_device_type(sequential_id) == CL_DEVICE_TYPE_CPU ?
		"-DDEVICE_IS_CPU " : "",
		"-DDEVICE_INFO=", device_info[sequential_id],
		"-D_OPENCL_COMPILER",
		opts ? opts : "");

	if (options.verbosity > 3)
		fprintf(stderr, "Options used: %s\n", include);
	return include;
}

void opencl_build(int sequential_id, char *opts, int save, char *file_name,
		  int showLog)
{
	cl_int build_code;
	char *build_log; size_t log_size;
	const char *srcptr[] = { kernel_source };

	assert(kernel_loaded);
	program[sequential_id] =
		clCreateProgramWithSource(context[sequential_id], 1, srcptr,
					  NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error while creating program");

	build_code = clBuildProgram(program[sequential_id], 0, NULL,
		include_source("$JOHN/kernels", sequential_id, opts),
		 NULL, NULL);

	HANDLE_CLERROR(clGetProgramBuildInfo(program[sequential_id],
					     devices[sequential_id],
					     CL_PROGRAM_BUILD_LOG, 0, NULL,
					     &log_size),
		       "Error while getting build info I");
	build_log = (char *) mem_calloc((log_size + 1));

	HANDLE_CLERROR(clGetProgramBuildInfo(program[sequential_id],
					     devices[sequential_id],
					     CL_PROGRAM_BUILD_LOG, log_size + 1,
					     (void *) build_log, NULL),
		       "Error while getting build info");

	// Report build errors and warnings
	if ((build_code != CL_SUCCESS) && showLog ) {
		// Give us much info about error and exit
		fprintf(stderr, "Build log: %s\n", build_log);
		fprintf(stderr, "Error %d building kernel %s. DEVICE_INFO=%d\n",
		        build_code, kernel_source_file,
		        device_info[sequential_id]);
		HANDLE_CLERROR (build_code, "clBuildProgram failed.");
	}
	// Nvidia may return a single '\n' that we ignore
	else if (options.verbosity >= LOG_VERB && strlen(build_log) > 1 &&
		 showLog)
		fprintf(stderr, "Build log: %s\n", build_log);
	MEM_FREE(build_log);

	if (save) {
		FILE *file;
		size_t source_size;
		char *source;

		HANDLE_CLERROR(clGetProgramInfo(program[sequential_id],
			CL_PROGRAM_BINARY_SIZES,
			sizeof(size_t), &source_size, NULL), "error");

		if (options.verbosity > 4)
			fprintf(stderr, "binary size %zu\n", source_size);

		source = mem_calloc(source_size);

		HANDLE_CLERROR(clGetProgramInfo(program[sequential_id],
						CL_PROGRAM_BINARIES,
						sizeof(char *), &source, NULL),
			       "error");

		file = fopen(path_expand(file_name), "w");

		if (file == NULL)
			fprintf(stderr, "Error creating binary file %s\n",
				file_name);
		else {
			if (fwrite(source, source_size, 1, file) != 1)
				fprintf(stderr, "error writing binary\n");
			fclose(file);
		}
		MEM_FREE(source);
	}
}

static void opencl_build_from_binary(int sequential_id)
{
	cl_int build_code;
	const char *srcptr[] = { kernel_source };
	assert(kernel_loaded);
	program[sequential_id] = clCreateProgramWithBinary(
		context[sequential_id], 1, &devices[sequential_id],
		&program_size, (const unsigned char**)srcptr, NULL, &ret_code);
	HANDLE_CLERROR(ret_code,
		       "Error while creating program (using cached binary)");

	build_code = clBuildProgram(program[sequential_id], 0,
				    NULL, NULL, NULL, NULL);

	HANDLE_CLERROR(clGetProgramBuildInfo(program[sequential_id],
					     devices[sequential_id],
		CL_PROGRAM_BUILD_LOG, sizeof(opencl_log), (void *) opencl_log,
		NULL), "Error while getting build info (using cached binary)");

	// Report build errors and warnings
	if (build_code != CL_SUCCESS) {
		// Give us much info about error and exit
		fprintf(stderr, "Binary build log: %s\n", opencl_log);
		fprintf(stderr, "Error %d building kernel using cached binary."
			" DEVICE_INFO=%d\n", build_code,
			device_info[sequential_id]);
		HANDLE_CLERROR (build_code, "clBuildProgram failed.");
	}
	// Nvidia may return a single '\n' that we ignore
	else if (options.verbosity >= LOG_VERB && strlen(opencl_log) > 1)
		fprintf(stderr, "Binary Build log: %s\n", opencl_log);
}

/*
 *   NOTE: Requirements for using this function:
 *
 * - Your kernel (or main kernel) should be crypt_kernel.
 * - Use profilingEvent in your crypt_all() when enqueueing crypt_kernel.
 * - Do not use profilingEvent for transfers or other subkernels.
 * - For split kernels, use firstEvent and lastEvent instead.
 */
void opencl_find_best_workgroup(struct fmt_main *self)
{
	opencl_find_best_workgroup_limit(self, UINT_MAX, gpu_id,
					 crypt_kernel);
}

void opencl_find_best_workgroup_limit(struct fmt_main *self,
				      size_t group_size_limit,
				      int sequential_id, cl_kernel crypt_kernel)
{
	cl_ulong startTime, endTime, kernelExecTimeNs = CL_ULONG_MAX;
	size_t my_work_group, optimal_work_group;
	cl_int ret_code;
	int i, numloops;
	size_t max_group_size, wg_multiple, sumStartTime, sumEndTime;
	cl_event benchEvent[2];
	size_t gws;
	int count, tidx = 0;

	/* Formats supporting vectorizing should have a default max keys per
	   crypt that is a multiple of 2 and of 3 */
	gws = global_work_size ? global_work_size :
		self->params.max_keys_per_crypt / opencl_v_width;

	if (get_device_version(sequential_id) < 110) {
		if (get_device_type(sequential_id) == CL_DEVICE_TYPE_GPU)
			wg_multiple = 32;
		else if (get_platform_vendor_id(get_platform_id(sequential_id))
			 == DEV_INTEL)
			wg_multiple = 8;
		else
			wg_multiple = 1;
	} else {
		wg_multiple = get_kernel_preferred_multiple(sequential_id,
							    crypt_kernel);
	}
	max_group_size = get_kernel_max_lws(sequential_id,
						     crypt_kernel);

	if (max_group_size > group_size_limit)
		// Needed to deal (at least) with cryptsha512-opencl limits.
		max_group_size = group_size_limit;

	// Safety harness
	if (wg_multiple > max_group_size)
		wg_multiple = max_group_size;

	// Command Queue changing:
	// 1) Delete old CQ
	clReleaseCommandQueue(queue[sequential_id]);
	// 2) Create new CQ with profiling enabled
	queue[sequential_id] =
		clCreateCommandQueue(context[sequential_id],
				     devices[sequential_id],
		CL_QUEUE_PROFILING_ENABLE, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating command queue");

	if (options.verbosity > 3)
		fprintf(stderr, "Max local work size %d, ",
			(int) max_group_size);

	self->methods.clear_keys();

	// Set keys - all keys from tests will be benchmarked and some
	// will be permuted to force them unique
	for (i = 0; i < self->params.max_keys_per_crypt; i++) {
		union {
			char c[PLAINTEXT_BUFFER_SIZE];
			unsigned int w;
		} uniq;
		int len;
		if (self->params.tests[tidx].plaintext == NULL)
			tidx = 0;
		len = strlen(self->params.tests[tidx].plaintext);
		strncpy(uniq.c, self->params.tests[tidx++].plaintext,
		    sizeof(uniq.c));
		uniq.w ^= i;
		uniq.c[len] = 0; // Do not change length
		self->methods.set_key(uniq.c, i);
	}
	// Set salt
	self->methods.set_salt(self->methods.salt(
				       self->params.tests[0].ciphertext));

	// Warm-up run
	local_work_size = wg_multiple;
	count = self->params.max_keys_per_crypt;
	self->methods.crypt_all(&count, NULL);

	// Activate events
	benchEvent[0] = benchEvent[1] = NULL;
	firstEvent = profilingEvent = &benchEvent[0];
	lastEvent = &benchEvent[1];

	// Some formats need this for "keys_dirty"
	self->methods.set_key(self->params.tests[0].plaintext,
			      self->params.max_keys_per_crypt - 1);

	// Timing run
	self->methods.crypt_all(&count, NULL);

	if (*lastEvent == NULL)
		lastEvent = firstEvent;

	HANDLE_CLERROR(clFinish(queue[sequential_id]), "clFinish error");
	HANDLE_CLERROR(clGetEventProfilingInfo(*firstEvent,
					       CL_PROFILING_COMMAND_SUBMIT,
					       sizeof(cl_ulong),
					       &startTime, NULL),
		       "Failed to get profiling info");
	HANDLE_CLERROR(clGetEventProfilingInfo(*lastEvent,
					       CL_PROFILING_COMMAND_END,
					       sizeof(cl_ulong), &endTime,
					       NULL),
		       "Failed to get profiling info");
	numloops = (int)(size_t)(500000000ULL / (endTime-startTime));

	if (numloops < 1)
		numloops = 1;
	else if (numloops > 10)
		numloops = 10;
	//fprintf(stderr, "%zu, %zu, time: %zu, loops: %d\n", endTime,
	//	startTime, (endTime-startTime), numloops);

	// Find minimum time
	for (optimal_work_group = my_work_group = wg_multiple;
		(int) my_work_group <= (int) max_group_size;
		my_work_group += wg_multiple) {

		if (gws % my_work_group != 0)
			continue;

		sumStartTime = 0;
		sumEndTime = 0;

		for (i = 0; i < numloops; i++) {
			advance_cursor();
			local_work_size = my_work_group;

			clReleaseEvent(benchEvent[0]);

			if (*lastEvent != *firstEvent)
				clReleaseEvent(benchEvent[1]);

			// Some formats need this for "keys_dirty"
			self->methods.set_key(
				self->params.tests[0].plaintext,
				self->params.max_keys_per_crypt - 1);

			if (self->methods.crypt_all(&count, NULL) < 0) {
				startTime = endTime = 0;
#ifdef DEBUG
				fprintf(stderr, " Error occured\n");
#endif
				break;
			}

			HANDLE_CLERROR(clFinish(queue[sequential_id]),
				       "clFinish error");
			HANDLE_CLERROR(clGetEventProfilingInfo(*firstEvent,
					   CL_PROFILING_COMMAND_SUBMIT,
					   sizeof(cl_ulong), &startTime, NULL),
				       "Failed to get profiling info");
			HANDLE_CLERROR(clGetEventProfilingInfo(*lastEvent,
					   CL_PROFILING_COMMAND_END,
					   sizeof(cl_ulong), &endTime, NULL),
				       "Failed to get profiling info");
			//fprintf(stderr, "%zu, %zu, time: %zu\n", endTime,
			//	startTime, (endTime-startTime));
			sumStartTime += startTime;
			sumEndTime += endTime;
		}
		if (!endTime)
			break;
		if ((sumEndTime - sumStartTime) < kernelExecTimeNs) {
			kernelExecTimeNs = sumEndTime - sumStartTime;
			optimal_work_group = my_work_group;
		}
		//fprintf(stderr, "LWS %d time=%llu ns\n",(int) my_work_group,
		//	(unsigned long long)sumEndTime-sumStartTime);
	}
	// Release profiling queue and create new with profiling disabled
	clReleaseCommandQueue(queue[sequential_id]);
	queue[sequential_id] =
		clCreateCommandQueue(context[sequential_id],
				     devices[sequential_id], 0, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating command queue");
	local_work_size = optimal_work_group;

	//fprintf(stderr, "Optimal local work size = %d\n",
	//	(int)local_work_size);
	// Release events
	clReleaseEvent(benchEvent[0]);
	if (benchEvent[1])
		clReleaseEvent(benchEvent[1]);

	// These ensure we don't get events from crypt_all() in real use
	profilingEvent = firstEvent = lastEvent = NULL;
}

// Do the proper test using different global work sizes.
static void clear_profiling_events()
{
	int i;

	// Release events
	for (i = 0; i < MAX_EVENTS; i++) {
		if (multi_profilingEvent[i] && *multi_profilingEvent[i])
			HANDLE_CLERROR(clReleaseEvent(*multi_profilingEvent[i]),
				       "Failed in clReleaseEvent");

		if (multi_profilingEvent[i])
			*multi_profilingEvent[i] = NULL;
		multi_profilingEvent[i] = NULL;
	}
}

// Do the proper test using different global work sizes.
static cl_ulong gws_test(size_t gws, unsigned int rounds, int sequential_id)
{
	cl_ulong startTime, endTime, runtime = 0, looptime = 0;
	int i, count, tidx = 0, total = 0;
	size_t kpc = gws * opencl_v_width;
	cl_event benchEvent[MAX_EVENTS];
	int number_of_events = 0;

	for (i = 0; i < MAX_EVENTS; i++)
		benchEvent[i] = NULL;

	// Prepare buffers.
	create_clobj(gws, self);

	self->methods.clear_keys();

	// Set keys - all keys from tests will be benchmarked and some
	// will be permuted to force them unique
	for (i = 0; i < kpc; i++) {
		union {
			char c[PLAINTEXT_BUFFER_SIZE];
			unsigned int w;
		} uniq;
		int len;
		if (self->params.tests[tidx].plaintext == NULL)
			tidx = 0;
		len = strlen(self->params.tests[tidx].plaintext);
		strncpy(uniq.c, self->params.tests[tidx++].plaintext,
		    sizeof(uniq.c));
		uniq.w ^= i;
		uniq.c[len] = 0; // Do not change length
		self->methods.set_key(uniq.c, i);
	}
	// Set salt
	self->methods.set_salt(
		self->methods.salt(self->params.tests[0].ciphertext));

	// Activate events. Then clear them later.
	for (i = 0; i < MAX_EVENTS; i++)
		multi_profilingEvent[i] = &benchEvent[i];

	// Timing run
	count = kpc;
	if (self->methods.crypt_all(&count, NULL) < 0) {
		runtime = looptime = 0;

		if (options.verbosity > 3)
			fprintf(stderr, " (error occured)");
		clear_profiling_events();
		release_clobj();
		return 0;
	}

	for (i = 0; (*multi_profilingEvent[i]); i++)
		number_of_events++;

	//** Get execution time **//
	for (i = 0; i < number_of_events; i++) {
		char mult[32] = "";

		HANDLE_CLERROR(
			clGetEventProfilingInfo(*multi_profilingEvent[i],
						CL_PROFILING_COMMAND_START,
						sizeof (cl_ulong), &startTime,
						NULL),
			"Failed in clGetEventProfilingInfo I");
		HANDLE_CLERROR(
			clGetEventProfilingInfo(*multi_profilingEvent[i],
						CL_PROFILING_COMMAND_END,
						sizeof (cl_ulong), &endTime,
						NULL),
			"Failed in clGetEventProfilingInfo II");

		if ((split_events) && (i == split_events[0] ||
				       i == split_events[1] ||
				       i == split_events[2])) {
			looptime += (endTime - startTime);
			total++;

			if (i == split_events[0])
				sprintf(mult, "%dx", rounds / hash_loops);
		} else
			runtime += (endTime - startTime);

		if (options.verbosity > 4)
			fprintf(stderr, "%s%s%.2fms", warnings[i], mult,
				(double)(endTime - startTime) / 1000000.);

		/* 200 ms duration limit for GCN to avoid ASIC hangs */
		if (amd_gcn(device_info[sequential_id]) &&
		    (endTime - startTime) > 200000000) {
			runtime = looptime = 0;

			if (options.verbosity > 4)
				fprintf(stderr, " (exceeds 200 ms)");
			break;
		}
	}
	if (options.verbosity > 4)
		fprintf(stderr, "\n");

	if (split_events)
		runtime += ((looptime / total) * (rounds / hash_loops));

	clear_profiling_events();
	release_clobj();
	return runtime;
}

void opencl_init_auto_setup(
	int p_default_value, int p_hash_loops,
	int *p_split_events, const char **p_warnings,
	int p_main_opencl_event, struct fmt_main *p_self,
	void (*p_create_clobj)(size_t gws, struct fmt_main *self),
	void (*p_release_clobj)(void), int p_buffer_size, size_t p_gws_limit)
{
	// Initialize events
	clear_profiling_events();

	// Get parameters
	buffer_size = p_buffer_size;
	default_value = p_default_value;
	hash_loops = p_hash_loops;
	split_events = p_split_events;
	warnings = p_warnings;
	main_opencl_event = p_main_opencl_event;
	self = p_self;
	create_clobj = p_create_clobj;
	release_clobj = p_release_clobj;
	gws_limit = p_gws_limit;
}

/*
 * Since opencl_find_best_gws() needs more event control (even more events) to
 * work properly, opencl_find_best_workgroup() cannot be used by formats that
 * are using it.  Therefore, despite the fact that opencl_find_best_lws() does
 * almost the same that opencl_find_best_workgroup() can do, it also handles
 * the necessary event(s) and can do a proper crypt_all() execution analysis
 * when shared GWS detection is used.
 */
void opencl_find_best_lws(
	size_t group_size_limit, int sequential_id, cl_kernel crypt_kernel)
{
	size_t gws;
	cl_int ret_code;
	int i, j, numloops, count, tidx = 0;
	size_t my_work_group, optimal_work_group;
	size_t max_group_size, wg_multiple, sumStartTime, sumEndTime;
	cl_ulong startTime, endTime, kernelExecTimeNs = CL_ULONG_MAX;
	char config_string[128];
	cl_event benchEvent[MAX_EVENTS];

	for (i = 0; i < MAX_EVENTS; i++)
		benchEvent[i] = NULL;

	if (options.verbosity > 3)
		fprintf(stderr, "Max local worksize %zd, ", group_size_limit);

	/* Formats supporting vectorizing should have a default max keys per
	   crypt that is a multiple of 2 and of 3 */
	gws = global_work_size ? global_work_size :
		self->params.max_keys_per_crypt / opencl_v_width;

	if (get_device_version(sequential_id) < 110) {
		if (get_device_type(sequential_id) == CL_DEVICE_TYPE_GPU)
			wg_multiple = 32;
		else if (get_platform_vendor_id(get_platform_id(sequential_id))
			 == DEV_INTEL)
			wg_multiple = 8;
		else
			wg_multiple = 1;
	} else
		wg_multiple = get_kernel_preferred_multiple(sequential_id,
							    crypt_kernel);

	max_group_size = get_kernel_max_lws(sequential_id,
						     crypt_kernel);

	if (max_group_size > group_size_limit)
		// Needed to deal (at least) with cryptsha512-opencl limits.
		max_group_size = group_size_limit;

	// Safety harness
	if (wg_multiple > max_group_size)
		wg_multiple = max_group_size;

	// Change command queue to be used by crypt_all (profile needed)
	clReleaseCommandQueue(queue[sequential_id]);

	// Create a new queue with profiling enabled
	queue[sequential_id] =
		clCreateCommandQueue(context[sequential_id],
				     devices[sequential_id],
		CL_QUEUE_PROFILING_ENABLE, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating command queue");

	self->methods.clear_keys();

	// Set keys - all keys from tests will be benchmarked and some
	// will be permuted to force them unique
	for (i = 0; i < self->params.max_keys_per_crypt; i++) {
		union {
			char c[PLAINTEXT_BUFFER_SIZE];
			unsigned int w;
		} uniq;
		int len;
		if (self->params.tests[tidx].plaintext == NULL)
			tidx = 0;
		len = strlen(self->params.tests[tidx].plaintext);
		strncpy(uniq.c, self->params.tests[tidx++].plaintext,
		    sizeof(uniq.c));
		uniq.w ^= i;
		uniq.c[len] = 0; // Do not change length
		self->methods.set_key(uniq.c, i);
	}
	// Set salt
	self->methods.set_salt(
		self->methods.salt(self->params.tests[0].ciphertext));

	// Warm-up run
	local_work_size = wg_multiple;
	count = global_work_size * opencl_v_width;
	self->methods.crypt_all(&count, NULL);

	// Activate events. Then clear them later.
	for (i = 0; i < MAX_EVENTS; i++)
		multi_profilingEvent[i] = &benchEvent[i];

	// Timing run
	self->methods.crypt_all(&count, NULL);

	HANDLE_CLERROR(clFinish(queue[sequential_id]), "clFinish error");
	HANDLE_CLERROR(clGetEventProfilingInfo(benchEvent[main_opencl_event],
					       CL_PROFILING_COMMAND_START,
					       sizeof(cl_ulong),
					       &startTime, NULL),
		       "Failed to get profiling info");
	HANDLE_CLERROR(clGetEventProfilingInfo(benchEvent[main_opencl_event],
					       CL_PROFILING_COMMAND_END,
					       sizeof(cl_ulong), &endTime,
					       NULL),
		       "Failed to get profiling info");
	numloops = (int)(size_t)(200000000ULL / (endTime-startTime));

	clear_profiling_events();

	if (numloops < 1)
		numloops = 1;
	else if (numloops > 5)
		numloops = 5;

	// Find minimum time
	for (optimal_work_group = my_work_group = wg_multiple;
		(int) my_work_group <= (int) max_group_size;
		my_work_group += wg_multiple) {

		if (gws % my_work_group != 0)
			continue;

		sumStartTime = 0;
		sumEndTime = 0;

		for (i = 0; i < numloops; i++) {
			advance_cursor();
			local_work_size = my_work_group;

			// Activate events. Then clear them later.
			for (j = 0; j < MAX_EVENTS; j++)
				multi_profilingEvent[j] = &benchEvent[j];

			if (self->methods.crypt_all(&count, NULL) < 0) {
				startTime = endTime = 0;

				if (options.verbosity > 3)
					fprintf(stderr, " Error occured\n");
				break;
			}

			HANDLE_CLERROR(clFinish(queue[sequential_id]),
				       "clFinish error");
			HANDLE_CLERROR(clGetEventProfilingInfo(benchEvent[main_opencl_event],
					   CL_PROFILING_COMMAND_START,
					   sizeof(cl_ulong), &startTime, NULL),
				       "Failed to get profiling info");
			HANDLE_CLERROR(clGetEventProfilingInfo(benchEvent[main_opencl_event],
					   CL_PROFILING_COMMAND_END,
					   sizeof(cl_ulong), &endTime, NULL),
				       "Failed to get profiling info");

			sumStartTime += startTime;
			sumEndTime += endTime;

			clear_profiling_events();
		}
		if (!endTime)
			break;
		if ((sumEndTime - sumStartTime) < kernelExecTimeNs) {
			kernelExecTimeNs = sumEndTime - sumStartTime;
			optimal_work_group = my_work_group;
		}
	}
	// Release profiling queue and create new with profiling disabled
	HANDLE_CLERROR(clReleaseCommandQueue(queue[sequential_id]),
		       "Failed in clReleaseCommandQueue");
	queue[sequential_id] =
		clCreateCommandQueue(context[sequential_id],
				     devices[sequential_id], 0, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating command queue");
	local_work_size = optimal_work_group;

	config_string[0] = '\0';
	strcat(config_string, config_name);
	strcat(config_string, LWS_CONFIG_NAME);

	if (options.verbosity > 3) {
		fprintf(stderr, "Optimal local worksize %zd\n",
			local_work_size);
		fprintf(stderr, "(to avoid this test on next run, put \""
			"%s = %zd\" in john.local.conf, section [Local:" SECTION_OPTIONS
			SUBSECTION_OPENCL "])\n", config_string,
			local_work_size);
	}
}

void opencl_find_best_gws(int step, unsigned long long int max_run_time,
			  int sequential_id, unsigned int rounds)
{
	size_t num = 0;
	int optimal_gws = local_work_size;
	unsigned int speed, best_speed = 0;
	cl_ulong run_time, min_time = CL_ULONG_MAX;
	char config_string[128];

	if (duration_time)
		max_run_time = duration_time;

	if (options.verbosity > 3)
		fprintf(stderr, "Calculating best global worksize (GWS); "
			"max. %2.1f s duration.\n",
			(float) max_run_time / 1000000000.);

	if (options.verbosity > 4)
		fprintf(stderr, "Raw speed figures including buffer "
			"transfers:\n");

	// Change command queue to be used by crypt_all (profile needed)
	clReleaseCommandQueue(queue[sequential_id]); // Delete old queue

	// Create a new queue with profiling enabled
	queue[sequential_id] =
		clCreateCommandQueue(context[sequential_id],
				     devices[sequential_id],
				     CL_QUEUE_PROFILING_ENABLE, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating command queue");

	for (num = common_get_next_gws_size(num, step, 1, default_value);;
	     num = common_get_next_gws_size(num, step, 0, default_value)) {
		int kpc = num * opencl_v_width;

		// Check if hardware can handle the size we are going
		// to try now.
		if ((gws_limit && (num > gws_limit)) || ((gws_limit == 0) &&
		    (buffer_size * kpc * 1.1 >
		     get_max_mem_alloc_size(gpu_id)))) {
			if (options.verbosity > 4)
				fprintf(stderr, "Hardware resources "
					"exhausted\n");
			break;
		}

		if (!(run_time = gws_test(num, rounds, sequential_id)))
			break;

		if (options.verbosity < 4)
			advance_cursor();

		speed = rounds * kpc / (run_time / 1000000000.);

		if (run_time < min_time)
			min_time = run_time;

		if (options.verbosity > 3) {
			if (rounds > 1)
				fprintf(stderr, "gws: %9zu\t%10llu c/s%12u "
					"rounds/s%8.3f sec per crypt_all()",
					num, (long long)(kpc / (run_time /
								1000000000.)),
					speed, (float)run_time / 1000000000.);
			else
				fprintf(stderr, "gws: %9zu\t%10llu c/s %8.3f "
					"ms per crypt_all()",
					num, (long long) (kpc / (run_time /
								 1000000000.)),
					(float)run_time / 1000000.);
		}

		if (run_time > max_run_time) {
			if (!optimal_gws)
				optimal_gws = num;

			if (options.verbosity > 3)
				fprintf(stderr, " - too slow\n");
			break;
		}

		if (speed > (1.01 * best_speed)) {
			if (options.verbosity > 3)
				fprintf(stderr, "+");
			best_speed = speed;
			optimal_gws = num;
		}
		if (options.verbosity > 3)
			fprintf(stderr, "\n");
	}
	// Release profiling queue and create new with profiling disabled
	HANDLE_CLERROR(clReleaseCommandQueue(queue[sequential_id]),
		       "Failed in clReleaseCommandQueue");
	queue[sequential_id] =
		clCreateCommandQueue(context[sequential_id],
				     devices[sequential_id], 0,
				     &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating command queue");
	global_work_size = optimal_gws;

	config_string[0] = '\0';
	strcat(config_string, config_name);
	strcat(config_string, GWS_CONFIG_NAME);

	if (options.verbosity > 3) {
		fprintf(stderr, "Optimal global worksize %zd\n",
			global_work_size);
		fprintf(stderr, "(to avoid this test on next run, put \""
			"%s = %zd\" in john.local.conf, section [Local:" SECTION_OPTIONS
			SUBSECTION_OPENCL "])\n", config_string,
			global_work_size);
	}
}

static void opencl_get_dev_info(int sequential_id)
{
	cl_device_type device;

	device = get_device_type(sequential_id);

	if (device == CL_DEVICE_TYPE_CPU)
		device_info[sequential_id] = DEV_CPU;
	else if (device == CL_DEVICE_TYPE_GPU)
		device_info[sequential_id] = DEV_GPU;
	else if (device == CL_DEVICE_TYPE_ACCELERATOR)
		device_info[sequential_id] = DEV_ACCELERATOR;

	device_info[sequential_id] += get_vendor_id(sequential_id);
	device_info[sequential_id] += get_processor_family(sequential_id);
	device_info[sequential_id] += get_byte_addressable(sequential_id);

#ifdef CL_DEVICE_COMPUTE_CAPABILITY_MAJOR_NV
	{
		unsigned int major = 0, minor = 0;

		get_compute_capability(sequential_id, &major, &minor);

		if (major) {
			device_info[sequential_id] +=
				(major == 2 ? DEV_NV_C2X : 0);
			device_info[sequential_id] +=
				(major == 3 && minor == 0 ? DEV_NV_C30 : 0);
			device_info[sequential_id] +=
				(major == 3 && minor == 5 ? DEV_NV_C35 : 0);
			device_info[sequential_id] +=
				(major == 5 ? DEV_NV_C5X : 0);
		}
	}
#endif
}

static void find_valid_opencl_device(int *dev_id, int *platform_id)
{
	cl_platform_id platform[MAX_PLATFORMS];
	cl_device_id devices[MAX_GPU_DEVICES];
	cl_uint num_platforms, num_devices;
	cl_ulong long_entries;
	int i, d;

	if (clGetPlatformIDs(MAX_PLATFORMS, platform, &num_platforms) !=
	    CL_SUCCESS)
		goto err;

	if (*platform_id == -1)
		*platform_id = 0;
	else
		num_platforms = *platform_id + 1;

	for (i = *platform_id; i < num_platforms; i++) {
		clGetDeviceIDs(platform[i], CL_DEVICE_TYPE_ALL, MAX_GPU_DEVICES,
			       devices, &num_devices);

		if (!num_devices)
			continue;

		for (d = 0; d < num_devices; ++d) {
			clGetDeviceInfo(devices[d], CL_DEVICE_TYPE,
					sizeof(cl_ulong), &long_entries, NULL);

			if (*platform_id == -1 || *dev_id  == -1) {
				*platform_id = i;
				*dev_id = d;
			}
			if (long_entries &
			    (CL_DEVICE_TYPE_GPU | CL_DEVICE_TYPE_ACCELERATOR)) {
				*platform_id = i;
				*dev_id = d;
				return;
			}
		}
	}
err:
	if (*platform_id < 0)
		*platform_id = 0;
	if (*dev_id < 0)
		*dev_id = 0;
	return;
}

void opencl_read_source(char *kernel_filename)
{
	char *kernel_path = path_expand(kernel_filename);
	FILE *fp = fopen(kernel_path, "r");
	size_t source_size, read_size;

	kernel_source_file = kernel_filename;

	if (!fp)
		fp = fopen(kernel_path, "rb");

	if (!fp)
		HANDLE_CLERROR(!CL_SUCCESS, "Source kernel not found!");

	fseek(fp, 0, SEEK_END);
	source_size = ftell(fp);
	fseek(fp, 0, SEEK_SET);
	if (kernel_source)	libc_free(kernel_source);
	kernel_source = NULL;
	kernel_source = libc_calloc(source_size + 1);
	read_size = fread(kernel_source, sizeof(char), source_size, fp);
	if (read_size != source_size)
		fprintf(stderr,
			"Error reading source: expected %zu, got %zu bytes.\n",
			source_size, read_size);
	fclose(fp);
	program_size = source_size;
	kernel_loaded = 1;
}

void opencl_build_kernel_opt(char *kernel_filename, int sequential_id,
			     char *opts)
{
	opencl_read_source(kernel_filename);
	opencl_build(sequential_id, opts, 0, NULL, 1);
}

void opencl_build_kernel(char *kernel_filename, int sequential_id, char *opts,
			 int warn) {
	struct stat source_stat, bin_stat;
	char dev_name[512], bin_name[512];
	char *p;
	uint64_t startTime, runtime;

	kernel_loaded = 0;

	if ((!gpu_amd(device_info[sequential_id]) &&
	     !platform_apple(platform_id)) ||
	    stat(path_expand(kernel_filename), &source_stat))
		opencl_build_kernel_opt(kernel_filename, sequential_id, opts);
	else {
		char pnum[16];

		startTime = (unsigned long) time(NULL);

		// Get device name.
		HANDLE_CLERROR(clGetDeviceInfo(devices[sequential_id],
					       CL_DEVICE_NAME, sizeof(dev_name),
					       dev_name, NULL),
			       "Error querying DEVICE_NAME");

		// Decide the binary name.
		strnzcpy(bin_name, kernel_filename, sizeof(bin_name));
		p = strstr(bin_name, ".cl");
		if (p) *p = 0;
		strcat(bin_name, "_");
		if (opts) {
			strcat(bin_name, opts);
			strcat(bin_name, "_");
		}
		strcat(bin_name, dev_name);
		sprintf(pnum, "_%d", platform_id);
		strcat(bin_name, pnum);
		strcat(bin_name, ".bin");

		// Change spaces to '_'
		while (p && *p) {
			if (isspace((unsigned char)(*p)))
				*p = '_';
			p++;
		}

		// Select the kernel to run.
		if (!stat(path_expand(bin_name), &bin_stat) &&
		    (source_stat.st_mtime < bin_stat.st_mtime)) {
			opencl_read_source(bin_name);
			opencl_build_from_binary(sequential_id);
		} else {
			if (warn && options.verbosity > 2) {
				fprintf(stderr, "Building the kernel, this "
					"could take a while\n");
				fflush(stdout);
			}
			opencl_read_source(kernel_filename);
			opencl_build(sequential_id, opts, 1, bin_name, 1);
		}
		if (warn && options.verbosity > 2) {
			if ((runtime = (unsigned long)(time(NULL) - startTime))
			    > 2UL)
				fprintf(stderr, "Build time: %lu seconds\n",
					(unsigned long)runtime);
			fflush(stdout);
		}
	}
}

int opencl_prepare_dev(int sequential_id)
{
	int err_type = 0;

	opencl_preinit();

	if (sequential_id < 0)
		sequential_id = gpu_id;

	profilingEvent = firstEvent = lastEvent = NULL;
	if (!context[sequential_id])
		start_opencl_device(sequential_id, &err_type);
	dev_init(sequential_id);

	return sequential_id;
}

void opencl_init(char *kernel_filename, int sequential_id, char *opts)
{
	kernel_loaded = 0;
	sequential_id = opencl_prepare_dev(sequential_id);
	opencl_build_kernel(kernel_filename, sequential_id, opts, 0);
}

cl_device_type get_device_type(int sequential_id)
{
	cl_device_type type;

	HANDLE_CLERROR(clGetDeviceInfo(devices[sequential_id], CL_DEVICE_TYPE,
				       sizeof(cl_device_type), &type, NULL),
		       "Error querying CL_DEVICE_TYPE");

	return type;
}

cl_ulong get_local_memory_size(int sequential_id)
{
	cl_ulong size;

	HANDLE_CLERROR(clGetDeviceInfo(devices[sequential_id],
				       CL_DEVICE_LOCAL_MEM_SIZE,
				       sizeof(cl_ulong), &size, NULL),
		       "Error querying CL_DEVICE_LOCAL_MEM_SIZE");

	return size;
}

cl_ulong get_global_memory_size(int sequential_id)
{
	cl_ulong size;
	HANDLE_CLERROR(clGetDeviceInfo(devices[sequential_id],
				       CL_DEVICE_GLOBAL_MEM_SIZE,
				       sizeof(cl_ulong), &size, NULL),
		       "Error querying CL_DEVICE_GLOBAL_MEM_SIZE");

	return size;
}

size_t get_device_max_lws(int sequential_id)
{
	size_t max_group_size;

	HANDLE_CLERROR(clGetDeviceInfo(devices[sequential_id],
				       CL_DEVICE_MAX_WORK_GROUP_SIZE,
				       sizeof(max_group_size),
				       &max_group_size, NULL),
		       "Error querying CL_DEVICE_MAX_WORK_GROUP_SIZE");

	return max_group_size;
}

cl_ulong get_max_mem_alloc_size(int sequential_id)
{
	cl_ulong max_alloc_size;

	HANDLE_CLERROR(clGetDeviceInfo(devices[sequential_id],
				       CL_DEVICE_MAX_MEM_ALLOC_SIZE,
				       sizeof(max_alloc_size),
				       &max_alloc_size, NULL),
		       "Error querying CL_DEVICE_MAX_MEM_ALLOC_SIZE");

	return max_alloc_size;
}

size_t get_kernel_max_lws(int sequential_id, cl_kernel crypt_kernel)
{
	size_t max_group_size;

	HANDLE_CLERROR(clGetKernelWorkGroupInfo(crypt_kernel,
						devices[sequential_id],
						CL_KERNEL_WORK_GROUP_SIZE,
						sizeof(max_group_size),
						&max_group_size, NULL),
		       "Error querying clGetKernelWorkGroupInfo");

	return max_group_size;
}

cl_uint get_max_compute_units(int sequential_id)
{
	cl_uint size;
	HANDLE_CLERROR(clGetDeviceInfo(devices[sequential_id],
				       CL_DEVICE_MAX_COMPUTE_UNITS,
				       sizeof(cl_uint), &size, NULL),
		       "Error querying CL_DEVICE_MAX_COMPUTE_UNITS");

	return size;
}

size_t get_kernel_preferred_multiple(int sequential_id, cl_kernel crypt_kernel)
{
	size_t size;

	HANDLE_CLERROR(clGetKernelWorkGroupInfo(crypt_kernel,
		devices[sequential_id],
		CL_KERNEL_PREFERRED_WORK_GROUP_SIZE_MULTIPLE,
		sizeof(size), &size, NULL),
	    "Error while getting CL_KERNEL_PREFERRED_WORK_GROUP_SIZE_MULTIPLE");

	return size;
}

#ifdef CL_DEVICE_COMPUTE_CAPABILITY_MAJOR_NV
void get_compute_capability(int sequential_id, unsigned int *major,
        unsigned int *minor)
{
        clGetDeviceInfo(devices[sequential_id],
                             CL_DEVICE_COMPUTE_CAPABILITY_MAJOR_NV,
                             sizeof(cl_uint), major, NULL);
        clGetDeviceInfo(devices[sequential_id],
                             CL_DEVICE_COMPUTE_CAPABILITY_MINOR_NV,
                             sizeof(cl_uint), minor, NULL);
}
#endif

cl_uint get_processors_count(int sequential_id)
{
	cl_uint core_count = get_max_compute_units(sequential_id);
	char dname[MAX_OCLINFO_STRING_LEN];

	HANDLE_CLERROR(clGetDeviceInfo(devices[sequential_id],
				       CL_DEVICE_NAME,
				       sizeof(dname), dname, NULL),
		       "Error querying CL_DEVICE_NAME");

	ocl_device_list[sequential_id].cores_per_MP = 0;

	if (gpu_nvidia(device_info[sequential_id])) {
#ifdef CL_DEVICE_COMPUTE_CAPABILITY_MAJOR_NV
		unsigned int major = 0, minor = 0;

		get_compute_capability(sequential_id, &major, &minor);
		if (major == 1)
			core_count *= (ocl_device_list[sequential_id].cores_per_MP = 8);
		else if (major == 2 && minor == 0)
			core_count *= (ocl_device_list[sequential_id].cores_per_MP = 32);	// 2.0
		else if (major == 2 && minor >= 1)
			core_count *= (ocl_device_list[sequential_id].cores_per_MP = 48);	// 2.1
		else if (major == 3)
			core_count *= (ocl_device_list[sequential_id].cores_per_MP = 192);	// 3.0
#else
		/* Apple does not expose get_compute_capability() so we need
		   to find out using mory hacky approaches. This needs more
		   much more clauses to be correct but it's a MESS:
		   http://en.wikipedia.org/wiki/Comparison_of_Nvidia_graphics_processing_units

		   Note that --list=cuda-devices will show the right figure
		   even under OSX. */

		// Kepler
		if (strstr(dname, "GT 65") || strstr(dname, "GTX 65") ||
			strstr(dname, "GT 66") || strstr(dname, "GTX 66") ||
			strstr(dname, "GT 67") || strstr(dname, "GTX 67") ||
			strstr(dname, "GT 68") || strstr(dname, "GTX 68") ||
			strstr(dname, "GT 69") || strstr(dname, "GTX 69"))
			core_count *= (ocl_device_list[sequential_id].cores_per_MP = 192);
#endif
	} else if (gpu_amd(device_info[sequential_id])) {
			// 16 thread proc * 5 SP
			core_count *= (ocl_device_list[sequential_id].cores_per_MP = (16 *
			((amd_gcn(device_info[sequential_id]) ||
			amd_vliw4(device_info[sequential_id])) ? 4 : 5)));
	} else if (!strncmp(dname, "HD Graphics", 11)) {
			core_count *= (ocl_device_list[sequential_id].cores_per_MP = 1);
	} else if (!strncmp(dname, "Iris", 4)) {
			core_count *= (ocl_device_list[sequential_id].cores_per_MP = 1);
	} else if (gpu(device_info[sequential_id]))
			// Any other GPU, if we don't know we wont guess
			core_count *= (ocl_device_list[sequential_id].cores_per_MP = 0);

	return core_count;
}

cl_uint get_processor_family(int sequential_id)
{
	char dname[MAX_OCLINFO_STRING_LEN];

	HANDLE_CLERROR(clGetDeviceInfo(devices[sequential_id], CL_DEVICE_NAME,
		sizeof(dname), dname, NULL), "Error querying CL_DEVICE_NAME");

	if gpu_amd(device_info[sequential_id]) {

		if ((strstr(dname, "Cedar") ||
			strstr(dname, "Redwood") ||
			strstr(dname, "Juniper") ||
			strstr(dname, "Cypress") ||
			strstr(dname, "Hemlock") ||
			strstr(dname, "Caicos") ||
			strstr(dname, "Turks") ||
			strstr(dname, "Barts") ||
			strstr(dname, "Cayman") ||
			strstr(dname, "Antilles") ||
			strstr(dname, "Wrestler") ||
			strstr(dname, "Zacate") ||
			strstr(dname, "WinterPark") ||
			strstr(dname, "BeaverCreek"))) {

			if (strstr(dname, "Cayman") ||
				strstr(dname, "Antilles"))
				return DEV_AMD_VLIW4;
			else
				return DEV_AMD_VLIW5;

		} else
			return DEV_AMD_GCN;
	}
	return DEV_UNKNOWN;
}

int get_byte_addressable(int sequential_id)
{
	char dname[MAX_OCLINFO_STRING_LEN];

	HANDLE_CLERROR(clGetDeviceInfo(devices[sequential_id],
				       CL_DEVICE_EXTENSIONS,
				       sizeof(dname), dname, NULL),
		       "Error querying CL_DEVICE_EXTENSIONS");

	if (strstr(dname, "cl_khr_byte_addressable_store") == NULL)
		return DEV_NO_BYTE_ADDRESSABLE;

	return DEV_UNKNOWN;
}

int get_vendor_id(int sequential_id)
{
	char dname[MAX_OCLINFO_STRING_LEN];

	HANDLE_CLERROR(clGetDeviceInfo(devices[sequential_id], CL_DEVICE_VENDOR,
				       sizeof(dname), dname, NULL),
		       "Error querying CL_DEVICE_VENDOR");

	if (strstr(dname, "NVIDIA") != NULL)
		return DEV_NVIDIA;

	if (strstr(dname, "Intel") != NULL)
		return DEV_INTEL;

	if (strstr(dname, "Advanced Micro") != NULL ||
		strstr(dname, "AMD") != NULL || strstr(dname, "ATI") != NULL)
		return DEV_AMD;

	return DEV_UNKNOWN;
}

int get_platform_vendor_id(int platform_id)
{
	char dname[MAX_OCLINFO_STRING_LEN];
	cl_platform_id platform[MAX_PLATFORMS];
	cl_uint num_platforms;

	HANDLE_CLERROR(
		clGetPlatformIDs(MAX_PLATFORMS, platform,
				 &num_platforms),
		"No OpenCL platform found");

	HANDLE_CLERROR(
		clGetPlatformInfo(platform[platform_id], CL_PLATFORM_NAME,
				  sizeof(dname), dname, NULL),
		"Error querying CL_PLATFORM_NAME");

	if (strstr(dname, "NVIDIA") != NULL)
		return DEV_NVIDIA;

	if (strstr(dname, "Apple") != NULL)
		return PLATFORM_APPLE;

	if (strstr(dname, "Intel") != NULL)
		return DEV_INTEL;

	if (strstr(dname, "Advanced Micro") != NULL ||
		strstr(dname, "AMD") != NULL || strstr(dname, "ATI") != NULL)
		return DEV_AMD;

	return DEV_UNKNOWN;
}

int get_device_version(int sequential_id)
{
	char dname[MAX_OCLINFO_STRING_LEN];

	clGetDeviceInfo(devices[sequential_id], CL_DEVICE_VERSION,
		MAX_OCLINFO_STRING_LEN, dname, NULL);

	if (strstr(dname, "1.0"))
		return 100;
	if (strstr(dname, "1.1"))
		return 110;
	if (strstr(dname, "1.2"))
		return 120;

	return DEV_UNKNOWN;
}

char *get_opencl_header_version()
{
	static char *opencl_versions[] = {
		"1.0","1.1","1.2","1.3","1.4","1.5",
	};
	int version = -1;
	#ifdef CL_VERSION_1_5
	version = 5;
	#elif CL_VERSION_1_4
	version = 4;
	#elif CL_VERSION_1_3
	version = 3;
	#elif CL_VERSION_1_2
	version = 2;
	#elif CL_VERSION_1_1
	version = 1;
	#elif CL_VERSION_1_0
	version = 0;
	#endif
	if (version == -1 || version > 5 ) {
		return "Unknown";
	}
	return opencl_versions[version];
}

char *get_error_name(cl_int cl_error)
{
	static char *err_small[] = {
		"CL_SUCCESS", "CL_DEVICE_NOT_FOUND", "CL_DEVICE_NOT_AVAILABLE",
		"CL_COMPILER_NOT_AVAILABLE",
		"CL_MEM_OBJECT_ALLOCATION_FAILURE", "CL_OUT_OF_RESOURCES",
		"CL_OUT_OF_HOST_MEMORY",
		"CL_PROFILING_INFO_NOT_AVAILABLE", "CL_MEM_COPY_OVERLAP",
		"CL_IMAGE_FORMAT_MISMATCH",
		"CL_IMAGE_FORMAT_NOT_SUPPORTED", "CL_BUILD_PROGRAM_FAILURE",
		"CL_MAP_FAILURE", "CL_MISALIGNED_SUB_BUFFER_OFFSET",
		"CL_EXEC_STATUS_ERROR_FOR_EVENTS_IN_WAIT_LIST",
		"CL_COMPILE_PROGRAM_FAILURE","CL_LINKER_NOT_AVAILABLE",
		"CL_LINK_PROGRAM_FAILURE","CL_DEVICE_PARTITION_FAILED",
		"CL_KERNEL_ARG_INFO_NOT_AVAILABLE"
	};
	static char *err_invalid[] = {
		"CL_INVALID_VALUE", "CL_INVALID_DEVICE_TYPE",
		"CL_INVALID_PLATFORM", "CL_INVALID_DEVICE",
		"CL_INVALID_CONTEXT", "CL_INVALID_QUEUE_PROPERTIES",
		"CL_INVALID_COMMAND_QUEUE", "CL_INVALID_HOST_PTR",
		"CL_INVALID_MEM_OBJECT", "CL_INVALID_IMAGE_FORMAT_DESCRIPTOR",
		"CL_INVALID_IMAGE_SIZE", "CL_INVALID_SAMPLER",
		"CL_INVALID_BINARY", "CL_INVALID_BUILD_OPTIONS",
		"CL_INVALID_PROGRAM", "CL_INVALID_PROGRAM_EXECUTABLE",
		"CL_INVALID_KERNEL_NAME", "CL_INVALID_KERNEL_DEFINITION",
		"CL_INVALID_KERNEL", "CL_INVALID_ARG_INDEX",
		"CL_INVALID_ARG_VALUE", "CL_INVALID_ARG_SIZE",
		"CL_INVALID_KERNEL_ARGS", "CL_INVALID_WORK_DIMENSION",
		"CL_INVALID_WORK_GROUP_SIZE", "CL_INVALID_WORK_ITEM_SIZE",
		"CL_INVALID_GLOBAL_OFFSET", "CL_INVALID_EVENT_WAIT_LIST",
		"CL_INVALID_EVENT", "CL_INVALID_OPERATION",
		"CL_INVALID_GL_OBJECT", "CL_INVALID_BUFFER_SIZE",
		"CL_INVALID_MIP_LEVEL", "CL_INVALID_GLOBAL_WORK_SIZE",
		"CL_INVALID_PROPERTY", "CL_INVALID_IMAGE_DESCRIPTOR",
		"CL_INVALID_COMPILER_OPTIONS","CL_INVALID_LINKER_OPTIONS",
		"CL_INVALID_DEVICE_PARTITION_COUNT"
	};

	if (cl_error <= 0 && cl_error >= -19) {
		return err_small[-cl_error];
	}
	if (cl_error <= -30 && cl_error >= -68) {
		return err_invalid[-cl_error - 30];
	}

	return "UNKNOWN OPENCL ERROR";
}

static char *human_format(size_t size)
{
	char pref[] = { ' ', 'K', 'M', 'G', 'T', 'P', 'E', 'Z', 'Y' };
	int prefid = 0;
	static char ret[32];

	while (size > 1024) {
		size /= 1024;
		prefid++;
	}
	sprintf(ret, "%zd.%zd %cB", size, (size % 1024) / 100, pref[prefid]);
	return ret;
}

/***
 * Despite of whatever the user uses as -dev=N, I will always list devices in
 * their natural order as definded by the OpenCL libraries.
 *
 * In order to be able to know everything about the device and list it obeying
 * its natural sequence (defined by hardware, PCI slots sequence, ...) is better
 * to scan all OpenCL stuff and list only when needed. Otherwise, I might need
 * to reorder first and then list.
 ***/
void opencl_list_devices(void)
{
	char dname[MAX_OCLINFO_STRING_LEN];
	cl_uint entries;
	cl_ulong long_entries;
	int i, j, sequence_nr = 0, err_type = 0, platform_in_use = -1;
	size_t p_size;

	/* Obtain list of platforms available */
	if (! platforms[0].platform) {
		fprintf(stderr, "Error: No OpenCL-capable devices were detected"
			" by the installed OpenCL driver.\n\n");
	}

	for (i = 0; platforms[i].platform; i++) {

		/* Query devices for information */
		for (j = 0; j < platforms[i].num_devices; j++, sequence_nr++) {
			cl_device_local_mem_type memtype;
			cl_bool boolean;
			char *p;
			int ret;
			int fan, temp, util;

			if (!default_gpu_selected &&
			    !get_if_device_is_in_use(sequence_nr))
				/* Nothing to do, skipping */
				continue;

			if (platform_in_use != i) {
				/* Now, dealing with different platform. */
				/* Obtain information about platform */
				clGetPlatformInfo(platforms[i].platform,
				                  CL_PLATFORM_NAME,
					sizeof(dname), dname, NULL);
				printf("Platform #%d name: %s\n", i, dname);
				clGetPlatformInfo(platforms[i].platform,
				                  CL_PLATFORM_VERSION,
					sizeof(dname), dname, NULL);
				printf("Platform version: %s\n", dname);

				clGetPlatformInfo(platforms[i].platform,
				                CL_PLATFORM_EXTENSIONS,
				                sizeof(dname), dname, NULL);
				if (options.verbosity > 3)
					printf("\tPlatform extensions:\t%s\n",
					       dname);

				/* Obtain a list of devices available */
				if (!platforms[i].num_devices)
					printf("%d devices found\n",
					       platforms[i].num_devices);

				platform_in_use = i;
			}
			clGetDeviceInfo(devices[sequence_nr], CL_DEVICE_NAME,
					sizeof(dname), dname, NULL);
			p = dname;
			while (isspace(ARCH_INDEX(*p))) /* Intel quirk */
				p++;
			printf("\tDevice #%d (%d) name:\t%s\n",
			       j, sequence_nr, p);

			// Check if device seems to be working.
			if (!start_opencl_device(sequence_nr, &err_type)) {

				if (err_type == 1)
					printf("\tStatus:\t\t\t%s (%s)\n",
					       "Context creation error",
					       get_error_name(ret_code));
				else
					printf("\tStatus:\t\t\t%s (%s)\n",
					       "Queue creation error",
					       get_error_name(ret_code));
			}
#ifdef CL_DEVICE_BOARD_NAME_AMD
			ret = clGetDeviceInfo(devices[sequence_nr],
					      CL_DEVICE_BOARD_NAME_AMD,
					      sizeof(dname), dname, NULL);
			if (ret == CL_SUCCESS && strlen(dname))
				printf("\tBoard name:\t\t%s\n", dname);
#endif
			clGetDeviceInfo(devices[sequence_nr], CL_DEVICE_VENDOR,
					sizeof(dname), dname, NULL);
			printf("\tDevice vendor:\t\t%s\n", dname);
			clGetDeviceInfo(devices[sequence_nr], CL_DEVICE_TYPE,
					sizeof(cl_ulong), &long_entries, NULL);
			printf("\tDevice type:\t\t");
			if (long_entries & CL_DEVICE_TYPE_CPU)
				printf("CPU ");
			if (long_entries & CL_DEVICE_TYPE_GPU)
				printf("GPU ");
			if (long_entries & CL_DEVICE_TYPE_ACCELERATOR)
				printf("Accelerator ");
			if (long_entries & CL_DEVICE_TYPE_DEFAULT)
				printf("Default ");
			if (long_entries & ~(CL_DEVICE_TYPE_DEFAULT |
					     CL_DEVICE_TYPE_ACCELERATOR |
					     CL_DEVICE_TYPE_GPU
					     | CL_DEVICE_TYPE_CPU))
				printf("Unknown ");
			clGetDeviceInfo(devices[sequence_nr],
					CL_DEVICE_ENDIAN_LITTLE,
					sizeof(cl_bool), &boolean, NULL);
			printf("(%s)\n", boolean == CL_TRUE ? "LE" : "BE");
			clGetDeviceInfo(devices[sequence_nr], CL_DEVICE_VERSION,
					sizeof(dname), dname, NULL);
			printf("\tDevice version:\t\t%s\n", dname);
			clGetDeviceInfo(devices[sequence_nr], CL_DRIVER_VERSION,
					sizeof(dname), dname, NULL);
			printf("\tDriver version:\t\t%s\n", dname);

			clGetDeviceInfo(devices[sequence_nr],
					CL_DEVICE_NATIVE_VECTOR_WIDTH_CHAR,
					sizeof(cl_uint), &entries, NULL);
			printf("\tNative vector widths:\tchar %d, ",
			       entries);
			clGetDeviceInfo(devices[sequence_nr],
					CL_DEVICE_NATIVE_VECTOR_WIDTH_SHORT,
					sizeof(cl_uint), &entries, NULL);
			printf("short %d, ", entries);
			clGetDeviceInfo(devices[sequence_nr],
					CL_DEVICE_NATIVE_VECTOR_WIDTH_INT,
					sizeof(cl_uint), &entries, NULL);
			printf("int %d, ", entries);
			clGetDeviceInfo(devices[sequence_nr],
					CL_DEVICE_NATIVE_VECTOR_WIDTH_LONG,
					sizeof(cl_uint), &entries, NULL);
			printf("long %d\n", entries);

			clGetDeviceInfo(devices[sequence_nr],
					CL_DEVICE_PREFERRED_VECTOR_WIDTH_CHAR,
					sizeof(cl_uint), &entries, NULL);
			printf("\tPreferred vector width:\tchar %d, ",
			       entries);
			clGetDeviceInfo(devices[sequence_nr],
					CL_DEVICE_PREFERRED_VECTOR_WIDTH_SHORT,
					sizeof(cl_uint), &entries, NULL);
			printf("short %d, ", entries);
			clGetDeviceInfo(devices[sequence_nr],
					CL_DEVICE_PREFERRED_VECTOR_WIDTH_INT,
					sizeof(cl_uint), &entries, NULL);
			printf("int %d, ", entries);
			clGetDeviceInfo(devices[sequence_nr],
					CL_DEVICE_PREFERRED_VECTOR_WIDTH_LONG,
					sizeof(cl_uint), &entries, NULL);
			printf("long %d\n", entries);

			clGetDeviceInfo(devices[sequence_nr],
					CL_DEVICE_GLOBAL_MEM_SIZE,
					sizeof(cl_ulong), &long_entries, NULL);
			clGetDeviceInfo(devices[sequence_nr],
					CL_DEVICE_ERROR_CORRECTION_SUPPORT,
					sizeof(cl_bool), &boolean, NULL);
			printf("\tGlobal Memory:\t\t%s%s\n",
			       human_format((unsigned long long) long_entries),
			       boolean == CL_TRUE ? " (ECC)" : "");

			clGetDeviceInfo(devices[sequence_nr],
					CL_DEVICE_EXTENSIONS,
					sizeof(dname), dname, NULL);
			if (options.verbosity > 3)
				printf("\tDevice extensions:\t%s\n", dname);

			clGetDeviceInfo(devices[sequence_nr],
					CL_DEVICE_GLOBAL_MEM_CACHE_SIZE,
					sizeof(cl_ulong),
					&long_entries, NULL);
			if (long_entries)
				printf("\tGlobal Memory Cache:\t%s\n",
				       human_format(
					       (unsigned long long)long_entries)
					);
			clGetDeviceInfo(devices[sequence_nr],
					CL_DEVICE_LOCAL_MEM_SIZE,
					sizeof(cl_ulong), &long_entries, NULL);
			clGetDeviceInfo(devices[sequence_nr],
					CL_DEVICE_LOCAL_MEM_TYPE,
					sizeof(cl_device_local_mem_type),
					&memtype, NULL);
			printf("\tLocal Memory:\t\t%s (%s)\n",
			       human_format((unsigned long long) long_entries),
			       memtype == CL_LOCAL ? "Local" : "Global");
			clGetDeviceInfo(devices[sequence_nr],
					CL_DEVICE_MAX_MEM_ALLOC_SIZE,
					sizeof(long_entries), &long_entries,
					NULL);
			printf("\tMax memory alloc. size:\t%s\n",
			       human_format(long_entries));
			ret = clGetDeviceInfo(devices[sequence_nr],
					      CL_DEVICE_MAX_CLOCK_FREQUENCY,
					      sizeof(cl_ulong),
					      &long_entries, NULL);
			if (ret == CL_SUCCESS && long_entries)
				printf("\tMax clock (MHz):\t%llu\n",
				       (unsigned long long) long_entries);
			ret = clGetDeviceInfo(devices[sequence_nr],
					      CL_DEVICE_PROFILING_TIMER_RESOLUTION,
					      sizeof(cl_ulong),
					      &long_entries, NULL);
			if (ret == CL_SUCCESS && long_entries)
				printf("\tProfiling timer res.:\t%llu ns\n",
				       (unsigned long long) long_entries);
			clGetDeviceInfo(devices[sequence_nr],
					CL_DEVICE_MAX_WORK_GROUP_SIZE,
					sizeof(size_t),
					&p_size, NULL);
			printf("\tMax Work Group Size:\t%d\n", (int) p_size);
			clGetDeviceInfo(devices[sequence_nr],
					CL_DEVICE_MAX_COMPUTE_UNITS,
					sizeof(cl_uint),
					&entries, NULL);
			printf("\tParallel compute cores:\t%d\n", entries);

			long_entries = get_processors_count(sequence_nr);
			if (ocl_device_list[sequence_nr].cores_per_MP > 1)
				printf("\tStream processors:\t%llu "
				       " (%d x %d)\n",
				       (unsigned long long)long_entries,
				       entries,
				       ocl_device_list[sequence_nr].cores_per_MP);

#ifdef CL_DEVICE_REGISTERS_PER_BLOCK_NV
			ret = clGetDeviceInfo(devices[sequence_nr],
					      CL_DEVICE_WARP_SIZE_NV,
					      sizeof(cl_uint),
					      &long_entries, NULL);
			if (ret == CL_SUCCESS)
				printf("\tWarp size:\t\t%llu\n",
				       (unsigned long long)long_entries);

			ret = clGetDeviceInfo(devices[sequence_nr],
					      CL_DEVICE_REGISTERS_PER_BLOCK_NV,
					      sizeof(cl_uint), &long_entries,
					      NULL);
			if (ret == CL_SUCCESS)
				printf("\tMax. GPRs/work-group:\t%llu\n",
				       (unsigned long long)long_entries);

			if (gpu_nvidia(device_info[sequence_nr])) {
				unsigned int major = 0, minor = 0;

				get_compute_capability(sequence_nr, &major, &minor);
				if (major && minor)
					printf("\tCompute capability:\t%u.%u "
					       "(sm_%u%u)\n",
					       major, minor, major, minor);
			}
			ret = clGetDeviceInfo(devices[sequence_nr],
					      CL_DEVICE_KERNEL_EXEC_TIMEOUT_NV,
					      sizeof(cl_bool), &boolean, NULL);
			if (ret == CL_SUCCESS)
				printf("\tKernel exec. timeout:\t%s\n",
				       boolean ? "yes" : "no");
#endif
			if (ocl_device_list[sequence_nr].pci_info.bus >= 0) {
				printf("\tPCI device topology:\t%s\n",
				       ocl_device_list[sequence_nr].pci_info.busId);
			}
			fan = temp = util = -1;
			if (gpu_nvidia(device_info[sequence_nr])) {
				if (nvml_lib)
				nvidia_get_temp(
					id2nvml(ocl_device_list[sequence_nr].pci_info),
					&temp, &fan, &util);
			} else if (gpu_amd(device_info[sequence_nr])) {
				if (adl_lib)
				amd_get_temp(id2adl(ocl_device_list[sequence_nr].pci_info),
					&temp, &fan, &util);
			}
			if (fan >= 0)
				printf("\tFan speed:\t\t%u%%\n", fan);
			if (temp >= 0)
				printf("\tTemperature:\t\t%u" DEGC "\n", temp);
			if (util >= 0)
				printf("\tUtilization:\t\t%u%%\n", util);
			puts("");
		}
	}
	return;
}

#undef LOG_SIZE
#undef SRC_SIZE
