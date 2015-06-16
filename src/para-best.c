/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-99,2003,2006,2011 by Solar Designer
 */

/*
 * Benchmark to detect the best algorithm for a particular architecture.
 *
 * This file made by magnum, based on best.c. No rights reserved.
 */

#ifdef __ultrix__
#define __POSIX
#define _POSIX_SOURCE
#endif

#ifdef _SCO_C_DIALECT
#include <limits.h>
#endif
#include <stdio.h>
#include <time.h>

#include "math.h"
#include "params.h"
#include "common.h"
#include "formats.h"
#include "bench.h"
#include "memdbg.h"

extern struct fmt_main fmt_rawMD4, fmt_rawMD5, fmt_MD5, fmt_rawSHA1;

int john_main_process = 0;
int john_child_count = 0;
int *john_child_pids = NULL;

int main(int argc, char **argv)
{
	struct fmt_main *format;
	struct bench_results results;
	unsigned long virtual;
	int64 tmp;
	char s_real[64], s_virtual[64];

	if (argc != 3) return 1;

	benchmark_time = atoi(argv[2]);

	switch (argv[1][0]) {
	case '2':
		format = &fmt_MD5;
		break;

	case '4':
		format = &fmt_rawMD4;
		break;

	case '5':
		format = &fmt_rawMD5;
		break;

	case '6':
		format = &fmt_rawSHA1;
		break;

	default:
		return 1;
	}

	fprintf(stderr, "Benchmarking: %s%s [%s]... ",
		format->params.format_name,
		format->params.benchmark_comment,
		format->params.algorithm_name);

	common_init();

	if (benchmark_format(format, BENCHMARK_MANY, &results)) {
		virtual = 0;

		fprintf(stderr, "FAILED\n");
	} else {
		tmp = results.crypts;
		mul64by32(&tmp, clk_tck * 10);
#ifdef _OPENMP
		virtual = div64by32lo(&tmp, results.real);
#else
		virtual = div64by32lo(&tmp, results.virtual);
#endif

		benchmark_cps(&results.crypts, results.real, s_real);
		benchmark_cps(&results.crypts, results.virtual, s_virtual);

		fprintf(stderr, "%s c/s real, %s c/s virtual\n",
			s_real, s_virtual);
	}

	printf("%lu\n", virtual);

	return virtual ? 0 : 1;
}
