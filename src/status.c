/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-2001,2004,2006,2010-2013 by Solar Designer
 *
 * ...with changes in the jumbo patch, by JimF and magnum.
 */

#ifdef __ultrix__
#define __POSIX
#define _POSIX_SOURCE
#endif

#ifdef _SCO_C_DIALECT
#include <limits.h>
#endif
#include <stdio.h>
#include <math.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <time.h>
#if !defined (__MINGW32__) && !defined (_MSC_VER)
#include <sys/times.h>
#endif

#include "times.h"

#if defined(__GNUC__) && defined(__i386__)
#include "arch.h" /* for CPU_REQ */
#endif

#include "misc.h"
#include "math.h"
#include "params.h"
#include "cracker.h"
#include "options.h"
#include "status.h"
#include "bench.h"
#include "config.h"
#include "unicode.h"
#include "signals.h"
#ifdef HAVE_MPI
#include "john-mpi.h"
#endif

struct status_main status;
unsigned int status_restored_time = 0;
static char* timeFmt = NULL;
static char* timeFmt24 = NULL;
static double ETAthreshold = 0.05;
static int showcand;
int (*status_get_progress)(int *) = NULL;

#if CPU_REQ && defined(__GNUC__) && defined(__i386__)
/* ETA reporting would be wrong when cracking some hash types at least on a
 * Pentium 3 without this... */
#define emms() \
	__asm__ __volatile__("emms");
#else
#define emms()
#endif

static clock_t get_time(void)
{
#if defined (__MINGW32__) || defined (_MSC_VER)
	return clock();
#else
	struct tms buf;

	return times(&buf);
#endif
}

void status_init(int (*get_progress)(int *), int start)
{
	char *cfg_threshold;
	if (start) {
		if (!status_restored_time)
			memset(&status, 0, sizeof(status));
		status.start_time = get_time();
	}

	status_get_progress = get_progress;

	if (!(timeFmt = cfg_get_param(SECTION_OPTIONS, NULL, "TimeFormat")))
		timeFmt = "%Y-%m-%d %H:%M";

	if (!(timeFmt24 = cfg_get_param(SECTION_OPTIONS, NULL, "TimeFormat24")))
		timeFmt24 = "%H:%M:%S";

	if ((cfg_threshold = cfg_get_param(SECTION_OPTIONS, NULL, "ETAthreshold")))
		if ((ETAthreshold = atof(cfg_threshold)) < 0.01)
			ETAthreshold = 0.01;

	showcand = cfg_get_bool(SECTION_OPTIONS, NULL, "StatusShowCandidates", 0);

	clk_tck_init();
}

void status_ticks_overflow_safety(void)
{
	unsigned int time;
	clock_t ticks;

	ticks = get_time() - status.start_time;
	if (ticks > ((clock_t)1 << (sizeof(clock_t) * 8 - 2))) {
		time = ticks / clk_tck;
		status_restored_time += time;
		status.start_time += (clock_t)time * clk_tck;
	}
}

void status_update_crypts(int64 *combs, unsigned int crypts)
{
	{
		unsigned int saved_hi = status.combs.hi;
		add64to64(&status.combs, combs);
		if (status.combs.hi < saved_hi)
			status.combs_ehi++;
	}

	{
		unsigned int saved_lo = status.crypts.lo;
		add32to64(&status.crypts, crypts);
		if ((status.crypts.lo ^ saved_lo) & 0xfff00000U)
			status_ticks_overflow_safety();
	}
}

void status_update_cands(unsigned int cands)
{
	unsigned int saved_lo = status.cands.lo;
	add32to64(&status.cands, cands);
	if ((status.cands.lo ^ saved_lo) & 0xfff00000U)
		status_ticks_overflow_safety();
}

static char *status_get_c(char *buffer, int64 *c, unsigned int c_ehi)
{
	int64 current, next, rem;
	char *p;

	if (c_ehi) {
		strcpy(buffer, "OVERFLOW");
		return buffer;
	}

	p = buffer + 31;
	*p = 0;

	current = *c;
	do {
		next = current;
		div64by32(&next, 10);
		rem = next;
		mul64by32(&rem, 10);
		neg64(&rem);
		add64to64(&rem, &current);
		*--p = rem.lo + '0';
		current = next;
	} while (current.lo || current.hi);

	return p;
}

unsigned int status_get_time(void)
{
	return status_restored_time +
		(get_time() - status.start_time) / clk_tck;
}

static char *status_get_cps(char *buffer, int64 *c, unsigned int c_ehi)
{
	int use_ticks;
	clock_t ticks;
	unsigned long time;
	int64 tmp, cps;

	if (!(c->lo | c->hi | c_ehi))
		return "0";

	use_ticks = !(c->hi | c_ehi | status_restored_time);

	ticks = get_time() - status.start_time;
	if (use_ticks)
		time = ticks;
	else
		time = status_restored_time + ticks / clk_tck;
	if (!time) time = 1;

	cps = *c;
	if (c_ehi) {
		cps.lo = cps.hi;
		cps.hi = c_ehi;
	}
	if (use_ticks)
		mul64by32(&cps, clk_tck);
	div64by32(&cps, time);
	if (c_ehi) {
		cps.hi = cps.lo;
		cps.lo = 0;
	}

	if (cps.hi > 232 || (cps.hi == 232 && cps.lo >= 3567587328U))
		sprintf(buffer, "%uG", div64by32lo(&cps, 1000000000));
	else
	if (cps.hi || cps.lo >= 1000000000)
		sprintf(buffer, "%uM", div64by32lo(&cps, 1000000));
	else
	if (cps.lo >= 1000000)
		sprintf(buffer, "%uK", div64by32lo(&cps, 1000));
	else
	if (cps.lo >= 1000)
		sprintf(buffer, "%u", cps.lo);
	else {
		const char *fmt;
		unsigned int div, frac;
		fmt = "%u.%06u"; div = 1000000;
		if (cps.lo >= 100) {
			fmt = "%u.%u"; div = 10;
		} else if (cps.lo >= 10) {
			fmt = "%u.%02u"; div = 100;
		} else if (cps.lo >= 1) {
			fmt = "%u.%03u"; div = 1000;
		}
		tmp = *c;
		if (use_ticks)
			mul64by32(&tmp, clk_tck);
		mul64by32(&tmp, div);
		frac = div64by32lo(&tmp, time);
		if (div == 1000000) {
			if (frac >= 100000) {
				fmt = "%u.%04u"; div = 10000; frac /= 100;
			} else if (frac >= 10000) {
				fmt = "%u.%05u"; div = 100000; frac /= 10;
			}
		}
		frac %= div;
		sprintf(buffer, fmt, cps.lo, frac);
	}

	return buffer;
}

static char *status_get_ETA(char *percent, unsigned int secs_done)
{
	static char s_ETA[128];
	char *cp;
	double sec_left, percent_left;
	time_t t_ETA;
	struct tm *pTm;

	emms();

	/* Compute the ETA for this run.  Assumes even run time for
	   work currently done and work left to do, and that the CPU
	   utilization of work done and work to do will stay same
	   which may not always be valid assumptions */
	cp = percent;
	while (cp && *cp && isspace(((unsigned char)(*cp))))
		++cp;
	if (!cp || *cp == 0 || !isdigit(((unsigned char)(*cp))))
		return "";  /* dont show ETA if no valid percentage. */
	else
	{
		double chk;
		percent_left = atof(percent);
		t_ETA = time(NULL);
		if (percent_left >= 100.0) {
			pTm = localtime(&t_ETA);
			strcpy(s_ETA, " (");
			strftime(&s_ETA[2], sizeof(s_ETA)-3, timeFmt, pTm);
			strcat(s_ETA, ")");
			return s_ETA;
		}
		if (percent_left == 0 || percent_left < ETAthreshold)
			return "";  /* mute ETA if too little progress */
		percent_left /= 100;
		sec_left = secs_done;
		sec_left /= percent_left;
		sec_left -= secs_done;
		/* Note, many localtime() will fault if given a time_t
		   later than Jan 19, 2038 (i.e. 0x7FFFFFFFF). We
		   check for that here, and if so, this run will
		   not end anyway, so simply tell user to not hold
		   her breath */
		chk = sec_left;
		chk += t_ETA;
		if (chk > 0x7FFFF000) { /* slightly less than 'max' 32 bit time_t, for safety */
			strcpy(s_ETA, " (ETA: never)");
			return s_ETA;
		}
		t_ETA += sec_left;
		pTm = localtime(&t_ETA);
		strcpy(s_ETA, " (ETA: ");
		if (sec_left < 24 * 3600)
			strftime(&s_ETA[7], sizeof(s_ETA)-10, timeFmt24, pTm);
		else
			strftime(&s_ETA[7], sizeof(s_ETA)-10, timeFmt, pTm);
		strcat(s_ETA, ")");
	}
	return s_ETA;
}

static void status_print_cracking(char *percent)
{
	unsigned int time = status_get_time();
	char *key1, key2[PLAINTEXT_BUFFER_SIZE];
	UTF8 t1buf[PLAINTEXT_BUFFER_SIZE + 1];
	int64 g = {status.guess_count, 0};
	char s_gps[32], s_pps[32], s_crypts_ps[32], s_combs_ps[32];
	char s1[32], s2[256], s3[72], s4[40];
	char sc[32];

	key1 = NULL;
	key2[0] = 0;
	if (!(options.flags & FLG_STATUS_CHK) &&
	    (status.crypts.lo | status.crypts.hi)) {
		char *key = crk_get_key2();
		if (key)
			strnzcpy(key2, key, sizeof(key2));
		key1 = crk_get_key1();

		if (options.report_utf8 && !options.utf8) {
			UTF8 t2buf[PLAINTEXT_BUFFER_SIZE + 1];
			char *t;
			key1 = (char*)enc_to_utf8_r(key1, t1buf, PLAINTEXT_BUFFER_SIZE);
			t = (char*)enc_to_utf8_r(key2, t2buf, PLAINTEXT_BUFFER_SIZE);
			strnzcpy(key2, t, sizeof(key2));
		}
	}

	s1[0] = s2[0] = s3[0] = s4[0] = 0;
	sc[0] = 0;

#ifndef HAVE_MPI
	if (options.fork)
#else
	if (options.fork || mpi_p > 1)
#endif
		sprintf(s1, "%u ", options.node_min);

	if (showcand)
		sprintf(sc, "/%llu",
		        ((unsigned long long)status.crypts.hi << 32) +
		        status.crypts.lo);

	sprintf(s2,
	    "%ug%s %u:%02u:%02u:%02u%s%s %sg/s ",
	    status.guess_count,
	    sc,
	    time / 86400, time % 86400 / 3600, time % 3600 / 60, time % 60,
		strncmp(percent, " 100", 4) ? percent : " DONE",
		status_get_ETA(percent,time),
	    status_get_cps(s_gps, &g, 0));

	if (!status.compat)
		sprintf(s3,
		    "%sp/s %sc/s ",
		    status_get_cps(s_pps, &status.cands, 0),
		    status_get_cps(s_crypts_ps, &status.crypts, 0));

	sprintf(s4, "%sC/s",
	    status_get_cps(s_combs_ps, &status.combs, status.combs_ehi));

	fprintf(stderr, "%s%s%s%s%s%s%s%s\n", s1, s2, s3, s4,
	    key1 ? " " : "", key1 ? key1 : "", key2[0] ? ".." : "", key2);
}

static void status_print_stdout(char *percent)
{
	unsigned int time = status_get_time();
	char *key;
	char s_pps[32], s_p[32];

	key = NULL;
	if (!(options.flags & FLG_STATUS_CHK) &&
	    (status.crypts.lo | status.crypts.hi))
		key = crk_get_key1();

	fprintf(stderr,
	    "%sp %u:%02u:%02u:%02u%s%s %sp/s%s%s",
	    status_get_c(s_p, &status.cands, 0),
	    time / 86400, time % 86400 / 3600, time % 3600 / 60, time % 60,
		strncmp(percent, " 100", 4) ? percent : " DONE",
		status_get_ETA(percent,time),
	    status_get_cps(s_pps, &status.cands, 0),
	    key ? " " : "", key ? key : "");
}

void status_print(void)
{
	int percent_value, hund_percent = 0;
	char s_percent[32];

	percent_value = -1;
	if (options.flags & FLG_STATUS_CHK)
		percent_value = status.progress;
	else
	if (status_get_progress)
		percent_value = status_get_progress(&hund_percent);

	s_percent[0] = 0;
	if (percent_value >= 0 && hund_percent >= 0)
		sprintf(s_percent, status.pass ? " %d.%02d%% %d/3" : " %d.%02d%%",
		    percent_value, hund_percent, status.pass);
	else
	if (status.pass)
		sprintf(s_percent, " %d/3", status.pass);

	if (options.flags & FLG_STDOUT)
		status_print_stdout(s_percent);
	else
		status_print_cracking(s_percent);
}
