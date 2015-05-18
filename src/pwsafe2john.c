/* pwsafe2john processes input Password Safe files into a format suitable
 * for use with JtR.
 *
 * This software is Copyright (c) 2012, Dhiru Kholia <dhiru.kholia at gmail.com>,
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted.
 *
 * Password Safe file format:
 *
 * 1. http://keybox.rubyforge.org/password-safe-db-format.html
 *
 * 2. formatV3.txt at http://passwordsafe.svn.sourceforge.net/viewvc/passwordsafe/trunk/pwsafe/pwsafe/docs/
 *
 * Output Format: filename:$passwordsaf$*version*salt*iterations*hash */

#include <stdio.h>
#include <stdlib.h>
#if !AC_BUILT || HAVE_LIMITS_H
#include <limits.h>
#endif
#include <errno.h>
#include <string.h>

#include "stdint.h"
#include "jumbo.h"
#include "memdbg.h"

static char *magic = "PWS3";

/* helper functions for byte order conversions, header values are stored
 * in little-endian byte order */
static uint32_t fget32(FILE * fp)
{
	uint32_t v = fgetc(fp);
	v |= fgetc(fp) << 8;
	v |= fgetc(fp) << 16;
	v |= fgetc(fp) << 24;
	return v;
}


static void print_hex(unsigned char *str, int len)
{
	int i;
	for (i = 0; i < len; ++i)
		printf("%02x", str[i]);
}

static void process_file(const char *filename)
{
	FILE *fp;
	int count;
	unsigned char buf[32];
	unsigned int iterations;
	const char *ext[] = {".psafe3"};

	if (!(fp = fopen(filename, "rb"))) {
		fprintf(stderr, "! %s: %s\n", filename, strerror(errno));
		return;
	}
	if (fread(buf, 4, 1, fp) != 1) {
		fprintf(stderr, "Error: read failed.\n");
		return;
	}
	if(memcmp(buf, magic, 4)) {
		fprintf(stderr, "%s : Couldn't find PWS3 magic string. Is this a Password Safe file?\n", filename);
		exit(1);
	}
	if (fread(buf, 32, 1, fp) != 1) {
		fprintf(stderr, "Error: read failed.\n");
		return;
	}
	iterations = fget32(fp);
	printf("%s:$pwsafe$*3*", strip_suffixes(basename(filename), ext, 1));
	print_hex(buf, 32);
	printf("*%d*", iterations);
	if (fread(buf, 32, 1, fp) != 1) {
		fprintf(stderr, "Error: read failed.\n");
		return;
	}
	print_hex(buf,32);
	printf("\n");

	fclose(fp);
}

int pwsafe2john(int argc, char **argv)
{
	int i;

	if (argc < 2) {
		puts("Usage: pwsafe2john [.psafe3 files]");
		return -1;
	}
	for (i = 1; i < argc; i++)
		process_file(argv[i]);

	return 0;
}
