/*
 * This software was written by Jim Fougeron jfoug AT cox dot net
 * in 2009. No copyright is claimed, and the software is hereby
 * placed in the public domain. In case this attempt to disclaim
 * copyright and place the software in the public domain is deemed
 * null and void, then the software is Copyright � 2009 Jim Fougeron
 * and it is hereby released to the general public under the following
 * terms:
 *
 * This software may be modified, redistributed, and used for any
 * purpose, in source and binary forms, with or without modification.
 *
 * Generic MD5 hashes cracker
 *
 * Preloaded types md5gen(0) to md5gen(100) are 'reserved' types.
 * They are loaded from this file. If someone tryes to build a 'custom'
 * type in their john.ini file using one of those, john will abort
 * the run.
 *
 * Renamed and changed from dynamic* to dynamic*.  We handle MD5 and SHA1
 * at the present time.  More crypt types 'may' be added later.
 *
 */

#include <string.h>

#include "arch.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "config.h"
#include "md5.h"
#include "dynamic.h"

void dynamic_DISPLAY_ALL_FORMATS()
{
	int i;
	for (i = 0; i < 1000; ++i)
	{
		char *sz = dynamic_PRELOAD_SIGNATURE(i);
		char Type[14], *cp;
		if (!sz)
			break;
		strncpy(Type, sz, sizeof(Type));
		Type[13] = 0;
		cp = strchr(Type, ':');
		if (cp) *cp = 0;
		printf ("Format = %s%s  type = %s\n", Type, strlen(Type)<10?" ":"", sz);
	}

	// The config has not been loaded, so we have to load it now, if we want to 'check'
	// and show any user set md5-generic functions.
#if JOHN_SYSTEMWIDE
	cfg_init(CFG_PRIVATE_FULL_NAME, 1);
	cfg_init(CFG_PRIVATE_ALT_NAME, 1);
#endif
	cfg_init(CFG_FULL_NAME, 1);
	cfg_init(CFG_ALT_NAME, 0);

	for (i = 1001; i < 10000; ++i)
	{
		char *sz = dynamic_LOAD_PARSER_SIGNATURE(i);
		if (sz)
			printf ("UserFormat = dynamic_%d  type = %s\n", i, sz);
	}
}

// Only called at load time, so does not have to be overly optimal
int ishexdigit(char c) {
	if (c >= '0' && c <= '9')
		return 1;
	if (c >= 'a' && c <= 'f')
		return 1;
	if (c >= 'A' && c <= 'F')
		return 1;
	return 0;
}
// Only called at load time, so does not have to be overly optimal
char *dynamic_Demangle(char *Line, int *Len)
{
	char *tmp, *cp, *cp2, digits[3];
	if (!Line || !strlen(Line)) {
		if (Len) *Len = 0;
		return str_alloc_copy("");
	}
	tmp = str_alloc_copy(Line);
	cp = tmp;
	cp2 = Line;
	while (*cp2)
	{
		if (*cp2 != '\\')
			*cp++ = *cp2++;
		else
		{
			++cp2;
			if (*cp2 == '\\')
				*cp++ = *cp2++;
			else
			{
				unsigned val;
				if (*cp2 != 'x') {
					*cp++ = '\\';
					continue;
				}
				++cp2;
				if (!cp2[0]) {
					*cp++ = '\\';
					*cp++ = 'x';
					continue;
				}
				digits[0] = *cp2++;
				if (!cp2[0] || !ishexdigit(digits[0])) {
					*cp++ = '\\';
					*cp++ = 'x';
					*cp++ = digits[0];
					continue;
				}
				digits[1] = *cp2++;
				if (!ishexdigit(digits[1])) {
					*cp++ = '\\';
					*cp++ = 'x';
					*cp++ = digits[0];
					*cp++ = digits[1];
					continue;
				}
				digits[2] = 0;
				val = (unsigned)strtol(digits, NULL, 16);
				sprintf(cp, "%c", val);
				++cp;
			}
		}
	}
	*cp = 0;
	if (Len) *Len = cp-tmp;
	return tmp;
}
