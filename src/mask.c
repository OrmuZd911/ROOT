/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 2013 by Solar Designer
 * Copyright (c) 2013 by magnum
 * Copyright (c) 2014 by Sayantan Datta
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 */

#include <stdio.h> /* for fprintf(stderr, ...) */
#include <string.h>

#include "misc.h" /* for error() */
#include "logger.h"
#include "recovery.h"
#include "os.h"
#include "signals.h"
#include "status.h"
#include "options.h"
#include "external.h"
#include "cracker.h"
#include "john.h"
#include "mask.h"
#include "unicode.h"
#include "encoding_data.h"
#include "memdbg.h"

static parsed_ctx parsed_mask;
static cpu_mask_context cpu_mask_ctx, rec_ctx;

static double cand;

/*
 * A "sequence number" for distributing the candidate passwords across nodes.
 * It is OK if this number overflows once in a while, as long as this happens
 * in the same way for all nodes (must be same size unsigned integer type).
 */
static unsigned int seq, rec_seq;

#define BUILT_IN_CHARSET "aludshHA1234"

#define store_op(k, i) \
	parsed_mask->stack_op_br[k] = i;

#define store_cl(k, i) \
	parsed_mask->stack_cl_br[k] = i;

#define load_op(i) \
	parsed_mask->stack_op_br[i]

#define load_cl(i) \
	parsed_mask->stack_cl_br[i]

#define load_qtn(i) \
	parsed_mask->stack_qtn[i]

/*
 * valid braces:
 * [abcd], [[[[[abcde], []]abcde]]], [[[ab]cdefr]]
 * invalid braces:
 * [[ab][c], parsed as two separate ranges [[ab] and [c]
 * [[ab][, error, sets parse_ok to 0.
 */
static void parse_braces(char *mask, parsed_ctx *parsed_mask)
{

	int i, j ,k;
	int cl_br_enc;

	for (i = 0; i < MAX_NUM_MASK_PLHDR; i++) {
		store_cl(i, -1);
		store_op(i, -1);
	}

	j = k = 0;
	while (j < strlen(mask)) {

		for (i = j; i < strlen(mask); i++)
			if (mask[i] == '[')
				break;

		if (i < strlen(mask))
		/* store first opening brace for kth placeholder */
			store_op(k, i);

		i++;

		cl_br_enc = 0;
		for (;i < strlen(mask); i++) {
			if (mask[i] == ']') {
			/* store last closing brace for kth placeholder */
				store_cl(k, i);
				cl_br_enc = 1;
			}
			if (mask[i] == '[' && cl_br_enc)
				break;
		}

		j = i;
		k++;
	}

	parsed_mask->parse_ok = 1;
	for (i = 0; i < MAX_NUM_MASK_PLHDR; i++)
		if ((load_op(i) == -1) ^ (load_cl(i) == -1))
			parsed_mask->parse_ok = 0;
}

/*
 * Stores the valid ? placeholders in a stack_qtn
 * valid:
 * -if outside [] braces and
 * -if ? is immediately followed by the identifier such as
 * ?a for all printable ASCII.
 */
static void parse_qtn(char *mask, parsed_ctx *parsed_mask)
{
	int i, j, k;

	for (i = 0; i < MAX_NUM_MASK_PLHDR; i++)
		parsed_mask->stack_qtn[i] = -1;

	for (i = 0, k = 0; i < strlen(mask); i++) {
		if (mask[i] == '?')
			if (i + 1 < strlen(mask))
				if (memchr(BUILT_IN_CHARSET, mask[i + 1],
				    strlen(BUILT_IN_CHARSET))) {
					j = 0;
					while (load_op(j) != -1 &&
					       load_cl(j) != -1) {
						if (i > load_op(j) &&
						    i < load_cl(j))
							goto cont;
						j++;
					}
					parsed_mask->stack_qtn[k++] = i;
				}
		cont:;
	}
}

static int search_stack(parsed_ctx *parsed_mask, int loc)
{
	int t;

	for (t = 0; load_op(t) != -1; t++)
		if (load_op(t) <= loc && load_cl(t) >= loc)
			return load_cl(t);

	for (t = 0; load_qtn(t) != -1; t++)
		if (load_qtn(t) == loc)
			return loc + 1;
	return 0;
}

/*
 * Maps the postion of a range in a mask to its actual postion in a key.
 * Offset for wordlist + mask is not taken into account.
 */
static int calc_pos_in_key(char *mask, parsed_ctx *parsed_mask, int mask_loc)
{
	int i, ret_pos;

	i = ret_pos = 0;
	while (i < mask_loc) {
		int t;
		t = search_stack(parsed_mask, i);
		i = t ? t + 1: i + 1;
		ret_pos++;
	}

	return ret_pos;
}

static void init_cpu_mask(char *mask, parsed_ctx *parsed_mask,
                          cpu_mask_context *cpu_mask_ctx, struct db_main *db)
{
	int i, qtn_ctr, op_ctr, cl_ctr;
	char *p;
	int fmt_case = (db->format->params.flags & FMT_CASE);

#define count(i) cpu_mask_ctx->ranges[i].count
#define swap(a, b) { x = a; a = b; b = x; }
#define fill_range() 							\
	if (a > b)							\
		swap(a, b);						\
	for (x = a; x <= b; x++) 					\
		if (!memchr((const char*)cpu_mask_ctx->ranges[i].chars, \
		    x, count(i)))					\
			cpu_mask_ctx->ranges[i].chars[count(i)++] = x;

/* Safe in non-bracketed if/for: The final ';' comes with this invocation */
#define add_range(a, b)							\
	for (j = a; j <= b; j++)					\
		cpu_mask_ctx->ranges[i].chars[count(i)++] = j

/* Safe in non-bracketed if/for: The final ';' comes with this invocation */
#define add_string(string)						\
	for (p = (char*)string; *p; p++)				\
		cpu_mask_ctx->ranges[i].chars[count(i)++] = *p

#define set_range_start()						\
	for (j = 0; j < cpu_mask_ctx->ranges[i].count; j++)		\
			if (cpu_mask_ctx->ranges[i].chars[0] + j !=	\
			    cpu_mask_ctx->ranges[i].chars[j])		\
				break;					\
	if (j == cpu_mask_ctx->ranges[i].count)				\
		cpu_mask_ctx->ranges[i].start =				\
			cpu_mask_ctx->ranges[i].chars[0];

	for (i = 0; i < MAX_NUM_MASK_PLHDR; i++) {
		cpu_mask_ctx->ranges[i].start =
		cpu_mask_ctx->ranges[i].count =
		cpu_mask_ctx->ranges[i].pos =
		cpu_mask_ctx->ranges[i].iter =
		cpu_mask_ctx->active_positions[i] = 0;
		cpu_mask_ctx->ranges[i].next = MAX_NUM_MASK_PLHDR;
	}
	cpu_mask_ctx->count = cpu_mask_ctx->offset = 0;

	qtn_ctr = op_ctr = cl_ctr = 0;
	for (i = 0; i < MAX_NUM_MASK_PLHDR; i++) {
		if ((unsigned int)load_op(op_ctr) <
		    (unsigned int)load_qtn(qtn_ctr)) {
			int j;

			cpu_mask_ctx->
			ranges[i].pos = calc_pos_in_key(mask,
						        parsed_mask,
				                        load_op(op_ctr));

			for (j = load_op(op_ctr) + 1; j < load_cl(cl_ctr);) {
				int a , b;
				if (mask[j] == '\\' &&
				    j + 8 < load_cl(cl_ctr) &&
				    sscanf(mask + j, "\\x%02x-\\x%02x", &a, &b)
				    == 2) {
					int x;
					fill_range();
					j = j + 8;
				}
				else if (mask[j] == '-' &&
					 j + 1 < load_cl(cl_ctr) &&
					 j - 1 > load_op(op_ctr)) {
					int x;
		/* Remove the character mask[j-1] added in previous iteration */
					count(i)--;

					a = mask[j - 1];
					b = mask[j + 1];

					fill_range();

					j++;
				}
				else if (!memchr((const char*)
				         cpu_mask_ctx->ranges[i].chars,
		                         (int)mask[j], count(i)))
						cpu_mask_ctx->
						ranges[i].
						chars[count(i)++] = mask[j];

				j++;
			}

			set_range_start();

			op_ctr++;
			cl_ctr++;
			cpu_mask_ctx->count++;
		}
		else if ((unsigned int)load_op(op_ctr) >
		         (unsigned int)load_qtn(qtn_ctr))  {
			int j;

			cpu_mask_ctx->
			ranges[i].pos = calc_pos_in_key(mask,
							parsed_mask,
							load_qtn(qtn_ctr));

			switch(mask[load_qtn(qtn_ctr) + 1]) {
			case '1': /* Custom masks */
				add_string(options.custom_mask[0]);
				break;
			case '2': /* Custom masks */
				add_string(options.custom_mask[1]);
				break;
			case '3': /* Custom masks */
				add_string(options.custom_mask[2]);
				break;
			case '4': /* Custom masks */
				add_string(options.custom_mask[3]);
				break;
			case 'a': /* Printable ASCII */
				if (fmt_case)
					add_range(0x20, 0x7e);
				else {
					add_range(0x20, 0x60);
					add_range(0x7b, 0x7e);
				}
				break;
			case 'l': /* lower-case letters */
				add_range('a', 'z');
				switch (pers_opts.internal_enc) {
				case CP437:
					add_string(CHARS_LOWER_CP437
					           CHARS_LOW_ONLY_CP437);
					break;
				case CP737:
					add_string(CHARS_LOWER_CP737
					           CHARS_LOW_ONLY_CP737);
					break;
				case CP850:
					add_string(CHARS_LOWER_CP850
					           CHARS_LOW_ONLY_CP850);
					break;
				case CP852:
					add_string(CHARS_LOWER_CP852
					           CHARS_LOW_ONLY_CP852);
					break;
				case CP858:
					add_string(CHARS_LOWER_CP858
					           CHARS_LOW_ONLY_CP858);
					break;
				case CP866:
					add_string(CHARS_LOWER_CP866
					           CHARS_LOW_ONLY_CP866);
					break;
				case CP1250:
					add_string(CHARS_LOWER_CP1250
					           CHARS_LOW_ONLY_CP1250);
					break;
				case CP1251:
					add_string(CHARS_LOWER_CP1251
					           CHARS_LOW_ONLY_CP1251);
					break;
				case CP1252:
					add_string(CHARS_LOWER_CP1252
					           CHARS_LOW_ONLY_CP1252);
					break;
				case CP1253:
					add_string(CHARS_LOWER_CP1253
					           CHARS_LOW_ONLY_CP1253);
					break;
				case ISO_8859_1:
					add_string(CHARS_LOWER_ISO_8859_1
					           CHARS_LOW_ONLY_ISO_8859_1);
					break;
				case ISO_8859_2:
					add_string(CHARS_LOWER_ISO_8859_2
					           CHARS_LOW_ONLY_ISO_8859_2);
					break;
				case ISO_8859_7:
					add_string(CHARS_LOWER_ISO_8859_7
					           CHARS_LOW_ONLY_ISO_8859_7);
					break;
				case ISO_8859_15:
					add_string(CHARS_LOWER_ISO_8859_15
					           CHARS_LOW_ONLY_ISO_8859_15);
					break;
				case KOI8_R:
					add_string(CHARS_LOWER_KOI8_R
					           CHARS_LOW_ONLY_KOI8_R);
					break;
				}
				break;
			case 'u': /* upper-case letters */
				add_range('A', 'Z');
				switch (pers_opts.internal_enc) {
				case CP437:
					add_string(CHARS_UPPER_CP437
					           CHARS_UP_ONLY_CP437);
					break;
				case CP737:
					add_string(CHARS_UPPER_CP737
					           CHARS_UP_ONLY_CP737);
					break;
				case CP850:
					add_string(CHARS_UPPER_CP850
					           CHARS_UP_ONLY_CP850);
					break;
				case CP852:
					add_string(CHARS_UPPER_CP852
					           CHARS_UP_ONLY_CP852);
					break;
				case CP858:
					add_string(CHARS_UPPER_CP858
					           CHARS_UP_ONLY_CP858);
					break;
				case CP866:
					add_string(CHARS_UPPER_CP866
					           CHARS_UP_ONLY_CP866);
					break;
				case CP1250:
					add_string(CHARS_UPPER_CP1250
					           CHARS_UP_ONLY_CP1250);
					break;
				case CP1251:
					add_string(CHARS_UPPER_CP1251
					           CHARS_UP_ONLY_CP1251);
					break;
				case CP1252:
					add_string(CHARS_UPPER_CP1252
					           CHARS_UP_ONLY_CP1252);
					break;
				case CP1253:
					add_string(CHARS_UPPER_CP1253
					           CHARS_UP_ONLY_CP1253);
					break;
				case ISO_8859_1:
					add_string(CHARS_UPPER_ISO_8859_1
					           CHARS_UP_ONLY_ISO_8859_1);
					break;
				case ISO_8859_2:
					add_string(CHARS_UPPER_ISO_8859_2
					           CHARS_UP_ONLY_ISO_8859_2);
					break;
				case ISO_8859_7:
					add_string(CHARS_UPPER_ISO_8859_7
					           CHARS_UP_ONLY_ISO_8859_7);
					break;
				case ISO_8859_15:
					add_string(CHARS_UPPER_ISO_8859_15
					           CHARS_UP_ONLY_ISO_8859_15);
					break;
				case KOI8_R:
					add_string(CHARS_UPPER_KOI8_R
					           CHARS_UP_ONLY_KOI8_R);
					break;
				}
				break;
			case 'd': /* digits */
				add_range('0', '9');
				switch (pers_opts.internal_enc) {
				case CP437:
					add_string(CHARS_DIGITS_CP437);
					break;
				case CP737:
					add_string(CHARS_DIGITS_CP737);
					break;
				case CP850:
					add_string(CHARS_DIGITS_CP850);
					break;
				case CP852:
					add_string(CHARS_DIGITS_CP852);
					break;
				case CP858:
					add_string(CHARS_DIGITS_CP858);
					break;
				case CP866:
					add_string(CHARS_DIGITS_CP866);
					break;
				case CP1250:
					add_string(CHARS_DIGITS_CP1250);
					break;
				case CP1251:
					add_string(CHARS_DIGITS_CP1251);
					break;
				case CP1252:
					add_string(CHARS_DIGITS_CP1252);
					break;
				case CP1253:
					add_string(CHARS_DIGITS_CP1253);
					break;
				case ISO_8859_1:
					add_string(CHARS_DIGITS_ISO_8859_1);
					break;
				case ISO_8859_2:
					add_string(CHARS_DIGITS_ISO_8859_2);
					break;
				case ISO_8859_7:
					add_string(CHARS_DIGITS_ISO_8859_7);
					break;
				case ISO_8859_15:
					add_string(CHARS_DIGITS_ISO_8859_15);
					break;
				case KOI8_R:
					add_string(CHARS_DIGITS_KOI8_R);
					break;
				}
				break;
			case 's': /* specials */
				add_range(32, 47);
				add_range(58, 64);
				add_range(91, 96);
				add_range(123, 126);
				switch (pers_opts.internal_enc) {
				case CP437:
					add_string(CHARS_PUNCTUATION_CP437
					           CHARS_SPECIALS_CP437
					           CHARS_WHITESPACE_CP437);
					break;
				case CP737:
					add_string(CHARS_PUNCTUATION_CP737
					           CHARS_SPECIALS_CP737
					           CHARS_WHITESPACE_CP737);
					break;
				case CP850:
					add_string(CHARS_PUNCTUATION_CP850
					           CHARS_SPECIALS_CP850
					           CHARS_WHITESPACE_CP850);
					break;
				case CP852:
					add_string(CHARS_PUNCTUATION_CP852
					           CHARS_SPECIALS_CP852
					           CHARS_WHITESPACE_CP852);
					break;
				case CP858:
					add_string(CHARS_PUNCTUATION_CP858
					           CHARS_SPECIALS_CP858
					           CHARS_WHITESPACE_CP858);
					break;
				case CP866:
					add_string(CHARS_PUNCTUATION_CP866
					           CHARS_SPECIALS_CP866
					           CHARS_WHITESPACE_CP866);
					break;
				case CP1250:
					add_string(CHARS_PUNCTUATION_CP1250
					           CHARS_SPECIALS_CP1250
					           CHARS_WHITESPACE_CP1250);
					break;
				case CP1251:
					add_string(CHARS_PUNCTUATION_CP1251
					           CHARS_SPECIALS_CP1251
					           CHARS_WHITESPACE_CP1251);
					break;
				case CP1252:
					add_string(CHARS_PUNCTUATION_CP1252
					           CHARS_SPECIALS_CP1252
					           CHARS_WHITESPACE_CP1252);
					break;
				case CP1253:
					add_string(CHARS_PUNCTUATION_CP1253
					           CHARS_SPECIALS_CP1253
					           CHARS_WHITESPACE_CP1253);
					break;
				case ISO_8859_1:
					add_string(CHARS_PUNCTUATION_ISO_8859_1
					           CHARS_SPECIALS_ISO_8859_1
					           CHARS_WHITESPACE_ISO_8859_1);
					break;
				case ISO_8859_2:
					add_string(CHARS_PUNCTUATION_ISO_8859_2
					           CHARS_SPECIALS_ISO_8859_2
					           CHARS_WHITESPACE_ISO_8859_2);
					break;
				case ISO_8859_7:
					add_string(CHARS_PUNCTUATION_ISO_8859_7
					           CHARS_SPECIALS_ISO_8859_7
					           CHARS_WHITESPACE_ISO_8859_7);
					break;
				case ISO_8859_15:
					add_string(CHARS_PUNCTUATION_ISO_8859_15
					           CHARS_SPECIALS_ISO_8859_15
					           CHARS_WHITESPACE_ISO_8859_15);
					break;
				case KOI8_R:
					add_string(CHARS_PUNCTUATION_KOI8_R
					           CHARS_SPECIALS_KOI8_R
					           CHARS_WHITESPACE_KOI8_R);
					break;
				}
				break;
			case 'h': /* All high-bit */
				add_range(0x80, 0xff);
				break;
			case 'H': /* All, except 0 (which we can't handle) */
				add_range(0x01, 0xff);
				break;
			case 'A': /* All valid chars in codepage */
				if (fmt_case)
					add_range(0x20, 0x7e);
				else {
					add_range(0x20, 0x60);
					add_range(0x7b, 0x7e);
				}
				switch (pers_opts.internal_enc) {
				case CP437:
					if (fmt_case)
						add_string(CHARS_ALPHA_CP437);
					else
						add_string(CHARS_UPPER_CP437);
					add_string(CHARS_DIGITS_CP437
					           CHARS_PUNCTUATION_CP437
					           CHARS_SPECIALS_CP437
					           CHARS_WHITESPACE_CP437);
					break;
				case CP737:
					if (fmt_case)
						add_string(CHARS_ALPHA_CP737);
					else
						add_string(CHARS_UPPER_CP737);
					add_string(CHARS_DIGITS_CP737
					           CHARS_PUNCTUATION_CP737
					           CHARS_SPECIALS_CP737
					           CHARS_WHITESPACE_CP737);
					break;
				case CP850:
					if (fmt_case)
						add_string(CHARS_ALPHA_CP850);
					else
						add_string(CHARS_UPPER_CP850);
					add_string(CHARS_DIGITS_CP850
					           CHARS_PUNCTUATION_CP850
					           CHARS_SPECIALS_CP850
					           CHARS_WHITESPACE_CP850);
					break;
				case CP852:
					if (fmt_case)
						add_string(CHARS_ALPHA_CP852);
					else
						add_string(CHARS_UPPER_CP852);
					add_string(CHARS_DIGITS_CP852
					           CHARS_PUNCTUATION_CP852
					           CHARS_SPECIALS_CP852
					           CHARS_WHITESPACE_CP852);
					break;
				case CP858:
					if (fmt_case)
						add_string(CHARS_ALPHA_CP858);
					else
						add_string(CHARS_UPPER_CP858);
					add_string(CHARS_DIGITS_CP858
					           CHARS_PUNCTUATION_CP858
					           CHARS_SPECIALS_CP858
					           CHARS_WHITESPACE_CP858);
					break;
				case CP866:
					if (fmt_case)
						add_string(CHARS_ALPHA_CP866);
					else
						add_string(CHARS_UPPER_CP866);
					add_string(CHARS_DIGITS_CP866
					           CHARS_PUNCTUATION_CP866
					           CHARS_SPECIALS_CP866
					           CHARS_WHITESPACE_CP866);
					break;
				case CP1250:
					if (fmt_case)
						add_string(CHARS_ALPHA_CP1250);
					else
						add_string(CHARS_UPPER_CP1250);
					add_string(CHARS_DIGITS_CP1250
					           CHARS_PUNCTUATION_CP1250
					           CHARS_SPECIALS_CP1250
					           CHARS_WHITESPACE_CP1250);
					break;
				case CP1251:
					if (fmt_case)
						add_string(CHARS_ALPHA_CP1251);
					else
						add_string(CHARS_UPPER_CP1251);
					add_string(CHARS_DIGITS_CP1251
					           CHARS_PUNCTUATION_CP1251
					           CHARS_SPECIALS_CP1251
					           CHARS_WHITESPACE_CP1251);
					break;
				case CP1252:
					if (fmt_case)
						add_string(CHARS_ALPHA_CP1252);
					else
						add_string(CHARS_UPPER_CP1252);
					add_string(CHARS_DIGITS_CP1252
					           CHARS_PUNCTUATION_CP1252
					           CHARS_SPECIALS_CP1252
					           CHARS_WHITESPACE_CP1252);
					break;
				case CP1253:
					if (fmt_case)
						add_string(CHARS_ALPHA_CP1253);
					else
						add_string(CHARS_UPPER_CP1253);
					add_string(CHARS_DIGITS_CP1253
					           CHARS_PUNCTUATION_CP1253
					           CHARS_SPECIALS_CP1253
					           CHARS_WHITESPACE_CP1253);
					break;
				case ISO_8859_1:
					if (fmt_case)
						add_string(CHARS_ALPHA_ISO_8859_1);
					else
						add_string(CHARS_UPPER_ISO_8859_1);
					add_string(CHARS_DIGITS_ISO_8859_1
					           CHARS_PUNCTUATION_ISO_8859_1
					           CHARS_SPECIALS_ISO_8859_1
					           CHARS_WHITESPACE_ISO_8859_1);
					break;
				case ISO_8859_2:
					if (fmt_case)
						add_string(CHARS_ALPHA_ISO_8859_2);
					else
						add_string(CHARS_UPPER_ISO_8859_2);
					add_string(CHARS_DIGITS_ISO_8859_2
					           CHARS_PUNCTUATION_ISO_8859_2
					           CHARS_SPECIALS_ISO_8859_2
					           CHARS_WHITESPACE_ISO_8859_2);
					break;
				case ISO_8859_7:
					if (fmt_case)
						add_string(CHARS_ALPHA_ISO_8859_7);
					else
						add_string(CHARS_UPPER_ISO_8859_7);
					add_string(CHARS_DIGITS_ISO_8859_7
					           CHARS_PUNCTUATION_ISO_8859_7
					           CHARS_SPECIALS_ISO_8859_7
					           CHARS_WHITESPACE_ISO_8859_7);
					break;
				case ISO_8859_15:
					if (fmt_case)
						add_string(CHARS_ALPHA_ISO_8859_15);
					else
						add_string(CHARS_UPPER_ISO_8859_15);
					add_string(CHARS_DIGITS_ISO_8859_15
					           CHARS_PUNCTUATION_ISO_8859_15
					           CHARS_SPECIALS_ISO_8859_15
					           CHARS_WHITESPACE_ISO_8859_15);
					break;
				case KOI8_R:
					if (fmt_case)
						add_string(CHARS_ALPHA_KOI8_R);
					else
						add_string(CHARS_UPPER_KOI8_R);
					add_string(CHARS_DIGITS_KOI8_R
					           CHARS_PUNCTUATION_KOI8_R
					           CHARS_SPECIALS_KOI8_R
					           CHARS_WHITESPACE_KOI8_R);
					break;
				default:
					add_range(0x80, 0xff);
				}
				break;
/*
 * Note: To add more cases, also append the symbol to string BUILT_IN_CHARSET.
 */
			default:  fprintf(stderr,
			                  "Unrecognized placeholder ?%c.\n",
			                  mask[load_qtn(qtn_ctr) + 1]);
				error();
			}

			set_range_start();

			qtn_ctr++;
			cpu_mask_ctx->count++;
		}
	}
#undef count
#undef swap
#undef fill_range
	for (i = 0; i < cpu_mask_ctx->count - 1; i++) {
		cpu_mask_ctx->ranges[i].next = i + 1;
		cpu_mask_ctx->active_positions[i] = 1;
	}
	cpu_mask_ctx->ranges[i].next = MAX_NUM_MASK_PLHDR;
	cpu_mask_ctx->active_positions[i] = 1;
}

/*
 * Returns the template of the keys corresponding to the mask.
 * Wordlist + mask not taken into account.
 */
static char* generate_template_key(char *mask, parsed_ctx *parsed_mask)
{
	char *template_key = (char*)mem_alloc(0x400);
	int i, k, t;
	i = 0, k = 0;

	while (i < strlen(mask)) {
		if ((t = search_stack(parsed_mask, i))){
			template_key[k++] = '#';
			i = t + 1;
		}
		else
			template_key[k++] = mask[i++];
	}
	template_key[k] = '\0';

	return template_key;
}

/* Handle internal encoding. */
static MAYBE_INLINE char* mask_cp_to_utf8(char *in)
{
	static char out[PLAINTEXT_BUFFER_SIZE + 1];

	if (pers_opts.internal_enc != UTF_8 &&
	    pers_opts.internal_enc != pers_opts.target_enc)
		return cp_to_utf8_r(in, out, PLAINTEXT_BUFFER_SIZE);

	return in;
}

static void generate_keys(char *template_key, cpu_mask_context *cpu_mask_ctx,
			  int my_words, int their_words)
{
	int i, j, k, ps1 = MAX_NUM_MASK_PLHDR, ps2 = MAX_NUM_MASK_PLHDR,
	    ps3 = MAX_NUM_MASK_PLHDR, ps;
	int offset = cpu_mask_ctx->offset, num_active_postions = 0;
	int start1, start2, start3;

	for (i = 0; i < cpu_mask_ctx->count; i++)
		if ((int)(cpu_mask_ctx->active_positions[i])) {
			ps1 = i;
			break;
		}

#define ranges(i) cpu_mask_ctx->ranges[i]

	ps2 = cpu_mask_ctx->ranges[ps1].next;
	ps3 = cpu_mask_ctx->ranges[ps2].next;

	for (i = 0; i < cpu_mask_ctx->count; i++)
		if ((int)(cpu_mask_ctx->active_positions[i]))
			num_active_postions++;

	if (!num_active_postions)
		fprintf(stdout, "%s\n", template_key);

#define inner_loop_body() {						\
	template_key[ranges(ps1).pos + offset] = start1 ? start1 + i:	\
		ranges(ps1).chars[i];  					\
	if (options.node_count) {					\
		seq++;							\
		if (their_words) {					\
			their_words--;					\
			continue;					\
		}							\
		if (--my_words == 0) {					\
			my_words =					\
				options.node_max - options.node_min + 1;\
			their_words = options.node_count - my_words;	\
		}							\
	}								\
	if (ext_filter(template_key))					\
		if (crk_process_key(mask_cp_to_utf8(template_key)))	\
			goto done;					\
	}

	else if (num_active_postions == 1) {
		start1 = ranges(ps1).start;
		for (i = 0; i < ranges(ps1).count; i++)
			inner_loop_body();
	}

	else if (num_active_postions == 2) {
		start1 = ranges(ps1).start;
		start2 = ranges(ps2).start;
		for (j = 0; j < ranges(ps2).count; j++) {
			template_key[ranges(ps2).pos + offset] =
			start2? start2 + j:
			ranges(ps2).chars[j];
			for (i = 0; i < ranges(ps1).count; i++)
				inner_loop_body();
		}
	}

	else if (num_active_postions > 2) {
		ps = ranges(ps3).next;

	/* Initialize the reaming placeholders other than the first three */
		while (ps != MAX_NUM_MASK_PLHDR) {
			template_key[ranges(ps).pos + offset] =
			ranges(ps).chars[ranges(ps).iter];
			ps = ranges(ps).next;
		}

		while (1) {
			start1 = ranges(ps1).start;
			start2 = ranges(ps2).start;
			start3 = ranges(ps3).start;
			/* Iterate over first three placeholders */
			for (k = 0; k < ranges(ps3).count; k++) {
				template_key[ranges(ps3).pos + offset] =
					start3 ? start3 + k:
					ranges(ps3).chars[k];
				for (j = 0; j < ranges(ps2).count; j++) {
					template_key[ranges(ps2).pos + offset] =
						start2 ? start2 + j:
						ranges(ps2).chars[j];
					for (i = 0; i < ranges(ps1).count; i++)
						inner_loop_body();
				}
			}

			ps = ranges(ps3).next;

			/*
			 * Calculate next state of remaing placeholders, working
			 * similar to counters.
			 */
			while(1) {

				if (ps == MAX_NUM_MASK_PLHDR) goto done;
				if ((++(ranges(ps).iter)) == ranges(ps).count) {
					ranges(ps).iter = 0;
					template_key[ranges(ps).pos + offset] =
						ranges(ps).chars[ranges(ps).iter];
					ps = ranges(ps).next;
				}
				else {
					template_key[ranges(ps).pos + offset] =
						ranges(ps).chars[ranges(ps).iter];
					break;
				}
			}
		}
#undef ranges
	}
	done: ;
}

/* Skips iteration for postions stored in arr */
static void skip_position(cpu_mask_context *cpu_mask_ctx, int *arr)
{
	if (arr != NULL) {
		int k = 0;
		while (arr[k] >= 0 && arr[k] < cpu_mask_ctx->count) {
			int j, i, flag1 = 0, flag2 = 0;
			cpu_mask_ctx->active_positions[arr[k]] = 0;
			cpu_mask_ctx->ranges[arr[k]].next = MAX_NUM_MASK_PLHDR;

			for (j = arr[k] - 1; j >= 0; j--)
				if ((int)(cpu_mask_ctx->active_positions[j])) {
					flag1 = 1;
					break;
				}

			for (i = arr[k] + 1; i < cpu_mask_ctx->count; i++)
				if ((int)(cpu_mask_ctx->active_positions[i])) {
					flag2 = 1;
					break;
				}

			if (flag1)
				cpu_mask_ctx->ranges[j].next =
					flag2?i:MAX_NUM_MASK_PLHDR;
			k++;
		}
	}
}

static double get_progress(void)
{
	double try;

	emms();

	try = ((unsigned long long)status.cands.hi << 32) + status.cands.lo;

	if (!cand)
		return -1;

	return 100.0 * try / cand;
}

static void save_state(FILE *file)
{
	int i;

	fprintf(file, "%u\n", rec_seq);
	fprintf(file, "%d\n", rec_ctx.count);
	fprintf(file, "%d\n", rec_ctx.offset);
	for (i = 0; i < rec_ctx.count; i++)
		fprintf(file, "%hhu\n", rec_ctx.ranges[i].iter);
}

static int restore_state(FILE *file)
{
	int i;

	if (fscanf(file, "%u\n", &seq) != 1)
		return 1;
	if (fscanf(file, "%d\n", &cpu_mask_ctx.count) != 1)
		return 1;
	if (fscanf(file, "%d\n", &cpu_mask_ctx.offset) != 1)
		return 1;
	for (i = 0; i < cpu_mask_ctx.count; i++)
		if (fscanf(file, "%hhu\n", &cpu_mask_ctx.ranges[i].iter) != 1)
			return 1;
	return 0;
}

static void fix_state(void)
{
	int i;
	rec_seq = seq;
	rec_ctx.count = cpu_mask_ctx.count;
	rec_ctx.offset = cpu_mask_ctx.offset;
	for (i = 0; i < rec_ctx.count; i++)
		rec_ctx.ranges[i].iter = cpu_mask_ctx.ranges[i].iter;
}

void do_mask_crack(struct db_main *db, char *mask)
{
	int my_words, their_words;
	int i;
	char *template_key;

	/* We do not yet support min/max-len */
	if (options.force_minlength >= 0 || options.force_maxlength) {
		fprintf(stderr, "Mask mode: --min-length and --max-length currently not supported\n");
		error();
	}

	log_event("Proceeding with mask mode");

	parse_braces(mask, &parsed_mask);
	if (parsed_mask.parse_ok)
		parse_qtn(mask, &parsed_mask);
	else {
		fprintf(stderr, "Parsing unsuccessful\n");
		error();
	}

	init_cpu_mask(mask, &parsed_mask, &cpu_mask_ctx, db);

	/*
	 * Warning: NULL to be raplaced by an array containing information
	 * regarding GPU portion of mask.
	 */
	skip_position(&cpu_mask_ctx, NULL);
	template_key = generate_template_key(mask, &parsed_mask);

	seq = 0;

	status_init(&get_progress, 0);

	rec_restore_mode(restore_state);
	rec_init(db, save_state);

	crk_init(db, fix_state, NULL);

	my_words = options.node_max - options.node_min + 1;
	their_words = options.node_min - 1;

	if (seq) {
/* Restored session.  seq is right after a word we've actually used. */
		int for_node = seq % options.node_count + 1;
		if (for_node < options.node_min ||
		        for_node > options.node_max) {
/* We assume that seq is at the beginning of other nodes' block */
			their_words = options.node_count - my_words;
		} else {
			my_words = options.node_max - for_node + 1;
			their_words = 0;
		}
	}

	cand = 1;
	for (i = 0; i < cpu_mask_ctx.count; i++)
		if ((int)(cpu_mask_ctx.active_positions[i]))
			cand *= cpu_mask_ctx.ranges[i].count;
	if (options.node_count)
		cand *= (double)(options.node_max - options.node_min + 1) /
			options.node_count;

	generate_keys(template_key, &cpu_mask_ctx, my_words, their_words);

	// For reporting DONE regardless of rounding errors
	if (!event_abort)
		cand = ((unsigned long long)status.cands.hi << 32) +
			status.cands.lo;

	crk_done();

	rec_done(event_abort);

	MEM_FREE(template_key);
}
