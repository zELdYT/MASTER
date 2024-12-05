
/*
 * Copyright (c) 2024 zELdYT
 *
 * Licensed under the BSD 2-Clause License.
 * See the LICENSE file in the project root for more details.
 */

#ifndef __MASTER_RANDOM_INCLUDE_H__
#define __MASTER_RANDOM_INCLUDE_H__

typedef unsigned char UI1;
typedef unsigned short UI2;
typedef unsigned long UI4;
typedef unsigned long long UI8;

// #! Linear Conngruental Generator

static UI4 MASTER_random_LCG32_seed = 0;

UI4
MASTER_random_LCG32( const UI4 m, const UI4 a, const UI4 c ) {
	return MASTER_random_LCG32_seed = ((m == 0) ? (MASTER_random_LCG32_seed * a + c) : ((MASTER_random_LCG32_seed * a + c) % m));
}

void
MASTER_random_LCG32_set( const UI4 new_seed ) {
	MASTER_random_LCG32_seed = new_seed;
}

static UI8 MASTER_random_LCG64_seed = 0;

UI8
MASTER_random_LCG64( const UI8 m, const UI8 a, const UI8 c ) {
	return MASTER_random_LCG64_seed = ((m == 0) ? (MASTER_random_LCG64_seed * a + c) : ((MASTER_random_LCG64_seed * a + c) % m));
}

void
MASTER_random_LCG64_set( const UI8 new_seed ) {
	MASTER_random_LCG64_seed = new_seed;
}

// !# Linear Conngruental Generator

// #! KDF

#include <string.h>

/*
 * "o" must be malloced with size (output_len)
*/
void
MASTER_random_KDF1( const char * s, UI4 l, char * o, void (*hashfunc)(const char *, UI4, UI1 *), const UI4 hash_len_output, const UI4 output_len ) {
	const UI4 k = output_len / hash_len_output + (output_len % hash_len_output > 0);
	UI4 i = 0;
	l += 4;
	char s_buf[l];
	memcpy(s_buf, s, l - 4);
	for (; i < k; i++) {
		*((UI4 *)(s_buf + l - 4)) = ((i & 0x000000FF) << 24) |
									((i & 0x0000FF00) << 8)  |
									((i & 0x00FF0000) >> 8)  |
									((i & 0xFF000000) >> 24);
		hashfunc(s_buf, l, o);
		o += hash_len_output;
	}
}

void
MASTER_random_KDF2( const char * s, UI4 l, char * o, void (*hashfunc)(const char *, UI4, UI1 *), const UI4 hash_len_output, const UI4 output_len ) {
	const UI4 k = output_len / hash_len_output + (output_len % hash_len_output > 0);
	UI4 i = 1;
	l += 4;
	char s_buf[l];
	memcpy(s_buf, s, l - 4);
	for (; i < k+1; i++) {
		*((UI4 *)(s_buf + l - 4)) = ((i & 0x000000FF) << 24) |
									((i & 0x0000FF00) << 8)  |
									((i & 0x00FF0000) >> 8)  |
									((i & 0xFF000000) >> 24);
		hashfunc(s_buf, l, o);
		o += hash_len_output;
	}
}

void
MASTER_random_KDF3( const char * s, UI4 l, char * o, void (*hashfunc)(const char *, UI4, UI1 *), const UI4 hash_len_output, const UI4 output_len, const UI4 pamt ) {
	const UI4 k = output_len / hash_len_output + (output_len % hash_len_output > 0);
	UI4 i = 0;
	l += pamt;
	char s_buf[l];
	memset(s_buf, 0, l * sizeof(char));
	memcpy(s_buf + pamt, s, l - pamt);
	for (; i < k; i++) {
		*((UI4 *)(s_buf + pamt - 4)) = ((i & 0x000000FF) << 24) |
									   ((i & 0x0000FF00) << 8)  |
									   ((i & 0x00FF0000) >> 8)  |
									   ((i & 0xFF000000) >> 24);
		hashfunc(s_buf, l, o);
		o += hash_len_output;
	}
}

// !# KDF

#endif /* __MASTER_RANDOM_INCLUDE_H__ */

// be master~
