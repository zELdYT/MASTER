
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

// #! Mersenne Twister random

typedef struct {
	unsigned long long __MT[312];
	int __index;
} MASTER_random_mt64;

static void
MASTER_random_mt64_twist( MASTER_random_mt64 * const __mt ) {
	register unsigned short i = 0;
	register unsigned long long y;
	for (; i < 312; i++) {
		y = (__mt->__MT[i] & 0x8000000000000000) + (__mt->__MT[(i + 1) % 312] & 0x7FFFFFFFFFFFFFFF);
		__mt->__MT[i] = __mt->__MT[(i + 156) % 312] ^ (y >> 1);
		if (y % 2 == 1)
			__mt->__MT[i] = __mt->__MT[i] ^ 0xB5026F5AA96619E9;
	}
	__mt->__index = 0;
}

MASTER_random_mt64
MASTER_random_mt64_init( const unsigned long long seed ) {
	MASTER_random_mt64 mt;
	mt.__index = 312;
	mt.__MT[0] = seed;
	register unsigned short i = 1;
	for (; i < 312; i++) 
		mt.__MT[i] = (6364136223846793005 * (mt.__MT[i - 1] ^ (mt.__MT[i - 1] >> 62)) + i) & 0xFFFFFFFFFFFFFFFF;
	return mt;
}

unsigned long long
MASTER_random_mt64_get( MASTER_random_mt64 * const mt ) {
	if (mt->__index >= 312)
		MASTER_random_mt64_twist(mt);
	register unsigned long long y = mt->__MT[mt->__index];
	y = (y ^ (y >> 29)) & 0x5555555555555555;
	y = (y ^ (y << 17)) & 0x71D67FFFEDA60000;
	y = (y ^ (y << 37)) & 0xFFF7EEE000000000;
	y = y ^ (y >> 43);
	mt->__index++;
	return y;
}

// !# Mersenne Twister random

// #! XorShift

// #!! 32

typedef struct {
	unsigned long __a;
} MASTER_random_xorshift32;

MASTER_random_xorshift32
MASTER_random_xorshift32_init(unsigned long seed) {
	MASTER_random_xorshift32 xs32;
	xs32.__a = seed;
	return xs32;
}

unsigned long
MASTER_random_xorshift32_get(MASTER_random_xorshift32 * const xs32) {
	unsigned long x = xs32->__a;
	x ^= x << 13;
	x ^= x >> 17;
	x ^= x << 5;
	return xs32->__a = x;
}

// !!# 32

// #!! 64

typedef struct {
	unsigned long long __a;
} MASTER_random_xorshift64;

MASTER_random_xorshift64
MASTER_random_xorshift64_init(unsigned long long seed) {
	MASTER_random_xorshift64 xs64;
	xs64.__a = seed;
	return xs64;
}

unsigned long
MASTER_random_xorshift64_get(MASTER_random_xorshift64 * const xs64) {
	unsigned long long x = xs64->__a;
	x ^= x << 13;
	x ^= x >> 7;
	x ^= x << 17;
	return xs64->__a = x;
}

// !!# 64

// #!! 128

typedef struct {
	unsigned long __x[4];
} MASTER_random_xorshift128;

MASTER_random_xorshift128
MASTER_random_xorshift128_init(unsigned long seed) {
	MASTER_random_xorshift128 xs128;
	xs128.__x[0] = seed;
	return xs128;
}

unsigned long
MASTER_random_xorshift128_get(MASTER_random_xorshift128 * const xs128) {
	unsigned long t = xs128->__x[3];
	const unsigned long s = xs128->__x[0];
	xs128->__x[3] = xs128->__x[2];
	xs128->__x[2] = xs128->__x[1];
	xs128->__x[1] = s;
	t ^= t << 11;
	t ^= t >> 8;
	return xs128->__x[0] = t ^ s ^ (s >> 19);
}

// !!# 128

// #!! XorWow

typedef struct {
	unsigned long __x[5];
	unsigned long __c;
} MASTER_random_xorwow;

MASTER_random_xorwow
MASTER_random_xorwow_init(unsigned long seed) {
	MASTER_random_xorwow xw;
	xw.__x[0] = seed;
	return xw;
}

unsigned long
MASTER_random_xorwow_get(MASTER_random_xorwow * const xw) {
	unsigned long t = xw->__x[4];
	const unsigned long s = xw->__x[0];
	xw->__x[4] = xw->__x[3];
	xw->__x[3] = xw->__x[2];
	xw->__x[2] = xw->__x[1];
	xw->__x[1] = s;
	
	t ^= t >> 2;
	t ^= t << 1;
	t ^= s ^ (s << 4);
	xw->__x[0] = t;
	xw->__c += 362437;
	return t + xw->__c;
}


// !!# XorWow

// #!! 64*

typedef struct {
	unsigned long long __x;
} MASTER_random_xorshift64star;

MASTER_random_xorshift64star
MASTER_random_xorshift64star_init(unsigned long long seed) {
	MASTER_random_xorshift64star xs64s;
	xs64s.__x = seed;
	return xs64s;
}

unsigned long long
MASTER_random_xorshift64star_get(MASTER_random_xorshift64star * const xs64s) {
	xs64s->__x ^= xs64s->__x >> 12;
	xs64s->__x ^= xs64s->__x << 25;
	xs64s->__x ^= xs64s->__x >> 27;
	return xs64s->__x * 0x2545F4914F6CDD1DULL;
}

// !!# 64*

// #!! 1024*

typedef struct {
	unsigned long long __x[16];
	int __i;
} MASTER_random_xorshift1024star;

MASTER_random_xorshift1024star
MASTER_random_xorshift1024star_init(unsigned long long seed) {
	MASTER_random_xorshift1024star xs1024s;
	xs1024s.__x[0] = seed;
	return xs1024s;
}

unsigned long
MASTER_random_xorshift1024star_get(MASTER_random_xorshift1024star * const xs1024s) {
	const unsigned long long s = xs1024s->__x[xs1024s->__i++];
	unsigned long long t = xs1024s->__x[xs1024s->__i &= 15];
	t ^= t << 31;
	t ^= t >> 11;
	t ^= s ^ (s >> 30);
	xs1024s->__x[xs1024s->__i] = t;
	return t * 1181783497276652981ULL;
}

// !!# 1024*

// #!! 128+

typedef struct {
	unsigned long long __x[2];
} MASTER_random_xorshift128plus;

MASTER_random_xorshift128plus
MASTER_random_xorshift128plus_init(unsigned long long seed) {
	MASTER_random_xorshift128plus xs128p;
	xs128p.__x[0] = seed;
	return xs128p;
}

unsigned long long
MASTER_random_xorshift128plus_get(MASTER_random_xorshift128plus * const xs128p) {
	unsigned long long t = xs128p->__x[0];
	const unsigned long long s = xs128p->__x[1];
	xs128p->__x[0] = s;
	t ^= t << 23;
	t ^= t >> 18;
	t ^= s ^ (s >> 5);
	xs128p->__x[1] = t;
	return t + s;
}

// !!# 128+

// #!! r128+

typedef struct {
	unsigned long long __x[2];
} MASTER_random_xorshiftr128plus;

MASTER_random_xorshiftr128plus
MASTER_random_xorshiftr128plus_init(unsigned long long seed) {
	MASTER_random_xorshiftr128plus xsr128p;
	xsr128p.__x[0] = seed;
	return xsr128p;
}

unsigned long long
MASTER_random_xorshiftr128plus_get(MASTER_random_xorshiftr128plus * const xsr128p) {
	unsigned long long x = xsr128p->__x[0];
	const unsigned long long y = xsr128p->__x[1];
	xsr128p->__x[0] = y;
	x ^= x << 23;
	x ^= x >> 17;
	x ^= y;
	xsr128p->__x[1] = x + y;
	return x;
}

// !!# r128+

#define MASTER_rol64(x, k) (((x) << (k)) | ((x) >> (64 - (k))))

// #!! xoshiro256+

typedef struct {
	unsigned long long __x[4];
} MASTER_random_xoshiro256plus;

MASTER_random_xoshiro256plus
MASTER_random_xoshiro256plus_init(unsigned long long seed) {
	MASTER_random_xoshiro256plus xs256p;
	xs256p.__x[0] = seed;
	return xs256p;
}

unsigned long long
MASTER_random_xoshiro256plus_get(MASTER_random_xoshiro256plus * const xs256p) {
	const unsigned long long res = xs256p->__x[0] + xs256p->__x[3];
	const unsigned long long t = xs256p->__x[1] << 17;
	
	xs256p->__x[2] ^= xs256p->__x[0];
	xs256p->__x[3] ^= xs256p->__x[1];
	xs256p->__x[1] ^= xs256p->__x[2];
	xs256p->__x[0] ^= xs256p->__x[3];
	xs256p->__x[2] ^= t;
	xs256p->__x[3] ^= MASTER_rol64(xs256p->__x[3], 45);
	
	return res;
}

// !!# xoshiro256+

// #!! xoshiro256++

typedef struct {
	unsigned long long __x[4];
} MASTER_random_xoshiro256plusplus;

MASTER_random_xoshiro256plusplus
MASTER_random_xoshiro256plusplus_init(unsigned long long seed) {
	MASTER_random_xoshiro256plusplus xs256pp;
	xs256pp.__x[0] = seed;
	return xs256pp;
}

unsigned long long
MASTER_random_xoshiro256plusplus_get(MASTER_random_xoshiro256plusplus * const xs256pp) {
	const unsigned long long r = MASTER_rol64(xs256pp->__x[0] + xs256pp->__x[3], 23) + xs256pp->__x[0];
	const unsigned long long t = xs256pp->__x[1] << 17;
	
	xs256pp->__x[2] ^= xs256pp->__x[0];
	xs256pp->__x[3] ^= xs256pp->__x[1];
	xs256pp->__x[1] ^= xs256pp->__x[2];
	xs256pp->__x[0] ^= xs256pp->__x[3];
	xs256pp->__x[2] ^= t;
	xs256pp->__x[3] ^= MASTER_rol64(xs256pp->__x[3], 45);
	
	return r;
}

// !!# xoshiro256++

// #!! xoshiro256**

typedef struct {
	unsigned long long __x[4];
} MASTER_random_xoshiro256starstar;

MASTER_random_xoshiro256starstar
MASTER_random_xoshiro256starstar_init(unsigned long long seed) {
	MASTER_random_xoshiro256starstar xs256ss;
	xs256ss.__x[0] = seed;
	return xs256ss;
}

unsigned long long
MASTER_random_xoshiro256starstar_get(MASTER_random_xoshiro256starstar * const xs256ss) {
	const unsigned long long res = MASTER_rol64(xs256ss->__x[1] * 5, 7) * 9;
	const unsigned long long t = xs256ss->__x[1] << 17;
	
	xs256ss->__x[2] ^= xs256ss->__x[0];
	xs256ss->__x[3] ^= xs256ss->__x[1];
	xs256ss->__x[1] ^= xs256ss->__x[2];
	xs256ss->__x[0] ^= xs256ss->__x[3];
	xs256ss->__x[2] ^= t;
	xs256ss->__x[3] ^= MASTER_rol64(xs256ss->__x[3], 45);
	
	return res;
}

// !!# xoshiro256**

// !# XorShift

#endif /* __MASTER_RANDOM_INCLUDE_H__ */

// be master~
