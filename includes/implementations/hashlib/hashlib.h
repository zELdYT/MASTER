
/*
 * Copyright (c) 2024 zELdYT
 *
 * Licensed under the BSD 2-Clause License.
 * See the LICENSE file in the project root for more details.
 */

#ifndef __MASTER_HASHLIB_INCLUDE_H__
#define __MASTER_HASHLIB_INCLUDE_H__

/* #! No priority !# */

#include <stdlib.h>
#include <string.h>
#include "../../headers/enumeration/master_enum.h"

#define __MASTER_CHANGE_ENDIAN_64(ptr) \
	(((UI8)((UI1 *)(ptr))[0]) ^ \
	(((UI8)((UI1 *)(ptr))[1]) << 8) ^ \
	(((UI8)((UI1 *)(ptr))[2]) << 16) ^ \
	(((UI8)((UI1 *)(ptr))[3]) << 24) ^ \
	(((UI8)((UI1 *)(ptr))[4]) << 32) ^ \
	(((UI8)((UI1 *)(ptr))[5]) << 40) ^ \
	(((UI8)((UI1 *)(ptr))[6]) << 48) ^ \
	(((UI8)((UI1 *)(ptr))[7]) << 56))
#define __MASTER_CHANGE_ENDIAN_32(ptr) \
	((UI4)((UI1 *)(ptr))[0]) ^ \
	(((UI4)((UI1 *)(ptr))[1]) << 8) ^ \
	(((UI4)((UI1 *)(ptr))[2]) << 16) ^ \
	(((UI4)((UI1 *)(ptr))[3]) << 24)
#define __MASTER_CHANGE_ENDIAN_32I(val) \
	((val & 0x000000FF) << 24) | \
	((val & 0x0000FF00) << 8) | \
	((val & 0x00FF0000) >> 8) | \
	((val & 0xFF000000) >> 24)
#define __MASTER_CHANGE_ENDIAN_64I(val) \
	((val & 0x00000000000000FF) << 56) | \
	((val & 0x000000000000FF00) << 40) | \
	((val & 0x0000000000FF0000) >> 24) | \
	((val & 0x00000000FF000000) << 8) | \
	((val & 0x000000FF00000000) >> 8) | \
	((val & 0x0000FF0000000000) >> 24) | \
	((val & 0x00FF000000000000) >> 40) | \
	((val & 0xFF00000000000000) >> 56)

// #! ADLER32

typedef struct {
	UI2 __A, __B;
} MASTER_Adler32;

MASTER_Adler32
MASTER_Adler32_Init(void) {
	MASTER_Adler32 __adler32 = { 1, 0 };
	return __adler32;
}

void
MASTER_Adler32_Update(MASTER_Adler32 * __adler32, const char * __s, UI4 __l) {
	while (__l--) {
		__adler32->__A = (__adler32->__A + *(__s++)) % 65521;
		__adler32->__B = (__adler32->__A + __adler32->__B) % 65521; }
}

void
MASTER_Adler32_Final(MASTER_Adler32 * __adler32, UI1 * hash_output) {
	UI4 result = (__adler32->__B << 16) | __adler32->__A;
	
	hash_output[0] = (result >> 24) & 0xFF;
	hash_output[1] = (result >> 16) & 0xFF;
	hash_output[2] = (result >> 8) & 0xFF;
	hash_output[3] = result & 0xFF;
}

void
MASTER_Adler32_CalculateHashSum(const UI1 * __s, UI4 __l, UI1 * hash_output) {
	UI2 A = 1, B = 0;
	while (__l--) {
		A = (A + *(__s++)) % 65521;
		B = (A + B) % 65521; }
	
	hash_output[0] = (B >> 8) & 0xFF;
	hash_output[1] = B & 0xFF;
	hash_output[2] = (A >> 8) & 0xFF;
	hash_output[3] = A & 0xFF;
}

void
MASTER_Adler32_CalculateHashSumExt(const UI1 * __s, UI4 __l, UI1 * hash_output, UI4 init) {
	UI4 A = init & 0xFFFF;
	UI4 B = (init >> 16) & 0xFFFF;

	while (__l--) {
		A = (A + *__s++) % 65521;
		B = (A + B) % 65521; }
		
	hash_output[0] = (B >> 8) & 0xFF;
	hash_output[1] = B & 0xFF;
	hash_output[2] = (A >> 8) & 0xFF;
	hash_output[3] = A & 0xFF;
}

// !# ADLER32

// #! CRC

UI1
MASTER_reverse(UI1 v) {
	UI1 r = 0;
	UI1 s = 0x01;
	UI1 d = 0x80;
	UI1 i = 0;
	for (; i < 8; i++){
		if (v & s)
			r |= d;
		s <<= 1;
		d >>= 1;
	}
	return r;
}

UI1
MASTER_reverse8(UI1 v) {
	v = ((v >> 1) & 0x55) | ((v & 0x55) << 1);
	v = ((v >> 2) & 0x33) | ((v & 0x33) << 2);
	return ((v >> 4) & 0x0F) | ((v & 0x0F) << 4);
}

UI4
MASTER_reflect32(UI4 v) {
	UI4 r = 0;
	UI4 s = 0x00000001;
	UI4 d = 0x80000000;
	UI1 i = 0;
	for (; i < 32; i++){
		if (v & s)
			r |= d;
		s <<= 1;
		d >>= 1;
	}
	return r;
}

UI8
MASTER_reflect64(UI8 v) {
	UI8 r = 0;
	UI8 s = 0x0000000000000001;
	UI8 d = 0x8000000000000000;
	UI8 i = 0;
	for (; i < 64; i++){
		if (v & s) r |= d;
		s <<= 1;
		d >>= 1;
	}
	return r;
}

UI8
MASTER_reflectN(UI8 v, UI1 n) {
	UI8 r = 0;
	UI8 s = 1;
	UI8 d = 1ULL << (n - 1);
	UI8 i = 0;
	for (; i < n; i++){
		if (v & s) r |= d;
		s <<= 1;
		d >>= 1;
	}
	return r;
}

#include "../../headers/cryptography/crc_enum.h"

UI8
MASTER_CRC_CalculateCheckSum(const char *__s, UI4 __l, const MASTER_CRC * const crc_struct) {
	// FIXME : support crc_struct->width < 8
	UI8 crc = crc_struct->init;
	UI1 byte, bit;
	const UI8 topbit = 1ULL << (crc_struct->width - 1);
	
	while (__l--) {
		byte = *__s++;
		if (crc_struct->refin == 1) byte = MASTER_reverse8(byte);
		if (crc_struct->width < 8) crc ^= byte;
		else crc ^= ((UI8)byte) << (crc_struct->width - 8);
		for (bit = 0; bit < 8; bit++) {
			if (crc & topbit) crc = (crc << 1) ^ crc_struct->poly;
			else crc <<= 1;
		}
	}
	if (crc_struct->refout == 1) crc = MASTER_reflectN(crc, crc_struct->width);
	crc ^= crc_struct->xorout;
	return crc;
}

// #!! CRC8

typedef struct {
	UI1 __crc;
} MASTER_CRC8;

MASTER_CRC8
MASTER_CRC8_Init(void) {
	MASTER_CRC8 __crc8 = { 0xFF };
	return __crc8;
}

void
MASTER_CRC8_Update(MASTER_CRC8 * __crc8, const char * __s, UI4 __l) {
	UI1 i;
	while (__l--) {
		__crc8->__crc ^= *__s++;
		for (i = 0; i < 8; i++)
			__crc8->__crc = (__crc8->__crc & 0x80) ? (__crc8->__crc << 1) ^ 0x31 : (__crc8->__crc << 1);
	}
}

void
MASTER_CRC8_Final(MASTER_CRC8 * __crc8, UI1 * hash_output) {
	hash_output[0] = __crc8->__crc;
}

void
MASTER_CRC8_CalculateHashSum(const char * __s, UI4 __l, UI1 * hash_output) {
	UI4 crc = 0xFF;
	UI1 i;
	
	while (__l--) {
		crc ^= *__s++;
		for (i = 0; i < 8; i++)
			crc = (crc & 0x80) ? (crc << 1) ^ 0x31 : (crc << 1);
	}
	hash_output[0] = crc;
}

// !!# CRC8

// #!! CRC16

typedef struct {
	UI2 __crc;
} MASTER_CRC16;

MASTER_CRC16
MASTER_CRC16_Init(void) {
	MASTER_CRC16 __crc16 = { 0xFFFF };
	return __crc16;
}

void
MASTER_CRC16_Update(MASTER_CRC16 * __crc16, const char * __s, UI4 __l) {
	UI1 i;
	while (__l--) {
		__crc16->__crc ^= *__s++ << 8;
		for (i = 0; i < 8; i++)
			__crc16->__crc = (__crc16->__crc & 0x8000) ? (__crc16->__crc << 1) ^ 0x1021 : (__crc16->__crc << 1);
	}
}

void
MASTER_CRC16_Final(MASTER_CRC16 * __crc16, UI1 * hash_output) {
	hash_output[0] = __crc16->__crc & 0xFF;
	hash_output[1] = (__crc16->__crc >> 8) & 0xFF;
}

void
MASTER_CRC16_CalculateHashSum(const char * __s, UI4 __l, UI1 * hash_output) {
	UI4 crc = 0xFFFF;
	UI1 i;
	
	while (__l--) {
		crc ^= *__s++ << 8;
		for (i = 0; i < 8; i++)
			crc = (crc & 0x8000) ? (crc << 1) ^ 0x1021 : (crc << 1);
	}
	hash_output[0] = crc & 0xFF;
	hash_output[1] = (crc >> 8) & 0xFF;
}

// !!# CRC16

// #!! CRC32

typedef struct {
	UI4 __crc;
} MASTER_CRC32B;

MASTER_CRC32B
MASTER_CRC32B_Init(void) {
	MASTER_CRC32B __crc32b = { 0xFFFFFFFF };
	return __crc32b;
}

void
MASTER_CRC32B_Update(MASTER_CRC32B * __crc32b, const char * __s, UI4 __l) {
	while (__l--) {
		UI1 ch = *__s++;
		for (UI1 j = 0; j < 8; j++) {
			UI1 b = (ch ^ __crc32b->__crc) & 1;
			__crc32b->__crc >>= 1;
			if (b) __crc32b->__crc ^= 0xEDB88320;
			ch >>= 1;
		}
	}
}

void
MASTER_CRC32B_Final(MASTER_CRC32B * __crc32b, UI1 * hash_output) {
	UI4 result = ~__crc32b->__crc;

	hash_output[0] = (result >> 24) & 0xFF;
	hash_output[1] = (result >> 16) & 0xFF;
	hash_output[2] = (result >> 8) & 0xFF;
	hash_output[3] = result & 0xFF;
}

void
MASTER_CRC32B_CalculateHashSum(const char * __s, UI4 __l, UI1 * hash_output) {
	UI4 crc = 0xFFFFFFFF;
	UI1 ch = 0, b, j;
	while (__l--) {
		ch ^= *__s++;
		for (j = 0; j < 8; j++) {
			b = (ch ^ crc) & 1;
			crc >>= 1;
			if (b) crc ^= 0xEDB88320; // 0x82F63B78 // crc32c
			ch >>= 1;
		}
	}
	crc = ~crc;

	hash_output[0] = (crc >> 24) & 0xFF;
	hash_output[1] = (crc >> 16) & 0xFF;
	hash_output[2] = (crc >> 8) & 0xFF;
	hash_output[3] = crc & 0xFF;
}

// !!# CRC32

// !# CRC

// #! MD2

static const UI1 MASTER_MD2_Table[256] = {
	41, 46, 67, 201, 162, 216, 124, 1,
	61, 54, 84, 161, 236, 240, 6, 19,
	98, 167, 5, 243, 192, 199, 115, 140,
	152, 147, 43, 217, 188, 76, 130, 202,
	30, 155, 87, 60, 253, 212, 224, 22,
	103, 66, 111, 24, 138, 23, 229, 18,
	190, 78, 196, 214, 218, 158, 222, 73,
	160, 251, 245, 142, 187, 47, 238, 122,
	169, 104, 121, 145, 21, 178, 7, 63,
	148, 194, 16, 137, 11, 34, 95, 33,
	128, 127, 93, 154, 90, 144, 50, 39,
	53, 62, 204, 231, 191, 247, 151, 3,
	255, 25, 48, 179, 72, 165, 181, 209,
	215, 94, 146, 42, 172, 86, 170, 198,
	79, 184, 56, 210, 150, 164, 125, 182,
	118, 252, 107, 226, 156, 116, 4, 241,
	69, 157, 112, 89, 100, 113, 135, 32,
	134, 91, 207, 101, 230, 45, 168, 2,
	27, 96, 37, 173, 174, 176, 185, 246,
	28, 70, 97, 105, 52, 64, 126, 15,
	85, 71, 163, 35, 221, 81, 175, 58,
	195, 92, 249, 206, 186, 197, 234, 38,
	44, 83, 13, 110, 133, 40, 132, 9,
	211, 223, 205, 244, 65, 129, 77, 82,
	106, 220, 55, 200, 108, 193, 171, 250,
	36, 225, 123, 8, 12, 189, 177, 74,
	120, 136, 149, 139, 227, 99, 232, 109,
	233, 203, 213, 254, 59, 0, 29, 57,
	242, 239, 183, 14, 102, 88, 208, 228,
	166, 119, 114, 248, 235, 117, 75, 10,
	49, 68, 80, 180, 143, 237, 31, 26,
	219, 153, 141, 51, 159, 17, 131, 20
};

typedef struct {
	UI1 __X[48];
	UI1 __M[16];
	UI1 __buffer[16];
	UI1 __l;
} MASTER_MD2;

MASTER_MD2
MASTER_MD2_Init(void) {
	MASTER_MD2 __md2;
	for (UI1 i = 0; i < 16; i++) __md2.__M[i] = 0x00;
	for (UI1 i = 0; i < 48; i++) __md2.__X[i] = 0x00;
	__md2.__l = 0;
	return __md2;
}

static void
__MASTER_MD2_Transform(MASTER_MD2 * __md2, const UI1 * __data) {
	UI1 t;
	UI4 j, k;
	for (j = 0; j < 16; j++) {
		__md2->__X[16 + j] = __data[j];
		__md2->__X[32 + j] = (__md2->__X[16 + j] ^ __md2->__X[j]); }
	t = 0;
	for (j = 0; j < 18; j++) {
		for (k = 0; k < 48; k++) {
			__md2->__X[k] = (__md2->__X[k] ^ MASTER_MD2_Table[t]);
			t = __md2->__X[k]; }
		t = (t + j) % 256; }

	t = __md2->__M[15];
	for ( j = 0; j < 16; j++) {
		__md2->__M[j] ^= MASTER_MD2_Table[__md2->__buffer[j] ^ t];
		t = __md2->__M[j]; }
}

void
MASTER_MD2_Update(MASTER_MD2 * __md2, const char * __s, UI4 __l) {
	while (__l--) {
		__md2->__buffer[__md2->__l++] = *(__s++);
		if (__md2->__l == 16) {
			__MASTER_MD2_Transform(__md2, __md2->__buffer);
			__md2->__l = 0; }
	}
}

void
MASTER_MD2_Final(MASTER_MD2 * __md2, UI1 * hash_output) {
	UI1 rem = 16 - __md2->__l;

	while (__md2->__l < 16)
		__md2->__buffer[__md2->__l++] = rem;

	__MASTER_MD2_Transform(__md2, __md2->__buffer);
	__MASTER_MD2_Transform(__md2, __md2->__M);

	for (UI1 i = 0; i < 16; i++)
		hash_output[i] = __md2->__X[i];
}

void
MASTER_MD2_CalculateHashSum(const char * __s, UI4 __l, UI1 * hash_output) {
	UI1 M[16], X[48];
	for (UI1 i = 0; i < 16; i++) M[i] = 0x00;
	for (UI1 i = 0; i < 48; i++) X[i] = 0x00;
	UI1 c, t;
	UI1 L = 0;
	UI1 rem = 16 - (__l % 16);
	UI4 i, j, k;
	char * __M = (char *)alloca((__l + rem + 16 + 1) * sizeof(char));
	for (i = 0; i < __l; i++)
		__M[i] = __s[i];
	for (i = 0; i < rem; i++)
		__M[__l + i] = rem;
	__l += rem;
	for (i = 0; i < __l / 16; i++) {
		for (j = 0; j < 16; j++) {
			c = __M[i * 16 + j];
			M[j] = MASTER_MD2_Table[c ^ L] ^ M[j];
			L = M[j]; }
	}
	for (i = 0; i < 16; i++)
		__M[__l + i] = M[i];
	__l += 16;
	for (i = 0; i < __l / 16; i++) {
		for (j = 0; j < 16; j++) {
			X[16 + j] = __M[i * 16 + j];
			X[32 + j] = (X[16 + j] ^ X[j]); }
		t = 0;
		for (j = 0; j < 18; j++) {
			for (k = 0; k < 48; k++) {
				X[k] = (X[k] ^ MASTER_MD2_Table[t]);
				t = X[k]; }
			t = (t + j) % 256; }
	}
	for (i = 0; i < 16; i++)
		hash_output[i] = X[i];
}

// !# MD2

// #! MD4

#define __MASTER_MD4_FUNCTION_F(X, Y, Z) ((X & Y) | ((~X) & Z))
#define __MASTER_MD4_FUNCTION_G(X, Y, Z) ((X & Y) | (X & Z) | (Y & Z))
#define __MASTER_MD4_FUNCTION_H(X, Y, Z) (X ^ Y ^ Z)
#define __MASTER_MD4_FUNCTION_FF(A, B, C, D, K, S) A += __MASTER_MD4_FUNCTION_F(B, C, D) + (X[K]); A = MASTER_RLL32(A, S)
#define __MASTER_MD4_FUNCTION_GG(A, B, C, D, K, S) A += __MASTER_MD4_FUNCTION_G(B, C, D) + (X[K]) + 0x5A827999; A = MASTER_RLL32(A, S)
#define __MASTER_MD4_FUNCTION_HH(A, B, C, D, K, S) A += __MASTER_MD4_FUNCTION_H(B, C, D) + (X[K]) + 0x6ED9EBA1; A = MASTER_RLL32(A, S)

typedef struct {
	UI4 __A, __B, __C, __D;
	UI1 __buffer[64];
	UI8 __l;
} MASTER_MD4;

MASTER_MD4
MASTER_MD4_Init(void) {
	MASTER_MD4 __md4;
	__md4.__A = 0x67452301;
	__md4.__B = 0xefcdab89;
	__md4.__C = 0x98badcfe;
	__md4.__D = 0x10325476;
	__md4.__l = 0;
	return __md4;
}

static void
__MASTER_MD4_Transform(MASTER_MD4 * __md4) {
	UI4 AA, BB, CC, DD, j;
	UI4 X[16];
	for (j = 0; j < 16; j++) 
		X[j] = (__md4->__buffer[j * 4]) | ((__md4->__buffer[j * 4 + 1]) << 8) |
				 ((__md4->__buffer[j * 4 + 2]) << 16) | ((__md4->__buffer[j * 4 + 3]) << 24);
	
	AA = __md4->__A;
	BB = __md4->__B;
	CC = __md4->__C;
	DD = __md4->__D;
	
	for (j = 0; j < 4; j++) {
		__MASTER_MD4_FUNCTION_FF(__md4->__A, __md4->__B, __md4->__C, __md4->__D, 0 + j * 4, 3);
		__MASTER_MD4_FUNCTION_FF(__md4->__D, __md4->__A, __md4->__B, __md4->__C, 1 + j * 4, 7);
		__MASTER_MD4_FUNCTION_FF(__md4->__C, __md4->__D, __md4->__A, __md4->__B, 2 + j * 4, 11);
		__MASTER_MD4_FUNCTION_FF(__md4->__B, __md4->__C, __md4->__D, __md4->__A, 3 + j * 4, 19);
	}
	
	for (j = 0; j < 4; j++) {
		__MASTER_MD4_FUNCTION_GG(__md4->__A, __md4->__B, __md4->__C, __md4->__D, 0 + j, 3);
		__MASTER_MD4_FUNCTION_GG(__md4->__D, __md4->__A, __md4->__B, __md4->__C, 4 + j, 5);
		__MASTER_MD4_FUNCTION_GG(__md4->__C, __md4->__D, __md4->__A, __md4->__B, 8 + j, 9);
		__MASTER_MD4_FUNCTION_GG(__md4->__B, __md4->__C, __md4->__D, __md4->__A, 12 + j, 13);
	}
	
	for (j = 0; j < 4; j++) {
		__MASTER_MD4_FUNCTION_HH(__md4->__A, __md4->__B, __md4->__C, __md4->__D, 0 + (j % 2) * 2 + (j / 2), 3);
		__MASTER_MD4_FUNCTION_HH(__md4->__D, __md4->__A, __md4->__B, __md4->__C, 8 + (j % 2) * 2 + (j / 2), 9);
		__MASTER_MD4_FUNCTION_HH(__md4->__C, __md4->__D, __md4->__A, __md4->__B, 4 + (j % 2) * 2 + (j / 2), 11);
		__MASTER_MD4_FUNCTION_HH(__md4->__B, __md4->__C, __md4->__D, __md4->__A, 12 + (j % 2) * 2 + (j / 2), 15);
	}
	
	__md4->__A += AA;
	__md4->__B += BB;
	__md4->__C += CC;
	__md4->__D += DD;
}

void
MASTER_MD4_Update(MASTER_MD4 * __md4, const char * __s, UI4 __l) {
	while (__l--) {
		__md4->__buffer[__md4->__l++ % 64] = *(__s++);
		if (__md4->__l % 64 == 0)
			__MASTER_MD4_Transform(__md4);
	}
}

void
MASTER_MD4_Final(MASTER_MD4 * __md4, UI1 * hash_output) {
	UI1 bits[8];
	UI4 index, padLen, i;

	bits[0] = ((__md4->__l << 3) & 0xff);
	bits[1] = ((__md4->__l << 3) >> 8) & 0xff;
	bits[2] = ((__md4->__l << 3) >> 16) & 0xff;
	bits[3] = ((__md4->__l << 3) >> 24) & 0xff;
	bits[4] = ((__md4->__l << 3) >> 32) & 0xff;
	bits[5] = ((__md4->__l << 3) >> 40) & 0xff;
	bits[6] = ((__md4->__l << 3) >> 48) & 0xff;
	bits[7] = ((__md4->__l << 3) >> 56) & 0xff;
	
	index = ((__md4->__l) & 0x3f);
	padLen = (index < 56) ? (56 - index) : (120 - index);
	const UI1 c = 0x80;
	MASTER_MD4_Update(__md4, (const char *)&c, 1);
	padLen--;
	while (padLen--) MASTER_MD4_Update(__md4, "\0", 1);
	
	MASTER_MD4_Update(__md4, (const char *)bits, 8);

	for (i = 0; i < 4; i++) hash_output[i] = (__md4->__A >> (8*i)) & 0xFF;
	for (i = 0; i < 4; i++) hash_output[4 + i] = (__md4->__B >> (8*i)) & 0xFF;
	for (i = 0; i < 4; i++) hash_output[8 + i] = (__md4->__C >> (8*i)) & 0xFF;
	for (i = 0; i < 4; i++) hash_output[12 + i] = (__md4->__D >> (8*i)) & 0xFF;
}

void
MASTER_MD4_CalculateHashSum(const char * __s, UI8 __l, UI1 * hash_output) {
	UI4 i, j;

	UI8 padding_bytes = ((__l * 8 + (8 * (56 - __l) % 512)) - __l * 8) / 8;

	UI1 * __M = (UI1 *)alloca( (__l + padding_bytes + 8) * sizeof(char));
	for (i = 0; i < __l; i++)
		__M[i] = __s[i];

	__M[__l] = 0x80;

	for (i = 0; i < padding_bytes - 1; i++)
		*(__M + __l + 1 + i) = 0;

	UI8 * length_append = (UI8 *)(__M + __l + padding_bytes);
	*length_append = __l * 8;
	
	__l += (padding_bytes + 8);

	UI4 A = 0x67452301;
	UI4 B = 0xefcdab89;
	UI4 C = 0x98badcfe;
	UI4 D = 0x10325476;
	
	UI4 AA, BB, CC, DD;
	
	UI4 X[16];
	for (i = 0; i < __l; i += 64) {
		for (j = 0; j < 16; j++) 
			X[j] = (__M[i + j * 4]) | ((__M[i + j * 4 + 1]) << 8) |
					 ((__M[i + j * 4 + 2]) << 16) | ((__M[i + j * 4 + 3]) << 24);
		
		AA = A;
		BB = B;
		CC = C;
		DD = D;
		
		for (j = 0; j < 4; j++) {
			__MASTER_MD4_FUNCTION_FF(A, B, C, D, 0 + j * 4, 3);
			__MASTER_MD4_FUNCTION_FF(D, A, B, C, 1 + j * 4, 7);
			__MASTER_MD4_FUNCTION_FF(C, D, A, B, 2 + j * 4, 11);
			__MASTER_MD4_FUNCTION_FF(B, C, D, A, 3 + j * 4, 19);
		}
		
		for (j = 0; j < 4; j++) {
			__MASTER_MD4_FUNCTION_GG(A, B, C, D, 0 + j, 3);
			__MASTER_MD4_FUNCTION_GG(D, A, B, C, 4 + j, 5);
			__MASTER_MD4_FUNCTION_GG(C, D, A, B, 8 + j, 9);
			__MASTER_MD4_FUNCTION_GG(B, C, D, A, 12 + j, 13);
		}
		
		for (j = 0; j < 4; j++) {
			__MASTER_MD4_FUNCTION_HH(A, B, C, D, 0 + (j % 2) * 2 + (j / 2), 3);
			__MASTER_MD4_FUNCTION_HH(D, A, B, C, 8 + (j % 2) * 2 + (j / 2), 9);
			__MASTER_MD4_FUNCTION_HH(C, D, A, B, 4 + (j % 2) * 2 + (j / 2), 11);
			__MASTER_MD4_FUNCTION_HH(B, C, D, A, 12 + (j % 2) * 2 + (j / 2), 15);
		}
		
		A += AA;
		B += BB;
		C += CC;
		D += DD;
	}
	
	for (i = 0; i < 4; i++) hash_output[i] = (A >> (8*i)) & 0xFF;
	for (i = 0; i < 4; i++) hash_output[4 + i] = (B >> (8*i)) & 0xFF;
	for (i = 0; i < 4; i++) hash_output[8 + i] = (C >> (8*i)) & 0xFF;
	for (i = 0; i < 4; i++) hash_output[12 + i] = (D >> (8*i)) & 0xFF;
}

#undef __MASTER_MD4_FUNCTION_F
#undef __MASTER_MD4_FUNCTION_G
#undef __MASTER_MD4_FUNCTION_H
#undef __MASTER_MD4_FUNCTION_FF
#undef __MASTER_MD4_FUNCTION_GG
#undef __MASTER_MD4_FUNCTION_HH

// !# MD4

// #! MD5

#define __MASTER_MD5_FUNCTION_F(X, Y, Z) ((X & Y) | ((~X) & Z))
#define __MASTER_MD5_FUNCTION_G(X, Y, Z) ((X & Z) | ((~Z) & Y))
#define __MASTER_MD5_FUNCTION_H(X, Y, Z) (X ^ Y ^ Z)
#define __MASTER_MD5_FUNCTION_I(X, Y, Z) (Y ^ ((~Z) | X))
#define __MASTER_MD5_FUNCTION_FF(A, B, C, D, K, S, I) A = B + MASTER_RLL32(A + __MASTER_MD5_FUNCTION_F(B, C, D) + X[K] + T[I], S)
#define __MASTER_MD5_FUNCTION_GG(A, B, C, D, K, S, I) A = B + MASTER_RLL32(A + __MASTER_MD5_FUNCTION_G(B, C, D) + X[K] + T[I], S)
#define __MASTER_MD5_FUNCTION_HH(A, B, C, D, K, S, I) A = B + MASTER_RLL32(A + __MASTER_MD5_FUNCTION_H(B, C, D) + X[K] + T[I], S)
#define __MASTER_MD5_FUNCTION_II(A, B, C, D, K, S, I) A = B + MASTER_RLL32(A + __MASTER_MD5_FUNCTION_I(B, C, D) + X[K] + T[I], S)

typedef struct {
	UI4 __A, __B, __C, __D;
	UI1 __buffer[64];
	UI8 __l;
} MASTER_MD5;

MASTER_MD5
MASTER_MD5_Init(void) {
	MASTER_MD5 __md5;
	__md5.__A = 0x67452301;
	__md5.__B = 0xefcdab89;
	__md5.__C = 0x98badcfe;
	__md5.__D = 0x10325476;
	__md5.__l = 0;
	return __md5;
}

static void
__MASTER_MD5_Transform(MASTER_MD5 * __md5) {
	UI4 AA, BB, CC, DD, j;
	UI4 T[64] = { 0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821, 0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8, 0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665, 0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1, 0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391 };
	UI4 X[16];
	for (j = 0; j < 16; j++) 
		X[j] = (__md5->__buffer[j * 4]) | ((__md5->__buffer[j * 4 + 1]) << 8) | ((__md5->__buffer[j * 4 + 2]) << 16) | ((__md5->__buffer[j * 4 + 3]) << 24);
	
	AA = __md5->__A;
	BB = __md5->__B;
	CC = __md5->__C;
	DD = __md5->__D;
	
	for (j = 0; j < 4; j++) {
		__MASTER_MD5_FUNCTION_FF(__md5->__A, __md5->__B, __md5->__C, __md5->__D, 0 + j * 4, 7, 0 + j * 4);
		__MASTER_MD5_FUNCTION_FF(__md5->__D, __md5->__A, __md5->__B, __md5->__C, 1 + j * 4, 12, 1 + j * 4);
		__MASTER_MD5_FUNCTION_FF(__md5->__C, __md5->__D, __md5->__A, __md5->__B, 2 + j * 4, 17, 2 + j * 4);
		__MASTER_MD5_FUNCTION_FF(__md5->__B, __md5->__C, __md5->__D, __md5->__A, 3 + j * 4, 22, 3 + j * 4);
	}
	
	for (j = 0; j < 4; j++) {
		__MASTER_MD5_FUNCTION_GG(__md5->__A, __md5->__B, __md5->__C, __md5->__D, 1 + j * 4, 5, 16 + j * 4);
		__MASTER_MD5_FUNCTION_GG(__md5->__D, __md5->__A, __md5->__B, __md5->__C, (6 + j * 4) % 16, 9, 17 + j * 4);
		__MASTER_MD5_FUNCTION_GG(__md5->__C, __md5->__D, __md5->__A, __md5->__B, (11 + j * 4) % 16, 14, 18 + j * 4);
		__MASTER_MD5_FUNCTION_GG(__md5->__B, __md5->__C, __md5->__D, __md5->__A, j * 4, 20, 19 + j * 4);
	}
	
	for (j = 0; j < 4; j++) {
		__MASTER_MD5_FUNCTION_HH(__md5->__A, __md5->__B, __md5->__C, __md5->__D, (16 + (5 - j * 4)) % 16, 4, 32 + j * 4);
		__MASTER_MD5_FUNCTION_HH(__md5->__D, __md5->__A, __md5->__B, __md5->__C, (16 + (8 - j * 4)) % 16, 11, 33 + j * 4);
		__MASTER_MD5_FUNCTION_HH(__md5->__C, __md5->__D, __md5->__A, __md5->__B, (16 + (11 - j * 4)) % 16, 16, 34 + j * 4);
		__MASTER_MD5_FUNCTION_HH(__md5->__B, __md5->__C, __md5->__D, __md5->__A, (16 + (14 - j * 4)) % 16, 23, 35 + j * 4);
	}
	
	for (j = 0; j < 4; j++) {
		__MASTER_MD5_FUNCTION_II(__md5->__A, __md5->__B, __md5->__C, __md5->__D, (16 + (0 - j * 4)) % 16, 6, 48 + j * 4);
		__MASTER_MD5_FUNCTION_II(__md5->__D, __md5->__A, __md5->__B, __md5->__C, (16 + (7 - j * 4)) % 16, 10, 49 + j * 4);
		__MASTER_MD5_FUNCTION_II(__md5->__C, __md5->__D, __md5->__A, __md5->__B, (16 + (14 - j * 4)) % 16, 15, 50 + j * 4);
		__MASTER_MD5_FUNCTION_II(__md5->__B, __md5->__C, __md5->__D, __md5->__A, (16 + (5 - j * 4)) % 16, 21, 51 + j * 4);
	}
		
	__md5->__A += AA;
	__md5->__B += BB;
	__md5->__C += CC;
	__md5->__D += DD;
}

void
MASTER_MD5_Update(MASTER_MD5 * __md5, const char * __s, UI4 __l) {
	while (__l--) {
		__md5->__buffer[__md5->__l++ % 64] = *(__s++);
		if (__md5->__l % 64 == 0)
			__MASTER_MD5_Transform(__md5);
	}
}

void
MASTER_MD5_Final(MASTER_MD5 * __md5, UI1 * hash_output) {
	UI1 bits[8];
	UI4 index, padLen, i;

	bits[0] = ((__md5->__l << 3) & 0xff);
	bits[1] = ((__md5->__l << 3) >> 8) & 0xff;
	bits[2] = ((__md5->__l << 3) >> 16) & 0xff;
	bits[3] = ((__md5->__l << 3) >> 24) & 0xff;
	bits[4] = ((__md5->__l << 3) >> 32) & 0xff;
	bits[5] = ((__md5->__l << 3) >> 40) & 0xff;
	bits[6] = ((__md5->__l << 3) >> 48) & 0xff;
	bits[7] = ((__md5->__l << 3) >> 56) & 0xff;
	
	index = ((__md5->__l) & 0x3f);
	padLen = (index < 56) ? (56 - index) : (120 - index);
	const UI1 c = 0x80;
	MASTER_MD5_Update(__md5, (const char *)&c, 1);
	padLen--;
	while (padLen--) MASTER_MD5_Update(__md5, "\0", 1);
	
	MASTER_MD5_Update(__md5, (const char *)bits, 8);

	for (i = 0; i < 4; i++) hash_output[i] = (__md5->__A >> (8*i)) & 0xFF;
	for (i = 0; i < 4; i++) hash_output[4 + i] = (__md5->__B >> (8*i)) & 0xFF;
	for (i = 0; i < 4; i++) hash_output[8 + i] = (__md5->__C >> (8*i)) & 0xFF;
	for (i = 0; i < 4; i++) hash_output[12 + i] = (__md5->__D >> (8*i)) & 0xFF;
}

void
MASTER_MD5_CalculateHashSum(const char * __s, UI8 __l, UI1 * hash_output) {
	UI4 i, j;

	UI8 padding_bytes = ((__l * 8 + (8 * (56 - __l) % 512)) - __l * 8) / 8;

	UI1 * __M = (UI1 *)alloca( (__l + padding_bytes + 8) * sizeof(char));
	for (i = 0; i < __l; i++)
		__M[i] = __s[i];

	__M[__l] = 0x80;

	for (i = 0; i < padding_bytes - 1; i++)
		*(__M + __l + 1 + i) = 0;

	UI8 * length_append = (UI8 *)(__M + __l + padding_bytes);
	*length_append = __l * 8;
	
	__l += (padding_bytes + 8);
	
	UI4 A = 0x67452301;
	UI4 B = 0xefcdab89;
	UI4 C = 0x98badcfe;
	UI4 D = 0x10325476;
	
	UI4 AA, BB, CC, DD;
	
	UI4 T[64] = { 0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821, 0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8, 0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665, 0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1, 0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391 };
	UI4 X[16];
	for (i = 0; i < __l; i += 64) {
		for (j = 0; j < 16; j++) 
			X[j] = (__M[i + j * 4]) | ((__M[i + j * 4 + 1]) << 8) | ((__M[i + j * 4 + 2]) << 16) | ((__M[i + j * 4 + 3]) << 24);
		
		AA = A;
		BB = B;
		CC = C;
		DD = D;
		
		for (j = 0; j < 4; j++) {
			__MASTER_MD5_FUNCTION_FF(A, B, C, D, 0 + j * 4, 7, 0 + j * 4);
			__MASTER_MD5_FUNCTION_FF(D, A, B, C, 1 + j * 4, 12, 1 + j * 4);
			__MASTER_MD5_FUNCTION_FF(C, D, A, B, 2 + j * 4, 17, 2 + j * 4);
			__MASTER_MD5_FUNCTION_FF(B, C, D, A, 3 + j * 4, 22, 3 + j * 4);
		}
		
		for (j = 0; j < 4; j++) {
			__MASTER_MD5_FUNCTION_GG(A, B, C, D, 1 + j * 4, 5, 16 + j * 4);
			__MASTER_MD5_FUNCTION_GG(D, A, B, C, (6 + j * 4) % 16, 9, 17 + j * 4);
			__MASTER_MD5_FUNCTION_GG(C, D, A, B, (11 + j * 4) % 16, 14, 18 + j * 4);
			__MASTER_MD5_FUNCTION_GG(B, C, D, A, j * 4, 20, 19 + j * 4);
		}
		
		for (j = 0; j < 4; j++) {
			__MASTER_MD5_FUNCTION_HH(A, B, C, D, (16 + (5 - j * 4)) % 16, 4, 32 + j * 4);
			__MASTER_MD5_FUNCTION_HH(D, A, B, C, (16 + (8 - j * 4)) % 16, 11, 33 + j * 4);
			__MASTER_MD5_FUNCTION_HH(C, D, A, B, (16 + (11 - j * 4)) % 16, 16, 34 + j * 4);
			__MASTER_MD5_FUNCTION_HH(B, C, D, A, (16 + (14 - j * 4)) % 16, 23, 35 + j * 4);
		}
		
		for (j = 0; j < 4; j++) {
			__MASTER_MD5_FUNCTION_II(A, B, C, D, (16 + (0 - j * 4)) % 16, 6, 48 + j * 4);
			__MASTER_MD5_FUNCTION_II(D, A, B, C, (16 + (7 - j * 4)) % 16, 10, 49 + j * 4);
			__MASTER_MD5_FUNCTION_II(C, D, A, B, (16 + (14 - j * 4)) % 16, 15, 50 + j * 4);
			__MASTER_MD5_FUNCTION_II(B, C, D, A, (16 + (5 - j * 4)) % 16, 21, 51 + j * 4);
		}
		
		A += AA;
		B += BB;
		C += CC;
		D += DD;
	}
	
	for (i = 0; i < 4; i++) hash_output[i] = (A >> (8*i)) & 0xFF;
	for (i = 0; i < 4; i++) hash_output[4 + i] = (B >> (8*i)) & 0xFF;
	for (i = 0; i < 4; i++) hash_output[8 + i] = (C >> (8*i)) & 0xFF;
	for (i = 0; i < 4; i++) hash_output[12 + i] = (D >> (8*i)) & 0xFF;
}

#undef __MASTER_MD5_FUNCTION_F
#undef __MASTER_MD5_FUNCTION_G
#undef __MASTER_MD5_FUNCTION_H
#undef __MASTER_MD5_FUNCTION_I
#undef __MASTER_MD5_FUNCTION_FF
#undef __MASTER_MD5_FUNCTION_GG
#undef __MASTER_MD5_FUNCTION_HH
#undef __MASTER_MD5_FUNCTION_II

// !# MD5

// #! MD6

static const UI8 MASTER_MD6_Q[] = {
	0x7311c2812425cfa0, 0x6432286434aac8e7, 0xb60450e9ef68b7c1, 0xe8fb23908d9f06f1, 
	0xdd2e76cba691e5bf, 0x0cd0d63b2c30bc41, 0x1f8ccf6823058f8a, 0x54e5ed5b88e3775d, 
	0x4ad12aae0a6d6031, 0x3e7f16bb88222e0d, 0x8af8671d3fb50c2c, 0x995ad1178bd25c31, 
	0xc878c1dd04c4b633, 0x3b72066c7a1552ac, 0x0d6f3522631effcb
};
// TODO

// !# MD6

// #! SHA-1

#define __MASTER_SHA1_FUNCTION_F(B, C, D) ((B & C) | ((~B) & D))
#define __MASTER_SHA1_FUNCTION_G(B, C, D) (B ^ C ^ D)
#define __MASTER_SHA1_FUNCTION_H(B, C, D) ((B & C) | (B & D) | (C & D))
#define __MASTER_SHA1_FUNCTION_I(B, C, D) (B ^ C ^ D)
#define __MASTER_SHA1_FUNCTION_FF(A, B, C, D, E, T) (MASTER_RLL32(A, 5) + __MASTER_SHA1_FUNCTION_F(B, C, D) + E + W[T] + 0x5A827999)
#define __MASTER_SHA1_FUNCTION_GG(A, B, C, D, E, T) (MASTER_RLL32(A, 5) + __MASTER_SHA1_FUNCTION_G(B, C, D) + E + W[T] + 0x6ED9EBA1)
#define __MASTER_SHA1_FUNCTION_HH(A, B, C, D, E, T) (MASTER_RLL32(A, 5) + __MASTER_SHA1_FUNCTION_H(B, C, D) + E + W[T] + 0x8F1BBCDC)
#define __MASTER_SHA1_FUNCTION_II(A, B, C, D, E, T) (MASTER_RLL32(A, 5) + __MASTER_SHA1_FUNCTION_I(B, C, D) + E + W[T] + 0xCA62C1D6)

typedef struct {
	UI4 __A, __B, __C, __D, __E;
	UI1 __buffer[64];
	UI8 __l;
} MASTER_SHA1;

MASTER_SHA1
MASTER_SHA1_Init(void) {
	MASTER_SHA1 __sha1;
	__sha1.__A = 0x67452301;
	__sha1.__B = 0xefcdab89;
	__sha1.__C = 0x98badcfe;
	__sha1.__D = 0x10325476;
	__sha1.__E = 0xc3d2e1f0;
	__sha1.__l = 0;
	return __sha1;
}

static void
__MASTER_SHA1_Transform(MASTER_SHA1 * __sha1) {
	UI4 W[80];
	UI4 buffer, j;
	UI4 AA, BB, CC, DD, EE;
	
	for (j = 0; j < 16; j++) 
		W[j] = (__sha1->__buffer[j * 4] << 24) | ((__sha1->__buffer[j * 4 + 1]) << 16) | ((__sha1->__buffer[j * 4 + 2]) << 8) | ((__sha1->__buffer[j * 4 + 3]));
	for (j = 16; j < 80; j++) 
		W[j] = MASTER_RLL32((W[j - 3] ^ W[j - 8] ^ W[j - 14] ^ W[j - 16]), 1);

	AA = __sha1->__A;
	BB = __sha1->__B;
	CC = __sha1->__C;
	DD = __sha1->__D;
	EE = __sha1->__E;
	
	for (j = 0; j < 80; j++) {
		if (j <= 19) {
			buffer = __MASTER_SHA1_FUNCTION_FF(__sha1->__A, __sha1->__B, __sha1->__C, __sha1->__D, __sha1->__E, j);
		} otherwise (j <= 39) {
			buffer = __MASTER_SHA1_FUNCTION_GG(__sha1->__A, __sha1->__B, __sha1->__C, __sha1->__D, __sha1->__E, j);
		} otherwise (j <= 59) {
			buffer = __MASTER_SHA1_FUNCTION_HH(__sha1->__A, __sha1->__B, __sha1->__C, __sha1->__D, __sha1->__E, j);
		} otherwise (j <= 79) {
			buffer = __MASTER_SHA1_FUNCTION_II(__sha1->__A, __sha1->__B, __sha1->__C, __sha1->__D, __sha1->__E, j);
		}
		__sha1->__E = __sha1->__D;
		__sha1->__D = __sha1->__C;
		__sha1->__C = MASTER_RLL32(__sha1->__B, 30);
		__sha1->__B =__sha1->__A;
		__sha1->__A = buffer;
	}
	
	__sha1->__A += AA;
	__sha1->__B += BB;
	__sha1->__C += CC;
	__sha1->__D += DD;
	__sha1->__E += EE;
}

void
MASTER_SHA1_Update(MASTER_SHA1 * __sha1, const char * __s, UI4 __l) {
	while (__l--) {
		__sha1->__buffer[__sha1->__l++ % 64] = *(__s++);
		if (__sha1->__l % 64 == 0)
			__MASTER_SHA1_Transform(__sha1);
	}
}

void
MASTER_SHA1_Final(MASTER_SHA1 * __sha1, UI1 * hash_output) {
	UI1 bits[8];
	UI4 index, padLen, i;

	bits[0] = ((__sha1->__l << 3) >> 56) & 0xff;
	bits[1] = ((__sha1->__l << 3) >> 48) & 0xff;
	bits[2] = ((__sha1->__l << 3) >> 40) & 0xff;
	bits[3] = ((__sha1->__l << 3) >> 32) & 0xff;
	bits[4] = ((__sha1->__l << 3) >> 24) & 0xff;
	bits[5] = ((__sha1->__l << 3) >> 16) & 0xff;
	bits[6] = ((__sha1->__l << 3) >> 8) & 0xff;
	bits[7] = ((__sha1->__l << 3)) & 0xff;
	
	index = ((__sha1->__l) & 0x3f);
	padLen = (index < 56) ? (56 - index) : (120 - index);
	const UI1 c = 0x80;
	MASTER_SHA1_Update(__sha1, (const char *)&c, 1);
	padLen--;
	while (padLen--) MASTER_SHA1_Update(__sha1, "\0", 1);
	
	MASTER_SHA1_Update(__sha1, (const char *)bits, 8);

	for (i = 0; i < 4; i++) hash_output[i] = (__sha1->__A >> (24 - 8*i)) & 0xFF;
	for (i = 0; i < 4; i++) hash_output[4 + i] = (__sha1->__B >> (24 - 8*i)) & 0xFF;
	for (i = 0; i < 4; i++) hash_output[8 + i] = (__sha1->__C >> (24 - 8*i)) & 0xFF;
	for (i = 0; i < 4; i++) hash_output[12 + i] = (__sha1->__D >> (24 - 8*i)) & 0xFF;
	for (i = 0; i < 4; i++) hash_output[16 + i] = (__sha1->__E >> (24 - 8*i)) & 0xFF;
}

void
MASTER_SHA1_CalculateHashSum(const char * __s, UI8 __l, UI1 * hash_output) {
	UI4 i, j;

	UI8 padding_bytes = ((__l * 8 + (8 * (56 - __l) % 512)) - __l * 8) / 8;

	UI1 * __M = (UI1 *)alloca( (__l + padding_bytes + 8) * sizeof(char));
	for (i = 0; i < __l; i++)
		__M[i] = __s[i];

	__M[__l] = 0x80;

	for (i = 0; i < padding_bytes - 1; i++)
		*(__M + __l + 1 + i) = 0;

	UI8 * length_append = (UI8 *)(__M + __l + padding_bytes);
	*length_append = ((((__l * 8)) & 0xFF) << 56) |
					 ((((__l * 8) >> 8) & 0xFF) << 48) |
					 ((((__l * 8) >> 16) & 0xFF) << 40) |
					 ((((__l * 8) >> 24) & 0xFF) << 32) |
					 ((((__l * 8) >> 32) & 0xFF) << 24) |
					 ((((__l * 8) >> 40) & 0xFF) << 16) |
					 ((((__l * 8) >> 48) & 0xFF) << 8) |
					 (((__l * 8) >> 56) & 0xFF) ;
	
	__l += (padding_bytes + 8);
	
	UI4 A = 0x67452301;
	UI4 B = 0xefcdab89;
	UI4 C = 0x98badcfe;
	UI4 D = 0x10325476;
	UI4 E = 0xc3d2e1f0;
	
	UI4 AA, BB, CC, DD, EE;
	
	UI4 W[80];
	UI4 buffer;
	for (i = 0; i < __l; i += 64) {
		for (j = 0; j < 16; j++) 
			W[j] = (__M[i + j * 4] << 24) | ((__M[i + j * 4 + 1]) << 16) | ((__M[i + j * 4 + 2]) << 8) | ((__M[i + j * 4 + 3]));
		for (j = 16; j < 80; j++) 
			W[j] = MASTER_RLL32((W[j - 3] ^ W[j - 8] ^ W[j - 14] ^ W[j - 16]), 1);

		AA = A;
		BB = B;
		CC = C;
		DD = D;
		EE = E;
		
		for (j = 0; j < 80; j++) {
			if (j <= 19) {
				buffer = __MASTER_SHA1_FUNCTION_FF(A, B, C, D, E, j);
			} otherwise (j <= 39) {
				buffer = __MASTER_SHA1_FUNCTION_GG(A, B, C, D, E, j);
			} otherwise (j <= 59) {
				buffer = __MASTER_SHA1_FUNCTION_HH(A, B, C, D, E, j);
			} otherwise (j <= 79) {
				buffer = __MASTER_SHA1_FUNCTION_II(A, B, C, D, E, j);
			}
			E = D;
			D = C;
			C = MASTER_RLL32(B, 30);
			B = A;
			A = buffer;
		}
		
		A += AA;
		B += BB;
		C += CC;
		D += DD;
		E += EE;
	}
	
	for (i = 0; i < 4; i++) hash_output[i] = (A >> (24 - 8*i)) & 0xFF;
	for (i = 0; i < 4; i++) hash_output[4 + i] = (B >> (24 - 8*i)) & 0xFF;
	for (i = 0; i < 4; i++) hash_output[8 + i] = (C >> (24 - 8*i)) & 0xFF;
	for (i = 0; i < 4; i++) hash_output[12 + i] = (D >> (24 - 8*i)) & 0xFF;
	for (i = 0; i < 4; i++) hash_output[16 + i] = (E >> (24 - 8*i)) & 0xFF;
}

#undef __MASTER_SHA1_FUNCTION_F
#undef __MASTER_SHA1_FUNCTION_G
#undef __MASTER_SHA1_FUNCTION_H
#undef __MASTER_SHA1_FUNCTION_I
#undef __MASTER_SHA1_FUNCTION_FF
#undef __MASTER_SHA1_FUNCTION_GG
#undef __MASTER_SHA1_FUNCTION_HH
#undef __MASTER_SHA1_FUNCTION_II

// !# SHA-1

// #! SHA-2

#define __MASTER_SHA2_FUNCTION_SIGMA0(A) ((MASTER_RLR32(A, 2)) ^ (MASTER_RLR32(A, 13)) ^ (MASTER_RLR32(A, 22)))
#define __MASTER_SHA2_FUNCTION_SIGMA1(A) ((MASTER_RLR32(E, 6)) ^ (MASTER_RLR32(E, 11)) ^ (MASTER_RLR32(E, 25)))
#define __MASTER_SHA2_FUNCTION_MAJ(A, B, C) ((A & B) ^ (A & C) ^ (B & C))
#define __MASTER_SHA2_FUNCTION_CH(E, F, G) ((E & F) ^ ((~E) & G))

static const UI4 MASTER_SHA2_TABLE_K[64] = {
	0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
	0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
	0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
	0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
	0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC,
	0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
	0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
	0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
	0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
	0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
	0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3,
	0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
	0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5,
	0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
	0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
	0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2
};

// #!! SHA-2-224

typedef struct {
	UI4 __H0, __H1, __H2, __H3,
					__H4, __H5, __H6, __H7;
	UI1 __buffer[64];
	UI8 __l;
} MASTER_SHA2_224;

MASTER_SHA2_224
MASTER_SHA2_224_Init(void) {
	MASTER_SHA2_224 __sha_2_224;
	__sha_2_224.__H0 = 0xC1059ED8;
	__sha_2_224.__H1 = 0x367CD507;
	__sha_2_224.__H2 = 0x3070DD17;
	__sha_2_224.__H3 = 0xF70E5939;
	__sha_2_224.__H4 = 0xFFC00B31;
	__sha_2_224.__H5 = 0x68581511;
	__sha_2_224.__H6 = 0x64F98FA7;
	__sha_2_224.__H7 = 0xBEFA4FA4;
	__sha_2_224.__l = 0;
	return __sha_2_224;
}

static void
__MASTER_SHA2_224_Transform(MASTER_SHA2_224 * __sha2_224) {
	UI4 A, B, C, D, E, F, G, H, j, t1, t2;
	
	UI4 W[64];
		for (j = 0; j < 16; j++) 
			W[j] = (__sha2_224->__buffer[j * 4] << 24) | ((__sha2_224->__buffer[j * 4 + 1]) << 16) | ((__sha2_224->__buffer[j * 4 + 2]) << 8) | ((__sha2_224->__buffer[j * 4 + 3]));
		for (j = 16; j < 64; j++) {
			UI4 s0 = (MASTER_RLR32(W[j - 15], 7)) ^ (MASTER_RLR32(W[j - 15], 18)) ^ (W[j - 15] >> 3);
					UI4 s1 = (MASTER_RLR32(W[j - 2], 17)) ^ (MASTER_RLR32(W[j - 2], 19)) ^ (W[j - 2] >> 10);
					W[j] = W[j - 16] + s0 + W[j - 7] + s1;
		}

		A = __sha2_224->__H0; B = __sha2_224->__H1;
		C = __sha2_224->__H2; D = __sha2_224->__H3;
		E = __sha2_224->__H4; F = __sha2_224->__H5;
		G = __sha2_224->__H6; H = __sha2_224->__H7;
		
		for (j = 0; j < 64; j++) {
			t1 = H + __MASTER_SHA2_FUNCTION_SIGMA1(A) + __MASTER_SHA2_FUNCTION_CH(E, F, G) + MASTER_SHA2_TABLE_K[j] + W[j];
			t2 = __MASTER_SHA2_FUNCTION_SIGMA0(A) + __MASTER_SHA2_FUNCTION_MAJ(A, B, C);

			H = G;
			G = F;
			F = E;
			E = D + t1;
			D = C;
			C = B;
			B = A;
			A = t1 + t2;
		}

		__sha2_224->__H0 += A;
		__sha2_224->__H1 += B;
		__sha2_224->__H2 += C;
		__sha2_224->__H3 += D;
		__sha2_224->__H4 += E;
		__sha2_224->__H5 += F;
		__sha2_224->__H6 += G;
		__sha2_224->__H7 += H;
}

void
MASTER_SHA2_224_Update(MASTER_SHA2_224 * __sha2_224, const char * __s, UI4 __l) {
	while (__l--) {
		__sha2_224->__buffer[__sha2_224->__l++ % 64] = *(__s++);
		if (__sha2_224->__l % 64 == 0)
			__MASTER_SHA2_224_Transform(__sha2_224);
	}
}

void
MASTER_SHA2_224_Final(MASTER_SHA2_224 * __sha2_224, UI1 * hash_output) {
	UI1 bits[8];
	UI4 index, padLen, i;

	bits[0] = ((__sha2_224->__l << 3) >> 56) & 0xff;
	bits[1] = ((__sha2_224->__l << 3) >> 48) & 0xff;
	bits[2] = ((__sha2_224->__l << 3) >> 40) & 0xff;
	bits[3] = ((__sha2_224->__l << 3) >> 32) & 0xff;
	bits[4] = ((__sha2_224->__l << 3) >> 24) & 0xff;
	bits[5] = ((__sha2_224->__l << 3) >> 16) & 0xff;
	bits[6] = ((__sha2_224->__l << 3) >> 8) & 0xff;
	bits[7] = ((__sha2_224->__l << 3)) & 0xff;
	
	index = ((__sha2_224->__l) & 0x3f);
	padLen = (index < 56) ? (56 - index) : (120 - index);
	const UI1 c = 0x80;
	MASTER_SHA2_224_Update(__sha2_224, (const char *)&c, 1);
	padLen--;
	while (padLen--) MASTER_SHA2_224_Update(__sha2_224, "\0", 1);
	
	MASTER_SHA2_224_Update(__sha2_224, (const char *)bits, 8);

	for (i = 0; i < 4; i++) hash_output[i] = (__sha2_224->__H0 >> (24 - 8*i)) & 0xFF;
	for (i = 0; i < 4; i++) hash_output[4 + i] = (__sha2_224->__H1 >> (24 - 8*i)) & 0xFF;
	for (i = 0; i < 4; i++) hash_output[8 + i] = (__sha2_224->__H2 >> (24 - 8*i)) & 0xFF;
	for (i = 0; i < 4; i++) hash_output[12 + i] = (__sha2_224->__H3 >> (24 - 8*i)) & 0xFF;
	for (i = 0; i < 4; i++) hash_output[16 + i] = (__sha2_224->__H4 >> (24 - 8*i)) & 0xFF;
	for (i = 0; i < 4; i++) hash_output[20 + i] = (__sha2_224->__H5 >> (24 - 8*i)) & 0xFF;
	for (i = 0; i < 4; i++) hash_output[24 + i] = (__sha2_224->__H6 >> (24 - 8*i)) & 0xFF;
}

void
MASTER_SHA2_224_CalculateHashSum(const char * __s, UI8 __l, UI1 * hash_output) {
	UI4 H0 = 0xC1059ED8;
	UI4 H1 = 0x367CD507;
	UI4 H2 = 0x3070DD17;
	UI4 H3 = 0xF70E5939;
	UI4 H4 = 0xFFC00B31;
	UI4 H5 = 0x68581511;
	UI4 H6 = 0x64F98FA7;
	UI4 H7 = 0xBEFA4FA4;
	
	UI4 i, j;

	UI8 padding_bytes = ((__l * 8 + (8 * (56 - __l) % 512)) - __l * 8) / 8;

	UI1 * __M = (UI1 *)alloca( (__l + padding_bytes + 8) * sizeof(char));
	for (i = 0; i < __l; i++)
		__M[i] = __s[i];

	__M[__l] = 0x80;

	for (i = 0; i < padding_bytes - 1; i++)
		*(__M + __l + 1 + i) = 0;

	UI8 * length_append = (UI8 *)(__M + __l + padding_bytes);
	*length_append = ((((__l * 8)) & 0xFF) << 56) |
					 ((((__l * 8) >> 8) & 0xFF) << 48) |
					 ((((__l * 8) >> 16) & 0xFF) << 40) |
					 ((((__l * 8) >> 24) & 0xFF) << 32) |
					 ((((__l * 8) >> 32) & 0xFF) << 24) |
					 ((((__l * 8) >> 40) & 0xFF) << 16) |
					 ((((__l * 8) >> 48) & 0xFF) << 8) |
					 (((__l * 8) >> 56) & 0xFF) ;
	
	__l += (padding_bytes + 8);
	
	UI4 A, B, C, D, E, F, G, H;
	
	UI4 W[64];
	UI4 t1, t2;
	for (i = 0; i < __l; i += 64) {
		for (j = 0; j < 16; j++) 
			W[j] = (__M[i + j * 4] << 24) | ((__M[i + j * 4 + 1]) << 16) | ((__M[i + j * 4 + 2]) << 8) | ((__M[i + j * 4 + 3]));
		for (j = 16; j < 64; j++) {
			UI4 s0 = (MASTER_RLR32(W[j - 15], 7)) ^ (MASTER_RLR32(W[j - 15], 18)) ^ (W[j - 15] >> 3);
					UI4 s1 = (MASTER_RLR32(W[j - 2], 17)) ^ (MASTER_RLR32(W[j - 2], 19)) ^ (W[j - 2] >> 10);
					W[j] = W[j - 16] + s0 + W[j - 7] + s1;
		}

		A = H0; B = H1; C = H2; D = H3;
		E = H4; F = H5; G = H6; H = H7;
		
		for (j = 0; j < 64; j++) {
			t1 = H + __MASTER_SHA2_FUNCTION_SIGMA1(A) + __MASTER_SHA2_FUNCTION_CH(E, F, G) + MASTER_SHA2_TABLE_K[j] + W[j];
			t2 = __MASTER_SHA2_FUNCTION_SIGMA0(A) + __MASTER_SHA2_FUNCTION_MAJ(A, B, C);

			H = G;
			G = F;
			F = E;
			E = D + t1;
			D = C;
			C = B;
			B = A;
			A = t1 + t2;
		}

		H0 += A;
		H1 += B;
		H2 += C;
		H3 += D;
		H4 += E;
		H5 += F;
		H6 += G;
		H7 += H;
	}
	
	for (i = 0; i < 4; i++) hash_output[i] = (H0 >> (24 - 8*i)) & 0xFF;
	for (i = 0; i < 4; i++) hash_output[4 + i] = (H1 >> (24 - 8*i)) & 0xFF;
	for (i = 0; i < 4; i++) hash_output[8 + i] = (H2 >> (24 - 8*i)) & 0xFF;
	for (i = 0; i < 4; i++) hash_output[12 + i] = (H3 >> (24 - 8*i)) & 0xFF;
	for (i = 0; i < 4; i++) hash_output[16 + i] = (H4 >> (24 - 8*i)) & 0xFF;
	for (i = 0; i < 4; i++) hash_output[20 + i] = (H5 >> (24 - 8*i)) & 0xFF;
	for (i = 0; i < 4; i++) hash_output[24 + i] = (H6 >> (24 - 8*i)) & 0xFF;
}

// !!# SHA-2-224

// #!! SHA-2-256

typedef struct {
	UI4 __H0, __H1, __H2, __H3,
				  __H4, __H5, __H6, __H7;
	UI1 __buffer[64];
	UI8 __l;
} MASTER_SHA2_256;

MASTER_SHA2_256
MASTER_SHA2_256_Init(void) {
	MASTER_SHA2_256 __sha2_256;
	__sha2_256.__H0 = 0x6A09E667;
	__sha2_256.__H1 = 0xBB67AE85;
	__sha2_256.__H2 = 0x3C6EF372;
	__sha2_256.__H3 = 0xA54FF53A;
	__sha2_256.__H4 = 0x510E527F;
	__sha2_256.__H5 = 0x9B05688C;
	__sha2_256.__H6 = 0x1F83D9AB;
	__sha2_256.__H7 = 0x5BE0CD19;
	__sha2_256.__l = 0;
	return __sha2_256;
}

static void
__MASTER_SHA2_256_Transform(MASTER_SHA2_256 * __sha2_256) {
	UI4 A, B, C, D, E, F, G, H, j, t1, t2;
	
	UI4 W[64];
	for (j = 0; j < 16; j++) 
		W[j] = (__sha2_256->__buffer[j * 4] << 24) | ((__sha2_256->__buffer[j * 4 + 1]) << 16) | ((__sha2_256->__buffer[j * 4 + 2]) << 8) | ((__sha2_256->__buffer[j * 4 + 3]));
	for (j = 16; j < 64; j++) {
		UI4 s0 = (MASTER_RLR32(W[j - 15], 7)) ^ (MASTER_RLR32(W[j - 15], 18)) ^ (W[j - 15] >> 3);
		UI4 s1 = (MASTER_RLR32(W[j - 2], 17)) ^ (MASTER_RLR32(W[j - 2], 19)) ^ (W[j - 2] >> 10);
		W[j] = W[j - 16] + s0 + W[j - 7] + s1;
	}

	A = __sha2_256->__H0; B = __sha2_256->__H1;
	C = __sha2_256->__H2; D = __sha2_256->__H3;
	E = __sha2_256->__H4; F = __sha2_256->__H5;
	G = __sha2_256->__H6; H = __sha2_256->__H7;
	
	for (j = 0; j < 64; j++) {
		t1 = H + __MASTER_SHA2_FUNCTION_SIGMA1(A) + __MASTER_SHA2_FUNCTION_CH(E, F, G) + MASTER_SHA2_TABLE_K[j] + W[j];
		t2 = __MASTER_SHA2_FUNCTION_SIGMA0(A) + __MASTER_SHA2_FUNCTION_MAJ(A, B, C);

		H = G;
		G = F;
		F = E;
		E = D + t1;
		D = C;
		C = B;
		B = A;
		A = t1 + t2;
	}

	__sha2_256->__H0 += A;
	__sha2_256->__H1 += B;
	__sha2_256->__H2 += C;
	__sha2_256->__H3 += D;
	__sha2_256->__H4 += E;
	__sha2_256->__H5 += F;
	__sha2_256->__H6 += G;
	__sha2_256->__H7 += H;
}

void
MASTER_SHA2_256_Update(MASTER_SHA2_256 * __sha2_256, const char * __s, UI4 __l) {
	while (__l--) {
		__sha2_256->__buffer[__sha2_256->__l++ % 64] = *(__s++);
		if (__sha2_256->__l % 64 == 0)
			__MASTER_SHA2_256_Transform(__sha2_256);
	}
}

void
MASTER_SHA2_256_Final(MASTER_SHA2_256 * __sha2_256, UI1 * hash_output) {
	UI1 bits[8];
	UI4 index, padLen, i;

	bits[0] = ((__sha2_256->__l << 3) >> 56) & 0xff;
	bits[1] = ((__sha2_256->__l << 3) >> 48) & 0xff;
	bits[2] = ((__sha2_256->__l << 3) >> 40) & 0xff;
	bits[3] = ((__sha2_256->__l << 3) >> 32) & 0xff;
	bits[4] = ((__sha2_256->__l << 3) >> 24) & 0xff;
	bits[5] = ((__sha2_256->__l << 3) >> 16) & 0xff;
	bits[6] = ((__sha2_256->__l << 3) >> 8) & 0xff;
	bits[7] = ((__sha2_256->__l << 3)) & 0xff;
	
	index = ((__sha2_256->__l) & 0x3f);
	padLen = (index < 56) ? (56 - index) : (120 - index);
	const UI1 c = 0x80;
	MASTER_SHA2_256_Update(__sha2_256, (const char *)&c, 1);
	padLen--;
	while (padLen--) MASTER_SHA2_256_Update(__sha2_256, "\0", 1);
	
	MASTER_SHA2_256_Update(__sha2_256, (const char *)bits, 8);

	for (i = 0; i < 4; i++) hash_output[i] = (__sha2_256->__H0 >> (24 - 8*i)) & 0xFF;
	for (i = 0; i < 4; i++) hash_output[4 + i] = (__sha2_256->__H1 >> (24 - 8*i)) & 0xFF;
	for (i = 0; i < 4; i++) hash_output[8 + i] = (__sha2_256->__H2 >> (24 - 8*i)) & 0xFF;
	for (i = 0; i < 4; i++) hash_output[12 + i] = (__sha2_256->__H3 >> (24 - 8*i)) & 0xFF;
	for (i = 0; i < 4; i++) hash_output[16 + i] = (__sha2_256->__H4 >> (24 - 8*i)) & 0xFF;
	for (i = 0; i < 4; i++) hash_output[20 + i] = (__sha2_256->__H5 >> (24 - 8*i)) & 0xFF;
	for (i = 0; i < 4; i++) hash_output[24 + i] = (__sha2_256->__H6 >> (24 - 8*i)) & 0xFF;
	for (i = 0; i < 4; i++) hash_output[28 + i] = (__sha2_256->__H7 >> (24 - 8*i)) & 0xFF;
}

void
MASTER_SHA2_256_CalculateHashSum(const char * __s, UI8 __l, UI1 * hash_output) {
	UI4 H0 = 0x6A09E667;
	UI4 H1 = 0xBB67AE85;
	UI4 H2 = 0x3C6EF372;
	UI4 H3 = 0xA54FF53A;
	UI4 H4 = 0x510E527F;
	UI4 H5 = 0x9B05688C;
	UI4 H6 = 0x1F83D9AB;
	UI4 H7 = 0x5BE0CD19;
	
	UI4 i, j;

	UI8 padding_bytes = ((__l * 8 + (8 * (56 - __l) % 512)) - __l * 8) / 8;

	UI1 * __M = (UI1 *)alloca( (__l + padding_bytes + 8) * sizeof(char));
	for (i = 0; i < __l; i++)
		__M[i] = __s[i];

	__M[__l] = 0x80;

	for (i = 0; i < padding_bytes - 1; i++)
		*(__M + __l + 1 + i) = 0;

	UI8 * length_append = (UI8 *)(__M + __l + padding_bytes);
	*length_append = ((((__l * 8)) & 0xFF) << 56) |
					 ((((__l * 8) >> 8) & 0xFF) << 48) |
					 ((((__l * 8) >> 16) & 0xFF) << 40) |
					 ((((__l * 8) >> 24) & 0xFF) << 32) |
					 ((((__l * 8) >> 32) & 0xFF) << 24) |
					 ((((__l * 8) >> 40) & 0xFF) << 16) |
					 ((((__l * 8) >> 48) & 0xFF) << 8) |
					 (((__l * 8) >> 56) & 0xFF) ;
	
	__l += (padding_bytes + 8);
	
	
	UI4 A, B, C, D, E, F, G, H;
	
	UI4 W[64];
	UI4 t1, t2;
	for (i = 0; i < __l; i += 64) {
		for (j = 0; j < 16; j++) 
			W[j] = (__M[i + j * 4] << 24) | ((__M[i + j * 4 + 1]) << 16) | ((__M[i + j * 4 + 2]) << 8) | ((__M[i + j * 4 + 3]));
		for (j = 16; j < 64; j++) {
			UI4 s0 = (MASTER_RLR32(W[j - 15], 7)) ^ (MASTER_RLR32(W[j - 15], 18)) ^ (W[j - 15] >> 3);
					UI4 s1 = (MASTER_RLR32(W[j - 2], 17)) ^ (MASTER_RLR32(W[j - 2], 19)) ^ (W[j - 2] >> 10);
					W[j] = W[j - 16] + s0 + W[j - 7] + s1;
		}

		A = H0; B = H1; C = H2; D = H3;
		E = H4; F = H5; G = H6; H = H7;
		
		for (j = 0; j < 64; j++) {
			t1 = H + __MASTER_SHA2_FUNCTION_SIGMA1(A) + __MASTER_SHA2_FUNCTION_CH(E, F, G) + MASTER_SHA2_TABLE_K[j] + W[j];
			t2 = __MASTER_SHA2_FUNCTION_SIGMA0(A) + __MASTER_SHA2_FUNCTION_MAJ(A, B, C);

			H = G;
			G = F;
			F = E;
			E = D + t1;
			D = C;
			C = B;
			B = A;
			A = t1 + t2;
		}

		H0 += A;
		H1 += B;
		H2 += C;
		H3 += D;
		H4 += E;
		H5 += F;
		H6 += G;
		H7 += H;
	}
	
	for (i = 0; i < 4; i++) hash_output[i] = (H0 >> (24 - 8*i)) & 0xFF;
	for (i = 0; i < 4; i++) hash_output[4 + i] = (H1 >> (24 - 8*i)) & 0xFF;
	for (i = 0; i < 4; i++) hash_output[8 + i] = (H2 >> (24 - 8*i)) & 0xFF;
	for (i = 0; i < 4; i++) hash_output[12 + i] = (H3 >> (24 - 8*i)) & 0xFF;
	for (i = 0; i < 4; i++) hash_output[16 + i] = (H4 >> (24 - 8*i)) & 0xFF;
	for (i = 0; i < 4; i++) hash_output[20 + i] = (H5 >> (24 - 8*i)) & 0xFF;
	for (i = 0; i < 4; i++) hash_output[24 + i] = (H6 >> (24 - 8*i)) & 0xFF;
	for (i = 0; i < 4; i++) hash_output[28 + i] = (H7 >> (24 - 8*i)) & 0xFF;
}

// !!# SHA-2-256

// #!! SHA-2-512

#define __MASTER_SHA2_512_FUNCTION_SIGMA0(A) ((MASTER_RLR64(A, 28)) ^ (MASTER_RLR64(A, 34)) ^ (MASTER_RLR64(A, 39)))
#define __MASTER_SHA2_512_FUNCTION_SIGMA1(A) ((MASTER_RLR64(E, 14)) ^ (MASTER_RLR64(E, 18)) ^ (MASTER_RLR64(E, 41)))
#define __MASTER_SHA2_512_FUNCTION_MAJ(A, B, C) ((A & B) ^ (A & C) ^ (B & C))
#define __MASTER_SHA2_512_FUNCTION_CH(E, F, G) ((E & F) ^ ((~E) & G))

typedef struct {
	UI8 __H0, __H1, __H2, __H3,
					   __H4, __H5, __H6, __H7;
	UI1 __buffer[128];
	UI8 __l;
} MASTER_SHA2_512;

MASTER_SHA2_512
MASTER_SHA2_512_Init(void) {
	MASTER_SHA2_512 __sha2_512;
	__sha2_512.__H0 = 0x6a09e667f3bcc908;
	__sha2_512.__H1 = 0xbb67ae8584caa73b;
	__sha2_512.__H2 = 0x3c6ef372fe94f82b;
	__sha2_512.__H3 = 0xa54ff53a5f1d36f1;
	__sha2_512.__H4 = 0x510e527fade682d1;
	__sha2_512.__H5 = 0x9b05688c2b3e6c1f;
	__sha2_512.__H6 = 0x1f83d9abfb41bd6b;
	__sha2_512.__H7 = 0x5be0cd19137e2179;
	__sha2_512.__l = 0;
	return __sha2_512;
}

static const UI8 MASTER_SHA2_512_TABLE_K[80] = {
	0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc, 0x3956c25bf348b538, 
	0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 0xd807aa98a3030242, 0x12835b0145706fbe, 
	0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2, 0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 
	0xc19bf174cf692694, 0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65, 
	0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5, 0x983e5152ee66dfab, 
	0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2, 0xd5a79147930aa725, 
	0x06ca6351e003826f, 0x142929670a0e6e70, 0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 
	0x53380d139d95b3df, 0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b, 
	0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218, 
	0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8, 0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 
	0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 
	0x682e6ff3d6b2b8a3, 0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec, 
	0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b, 0xca273eceea26619c, 
	0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba, 0x0a637dc5a2c898a6, 
	0x113f9804bef90dae, 0x1b710b35131c471b, 0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 
	0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
};

static void
__MASTER_SHA2_512_Transform(MASTER_SHA2_512 * __sha2_512) {
	UI8 A, B, C, D, E, F, G, H;
	UI4 j;
	
	UI8 W[80];
	UI8 t1, t2;
	for (j = 0; j < 16; j++) {
		W[j] = (((UI8)__sha2_512->__buffer[j * 8 + 7]) << 0) |
				 (((UI8)__sha2_512->__buffer[j * 8 + 6]) << 8) |
				 (((UI8)__sha2_512->__buffer[j * 8 + 5]) << 16) |
				 (((UI8)__sha2_512->__buffer[j * 8 + 4]) << 24) |
				 (((UI8)__sha2_512->__buffer[j * 8 + 3]) << 32) |
				 (((UI8)__sha2_512->__buffer[j * 8 + 2]) << 40) |
				 (((UI8)__sha2_512->__buffer[j * 8 + 1]) << 48) |
				 (((UI8)__sha2_512->__buffer[j * 8 + 0]) << 56);
	}
	for (j = 16; j < 80; j++) {
		UI8 s0 = (MASTER_RLR64(W[j - 15], 1)) ^ (MASTER_RLR64(W[j - 15], 8)) ^ (W[j - 15] >> 7);
		UI8 s1 = (MASTER_RLR64(W[j - 2], 19)) ^ (MASTER_RLR64(W[j - 2], 61)) ^ (W[j - 2] >> 6);
		W[j] = W[j - 16] + s0 + W[j - 7] + s1;
	}

	A = __sha2_512->__H0; B = __sha2_512->__H1; C = __sha2_512->__H2; D = __sha2_512->__H3;
	E = __sha2_512->__H4; F = __sha2_512->__H5; G = __sha2_512->__H6; H = __sha2_512->__H7;
	
	for (j = 0; j < 80; j++) {
		t1 = H + __MASTER_SHA2_512_FUNCTION_SIGMA1(A) + __MASTER_SHA2_FUNCTION_CH(E, F, G) + MASTER_SHA2_512_TABLE_K[j] + W[j];
		t2 = __MASTER_SHA2_512_FUNCTION_SIGMA0(A) + __MASTER_SHA2_FUNCTION_MAJ(A, B, C);

		H = G;
		G = F;
		F = E;
		E = D + t1;
		D = C;
		C = B;
		B = A;
		A = t1 + t2;
	}

	__sha2_512->__H0 += A;
	__sha2_512->__H1 += B;
	__sha2_512->__H2 += C;
	__sha2_512->__H3 += D;
	__sha2_512->__H4 += E;
	__sha2_512->__H5 += F;
	__sha2_512->__H6 += G;
	__sha2_512->__H7 += H;
}

void
MASTER_SHA2_512_Update(MASTER_SHA2_512 * __sha2_512, const char * __s, UI4 __l) {
	while (__l--) {
		__sha2_512->__buffer[__sha2_512->__l++ % 128] = *(__s++);
		if (__sha2_512->__l % 128 == 0)
			__MASTER_SHA2_512_Transform(__sha2_512);
	}
}

void
MASTER_SHA2_512_Final(MASTER_SHA2_512 * __sha2_512, UI1 * hash_output) {
	UI1 bits[8];
	UI4 mdi, padding_len, i;
	
	bits[0] = ((__sha2_512->__l << 3) >> 56) & 0xff;
	bits[1] = ((__sha2_512->__l << 3) >> 48) & 0xff;
	bits[2] = ((__sha2_512->__l << 3) >> 40) & 0xff;
	bits[3] = ((__sha2_512->__l << 3) >> 32) & 0xff;
	bits[4] = ((__sha2_512->__l << 3) >> 24) & 0xff;
	bits[5] = ((__sha2_512->__l << 3) >> 16) & 0xff;
	bits[6] = ((__sha2_512->__l << 3) >> 8) & 0xff;
	bits[7] = ((__sha2_512->__l << 3)) & 0xff;
	
	mdi = __sha2_512->__l % 128;
	padding_len = (mdi < 112) ? 119 - mdi : 247 - mdi;
	const UI1 c = 0x80;
	MASTER_SHA2_512_Update(__sha2_512, (const char *)&c, 1);
	while (padding_len--) MASTER_SHA2_512_Update(__sha2_512, "\0", 1);
	
	MASTER_SHA2_512_Update(__sha2_512, (const char *)bits, 8);
	
	for (i = 0; i < 8; i++) hash_output[i] = (__sha2_512->__H0 >> (56 - 8*i)) & 0xFF;
	for (i = 0; i < 8; i++) hash_output[8 + i] = (__sha2_512->__H1 >> (56 - 8*i)) & 0xFF;
	for (i = 0; i < 8; i++) hash_output[16 + i] = (__sha2_512->__H2 >> (56 - 8*i)) & 0xFF;
	for (i = 0; i < 8; i++) hash_output[24 + i] = (__sha2_512->__H3 >> (56 - 8*i)) & 0xFF;
	for (i = 0; i < 8; i++) hash_output[32 + i] = (__sha2_512->__H4 >> (56 - 8*i)) & 0xFF;
	for (i = 0; i < 8; i++) hash_output[40 + i] = (__sha2_512->__H5 >> (56 - 8*i)) & 0xFF;
	for (i = 0; i < 8; i++) hash_output[48 + i] = (__sha2_512->__H6 >> (56 - 8*i)) & 0xFF;
	for (i = 0; i < 8; i++) hash_output[56 + i] = (__sha2_512->__H7 >> (56 - 8*i)) & 0xFF;
}

void
MASTER_SHA2_512_CalculateHashSum(const char * __s, UI8 __l, UI1 * hash_output) {
	UI8 H0 = 0x6a09e667f3bcc908;
	UI8 H1 = 0xbb67ae8584caa73b;
	UI8 H2 = 0x3c6ef372fe94f82b;
	UI8 H3 = 0xa54ff53a5f1d36f1;
	UI8 H4 = 0x510e527fade682d1;
	UI8 H5 = 0x9b05688c2b3e6c1f;
	UI8 H6 = 0x1f83d9abfb41bd6b;
	UI8 H7 = 0x5be0cd19137e2179;
	
	UI4 i, j;

	UI8 mdi = __l % 128;
	UI8 padding_len = (mdi < 112) ? 119 - mdi : 247 - mdi;

	UI1 * __M = (UI1 *)alloca( (__l + padding_len + 8) * sizeof(char));
	for (i = 0; i < __l; i++)
		__M[i] = __s[i];

	__M[__l] = 0x80;
	for (i = 0; i < padding_len - 1; i++)
		*(__M + __l + 1 + i) = 0;

	UI8 * length_append = (UI8 *)(__M + __l + padding_len + 1);
	*length_append = ((((__l * 8)) & 0xFF) << 56) |
					 ((((__l * 8) >> 8) & 0xFF) << 48) |
					 ((((__l * 8) >> 16) & 0xFF) << 40) |
					 ((((__l * 8) >> 24) & 0xFF) << 32) |
					 ((((__l * 8) >> 32) & 0xFF) << 24) |
					 ((((__l * 8) >> 40) & 0xFF) << 16) |
					 ((((__l * 8) >> 48) & 0xFF) << 8) |
					 (((__l * 8) >> 56) & 0xFF);
	
	__l += (padding_len + 9);
	
	UI8 A, B, C, D, E, F, G, H;
	
	UI8 W[80];
	UI8 t1, t2;
	for (i = 0; i < __l; i += 128) {
		for (j = 0; j < 16; j++) {
			W[j] = (((UI8)__M[i + j * 8 + 7]) << 0) |
					 (((UI8)__M[i + j * 8 + 6]) << 8) |
					 (((UI8)__M[i + j * 8 + 5]) << 16) |
					 (((UI8)__M[i + j * 8 + 4]) << 24) |
					 (((UI8)__M[i + j * 8 + 3]) << 32) |
					 (((UI8)__M[i + j * 8 + 2]) << 40) |
					 (((UI8)__M[i + j * 8 + 1]) << 48) |
					 (((UI8)__M[i + j * 8 + 0]) << 56);
		}
		for (j = 16; j < 80; j++) {
			UI8 s0 = (MASTER_RLR64(W[j - 15], 1)) ^ (MASTER_RLR64(W[j - 15], 8)) ^ (W[j - 15] >> 7);
					UI8 s1 = (MASTER_RLR64(W[j - 2], 19)) ^ (MASTER_RLR64(W[j - 2], 61)) ^ (W[j - 2] >> 6);
					W[j] = W[j - 16] + s0 + W[j - 7] + s1;
		}

		A = H0; B = H1; C = H2; D = H3;
		E = H4; F = H5; G = H6; H = H7;
		
		for (j = 0; j < 80; j++) {
			t1 = H + __MASTER_SHA2_512_FUNCTION_SIGMA1(A) + __MASTER_SHA2_FUNCTION_CH(E, F, G) + MASTER_SHA2_512_TABLE_K[j] + W[j];
			t2 = __MASTER_SHA2_512_FUNCTION_SIGMA0(A) + __MASTER_SHA2_FUNCTION_MAJ(A, B, C);

			H = G;
			G = F;
			F = E;
			E = D + t1;
			D = C;
			C = B;
			B = A;
			A = t1 + t2;
		}

		H0 += A;
		H1 += B;
		H2 += C;
		H3 += D;
		H4 += E;
		H5 += F;
		H6 += G;
		H7 += H;
	}
	
	for (i = 0; i < 8; i++) hash_output[i] = (H0 >> (56 - 8*i)) & 0xFF;
	for (i = 0; i < 8; i++) hash_output[8 + i] = (H1 >> (56 - 8*i)) & 0xFF;
	for (i = 0; i < 8; i++) hash_output[16 + i] = (H2 >> (56 - 8*i)) & 0xFF;
	for (i = 0; i < 8; i++) hash_output[24 + i] = (H3 >> (56 - 8*i)) & 0xFF;
	for (i = 0; i < 8; i++) hash_output[32 + i] = (H4 >> (56 - 8*i)) & 0xFF;
	for (i = 0; i < 8; i++) hash_output[40 + i] = (H5 >> (56 - 8*i)) & 0xFF;
	for (i = 0; i < 8; i++) hash_output[48 + i] = (H6 >> (56 - 8*i)) & 0xFF;
	for (i = 0; i < 8; i++) hash_output[56 + i] = (H7 >> (56 - 8*i)) & 0xFF;
}

// !!# SHA-2-512

// #!! SHA-2-384

typedef struct {
	UI8 __H0, __H1, __H2, __H3,
						 __H4, __H5, __H6, __H7;
	UI1 __buffer[128];
	UI8 __l;
} MASTER_SHA2_384;

MASTER_SHA2_384
MASTER_SHA2_384_Init(void) {
	MASTER_SHA2_384 __sha2_384;
	__sha2_384.__H0 = 0xcbbb9d5dc1059ed8;
	__sha2_384.__H1 = 0x629a292a367cd507;
	__sha2_384.__H2 = 0x9159015a3070dd17;
	__sha2_384.__H3 = 0x152fecd8f70e5939;
	__sha2_384.__H4 = 0x67332667ffc00b31;
	__sha2_384.__H5 = 0x8eb44a8768581511;
	__sha2_384.__H6 = 0xdb0c2e0d64f98fa7;
	__sha2_384.__H7 = 0x47b5481dbefa4fa4;
	__sha2_384.__l = 0;
	return __sha2_384;
}

static void
__MASTER_SHA2_384_Transform(MASTER_SHA2_384 * __sha2_384) {
	UI8 A, B, C, D, E, F, G, H;
	UI4 j;
	
	UI8 W[80];
	UI8 t1, t2;
	for (j = 0; j < 16; j++) {
		W[j] = (((UI8)__sha2_384->__buffer[j * 8 + 7]) << 0) |
				 (((UI8)__sha2_384->__buffer[j * 8 + 6]) << 8) |
				 (((UI8)__sha2_384->__buffer[j * 8 + 5]) << 16) |
				 (((UI8)__sha2_384->__buffer[j * 8 + 4]) << 24) |
				 (((UI8)__sha2_384->__buffer[j * 8 + 3]) << 32) |
				 (((UI8)__sha2_384->__buffer[j * 8 + 2]) << 40) |
				 (((UI8)__sha2_384->__buffer[j * 8 + 1]) << 48) |
				 (((UI8)__sha2_384->__buffer[j * 8 + 0]) << 56);
	}
	for (j = 16; j < 80; j++) {
		UI8 s0 = (MASTER_RLR64(W[j - 15], 1)) ^ (MASTER_RLR64(W[j - 15], 8)) ^ (W[j - 15] >> 7);
		UI8 s1 = (MASTER_RLR64(W[j - 2], 19)) ^ (MASTER_RLR64(W[j - 2], 61)) ^ (W[j - 2] >> 6);
		W[j] = W[j - 16] + s0 + W[j - 7] + s1;
	}

	A = __sha2_384->__H0; B = __sha2_384->__H1; C = __sha2_384->__H2; D = __sha2_384->__H3;
	E = __sha2_384->__H4; F = __sha2_384->__H5; G = __sha2_384->__H6; H = __sha2_384->__H7;
	
	for (j = 0; j < 80; j++) {
		t1 = H + __MASTER_SHA2_512_FUNCTION_SIGMA1(A) + __MASTER_SHA2_FUNCTION_CH(E, F, G) + MASTER_SHA2_512_TABLE_K[j] + W[j];
		t2 = __MASTER_SHA2_512_FUNCTION_SIGMA0(A) + __MASTER_SHA2_FUNCTION_MAJ(A, B, C);

		H = G;
		G = F;
		F = E;
		E = D + t1;
		D = C;
		C = B;
		B = A;
		A = t1 + t2;
	}

	__sha2_384->__H0 += A;
	__sha2_384->__H1 += B;
	__sha2_384->__H2 += C;
	__sha2_384->__H3 += D;
	__sha2_384->__H4 += E;
	__sha2_384->__H5 += F;
	__sha2_384->__H6 += G;
	__sha2_384->__H7 += H;
}

void
MASTER_SHA2_384_Update(MASTER_SHA2_384 * __sha2_384, const char * __s, UI4 __l) {
	while (__l--) {
		__sha2_384->__buffer[__sha2_384->__l++ % 128] = *(__s++);
		if (__sha2_384->__l % 128 == 0)
			__MASTER_SHA2_384_Transform(__sha2_384);
	}
}

void
MASTER_SHA2_384_Final(MASTER_SHA2_384 * __sha2_384, UI1 * hash_output) {
	UI1 bits[8];
	UI4 mdi, padding_len, i;
	
	bits[0] = ((__sha2_384->__l << 3) >> 56) & 0xff;
	bits[1] = ((__sha2_384->__l << 3) >> 48) & 0xff;
	bits[2] = ((__sha2_384->__l << 3) >> 40) & 0xff;
	bits[3] = ((__sha2_384->__l << 3) >> 32) & 0xff;
	bits[4] = ((__sha2_384->__l << 3) >> 24) & 0xff;
	bits[5] = ((__sha2_384->__l << 3) >> 16) & 0xff;
	bits[6] = ((__sha2_384->__l << 3) >> 8) & 0xff;
	bits[7] = ((__sha2_384->__l << 3)) & 0xff;
	
	mdi = __sha2_384->__l % 128;
	padding_len = (mdi < 112) ? 119 - mdi : 247 - mdi;
	const UI1 c = 0x80;
	MASTER_SHA2_384_Update(__sha2_384, (const char *)&c, 1);
	while (padding_len--) MASTER_SHA2_384_Update(__sha2_384, "\0", 1);
	
	MASTER_SHA2_384_Update(__sha2_384, (const char *)bits, 8);
	
	for (i = 0; i < 8; i++) hash_output[i] = (__sha2_384->__H0 >> (56 - 8*i)) & 0xFF;
	for (i = 0; i < 8; i++) hash_output[8 + i] = (__sha2_384->__H1 >> (56 - 8*i)) & 0xFF;
	for (i = 0; i < 8; i++) hash_output[16 + i] = (__sha2_384->__H2 >> (56 - 8*i)) & 0xFF;
	for (i = 0; i < 8; i++) hash_output[24 + i] = (__sha2_384->__H3 >> (56 - 8*i)) & 0xFF;
	for (i = 0; i < 8; i++) hash_output[32 + i] = (__sha2_384->__H4 >> (56 - 8*i)) & 0xFF;
	for (i = 0; i < 8; i++) hash_output[40 + i] = (__sha2_384->__H5 >> (56 - 8*i)) & 0xFF;
}

void
MASTER_SHA2_384_CalculateHashSum(const char * __s, UI8 __l, UI1 * hash_output) {
	UI8 H0 = 0xcbbb9d5dc1059ed8;
	UI8 H1 = 0x629a292a367cd507;
	UI8 H2 = 0x9159015a3070dd17;
	UI8 H3 = 0x152fecd8f70e5939;
	UI8 H4 = 0x67332667ffc00b31;
	UI8 H5 = 0x8eb44a8768581511;
	UI8 H6 = 0xdb0c2e0d64f98fa7;
	UI8 H7 = 0x47b5481dbefa4fa4;
	
	UI4 i, j;

	UI8 mdi = __l % 128;
	UI8 padding_len = (mdi < 112) ? 119 - mdi : 247 - mdi;

	UI1 * __M = (UI1 *)alloca( (__l + padding_len + 8) * sizeof(char));
	for (i = 0; i < __l; i++)
		__M[i] = __s[i];

	__M[__l] = 0x80;
	for (i = 0; i < padding_len - 1; i++)
		*(__M + __l + 1 + i) = 0;

	UI8 * length_append = (UI8 *)(__M + __l + padding_len + 1);
	*length_append = ((((__l * 8)) & 0xFF) << 56) |
					 ((((__l * 8) >> 8) & 0xFF) << 48) |
					 ((((__l * 8) >> 16) & 0xFF) << 40) |
					 ((((__l * 8) >> 24) & 0xFF) << 32) |
					 ((((__l * 8) >> 32) & 0xFF) << 24) |
					 ((((__l * 8) >> 40) & 0xFF) << 16) |
					 ((((__l * 8) >> 48) & 0xFF) << 8) |
					 (((__l * 8) >> 56) & 0xFF);
	
	__l += (padding_len + 9);
	
	UI8 A, B, C, D, E, F, G, H;
	
	UI8 W[80];
	UI8 t1, t2;
	for (i = 0; i < __l; i += 128) {
		for (j = 0; j < 16; j++) {
			W[j] = (((UI8)__M[i + j * 8 + 7]) << 0) |
					 (((UI8)__M[i + j * 8 + 6]) << 8) |
					 (((UI8)__M[i + j * 8 + 5]) << 16) |
					 (((UI8)__M[i + j * 8 + 4]) << 24) |
					 (((UI8)__M[i + j * 8 + 3]) << 32) |
					 (((UI8)__M[i + j * 8 + 2]) << 40) |
					 (((UI8)__M[i + j * 8 + 1]) << 48) |
					 (((UI8)__M[i + j * 8 + 0]) << 56);
		}
		for (j = 16; j < 80; j++) {
			UI8 s0 = (MASTER_RLR64(W[j - 15], 1)) ^ (MASTER_RLR64(W[j - 15], 8)) ^ (W[j - 15] >> 7);
					UI8 s1 = (MASTER_RLR64(W[j - 2], 19)) ^ (MASTER_RLR64(W[j - 2], 61)) ^ (W[j - 2] >> 6);
					W[j] = W[j - 16] + s0 + W[j - 7] + s1;
		}

		A = H0; B = H1; C = H2; D = H3;
		E = H4; F = H5; G = H6; H = H7;
		
		for (j = 0; j < 80; j++) {
			t1 = H + __MASTER_SHA2_512_FUNCTION_SIGMA1(A) + __MASTER_SHA2_FUNCTION_CH(E, F, G) + MASTER_SHA2_512_TABLE_K[j] + W[j];
			t2 = __MASTER_SHA2_512_FUNCTION_SIGMA0(A) + __MASTER_SHA2_FUNCTION_MAJ(A, B, C);

			H = G;
			G = F;
			F = E;
			E = D + t1;
			D = C;
			C = B;
			B = A;
			A = t1 + t2;
		}

		H0 += A;
		H1 += B;
		H2 += C;
		H3 += D;
		H4 += E;
		H5 += F;
		H6 += G;
		H7 += H;
	}
	
	for (i = 0; i < 8; i++) hash_output[i] = (H0 >> (56 - 8*i)) & 0xFF;
	for (i = 0; i < 8; i++) hash_output[8 + i] = (H1 >> (56 - 8*i)) & 0xFF;
	for (i = 0; i < 8; i++) hash_output[16 + i] = (H2 >> (56 - 8*i)) & 0xFF;
	for (i = 0; i < 8; i++) hash_output[24 + i] = (H3 >> (56 - 8*i)) & 0xFF;
	for (i = 0; i < 8; i++) hash_output[32 + i] = (H4 >> (56 - 8*i)) & 0xFF;
	for (i = 0; i < 8; i++) hash_output[40 + i] = (H5 >> (56 - 8*i)) & 0xFF;
}

// !!# SHA-2-384

// #!! SHA-2-512-224

typedef struct {
	UI8 __H0, __H1, __H2, __H3,
						 __H4, __H5, __H6, __H7;
	UI1 __buffer[128];
	UI8 __l;
} MASTER_SHA2_512_224;

MASTER_SHA2_512_224
MASTER_SHA2_512_224_Init(void) {
	MASTER_SHA2_512_224 __sha2_512_224;
	__sha2_512_224.__H0 = 0x8C3D37C819544DA2;
	__sha2_512_224.__H1 = 0x73E1996689DCD4D6;
	__sha2_512_224.__H2 = 0x1DFAB7AE32FF9C82;
	__sha2_512_224.__H3 = 0x679DD514582F9FCF;
	__sha2_512_224.__H4 = 0x0F6D2B697BD44DA8;
	__sha2_512_224.__H5 = 0x77E36F7304C48942;
	__sha2_512_224.__H6 = 0x3F9D85A86A1D36C8;
	__sha2_512_224.__H7 = 0x1112E6AD91D692A1;
	__sha2_512_224.__l = 0;
	return __sha2_512_224;
}

static void
__MASTER_SHA2_512_224_Transform(MASTER_SHA2_512_224 * __sha2_512_224) {
	UI8 A, B, C, D, E, F, G, H;
	UI4 j;
	
	UI8 W[80];
	UI8 t1, t2;
	for (j = 0; j < 16; j++) {
		W[j] = (((UI8)__sha2_512_224->__buffer[j * 8 + 7]) << 0) |
				 (((UI8)__sha2_512_224->__buffer[j * 8 + 6]) << 8) |
				 (((UI8)__sha2_512_224->__buffer[j * 8 + 5]) << 16) |
				 (((UI8)__sha2_512_224->__buffer[j * 8 + 4]) << 24) |
				 (((UI8)__sha2_512_224->__buffer[j * 8 + 3]) << 32) |
				 (((UI8)__sha2_512_224->__buffer[j * 8 + 2]) << 40) |
				 (((UI8)__sha2_512_224->__buffer[j * 8 + 1]) << 48) |
				 (((UI8)__sha2_512_224->__buffer[j * 8 + 0]) << 56);
	}
	for (j = 16; j < 80; j++) {
		UI8 s0 = (MASTER_RLR64(W[j - 15], 1)) ^ (MASTER_RLR64(W[j - 15], 8)) ^ (W[j - 15] >> 7);
		UI8 s1 = (MASTER_RLR64(W[j - 2], 19)) ^ (MASTER_RLR64(W[j - 2], 61)) ^ (W[j - 2] >> 6);
		W[j] = W[j - 16] + s0 + W[j - 7] + s1;
	}

	A = __sha2_512_224->__H0; B = __sha2_512_224->__H1; C = __sha2_512_224->__H2; D = __sha2_512_224->__H3;
	E = __sha2_512_224->__H4; F = __sha2_512_224->__H5; G = __sha2_512_224->__H6; H = __sha2_512_224->__H7;
	
	for (j = 0; j < 80; j++) {
		t1 = H + __MASTER_SHA2_512_FUNCTION_SIGMA1(A) + __MASTER_SHA2_FUNCTION_CH(E, F, G) + MASTER_SHA2_512_TABLE_K[j] + W[j];
		t2 = __MASTER_SHA2_512_FUNCTION_SIGMA0(A) + __MASTER_SHA2_FUNCTION_MAJ(A, B, C);

		H = G;
		G = F;
		F = E;
		E = D + t1;
		D = C;
		C = B;
		B = A;
		A = t1 + t2;
	}

	__sha2_512_224->__H0 += A;
	__sha2_512_224->__H1 += B;
	__sha2_512_224->__H2 += C;
	__sha2_512_224->__H3 += D;
	__sha2_512_224->__H4 += E;
	__sha2_512_224->__H5 += F;
	__sha2_512_224->__H6 += G;
	__sha2_512_224->__H7 += H;
}

void
MASTER_SHA2_512_224_Update(MASTER_SHA2_512_224 * __sha2_512_224, const char * __s, UI4 __l) {
	while (__l--) {
		__sha2_512_224->__buffer[__sha2_512_224->__l++ % 128] = *(__s++);
		if (__sha2_512_224->__l % 128 == 0)
			__MASTER_SHA2_512_224_Transform(__sha2_512_224);
	}
}

void
MASTER_SHA2_512_224_Final(MASTER_SHA2_512_224 * __sha2_512_224, UI1 * hash_output) {
	UI1 bits[8];
	UI4 mdi, padding_len, i;
	
	bits[0] = ((__sha2_512_224->__l << 3) >> 56) & 0xff;
	bits[1] = ((__sha2_512_224->__l << 3) >> 48) & 0xff;
	bits[2] = ((__sha2_512_224->__l << 3) >> 40) & 0xff;
	bits[3] = ((__sha2_512_224->__l << 3) >> 32) & 0xff;
	bits[4] = ((__sha2_512_224->__l << 3) >> 24) & 0xff;
	bits[5] = ((__sha2_512_224->__l << 3) >> 16) & 0xff;
	bits[6] = ((__sha2_512_224->__l << 3) >> 8) & 0xff;
	bits[7] = ((__sha2_512_224->__l << 3)) & 0xff;
	
	mdi = __sha2_512_224->__l % 128;
	padding_len = (mdi < 112) ? 119 - mdi : 247 - mdi;
	const UI1 c = 0x80;
	MASTER_SHA2_512_224_Update(__sha2_512_224, (const char *)&c, 1);
	while (padding_len--) MASTER_SHA2_512_224_Update(__sha2_512_224, "\0", 1);
	
	MASTER_SHA2_512_224_Update(__sha2_512_224, (const char *)bits, 8);
	
	for (i = 0; i < 8; i++) hash_output[i] = (__sha2_512_224->__H0 >> (56 - 8*i)) & 0xFF;
	for (i = 0; i < 8; i++) hash_output[8 + i] = (__sha2_512_224->__H1 >> (56 - 8*i)) & 0xFF;
	for (i = 0; i < 8; i++) hash_output[16 + i] = (__sha2_512_224->__H2 >> (56 - 8*i)) & 0xFF;
	for (i = 0; i < 4; i++) hash_output[24 + i] = (__sha2_512_224->__H3 >> (56 - 8*i)) & 0xFF;
}

void
MASTER_SHA2_512_224_CalculateHashSum(const char * __s, UI8 __l, UI1 * hash_output) {
	UI8 H0 = 0x8C3D37C819544DA2;
	UI8 H1 = 0x73E1996689DCD4D6;
	UI8 H2 = 0x1DFAB7AE32FF9C82;
	UI8 H3 = 0x679DD514582F9FCF;
	UI8 H4 = 0x0F6D2B697BD44DA8;
	UI8 H5 = 0x77E36F7304C48942;
	UI8 H6 = 0x3F9D85A86A1D36C8;
	UI8 H7 = 0x1112E6AD91D692A1;
	
	UI4 i, j;

	UI8 mdi = __l % 128;
	UI8 padding_len = (mdi < 112) ? 119 - mdi : 247 - mdi;

	UI1 * __M = (UI1 *)alloca( (__l + padding_len + 8) * sizeof(char));
	for (i = 0; i < __l; i++)
		__M[i] = __s[i];

	__M[__l] = 0x80;
	for (i = 0; i < padding_len - 1; i++)
		*(__M + __l + 1 + i) = 0;

	UI8 * length_append = (UI8 *)(__M + __l + padding_len + 1);
	*length_append = ((((__l * 8)) & 0xFF) << 56) |
					 ((((__l * 8) >> 8) & 0xFF) << 48) |
					 ((((__l * 8) >> 16) & 0xFF) << 40) |
					 ((((__l * 8) >> 24) & 0xFF) << 32) |
					 ((((__l * 8) >> 32) & 0xFF) << 24) |
					 ((((__l * 8) >> 40) & 0xFF) << 16) |
					 ((((__l * 8) >> 48) & 0xFF) << 8) |
					 (((__l * 8) >> 56) & 0xFF);
	
	__l += (padding_len + 9);
	
	UI8 A, B, C, D, E, F, G, H;
	
	UI8 W[80];
	UI8 t1, t2;
	for (i = 0; i < __l; i += 128) {
		for (j = 0; j < 16; j++) {
			W[j] = (((UI8)__M[i + j * 8 + 7]) << 0) |
					 (((UI8)__M[i + j * 8 + 6]) << 8) |
					 (((UI8)__M[i + j * 8 + 5]) << 16) |
					 (((UI8)__M[i + j * 8 + 4]) << 24) |
					 (((UI8)__M[i + j * 8 + 3]) << 32) |
					 (((UI8)__M[i + j * 8 + 2]) << 40) |
					 (((UI8)__M[i + j * 8 + 1]) << 48) |
					 (((UI8)__M[i + j * 8 + 0]) << 56);
		}
		for (j = 16; j < 80; j++) {
			UI8 s0 = (MASTER_RLR64(W[j - 15], 1)) ^ (MASTER_RLR64(W[j - 15], 8)) ^ (W[j - 15] >> 7);
					UI8 s1 = (MASTER_RLR64(W[j - 2], 19)) ^ (MASTER_RLR64(W[j - 2], 61)) ^ (W[j - 2] >> 6);
					W[j] = W[j - 16] + s0 + W[j - 7] + s1;
		}

		A = H0; B = H1; C = H2; D = H3;
		E = H4; F = H5; G = H6; H = H7;
		
		for (j = 0; j < 80; j++) {
			t1 = H + __MASTER_SHA2_512_FUNCTION_SIGMA1(A) + __MASTER_SHA2_FUNCTION_CH(E, F, G) + MASTER_SHA2_512_TABLE_K[j] + W[j];
			t2 = __MASTER_SHA2_512_FUNCTION_SIGMA0(A) + __MASTER_SHA2_FUNCTION_MAJ(A, B, C);

			H = G;
			G = F;
			F = E;
			E = D + t1;
			D = C;
			C = B;
			B = A;
			A = t1 + t2;
		}

		H0 += A;
		H1 += B;
		H2 += C;
		H3 += D;
		H4 += E;
		H5 += F;
		H6 += G;
		H7 += H;
	}
	
	for (i = 0; i < 8; i++) hash_output[i] = (H0 >> (56 - 8*i)) & 0xFF;
	for (i = 0; i < 8; i++) hash_output[8 + i] = (H1 >> (56 - 8*i)) & 0xFF;
	for (i = 0; i < 8; i++) hash_output[16 + i] = (H2 >> (56 - 8*i)) & 0xFF;
	for (i = 0; i < 4; i++) hash_output[24 + i] = (H3 >> (56 - 8*i)) & 0xFF;
}

// !!# SHA-2-512-224

// #!! SHA-2-512-256

typedef struct {
	UI8 __H0, __H1, __H2, __H3,
						 __H4, __H5, __H6, __H7;
	UI1 __buffer[128];
	UI8 __l;
} MASTER_SHA2_512_256;

MASTER_SHA2_512_256
MASTER_SHA2_512_256_Init(void) {
	MASTER_SHA2_512_256 __sha2_512_256;
	__sha2_512_256.__H0 = 0x22312194FC2BF72C;
	__sha2_512_256.__H1 = 0x9F555FA3C84C64C2;
	__sha2_512_256.__H2 = 0x2393B86B6F53B151;
	__sha2_512_256.__H3 = 0x963877195940EABD;
	__sha2_512_256.__H4 = 0x96283EE2A88EFFE3;
	__sha2_512_256.__H5 = 0xBE5E1E2553863992;
	__sha2_512_256.__H6 = 0x2B0199FC2C85B8AA;
	__sha2_512_256.__H7 = 0x0EB72DDC81C52CA2;
	__sha2_512_256.__l = 0;
	return __sha2_512_256;
}

static void
__MASTER_SHA2_512_256_Transform(MASTER_SHA2_512_256 * __sha2_512_256) {
	UI8 A, B, C, D, E, F, G, H;
	UI4 j;
	
	UI8 W[80];
	UI8 t1, t2;
	for (j = 0; j < 16; j++) {
		W[j] = (((UI8)__sha2_512_256->__buffer[j * 8 + 7]) << 0) |
				 (((UI8)__sha2_512_256->__buffer[j * 8 + 6]) << 8) |
				 (((UI8)__sha2_512_256->__buffer[j * 8 + 5]) << 16) |
				 (((UI8)__sha2_512_256->__buffer[j * 8 + 4]) << 24) |
				 (((UI8)__sha2_512_256->__buffer[j * 8 + 3]) << 32) |
				 (((UI8)__sha2_512_256->__buffer[j * 8 + 2]) << 40) |
				 (((UI8)__sha2_512_256->__buffer[j * 8 + 1]) << 48) |
				 (((UI8)__sha2_512_256->__buffer[j * 8 + 0]) << 56);
	}
	for (j = 16; j < 80; j++) {
		UI8 s0 = (MASTER_RLR64(W[j - 15], 1)) ^ (MASTER_RLR64(W[j - 15], 8)) ^ (W[j - 15] >> 7);
		UI8 s1 = (MASTER_RLR64(W[j - 2], 19)) ^ (MASTER_RLR64(W[j - 2], 61)) ^ (W[j - 2] >> 6);
		W[j] = W[j - 16] + s0 + W[j - 7] + s1;
	}

	A = __sha2_512_256->__H0; B = __sha2_512_256->__H1; C = __sha2_512_256->__H2; D = __sha2_512_256->__H3;
	E = __sha2_512_256->__H4; F = __sha2_512_256->__H5; G = __sha2_512_256->__H6; H = __sha2_512_256->__H7;
	
	for (j = 0; j < 80; j++) {
		t1 = H + __MASTER_SHA2_512_FUNCTION_SIGMA1(A) + __MASTER_SHA2_FUNCTION_CH(E, F, G) + MASTER_SHA2_512_TABLE_K[j] + W[j];
		t2 = __MASTER_SHA2_512_FUNCTION_SIGMA0(A) + __MASTER_SHA2_FUNCTION_MAJ(A, B, C);

		H = G;
		G = F;
		F = E;
		E = D + t1;
		D = C;
		C = B;
		B = A;
		A = t1 + t2;
	}

	__sha2_512_256->__H0 += A;
	__sha2_512_256->__H1 += B;
	__sha2_512_256->__H2 += C;
	__sha2_512_256->__H3 += D;
	__sha2_512_256->__H4 += E;
	__sha2_512_256->__H5 += F;
	__sha2_512_256->__H6 += G;
	__sha2_512_256->__H7 += H;
}

void
MASTER_SHA2_512_256_Update(MASTER_SHA2_512_256 * __sha2_512_256, const char * __s, UI4 __l) {
	while (__l--) {
		__sha2_512_256->__buffer[__sha2_512_256->__l++ % 128] = *(__s++);
		if (__sha2_512_256->__l % 128 == 0)
			__MASTER_SHA2_512_256_Transform(__sha2_512_256);
	}
}

void
MASTER_SHA2_512_256_Final(MASTER_SHA2_512_256 * __sha2_512_256, UI1 * hash_output) {
	UI1 bits[8];
	UI4 mdi, padding_len, i;
	
	bits[0] = ((__sha2_512_256->__l << 3) >> 56) & 0xff;
	bits[1] = ((__sha2_512_256->__l << 3) >> 48) & 0xff;
	bits[2] = ((__sha2_512_256->__l << 3) >> 40) & 0xff;
	bits[3] = ((__sha2_512_256->__l << 3) >> 32) & 0xff;
	bits[4] = ((__sha2_512_256->__l << 3) >> 24) & 0xff;
	bits[5] = ((__sha2_512_256->__l << 3) >> 16) & 0xff;
	bits[6] = ((__sha2_512_256->__l << 3) >> 8) & 0xff;
	bits[7] = ((__sha2_512_256->__l << 3)) & 0xff;
	
	mdi = __sha2_512_256->__l % 128;
	padding_len = (mdi < 112) ? 119 - mdi : 247 - mdi;
	const UI1 c = 0x80;
	MASTER_SHA2_512_256_Update(__sha2_512_256, (const char *)&c, 1);
	while (padding_len--) MASTER_SHA2_512_256_Update(__sha2_512_256, "\0", 1);
	
	MASTER_SHA2_512_256_Update(__sha2_512_256, (const char *)bits, 8);
	
	for (i = 0; i < 8; i++) hash_output[i] = (__sha2_512_256->__H0 >> (56 - 8*i)) & 0xFF;
	for (i = 0; i < 8; i++) hash_output[8 + i] = (__sha2_512_256->__H1 >> (56 - 8*i)) & 0xFF;
	for (i = 0; i < 8; i++) hash_output[16 + i] = (__sha2_512_256->__H2 >> (56 - 8*i)) & 0xFF;
	for (i = 0; i < 8; i++) hash_output[24 + i] = (__sha2_512_256->__H3 >> (56 - 8*i)) & 0xFF;
}

void
MASTER_SHA2_512_256_CalculateHashSum(const char * __s, UI8 __l, UI1 * hash_output) {
	UI8 H0 = 0x22312194FC2BF72C;
	UI8 H1 = 0x9F555FA3C84C64C2;
	UI8 H2 = 0x2393B86B6F53B151;
	UI8 H3 = 0x963877195940EABD;
	UI8 H4 = 0x96283EE2A88EFFE3;
	UI8 H5 = 0xBE5E1E2553863992;
	UI8 H6 = 0x2B0199FC2C85B8AA;
	UI8 H7 = 0x0EB72DDC81C52CA2;
	
	UI4 i, j;

	UI8 mdi = __l % 128;
	UI8 padding_len = (mdi < 112) ? 119 - mdi : 247 - mdi;

	UI1 * __M = (UI1 *)alloca( (__l + padding_len + 8) * sizeof(char));
	for (i = 0; i < __l; i++)
		__M[i] = __s[i];

	__M[__l] = 0x80;
	for (i = 0; i < padding_len - 1; i++)
		*(__M + __l + 1 + i) = 0;

	UI8 * length_append = (UI8 *)(__M + __l + padding_len + 1);
	*length_append = ((((__l * 8)) & 0xFF) << 56) |
					 ((((__l * 8) >> 8) & 0xFF) << 48) |
					 ((((__l * 8) >> 16) & 0xFF) << 40) |
					 ((((__l * 8) >> 24) & 0xFF) << 32) |
					 ((((__l * 8) >> 32) & 0xFF) << 24) |
					 ((((__l * 8) >> 40) & 0xFF) << 16) |
					 ((((__l * 8) >> 48) & 0xFF) << 8) |
					 (((__l * 8) >> 56) & 0xFF);
	
	__l += (padding_len + 9);
	
	UI8 A, B, C, D, E, F, G, H;
	
	UI8 W[80];
	UI8 t1, t2;
	for (i = 0; i < __l; i += 128) {
		for (j = 0; j < 16; j++) {
			W[j] = (((UI8)__M[i + j * 8 + 7]) << 0) |
					 (((UI8)__M[i + j * 8 + 6]) << 8) |
					 (((UI8)__M[i + j * 8 + 5]) << 16) |
					 (((UI8)__M[i + j * 8 + 4]) << 24) |
					 (((UI8)__M[i + j * 8 + 3]) << 32) |
					 (((UI8)__M[i + j * 8 + 2]) << 40) |
					 (((UI8)__M[i + j * 8 + 1]) << 48) |
					 (((UI8)__M[i + j * 8 + 0]) << 56);
		}
		for (j = 16; j < 80; j++) {
			UI8 s0 = (MASTER_RLR64(W[j - 15], 1)) ^ (MASTER_RLR64(W[j - 15], 8)) ^ (W[j - 15] >> 7);
					UI8 s1 = (MASTER_RLR64(W[j - 2], 19)) ^ (MASTER_RLR64(W[j - 2], 61)) ^ (W[j - 2] >> 6);
					W[j] = W[j - 16] + s0 + W[j - 7] + s1;
		}

		A = H0; B = H1; C = H2; D = H3;
		E = H4; F = H5; G = H6; H = H7;
		
		for (j = 0; j < 80; j++) {
			t1 = H + __MASTER_SHA2_512_FUNCTION_SIGMA1(A) + __MASTER_SHA2_FUNCTION_CH(E, F, G) + MASTER_SHA2_512_TABLE_K[j] + W[j];
			t2 = __MASTER_SHA2_512_FUNCTION_SIGMA0(A) + __MASTER_SHA2_FUNCTION_MAJ(A, B, C);

			H = G;
			G = F;
			F = E;
			E = D + t1;
			D = C;
			C = B;
			B = A;
			A = t1 + t2;
		}

		H0 += A;
		H1 += B;
		H2 += C;
		H3 += D;
		H4 += E;
		H5 += F;
		H6 += G;
		H7 += H;
	}
	
	for (i = 0; i < 8; i++) hash_output[i] = (H0 >> (56 - 8*i)) & 0xFF;
	for (i = 0; i < 8; i++) hash_output[8 + i] = (H1 >> (56 - 8*i)) & 0xFF;
	for (i = 0; i < 8; i++) hash_output[16 + i] = (H2 >> (56 - 8*i)) & 0xFF;
	for (i = 0; i < 8; i++) hash_output[24 + i] = (H3 >> (56 - 8*i)) & 0xFF;
}

// !!# SHA-2-512-256

#undef __MASTER_SHA2_FUNCTION_SIGMA0
#undef __MASTER_SHA2_FUNCTION_SIGMA1
#undef __MASTER_SHA2_FUNCTION_MAJ
#undef __MASTER_SHA2_FUNCTION_CH
#undef __MASTER_SHA2_512_FUNCTION_SIGMA0
#undef __MASTER_SHA2_512_FUNCTION_SIGMA1
#undef __MASTER_SHA2_512_FUNCTION_MAJ
#undef __MASTER_SHA2_512_FUNCTION_CH

// !# SHA-2

// #! SHA-3

#define REPEAT6(e) e e e e e e
#define REPEAT24(e) REPEAT6(e e e e)
#define REPEAT5(e) e e e e e
#define FOR5(v, s, e) \
	v = 0; \
	REPEAT5(e; v += s;)

#define FOR(i, ST, L, S) \
	 do { for (UI4 i = 0; i < L; i += ST) { S; } } while (0)
#define mkapply_ds(NAME, S) \
	static inline void \
	NAME(UI1 * dst, \
		 const UI1 * src, \
		 UI4 len) { \
		FOR(i, 1, len, S); \
	}
#define mkapply_sd(NAME, S) \
	static inline void \
	NAME(const UI1 * src, \
		 UI1 * dst, \
		 UI4 len) { \
		FOR(i, 1, len, S); }

#define foldP(I, L, F) \
	while (L >= rate) { \
		F(a, I, rate); \
		MASTER_SHA3_FUNCTION_KECCAKF(a); \
		I += rate; \
		L -= rate; }

#define defshake(bits) \
	typedef struct { \
		UI1 __A[200]; \
		UI4 __rate; \
		UI4 __absorbed; \
	} MASTER_SHAKE##bits; \
	\
	MASTER_SHAKE##bits \
	MASTER_SHAKE##bits##_Init(void) { \
		MASTER_SHAKE##bits __shake##bits; \
		memset(__shake##bits.__A, 0, 200); \
		__shake##bits.__rate = 200 - bits / 4; \
		__shake##bits.__absorbed = 0; \
		return __shake##bits; } \
	\
	void \
	MASTER_SHAKE##bits##_Update(MASTER_SHAKE##bits * __shake##bits, const char * __s, UI4 __l) { \
		while (__l > 0) { \
			UI4 capacity = __shake##bits->__rate - __shake##bits->__absorbed; \
			UI4 to_absorb = (__l < capacity) ? __l : capacity; \
			xorin(__shake##bits->__A + __shake##bits->__absorbed, __s, to_absorb); \
			__shake##bits->__absorbed += to_absorb; \
			__s += to_absorb; \
			__l -= to_absorb; \
			if (__shake##bits->__absorbed == __shake##bits->__rate) { \
				MASTER_SHA3_FUNCTION_KECCAKF(__shake##bits->__A); \
				__shake##bits->__absorbed = 0; } \
		} \
	} \
	\
	void \
	MASTER_SHAKE##bits##_Final(MASTER_SHAKE##bits * __shake##bits, UI1 * hash_output) { \
		UI4 outlen = bits / 4; \
		__shake##bits->__A[__shake##bits->__absorbed] ^= 0x1f; \
		__shake##bits->__A[__shake##bits->__rate - 1] ^= 0x80; \
		MASTER_SHA3_FUNCTION_KECCAKF(__shake##bits->__A); \
		while (outlen > 0) { \
			UI4 to_copy = (outlen < __shake##bits->__rate) ? outlen : __shake##bits->__rate; \
			memcpy(hash_output, __shake##bits->__A, to_copy); \
			hash_output += to_copy; \
			outlen -= to_copy; \
			if (outlen > 0) MASTER_SHA3_FUNCTION_KECCAKF(__shake##bits->__A); } \
	} \
	\
	void \
	MASTER_SHAKE##bits##_CalculateHashSum(const char * __s, UI4 __l, UI1 * hash_output) { \
		MASTER_SHA3_FUNCTION_HASH(hash_output, bits / 4, __s, __l, 200 - (bits / 4), 0x1f); }

#define defsha3(bits) \
	typedef struct { \
		UI1 __A[200]; \
		UI4 __rate; \
		UI4 __absorbed; \
	} MASTER_SHA3_##bits; \
	\
	MASTER_SHA3_##bits \
	MASTER_SHA3_##bits##_Init(void) { \
		MASTER_SHA3_##bits __sha3_##bits; \
		memset(__sha3_##bits.__A, 0, 200); \
		__sha3_##bits.__rate = 200 - bits / 4; \
		__sha3_##bits.__absorbed = 0; \
		return __sha3_##bits; } \
	\
	void \
	MASTER_SHA3_##bits##_Update(MASTER_SHA3_##bits * __sha3_##bits, const char * __s, UI4 __l) { \
		while (__l > 0) { \
			UI4 capacity = __sha3_##bits->__rate - __sha3_##bits->__absorbed; \
			UI4 to_absorb = (__l < capacity) ? __l : capacity; \
			xorin(__sha3_##bits->__A + __sha3_##bits->__absorbed, __s, to_absorb); \
			__sha3_##bits->__absorbed += to_absorb; \
			__s += to_absorb; \
			__l -= to_absorb; \
			if (__sha3_##bits->__absorbed == __sha3_##bits->__rate) { \
				MASTER_SHA3_FUNCTION_KECCAKF(__sha3_##bits->__A); \
				__sha3_##bits->__absorbed = 0; } \
		} \
	} \
	\
	void \
	MASTER_SHA3_##bits##_Final(MASTER_SHA3_##bits * __sha3_##bits, UI1 * hash_output) { \
		UI4 outlen = bits / 8; \
		__sha3_##bits->__A[__sha3_##bits->__absorbed] ^= 0x06; \
		__sha3_##bits->__A[__sha3_##bits->__rate - 1] ^= 0x80; \
		MASTER_SHA3_FUNCTION_KECCAKF(__sha3_##bits->__A); \
		while (outlen > 0) { \
			UI4 to_copy = (outlen < __sha3_##bits->__rate) ? outlen : __sha3_##bits->__rate; \
			memcpy(hash_output, __sha3_##bits->__A, to_copy); \
			hash_output += to_copy; \
			outlen -= to_copy; \
			if (outlen > 0) MASTER_SHA3_FUNCTION_KECCAKF(__sha3_##bits->__A); \
		} \
	} \
	\
	void \
	MASTER_SHA3_##bits##_CalculateHashSum(const char * __s, UI4 __l, UI1 * hash_output) { \
		MASTER_SHA3_FUNCTION_HASH(hash_output, bits / 8, __s, __l, 200 - (bits / 4), 0x06); }

static const UI1 MASTER_SHA3_Table_RHO[24] = {
	1, 3, 6, 10, 15, 21,
	28, 36, 45, 55, 2, 14,
	27, 41, 56, 8, 25, 43,
	62, 18, 39, 61, 20, 44
};
static const UI1 MASTER_SHA3_Table_PI[24] = {
	10,7, 11, 17, 18, 3,
	5, 16, 8, 21, 24, 4,
	15, 23, 19, 13, 12, 2,
	20, 14, 22, 9, 6, 1
};
static const UI8 MASTER_SHA3_Table_RC[24] = {
	1, 0x8082, 0x800000000000808a, 0x8000000080008000,
	0x808b, 0x80000001, 0x8000000080008081, 0x8000000000008009,
	0x8a, 0x88, 0x80008009, 0x8000000a,
	0x8000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
	0x8000000000008002, 0x8000000000000080, 0x800a, 0x800000008000000a,
	0x8000000080008081, 0x8000000000008080, 0x80000001, 0x8000000080008008
};

static inline void
MASTER_SHA3_FUNCTION_KECCAKF(void* state) {
	UI8 * a = (UI8 *)state;
	UI8 b[5] = {0};
	UI8 t = 0;
	UI1 x, y;

	for (int i = 0; i < 24; i++) {
		FOR5(x, 1,
				 b[x] = 0;
				 FOR5(y, 5,
							b[x] ^= a[x + y]; ))
		FOR5(x, 1,
				 FOR5(y, 5,
							a[y + x] ^= b[(x + 4) % 5] ^ MASTER_RLL64(b[(x + 1) % 5], 1); ))
		t = a[1];
		x = 0;
		REPEAT24(b[0] = a[MASTER_SHA3_Table_PI[x]];
						 a[MASTER_SHA3_Table_PI[x]] = MASTER_RLL64(t, MASTER_SHA3_Table_RHO[x]);
						 t = b[0];
						 x++; )
		FOR5(y,
			 5,
			 FOR5(x, 1,
						b[x] = a[y + x];)
			 FOR5(x, 1,
						a[y + x] = b[x] ^ ((~b[(x + 1) % 5]) & b[(x + 2) % 5]); ))
		a[0] ^= MASTER_SHA3_Table_RC[i];
	}
}

mkapply_ds(xorin, dst[i] ^= src[i])
mkapply_sd(setout, dst[i] = src[i])

static inline void
MASTER_SHA3_FUNCTION_HASH(UI1 * out, UI4 outlen, const UI1 * in, UI4 inlen, UI4 rate, UI1 delim) {
	UI1 a[200] = {0};
	foldP(in, inlen, xorin);
	a[inlen] ^= delim;
	a[rate - 1] ^= 0x80;
	xorin(a, in, inlen);
	MASTER_SHA3_FUNCTION_KECCAKF(a);
	foldP(out, outlen, setout);
	setout(a, out, outlen);
	memset(a, 0, 200);
}

defshake(128)
defshake(256)

defsha3(224)
defsha3(256)
defsha3(384)
defsha3(512)

#undef REPEAT6
#undef REPEAT24
#undef REPEAT5
#undef FOR5
#undef FOR
#undef mkapply_ds
#undef mkapply_sd
#undef foldP
#undef defshake
#undef defsha3

// !# SHA-3

// #! RIPEMD

// #!! RIPEMD128

#define __MASTER_RIPEMD128_FUNCTION_F(x, y, z) ((x) ^ (y) ^ (z))
#define __MASTER_RIPEMD128_FUNCTION_G(x, y, z) (((x) & (y)) | (~(x) & (z)))
#define __MASTER_RIPEMD128_FUNCTION_H(x, y, z) (((x) | ~(y)) ^ (z))
#define __MASTER_RIPEMD128_FUNCTION_I(x, y, z) (((x) & (z)) | ((y) & ~(z)))
#define __MASTER_RIPEMD128_FUNCTION_FF(a, b, c, d, x, s) a += __MASTER_RIPEMD128_FUNCTION_F(b, c, d) + (x), a = MASTER_RLL32(a, s)
#define __MASTER_RIPEMD128_FUNCTION_GG(a, b, c, d, x, s) a += __MASTER_RIPEMD128_FUNCTION_G(b, c, d) + (x) + 0x5A827999, a = MASTER_RLL32(a, s)
#define __MASTER_RIPEMD128_FUNCTION_HH(a, b, c, d, x, s) a += __MASTER_RIPEMD128_FUNCTION_H(b, c, d) + (x) + 0x6ED9EBA1, a = MASTER_RLL32(a, s)
#define __MASTER_RIPEMD128_FUNCTION_II(a, b, c, d, x, s) a += __MASTER_RIPEMD128_FUNCTION_I(b, c, d) + (x) + 0x8F1BBCDC, a = MASTER_RLL32(a, s)
#define __MASTER_RIPEMD128_FUNCTION_FFF(a, b, c, d, x, s) a += __MASTER_RIPEMD128_FUNCTION_F(b, c, d) + (x), a = MASTER_RLL32(a, s)
#define __MASTER_RIPEMD128_FUNCTION_GGG(a, b, c, d, x, s) a += __MASTER_RIPEMD128_FUNCTION_G(b, c, d) + (x) + 0x6D703EF3, a = MASTER_RLL32(a, s)
#define __MASTER_RIPEMD128_FUNCTION_HHH(a, b, c, d, x, s) a += __MASTER_RIPEMD128_FUNCTION_H(b, c, d) + (x) + 0x5C4DD124, a = MASTER_RLL32(a, s)
#define __MASTER_RIPEMD128_FUNCTION_III(a, b, c, d, x, s) a += __MASTER_RIPEMD128_FUNCTION_I(b, c, d) + (x) + 0x50A28BE6, a = MASTER_RLL32(a, s)

#include <string.h>

typedef struct {
	UI4 __h[4];
	UI1 __b[64];
	UI4 __l;
	UI8 __tl;
} MASTER_RIPEMD128;

MASTER_RIPEMD128
MASTER_RIPEMD128_Init(void) {
	MASTER_RIPEMD128 __ripemd128;
	__ripemd128.__h[0] = 0x67452301;
	__ripemd128.__h[1] = 0xEFCDAB89;
	__ripemd128.__h[2] = 0x98BADCFE;
	__ripemd128.__h[3] = 0x10325476;
	__ripemd128.__l = __ripemd128.__tl = 0;
	return __ripemd128;
}

static void
MASTER_RIPEMD128_Transform(MASTER_RIPEMD128 * __ripemd128) {
	UI4 aa = __ripemd128->__h[0];
	UI4 bb = __ripemd128->__h[1];
	UI4 cc = __ripemd128->__h[2];
	UI4 dd = __ripemd128->__h[3];
	UI4 aaa = __ripemd128->__h[0];
	UI4 bbb = __ripemd128->__h[1];
	UI4 ccc = __ripemd128->__h[2];
	UI4 ddd = __ripemd128->__h[3];
	UI4 * x = (UI4 *)__ripemd128->__b;
	
	__MASTER_RIPEMD128_FUNCTION_FF(aa, bb, cc, dd, x[0],  11);
	__MASTER_RIPEMD128_FUNCTION_FF(dd, aa, bb, cc, x[1],  14);
	__MASTER_RIPEMD128_FUNCTION_FF(cc, dd, aa, bb, x[2],  15);
	__MASTER_RIPEMD128_FUNCTION_FF(bb, cc, dd, aa, x[3],  12);
	__MASTER_RIPEMD128_FUNCTION_FF(aa, bb, cc, dd, x[4],  5);
	__MASTER_RIPEMD128_FUNCTION_FF(dd, aa, bb, cc, x[5],  8);
	__MASTER_RIPEMD128_FUNCTION_FF(cc, dd, aa, bb, x[6],  7);
	__MASTER_RIPEMD128_FUNCTION_FF(bb, cc, dd, aa, x[7],  9);
	__MASTER_RIPEMD128_FUNCTION_FF(aa, bb, cc, dd, x[8],  11);
	__MASTER_RIPEMD128_FUNCTION_FF(dd, aa, bb, cc, x[9],  13);
	__MASTER_RIPEMD128_FUNCTION_FF(cc, dd, aa, bb, x[10], 14);
	__MASTER_RIPEMD128_FUNCTION_FF(bb, cc, dd, aa, x[11], 15);
	__MASTER_RIPEMD128_FUNCTION_FF(aa, bb, cc, dd, x[12], 6);
	__MASTER_RIPEMD128_FUNCTION_FF(dd, aa, bb, cc, x[13], 7);
	__MASTER_RIPEMD128_FUNCTION_FF(cc, dd, aa, bb, x[14], 9);
	__MASTER_RIPEMD128_FUNCTION_FF(bb, cc, dd, aa, x[15], 8);
	
	__MASTER_RIPEMD128_FUNCTION_GG(aa, bb, cc, dd, x[7],  7);
	__MASTER_RIPEMD128_FUNCTION_GG(dd, aa, bb, cc, x[4],  6);
	__MASTER_RIPEMD128_FUNCTION_GG(cc, dd, aa, bb, x[13], 8);
	__MASTER_RIPEMD128_FUNCTION_GG(bb, cc, dd, aa, x[1],  13);
	__MASTER_RIPEMD128_FUNCTION_GG(aa, bb, cc, dd, x[10], 11);
	__MASTER_RIPEMD128_FUNCTION_GG(dd, aa, bb, cc, x[6],  9);
	__MASTER_RIPEMD128_FUNCTION_GG(cc, dd, aa, bb, x[15], 7);
	__MASTER_RIPEMD128_FUNCTION_GG(bb, cc, dd, aa, x[3],  15);
	__MASTER_RIPEMD128_FUNCTION_GG(aa, bb, cc, dd, x[12], 7);
	__MASTER_RIPEMD128_FUNCTION_GG(dd, aa, bb, cc, x[0],  12);
	__MASTER_RIPEMD128_FUNCTION_GG(cc, dd, aa, bb, x[9],  15);
	__MASTER_RIPEMD128_FUNCTION_GG(bb, cc, dd, aa, x[5],  9);
	__MASTER_RIPEMD128_FUNCTION_GG(aa, bb, cc, dd, x[2],  11);
	__MASTER_RIPEMD128_FUNCTION_GG(dd, aa, bb, cc, x[14], 7);
	__MASTER_RIPEMD128_FUNCTION_GG(cc, dd, aa, bb, x[11], 13);
	__MASTER_RIPEMD128_FUNCTION_GG(bb, cc, dd, aa, x[8],  12);
	
	__MASTER_RIPEMD128_FUNCTION_HH(aa, bb, cc, dd, x[3],  11);
	__MASTER_RIPEMD128_FUNCTION_HH(dd, aa, bb, cc, x[10], 13);
	__MASTER_RIPEMD128_FUNCTION_HH(cc, dd, aa, bb, x[14], 6);
	__MASTER_RIPEMD128_FUNCTION_HH(bb, cc, dd, aa, x[4],  7);
	__MASTER_RIPEMD128_FUNCTION_HH(aa, bb, cc, dd, x[9],  14);
	__MASTER_RIPEMD128_FUNCTION_HH(dd, aa, bb, cc, x[15], 9);
	__MASTER_RIPEMD128_FUNCTION_HH(cc, dd, aa, bb, x[8],  13);
	__MASTER_RIPEMD128_FUNCTION_HH(bb, cc, dd, aa, x[1],  15);
	__MASTER_RIPEMD128_FUNCTION_HH(aa, bb, cc, dd, x[2],  14);
	__MASTER_RIPEMD128_FUNCTION_HH(dd, aa, bb, cc, x[7],  8);
	__MASTER_RIPEMD128_FUNCTION_HH(cc, dd, aa, bb, x[0],  13);
	__MASTER_RIPEMD128_FUNCTION_HH(bb, cc, dd, aa, x[6],  6);
	__MASTER_RIPEMD128_FUNCTION_HH(aa, bb, cc, dd, x[13], 5);
	__MASTER_RIPEMD128_FUNCTION_HH(dd, aa, bb, cc, x[11], 12);
	__MASTER_RIPEMD128_FUNCTION_HH(cc, dd, aa, bb, x[5],  7);
	__MASTER_RIPEMD128_FUNCTION_HH(bb, cc, dd, aa, x[12], 5);
	
	__MASTER_RIPEMD128_FUNCTION_II(aa, bb, cc, dd, x[1],  11);
	__MASTER_RIPEMD128_FUNCTION_II(dd, aa, bb, cc, x[9],  12);
	__MASTER_RIPEMD128_FUNCTION_II(cc, dd, aa, bb, x[11], 14);
	__MASTER_RIPEMD128_FUNCTION_II(bb, cc, dd, aa, x[10], 15);
	__MASTER_RIPEMD128_FUNCTION_II(aa, bb, cc, dd, x[0],  14);
	__MASTER_RIPEMD128_FUNCTION_II(dd, aa, bb, cc, x[8],  15);
	__MASTER_RIPEMD128_FUNCTION_II(cc, dd, aa, bb, x[12], 9);
	__MASTER_RIPEMD128_FUNCTION_II(bb, cc, dd, aa, x[4],  8);
	__MASTER_RIPEMD128_FUNCTION_II(aa, bb, cc, dd, x[13], 9);
	__MASTER_RIPEMD128_FUNCTION_II(dd, aa, bb, cc, x[3],  14);
	__MASTER_RIPEMD128_FUNCTION_II(cc, dd, aa, bb, x[7],  5);
	__MASTER_RIPEMD128_FUNCTION_II(bb, cc, dd, aa, x[15], 6);
	__MASTER_RIPEMD128_FUNCTION_II(aa, bb, cc, dd, x[14], 8);
	__MASTER_RIPEMD128_FUNCTION_II(dd, aa, bb, cc, x[5],  6);
	__MASTER_RIPEMD128_FUNCTION_II(cc, dd, aa, bb, x[6],  5);
	__MASTER_RIPEMD128_FUNCTION_II(bb, cc, dd, aa, x[2],  12);
	
	__MASTER_RIPEMD128_FUNCTION_III(aaa, bbb, ccc, ddd, x[5],  8);
	__MASTER_RIPEMD128_FUNCTION_III(ddd, aaa, bbb, ccc, x[14], 9);
	__MASTER_RIPEMD128_FUNCTION_III(ccc, ddd, aaa, bbb, x[7],  9);
	__MASTER_RIPEMD128_FUNCTION_III(bbb, ccc, ddd, aaa, x[0],  11);
	__MASTER_RIPEMD128_FUNCTION_III(aaa, bbb, ccc, ddd, x[9],  13);
	__MASTER_RIPEMD128_FUNCTION_III(ddd, aaa, bbb, ccc, x[2],  15);
	__MASTER_RIPEMD128_FUNCTION_III(ccc, ddd, aaa, bbb, x[11], 15);
	__MASTER_RIPEMD128_FUNCTION_III(bbb, ccc, ddd, aaa, x[4],  5);
	__MASTER_RIPEMD128_FUNCTION_III(aaa, bbb, ccc, ddd, x[13], 7);
	__MASTER_RIPEMD128_FUNCTION_III(ddd, aaa, bbb, ccc, x[6],  7);
	__MASTER_RIPEMD128_FUNCTION_III(ccc, ddd, aaa, bbb, x[15], 8);
	__MASTER_RIPEMD128_FUNCTION_III(bbb, ccc, ddd, aaa, x[8],  11);
	__MASTER_RIPEMD128_FUNCTION_III(aaa, bbb, ccc, ddd, x[1],  14);
	__MASTER_RIPEMD128_FUNCTION_III(ddd, aaa, bbb, ccc, x[10], 14);
	__MASTER_RIPEMD128_FUNCTION_III(ccc, ddd, aaa, bbb, x[3],  12);
	__MASTER_RIPEMD128_FUNCTION_III(bbb, ccc, ddd, aaa, x[12], 6);
	
	__MASTER_RIPEMD128_FUNCTION_HHH(aaa, bbb, ccc, ddd, x[6],  9);
	__MASTER_RIPEMD128_FUNCTION_HHH(ddd, aaa, bbb, ccc, x[11], 13);
	__MASTER_RIPEMD128_FUNCTION_HHH(ccc, ddd, aaa, bbb, x[3],  15);
	__MASTER_RIPEMD128_FUNCTION_HHH(bbb, ccc, ddd, aaa, x[7],  7);
	__MASTER_RIPEMD128_FUNCTION_HHH(aaa, bbb, ccc, ddd, x[0],  12);
	__MASTER_RIPEMD128_FUNCTION_HHH(ddd, aaa, bbb, ccc, x[13], 8);
	__MASTER_RIPEMD128_FUNCTION_HHH(ccc, ddd, aaa, bbb, x[5],  9);
	__MASTER_RIPEMD128_FUNCTION_HHH(bbb, ccc, ddd, aaa, x[10], 11);
	__MASTER_RIPEMD128_FUNCTION_HHH(aaa, bbb, ccc, ddd, x[14], 7);
	__MASTER_RIPEMD128_FUNCTION_HHH(ddd, aaa, bbb, ccc, x[15], 7);
	__MASTER_RIPEMD128_FUNCTION_HHH(ccc, ddd, aaa, bbb, x[8],  12);
	__MASTER_RIPEMD128_FUNCTION_HHH(bbb, ccc, ddd, aaa, x[12], 7);
	__MASTER_RIPEMD128_FUNCTION_HHH(aaa, bbb, ccc, ddd, x[4],  6);
	__MASTER_RIPEMD128_FUNCTION_HHH(ddd, aaa, bbb, ccc, x[9],  15);
	__MASTER_RIPEMD128_FUNCTION_HHH(ccc, ddd, aaa, bbb, x[1],  13);
	__MASTER_RIPEMD128_FUNCTION_HHH(bbb, ccc, ddd, aaa, x[2],  11);
	
	__MASTER_RIPEMD128_FUNCTION_GGG(aaa, bbb, ccc, ddd, x[15], 9);
	__MASTER_RIPEMD128_FUNCTION_GGG(ddd, aaa, bbb, ccc, x[5],  7);
	__MASTER_RIPEMD128_FUNCTION_GGG(ccc, ddd, aaa, bbb, x[1],  15);
	__MASTER_RIPEMD128_FUNCTION_GGG(bbb, ccc, ddd, aaa, x[3],  11);
	__MASTER_RIPEMD128_FUNCTION_GGG(aaa, bbb, ccc, ddd, x[7],  8);
	__MASTER_RIPEMD128_FUNCTION_GGG(ddd, aaa, bbb, ccc, x[14], 6);
	__MASTER_RIPEMD128_FUNCTION_GGG(ccc, ddd, aaa, bbb, x[6],  6);
	__MASTER_RIPEMD128_FUNCTION_GGG(bbb, ccc, ddd, aaa, x[9],  14);
	__MASTER_RIPEMD128_FUNCTION_GGG(aaa, bbb, ccc, ddd, x[11], 12);
	__MASTER_RIPEMD128_FUNCTION_GGG(ddd, aaa, bbb, ccc, x[8],  13);
	__MASTER_RIPEMD128_FUNCTION_GGG(ccc, ddd, aaa, bbb, x[12], 5);
	__MASTER_RIPEMD128_FUNCTION_GGG(bbb, ccc, ddd, aaa, x[2],  14);
	__MASTER_RIPEMD128_FUNCTION_GGG(aaa, bbb, ccc, ddd, x[10], 13);
	__MASTER_RIPEMD128_FUNCTION_GGG(ddd, aaa, bbb, ccc, x[0],  13);
	__MASTER_RIPEMD128_FUNCTION_GGG(ccc, ddd, aaa, bbb, x[4],  7);
	__MASTER_RIPEMD128_FUNCTION_GGG(bbb, ccc, ddd, aaa, x[13], 5);
	
	__MASTER_RIPEMD128_FUNCTION_FFF(aaa, bbb, ccc, ddd, x[8],  15);
	__MASTER_RIPEMD128_FUNCTION_FFF(ddd, aaa, bbb, ccc, x[6],  5);
	__MASTER_RIPEMD128_FUNCTION_FFF(ccc, ddd, aaa, bbb, x[4],  8);
	__MASTER_RIPEMD128_FUNCTION_FFF(bbb, ccc, ddd, aaa, x[1],  11);
	__MASTER_RIPEMD128_FUNCTION_FFF(aaa, bbb, ccc, ddd, x[3],  14);
	__MASTER_RIPEMD128_FUNCTION_FFF(ddd, aaa, bbb, ccc, x[11], 14);
	__MASTER_RIPEMD128_FUNCTION_FFF(ccc, ddd, aaa, bbb, x[15], 6);
	__MASTER_RIPEMD128_FUNCTION_FFF(bbb, ccc, ddd, aaa, x[0],  14);
	__MASTER_RIPEMD128_FUNCTION_FFF(aaa, bbb, ccc, ddd, x[5],  6);
	__MASTER_RIPEMD128_FUNCTION_FFF(ddd, aaa, bbb, ccc, x[12], 9);
	__MASTER_RIPEMD128_FUNCTION_FFF(ccc, ddd, aaa, bbb, x[2],  12);
	__MASTER_RIPEMD128_FUNCTION_FFF(bbb, ccc, ddd, aaa, x[13], 9);
	__MASTER_RIPEMD128_FUNCTION_FFF(aaa, bbb, ccc, ddd, x[9],  12);
	__MASTER_RIPEMD128_FUNCTION_FFF(ddd, aaa, bbb, ccc, x[7],  5);
	__MASTER_RIPEMD128_FUNCTION_FFF(ccc, ddd, aaa, bbb, x[10], 15);
	__MASTER_RIPEMD128_FUNCTION_FFF(bbb, ccc, ddd, aaa, x[14], 8);
	
	ddd = __ripemd128->__h[1] + cc + ddd;
	__ripemd128->__h[1] = __ripemd128->__h[2] + dd + aaa;
	__ripemd128->__h[2] = __ripemd128->__h[3] + aa + bbb;
	__ripemd128->__h[3] = __ripemd128->__h[0] + bb + ccc;
	__ripemd128->__h[0] = ddd;
}

void
MASTER_RIPEMD128_Update(MASTER_RIPEMD128 * __ripemd128, const char * __s, UI4 __l) {
	UI4 n;
	while (__l > 0) {
		n = (__l < 64 - __ripemd128->__l) ? (__l) : (64 - __ripemd128->__l);
		memcpy(__ripemd128->__b + __ripemd128->__l, __s, n);
		__ripemd128->__l += n;
		__ripemd128->__tl += n;
		__s += n;
		__l -= n;
		if (__ripemd128->__l == 64) {
			MASTER_RIPEMD128_Transform(__ripemd128);
			__ripemd128->__l = 0;
		}
	}
}

void
MASTER_RIPEMD128_Final(MASTER_RIPEMD128 * __ripemd128, UI1 * hash_output) {
	UI4 pad;
	UI8 tl;
	tl = __ripemd128->__tl * 8;
	if (__ripemd128->__l < 56) pad = 56 - __ripemd128->__l;
	else pad = 64 + 56 - __ripemd128->__l;
	static const UI1 padding[64] = {
	 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
	};
	MASTER_RIPEMD128_Update(__ripemd128, (const char *)padding, pad);
	*((UI4 *)&__ripemd128->__b[14 * sizeof(UI4)]) = tl;
	*((UI4 *)&__ripemd128->__b[15 * sizeof(UI4)]) = tl >> 32;
	MASTER_RIPEMD128_Transform(__ripemd128);
	memcpy(hash_output, __ripemd128->__h, 16);
}

void
MASTER_RIPEMD128_CalculateHashSum(const char * __s, UI4 __l, UI1 * hash_output) {
	MASTER_RIPEMD128 __ripemd128 = MASTER_RIPEMD128_Init();
	MASTER_RIPEMD128_Update(&__ripemd128, __s, __l);
	MASTER_RIPEMD128_Final(&__ripemd128, hash_output);
}

#undef __MASTER_RIPEMD128_FUNCTION_F
#undef __MASTER_RIPEMD128_FUNCTION_G
#undef __MASTER_RIPEMD128_FUNCTION_H
#undef __MASTER_RIPEMD128_FUNCTION_I
#undef __MASTER_RIPEMD128_FUNCTION_FF
#undef __MASTER_RIPEMD128_FUNCTION_GG
#undef __MASTER_RIPEMD128_FUNCTION_HH
#undef __MASTER_RIPEMD128_FUNCTION_II
#undef __MASTER_RIPEMD128_FUNCTION_FFF
#undef __MASTER_RIPEMD128_FUNCTION_GGG
#undef __MASTER_RIPEMD128_FUNCTION_HHH
#undef __MASTER_RIPEMD128_FUNCTION_III

// !!# RIPEMD128

// #!! RIPEMD160

#define __MASTER_RIPEMD160_FUNCTION_F(x, y, z) ((x) ^ (y) ^ (z))
#define __MASTER_RIPEMD160_FUNCTION_G(x, y, z) (((x) & (y)) | (~(x) & (z)))
#define __MASTER_RIPEMD160_FUNCTION_H(x, y, z) (((x) | ~(y)) ^ (z))
#define __MASTER_RIPEMD160_FUNCTION_I(x, y, z) (((x) & (z)) | ((y) & ~(z)))
#define __MASTER_RIPEMD160_FUNCTION_J(x, y, z) ((x) ^ ((y) | ~(z)))
#define __MASTER_RIPEMD160_FUNCTION_FF(a, b, c, d, e, x, s) a += __MASTER_RIPEMD160_FUNCTION_F(b, c, d) + (x), a = MASTER_RLL32(a, s) + (e), c = MASTER_RLL32(c, 10)
#define __MASTER_RIPEMD160_FUNCTION_GG(a, b, c, d, e, x, s) a += __MASTER_RIPEMD160_FUNCTION_G(b, c, d) + (x) + 0x5A827999, a = MASTER_RLL32(a, s) + (e), c = MASTER_RLL32(c, 10)
#define __MASTER_RIPEMD160_FUNCTION_HH(a, b, c, d, e, x, s) a += __MASTER_RIPEMD160_FUNCTION_H(b, c, d) + (x) + 0x6ED9EBA1, a = MASTER_RLL32(a, s) + (e), c = MASTER_RLL32(c, 10)
#define __MASTER_RIPEMD160_FUNCTION_II(a, b, c, d, e, x, s) a += __MASTER_RIPEMD160_FUNCTION_I(b, c, d) + (x) + 0x8F1BBCDC, a = MASTER_RLL32(a, s) + (e), c = MASTER_RLL32(c, 10)
#define __MASTER_RIPEMD160_FUNCTION_JJ(a, b, c, d, e, x, s) a += __MASTER_RIPEMD160_FUNCTION_J(b, c, d) + (x) + 0xA953FD4E, a = MASTER_RLL32(a, s) + (e), c = MASTER_RLL32(c, 10)
#define __MASTER_RIPEMD160_FUNCTION_FFF(a, b, c, d, e, x, s) a += __MASTER_RIPEMD160_FUNCTION_F(b, c, d) + (x), a = MASTER_RLL32(a, s) + (e), c = MASTER_RLL32(c, 10)
#define __MASTER_RIPEMD160_FUNCTION_GGG(a, b, c, d, e, x, s) a += __MASTER_RIPEMD160_FUNCTION_G(b, c, d) + (x) + 0x7A6D76E9, a = MASTER_RLL32(a, s) + (e), c = MASTER_RLL32(c, 10)
#define __MASTER_RIPEMD160_FUNCTION_HHH(a, b, c, d, e, x, s) a += __MASTER_RIPEMD160_FUNCTION_H(b, c, d) + (x) + 0x6D703EF3, a = MASTER_RLL32(a, s) + (e), c = MASTER_RLL32(c, 10)
#define __MASTER_RIPEMD160_FUNCTION_III(a, b, c, d, e, x, s) a += __MASTER_RIPEMD160_FUNCTION_I(b, c, d) + (x) + 0x5C4DD124, a = MASTER_RLL32(a, s) + (e), c = MASTER_RLL32(c, 10)
#define __MASTER_RIPEMD160_FUNCTION_JJJ(a, b, c, d, e, x, s) a += __MASTER_RIPEMD160_FUNCTION_J(b, c, d) + (x) + 0x50A28BE6, a = MASTER_RLL32(a, s) + (e), c = MASTER_RLL32(c, 10)

typedef struct {
	UI4 __h[5];
	UI1 __b[64];
	UI4 __l;
	UI8 __tl;
} MASTER_RIPEMD160;

MASTER_RIPEMD160
MASTER_RIPEMD160_Init(void) {
	MASTER_RIPEMD160 __ripemd160;
	__ripemd160.__h[0] = 0x67452301;
	__ripemd160.__h[1] = 0xEFCDAB89;
	__ripemd160.__h[2] = 0x98BADCFE;
	__ripemd160.__h[3] = 0x10325476;
	__ripemd160.__h[4] = 0xC3D2E1F0;
	__ripemd160.__l = __ripemd160.__tl = 0;
	return __ripemd160;
}

static void
MASTER_RIPEMD160_Transform(MASTER_RIPEMD160 * __ripemd160) {
	UI4 aa = __ripemd160->__h[0];
	UI4 bb = __ripemd160->__h[1];
	UI4 cc = __ripemd160->__h[2];
	UI4 dd = __ripemd160->__h[3];
	UI4 ee = __ripemd160->__h[4];
	UI4 aaa = __ripemd160->__h[0];
	UI4 bbb = __ripemd160->__h[1];
	UI4 ccc = __ripemd160->__h[2];
	UI4 ddd = __ripemd160->__h[3];
	UI4 eee = __ripemd160->__h[4];
	UI4 * x = (UI4 *)__ripemd160->__b;
	
	__MASTER_RIPEMD160_FUNCTION_FF(aa, bb, cc, dd, ee, x[0],  11);
	__MASTER_RIPEMD160_FUNCTION_FF(ee, aa, bb, cc, dd, x[1],  14);
	__MASTER_RIPEMD160_FUNCTION_FF(dd, ee, aa, bb, cc, x[2],  15);
	__MASTER_RIPEMD160_FUNCTION_FF(cc, dd, ee, aa, bb, x[3],  12);
	__MASTER_RIPEMD160_FUNCTION_FF(bb, cc, dd, ee, aa, x[4],  5);
	__MASTER_RIPEMD160_FUNCTION_FF(aa, bb, cc, dd, ee, x[5],  8);
	__MASTER_RIPEMD160_FUNCTION_FF(ee, aa, bb, cc, dd, x[6],  7);
	__MASTER_RIPEMD160_FUNCTION_FF(dd, ee, aa, bb, cc, x[7],  9);
	__MASTER_RIPEMD160_FUNCTION_FF(cc, dd, ee, aa, bb, x[8],  11);
	__MASTER_RIPEMD160_FUNCTION_FF(bb, cc, dd, ee, aa, x[9],  13);
	__MASTER_RIPEMD160_FUNCTION_FF(aa, bb, cc, dd, ee, x[10], 14);
	__MASTER_RIPEMD160_FUNCTION_FF(ee, aa, bb, cc, dd, x[11], 15);
	__MASTER_RIPEMD160_FUNCTION_FF(dd, ee, aa, bb, cc, x[12], 6);
	__MASTER_RIPEMD160_FUNCTION_FF(cc, dd, ee, aa, bb, x[13], 7);
	__MASTER_RIPEMD160_FUNCTION_FF(bb, cc, dd, ee, aa, x[14], 9);
	__MASTER_RIPEMD160_FUNCTION_FF(aa, bb, cc, dd, ee, x[15], 8);
	
	__MASTER_RIPEMD160_FUNCTION_GG(ee, aa, bb, cc, dd, x[7],  7);
	__MASTER_RIPEMD160_FUNCTION_GG(dd, ee, aa, bb, cc, x[4],  6);
	__MASTER_RIPEMD160_FUNCTION_GG(cc, dd, ee, aa, bb, x[13], 8);
	__MASTER_RIPEMD160_FUNCTION_GG(bb, cc, dd, ee, aa, x[1],  13);
	__MASTER_RIPEMD160_FUNCTION_GG(aa, bb, cc, dd, ee, x[10], 11);
	__MASTER_RIPEMD160_FUNCTION_GG(ee, aa, bb, cc, dd, x[6],  9);
	__MASTER_RIPEMD160_FUNCTION_GG(dd, ee, aa, bb, cc, x[15], 7);
	__MASTER_RIPEMD160_FUNCTION_GG(cc, dd, ee, aa, bb, x[3],  15);
	__MASTER_RIPEMD160_FUNCTION_GG(bb, cc, dd, ee, aa, x[12], 7);
	__MASTER_RIPEMD160_FUNCTION_GG(aa, bb, cc, dd, ee, x[0],  12);
	__MASTER_RIPEMD160_FUNCTION_GG(ee, aa, bb, cc, dd, x[9],  15);
	__MASTER_RIPEMD160_FUNCTION_GG(dd, ee, aa, bb, cc, x[5],  9);
	__MASTER_RIPEMD160_FUNCTION_GG(cc, dd, ee, aa, bb, x[2],  11);
	__MASTER_RIPEMD160_FUNCTION_GG(bb, cc, dd, ee, aa, x[14], 7);
	__MASTER_RIPEMD160_FUNCTION_GG(aa, bb, cc, dd, ee, x[11], 13);
	__MASTER_RIPEMD160_FUNCTION_GG(ee, aa, bb, cc, dd, x[8],  12);
	
	__MASTER_RIPEMD160_FUNCTION_HH(dd, ee, aa, bb, cc, x[3],  11);
	__MASTER_RIPEMD160_FUNCTION_HH(cc, dd, ee, aa, bb, x[10], 13);
	__MASTER_RIPEMD160_FUNCTION_HH(bb, cc, dd, ee, aa, x[14], 6);
	__MASTER_RIPEMD160_FUNCTION_HH(aa, bb, cc, dd, ee, x[4],  7);
	__MASTER_RIPEMD160_FUNCTION_HH(ee, aa, bb, cc, dd, x[9],  14);
	__MASTER_RIPEMD160_FUNCTION_HH(dd, ee, aa, bb, cc, x[15], 9);
	__MASTER_RIPEMD160_FUNCTION_HH(cc, dd, ee, aa, bb, x[8],  13);
	__MASTER_RIPEMD160_FUNCTION_HH(bb, cc, dd, ee, aa, x[1],  15);
	__MASTER_RIPEMD160_FUNCTION_HH(aa, bb, cc, dd, ee, x[2],  14);
	__MASTER_RIPEMD160_FUNCTION_HH(ee, aa, bb, cc, dd, x[7],  8);
	__MASTER_RIPEMD160_FUNCTION_HH(dd, ee, aa, bb, cc, x[0],  13);
	__MASTER_RIPEMD160_FUNCTION_HH(cc, dd, ee, aa, bb, x[6],  6);
	__MASTER_RIPEMD160_FUNCTION_HH(bb, cc, dd, ee, aa, x[13], 5);
	__MASTER_RIPEMD160_FUNCTION_HH(aa, bb, cc, dd, ee, x[11], 12);
	__MASTER_RIPEMD160_FUNCTION_HH(ee, aa, bb, cc, dd, x[5],  7);
	__MASTER_RIPEMD160_FUNCTION_HH(dd, ee, aa, bb, cc, x[12], 5);
	
	__MASTER_RIPEMD160_FUNCTION_II(cc, dd, ee, aa, bb, x[1],  11);
	__MASTER_RIPEMD160_FUNCTION_II(bb, cc, dd, ee, aa, x[9],  12);
	__MASTER_RIPEMD160_FUNCTION_II(aa, bb, cc, dd, ee, x[11], 14);
	__MASTER_RIPEMD160_FUNCTION_II(ee, aa, bb, cc, dd, x[10], 15);
	__MASTER_RIPEMD160_FUNCTION_II(dd, ee, aa, bb, cc, x[0],  14);
	__MASTER_RIPEMD160_FUNCTION_II(cc, dd, ee, aa, bb, x[8],  15);
	__MASTER_RIPEMD160_FUNCTION_II(bb, cc, dd, ee, aa, x[12], 9);
	__MASTER_RIPEMD160_FUNCTION_II(aa, bb, cc, dd, ee, x[4],  8);
	__MASTER_RIPEMD160_FUNCTION_II(ee, aa, bb, cc, dd, x[13], 9);
	__MASTER_RIPEMD160_FUNCTION_II(dd, ee, aa, bb, cc, x[3],  14);
	__MASTER_RIPEMD160_FUNCTION_II(cc, dd, ee, aa, bb, x[7],  5);
	__MASTER_RIPEMD160_FUNCTION_II(bb, cc, dd, ee, aa, x[15], 6);
	__MASTER_RIPEMD160_FUNCTION_II(aa, bb, cc, dd, ee, x[14], 8);
	__MASTER_RIPEMD160_FUNCTION_II(ee, aa, bb, cc, dd, x[5],  6);
	__MASTER_RIPEMD160_FUNCTION_II(dd, ee, aa, bb, cc, x[6],  5);
	__MASTER_RIPEMD160_FUNCTION_II(cc, dd, ee, aa, bb, x[2],  12);
	
	__MASTER_RIPEMD160_FUNCTION_JJ(bb, cc, dd, ee, aa, x[4],  9);
	__MASTER_RIPEMD160_FUNCTION_JJ(aa, bb, cc, dd, ee, x[0],  15);
	__MASTER_RIPEMD160_FUNCTION_JJ(ee, aa, bb, cc, dd, x[5],  5);
	__MASTER_RIPEMD160_FUNCTION_JJ(dd, ee, aa, bb, cc, x[9],  11);
	__MASTER_RIPEMD160_FUNCTION_JJ(cc, dd, ee, aa, bb, x[7],  6);
	__MASTER_RIPEMD160_FUNCTION_JJ(bb, cc, dd, ee, aa, x[12], 8);
	__MASTER_RIPEMD160_FUNCTION_JJ(aa, bb, cc, dd, ee, x[2],  13);
	__MASTER_RIPEMD160_FUNCTION_JJ(ee, aa, bb, cc, dd, x[10], 12);
	__MASTER_RIPEMD160_FUNCTION_JJ(dd, ee, aa, bb, cc, x[14], 5);
	__MASTER_RIPEMD160_FUNCTION_JJ(cc, dd, ee, aa, bb, x[1],  12);
	__MASTER_RIPEMD160_FUNCTION_JJ(bb, cc, dd, ee, aa, x[3],  13);
	__MASTER_RIPEMD160_FUNCTION_JJ(aa, bb, cc, dd, ee, x[8],  14);
	__MASTER_RIPEMD160_FUNCTION_JJ(ee, aa, bb, cc, dd, x[11], 11);
	__MASTER_RIPEMD160_FUNCTION_JJ(dd, ee, aa, bb, cc, x[6],  8);
	__MASTER_RIPEMD160_FUNCTION_JJ(cc, dd, ee, aa, bb, x[15], 5);
	__MASTER_RIPEMD160_FUNCTION_JJ(bb, cc, dd, ee, aa, x[13], 6);
	
	__MASTER_RIPEMD160_FUNCTION_JJJ(aaa, bbb, ccc, ddd, eee, x[5],  8);
	__MASTER_RIPEMD160_FUNCTION_JJJ(eee, aaa, bbb, ccc, ddd, x[14], 9);
	__MASTER_RIPEMD160_FUNCTION_JJJ(ddd, eee, aaa, bbb, ccc, x[7],  9);
	__MASTER_RIPEMD160_FUNCTION_JJJ(ccc, ddd, eee, aaa, bbb, x[0],  11);
	__MASTER_RIPEMD160_FUNCTION_JJJ(bbb, ccc, ddd, eee, aaa, x[9],  13);
	__MASTER_RIPEMD160_FUNCTION_JJJ(aaa, bbb, ccc, ddd, eee, x[2],  15);
	__MASTER_RIPEMD160_FUNCTION_JJJ(eee, aaa, bbb, ccc, ddd, x[11], 15);
	__MASTER_RIPEMD160_FUNCTION_JJJ(ddd, eee, aaa, bbb, ccc, x[4],  5);
	__MASTER_RIPEMD160_FUNCTION_JJJ(ccc, ddd, eee, aaa, bbb, x[13], 7);
	__MASTER_RIPEMD160_FUNCTION_JJJ(bbb, ccc, ddd, eee, aaa, x[6],  7);
	__MASTER_RIPEMD160_FUNCTION_JJJ(aaa, bbb, ccc, ddd, eee, x[15], 8);
	__MASTER_RIPEMD160_FUNCTION_JJJ(eee, aaa, bbb, ccc, ddd, x[8],  11);
	__MASTER_RIPEMD160_FUNCTION_JJJ(ddd, eee, aaa, bbb, ccc, x[1],  14);
	__MASTER_RIPEMD160_FUNCTION_JJJ(ccc, ddd, eee, aaa, bbb, x[10], 14);
	__MASTER_RIPEMD160_FUNCTION_JJJ(bbb, ccc, ddd, eee, aaa, x[3],  12);
	__MASTER_RIPEMD160_FUNCTION_JJJ(aaa, bbb, ccc, ddd, eee, x[12], 6);
	
	__MASTER_RIPEMD160_FUNCTION_III(eee, aaa, bbb, ccc, ddd, x[6],   9);
	__MASTER_RIPEMD160_FUNCTION_III(ddd, eee, aaa, bbb, ccc, x[11], 13);
	__MASTER_RIPEMD160_FUNCTION_III(ccc, ddd, eee, aaa, bbb, x[3],  15);
	__MASTER_RIPEMD160_FUNCTION_III(bbb, ccc, ddd, eee, aaa, x[7],  7);
	__MASTER_RIPEMD160_FUNCTION_III(aaa, bbb, ccc, ddd, eee, x[0],  12);
	__MASTER_RIPEMD160_FUNCTION_III(eee, aaa, bbb, ccc, ddd, x[13], 8);
	__MASTER_RIPEMD160_FUNCTION_III(ddd, eee, aaa, bbb, ccc, x[5],  9);
	__MASTER_RIPEMD160_FUNCTION_III(ccc, ddd, eee, aaa, bbb, x[10], 11);
	__MASTER_RIPEMD160_FUNCTION_III(bbb, ccc, ddd, eee, aaa, x[14], 7);
	__MASTER_RIPEMD160_FUNCTION_III(aaa, bbb, ccc, ddd, eee, x[15], 7);
	__MASTER_RIPEMD160_FUNCTION_III(eee, aaa, bbb, ccc, ddd, x[8],  12);
	__MASTER_RIPEMD160_FUNCTION_III(ddd, eee, aaa, bbb, ccc, x[12], 7);
	__MASTER_RIPEMD160_FUNCTION_III(ccc, ddd, eee, aaa, bbb, x[4],  6);
	__MASTER_RIPEMD160_FUNCTION_III(bbb, ccc, ddd, eee, aaa, x[9],  15);
	__MASTER_RIPEMD160_FUNCTION_III(aaa, bbb, ccc, ddd, eee, x[1],  13);
	__MASTER_RIPEMD160_FUNCTION_III(eee, aaa, bbb, ccc, ddd, x[2],  11);
	
	__MASTER_RIPEMD160_FUNCTION_HHH(ddd, eee, aaa, bbb, ccc, x[15], 9);
	__MASTER_RIPEMD160_FUNCTION_HHH(ccc, ddd, eee, aaa, bbb, x[5],  7);
	__MASTER_RIPEMD160_FUNCTION_HHH(bbb, ccc, ddd, eee, aaa, x[1],  15);
	__MASTER_RIPEMD160_FUNCTION_HHH(aaa, bbb, ccc, ddd, eee, x[3],  11);
	__MASTER_RIPEMD160_FUNCTION_HHH(eee, aaa, bbb, ccc, ddd, x[7],  8);
	__MASTER_RIPEMD160_FUNCTION_HHH(ddd, eee, aaa, bbb, ccc, x[14], 6);
	__MASTER_RIPEMD160_FUNCTION_HHH(ccc, ddd, eee, aaa, bbb, x[6],  6);
	__MASTER_RIPEMD160_FUNCTION_HHH(bbb, ccc, ddd, eee, aaa, x[9],  14);
	__MASTER_RIPEMD160_FUNCTION_HHH(aaa, bbb, ccc, ddd, eee, x[11], 12);
	__MASTER_RIPEMD160_FUNCTION_HHH(eee, aaa, bbb, ccc, ddd, x[8],  13);
	__MASTER_RIPEMD160_FUNCTION_HHH(ddd, eee, aaa, bbb, ccc, x[12], 5);
	__MASTER_RIPEMD160_FUNCTION_HHH(ccc, ddd, eee, aaa, bbb, x[2],  14);
	__MASTER_RIPEMD160_FUNCTION_HHH(bbb, ccc, ddd, eee, aaa, x[10], 13);
	__MASTER_RIPEMD160_FUNCTION_HHH(aaa, bbb, ccc, ddd, eee, x[0],  13);
	__MASTER_RIPEMD160_FUNCTION_HHH(eee, aaa, bbb, ccc, ddd, x[4],  7);
	__MASTER_RIPEMD160_FUNCTION_HHH(ddd, eee, aaa, bbb, ccc, x[13], 5);
	
	__MASTER_RIPEMD160_FUNCTION_GGG(ccc, ddd, eee, aaa, bbb, x[8],  15);
	__MASTER_RIPEMD160_FUNCTION_GGG(bbb, ccc, ddd, eee, aaa, x[6],  5);
	__MASTER_RIPEMD160_FUNCTION_GGG(aaa, bbb, ccc, ddd, eee, x[4],  8);
	__MASTER_RIPEMD160_FUNCTION_GGG(eee, aaa, bbb, ccc, ddd, x[1],  11);
	__MASTER_RIPEMD160_FUNCTION_GGG(ddd, eee, aaa, bbb, ccc, x[3],  14);
	__MASTER_RIPEMD160_FUNCTION_GGG(ccc, ddd, eee, aaa, bbb, x[11], 14);
	__MASTER_RIPEMD160_FUNCTION_GGG(bbb, ccc, ddd, eee, aaa, x[15], 6);
	__MASTER_RIPEMD160_FUNCTION_GGG(aaa, bbb, ccc, ddd, eee, x[0],  14);
	__MASTER_RIPEMD160_FUNCTION_GGG(eee, aaa, bbb, ccc, ddd, x[5],  6);
	__MASTER_RIPEMD160_FUNCTION_GGG(ddd, eee, aaa, bbb, ccc, x[12], 9);
	__MASTER_RIPEMD160_FUNCTION_GGG(ccc, ddd, eee, aaa, bbb, x[2],  12);
	__MASTER_RIPEMD160_FUNCTION_GGG(bbb, ccc, ddd, eee, aaa, x[13], 9);
	__MASTER_RIPEMD160_FUNCTION_GGG(aaa, bbb, ccc, ddd, eee, x[9],  12);
	__MASTER_RIPEMD160_FUNCTION_GGG(eee, aaa, bbb, ccc, ddd, x[7],  5);
	__MASTER_RIPEMD160_FUNCTION_GGG(ddd, eee, aaa, bbb, ccc, x[10], 15);
	__MASTER_RIPEMD160_FUNCTION_GGG(ccc, ddd, eee, aaa, bbb, x[14], 8);
	
	__MASTER_RIPEMD160_FUNCTION_FFF(bbb, ccc, ddd, eee, aaa, x[12], 8);
	__MASTER_RIPEMD160_FUNCTION_FFF(aaa, bbb, ccc, ddd, eee, x[15], 5);
	__MASTER_RIPEMD160_FUNCTION_FFF(eee, aaa, bbb, ccc, ddd, x[10], 12);
	__MASTER_RIPEMD160_FUNCTION_FFF(ddd, eee, aaa, bbb, ccc, x[4],  9);
	__MASTER_RIPEMD160_FUNCTION_FFF(ccc, ddd, eee, aaa, bbb, x[1],  12);
	__MASTER_RIPEMD160_FUNCTION_FFF(bbb, ccc, ddd, eee, aaa, x[5],  5);
	__MASTER_RIPEMD160_FUNCTION_FFF(aaa, bbb, ccc, ddd, eee, x[8],  14);
	__MASTER_RIPEMD160_FUNCTION_FFF(eee, aaa, bbb, ccc, ddd, x[7],  6);
	__MASTER_RIPEMD160_FUNCTION_FFF(ddd, eee, aaa, bbb, ccc, x[6],  8);
	__MASTER_RIPEMD160_FUNCTION_FFF(ccc, ddd, eee, aaa, bbb, x[2],  13);
	__MASTER_RIPEMD160_FUNCTION_FFF(bbb, ccc, ddd, eee, aaa, x[13], 6);
	__MASTER_RIPEMD160_FUNCTION_FFF(aaa, bbb, ccc, ddd, eee, x[14], 5);
	__MASTER_RIPEMD160_FUNCTION_FFF(eee, aaa, bbb, ccc, ddd, x[0],  15);
	__MASTER_RIPEMD160_FUNCTION_FFF(ddd, eee, aaa, bbb, ccc, x[3],  13);
	__MASTER_RIPEMD160_FUNCTION_FFF(ccc, ddd, eee, aaa, bbb, x[9],  11);
	__MASTER_RIPEMD160_FUNCTION_FFF(bbb, ccc, ddd, eee, aaa, x[11], 11);
	
	ddd = __ripemd160->__h[1] + cc + ddd;
	__ripemd160->__h[1] = __ripemd160->__h[2] + dd + eee;
	__ripemd160->__h[2] = __ripemd160->__h[3] + ee + aaa;
	__ripemd160->__h[3] = __ripemd160->__h[4] + aa + bbb;
	__ripemd160->__h[4] = __ripemd160->__h[0] + bb + ccc;
	__ripemd160->__h[0] = ddd;
}

void
MASTER_RIPEMD160_Update(MASTER_RIPEMD160 * __ripemd160, const char * __s, UI4 __l) {
	UI4 n;
	while (__l > 0) {
		n = (__l < 64 - __ripemd160->__l) ? (__l) : (64 - __ripemd160->__l);
		memcpy(__ripemd160->__b + __ripemd160->__l, __s, n);
		__ripemd160->__l += n;
		__ripemd160->__tl += n;
		__s += n;
		__l -= n;
		if (__ripemd160->__l == 64) {
			MASTER_RIPEMD160_Transform(__ripemd160);
			__ripemd160->__l = 0;
		}
	}
}

void
MASTER_RIPEMD160_Final(MASTER_RIPEMD160 * __ripemd160, UI1 * hash_output) {
	UI4 pad;
	UI8 tl;
	tl = __ripemd160->__tl * 8;
	if (__ripemd160->__l < 56) pad = 56 - __ripemd160->__l;
	else pad = 64 + 56 - __ripemd160->__l;
	static const UI1 padding[64] = {
	 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
	};
	MASTER_RIPEMD160_Update(__ripemd160, (const char *)padding, pad);
	*((UI4 *)&__ripemd160->__b[14 * sizeof(UI4)]) = tl;
	*((UI4 *)&__ripemd160->__b[15 * sizeof(UI4)]) = tl >> 32;
	MASTER_RIPEMD160_Transform(__ripemd160);
	memcpy(hash_output, __ripemd160->__h, 20);
}

void
MASTER_RIPEMD160_CalculateHashSum(const char * __s, UI4 __l, UI1 * hash_output) {
	MASTER_RIPEMD160 __ripemd160 = MASTER_RIPEMD160_Init();
	MASTER_RIPEMD160_Update(&__ripemd160, __s, __l);
	MASTER_RIPEMD160_Final(&__ripemd160, hash_output);
}

#undef __MASTER_RIPEMD160_FUNCTION_F
#undef __MASTER_RIPEMD160_FUNCTION_G
#undef __MASTER_RIPEMD160_FUNCTION_H
#undef __MASTER_RIPEMD160_FUNCTION_I
#undef __MASTER_RIPEMD160_FUNCTION_J
#undef __MASTER_RIPEMD160_FUNCTION_FF
#undef __MASTER_RIPEMD160_FUNCTION_GG
#undef __MASTER_RIPEMD160_FUNCTION_HH
#undef __MASTER_RIPEMD160_FUNCTION_II
#undef __MASTER_RIPEMD160_FUNCTION_JJ
#undef __MASTER_RIPEMD160_FUNCTION_FFF
#undef __MASTER_RIPEMD160_FUNCTION_GGG
#undef __MASTER_RIPEMD160_FUNCTION_HHH
#undef __MASTER_RIPEMD160_FUNCTION_III
#undef __MASTER_RIPEMD160_FUNCTION_JJJ

// !!# RIPEMD160

// #!! RIPEMD256

#define __MASTER_RIPEMD256_FUNCTION_F(x, y, z) ((x) ^ (y) ^ (z))
#define __MASTER_RIPEMD256_FUNCTION_G(x, y, z) (((x) & (y)) | (~(x) & (z)))
#define __MASTER_RIPEMD256_FUNCTION_H(x, y, z) (((x) | ~(y)) ^ (z))
#define __MASTER_RIPEMD256_FUNCTION_I(x, y, z) (((x) & (z)) | ((y) & ~(z)))
#define __MASTER_RIPEMD256_FUNCTION_FUNC(i, x, y, z) ((i <= 15) ? __MASTER_RIPEMD256_FUNCTION_F(x, y, z) : \
													 (i <= 31) ? __MASTER_RIPEMD256_FUNCTION_G(x, y, z) : \
													 (i <= 47) ? __MASTER_RIPEMD256_FUNCTION_H(x, y, z) : __MASTER_RIPEMD256_FUNCTION_I(x, y, z))

typedef struct {
	UI4 __h[8];
	UI1 __b[64];
	UI4 __l;
	UI8 __tl;
} MASTER_RIPEMD256;

MASTER_RIPEMD256
MASTER_RIPEMD256_Init(void) {
	MASTER_RIPEMD256 __ripemd256;
	__ripemd256.__h[0] = 0x67452301;
	__ripemd256.__h[1] = 0xEFCDAB89;
	__ripemd256.__h[2] = 0x98BADCFE;
	__ripemd256.__h[3] = 0x10325476;
	__ripemd256.__h[4] = 0x76543210;
	__ripemd256.__h[5] = 0xFEDCBA98;
	__ripemd256.__h[6] = 0x89ABCDEF;
	__ripemd256.__h[7] = 0x01234567;
	__ripemd256.__l = __ripemd256.__tl = 0;
	return __ripemd256;
}

static void
MASTER_RIPEMD256_Transform(MASTER_RIPEMD256 * __ripemd256) {
	UI4 aa = __ripemd256->__h[0];
	UI4 bb = __ripemd256->__h[1];
	UI4 cc = __ripemd256->__h[2];
	UI4 dd = __ripemd256->__h[3];
	UI4 aaa = __ripemd256->__h[4];
	UI4 bbb = __ripemd256->__h[5];
	UI4 ccc = __ripemd256->__h[6];
	UI4 ddd = __ripemd256->__h[7];
	UI4 * x = (UI4 *)__ripemd256->__b;
	UI4 t;
	UI4 i = 0;

	static const UI4 k[8] = {
		0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x00000000
	};

	static const UI1 r[128] = {
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
		7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
		3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
		1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
		5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
		6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
		15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
		8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14
	};
	static const UI1 s[128] = {
		11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
		7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
		11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
		11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
		8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
		9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
		9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
		15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8
	};
	
	for (i = 0; i < 64; i++) {
		t = MASTER_RLL32(aa + __MASTER_RIPEMD256_FUNCTION_FUNC(i, bb, cc, dd) + x[r[i]] + k[i/16], s[i]);
		aa = dd;
		dd = cc;
		cc = bb;
		bb = t;
		
		t = MASTER_RLL32(aaa + __MASTER_RIPEMD256_FUNCTION_FUNC(63 - i, bbb, ccc, ddd) + x[r[64 + i]] + k[4 + (i/16)], s[64 + i]);
		aaa = ddd;
		ddd = ccc;
		ccc = bbb;
		bbb = t;

		if (i == 15) { t = aa; aa = aaa; aaa = t; }
		otherwise (i == 31) { t = bb; bb = bbb; bbb = t; }
		otherwise (i == 47) { t = cc; cc = ccc; ccc = t; }
		otherwise (i == 63) { t = dd; dd = ddd; ddd = t; }
	}

	__ripemd256->__h[0] += aa;
	__ripemd256->__h[1] += bb;
	__ripemd256->__h[2] += cc;
	__ripemd256->__h[3] += dd;
	__ripemd256->__h[4] += aaa;
	__ripemd256->__h[5] += bbb;
	__ripemd256->__h[6] += ccc;
	__ripemd256->__h[7] += ddd;
}

void
MASTER_RIPEMD256_Update(MASTER_RIPEMD256 * __ripemd256, const char * __s, UI4 __l) {
	UI4 n;
	while (__l > 0) {
		n = (__l < 64 - __ripemd256->__l) ? (__l) : (64 - __ripemd256->__l);
		memcpy(__ripemd256->__b + __ripemd256->__l, __s, n);
		__ripemd256->__l += n;
		__ripemd256->__tl += n;
		__s += n;
		__l -= n;
		if (__ripemd256->__l == 64) {
			MASTER_RIPEMD256_Transform(__ripemd256);
			__ripemd256->__l = 0;
		}
	}
}

void
MASTER_RIPEMD256_Final(MASTER_RIPEMD256 * __ripemd256, UI1 * hash_output) {
	UI4 pad;
	UI8 tl;
	tl = __ripemd256->__tl * 8;
	if (__ripemd256->__l < 56) pad = 56 - __ripemd256->__l;
	else pad = 64 + 56 - __ripemd256->__l;
	static const UI1 padding[64] = {
	 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
	};
	MASTER_RIPEMD256_Update(__ripemd256, (const char *)padding, pad);
	*((UI4 *)&__ripemd256->__b[14 * sizeof(UI4)]) = tl;
	*((UI4 *)&__ripemd256->__b[15 * sizeof(UI4)]) = tl >> 32;
	MASTER_RIPEMD256_Transform(__ripemd256);
	memcpy(hash_output, __ripemd256->__h, 32);
}

void
MASTER_RIPEMD256_CalculateHashSum(const char * __s, UI4 __l, UI1 * hash_output) {
	MASTER_RIPEMD256 __ripemd256 = MASTER_RIPEMD256_Init();
	MASTER_RIPEMD256_Update(&__ripemd256, __s, __l);
	MASTER_RIPEMD256_Final(&__ripemd256, hash_output);
}

#undef __MASTER_RIPEMD256_FUNCTION_F
#undef __MASTER_RIPEMD256_FUNCTION_G
#undef __MASTER_RIPEMD256_FUNCTION_H
#undef __MASTER_RIPEMD256_FUNCTION_I
#undef __MASTER_RIPEMD256_FUNCTION_FUNC

// !!# RIPEMD256

// #!! RIPEMD320

#define __MASTER_RIPEMD320_FUNCTION_F(x, y, z) ((x) ^ (y) ^ (z))
#define __MASTER_RIPEMD320_FUNCTION_G(x, y, z) (((x) & (y)) | (~(x) & (z)))
#define __MASTER_RIPEMD320_FUNCTION_H(x, y, z) (((x) | ~(y)) ^ (z))
#define __MASTER_RIPEMD320_FUNCTION_I(x, y, z) (((x) & (z)) | ((y) & ~(z)))
#define __MASTER_RIPEMD320_FUNCTION_J(x, y, z) (x ^ (y | ~(z)))
#define __MASTER_RIPEMD320_FUNCTION_FUNC(i, x, y, z) ((i <= 15) ? __MASTER_RIPEMD320_FUNCTION_F(x, y, z) : \
													 (i <= 31) ? __MASTER_RIPEMD320_FUNCTION_G(x, y, z) : \
													 (i <= 47) ? __MASTER_RIPEMD320_FUNCTION_H(x, y, z) : \
													 (i <= 63) ? __MASTER_RIPEMD320_FUNCTION_I(x, y, z) : __MASTER_RIPEMD320_FUNCTION_J(x, y, z))

typedef struct {
	UI4 __h[10];
	UI1 __b[64];
	UI4 __l;
	UI8 __tl;
} MASTER_RIPEMD320;

MASTER_RIPEMD320
MASTER_RIPEMD320_Init(void) {
	MASTER_RIPEMD320 __ripemd320;
	__ripemd320.__h[0] = 0x67452301;
	__ripemd320.__h[1] = 0xEFCDAB89;
	__ripemd320.__h[2] = 0x98BADCFE;
	__ripemd320.__h[3] = 0x10325476;
	__ripemd320.__h[4] = 0xC3D2E1F0;
	__ripemd320.__h[5] = 0x76543210;
	__ripemd320.__h[6] = 0xFEDCBA98;
	__ripemd320.__h[7] = 0x89ABCDEF;
	__ripemd320.__h[8] = 0x01234567;
	__ripemd320.__h[9] = 0x3C2D1E0F;
	__ripemd320.__l = __ripemd320.__tl = 0;
	return __ripemd320;
}

static void
MASTER_RIPEMD320_Transform(MASTER_RIPEMD320 * __ripemd320) {
	UI4 aa = __ripemd320->__h[0];
	UI4 bb = __ripemd320->__h[1];
	UI4 cc = __ripemd320->__h[2];
	UI4 dd = __ripemd320->__h[3];
	UI4 ee = __ripemd320->__h[4];
	UI4 aaa = __ripemd320->__h[5];
	UI4 bbb = __ripemd320->__h[6];
	UI4 ccc = __ripemd320->__h[7];
	UI4 ddd = __ripemd320->__h[8];
	UI4 eee = __ripemd320->__h[9];
	UI4 * x = (UI4 *)__ripemd320->__b;
	UI4 t;
	UI4 i = 0;

	static const UI4 k[10] = {
		0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E, 0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0x00000000
	};

	static const UI1 r[160] = {
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
		7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
		3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
		1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
		4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13,
		5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
		6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
		15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
		8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
		12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11
	};
	static const UI1 s[160] = {
		11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
		7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
		11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
		11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
		9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6,
		8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
		9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
		9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
		15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
		8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11
	};
	
	for (i = 0; i < 80; i++) {
		t = MASTER_RLL32(aa + __MASTER_RIPEMD320_FUNCTION_FUNC(i, bb, cc, dd) + x[r[i]] + k[i/16], s[i]) + ee;
		aa = ee;
		ee = dd;
		dd = MASTER_RLL32(cc, 10);
		cc = bb;
		bb = t;

		t = MASTER_RLL32(aaa + __MASTER_RIPEMD320_FUNCTION_FUNC(79 - i, bbb, ccc, ddd) + x[r[80 + i]] + k[5 + i/16], s[80 + i]) + eee;
		aaa = eee;
		eee = ddd;
		ddd = MASTER_RLL32(ccc, 10);
		ccc = bbb;
		bbb = t;

		if (i == 15) { t = bb; bb = bbb; bbb = t; }
		otherwise (i == 31) { t = dd; dd = ddd; ddd = t; }
		otherwise (i == 47) { t = aa; aa = aaa; aaa = t; }
		otherwise (i == 63) { t = cc; cc = ccc; ccc = t; }
		otherwise (i == 79) { t = ee; ee = eee; eee = t; }
	}

	__ripemd320->__h[0] += aa;
	__ripemd320->__h[1] += bb;
	__ripemd320->__h[2] += cc;
	__ripemd320->__h[3] += dd;
	__ripemd320->__h[4] += ee;
	__ripemd320->__h[5] += aaa;
	__ripemd320->__h[6] += bbb;
	__ripemd320->__h[7] += ccc;
	__ripemd320->__h[8] += ddd;
	__ripemd320->__h[9] += eee;
}

void
MASTER_RIPEMD320_Update(MASTER_RIPEMD320 * __ripemd320, const char * __s, UI4 __l) {
	UI4 n;
	while (__l > 0) {
		n = (__l < 64 - __ripemd320->__l) ? (__l) : (64 - __ripemd320->__l);
		memcpy(__ripemd320->__b + __ripemd320->__l, __s, n);
		__ripemd320->__l += n;
		__ripemd320->__tl += n;
		__s += n;
		__l -= n;
		if (__ripemd320->__l == 64) {
			MASTER_RIPEMD320_Transform(__ripemd320);
			__ripemd320->__l = 0;
		}
	}
}

void
MASTER_RIPEMD320_Final(MASTER_RIPEMD320 * __ripemd320, UI1 * hash_output) {
	UI4 pad;
	UI8 tl;
	tl = __ripemd320->__tl * 8;
	if (__ripemd320->__l < 56) pad = 56 - __ripemd320->__l;
	else pad = 64 + 56 - __ripemd320->__l;
	static const UI1 padding[64] = {
	 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
	};
	MASTER_RIPEMD320_Update(__ripemd320, (const char *)padding, pad);
	*((UI4 *)&__ripemd320->__b[14 * sizeof(UI4)]) = tl;
	*((UI4 *)&__ripemd320->__b[15 * sizeof(UI4)]) = tl >> 32;
	MASTER_RIPEMD320_Transform(__ripemd320);
	memcpy(hash_output, __ripemd320->__h, 40);
}

void
MASTER_RIPEMD320_CalculateHashSum(const char * __s, UI4 __l, UI1 * hash_output) {
	MASTER_RIPEMD320 __ripemd320 = MASTER_RIPEMD320_Init();
	MASTER_RIPEMD320_Update(&__ripemd320, __s, __l);
	MASTER_RIPEMD320_Final(&__ripemd320, hash_output);
}

#undef __MASTER_RIPEMD320_FUNCTION_F
#undef __MASTER_RIPEMD320_FUNCTION_G
#undef __MASTER_RIPEMD320_FUNCTION_H
#undef __MASTER_RIPEMD320_FUNCTION_I
#undef __MASTER_RIPEMD320_FUNCTION_J
#undef __MASTER_RIPEMD320_FUNCTION_FUNC

// !!# RIPEMD320

// !# RIPEMD

// #! MURMURHASH2

#define __MASTER_MURMURHASH2_FUNCTION_MMIX(h, k) { k *= m; k ^= k >> r; k *= m; h *= m; h ^= k; }

void
MASTER_MurmurHash2_CalculateHashSum(const char * __s, unsigned int __l, UI1 * hash_output) {
	const UI4 m = 0x5bd1e995;
	const UI4 seed = 0;
	const int r = 24;
	UI4 h = seed ^ __l;
	UI4 k = 0;
	while (__l >= 4) {
		k = *(UI4 *)__s;
		
		k *= m;
		k ^= k >> r;
		k *= m;
		
		h *= m;
		h ^= k;
		
		__s += 4;
		__l -= 4;
	}
	switch (__l) {
		case 3:
			h ^= __s[2] << 16;
		case 2:
			h ^= __s[1] << 8;
		case 1:
			h ^= __s[0];
			h *= m;
	};
	h ^= h >> 13;
	h *= m;
	h ^= h >> 15;
	
	hash_output[0] = (h >> 24) & 0xFF;
	hash_output[1] = (h >> 16) & 0xFF;
	hash_output[2] = (h >> 8) & 0xFF;
	hash_output[3] = (h >> 0) & 0xFF;
}

void
MASTER_MurmurHash2A_CalculateHashSum(const char * __s, UI4 __l, UI4 seed, UI1 * hash_output) {
	const UI4 m = 0x5bd1e995;
	const int r = 24;
	UI4 l = __l;

	UI4 h = seed;
	UI4 k, t = 0;

	while (__l >= 4) {
		k = *(UI4 *)__s;
		__MASTER_MURMURHASH2_FUNCTION_MMIX(h,k);
		__s += 4;
		__l -= 4;
	}

	switch(__l) {
		case 3:
			t ^= __s[2] << 16;
		case 2:
			t ^= __s[1] << 8;
		case 1:
			t ^= __s[0];
	};

	__MASTER_MURMURHASH2_FUNCTION_MMIX(h,t);
	__MASTER_MURMURHASH2_FUNCTION_MMIX(h,l);

	h ^= h >> 13;
	h *= m;
	h ^= h >> 15;

	hash_output[0] = (h >> 24) & 0xFF;
	hash_output[1] = (h >> 16) & 0xFF;
	hash_output[2] = (h >> 8) & 0xFF;
	hash_output[3] = (h >> 0) & 0xFF;
}

#undef __MASTER_MURMURHASH2_FUNCTION_MMIX

// !# MURMURHASH2

// #! BLAKE

// #!! BLAKE2B

#define __MASTER_BLAKE2B_FUNCTION_G(x, y, a, b, c, d) do { \
	a = a + b + x; \
	d = MASTER_RLR64(d ^ a, 32); \
	c += d; \
	b = MASTER_RLR64(b ^ c, 24); \
	a = a + b + y; \
	d = MASTER_RLR64(d ^ a, 16); \
	c += d; \
	b = MASTER_RLR64(b ^ c, 63); \
} while (0);
#define __MASTER_BLAKE2S_FUNCTION_G(x, y, a, b, c, d) do { \
	a = a + b + x; \
	d = MASTER_RLR32(d ^ a, 16); \
	c += d; \
	b = MASTER_RLR32(b ^ c, 12); \
	a = a + b + y; \
	d = MASTER_RLR32(d ^ a, 8); \
	c += d; \
	b = MASTER_RLR32(b ^ c, 7); \
} while (0);

static const UI1 MASTER_BLAKE2B_TABLE_SIGMA[10][16] = {
	{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
	{ 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 },
	{ 11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4 },
	{ 7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8 },
	{ 9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13 },
	{ 2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9 },
	{ 12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11 },
	{ 13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10 },
	{ 6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5 },
	{ 10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0 },
};

static const UI8 MASTER_BLAKE2B_TABLE_IV[8] = {
	0x6A09E667F3BCC908, 0xBB67AE8584CAA73B,
	0x3C6EF372FE94F82B, 0xA54FF53A5F1D36F1,
	0x510E527FADE682D1, 0x9B05688C2B3E6C1F,
	0x1F83D9ABFB41BD6B, 0x5BE0CD19137E2179
};

typedef struct {
	UI1 __b[128];
	UI8 __h[8];
	UI8 __t[2];
	UI4 __c, __outl;
} MASTER_BLAKE2B;

static void
MASTER_BLAKE2B_Compress(MASTER_BLAKE2B * __blake2b, const UI1 __is_last) {
	UI8 i;
	UI8 v[16], m[16];
	for (i = 0; i < 8; i++) {
		v[i] = __blake2b->__h[i];
		v[i + 8] = MASTER_BLAKE2B_TABLE_IV[i];
	}
	v[12] ^= __blake2b->__t[0];
	v[13] ^= __blake2b->__t[1];
	if (__is_last == 1) v[14] = ~v[14];
	for (i = 0; i < 16; i++)
		m[i] = __MASTER_CHANGE_ENDIAN_64(&__blake2b->__b[i * 8]);
	for (i = 0; i < 12; i++) {
		__MASTER_BLAKE2B_FUNCTION_G(m[MASTER_BLAKE2B_TABLE_SIGMA[i % 10][0]], m[MASTER_BLAKE2B_TABLE_SIGMA[i % 10][1]], v[0], v[4], v[8], v[12]);
		__MASTER_BLAKE2B_FUNCTION_G(m[MASTER_BLAKE2B_TABLE_SIGMA[i % 10][2]], m[MASTER_BLAKE2B_TABLE_SIGMA[i % 10][3]], v[1], v[5], v[9], v[13]);
		__MASTER_BLAKE2B_FUNCTION_G(m[MASTER_BLAKE2B_TABLE_SIGMA[i % 10][4]], m[MASTER_BLAKE2B_TABLE_SIGMA[i % 10][5]], v[2], v[6], v[10], v[14]);
		__MASTER_BLAKE2B_FUNCTION_G(m[MASTER_BLAKE2B_TABLE_SIGMA[i % 10][6]], m[MASTER_BLAKE2B_TABLE_SIGMA[i % 10][7]], v[3], v[7], v[11], v[15]);
		__MASTER_BLAKE2B_FUNCTION_G(m[MASTER_BLAKE2B_TABLE_SIGMA[i % 10][8]], m[MASTER_BLAKE2B_TABLE_SIGMA[i % 10][9]], v[0], v[5], v[10], v[15]);
		__MASTER_BLAKE2B_FUNCTION_G(m[MASTER_BLAKE2B_TABLE_SIGMA[i % 10][10]], m[MASTER_BLAKE2B_TABLE_SIGMA[i % 10][11]], v[1], v[6], v[11], v[12]);
		__MASTER_BLAKE2B_FUNCTION_G(m[MASTER_BLAKE2B_TABLE_SIGMA[i % 10][12]], m[MASTER_BLAKE2B_TABLE_SIGMA[i % 10][13]], v[2], v[7], v[8], v[13]);
		__MASTER_BLAKE2B_FUNCTION_G(m[MASTER_BLAKE2B_TABLE_SIGMA[i % 10][14]], m[MASTER_BLAKE2B_TABLE_SIGMA[i % 10][15]], v[3], v[4], v[9], v[14]);
	}
	for (i = 0; i < 8; i++) __blake2b->__h[i] ^= v[i] ^ v[8 + i];
}

/* #! outl must be (0; 64] !# */
MASTER_BLAKE2B
MASTER_BLAKE2B_Init(UI4 outl) {
	MASTER_BLAKE2B __blake2b;
	UI4 i;
	for (i = 0; i < 8; i++)
		__blake2b.__h[i] = MASTER_BLAKE2B_TABLE_IV[i];
	__blake2b.__h[0] ^= 0x01010000 ^ outl;
	__blake2b.__t[0] = __blake2b.__t[1] = __blake2b.__c = 0;
	__blake2b.__outl = outl;
	for (i = 0; i < 128; i++)
		__blake2b.__b[i] = 0;
	return __blake2b;
}

void
MASTER_BLAKE2B_Update(MASTER_BLAKE2B * __blake2b, const char * __s, UI8 __l) {
	UI8 i;
	for (i = 0; i < __l; i++) {
		if (__blake2b->__c == 128) {
			__blake2b->__t[0] += __blake2b->__c;
			if (__blake2b->__t[0] < __blake2b->__c)
				__blake2b->__t[1]++;
			MASTER_BLAKE2B_Compress(__blake2b, 0);
			__blake2b->__c = 0;
		}
		__blake2b->__b[__blake2b->__c++] = __s[i];
	}
}

void
MASTER_BLAKE2B_Final(MASTER_BLAKE2B * __blake2b, UI1 * hash_output) {
	UI8 i;
	__blake2b->__t[0] += __blake2b->__c;
	if (__blake2b->__t[0] < __blake2b->__c)
		__blake2b->__t[1]++;
	while (__blake2b->__c < 128)
		__blake2b->__b[__blake2b->__c++] = 0;
	MASTER_BLAKE2B_Compress(__blake2b, 1);
	for (i = 0; i < __blake2b->__outl; i++)
		hash_output[i] = (__blake2b->__h[i >> 3] >> (8 * (i & 7))) & 0xFF;
}

void
MASTER_BLAKE2B_CalculateHashSum(const char * __s, UI8 __l, UI1 * hash_output, UI4 outl) {
	MASTER_BLAKE2B __blake2b = MASTER_BLAKE2B_Init(outl);
	MASTER_BLAKE2B_Update(&__blake2b, __s, __l);
	MASTER_BLAKE2B_Final(&__blake2b, hash_output);
}

// !!# BLAKE2B

// #!! BLAKE2S

static const UI4 MASTER_BLAKE2S_TABLE_IV[8] = {
	0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
	0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
};

typedef struct {
	UI1 __b[64];
	UI4 __h[8];
	UI4 __t[2];
	UI4 __c, __outl;
} MASTER_BLAKE2S;

static void
MASTER_BLAKE2S_Compress(MASTER_BLAKE2S * __blake2s, const UI1 __is_last) {
	UI4 i;
	UI4 v[16], m[16];
	for (i = 0; i < 8; i++) {
		v[i] = __blake2s->__h[i];
		v[i + 8] = MASTER_BLAKE2S_TABLE_IV[i];
	}
	v[12] ^= __blake2s->__t[0];
	v[13] ^= __blake2s->__t[1];
	if (__is_last == 1) v[14] = ~v[14];
	for (i = 0; i < 16; i++) m[i] = __MASTER_CHANGE_ENDIAN_32(&__blake2s->__b[i * 4]);
	for (i = 0; i < 10; i++) {
		__MASTER_BLAKE2S_FUNCTION_G(m[MASTER_BLAKE2B_TABLE_SIGMA[i % 10][0]], m[MASTER_BLAKE2B_TABLE_SIGMA[i % 10][1]], v[0], v[4], v[8], v[12]);
		__MASTER_BLAKE2S_FUNCTION_G(m[MASTER_BLAKE2B_TABLE_SIGMA[i % 10][2]], m[MASTER_BLAKE2B_TABLE_SIGMA[i % 10][3]], v[1], v[5], v[9], v[13]);
		__MASTER_BLAKE2S_FUNCTION_G(m[MASTER_BLAKE2B_TABLE_SIGMA[i % 10][4]], m[MASTER_BLAKE2B_TABLE_SIGMA[i % 10][5]], v[2], v[6], v[10], v[14]);
		__MASTER_BLAKE2S_FUNCTION_G(m[MASTER_BLAKE2B_TABLE_SIGMA[i % 10][6]], m[MASTER_BLAKE2B_TABLE_SIGMA[i % 10][7]], v[3], v[7], v[11], v[15]);
		__MASTER_BLAKE2S_FUNCTION_G(m[MASTER_BLAKE2B_TABLE_SIGMA[i % 10][8]], m[MASTER_BLAKE2B_TABLE_SIGMA[i % 10][9]], v[0], v[5], v[10], v[15]);
		__MASTER_BLAKE2S_FUNCTION_G(m[MASTER_BLAKE2B_TABLE_SIGMA[i % 10][10]], m[MASTER_BLAKE2B_TABLE_SIGMA[i % 10][11]], v[1], v[6], v[11], v[12]);
		__MASTER_BLAKE2S_FUNCTION_G(m[MASTER_BLAKE2B_TABLE_SIGMA[i % 10][12]], m[MASTER_BLAKE2B_TABLE_SIGMA[i % 10][13]], v[2], v[7], v[8], v[13]);
		__MASTER_BLAKE2S_FUNCTION_G(m[MASTER_BLAKE2B_TABLE_SIGMA[i % 10][14]], m[MASTER_BLAKE2B_TABLE_SIGMA[i % 10][15]], v[3], v[4], v[9], v[14]);
	}
	for (i = 0; i < 8; i++) __blake2s->__h[i] ^= v[i] ^ v[8 + i];
}

/* #! outl must be (0; 32] !# */
MASTER_BLAKE2S
MASTER_BLAKE2S_Init(UI4 outl) {
	MASTER_BLAKE2S __blake2s;
	UI4 i;
	for (i = 0; i < 8; i++) __blake2s.__h[i] = MASTER_BLAKE2S_TABLE_IV[i];
	__blake2s.__h[0] ^= 0x01010000 ^ outl;
	__blake2s.__t[0] = __blake2s.__t[1] = __blake2s.__c = 0;
	__blake2s.__outl = outl;
	for (i = 0; i < 64; i++) __blake2s.__b[i] = 0;
	return __blake2s;
}

void
MASTER_BLAKE2S_Update(MASTER_BLAKE2S * __blake2s, const char * __s, UI4 __l) {
	UI8 i;
	for (i = 0; i < __l; i++) {
		if (__blake2s->__c == 64) {
			__blake2s->__t[0] += __blake2s->__c;
			if (__blake2s->__t[0] < __blake2s->__c) __blake2s->__t[1]++;
			MASTER_BLAKE2S_Compress(__blake2s, 0);
			__blake2s->__c = 0;
		}
		__blake2s->__b[__blake2s->__c++] = __s[i];
	}
}

void
MASTER_BLAKE2S_Final(MASTER_BLAKE2S * __blake2s, UI1 * hash_output) {
	UI8 i;
	__blake2s->__t[0] += __blake2s->__c;
	if (__blake2s->__t[0] < __blake2s->__c) __blake2s->__t[1]++;
	while (__blake2s->__c < 64) __blake2s->__b[__blake2s->__c++] = 0;
	MASTER_BLAKE2S_Compress(__blake2s, 1);
	for (i = 0; i < __blake2s->__outl; i++) hash_output[i] = (__blake2s->__h[i >> 2] >> (8 * (i & 3))) & 0xFF;
}

void
MASTER_BLAKE2S_CalculateHashSum(const char * __s, UI4 __l, UI1 * hash_output, UI4 outl) {
	MASTER_BLAKE2S __blake2s = MASTER_BLAKE2S_Init(outl);
	MASTER_BLAKE2S_Update(&__blake2s, __s, __l);
	MASTER_BLAKE2S_Final(&__blake2s, hash_output);
}

// !!# BLAKE2S

#undef __MASTER_BLAKE2B_FUNCTION_G
#undef __MASTER_BLAKE2S_FUNCTION_G

// !# BLAKE

// #! WHIRLPOOL

typedef struct {
	UI1 __bl[32];
	UI1 __b[64];
	UI8 __h[8];
	UI4 __bb;
	UI4 __bp;
} MASTER_WHIRLPOOL;

static const UI8 MASTER_WHIRLPOOL_TABLE_C0[256] = {
	0x18186018c07830d8, 0x23238c2305af4626, 0xc6c63fc67ef991b8, 0xe8e887e8136fcdfb,
	0x878726874ca113cb, 0xb8b8dab8a9626d11, 0x0101040108050209, 0x4f4f214f426e9e0d,
	0x3636d836adee6c9b, 0xa6a6a2a6590451ff, 0xd2d26fd2debdb90c, 0xf5f5f3f5fb06f70e,
	0x7979f979ef80f296, 0x6f6fa16f5fcede30, 0x91917e91fcef3f6d, 0x52525552aa07a4f8,
	0x60609d6027fdc047, 0xbcbccabc89766535, 0x9b9b569baccd2b37, 0x8e8e028e048c018a,
	0xa3a3b6a371155bd2, 0x0c0c300c603c186c, 0x7b7bf17bff8af684, 0x3535d435b5e16a80,
	0x1d1d741de8693af5, 0xe0e0a7e05347ddb3, 0xd7d77bd7f6acb321, 0xc2c22fc25eed999c,
	0x2e2eb82e6d965c43, 0x4b4b314b627a9629, 0xfefedffea321e15d, 0x575741578216aed5,
	0x15155415a8412abd, 0x7777c1779fb6eee8, 0x3737dc37a5eb6e92, 0xe5e5b3e57b56d79e,
	0x9f9f469f8cd92313, 0xf0f0e7f0d317fd23, 0x4a4a354a6a7f9420, 0xdada4fda9e95a944,
	0x58587d58fa25b0a2, 0xc9c903c906ca8fcf, 0x2929a429558d527c, 0x0a0a280a5022145a,
	0xb1b1feb1e14f7f50, 0xa0a0baa0691a5dc9, 0x6b6bb16b7fdad614, 0x85852e855cab17d9,
	0xbdbdcebd8173673c, 0x5d5d695dd234ba8f, 0x1010401080502090, 0xf4f4f7f4f303f507,
	0xcbcb0bcb16c08bdd, 0x3e3ef83eedc67cd3, 0x0505140528110a2d, 0x676781671fe6ce78,
	0xe4e4b7e47353d597, 0x27279c2725bb4e02, 0x4141194132588273, 0x8b8b168b2c9d0ba7,
	0xa7a7a6a7510153f6, 0x7d7de97dcf94fab2, 0x95956e95dcfb3749, 0xd8d847d88e9fad56,
	0xfbfbcbfb8b30eb70, 0xeeee9fee2371c1cd, 0x7c7ced7cc791f8bb, 0x6666856617e3cc71,
	0xdddd53dda68ea77b, 0x17175c17b84b2eaf, 0x4747014702468e45, 0x9e9e429e84dc211a,
	0xcaca0fca1ec589d4, 0x2d2db42d75995a58, 0xbfbfc6bf9179632e, 0x07071c07381b0e3f,
	0xadad8ead012347ac, 0x5a5a755aea2fb4b0, 0x838336836cb51bef, 0x3333cc3385ff66b6,
	0x636391633ff2c65c, 0x02020802100a0412, 0xaaaa92aa39384993, 0x7171d971afa8e2de,
	0xc8c807c80ecf8dc6, 0x19196419c87d32d1, 0x494939497270923b, 0xd9d943d9869aaf5f,
	0xf2f2eff2c31df931, 0xe3e3abe34b48dba8, 0x5b5b715be22ab6b9, 0x88881a8834920dbc,
	0x9a9a529aa4c8293e, 0x262698262dbe4c0b, 0x3232c8328dfa64bf, 0xb0b0fab0e94a7d59,
	0xe9e983e91b6acff2, 0x0f0f3c0f78331e77, 0xd5d573d5e6a6b733, 0x80803a8074ba1df4,
	0xbebec2be997c6127, 0xcdcd13cd26de87eb, 0x3434d034bde46889, 0x48483d487a759032,
	0xFFffdbffab24e354, 0x7a7af57af78ff48d, 0x90907a90f4ea3d64, 0x5f5f615fc23ebe9d,
	0x202080201da0403d, 0x6868bd6867d5d00f, 0x1a1a681ad07234ca, 0xaeae82ae192c41b7,
	0xb4b4eab4c95e757d, 0x54544d549a19a8ce, 0x93937693ece53b7f, 0x222288220daa442f,
	0x64648d6407e9c863, 0xf1f1e3f1db12ff2a, 0x7373d173bfa2e6cc, 0x12124812905a2482,
	0x40401d403a5d807a, 0x0808200840281048, 0xc3c32bc356e89b95, 0xecec97ec337bc5df,
	0xdbdb4bdb9690ab4d, 0xa1a1bea1611f5fc0, 0x8d8d0e8d1c830791, 0x3d3df43df5c97ac8,
	0x97976697ccf1335b, 0x0000000000000000, 0xcfcf1bcf36d483f9, 0x2b2bac2b4587566e,
	0x7676c57697b3ece1, 0x8282328264b019e6, 0xd6d67fd6fea9b128, 0x1b1b6c1bd87736c3,
	0xb5b5eeb5c15b7774, 0xafaf86af112943be, 0x6a6ab56a77dfd41d, 0x50505d50ba0da0ea,
	0x45450945124c8a57, 0xf3f3ebf3cb18fb38, 0x3030c0309df060ad, 0xefef9bef2b74c3c4,
	0x3f3ffc3fe5c37eda, 0x55554955921caac7, 0xa2a2b2a2791059db, 0xeaea8fea0365c9e9,
	0x656589650fecca6a, 0xbabad2bab9686903, 0x2f2fbc2f65935e4a, 0xc0c027c04ee79d8e,
	0xdede5fdebe81a160, 0x1c1c701ce06c38fc, 0xfdfdd3fdbb2ee746, 0x4d4d294d52649a1f,
	0x92927292e4e03976, 0x7575c9758fbceafa, 0x06061806301e0c36, 0x8a8a128a249809ae,
	0xb2b2f2b2f940794b, 0xe6e6bfe66359d185, 0x0e0e380e70361c7e, 0x1f1f7c1ff8633ee7,
	0x6262956237f7c455, 0xd4d477d4eea3b53a, 0xa8a89aa829324d81, 0x96966296c4f43152,
	0xf9f9c3f99b3aef62, 0xc5c533c566f697a3, 0x2525942535b14a10, 0x59597959f220b2ab,
	0x84842a8454ae15d0, 0x7272d572b7a7e4c5, 0x3939e439d5dd72ec, 0x4c4c2d4c5a619816,
	0x5e5e655eca3bbc94, 0x7878fd78e785f09f, 0x3838e038ddd870e5, 0x8c8c0a8c14860598,
	0xd1d163d1c6b2bf17, 0xa5a5aea5410b57e4, 0xe2e2afe2434dd9a1, 0x616199612ff8c24e,
	0xb3b3f6b3f1457b42, 0x2121842115a54234, 0x9c9c4a9c94d62508, 0x1e1e781ef0663cee,
	0x4343114322528661, 0xc7c73bc776fc93b1, 0xfcfcd7fcb32be54f, 0x0404100420140824,
	0x51515951b208a2e3, 0x99995e99bcc72f25, 0x6d6da96d4fc4da22, 0x0d0d340d68391a65,
	0xfafacffa8335e979, 0xdfdf5bdfb684a369, 0x7e7ee57ed79bfca9, 0x242490243db44819,
	0x3b3bec3bc5d776fe, 0xabab96ab313d4b9a, 0xcece1fce3ed181f0, 0x1111441188552299,
	0x8f8f068f0c890383, 0x4e4e254e4a6b9c04, 0xb7b7e6b7d1517366, 0xebeb8beb0b60cbe0,
	0x3c3cf03cfdcc78c1, 0x81813e817cbf1ffd, 0x94946a94d4fe3540, 0xf7f7fbf7eb0cf31c,
	0xb9b9deb9a1676f18, 0x13134c13985f268b, 0x2c2cb02c7d9c5851, 0xd3d36bd3d6b8bb05,
	0xe7e7bbe76b5cd38c, 0x6e6ea56e57cbdc39, 0xc4c437c46ef395aa, 0x03030c03180f061b,
	0x565645568a13acdc, 0x44440d441a49885e, 0x7f7fe17fdf9efea0, 0xa9a99ea921374f88,
	0x2a2aa82a4d825467, 0xbbbbd6bbb16d6b0a, 0xc1c123c146e29f87, 0x53535153a202a6f1,
	0xdcdc57dcae8ba572, 0x0b0b2c0b58271653, 0x9d9d4e9d9cd32701, 0x6c6cad6c47c1d82b,
	0x3131c43195f562a4, 0x7474cd7487b9e8f3, 0xf6f6fff6e309f115, 0x464605460a438c4c,
	0xacac8aac092645a5, 0x89891e893c970fb5, 0x14145014a04428b4, 0xe1e1a3e15b42dfba,
	0x16165816b04e2ca6, 0x3a3ae83acdd274f7, 0x6969b9696fd0d206, 0x09092409482d1241,
	0x7070dd70a7ade0d7, 0xb6b6e2b6d954716f, 0xd0d067d0ceb7bd1e, 0xeded93ed3b7ec7d6,
	0xcccc17cc2edb85e2, 0x424215422a578468, 0x98985a98b4c22d2c, 0xa4a4aaa4490e55ed,
	0x2828a0285d885075, 0x5c5c6d5cda31b886, 0xf8f8c7f8933fed6b, 0x8686228644a411c2,
};

static const UI8 MASTER_WHIRLPOOL_TABLE_C1[256] = {
	0xd818186018c07830, 0x2623238c2305af46, 0xb8c6c63fc67ef991, 0xfbe8e887e8136fcd,
	0xcb878726874ca113, 0x11b8b8dab8a9626d, 0x0901010401080502, 0x0d4f4f214f426e9e,
	0x9b3636d836adee6c, 0xFFa6a6a2a6590451, 0x0cd2d26fd2debdb9, 0x0ef5f5f3f5fb06f7,
	0x967979f979ef80f2, 0x306f6fa16f5fcede, 0x6d91917e91fcef3f, 0xf852525552aa07a4,
	0x4760609d6027fdc0, 0x35bcbccabc897665, 0x379b9b569baccd2b, 0x8a8e8e028e048c01,
	0xd2a3a3b6a371155b, 0x6c0c0c300c603c18, 0x847b7bf17bff8af6, 0x803535d435b5e16a,
	0xf51d1d741de8693a, 0xb3e0e0a7e05347dd, 0x21d7d77bd7f6acb3, 0x9cc2c22fc25eed99,
	0x432e2eb82e6d965c, 0x294b4b314b627a96, 0x5dfefedffea321e1, 0xd5575741578216ae,
	0xbd15155415a8412a, 0xe87777c1779fb6ee, 0x923737dc37a5eb6e, 0x9ee5e5b3e57b56d7,
	0x139f9f469f8cd923, 0x23f0f0e7f0d317fd, 0x204a4a354a6a7f94, 0x44dada4fda9e95a9,
	0xa258587d58fa25b0, 0xcfc9c903c906ca8f, 0x7c2929a429558d52, 0x5a0a0a280a502214,
	0x50b1b1feb1e14f7f, 0xc9a0a0baa0691a5d, 0x146b6bb16b7fdad6, 0xd985852e855cab17,
	0x3cbdbdcebd817367, 0x8f5d5d695dd234ba, 0x9010104010805020, 0x07f4f4f7f4f303f5,
	0xddcbcb0bcb16c08b, 0xd33e3ef83eedc67c, 0x2d0505140528110a, 0x78676781671fe6ce,
	0x97e4e4b7e47353d5, 0x0227279c2725bb4e, 0x7341411941325882, 0xa78b8b168b2c9d0b,
	0xf6a7a7a6a7510153, 0xb27d7de97dcf94fa, 0x4995956e95dcfb37, 0x56d8d847d88e9fad,
	0x70fbfbcbfb8b30eb, 0xcdeeee9fee2371c1, 0xbb7c7ced7cc791f8, 0x716666856617e3cc,
	0x7bdddd53dda68ea7, 0xaf17175c17b84b2e, 0x454747014702468e, 0x1a9e9e429e84dc21,
	0xd4caca0fca1ec589, 0x582d2db42d75995a, 0x2ebfbfc6bf917963, 0x3f07071c07381b0e,
	0xacadad8ead012347, 0xb05a5a755aea2fb4, 0xef838336836cb51b, 0xb63333cc3385ff66,
	0x5c636391633ff2c6, 0x1202020802100a04, 0x93aaaa92aa393849, 0xde7171d971afa8e2,
	0xc6c8c807c80ecf8d, 0xd119196419c87d32, 0x3b49493949727092, 0x5fd9d943d9869aaf,
	0x31f2f2eff2c31df9, 0xa8e3e3abe34b48db, 0xb95b5b715be22ab6, 0xbc88881a8834920d,
	0x3e9a9a529aa4c829, 0x0b262698262dbe4c, 0xbf3232c8328dfa64, 0x59b0b0fab0e94a7d,
	0xf2e9e983e91b6acf, 0x770f0f3c0f78331e, 0x33d5d573d5e6a6b7, 0xf480803a8074ba1d,
	0x27bebec2be997c61, 0xebcdcd13cd26de87, 0x893434d034bde468, 0x3248483d487a7590,
	0x54ffffdbffab24e3, 0x8d7a7af57af78ff4, 0x6490907a90f4ea3d, 0x9d5f5f615fc23ebe,
	0x3d202080201da040, 0x0f6868bd6867d5d0, 0xca1a1a681ad07234, 0xb7aeae82ae192c41,
	0x7db4b4eab4c95e75, 0xce54544d549a19a8, 0x7f93937693ece53b, 0x2f222288220daa44,
	0x6364648d6407e9c8, 0x2af1f1e3f1db12ff, 0xcc7373d173bfa2e6, 0x8212124812905a24,
	0x7a40401d403a5d80, 0x4808082008402810, 0x95c3c32bc356e89b, 0xdfecec97ec337bc5,
	0x4ddbdb4bdb9690ab, 0xc0a1a1bea1611f5f, 0x918d8d0e8d1c8307, 0xc83d3df43df5c97a,
	0x5b97976697ccf133, 0x0000000000000000, 0xf9cfcf1bcf36d483, 0x6e2b2bac2b458756,
	0xe17676c57697b3ec, 0xe68282328264b019, 0x28d6d67fd6fea9b1, 0xc31b1b6c1bd87736,
	0x74b5b5eeb5c15b77, 0xbeafaf86af112943, 0x1d6a6ab56a77dfd4, 0xea50505d50ba0da0,
	0x5745450945124c8a, 0x38f3f3ebf3cb18fb, 0xad3030c0309df060, 0xc4efef9bef2b74c3,
	0xda3f3ffc3fe5c37e, 0xc755554955921caa, 0xdba2a2b2a2791059, 0xe9eaea8fea0365c9,
	0x6a656589650fecca, 0x03babad2bab96869, 0x4a2f2fbc2f65935e, 0x8ec0c027c04ee79d,
	0x60dede5fdebe81a1, 0xfc1c1c701ce06c38, 0x46fdfdd3fdbb2ee7, 0x1f4d4d294d52649a,
	0x7692927292e4e039, 0xfa7575c9758fbcea, 0x3606061806301e0c, 0xae8a8a128a249809,
	0x4bb2b2f2b2f94079, 0x85e6e6bfe66359d1, 0x7e0e0e380e70361c, 0xe71f1f7c1ff8633e,
	0x556262956237f7c4, 0x3ad4d477d4eea3b5, 0x81a8a89aa829324d, 0x5296966296c4f431,
	0x62f9f9c3f99b3aef, 0xa3c5c533c566f697, 0x102525942535b14a, 0xab59597959f220b2,
	0xd084842a8454ae15, 0xc57272d572b7a7e4, 0xec3939e439d5dd72, 0x164c4c2d4c5a6198,
	0x945e5e655eca3bbc, 0x9f7878fd78e785f0, 0xe53838e038ddd870, 0x988c8c0a8c148605,
	0x17d1d163d1c6b2bf, 0xe4a5a5aea5410b57, 0xa1e2e2afe2434dd9, 0x4e616199612ff8c2,
	0x42b3b3f6b3f1457b, 0x342121842115a542, 0x089c9c4a9c94d625, 0xee1e1e781ef0663c,
	0x6143431143225286, 0xb1c7c73bc776fc93, 0x4ffcfcd7fcb32be5, 0x2404041004201408,
	0xe351515951b208a2, 0x2599995e99bcc72f, 0x226d6da96d4fc4da, 0x650d0d340d68391a,
	0x79fafacffa8335e9, 0x69dfdf5bdfb684a3, 0xa97e7ee57ed79bfc, 0x19242490243db448,
	0xfe3b3bec3bc5d776, 0x9aabab96ab313d4b, 0xf0cece1fce3ed181, 0x9911114411885522,
	0x838f8f068f0c8903, 0x044e4e254e4a6b9c, 0x66b7b7e6b7d15173, 0xe0ebeb8beb0b60cb,
	0xc13c3cf03cfdcc78, 0xfd81813e817cbf1f, 0x4094946a94d4fe35, 0x1cf7f7fbf7eb0cf3,
	0x18b9b9deb9a1676f, 0x8b13134c13985f26, 0x512c2cb02c7d9c58, 0x05d3d36bd3d6b8bb,
	0x8ce7e7bbe76b5cd3, 0x396e6ea56e57cbdc, 0xaac4c437c46ef395, 0x1b03030c03180f06,
	0xdc565645568a13ac, 0x5e44440d441a4988, 0xa07f7fe17fdf9efe, 0x88a9a99ea921374f,
	0x672a2aa82a4d8254, 0x0abbbbd6bbb16d6b, 0x87c1c123c146e29f, 0xf153535153a202a6,
	0x72dcdc57dcae8ba5, 0x530b0b2c0b582716, 0x019d9d4e9d9cd327, 0x2b6c6cad6c47c1d8,
	0xa43131c43195f562, 0xf37474cd7487b9e8, 0x15f6f6fff6e309f1, 0x4c464605460a438c,
	0xa5acac8aac092645, 0xb589891e893c970f, 0xb414145014a04428, 0xbae1e1a3e15b42df,
	0xa616165816b04e2c, 0xf73a3ae83acdd274, 0x066969b9696fd0d2, 0x4109092409482d12,
	0xd77070dd70a7ade0, 0x6fb6b6e2b6d95471, 0x1ed0d067d0ceb7bd, 0xd6eded93ed3b7ec7,
	0xe2cccc17cc2edb85, 0x68424215422a5784, 0x2c98985a98b4c22d, 0xeda4a4aaa4490e55,
	0x752828a0285d8850, 0x865c5c6d5cda31b8, 0x6bf8f8c7f8933fed, 0xc28686228644a411,
};

static const UI8 MASTER_WHIRLPOOL_TABLE_C2[256] = {
	0x30d818186018c078, 0x462623238c2305af, 0x91b8c6c63fc67ef9, 0xcdfbe8e887e8136f,
	0x13cb878726874ca1, 0x6d11b8b8dab8a962, 0x0209010104010805, 0x9e0d4f4f214f426e,
	0x6c9b3636d836adee, 0x51ffa6a6a2a65904, 0xb90cd2d26fd2debd, 0xf70ef5f5f3f5fb06,
	0xf2967979f979ef80, 0xde306f6fa16f5fce, 0x3f6d91917e91fcef, 0xa4f852525552aa07,
	0xc04760609d6027fd, 0x6535bcbccabc8976, 0x2b379b9b569baccd, 0x018a8e8e028e048c,
	0x5bd2a3a3b6a37115, 0x186c0c0c300c603c, 0xf6847b7bf17bff8a, 0x6a803535d435b5e1,
	0x3af51d1d741de869, 0xddb3e0e0a7e05347, 0xb321d7d77bd7f6ac, 0x999cc2c22fc25eed,
	0x5c432e2eb82e6d96, 0x96294b4b314b627a, 0xe15dfefedffea321, 0xaed5575741578216,
	0x2abd15155415a841, 0xeee87777c1779fb6, 0x6e923737dc37a5eb, 0xd79ee5e5b3e57b56,
	0x23139f9f469f8cd9, 0xfd23f0f0e7f0d317, 0x94204a4a354a6a7f, 0xa944dada4fda9e95,
	0xb0a258587d58fa25, 0x8fcfc9c903c906ca, 0x527c2929a429558d, 0x145a0a0a280a5022,
	0x7f50b1b1feb1e14f, 0x5dc9a0a0baa0691a, 0xd6146b6bb16b7fda, 0x17d985852e855cab,
	0x673cbdbdcebd8173, 0xba8f5d5d695dd234, 0x2090101040108050, 0xf507f4f4f7f4f303,
	0x8bddcbcb0bcb16c0, 0x7cd33e3ef83eedc6, 0x0a2d050514052811, 0xce78676781671fe6,
	0xd597e4e4b7e47353, 0x4e0227279c2725bb, 0x8273414119413258, 0x0ba78b8b168b2c9d,
	0x53f6a7a7a6a75101, 0xfab27d7de97dcf94, 0x374995956e95dcfb, 0xad56d8d847d88e9f,
	0xeb70fbfbcbfb8b30, 0xc1cdeeee9fee2371, 0xf8bb7c7ced7cc791, 0xcc716666856617e3,
	0xa77bdddd53dda68e, 0x2eaf17175c17b84b, 0x8e45474701470246, 0x211a9e9e429e84dc,
	0x89d4caca0fca1ec5, 0x5a582d2db42d7599, 0x632ebfbfc6bf9179, 0x0e3f07071c07381b,
	0x47acadad8ead0123, 0xb4b05a5a755aea2f, 0x1bef838336836cb5, 0x66b63333cc3385ff,
	0xc65c636391633ff2, 0x041202020802100a, 0x4993aaaa92aa3938, 0xe2de7171d971afa8,
	0x8dc6c8c807c80ecf, 0x32d119196419c87d, 0x923b494939497270, 0xaf5fd9d943d9869a,
	0xf931f2f2eff2c31d, 0xdba8e3e3abe34b48, 0xb6b95b5b715be22a, 0x0dbc88881a883492,
	0x293e9a9a529aa4c8, 0x4c0b262698262dbe, 0x64bf3232c8328dfa, 0x7d59b0b0fab0e94a,
	0xcff2e9e983e91b6a, 0x1e770f0f3c0f7833, 0xb733d5d573d5e6a6, 0x1df480803a8074ba,
	0x6127bebec2be997c, 0x87ebcdcd13cd26de, 0x68893434d034bde4, 0x903248483d487a75,
	0xe354ffffdbffab24, 0xf48d7a7af57af78f, 0x3d6490907a90f4ea, 0xbe9d5f5f615fc23e,
	0x403d202080201da0, 0xd00f6868bd6867d5, 0x34ca1a1a681ad072, 0x41b7aeae82ae192c,
	0x757db4b4eab4c95e, 0xa8ce54544d549a19, 0x3b7f93937693ece5, 0x442f222288220daa,
	0xc86364648d6407e9, 0xFF2af1f1e3f1db12, 0xe6cc7373d173bfa2, 0x248212124812905a,
	0x807a40401d403a5d, 0x1048080820084028, 0x9b95c3c32bc356e8, 0xc5dfecec97ec337b,
	0xab4ddbdb4bdb9690, 0x5fc0a1a1bea1611f, 0x07918d8d0e8d1c83, 0x7ac83d3df43df5c9,
	0x335b97976697ccf1, 0x0000000000000000, 0x83f9cfcf1bcf36d4, 0x566e2b2bac2b4587,
	0xece17676c57697b3, 0x19e68282328264b0, 0xb128d6d67fd6fea9, 0x36c31b1b6c1bd877,
	0x7774b5b5eeb5c15b, 0x43beafaf86af1129, 0xd41d6a6ab56a77df, 0xa0ea50505d50ba0d,
	0x8a5745450945124c, 0xfb38f3f3ebf3cb18, 0x60ad3030c0309df0, 0xc3c4efef9bef2b74,
	0x7eda3f3ffc3fe5c3, 0xaac755554955921c, 0x59dba2a2b2a27910, 0xc9e9eaea8fea0365,
	0xca6a656589650fec, 0x6903babad2bab968, 0x5e4a2f2fbc2f6593, 0x9d8ec0c027c04ee7,
	0xa160dede5fdebe81, 0x38fc1c1c701ce06c, 0xe746fdfdd3fdbb2e, 0x9a1f4d4d294d5264,
	0x397692927292e4e0, 0xeafa7575c9758fbc, 0x0c3606061806301e, 0x09ae8a8a128a2498,
	0x794bb2b2f2b2f940, 0xd185e6e6bfe66359, 0x1c7e0e0e380e7036, 0x3ee71f1f7c1ff863,
	0xc4556262956237f7, 0xb53ad4d477d4eea3, 0x4d81a8a89aa82932, 0x315296966296c4f4,
	0xef62f9f9c3f99b3a, 0x97a3c5c533c566f6, 0x4a102525942535b1, 0xb2ab59597959f220,
	0x15d084842a8454ae, 0xe4c57272d572b7a7, 0x72ec3939e439d5dd, 0x98164c4c2d4c5a61,
	0xbc945e5e655eca3b, 0xf09f7878fd78e785, 0x70e53838e038ddd8, 0x05988c8c0a8c1486,
	0xbf17d1d163d1c6b2, 0x57e4a5a5aea5410b, 0xd9a1e2e2afe2434d, 0xc24e616199612ff8,
	0x7b42b3b3f6b3f145, 0x42342121842115a5, 0x25089c9c4a9c94d6, 0x3cee1e1e781ef066,
	0x8661434311432252, 0x93b1c7c73bc776fc, 0xe54ffcfcd7fcb32b, 0x0824040410042014,
	0xa2e351515951b208, 0x2f2599995e99bcc7, 0xda226d6da96d4fc4, 0x1a650d0d340d6839,
	0xe979fafacffa8335, 0xa369dfdf5bdfb684, 0xfca97e7ee57ed79b, 0x4819242490243db4,
	0x76fe3b3bec3bc5d7, 0x4b9aabab96ab313d, 0x81f0cece1fce3ed1, 0x2299111144118855,
	0x03838f8f068f0c89, 0x9c044e4e254e4a6b, 0x7366b7b7e6b7d151, 0xcbe0ebeb8beb0b60,
	0x78c13c3cf03cfdcc, 0x1ffd81813e817cbf, 0x354094946a94d4fe, 0xf31cf7f7fbf7eb0c,
	0x6f18b9b9deb9a167, 0x268b13134c13985f, 0x58512c2cb02c7d9c, 0xbb05d3d36bd3d6b8,
	0xd38ce7e7bbe76b5c, 0xdc396e6ea56e57cb, 0x95aac4c437c46ef3, 0x061b03030c03180f,
	0xacdc565645568a13, 0x885e44440d441a49, 0xfea07f7fe17fdf9e, 0x4f88a9a99ea92137,
	0x54672a2aa82a4d82, 0x6b0abbbbd6bbb16d, 0x9f87c1c123c146e2, 0xa6f153535153a202,
	0xa572dcdc57dcae8b, 0x16530b0b2c0b5827, 0x27019d9d4e9d9cd3, 0xd82b6c6cad6c47c1,
	0x62a43131c43195f5, 0xe8f37474cd7487b9, 0xf115f6f6fff6e309, 0x8c4c464605460a43,
	0x45a5acac8aac0926, 0x0fb589891e893c97, 0x28b414145014a044, 0xdfbae1e1a3e15b42,
	0x2ca616165816b04e, 0x74f73a3ae83acdd2, 0xd2066969b9696fd0, 0x124109092409482d,
	0xe0d77070dd70a7ad, 0x716fb6b6e2b6d954, 0xbd1ed0d067d0ceb7, 0xc7d6eded93ed3b7e,
	0x85e2cccc17cc2edb, 0x8468424215422a57, 0x2d2c98985a98b4c2, 0x55eda4a4aaa4490e,
	0x50752828a0285d88, 0xb8865c5c6d5cda31, 0xed6bf8f8c7f8933f, 0x11c28686228644a4,
};

static const UI8 MASTER_WHIRLPOOL_TABLE_C3[256] = {
	0x7830d818186018c0, 0xaf462623238c2305, 0xf991b8c6c63fc67e, 0x6fcdfbe8e887e813,
	0xa113cb878726874c, 0x626d11b8b8dab8a9, 0x0502090101040108, 0x6e9e0d4f4f214f42,
	0xee6c9b3636d836ad, 0x0451ffa6a6a2a659, 0xbdb90cd2d26fd2de, 0x06f70ef5f5f3f5fb,
	0x80f2967979f979ef, 0xcede306f6fa16f5f, 0xef3f6d91917e91fc, 0x07a4f852525552aa,
	0xfdc04760609d6027, 0x766535bcbccabc89, 0xcd2b379b9b569bac, 0x8c018a8e8e028e04,
	0x155bd2a3a3b6a371, 0x3c186c0c0c300c60, 0x8af6847b7bf17bff, 0xe16a803535d435b5,
	0x693af51d1d741de8, 0x47ddb3e0e0a7e053, 0xacb321d7d77bd7f6, 0xed999cc2c22fc25e,
	0x965c432e2eb82e6d, 0x7a96294b4b314b62, 0x21e15dfefedffea3, 0x16aed55757415782,
	0x412abd15155415a8, 0xb6eee87777c1779f, 0xeb6e923737dc37a5, 0x56d79ee5e5b3e57b,
	0xd923139f9f469f8c, 0x17fd23f0f0e7f0d3, 0x7f94204a4a354a6a, 0x95a944dada4fda9e,
	0x25b0a258587d58fa, 0xca8fcfc9c903c906, 0x8d527c2929a42955, 0x22145a0a0a280a50,
	0x4f7f50b1b1feb1e1, 0x1a5dc9a0a0baa069, 0xdad6146b6bb16b7f, 0xab17d985852e855c,
	0x73673cbdbdcebd81, 0x34ba8f5d5d695dd2, 0x5020901010401080, 0x03f507f4f4f7f4f3,
	0xc08bddcbcb0bcb16, 0xc67cd33e3ef83eed, 0x110a2d0505140528, 0xe6ce78676781671f,
	0x53d597e4e4b7e473, 0xbb4e0227279c2725, 0x5882734141194132, 0x9d0ba78b8b168b2c,
	0x0153f6a7a7a6a751, 0x94fab27d7de97dcf, 0xfb374995956e95dc, 0x9fad56d8d847d88e,
	0x30eb70fbfbcbfb8b, 0x71c1cdeeee9fee23, 0x91f8bb7c7ced7cc7, 0xe3cc716666856617,
	0x8ea77bdddd53dda6, 0x4b2eaf17175c17b8, 0x468e454747014702, 0xdc211a9e9e429e84,
	0xc589d4caca0fca1e, 0x995a582d2db42d75, 0x79632ebfbfc6bf91, 0x1b0e3f07071c0738,
	0x2347acadad8ead01, 0x2fb4b05a5a755aea, 0xb51bef838336836c, 0xFF66b63333cc3385,
	0xf2c65c636391633f, 0x0a04120202080210, 0x384993aaaa92aa39, 0xa8e2de7171d971af,
	0xcf8dc6c8c807c80e, 0x7d32d119196419c8, 0x70923b4949394972, 0x9aaf5fd9d943d986,
	0x1df931f2f2eff2c3, 0x48dba8e3e3abe34b, 0x2ab6b95b5b715be2, 0x920dbc88881a8834,
	0xc8293e9a9a529aa4, 0xbe4c0b262698262d, 0xfa64bf3232c8328d, 0x4a7d59b0b0fab0e9,
	0x6acff2e9e983e91b, 0x331e770f0f3c0f78, 0xa6b733d5d573d5e6, 0xba1df480803a8074,
	0x7c6127bebec2be99, 0xde87ebcdcd13cd26, 0xe468893434d034bd, 0x75903248483d487a,
	0x24e354ffffdbffab, 0x8ff48d7a7af57af7, 0xea3d6490907a90f4, 0x3ebe9d5f5f615fc2,
	0xa0403d202080201d, 0xd5d00f6868bd6867, 0x7234ca1a1a681ad0, 0x2c41b7aeae82ae19,
	0x5e757db4b4eab4c9, 0x19a8ce54544d549a, 0xe53b7f93937693ec, 0xaa442f222288220d,
	0xe9c86364648d6407, 0x12ff2af1f1e3f1db, 0xa2e6cc7373d173bf, 0x5a24821212481290,
	0x5d807a40401d403a, 0x2810480808200840, 0xe89b95c3c32bc356, 0x7bc5dfecec97ec33,
	0x90ab4ddbdb4bdb96, 0x1f5fc0a1a1bea161, 0x8307918d8d0e8d1c, 0xc97ac83d3df43df5,
	0xf1335b97976697cc, 0x0000000000000000, 0xd483f9cfcf1bcf36, 0x87566e2b2bac2b45,
	0xb3ece17676c57697, 0xb019e68282328264, 0xa9b128d6d67fd6fe, 0x7736c31b1b6c1bd8,
	0x5b7774b5b5eeb5c1, 0x2943beafaf86af11, 0xdfd41d6a6ab56a77, 0x0da0ea50505d50ba,
	0x4c8a574545094512, 0x18fb38f3f3ebf3cb, 0xf060ad3030c0309d, 0x74c3c4efef9bef2b,
	0xc37eda3f3ffc3fe5, 0x1caac75555495592, 0x1059dba2a2b2a279, 0x65c9e9eaea8fea03,
	0xecca6a656589650f, 0x686903babad2bab9, 0x935e4a2f2fbc2f65, 0xe79d8ec0c027c04e,
	0x81a160dede5fdebe, 0x6c38fc1c1c701ce0, 0x2ee746fdfdd3fdbb, 0x649a1f4d4d294d52,
	0xe0397692927292e4, 0xbceafa7575c9758f, 0x1e0c360606180630, 0x9809ae8a8a128a24,
	0x40794bb2b2f2b2f9, 0x59d185e6e6bfe663, 0x361c7e0e0e380e70, 0x633ee71f1f7c1ff8,
	0xf7c4556262956237, 0xa3b53ad4d477d4ee, 0x324d81a8a89aa829, 0xf4315296966296c4,
	0x3aef62f9f9c3f99b, 0xf697a3c5c533c566, 0xb14a102525942535, 0x20b2ab59597959f2,
	0xae15d084842a8454, 0xa7e4c57272d572b7, 0xdd72ec3939e439d5, 0x6198164c4c2d4c5a,
	0x3bbc945e5e655eca, 0x85f09f7878fd78e7, 0xd870e53838e038dd, 0x8605988c8c0a8c14,
	0xb2bf17d1d163d1c6, 0x0b57e4a5a5aea541, 0x4dd9a1e2e2afe243, 0xf8c24e616199612f,
	0x457b42b3b3f6b3f1, 0xa542342121842115, 0xd625089c9c4a9c94, 0x663cee1e1e781ef0,
	0x5286614343114322, 0xfc93b1c7c73bc776, 0x2be54ffcfcd7fcb3, 0x1408240404100420,
	0x08a2e351515951b2, 0xc72f2599995e99bc, 0xc4da226d6da96d4f, 0x391a650d0d340d68,
	0x35e979fafacffa83, 0x84a369dfdf5bdfb6, 0x9bfca97e7ee57ed7, 0xb44819242490243d,
	0xd776fe3b3bec3bc5, 0x3d4b9aabab96ab31, 0xd181f0cece1fce3e, 0x5522991111441188,
	0x8903838f8f068f0c, 0x6b9c044e4e254e4a, 0x517366b7b7e6b7d1, 0x60cbe0ebeb8beb0b,
	0xcc78c13c3cf03cfd, 0xbf1ffd81813e817c, 0xfe354094946a94d4, 0x0cf31cf7f7fbf7eb,
	0x676f18b9b9deb9a1, 0x5f268b13134c1398, 0x9c58512c2cb02c7d, 0xb8bb05d3d36bd3d6,
	0x5cd38ce7e7bbe76b, 0xcbdc396e6ea56e57, 0xf395aac4c437c46e, 0x0f061b03030c0318,
	0x13acdc565645568a, 0x49885e44440d441a, 0x9efea07f7fe17fdf, 0x374f88a9a99ea921,
	0x8254672a2aa82a4d, 0x6d6b0abbbbd6bbb1, 0xe29f87c1c123c146, 0x02a6f153535153a2,
	0x8ba572dcdc57dcae, 0x2716530b0b2c0b58, 0xd327019d9d4e9d9c, 0xc1d82b6c6cad6c47,
	0xf562a43131c43195, 0xb9e8f37474cd7487, 0x09f115f6f6fff6e3, 0x438c4c464605460a,
	0x2645a5acac8aac09, 0x970fb589891e893c, 0x4428b414145014a0, 0x42dfbae1e1a3e15b,
	0x4e2ca616165816b0, 0xd274f73a3ae83acd, 0xd0d2066969b9696f, 0x2d12410909240948,
	0xade0d77070dd70a7, 0x54716fb6b6e2b6d9, 0xb7bd1ed0d067d0ce, 0x7ec7d6eded93ed3b,
	0xdb85e2cccc17cc2e, 0x578468424215422a, 0xc22d2c98985a98b4, 0x0e55eda4a4aaa449,
	0x8850752828a0285d, 0x31b8865c5c6d5cda, 0x3fed6bf8f8c7f893, 0xa411c28686228644,
};

static const UI8 MASTER_WHIRLPOOL_TABLE_C4[256] = {
	0xc07830d818186018, 0x05af462623238c23, 0x7ef991b8c6c63fc6, 0x136fcdfbe8e887e8,
	0x4ca113cb87872687, 0xa9626d11b8b8dab8, 0x0805020901010401, 0x426e9e0d4f4f214f,
	0xadee6c9b3636d836, 0x590451ffa6a6a2a6, 0xdebdb90cd2d26fd2, 0xfb06f70ef5f5f3f5,
	0xef80f2967979f979, 0x5fcede306f6fa16f, 0xfcef3f6d91917e91, 0xaa07a4f852525552,
	0x27fdc04760609d60, 0x89766535bcbccabc, 0xaccd2b379b9b569b, 0x048c018a8e8e028e,
	0x71155bd2a3a3b6a3, 0x603c186c0c0c300c, 0xFF8af6847b7bf17b, 0xb5e16a803535d435,
	0xe8693af51d1d741d, 0x5347ddb3e0e0a7e0, 0xf6acb321d7d77bd7, 0x5eed999cc2c22fc2,
	0x6d965c432e2eb82e, 0x627a96294b4b314b, 0xa321e15dfefedffe, 0x8216aed557574157,
	0xa8412abd15155415, 0x9fb6eee87777c177, 0xa5eb6e923737dc37, 0x7b56d79ee5e5b3e5,
	0x8cd923139f9f469f, 0xd317fd23f0f0e7f0, 0x6a7f94204a4a354a, 0x9e95a944dada4fda,
	0xfa25b0a258587d58, 0x06ca8fcfc9c903c9, 0x558d527c2929a429, 0x5022145a0a0a280a,
	0xe14f7f50b1b1feb1, 0x691a5dc9a0a0baa0, 0x7fdad6146b6bb16b, 0x5cab17d985852e85,
	0x8173673cbdbdcebd, 0xd234ba8f5d5d695d, 0x8050209010104010, 0xf303f507f4f4f7f4,
	0x16c08bddcbcb0bcb, 0xedc67cd33e3ef83e, 0x28110a2d05051405, 0x1fe6ce7867678167,
	0x7353d597e4e4b7e4, 0x25bb4e0227279c27, 0x3258827341411941, 0x2c9d0ba78b8b168b,
	0x510153f6a7a7a6a7, 0xcf94fab27d7de97d, 0xdcfb374995956e95, 0x8e9fad56d8d847d8,
	0x8b30eb70fbfbcbfb, 0x2371c1cdeeee9fee, 0xc791f8bb7c7ced7c, 0x17e3cc7166668566,
	0xa68ea77bdddd53dd, 0xb84b2eaf17175c17, 0x02468e4547470147, 0x84dc211a9e9e429e,
	0x1ec589d4caca0fca, 0x75995a582d2db42d, 0x9179632ebfbfc6bf, 0x381b0e3f07071c07,
	0x012347acadad8ead, 0xea2fb4b05a5a755a, 0x6cb51bef83833683, 0x85ff66b63333cc33,
	0x3ff2c65c63639163, 0x100a041202020802, 0x39384993aaaa92aa, 0xafa8e2de7171d971,
	0x0ecf8dc6c8c807c8, 0xc87d32d119196419, 0x7270923b49493949, 0x869aaf5fd9d943d9,
	0xc31df931f2f2eff2, 0x4b48dba8e3e3abe3, 0xe22ab6b95b5b715b, 0x34920dbc88881a88,
	0xa4c8293e9a9a529a, 0x2dbe4c0b26269826, 0x8dfa64bf3232c832, 0xe94a7d59b0b0fab0,
	0x1b6acff2e9e983e9, 0x78331e770f0f3c0f, 0xe6a6b733d5d573d5, 0x74ba1df480803a80,
	0x997c6127bebec2be, 0x26de87ebcdcd13cd, 0xbde468893434d034, 0x7a75903248483d48,
	0xab24e354ffffdbff, 0xf78ff48d7a7af57a, 0xf4ea3d6490907a90, 0xc23ebe9d5f5f615f,
	0x1da0403d20208020, 0x67d5d00f6868bd68, 0xd07234ca1a1a681a, 0x192c41b7aeae82ae,
	0xc95e757db4b4eab4, 0x9a19a8ce54544d54, 0xece53b7f93937693, 0x0daa442f22228822,
	0x07e9c86364648d64, 0xdb12ff2af1f1e3f1, 0xbfa2e6cc7373d173, 0x905a248212124812,
	0x3a5d807a40401d40, 0x4028104808082008, 0x56e89b95c3c32bc3, 0x337bc5dfecec97ec,
	0x9690ab4ddbdb4bdb, 0x611f5fc0a1a1bea1, 0x1c8307918d8d0e8d, 0xf5c97ac83d3df43d,
	0xccf1335b97976697, 0x0000000000000000, 0x36d483f9cfcf1bcf, 0x4587566e2b2bac2b,
	0x97b3ece17676c576, 0x64b019e682823282, 0xfea9b128d6d67fd6, 0xd87736c31b1b6c1b,
	0xc15b7774b5b5eeb5, 0x112943beafaf86af, 0x77dfd41d6a6ab56a, 0xba0da0ea50505d50,
	0x124c8a5745450945, 0xcb18fb38f3f3ebf3, 0x9df060ad3030c030, 0x2b74c3c4efef9bef,
	0xe5c37eda3f3ffc3f, 0x921caac755554955, 0x791059dba2a2b2a2, 0x0365c9e9eaea8fea,
	0x0fecca6a65658965, 0xb9686903babad2ba, 0x65935e4a2f2fbc2f, 0x4ee79d8ec0c027c0,
	0xbe81a160dede5fde, 0xe06c38fc1c1c701c, 0xbb2ee746fdfdd3fd, 0x52649a1f4d4d294d,
	0xe4e0397692927292, 0x8fbceafa7575c975, 0x301e0c3606061806, 0x249809ae8a8a128a,
	0xf940794bb2b2f2b2, 0x6359d185e6e6bfe6, 0x70361c7e0e0e380e, 0xf8633ee71f1f7c1f,
	0x37f7c45562629562, 0xeea3b53ad4d477d4, 0x29324d81a8a89aa8, 0xc4f4315296966296,
	0x9b3aef62f9f9c3f9, 0x66f697a3c5c533c5, 0x35b14a1025259425, 0xf220b2ab59597959,
	0x54ae15d084842a84, 0xb7a7e4c57272d572, 0xd5dd72ec3939e439, 0x5a6198164c4c2d4c,
	0xca3bbc945e5e655e, 0xe785f09f7878fd78, 0xddd870e53838e038, 0x148605988c8c0a8c,
	0xc6b2bf17d1d163d1, 0x410b57e4a5a5aea5, 0x434dd9a1e2e2afe2, 0x2ff8c24e61619961,
	0xf1457b42b3b3f6b3, 0x15a5423421218421, 0x94d625089c9c4a9c, 0xf0663cee1e1e781e,
	0x2252866143431143, 0x76fc93b1c7c73bc7, 0xb32be54ffcfcd7fc, 0x2014082404041004,
	0xb208a2e351515951, 0xbcc72f2599995e99, 0x4fc4da226d6da96d, 0x68391a650d0d340d,
	0x8335e979fafacffa, 0xb684a369dfdf5bdf, 0xd79bfca97e7ee57e, 0x3db4481924249024,
	0xc5d776fe3b3bec3b, 0x313d4b9aabab96ab, 0x3ed181f0cece1fce, 0x8855229911114411,
	0x0c8903838f8f068f, 0x4a6b9c044e4e254e, 0xd1517366b7b7e6b7, 0x0b60cbe0ebeb8beb,
	0xfdcc78c13c3cf03c, 0x7cbf1ffd81813e81, 0xd4fe354094946a94, 0xeb0cf31cf7f7fbf7,
	0xa1676f18b9b9deb9, 0x985f268b13134c13, 0x7d9c58512c2cb02c, 0xd6b8bb05d3d36bd3,
	0x6b5cd38ce7e7bbe7, 0x57cbdc396e6ea56e, 0x6ef395aac4c437c4, 0x180f061b03030c03,
	0x8a13acdc56564556, 0x1a49885e44440d44, 0xdf9efea07f7fe17f, 0x21374f88a9a99ea9,
	0x4d8254672a2aa82a, 0xb16d6b0abbbbd6bb, 0x46e29f87c1c123c1, 0xa202a6f153535153,
	0xae8ba572dcdc57dc, 0x582716530b0b2c0b, 0x9cd327019d9d4e9d, 0x47c1d82b6c6cad6c,
	0x95f562a43131c431, 0x87b9e8f37474cd74, 0xe309f115f6f6fff6, 0x0a438c4c46460546,
	0x092645a5acac8aac, 0x3c970fb589891e89, 0xa04428b414145014, 0x5b42dfbae1e1a3e1,
	0xb04e2ca616165816, 0xcdd274f73a3ae83a, 0x6fd0d2066969b969, 0x482d124109092409,
	0xa7ade0d77070dd70, 0xd954716fb6b6e2b6, 0xceb7bd1ed0d067d0, 0x3b7ec7d6eded93ed,
	0x2edb85e2cccc17cc, 0x2a57846842421542, 0xb4c22d2c98985a98, 0x490e55eda4a4aaa4,
	0x5d8850752828a028, 0xda31b8865c5c6d5c, 0x933fed6bf8f8c7f8, 0x44a411c286862286,
};

static const UI8 MASTER_WHIRLPOOL_TABLE_C5[256] = {
	0x18c07830d8181860, 0x2305af462623238c, 0xc67ef991b8c6c63f, 0xe8136fcdfbe8e887,
	0x874ca113cb878726, 0xb8a9626d11b8b8da, 0x0108050209010104, 0x4f426e9e0d4f4f21,
	0x36adee6c9b3636d8, 0xa6590451ffa6a6a2, 0xd2debdb90cd2d26f, 0xf5fb06f70ef5f5f3,
	0x79ef80f2967979f9, 0x6f5fcede306f6fa1, 0x91fcef3f6d91917e, 0x52aa07a4f8525255,
	0x6027fdc04760609d, 0xbc89766535bcbcca, 0x9baccd2b379b9b56, 0x8e048c018a8e8e02,
	0xa371155bd2a3a3b6, 0x0c603c186c0c0c30, 0x7bff8af6847b7bf1, 0x35b5e16a803535d4,
	0x1de8693af51d1d74, 0xe05347ddb3e0e0a7, 0xd7f6acb321d7d77b, 0xc25eed999cc2c22f,
	0x2e6d965c432e2eb8, 0x4b627a96294b4b31, 0xfea321e15dfefedf, 0x578216aed5575741,
	0x15a8412abd151554, 0x779fb6eee87777c1, 0x37a5eb6e923737dc, 0xe57b56d79ee5e5b3,
	0x9f8cd923139f9f46, 0xf0d317fd23f0f0e7, 0x4a6a7f94204a4a35, 0xda9e95a944dada4f,
	0x58fa25b0a258587d, 0xc906ca8fcfc9c903, 0x29558d527c2929a4, 0x0a5022145a0a0a28,
	0xb1e14f7f50b1b1fe, 0xa0691a5dc9a0a0ba, 0x6b7fdad6146b6bb1, 0x855cab17d985852e,
	0xbd8173673cbdbdce, 0x5dd234ba8f5d5d69, 0x1080502090101040, 0xf4f303f507f4f4f7,
	0xcb16c08bddcbcb0b, 0x3eedc67cd33e3ef8, 0x0528110a2d050514, 0x671fe6ce78676781,
	0xe47353d597e4e4b7, 0x2725bb4e0227279c, 0x4132588273414119, 0x8b2c9d0ba78b8b16,
	0xa7510153f6a7a7a6, 0x7dcf94fab27d7de9, 0x95dcfb374995956e, 0xd88e9fad56d8d847,
	0xfb8b30eb70fbfbcb, 0xee2371c1cdeeee9f, 0x7cc791f8bb7c7ced, 0x6617e3cc71666685,
	0xdda68ea77bdddd53, 0x17b84b2eaf17175c, 0x4702468e45474701, 0x9e84dc211a9e9e42,
	0xca1ec589d4caca0f, 0x2d75995a582d2db4, 0xbf9179632ebfbfc6, 0x07381b0e3f07071c,
	0xad012347acadad8e, 0x5aea2fb4b05a5a75, 0x836cb51bef838336, 0x3385ff66b63333cc,
	0x633ff2c65c636391, 0x02100a0412020208, 0xaa39384993aaaa92, 0x71afa8e2de7171d9,
	0xc80ecf8dc6c8c807, 0x19c87d32d1191964, 0x497270923b494939, 0xd9869aaf5fd9d943,
	0xf2c31df931f2f2ef, 0xe34b48dba8e3e3ab, 0x5be22ab6b95b5b71, 0x8834920dbc88881a,
	0x9aa4c8293e9a9a52, 0x262dbe4c0b262698, 0x328dfa64bf3232c8, 0xb0e94a7d59b0b0fa,
	0xe91b6acff2e9e983, 0x0f78331e770f0f3c, 0xd5e6a6b733d5d573, 0x8074ba1df480803a,
	0xbe997c6127bebec2, 0xcd26de87ebcdcd13, 0x34bde468893434d0, 0x487a75903248483d,
	0xFFab24e354ffffdb, 0x7af78ff48d7a7af5, 0x90f4ea3d6490907a, 0x5fc23ebe9d5f5f61,
	0x201da0403d202080, 0x6867d5d00f6868bd, 0x1ad07234ca1a1a68, 0xae192c41b7aeae82,
	0xb4c95e757db4b4ea, 0x549a19a8ce54544d, 0x93ece53b7f939376, 0x220daa442f222288,
	0x6407e9c86364648d, 0xf1db12ff2af1f1e3, 0x73bfa2e6cc7373d1, 0x12905a2482121248,
	0x403a5d807a40401d, 0x0840281048080820, 0xc356e89b95c3c32b, 0xec337bc5dfecec97,
	0xdb9690ab4ddbdb4b, 0xa1611f5fc0a1a1be, 0x8d1c8307918d8d0e, 0x3df5c97ac83d3df4,
	0x97ccf1335b979766, 0x0000000000000000, 0xcf36d483f9cfcf1b, 0x2b4587566e2b2bac,
	0x7697b3ece17676c5, 0x8264b019e6828232, 0xd6fea9b128d6d67f, 0x1bd87736c31b1b6c,
	0xb5c15b7774b5b5ee, 0xaf112943beafaf86, 0x6a77dfd41d6a6ab5, 0x50ba0da0ea50505d,
	0x45124c8a57454509, 0xf3cb18fb38f3f3eb, 0x309df060ad3030c0, 0xef2b74c3c4efef9b,
	0x3fe5c37eda3f3ffc, 0x55921caac7555549, 0xa2791059dba2a2b2, 0xea0365c9e9eaea8f,
	0x650fecca6a656589, 0xbab9686903babad2, 0x2f65935e4a2f2fbc, 0xc04ee79d8ec0c027,
	0xdebe81a160dede5f, 0x1ce06c38fc1c1c70, 0xfdbb2ee746fdfdd3, 0x4d52649a1f4d4d29,
	0x92e4e03976929272, 0x758fbceafa7575c9, 0x06301e0c36060618, 0x8a249809ae8a8a12,
	0xb2f940794bb2b2f2, 0xe66359d185e6e6bf, 0x0e70361c7e0e0e38, 0x1ff8633ee71f1f7c,
	0x6237f7c455626295, 0xd4eea3b53ad4d477, 0xa829324d81a8a89a, 0x96c4f43152969662,
	0xf99b3aef62f9f9c3, 0xc566f697a3c5c533, 0x2535b14a10252594, 0x59f220b2ab595979,
	0x8454ae15d084842a, 0x72b7a7e4c57272d5, 0x39d5dd72ec3939e4, 0x4c5a6198164c4c2d,
	0x5eca3bbc945e5e65, 0x78e785f09f7878fd, 0x38ddd870e53838e0, 0x8c148605988c8c0a,
	0xd1c6b2bf17d1d163, 0xa5410b57e4a5a5ae, 0xe2434dd9a1e2e2af, 0x612ff8c24e616199,
	0xb3f1457b42b3b3f6, 0x2115a54234212184, 0x9c94d625089c9c4a, 0x1ef0663cee1e1e78,
	0x4322528661434311, 0xc776fc93b1c7c73b, 0xfcb32be54ffcfcd7, 0x0420140824040410,
	0x51b208a2e3515159, 0x99bcc72f2599995e, 0x6d4fc4da226d6da9, 0x0d68391a650d0d34,
	0xfa8335e979fafacf, 0xdfb684a369dfdf5b, 0x7ed79bfca97e7ee5, 0x243db44819242490,
	0x3bc5d776fe3b3bec, 0xab313d4b9aabab96, 0xce3ed181f0cece1f, 0x1188552299111144,
	0x8f0c8903838f8f06, 0x4e4a6b9c044e4e25, 0xb7d1517366b7b7e6, 0xeb0b60cbe0ebeb8b,
	0x3cfdcc78c13c3cf0, 0x817cbf1ffd81813e, 0x94d4fe354094946a, 0xf7eb0cf31cf7f7fb,
	0xb9a1676f18b9b9de, 0x13985f268b13134c, 0x2c7d9c58512c2cb0, 0xd3d6b8bb05d3d36b,
	0xe76b5cd38ce7e7bb, 0x6e57cbdc396e6ea5, 0xc46ef395aac4c437, 0x03180f061b03030c,
	0x568a13acdc565645, 0x441a49885e44440d, 0x7fdf9efea07f7fe1, 0xa921374f88a9a99e,
	0x2a4d8254672a2aa8, 0xbbb16d6b0abbbbd6, 0xc146e29f87c1c123, 0x53a202a6f1535351,
	0xdcae8ba572dcdc57, 0x0b582716530b0b2c, 0x9d9cd327019d9d4e, 0x6c47c1d82b6c6cad,
	0x3195f562a43131c4, 0x7487b9e8f37474cd, 0xf6e309f115f6f6ff, 0x460a438c4c464605,
	0xac092645a5acac8a, 0x893c970fb589891e, 0x14a04428b4141450, 0xe15b42dfbae1e1a3,
	0x16b04e2ca6161658, 0x3acdd274f73a3ae8, 0x696fd0d2066969b9, 0x09482d1241090924,
	0x70a7ade0d77070dd, 0xb6d954716fb6b6e2, 0xd0ceb7bd1ed0d067, 0xed3b7ec7d6eded93,
	0xcc2edb85e2cccc17, 0x422a578468424215, 0x98b4c22d2c98985a, 0xa4490e55eda4a4aa,
	0x285d8850752828a0, 0x5cda31b8865c5c6d, 0xf8933fed6bf8f8c7, 0x8644a411c2868622,
};

static const UI8 MASTER_WHIRLPOOL_TABLE_C6[256] = {
	0x6018c07830d81818, 0x8c2305af46262323, 0x3fc67ef991b8c6c6, 0x87e8136fcdfbe8e8,
	0x26874ca113cb8787, 0xdab8a9626d11b8b8, 0x0401080502090101, 0x214f426e9e0d4f4f,
	0xd836adee6c9b3636, 0xa2a6590451ffa6a6, 0x6fd2debdb90cd2d2, 0xf3f5fb06f70ef5f5,
	0xf979ef80f2967979, 0xa16f5fcede306f6f, 0x7e91fcef3f6d9191, 0x5552aa07a4f85252,
	0x9d6027fdc0476060, 0xcabc89766535bcbc, 0x569baccd2b379b9b, 0x028e048c018a8e8e,
	0xb6a371155bd2a3a3, 0x300c603c186c0c0c, 0xf17bff8af6847b7b, 0xd435b5e16a803535,
	0x741de8693af51d1d, 0xa7e05347ddb3e0e0, 0x7bd7f6acb321d7d7, 0x2fc25eed999cc2c2,
	0xb82e6d965c432e2e, 0x314b627a96294b4b, 0xdffea321e15dfefe, 0x41578216aed55757,
	0x5415a8412abd1515, 0xc1779fb6eee87777, 0xdc37a5eb6e923737, 0xb3e57b56d79ee5e5,
	0x469f8cd923139f9f, 0xe7f0d317fd23f0f0, 0x354a6a7f94204a4a, 0x4fda9e95a944dada,
	0x7d58fa25b0a25858, 0x03c906ca8fcfc9c9, 0xa429558d527c2929, 0x280a5022145a0a0a,
	0xfeb1e14f7f50b1b1, 0xbaa0691a5dc9a0a0, 0xb16b7fdad6146b6b, 0x2e855cab17d98585,
	0xcebd8173673cbdbd, 0x695dd234ba8f5d5d, 0x4010805020901010, 0xf7f4f303f507f4f4,
	0x0bcb16c08bddcbcb, 0xf83eedc67cd33e3e, 0x140528110a2d0505, 0x81671fe6ce786767,
	0xb7e47353d597e4e4, 0x9c2725bb4e022727, 0x1941325882734141, 0x168b2c9d0ba78b8b,
	0xa6a7510153f6a7a7, 0xe97dcf94fab27d7d, 0x6e95dcfb37499595, 0x47d88e9fad56d8d8,
	0xcbfb8b30eb70fbfb, 0x9fee2371c1cdeeee, 0xed7cc791f8bb7c7c, 0x856617e3cc716666,
	0x53dda68ea77bdddd, 0x5c17b84b2eaf1717, 0x014702468e454747, 0x429e84dc211a9e9e,
	0x0fca1ec589d4caca, 0xb42d75995a582d2d, 0xc6bf9179632ebfbf, 0x1c07381b0e3f0707,
	0x8ead012347acadad, 0x755aea2fb4b05a5a, 0x36836cb51bef8383, 0xcc3385ff66b63333,
	0x91633ff2c65c6363, 0x0802100a04120202, 0x92aa39384993aaaa, 0xd971afa8e2de7171,
	0x07c80ecf8dc6c8c8, 0x6419c87d32d11919, 0x39497270923b4949, 0x43d9869aaf5fd9d9,
	0xeff2c31df931f2f2, 0xabe34b48dba8e3e3, 0x715be22ab6b95b5b, 0x1a8834920dbc8888,
	0x529aa4c8293e9a9a, 0x98262dbe4c0b2626, 0xc8328dfa64bf3232, 0xfab0e94a7d59b0b0,
	0x83e91b6acff2e9e9, 0x3c0f78331e770f0f, 0x73d5e6a6b733d5d5, 0x3a8074ba1df48080,
	0xc2be997c6127bebe, 0x13cd26de87ebcdcd, 0xd034bde468893434, 0x3d487a7590324848,
	0xdbffab24e354ffff, 0xf57af78ff48d7a7a, 0x7a90f4ea3d649090, 0x615fc23ebe9d5f5f,
	0x80201da0403d2020, 0xbd6867d5d00f6868, 0x681ad07234ca1a1a, 0x82ae192c41b7aeae,
	0xeab4c95e757db4b4, 0x4d549a19a8ce5454, 0x7693ece53b7f9393, 0x88220daa442f2222,
	0x8d6407e9c8636464, 0xe3f1db12ff2af1f1, 0xd173bfa2e6cc7373, 0x4812905a24821212,
	0x1d403a5d807a4040, 0x2008402810480808, 0x2bc356e89b95c3c3, 0x97ec337bc5dfecec,
	0x4bdb9690ab4ddbdb, 0xbea1611f5fc0a1a1, 0x0e8d1c8307918d8d, 0xf43df5c97ac83d3d,
	0x6697ccf1335b9797, 0x0000000000000000, 0x1bcf36d483f9cfcf, 0xac2b4587566e2b2b,
	0xc57697b3ece17676, 0x328264b019e68282, 0x7fd6fea9b128d6d6, 0x6c1bd87736c31b1b,
	0xeeb5c15b7774b5b5, 0x86af112943beafaf, 0xb56a77dfd41d6a6a, 0x5d50ba0da0ea5050,
	0x0945124c8a574545, 0xebf3cb18fb38f3f3, 0xc0309df060ad3030, 0x9bef2b74c3c4efef,
	0xfc3fe5c37eda3f3f, 0x4955921caac75555, 0xb2a2791059dba2a2, 0x8fea0365c9e9eaea,
	0x89650fecca6a6565, 0xd2bab9686903baba, 0xbc2f65935e4a2f2f, 0x27c04ee79d8ec0c0,
	0x5fdebe81a160dede, 0x701ce06c38fc1c1c, 0xd3fdbb2ee746fdfd, 0x294d52649a1f4d4d,
	0x7292e4e039769292, 0xc9758fbceafa7575, 0x1806301e0c360606, 0x128a249809ae8a8a,
	0xf2b2f940794bb2b2, 0xbfe66359d185e6e6, 0x380e70361c7e0e0e, 0x7c1ff8633ee71f1f,
	0x956237f7c4556262, 0x77d4eea3b53ad4d4, 0x9aa829324d81a8a8, 0x6296c4f431529696,
	0xc3f99b3aef62f9f9, 0x33c566f697a3c5c5, 0x942535b14a102525, 0x7959f220b2ab5959,
	0x2a8454ae15d08484, 0xd572b7a7e4c57272, 0xe439d5dd72ec3939, 0x2d4c5a6198164c4c,
	0x655eca3bbc945e5e, 0xfd78e785f09f7878, 0xe038ddd870e53838, 0x0a8c148605988c8c,
	0x63d1c6b2bf17d1d1, 0xaea5410b57e4a5a5, 0xafe2434dd9a1e2e2, 0x99612ff8c24e6161,
	0xf6b3f1457b42b3b3, 0x842115a542342121, 0x4a9c94d625089c9c, 0x781ef0663cee1e1e,
	0x1143225286614343, 0x3bc776fc93b1c7c7, 0xd7fcb32be54ffcfc, 0x1004201408240404,
	0x5951b208a2e35151, 0x5e99bcc72f259999, 0xa96d4fc4da226d6d, 0x340d68391a650d0d,
	0xcffa8335e979fafa, 0x5bdfb684a369dfdf, 0xe57ed79bfca97e7e, 0x90243db448192424,
	0xec3bc5d776fe3b3b, 0x96ab313d4b9aabab, 0x1fce3ed181f0cece, 0x4411885522991111,
	0x068f0c8903838f8f, 0x254e4a6b9c044e4e, 0xe6b7d1517366b7b7, 0x8beb0b60cbe0ebeb,
	0xf03cfdcc78c13c3c, 0x3e817cbf1ffd8181, 0x6a94d4fe35409494, 0xfbf7eb0cf31cf7f7,
	0xdeb9a1676f18b9b9, 0x4c13985f268b1313, 0xb02c7d9c58512c2c, 0x6bd3d6b8bb05d3d3,
	0xbbe76b5cd38ce7e7, 0xa56e57cbdc396e6e, 0x37c46ef395aac4c4, 0x0c03180f061b0303,
	0x45568a13acdc5656, 0x0d441a49885e4444, 0xe17fdf9efea07f7f, 0x9ea921374f88a9a9,
	0xa82a4d8254672a2a, 0xd6bbb16d6b0abbbb, 0x23c146e29f87c1c1, 0x5153a202a6f15353,
	0x57dcae8ba572dcdc, 0x2c0b582716530b0b, 0x4e9d9cd327019d9d, 0xad6c47c1d82b6c6c,
	0xc43195f562a43131, 0xcd7487b9e8f37474, 0xFFf6e309f115f6f6, 0x05460a438c4c4646,
	0x8aac092645a5acac, 0x1e893c970fb58989, 0x5014a04428b41414, 0xa3e15b42dfbae1e1,
	0x5816b04e2ca61616, 0xe83acdd274f73a3a, 0xb9696fd0d2066969, 0x2409482d12410909,
	0xdd70a7ade0d77070, 0xe2b6d954716fb6b6, 0x67d0ceb7bd1ed0d0, 0x93ed3b7ec7d6eded,
	0x17cc2edb85e2cccc, 0x15422a5784684242, 0x5a98b4c22d2c9898, 0xaaa4490e55eda4a4,
	0xa0285d8850752828, 0x6d5cda31b8865c5c, 0xc7f8933fed6bf8f8, 0x228644a411c28686,
};

static const UI8 MASTER_WHIRLPOOL_TABLE_C7[256] = {
	0x186018c07830d818, 0x238c2305af462623, 0xc63fc67ef991b8c6, 0xe887e8136fcdfbe8,
	0x8726874ca113cb87, 0xb8dab8a9626d11b8, 0x0104010805020901, 0x4f214f426e9e0d4f,
	0x36d836adee6c9b36, 0xa6a2a6590451ffa6, 0xd26fd2debdb90cd2, 0xf5f3f5fb06f70ef5,
	0x79f979ef80f29679, 0x6fa16f5fcede306f, 0x917e91fcef3f6d91, 0x525552aa07a4f852,
	0x609d6027fdc04760, 0xbccabc89766535bc, 0x9b569baccd2b379b, 0x8e028e048c018a8e,
	0xa3b6a371155bd2a3, 0x0c300c603c186c0c, 0x7bf17bff8af6847b, 0x35d435b5e16a8035,
	0x1d741de8693af51d, 0xe0a7e05347ddb3e0, 0xd77bd7f6acb321d7, 0xc22fc25eed999cc2,
	0x2eb82e6d965c432e, 0x4b314b627a96294b, 0xfedffea321e15dfe, 0x5741578216aed557,
	0x155415a8412abd15, 0x77c1779fb6eee877, 0x37dc37a5eb6e9237, 0xe5b3e57b56d79ee5,
	0x9f469f8cd923139f, 0xf0e7f0d317fd23f0, 0x4a354a6a7f94204a, 0xda4fda9e95a944da,
	0x587d58fa25b0a258, 0xc903c906ca8fcfc9, 0x29a429558d527c29, 0x0a280a5022145a0a,
	0xb1feb1e14f7f50b1, 0xa0baa0691a5dc9a0, 0x6bb16b7fdad6146b, 0x852e855cab17d985,
	0xbdcebd8173673cbd, 0x5d695dd234ba8f5d, 0x1040108050209010, 0xf4f7f4f303f507f4,
	0xcb0bcb16c08bddcb, 0x3ef83eedc67cd33e, 0x05140528110a2d05, 0x6781671fe6ce7867,
	0xe4b7e47353d597e4, 0x279c2725bb4e0227, 0x4119413258827341, 0x8b168b2c9d0ba78b,
	0xa7a6a7510153f6a7, 0x7de97dcf94fab27d, 0x956e95dcfb374995, 0xd847d88e9fad56d8,
	0xfbcbfb8b30eb70fb, 0xee9fee2371c1cdee, 0x7ced7cc791f8bb7c, 0x66856617e3cc7166,
	0xdd53dda68ea77bdd, 0x175c17b84b2eaf17, 0x47014702468e4547, 0x9e429e84dc211a9e,
	0xca0fca1ec589d4ca, 0x2db42d75995a582d, 0xbfc6bf9179632ebf, 0x071c07381b0e3f07,
	0xad8ead012347acad, 0x5a755aea2fb4b05a, 0x8336836cb51bef83, 0x33cc3385ff66b633,
	0x6391633ff2c65c63, 0x020802100a041202, 0xaa92aa39384993aa, 0x71d971afa8e2de71,
	0xc807c80ecf8dc6c8, 0x196419c87d32d119, 0x4939497270923b49, 0xd943d9869aaf5fd9,
	0xf2eff2c31df931f2, 0xe3abe34b48dba8e3, 0x5b715be22ab6b95b, 0x881a8834920dbc88,
	0x9a529aa4c8293e9a, 0x2698262dbe4c0b26, 0x32c8328dfa64bf32, 0xb0fab0e94a7d59b0,
	0xe983e91b6acff2e9, 0x0f3c0f78331e770f, 0xd573d5e6a6b733d5, 0x803a8074ba1df480,
	0xbec2be997c6127be, 0xcd13cd26de87ebcd, 0x34d034bde4688934, 0x483d487a75903248,
	0xFFdbffab24e354ff, 0x7af57af78ff48d7a, 0x907a90f4ea3d6490, 0x5f615fc23ebe9d5f,
	0x2080201da0403d20, 0x68bd6867d5d00f68, 0x1a681ad07234ca1a, 0xae82ae192c41b7ae,
	0xb4eab4c95e757db4, 0x544d549a19a8ce54, 0x937693ece53b7f93, 0x2288220daa442f22,
	0x648d6407e9c86364, 0xf1e3f1db12ff2af1, 0x73d173bfa2e6cc73, 0x124812905a248212,
	0x401d403a5d807a40, 0x0820084028104808, 0xc32bc356e89b95c3, 0xec97ec337bc5dfec,
	0xdb4bdb9690ab4ddb, 0xa1bea1611f5fc0a1, 0x8d0e8d1c8307918d, 0x3df43df5c97ac83d,
	0x976697ccf1335b97, 0x0000000000000000, 0xcf1bcf36d483f9cf, 0x2bac2b4587566e2b,
	0x76c57697b3ece176, 0x82328264b019e682, 0xd67fd6fea9b128d6, 0x1b6c1bd87736c31b,
	0xb5eeb5c15b7774b5, 0xaf86af112943beaf, 0x6ab56a77dfd41d6a, 0x505d50ba0da0ea50,
	0x450945124c8a5745, 0xf3ebf3cb18fb38f3, 0x30c0309df060ad30, 0xef9bef2b74c3c4ef,
	0x3ffc3fe5c37eda3f, 0x554955921caac755, 0xa2b2a2791059dba2, 0xea8fea0365c9e9ea,
	0x6589650fecca6a65, 0xbad2bab9686903ba, 0x2fbc2f65935e4a2f, 0xc027c04ee79d8ec0,
	0xde5fdebe81a160de, 0x1c701ce06c38fc1c, 0xfdd3fdbb2ee746fd, 0x4d294d52649a1f4d,
	0x927292e4e0397692, 0x75c9758fbceafa75, 0x061806301e0c3606, 0x8a128a249809ae8a,
	0xb2f2b2f940794bb2, 0xe6bfe66359d185e6, 0x0e380e70361c7e0e, 0x1f7c1ff8633ee71f,
	0x62956237f7c45562, 0xd477d4eea3b53ad4, 0xa89aa829324d81a8, 0x966296c4f4315296,
	0xf9c3f99b3aef62f9, 0xc533c566f697a3c5, 0x25942535b14a1025, 0x597959f220b2ab59,
	0x842a8454ae15d084, 0x72d572b7a7e4c572, 0x39e439d5dd72ec39, 0x4c2d4c5a6198164c,
	0x5e655eca3bbc945e, 0x78fd78e785f09f78, 0x38e038ddd870e538, 0x8c0a8c148605988c,
	0xd163d1c6b2bf17d1, 0xa5aea5410b57e4a5, 0xe2afe2434dd9a1e2, 0x6199612ff8c24e61,
	0xb3f6b3f1457b42b3, 0x21842115a5423421, 0x9c4a9c94d625089c, 0x1e781ef0663cee1e,
	0x4311432252866143, 0xc73bc776fc93b1c7, 0xfcd7fcb32be54ffc, 0x0410042014082404,
	0x515951b208a2e351, 0x995e99bcc72f2599, 0x6da96d4fc4da226d, 0x0d340d68391a650d,
	0xfacffa8335e979fa, 0xdf5bdfb684a369df, 0x7ee57ed79bfca97e, 0x2490243db4481924,
	0x3bec3bc5d776fe3b, 0xab96ab313d4b9aab, 0xce1fce3ed181f0ce, 0x1144118855229911,
	0x8f068f0c8903838f, 0x4e254e4a6b9c044e, 0xb7e6b7d1517366b7, 0xeb8beb0b60cbe0eb,
	0x3cf03cfdcc78c13c, 0x813e817cbf1ffd81, 0x946a94d4fe354094, 0xf7fbf7eb0cf31cf7,
	0xb9deb9a1676f18b9, 0x134c13985f268b13, 0x2cb02c7d9c58512c, 0xd36bd3d6b8bb05d3,
	0xe7bbe76b5cd38ce7, 0x6ea56e57cbdc396e, 0xc437c46ef395aac4, 0x030c03180f061b03,
	0x5645568a13acdc56, 0x440d441a49885e44, 0x7fe17fdf9efea07f, 0xa99ea921374f88a9,
	0x2aa82a4d8254672a, 0xbbd6bbb16d6b0abb, 0xc123c146e29f87c1, 0x535153a202a6f153,
	0xdc57dcae8ba572dc, 0x0b2c0b582716530b, 0x9d4e9d9cd327019d, 0x6cad6c47c1d82b6c,
	0x31c43195f562a431, 0x74cd7487b9e8f374, 0xf6fff6e309f115f6, 0x4605460a438c4c46,
	0xac8aac092645a5ac, 0x891e893c970fb589, 0x145014a04428b414, 0xe1a3e15b42dfbae1,
	0x165816b04e2ca616, 0x3ae83acdd274f73a, 0x69b9696fd0d20669, 0x092409482d124109,
	0x70dd70a7ade0d770, 0xb6e2b6d954716fb6, 0xd067d0ceb7bd1ed0, 0xed93ed3b7ec7d6ed,
	0xcc17cc2edb85e2cc, 0x4215422a57846842, 0x985a98b4c22d2c98, 0xa4aaa4490e55eda4,
	0x28a0285d88507528, 0x5c6d5cda31b8865c, 0xf8c7f8933fed6bf8, 0x86228644a411c286,
};

static const UI8 MASTER_WHIRLPOOL_TABLE_RC[] = {
	0x1823c6e887b8014f,
	0x36a6d2f5796f9152,
	0x60bc9b8ea30c7b35,
	0x1de0d7c22e4bfe57,
	0x157737e59ff04ada,
	0x58c9290ab1a06b85,
	0xbd5d10f4cb3e0567,
	0xe427418ba77d95d8,
	0xfbee7c66dd17479e,
	0xca2dbf07ad5a8333,
};

#define MASTER_WHIRLPOOL_FUNCTION_F1(l, c0, c1, c2, c3, c4, c5, c6, c7) \
		L[l] = MASTER_WHIRLPOOL_TABLE_C0[(K[c0] >> 56)] ^ \
			   MASTER_WHIRLPOOL_TABLE_C1[(K[c1] >> 48) & 0xFF] ^ \
			   MASTER_WHIRLPOOL_TABLE_C2[(K[c2] >> 40) & 0xFF] ^ \
			   MASTER_WHIRLPOOL_TABLE_C3[(K[c3] >> 32) & 0xFF] ^ \
			   MASTER_WHIRLPOOL_TABLE_C4[(K[c4] >> 24) & 0xFF] ^ \
			   MASTER_WHIRLPOOL_TABLE_C5[(K[c5] >> 16) & 0xFF] ^ \
			   MASTER_WHIRLPOOL_TABLE_C6[(K[c6] >> 8) & 0xFF] ^ \
			   MASTER_WHIRLPOOL_TABLE_C7[K[c7] & 0xFF]

#define MASTER_WHIRLPOOL_FUNCTION_F2(l, c0, c1, c2, c3, c4, c5, c6, c7, k) \
		L[l] = MASTER_WHIRLPOOL_TABLE_C0[(state[c0] >> 56)] ^ \
			   MASTER_WHIRLPOOL_TABLE_C1[(state[c1] >> 48) & 0xFF] ^ \
			   MASTER_WHIRLPOOL_TABLE_C2[(state[c2] >> 40) & 0xFF] ^ \
			   MASTER_WHIRLPOOL_TABLE_C3[(state[c3] >> 32) & 0xFF] ^ \
			   MASTER_WHIRLPOOL_TABLE_C4[(state[c4] >> 24) & 0xFF] ^ \
			   MASTER_WHIRLPOOL_TABLE_C5[(state[c5] >> 16) & 0xFF] ^ \
			   MASTER_WHIRLPOOL_TABLE_C6[(state[c6] >> 8) & 0xFF] ^ \
			   MASTER_WHIRLPOOL_TABLE_C7[state[c7] & 0xFF] ^ \
			   K[k];

static void
MASTER_WHIRLPOOL_Transform(MASTER_WHIRLPOOL * const __whirlpool) {
	UI4 i, r;
	UI8 K[8];
	UI8 block[8];
	UI8 state[8];
	UI8 L[8];
	UI1 * __b = __whirlpool->__b;

	for (i = 0; i < 8; i++, __b += 8) {
		block[i] = (((UI8)__b[0]) << 56) ^
				   (((UI8)__b[1] & 0xFF) << 48) ^
				   (((UI8)__b[2] & 0xFF) << 40) ^
				   (((UI8)__b[3] & 0xFF) << 32) ^
				   (((UI8)__b[4] & 0xFF) << 24) ^
				   (((UI8)__b[5] & 0xFF) << 16) ^
				   (((UI8)__b[6] & 0xFF) << 8) ^
				   (((UI8)__b[7] & 0xFF));
		state[i] = block[i] ^ (K[i] = __whirlpool->__h[i]);
	}

	for (r = 0; r <= 9; r++) {
		MASTER_WHIRLPOOL_FUNCTION_F1(0, 0, 7, 6, 5, 4, 3, 2, 1) ^ MASTER_WHIRLPOOL_TABLE_RC[r];
		MASTER_WHIRLPOOL_FUNCTION_F1(1, 1, 0, 7, 6, 5, 4, 3, 2);
		MASTER_WHIRLPOOL_FUNCTION_F1(2, 2, 1, 0, 7, 6, 5, 4, 3);
		MASTER_WHIRLPOOL_FUNCTION_F1(3, 3, 2, 1, 0, 7, 6, 5, 4);
		MASTER_WHIRLPOOL_FUNCTION_F1(4, 4, 3, 2, 1, 0, 7, 6, 5);
		MASTER_WHIRLPOOL_FUNCTION_F1(5, 5, 4, 3, 2, 1, 0, 7, 6);
		MASTER_WHIRLPOOL_FUNCTION_F1(6, 6, 5, 4, 3, 2, 1, 0, 7);
		MASTER_WHIRLPOOL_FUNCTION_F1(7, 7, 6, 5, 4, 3, 2, 1, 0);
		for (i = 0; i < 8; i++) K[i] = L[i];
		MASTER_WHIRLPOOL_FUNCTION_F2(0, 0, 7, 6, 5, 4, 3, 2, 1, 0);
		MASTER_WHIRLPOOL_FUNCTION_F2(1, 1, 0, 7, 6, 5, 4, 3, 2, 1);
		MASTER_WHIRLPOOL_FUNCTION_F2(2, 2, 1, 0, 7, 6, 5, 4, 3, 2);
		MASTER_WHIRLPOOL_FUNCTION_F2(3, 3, 2, 1, 0, 7, 6, 5, 4, 3);
		MASTER_WHIRLPOOL_FUNCTION_F2(4, 4, 3, 2, 1, 0, 7, 6, 5, 4);
		MASTER_WHIRLPOOL_FUNCTION_F2(5, 5, 4, 3, 2, 1, 0, 7, 6, 5);
		MASTER_WHIRLPOOL_FUNCTION_F2(6, 6, 5, 4, 3, 2, 1, 0, 7, 6);
		MASTER_WHIRLPOOL_FUNCTION_F2(7, 7, 6, 5, 4, 3, 2, 1, 0, 7);
		for (i = 0; i < 8; i++) state[i] = L[i];
	}
	for (i = 0; i < 8; i++) __whirlpool->__h[i] ^= state[i] ^ block[i];
}

#undef MASTER_WHIRLPOOL_FUNCTION_F1
#undef MASTER_WHIRLPOOL_FUNCTION_F2

MASTER_WHIRLPOOL
MASTER_WHIRLPOOL_Init(void) {
	MASTER_WHIRLPOOL __whirlpool;
	memset(__whirlpool.__bl, 0, 32 * sizeof(UI1));
	memset(__whirlpool.__h, 0, 8 * sizeof(UI8));
	__whirlpool.__bb = __whirlpool.__bp = 0;
	__whirlpool.__b[0] = 0;
	return __whirlpool;
}

void
MASTER_WHIRLPOOL_Update(MASTER_WHIRLPOOL * const __whirlpool, const char * __s, UI8 __l) {
	UI4 __sp = 0;
	__l *= 8;
	UI4 __sg = (8 - (__l & 7)) & 7;
	UI4 __br = __whirlpool->__bb & 7;
	int i;
	UI4 b, c;
	UI1 * __b = __whirlpool->__b, * __bl  = __whirlpool->__bl;
	UI4 __bb = __whirlpool->__bb,  __bp = __whirlpool->__bp;
	UI8 value = __l;
	for (i = 31, c = 0; i >= 0 && (c != 0 || value != 0); i--) {
		c += __bl[i] + ((UI4)value & 0xFF);
		__bl[i] = c;
		c >>= 8;
		value >>= 8;
	}
	while (__l > 8) {
		b = ((__s[__sp] << __sg) & 0xFF) | ((__s[__sp + 1] & 0xFF) >> (8 - __sg));
		__b[__bp++] |= (b >> __br);
		__bb += 8 - __br;
		if (__bb == 512) {
			MASTER_WHIRLPOOL_Transform(__whirlpool);
			__bb = __bp = 0;
		}
		__b[__bp] = b << (8 - __br);
		__bb += __br;
		__l -= 8;
		__sp++;
	}
	if (__l > 0) {
		b = (__s[__sp] << __sg) & 0xFF;
		__b[__bp] |= b >> __br;
	} else b = 0;
	if (__br + __l < 8) __bb += __l;
	else {
		__bp++;
		__bb += 8 - __br;
		__l -= 8 - __br;
		if (__bb == 512) {
			MASTER_WHIRLPOOL_Transform(__whirlpool);
			__bb = __bp = 0;
		}
		__b[__bp] = b << (8 - __br);
		__bb += __l;
	}
	__whirlpool->__bb = __bb;
	__whirlpool->__bp = __bp;
}

void
MASTER_WHIRLPOOL_Final(MASTER_WHIRLPOOL * const __whirlpool, UI1 * hash_output) {
	UI4 i;
	UI1 * __b = __whirlpool->__b;
	UI1 * __bl = __whirlpool->__bl;
	UI4 __bb = __whirlpool->__bb;
	UI4 __bp = __whirlpool->__bp;

	__b[__bp] |= 0x80 >> (__bb & 7);
	__bp++;
	if (__bp > 32) {
		if (__bp < 64) memset(&__b[__bp], 0, 64 - __bp);
		MASTER_WHIRLPOOL_Transform(__whirlpool);
		__bp = 0;
	}
	if (__bp < 32) memset(&__b[__bp], 0, 32 - __bp);
	__bp = 32;
	memcpy(&__b[32], __bl, 32);
	MASTER_WHIRLPOOL_Transform(__whirlpool);
	for (i = 0; i < 8; i++) {
		hash_output[0] = (__whirlpool->__h[i] >> 56);
		hash_output[1] = (__whirlpool->__h[i] >> 48);
		hash_output[2] = (__whirlpool->__h[i] >> 40);
		hash_output[3] = (__whirlpool->__h[i] >> 32);
		hash_output[4] = (__whirlpool->__h[i] >> 24);
		hash_output[5] = (__whirlpool->__h[i] >> 16);
		hash_output[6] = (__whirlpool->__h[i] >> 8);
		hash_output[7] = (__whirlpool->__h[i]);
		hash_output += 8;
	}
	__whirlpool->__bb = __bb;
	__whirlpool->__bp = __bp;
}

void
MASTER_WHIRLPOOL_CalculateHashSum(const char * __s, UI4 __l, UI1 * hash_output) {
	MASTER_WHIRLPOOL __whirlpool = MASTER_WHIRLPOOL_Init();
	MASTER_WHIRLPOOL_Update(&__whirlpool, __s, __l);
	MASTER_WHIRLPOOL_Final(&__whirlpool, hash_output);
}

// !# WHIRLPOOL

// #! TIGER

UI8
MASTER_TIGER_TABLE_T1[256] = {
	0x02AAB17CF7E90C5E, 0xAC424B03E243A8EC, 0x72CD5BE30DD5FCD3, 0x6D019B93F6F97F3A,
	0xCD9978FFD21F9193, 0x7573A1C9708029E2, 0xB164326B922A83C3, 0x46883EEE04915870,
	0xEAACE3057103ECE6, 0xC54169B808A3535C, 0x4CE754918DDEC47C, 0x0AA2F4DFDC0DF40C,
	0x10B76F18A74DBEFA, 0xC6CCB6235AD1AB6A, 0x13726121572FE2FF, 0x1A488C6F199D921E,
	0x4BC9F9F4DA0007CA, 0x26F5E6F6E85241C7, 0x859079DBEA5947B6, 0x4F1885C5C99E8C92,
	0xD78E761EA96F864B, 0x8E36428C52B5C17D, 0x69CF6827373063C1, 0xB607C93D9BB4C56E,
	0x7D820E760E76B5EA, 0x645C9CC6F07FDC42, 0xBF38A078243342E0, 0x5F6B343C9D2E7D04,
	0xF2C28AEB600B0EC6, 0x6C0ED85F7254BCAC, 0x71592281A4DB4FE5, 0x1967FA69CE0FED9F,
	0xFD5293F8B96545DB, 0xC879E9D7F2A7600B, 0x860248920193194E, 0xA4F9533B2D9CC0B3,
	0x9053836C15957613, 0xDB6DCF8AFC357BF1, 0x18BEEA7A7A370F57, 0x037117CA50B99066,
	0x6AB30A9774424A35, 0xF4E92F02E325249B, 0x7739DB07061CCAE1, 0xD8F3B49CECA42A05,
	0xBD56BE3F51382F73, 0x45FAED5843B0BB28, 0x1C813D5C11BF1F83, 0x8AF0E4B6D75FA169,
	0x33EE18A487AD9999, 0x3C26E8EAB1C94410, 0xB510102BC0A822F9, 0x141EEF310CE6123B,
	0xFC65B90059DDB154, 0xE0158640C5E0E607, 0x884E079826C3A3CF, 0x930D0D9523C535FD,
	0x35638D754E9A2B00, 0x4085FCCF40469DD5, 0xC4B17AD28BE23A4C, 0xCAB2F0FC6A3E6A2E,
	0x2860971A6B943FCD, 0x3DDE6EE212E30446, 0x6222F32AE01765AE, 0x5D550BB5478308FE,
	0xA9EFA98DA0EDA22A, 0xC351A71686C40DA7, 0x1105586D9C867C84, 0xDCFFEE85FDA22853,
	0xCCFBD0262C5EEF76, 0xBAF294CB8990D201, 0xE69464F52AFAD975, 0x94B013AFDF133E14,
	0x06A7D1A32823C958, 0x6F95FE5130F61119, 0xD92AB34E462C06C0, 0xED7BDE33887C71D2,
	0x79746D6E6518393E, 0x5BA419385D713329, 0x7C1BA6B948A97564, 0x31987C197BFDAC67,
	0xDE6C23C44B053D02, 0x581C49FED002D64D, 0xDD474D6338261571, 0xAA4546C3E473D062,
	0x928FCE349455F860, 0x48161BBACAAB94D9, 0x63912430770E6F68, 0x6EC8A5E602C6641C,
	0x87282515337DDD2B, 0x2CDA6B42034B701B, 0xB03D37C181CB096D, 0xE108438266C71C6F,
	0x2B3180C7EB51B255, 0xDF92B82F96C08BBC, 0x5C68C8C0A632F3BA, 0x5504CC861C3D0556,
	0xABBFA4E55FB26B8F, 0x41848B0AB3BACEB4, 0xB334A273AA445D32, 0xBCA696F0A85AD881,
	0x24F6EC65B528D56C, 0x0CE1512E90F4524A, 0x4E9DD79D5506D35A, 0x258905FAC6CE9779,
	0x2019295B3E109B33, 0xF8A9478B73A054CC, 0x2924F2F934417EB0, 0x3993357D536D1BC4,
	0x38A81AC21DB6FF8B, 0x47C4FBF17D6016BF, 0x1E0FAADD7667E3F5, 0x7ABCFF62938BEB96,
	0xA78DAD948FC179C9, 0x8F1F98B72911E50D, 0x61E48EAE27121A91, 0x4D62F7AD31859808,
	0xECEBA345EF5CEAEB, 0xF5CEB25EBC9684CE, 0xF633E20CB7F76221, 0xA32CDF06AB8293E4,
	0x985A202CA5EE2CA4, 0xCF0B8447CC8A8FB1, 0x9F765244979859A3, 0xA8D516B1A1240017,
	0x0BD7BA3EBB5DC726, 0xE54BCA55B86ADB39, 0x1D7A3AFD6C478063, 0x519EC608E7669EDD,
	0x0E5715A2D149AA23, 0x177D4571848FF194, 0xEEB55F3241014C22, 0x0F5E5CA13A6E2EC2,
	0x8029927B75F5C361, 0xAD139FABC3D6E436, 0x0D5DF1A94CCF402F, 0x3E8BD948BEA5DFC8,
	0xA5A0D357BD3FF77E, 0xA2D12E251F74F645, 0x66FD9E525E81A082, 0x2E0C90CE7F687A49,
	0xC2E8BCBEBA973BC5, 0x000001BCE509745F, 0x423777BBE6DAB3D6, 0xD1661C7EAEF06EB5,
	0xA1781F354DAACFD8, 0x2D11284A2B16AFFC, 0xF1FC4F67FA891D1F, 0x73ECC25DCB920ADA,
	0xAE610C22C2A12651, 0x96E0A810D356B78A, 0x5A9A381F2FE7870F, 0xD5AD62EDE94E5530,
	0xD225E5E8368D1427, 0x65977B70C7AF4631, 0x99F889B2DE39D74F, 0x233F30BF54E1D143,
	0x9A9675D3D9A63C97, 0x5470554FF334F9A8, 0x166ACB744A4F5688, 0x70C74CAAB2E4AEAD,
	0xF0D091646F294D12, 0x57B82A89684031D1, 0xEFD95A5A61BE0B6B, 0x2FBD12E969F2F29A,
	0x9BD37013FEFF9FE8, 0x3F9B0404D6085A06, 0x4940C1F3166CFE15, 0x09542C4DCDF3DEFB,
	0xB4C5218385CD5CE3, 0xC935B7DC4462A641, 0x3417F8A68ED3B63F, 0xB80959295B215B40,
	0xF99CDAEF3B8C8572, 0x018C0614F8FCB95D, 0x1B14ACCD1A3ACDF3, 0x84D471F200BB732D,
	0xC1A3110E95E8DA16, 0x430A7220BF1A82B8, 0xB77E090D39DF210E, 0x5EF4BD9F3CD05E9D,
	0x9D4FF6DA7E57A444, 0xDA1D60E183D4A5F8, 0xB287C38417998E47, 0xFE3EDC121BB31886,
	0xC7FE3CCC980CCBEF, 0xE46FB590189BFD03, 0x3732FD469A4C57DC, 0x7EF700A07CF1AD65,
	0x59C64468A31D8859, 0x762FB0B4D45B61F6, 0x155BAED099047718, 0x68755E4C3D50BAA6,
	0xE9214E7F22D8B4DF, 0x2ADDBF532EAC95F4, 0x32AE3909B4BD0109, 0x834DF537B08E3450,
	0xFA209DA84220728D, 0x9E691D9B9EFE23F7, 0x0446D288C4AE8D7F, 0x7B4CC524E169785B,
	0x21D87F0135CA1385, 0xCEBB400F137B8AA5, 0x272E2B66580796BE, 0x3612264125C2B0DE,
	0x057702BDAD1EFBB2, 0xD4BABB8EACF84BE9, 0x91583139641BC67B, 0x8BDC2DE08036E024,
	0x603C8156F49F68ED, 0xF7D236F7DBEF5111, 0x9727C4598AD21E80, 0xA08A0896670A5FD7,
	0xCB4A8F4309EBA9CB, 0x81AF564B0F7036A1, 0xC0B99AA778199ABD, 0x959F1EC83FC8E952,
	0x8C505077794A81B9, 0x3ACAAF8F056338F0, 0x07B43F50627A6778, 0x4A44AB49F5ECCC77,
	0x3BC3D6E4B679EE98, 0x9CC0D4D1CF14108C, 0x4406C00B206BC8A0, 0x82A18854C8D72D89,
	0x67E366B35C3C432C, 0xB923DD61102B37F2, 0x56AB2779D884271D, 0xBE83E1B0FF1525AF,
	0xFB7C65D4217E49A9, 0x6BDBE0E76D48E7D4, 0x08DF828745D9179E, 0x22EA6A9ADD53BD34,
	0xE36E141C5622200A, 0x7F805D1B8CB750EE, 0xAFE5C7A59F58E837, 0xE27F996A4FB1C23C,
	0xD3867DFB0775F0D0, 0xD0E673DE6E88891A, 0x123AEB9EAFB86C25, 0x30F1D5D5C145B895,
	0xBB434A2DEE7269E7, 0x78CB67ECF931FA38, 0xF33B0372323BBF9C, 0x52D66336FB279C74,
	0x505F33AC0AFB4EAA, 0xE8A5CD99A2CCE187, 0x534974801E2D30BB, 0x8D2D5711D5876D90,
	0x1F1A412891BC038E, 0xD6E2E71D82E56648, 0x74036C3A497732B7, 0x89B67ED96361F5AB,
	0xFFED95D8F1EA02A2, 0xE72B3BD61464D43D, 0xA6300F170BDC4820, 0xEBC18760ED78A77A
};
UI8
MASTER_TIGER_TABLE_T2[256] = {
	0xE6A6BE5A05A12138, 0xB5A122A5B4F87C98, 0x563C6089140B6990, 0x4C46CB2E391F5DD5,
	0xD932ADDBC9B79434, 0x08EA70E42015AFF5, 0xD765A6673E478CF1, 0xC4FB757EAB278D99,
	0xDF11C6862D6E0692, 0xDDEB84F10D7F3B16, 0x6F2EF604A665EA04, 0x4A8E0F0FF0E0DFB3,
	0xA5EDEEF83DBCBA51, 0xFC4F0A2A0EA4371E, 0xE83E1DA85CB38429, 0xDC8FF882BA1B1CE2,
	0xCD45505E8353E80D, 0x18D19A00D4DB0717, 0x34A0CFEDA5F38101, 0x0BE77E518887CAF2,
	0x1E341438B3C45136, 0xE05797F49089CCF9, 0xFFD23F9DF2591D14, 0x543DDA228595C5CD,
	0x661F81FD99052A33, 0x8736E641DB0F7B76, 0x15227725418E5307, 0xE25F7F46162EB2FA,
	0x48A8B2126C13D9FE, 0xAFDC541792E76EEA, 0x03D912BFC6D1898F, 0x31B1AAFA1B83F51B,
	0xF1AC2796E42AB7D9, 0x40A3A7D7FCD2EBAC, 0x1056136D0AFBBCC5, 0x7889E1DD9A6D0C85,
	0xD33525782A7974AA, 0xA7E25D09078AC09B, 0xBD4138B3EAC6EDD0, 0x920ABFBE71EB9E70,
	0xA2A5D0F54FC2625C, 0xC054E36B0B1290A3, 0xF6DD59FF62FE932B, 0x3537354511A8AC7D,
	0xCA845E9172FADCD4, 0x84F82B60329D20DC, 0x79C62CE1CD672F18, 0x8B09A2ADD124642C,
	0xD0C1E96A19D9E726, 0x5A786A9B4BA9500C, 0x0E020336634C43F3, 0xC17B474AEB66D822,
	0x6A731AE3EC9BAAC2, 0x8226667AE0840258, 0x67D4567691CAECA5, 0x1D94155C4875ADB5,
	0x6D00FD985B813FDF, 0x51286EFCB774CD06, 0x5E8834471FA744AF, 0xF72CA0AEE761AE2E,
	0xBE40E4CDAEE8E09A, 0xE9970BBB5118F665, 0x726E4BEB33DF1964, 0x703B000729199762,
	0x4631D816F5EF30A7, 0xB880B5B51504A6BE, 0x641793C37ED84B6C, 0x7B21ED77F6E97D96,
	0x776306312EF96B73, 0xAE528948E86FF3F4, 0x53DBD7F286A3F8F8, 0x16CADCE74CFC1063,
	0x005C19BDFA52C6DD, 0x68868F5D64D46AD3, 0x3A9D512CCF1E186A, 0x367E62C2385660AE,
	0xE359E7EA77DCB1D7, 0x526C0773749ABE6E, 0x735AE5F9D09F734B, 0x493FC7CC8A558BA8,
	0xB0B9C1533041AB45, 0x321958BA470A59BD, 0x852DB00B5F46C393, 0x91209B2BD336B0E5,
	0x6E604F7D659EF19F, 0xB99A8AE2782CCB24, 0xCCF52AB6C814C4C7, 0x4727D9AFBE11727B,
	0x7E950D0C0121B34D, 0x756F435670AD471F, 0xF5ADD442615A6849, 0x4E87E09980B9957A,
	0x2ACFA1DF50AEE355, 0xD898263AFD2FD556, 0xC8F4924DD80C8FD6, 0xCF99CA3D754A173A,
	0xFE477BACAF91BF3C, 0xED5371F6D690C12D, 0x831A5C285E687094, 0xC5D3C90A3708A0A4,
	0x0F7F903717D06580, 0x19F9BB13B8FDF27F, 0xB1BD6F1B4D502843, 0x1C761BA38FFF4012,
	0x0D1530C4E2E21F3B, 0x8943CE69A7372C8A, 0xE5184E11FEB5CE66, 0x618BDB80BD736621,
	0x7D29BAD68B574D0B, 0x81BB613E25E6FE5B, 0x071C9C10BC07913F, 0xC7BEEB7909AC2D97,
	0xC3E58D353BC5D757, 0xEB017892F38F61E8, 0xD4EFFB9C9B1CC21A, 0x99727D26F494F7AB,
	0xA3E063A2956B3E03, 0x9D4A8B9A4AA09C30, 0x3F6AB7D500090FB4, 0x9CC0F2A057268AC0,
	0x3DEE9D2DEDBF42D1, 0x330F49C87960A972, 0xC6B2720287421B41, 0x0AC59EC07C00369C,
	0xEF4EAC49CB353425, 0xF450244EEF0129D8, 0x8ACC46E5CAF4DEB6, 0x2FFEAB63989263F7,
	0x8F7CB9FE5D7A4578, 0x5BD8F7644E634635, 0x427A7315BF2DC900, 0x17D0C4AA2125261C,
	0x3992486C93518E50, 0xB4CBFEE0A2D7D4C3, 0x7C75D6202C5DDD8D, 0xDBC295D8E35B6C61,
	0x60B369D302032B19, 0xCE42685FDCE44132, 0x06F3DDB9DDF65610, 0x8EA4D21DB5E148F0,
	0x20B0FCE62FCD496F, 0x2C1B912358B0EE31, 0xB28317B818F5A308, 0xA89C1E189CA6D2CF,
	0x0C6B18576AAADBC8, 0xB65DEAA91299FAE3, 0xFB2B794B7F1027E7, 0x04E4317F443B5BEB,
	0x4B852D325939D0A6, 0xD5AE6BEEFB207FFC, 0x309682B281C7D374, 0xBAE309A194C3B475,
	0x8CC3F97B13B49F05, 0x98A9422FF8293967, 0x244B16B01076FF7C, 0xF8BF571C663D67EE,
	0x1F0D6758EEE30DA1, 0xC9B611D97ADEB9B7, 0xB7AFD5887B6C57A2, 0x6290AE846B984FE1,
	0x94DF4CDEACC1A5FD, 0x058A5BD1C5483AFF, 0x63166CC142BA3C37, 0x8DB8526EB2F76F40,
	0xE10880036F0D6D4E, 0x9E0523C9971D311D, 0x45EC2824CC7CD691, 0x575B8359E62382C9,
	0xFA9E400DC4889995, 0xD1823ECB45721568, 0xDAFD983B8206082F, 0xAA7D29082386A8CB,
	0x269FCD4403B87588, 0x1B91F5F728BDD1E0, 0xE4669F39040201F6, 0x7A1D7C218CF04ADE,
	0x65623C29D79CE5CE, 0x2368449096C00BB1, 0xAB9BF1879DA503BA, 0xBC23ECB1A458058E,
	0x9A58DF01BB401ECC, 0xA070E868A85F143D, 0x4FF188307DF2239E, 0x14D565B41A641183,
	0xEE13337452701602, 0x950E3DCF3F285E09, 0x59930254B9C80953, 0x3BF299408930DA6D,
	0xA955943F53691387, 0xA15EDECAA9CB8784, 0x29142127352BE9A0, 0x76F0371FFF4E7AFB,
	0x0239F450274F2228, 0xBB073AF01D5E868B, 0xBFC80571C10E96C1, 0xD267088568222E23,
	0x9671A3D48E80B5B0, 0x55B5D38AE193BB81, 0x693AE2D0A18B04B8, 0x5C48B4ECADD5335F,
	0xFD743B194916A1CA, 0x2577018134BE98C4, 0xE77987E83C54A4AD, 0x28E11014DA33E1B9,
	0x270CC59E226AA213, 0x71495F756D1A5F60, 0x9BE853FB60AFEF77, 0xADC786A7F7443DBF,
	0x0904456173B29A82, 0x58BC7A66C232BD5E, 0xF306558C673AC8B2, 0x41F639C6B6C9772A,
	0x216DEFE99FDA35DA, 0x11640CC71C7BE615, 0x93C43694565C5527, 0xEA038E6246777839,
	0xF9ABF3CE5A3E2469, 0x741E768D0FD312D2, 0x0144B883CED652C6, 0xC20B5A5BA33F8552,
	0x1AE69633C3435A9D, 0x97A28CA4088CFDEC, 0x8824A43C1E96F420, 0x37612FA66EEEA746,
	0x6B4CB165F9CF0E5A, 0x43AA1C06A0ABFB4A, 0x7F4DC26FF162796B, 0x6CBACC8E54ED9B0F,
	0xA6B7FFEFD2BB253E, 0x2E25BC95B0A29D4F, 0x86D6A58BDEF1388C, 0xDED74AC576B6F054,
	0x8030BDBC2B45805D, 0x3C81AF70E94D9289, 0x3EFF6DDA9E3100DB, 0xB38DC39FDFCC8847,
	0x123885528D17B87E, 0xF2DA0ED240B1B642, 0x44CEFADCD54BF9A9, 0x1312200E433C7EE6,
	0x9FFCC84F3A78C748, 0xF0CD1F72248576BB, 0xEC6974053638CFE4, 0x2BA7B67C0CEC4E4C,
	0xAC2F4DF3E5CE32ED, 0xCB33D14326EA4C11, 0xA4E9044CC77E58BC, 0x5F513293D934FCEF,
	0x5DC9645506E55444, 0x50DE418F317DE40A, 0x388CB31A69DDE259, 0x2DB4A83455820A86,
	0x9010A91E84711AE9, 0x4DF7F0B7B1498371, 0xD62A2EABC0977179, 0x22FAC097AA8D5C0E
};
UI8
MASTER_TIGER_TABLE_T3[256] = {
	0xF49FCC2FF1DAF39B, 0x487FD5C66FF29281, 0xE8A30667FCDCA83F, 0x2C9B4BE3D2FCCE63,
	0xDA3FF74B93FBBBC2, 0x2FA165D2FE70BA66, 0xA103E279970E93D4, 0xBECDEC77B0E45E71,
	0xCFB41E723985E497, 0xB70AAA025EF75017, 0xD42309F03840B8E0, 0x8EFC1AD035898579,
	0x96C6920BE2B2ABC5, 0x66AF4163375A9172, 0x2174ABDCCA7127FB, 0xB33CCEA64A72FF41,
	0xF04A4933083066A5, 0x8D970ACDD7289AF5, 0x8F96E8E031C8C25E, 0xF3FEC02276875D47,
	0xEC7BF310056190DD, 0xF5ADB0AEBB0F1491, 0x9B50F8850FD58892, 0x4975488358B74DE8,
	0xA3354FF691531C61, 0x0702BBE481D2C6EE, 0x89FB24057DEDED98, 0xAC3075138596E902,
	0x1D2D3580172772ED, 0xEB738FC28E6BC30D, 0x5854EF8F63044326, 0x9E5C52325ADD3BBE,
	0x90AA53CF325C4623, 0xC1D24D51349DD067, 0x2051CFEEA69EA624, 0x13220F0A862E7E4F,
	0xCE39399404E04864, 0xD9C42CA47086FCB7, 0x685AD2238A03E7CC, 0x066484B2AB2FF1DB,
	0xFE9D5D70EFBF79EC, 0x5B13B9DD9C481854, 0x15F0D475ED1509AD, 0x0BEBCD060EC79851,
	0xD58C6791183AB7F8, 0xD1187C5052F3EEE4, 0xC95D1192E54E82FF, 0x86EEA14CB9AC6CA2,
	0x3485BEB153677D5D, 0xDD191D781F8C492A, 0xF60866BAA784EBF9, 0x518F643BA2D08C74,
	0x8852E956E1087C22, 0xA768CB8DC410AE8D, 0x38047726BFEC8E1A, 0xA67738B4CD3B45AA,
	0xAD16691CEC0DDE19, 0xC6D4319380462E07, 0xC5A5876D0BA61938, 0x16B9FA1FA58FD840,
	0x188AB1173CA74F18, 0xABDA2F98C99C021F, 0x3E0580AB134AE816, 0x5F3B05B773645ABB,
	0x2501A2BE5575F2F6, 0x1B2F74004E7E8BA9, 0x1CD7580371E8D953, 0x7F6ED89562764E30,
	0xB15926FF596F003D, 0x9F65293DA8C5D6B9, 0x6ECEF04DD690F84C, 0x4782275FFF33AF88,
	0xE41433083F820801, 0xFD0DFE409A1AF9B5, 0x4325A3342CDB396B, 0x8AE77E62B301B252,
	0xC36F9E9F6655615A, 0x85455A2D92D32C09, 0xF2C7DEA949477485, 0x63CFB4C133A39EBA,
	0x83B040CC6EBC5462, 0x3B9454C8FDB326B0, 0x56F56A9E87FFD78C, 0x2DC2940D99F42BC6,
	0x98F7DF096B096E2D, 0x19A6E01E3AD852BF, 0x42A99CCBDBD4B40B, 0xA59998AF45E9C559,
	0x366295E807D93186, 0x6B48181BFAA1F773, 0x1FEC57E2157A0A1D, 0x4667446AF6201AD5,
	0xE615EBCACFB0F075, 0xB8F31F4F68290778, 0x22713ED6CE22D11E, 0x3057C1A72EC3C93B,
	0xCB46ACC37C3F1F2F, 0xDBB893FD02AAF50E, 0x331FD92E600B9FCF, 0xA498F96148EA3AD6,
	0xA8D8426E8B6A83EA, 0xA089B274B7735CDC, 0x87F6B3731E524A11, 0x118808E5CBC96749,
	0x9906E4C7B19BD394, 0xAFED7F7E9B24A20C, 0x6509EADEEB3644A7, 0x6C1EF1D3E8EF0EDE,
	0xB9C97D43E9798FB4, 0xA2F2D784740C28A3, 0x7B8496476197566F, 0x7A5BE3E6B65F069D,
	0xF96330ED78BE6F10, 0xEEE60DE77A076A15, 0x2B4BEE4AA08B9BD0, 0x6A56A63EC7B8894E,
	0x02121359BA34FEF4, 0x4CBF99F8283703FC, 0x398071350CAF30C8, 0xD0A77A89F017687A,
	0xF1C1A9EB9E423569, 0x8C7976282DEE8199, 0x5D1737A5DD1F7ABD, 0x4F53433C09A9FA80,
	0xFA8B0C53DF7CA1D9, 0x3FD9DCBC886CCB77, 0xC040917CA91B4720, 0x7DD00142F9D1DCDF,
	0x8476FC1D4F387B58, 0x23F8E7C5F3316503, 0x032A2244E7E37339, 0x5C87A5D750F5A74B,
	0x082B4CC43698992E, 0xDF917BECB858F63C, 0x3270B8FC5BF86DDA, 0x10AE72BB29B5DD76,
	0x576AC94E7700362B, 0x1AD112DAC61EFB8F, 0x691BC30EC5FAA427, 0xFF246311CC327143,
	0x3142368E30E53206, 0x71380E31E02CA396, 0x958D5C960AAD76F1, 0xF8D6F430C16DA536,
	0xC8FFD13F1BE7E1D2, 0x7578AE66004DDBE1, 0x05833F01067BE646, 0xBB34B5AD3BFE586D,
	0x095F34C9A12B97F0, 0x247AB64525D60CA8, 0xDCDBC6F3017477D1, 0x4A2E14D4DECAD24D,
	0xBDB5E6D9BE0A1EEB, 0x2A7E70F7794301AB, 0xDEF42D8A270540FD, 0x01078EC0A34C22C1,
	0xE5DE511AF4C16387, 0x7EBB3A52BD9A330A, 0x77697857AA7D6435, 0x004E831603AE4C32,
	0xE7A21020AD78E312, 0x9D41A70C6AB420F2, 0x28E06C18EA1141E6, 0xD2B28CBD984F6B28,
	0x26B75F6C446E9D83, 0xBA47568C4D418D7F, 0xD80BADBFE6183D8E, 0x0E206D7F5F166044,
	0xE258A43911CBCA3E, 0x723A1746B21DC0BC, 0xC7CAA854F5D7CDD3, 0x7CAC32883D261D9C,
	0x7690C26423BA942C, 0x17E55524478042B8, 0xE0BE477656A2389F, 0x4D289B5E67AB2DA0,
	0x44862B9C8FBBFD31, 0xB47CC8049D141365, 0x822C1B362B91C793, 0x4EB14655FB13DFD8,
	0x1ECBBA0714E2A97B, 0x6143459D5CDE5F14, 0x53A8FBF1D5F0AC89, 0x97EA04D81C5E5B00,
	0x622181A8D4FDB3F3, 0xE9BCD341572A1208, 0x1411258643CCE58A, 0x9144C5FEA4C6E0A4,
	0x0D33D06565CF620F, 0x54A48D489F219CA1, 0xC43E5EAC6D63C821, 0xA9728B3A72770DAF,
	0xD7934E7B20DF87EF, 0xE35503B61A3E86E5, 0xCAE321FBC819D504, 0x129A50B3AC60BFA6,
	0xCD5E68EA7E9FB6C3, 0xB01C90199483B1C7, 0x3DE93CD5C295376C, 0xAED52EDF2AB9AD13,
	0x2E60F512C0A07884, 0xBC3D86A3E36210C9, 0x35269D9B163951CE, 0x0C7D6E2AD0CDB5FA,
	0x59E86297D87F5733, 0x298EF221898DB0E7, 0x55000029D1A5AA7E, 0x8BC08AE1B5061B45,
	0xC2C31C2B6C92703A, 0x94CC596BAF25EF42, 0x0A1D73DB22540456, 0x04B6A0F9D9C4179A,
	0xEFFDAFA2AE3D3C60, 0xF7C8075BB49496C4, 0x9CC5C7141D1CD4E3, 0x78BD1638218E5534,
	0xB2F11568F850246A, 0xEDFABCFA9502BC29, 0x796CE5F2DA23051B, 0xAAE128B0DC93537C,
	0x3A493DA0EE4B29AE, 0xB5DF6B2C416895D7, 0xFCABBD25122D7F37, 0x70810B58105DC4B1,
	0xE10FDD37F7882A90, 0x524DCAB5518A3F5C, 0x3C9E85878451255B, 0x4029828119BD34E2,
	0x74A05B6F5D3CECCB, 0xB610021542E13ECA, 0x0FF979D12F59E2AC, 0x6037DA27E4F9CC50,
	0x5E92975A0DF1847D, 0xD66DE190D3E623FE, 0x5032D6B87B568048, 0x9A36B7CE8235216E,
	0x80272A7A24F64B4A, 0x93EFED8B8C6916F7, 0x37DDBFF44CCE1555, 0x4B95DB5D4B99BD25,
	0x92D3FDA169812FC0, 0xFB1A4A9A90660BB6, 0x730C196946A4B9B2, 0x81E289AA7F49DA68,
	0x64669A0F83B1A05F, 0x27B3FF7D9644F48B, 0xCC6B615C8DB675B3, 0x674F20B9BCEBBE95,
	0x6F31238275655982, 0x5AE488713E45CF05, 0xBF619F9954C21157, 0xEABAC46040A8EAE9,
	0x454C6FE9F2C0C1CD, 0x419CF6496412691C, 0xD3DC3BEF265B0F70, 0x6D0E60F5C3578A9E
};
UI8
MASTER_TIGER_TABLE_T4[256] = {
	0x5B0E608526323C55, 0x1A46C1A9FA1B59F5, 0xA9E245A17C4C8FFA, 0x65CA5159DB2955D7,
	0x05DB0A76CE35AFC2, 0x81EAC77EA9113D45, 0x528EF88AB6AC0A0D, 0xA09EA253597BE3FF,
	0x430DDFB3AC48CD56, 0xC4B3A67AF45CE46F, 0x4ECECFD8FBE2D05E, 0x3EF56F10B39935F0,
	0x0B22D6829CD619C6, 0x17FD460A74DF2069, 0x6CF8CC8E8510ED40, 0xD6C824BF3A6ECAA7,
	0x61243D581A817049, 0x048BACB6BBC163A2, 0xD9A38AC27D44CC32, 0x7FDDFF5BAAF410AB,
	0xAD6D495AA804824B, 0xE1A6A74F2D8C9F94, 0xD4F7851235DEE8E3, 0xFD4B7F886540D893,
	0x247C20042AA4BFDA, 0x096EA1C517D1327C, 0xD56966B4361A6685, 0x277DA5C31221057D,
	0x94D59893A43ACFF7, 0x64F0C51CCDC02281, 0x3D33BCC4FF6189DB, 0xE005CB184CE66AF1,
	0xFF5CCD1D1DB99BEA, 0xB0B854A7FE42980F, 0x7BD46A6A718D4B9F, 0xD10FA8CC22A5FD8C,
	0xD31484952BE4BD31, 0xC7FA975FCB243847, 0x4886ED1E5846C407, 0x28CDDB791EB70B04,
	0xC2B00BE2F573417F, 0x5C9590452180F877, 0x7A6BDDFFF370EB00, 0xCE509E38D6D9D6A4,
	0xEBEB0F00647FA702, 0x1DCC06CF76606F06, 0xE4D9F28BA286FF0A, 0xD85A305DC918C262,
	0x475B1D8732225F54, 0x2D4FB51668CCB5FE, 0xA679B9D9D72BBA20, 0x53841C0D912D43A5,
	0x3B7EAA48BF12A4E8, 0x781E0E47F22F1DDF, 0xEFF20CE60AB50973, 0x20D261D19DFFB742,
	0x16A12B03062A2E39, 0x1960EB2239650495, 0x251C16FED50EB8B8, 0x9AC0C330F826016E,
	0xED152665953E7671, 0x02D63194A6369570, 0x5074F08394B1C987, 0x70BA598C90B25CE1,
	0x794A15810B9742F6, 0x0D5925E9FCAF8C6C, 0x3067716CD868744E, 0x910AB077E8D7731B,
	0x6A61BBDB5AC42F61, 0x93513EFBF0851567, 0xF494724B9E83E9D5, 0xE887E1985C09648D,
	0x34B1D3C675370CFD, 0xDC35E433BC0D255D, 0xD0AAB84234131BE0, 0x08042A50B48B7EAF,
	0x9997C4EE44A3AB35, 0x829A7B49201799D0, 0x263B8307B7C54441, 0x752F95F4FD6A6CA6,
	0x927217402C08C6E5, 0x2A8AB754A795D9EE, 0xA442F7552F72943D, 0x2C31334E19781208,
	0x4FA98D7CEAEE6291, 0x55C3862F665DB309, 0xBD0610175D53B1F3, 0x46FE6CB840413F27,
	0x3FE03792DF0CFA59, 0xCFE700372EB85E8F, 0xA7BE29E7ADBCE118, 0xE544EE5CDE8431DD,
	0x8A781B1B41F1873E, 0xA5C94C78A0D2F0E7, 0x39412E2877B60728, 0xA1265EF3AFC9A62C,
	0xBCC2770C6A2506C5, 0x3AB66DD5DCE1CE12, 0xE65499D04A675B37, 0x7D8F523481BFD216,
	0x0F6F64FCEC15F389, 0x74EFBE618B5B13C8, 0xACDC82B714273E1D, 0xDD40BFE003199D17,
	0x37E99257E7E061F8, 0xFA52626904775AAA, 0x8BBBF63A463D56F9, 0xF0013F1543A26E64,
	0xA8307E9F879EC898, 0xCC4C27A4150177CC, 0x1B432F2CCA1D3348, 0xDE1D1F8F9F6FA013,
	0x606602A047A7DDD6, 0xD237AB64CC1CB2C7, 0x9B938E7225FCD1D3, 0xEC4E03708E0FF476,
	0xFEB2FBDA3D03C12D, 0xAE0BCED2EE43889A, 0x22CB8923EBFB4F43, 0x69360D013CF7396D,
	0x855E3602D2D4E022, 0x073805BAD01F784C, 0x33E17A133852F546, 0xDF4874058AC7B638,
	0xBA92B29C678AA14A, 0x0CE89FC76CFAADCD, 0x5F9D4E0908339E34, 0xF1AFE9291F5923B9,
	0x6E3480F60F4A265F, 0xEEBF3A2AB29B841C, 0xE21938A88F91B4AD, 0x57DFEFF845C6D3C3,
	0x2F006B0BF62CAAF2, 0x62F479EF6F75EE78, 0x11A55AD41C8916A9, 0xF229D29084FED453,
	0x42F1C27B16B000E6, 0x2B1F76749823C074, 0x4B76ECA3C2745360, 0x8C98F463B91691BD,
	0x14BCC93CF1ADE66A, 0x8885213E6D458397, 0x8E177DF0274D4711, 0xB49B73B5503F2951,
	0x10168168C3F96B6B, 0x0E3D963B63CAB0AE, 0x8DFC4B5655A1DB14, 0xF789F1356E14DE5C,
	0x683E68AF4E51DAC1, 0xC9A84F9D8D4B0FD9, 0x3691E03F52A0F9D1, 0x5ED86E46E1878E80,
	0x3C711A0E99D07150, 0x5A0865B20C4E9310, 0x56FBFC1FE4F0682E, 0xEA8D5DE3105EDF9B,
	0x71ABFDB12379187A, 0x2EB99DE1BEE77B9C, 0x21ECC0EA33CF4523, 0x59A4D7521805C7A1,
	0x3896F5EB56AE7C72, 0xAA638F3DB18F75DC, 0x9F39358DABE9808E, 0xB7DEFA91C00B72AC,
	0x6B5541FD62492D92, 0x6DC6DEE8F92E4D5B, 0x353F57ABC4BEEA7E, 0x735769D6DA5690CE,
	0x0A234AA642391484, 0xF6F9508028F80D9D, 0xB8E319A27AB3F215, 0x31AD9C1151341A4D,
	0x773C22A57BEF5805, 0x45C7561A07968633, 0xF913DA9E249DBE36, 0xDA652D9B78A64C68,
	0x4C27A97F3BC334EF, 0x76621220E66B17F4, 0x967743899ACD7D0B, 0xF3EE5BCAE0ED6782,
	0x409F753600C879FC, 0x06D09A39B5926DB6, 0x6F83AEB0317AC588, 0x01E6CA4A86381F21,
	0x66FF3462D19F3025, 0x72207C24DDFD3BFB, 0x4AF6B6D3E2ECE2EB, 0x9C994DBEC7EA08DE,
	0x49ACE597B09A8BC4, 0xB38C4766CF0797BA, 0x131B9373C57C2A75, 0xB1822CCE61931E58,
	0x9D7555B909BA1C0C, 0x127FAFDD937D11D2, 0x29DA3BADC66D92E4, 0xA2C1D57154C2ECBC,
	0x58C5134D82F6FE24, 0x1C3AE3515B62274F, 0xE907C82E01CB8126, 0xF8ED091913E37FCB,
	0x3249D8F9C80046C9, 0x80CF9BEDE388FB63, 0x1881539A116CF19E, 0x5103F3F76BD52457,
	0x15B7E6F5AE47F7A8, 0xDBD7C6DED47E9CCF, 0x44E55C410228BB1A, 0xB647D4255EDB4E99,
	0x5D11882BB8AAFC30, 0xF5098BBB29D3212A, 0x8FB5EA14E90296B3, 0x677B942157DD025A,
	0xFB58E7C0A390ACB5, 0x89D3674C83BD4A01, 0x9E2DA4DF4BF3B93B, 0xFCC41E328CAB4829,
	0x03F38C96BA582C52, 0xCAD1BDBD7FD85DB2, 0xBBB442C16082AE83, 0xB95FE86BA5DA9AB0,
	0xB22E04673771A93F, 0x845358C9493152D8, 0xBE2A488697B4541E, 0x95A2DC2DD38E6966,
	0xC02C11AC923C852B, 0x2388B1990DF2A87B, 0x7C8008FA1B4F37BE, 0x1F70D0C84D54E503,
	0x5490ADEC7ECE57D4, 0x002B3C27D9063A3A, 0x7EAEA3848030A2BF, 0xC602326DED2003C0,
	0x83A7287D69A94086, 0xC57A5FCB30F57A8A, 0xB56844E479EBE779, 0xA373B40F05DCBCE9,
	0xD71A786E88570EE2, 0x879CBACDBDE8F6A0, 0x976AD1BCC164A32F, 0xAB21E25E9666D78B,
	0x901063AAE5E5C33C, 0x9818B34448698D90, 0xE36487AE3E1E8ABB, 0xAFBDF931893BDCB4,
	0x6345A0DC5FBBD519, 0x8628FE269B9465CA, 0x1E5D01603F9C51EC, 0x4DE44006A15049B7,
	0xBF6C70E5F776CBB1, 0x411218F2EF552BED, 0xCB0C0708705A36A3, 0xE74D14754F986044,
	0xCD56D9430EA8280E, 0xC12591D7535F5065, 0xC83223F1720AEF96, 0xC3A0396F7363A51F
};

#define __MASTER_TIGER_FUNCTION_ROUND__(a,b,c,x,mul) \
	c ^= x; \
	a -= MASTER_TIGER_TABLE_T1[(UI1)(c)] ^ \
		MASTER_TIGER_TABLE_T2[(UI1)(((UI4)(c)) >> (2 * 8))] ^ \
		MASTER_TIGER_TABLE_T3[(UI1)((c) >> (4 * 8))] ^ \
		MASTER_TIGER_TABLE_T4[(UI1)(((UI4)((c) >> (4 * 8))) >> (2 * 8))] ; \
	b += MASTER_TIGER_TABLE_T4[(UI1)(((UI4)(c)) >> (1 * 8))] ^ \
		MASTER_TIGER_TABLE_T3[(UI1)(((UI4)(c)) >> (3 * 8))] ^ \
		MASTER_TIGER_TABLE_T2[(UI1)(((UI4)((c) >> (4 * 8))) >> (1 * 8))] ^ \
		MASTER_TIGER_TABLE_T1[(UI1)(((UI4)((c) >> (4 * 8))) >> (3 * 8))]; \
	b *= mul;

#define __MASTER_TIGER_FUNCTION_P__(a,b,c,mul) \
	__MASTER_TIGER_FUNCTION_ROUND__(a,b,c,x0,mul) \
	__MASTER_TIGER_FUNCTION_ROUND__(b,c,a,x1,mul) \
	__MASTER_TIGER_FUNCTION_ROUND__(c,a,b,x2,mul) \
	__MASTER_TIGER_FUNCTION_ROUND__(a,b,c,x3,mul) \
	__MASTER_TIGER_FUNCTION_ROUND__(b,c,a,x4,mul) \
	__MASTER_TIGER_FUNCTION_ROUND__(c,a,b,x5,mul) \
	__MASTER_TIGER_FUNCTION_ROUND__(a,b,c,x6,mul) \
	__MASTER_TIGER_FUNCTION_ROUND__(b,c,a,x7,mul)

#define __MASTER_TIGER_FUNCTION_KS__ do { \
	x0 -= x7 ^ 0xA5A5A5A5A5A5A5A5; \
	x1 ^= x0; \
	x2 += x1; \
	x3 -= x2 ^ ((~x1)<<19); \
	x4 ^= x3; \
	x5 += x4; \
	x6 -= x5 ^ ((~x4)>>23); \
	x7 ^= x6; \
	x0 += x7; \
	x1 -= x0 ^ ((~x7)<<19); \
	x2 ^= x1; \
	x3 += x2; \
	x4 -= x3 ^ ((~x2)>>23); \
	x5 ^= x4; \
	x6 += x5; \
	x7 -= x6 ^ 0x0123456789ABCDEF; \
} while (0)

typedef struct {
	UI8 __h[3]; 
	UI1 __b[64]; 
	UI8 __l;  
} MASTER_TIGER, MASTER_TIGER2;

MASTER_TIGER
MASTER_TIGER_Init(void) {
	MASTER_TIGER __tiger;
	__tiger.__l = 0;
	__tiger.__h[0] = 0x0123456789ABCDEF;
	__tiger.__h[1] = 0xFEDCBA9876543210;
	__tiger.__h[2] = 0xF096A5B4C3B2E187;
	return __tiger;
}

MASTER_TIGER2
MASTER_TIGER2_Init(void) {
	MASTER_TIGER2 __tiger;
	__tiger.__l = 0x8000000000000000;
	__tiger.__h[0] = 0x0123456789ABCDEF;
	__tiger.__h[1] = 0xFEDCBA9876543210;
	__tiger.__h[2] = 0xF096A5B4C3B2E187;
	return __tiger;
}

static void
MASTER_TIGER_Transform(UI8 * const state, UI8 * const block) {
	UI8 a, b, c;
	UI8 x0, x1, x2, x3, x4, x5, x6, x7;

	x0 = block[0]; x1 = block[1];
	x2 = block[2]; x3 = block[3];
	x4 = block[4]; x5 = block[5];
	x6 = block[6]; x7 = block[7];

	a = state[0];
	b = state[1];
	c = state[2];

	__MASTER_TIGER_FUNCTION_P__(a, b, c, 5);
	__MASTER_TIGER_FUNCTION_KS__;
	__MASTER_TIGER_FUNCTION_P__(c, a, b, 7);
	__MASTER_TIGER_FUNCTION_KS__;
	__MASTER_TIGER_FUNCTION_P__(b, c, a, 9);
	
	state[0] = a ^ state[0];
	state[1] = b - state[1];
	state[2] = c + state[2];
}

void
MASTER_TIGER_Update(MASTER_TIGER * const __tiger, const char * __s, UI8 __l) {
	UI8 index = (UI8)__tiger->__l & 63;
	__tiger->__l += __l;
	UI8 left;

	if (index) {
		left = 64 - index;
		if (__l < left) {
			if (__l > 0) memcpy(__tiger->__b + index, __s, __l);
			return;
		} else {
			memcpy(__tiger->__b + index, __s, left);
			MASTER_TIGER_Transform(__tiger->__h, (UI8 *)__tiger->__b);
			__s += left;
			__l -= left;
		}
	}
	while (__l >= 64) {
		if (0 == (7 & (UI8)__s)) MASTER_TIGER_Transform(__tiger->__h, (UI8 *)__s);
		else {
			memcpy(__tiger->__b, __s, 64);
			MASTER_TIGER_Transform(__tiger->__h, (UI8 *)__tiger->__b);
		}
		__s += 64;
		__l -= 64;
	}
	if (__l) memcpy(__tiger->__b, __s, __l);
}

void
MASTER_TIGER_Final(MASTER_TIGER * const __tiger, UI1 * hash_output) {
	UI4 index = (UI4)__tiger->__l & 63;
	UI8 * __M = (UI8 *)__tiger->__b;

	__tiger->__b[index++] = (__tiger->__l & 0x8000000000000000 ? 0x80 : 0x01);

	if (index > 56) {
		while (index < 64) __tiger->__b[index++] = 0;
		MASTER_TIGER_Transform(__tiger->__h, __M);
		index = 0;
	}
	while (index < 56) __tiger->__b[index++] = 0;
	__M[7] = (__tiger->__l & (~0x8000000000000000)) << 3;
	MASTER_TIGER_Transform(__tiger->__h, __M);

	memcpy(hash_output, &__tiger->__h, 24);
}

#define MASTER_TIGER2_Update MASTER_TIGER_Update
#define MASTER_TIGER2_Final MASTER_TIGER_Final

void
MASTER_TIGER_CalculateHashSum(const char * __s, UI4 __l, UI1 * hash_output) {
	MASTER_TIGER2 __tiger = MASTER_TIGER2_Init();
	MASTER_TIGER2_Update(&__tiger, __s, __l);
	MASTER_TIGER2_Final(&__tiger, hash_output);
}

void
MASTER_TIGER2_CalculateHashSum(const char * __s, UI4 __l, UI1 * hash_output) {
	MASTER_TIGER2 __tiger = MASTER_TIGER2_Init();
	MASTER_TIGER2_Update(&__tiger, __s, __l);
	MASTER_TIGER2_Final(&__tiger, hash_output);
}

#undef __MASTER_TIGER_FUNCTION_ROUND__
#undef __MASTER_TIGER_FUNCTION_P__
#undef __MASTER_TIGER_FUNCTION_KS__

// !# TIGER

// #! SNEFRU

typedef struct MASTER_SNEFRU {
	UI4 __h[8];		 
	UI1 __b[48]; 
	UI8 __l;		 
	UI4 __i;		 
	UI4 __dl; 
} MASTER_SNEFRU;

static const UI4
MASTER_SNEFRU_TABLE_SB[8 * 512] = {
	0x64f9001b, 0xfeddcdf6, 0x7c8ff1e2, 0x11d71514, 0x8b8c18d3, 0xdddf881e,
	0x6eab5056, 0x88ced8e1, 0x49148959, 0x69c56fd5, 0xb7994f03, 0x0fbcee3e,
	0x3c264940, 0x21557e58, 0xe14b3fc2, 0x2e5cf591, 0xdceff8ce, 0x092a1648,
	0xbe812936, 0xff7b0c6a, 0xd5251037, 0xafa448f1, 0x7dafc95a, 0x1ea69c3f,
	0xa417abe7, 0x5890e423, 0xb0cb70c0, 0xc85025f7, 0x244d97e3, 0x1ff3595f,
	0xc4ec6396, 0x59181e17, 0xe635b477, 0x354e7dbf, 0x796f7753, 0x66eb52cc,
	0x77c3f995, 0x32e3a927, 0x80ccaed6, 0x4e2be89d, 0x375bbd28, 0xad1a3d05,
	0x2b1b42b3, 0x16c44c71, 0x4d54bfa8, 0xe57ddc7a, 0xec6d8144, 0x5a71046b,
	0xd8229650, 0x87fc8f24, 0xcbc60e09, 0xb6390366, 0xd9f76092, 0xd393a70b,
	0x1d31a08a, 0x9cd971c9, 0x5c1ef445, 0x86fab694, 0xfdb44165, 0x8eaafcbe,
	0x4bcac6eb, 0xfb7a94e5, 0x5789d04e, 0xfa13cf35, 0x236b8da9, 0x4133f000,
	0x6224261c, 0xf412f23b, 0xe75e56a4, 0x30022116, 0xbaf17f1f, 0xd09872f9,
	0xc1a3699c, 0xf1e802aa, 0x0dd145dc, 0x4fdce093, 0x8d8412f0, 0x6cd0f376,
	0x3de6b73d, 0x84ba737f, 0xb43a30f2, 0x44569f69, 0x00e4eaca, 0xb58de3b0,
	0x959113c8, 0xd62efee9, 0x90861f83, 0xced69874, 0x2f793cee, 0xe8571c30,
	0x483665d1, 0xab07b031, 0x914c844f, 0x15bf3be8, 0x2c3f2a9a, 0x9eb95fd4,
	0x92e7472d, 0x2297cc5b, 0xee5f2782, 0x5377b562, 0xdb8ebbcf, 0xf961dedd,
	0xc59b5c60, 0x1bd3910d, 0x26d206ad, 0xb28514d8, 0x5ecf6b52, 0x7fea78bb,
	0x504879ac, 0xed34a884, 0x36e51d3c, 0x1753741d, 0x8c47caed, 0x9d0a40ef,
	0x3145e221, 0xda27eb70, 0xdf730ba3, 0x183c8789, 0x739ac0a6, 0x9a58dfc6,
	0x54b134c1, 0xac3e242e, 0xcc493902, 0x7b2dda99, 0x8f15bc01, 0x29fd38c7,
	0x27d5318f, 0x604aaff5, 0xf29c6818, 0xc38aa2ec, 0x1019d4c3, 0xa8fb936e,
	0x20ed7b39, 0x0b686119, 0x89a0906f, 0x1cc7829e, 0x9952ef4b, 0x850e9e8c,
	0xcd063a90, 0x67002f8e, 0xcfac8cb7, 0xeaa24b11, 0x988b4e6c, 0x46f066df,
	0xca7eec08, 0xc7bba664, 0x831d17bd, 0x63f575e6, 0x9764350e, 0x47870d42,
	0x026ca4a2, 0x8167d587, 0x61b6adab, 0xaa6564d2, 0x70da237b, 0x25e1c74a,
	0xa1c901a0, 0x0eb0a5da, 0x7670f741, 0x51c05aea, 0x933dfa32, 0x0759ff1a,
	0x56010ab8, 0x5fdecb78, 0x3f32edf8, 0xaebedbb9, 0x39f8326d, 0xd20858c5,
	0x9b638be4, 0xa572c80a, 0x28e0a19f, 0x432099fc, 0x3a37c3cd, 0xbf95c585,
	0xb392c12a, 0x6aa707d7, 0x52f66a61, 0x12d483b1, 0x96435b5e, 0x3e75802b,
	0x3ba52b33, 0xa99f51a5, 0xbda1e157, 0x78c2e70c, 0xfcae7ce0, 0xd1602267,
	0x2affac4d, 0x4a510947, 0x0ab2b83a, 0x7a04e579, 0x340dfd80, 0xb916e922,
	0xe29d5e9b, 0xf5624af4, 0x4ca9d9af, 0x6bbd2cfe, 0xe3b7f620, 0xc2746e07,
	0x5b42b9b6, 0xa06919bc, 0xf0f2c40f, 0x72217ab5, 0x14c19df3, 0xf3802dae,
	0xe094beb4, 0xa2101aff, 0x0529575d, 0x55cdb27c, 0xa33bddb2, 0x6528b37d,
	0x740c05db, 0xe96a62c4, 0x40782846, 0x6d30d706, 0xbbf48e2c, 0xbce2d3de,
	0x049e37fa, 0x01b5e634, 0x2d886d8d, 0x7e5a2e7e, 0xd7412013, 0x06e90f97,
	0xe45d3eba, 0xb8ad3386, 0x13051b25, 0x0c035354, 0x71c89b75, 0xc638fbd0,
	0x197f11a1, 0xef0f08fb, 0xf8448651, 0x38409563, 0x452f4443, 0x5d464d55,
	0x03d8764c, 0xb1b8d638, 0xa70bba2f, 0x94b3d210, 0xeb6692a7, 0xd409c2d9,
	0x68838526, 0xa6db8a15, 0x751f6c98, 0xde769a88, 0xc9ee4668, 0x1a82a373,
	0x0896aa49, 0x42233681, 0xf62c55cb, 0x9f1c5404, 0xf74fb15c, 0xc06e4312,
	0x6ffe5d72, 0x8aa8678b, 0x337cd129, 0x8211cefd, 0x074a1d09, 0x52a10e5a,
	0x9275a3f8, 0x4b82506c, 0x37df7e1b, 0x4c78b3c5, 0xcefab1da, 0xf472267e,
	0xb63045f6, 0xd66a1fc0, 0x400298e3, 0x27e60c94, 0x87d2f1b8, 0xdf9e56cc,
	0x45cd1803, 0x1d35e098, 0xcce7c736, 0x03483bf1, 0x1f7307d7, 0xc6e8f948,
	0xe613c111, 0x3955c6ff, 0x1170ed7c, 0x8e95da41, 0x99c31bf4, 0xa4da8021,
	0x7b5f94fb, 0xdd0da51f, 0x6562aa77, 0x556bcb23, 0xdb1bacc6, 0x798040b9,
	0xbfe5378f, 0x731d55e6, 0xdaa5bfee, 0x389bbc60, 0x1b33fba4, 0x9c567204,
	0x36c26c68, 0x77ee9d69, 0x8aeb3e88, 0x2d50b5ce, 0x9579e790, 0x42b13cfc,
	0x33fbd32b, 0xee0503a7, 0xb5862824, 0x15e41ead, 0xc8412ef7, 0x9d441275,
	0x2fcec582, 0x5ff483b7, 0x8f3931df, 0x2e5d2a7b, 0x49467bf9, 0x0653dea9,
	0x2684ce35, 0x7e655e5c, 0xf12771d8, 0xbb15cc67, 0xab097ca1, 0x983dcf52,
	0x10ddf026, 0x21267f57, 0x2c58f6b4, 0x31043265, 0x0bab8c01, 0xd5492099,
	0xacaae619, 0x944ce54a, 0xf2d13d39, 0xadd3fc32, 0xcda08a40, 0xe2b0d451,
	0x9efe08ae, 0xb9d50fd2, 0xea5cd7fd, 0xc9a749dd, 0x13ea2253, 0x832debaa,
	0x24be640f, 0xe03e926a, 0x29e01cde, 0x8bf59f18, 0x0f9d00b6, 0xe1238b46,
	0x1e7d8e34, 0x93619adb, 0x76b32f9f, 0xbd972cec, 0xe31fa976, 0xa68fbb10,
	0xfb3ba49d, 0x8587c41d, 0xa5add1d0, 0xf3cf84bf, 0xd4e11150, 0xd9ffa6bc,
	0xc3f6018c, 0xaef10572, 0x74a64b2f, 0xe7dc9559, 0x2aae35d5, 0x5b6f587f,
	0xa9e353fe, 0xca4fb674, 0x04ba24a8, 0xe5c6875f, 0xdcbc6266, 0x6bc5c03f,
	0x661eef02, 0xed740bab, 0x058e34e4, 0xb7e946cf, 0x88698125, 0x72ec48ed,
	0xb11073a3, 0xa13485eb, 0xa2a2429c, 0xfa407547, 0x50b76713, 0x5418c37d,
	0x96192da5, 0x170bb04b, 0x518a021e, 0xb0ac13d1, 0x0963fa2a, 0x4a6e10e1,
	0x58472bdc, 0xf7f8d962, 0x979139ea, 0x8d856538, 0xc0997042, 0x48324d7a,
	0x447623cb, 0x8cbbe364, 0x6e0c6b0e, 0xd36d63b0, 0x3f244c84, 0x3542c971,
	0x2b228dc1, 0xcb0325bb, 0xf8c0d6e9, 0xde11066b, 0xa8649327, 0xfc31f83e,
	0x7dd80406, 0xf916dd61, 0xd89f79d3, 0x615144c2, 0xebb45d31, 0x28002958,
	0x56890a37, 0xf05b3808, 0x123ae844, 0x86839e16, 0x914b0d83, 0xc506b43c,
	0xcf3cba5e, 0x7c60f5c9, 0x22deb2a0, 0x5d9c2715, 0xc77ba0ef, 0x4f45360b,
	0xc1017d8b, 0xe45adc29, 0xa759909b, 0x412cd293, 0xd7d796b1, 0x00c8ff30,
	0x23a34a80, 0x4ec15c91, 0x714e78b5, 0x47b9e42e, 0x78f3ea4d, 0x7f078f5b,
	0x346c593a, 0xa3a87a1a, 0x9bcbfe12, 0x3d439963, 0xb2ef6d8e, 0xb8d46028,
	0x6c2fd5ca, 0x62675256, 0x01f2a2f3, 0xbc96ae0a, 0x709a8920, 0xb4146e87,
	0x6308b9e2, 0x64bda7ba, 0xafed6892, 0x6037f2a2, 0xf52969e0, 0x0adb43a6,
	0x82811400, 0x90d0bdf0, 0x19c9549e, 0x203f6a73, 0x1accaf4f, 0x89714e6d,
	0x164d4705, 0x67665f07, 0xec206170, 0x0c2182b2, 0xa02b9c81, 0x53289722,
	0xf6a97686, 0x140e4179, 0x9f778849, 0x9a88e15d, 0x25cadb54, 0xd157f36f,
	0x32a421c3, 0xb368e98a, 0x5a92cd0d, 0x757aa8d4, 0xc20ac278, 0x08b551c7,
	0x849491e8, 0x4dc75ad6, 0x697c33be, 0xbaf0ca33, 0x46125b4e, 0x59d677b3,
	0x30d9c8f2, 0xd0af860c, 0x1c7fd0fa, 0xfe0ff72c, 0x5c8d6f43, 0x57fdec3b,
	0x6ab6ad97, 0xd22adf89, 0x18171785, 0x02bfe22d, 0x6db80917, 0x80b216af,
	0xe85e4f9a, 0x7a1c306e, 0x6fc49bf5, 0x3af7a11c, 0x81e215e7, 0x68363fcd,
	0x3e9357c8, 0xef52fd55, 0x3b8bab4c, 0x3c8cf495, 0xbefceebd, 0xfd25b714,
	0xc498d83d, 0x0d2e1a8d, 0xe9f966ac, 0x0e387445, 0x435419e5, 0x5e7ebec4,
	0xaa90b8d9, 0xff1a3a96, 0x4a8fe4e3, 0xf27d99cd, 0xd04a40ca, 0xcb5ff194,
	0x3668275a, 0xff4816be, 0xa78b394c, 0x4c6be9db, 0x4eec38d2, 0x4296ec80,
	0xcdce96f8, 0x888c2f38, 0xe75508f5, 0x7b916414, 0x060aa14a, 0xa214f327,
	0xbe608daf, 0x1ebbdec2, 0x61f98ce9, 0xe92156fe, 0x4f22d7a3, 0x3f76a8d9,
	0x559a4b33, 0x38ad2959, 0xf3f17e9e, 0x85e1ba91, 0xe5eba6fb, 0x73dcd48c,
	0xf5c3ff78, 0x481b6058, 0x8a3297f7, 0x8f1f3bf4, 0x93785ab2, 0x477a4a5b,
	0x6334eb5d, 0x6d251b2e, 0x74a9102d, 0x07e38ffa, 0x915c9c62, 0xccc275ea,
	0x6be273ec, 0x3ebddd70, 0xd895796c, 0xdc54a91b, 0xc9afdf81, 0x23633f73,
	0x275119b4, 0xb19f6b67, 0x50756e22, 0x2bb152e2, 0x76ea46a2, 0xa353e232,
	0x2f596ad6, 0x0b1edb0b, 0x02d3d9a4, 0x78b47843, 0x64893e90, 0x40f0caad,
	0xf68d3ad7, 0x46fd1707, 0x1c9c67ef, 0xb5e086de, 0x96ee6ca6, 0x9aa34774,
	0x1ba4f48a, 0x8d01abfd, 0x183ee1f6, 0x5ff8aa7a, 0x17e4faae, 0x303983b0,
	0x6c08668b, 0xd4ac4382, 0xe6c5849f, 0x92fefb53, 0xc1cac4ce, 0x43501388,
	0x441118cf, 0xec4fb308, 0x53a08e86, 0x9e0fe0c5, 0xf91c1525, 0xac45be05,
	0xd7987cb5, 0x49ba1487, 0x57938940, 0xd5877648, 0xa958727f, 0x58dfe3c3,
	0xf436cf77, 0x399e4d11, 0xf0a5bfa9, 0xef61a33b, 0xa64cac60, 0x04a8d0ba,
	0x030dd572, 0xb83d320f, 0xcab23045, 0xe366f2f0, 0x815d008d, 0xc897a43a,
	0x1d352df3, 0xb9cc571d, 0x8bf38744, 0x72209092, 0xeba124eb, 0xfb99ce5e,
	0x3bb94293, 0x28da549c, 0xaab8a228, 0xa4197785, 0x33c70296, 0x25f6259b,
	0x5c85da21, 0xdf15bdee, 0x15b7c7e8, 0xe2abef75, 0xfcc19bc1, 0x417ff868,
	0x14884434, 0x62825179, 0xc6d5c11c, 0x0e4705dc, 0x22700de0, 0xd3d2af18,
	0x9be822a0, 0x35b669f1, 0xc42bb55c, 0x0a801252, 0x115bf0fc, 0x3cd7d856,
	0xb43f5f9d, 0xc2306516, 0xa1231c47, 0xf149207e, 0x5209a795, 0x34b3ccd8,
	0x67aefe54, 0x2c83924e, 0x6662cbac, 0x5eedd161, 0x84e681aa, 0x5d57d26b,
	0xfa465cc4, 0x7e3ac3a8, 0xbf7c0cc6, 0xe18a9aa1, 0xc32f0a6f, 0xb22cc00d,
	0x3d280369, 0x994e554f, 0x68f480d3, 0xadcff5e6, 0x3a8eb265, 0x83269831,
	0xbd568a09, 0x4bc8ae6a, 0x69f56d2b, 0x0f17eac8, 0x772eb6c7, 0x9f41343c,
	0xab1d0742, 0x826a6f50, 0xfea2097c, 0x1912c283, 0xce185899, 0xe4444839,
	0x2d8635d5, 0x65d0b1ff, 0x865a7f17, 0x326d9fb1, 0x59e52820, 0x0090ade1,
	0x753c7149, 0x9ddd8b98, 0xa5a691da, 0x0d0382bb, 0x8904c930, 0x086cb000,
	0x6e69d3bd, 0x24d4e7a7, 0x05244fd0, 0x101a5e0c, 0x6a947dcb, 0xe840f77b,
	0x7d0c5003, 0x7c370f1f, 0x805245ed, 0xe05e3d3f, 0x7906880e, 0xbabfcd35,
	0x1a7ec697, 0x8c052324, 0x0c6ec8df, 0xd129a589, 0xc7a75b02, 0x12d81de7,
	0xd9be2a66, 0x1f4263ab, 0xde73fdb6, 0x2a00680a, 0x56649e36, 0x3133ed55,
	0x90fa0bf2, 0x2910a02a, 0x949d9d46, 0xa0d1dcdd, 0xcfc9b7d4, 0xd2677be5,
	0x95cb36b3, 0x13cd9410, 0xdbf73313, 0xb7c6e8c0, 0xf781414b, 0x510b016d,
	0xb0de1157, 0xd6b0f62c, 0xbb074ecc, 0x7f1395b7, 0xee792cf9, 0xea6fd63e,
	0x5bd6938e, 0xaf02fc64, 0xdab57ab8, 0x8edb3784, 0x8716318f, 0x164d1a01,
	0x26f26141, 0xb372e6b9, 0xf8fc2b06, 0x7ac00e04, 0x3727b89a, 0x97e9bca5,
	0x9c2a742f, 0xbc3b1f7d, 0x7165b471, 0x609b4c29, 0x20925351, 0x5ae72112,
	0x454be5d1, 0xc0ffb95f, 0xdd0ef919, 0x6f2d70c9, 0x0974c5bf, 0x98aa6263,
	0x01d91e4d, 0x2184bb6e, 0x70c43c1e, 0x4d435915, 0xae7b8523, 0xb6fb06bc,
	0x5431ee76, 0xfdbc5d26, 0xed77493d, 0xc5712ee4, 0xa8380437, 0x2eef261a,
	0x5a79392b, 0xb8af32c2, 0x41f7720a, 0x833a61ec, 0x13dfedac, 0xc4990bc4,
	0xdc0f54bc, 0xfedd5e88, 0x80da1881, 0x4dea1afd, 0xfd402cc6, 0xae67cc7a,
	0xc5238525, 0x8ea01254, 0xb56b9bd5, 0x862fbd6d, 0xac8575d3, 0x6fba3714,
	0xda7ebf46, 0x59cd5238, 0x8ac9dbfe, 0x353729fc, 0xe497d7f2, 0xc3ab84e0,
	0xf05a114b, 0x7b887a75, 0xedc603dd, 0x5e6fe680, 0x2c84b399, 0x884eb1da,
	0x1cb8c8bf, 0xaa51098a, 0xc862231c, 0x8bac2221, 0x21b387e5, 0x208a430d,
	0x2a3f0f8b, 0xa5ff9cd2, 0x6012a2ea, 0x147a9ee7, 0xf62a501d, 0xb4b2e51a,
	0x3ef3484c, 0xc0253c59, 0x2b82b536, 0x0aa9696b, 0xbe0c109b, 0xc70b7929,
	0xce3e8a19, 0x2f66950e, 0x459f1c2c, 0xe68fb93d, 0xa3c3ff3e, 0x62b45c62,
	0x300991cb, 0x01914c57, 0x7f7bc06a, 0x182831f5, 0xe7b74bca, 0xfa50f6d0,
	0x523caa61, 0xe3a7cf05, 0xe9e41311, 0x280a21d1, 0x6a4297e1, 0xf24dc67e,
	0xfc3189e6, 0xb72bf34f, 0x4b1e67af, 0x543402ce, 0x79a59867, 0x0648e02a,
	0x00a3ac17, 0xc6208d35, 0x6e7f5f76, 0xa45bb4be, 0xf168fa63, 0x3f4125f3,
	0xf311406f, 0x02706565, 0xbfe58022, 0x0cfcfdd9, 0x0735a7f7, 0x8f049092,
	0xd98edc27, 0xf5c5d55c, 0xe0f201db, 0x0dcafc9a, 0x7727fb79, 0xaf43abf4,
	0x26e938c1, 0x401b26a6, 0x900720fa, 0x2752d97b, 0xcff1d1b3, 0xa9d9e424,
	0x42db99ab, 0x6cf8be5f, 0xe82cebe3, 0x3afb733b, 0x6b734eb6, 0x1036414a,
	0x975f667c, 0x049d6377, 0xba587c60, 0xb1d10483, 0xde1aefcc, 0x1129d055,
	0x72051e91, 0x6946d623, 0xf9e86ea7, 0x48768c00, 0xb0166c93, 0x9956bbf0,
	0x1f1f6d84, 0xfb15e18e, 0x033b495d, 0x56e3362e, 0x4f44c53c, 0x747cba51,
	0x89d37872, 0x5d9c331b, 0xd2ef9fa8, 0x254917f8, 0x1b106f47, 0x37d75553,
	0xb3f053b0, 0x7dccd8ef, 0xd30eb802, 0x5889f42d, 0x610206d7, 0x1a7d34a1,
	0x92d87dd8, 0xe5f4a315, 0xd1cf0e71, 0xb22dfe45, 0xb901e8eb, 0x0fc0ce5e,
	0x2efa60c9, 0x2de74290, 0x36d0c906, 0x381c70e4, 0x4c6da5b5, 0x3d81a682,
	0x7e381f34, 0x396c4f52, 0x95ad5901, 0x1db50c5a, 0x29982e9e, 0x1557689f,
	0x3471ee42, 0xd7e2f7c0, 0x8795a1e2, 0xbc324d8d, 0xe224c3c8, 0x12837e39,
	0xcdee3d74, 0x7ad2143f, 0x0e13d40c, 0x78bd4a68, 0xa2eb194d, 0xdb9451f9,
	0x859b71dc, 0x5c4f5b89, 0xca14a8a4, 0xef92f003, 0x16741d98, 0x33aa4444,
	0x9e967fbb, 0x092e3020, 0xd86a35b8, 0x8cc17b10, 0xe1bf08ae, 0x55693fc5,
	0x7680ad13, 0x1e6546e8, 0x23b6e7b9, 0xee77a4b2, 0x08ed0533, 0x44fd2895,
	0xb6393b69, 0x05d6cacf, 0x9819b209, 0xecbbb72f, 0x9a75779c, 0xeaec0749,
	0x94a65aee, 0xbdf52dc3, 0xd6a25d04, 0x82008e4e, 0xa6de160f, 0x9b036afb,
	0x228b3a66, 0x5fb10a70, 0xcc338b58, 0x5378a9df, 0xc908bca9, 0x4959e25b,
	0x46909a97, 0x66ae8f6e, 0xdd0683e9, 0x65f994b4, 0x6426cda5, 0xc24b8840,
	0x32539da0, 0x63175650, 0xd0c815ff, 0x50cbc41e, 0xf7c774a3, 0x31b0c231,
	0x8d0d8116, 0x24bef16c, 0xd555d256, 0xdf47ea8c, 0x6d21eccd, 0xa887a012,
	0x84542aed, 0xa7b9c1bd, 0x914c1bb1, 0xa0d5b67d, 0x438ce937, 0x7030f873,
	0x71f6b0c7, 0x574576ba, 0xf8bc4541, 0x9c61d348, 0x1960579d, 0x17c4daad,
	0x96a4cb0b, 0xc193f2f6, 0x756eafa2, 0x7c1d2f94, 0xf4fe2b43, 0xcb86e33a,
	0xebd4c728, 0x9d18ae64, 0x9fe13e30, 0x3ce0f5de, 0xaba1f985, 0xaddc2718,
	0x68ce6278, 0xd45e241f, 0xa15c82b7, 0x3b2293d4, 0x739edd32, 0x674a6bf1,
	0x5b5d587f, 0x4772deaa, 0x4a63968f, 0x0be68686, 0x513d6426, 0x939a4787,
	0xbba89296, 0x4ec20007, 0x818d0d08, 0xff64dfd6, 0xcb2297cb, 0xdb48a144,
	0xa16cbe4b, 0xbbea1d6c, 0x5af6b6b7, 0x8a8110b6, 0xf9236ef9, 0xc98f83e6,
	0x0f9c65b8, 0x252d4a89, 0xa497f068, 0xa5d7ed2d, 0x94c22845, 0x9da1c8c4,
	0xe27c2e2e, 0x6e8ba2b4, 0xc3dd17fb, 0x498cd482, 0x0dfe6a9f, 0xb0705829,
	0x9a1e6dc1, 0xf829717c, 0x07bb8e3a, 0xda3c0b02, 0x1af82fc7, 0x73b70955,
	0x7a04379c, 0x5ee20a28, 0x83712ae5, 0xf4c47c6d, 0xdf72ba56, 0xd794858d,
	0x8c0cf709, 0x18f0f390, 0xb6c69b35, 0xbf2f01db, 0x2fa74dca, 0xd0cd9127,
	0xbde66cec, 0x3deebd46, 0x57c88fc3, 0xcee1406f, 0x0066385a, 0xf3c3444f,
	0x3a79d5d5, 0x75751eb9, 0x3e7f8185, 0x521c2605, 0xe1aaab6e, 0x38ebb80f,
	0xbee7e904, 0x61cb9647, 0xea54904e, 0x05ae00e4, 0x2d7ac65f, 0x087751a1,
	0xdcd82915, 0x0921ee16, 0xdd86d33b, 0xd6bd491a, 0x40fbadf0, 0x4232cbd2,
	0x33808d10, 0x39098c42, 0x193f3199, 0x0bc1e47a, 0x4a82b149, 0x02b65a8a,
	0x104cdc8e, 0x24a8f52c, 0x685c6077, 0xc79f95c9, 0x1d11fe50, 0xc08dafcd,
	0x7b1a9a03, 0x1c1f11d8, 0x84250e7f, 0x979db248, 0xebdc0501, 0xb9553395,
	0xe3c05ea8, 0xb1e51c4c, 0x13b0e681, 0x3b407766, 0x36db3087, 0xee17c9fc,
	0x6c53ecf2, 0xadccc58f, 0xc427660b, 0xefd5867d, 0x9b6d54a5, 0x6ff1aeff,
	0x8e787952, 0x9e2bffe0, 0x8761d034, 0xe00bdbad, 0xae99a8d3, 0xcc03f6e2,
	0xfd0ed807, 0x0e508ae3, 0xb74182ab, 0x4349245d, 0xd120a465, 0xb246a641,
	0xaf3b7ab0, 0x2a6488bb, 0x4b3a0d1f, 0xe7c7e58c, 0x3faff2eb, 0x90445ffd,
	0xcf38c393, 0x995d07e7, 0xf24f1b36, 0x356f6891, 0x6d6ebcbe, 0x8da9e262,
	0x50fd520e, 0x5bca9e1e, 0x37472cf3, 0x69075057, 0x7ec5fded, 0x0cab892a,
	0xfb2412ba, 0x1728debf, 0xa000a988, 0xd843ce79, 0x042e20dd, 0x4fe8f853,
	0x56659c3c, 0x2739d119, 0xa78a6120, 0x80960375, 0x70420611, 0x85e09f78,
	0xabd17e96, 0x1b513eaf, 0x1e01eb63, 0x26ad2133, 0xa890c094, 0x7613cf60,
	0x817e781b, 0xa39113d7, 0xe957fa58, 0x4131b99e, 0x28b1efda, 0x66acfba7,
	0xff68944a, 0x77a44fd1, 0x7f331522, 0x59ffb3fa, 0xa6df935b, 0xfa12d9df,
	0xc6bf6f3f, 0x89520cf6, 0x659edd6a, 0x544da739, 0x8b052538, 0x7c30ea21,
	0xc2345525, 0x15927fb2, 0x144a436b, 0xba107b8b, 0x1219ac97, 0x06730432,
	0x31831ab3, 0xc55a5c24, 0xaa0fcd3e, 0xe5606be8, 0x5c88f19b, 0x4c0841ee,
	0x1fe37267, 0x11f9c4f4, 0x9f1b9dae, 0x864e76d0, 0xe637c731, 0xd97d23a6,
	0x32f53d5c, 0xb8161980, 0x93fa0f84, 0xcaef0870, 0x8874487e, 0x98f2cc73,
	0x645fb5c6, 0xcd853659, 0x2062470d, 0x16ede8e9, 0x6b06dab5, 0x78b43900,
	0xfc95b786, 0x5d8e7de1, 0x465b5954, 0xfe7ba014, 0xf7d23f7b, 0x92bc8b18,
	0x03593592, 0x55cef4f7, 0x74b27317, 0x79de1fc2, 0xc8a0bfbd, 0x229398cc,
	0x62a602ce, 0xbcb94661, 0x5336d206, 0xd2a375fe, 0x6a6ab483, 0x4702a5a4,
	0xa2e9d73d, 0x23a2e0f1, 0x9189140a, 0x581d18dc, 0xb39a922b, 0x82356212,
	0xd5f432a9, 0xd356c2a3, 0x5f765b4d, 0x450afcc8, 0x4415e137, 0xe8ecdfbc,
	0xed0de3ea, 0x60d42b13, 0xf13df971, 0x71fc5da2, 0xc1455340, 0xf087742f,
	0xf55e5751, 0x67b3c1f8, 0xac6b8774, 0x7dcfaaac, 0x95983bc0, 0x489bb0b1,
	0x2c184223, 0x964b6726, 0x2bd3271c, 0x72266472, 0xded64530, 0x0a2aa343,
	0xd4f716a0, 0xb4dad6d9, 0x2184345e, 0x512c990c, 0x29d92d08, 0x2ebe709a,
	0x01144c69, 0x34584b9d, 0xe4634ed6, 0xecc963cf, 0x3c6984aa, 0x4ed056ef,
	0x9ca56976, 0x8f3e80d4, 0xb5bae7c5, 0x30b5caf5, 0x63f33a64, 0xa9e4bbde,
	0xf6b82298, 0x4d673c1d, 0x4b4f1121, 0xba183081, 0xc784f41f, 0xd17d0bac,
	0x083d2267, 0x37b1361e, 0x3581ad05, 0xfda2f6bc, 0x1e892cdd, 0xb56d3c3a,
	0x32140e46, 0x138d8aab, 0xe14773d4, 0x5b0e71df, 0x5d1fe055, 0x3fb991d3,
	0xf1f46c71, 0xa325988c, 0x10f66e80, 0xb1006348, 0x726a9f60, 0x3b67f8ba,
	0x4e114ef4, 0x05c52115, 0x4c5ca11c, 0x99e1efd8, 0x471b83b3, 0xcbf7e524,
	0x43ad82f5, 0x690ca93b, 0xfaa61bb2, 0x12a832b5, 0xb734f943, 0xbd22aea7,
	0x88fec626, 0x5e80c3e7, 0xbe3eaf5e, 0x44617652, 0xa5724475, 0xbb3b9695,
	0x7f3fee8f, 0x964e7deb, 0x518c052d, 0x2a0bbc2b, 0xc2175f5c, 0x9a7b3889,
	0xa70d8d0c, 0xeaccdd29, 0xcccd6658, 0x34bb25e6, 0xb8391090, 0xf651356f,
	0x52987c9e, 0x0c16c1cd, 0x8e372d3c, 0x2fc6ebbd, 0x6e5da3e3, 0xb0e27239,
	0x5f685738, 0x45411786, 0x067f65f8, 0x61778b40, 0x81ab2e65, 0x14c8f0f9,
	0xa6b7b4ce, 0x4036eaec, 0xbf62b00a, 0xecfd5e02, 0x045449a6, 0xb20afd28,
	0x2166d273, 0x0d13a863, 0x89508756, 0xd51a7530, 0x2d653f7a, 0x3cdbdbc3,
	0x80c9df4f, 0x3d5812d9, 0x53fbb1f3, 0xc0f185c0, 0x7a3c3d7e, 0x68646410,
	0x857607a0, 0x1d12622e, 0x97f33466, 0xdb4c9917, 0x6469607c, 0x566e043d,
	0x79ef1edb, 0x2c05898d, 0xc9578e25, 0xcd380101, 0x46e04377, 0x7d1cc7a9,
	0x6552b837, 0x20192608, 0xb97500c5, 0xed296b44, 0x368648b4, 0x62995cd5,
	0x82731400, 0xf9aebd8b, 0x3844c0c7, 0x7c2de794, 0x33a1a770, 0x8ae528c2,
	0x5a2be812, 0x1f8f4a07, 0x2b5ed7ca, 0x937eb564, 0x6fda7e11, 0xe49b5d6c,
	0xb4b3244e, 0x18aa53a4, 0x3a061334, 0x4d6067a3, 0x83ba5868, 0x9bdf4dfe,
	0x7449f261, 0x709f8450, 0xcad133cb, 0xde941c3f, 0xf52ae484, 0x781d77ed,
	0x7e4395f0, 0xae103b59, 0x922331bb, 0x42ce50c8, 0xe6f08153, 0xe7d941d0,
	0x5028ed6b, 0xb3d2c49b, 0xad4d9c3e, 0xd201fb6e, 0xa45bd5be, 0xffcb7f4b,
	0x579d7806, 0xf821bb5b, 0x59d592ad, 0xd0be0c31, 0xd4e3b676, 0x0107165a,
	0x0fe939d2, 0x49bcaafd, 0x55ffcfe5, 0x2ec1f783, 0xf39a09a5, 0x3eb42772,
	0x19b55a5d, 0x024a0679, 0x8c83b3f7, 0x8642ba1d, 0xacacd9ea, 0x87d352c4,
	0x60931f45, 0xa05f97d7, 0x1cecd42c, 0xe2fcc87b, 0xb60f94e2, 0x67a34b0b,
	0xfcdd40c9, 0x0b150a27, 0xd3ee9e04, 0x582e29e9, 0x4ac22b41, 0x6ac4e1b8,
	0xbccaa51a, 0x237af30e, 0xebc3b709, 0xc4a59d19, 0x284bc98a, 0xe9d41a93,
	0x6bfa2018, 0x73b2d651, 0x11f9a2fa, 0xce09bff1, 0x41a470aa, 0x25888f22,
	0x77e754e8, 0xf7330d8e, 0x158eab16, 0xc5d68842, 0xc685a6f6, 0xe5b82fde,
	0x09ea3a96, 0x6dde1536, 0x4fa919da, 0x26c0be9f, 0x9eed6f69, 0xf05555f2,
	0xe06fc285, 0x9cd76d23, 0xaf452a92, 0xefc74cb7, 0x9d6b4732, 0x8be408ee,
	0x22401d0d, 0xee6c459d, 0x7587cb82, 0xe8746862, 0x5cbdde87, 0x98794278,
	0x31afb94d, 0xc11e0f2f, 0x30e8fc2a, 0xcf3261ef, 0x1a3023e1, 0xaa2f86cf,
	0xf202e24a, 0x8d08dcff, 0x764837c6, 0xa26374cc, 0x9f7c3e88, 0x949cc57d,
	0xdd26a07f, 0xc39efab0, 0xc8f879a1, 0xdce67bb9, 0xf4b0a435, 0x912c9ae0,
	0xd85603e4, 0x953a9bbf, 0xfb8290d6, 0x0aebcd5f, 0x16206a9a, 0x6c787a14,
	0xd9a0f16a, 0x29bf4f74, 0x8f8bce91, 0x0e5a9354, 0xab038cb1, 0x1b8ad11b,
	0xe327ff49, 0x0053da20, 0x90cf51dc, 0xda92fe6d, 0x0390ca47, 0xa8958097,
	0xa9dc5baf, 0x3931e3c1, 0x840446b6, 0x63d069fb, 0xd7460299, 0x7124ecd1,
	0x0791e613, 0x485918fc, 0xd635d04c, 0xdf96ac33, 0x66f2d303, 0x247056ae,
	0xa1a7b2a8, 0x27d8cc9c, 0x17b6e998, 0x7bf5590f, 0xfe97f557, 0x5471d8a2,
	0x83a327a1, 0x9f379f51, 0x40a7d007, 0x11307423, 0x224587c1, 0xac27d63b,
	0x3b7e64ea, 0x2e1cbfa6, 0x09996000, 0x03bc0e2c, 0xd4c4478a, 0x4542e0ab,
	0xfeda26d4, 0xc1d10fcb, 0x8252f596, 0x4494eb5c, 0xa362f314, 0xf5ba81fd,
	0x75c3a376, 0x4ca214ca, 0xe164dedd, 0x5088fa97, 0x4b0930e0, 0x2fcfb7e8,
	0x33a6f4b2, 0xc7e94211, 0x2d66c774, 0x43be8bae, 0xc663d445, 0x908eb130,
	0xf4e3be15, 0x63b9d566, 0x529396b5, 0x1e1be743, 0x4d5ff63f, 0x985e4a83,
	0x71ab9df7, 0xc516c6f5, 0x85c19ab4, 0x1f4daee4, 0xf2973431, 0xb713dc5e,
	0x3f2e159a, 0xc824da16, 0x06bf376a, 0xb2fe23ec, 0xe39b1c22, 0xf1eecb5f,
	0x08e82d52, 0x565686c2, 0xab0aea93, 0xfd47219f, 0xebdbabd7, 0x2404a185,
	0x8c7312b9, 0xa8f2d828, 0x0c8902da, 0x65b42b63, 0xc0bbef62, 0x4e3e4cef,
	0x788f8018, 0xee1ebab7, 0x93928f9d, 0x683d2903, 0xd3b60689, 0xafcb0ddc,
	0x88a4c47a, 0xf6dd9c3d, 0x7ea5fca0, 0x8a6d7244, 0xbe11f120, 0x04ff91b8,
	0x8d2dc8c0, 0x27f97fdb, 0x7f9e1f47, 0x1734f0c7, 0x26f3ed8e, 0x0df8f2bf,
	0xb0833d9e, 0xe420a4e5, 0xa423cae6, 0x95616772, 0x9ae6c049, 0x075941f2,
	0xd8e12812, 0x000f6f4f, 0x3c0d6b05, 0x6cef921c, 0xb82bc264, 0x396cb008,
	0x5d608a6f, 0x6d7782c8, 0x186550aa, 0x6b6fec09, 0x28e70b13, 0x57ce5688,
	0xecd3af84, 0x23335a95, 0x91f40cd2, 0x7b6a3b26, 0xbd32b3b6, 0x3754a6fb,
	0x8ed088f0, 0xf867e87c, 0x20851746, 0x6410f9c6, 0x35380442, 0xc2ca10a7,
	0x1adea27f, 0x76bddd79, 0x92742cf4, 0x0e98f7ee, 0x164e931d, 0xb9c835b3,
	0x69060a99, 0xb44c531e, 0xfa7b66fe, 0xc98a5b53, 0x7d95aae9, 0x302f467b,
	0x74b811de, 0xf3866abd, 0xb5b3d32d, 0xfc3157a4, 0xd251fe19, 0x0b5d8eac,
	0xda71ffd5, 0x47ea05a3, 0x05c6a9e1, 0xca0ee958, 0x9939034d, 0x25dc5edf,
	0x79083cb1, 0x86768450, 0xcf757d6d, 0x5972b6bc, 0xa78d59c9, 0xc4ad8d41,
	0x2a362ad3, 0xd1179991, 0x601407ff, 0xdcf50917, 0x587069d0, 0xe0821ed6,
	0xdbb59427, 0x73911a4b, 0x7c904fc3, 0x844afb92, 0x6f8c955d, 0xe8c0c5bb,
	0xb67ab987, 0xa529d96c, 0xf91f7181, 0x618b1b06, 0xe718bb0c, 0x8bd7615b,
	0xd5a93a59, 0x54aef81b, 0x772136e3, 0xce44fd9c, 0x10cda57e, 0x87d66e0b,
	0x3d798967, 0x1b2c1804, 0x3edfbd68, 0x15f6e62b, 0xef68b854, 0x3896db35,
	0x12b7b5e2, 0xcb489029, 0x9e4f98a5, 0x62eb77a8, 0x217c24a2, 0x964152f6,
	0x49b2080a, 0x53d23ee7, 0x48fb6d69, 0x1903d190, 0x9449e494, 0xbf6e7886,
	0xfb356cfa, 0x3a261365, 0x424bc1eb, 0xa1192570, 0x019ca782, 0x9d3f7e0e,
	0x9c127575, 0xedf02039, 0xad57bcce, 0x5c153277, 0x81a84540, 0xbcaa7356,
	0xccd59b60, 0xa62a629b, 0xa25ccd10, 0x2b5b65cf, 0x1c535832, 0x55fd4e3a,
	0x31d9790d, 0xf06bc37d, 0x4afc1d71, 0xaeed5533, 0xba461634, 0xbb694b78,
	0x5f3a5c73, 0x6a3c764a, 0x8fb0cca9, 0xf725684c, 0x4fe5382f, 0x1d0163af,
	0x5aa07a8f, 0xe205a8ed, 0xc30bad38, 0xff22cf1f, 0x72432e2e, 0x32c2518b,
	0x3487ce4e, 0x7ae0ac02, 0x709fa098, 0x0a3b395a, 0x5b4043f8, 0xa9e48c36,
	0x149a8521, 0xd07dee6b, 0x46acd2f3, 0x8958dffc, 0xb3a1223c, 0xb11d31c4,
	0xcd7f4d3e, 0x0f28e3ad, 0xe5b100be, 0xaac54824, 0xe9c9d7ba, 0x9bd47001,
	0x80f149b0, 0x66022f0f, 0x020c4048, 0x6efa192a, 0x67073f8d, 0x13ec7bf9,
	0x3655011a, 0xe6afe157, 0xd9845f6e, 0xdecc4425, 0x511ae2cc, 0xdf81b4d8,
	0xd7809e55, 0xd6d883d9, 0x2cc7978c, 0x5e787cc5, 0xdd0033d1, 0xa050c937,
	0x97f75dcd, 0x299de580, 0x41e2b261, 0xea5a54f1, 0x7e672590, 0xbea513bb,
	0x2c906fe6, 0x86029c2b, 0x55dc4f74, 0x0553398e, 0x63e09647, 0xcafd0bab,
	0x264c37df, 0x8272210f, 0x67afa669, 0x12d98a5f, 0x8cab23c4, 0x75c68bd1,
	0xc3370470, 0x33f37f4e, 0x283992ff, 0xe73a3a67, 0x1032f283, 0xf5ad9fc2,
	0x963f0c5d, 0x664fbc45, 0x202ba41c, 0xc7c02d80, 0x54731e84, 0x8a1085f5,
	0x601d80fb, 0x2f968e55, 0x35e96812, 0xe45a8f78, 0xbd7de662, 0x3b6e6ead,
	0x8097c5ef, 0x070b6781, 0xb1e508f3, 0x24e4fae3, 0xb81a7805, 0xec0fc918,
	0x43c8774b, 0x9b2512a9, 0x2b05ad04, 0x32c2536f, 0xedf236e0, 0x8bc4b0cf,
	0xbaceb837, 0x4535b289, 0x0d0e94c3, 0xa5a371d0, 0xad695a58, 0x39e3437d,
	0x9186bffc, 0x21038c3b, 0x0aa9dff9, 0x5d1f06ce, 0x62def8a4, 0xf740a2b4,
	0xa2575868, 0x682683c1, 0xdbb30fac, 0x61fe1928, 0x468a6511, 0xc61cd5f4,
	0xe54d9800, 0x6b98d7f7, 0x8418b6a5, 0x5f09a5d2, 0x90b4e80b, 0x49b2c852,
	0x69f11c77, 0x17412b7e, 0x7f6fc0ed, 0x56838dcc, 0x6e9546a2, 0xd0758619,
	0x087b9b9a, 0xd231a01d, 0xaf46d415, 0x097060fd, 0xd920f657, 0x882d3f9f,
	0x3ae7c3c9, 0xe8a00d9b, 0x4fe67ebe, 0x2ef80eb2, 0xc1916b0c, 0xf4dffea0,
	0xb97eb3eb, 0xfdff84dd, 0xff8b14f1, 0xe96b0572, 0xf64b508c, 0xae220a6e,
	0x4423ae5a, 0xc2bece5e, 0xde27567c, 0xfc935c63, 0x47075573, 0xe65b27f0,
	0xe121fd22, 0xf2668753, 0x2debf5d7, 0x8347e08d, 0xac5eda03, 0x2a7cebe9,
	0x3fe8d92e, 0x23542fe4, 0x1fa7bd50, 0xcf9b4102, 0x9d0dba39, 0x9cb8902a,
	0xa7249d8b, 0x0f6d667a, 0x5ebfa9ec, 0x6a594df2, 0x79600938, 0x023b7591,
	0xea2c79c8, 0xc99d07ea, 0x64cb5ee1, 0x1a9cab3d, 0x76db9527, 0xc08e012f,
	0x3dfb481a, 0x872f22e7, 0x2948d15c, 0xa4782c79, 0x6f50d232, 0x78f0728a,
	0x5a87aab1, 0xc4e2c19c, 0xee767387, 0x1b2a1864, 0x7b8d10d3, 0xd1713161,
	0x0eeac456, 0xd8799e06, 0xb645b548, 0x4043cb65, 0xa874fb29, 0x4b12d030,
	0x7d687413, 0x18ef9a1f, 0xd7631d4c, 0x5829c7da, 0xcdfa30fa, 0xc5084bb0,
	0x92cd20e2, 0xd4c16940, 0x03283ec0, 0xa917813f, 0x9a587d01, 0x70041f8f,
	0xdc6ab1dc, 0xddaee3d5, 0x31829742, 0x198c022d, 0x1c9eafcb, 0x5bbc6c49,
	0xd3d3293a, 0x16d50007, 0x04bb8820, 0x3c5c2a41, 0x37ee7af8, 0x8eb04025,
	0x9313ecba, 0xbffc4799, 0x8955a744, 0xef85d633, 0x504499a7, 0xa6ca6a86,
	0xbb3d3297, 0xb34a8236, 0x6dccbe4f, 0x06143394, 0xce19fc7b, 0xccc3c6c6,
	0xe36254ae, 0x77b7eda1, 0xa133dd9e, 0xebf9356a, 0x513ccf88, 0xe2a1b417,
	0x972ee5bd, 0x853824cd, 0x5752f4ee, 0x6c1142e8, 0x3ea4f309, 0xb2b5934a,
	0xdfd628aa, 0x59acea3e, 0xa01eb92c, 0x389964bc, 0xda305dd4, 0x019a59b7,
	0x11d2ca93, 0xfaa6d3b9, 0x4e772eca, 0x72651776, 0xfb4e5b0e, 0xa38f91a8,
	0x1d0663b5, 0x30f4f192, 0xb50051b6, 0xb716ccb3, 0x4abd1b59, 0x146c5f26,
	0xf134e2de, 0x00f67c6c, 0xb0e1b795, 0x98aa4ec7, 0x0cc73b34, 0x654276a3,
	0x8d1ba871, 0x740a5216, 0xe0d01a23, 0x9ed161d6, 0x9f36a324, 0x993ebb7f,
	0xfeb9491b, 0x365ddcdb, 0x810cffc5, 0x71ec0382, 0x2249e7bf, 0x48817046,
	0xf3a24a5b, 0x4288e4d9, 0x0bf5c243, 0x257fe151, 0x95b64c0d, 0x4164f066,
	0xaaf7db08, 0x73b1119d, 0x8f9f7bb8, 0xd6844596, 0xf07a34a6, 0x53943d0a,
	0xf9dd166d, 0x7a8957af, 0xf8ba3ce5, 0x27c9621e, 0x5cdae910, 0xc8518998,
	0x941538fe, 0x136115d8, 0xaba8443c, 0x4d01f931, 0x34edf760, 0xb45f266b,
	0xd5d4de14, 0x52d8ac35, 0x15cfd885, 0xcbc5cd21, 0x4cd76d4d, 0x7c80ef54,
	0xbc92ee75, 0x1e56a1f6, 0xbaa20b6c, 0x9ffbad26, 0xe1f7d738, 0x794aec8d,
	0xc9e9cf3c, 0x8a9a7846, 0xc57c4685, 0xb9a92fed, 0x29cb141f, 0x52f9ddb7,
	0xf68ba6bc, 0x19ccc020, 0x4f584aaa, 0x3bf6a596, 0x003b7cf7, 0x54f0ce9a,
	0xa7ec4303, 0x46cf0077, 0x78d33aa1, 0x215247d9, 0x74bcdf91, 0x08381d30,
	0xdac43e40, 0x64872531, 0x0beffe5f, 0xb317f457, 0xaebb12da, 0xd5d0d67b,
	0x7d75c6b4, 0x42a6d241, 0x1502d0a9, 0x3fd97fff, 0xc6c3ed28, 0x81868d0a,
	0x92628bc5, 0x86679544, 0xfd1867af, 0x5ca3ea61, 0x568d5578, 0x4a2d71f4,
	0x43c9d549, 0x8d95de2b, 0x6e5c74a0, 0x9120ffc7, 0x0d05d14a, 0xa93049d3,
	0xbfa80e17, 0xf4096810, 0x043f5ef5, 0xa673b4f1, 0x6d780298, 0xa4847783,
	0x5ee726fb, 0x9934c281, 0x220a588c, 0x384e240f, 0x933d5c69, 0x39e5ef47,
	0x26e8b8f3, 0x4c1c6212, 0x8040f75d, 0x074b7093, 0x6625a8d7, 0x36298945,
	0x76285088, 0x651d37c3, 0x24f5274d, 0xdbca3dab, 0x186b7ee1, 0xd80f8182,
	0x14210c89, 0x943a3075, 0x4e6e11c4, 0x4d7e6bad, 0xf05064c8, 0x025dcd97,
	0x4bc10302, 0x7cede572, 0x8f90a970, 0xab88eeba, 0xb5998029, 0x5124d839,
	0xb0eeb6a3, 0x89ddabdc, 0xe8074d76, 0xa1465223, 0x32518cf2, 0x9d39d4eb,
	0xc0d84524, 0xe35e6ea8, 0x7abf3804, 0x113e2348, 0x9ae6069d, 0xb4dfdabb,
	0xa8c5313f, 0x23ea3f79, 0x530e36a2, 0xa5fd228b, 0x95d1d350, 0x2b14cc09,
	0x40042956, 0x879d05cc, 0x2064b9ca, 0xacaca40e, 0xb29c846e, 0x9676c9e3,
	0x752b7b8a, 0x7be2bcc2, 0x6bd58f5e, 0xd48f4c32, 0x606835e4, 0x9cd7c364,
	0x2c269b7a, 0x3a0d079c, 0x73b683fe, 0x45374f1e, 0x10afa242, 0x577f8666,
	0xddaa10f6, 0xf34f561c, 0x3d355d6b, 0xe47048ae, 0xaa13c492, 0x050344fd,
	0x2aab5151, 0xf5b26ae5, 0xed919a59, 0x5ac67900, 0xf1cde380, 0x0c79a11b,
	0x351533fc, 0xcd4d8e36, 0x1f856005, 0x690b9fdd, 0xe736dccf, 0x1d47bf6a,
	0x7f66c72a, 0x85f21b7f, 0x983cbdb6, 0x01ebbebf, 0x035f3b99, 0xeb111f34,
	0x28cefdc6, 0x5bfc9ecd, 0xf22eacb0, 0x9e41cbb2, 0xe0f8327c, 0x82e3e26f,
	0xfc43fc86, 0xd0ba66df, 0x489ef2a7, 0xd9e0c81d, 0x68690d52, 0xcc451367,
	0xc2232e16, 0xe95a7335, 0x0fdae19b, 0xff5b962c, 0x97596527, 0xc46db333,
	0x3ed4c562, 0xc14c9d9e, 0x5d6faa21, 0x638e940d, 0xf9316d58, 0x47b3b0ea,
	0x30ffcad2, 0xce1bba7d, 0x1e6108e6, 0x2e1ea33d, 0x507bf05b, 0xfafef94b,
	0xd17de8e2, 0x5598b214, 0x1663f813, 0x17d25a2d, 0xeefa5ff9, 0x582f4e37,
	0x12128773, 0xfef17ab8, 0x06005322, 0xbb32bbc9, 0x8c898508, 0x592c15f0,
	0xd38a4054, 0x4957b7d6, 0xd2b891db, 0x37bd2d3e, 0x34ad20cb, 0x622288e9,
	0x2dc7345a, 0xafb416c0, 0x1cf459b1, 0xdc7739fa, 0x0a711a25, 0x13e18a0c,
	0x5f72af4c, 0x6ac8db11, 0xbe53c18e, 0x1aa569b9, 0xef551ea4, 0xa02a429f,
	0xbd16e790, 0x7eb9171a, 0x77d693d8, 0x8e06993a, 0x9bde7560, 0xe5801987,
	0xc37a09be, 0xb8db76ac, 0xe2087294, 0x6c81616d, 0xb7f30fe7, 0xbc9b82bd,
	0xfba4e4d4, 0xc7b1012f, 0xa20c043b, 0xde9febd0, 0x2f9297ce, 0xe610aef8,
	0x70b06f19, 0xc86ae00b, 0x0e01988f, 0x41192ae0, 0x448c1cb5, 0xadbe92ee,
	0x7293a007, 0x1b54b5b3, 0xd61f63d1, 0xeae40a74, 0x61a72b55, 0xec83a7d5,
	0x88942806, 0x90a07da5, 0xd7424b95, 0x67745b4e, 0xa31a1853, 0xca6021ef,
	0xdfb56c4f, 0xcbc2d915, 0x3c48e918, 0x8bae3c63, 0x6f659c71, 0xf8b754c1,
	0x2782f3de, 0xf796f168, 0x71492c84, 0x33c0f5a6, 0x3144f6ec, 0x25dc412e,
	0xb16c5743, 0x83a1fa7e, 0x0997b101, 0xb627e6e8, 0xcf33905c, 0x8456fb65,
	0xb29bea74, 0xc35da605, 0x305c1ca3, 0xd2e9f5bc, 0x6fd5bff4, 0xff347703,
	0xfc45b163, 0xf498e068, 0xb71229fc, 0x81acc3fb, 0x78538a8b, 0x984ecf81,
	0xa5da47a4, 0x8f259eef, 0x6475dc65, 0x081865b9, 0x49e14a3c, 0x19e66079,
	0xd382e91b, 0x5b109794, 0x3f9f81e1, 0x4470a388, 0x41601abe, 0xaaf9f407,
	0x8e175ef6, 0xed842297, 0x893a4271, 0x1790839a, 0xd566a99e, 0x6b417dee,
	0x75c90d23, 0x715edb31, 0x723553f7, 0x9afb50c9, 0xfbc5f600, 0xcd3b6a4e,
	0x97ed0fba, 0x29689aec, 0x63135c8e, 0xf0e26c7e, 0x0692ae7f, 0xdbb208ff,
	0x2ede3e9b, 0x6a65bebd, 0xd40867e9, 0xc954afc5, 0x73b08201, 0x7ffdf809,
	0x1195c24f, 0x1ca5adca, 0x74bd6d1f, 0xb393c455, 0xcadfd3fa, 0x99f13011,
	0x0ebca813, 0x60e791b8, 0x6597ac7a, 0x18a7e46b, 0x09cb49d3, 0x0b27df6d,
	0xcfe52f87, 0xcef66837, 0xe6328035, 0xfa87c592, 0x37baff93, 0xd71fcc99,
	0xdcab205c, 0x4d7a5638, 0x48012510, 0x62797558, 0xb6cf1fe5, 0xbc311834,
	0x9c2373ac, 0x14ec6175, 0xa439cbdf, 0x54afb0ea, 0xd686960b, 0xfdd0d47b,
	0x7b063902, 0x8b78bac3, 0x26c6a4d5, 0x5c0055b6, 0x2376102e, 0x0411783e,
	0x2aa3f1cd, 0x51fc6ea8, 0x701ce243, 0x9b2a0abb, 0x0ad93733, 0x6e80d03d,
	0xaf6295d1, 0xf629896f, 0xa30b0648, 0x463d8dd4, 0x963f84cb, 0x01ff94f8,
	0x8d7fefdc, 0x553611c0, 0xa97c1719, 0xb96af759, 0xe0e3c95e, 0x0528335b,
	0x21fe5925, 0x821a5245, 0x807238b1, 0x67f23db5, 0xea6b4eab, 0x0da6f985,
	0xab1bc85a, 0xef8c90e4, 0x4526230e, 0x38eb8b1c, 0x1b91cd91, 0x9fce5f0c,
	0xf72cc72b, 0xc64f2617, 0xdaf7857d, 0x7d373cf1, 0x28eaedd7, 0x203887d0,
	0xc49a155f, 0xa251b3b0, 0xf2d47ae3, 0x3d9ef267, 0x4a94ab2f, 0x7755a222,
	0x0205e329, 0xc28fa7a7, 0xaec1fe51, 0x270f164c, 0x8c6d01bf, 0x53b5bc98,
	0xc09d3feb, 0x834986cc, 0x4309a12c, 0x578b2a96, 0x3bb74b86, 0x69561b4a,
	0x037e32f3, 0xde335b08, 0xc5156be0, 0xe7ef09ad, 0x93b834c7, 0xa7719352,
	0x59302821, 0xe3529d26, 0xf961da76, 0xcb142c44, 0xa0f3b98d, 0x76502457,
	0x945a414b, 0x078eeb12, 0xdff8de69, 0xeb6c8c2d, 0xbda90c4d, 0xe9c44d16,
	0x168dfd66, 0xad64763b, 0xa65fd764, 0x95a29c06, 0x32d7713f, 0x40f0b277,
	0x224af08f, 0x004cb5e8, 0x92574814, 0x8877d827, 0x3e5b2d04, 0x68c2d5f2,
	0x86966273, 0x1d433ada, 0x8774988a, 0x3c0e0bfe, 0xddad581d, 0x2fd654ed,
	0x0f4769fd, 0xc181ee9d, 0x5fd88f61, 0x341dbb3a, 0x528543f9, 0xd92235cf,
	0x1ea82eb4, 0xb5cd790f, 0x91d24f1e, 0xa869e6c2, 0x61f474d2, 0xcc205add,
	0x0c7bfba9, 0xbf2b0489, 0xb02d72d8, 0x2b46ece6, 0xe4dcd90a, 0xb8a11440,
	0xee8a63b7, 0x854dd1a1, 0xd1e00583, 0x42b40e24, 0x9e8964de, 0xb4b35d78,
	0xbec76f6e, 0x24b9c620, 0xd8d399a6, 0x5adb2190, 0x2db12730, 0x3a5866af,
	0x58c8fadb, 0x5d8844e7, 0x8a4bf380, 0x15a01d70, 0x79f5c028, 0x66be3b8c,
	0xf3e42b53, 0x56990039, 0x2c0c3182, 0x5e16407c, 0xecc04515, 0x6c440284,
	0x4cb6701a, 0x13bfc142, 0x9d039f6a, 0x4f6e92c8, 0xa1407c62, 0x8483a095,
	0xc70ae1c4, 0xe20213a2, 0xbacafc41, 0x4ecc12b3, 0x4bee3646, 0x1fe807ae,
	0x25217f9c, 0x35dde5f5, 0x7a7dd6ce, 0xf89cce50, 0xac07b718, 0x7e73d2c6,
	0xe563e76c, 0x123ca536, 0x3948ca56, 0x9019dd49, 0x10aa88d9, 0xc82451e2,
	0x473eb6d6, 0x506fe854, 0xe8bb03a5, 0x332f4c32, 0xfe1e1e72, 0xb1ae572a,
	0x7c0d7bc1, 0xe1c37eb2, 0xf542aa60, 0xf1a48ea0, 0xd067b89f, 0xbbfa195d,
	0x1a049b0d, 0x315946aa, 0x36d1b447, 0x6d2ebdf0, 0x0d188a6d, 0x12cea0db,
	0x7e63740e, 0x6a444821, 0x253d234f, 0x6ffc6597, 0x94a6bdef, 0x33ee1b2f,
	0x0a6c00c0, 0x3aa336b1, 0x5af55d17, 0x265fb3dc, 0x0e89cf4d, 0x0786b008,
	0xc80055b8, 0x6b17c3ce, 0x72b05a74, 0xd21a8d78, 0xa6b70840, 0xfe8eae77,
	0xed69565c, 0x55e1bcf4, 0x585c2f60, 0xe06f1a62, 0xad67c0cd, 0x7712af88,
	0x9cc26aca, 0x1888053d, 0x37eb853e, 0x9215abd7, 0xde30adfc, 0x1f1038e6,
	0x70c51c8a, 0x8d586c26, 0xf72bdd90, 0x4dc3ce15, 0x68eaeefa, 0xd0e9c8b9,
	0x200f9c44, 0xddd141ba, 0x024bf1d3, 0x0f64c9d4, 0xc421e9e9, 0x9d11c14c,
	0x9a0dd9e4, 0x5f92ec19, 0x1b980df0, 0x1dcc4542, 0xb8fe8c56, 0x0c9c9167,
	0x4e81eb49, 0xca368f27, 0xe3603b37, 0xea08accc, 0xac516992, 0xc34f513b,
	0x804d100d, 0x6edca4c4, 0xfc912939, 0x29d219b0, 0x278aaa3c, 0x4868da7d,
	0x54e890b7, 0xb46d735a, 0x514589aa, 0xd6c630af, 0x4980dfe8, 0xbe3ccc55,
	0x59d41202, 0x650c078b, 0xaf3a9e7b, 0x3ed9827a, 0x9e79fc6e, 0xaadbfbae,
	0xc5f7d803, 0x3daf7f50, 0x67b4f465, 0x73406e11, 0x39313f8c, 0x8a6e6686,
	0xd8075f1f, 0xd3cbfed1, 0x69c7e49c, 0x930581e0, 0xe4b1a5a8, 0xbbc45472,
	0x09ddbf58, 0xc91d687e, 0xbdbffda5, 0x88c08735, 0xe9e36bf9, 0xdb5ea9b6,
	0x95559404, 0x08f432fb, 0xe24ea281, 0x64663579, 0x000b8010, 0x7914e7d5,
	0x32fd0473, 0xd1a7f0a4, 0x445ab98e, 0xec72993f, 0xa29a4d32, 0xb77306d8,
	0xc7c97cf6, 0x7b6ab645, 0xf5ef7adf, 0xfb2e15f7, 0xe747f757, 0x5e944354,
	0x234a2669, 0x47e46359, 0x9b9d11a9, 0x40762ced, 0x56f1de98, 0x11334668,
	0x890a9a70, 0x1a296113, 0xb3bd4af5, 0x163b7548, 0xd51b4f84, 0xb99b2abc,
	0x3cc1dc30, 0xa9f0b56c, 0x812272b2, 0x0b233a5f, 0xb650dbf2, 0xf1a0771b,
	0x36562b76, 0xdc037b0f, 0x104c97ff, 0xc2ec98d2, 0x90596f22, 0x28b6620b,
	0xdf42b212, 0xfdbc4243, 0xf3fb175e, 0x4a2d8b00, 0xe8f3869b, 0x30d69bc3,
	0x853714c8, 0xa7751d2e, 0x31e56dea, 0xd4840b0c, 0x9685d783, 0x068c9333,
	0x8fba032c, 0x76d7bb47, 0x6d0ee22b, 0xb546794b, 0xd971b894, 0x8b09d253,
	0xa0ad5761, 0xee77ba06, 0x46359f31, 0x577cc7ec, 0x52825efd, 0xa4beed95,
	0x9825c52a, 0xeb48029a, 0xbaae59f8, 0xcf490ee1, 0xbc990164, 0x8ca49dfe,
	0x4f38a6e7, 0x2ba98389, 0x8228f538, 0x199f64ac, 0x01a1cac5, 0xa8b51641,
	0x5ce72d01, 0x8e5df26b, 0x60f28e1e, 0xcd5be125, 0xe5b376bf, 0x1c8d3116,
	0x7132cbb3, 0xcb7ae320, 0xc0fa5366, 0xd7653e34, 0x971c88c2, 0xc62c7dd0,
	0x34d0a3da, 0x868f6709, 0x7ae6fa8f, 0x22bbd523, 0x66cd3d5b, 0x1ef9288d,
	0xf9cf58c1, 0x5b784e80, 0x7439a191, 0xae134c36, 0x9116c463, 0x2e9e1396,
	0xf8611f3a, 0x2d2f3307, 0x247f37dd, 0xc1e2ff9d, 0x43c821e5, 0x05ed5cab,
	0xef74e80a, 0x4cca6028, 0xf0ac3cbd, 0x5d874b29, 0x6c62f6a6, 0x4b2a2ef3,
	0xb1aa2087, 0x62a5d0a3, 0x0327221c, 0xb096b4c6, 0x417ec693, 0xaba840d6,
	0x789725eb, 0xf4b9e02d, 0xe6e00975, 0xcc04961a, 0x63f624bb, 0x7fa21ecb,
	0x2c01ea7f, 0xb2415005, 0x2a8bbeb5, 0x83b2b14e, 0xa383d1a7, 0x5352f96a,
	0x043ecdad, 0xce1918a1, 0xfa6be6c9, 0x50def36f, 0xf6b80ce2, 0x4543ef7c,
	0x9953d651, 0xf257955d, 0x87244914, 0xda1e0a24, 0xffda4785, 0x14d327a2,
	0x3b93c29f, 0x840684b4, 0x61ab71a0, 0x9f7b784a, 0x2fd570cf, 0x15955bde,
	0x38f8d471, 0x3534a718, 0x133fb71d, 0x3fd80f52, 0x4290a8be, 0x75ff44c7,
	0xa554e546, 0xe1023499, 0xbf2652e3, 0x7d20399e, 0xa1df7e82, 0x177092ee,
	0x217dd3f1, 0x7c1ff8d9, 0x12113f2e, 0xbfbd0785, 0xf11793fb, 0xa5bff566,
	0x83c7b0e5, 0x72fb316b, 0x75526a9a, 0x41e0e612, 0x7156ba09, 0x53ce7dee,
	0x0aa26881, 0xa43e0d7d, 0x3da73ca3, 0x182761ed, 0xbd5077ff, 0x56db4aa0,
	0xe792711c, 0xf0a4eb1d, 0x7f878237, 0xec65c4e8, 0x08dc8d43, 0x0f8ce142,
	0x8258abda, 0xf4154e16, 0x49dec2fd, 0xcd8d5705, 0x6c2c3a0f, 0x5c12bb88,
	0xeff3cdb6, 0x2c89ed8c, 0x7beba967, 0x2a142157, 0xc6d0836f, 0xb4f97e96,
	0x6931e969, 0x514e6c7c, 0xa7792600, 0x0bbbf780, 0x59671bbd, 0x0707b676,
	0x37482d93, 0x80af1479, 0x3805a60d, 0xe1f4cac1, 0x580b3074, 0x30b8d6ce,
	0x05a304be, 0xd176626d, 0xebca97f3, 0xbb201f11, 0x6a1afe23, 0xffaa86e4,
	0x62b4da49, 0x1b6629f5, 0xf5d9e092, 0xf37f3dd1, 0x619bd45b, 0xa6ec8e4f,
	0x29c80939, 0x0c7c0c34, 0x9cfe6e48, 0xe65fd3ac, 0x73613b65, 0xb3c669f9,
	0xbe2e8a9e, 0x286f9678, 0x5797fd13, 0x99805d75, 0xcfb641c5, 0xa91074ba,
	0x6343af47, 0x6403cb46, 0x8894c8db, 0x2663034c, 0x3c40dc5e, 0x00995231,
	0x96789aa2, 0x2efde4b9, 0x7dc195e1, 0x547dadd5, 0x06a8ea04, 0xf2347a63,
	0x5e0dc6f7, 0x8462dfc2, 0x1e6b2c3c, 0x9bd275b3, 0x91d419e2, 0xbcefd17e,
	0xb9003924, 0xd07e7320, 0xdef0495c, 0xc36ad00e, 0x1785b1ab, 0x92e20bcf,
	0xb139f0e9, 0x675bb9a1, 0xaecfa4af, 0x132376cb, 0xe84589d3, 0x79a05456,
	0xa2f860bc, 0x1ae4f8b5, 0x20df4db4, 0xa1e1428b, 0x3bf60a1a, 0x27ff7bf1,
	0xcb44c0e7, 0xf7f587c4, 0x1f3b9b21, 0x94368f01, 0x856e23a4, 0x6f93de3f,
	0x773f5bbf, 0x8b22056e, 0xdf41f654, 0xb8246ff4, 0x8d57bff2, 0xd57167ea,
	0xc5699f22, 0x40734ba7, 0x5d5c2772, 0x033020a8, 0xe30a7c4d, 0xadc40fd6,
	0x76353441, 0x5aa5229b, 0x81516590, 0xda49f14e, 0x4fa672a5, 0x4d9fac5f,
	0x154be230, 0x8a7a5cc0, 0xce3d2f84, 0xcca15514, 0x5221360c, 0xaf0fb81e,
	0x5bdd5873, 0xf6825f8f, 0x1113d228, 0x70ad996c, 0x93320051, 0x60471c53,
	0xe9ba567b, 0x3a462ae3, 0x5f55e72d, 0x1d3c5ad7, 0xdcfc45ec, 0x34d812ef,
	0xfa96ee1b, 0x369d1ef8, 0xc9b1a189, 0x7c1d3555, 0x50845edc, 0x4bb31877,
	0x8764a060, 0x8c9a9415, 0x230e1a3a, 0xb05e9133, 0x242b9e03, 0xa3b99db7,
	0xc2d7fb0a, 0x3333849d, 0xd27278d4, 0xb5d3efa6, 0x78ac28ad, 0xc7b2c135,
	0x0926ecf0, 0xc1374c91, 0x74f16d98, 0x2274084a, 0x3f6d9cfa, 0x7ac0a383,
	0xb73aff1f, 0x3909a23d, 0x9f1653ae, 0x4e2f3e71, 0xca5ab22a, 0xe01e3858,
	0x90c5a7eb, 0x3e4a17df, 0xaa987fb0, 0x488bbd62, 0xb625062b, 0x2d776bb8,
	0x43b5fc08, 0x1490d532, 0xd6d12495, 0x44e89845, 0x2fe60118, 0x9d9ef950,
	0xac38133e, 0xd3864329, 0x017b255a, 0xfdc2dd26, 0x256851e6, 0x318e7086,
	0x2bfa4861, 0x89eac706, 0xee5940c6, 0x68c3bc2f, 0xe260334b, 0x98da90bb,
	0xf818f270, 0x4706d897, 0x212d3799, 0x4cf7e5d0, 0xd9c9649f, 0xa85db5cd,
	0x35e90e82, 0x6b881152, 0xab1c02c7, 0x46752b02, 0x664f598e, 0x45ab2e64,
	0xc4cdb4b2, 0xba42107f, 0xea2a808a, 0x971bf3de, 0x4a54a836, 0x4253aecc,
	0x1029be68, 0x6dcc9225, 0xe4bca56a, 0xc0ae50b1, 0x7e011d94, 0xe59c162c,
	0xd8e5c340, 0xd470fa0b, 0xb2be79dd, 0xd783889c, 0x1cede8f6, 0x8f4c817a,
	0xddb785c9, 0x860232d8, 0x198aaad9, 0xa0814738, 0x3219cffc, 0x169546d2,
	0xfc0cb759, 0x55911510, 0x04d5cec3, 0xed08cc3b, 0x0d6cf427, 0xc8e38cca,
	0x0eeee3fe, 0x9ee7d7c8, 0xf9f24fa9, 0xdb04b35d, 0x9ab0c9e0, 0x651f4417,
	0x028f8b07, 0x6e28d9aa, 0xfba96319, 0x8ed66687, 0xfecbc58d, 0x954ddb44,
	0x7b0bdffe, 0x865d16b1, 0x49a058c0, 0x97abaa3f, 0xcaacc75d, 0xaba6c17d,
	0xf8746f92, 0x6f48aeed, 0x8841d4b5, 0xf36a146a, 0x73c390ab, 0xe6fb558f,
	0x87b1019e, 0x26970252, 0x246377b2, 0xcbf676ae, 0xf923db06, 0xf7389116,
	0x14c81a90, 0x83114eb4, 0x8b137559, 0x95a86a7a, 0xd5b8da8c, 0xc4df780e,
	0x5a9cb3e2, 0xe44d4062, 0xe8dc8ef6, 0x9d180845, 0x817ad18b, 0xc286c85b,
	0x251f20de, 0xee6d5933, 0xf6edef81, 0xd4d16c1e, 0xc94a0c32, 0x8437fd22,
	0x3271ee43, 0x42572aee, 0x5f91962a, 0x1c522d98, 0x59b23f0c, 0xd86b8804,
	0x08c63531, 0x2c0d7a40, 0xb97c4729, 0x04964df9, 0x13c74a17, 0x5878362f,
	0x4c808cd6, 0x092cb1e0, 0x6df02885, 0xa0c2105e, 0x8aba9e68, 0x64e03057,
	0xe5d61325, 0x0e43a628, 0x16dbd62b, 0x2733d90b, 0x3ae57283, 0xc0c1052c,
	0x4b6fb620, 0x37513953, 0xfc898bb3, 0x471b179f, 0xdf6e66b8, 0xd32142f5,
	0x9b30fafc, 0x4ed92549, 0x105c6d99, 0x4acd69ff, 0x2b1a27d3, 0x6bfcc067,
	0x6301a278, 0xad36e6f2, 0xef3ff64e, 0x56b3cadb, 0x0184bb61, 0x17beb9fd,
	0xfaec6109, 0xa2e1ffa1, 0x2fd224f8, 0x238f5be6, 0x8f8570cf, 0xaeb5f25a,
	0x4f1d3e64, 0x4377eb24, 0x1fa45346, 0xb2056386, 0x52095e76, 0xbb7b5adc,
	0x3514e472, 0xdde81e6e, 0x7acea9c4, 0xac15cc48, 0x71c97d93, 0x767f941c,
	0x911052a2, 0xffea09bf, 0xfe3ddcf0, 0x15ebf3aa, 0x9235b8bc, 0x75408615,
	0x9a723437, 0xe1a1bd38, 0x33541b7e, 0x1bdd6856, 0xb307e13e, 0x90814bb0,
	0x51d7217b, 0x0bb92219, 0x689f4500, 0xc568b01f, 0x5df3d2d7, 0x3c0ecd0d,
	0x2a0244c8, 0x852574e8, 0xe72f23a9, 0x8e26ed02, 0x2d92cbdd, 0xdabc0458,
	0xcdf5feb6, 0x9e4e8dcc, 0xf4f1e344, 0x0d8c436d, 0x4427603b, 0xbdd37fda,
	0x80505f26, 0x8c7d2b8e, 0xb73273c5, 0x397362ea, 0x618a3811, 0x608bfb88,
	0x06f7d714, 0x212e4677, 0x28efcead, 0x076c0371, 0x36a3a4d9, 0x5487b455,
	0x3429a365, 0x65d467ac, 0x78ee7eeb, 0x99bf12b7, 0x4d129896, 0x772a5601,
	0xcce284c7, 0x2ed85c21, 0xd099e8a4, 0xa179158a, 0x6ac0ab1a, 0x299a4807,
	0xbe67a58d, 0xdc19544a, 0xb8949b54, 0x8d315779, 0xb6f849c1, 0x53c5ac34,
	0x66de92a5, 0xf195dd13, 0x318d3a73, 0x301ec542, 0x0cc40da6, 0xf253ade4,
	0x467ee566, 0xea5585ec, 0x3baf19bb, 0x7de9f480, 0x79006e7c, 0xa9b7a197,
	0xa44bd8f1, 0xfb2ba739, 0xec342fd4, 0xed4fd32d, 0x3d1789ba, 0x400f5d7f,
	0xc798f594, 0x4506a847, 0x034c0a95, 0xe2162c9d, 0x55a9cfd0, 0x692d832e,
	0xcf9db2ca, 0x5e2287e9, 0xd2610ef3, 0x1ae7ecc2, 0x48399ca0, 0xa7e4269b,
	0x6ee3a0af, 0x7065bfe1, 0xa6ffe708, 0x2256804c, 0x7476e21b, 0x41b0796c,
	0x7c243b05, 0x000a950f, 0x1858416b, 0xf5a53c89, 0xe9fef823, 0x3f443275,
	0xe0cbf091, 0x0af27b84, 0x3ebb0f27, 0x1de6f7f4, 0xc31c29f7, 0xb166de3d,
	0x12932ec3, 0x9c0c0674, 0x5cda81b9, 0xd1bd9d12, 0xaffd7c82, 0x8962bca7,
	0xa342c4a8, 0x62457151, 0x82089f03, 0xeb49c670, 0x5b5f6530, 0x7e28bad2,
	0x20880ba3, 0xf0faafcd, 0xce82b56f, 0x0275335c, 0xc18e8afb, 0xde601d69,
	0xba9b820a, 0xc8a2be4f, 0xd7cac335, 0xd9a73741, 0x115e974d, 0x7f5ac21d,
	0x383bf9c6, 0xbcaeb75f, 0xfd0350ce, 0xb5d06b87, 0x9820e03c, 0x72d5f163,
	0xe3644fc9, 0xa5464c4b, 0x57048fcb, 0x9690c9df, 0xdbf9eafa, 0xbff4649a,
	0x053c00e3, 0xb4b61136, 0x67593dd1, 0x503ee960, 0x9fb4993a, 0x19831810,
	0xc670d518, 0xb05b51d8, 0x0f3a1ce5, 0x6caa1f9c, 0xaacc31be, 0x949ed050,
	0x1ead07e7, 0xa8479abd, 0xd6cffcd5, 0x936993ef, 0x472e91cb, 0x5444b5b6,
	0x62be5861, 0x1be102c7, 0x63e4b31e, 0xe81f71b7, 0x9e2317c9, 0x39a408ae,
	0x518024f4, 0x1731c66f, 0x68cbc918, 0x71fb0c9e, 0xd03b7fdd, 0x7d6222eb,
	0x9057eda3, 0x1a34a407, 0x8cc2253d, 0xb6f6979d, 0x835675dc, 0xf319be9f,
	0xbe1cd743, 0x4d32fee4, 0x77e7d887, 0x37e9ebfd, 0x15f851e8, 0x23dc3706,
	0x19d78385, 0xbd506933, 0xa13ad4a6, 0x913f1a0e, 0xdde560b9, 0x9a5f0996,
	0xa65a0435, 0x48d34c4d, 0xe90839a7, 0x8abba54e, 0x6fd13ce1, 0xc7eebd3c,
	0x0e297602, 0x58b9bbb4, 0xef7901e6, 0x64a28a62, 0xa509875a, 0xf8834442,
	0x2702c709, 0x07353f31, 0x3b39f665, 0xf5b18b49, 0x4010ae37, 0x784de00b,
	0x7a1121e9, 0xde918ed3, 0xc8529dcd, 0x816a5d05, 0x02ed8298, 0x04e3dd84,
	0xfd2bc3e2, 0xaf167089, 0x96af367e, 0xa4da6232, 0x18ff7325, 0x05f9a9f1,
	0x4fefb9f9, 0xcd94eaa5, 0xbfaa5069, 0xa0b8c077, 0x60d86f57, 0xfe71c813,
	0x29ebd2c8, 0x4ca86538, 0x6bf1a030, 0xa237b88a, 0xaa8af41d, 0xe1f7b6ec,
	0xe214d953, 0x33057879, 0x49caa736, 0xfa45cff3, 0xc063b411, 0xba7e27d0,
	0x31533819, 0x2a004ac1, 0x210efc3f, 0x2646885e, 0x66727dcf, 0x9d7fbf54,
	0xa8dd0ea8, 0x3447cace, 0x3f0c14db, 0xb8382aac, 0x4ace3539, 0x0a518d51,
	0x95178981, 0x35aee2ca, 0x73f0f7e3, 0x94281140, 0x59d0e523, 0xd292cb88,
	0x565d1b27, 0x7ec8fbaf, 0x069af08d, 0xc127fd24, 0x0bc77b10, 0x5f03e7ef,
	0x453e99ba, 0xeed9ff7f, 0x87b55215, 0x7915ab4c, 0xd389a358, 0x5e75ce6d,
	0x28d655c0, 0xdad26c73, 0x2e2510ff, 0x9fa7eecc, 0x1d0629c3, 0xdc9c9c46,
	0x2d67ecd7, 0xe75e94bd, 0x3d649e2a, 0x6c413a2b, 0x706f0d7c, 0xdfb0127b,
	0x4e366b55, 0x2c825650, 0x24205720, 0xb5c998f7, 0x3e95462c, 0x756e5c72,
	0x3259488f, 0x11e8771a, 0xa7c0a617, 0x577663e5, 0x089b6401, 0x8eab1941,
	0xae55ef8c, 0x3aac5460, 0xd4e6262f, 0x5d979a47, 0xb19823b0, 0x7f8d6a0c,
	0xffa08683, 0x0170cd0f, 0x858cd5d8, 0x53961c90, 0xc4c61556, 0x41f2f226,
	0xcfcd062d, 0xf24c03b8, 0xea81df5b, 0x7be2fa52, 0xb361f98b, 0xc2901316,
	0x55ba4bbc, 0x93b234a9, 0x0fbc6603, 0x80a96822, 0x6d60491f, 0x22bd00f8,
	0xbcad5aad, 0x52f3f13b, 0x42fd2b28, 0xb41dd01c, 0xc52c93bf, 0xfc663094,
	0x8f58d100, 0x43fecc08, 0xc6331e5d, 0xe6480f66, 0xca847204, 0x4bdf1da0,
	0x30cc2efb, 0x13e02dea, 0xfb49ac45, 0xf9d4434f, 0xf47c5b9c, 0x148879c2,
	0x039fc234, 0xa3db9bfc, 0xd1a1dc5c, 0x763d7cd4, 0xed6d2f93, 0xab13af6e,
	0x1e8e054a, 0xd68f4f9a, 0xc30484b3, 0xd7d50afa, 0x6930855f, 0xcc07db95,
	0xce746db1, 0x744e967d, 0xf16cf575, 0x8643e8b5, 0xf0eae38e, 0xe52de1d1,
	0x6587dae0, 0x0c4b8121, 0x1c7ac567, 0xac0db20a, 0x36c3a812, 0x5b1a4514,
	0xa9a3f868, 0xb9263baa, 0xcb3ce9d2, 0xe44fb1a4, 0x9221bc82, 0xb29390fe,
	0x6ab41863, 0x974a3e2e, 0x89f531c5, 0x255ca13e, 0x8b65d348, 0xec248f78,
	0xd8fc16f0, 0x50ecdeee, 0x09010792, 0x3c7d1fb2, 0xeba5426b, 0x847b417a,
	0x468b40d9, 0x8dc4e680, 0x7cc1f391, 0x2f1eb086, 0x6e5baa6a, 0xe0b395da,
	0xe31b2cf6, 0xd9690b0d, 0x729ec464, 0x38403dde, 0x610b80a2, 0x5cf433ab,
	0xb0785fc4, 0xd512e4c6, 0xbbb7d699, 0x5a86591b, 0x10cf5376, 0x12bf9f4b,
	0x980fbaa1, 0x992a4e70, 0x20fa7ae7, 0xf7996ebb, 0xc918a2be, 0x82de74f2,
	0xad54209b, 0xf66b4d74, 0x1fc5b771, 0x169d9229, 0x887761df, 0x00b667d5,
	0xdb425e59, 0xb72f2844, 0x9b0ac1f5, 0x9c737e3a, 0x2b85476c, 0x6722add6,
	0x44a63297, 0x0d688ced, 0xabc59484, 0x4107778a, 0x8ad94c6f, 0xfe83df90,
	0x0f64053f, 0xd1292e9d, 0xc5744356, 0x8dd1abb4, 0x4c4e7667, 0xfb4a7fc1,
	0x74f402cb, 0x70f06afd, 0xa82286f2, 0x918dd076, 0x7a97c5ce, 0x48f7bde3,
	0x6a04d11d, 0xac243ef7, 0x33ac10ca, 0x2f7a341e, 0x5f75157a, 0xf4773381,
	0x591c870e, 0x78df8cc8, 0x22f3adb0, 0x251a5993, 0x09fbef66, 0x796942a8,
	0x97541d2e, 0x2373daa9, 0x1bd2f142, 0xb57e8eb2, 0xe1a5bfdb, 0x7d0efa92,
	0xb3442c94, 0xd2cb6447, 0x386ac97e, 0x66d61805, 0xbdada15e, 0x11bc1aa7,
	0x14e9f6ea, 0xe533a0c0, 0xf935ee0a, 0x8fee8a04, 0x810d6d85, 0x7c68b6d6,
	0x4edc9aa2, 0x956e897d, 0xed87581a, 0x264be9d7, 0xff4ddb29, 0x823857c2,
	0xe005a9a0, 0xf1cc2450, 0x6f9951e1, 0xaade2310, 0xe70c75f5, 0x83e1a31f,
	0x4f7dde8e, 0xf723b563, 0x368e0928, 0x86362b71, 0x21e8982d, 0xdfb3f92b,
	0x44676352, 0x99efba31, 0x2eab4e1c, 0xfc6ca5e7, 0x0ebe5d4e, 0xa0717d0c,
	0xb64f8199, 0x946b31a1, 0x5656cbc6, 0xcffec3ef, 0x622766c9, 0xfa211e35,
	0x52f98b89, 0x6d01674b, 0x4978a802, 0xf651f701, 0x15b0d43d, 0xd6ff4683,
	0x3463855f, 0x672ba29c, 0xbc128312, 0x4626a70d, 0xc8927a5a, 0xb8481cf9,
	0x1c962262, 0xa21196ba, 0xbaba5ee9, 0x5bb162d0, 0x69943bd1, 0x0c47e35c,
	0x8cc9619a, 0xe284d948, 0x271bf264, 0xc27fb398, 0x4bc70897, 0x60cf202c,
	0x7f42d6aa, 0xa5a13506, 0x5d3e8860, 0xcea63d3c, 0x63bf0a8f, 0xf02e9efa,
	0xb17b0674, 0xb072b1d3, 0x06e5723b, 0x3737e436, 0x24aa49c7, 0x0ded0d18,
	0xdb256b14, 0x58b27877, 0xecb49f54, 0x6c40256a, 0x6ea92ffb, 0x3906aa4c,
	0xc9866fd5, 0x4549323e, 0xa7b85fab, 0x1918cc27, 0x7308d7b5, 0x1e16c7ad,
	0x71850b37, 0x3095fd78, 0xa63b70e6, 0xd880e2ae, 0x3e282769, 0xa39ba6bc,
	0x98700fa3, 0xf34c53e8, 0x288af426, 0xb99d930f, 0xf5b99df1, 0xe9d0c8cf,
	0x5ac8405d, 0x50e7217b, 0x511fbbbe, 0x2ca2e639, 0xc020301b, 0x356dbc00,
	0x8e43ddb9, 0x4d327b4a, 0xf20ff3ed, 0x1dbb29bd, 0x43d44779, 0xa1b68f70,
	0x6114455b, 0xe63d280b, 0x6bf6ff65, 0x10fc39e5, 0x3dae126e, 0xc1d7cf11,
	0xcb60b795, 0x1789d5b3, 0x9bca36b7, 0x08306075, 0x84615608, 0x8b3a0186,
	0xe88fbecd, 0x7ba47c4d, 0x2de44dac, 0x653fe58d, 0xcca0b968, 0xd7fa0e72,
	0x93901780, 0x1f2c26cc, 0xae595b6b, 0xa9ecea9b, 0xe3dbf8c4, 0x319cc130,
	0x12981196, 0x01a3a4de, 0x32c454b6, 0x755bd817, 0x3cd871e4, 0xa48bb8da,
	0x02fdec09, 0xfd2dc2e2, 0x9e578088, 0x9a9f916d, 0x4065fe6c, 0x1853999e,
	0xc7793f23, 0xdc1016bb, 0x969355ff, 0x7ef292f6, 0xcdce4adc, 0x05e24416,
	0x85c16c46, 0xd441d37f, 0x57bd6855, 0x8746f54f, 0x9ca773df, 0x770bae22,
	0x54828413, 0xb75e4b19, 0x04c35c03, 0xbf7cca07, 0x2955c4dd, 0x721db041,
	0xb2394f33, 0x03f51387, 0x89b73c9f, 0x0b1737f3, 0x07e69024, 0x9231d245,
	0x76193861, 0x88159c15, 0xdeb552d9, 0xd9767e40, 0x20c6c0c3, 0x4281977c,
	0xf8afe1e0, 0xd32a0751, 0x3fc27432, 0xddf1dcc5, 0x68581f34, 0x3bcd5025,
	0x0091b2ee, 0x4aeb6944, 0x1602e743, 0xea09eb58, 0xef0a2a8b, 0x641e03a5,
	0xeb50e021, 0x5c8ccef8, 0x802ff0b8, 0xd5e3edfe, 0xc4dd1b49, 0x5334cd2a,
	0x13f82d2f, 0x47450c20, 0x55dafbd2, 0xbec0c6f4, 0xb45d7959, 0x3ad36e8c,
	0x0aa8ac57, 0x1a3c8d73, 0xe45aafb1, 0x9f664838, 0xc6880053, 0xd0039bbf,
	0xee5f19eb, 0xca0041d8, 0xbbea3aaf, 0xda628291, 0x9d5c95d4, 0xadd504a6,
	0xc39ab482, 0x5e9e14a4, 0x2be065f0, 0x2a13fc3a, 0x9052e8ec, 0xaf6f5afc,
	0x519aa8b5, 0xbb303da9, 0xe00e2b10, 0xdfa6c1db, 0x2e6b952e, 0xee10dc23,
	0x37936d09, 0x1fc42e92, 0x39b25a9f, 0x13ff89f4, 0xc8f53fea, 0x18500bc7,
	0x95a0379d, 0x98f751c2, 0x2289c42f, 0xa21e4098, 0x6f391f41, 0xf27e7e58,
	0x0d0df887, 0x4b79d540, 0x8e8409aa, 0x71fe46f8, 0x688a9b29, 0x3f08b548,
	0x84abe03a, 0x5e91b6c1, 0xfde4c2ae, 0x251d0e72, 0x92d4fee5, 0xf9371967,
	0x9175108f, 0xe6e81835, 0x8c8cb8ee, 0xb55a67b3, 0xcef138cc, 0x8b256268,
	0x00d815f5, 0xe8810812, 0x77826189, 0xea73267d, 0x19b90f8d, 0x45c33bb4,
	0x82477056, 0xe1770075, 0x09467aa6, 0xa7c6f54a, 0x79768742, 0x61b86bca,
	0xd6644a44, 0xe33f0171, 0xc229fbcd, 0x41b08feb, 0xd1903e30, 0x65ec9080,
	0x563d6fbd, 0xf56da488, 0xebf64cd8, 0x4934426b, 0x7c8592fc, 0x6aca8cf2,
	0x1cea111b, 0x3a57ee7a, 0xace11c0d, 0x9942d85e, 0xc4613407, 0xfa8e643b,
	0x327fc701, 0x4ca9be82, 0x3352526d, 0x2c047f63, 0xf3a8f7dd, 0x1a4a98a8,
	0x762ed4d1, 0x27c75008, 0xbdf497c0, 0x7a7b84df, 0x315c28ab, 0x801f93e3,
	0xf19b0ca1, 0x8f14e46a, 0xe48ba333, 0x9605e625, 0xf03ecb60, 0x60385f2d,
	0x902845ba, 0x7f96d66f, 0x24bff05c, 0x2820730b, 0x947133cb, 0xd444828a,
	0xb343f6f1, 0x0bef4705, 0x8da574f9, 0x01e25d6c, 0x1732793e, 0x4f0f7b27,
	0x364b7117, 0xb2d1da77, 0xa6c5f1e9, 0x574ca5b1, 0x386a3076, 0xad6894d6,
	0x1156d7fa, 0xa48d1d9a, 0x4794c0af, 0x150c0aa0, 0x26d348ac, 0x29fdeabe,
	0xa5dede53, 0x81671e8e, 0x594ee3bf, 0xa96c56e6, 0x3426a726, 0xc5976579,
	0xbc22e5e4, 0xc1006319, 0xdaafdd2a, 0xa1a1aa83, 0x3badd0e7, 0xc3b14981,
	0xd770b155, 0xccd7c693, 0x42e944c5, 0x03e0064f, 0xca95b4ef, 0x3dee81c3,
	0xfbbcd98c, 0x1e07e15b, 0x667ce949, 0xe7d6773f, 0x21b6124b, 0x6b2a6ef7,
	0xd3278a9c, 0x9a988304, 0x75d2ae9b, 0xfe49e2ff, 0x9bc24f46, 0x74cc2cf6,
	0xa3139f36, 0x6c9ef35a, 0x9fc1dffe, 0x9e5facdc, 0xaadc8bbb, 0x5abdbc5f,
	0x44b3b390, 0xf754efa7, 0x5fe3bdb7, 0x4e59c886, 0x06a4c984, 0xa0338878,
	0xcd513cd7, 0x63ebd27e, 0x8aba80ad, 0x50da144e, 0x5d9f4e97, 0x025b751c,
	0x2d580200, 0xb6c05837, 0x580aa15d, 0x54022a6e, 0xb41a5415, 0x4863fab6,
	0xb0b79957, 0x46d0d159, 0xdc2b8650, 0x20a7bb0c, 0x4a032974, 0xec8636a2,
	0x8548f24c, 0xf6a2bf16, 0x1088f4b0, 0x0c2f3a94, 0x525dc396, 0x14065785,
	0x2b4dca52, 0x08aeed39, 0xabedfc99, 0xb1dbcf18, 0x87f85bbc, 0xae3aff61,
	0x433ccd70, 0x5b23cc64, 0x7b453213, 0x5355c545, 0x9318ec0a, 0x78692d31,
	0x0a21693d, 0xd5666814, 0x05fb59d9, 0xc71985b2, 0x2abb8e0e, 0xcf6e6c91,
	0xd9cfe7c6, 0xefe7132c, 0x9711ab28, 0x3ce52732, 0x12d516d2, 0x7209a0d0,
	0xd278d306, 0x70fa4b7b, 0x1d407dd3, 0xdb0beba4, 0xbfd97621, 0xa8be21e1,
	0x1b6f1b66, 0x30650dda, 0xba7ddbb9, 0x7df953fb, 0x9d1c3902, 0xedf0e8d5,
	0xb8741ae0, 0x0f240565, 0x62cd438b, 0xc616a924, 0xaf7a96a3, 0x35365538,
	0xe583af4d, 0x73415eb8, 0x23176a47, 0xfc9ccee8, 0x7efc9de2, 0x695e03cf,
	0xf8ce66d4, 0x88b4781d, 0x67dd9c03, 0x3e8f9e73, 0xc0c95c51, 0xbe314d22,
	0x55aa0795, 0xcb1bb011, 0xe980fdc8, 0x9c62b7ce, 0xde2d239e, 0x042cadf3,
	0xffdf04de, 0x5ce6a60f, 0xd8c831ed, 0xb7b5b9ec, 0xb9cbf962, 0xe253b254,
	0x0735ba1f, 0x16ac917f, 0xdd607c2b, 0x64a335c4, 0x40159a7c, 0x869222f0,
	0x6ef21769, 0x839d20a5, 0xd03b24c9, 0xf412601e, 0x6d72a243, 0x0e018dfd,
	0x89f3721a, 0xc94f4134, 0x2f992f20, 0x4d87253c
};

#define __MASTER_SNEFRU_FUNCTION_F(i) do { \
	x = sbox[(i << 7 & 0x100) + (W[i] & 0xff)]; \
	W[(i - 1) & 0x0F] ^= x; \
	if (i >= 2) W[(i - 1) & 0x0F] = \
	MASTER_RLR32(W[(i - 1) & 0x0F], (UI1)rot); \
	W[(i + 1) & 0x0F] ^= x; \
} while (0)

MASTER_SNEFRU
MASTER_SNEFRU_Init(UI4 outl) {
	MASTER_SNEFRU __snefru;
	memset(&__snefru, 0, sizeof(MASTER_SNEFRU));
	__snefru.__dl = outl / 8;
	return __snefru;
}

static void
MASTER_SNEFRU_Transform(MASTER_SNEFRU * const __snefru, UI4 * block) {
	UI4 W[16];
	UI4 rot, i, x;

	const UI4 * sbox;
	const UI4 * const sbox_end = MASTER_SNEFRU_TABLE_SB + 512 * 8;
	UI4 * const __h = __snefru->__h;

	for (i = 0; i < 4; i++) W[i] = __snefru->__h[i];
	if (__snefru->__dl == 32) for (; i < 8; i++) W[i] = __snefru->__h[i];
	else {
		for (; i < 8; i++) W[i] = __MASTER_CHANGE_ENDIAN_32I(block[i - 4]);
		block += 4;
	}
	for (i = 8; i < 16; i++) W[i] = __MASTER_CHANGE_ENDIAN_32I(block[i - 8]);
	for (sbox = MASTER_SNEFRU_TABLE_SB; sbox < sbox_end; sbox += 512) {
		for (rot = 0x18100810; rot; rot >>= 8) {
			for (i = 0; i < 16; i++) __MASTER_SNEFRU_FUNCTION_F(i);
			W[0] = MASTER_RLR32(W[0], (UI1)rot);
			W[15] = MASTER_RLR32(W[15], (UI1)rot);
		}
	}

	__h[0] ^= W[15];
	__h[1] ^= W[14];
	__h[2] ^= W[13];
	__h[3] ^= W[12];
	if (__snefru->__dl == 32) {
		__h[4] ^= W[11];
		__h[5] ^= W[10];
		__h[6] ^= W[9];
		__h[7] ^= W[8];
	}
}

void
MASTER_SNEFRU_Update(MASTER_SNEFRU * const __snefru, const UI1 * __s, UI8 __l) {
	const UI4 data_block_size = 64 - __snefru->__dl;
	__snefru->__l += __l;

	if (__snefru->__i) {
		UI4 left = data_block_size - __snefru->__i;
		memcpy((char *)__snefru->__b + __snefru->__i, __s, (__l < left ? __l : left));
		if (__l < left) {
			__snefru->__i += (UI4)__l;
			return;
		}
		MASTER_SNEFRU_Transform(__snefru, (UI4 *)__snefru->__b);
		__s += left;
		__l -= left;
	}
	while (__l >= data_block_size) {
		UI4 * aligned_message_block;

		if (((UI8)(__s) & 3) == 0) aligned_message_block = (UI4 *)__s;
		else {
			memcpy(__snefru->__b, __s, data_block_size);
			aligned_message_block = (UI4 *)__snefru->__b;
		}
		MASTER_SNEFRU_Transform(__snefru, aligned_message_block);
		__s += data_block_size;
		__l -= data_block_size;
	}

	__snefru->__i = (UI4)__l;
	if (__l) memcpy(__snefru->__b, __s, __l);
}

int
MASTER_SNEFRU_Final(MASTER_SNEFRU * const __snefru, UI1 * hash_output) {
	const UI4 digest_dw_len = __snefru->__dl / 4; 
	const UI4 data_block_size = 64 - __snefru->__dl;

	if (__snefru->__i != (UI4)(__snefru->__l % data_block_size)) return 1;
	if (__snefru->__i) {
		memset((char *)__snefru->__b + __snefru->__i, 0, data_block_size - __snefru->__i);
		MASTER_SNEFRU_Transform(__snefru, (UI4 *)__snefru->__b);
	}

	memset(__snefru->__b, 0, data_block_size - 8);
	((UI4 *)__snefru->__b)[14 - digest_dw_len] = __MASTER_CHANGE_ENDIAN_32I((UI4)(__snefru->__l >> 29));
	((UI4 *)__snefru->__b)[15 - digest_dw_len] = __MASTER_CHANGE_ENDIAN_32I((UI4)(__snefru->__l << 3));
	MASTER_SNEFRU_Transform(__snefru, (UI4 *)__snefru->__b);

	UI8 __i = 0;
	if (((((UI8)hash_output | (UI8)__snefru->__h | __snefru->__dl) & 3) == 0) ) {
		const UI4 * src = (const UI4 *)__snefru->__h;
		const UI4 * end = (const UI4 *)((const char *)src + __snefru->__dl);
		UI4 * dst = (UI4 *)((char *)hash_output + __i);
		for (; src < end; dst++, src++) *dst = __MASTER_CHANGE_ENDIAN_32I(*src);
	} else {
		const char * src = (const char *)__snefru->__h;
		for (__snefru->__dl += __i; (UI8)__i < __snefru->__dl; __i++) ((char *)hash_output)[__i ^ 3] = *(src++);
	}
	return 0;
}

int
MASTER_SNEFRU_CalculateHashSum(const char * __s, UI4 __l, UI1 * hash_output, UI4 outl) {
	MASTER_SNEFRU __snefru = MASTER_SNEFRU_Init(outl);
	MASTER_SNEFRU_Update(&__snefru, __s, __l);
	return MASTER_SNEFRU_Final(&__snefru, hash_output);
}

#undef __MASTER_SNEFRU_FUNCTION_F

// !# SNEFRU

// #! GOST12

static const UI8
MASTER_GOST12_TABLE_T[8][256] = {
	{
		0xD01F715B5C7EF8E6, 0x16FA240980778325, 0xA8A42E857EE049C8, 0x6AC1068FA186465B, 
		0x6E417BD7A2E9320B, 0x665C8167A437DAAB, 0x7666681AA89617F6, 0x4B959163700BDCF5, 
		0xF14BE6B78DF36248, 0xC585BD689A625CFF, 0x9557D7FCA67D82CB, 0x89F0B969AF6DD366, 
		0xB0833D48749F6C35, 0xA1998C23B1ECBC7C, 0x8D70C431AC02A736, 0xD6DFBC2FD0A8B69E, 
		0x37AEB3E551FA198B, 0x0B7D128A40B5CF9C, 0x5A8F2008B5780CBC, 0xEDEC882284E333E5, 
		0xD25FC177D3C7C2CE, 0x5E0F5D50B61778EC, 0x1D873683C0C24CB9, 0xAD040BCBB45D208C, 
		0x2F89A0285B853C76, 0x5732FFF6791B8D58, 0x3E9311439EF6EC3F, 0xC9183A809FD3C00F, 
		0x83ADF3F5260A01EE, 0xA6791941F4E8EF10, 0x103AE97D0CA1CD5D, 0x2CE948121DEE1B4A, 
		0x39738421DBF2BF53, 0x093DA2A6CF0CF5B4, 0xCD9847D89CBCB45F, 0xF9561C078B2D8AE8, 
		0x9C6A755A6971777F, 0xBC1EBAA0712EF0C5, 0x72E61542ABF963A6, 0x78BB5FDE229EB12E, 
		0x14BA94250FCEB90D, 0x844D6697630E5282, 0x98EA08026A1E032F, 0xF06BBEA144217F5C, 
		0xDB6263D11CCB377A, 0x641C314B2B8EE083, 0x320E96AB9B4770CF, 0x1EE7DEB986A96B85, 
		0xE96CF57A878C47B5, 0xFDD6615F8842FEB8, 0xC83862965601DD1B, 0x2EA9F83E92572162, 
		0xF876441142FF97FC, 0xEB2C455608357D9D, 0x5612A7E0B0C9904C, 0x6C01CBFB2D500823, 
		0x4548A6A7FA037A2D, 0xABC4C6BF388B6EF4, 0xBADE77D4FDF8BEBD, 0x799B07C8EB4CAC3A, 
		0x0C9D87E805B19CF0, 0xCB588AAC106AFA27, 0xEA0C1D40C1E76089, 0x2869354A1E816F1A, 
		0xFF96D17307FBC490, 0x9F0A9D602F1A5043, 0x96373FC6E016A5F7, 0x5292DAB8B3A6E41C, 
		0x9B8AE0382C752413, 0x4F15EC3B7364A8A5, 0x3FB349555724F12B, 0xC7C50D4415DB66D7, 
		0x92B7429EE379D1A7, 0xD37F99611A15DFDA, 0x231427C05E34A086, 0xA439A96D7B51D538, 
		0xB403401077F01865, 0xDDA2AEA5901D7902, 0x0A5D4A9C8967D288, 0xC265280ADF660F93, 
		0x8BB0094520D4E94E, 0x2A29856691385532, 0x42A833C5BF072941, 0x73C64D54622B7EB2, 
		0x07E095624504536C, 0x8A905153E906F45A, 0x6F6123C16B3B2F1F, 0xC6E55552DC097BC3, 
		0x4468FEB133D16739, 0xE211E7F0C7398829, 0xA2F96419F7879B40, 0x19074BDBC3AD38E9, 
		0xF4EBC3F9474E0B0C, 0x43886BD376D53455, 0xD8028BEB5AA01046, 0x51F23282F5CDC320, 
		0xE7B1C2BE0D84E16D, 0x081DFAB006DEE8A0, 0x3B33340D544B857B, 0x7F5BCABC679AE242, 
		0x0EDD37C48A08A6D8, 0x81ED43D9A9B33BC6, 0xB1A3655EBD4D7121, 0x69A1EEB5E7ED6167, 
		0xF6AB73D5C8F73124, 0x1A67A3E185C61FD5, 0x2DC91004D43C065E, 0x0240B02C8FB93A28, 
		0x90F7F2B26CC0EB8F, 0x3CD3A16F114FD617, 0xAAE49EA9F15973E0, 0x06C0CD748CD64E78, 
		0xDA423BC7D5192A6E, 0xC345701C16B41287, 0x6D2193EDE4821537, 0xFCF639494190E3AC, 
		0x7C3B228621F1C57E, 0xFB16AC2B0494B0C0, 0xBF7E529A3745D7F9, 0x6881B6A32E3F7C73, 
		0xCA78D2BAD9B8E733, 0xBBFE2FC2342AA3A9, 0x0DBDDFFECC6381E4, 0x70A6A56E2440598E, 
		0xE4D12A844BEFC651, 0x8C509C2765D0BA22, 0xEE8C6018C28814D9, 0x17DA7C1F49A59E31, 
		0x609C4C1328E194D3, 0xB3E3D57232F44B09, 0x91D7AAA4A512F69B, 0x0FFD6FD243DABBCC, 
		0x50D26A943C1FDE34, 0x6BE15E9968545B4F, 0x94778FEA6FAF9FDF, 0x2B09DD7058EA4826, 
		0x677CD9716DE5C7BF, 0x49D5214FFFB2E6DD, 0x0360E83A466B273C, 0x1FC786AF4F7B7691, 
		0xA0B9D435783EA168, 0xD49F0C035F118CB6, 0x01205816C9D21D14, 0xAC2453DD7D8F3D98, 
		0x545217CC3F70AA64, 0x26B4028E9489C9C2, 0xDEC2469FD6765E3E, 0x04807D58036F7450, 
		0xE5F17292823DDB45, 0xF30B569B024A5860, 0x62DCFC3FA758AEFB, 0xE84CAD6C4E5E5AA1, 
		0xCCB81FCE556EA94B, 0x53B282AE7A74F908, 0x1B47FBF74C1402C1, 0x368EEBF39828049F, 
		0x7AFBEFF2AD278B06, 0xBE5E0A8CFE97CAED, 0xCFD8F7F413058E77, 0xF78B2BC301252C30, 
		0x4D555C17FCDD928D, 0x5F2F05467FC565F8, 0x24F4B2A21B30F3EA, 0x860DD6BBECB768AA, 
		0x4C750401350F8F99, 0x0000000000000000, 0xECCCD0344D312EF1, 0xB5231806BE220571, 
		0xC105C030990D28AF, 0x653C695DE25CFD97, 0x159ACC33C61CA419, 0xB89EC7F872418495, 
		0xA9847693B73254DC, 0x58CF90243AC13694, 0x59EFC832F3132B80, 0x5C4FED7C39AE42C4, 
		0x828DABE3EFD81CFA, 0xD13F294D95ACE5F2, 0x7D1B7A90E823D86A, 0xB643F03CF849224D, 
		0x3DF3F979D89DCB03, 0x7426D836272F2DDE, 0xDFE21E891FA4432A, 0x3A136C1B9D99986F, 
		0xFA36F43DCD46ADD4, 0xC025982650DF35BB, 0x856D3E81AADC4F96, 0xC4A5E57E53B041EB, 
		0x4708168B75BA4005, 0xAF44BBE73BE41AA4, 0x971767D029C4B8E3, 0xB9BE9FEEBB939981, 
		0x215497ECD18D9AAE, 0x316E7E91DD2C57F3, 0xCEF8AFE2DAD79363, 0x3853DC371220A247, 
		0x35EE03C9DE4323A3, 0xE6919AA8C456FC79, 0xE05157DC4880B201, 0x7BDBB7E464F59612, 
		0x127A59518318F775, 0x332ECEBD52956DDB, 0x8F30741D23BB9D1E, 0xD922D3FD93720D52, 
		0x7746300C61440AE2, 0x25D4EAB4D2E2EEFE, 0x75068020EEFD30CA, 0x135A01474ACAEA61, 
		0x304E268714FE4AE7, 0xA519F17BB283C82C, 0xDC82F6B359CF6416, 0x5BAF781E7CAA11A8, 
		0xB2C38D64FB26561D, 0x34CE5BDF17913EB7, 0x5D6FB56AF07C5FD0, 0x182713CD0A7F25FD, 
		0x9E2AC576E6C84D57, 0x9AAAB82EE5A73907, 0xA3D93C0F3E558654, 0x7E7B92AAAE48FF56, 
		0x872D8EAD256575BE, 0x41C8DBFFF96C0E7D, 0x99CA5014A3CC1E3B, 0x40E883E930BE1369, 
		0x1CA76E95091051AD, 0x4E35B42DBAB6B5B1, 0x05A0254ECABD6944, 0xE1710FCA8152AF15, 
		0xF22B0E8DCB984574, 0xB763A82A319B3F59, 0x63FCA4296E8AB3EF, 0x9D4A2D4CA0A36A6B, 
		0xE331BFE60EEB953D, 0xD5BF541596C391A2, 0xF5CB9BEF8E9C1618, 0x46284E9DBC685D11, 
		0x2074CFFA185F87BA, 0xBD3EE2B6B8FCEDD1, 0xAE64E3F1F23607B0, 0xFEB68965CE29D984, 
		0x55724FDAF6A2B770, 0x29496D5CD753720E, 0xA75941573D3AF204, 0x8E102C0BEA69800A, 
		0x111AB16BC573D049, 0xD7FFE439197AAB8A, 0xEFAC380E0B5A09CD, 0x48F579593660FBC9, 
		0x22347FD697E6BD92, 0x61BC1405E13389C7, 0x4AB5C975B9D9C1E1, 0x80CD1BCF606126D2, 
		0x7186FD78ED92449A, 0x93971A882AABCCB3, 0x88D0E17F66BFCE72, 0x27945A985D5BD4D6
	}, {
		0xDE553F8C05A811C8, 0x1906B59631B4F565, 0x436E70D6B1964FF7, 0x36D343CB8B1E9D85, 
		0x843DFACC858AAB5A, 0xFDFC95C299BFC7F9, 0x0F634BDEA1D51FA2, 0x6D458B3B76EFB3CD, 
		0x85C3F77CF8593F80, 0x3C91315FBE737CB2, 0x2148B03366ACE398, 0x18F8B8264C6761BF, 
		0xC830C1C495C9FB0F, 0x981A76102086A0AA, 0xAA16012142F35760, 0x35CC54060C763CF6, 
		0x42907D66CC45DB2D, 0x8203D44B965AF4BC, 0x3D6F3CEFC3A0E868, 0xBC73FF69D292BDA7, 
		0x8722ED0102E20A29, 0x8F8185E8CD34DEB7, 0x9B0561DDA7EE01D9, 0x5335A0193227FAD6, 
		0xC9CECC74E81A6FD5, 0x54F5832E5C2431EA, 0x99E47BA05D553470, 0xF7BEE756ACD226CE, 
		0x384E05A5571816FD, 0xD1367452A47D0E6A, 0xF29FDE1C386AD85B, 0x320C77316275F7CA, 
		0xD0C879E2D9AE9AB0, 0xDB7406C69110EF5D, 0x45505E51A2461011, 0xFC029872E46C5323, 
		0xFA3CB6F5F7BC0CC5, 0x031F17CD8768A173, 0xBD8DF2D9AF41297D, 0x9D3B4F5AB43E5E3F, 
		0x4071671B36FEEE84, 0x716207E7D3E3B83D, 0x48D20FF2F9283A1A, 0x27769EB4757CBC7E, 
		0x5C56EBC793F2E574, 0xA48B474F9EF5DC18, 0x52CBADA94FF46E0C, 0x60C7DA982D8199C6, 
		0x0E9D466EDC068B78, 0x4EEC2175EAF865FC, 0x550B8E9E21F7A530, 0x6B7BA5BC653FEC2B, 
		0x5EB7F1BA6949D0DD, 0x57EA94E3DB4C9099, 0xF640EAE6D101B214, 0xDD4A284182C0B0BB, 
		0xFF1D8FBF6304F250, 0xB8ACCB933BF9D7E8, 0xE8867C478EB68C4D, 0x3F8E2692391BDDC1, 
		0xCB2FD60912A15A7C, 0xAEC935DBAB983D2F, 0xF55FFD2B56691367, 0x80E2CE366CE1C115, 
		0x179BF3F8EDB27E1D, 0x01FE0DB07DD394DA, 0xDA8A0B76ECC37B87, 0x44AE53E1DF9584CB, 
		0xB310B4B77347A205, 0xDFAB323C787B8512, 0x3B511268D070B78E, 0x65E6E3D2B9396753, 
		0x6864B271E2574D58, 0x259784C98FC789D7, 0x02E11A7DFABB35A9, 0x8841A6DFA337158B, 
		0x7ADE78C39B5DCDD0, 0xB7CF804D9A2CC84A, 0x20B6BD831B7F7742, 0x75BD331D3A88D272, 
		0x418F6AAB4B2D7A5E, 0xD9951CBB6BABDAF4, 0xB6318DFDE7FF5C90, 0x1F389B112264AA83, 
		0x492C024284FBAEC0, 0xE33A0363C608F9A0, 0x2688930408AF28A4, 0xC7538A1A341CE4AD, 
		0x5DA8E677EE2171AE, 0x8C9E92254A5C7FC4, 0x63D8CD55AAE938B5, 0x29EBD8DAA97A3706, 
		0x959827B37BE88AA1, 0x1484E4356ADADF6E, 0xA7945082199D7D6B, 0xBF6CE8A455FA1CD4, 
		0x9CC542EAC9EDCAE5, 0x79C16F0E1C356CA3, 0x89BFAB6FDEE48151, 0xD4174D1830C5F0FF, 
		0x9258048415EB419D, 0x6139D72850520D1C, 0x6A85A80C18EC78F1, 0xCD11F88E0171059A, 
		0xCCEFF53E7CA29140, 0xD229639F2315AF19, 0x90B91EF9EF507434, 0x5977D28D074A1BE1, 
		0x311360FCE51D56B9, 0xC093A92D5A1F2F91, 0x1A19A25BB6DC5416, 0xEB996B8A09DE2D3E, 
		0xFEE3820F1ED7668A, 0xD7085AD5B7AD518C, 0x7FFF41890FE53345, 0xEC5948BD67DDE602, 
		0x2FD5F65DBAAA68E0, 0xA5754AFFE32648C2, 0xF8DDAC880D07396C, 0x6FA491468C548664, 
		0x0C7C5C1326BDBED1, 0x4A33158F03930FB3, 0x699ABFC19F84D982, 0xE4FA2054A80B329C, 
		0x6707F9AF438252FA, 0x08A368E9CFD6D49E, 0x47B1442C58FD25B8, 0xBBB3DC5EBC91769B, 
		0x1665FE489061EAC7, 0x33F27A811FA66310, 0x93A609346838D547, 0x30ED6D4C98CEC263, 
		0x1DD9816CD8DF9F2A, 0x94662A03063B1E7B, 0x83FDD9FBEB896066, 0x7B207573E68E590A, 
		0x5F49FC0A149A4407, 0x343259B671A5A82C, 0xFBC2BB458A6F981F, 0xC272B350A0A41A38, 
		0x3AAF1FD8ADA32354, 0x6CBB868B0B3C2717, 0xA2B569C88D2583FE, 0xF180C9D1BF027928, 
		0xAF37386BD64BA9F5, 0x12BACAB2790A8088, 0x4C0D3B0810435055, 0xB2EEB9070E9436DF, 
		0xC5B29067CEA7D104, 0xDCB425F1FF132461, 0x4F122CC5972BF126, 0xAC282FA651230886, 
		0xE7E537992F6393EF, 0xE61B3A2952B00735, 0x709C0A57AE302CE7, 0xE02514AE416058D3, 
		0xC44C9DD7B37445DE, 0x5A68C5408022BA92, 0x1C278CDCA50C0BF0, 0x6E5A9CF6F18712BE, 
		0x86DCE0B17F319EF3, 0x2D34EC2040115D49, 0x4BCD183F7E409B69, 0x2815D56AD4A9A3DC, 
		0x24698979F2141D0D, 0x0000000000000000, 0x1EC696A15FB73E59, 0xD86B110B16784E2E, 
		0x8E7F8858B0E74A6D, 0x063E2E8713D05FE6, 0xE2C40ED3BBDB6D7A, 0xB1F1AECA89FC97AC, 
		0xE1DB191E3CB3CC09, 0x6418EE62C4EAF389, 0xC6AD87AA49CF7077, 0xD6F65765CA7EC556, 
		0x9AFB6C6DDA3D9503, 0x7CE05644888D9236, 0x8D609F95378FEB1E, 0x23A9AA4E9C17D631, 
		0x6226C0E5D73AAC6F, 0x56149953A69F0443, 0xEEB852C09D66D3AB, 0x2B0AC2A753C102AF, 
		0x07C023376E03CB3C, 0x2CCAE1903DC2C993, 0xD3D76E2F5EC63BC3, 0x9E2458973356FF4C, 
		0xA66A5D32644EE9B1, 0x0A427294356DE137, 0x783F62BE61E6F879, 0x1344C70204D91452, 
		0x5B96C8F0FDF12E48, 0xA90916ECC59BF613, 0xBE92E5142829880E, 0x727D102A548B194E, 
		0x1BE7AFEBCB0FC0CC, 0x3E702B2244C8491B, 0xD5E940A84D166425, 0x66F9F41F3E51C620, 
		0xABE80C913F20C3BA, 0xF07EC461C2D1EDF2, 0xF361D3AC45B94C81, 0x0521394A94B8FE95, 
		0xADD622162CF09C5C, 0xE97871F7F3651897, 0xF4A1F09B2BBA87BD, 0x095D6559B2054044, 
		0x0BBC7F2448BE75ED, 0x2AF4CF172E129675, 0x157AE98517094BB4, 0x9FDA55274E856B96, 
		0x914713499283E0EE, 0xB952C623462A4332, 0x74433EAD475B46A8, 0x8B5EB112245FB4F8, 
		0xA34B6478F0F61724, 0x11A5DD7FFE6221FB, 0xC16DA49D27CCBB4B, 0x76A224D0BDE07301, 
		0x8AA0BCA2598C2022, 0x4DF336B86D90C48F, 0xEA67663A740DB9E4, 0xEF465F70E0B54771, 
		0x39B008152ACB8227, 0x7D1E5BF4F55E06EC, 0x105BD0CF83B1B521, 0x775C2960C033E7DB, 
		0x7E014C397236A79F, 0x811CC386113255CF, 0xEDA7450D1A0E72D8, 0x5889DF3D7A998F3B, 
		0x2E2BFBEDC779FC3A, 0xCE0EEF438619A4E9, 0x372D4E7BF6CD095F, 0x04DF34FAE96B6A4F, 
		0xF923A13870D4ADB6, 0xA1AA7E050A4D228D, 0xA8F71B5CB84862C9, 0xB52E9A306097FDE3, 
		0x0D8251A35B6E2A0B, 0x2257A7FEE1C442EB, 0x73831D9A29588D94, 0x51D4BA64C89CCF7F, 
		0x502AB7D4B54F5BA5, 0x97793DCE8153BF08, 0xE5042DE4D5D8A646, 0x9687307EFC802BD2, 
		0xA05473B5779EB657, 0xB4D097801D446939, 0xCFF0E2F3FBCA3033, 0xC38CBEE0DD778EE2, 
		0x464F499C252EB162, 0xCAD1DBB96F72CEA6, 0xBA4DD1EEC142E241, 0xB00FA37AF42F0376
	}, {
		0xCCE4CD3AA968B245, 0x089D5484E80B7FAF, 0x638246C1B3548304, 0xD2FE0EC8C2355492, 
		0xA7FBDF7FF2374EEE, 0x4DF1600C92337A16, 0x84E503EA523B12FB, 0x0790BBFD53AB0C4A, 
		0x198A780F38F6EA9D, 0x2AB30C8F55EC48CB, 0xE0F7FED6B2C49DB5, 0xB6ECF3F422CADBDC, 
		0x409C9A541358DF11, 0xD3CE8A56DFDE3FE3, 0xC3E9224312C8C1A0, 0x0D6DFA58816BA507, 
		0xDDF3E1B179952777, 0x04C02A42748BB1D9, 0x94C2ABFF9F2DECB8, 0x4F91752DA8F8ACF4, 
		0x78682BEFB169BF7B, 0xE1C77A48AF2FF6C4, 0x0C5D7EC69C80CE76, 0x4CC1E4928FD81167, 
		0xFEED3D24D9997B62, 0x518BB6DFC3A54A23, 0x6DBF2D26151F9B90, 0xB5BC624B05EA664F, 
		0xE86AAA525ACFE21A, 0x4801CED0FB53A0BE, 0xC91463E6C00868ED, 0x1027A815CD16FE43, 
		0xF67069A0319204CD, 0xB04CCC976C8ABCE7, 0xC0B9B3FC35E87C33, 0xF380C77C58F2DE65, 
		0x50BB3241DE4E2152, 0xDF93F490435EF195, 0xF1E0D25D62390887, 0xAF668BFB1A3C3141, 
		0xBC11B251F00A7291, 0x73A5EED47E427D47, 0x25BEE3F6EE4C3B2E, 0x43CC0BEB34786282, 
		0xC824E778DDE3039C, 0xF97D86D98A327728, 0xF2B043E24519B514, 0xE297EBF7880F4B57, 
		0x3A94A49A98FAB688, 0x868516CB68F0C419, 0xEFFA11AF0964EE50, 0xA4AB4EC0D517F37D, 
		0xA9C6B498547C567A, 0x8E18424F80FBBBB6, 0x0BCDC53BCF2BC23C, 0x137739AAEA3643D0, 
		0x2C1333EC1BAC2FF0, 0x8D48D3F0A7DB0625, 0x1E1AC3F26B5DE6D7, 0xF520F81F16B2B95E, 
		0x9F0F6EC450062E84, 0x0130849E1DEB6B71, 0xD45E31AB8C7533A9, 0x652279A2FD14E43F, 
		0x3209F01E70F1C927, 0xBE71A770CAC1A473, 0x0E3D6BE7A64B1894, 0x7EC8148CFF29D840, 
		0xCB7476C7FAC3BE0F, 0x72956A4A63A91636, 0x37F95EC21991138F, 0x9E3FEA5A4DED45F5, 
		0x7B38BA50964902E8, 0x222E580BBDE73764, 0x61E253E0899F55E6, 0xFC8D2805E352AD80, 
		0x35994BE3235AC56D, 0x09ADD01AF5E014DE, 0x5E8659A6780539C6, 0xB17C48097161D796, 
		0x026015213ACBD6E2, 0xD1AE9F77E515E901, 0xB7DC776A3F21B0AD, 0xABA6A1B96EB78098, 
		0x9BCF4486248D9F5D, 0x582666C536455EFD, 0xFDBDAC9BFEB9C6F1, 0xC47999BE4163CDEA, 
		0x765540081722A7EF, 0x3E548ED8EC710751, 0x3D041F67CB51BAC2, 0x7958AF71AC82D40A, 
		0x36C9DA5C047A78FE, 0xED9A048E33AF38B2, 0x26EE7249C96C86BD, 0x900281BDEBA65D61, 
		0x11172C8BD0FD9532, 0xEA0ABF73600434F8, 0x42FC8F75299309F3, 0x34A9CF7D3EB1AE1C, 
		0x2B838811480723BA, 0x5CE64C8742CEEF24, 0x1ADAE9B01FD6570E, 0x3C349BF9D6BAD1B3, 
		0x82453C891C7B75C0, 0x97923A40B80D512B, 0x4A61DBF1C198765C, 0xB48CE6D518010D3E, 
		0xCFB45C858E480FD6, 0xD933CBF30D1E96AE, 0xD70EA014AB558E3A, 0xC189376228031742, 
		0x9262949CD16D8B83, 0xEB3A3BED7DEF5F89, 0x49314A4EE6B8CBCF, 0xDCC3652F647E4C06, 
		0xDA635A4C2A3E2B3D, 0x470C21A940F3D35B, 0x315961A157D174B4, 0x6672E81DDA3459AC, 
		0x5B76F77A1165E36E, 0x445CB01667D36EC8, 0xC5491D205C88A69B, 0x456C34887A3805B9, 
		0xFFDDB9BAC4721013, 0x99AF51A71E4649BF, 0xA15BE01CBC7729D5, 0x52DB2760E485F7B0, 
		0x8C78576EBA306D54, 0xAE560F6507D75A30, 0x95F22F6182C687C9, 0x71C5FBF54489ABA5, 
		0xCA44F259E728D57E, 0x88B87D2CCEBBDC8D, 0xBAB18D32BE4A15AA, 0x8BE8EC93E99B611E, 
		0x17B713E89EBDF209, 0xB31C5D284BAA0174, 0xEECA9531148F8521, 0xB8D198138481C348, 
		0x8988F9B2D350B7FC, 0xB9E11C8D996AA839, 0x5A4673E40C8E881F, 0x1687977683569978, 
		0xBF4123EED72ACF02, 0x4EA1F1B3B513C785, 0xE767452BE16F91FF, 0x7505D1B730021A7C, 
		0xA59BCA5EC8FC980C, 0xAD069EDA20F7E7A3, 0x38F4B1BBA231606A, 0x60D2D77E94743E97, 
		0x9AFFC0183966F42C, 0x248E6768F3A7505F, 0xCDD449A4B483D934, 0x87B59255751BAF68, 
		0x1BEA6D2E023D3C7F, 0x6B1F12455B5FFCAB, 0x743555292DE9710D, 0xD8034F6D10F5FDDF, 
		0xC6198C9F7BA81B08, 0xBB8109ACA3A17EDB, 0xFA2D1766AD12CABB, 0xC729080166437079, 
		0x9C5FFF7B77269317, 0x0000000000000000, 0x15D706C9A47624EB, 0x6FDF38072FD44D72, 
		0x5FB6DD3865EE52B7, 0xA33BF53D86BCFF37, 0xE657C1B5FC84FA8E, 0xAA962527735CEBE9, 
		0x39C43525BFDA0B1B, 0x204E4D2A872CE186, 0x7A083ECE8BA26999, 0x554B9C9DB72EFBFA, 
		0xB22CD9B656416A05, 0x96A2BEDEA5E63A5A, 0x802529A826B0A322, 0x8115AD363B5BC853, 
		0x8375B81701901EB1, 0x3069E53F4A3A1FC5, 0xBD2136CFEDE119E0, 0x18BAFC91251D81EC, 
		0x1D4A524D4C7D5B44, 0x05F0AEDC6960DAA8, 0x29E39D3072CCF558, 0x70F57F6B5962C0D4, 
		0x989FD53903AD22CE, 0xF84D024797D91C59, 0x547B1803AAC5908B, 0xF0D056C37FD263F6, 
		0xD56EB535919E58D8, 0x1C7AD6D351963035, 0x2E7326CD2167F912, 0xAC361A443D1C8CD2, 
		0x697F076461942A49, 0x4B515F6FDC731D2D, 0x8AD8680DF4700A6F, 0x41AC1ECA0EB3B460, 
		0x7D988533D80965D3, 0xA8F6300649973D0B, 0x7765C4960AC9CC9E, 0x7CA801ADC5E20EA2, 
		0xDEA3700E5EB59AE4, 0xA06B6482A19C42A4, 0x6A2F96DB46B497DA, 0x27DEF6D7D487EDCC, 
		0x463CA5375D18B82A, 0xA6CB5BE1EFDC259F, 0x53EBA3FEF96E9CC1, 0xCE84D81B93A364A7, 
		0xF4107C810B59D22F, 0x333974806D1AA256, 0x0F0DEF79BBA073E5, 0x231EDC95A00C5C15, 
		0xE437D494C64F2C6C, 0x91320523F64D3610, 0x67426C83C7DF32DD, 0x6EEFBC99323F2603, 
		0x9D6F7BE56ACDF866, 0x5916E25B2BAE358C, 0x7FF89012E2C2B331, 0x035091BF2720BD93, 
		0x561B0D22900E4669, 0x28D319AE6F279E29, 0x2F43A2533C8C9263, 0xD09E1BE9F8FE8270, 
		0xF740ED3E2C796FBC, 0xDB53DED237D5404C, 0x62B2C25FAEBFE875, 0x0AFD41A5D2C0A94D, 
		0x6412FD3CE0FF8F4E, 0xE3A76F6995E42026, 0x6C8FA9B808F4F0E1, 0xC2D9A6DD0F23AAD1, 
		0x8F28C6D19D10D0C7, 0x85D587744FD0798A, 0xA20B71A39B579446, 0x684F83FA7C7F4138, 
		0xE507500ADBA4471D, 0x3F640A46F19A6C20, 0x1247BD34F7DD28A1, 0x2D23B77206474481, 
		0x93521002CC86E0F2, 0x572B89BC8DE52D18, 0xFB1D93F8B0F9A1CA, 0xE95A2ECC4724896B, 
		0x3BA420048511DDF9, 0xD63E248AB6BEE54B, 0x5DD6C8195F258455, 0x06A03F634E40673B, 
		0x1F2A476C76B68DA6, 0x217EC9B49AC78AF7, 0xECAA80102E4453C3, 0x14E78257B99D4F9A
	}, {
		0x20329B2CC87BBA05, 0x4F5EB6F86546A531, 0xD4F44775F751B6B1, 0x8266A47B850DFA8B, 
		0xBB986AA15A6CA985, 0xC979EB08F9AE0F99, 0x2DA6F447A2375EA1, 0x1E74275DCD7D8576, 
		0xBC20180A800BC5F8, 0xB4A2F701B2DC65BE, 0xE726946F981B6D66, 0x48E6C453BF21C94C, 
		0x42CAD9930F0A4195, 0xEFA47B64AACCCD20, 0x71180A8960409A42, 0x8BB3329BF6A44E0C, 
		0xD34C35DE2D36DACC, 0xA92F5B7CBC23DC96, 0xB31A85AA68BB09C3, 0x13E04836A73161D2, 
		0xB24DFC4129C51D02, 0x8AE44B70B7DA5ACD, 0xE671ED84D96579A7, 0xA4BB3417D66F3832, 
		0x4572AB38D56D2DE8, 0xB1B47761EA47215C, 0xE81C09CF70ABA15D, 0xFFBDB872CE7F90AC, 
		0xA8782297FD5DC857, 0x0D946F6B6A4CE4A4, 0xE4DF1F4F5B995138, 0x9EBC71EDCA8C5762, 
		0x0A2C1DC0B02B88D9, 0x3B503C115D9D7B91, 0xC64376A8111EC3A2, 0xCEC199A323C963E4, 
		0xDC76A87EC58616F7, 0x09D596E073A9B487, 0x14583A9D7D560DAF, 0xF4C6DC593F2A0CB4, 
		0xDD21D19584F80236, 0x4A4836983DDDE1D3, 0xE58866A41AE745F9, 0xF591A5B27E541875, 
		0x891DC05074586693, 0x5B068C651810A89E, 0xA30346BC0C08544F, 0x3DBF3751C684032D, 
		0x2A1E86EC785032DC, 0xF73F5779FCA830EA, 0xB60C05CA30204D21, 0x0CC316802B32F065, 
		0x8770241BDD96BE69, 0xB861E18199EE95DB, 0xF805CAD91418FCD1, 0x29E70DCCBBD20E82, 
		0xC7140F435060D763, 0x0F3A9DA0E8B0CC3B, 0xA2543F574D76408E, 0xBD7761E1C175D139, 
		0x4B1F4F737CA3F512, 0x6DC2DF1F2FC137AB, 0xF1D05C3967B14856, 0xA742BF3715ED046C, 
		0x654030141D1697ED, 0x07B872ABDA676C7D, 0x3CE84EBA87FA17EC, 0xC1FB0403CB79AFDF, 
		0x3E46BC7105063F73, 0x278AE987121CD678, 0xA1ADB4778EF47CD0, 0x26DD906C5362C2B9, 
		0x05168060589B44E2, 0xFBFC41F9D79AC08F, 0x0E6DE44BA9CED8FA, 0x9FEB08068BF243A3, 
		0x7B341749D06B129B, 0x229C69E74A87929A, 0xE09EE6C4427C011B, 0x5692E30E725C4C3A, 
		0xDA99A33E5E9F6E4B, 0x353DD85AF453A36B, 0x25241B4C90E0FEE7, 0x5DE987258309D022, 
		0xE230140FC0802984, 0x93281E86A0C0B3C6, 0xF229D719A4337408, 0x6F6C2DD4AD3D1F34, 
		0x8EA5B2FBAE3F0AEE, 0x8331DD90C473EE4A, 0x346AA1B1B52DB7AA, 0xDF8F235E06042AA9, 
		0xCC6F6B68A1354B7B, 0x6C95A6F46EBF236A, 0x52D31A856BB91C19, 0x1A35DED6D498D555, 
		0xF37EAEF2E54D60C9, 0x72E181A9A3C2A61C, 0x98537AAD51952FDE, 0x16F6C856FFAA2530, 
		0xD960281E9D1D5215, 0x3A0745FA1CE36F50, 0x0B7B642BF1559C18, 0x59A87EAE9AEC8001, 
		0x5E100C05408BEC7C, 0x0441F98B19E55023, 0xD70DCC5534D38AEF, 0x927F676DE1BEA707, 
		0x9769E70DB925E3E5, 0x7A636EA29115065A, 0x468B201816EF11B6, 0xAB81A9B73EDFF409, 
		0xC0AC7DE88A07BB1E, 0x1F235EB68C0391B7, 0x6056B074458DD30F, 0xBE8EEAC102F7ED67, 
		0xCD381283E04B5FBA, 0x5CBEFECEC277C4E3, 0xD21B4C356C48CE0D, 0x1019C31664B35D8C, 
		0x247362A7D19EEA26, 0xEBE582EFB3299D03, 0x02AEF2CB82FC289F, 0x86275DF09CE8AAA8, 
		0x28B07427FAAC1A43, 0x38A9B7319E1F47CF, 0xC82E92E3B8D01B58, 0x06EF0B409B1978BC, 
		0x62F842BFC771FB90, 0x9904034610EB3B1F, 0xDED85AB5477A3E68, 0x90D195A663428F98, 
		0x5384636E2AC708D8, 0xCBD719C37B522706, 0xAE9729D76644B0EB, 0x7C8C65E20A0C7EE6, 
		0x80C856B007F1D214, 0x8C0B40302CC32271, 0xDBCEDAD51FE17A8A, 0x740E8AE938DBDEA0, 
		0xA615C6DC549310AD, 0x19CC55F6171AE90B, 0x49B1BDB8FE5FDD8D, 0xED0A89AF2830E5BF, 
		0x6A7AADB4F5A65BD6, 0x7E22972988F05679, 0xF952B3325566E810, 0x39FECEDADF61530E, 
		0x6101C99F04F3C7CE, 0x2E5F7F6761B562FF, 0xF08725D226CF5C97, 0x63AF3B54860FEF51, 
		0x8FF2CB10EF411E2F, 0x884AB9BB35267252, 0x4DF04433E7BA8DAE, 0x9AFD8866D3690741, 
		0x66B9BB34DE94ABB3, 0x9BAAF18D92171380, 0x543C11C5F0A064A5, 0x17A1B1BDBED431F1, 
		0xB5F58EEAF3A2717F, 0xC355F6C849858740, 0xEC5DF044694EF17E, 0xD83751F5DC6346D4, 
		0xFC4433520DFDACF2, 0x0000000000000000, 0x5A51F58E596EBC5F, 0x3285AAF12E34CF16, 
		0x8D5C39DB6DBD36B0, 0x12B731DDE64F7513, 0x94906C2D7AA7DFBB, 0x302B583AACC8E789, 
		0x9D45FACD090E6B3C, 0x2165E2C78905AEC4, 0x68D45F7F775A7349, 0x189B2C1D5664FDCA, 
		0xE1C99F2F030215DA, 0x6983269436246788, 0x8489AF3B1E148237, 0xE94B702431D5B59C, 
		0x33D2D31A6F4ADBD7, 0xBFD9932A4389F9A6, 0xB0E30E8AAB39359D, 0xD1E2C715AFCAF253, 
		0x150F43763C28196E, 0xC4ED846393E2EB3D, 0x03F98B20C3823C5E, 0xFD134AB94C83B833, 
		0x556B682EB1DE7064, 0x36C4537A37D19F35, 0x7559F30279A5CA61, 0x799AE58252973A04, 
		0x9C12832648707FFD, 0x78CD9C6913E92EC5, 0x1D8DAC7D0EFFB928, 0x439DA0784E745554, 
		0x413352B3CC887DCB, 0xBACF134A1B12BD44, 0x114EBAFD25CD494D, 0x2F08068C20CB763E, 
		0x76A07822BA27F63F, 0xEAB2FB04F25789C2, 0xE3676DE481FE3D45, 0x1B62A73D95E6C194, 
		0x641749FF5C68832C, 0xA5EC4DFC97112CF3, 0xF6682E92BDD6242B, 0x3F11C59A44782BB2, 
		0x317C21D1EDB6F348, 0xD65AB5BE75AD9E2E, 0x6B2DD45FB4D84F17, 0xFAAB381296E4D44E, 
		0xD0B5BEFEEEB4E692, 0x0882EF0B32D7A046, 0x512A91A5A83B2047, 0x963E9EE6F85BF724, 
		0x4E09CF132438B1F0, 0x77F701C9FB59E2FE, 0x7DDB1C094B726A27, 0x5F4775EE01F5F8BD, 
		0x9186EC4D223C9B59, 0xFEEAC1998F01846D, 0xAC39DB1CE4B89874, 0xB75B7C21715E59E0, 
		0xAFC0503C273AA42A, 0x6E3B543FEC430BF5, 0x704F7362213E8E83, 0x58FF0745DB9294C0, 
		0x67EEC2DF9FEABF72, 0xA0FACD9CCF8A6811, 0xB936986AD890811A, 0x95C715C63BD9CB7A, 
		0xCA8060283A2C33C7, 0x507DE84EE9453486, 0x85DED6D05F6A96F6, 0x1CDAD5964F81ADE9, 
		0xD5A33E9EB62FA270, 0x40642B588DF6690A, 0x7F75EEC2C98E42B8, 0x2CF18DACE3494A60, 
		0x23CB100C0BF9865B, 0xEEF3028FEBB2D9E1, 0x4425D2D394133929, 0xAAD6D05C7FA1E0C8, 
		0xAD6EA2F7A5C68CB5, 0xC2028F2308FB9381, 0x819F2F5B468FC6D5, 0xC5BAFD88D29CFFFC, 
		0x47DC59F357910577, 0x2B49FF07392E261D, 0x57C59AE5332258FB, 0x73B6F842E2BCB2DD, 
		0xCF96E04862B77725, 0x4CA73DD8A6C4996F, 0x015779EB417E14C1, 0x37932A9176AF8BF4
	}, {
		0x190A2C9B249DF23E, 0x2F62F8B62263E1E9, 0x7A7F754740993655, 0x330B7BA4D5564D9F, 
		0x4C17A16A46672582, 0xB22F08EB7D05F5B8, 0x535F47F40BC148CC, 0x3AEC5D27D4883037, 
		0x10ED0A1825438F96, 0x516101F72C233D17, 0x13CC6F949FD04EAE, 0x739853C441474BFD, 
		0x653793D90D3F5B1B, 0x5240647B96B0FC2F, 0x0C84890AD27623E0, 0xD7189B32703AAEA3, 
		0x2685DE3523BD9C41, 0x99317C5B11BFFEFA, 0x0D9BAA854F079703, 0x70B93648FBD48AC5, 
		0xA80441FCE30BC6BE, 0x7287704BDC36FF1E, 0xB65384ED33DC1F13, 0xD36417343EE34408, 
		0x39CD38AB6E1BF10F, 0x5AB861770A1F3564, 0x0EBACF09F594563B, 0xD04572B884708530, 
		0x3CAE9722BDB3AF47, 0x4A556B6F2F5CBAF2, 0xE1704F1F76C4BD74, 0x5EC4ED7144C6DFCF, 
		0x16AFC01D4C7810E6, 0x283F113CD629CA7A, 0xAF59A8761741ED2D, 0xEED5A3991E215FAC, 
		0x3BF37EA849F984D4, 0xE413E096A56CE33C, 0x2C439D3A98F020D1, 0x637559DC6404C46B, 
		0x9E6C95D1E5F5D569, 0x24BB9836045FE99A, 0x44EFA466DAC8ECC9, 0xC6EAB2A5C80895D6, 
		0x803B50C035220CC4, 0x0321658CBA93C138, 0x8F9EBC465DC7EE1C, 0xD15A5137190131D3, 
		0x0FA5EC8668E5E2D8, 0x91C979578D1037B1, 0x0642CA05693B9F70, 0xEFCA80168350EB4F, 
		0x38D21B24F36A45EC, 0xBEAB81E1AF73D658, 0x8CBFD9CAE7542F24, 0xFD19CC0D81F11102, 
		0x0AC6430FBB4DBC90, 0x1D76A09D6A441895, 0x2A01573FF1CBBFA1, 0xB572E161894FDE2B, 
		0x8124734FA853B827, 0x614B1FDF43E6B1B0, 0x68AC395C4238CC18, 0x21D837BFD7F7B7D2, 
		0x20C714304A860331, 0x5CFAAB726324AA14, 0x74C5BA4EB50D606E, 0xF3A3030474654739, 
		0x23E671BCF015C209, 0x45F087E947B9582A, 0xD8BD77B418DF4C7B, 0xE06F6C90EBB50997, 
		0x0BD96080263C0873, 0x7E03F9410E40DCFE, 0xB8E94BE4C6484928, 0xFB5B0608E8CA8E72, 
		0x1A2B49179E0E3306, 0x4E29E76961855059, 0x4F36C4E6FCF4E4BA, 0x49740EE395CF7BCA, 
		0xC2963EA386D17F7D, 0x90D65AD810618352, 0x12D34C1B02A1FA4D, 0xFA44258775BB3A91, 
		0x18150F14B9EC46DD, 0x1491861E6B9A653D, 0x9A1019D7AB2C3FC2, 0x3668D42D06FE13D7, 
		0xDCC1FBB25606A6D0, 0x969490DD795A1C22, 0x3549B1A1BC6DD2EF, 0xC94F5E23A0ED770E, 
		0xB9F6686B5B39FDCB, 0xC4D4F4A6EFEAE00D, 0xE732851A1FFF2204, 0x94AAD6DE5EB869F9, 
		0x3F8FF2AE07206E7F, 0xFE38A9813B62D03A, 0xA7A1AD7A8BEE2466, 0x7B6056C8DDE882B6, 
		0x302A1E286FC58CA7, 0x8DA0FA457A259BC7, 0xB3302B64E074415B, 0x5402AE7EFF8B635F, 
		0x08F8050C9CAFC94B, 0xAE468BF98A3059CE, 0x88C355CCA98DC58F, 0xB10E6D67C7963480, 
		0xBAD70DE7E1AA3CF3, 0xBFB4A26E320262BB, 0xCB711820870F02D5, 0xCE12B7A954A75C9D, 
		0x563CE87DD8691684, 0x9F73B65E7884618A, 0x2B1E74B06CBA0B42, 0x47CEC1EA605B2DF1, 
		0x1C698312F735AC76, 0x5FDBCEFED9B76B2C, 0x831A354C8FB1CDFC, 0x820516C312C0791F, 
		0xB74CA762AEADABF0, 0xFC06EF821C80A5E1, 0x5723CBF24518A267, 0x9D4DF05D5F661451, 
		0x588627742DFD40BF, 0xDA8331B73F3D39A0, 0x17B0E392D109A405, 0xF965400BCF28FBA9, 
		0x7C3DBF4229A2A925, 0x023E460327E275DB, 0x6CD0B55A0CE126B3, 0xE62DA695828E96E7, 
		0x42AD6E63B3F373B9, 0xE50CC319381D57DF, 0xC5CBD729729B54EE, 0x46D1E265FD2A9912, 
		0x6428B056904EEFF8, 0x8BE23040131E04B7, 0x6709D5DA2ADD2EC0, 0x075DE98AF44A2B93, 
		0x8447DCC67BFBE66F, 0x6616F655B7AC9A23, 0xD607B8BDED4B1A40, 0x0563AF89D3A85E48, 
		0x3DB1B4AD20C21BA4, 0x11F22997B8323B75, 0x292032B34B587E99, 0x7F1CDACE9331681D, 
		0x8E819FC9C0B65AFF, 0xA1E3677FE2D5BB16, 0xCD33D225EE349DA5, 0xD9A2543B85AEF898, 
		0x795E10CBFA0AF76D, 0x25A4BBB9992E5D79, 0x78413344677B438E, 0xF0826688CEF68601, 
		0xD27B34BBA392F0EB, 0x551D8DF162FAD7BC, 0x1E57C511D0D7D9AD, 0xDEFFBDB171E4D30B, 
		0xF4FEEA8E802F6CAA, 0xA480C8F6317DE55E, 0xA0FC44F07FA40FF5, 0x95B5F551C3C9DD1A, 
		0x22F952336D6476EA, 0x0000000000000000, 0xA6BE8EF5169F9085, 0xCC2CF1AA73452946, 
		0x2E7DDB39BF12550A, 0xD526DD3157D8DB78, 0x486B2D6C08BECF29, 0x9B0F3A58365D8B21, 
		0xAC78CDFAADD22C15, 0xBC95C7E28891A383, 0x6A927F5F65DAB9C3, 0xC3891D2C1BA0CB9E, 
		0xEAA92F9F50F8B507, 0xCF0D9426C9D6E87E, 0xCA6E3BAF1A7EB636, 0xAB25247059980786, 
		0x69B31AD3DF4978FB, 0xE2512A93CC577C4C, 0xFF278A0EA61364D9, 0x71A615C766A53E26, 
		0x89DC764334FC716C, 0xF87A638452594F4A, 0xF2BC208BE914F3DA, 0x8766B94AC1682757, 
		0xBBC82E687CDB8810, 0x626A7A53F9757088, 0xA2C202F358467A2E, 0x4D0882E5DB169161, 
		0x09E7268301DE7DA8, 0xE897699C771AC0DC, 0xC8507DAC3D9CC3ED, 0xC0A878A0A1330AA6, 
		0x978BB352E42BA8C1, 0xE9884A13EA6B743F, 0x279AFDBABECC28A2, 0x047C8C064ED9EAAB, 
		0x507E2278B15289F4, 0x599904FBB08CF45C, 0xBD8AE46D15E01760, 0x31353DA7F2B43844, 
		0x8558FF49E68A528C, 0x76FBFC4D92EF15B5, 0x3456922E211C660C, 0x86799AC55C1993B4, 
		0x3E90D1219A51DA9C, 0x2D5CBEB505819432, 0x982E5FD48CCE4A19, 0xDB9C1238A24C8D43, 
		0xD439FEBECAA96F9B, 0x418C0BEF0960B281, 0x158EA591F6EBD1DE, 0x1F48E69E4DA66D4E, 
		0x8AFD13CF8E6FB054, 0xF5E1C9011D5ED849, 0xE34E091C5126C8AF, 0xAD67EE7530A398F6, 
		0x43B24DEC2E82C75A, 0x75DA99C1287CD48D, 0x92E81CDB3783F689, 0xA3DD217CC537CECD, 
		0x60543C50DE970553, 0x93F73F54AAF2426A, 0xA91B62737E7A725D, 0xF19D4507538732E2, 
		0x77E4DFC20F9EA156, 0x7D229CCDB4D31DC6, 0x1B346A98037F87E5, 0xEDF4C615A4B29E94, 
		0x4093286094110662, 0xB0114EE85AE78063, 0x6FF1D0D6B672E78B, 0x6DCF96D591909250, 
		0xDFE09E3EEC9567E8, 0x3214582B4827F97C, 0xB46DC2EE143E6AC8, 0xF6C0AC8DA7CD1971, 
		0xEBB60C10CD8901E4, 0xF7DF8F023ABCAD92, 0x9C52D3D2C217A0B2, 0x6B8D5CD0F8AB0D20, 
		0x3777F7A29B8FA734, 0x011F238F9D71B4E3, 0xC1B75B2F3C42BE45, 0x5DE588FDFE551EF7, 
		0x6EEEF3592B035368, 0xAA3A07FFC4E9B365, 0xECEBE59A39C32A77, 0x5BA742F8976E8187, 
		0x4B4A48E0B22D0E11, 0xDDDED83DCB771233, 0xA59FEB79AC0C51BD, 0xC7F5912A55792135
	}, {
		0x6D6AE04668A9B08A, 0x3AB3F04B0BE8C743, 0xE51E166B54B3C908, 0xBE90A9EB35C2F139, 
		0xB2C7066637F2BEC1, 0xAA6945613392202C, 0x9A28C36F3B5201EB, 0xDDCE5A93AB536994, 
		0x0E34133EF6382827, 0x52A02BA1EC55048B, 0xA2F88F97C4B2A177, 0x8640E513CA2251A5, 
		0xCDF1D36258137622, 0xFE6CB708DEDF8DDB, 0x8A174A9EC8121E5D, 0x679896036B81560E, 
		0x59ED033395795FEE, 0x1DD778AB8B74EDAF, 0xEE533EF92D9F926D, 0x2A8C79BAF8A8D8F5, 
		0x6BCF398E69B119F6, 0xE20491742FAFDD95, 0x276488E0809C2AEC, 0xEA955B82D88F5CCE, 
		0x7102C63A99D9E0C4, 0xF9763017A5C39946, 0x429FA2501F151B3D, 0x4659C72BEA05D59E, 
		0x984B7FDCCF5A6634, 0xF742232953FBB161, 0x3041860E08C021C7, 0x747BFD9616CD9386, 
		0x4BB1367192312787, 0x1B72A1638A6C44D3, 0x4A0E68A6E8359A66, 0x169A5039F258B6CA, 
		0xB98A2EF44EDEE5A4, 0xD9083FE85E43A737, 0x967F6CE239624E13, 0x8874F62D3C1A7982, 
		0x3C1629830AF06E3F, 0x9165EBFD427E5A8E, 0xB5DD81794CEEAA5C, 0x0DE8F15A7834F219, 
		0x70BD98EDE3DD5D25, 0xACCC9CA9328A8950, 0x56664EDA1945CA28, 0x221DB34C0F8859AE, 
		0x26DBD637FA98970D, 0x1ACDFFB4F068F932, 0x4585254F64090FA0, 0x72DE245E17D53AFA, 
		0x1546B25D7C546CF4, 0x207E0FFFFB803E71, 0xFAAAD2732BCF4378, 0xB462DFAE36EA17BD, 
		0xCF926FD1AC1B11FD, 0xE0672DC7DBA7BA4A, 0xD3FA49AD5D6B41B3, 0x8BA81449B216A3BC, 
		0x14F9EC8A0650D115, 0x40FC1EE3EB1D7CE2, 0x23A2ED9B758CE44F, 0x782C521B14FDDC7E, 
		0x1C68267CF170504E, 0xBCF31558C1CA96E6, 0xA781B43B4BA6D235, 0xF6FD7DFE29FF0C80, 
		0xB0A4BAD5C3FAD91E, 0xD199F51EA963266C, 0x414340349119C103, 0x5405F269ED4DADF7, 
		0xABD61BB649969DCD, 0x6813DBEAE7BDC3C8, 0x65FB2AB09F8931D1, 0xF1E7FAE152E3181D, 
		0xC1A67CEF5A2339DA, 0x7A4FEEA8E0F5BBA1, 0x1E0B9ACF05783791, 0x5B8EBF8061713831, 
		0x80E53CDBCB3AF8D9, 0x7E898BD315E57502, 0xC6BCFBF0213F2D47, 0x95A38E86B76E942D, 
		0x092E94218D243CBA, 0x8339DEBF453622E7, 0xB11BE402B9FE64FF, 0x57D9100D634177C9, 
		0xCC4E8DB52217CBC3, 0x3B0CAE9C71EC7AA2, 0xFB158CA451CBFE99, 0x2B33276D82AC6514, 
		0x01BF5ED77A04BDE1, 0xC5601994AF33F779, 0x75C4A3416CC92E67, 0xF3844652A6EB7FC2, 
		0x3487E375FDD0EF64, 0x18AE430704609EED, 0x4D14EFB993298EFB, 0x815A620CB13E4538, 
		0x125C354207487869, 0x9EEEA614CE42CF48, 0xCE2D3106D61FAC1C, 0xBBE99247BAD6827B, 
		0x071A871F7B1C149D, 0x2E4A1CC10DB81656, 0x77A71FF298C149B8, 0x06A5D9C80118A97C, 
		0xAD73C27E488E34B1, 0x443A7B981E0DB241, 0xE3BBCFA355AB6074, 0x0AF276450328E684, 
		0x73617A896DD1871B, 0x58525DE4EF7DE20F, 0xB7BE3DCAB8E6CD83, 0x19111DD07E64230C, 
		0x842359A03E2A367A, 0x103F89F1F3401FB6, 0xDC710444D157D475, 0xB835702334DA5845, 
		0x4320FC876511A6DC, 0xD026ABC9D3679B8D, 0x17250EEE885C0B2B, 0x90DAB52A387AE76F, 
		0x31FED8D972C49C26, 0x89CBA8FA461EC463, 0x2FF5421677BCABB7, 0x396F122F85E41D7D, 
		0xA09B332430BAC6A8, 0xC888E8CED7070560, 0xAEAF201AC682EE8F, 0x1180D7268944A257, 
		0xF058A43628E7A5FC, 0xBD4C4B8FBBCE2B07, 0xA1246DF34ABE7B49, 0x7D5569B79BE9AF3C, 
		0xA9B5A705BD9EFA12, 0xDB6B835BAA4BC0E8, 0x05793BAC8F147342, 0x21C1512881848390, 
		0xFDB0556C50D357E5, 0x613D4FCB6A99FF72, 0x03DCE2648E0CDA3E, 0xE949B9E6568386F0, 
		0xFC0F0BBB2AD7EA04, 0x6A70675913B5A417, 0x7F36D5046FE1C8E3, 0x0C57AF8D02304FF8, 
		0x32223ABDFCC84618, 0x0891CAF6F720815B, 0xA63EEAEC31A26FD4, 0x2507345374944D33, 
		0x49D28AC266394058, 0xF5219F9AA7F3D6BE, 0x2D96FEA583B4CC68, 0x5A31E1571B7585D0, 
		0x8ED12FE53D02D0FE, 0xDFADE6205F5B0E4B, 0x4CABB16EE92D331A, 0x04C6657BF510CEA3, 
		0xD73C2CD6A87B8F10, 0xE1D87310A1A307AB, 0x6CD5BE9112AD0D6B, 0x97C032354366F3F2, 
		0xD4E0CEB22677552E, 0x0000000000000000, 0x29509BDE76A402CB, 0xC27A9E8BD42FE3E4, 
		0x5EF7842CEE654B73, 0xAF107ECDBC86536E, 0x3FCACBE784FCB401, 0xD55F90655C73E8CF, 
		0xE6C2F40FDABF1336, 0xE8F6E7312C873B11, 0xEB2A0555A28BE12F, 0xE4A148BC2EB774E9, 
		0x9B979DB84156BC0A, 0x6EB60222E6A56AB4, 0x87FFBBC4B026EC44, 0xC703A5275B3B90A6, 
		0x47E699FC9001687F, 0x9C8D1AA73A4AA897, 0x7CEA3760E1ED12DD, 0x4EC80DDD1D2554C5, 
		0x13E36B957D4CC588, 0x5D2B66486069914D, 0x92B90999CC7280B0, 0x517CC9C56259DEB5, 
		0xC937B619AD03B881, 0xEC30824AD997F5B2, 0xA45D565FC5AA080B, 0xD6837201D27F32F1, 
		0x635EF3789E9198AD, 0x531F75769651B96A, 0x4F77530A6721E924, 0x486DD4151C3DFDB9, 
		0x5F48DAFB9461F692, 0x375B011173DC355A, 0x3DA9775470F4D3DE, 0x8D0DCD81B30E0AC0, 
		0x36E45FC609D888BB, 0x55BAACBE97491016, 0x8CB29356C90AB721, 0x76184125E2C5F459, 
		0x99F4210BB55EDBD5, 0x6F095CF59CA1D755, 0x9F51F8C3B44672A9, 0x3538BDA287D45285, 
		0x50C39712185D6354, 0xF23B1885DCEFC223, 0x79930CCC6EF9619F, 0xED8FDC9DA3934853, 
		0xCB540AAA590BDF5E, 0x5C94389F1A6D2CAC, 0xE77DAAD8A0BBAED7, 0x28EFC5090CA0BF2A, 
		0xBF2FF73C4FC64CD8, 0xB37858B14DF60320, 0xF8C96EC0DFC724A7, 0x828680683F329F06, 
		0x941CD051CD6A29CC, 0xC3C5C05CAE2B5E05, 0xB601631DC2E27062, 0xC01922382027843B, 
		0x24B86A840E90F0D2, 0xD245177A276FFC52, 0x0F8B4DE98C3C95C6, 0x3E759530FEF809E0, 
		0x0B4D2892792C5B65, 0xC4DF4743D5374A98, 0xA5E20888BFAEB5EA, 0xBA56CC90C0D23F9A, 
		0x38D04CF8FFE0A09C, 0x62E1ADAFE495254C, 0x0263BCB3F40867DF, 0xCAEB547D230F62BF, 
		0x6082111C109D4293, 0xDAD4DD8CD04F7D09, 0xEFEC602E579B2F8C, 0x1FB4C4187F7C8A70, 
		0xFFD3E9DFA4DB303A, 0x7BF0B07F9AF10640, 0xF49EC14DDDF76B5F, 0x8F6E713247066D1F, 
		0x339D646A86CCFBF9, 0x64447467E58D8C30, 0x2C29A072F9B07189, 0xD8B7613F24471AD6, 
		0x6627C8D41185EBEF, 0xA347D140BEB61C96, 0xDE12B8F7255FB3AA, 0x9D324470404E1576, 
		0x9306574EB6763D51, 0xA80AF9D2C79A47F3, 0x859C0777442E8B9B, 0x69AC853D9DB97E29
	}, {
		0xC3407DFC2DE6377E, 0x5B9E93EEA4256F77, 0xADB58FDD50C845E0, 0x5219FF11A75BED86, 
		0x356B61CFD90B1DE9, 0xFB8F406E25ABE037, 0x7A5A0231C0F60796, 0x9D3CD216E1F5020B, 
		0x0C6550FB6B48D8F3, 0xF57508C427FF1C62, 0x4AD35FFA71CB407D, 0x6290A2DA1666AA6D, 
		0xE284EC2349355F9F, 0xB3C307C53D7C84EC, 0x05E23C0468365A02, 0x190BAC4D6C9EBFA8, 
		0x94BBBEE9E28B80FA, 0xA34FC777529CB9B5, 0xCC7B39F095BCD978, 0x2426ADDB0CE532E3, 
		0x7E79329312CE4FC7, 0xAB09A72EEBEC2917, 0xF8D15499F6B9D6C2, 0x1A55B8BABF8C895D, 
		0xDB8ADD17FB769A85, 0xB57F2F368658E81B, 0x8ACD36F18F3F41F6, 0x5CE3B7BBA50F11D3, 
		0x114DCC14D5EE2F0A, 0xB91A7FCDED1030E8, 0x81D5425FE55DE7A1, 0xB6213BC1554ADEEE, 
		0x80144EF95F53F5F2, 0x1E7688186DB4C10C, 0x3B912965DB5FE1BC, 0xC281715A97E8252D, 
		0x54A5D7E21C7F8171, 0x4B12535CCBC5522E, 0x1D289CEFBEA6F7F9, 0x6EF5F2217D2E729E, 
		0xE6A7DC819B0D17CE, 0x1B94B41C05829B0E, 0x33D7493C622F711E, 0xDCF7F942FA5CE421, 
		0x600FBA8B7F7A8ECB, 0x46B60F011A83988E, 0x235B898E0DCF4C47, 0x957AB24F588592A9, 
		0x4354330572B5C28C, 0xA5F3EF84E9B8D542, 0x8C711E02341B2D01, 0x0B1874AE6A62A657, 
		0x1213D8E306FC19FF, 0xFE6D7C6A4D9DBA35, 0x65ED868F174CD4C9, 0x88522EA0E6236550, 
		0x899322065C2D7703, 0xC01E690BFEF4018B, 0x915982ED8ABDDAF8, 0xBE675B98EC3A4E4C, 
		0xA996BF7F82F00DB1, 0xE1DAF8D49A27696A, 0x2EFFD5D3DC8986E7, 0xD153A51F2B1A2E81, 
		0x18CAA0EBD690ADFB, 0x390E3134B243C51A, 0x2778B92CDFF70416, 0x029F1851691C24A6, 
		0x5E7CAFEACC133575, 0xFA4E4CC89FA5F264, 0x5A5F9F481E2B7D24, 0x484C47AB18D764DB, 
		0x400A27F2A1A7F479, 0xAEEB9B2A83DA7315, 0x721C626879869734, 0x042330A2D2384851, 
		0x85F672FD3765AFF0, 0xBA446B3A3E02061D, 0x73DD6ECEC3888567, 0xFFAC70CCF793A866, 
		0xDFA9EDB5294ED2D4, 0x6C6AEA7014325638, 0x834A5A0E8C41C307, 0xCDBA35562FB2CB2B, 
		0x0AD97808D06CB404, 0x0F3B440CB85AEE06, 0xE5F9C876481F213B, 0x98DEEE1289C35809, 
		0x59018BBFCD394BD1, 0xE01BF47220297B39, 0xDE68E1139340C087, 0x9FA3CA4788E926AD, 
		0xBB85679C840C144E, 0x53D8F3B71D55FFD5, 0x0DA45C5DD146CAA0, 0x6F34FE87C72060CD, 
		0x57FBC315CF6DB784, 0xCEE421A1FCA0FDDE, 0x3D2D0196607B8D4B, 0x642C8A29AD42C69A, 
		0x14AFF010BDD87508, 0xAC74837BEAC657B3, 0x3216459AD821634D, 0x3FB219C70967A9ED, 
		0x06BC28F3BB246CF7, 0xF2082C9126D562C6, 0x66B39278C45EE23C, 0xBD394F6F3F2878B9, 
		0xFD33689D9E8F8CC0, 0x37F4799EB017394F, 0x108CC0B26FE03D59, 0xDA4BD1B1417888D6, 
		0xB09D1332EE6EB219, 0x2F3ED975668794B4, 0x58C0871977375982, 0x7561463D78ACE990, 
		0x09876CFF037E82F1, 0x7FB83E35A8C05D94, 0x26B9B58A65F91645, 0xEF20B07E9873953F, 
		0x3148516D0B3355B8, 0x41CB2B541BA9E62A, 0x790416C613E43163, 0xA011D380818E8F40, 
		0x3A5025C36151F3EF, 0xD57095BDF92266D0, 0x498D4B0DA2D97688, 0x8B0C3A57353153A5, 
		0x21C491DF64D368E1, 0x8F2F0AF5E7091BF4, 0x2DA1C1240F9BB012, 0xC43D59A92CCC49DA, 
		0xBFA6573E56345C1F, 0x828B56A8364FD154, 0x9A41F643E0DF7CAF, 0xBCF843C985266AEA, 
		0x2B1DE9D7B4BFDCE5, 0x20059D79DEDD7AB2, 0x6DABE6D6AE3C446B, 0x45E81BF6C991AE7B, 
		0x6351AE7CAC68B83E, 0xA432E32253B6C711, 0xD092A9B991143CD2, 0xCAC711032E98B58F, 
		0xD8D4C9E02864AC70, 0xC5FC550F96C25B89, 0xD7EF8DEC903E4276, 0x67729EDE7E50F06F, 
		0xEAC28C7AF045CF3D, 0xB15C1F945460A04A, 0x9CFDDEB05BFB1058, 0x93C69ABCE3A1FE5E, 
		0xEB0380DC4A4BDD6E, 0xD20DB1E8F8081874, 0x229A8528B7C15E14, 0x44291750739FBC28, 
		0xD3CCBD4E42060A27, 0xF62B1C33F4ED2A97, 0x86A8660AE4779905, 0xD62E814A2A305025, 
		0x477703A7A08D8ADD, 0x7B9B0E977AF815C5, 0x78C51A60A9EA2330, 0xA6ADFB733AAAE3B7, 
		0x97E5AA1E3199B60F, 0x0000000000000000, 0xF4B404629DF10E31, 0x5564DB44A6719322, 
		0x9207961A59AFEC0D, 0x9624A6B88B97A45C, 0x363575380A192B1C, 0x2C60CD82B595A241, 
		0x7D272664C1DC7932, 0x7142769FAA94A1C1, 0xA1D0DF263B809D13, 0x1630E841D4C451AE, 
		0xC1DF65AD44FA13D8, 0x13D2D445BCF20BAC, 0xD915C546926ABE23, 0x38CF3D92084DD749, 
		0xE766D0272103059D, 0xC7634D5EFFDE7F2F, 0x077D2455012A7EA4, 0xEDBFA82FF16FB199, 
		0xAF2A978C39D46146, 0x42953FA3C8BBD0DF, 0xCB061DA59496A7DC, 0x25E7A17DB6EB20B0, 
		0x34AA6D6963050FBA, 0xA76CF7D580A4F1E4, 0xF7EA10954EE338C4, 0xFCF2643B24819E93, 
		0xCF252D0746AEEF8D, 0x4EF06F58A3F3082C, 0x563ACFB37563A5D7, 0x5086E740CE47C920, 
		0x2982F186DDA3F843, 0x87696AAC5E798B56, 0x5D22BB1D1F010380, 0x035E14F7D31236F5, 
		0x3CEC0D30DA759F18, 0xF3C920379CDB7095, 0xB8DB736B571E22BB, 0xDD36F5E44052F672, 
		0xAAC8AB8851E23B44, 0xA857B3D938FE1FE2, 0x17F1E4E76ECA43FD, 0xEC7EA4894B61A3CA, 
		0x9E62C6E132E734FE, 0xD4B1991B432C7483, 0x6AD6C283AF163ACF, 0x1CE9904904A8E5AA, 
		0x5FBDA34C761D2726, 0xF910583F4CB7C491, 0xC6A241F845D06D7C, 0x4F3163FE19FD1A7F, 
		0xE99C988D2357F9C8, 0x8EEE06535D0709A7, 0x0EFA48AA0254FC55, 0xB4BE23903C56FA48, 
		0x763F52CAABBEDF65, 0xEEE1BCD8227D876C, 0xE345E085F33B4DCC, 0x3E731561B369BBBE, 
		0x2843FD2067ADEA10, 0x2ADCE5710EB1CEB6, 0xB7E03767EF44CCBD, 0x8DB012A48E153F52, 
		0x61CEB62DC5749C98, 0xE85D942B9959EB9B, 0x4C6F7709CAEF2C8A, 0x84377E5B8D6BBDA3, 
		0x30895DCBB13D47EB, 0x74A04A9BC2A2FBC3, 0x6B17CE251518289C, 0xE438C4D0F2113368, 
		0x1FB784BED7BAD35F, 0x9B80FAE55AD16EFC, 0x77FE5E6C11B0CD36, 0xC858095247849129, 
		0x08466059B97090A2, 0x01C10CA6BA0E1253, 0x6988D6747C040C3A, 0x6849DAD2C60A1E69, 
		0x5147EBE67449DB73, 0xC99905F4FD8A837A, 0x991FE2B433CD4A5A, 0xF09734C04FC94660, 
		0xA28ECBD1E892ABE6, 0xF1563866F5C75433, 0x4DAE7BAF70E13ED9, 0x7CE62AC27BD26B61, 
		0x70837A39109AB392, 0x90988E4B30B3C8AB, 0xB2020B63877296BF, 0x156EFCB607D6675B
	}, {
		0xE63F55CE97C331D0, 0x25B506B0015BBA16, 0xC8706E29E6AD9BA8, 0x5B43D3775D521F6A, 
		0x0BFA3D577035106E, 0xAB95FC172AFB0E66, 0xF64B63979E7A3276, 0xF58B4562649DAD4B, 
		0x48F7C3DBAE0C83F1, 0xFF31916642F5C8C5, 0xCBB048DC1C4A0495, 0x66B8F83CDF622989, 
		0x35C130E908E2B9B0, 0x7C761A61F0B34FA1, 0x3601161CF205268D, 0x9E54CCFE2219B7D6, 
		0x8B7D90A538940837, 0x9CD403588EA35D0B, 0xBC3C6FEA9CCC5B5A, 0xE5FF733B6D24AEED, 
		0xCEED22DE0F7EB8D2, 0xEC8581CAB1AB545E, 0xB96105E88FF8E71D, 0x8CA03501871A5EAD, 
		0x76CCCE65D6DB2A2F, 0x5883F582A7B58057, 0x3F7BE4ED2E8ADC3E, 0x0FE7BE06355CD9C9, 
		0xEE054E6C1D11BE83, 0x1074365909B903A6, 0x5DDE9F80B4813C10, 0x4A770C7D02B6692C, 
		0x5379C8D5D7809039, 0xB4067448161ED409, 0x5F5E5026183BD6CD, 0xE898029BF4C29DF9, 
		0x7FB63C940A54D09C, 0xC5171F897F4BA8BC, 0xA6F28DB7B31D3D72, 0x2E4F3BE7716EAA78, 
		0x0D6771A099E63314, 0x82076254E41BF284, 0x2F0FD2B42733DF98, 0x5C9E76D3E2DC49F0, 
		0x7AEB569619606CDB, 0x83478B07B2468764, 0xCFADCB8D5923CD32, 0x85DAC7F05B95A41E, 
		0xB5469D1B4043A1E9, 0xB821ECBBD9A592FD, 0x1B8E0B0E798C13C8, 0x62A57B6D9A0BE02E, 
		0xFCF1B793B81257F8, 0x9D94EA0BD8FE28EB, 0x4CEA408AEB654A56, 0x23284A47E888996C, 
		0x2D8F1D128B893545, 0xF4CBAC3132C0D8AB, 0xBD7C86B9CA912EBA, 0x3A268EEF3DBE6079, 
		0xF0D62F6077A9110C, 0x2735C916ADE150CB, 0x89FD5F03942EE2EA, 0x1ACEE25D2FD16628, 
		0x90F39BAB41181BFF, 0x430DFE8CDE39939F, 0xF70B8AC4C8274796, 0x1C53AEAAC6024552, 
		0x13B410ACF35E9C9B, 0xA532AB4249FAA24F, 0x2B1251E5625A163F, 0xD7E3E676DA4841C7, 
		0xA7B264E4E5404892, 0xDA8497D643AE72D3, 0x861AE105A1723B23, 0x38A6414991048AA4, 
		0x6578DEC92585B6B4, 0x0280CFA6ACBAEADD, 0x88BDB650C273970A, 0x9333BD5EBBFF84C2, 
		0x4E6A8F2C47DFA08B, 0x321C954DB76CEF2A, 0x418D312A72837942, 0xB29B38BFFFCDF773, 
		0x6C022C38F90A4C07, 0x5A033A240B0F6A8A, 0x1F93885F3CE5DA6F, 0xC38A537E96988BC6, 
		0x39E6A81AC759FF44, 0x29929E43CEE0FCE2, 0x40CDD87924DE0CA2, 0xE9D8EBC8A29FE819, 
		0x0C2798F3CFBB46F4, 0x55E484223E53B343, 0x4650948ECD0D2FD8, 0x20E86CB2126F0651, 
		0x6D42C56BAF5739E7, 0xA06FC1405ACE1E08, 0x7BABBFC54F3D193B, 0x424D17DF8864E67F, 
		0xD8045870EF14980E, 0xC6D7397C85AC3781, 0x21A885E1443273B1, 0x67F8116F893F5C69, 
		0x24F5EFE35706CFF6, 0xD56329D076F2AB1A, 0x5E1EB9754E66A32D, 0x28D2771098BD8902, 
		0x8F6013F47DFDC190, 0x17A993FDB637553C, 0xE0A219397E1012AA, 0x786B9930B5DA8606, 
		0x6E82E39E55B0A6DA, 0x875A0856F72F4EC3, 0x3741FF4FA458536D, 0xAC4859B3957558FC, 
		0x7EF6D5C75C09A57C, 0xC04A758B6C7F14FB, 0xF9ACDD91AB26EBBF, 0x7391A467C5EF9668, 
		0x335C7C1EE1319ACA, 0xA91533B18641E4BB, 0xE4BF9A683B79DB0D, 0x8E20FAA72BA0B470, 
		0x51F907737B3A7AE4, 0x2268A314BED5EC8C, 0xD944B123B949EDEE, 0x31DCB3B84D8B7017, 
		0xD3FE65279F218860, 0x097AF2F1DC8FFAB3, 0x9B09A6FC312D0B91, 0xCC6DED78A3C4520F, 
		0x3481D9BA5EBFCC50, 0x4F2A667F1182D56B, 0xDFD9FDD4509ACE94, 0x26752045FBBC252B, 
		0xBFFC491F662BC467, 0xDD593272FC202449, 0x3CBBC218D46D4303, 0x91B372F817456E1F, 
		0x681FAF69BC6385A0, 0xB686BBEEBAA43ED4, 0x1469B5084CD0CA01, 0x98C98009CBCA94AC, 
		0x6438379A73D8C354, 0xC2CABA2DC0C5FE26, 0x3E3B0DBE78D7A9DE, 0x50B9EE202D670F04, 
		0x4590B27B37EAB0E5, 0x6025B4CB36B10AF3, 0xFB2C1237079C0162, 0xA12F28130C936BE8, 
		0x4B37E52E54EB1CCC, 0x083A1BA28AD28F53, 0xC10A9CD83A22611B, 0x9F1425AD7444C236, 
		0x069D4CF7E9D3237A, 0xEDC56899E7F621BE, 0x778C273680865FCF, 0x309C5AEB1BD605F7, 
		0x8DE0DC52D1472B4D, 0xF8EC34C2FD7B9E5F, 0xEA18CD3D58787724, 0xAAD515447CA67B86, 
		0x9989695A9D97E14C, 0x0000000000000000, 0xF196C63321F464EC, 0x71116BC169557CB5, 
		0xAF887F466F92C7C1, 0x972E3E0FFE964D65, 0x190EC4A8D536F915, 0x95AEF1A9522CA7B8, 
		0xDC19DB21AA7D51A9, 0x94EE18FA0471D258, 0x8087ADF248A11859, 0xC457F6DA2916DD5C, 
		0xFA6CFB6451C17482, 0xF256E0C6DB13FBD1, 0x6A9F60CF10D96F7D, 0x4DAAA9D9BD383FB6, 
		0x03C026F5FAE79F3D, 0xDE99148706C7BB74, 0x2A52B8B6340763DF, 0x6FC20ACD03EDD33A, 
		0xD423C08320AFDEFA, 0xBBE1CA4E23420DC0, 0x966ED75CA8CB3885, 0xEB58246E0E2502C4, 
		0x055D6A021334BC47, 0xA47242111FA7D7AF, 0xE3623FCC84F78D97, 0x81C744A11EFC6DB9, 
		0xAEC8961539CFB221, 0xF31609958D4E8E31, 0x63E5923ECC5695CE, 0x47107DDD9B505A38, 
		0xA3AFE7B5A0298135, 0x792B7063E387F3E6, 0x0140E953565D75E0, 0x12F4F9FFA503E97B, 
		0x750CE8902C3CB512, 0xDBC47E8515F30733, 0x1ED3610C6AB8AF8F, 0x5239218681DDE5D9, 
		0xE222D69FD2AAF877, 0xFE71783514A8BD25, 0xCAF0A18F4A177175, 0x61655D9860EC7F13, 
		0xE77FBC9DC19E4430, 0x2CCFF441DDD440A5, 0x16E97AAEE06A20DC, 0xA855DAE2D01C915B, 
		0x1D1347F9905F30B2, 0xB7C652BDECF94B34, 0xD03E43D265C6175D, 0xFDB15EC0EE4F2218, 
		0x57644B8492E9599E, 0x07DDA5A4BF8E569A, 0x54A46D71680EC6A3, 0x5624A2D7C4B42C7E, 
		0xBEBCA04C3076B187, 0x7D36F332A6EE3A41, 0x3B6667BC6BE31599, 0x695F463AEA3EF040, 
		0xAD08B0E0C3282D1C, 0xB15B1E4A052A684E, 0x44D05B2861B7C505, 0x15295C5B1A8DBFE1, 
		0x744C01C37A61C0F2, 0x59C31CD1F1E8F5B7, 0xEF45A73F4B4CCB63, 0x6BDF899C46841A9D, 
		0x3DFB2B4B823036E3, 0xA2EF0EE6F674F4D5, 0x184E2DFB836B8CF5, 0x1134DF0A5FE47646, 
		0xBAA1231D751F7820, 0xD17EAA81339B62BD, 0xB01BF71953771DAE, 0x849A2EA30DC8D1FE, 
		0x705182923F080955, 0x0EA757556301AC29, 0x041D83514569C9A7, 0x0ABAD4042668658E, 
		0x49B72A88F851F611, 0x8A3D79F66EC97DD7, 0xCD2D042BF59927EF, 0xC930877AB0F0EE48, 
		0x9273540DEDA2F122, 0xC797D02FD3F14261, 0xE1E2F06A284D674A, 0xD2BE8C74C97CFD80, 
		0x9A494FAF67707E71, 0xB3DBD1ECA9908293, 0x72D14D3493B2E388, 0xD6A30F258C153427
	}
};

static const UI8
MASTER_GOST12_TABLE_IC[12][8] = { {
		0xDD806559F2A64507, 0x05767436CC744D23, 0xA2422A08A460D315, 0x4B7CE09192676901, 
		0x714EB88D7585C4FC, 0x2F6A76432E45D016, 0xEBCB2F81C0657C1F, 0xB1085BDA1ECADAE9
	}, {
		0xE679047021B19BB7, 0x55DDA21BD7CBCD56, 0x5CB561C2DB0AA7CA, 0x9AB5176B12D69958, 
		0x61D55E0F16B50131, 0xF3FEEA720A232B98, 0x4FE39D460F70B5D7, 0x6FA3B58AA99D2F1A
	}, {
		0x991E96F50ABA0AB2, 0xC2B6F443867ADB31, 0xC1C93A376062DB09, 0xD3E20FE490359EB1, 
		0xF2EA7514B1297B7B, 0x06F15E5F529C1F8B, 0x0A39FC286A3D8435, 0xF574DCAC2BCE2FC7
	}, {
		0x220CBEBC84E3D12E, 0x3453EAA193E837F1, 0xD8B71333935203BE, 0xA9D72C82ED03D675, 
		0x9D721CAD685E353F, 0x488E857E335C3C7D, 0xF948E1A05D71E4DD, 0xEF1FDFB3E81566D2
	}, {
		0x601758FD7C6CFE57, 0x7A56A27EA9EA63F5, 0xDFFF00B723271A16, 0xBFCD1747253AF5A3, 
		0x359E35D7800FFFBD, 0x7F151C1F1686104A, 0x9A3F410C6CA92363, 0x4BEA6BACAD474799
	}, {
		0xFA68407A46647D6E, 0xBF71C57236904F35, 0x0AF21F66C2BEC6B6, 0xCFFAA6B71C9AB7B4, 
		0x187F9AB49AF08EC6, 0x2D66C4F95142A46C, 0x6FA4C33B7A3039C0, 0xAE4FAEAE1D3AD3D9
	}, {
		0x8886564D3A14D493, 0x3517454CA23C4AF3, 0x06476983284A0504, 0x0992ABC52D822C37, 
		0xD3473E33197A93C9, 0x399EC6C7E6BF87C9, 0x51AC86FEBF240954, 0xF4C70E16EEAAC5EC
	}, {
		0xA47F0DD4BF02E71E, 0x36ACC2355951A8D9, 0x69D18D2BD1A5C42F, 0xF4892BCB929B0690, 
		0x89B4443B4DDBC49A, 0x4EB7F8719C36DE1E, 0x03E7AA020C6E4141, 0x9B1F5B424D93C9A7
	}, {
		0x7261445183235ADB, 0x0E38DC92CB1F2A60, 0x7B2B8A9AA6079C54, 0x800A440BDBB2CEB1, 
		0x3CD955B7E00D0984, 0x3A7D3A1B25894224, 0x944C9AD8EC165FDE, 0x378F5A541631229B
	}, {
		0x74B4C7FB98459CED, 0x3698FAD1153BB6C3, 0x7A1E6C303B7652F4, 0x9FE76702AF69334B, 
		0x1FFFE18A1B336103, 0x8941E71CFF8A78DB, 0x382AE548B2E4F3F3, 0xABBEDEA680056F52
	}, {
		0x6BCAA4CD81F32D1B, 0xDEA2594AC06FD85D, 0xEFBACD1D7D476E98, 0x8A1D71EFEA48B9CA, 
		0x2001802114846679, 0xD8FA6BBBEBAB0761, 0x3002C6CD635AFE94, 0x7BCD9ED0EFC889FB
	}, {
		0x48BC924AF11BD720, 0xFAF417D5D9B21B99, 0xE71DA4AA88E12852, 0x5D80EF9D1891CC86, 
		0xF82012D430219F9B, 0xCDA43C32BCDF1D77, 0xD21380B00449B17A, 0x378EE767F11631BA
	}
};

static const UI8 MASTER_GOST12_ARRAY_Z512[8] = { 0, 0, 0, 0, 0, 0, 0, 0 };
static const UI8 MASTER_GOST12_S2C[8] = { 512, 0, 0, 0, 0, 0, 0, 0 };

typedef struct {
	UI8 __h[8];
	UI8 __n[8];
	UI8 __s[8];
	UI8 __b[8];
	UI4 __i;
	UI4 __hs;
} MASTER_GOST12;

MASTER_GOST12
MASTER_GOST12_Init(UI8 __hs) {
	MASTER_GOST12 __gost12;
	memset(&__gost12, 0, sizeof(MASTER_GOST12));
	if (__hs != 64) memset(__gost12.__h, 1, 64);
	__gost12.__hs = __hs;
	return __gost12;
}

static void
MASTER_GOST12_FUNCTION_LPSX(const UI8 * a, const UI8 * b, UI8 * result) {
	UI8 r[8];
	UI1 i, j;

	for (i = 0; i < 8; i++) r[i] = a[i] ^ b[i];
	for (i = 0; i < 8; i++) {
		result[i] = MASTER_GOST12_TABLE_T[0][(r[0] >> (i << 3)) & 0xFF];
		for (j = 1; j < 8; j++) result[i] ^= MASTER_GOST12_TABLE_T[j][(r[j] >> (i << 3)) & 0xFF];
	}
}

static void
MASTER_GOST12_GN(const UI8 * __n, UI8 * __h, const UI8 * m) {
	UI8 K_i[8], state[8];
	UI1 i, j;

	MASTER_GOST12_FUNCTION_LPSX(__h, __n, K_i);
	MASTER_GOST12_FUNCTION_LPSX(K_i, m, state);

	for (i = 0; i < 11; i++) {
		MASTER_GOST12_FUNCTION_LPSX(K_i, MASTER_GOST12_TABLE_IC[i], K_i);
		MASTER_GOST12_FUNCTION_LPSX(K_i, state, state);
	}
	
	MASTER_GOST12_FUNCTION_LPSX(K_i, MASTER_GOST12_TABLE_IC[11], K_i);
	
	for (j = 0; j < 8; j++) {
		state[j] ^= K_i[j];
		state[j] ^= __h[j];
		__h[j] = state[j] ^ m[j];
	}
}

static void
MASTER_GOST12_ADDUI64(UI8 * sum, const UI8 * x) {
	UI1 i;
	UI8 c = 0;

	for (i = 0; i < 8; i++) {
		sum[i] += x[i] + c;
		c = (sum[i] < x[i] ? 1 : sum[i] == x[i] ? c : 0);
	}
}

static void
MASTER_GOST12_S2(MASTER_GOST12 * const __gost12, UI8 * m) {
	MASTER_GOST12_GN(__gost12->__n, __gost12->__h, m);
	MASTER_GOST12_ADDUI64(__gost12->__n, MASTER_GOST12_S2C);
	MASTER_GOST12_ADDUI64(__gost12->__s, m);
}

void
MASTER_GOST12_Update(MASTER_GOST12 * const __gost12, const UI1 * __s, UI8 __l) {
	if (__gost12->__i) {
		UI8 rest = 64 - __gost12->__i;

		memcpy(__gost12->__b + __gost12->__i, __s, __l < rest ? __l : rest);
		__gost12->__i += __l;
		if (__l < rest) return;

		MASTER_GOST12_S2(__gost12, __gost12->__b);
		__s += rest;
		__l -= rest;
		__gost12->__i = 0;
	}
	if ((7 & (UI8)(__s)) == 0) {
		while (__l >= 64) {
			MASTER_GOST12_S2(__gost12, (UI8 *)__s);
			__s += 64;
			__l -= 64;
		}
	} else {
		while (__l >= 64) {
			memcpy(__gost12->__b, __s, 64);
			MASTER_GOST12_S2(__gost12, __gost12->__b);
			__s += 64;
			__l -= 64;
		}
	}
	if (__l) {
		__gost12->__i = __l;
		memcpy(__gost12->__b, __s, __l);
	}
}

void
MASTER_GOST12_Final(MASTER_GOST12 * const __gost12, UI1 * hash_output) {
	UI8 __ubc[8] = { 0, 0, 0, 0, 0, 0, 0, 0 };
	UI8 __i = __gost12->__i >> 3;
	UI4 __sh = (__gost12->__i & 7) * 8;

	__ubc[0] = __gost12->__i * 8;
	__gost12->__b[__i] &= ~(0xFFFFFFFFFFFFFFFF << __sh);
	__gost12->__b[__i++] ^= 0x01 << __sh;
	memset(&__gost12->__b[__i], 0, 64 - __i * 8);

	MASTER_GOST12_GN(__gost12->__n, __gost12->__h, __gost12->__b);
	MASTER_GOST12_ADDUI64(__gost12->__n, __ubc);
	MASTER_GOST12_ADDUI64(__gost12->__s, __gost12->__b);
	MASTER_GOST12_GN(MASTER_GOST12_ARRAY_Z512, __gost12->__h, __gost12->__n);
	MASTER_GOST12_GN(MASTER_GOST12_ARRAY_Z512, __gost12->__h, __gost12->__s);

	memcpy(hash_output, &(__gost12->__h[8 - __gost12->__hs / 8]), __gost12->__hs);
}

void
MASTER_GOST12_CalculateHashSum(const char * __s, UI4 __l, UI1 * hash_output, UI4 outl) {
	MASTER_GOST12 __gost12 = MASTER_GOST12_Init(outl / 8);
	MASTER_GOST12_Update(&__gost12, __s, __l);
	MASTER_GOST12_Final(&__gost12, hash_output);
}

// !# GOST12

#endif /* __MASTER_HASHLIB_INCLUDE_H__ */

// be master~
