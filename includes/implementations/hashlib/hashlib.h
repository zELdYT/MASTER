
/*
 * Copyright (c) 2024 zELdYT
 *
 * Licensed under the BSD 2-Clause License.
 * See the LICENSE file in the project root for more details.
 */

#ifndef __MASTER_HASHLIB_INCLUDE_H__
#define __MASTER_HASHLIB_INCLUDE_H__

#include <string.h>
#include <stdlib.h>

#define __MASTER_HASHLIB_FUNCTION_RLL32(X, C) (((X) << (C)) | ((X) >> (32 - (C))))
#define __MASTER_HASHLIB_FUNCTION_RLL64(X, C) (((X) << (C)) | ((X) >> (64 - (C))))
#define __MASTER_HASHLIB_FUNCTION_RLR32(X, C) (((X) >> (C)) | ((X) << (32 - (C))))
#define __MASTER_HASHLIB_FUNCTION_RLR64(X, C) (((X) >> (C)) | ((X) << (64 - (C))))
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
	((val & 0xFF000000) >> 24);

typedef unsigned char UI1;
typedef unsigned short UI2;
typedef unsigned long UI4;
typedef unsigned long long UI8;

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
MASTER_Adler32_CalculateHashSum(const char * __s, UI4 __l, UI1 * hash_output) {
	UI2 A = 1, B = 0;
	while (__l--) {
		A = (A + *(__s++)) % 65521;
		B = (A + B) % 65521; }
	UI4 result = (B << 16) | A;
	
	hash_output[0] = (result >> 24) & 0xFF;
	hash_output[1] = (result >> 16) & 0xFF;
	hash_output[2] = (result >> 8) & 0xFF;
	hash_output[3] = result & 0xFF;
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
		if (v & s)
			r |= d;
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
		if (v & s)
			r |= d;
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
			ch >>= 1; }
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
			ch >>= 1; }
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
	41 , 46 , 67 , 201, 162, 216, 124, 1,
	61 , 54 , 84 , 161, 236, 240, 6	, 19 ,
	98 , 167, 5	, 243, 192, 199, 115, 140,
	152, 147, 43 , 217, 188, 76 , 130, 202,
	30 , 155, 87 , 60 , 253, 212, 224, 22 ,
	103, 66 , 111, 24 , 138, 23 , 229, 18 ,
	190, 78 , 196, 214, 218, 158, 222, 73 ,
	160, 251, 245, 142, 187, 47 , 238, 122,
	169, 104, 121, 145, 21 , 178, 7	, 63 ,
	148, 194, 16 , 137, 11 , 34 , 95 , 33 ,
	128, 127, 93 , 154, 90 , 144, 50 , 39 ,
	53 , 62 , 204, 231, 191, 247, 151, 3,
	255, 25 , 48 , 179, 72 , 165, 181, 209,
	215, 94 , 146, 42 , 172, 86 , 170, 198,
	79 , 184, 56 , 210, 150, 164, 125, 182,
	118, 252, 107, 226, 156, 116, 4	, 241,
	69 , 157, 112, 89 , 100, 113, 135, 32 ,
	134, 91 , 207, 101, 230, 45 , 168, 2,
	27 , 96 , 37 , 173, 174, 176, 185, 246,
	28 , 70 , 97 , 105, 52 , 64 , 126, 15 ,
	85 , 71 , 163, 35 , 221, 81 , 175, 58 ,
	195, 92 , 249, 206, 186, 197, 234, 38 ,
	44 , 83 , 13 , 110, 133, 40 , 132, 9,
	211, 223, 205, 244, 65 , 129, 77 , 82 ,
	106, 220, 55 , 200, 108, 193, 171, 250,
	36 , 225, 123, 8, 12 , 189, 177, 74 ,
	120, 136, 149, 139, 227, 99 , 232, 109,
	233, 203, 213, 254, 59 , 0	, 29 , 57 ,
	242, 239, 183, 14 , 102, 88 , 208, 228,
	166, 119, 114, 248, 235, 117, 75 , 10 ,
	49 , 68 , 80 , 180, 143, 237, 31 , 26 ,
	219, 153, 141, 51 , 159, 17 , 131, 20
};

typedef struct {
	UI1 __X[48];
	UI1 __M[16];
	UI1 __buffer[16];
	UI1 __len;
} MASTER_MD2;

MASTER_MD2
MASTER_MD2_Init(void) {
	MASTER_MD2 __md2;
	for (UI1 i = 0; i < 16; i++) __md2.__M[i] = 0x00;
	for (UI1 i = 0; i < 48; i++) __md2.__X[i] = 0x00;
	__md2.__len = 0;
	return __md2;
}

static void
__MASTED_MD2_Transform(MASTER_MD2 * __md2, const UI1 * __data) {
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
		__md2->__buffer[__md2->__len++] = *(__s++);
		if (__md2->__len == 16) {
			__MASTED_MD2_Transform(__md2, __md2->__buffer);
			__md2->__len = 0; }
	}
}

void
MASTER_MD2_Final(MASTER_MD2 * __md2, UI1 * hash_output) {
	UI1 rem = 16 - __md2->__len;

	while (__md2->__len < 16)
		__md2->__buffer[__md2->__len++] = rem;

	__MASTED_MD2_Transform(__md2, __md2->__buffer);
	__MASTED_MD2_Transform(__md2, __md2->__M);

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
#define __MASTER_MD4_FUNCTION_FF(A, B, C, D, K, S) A += __MASTER_MD4_FUNCTION_F(B, C, D) + (X[K]); A = __MASTER_HASHLIB_FUNCTION_RLL32(A, S)
#define __MASTER_MD4_FUNCTION_GG(A, B, C, D, K, S) A += __MASTER_MD4_FUNCTION_G(B, C, D) + (X[K]) + 0x5A827999; A = __MASTER_HASHLIB_FUNCTION_RLL32(A, S)
#define __MASTER_MD4_FUNCTION_HH(A, B, C, D, K, S) A += __MASTER_MD4_FUNCTION_H(B, C, D) + (X[K]) + 0x6ED9EBA1; A = __MASTER_HASHLIB_FUNCTION_RLL32(A, S)

typedef struct {
	UI4 __A, __B, __C, __D;
	UI1 __buffer[64];
	UI8 __len;
} MASTER_MD4;

MASTER_MD4
MASTER_MD4_Init(void) {
	MASTER_MD4 __md4;
	__md4.__A = 0x67452301;
	__md4.__B = 0xefcdab89;
	__md4.__C = 0x98badcfe;
	__md4.__D = 0x10325476;
	__md4.__len = 0;
	return __md4;
}

static void
__MASTED_MD4_Transform(MASTER_MD4 * __md4) {
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
		__md4->__buffer[__md4->__len++ % 64] = *(__s++);
		if (__md4->__len % 64 == 0)
			__MASTED_MD4_Transform(__md4);
	}
}

void
MASTER_MD4_Final(MASTER_MD4 * __md4, UI1 * hash_output) {
	UI1 bits[8];
	UI4 index, padLen, i;

	bits[0] = ((__md4->__len << 3) & 0xff);
	bits[1] = ((__md4->__len << 3) >> 8) & 0xff;
	bits[2] = ((__md4->__len << 3) >> 16) & 0xff;
	bits[3] = ((__md4->__len << 3) >> 24) & 0xff;
	bits[4] = ((__md4->__len << 3) >> 32) & 0xff;
	bits[5] = ((__md4->__len << 3) >> 40) & 0xff;
	bits[6] = ((__md4->__len << 3) >> 48) & 0xff;
	bits[7] = ((__md4->__len << 3) >> 56) & 0xff;
	
	index = ((__md4->__len) & 0x3f);
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
#define __MASTER_MD5_FUNCTION_FF(A, B, C, D, K, S, I) A = B + __MASTER_HASHLIB_FUNCTION_RLL32(A + __MASTER_MD5_FUNCTION_F(B, C, D) + X[K] + T[I], S)
#define __MASTER_MD5_FUNCTION_GG(A, B, C, D, K, S, I) A = B + __MASTER_HASHLIB_FUNCTION_RLL32(A + __MASTER_MD5_FUNCTION_G(B, C, D) + X[K] + T[I], S)
#define __MASTER_MD5_FUNCTION_HH(A, B, C, D, K, S, I) A = B + __MASTER_HASHLIB_FUNCTION_RLL32(A + __MASTER_MD5_FUNCTION_H(B, C, D) + X[K] + T[I], S)
#define __MASTER_MD5_FUNCTION_II(A, B, C, D, K, S, I) A = B + __MASTER_HASHLIB_FUNCTION_RLL32(A + __MASTER_MD5_FUNCTION_I(B, C, D) + X[K] + T[I], S)

typedef struct {
	UI4 __A, __B, __C, __D;
	UI1 __buffer[64];
	UI8 __len;
} MASTER_MD5;

MASTER_MD5
MASTER_MD5_Init(void) {
	MASTER_MD5 __md5;
	__md5.__A = 0x67452301;
	__md5.__B = 0xefcdab89;
	__md5.__C = 0x98badcfe;
	__md5.__D = 0x10325476;
	__md5.__len = 0;
	return __md5;
}

static void
__MASTED_MD5_Transform(MASTER_MD5 * __md5) {
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
		__md5->__buffer[__md5->__len++ % 64] = *(__s++);
		if (__md5->__len % 64 == 0)
			__MASTED_MD5_Transform(__md5);
	}
}

void
MASTER_MD5_Final(MASTER_MD5 * __md5, UI1 * hash_output) {
	UI1 bits[8];
	UI4 index, padLen, i;

	bits[0] = ((__md5->__len << 3) & 0xff);
	bits[1] = ((__md5->__len << 3) >> 8) & 0xff;
	bits[2] = ((__md5->__len << 3) >> 16) & 0xff;
	bits[3] = ((__md5->__len << 3) >> 24) & 0xff;
	bits[4] = ((__md5->__len << 3) >> 32) & 0xff;
	bits[5] = ((__md5->__len << 3) >> 40) & 0xff;
	bits[6] = ((__md5->__len << 3) >> 48) & 0xff;
	bits[7] = ((__md5->__len << 3) >> 56) & 0xff;
	
	index = ((__md5->__len) & 0x3f);
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
#define __MASTER_SHA1_FUNCTION_FF(A, B, C, D, E, T) (__MASTER_HASHLIB_FUNCTION_RLL32(A, 5) + __MASTER_SHA1_FUNCTION_F(B, C, D) + E + W[T] + 0x5A827999)
#define __MASTER_SHA1_FUNCTION_GG(A, B, C, D, E, T) (__MASTER_HASHLIB_FUNCTION_RLL32(A, 5) + __MASTER_SHA1_FUNCTION_G(B, C, D) + E + W[T] + 0x6ED9EBA1)
#define __MASTER_SHA1_FUNCTION_HH(A, B, C, D, E, T) (__MASTER_HASHLIB_FUNCTION_RLL32(A, 5) + __MASTER_SHA1_FUNCTION_H(B, C, D) + E + W[T] + 0x8F1BBCDC)
#define __MASTER_SHA1_FUNCTION_II(A, B, C, D, E, T) (__MASTER_HASHLIB_FUNCTION_RLL32(A, 5) + __MASTER_SHA1_FUNCTION_I(B, C, D) + E + W[T] + 0xCA62C1D6)

typedef struct {
	UI4 __A, __B, __C, __D, __E;
	UI1 __buffer[64];
	UI8 __len;
} MASTER_SHA1;

MASTER_SHA1
MASTER_SHA1_Init(void) {
	MASTER_SHA1 __sha1;
	__sha1.__A = 0x67452301;
	__sha1.__B = 0xefcdab89;
	__sha1.__C = 0x98badcfe;
	__sha1.__D = 0x10325476;
	__sha1.__E = 0xc3d2e1f0;
	__sha1.__len = 0;
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
		W[j] = __MASTER_HASHLIB_FUNCTION_RLL32((W[j - 3] ^ W[j - 8] ^ W[j - 14] ^ W[j - 16]), 1);

	AA = __sha1->__A;
	BB = __sha1->__B;
	CC = __sha1->__C;
	DD = __sha1->__D;
	EE = __sha1->__E;
	
	for (j = 0; j < 80; j++) {
		if (j <= 19) {
			buffer = __MASTER_SHA1_FUNCTION_FF(__sha1->__A, __sha1->__B, __sha1->__C, __sha1->__D, __sha1->__E, j);
		} else if (j <= 39) {
			buffer = __MASTER_SHA1_FUNCTION_GG(__sha1->__A, __sha1->__B, __sha1->__C, __sha1->__D, __sha1->__E, j);
		} else if (j <= 59) {
			buffer = __MASTER_SHA1_FUNCTION_HH(__sha1->__A, __sha1->__B, __sha1->__C, __sha1->__D, __sha1->__E, j);
		} else if (j <= 79) {
			buffer = __MASTER_SHA1_FUNCTION_II(__sha1->__A, __sha1->__B, __sha1->__C, __sha1->__D, __sha1->__E, j);
		}
		__sha1->__E = __sha1->__D;
		__sha1->__D = __sha1->__C;
		__sha1->__C = __MASTER_HASHLIB_FUNCTION_RLL32(__sha1->__B, 30);
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
		__sha1->__buffer[__sha1->__len++ % 64] = *(__s++);
		if (__sha1->__len % 64 == 0)
			__MASTER_SHA1_Transform(__sha1);
	}
}

void
MASTER_SHA1_Final(MASTER_SHA1 * __sha1, UI1 * hash_output) {
	UI1 bits[8];
	UI4 index, padLen, i;

	bits[0] = ((__sha1->__len << 3) >> 56) & 0xff;
	bits[1] = ((__sha1->__len << 3) >> 48) & 0xff;
	bits[2] = ((__sha1->__len << 3) >> 40) & 0xff;
	bits[3] = ((__sha1->__len << 3) >> 32) & 0xff;
	bits[4] = ((__sha1->__len << 3) >> 24) & 0xff;
	bits[5] = ((__sha1->__len << 3) >> 16) & 0xff;
	bits[6] = ((__sha1->__len << 3) >> 8) & 0xff;
	bits[7] = ((__sha1->__len << 3)) & 0xff;
	
	index = ((__sha1->__len) & 0x3f);
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
			W[j] = __MASTER_HASHLIB_FUNCTION_RLL32((W[j - 3] ^ W[j - 8] ^ W[j - 14] ^ W[j - 16]), 1);

		AA = A;
		BB = B;
		CC = C;
		DD = D;
		EE = E;
		
		for (j = 0; j < 80; j++) {
			if (j <= 19) {
				buffer = __MASTER_SHA1_FUNCTION_FF(A, B, C, D, E, j);
			} else if (j <= 39) {
				buffer = __MASTER_SHA1_FUNCTION_GG(A, B, C, D, E, j);
			} else if (j <= 59) {
				buffer = __MASTER_SHA1_FUNCTION_HH(A, B, C, D, E, j);
			} else if (j <= 79) {
				buffer = __MASTER_SHA1_FUNCTION_II(A, B, C, D, E, j);
			}
			E = D;
			D = C;
			C = __MASTER_HASHLIB_FUNCTION_RLL32(B, 30);
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

#define __MASTER_SHA2_FUNCTION_SIGMA0(A) ((__MASTER_HASHLIB_FUNCTION_RLR32(A, 2)) ^ (__MASTER_HASHLIB_FUNCTION_RLR32(A, 13)) ^ (__MASTER_HASHLIB_FUNCTION_RLR32(A, 22)))
#define __MASTER_SHA2_FUNCTION_SIGMA1(A) ((__MASTER_HASHLIB_FUNCTION_RLR32(E, 6)) ^ (__MASTER_HASHLIB_FUNCTION_RLR32(E, 11)) ^ (__MASTER_HASHLIB_FUNCTION_RLR32(E, 25)))
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
	UI8 __len;
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
	__sha_2_224.__len = 0;
	return __sha_2_224;
}

static void
__MASTER_SHA2_224_Transform(MASTER_SHA2_224 * __sha2_224) {
	UI4 A, B, C, D, E, F, G, H, j, t1, t2;
	
	UI4 W[64];
		for (j = 0; j < 16; j++) 
			W[j] = (__sha2_224->__buffer[j * 4] << 24) | ((__sha2_224->__buffer[j * 4 + 1]) << 16) | ((__sha2_224->__buffer[j * 4 + 2]) << 8) | ((__sha2_224->__buffer[j * 4 + 3]));
		for (j = 16; j < 64; j++) {
			UI4 s0 = (__MASTER_HASHLIB_FUNCTION_RLR32(W[j - 15], 7)) ^ (__MASTER_HASHLIB_FUNCTION_RLR32(W[j - 15], 18)) ^ (W[j - 15] >> 3);
					UI4 s1 = (__MASTER_HASHLIB_FUNCTION_RLR32(W[j - 2], 17)) ^ (__MASTER_HASHLIB_FUNCTION_RLR32(W[j - 2], 19)) ^ (W[j - 2] >> 10);
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
		__sha2_224->__buffer[__sha2_224->__len++ % 64] = *(__s++);
		if (__sha2_224->__len % 64 == 0)
			__MASTER_SHA2_224_Transform(__sha2_224);
	}
}

void
MASTER_SHA2_224_Final(MASTER_SHA2_224 * __sha2_224, UI1 * hash_output) {
	UI1 bits[8];
	UI4 index, padLen, i;

	bits[0] = ((__sha2_224->__len << 3) >> 56) & 0xff;
	bits[1] = ((__sha2_224->__len << 3) >> 48) & 0xff;
	bits[2] = ((__sha2_224->__len << 3) >> 40) & 0xff;
	bits[3] = ((__sha2_224->__len << 3) >> 32) & 0xff;
	bits[4] = ((__sha2_224->__len << 3) >> 24) & 0xff;
	bits[5] = ((__sha2_224->__len << 3) >> 16) & 0xff;
	bits[6] = ((__sha2_224->__len << 3) >> 8) & 0xff;
	bits[7] = ((__sha2_224->__len << 3)) & 0xff;
	
	index = ((__sha2_224->__len) & 0x3f);
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
			UI4 s0 = (__MASTER_HASHLIB_FUNCTION_RLR32(W[j - 15], 7)) ^ (__MASTER_HASHLIB_FUNCTION_RLR32(W[j - 15], 18)) ^ (W[j - 15] >> 3);
					UI4 s1 = (__MASTER_HASHLIB_FUNCTION_RLR32(W[j - 2], 17)) ^ (__MASTER_HASHLIB_FUNCTION_RLR32(W[j - 2], 19)) ^ (W[j - 2] >> 10);
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
	UI8 __len;
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
	__sha2_256.__len = 0;
	return __sha2_256;
}

static void
__MASTER_SHA2_256_Transform(MASTER_SHA2_256 * __sha2_256) {
	UI4 A, B, C, D, E, F, G, H, j, t1, t2;
	
	UI4 W[64];
	for (j = 0; j < 16; j++) 
		W[j] = (__sha2_256->__buffer[j * 4] << 24) | ((__sha2_256->__buffer[j * 4 + 1]) << 16) | ((__sha2_256->__buffer[j * 4 + 2]) << 8) | ((__sha2_256->__buffer[j * 4 + 3]));
	for (j = 16; j < 64; j++) {
		UI4 s0 = (__MASTER_HASHLIB_FUNCTION_RLR32(W[j - 15], 7)) ^ (__MASTER_HASHLIB_FUNCTION_RLR32(W[j - 15], 18)) ^ (W[j - 15] >> 3);
		UI4 s1 = (__MASTER_HASHLIB_FUNCTION_RLR32(W[j - 2], 17)) ^ (__MASTER_HASHLIB_FUNCTION_RLR32(W[j - 2], 19)) ^ (W[j - 2] >> 10);
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
		__sha2_256->__buffer[__sha2_256->__len++ % 64] = *(__s++);
		if (__sha2_256->__len % 64 == 0)
			__MASTER_SHA2_256_Transform(__sha2_256);
	}
}

void
MASTER_SHA2_256_Final(MASTER_SHA2_256 * __sha2_256, UI1 * hash_output) {
	UI1 bits[8];
	UI4 index, padLen, i;

	bits[0] = ((__sha2_256->__len << 3) >> 56) & 0xff;
	bits[1] = ((__sha2_256->__len << 3) >> 48) & 0xff;
	bits[2] = ((__sha2_256->__len << 3) >> 40) & 0xff;
	bits[3] = ((__sha2_256->__len << 3) >> 32) & 0xff;
	bits[4] = ((__sha2_256->__len << 3) >> 24) & 0xff;
	bits[5] = ((__sha2_256->__len << 3) >> 16) & 0xff;
	bits[6] = ((__sha2_256->__len << 3) >> 8) & 0xff;
	bits[7] = ((__sha2_256->__len << 3)) & 0xff;
	
	index = ((__sha2_256->__len) & 0x3f);
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
			UI4 s0 = (__MASTER_HASHLIB_FUNCTION_RLR32(W[j - 15], 7)) ^ (__MASTER_HASHLIB_FUNCTION_RLR32(W[j - 15], 18)) ^ (W[j - 15] >> 3);
					UI4 s1 = (__MASTER_HASHLIB_FUNCTION_RLR32(W[j - 2], 17)) ^ (__MASTER_HASHLIB_FUNCTION_RLR32(W[j - 2], 19)) ^ (W[j - 2] >> 10);
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

#define __MASTER_SHA2_512_FUNCTION_SIGMA0(A) ((__MASTER_HASHLIB_FUNCTION_RLR64(A, 28)) ^ (__MASTER_HASHLIB_FUNCTION_RLR64(A, 34)) ^ (__MASTER_HASHLIB_FUNCTION_RLR64(A, 39)))
#define __MASTER_SHA2_512_FUNCTION_SIGMA1(A) ((__MASTER_HASHLIB_FUNCTION_RLR64(E, 14)) ^ (__MASTER_HASHLIB_FUNCTION_RLR64(E, 18)) ^ (__MASTER_HASHLIB_FUNCTION_RLR64(E, 41)))
#define __MASTER_SHA2_512_FUNCTION_MAJ(A, B, C) ((A & B) ^ (A & C) ^ (B & C))
#define __MASTER_SHA2_512_FUNCTION_CH(E, F, G) ((E & F) ^ ((~E) & G))

typedef struct {
	UI8 __H0, __H1, __H2, __H3,
					   __H4, __H5, __H6, __H7;
	UI1 __buffer[128];
	UI8 __len;
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
	__sha2_512.__len = 0;
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
		UI8 s0 = (__MASTER_HASHLIB_FUNCTION_RLR64(W[j - 15], 1)) ^ (__MASTER_HASHLIB_FUNCTION_RLR64(W[j - 15], 8)) ^ (W[j - 15] >> 7);
		UI8 s1 = (__MASTER_HASHLIB_FUNCTION_RLR64(W[j - 2], 19)) ^ (__MASTER_HASHLIB_FUNCTION_RLR64(W[j - 2], 61)) ^ (W[j - 2] >> 6);
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
		__sha2_512->__buffer[__sha2_512->__len++ % 128] = *(__s++);
		if (__sha2_512->__len % 128 == 0)
			__MASTER_SHA2_512_Transform(__sha2_512);
	}
}

void
MASTER_SHA2_512_Final(MASTER_SHA2_512 * __sha2_512, UI1 * hash_output) {
	UI1 bits[8];
	UI4 mdi, padding_len, i;
	
	bits[0] = ((__sha2_512->__len << 3) >> 56) & 0xff;
	bits[1] = ((__sha2_512->__len << 3) >> 48) & 0xff;
	bits[2] = ((__sha2_512->__len << 3) >> 40) & 0xff;
	bits[3] = ((__sha2_512->__len << 3) >> 32) & 0xff;
	bits[4] = ((__sha2_512->__len << 3) >> 24) & 0xff;
	bits[5] = ((__sha2_512->__len << 3) >> 16) & 0xff;
	bits[6] = ((__sha2_512->__len << 3) >> 8) & 0xff;
	bits[7] = ((__sha2_512->__len << 3)) & 0xff;
	
	mdi = __sha2_512->__len % 128;
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
			UI8 s0 = (__MASTER_HASHLIB_FUNCTION_RLR64(W[j - 15], 1)) ^ (__MASTER_HASHLIB_FUNCTION_RLR64(W[j - 15], 8)) ^ (W[j - 15] >> 7);
					UI8 s1 = (__MASTER_HASHLIB_FUNCTION_RLR64(W[j - 2], 19)) ^ (__MASTER_HASHLIB_FUNCTION_RLR64(W[j - 2], 61)) ^ (W[j - 2] >> 6);
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
	UI8 __len;
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
	__sha2_384.__len = 0;
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
		UI8 s0 = (__MASTER_HASHLIB_FUNCTION_RLR64(W[j - 15], 1)) ^ (__MASTER_HASHLIB_FUNCTION_RLR64(W[j - 15], 8)) ^ (W[j - 15] >> 7);
		UI8 s1 = (__MASTER_HASHLIB_FUNCTION_RLR64(W[j - 2], 19)) ^ (__MASTER_HASHLIB_FUNCTION_RLR64(W[j - 2], 61)) ^ (W[j - 2] >> 6);
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
		__sha2_384->__buffer[__sha2_384->__len++ % 128] = *(__s++);
		if (__sha2_384->__len % 128 == 0)
			__MASTER_SHA2_384_Transform(__sha2_384);
	}
}

void
MASTER_SHA2_384_Final(MASTER_SHA2_384 * __sha2_384, UI1 * hash_output) {
	UI1 bits[8];
	UI4 mdi, padding_len, i;
	
	bits[0] = ((__sha2_384->__len << 3) >> 56) & 0xff;
	bits[1] = ((__sha2_384->__len << 3) >> 48) & 0xff;
	bits[2] = ((__sha2_384->__len << 3) >> 40) & 0xff;
	bits[3] = ((__sha2_384->__len << 3) >> 32) & 0xff;
	bits[4] = ((__sha2_384->__len << 3) >> 24) & 0xff;
	bits[5] = ((__sha2_384->__len << 3) >> 16) & 0xff;
	bits[6] = ((__sha2_384->__len << 3) >> 8) & 0xff;
	bits[7] = ((__sha2_384->__len << 3)) & 0xff;
	
	mdi = __sha2_384->__len % 128;
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
			UI8 s0 = (__MASTER_HASHLIB_FUNCTION_RLR64(W[j - 15], 1)) ^ (__MASTER_HASHLIB_FUNCTION_RLR64(W[j - 15], 8)) ^ (W[j - 15] >> 7);
					UI8 s1 = (__MASTER_HASHLIB_FUNCTION_RLR64(W[j - 2], 19)) ^ (__MASTER_HASHLIB_FUNCTION_RLR64(W[j - 2], 61)) ^ (W[j - 2] >> 6);
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
	UI8 __len;
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
	__sha2_512_224.__len = 0;
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
		UI8 s0 = (__MASTER_HASHLIB_FUNCTION_RLR64(W[j - 15], 1)) ^ (__MASTER_HASHLIB_FUNCTION_RLR64(W[j - 15], 8)) ^ (W[j - 15] >> 7);
		UI8 s1 = (__MASTER_HASHLIB_FUNCTION_RLR64(W[j - 2], 19)) ^ (__MASTER_HASHLIB_FUNCTION_RLR64(W[j - 2], 61)) ^ (W[j - 2] >> 6);
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
		__sha2_512_224->__buffer[__sha2_512_224->__len++ % 128] = *(__s++);
		if (__sha2_512_224->__len % 128 == 0)
			__MASTER_SHA2_512_224_Transform(__sha2_512_224);
	}
}

void
MASTER_SHA2_512_224_Final(MASTER_SHA2_512_224 * __sha2_512_224, UI1 * hash_output) {
	UI1 bits[8];
	UI4 mdi, padding_len, i;
	
	bits[0] = ((__sha2_512_224->__len << 3) >> 56) & 0xff;
	bits[1] = ((__sha2_512_224->__len << 3) >> 48) & 0xff;
	bits[2] = ((__sha2_512_224->__len << 3) >> 40) & 0xff;
	bits[3] = ((__sha2_512_224->__len << 3) >> 32) & 0xff;
	bits[4] = ((__sha2_512_224->__len << 3) >> 24) & 0xff;
	bits[5] = ((__sha2_512_224->__len << 3) >> 16) & 0xff;
	bits[6] = ((__sha2_512_224->__len << 3) >> 8) & 0xff;
	bits[7] = ((__sha2_512_224->__len << 3)) & 0xff;
	
	mdi = __sha2_512_224->__len % 128;
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
			UI8 s0 = (__MASTER_HASHLIB_FUNCTION_RLR64(W[j - 15], 1)) ^ (__MASTER_HASHLIB_FUNCTION_RLR64(W[j - 15], 8)) ^ (W[j - 15] >> 7);
					UI8 s1 = (__MASTER_HASHLIB_FUNCTION_RLR64(W[j - 2], 19)) ^ (__MASTER_HASHLIB_FUNCTION_RLR64(W[j - 2], 61)) ^ (W[j - 2] >> 6);
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
	UI8 __len;
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
	__sha2_512_256.__len = 0;
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
		UI8 s0 = (__MASTER_HASHLIB_FUNCTION_RLR64(W[j - 15], 1)) ^ (__MASTER_HASHLIB_FUNCTION_RLR64(W[j - 15], 8)) ^ (W[j - 15] >> 7);
		UI8 s1 = (__MASTER_HASHLIB_FUNCTION_RLR64(W[j - 2], 19)) ^ (__MASTER_HASHLIB_FUNCTION_RLR64(W[j - 2], 61)) ^ (W[j - 2] >> 6);
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
		__sha2_512_256->__buffer[__sha2_512_256->__len++ % 128] = *(__s++);
		if (__sha2_512_256->__len % 128 == 0)
			__MASTER_SHA2_512_256_Transform(__sha2_512_256);
	}
}

void
MASTER_SHA2_512_256_Final(MASTER_SHA2_512_256 * __sha2_512_256, UI1 * hash_output) {
	UI1 bits[8];
	UI4 mdi, padding_len, i;
	
	bits[0] = ((__sha2_512_256->__len << 3) >> 56) & 0xff;
	bits[1] = ((__sha2_512_256->__len << 3) >> 48) & 0xff;
	bits[2] = ((__sha2_512_256->__len << 3) >> 40) & 0xff;
	bits[3] = ((__sha2_512_256->__len << 3) >> 32) & 0xff;
	bits[4] = ((__sha2_512_256->__len << 3) >> 24) & 0xff;
	bits[5] = ((__sha2_512_256->__len << 3) >> 16) & 0xff;
	bits[6] = ((__sha2_512_256->__len << 3) >> 8) & 0xff;
	bits[7] = ((__sha2_512_256->__len << 3)) & 0xff;
	
	mdi = __sha2_512_256->__len % 128;
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
			UI8 s0 = (__MASTER_HASHLIB_FUNCTION_RLR64(W[j - 15], 1)) ^ (__MASTER_HASHLIB_FUNCTION_RLR64(W[j - 15], 8)) ^ (W[j - 15] >> 7);
					UI8 s1 = (__MASTER_HASHLIB_FUNCTION_RLR64(W[j - 2], 19)) ^ (__MASTER_HASHLIB_FUNCTION_RLR64(W[j - 2], 61)) ^ (W[j - 2] >> 6);
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

// !# SHA-2

#undef __MASTER_SHA2_FUNCTION_SIGMA0
#undef __MASTER_SHA2_FUNCTION_SIGMA1
#undef __MASTER_SHA2_FUNCTION_MAJ
#undef __MASTER_SHA2_FUNCTION_CH
#undef __MASTER_SHA2_512_FUNCTION_SIGMA0
#undef __MASTER_SHA2_512_FUNCTION_SIGMA1
#undef __MASTER_SHA2_512_FUNCTION_MAJ
#undef __MASTER_SHA2_512_FUNCTION_CH

// #! SHA-3

#define REPEAT6(e) e e e e e e
#define REPEAT24(e) REPEAT6(e e e e)
#define REPEAT5(e) e e e e e
#define FOR5(v, s, e) \
	v = 0; \
	REPEAT5(e; v += s;)

#define FOR(i, ST, L, S) \
	 do { for (UI4 i = 0; i < L; i += ST) { S; } } while (0)
#define mkapply_ds(NAME, S)	\
	static inline void \
	NAME(UI1 * dst, \
		 const UI1 * src, \
		 UI4 len) { \
		FOR(i, 1, len, S); \
	}
#define mkapply_sd(NAME, S) \
	static inline void \
	NAME(const UI1 * src, \
		 UI1 * dst,	\
		 UI4 len) { \
		FOR(i, 1, len, S); }

#define foldP(I, L, F) \
	while (L >= rate) {	\
		F(a, I, rate); \
		MASTER_SHA3_FUNCTION_KECCAKF(a);	\
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
	MASTER_SHAKE##bits \
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
		MASTER_SHA3_FUNCTION_HASH(hash_output, bits / 4, __s, __l, 200 - (bits / 4), 0x1f);	}

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
	MASTER_SHA3_##bits \
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
		MASTER_SHA3_FUNCTION_HASH(hash_output, bits / 8, __s, __l, 200 - (bits / 4), 0x06);	}

static const UI1 MASTER_SHA3_Table_RHO[24] = {
	1, 3, 6, 10, 15, 21,
	28, 36, 45, 55,	2, 14,
	27, 41, 56,	8, 25, 43,
	62, 18, 39, 61, 20, 44
};
static const UI1 MASTER_SHA3_Table_PI[24] = {
	10,7, 11, 17, 18, 3,
	5, 16, 8, 21, 24, 4,
	15, 23, 19, 13, 12, 2,
	20, 14, 22, 9, 6, 1
};
static const UI8 MASTER_SHA3_Table_RC[24] = {
	1ULL, 0x8082ULL, 0x800000000000808aULL, 0x8000000080008000ULL,
	0x808bULL, 0x80000001ULL, 0x8000000080008081ULL, 0x8000000000008009ULL,
	0x8aULL, 0x88ULL, 0x80008009ULL, 0x8000000aULL,
	0x8000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL, 0x8000000000008003ULL,
	0x8000000000008002ULL, 0x8000000000000080ULL, 0x800aULL, 0x800000008000000aULL,
	0x8000000080008081ULL, 0x8000000000008080ULL, 0x80000001ULL, 0x8000000080008008ULL
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
							a[y + x] ^= b[(x + 4) % 5] ^ __MASTER_HASHLIB_FUNCTION_RLL64(b[(x + 1) % 5], 1); ))
		t = a[1];
		x = 0;
		REPEAT24(b[0] = a[MASTER_SHA3_Table_PI[x]];
						 a[MASTER_SHA3_Table_PI[x]] = __MASTER_HASHLIB_FUNCTION_RLL64(t, MASTER_SHA3_Table_RHO[x]);
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
MASTER_SHA3_FUNCTION_HASH(UI1 * out, UI4 outlen,
						  const UI1 * in, UI4 inlen,
						  UI4 rate, UI1 delim) {
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
#define __MASTER_RIPEMD128_FUNCTION_FF(a, b, c, d, x, s) a += __MASTER_RIPEMD128_FUNCTION_F(b, c, d) + (x), a = __MASTER_HASHLIB_FUNCTION_RLL32(a, s)
#define __MASTER_RIPEMD128_FUNCTION_GG(a, b, c, d, x, s) a += __MASTER_RIPEMD128_FUNCTION_G(b, c, d) + (x) + 0x5A827999, a = __MASTER_HASHLIB_FUNCTION_RLL32(a, s)
#define __MASTER_RIPEMD128_FUNCTION_HH(a, b, c, d, x, s) a += __MASTER_RIPEMD128_FUNCTION_H(b, c, d) + (x) + 0x6ED9EBA1, a = __MASTER_HASHLIB_FUNCTION_RLL32(a, s)
#define __MASTER_RIPEMD128_FUNCTION_II(a, b, c, d, x, s) a += __MASTER_RIPEMD128_FUNCTION_I(b, c, d) + (x) + 0x8F1BBCDC, a = __MASTER_HASHLIB_FUNCTION_RLL32(a, s)
#define __MASTER_RIPEMD128_FUNCTION_FFF(a, b, c, d, x, s) a += __MASTER_RIPEMD128_FUNCTION_F(b, c, d) + (x), a = __MASTER_HASHLIB_FUNCTION_RLL32(a, s)
#define __MASTER_RIPEMD128_FUNCTION_GGG(a, b, c, d, x, s) a += __MASTER_RIPEMD128_FUNCTION_G(b, c, d) + (x) + 0x6D703EF3, a = __MASTER_HASHLIB_FUNCTION_RLL32(a, s)
#define __MASTER_RIPEMD128_FUNCTION_HHH(a, b, c, d, x, s) a += __MASTER_RIPEMD128_FUNCTION_H(b, c, d) + (x) + 0x5C4DD124, a = __MASTER_HASHLIB_FUNCTION_RLL32(a, s)
#define __MASTER_RIPEMD128_FUNCTION_III(a, b, c, d, x, s) a += __MASTER_RIPEMD128_FUNCTION_I(b, c, d) + (x) + 0x50A28BE6, a = __MASTER_HASHLIB_FUNCTION_RLL32(a, s)

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

// !!# RIPEMD128

// #!! RIPEMD160

#define __MASTER_RIPEMD160_FUNCTION_F(x, y, z) ((x) ^ (y) ^ (z))
#define __MASTER_RIPEMD160_FUNCTION_G(x, y, z) (((x) & (y)) | (~(x) & (z)))
#define __MASTER_RIPEMD160_FUNCTION_H(x, y, z) (((x) | ~(y)) ^ (z))
#define __MASTER_RIPEMD160_FUNCTION_I(x, y, z) (((x) & (z)) | ((y) & ~(z)))
#define __MASTER_RIPEMD160_FUNCTION_J(x, y, z) ((x) ^ ((y) | ~(z)))
#define __MASTER_RIPEMD160_FUNCTION_FF(a, b, c, d, e, x, s) a += __MASTER_RIPEMD160_FUNCTION_F(b, c, d) + (x), a = __MASTER_HASHLIB_FUNCTION_RLL32(a, s) + (e), c = __MASTER_HASHLIB_FUNCTION_RLL32(c, 10)
#define __MASTER_RIPEMD160_FUNCTION_GG(a, b, c, d, e, x, s) a += __MASTER_RIPEMD160_FUNCTION_G(b, c, d) + (x) + 0x5A827999, a = __MASTER_HASHLIB_FUNCTION_RLL32(a, s) + (e), c = __MASTER_HASHLIB_FUNCTION_RLL32(c, 10)
#define __MASTER_RIPEMD160_FUNCTION_HH(a, b, c, d, e, x, s) a += __MASTER_RIPEMD160_FUNCTION_H(b, c, d) + (x) + 0x6ED9EBA1, a = __MASTER_HASHLIB_FUNCTION_RLL32(a, s) + (e), c = __MASTER_HASHLIB_FUNCTION_RLL32(c, 10)
#define __MASTER_RIPEMD160_FUNCTION_II(a, b, c, d, e, x, s) a += __MASTER_RIPEMD160_FUNCTION_I(b, c, d) + (x) + 0x8F1BBCDC, a = __MASTER_HASHLIB_FUNCTION_RLL32(a, s) + (e), c = __MASTER_HASHLIB_FUNCTION_RLL32(c, 10)
#define __MASTER_RIPEMD160_FUNCTION_JJ(a, b, c, d, e, x, s) a += __MASTER_RIPEMD160_FUNCTION_J(b, c, d) + (x) + 0xA953FD4E, a = __MASTER_HASHLIB_FUNCTION_RLL32(a, s) + (e), c = __MASTER_HASHLIB_FUNCTION_RLL32(c, 10)
#define __MASTER_RIPEMD160_FUNCTION_FFF(a, b, c, d, e, x, s) a += __MASTER_RIPEMD160_FUNCTION_F(b, c, d) + (x), a = __MASTER_HASHLIB_FUNCTION_RLL32(a, s) + (e), c = __MASTER_HASHLIB_FUNCTION_RLL32(c, 10)
#define __MASTER_RIPEMD160_FUNCTION_GGG(a, b, c, d, e, x, s) a += __MASTER_RIPEMD160_FUNCTION_G(b, c, d) + (x) + 0x7A6D76E9, a = __MASTER_HASHLIB_FUNCTION_RLL32(a, s) + (e), c = __MASTER_HASHLIB_FUNCTION_RLL32(c, 10)
#define __MASTER_RIPEMD160_FUNCTION_HHH(a, b, c, d, e, x, s) a += __MASTER_RIPEMD160_FUNCTION_H(b, c, d) + (x) + 0x6D703EF3, a = __MASTER_HASHLIB_FUNCTION_RLL32(a, s) + (e), c = __MASTER_HASHLIB_FUNCTION_RLL32(c, 10)
#define __MASTER_RIPEMD160_FUNCTION_III(a, b, c, d, e, x, s) a += __MASTER_RIPEMD160_FUNCTION_I(b, c, d) + (x) + 0x5C4DD124, a = __MASTER_HASHLIB_FUNCTION_RLL32(a, s) + (e), c = __MASTER_HASHLIB_FUNCTION_RLL32(c, 10)
#define __MASTER_RIPEMD160_FUNCTION_JJJ(a, b, c, d, e, x, s) a += __MASTER_RIPEMD160_FUNCTION_J(b, c, d) + (x) + 0x50A28BE6, a = __MASTER_HASHLIB_FUNCTION_RLL32(a, s) + (e), c = __MASTER_HASHLIB_FUNCTION_RLL32(c, 10)

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
        t = __MASTER_HASHLIB_FUNCTION_RLL32(aa + __MASTER_RIPEMD256_FUNCTION_FUNC(i, bb, cc, dd) + x[r[i]] + k[i/16], s[i]);
        aa = dd;
        dd = cc;
        cc = bb;
        bb = t;
        
        t = __MASTER_HASHLIB_FUNCTION_RLL32(aaa + __MASTER_RIPEMD256_FUNCTION_FUNC(63 - i, bbb, ccc, ddd) + x[r[64 + i]] + k[4 + (i/16)], s[64 + i]);
        aaa = ddd;
        ddd = ccc;
        ccc = bbb;
        bbb = t;

        if (i == 15) { t = aa; aa = aaa; aaa = t; }
        else if (i == 31) { t = bb; bb = bbb; bbb = t; }
        else if (i == 47) { t = cc; cc = ccc; ccc = t; }
        else if (i == 63) { t = dd; dd = ddd; ddd = t; }
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
        t = __MASTER_HASHLIB_FUNCTION_RLL32(aa + __MASTER_RIPEMD320_FUNCTION_FUNC(i, bb, cc, dd) + x[r[i]] + k[i/16], s[i]) + ee;
        aa = ee;
        ee = dd;
        dd = __MASTER_HASHLIB_FUNCTION_RLL32(cc, 10);
        cc = bb;
        bb = t;

        t = __MASTER_HASHLIB_FUNCTION_RLL32(aaa + __MASTER_RIPEMD320_FUNCTION_FUNC(79 - i, bbb, ccc, ddd) + x[r[80 + i]] + k[5 + i/16], s[80 + i]) + eee;
        aaa = eee;
        eee = ddd;
        ddd = __MASTER_HASHLIB_FUNCTION_RLL32(ccc, 10);
        ccc = bbb;
        bbb = t;

        if (i == 15) { t = bb; bb = bbb; bbb = t; }
        else if (i == 31) { t = dd; dd = ddd; ddd = t; }
        else if (i == 47) { t = aa; aa = aaa; aaa = t; }
        else if (i == 63) { t = cc; cc = ccc; ccc = t; }
        else if (i == 79) { t = ee; ee = eee; eee = t; }
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

// #! BLAKE2B

#define __MASTER_BLAKE2B_FUNCTION_G(x, y, a, b, c, d) do { \
	a = a + b + x; \
	d = __MASTER_HASHLIB_FUNCTION_RLR64(d ^ a, 32); \
	c += d; \
	b = __MASTER_HASHLIB_FUNCTION_RLR64(b ^ c, 24); \
	a = a + b + y; \
	d = __MASTER_HASHLIB_FUNCTION_RLR64(d ^ a, 16); \
	c += d; \
	b = __MASTER_HASHLIB_FUNCTION_RLR64(b ^ c, 63); \
} while (0);
#define __MASTER_BLAKE2S_FUNCTION_G(x, y, a, b, c, d) do { \
	a = a + b + x; \
	d = __MASTER_HASHLIB_FUNCTION_RLR32(d ^ a, 16); \
	c += d; \
	b = __MASTER_HASHLIB_FUNCTION_RLR32(b ^ c, 12); \
	a = a + b + y; \
	d = __MASTER_HASHLIB_FUNCTION_RLR32(d ^ a, 8); \
	c += d; \
	b = __MASTER_HASHLIB_FUNCTION_RLR32(b ^ c, 7); \
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

// !# BLAKE2B

// #! BLAKE2S

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
	for (i = 0; i < 8; i++)
		__blake2s.__h[i] = MASTER_BLAKE2S_TABLE_IV[i];
	__blake2s.__h[0] ^= 0x01010000 ^ outl;
	__blake2s.__t[0] = __blake2s.__t[1] = __blake2s.__c = 0;
	__blake2s.__outl = outl;
	for (i = 0; i < 64; i++)
		__blake2s.__b[i] = 0;
	return __blake2s;
}

void
MASTER_BLAKE2S_Update(MASTER_BLAKE2S * __blake2s, const char * __s, UI4 __l) {
	UI8 i;
	for (i = 0; i < __l; i++) {
		if (__blake2s->__c == 64) {
			__blake2s->__t[0] += __blake2s->__c;
			if (__blake2s->__t[0] < __blake2s->__c)
				__blake2s->__t[1]++;
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
	if (__blake2s->__t[0] < __blake2s->__c)
		__blake2s->__t[1]++;
	while (__blake2s->__c < 64)
		__blake2s->__b[__blake2s->__c++] = 0;
	MASTER_BLAKE2S_Compress(__blake2s, 1);
	for (i = 0; i < __blake2s->__outl; i++)
		hash_output[i] = (__blake2s->__h[i >> 2] >> (8 * (i & 3))) & 0xFF;
}

void
MASTER_BLAKE2S_CalculateHashSum(const char * __s, UI4 __l, UI1 * hash_output, UI4 outl) {
	MASTER_BLAKE2S __blake2s = MASTER_BLAKE2S_Init(outl);
	MASTER_BLAKE2S_Update(&__blake2s, __s, __l);
	MASTER_BLAKE2S_Final(&__blake2s, hash_output);
}

// !# BLAKE2S

// !# BLAKE

// #! WHIRLPOOL

typedef unsigned char UI1;
typedef unsigned short UI2;
typedef unsigned long UI4;
typedef unsigned long long UI8;

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
		b = ((__s[__sp] << __sg) & 0xFF) |
			((__s[__sp + 1] & 0xFF) >> (8 - __sg));
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
	__whirlpool->__bp	= __bp;
}

void
MASTER_WHIRLPOOL_CalculateHashSum(const char * __s, UI4 __l, UI1 * hash_output) {
	MASTER_WHIRLPOOL __whirlpool = MASTER_WHIRLPOOL_Init();
	MASTER_WHIRLPOOL_Update(&__whirlpool, __s, __l);
	MASTER_WHIRLPOOL_Final(&__whirlpool, hash_output);
}

// !# WHIRLPOOL

#endif /* __MASTER_HASHLIB_INCLUDE_H__ */

// be master~
