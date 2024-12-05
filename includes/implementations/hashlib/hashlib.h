
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
	UI1 ch, b, j;
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

#endif /* __MASTER_HASHLIB_INCLUDE_H__ */

// be master~
