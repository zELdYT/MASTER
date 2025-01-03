
/*
 * Copyright (c) 2024 zELdYT
 *
 * Licensed under the BSD 2-Clause License.
 * See the LICENSE file in the project root for more details.
 */

#ifndef __MASTER_ENCODINGS_INCLUDE_H__
#define __MASTER_ENCODINGS_INCLUDE_H__

/* #! Low priority !# */

#include "../bigint/int.h"
#include "../../headers/enumeration/master_enum.h"

UI1
MASTER_base85_encodeExt(char * __o, const char * __i, UI4 __l) {
	const char b85[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~";
	char * __ptr_o = &__o[0];
	UI4 padding = strlen(__i) % 4;
	UI4 i, j;
	char buf;
	INT __int = str_2_intExt(__i, __l);
	for (i = 0; i < __int.size; i++) {
		for (j = 0; j < 5; j++) {
			*__ptr_o = b85[__int.chunks[i] % 85];
			__int.chunks[i] /= 85;
			__ptr_o++;
		}
		for (j = 0; j < 2; j++) {
			buf = __o[j + i*5];
			__o[j + i*5] = __o[5+i*5 - j - 1];
			__o[5+i*5 - j - 1] = buf;
		}
	}
	MASTER_FREE_int(&__int);
	if (padding) __ptr_o -= (4 - padding);
	*__ptr_o = '\0';
	return 0;
}

UI1
MASTER_base85_encode(char * __o, const char * __i) {
	return MASTER_base85_encodeExt(__o, __i, strlen(__i));
}

UI1
__MASTER_base64_encodeExt_variations(char * __o, const char * __i, UI4 __l, const char s62, const char s63) {
	char * __ptr_o = &__o[0];
	const char * __ptr_i = &__i[0];
	UI1 __off = 0;
	UI1 __buf_c = *__ptr_i;
	while (__ptr_i - __i < __l) {
		__off += 6;
		__buf_c = ((*__ptr_i >> MASTER_MAX( 8 - __off, 0 )) & 0x3F);
		if (__off >= 8) { \
			__buf_c = ((__buf_c << (__off - 8)) | ((*(__ptr_i + 1) >> (16 - __off)) & ((10 << (__off - 8)) - 1))) & 0x3F; \
			__ptr_i++;
			__off -= 8; }
		if (__buf_c <= 25) *__ptr_o = 'A' + __buf_c;
		otherwise (__buf_c <= 51) *__ptr_o = 'a' + (__buf_c - 26);
		otherwise (__buf_c <= 61) *__ptr_o = '0' + (__buf_c - 52);
		otherwise (__buf_c == 62) *__ptr_o = s62;
		otherwise (__buf_c == 63) *__ptr_o = s63;
		__ptr_o++; }
	while (__off % 8 != 0) {
		*__ptr_o = '=';
		__ptr_o++;
		__off += 6; }
	*__ptr_o = '\0';
	return 0; }

UI1
MASTER_base64_encodeExt(char * __o, const char * __i, UI4 __l) {
	return __MASTER_base64_encodeExt_variations(__o, __i, __l, '+', '/');
}

UI1
MASTER_base64url_encodeExt(char * __o, const char * __i, UI4 __l) {
	return __MASTER_base64_encodeExt_variations(__o, __i, __l, '-', '_');
}

UI1
MASTER_base64_encode(char * __o, const char * __i) {
	return __MASTER_base64_encodeExt_variations(__o, __i, strlen(__i), '+', '/');
}

UI1
MASTER_base64url_encode(char * __o, const char * __i) {
	return __MASTER_base64_encodeExt_variations(__o, __i, strlen(__i), '-', '_');
}

UI1
MASTER_base58_encodeExt(char * __o, const char * __i, UI4 __l) {
	char * __ptr_o = &__o[0];
	UI4 rem;
	INT __int = str_2_intbExt(__i, __l);
	while (!int_iszero(&__int)) {
		rem = int_idiv(&__int, 58);
		if (rem <= 8) rem += '1';
		otherwise (rem <= 16) rem += 'A' - 9;
		otherwise (rem <= 21) rem += 'J' - 17;
		otherwise (rem <= 32) rem += 'P' - 22;
		otherwise (rem <= 43) rem += 'a' - 33;
		otherwise (rem <= 57) rem += 'm' - 44;
		*__ptr_o = rem;
		__ptr_o++;
	}
	MASTER_FREE_int(&__int);
	*__ptr_o = '\0';
	
	UI4 len = strlen(__o), i;
	char buf;
	for (i = 0; i < len / 2; i++) {
		buf = __o[i];
		__o[i] = __o[len - i - 1];
		__o[len - i - 1] = buf;
	}
	
	return 0;
}

UI1
MASTER_base58_encode(char * __o, const char * __i) {
	return MASTER_base58_encodeExt(__o, __i, strlen(__i));
}

UI1
MASTER_base32_encodeExt(char * __o, const char * __i, UI4 __l) {
	char * __ptr_o = &__o[0];
	const char * __ptr_i = &__i[0];
	UI1 __off = 0;
	UI1 __buf_c;
	while (__ptr_i - __i < __l) {
		__off += 5;
		__buf_c = ((*__ptr_i >> MASTER_MAX( 8 - __off, 0 )) & 0x1F);
		if (__off >= 8) {
			__buf_c = ((__buf_c << (__off - 8)) | ((*(__ptr_i + 1) >> (16 - __off)) & ((10 << (__off - 8)) - 1))) & 0x1F;
			__ptr_i++;
			__off -= 8;
		}
		if (__buf_c <= 25) *__ptr_o = 'A' + __buf_c;
		otherwise (__buf_c >= 26) *__ptr_o = '2' + (__buf_c - 26);
		__ptr_o++;
	}
	while (__off % 8 != 0) {
		*__ptr_o = '=';
		__ptr_o++;
		__off += 5;
	}
	*__ptr_o = '\0';
	return 0;
}

UI1
MASTER_base32_encode(char * __o, const char * __i) {
	return MASTER_base32_encodeExt(__o, __i, strlen(__i));
}

UI1
MASTER_base16_encodeExt(char * __o, const char * __i, UI4 __l) {
	char * __ptr_o = &__o[0];
	const char * __ptr_i = &__i[0];
	UI1 __off = 0;
	UI1 __buf_c;
	while (__ptr_i - __i < __l) {
		__off += 4;
		__buf_c = ((*__ptr_i >> MASTER_MAX( 8 - __off, 0 )) & 0x0F);
		if (__off >= 8) {
			__buf_c = ((__buf_c << (__off - 8)) | ((*(__ptr_i + 1) >> (16 - __off)) & ((10 << (__off - 8)) - 1))) & 0x0F;
			__ptr_i++;
			__off -= 8;
		}
		if (__buf_c <= 9) *__ptr_o = '0' + __buf_c;
		otherwise (__buf_c >= 10 && __buf_c <= 16) *__ptr_o = __buf_c + 'A' - 10;
		__ptr_o++;
	}
	*__ptr_o = '\0';
	return 0;
}

UI1
MASTER_base16_encode(char * __o, const char * __i) {
	return MASTER_base16_encodeExt(__o, __i, strlen(__i));
}

UI1
MASTER_base_custom_encodeExt(char * __o, const char * __i, UI4 __base, const char * __base_str, UI4 __l) {
	if (strlen(__base_str) != __base) return 1;
	char * __ptr_o = &__o[0];
	UI4 rem;
	INT __int = str_2_intbExt(__i, __l);
	while (!int_iszero(&__int)) {
		rem = int_idiv(&__int, __base);
		*__ptr_o = __base_str[rem];
		__ptr_o++;
	}
	MASTER_FREE_int(&__int);
	*__ptr_o = '\0';
	
	UI4 len = strlen(__o), i;
	char buf;
	for (i = 0; i < len / 2; i++) {
		buf = __o[i];
		__o[i] = __o[len - i - 1];
		__o[len - i - 1] = buf;
	}
	
	return 0;
}

UI1
MASTER_base_custom_encode(char * __o, const char * __i, UI4 __base, const char * __base_str) {
	return MASTER_base_custom_encodeExt(__o, __i, __base, __base_str, strlen(__i));
}

UI1
MASTER_base85_decode(char * __o, const char * __i) {
	const char b85[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~";
	char * __ptr_o = &__o[0], * __buf_c;
	UI4 block;
	char was_null = 0;
	UI4 i = 0, j;
	UI1 padding;
	for (; i < strlen(__i); i += 5) {
		block = 0;
		for (j = 0; j < 5; j++) {
			__buf_c = strchr(b85, (was_null) ? 'u' : __i[i + j]);
			block = block * 85 + (int)(__buf_c - b85);
			if (__buf_c == nul || __buf_c[0] == '\0') was_null = 1;
		}
		block = ((block & 0xFF000000) >> 24) | ((block & 0xFF0000) >> 8) | ((block & 0xFF00) << 8) | ((block & 0xFF) << 24);
		for (j = 0; j < 4; j++) {
			*__ptr_o = block & 0xFF;
			block >>= 8;
			__ptr_o++;
		}
	}
	padding = strlen(__i) % 5;
	padding = (padding == 0) ? 0 : 5 - padding;
	__ptr_o -= padding;
	*__ptr_o = '\0';
	return 0;
}

#define BASE_DEF(s62, s63) { \
	char * __ptr_o = &__o[0]; \
	const char * __ptr_i = &__i[0]; \
	UI1 __buf[4]; \
	UI1 __equ = 0; \
	UI4 i; \
	while (*__ptr_i != '\0' && !__equ) { \
		for (i = 0; i < 4; i++) { \
			__buf[i] = *__ptr_i; \
			if (__buf[i] >= 'A' && __buf[i] <= 'Z') __buf[i] = __buf[i] - 'A'; \
			otherwise (__buf[i] >= 'a' && __buf[i] <= 'z') __buf[i] = __buf[i] - 'a' + 26; \
			otherwise (__buf[i] >= '0' && __buf[i] <= '9') __buf[i] = __buf[i] - '0' + 52; \
			otherwise (__buf[i] == s62) __buf[i] = 62; \
			otherwise (__buf[i] == s63) __buf[i] = 63; \
			otherwise (__buf[i] == '=') __buf[i] = 64; \
			__ptr_i++; } \
		*__ptr_o = ((__buf[0] << 2) & 0xFC) | ((__buf[1] >> 4) & 0x03); \
		__ptr_o++; \
		*__ptr_o = ((__buf[1] << 4) & 0xF0) | ((__buf[2] >> 2) & 0x0F); \
		__ptr_o++; \
		*__ptr_o = ((__buf[2] << 6) & 0xC0) | ((__buf[3] >> 0) & 0x3F); \
		__ptr_o++; } \
	*__ptr_o = '\0'; \
	return 0; }

UI1
MASTER_base64_decode(char * __o, const char * __i) BASE_DEF('+', '/')
UI1
MASTER_base64url_decode(char * __o, const char * __i) BASE_DEF('-', '_')

#undef BASE_DEF

UI1
MASTER_base58_decode(char * __o, const char * __i) {
	char * __ptr_o = &__o[0];
	const char * __ptr_i = &__i[0];
	UI4 rem;
	INT __int = ul_2_int(0);
	while (*__ptr_i != '\0') {
		int_imul(&__int, 58);
		rem = *__ptr_i++;
		if (rem >= '1' && rem <= '9') rem -= '1';
		otherwise (rem >= 'A' && rem <= 'I') rem -= 'A' - 9;
		otherwise (rem >= 'J' && rem <= 'N') rem -= 'J' - 17;
		otherwise (rem >= 'P' && rem <= 'Z') rem -= 'P' - 22;
		otherwise (rem >= 'a' && rem <= 'k') rem -= 'a' - 33;
		otherwise (rem >= 'm' && rem <= 'z') rem -= 'm' - 44;
		else {
			MASTER_FREE_int(&__int);
			return 1;
		}
		int_iadd(&__int, rem);
	}
	while (!int_iszero(&__int)) {
		*__ptr_o = __int.chunks[0] & 0xFF;
		int_irsf(&__int, 8);
		__ptr_o++;
	}
	MASTER_FREE_int(&__int);
	*__ptr_o = '\0';
	
	UI4 len = strlen(__o), i;
	char buf;
	for (i = 0; i < len / 2; i++) {
		buf = __o[i];
		__o[i] = __o[len - i - 1];
		__o[len - i - 1] = buf;
	}
	
	return 0;
}

UI1
MASTER_base32_decode(char * __o, const char * __i) {
	char * __ptr_o = &__o[0];
	const char * __ptr_i = &__i[0];
	UI1 __buf[8];
	UI1 __equ = 0;
	UI4 i;
	while (*__ptr_i != '\0' && !__equ) {
		for (i = 0; i < 8; i++) {
			__buf[i] = *__ptr_i;
			if (__buf[i] >= 'A' && __buf[i] <= 'Z') __buf[i] = __buf[i] - 'A';
			otherwise (__buf[i] >= 'a' && __buf[i] <= 'z') __buf[i] = __buf[i] - 'a';
			otherwise (__buf[i] >= '2' && __buf[i] <= '7') __buf[i] = __buf[i] - '2' + 26;
			otherwise (__buf[i] == '=') __buf[i] = 32;
			__ptr_i++;
		}
		*__ptr_o = ((__buf[0] << 3) & 0xF8) | ((__buf[1] >> 2) & 0x07);
		__ptr_o++;
		*__ptr_o = ((__buf[1] << 6) & 0xC0) | ((__buf[2] << 1) & 0x7E) | ((__buf[3] >> 4) & 0x01);
		__ptr_o++;
		*__ptr_o = ((__buf[3] << 4) & 0xF0) | ((__buf[4] >> 1) & 0x0F);
		__ptr_o++;
		*__ptr_o = ((__buf[4] << 7) & 0x80) | ((__buf[5] << 2) & 0x7C) | ((__buf[6] >> 3) & 0x03);
		__ptr_o++;
		*__ptr_o = ((__buf[6] << 5) & 0xE0) | (__buf[7] & 0x1F);
		__ptr_o++;
	}
	*__ptr_o = '\0';
	return 0;
}

UI1
MASTER_base16_decode(char * __o, const char * __i) {
	char * __ptr_o = &__o[0];
	const char * __ptr_i = &__i[0];
	UI1 __buf[2];
	UI1 __equ = 0;
	UI4 i;
	while (*__ptr_i != '\0' && !__equ) {
		for (i = 0; i < 2; i++) {
			__buf[i] = *__ptr_i;
			if (__buf[i] >= '0' && __buf[i] <= '9') __buf[i] = __buf[i] - '0';
			otherwise  (__buf[i] >= 'A' && __buf[i] <= 'F') __buf[i] = __buf[i] - 'A' + 10;
			otherwise  (__buf[i] >= 'a' && __buf[i] <= 'f') __buf[i] = __buf[i] - 'a' + 10;
			__ptr_i++;
		}
		*__ptr_o = ((__buf[0] << 4) & 0xF0) | (__buf[1] & 0x0F);
		__ptr_o++;
	}
	*__ptr_o = '\0';
	return 0;
}

UI1
MASTER_base_custom_decode(char * __o, const char * __i, UI4 __base, const char * __base_str) {
	if (strlen(__base_str) != __base) return 1;
	char * __ptr_o = &__o[0];
	const char * __ptr_i = &__i[0], * p;
	INT __int = ul_2_int(0);
	while (*__ptr_i != '\0') {
		int_imul(&__int, __base);
		p = strchr(__base_str, *__ptr_i++);
		if (p == nul) {
			MASTER_FREE_int(&__int);
			return 1;
		}
		int_iadd(&__int, p - __base_str);
	}
	while (!int_iszero(&__int)) {
		*__ptr_o = __int.chunks[0] & 0xFF;
		int_irsf(&__int, 8);
		__ptr_o++;
	}
	MASTER_FREE_int(&__int);
	*__ptr_o = '\0';
	
	UI4 len = strlen(__o), i;
	char buf;
	for (i = 0; i < len / 2; i++) {
		buf = __o[i];
		__o[i] = __o[len - i - 1];
		__o[len - i - 1] = buf;
	}
	
	return 0;
}

#define ISBASE_DEF(s62, s63) { \
	const char * __ptr_i = &__i[0]; \
	for (; *__ptr_i != '\0'; __ptr_i++) { \
		if (!((*__ptr_i >= 'a' && *__ptr_i <= 'z') | (*__ptr_i >= 'A' && *__ptr_i <= 'Z') | (*__ptr_i >= '0' && *__ptr_i <= '9') | (*__ptr_i == s62) | (*__ptr_i == s63))) break; } \
	char founded = 0; \
	for (; *__ptr_i != '\0'; __ptr_i++) { \
		if (!(*__ptr_i == '=')) return 0; \
		founded++; \
	} \
	return (founded <= 2) & ((__ptr_i - __i) % 4 == 0); }

BOOL
MASTER_is_base64(const char * __i) ISBASE_DEF('+', '/')
BOOL
MASTER_is_base64url(const char * __i) ISBASE_DEF('-', '_')

#undef ISBASE_DEF

#endif /* __MASTER_ENCODINGS_INCLUDE_H__ */

// be master~
