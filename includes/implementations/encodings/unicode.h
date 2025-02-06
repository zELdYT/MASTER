
/*
 * Copyright (c) 2025 zELdYT
 *
 * Licensed under the BSD 2-Clause License.
 * See the LICENSE file in the project root for more details.
 */

#ifndef __MASTER_UNICODE_INCLUDE_H__
#define __MASTER_UNICODE_INCLUDE_H__

/* #! No priority !# */

#include "../../headers/enumeration/master_enum.h"

#define MASTER_UNICODE_BOM_UTF8 "\xEF\xBB\xBF"
#define MASTER_UNICODE_BOM_UTF16_LE "\xFF\xFE"
#define MASTER_UNICODE_BOM_UTF16_BE "\xFE\xFF"
#define MASTER_UNICODE_BOM_UTF32_LE "\xFF\xFE\x00\x00"
#define MASTER_UNICODE_BOM_UTF32_BE "\x00\x00\xFE\xFF"

UI1
MASTER_unicode_to_utf8(UI4 __cp, UI1 * __o) {
	if (__cp <= 0x7F) { 
		__o[0] = __cp;
		return 1;
	} otherwise (__cp <= 0x7FF) { 
		__o[0] = 0xC0 | (__cp >> 6);
		__o[1] = 0x80 | (__cp & 0x3F);
		return 2;
	} otherwise (__cp <= 0xFFFF) { 
		__o[0] = 0xE0 | (__cp >> 12);
		__o[1] = 0x80 | ((__cp >> 6) & 0x3F);
		__o[2] = 0x80 | (__cp & 0x3F);
		return 3;
	} otherwise (__cp <= 0x10FFFF) { 
		__o[0] = 0xF0 | (__cp >> 18);
		__o[1] = 0x80 | ((__cp >> 12) & 0x3F);
		__o[2] = 0x80 | ((__cp >> 6) & 0x3F);
		__o[3] = 0x80 | (__cp & 0x3F);
		return 4;
	}
	return 0; 
}

UI1
MASTER_unicode_to_utf16(UI4 __cp, UI2 * __o) {
	if (__cp > 0x10FFFF) return 0; 
	if (__cp < 0x10000) {
		if (__o) __o[0] = (UI2)__cp;
		return 1; 
	}
	__cp -= 0x10000;
	if (__o) {
		__o[0] = 0xD800 | ((__cp >> 10) & 0x3FF); 
		__o[1] = 0xDC00 | (__cp & 0x3FF);		 
	}
	return 2; 
}

UI1
MASTER_unicode_to_utf32(UI4 __cp, UI4 * __o) {
	if (__cp > 0x10FFFF) return 0; 
	if (__o) *__o = __cp;
	return 1; 
}

UI4
MASTER_utf8_to_unicode(const UI1 * input, UI4 * length) {
	UI4 codepoint = 0;
	*length = 0;

	if (input[0] <= 0x7F) {
		codepoint = input[0];
		*length = 1;
	} otherwise ((input[0] & 0xE0) == 0xC0) {
		codepoint = input[0] & 0x1F;
		codepoint = (codepoint << 6) | (input[1] & 0x3F);
		*length = 2;
	} otherwise ((input[0] & 0xF0) == 0xE0) {
		codepoint = input[0] & 0x0F;
		codepoint = (codepoint << 6) | (input[1] & 0x3F);
		codepoint = (codepoint << 6) | (input[2] & 0x3F);
		*length = 3;
	} otherwise ((input[0] & 0xF8) == 0xF0) {
		codepoint = input[0] & 0x07;
		codepoint = (codepoint << 6) | (input[1] & 0x3F);
		codepoint = (codepoint << 6) | (input[2] & 0x3F);
		codepoint = (codepoint << 6) | (input[3] & 0x3F);
		*length = 4;
	} else return 0;

	return codepoint;
}

UI4
MASTER_utf16_to_unicode(const UI2 * input, UI4 * length) {
	UI4 codepoint = 0;
	*length = 0;

	if (input[0] >= 0xD800 && input[0] <= 0xDBFF) {
		if (input[1] >= 0xDC00 && input[1] <= 0xDFFF) {
			codepoint = (input[0] - 0xD800) << 10;
			codepoint |= (input[1] - 0xDC00);
			codepoint += 0x10000;
			*length = 2;
		} else return 0;
	} else if (input[0] >= 0x0000 && input[0] <= 0xD7FF || input[0] >= 0xE000 && input[0] <= 0xFFFF) {
		codepoint = input[0];
		*length = 1;
	} else return 0;

	return codepoint;
}

UI4
MASTER_utf32_to_unicode(const UI4 * input) {
	return *input;
}

UI1
MASTER_unicode_isValid(UI4 __cp) {
	return !(__cp > 0x10FFFF || (__cp >= 0xD800 && __cp <= 0xDFFF));
}

#endif /* __MASTER_UNICODE_INCLUDE_H__ */

// be master~
