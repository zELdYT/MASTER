
/*
 * Copyright (c) 2024 zELdYT
 *
 * Licensed under the BSD 2-Clause License.
 * See the LICENSE file in the project root for more details.
 */

#ifndef __MASTER_UNICODE_INCLUDE_H__
#define __MASTER_UNICODE_INCLUDE_H__

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
	} else if (__cp <= 0x7FF) { 
		__o[0] = 0xC0 | (__cp >> 6);
		__o[1] = 0x80 | (__cp & 0x3F);
		return 2;
	} else if (__cp <= 0xFFFF) { 
		__o[0] = 0xE0 | (__cp >> 12);
		__o[1] = 0x80 | ((__cp >> 6) & 0x3F);
		__o[2] = 0x80 | (__cp & 0x3F);
		return 3;
	} else if (__cp <= 0x10FFFF) { 
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

UI1
MASTER_unicode_isValid(UI4 __cp) {
	return !(__cp > 0x10FFFF || (__cp >= 0xD800 && __cp <= 0xDFFF));
}

#endif /* __MASTER_UNICODE_INCLUDE_H__ */

// be master~
