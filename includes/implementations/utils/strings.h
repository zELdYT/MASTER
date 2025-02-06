
/*
 * Copyright (c) 2025 zELdYT
 *
 * Licensed under the BSD 2-Clause License.
 * See the LICENSE file in the project root for more details.
 */

#ifndef __MASTER_STRINGS_INCLUDE_H__
#define __MASTER_STRINGS_INCLUDE_H__

#include "../../headers/enumeration/master_enum.h"
#include <string.h>

void
MASTER_strings_computeLPS( const char * pattern, const UI4 len, UI4 * lps ) {
	UI4 j = 0;
	lps[0] = 0;
	UI4 i = 1;
	while (i < len) {
		if (pattern[i] == pattern[j]) {
			j++;
			lps[i] = j;
			i++;
		} else {
			if (j != 0) j = lps[j - 1];
			else {
				lps[i] = 0;
				i++;
			}
		}
	}
}

UI4 * /* KMP algorithm - O(n + m) */
MASTER_strings_compare( const char * const p, const char * const s, UI4 * resultSize ) {
	if (p == 0 || s == 0 || resultSize == 0) return 0;
	UI4 n = strlen(s);
	UI4 m = strlen(p);
	UI4 lps[m];
	MASTER_strings_computeLPS(p, m, lps);
	UI4 * found = MASTER_MALLOC(16 * sizeof(UI4));
	UI4 i = 0, j = 0, k = 0;
	while (i < n) {
		if (p[j] == s[i]) {
			i++;
			j++;
		}
		if (j == m) {
			if (*resultSize % 16 == 0 && *resultSize != 0) found = MASTER_REALLOC(found, (*resultSize / 16 + 1) * 16);
			found[k++] = i - j;
			j = lps[j - 1];
		} else if (i < n && p[j] != s[i]) {
			if (j != 0) j = lps[j - 1];
			else i++;
		}
	}
	*resultSize = k;
	return found;
}

#endif /* __MASTER_STRINGS_INCLUDE_H__ */

// be master~
