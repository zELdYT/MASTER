
/*
 * Copyright (c) 2025 zELdYT
 *
 * Licensed under the BSD 2-Clause License.
 * See the LICENSE file in the project root for more details.
 */

#ifndef __MASTER_BIGINT_INCLUDE_H__
#define __MASTER_BIGINT_INCLUDE_H__

/* #! High priority !# */

#include "../../headers/enumeration/master_enum.h"

#define MASTER_IS_SIGN(c) ((c) == '+' || (c) == '-')

typedef struct {
	UI4 * chunks;
	UI4 size;
	// 0bEERRRNIS
	// S - sign (0 - "+", 1 - "-")
	// I - Infinity
	// N - NaN
	// E - error :
	// 00 - no error
	// 01 - cant MASTER_MALLOC / MASTER_REALLOC
	// 10 - incorrect action
	UI1 flags;
} MASTER_bigint;

#include <stdlib.h>
#include <string.h>

static void
MASTER_bigint_deleteZeros( MASTER_bigint * const bi ) {
	UI4 size = bi->size;
	UI4 * temp;
	while (size > 1 && bi->chunks[size - 1] == 0) size--;
	temp = MASTER_REALLOC(bi->chunks, size * sizeof(UI4));
	if (temp == 0) {
		bi->flags |= 0x40;
		return;
	}
	bi->chunks = temp;
	bi->size = size;
	if (bi->size == 1 && bi->chunks[0] == 0) bi->flags &= ~0x01;
	bi->flags &= ~0xA0;
}

MASTER_bigint
MASTER_bigint_fromUI32( UI4 value ) {
	MASTER_bigint bi;
	bi.size = 1;
	bi.flags = 0;
	bi.chunks = MASTER_MALLOC(sizeof(UI4));
	if (bi.chunks == 0) {
		bi.flags |= 0x40;
		return bi;
	}
	bi.chunks[0] = value;
	bi.flags &= ~0xA0;
	return bi;
}

MASTER_bigint
MASTER_bigint_fromSI32( SI4 value ) {
	MASTER_bigint bi;
	bi.size = 1;
	bi.flags = (value < 0);
	bi.chunks = MASTER_MALLOC(sizeof(UI4));
	if (bi.chunks == 0) {
		bi.flags |= 0x40;
		return bi;
	}
	if (bi.flags & 0x01) value = -value;
	bi.chunks[0] = value;
	bi.flags &= ~0xA0;
	return bi;
}

UI1
MASTER_bigint_checkErrors( const MASTER_bigint * const bi ) {
	return (bi->flags & 0xC0) >> 6;
}

void
MASTER_bigint_resetErrors( MASTER_bigint * const bi ) {
	bi->flags &= ~0xC0;
}

void
MASTER_bigint_MASTER_FREE( MASTER_bigint * const bi ) {
	if (bi) {
		if (bi->chunks) {
			MASTER_FREE(bi->chunks);
			bi->chunks = 0;
		}
		bi->size = bi->flags = 0;
	}
}

// #! OPERATORS

static UI1
MASTER_bigint_abs_greater_equal(const MASTER_bigint * const left, const MASTER_bigint * const right) {
	if (left->size > right->size) return 1;
	if (right->size > left->size) return 0;
	for (int i = left->size - 1; i >= 0; i--) {
		if (left->chunks[i] > right->chunks[i]) return 1;
		if (left->chunks[i] < right->chunks[i]) return 0;
	}
	return 1;
}

MASTER_bigint
MASTER_bigint_add( const MASTER_bigint * const, const MASTER_bigint * const );
MASTER_bigint
MASTER_bigint_sub( const MASTER_bigint * const, const MASTER_bigint * const );

MASTER_bigint
MASTER_bigint_add( const MASTER_bigint * const left, const MASTER_bigint * const right ) {
	MASTER_bigint result;
	result.size = 0;
	result.flags = 0;
	result.chunks = 0;

	/* Handling NaN */
	if (left->flags & 0x04 || right->flags & 0x04) {
		result.flags |= 0x04;
		result.chunks = MASTER_MALLOC(sizeof(UI4));
		if (!result.chunks) result.flags |= 0x40;
		result.size = 1;
		return result;
	}

	/* Handling infinity */
	if (left->flags & 0x02 || right->flags & 0x02) {
		result.flags |= 0x02;
		result.chunks = MASTER_MALLOC(sizeof(UI4));
		if (!result.chunks) result.flags |= 0x40;
		result.size = 1;
		if ((left->flags & 0x02) && (right->flags & 0x02)) {
			/* Infinity + Infinity */
			if ((left->flags & 0x01) == (right->flags & 0x01)) { /* Both positive or both negative */
				result.flags |= (left->flags & 0x01); /* Preserve the sign */
			} else { /* Different signs => NaN */
				result.flags &= ~0x02; /* Remove the infinity flag */
				result.flags |= 0x04; /* Set NaN flag */
				result.flags |= 0x80; /* Set "incorrect action" error flag */
			}
		} else if (left->flags & 0x02) { /* Infinity + finite number */
			result.flags |= (left->flags & 0x01); /* Sign as infinity */
		} else { /* Finite number + Infinity */
			result.flags |= (right->flags & 0x01); /* Sign as infinity */
		}
		return result;
	}

	if (left->flags & 0x01 && !(right->flags & 0x01)) { /* -left + right  => right - left */
		MASTER_bigint temp_left = *left;
		temp_left.flags &= ~0x01;
		return MASTER_bigint_sub(right, &temp_left);
	} else if (!(left->flags & 0x01) && (right->flags & 0x01)) { /* left + -right => left - right */
		MASTER_bigint temp_right = *right;
		temp_right.flags &= ~0x01;
		return MASTER_bigint_sub(left, &temp_right);
	} else if (left->flags & 0x01 && right->flags & 0x01) { /* -left + -right => -(left + right) */
		MASTER_bigint temp_left = *left;
		temp_left.flags &= ~0x01;
		MASTER_bigint temp_right = *right;
		temp_right.flags &= ~0x01;
		result = MASTER_bigint_add(&temp_left, &temp_right);
		if (!(result.flags & 0x40) && !(result.flags & 0x04)) result.flags |= 0x01; /* Don't set the minus sign if the result is NaN */
		return result;
	}

	UI4 size = (left->size > right->size ? left->size : right->size) + 1;
	result.chunks = MASTER_CALLOC(size, sizeof(UI4));
	if (!result.chunks) {
		result.flags |= 0x40;
		return result;
	}
	result.size = size;

	UI4 carry = 0, a, b, i = 0;
	for (; i < size - 1; i++) {
		a = (i < left->size) ? left->chunks[i] : 0;
		b = (i < right->size) ? right->chunks[i] : 0;
		result.chunks[i] = a + b + carry;
		MASTER_ADD_OVERFLOW_UI4(a, b, carry);
	}
	result.chunks[size - 1] = carry;

	MASTER_bigint_deleteZeros(&result);
	return result;
}

MASTER_bigint
MASTER_bigint_sub( const MASTER_bigint * const left, const MASTER_bigint * const right ) {
	MASTER_bigint result;
	result.size = 0;
	result.flags = 0;
	result.chunks = 0;

	/* Handling NaN */
	if (left->flags & 0x04 || right->flags & 0x04) {
		result.flags |= 0x04;
		result.chunks = MASTER_MALLOC(sizeof(UI4));
		if (!result.chunks) result.flags |= 0x40;
		result.size = 1;
		return result;
	}

	/* Handling infinity */
	if (left->flags & 0x02 || right->flags & 0x02) {
		result.flags |= 0x02;
		result.chunks = MASTER_MALLOC(sizeof(UI4));
		if (!result.chunks) result.flags |= 0x40;
		result.size = 1;
		if ((left->flags & 0x02) && (right->flags & 0x02)) { /* Infinity - Infinity */
			if ((left->flags & 0x01) == (right->flags & 0x01)) { /* Same signs => NaN */
				result.flags &= ~0x02;
				result.flags |= 0x04;
				result.flags |= 0x80;
			} else { /* Different signs */
				result.flags |= (left->flags & 0x01);
			}
		} else if (left->flags & 0x02) { /* Infinity - finite number */
			result.flags |= (left->flags & 0x01);
		} else { /* Finite number - Infinity */
			result.flags |= !(right->flags & 0x01);
		}
		return result;
	}

	if (!(left->flags & 0x01) && (right->flags & 0x01)) { /* left - (-right) => left + right */
		MASTER_bigint temp_right = *right;
		temp_right.flags &= ~0x01;
		return MASTER_bigint_add(left, &temp_right);
	} else if ((left->flags & 0x01) && !(right->flags & 0x01)) { /* -left - right => -(left + right) */
		MASTER_bigint temp_left = *left;
		temp_left.flags &= ~0x01;
		return MASTER_bigint_add(&temp_left, right);
	} else if (left->flags & 0x01 && right->flags & 0x01) { /* -left - (-right) => -left + right => right - left */
		MASTER_bigint temp_left = *left;
		temp_left.flags &= ~0x01;
		MASTER_bigint temp_right = *right;
		temp_right.flags &= ~0x01;
		return MASTER_bigint_sub(&temp_right, &temp_left);
	}

	const UI1 left_is_greater_or_equal = MASTER_bigint_abs_greater_equal(left, right);

	const MASTER_bigint * bigger = left_is_greater_or_equal ? left : right;
	const MASTER_bigint * smaller = left_is_greater_or_equal ? right : left;

	result.size = bigger->size;
	result.chunks = MASTER_CALLOC(result.size, sizeof(UI4));
	if (!result.chunks) {
		result.flags |= 0x40;
		return result;
	}

	UI4 borrow = 0, a, b;
	for (UI4 i = 0; i < result.size; i++) {
		a = (i < bigger->size) ? bigger->chunks[i] : 0;
		b = (i < smaller->size) ? smaller->chunks[i] : 0;

		if (borrow) {
			if (a > 0) a--;
			else a = ~0;
		}

		if (a >= b) {
			result.chunks[i] = a - b;
			borrow = 0;
		} else {
			result.chunks[i] = (a + (~((UI4)0)) + 1) - b;
			borrow = 1;
		}
	}

	if (!left_is_greater_or_equal) result.flags |= 0x01;

	MASTER_bigint_deleteZeros(&result);
	return result;
}

// !# OPERATORS

/* TODO :
 * Multiply :
 * - School algorithm
 * - Caracuba
 * - Tooma
 * - Tooma-3
 * - Tooma-4
 * - Fourier
 * Divide
 * Find sqrt
 * Compare :
 * - "=="
 * - "!="
 * - ">"
 * - ">="
 * - "<"
 * - "<="
 * To cpr
 */

#endif /* __MASTER_BIGINT_INCLUDE_H__ */

#include <stdio.h>

int
main() {
	MASTER_bigint bi = MASTER_bigint_fromUI32(2147483647);
	if (MASTER_bigint_checkErrors(&bi)) {
		puts("Error initializing number!");
		return 1;
	}
	MASTER_bigint bi2 = MASTER_bigint_fromUI32(2147483649);
	if (MASTER_bigint_checkErrors(&bi2)) {
		puts("Error initializing number!");
		return 1;
	}
	MASTER_bigint bi3 = MASTER_bigint_sub(&bi, &bi2);
	printf("%lu %lu, %d\n", bi3.chunks[1], bi3.chunks[0], bi3.flags);
	MASTER_bigint_MASTER_FREE(&bi);
	MASTER_bigint_MASTER_FREE(&bi2);
	MASTER_bigint_MASTER_FREE(&bi3);
	return 0;
}


// be master~
