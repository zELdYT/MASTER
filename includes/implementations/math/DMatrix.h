
/*
 * Copyright (c) 2025 zELdYT
 *
 * Licensed under the BSD 2-Clause License.
 * See the LICENSE file in the project root for more details.
 */

#ifndef __MASTER_DMATRIX_INCLUDE_H__
#define __MASTER_DMATRIX_INCLUDE_H__

/* #! Low priority !# */

#include <stdlib.h>
#include <math.h>

#include "../../headers/enumeration/master_enum.h"

#define __MASTER_dmatrix_IsSameSizes(m, n) ((m->__width == n->__width) && (m->__height == n->__height))
#define NULL_MATRIX {0, 0, 0, 0}

#define __MASTER_MACROS_CREATE_DMATRIX_TYPE__(type, suff) \
typedef struct { \
	UI2 __width, __height, __size; \
	type** __data; \
} MASTER_dmatrix##suff; \
\
void \
MASTER_dmatrix##suff##_MASTER_FREE(MASTER_dmatrix##suff * const m) { \
	if (m == 0) return; \
	UI2 i; \
	if (m->__data != 0) { \
		for (i = 0; i < m->__height; i++) { \
			if (m->__data[i] != 0) \
				MASTER_FREE(m->__data[i]); \
		} \
		MASTER_FREE(m->__data); \
		m->__data = 0; \
	} \
} \
\
int \
MASTER_dmatrix##suff##_init(MASTER_dmatrix##suff * const m, UI2 __width, UI2 __height) { \
	m->__data = (type**)MASTER_CALLOC(__height, sizeof(type *)); \
	if (m->__data == 0) { \
		MASTER_dmatrix##suff##_MASTER_FREE(m); \
		return 1; \
	} \
	UI2 i = 0; \
	for (; i < __height; i++) { \
		m->__data[i] = (type *)MASTER_MALLOC(__width * sizeof(type)); \
		if (m->__data[i] == 0) { \
			MASTER_dmatrix##suff##_MASTER_FREE(m); \
			return 1; \
		} \
	} \
	m->__width = __width; \
	m->__height = __height; \
	m->__size = sizeof(type); \
	return 0; \
} \
\
void \
MASTER_dmatrix##suff##_fill(MASTER_dmatrix##suff * const m, type filler) { \
	if (m == 0) return; \
	UI2 y, x; \
	for (y = 0; y < m->__height; y++) \
		for (x = 0; x < m->__width; x++) \
			m->__data[y][x] = filler; \
} \
\
void \
MASTER_dmatrix##suff##_fillZeros(MASTER_dmatrix##suff * const m) { \
	MASTER_dmatrix##suff##_fill(m, 0); \
} \
\
void \
MASTER_dmatrix##suff##_fillOnes(MASTER_dmatrix##suff * const m) { \
	MASTER_dmatrix##suff##_fill(m, 1); \
} \
\
void \
MASTER_dmatrix##suff##_mulScalar(MASTER_dmatrix##suff * const m, const type scalar) { \
	if (m == 0) return; \
	UI2 y, x; \
	for (y = 0; y < m->__height; y++) \
		for (x = 0; x < m->__width; x++) \
			m->__data[y][x] *= scalar; \
} \
\
void \
MASTER_dmatrix##suff##_negative(MASTER_dmatrix##suff * const m) { \
	if (m == 0) return; \
	MASTER_dmatrix##suff##_mulScalar(m, -1.0f); \
} \
\
MASTER_dmatrix##suff \
MASTER_dmatrix##suff##_transpose(MASTER_dmatrix##suff * const m) { \
	if (m == 0) return ((MASTER_dmatrix##suff)NULL_MATRIX); \
	MASTER_dmatrix##suff n; \
	if (MASTER_dmatrix##suff##_init(&n, m->__height, m->__width)) return ((MASTER_dmatrix##suff)NULL_MATRIX); \
	UI2 y, x; \
	for (y = 0; y < m->__height; y++) \
		for (x = 0; x < m->__width; x++) \
			n.__data[x][y] = m->__data[y][x]; \
	return n; \
} \
\
void \
MASTER_dmatrix##suff##_setXY(MASTER_dmatrix##suff * const m, UI2 x, UI2 y, type number) { \
	if (m == 0) return; \
	m->__data[y][x] = number; \
} \
\
type \
MASTER_dmatrix##suff##_getXY(MASTER_dmatrix##suff * const m, UI2 x, UI2 y) { \
	if (m == 0) return -1; \
	return m->__data[y][x]; \
} \
\
MASTER_dmatrix##suff \
MASTER_dmatrix##suff##_add(MASTER_dmatrix##suff * const m, MASTER_dmatrix##suff * n) { \
	if (m == 0 || n == 0 || !__MASTER_dmatrix_IsSameSizes(m, n)) return ((MASTER_dmatrix##suff)NULL_MATRIX); \
	MASTER_dmatrix##suff k; \
	if (MASTER_dmatrix##suff##_init(&k, m->__width, m->__height)) return ((MASTER_dmatrix##suff)NULL_MATRIX); \
	UI2 y, x; \
	for (y = 0; y < k.__height; y++) \
		for (x = 0; x < k.__width; x++) \
			k.__data[y][x] = m->__data[y][x] + n->__data[y][x]; \
	return k; \
} \
\
MASTER_dmatrix##suff \
MASTER_dmatrix##suff##_sub(MASTER_dmatrix##suff * const m, MASTER_dmatrix##suff * n) { \
	if (m == 0 || n == 0 || !__MASTER_dmatrix_IsSameSizes(m, n)) return ((MASTER_dmatrix##suff)NULL_MATRIX); \
	MASTER_dmatrix##suff k; \
	if (MASTER_dmatrix##suff##_init(&k, m->__width, m->__height)) return ((MASTER_dmatrix##suff)NULL_MATRIX); \
	UI2 y, x; \
	for (y = 0; y < k.__height; y++) \
		for (x = 0; x < k.__width; x++) \
			k.__data[y][x] = m->__data[y][x] - n->__data[y][x]; \
	return k; \
} \
\
MASTER_dmatrix##suff \
MASTER_dmatrix##suff##_mul(MASTER_dmatrix##suff * const m, MASTER_dmatrix##suff * n) { \
	if (m == 0 || n == 0 || m->__width != n->__height) return ((MASTER_dmatrix##suff)NULL_MATRIX); \
	MASTER_dmatrix##suff k; \
	if (MASTER_dmatrix##suff##_init(&k, m->__width, m->__height)) return ((MASTER_dmatrix##suff)NULL_MATRIX); \
	MASTER_dmatrix##suff##_fillZeros(&k); \
	UI2 y, x, yD; \
	for (y = 0; y < k.__height; y++) \
		for (x = 0; x < k.__width; x++) \
			for (yD = 0; yD < k.__height; yD++) \
				k.__data[y][x] += m->__data[y][yD] * n->__data[yD][x]; \
	return k; \
} \
\
MASTER_dmatrix##suff \
MASTER_dmatrix##suff##_div(MASTER_dmatrix##suff * const m, MASTER_dmatrix##suff * n) { \
	if (m == 0 || n == 0 || m->__width != n->__height) return ((MASTER_dmatrix##suff)NULL_MATRIX); \
	MASTER_dmatrix##suff k; \
	if (MASTER_dmatrix##suff##_init(&k, m->__width, m->__height)) return ((MASTER_dmatrix##suff)NULL_MATRIX); \
	MASTER_dmatrix##suff##_fillZeros(&k); \
	UI2 y, x, yD; \
	for (y = 0; y < k.__height; y++) \
		for (x = 0; x < k.__width; x++) \
			for (yD = 0; yD < k.__height; yD++) \
				k.__data[y][x] += m->__data[y][yD] / n->__data[yD][x]; \
	return k; \
} \
\
type \
MASTER_dmatrix##suff##_determinant(MASTER_dmatrix##suff * const m) { \
	if (m->__width != m->__height) return 0.0 / 0.0; \
	UI2 i, j, k, max_row; \
	type det = 1.0, * swap, factor; \
	if (m->__width == 1) return m->__data[0][0]; \
	if (m->__width == 2) return m->__data[0][0] * m->__data[1][1] - m->__data[0][1] * m->__data[1][0]; \
\
	MASTER_dmatrix##suff temp = ((MASTER_dmatrix##suff)NULL_MATRIX); \
	if (MASTER_dmatrix##suff##_init(&temp, m->__width, m->__width)) return 0.0 / 0.0; \
	for (i = 0; i < m->__width; i++) { \
		for (j = 0; j < m->__width; j++) \
			temp.__data[i][j] = m->__data[i][j]; \
	} \
\
	for (i = 0; i < m->__width - 1; i++) { \
		max_row = i; \
		for (k = i + 1; k < m->__width; k++) \
			if (MASTER_ABS(temp.__data[k][i]) > MASTER_ABS(temp.__data[max_row][i])) max_row = k; \
\
		if (i != max_row) { \
			swap = temp.__data[i]; \
			temp.__data[i] = temp.__data[max_row]; \
			temp.__data[max_row] = swap; \
			det *= -1.0f; \
		} \
\
		if (MASTER_ABS(temp.__data[i][i]) < 1e-6) { \
			MASTER_dmatrix##suff##_MASTER_FREE(&temp); \
			return 0.0f; \
		} \
\
		for (k = i + 1; k < m->__width; k++) { \
			factor = temp.__data[k][i] / temp.__data[i][i]; \
			for (j = i + 1; j < m->__width; j++) temp.__data[k][j] -= factor * temp.__data[i][j]; \
		} \
	} \
\
	for (i = 0; i < m->__width; i++) \
		det *= temp.__data[i][i]; \
\
	MASTER_dmatrix##suff##_MASTER_FREE(&temp); \
	return det; \
} \
\
MASTER_dmatrix##suff \
MASTER_dmatrix##suff##_minor(MASTER_dmatrix##suff * const m) { \
	if (m == 0 || m->__width != m->__height) return ((MASTER_dmatrix##suff)NULL_MATRIX); \
	MASTER_dmatrix##suff M = ((MASTER_dmatrix##suff)NULL_MATRIX), c = ((MASTER_dmatrix##suff)NULL_MATRIX); \
	if (MASTER_dmatrix##suff##_init(&M,  m->__width, m->__height)) return ((MASTER_dmatrix##suff)NULL_MATRIX); \
	if (MASTER_dmatrix##suff##_init(&c,  m->__width - 1, m->__height - 1)) return ((MASTER_dmatrix##suff)NULL_MATRIX); \
	UI2 y, x, yD, xD, yC, xC; \
	for (y = 0; y < m->__height; y++) \
		for (x = 0; x < m->__width; x++) { \
			xC = 0; yC = 0; \
			for (yD = 0; yD < m->__height; yD++) \
				for (xD = 0; xD < m->__width; xD++) \
					if (xD != x && yD != y) { \
						MASTER_dmatrix##suff##_setXY(&c, xC, yC, m->__data[yD][xD]); \
						if (++yC >= c.__height) { \
							yC = 0; \
							xC++; \
						} \
					} \
			MASTER_dmatrix##suff##_setXY(&M, x, y, MASTER_dmatrix##suff##_determinant(&c)); \
		} \
	return M; \
} \
\
MASTER_dmatrix##suff \
MASTER_dmatrix##suff##_algebraicAdditions(MASTER_dmatrix##suff * const m) { \
	if (m == 0) return ((MASTER_dmatrix##suff)NULL_MATRIX); \
	MASTER_dmatrix##suff n = *m; \
	UI2 y, x; \
	for (y = 0; y < n.__height; y++) \
		for (x = 0; x < n.__width; x++) \
			if ((y % 2 == 1) ^ (x % 2 == 1)) n.__data[y][x] *= -1; \
	return n;	 \
} \
\
MASTER_dmatrix##suff \
MASTER_dmatrix##suff##_inverse(MASTER_dmatrix##suff * const m) { \
	if (m == 0) return ((MASTER_dmatrix##suff)NULL_MATRIX); \
	MASTER_dmatrix##suff M = MASTER_dmatrix##suff##_minor(m); \
	M = MASTER_dmatrix##suff##_algebraicAdditions(&M); \
	M = MASTER_dmatrix##suff##_transpose(&M); \
	MASTER_dmatrix##suff##_mulScalar(&M, -1); \
	return M; \
}

__MASTER_MACROS_CREATE_DMATRIX_TYPE__(char,        c)
__MASTER_MACROS_CREATE_DMATRIX_TYPE__(short,       s)
__MASTER_MACROS_CREATE_DMATRIX_TYPE__(long,        l)
__MASTER_MACROS_CREATE_DMATRIX_TYPE__(long long,   ll)
__MASTER_MACROS_CREATE_DMATRIX_TYPE__(float,       f)
__MASTER_MACROS_CREATE_DMATRIX_TYPE__(double,      d)
__MASTER_MACROS_CREATE_DMATRIX_TYPE__(long double, ld)

#undef __MASTER_dmatrix_IsSameSizes
#undef __MASTER_CREATE_MATRIX_PACKAGE_TYPE

#endif /* __MASTER_DMATRIX_INCLUDE_H__ */

// be master~
