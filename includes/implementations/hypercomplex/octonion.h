
/*
 * Copyright (c) 2025 zELdYT
 *
 * Licensed under the BSD 2-Clause License.
 * See the LICENSE file in the project root for more details.
 */

#ifndef __MASTER_OCTONION_INCLUDE_H__
#define __MASTER_OCTONION_INCLUDE_H__

/* #! Low priority !# */

#include <math.h> // sqrt
#include "../../headers/enumeration/master_enum.h"

#define __MASTER_MACROS_OCTONION_DEFINE_TYPE(type, prefix) \
typedef struct { \
	type real; \
	type imag; /* e1 */ \
	type jmag; /* e2 */ \
	type kmag; /* e3 */ \
	type lmag; /* e4 */ \
	type mmag; /* e5 */ \
	type nmag; /* e6 */ \
	type omag; /* e7 */ \
} MASTER_octonion##prefix; \
\
MASTER_octonion##prefix \
MASTER_octonion_toOctonion##prefix(type value) { \
	MASTER_octonion##prefix __octo; \
	__octo.real = value; \
	__octo.imag = __octo.jmag = __octo.kmag = __octo.lmag = __octo.mmag = __octo.nmag = __octo.omag = 0; \
	return __octo; } \
\
MASTER_octonion##prefix \
MASTER_octonion_add##prefix(const MASTER_octonion##prefix * __octo1, const MASTER_octonion##prefix * __octo2) { \
	MASTER_octonion##prefix octo; \
	octo.real = __octo1->real + __octo2->real; \
	octo.imag = __octo1->imag + __octo2->imag; \
	octo.jmag = __octo1->jmag + __octo2->jmag; \
	octo.kmag = __octo1->kmag + __octo2->kmag; \
	octo.lmag = __octo1->lmag + __octo2->lmag; \
	octo.mmag = __octo1->mmag + __octo2->mmag; \
	octo.nmag = __octo1->nmag + __octo2->nmag; \
	octo.omag = __octo1->omag + __octo2->omag; \
	return octo; } \
\
MASTER_octonion##prefix \
MASTER_octonion_sub##prefix(const MASTER_octonion##prefix * __octo1, const MASTER_octonion##prefix * __octo2) { \
	MASTER_octonion##prefix octo; \
	octo.real = __octo1->real - __octo2->real; \
	octo.imag = __octo1->imag - __octo2->imag; \
	octo.jmag = __octo1->jmag - __octo2->jmag; \
	octo.kmag = __octo1->kmag - __octo2->kmag; \
	octo.lmag = __octo1->lmag - __octo2->lmag; \
	octo.mmag = __octo1->mmag - __octo2->mmag; \
	octo.nmag = __octo1->nmag - __octo2->nmag; \
	octo.omag = __octo1->omag - __octo2->omag; \
	return octo; } \
\
MASTER_octonion##prefix \
MASTER_octonion_scalarmul##prefix(const MASTER_octonion##prefix * __octo1, const MASTER_octonion##prefix * __octo2) { \
	MASTER_octonion##prefix octo; \
	octo.real = __octo1->real * __octo2->real; \
	octo.imag = __octo1->imag * __octo2->imag; \
	octo.jmag = __octo1->jmag * __octo2->jmag; \
	octo.kmag = __octo1->kmag * __octo2->kmag; \
	octo.lmag = __octo1->lmag * __octo2->lmag; \
	octo.mmag = __octo1->mmag * __octo2->mmag; \
	octo.nmag = __octo1->nmag * __octo2->nmag; \
	octo.omag = __octo1->omag * __octo2->omag; \
	return octo; } \
\
MASTER_octonion##prefix \
MASTER_octonion_mul##prefix(const MASTER_octonion##prefix * __octo1, const MASTER_octonion##prefix * __octo2) { \
	MASTER_octonion##prefix octo; \
	octo.real = __octo1->real * __octo2->real - __octo1->imag * __octo2->imag \
				- __octo1->jmag * __octo2->jmag - __octo1->kmag * __octo2->kmag \
				- __octo1->lmag * __octo2->lmag - __octo1->mmag * __octo2->mmag \
				- __octo1->nmag * __octo2->nmag - __octo1->omag * __octo2->omag; \
	octo.imag = __octo1->real * __octo2->imag + __octo1->imag * __octo2->real \
				+ __octo1->jmag * __octo2->kmag - __octo1->kmag * __octo2->jmag \
				+ __octo1->lmag * __octo2->mmag - __octo1->mmag * __octo2->lmag \
				- __octo1->nmag * __octo2->omag + __octo1->omag * __octo2->nmag; \
	octo.jmag = __octo1->real * __octo2->jmag + __octo1->imag * __octo2->kmag \
				+ __octo1->jmag * __octo2->real - __octo1->kmag * __octo2->imag \
				+ __octo1->lmag * __octo2->nmag - __octo1->mmag * __octo2->omag \
				- __octo1->nmag * __octo2->lmag + __octo1->omag * __octo2->mmag; \
	octo.kmag = __octo1->real * __octo2->kmag + __octo1->imag * __octo2->lmag \
				+ __octo1->jmag * __octo2->nmag + __octo1->kmag * __octo2->real \
				- __octo1->lmag * __octo2->imag + __octo1->mmag * __octo2->jmag \
				- __octo1->nmag * __octo2->mmag + __octo1->omag * __octo2->lmag; \
	octo.lmag = __octo1->real * __octo2->lmag + __octo1->imag * __octo2->mmag \
				+ __octo1->jmag * __octo2->omag + __octo1->kmag * __octo2->nmag \
				+ __octo1->lmag * __octo2->real - __octo1->mmag * __octo2->imag \
				+ __octo1->nmag * __octo2->jmag - __octo1->omag * __octo2->kmag; \
	octo.mmag = __octo1->real * __octo2->mmag + __octo1->imag * __octo2->nmag \
				+ __octo1->jmag * __octo2->lmag + __octo1->kmag * __octo2->omag \
				+ __octo1->lmag * __octo2->kmag + __octo1->mmag * __octo2->real \
				- __octo1->nmag * __octo2->imag + __octo1->omag * __octo2->jmag; \
	octo.nmag = __octo1->real * __octo2->nmag + __octo1->imag * __octo2->omag \
				+ __octo1->jmag * __octo2->mmag + __octo1->kmag * __octo2->lmag \
				+ __octo1->lmag * __octo2->nmag + __octo1->mmag * __octo2->kmag \
				- __octo1->nmag * __octo2->real + __octo1->omag * __octo2->imag; \
	octo.omag = __octo1->real * __octo2->omag + __octo1->imag * __octo2->real \
				+ __octo1->jmag * __octo2->jmag + __octo1->kmag * __octo2->kmag \
				+ __octo1->lmag * __octo2->lmag + __octo1->mmag * __octo2->mmag \
				+ __octo1->nmag * __octo2->nmag + __octo1->omag * __octo2->real; \
	return octo; } /* Previous has been generated by AI. Can have problems. I will check it later */\
\
MASTER_octonion##prefix \
MASTER_octonion_div##prefix(const MASTER_octonion##prefix * __octo1, const MASTER_octonion##prefix * __octo2) { \
	MASTER_octonion##prefix octo; \
	octo.real = __octo2->real; \
	octo.imag = -__octo2->imag; \
	octo.jmag = -__octo2->jmag; \
	octo.kmag = -__octo2->kmag; \
	octo.lmag = -__octo2->lmag; \
	octo.mmag = -__octo2->mmag; \
	octo.nmag = -__octo2->nmag; \
	octo.omag = -__octo2->omag; \
	octo = MASTER_octonion_mul##prefix(__octo1, &octo); \
	type delim = MASTER_SQUARE(__octo2->real) + MASTER_SQUARE(__octo2->imag) + MASTER_SQUARE(__octo2->jmag) + MASTER_SQUARE(__octo2->kmag) + MASTER_SQUARE(__octo2->lmag) + MASTER_SQUARE(__octo2->mmag) + MASTER_SQUARE(__octo2->nmag) + MASTER_SQUARE(__octo2->omag); \
	octo.real /= delim; \
	octo.imag /= delim; \
	octo.jmag /= delim; \
	octo.kmag /= delim; \
	octo.lmag /= delim; \
	octo.mmag /= delim; \
	octo.nmag /= delim; \
	octo.omag /= delim; \
	return octo; } /* Teoretically & in my mind it need to work correctly */ \
\
type \
MASTER_octonion_norm##prefix(const MASTER_octonion##prefix * __octo) { \
	return sqrt(MASTER_SQUARE(__octo->real) + MASTER_SQUARE(__octo->imag) + MASTER_SQUARE(__octo->jmag) + MASTER_SQUARE(__octo->kmag) + MASTER_SQUARE(__octo->lmag) + MASTER_SQUARE(__octo->mmag) + MASTER_SQUARE(__octo->nmag) + MASTER_SQUARE(__octo->omag)); } \
\
MASTER_octonion##prefix \
MASTER_octonion_normalize##prefix(const MASTER_octonion##prefix * __octo) { \
	MASTER_octonion##prefix octo; \
	type delim = MASTER_octonion_norm##prefix(__octo); \
	octo.real = __octo->real / delim; \
	octo.imag = __octo->imag / delim; \
	octo.jmag = __octo->jmag / delim; \
	octo.kmag = __octo->kmag / delim; \
	octo.lmag = __octo->lmag / delim; \
	octo.mmag = __octo->mmag / delim; \
	octo.nmag = __octo->nmag / delim; \
	octo.omag = __octo->omag / delim; \
	return octo; } \
\
MASTER_octonion##prefix \
MASTER_octonion_conj##prefix(const MASTER_octonion##prefix * const __octo) { \
	MASTER_octonion##prefix octo; \
	octo.real = __octo->real; \
	octo.imag = -__octo->imag; \
	octo.jmag = -__octo->jmag; \
	octo.kmag = -__octo->kmag; \
	octo.lmag = -__octo->lmag; \
	octo.mmag = -__octo->mmag; \
	octo.nmag = -__octo->nmag; \
	octo.omag = -__octo->omag; \
	return octo; }

__MASTER_MACROS_OCTONION_DEFINE_TYPE(char,        c)
__MASTER_MACROS_OCTONION_DEFINE_TYPE(short,       s)
__MASTER_MACROS_OCTONION_DEFINE_TYPE(long,        l)
__MASTER_MACROS_OCTONION_DEFINE_TYPE(long long,   ll)
__MASTER_MACROS_OCTONION_DEFINE_TYPE(float,       f)
__MASTER_MACROS_OCTONION_DEFINE_TYPE(double,      d)
__MASTER_MACROS_OCTONION_DEFINE_TYPE(long double, ld)

#undef __MASTER_MACROS_OCTONION_DEFINE_TYPE

#endif /* __MASTER_OCTONION_INCLUDE_H__ */

// be master~
