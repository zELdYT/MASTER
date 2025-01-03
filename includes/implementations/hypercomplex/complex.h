
/*
 * Copyright (c) 2024 zELdYT
 *
 * Licensed under the BSD 2-Clause License.
 * See the LICENSE file in the project root for more details.
 */

#ifndef __MASTER_COMPLEX_INCLUDE_H__
#define __MASTER_COMPLEX_INCLUDE_H__

/* #! Low priority !# */

#include <math.h> // sqrt
#include "../../headers/enumeration/master_enum.h"

#define __MASTER_MACROS_COMPLEX_DEFINE_TYPE(type, prefix) \
typedef struct { \
	type real; \
	type imag; \
} MASTER_complex##prefix; \
\
MASTER_complex##prefix \
MASTER_complex_toComplex##prefix(const type value) { \
	MASTER_complex##prefix __comp; \
	__comp.real = value; \
	__comp.imag = 0; \
	return __comp; } \
\
MASTER_complex##prefix \
MASTER_complex_toComplexExt##prefix(const type real, const type imag) { \
	MASTER_complex##prefix __comp; \
	__comp.real = real; \
	__comp.imag = imag; \
	return __comp; } \
\
MASTER_complex##prefix \
MASTER_complex_add##prefix(const MASTER_complex##prefix * const __comp1, const MASTER_complex##prefix * const __comp2) { \
	MASTER_complex##prefix comp; \
	comp.real = __comp1->real + __comp2->real; \
	comp.imag = __comp1->imag + __comp2->imag; \
	return comp; } \
\
MASTER_complex##prefix \
MASTER_complex_sub##prefix(const MASTER_complex##prefix * const __comp1, const MASTER_complex##prefix * const __comp2) { \
	MASTER_complex##prefix comp; \
	comp.real = __comp1->real - __comp2->real; \
	comp.imag = __comp1->imag - __comp2->imag; \
	return comp; } \
\
MASTER_complex##prefix \
MASTER_complex_scalarmul##prefix(const MASTER_complex##prefix * const __comp1, const type scalar) { \
	MASTER_complex##prefix comp; \
	comp.real = __comp1->real * scalar; \
	comp.imag = __comp1->imag * scalar; \
	return comp; } \
\
MASTER_complex##prefix \
MASTER_complex_mul##prefix(const MASTER_complex##prefix * const __comp1, const MASTER_complex##prefix * const __comp2) { \
	MASTER_complex##prefix comp; \
	comp.real = __comp1->real * __comp2->real - __comp1->imag * __comp2->imag; \
	comp.imag = __comp1->real * __comp2->imag + __comp2->real * __comp1->imag; \
	return comp; } \
\
MASTER_complex##prefix \
MASTER_complex_div##prefix(const MASTER_complex##prefix * const __comp1, const MASTER_complex##prefix * const __comp2) { \
	MASTER_complex##prefix comp; \
	type delim = MASTER_SQUARE(__comp2->real) + MASTER_SQUARE(__comp2->imag); \
	comp.real = (__comp1->real * __comp2->real + __comp1->imag * __comp2->imag) / delim; \
	comp.imag = (__comp2->real * __comp1->imag - __comp1->real * __comp2->imag) / delim; \
	return comp; } \
\
type \
MASTER_complex_norm##prefix(const MASTER_complex##prefix * const __comp) { \
	return sqrt(MASTER_SQUARE(__comp->real) + MASTER_SQUARE(__comp->imag)); } \
\
MASTER_complex##prefix \
MASTER_complex_normalize##prefix(const MASTER_complex##prefix * const __comp) { \
	MASTER_complex##prefix comp; \
	type delim = MASTER_complex_norm##prefix(__comp); \
	comp.real = __comp->real / delim; \
	comp.imag = __comp->imag / delim; \
	return comp; } \
\
MASTER_complex##prefix \
MASTER_complex_exp##prefix(const MASTER_complex##prefix * const __comp) { \
	type e_real = exp(__comp->real); \
	MASTER_complex##prefix comp; \
	comp.real = e_real * cos(__comp->imag); \
	comp.imag = e_real * sin(__comp->imag); \
	return comp; } \
\
type \
MASTER_complex_arg##prefix(const MASTER_complex##prefix * const __comp) { \
	return atan2(__comp->imag, __comp->real); } \
\
MASTER_complex##prefix \
MASTER_complex_log##prefix(const MASTER_complex##prefix * const __comp) { \
	MASTER_complex##prefix comp; \
	comp.real = log(MASTER_complex_norm##prefix(__comp)); \
	comp.imag = MASTER_complex_arg##prefix(__comp); \
	return comp; } \
\
MASTER_complex##prefix \
MASTER_complex_sin##prefix(const MASTER_complex##prefix * const __comp) { \
	MASTER_complex##prefix comp; \
	comp.real = sin(__comp->real) * cosh(__comp->imag); \
	comp.imag = cos(__comp->real) * sinh(__comp->imag); \
	return comp; } \
\
MASTER_complex##prefix \
MASTER_complex_cos##prefix(const MASTER_complex##prefix * const __comp) { \
	MASTER_complex##prefix comp; \
	comp.real = cos(__comp->real) * cosh(__comp->imag); \
	comp.imag = -sin(__comp->real) * sinh(__comp->imag); \
	return comp; } \
\
MASTER_complex##prefix \
MASTER_complex_conj##prefix(const MASTER_complex##prefix * const __comp) { \
	MASTER_complex##prefix comp; \
	comp.real = __comp->real; \
	comp.imag = -__comp->imag; \
	return comp; } \
\
MASTER_complex##prefix \
MASTER_complex_from_polar##prefix(const type r, const type theta) { \
	MASTER_complex##prefix comp; \
	comp.real = r * cos(theta); \
	comp.imag = r * sin(theta); \
	return comp; }

__MASTER_MACROS_COMPLEX_DEFINE_TYPE(char,        c)
__MASTER_MACROS_COMPLEX_DEFINE_TYPE(short,       s)
__MASTER_MACROS_COMPLEX_DEFINE_TYPE(long,        l)
__MASTER_MACROS_COMPLEX_DEFINE_TYPE(long long,   ll)
__MASTER_MACROS_COMPLEX_DEFINE_TYPE(float,       f)
__MASTER_MACROS_COMPLEX_DEFINE_TYPE(double,      d)
__MASTER_MACROS_COMPLEX_DEFINE_TYPE(long double, ld)

#undef __MASTER_MACROS_COMPLEX_DEFINE_TYPE

#endif /* __MASTER_COMPLEX_INCLUDE_H__ */

// be master~
