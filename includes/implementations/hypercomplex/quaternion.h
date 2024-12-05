
/*
 * Copyright (c) 2024 zELdYT
 *
 * Licensed under the BSD 2-Clause License.
 * See the LICENSE file in the project root for more details.
 */

#ifndef __MASTER_QUATERNION_INCLUDE_H__
#define __MASTER_QUATERNION_INCLUDE_H__

#include <math.h> // sqrt

#define MASTER_SQUARE(x) (x*x)

#define __MASTER_MACROS_QUATERNION_DEFINE_TYPE(type, prefix) \
typedef struct { \
	type real; \
	type imag; \
	type jmag; \
	type kmag; \
} MASTER_quaternion##prefix; \
\
MASTER_quaternion##prefix \
MASTER_quaternion_toQuaternion##prefix(type value) { \
	MASTER_quaternion##prefix __quat; \
	__quat.real = value; \
	__quat.imag = __quat.jmag = __quat.kmag = 0; \
	return __quat; } \
\
MASTER_quaternion##prefix \
MASTER_quaternion_add##prefix(const MASTER_quaternion##prefix * __quat1, const MASTER_quaternion##prefix * __quat2) { \
	MASTER_quaternion##prefix quat; \
	quat.real = __quat1->real + __quat2->real; \
	quat.imag = __quat1->imag + __quat2->imag; \
	quat.jmag = __quat1->jmag + __quat2->jmag; \
	quat.kmag = __quat1->kmag + __quat2->kmag; \
	return quat; } \
\
MASTER_quaternion##prefix \
MASTER_quaternion_sub##prefix(const MASTER_quaternion##prefix * __quat1, const MASTER_quaternion##prefix * __quat2) { \
	MASTER_quaternion##prefix quat; \
	quat.real = __quat1->real - __quat2->real; \
	quat.imag = __quat1->imag - __quat2->imag; \
	quat.jmag = __quat1->jmag - __quat2->jmag; \
	quat.kmag = __quat1->kmag - __quat2->kmag; \
	return quat; } \
\
MASTER_quaternion##prefix \
MASTER_quaternion_scalarmul##prefix(const MASTER_quaternion##prefix * __quat1, const type scalar) { \
	MASTER_quaternion##prefix quat; \
	quat.real = __quat1->real * scalar; \
	quat.imag = __quat1->imag * scalar; \
	quat.jmag = __quat1->jmag * scalar; \
	quat.kmag = __quat1->kmag * scalar; \
	return quat; } \
\
MASTER_quaternion##prefix \
MASTER_quaternion_mul##prefix(const MASTER_quaternion##prefix * __quat1, const MASTER_quaternion##prefix * __quat2) { \
	MASTER_quaternion##prefix quat; \
	quat.real = __quat1->real * __quat2->real - __quat1->imag * __quat2->imag - __quat1->jmag * __quat2->jmag - __quat1->kmag * __quat2->kmag; \
	quat.imag = __quat1->real * __quat2->imag + __quat2->real * __quat1->imag + __quat1->jmag * __quat2->kmag - __quat2->jmag * __quat1->kmag; \
	quat.jmag = __quat1->real * __quat2->jmag + __quat2->real * __quat1->jmag + __quat2->imag * __quat1->kmag - __quat1->imag * __quat2->kmag; \
	quat.kmag = __quat1->real * __quat2->kmag + __quat2->real * __quat1->kmag + __quat1->imag * __quat2->jmag - __quat2->imag * __quat1->jmag; \
	return quat; } \
\
MASTER_quaternion##prefix \
MASTER_quaternion_div##prefix(const MASTER_quaternion##prefix * __quat1, const MASTER_quaternion##prefix * __quat2) { \
	MASTER_quaternion##prefix quat; \
	quat.real = __quat2->real; \
	quat.imag = -__quat2->imag; \
	quat.jmag = -__quat2->jmag; \
	quat.kmag = -__quat2->kmag; \
	quat = MASTER_quaternion_mul##prefix(__quat1, &quat); \
	type delim = MASTER_SQUARE(__quat2->real) + MASTER_SQUARE(__quat2->imag) + MASTER_SQUARE(__quat2->jmag) + MASTER_SQUARE(__quat2->kmag); \
	quat.real /= delim; \
	quat.imag /= delim; \
	quat.jmag /= delim; \
	quat.kmag /= delim; \
	return quat; } /* Teoretically & in my mind it need to work correctly */ \
\
type \
MASTER_quaternion_norm##prefix(const MASTER_quaternion##prefix * __quat) { \
	return sqrt(MASTER_SQUARE(__quat->real) + MASTER_SQUARE(__quat->imag) + MASTER_SQUARE(__quat->jmag) + MASTER_SQUARE(__quat->kmag)); } \
\
MASTER_quaternion##prefix \
MASTER_quaternion_normalize##prefix(const MASTER_quaternion##prefix * __quat) { \
	MASTER_quaternion##prefix quat; \
	type delim = MASTER_quaternion_norm##prefix(__quat); \
	quat.real = __quat->real / delim; \
	quat.imag = __quat->imag / delim; \
	quat.jmag = __quat->jmag / delim; \
	quat.kmag = __quat->kmag / delim; \
	return quat; }

__MASTER_MACROS_QUATERNION_DEFINE_TYPE(char,        c)
__MASTER_MACROS_QUATERNION_DEFINE_TYPE(short,       s)
__MASTER_MACROS_QUATERNION_DEFINE_TYPE(long,        l)
__MASTER_MACROS_QUATERNION_DEFINE_TYPE(long long,   ll)
__MASTER_MACROS_QUATERNION_DEFINE_TYPE(float,       f)
__MASTER_MACROS_QUATERNION_DEFINE_TYPE(double,      d)
__MASTER_MACROS_QUATERNION_DEFINE_TYPE(long double, ld)

#undef __MASTER_MACROS_QUATERNION_DEFINE_TYPE

#endif /* __MASTER_QUATERNION_INCLUDE_H__ */

// be master~
