
/*
 * Copyright (c) 2025 zELdYT
 *
 * Licensed under the BSD 2-Clause License.
 * See the LICENSE file in the project root for more details.
 */

#ifndef __MASTER_CODE_STYLE_INCLUDE_H__
#define __MASTER_CODE_STYLE_INCLUDE_H__

/* #! High priority !# */

typedef unsigned char UI1;
typedef unsigned short UI2;
typedef unsigned int UI4;

typedef signed char SI1;
typedef signed short SI2;
typedef signed int SI4;

#ifdef __cplusplus
	typedef unsigned long long MASTER_maxint;
	#define MASTER_64_AVAILABLE 1
#elif defined(__STDC_VERSION__) && __STDC_VERSION__ >= 199901L
	#include <limits.h>
	#if defined(ULLONG_MAX)
		typedef unsigned long long MASTER_maxint;
		#define MASTER_64_AVAILABLE 1
	#elif defined(ULONG_MAX) && (ULONG_MAX >= 0xFFFFFFFFFFFFFFFFULL)
		typedef unsigned long MASTER_maxint;
		#define MASTER_64_AVAILABLE 1
	#else
		typedef unsigned long MASTER_maxint;
		#define MASTER_64_AVAILABLE 0
	#endif
#else
	#include <limits.h>
	#if defined(ULONG_MAX) && (ULONG_MAX >= 0xFFFFFFFFFFFFFFFFULL)
		typedef unsigned long MASTER_maxint;
		#define MASTER_64_AVAILABLE 1
	#elif defined(ULONG_MAX) && (ULONG_MAX >= 0xFFFFFFFFUL)
		typedef unsigned long MASTER_maxint;
		#define MASTER_64_AVAILABLE 0
	#else
		typedef unsigned short MASTER_maxint;
		#define MASTER_64_AVAILABLE 0
	#endif
#endif

#if MASTER_64_AVAILABLE == 1
	typedef unsigned long long int UI8;
	typedef signed long long int SI8;
#endif /* MASTER_64_AVAILABLE */

typedef enum {
	MASTER_NO_ERROR = 0,
	MASTER_ERROR,
	
	MASTER_FILE_NOT_FOUND,
	MASTER_FILE_CANT_CREATE,
	MASTER_FILE_READ_FAILURE,
	MASTER_FILE_WRITE_FAILURE,
	MASTER_FAILED_MALLOC,
	MASTER_FAILED_REALLOC,
	MASTER_GOT_NULL_ARGUMENT,
	
	MASTER_CSV_NOT_CLOSED_QUOTES,
	MASTER_CSV_EMPTY,
	
	MASTER_QUEUE_IS_EMPTY,
} MASTER_return_code;

#define MASTER_IS_SUCCESS(code) ((code) == MASTER_NO_ERROR)
#define MASTER_IS_FAILURE(code) ((code) != MASTER_NO_ERROR)

#ifdef MASTER_ENABLE_ASSERTIONS
	#ifndef MASTER_FUNCTION_ASSERTION
		#error \
		With defined "MASTER_ENABLE_ASSERTIONS" function "MASTER_FUNCTION_ASSERTION" with arguments (expr, msg) must be defined.
	#endif /* MASTER_FUNCTION_ASSERTION */
	#define MASTER_ASSERT(expr, msg) MASTER_FUNCTION_ASSERTION((expr), (msg))
#else
	#define MASTER_ASSERT(expr, msg)
#endif /* MASTER_ENABLE_ASSERTIONS */

#include <stdlib.h>
#ifdef MASTER_MEMORY_SAFE
	#ifndef MASTER_FUNCTION_ON_FAILURE_MALLOC
		#error \
		With defined "MASTER_MEMORY_SAFE" function /* */ "MASTER_FUNCTION_ON_FAILURE_MALLOC" must be defined.
	#endif /* MASTER_FUNCTION_ON_FAILURE_MALLOC */
	#ifndef MASTER_FUNCTION_ON_FAILURE_CALLOC
		#error \
		With defined "MASTER_MEMORY_SAFE" function "MASTER_FUNCTION_ON_FAILURE_CALLOC" must be defined.
	#endif /* MASTER_FUNCTION_ON_FAILURE_CALLOC */
	#ifndef MASTER_FUNCTION_ON_FAILURE_REALLOC
		#error \
		With defined "MASTER_MEMORY_SAFE" function "MASTER_FUNCTION_ON_FAILURE_REALLOC" must be defined.
	#endif /* MASTER_FUNCTION_ON_FAILURE_REALLOC */
	#define MASTER_MALLOC(__size) ({ \
		void * __ptr = malloc(__size); \
		if (__ptr == 0 && __size > 0) MASTER_FUNCTION_ON_FAILURE_MALLOC; \
		__ptr; })
	#define MASTER_CALLOC(__count, __size) ({ \
		void * __ptr = calloc(__count, __size); \
		if (__ptr == 0 && __size > 0) MASTER_FUNCTION_ON_FAILURE_CALLOC; \
		__ptr; })
	#define MASTER_REALLOC(__ptr, __size) ({ \
		void * __new_ptr = realloc(__ptr, __size); \
		if (__ptr == 0 && __size > 0) MASTER_FUNCTION_ON_FAILURE_REALLOC; \
		__new_ptr; })
#else
	#define MASTER_MALLOC(__size) malloc(__size)
	#define MASTER_CALLOC(__count, __size) calloc(__count, __size)
	#define MASTER_REALLOC(__ptr, __size) realloc(__ptr, __size)
#endif /* MASTER_MEMORY_SAFE */
#define MASTER_FREE(__ptr) free(__ptr)

#define otherwise else if
#define nul 0

#define MASTER_MAX(a, b) (((a) > (b)) ? (a) : (b))
#define MASTER_MIN(a, b) (((a) < (b)) ? (a) : (b))
#define MASTER_CLAMP(a, min, max) MASTER_MAX(min, MASTER_MIN(max, a))
#define MASTER_ABS(a)    (((a) < 0) ? (-(a)) : (a))
#define MASTER_SQUARE(a) ((a)*(a))
#define MASTER_2BYTES_TO_INT(a, b) (((a) << 8) | (b))
#define MASTER_4BYTES_TO_INT(a, b, c, d) (((a) << 24) | ((b) << 16) | ((c) << 8) | (d))

#define MASTER_ADD_OVERFLOW_UI1(a, b, carry) carry = ((a >= ((UI1)-1) - b) ? (1) : (0))
#define MASTER_ADD_OVERFLOW_UI2(a, b, carry) carry = ((a >= ((UI2)-1) - b) ? (1) : (0))
#define MASTER_ADD_OVERFLOW_UI4(a, b, carry) carry = ((a >= ((UI4)-1) - b) ? (1) : (0))

/* ENDIAN CHECK */

#define MASTER_RLL8(a, n) (((a) << (n)) | ((a) >> (8 - (n))))
#define MASTER_RLL16(a, n) (((a) << (n)) | ((a) >> (16 - (n))))
#define MASTER_RLL32(a, n) (((a) << (n)) | ((a) >> (32 - (n))))
#define MASTER_RLL64(a, n) (((a) << (n)) | ((a) >> (64 - (n))))
#define MASTER_RLLN(a, n, k) (((a) << (n)) | ((a) >> ((k) - (n))))
#define MASTER_RLR8(a, n) (((a) >> (n)) | ((a) << (8 - (n))))
#define MASTER_RLR16(a, n) (((a) >> (n)) | ((a) << (16 - (n))))
#define MASTER_RLR32(a, n) (((a) >> (n)) | ((a) << (32 - (n))))
#define MASTER_RLR64(a, n) (((a) >> (n)) | ((a) << (64 - (n))))
#define MASTER_RLRN(a, n, k) (((a) >> (n)) | ((a) << ((k) - (n))))

#define MASTER_UNKNOWN_ENDIAN 0
#define MASTER_LITTLE_ENDIAN 1
#define MASTER_BIG_ENDIAN 2

#if defined(__BYTE_ORDER__) && defined(__ORDER_LITTLE_ENDIAN__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	#define MASTER_ENDIANNESS MASTER_LITTLE_ENDIAN
#elif defined(__BYTE_ORDER__) && defined(__ORDER_BIG_ENDIAN__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
	#define MASTER_ENDIANNESS MASTER_BIG_ENDIAN
#else
	static UI1
	MASTER_getEndianness(void) {
		const UI4 value = 0x01020304;
		const UI1 * bytes = (const UI1 *)&value;

		if (bytes[0] == 0x04) return MASTER_LITTLE_ENDIAN;
		otherwise (bytes[0] == 0x01) return MASTER_BIG_ENDIAN;
		else return MASTER_UNKNOWN_ENDIAN;
	}
	#define MASTER_ENDIANNESS MASTER_getEndianness()
	#define MASTER_UNKNOWN_ENDIANNESS
#endif

#define MASTER_BSWAP16(x) (((x) >> 8) | ((x) << 8))
#define MASTER_BSWAP32(x) ( \
	(((x) >> 24) & 0x000000FF) | \
	(((x) >>  8) & 0x0000FF00) | \
	(((x) <<  8) & 0x00FF0000) | \
	(((x) << 24) & 0xFF000000))
#define MASTER_BSWAP64(x) ( \
	(((x) >> 56) & 0x00000000000000FF) | \
	(((x) >> 40) & 0x000000000000FF00) | \
	(((x) >> 24) & 0x0000000000FF0000) | \
	(((x) >>  8) & 0x00000000FF000000) | \
	(((x) <<  8) & 0x000000FF00000000) | \
	(((x) << 24) & 0x0000FF0000000000) | \
	(((x) << 40) & 0x00FF000000000000) | \
	(((x) << 56) & 0xFF00000000000000))
#define MASTER_BSWAP_GENERIC(x, size) \
	((size == 1) ? (x) : (size == 2) ? MASTER_BSWAP16(x) : (size == 4) ? MASTER_BSWAP32(x) : MASTER_BSWAP64(x))

#ifndef MASTER_UNKNOWN_ENDIANNESS
	#if MASTER_ENDIANNESS == MASTER_LITTLE_ENDIAN
		#define MASTER_TOLE(x) (x)
		#define MASTER_TOBE(x) MASTER_BSWAP_GENERIC(x, sizeof(x))
	#elif MASTER_ENDIANNESS == MASTER_BIG_ENDIAN
		#define MASTER_TOLE(x) MASTER_BSWAP_GENERIC(x, sizeof(x))
		#define MASTER_TOBE(x) (x)
	#endif /* MASTER_UNKNOWN_ENDIANNESS */
#else // MASTER_UNKNOWN_ENDIAN - runtime check
	#define MASTER_TOLE(x) (MASTER_ENDIANNESS == MASTER_LITTLE_ENDIAN ? (x) : MASTER_BSWAP_GENERIC(x, sizeof(x)))
	#define MASTER_TOBE(x) (MASTER_ENDIANNESS == MASTER_BIG_ENDIAN ? (x) : MASTER_BSWAP_GENERIC(x, sizeof(x)))
#endif /* ENDIANNESS */

#endif /* __MASTER_CODE_STYLE_INCLUDE_H__ */

// be master~
