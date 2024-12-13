
/*
 * Copyright (c) 2024 zELdYT
 *
 * Licensed under the BSD 2-Clause License.
 * See the LICENSE file in the project root for more details.
 */

#ifndef __MASTER_CODE_STYLE_INCLUDE_H__
#define __MASTER_CODE_STYLE_INCLUDE_H__

typedef unsigned char UI1;
typedef unsigned short UI2;
typedef unsigned long UI4;
typedef unsigned long long UI8;

typedef signed char SI1;
typedef signed short SI2;
typedef signed long SI4;
typedef signed long long SI8;

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

#define otherwise else if
#define nul 0

#define MASTER_MAX(a, b) (((a) > (b)) ? (a) : (b))
#define MASTER_MIN(a, b) (((a) < (b)) ? (a) : (b))
#define MASTER_ABS(a)	(((a) < 0) ? (-(a)) : (a))
#define MASTER_SQUARE(a) ((a)*(a))

/* ENDIAN CHECK */

#define MASTER_RLL32(a, n) (((a) << (n)) | ((a) >> (32 - (n))))
#define MASTER_RLL64(a, n) (((a) << (n)) | ((a) >> (64 - (n))))
#define MASTER_RLR32(a, n) (((a) >> (n)) | ((a) << (32 - (n))))
#define MASTER_RLR64(a, n) (((a) >> (n)) | ((a) << (64 - (n))))

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

#if MASTER_ENDIANNESS == MASTER_LITTLE_ENDIAN
	#define MASTER_TOLE(x) (x)
	#define MASTER_TOBE(x) MASTER_BSWAP_GENERIC(x, sizeof(x))
#elif MASTER_ENDIANNESS == MASTER_BIG_ENDIAN
	#define MASTER_TOLE(x) MASTER_BSWAP_GENERIC(x, sizeof(x))
	#define MASTER_TOBE(x) (x)
#else // MASTER_UNKNOWN_ENDIAN - runtime check
	#define MASTER_TOLE(x) (MASTER_ENDIANNESS == MASTER_LITTLE_ENDIAN ? (x) : MASTER_BSWAP_GENERIC(x, sizeof(x)))
	#define MASTER_TOBE(x) (MASTER_ENDIANNESS == MASTER_BIG_ENDIAN ? (x) : MASTER_BSWAP_GENERIC(x, sizeof(x)))
#endif

#endif /* __MASTER_CODE_STYLE_INCLUDE_H__ */

// be master~
