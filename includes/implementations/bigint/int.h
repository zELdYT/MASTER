
/*
 * Copyright (c) 2024 zELdYT
 *
 * Licensed under the BSD 2-Clause License.
 * See the LICENSE file in the project root for more details.
 */

#ifndef __MASTER_INT_INCLUDE_H__
#define __MASTER_INT_INCLUDE_H__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

//#define __MASTER_MACROS_TRASHCAN__
#include "../utils/memory_safe.h"

#define otherwise else if
#define BOOL char
#define TRUE 1
#define FALSE 0

typedef struct {
	unsigned long * chunks;
	unsigned long size;
} INT;

// $a
void
int_delete_empty(INT * __i) {
	for (unsigned long i = __i->size - 1;; i--) {
		if (__i->chunks[i] == 0x0) {
			if (__i->size == 1) break;
			__i->size--;
		}
		else break;
	}
	__i->chunks = (unsigned long *)MASTER_realloc(__i->chunks, sizeof(unsigned long) * __i->size);
}

#define min(a, b) (((a) < (b)) ? (a) : (b))

// a = bytes(b[:l])
INT
str_2_intExt(const char * __s, unsigned long __l) {
	INT __i;
	unsigned long size = min(strlen(__s), __l);
	__i.size = size / 4 + ((size % 4 > 0) ? 1 : 0);
	__i.chunks = (unsigned long *)MASTER_calloc(__i.size, sizeof(unsigned long));
	for (unsigned long i = size - 1;; i--) {
		__i.chunks[i / 4] |= ((unsigned char)__s[i]) << (24 - (i % 4) * 8);
		if (i == 0) break;
	}
	return __i;
}

// a = bytes(b)
INT
str_2_int(const char * __s) {
	return str_2_intExt(__s, strlen(__s));
}

// a = bytes(b[:l])
INT
str_2_intbExt(const char * __s, unsigned long __l) {
	INT __i;
	unsigned long size = min(strlen(__s), __l);
	__i.size = size / 4 + ((size % 4 > 0) ? 1 : 0);
	__i.chunks = (unsigned long *)MASTER_calloc(__i.size, sizeof(unsigned long));
	for (unsigned long i = 0; i < size; i++) {
		__i.chunks[__i.size - 1 - i / 4] |= ((unsigned char)__s[size - 1 -i]) << ((i % 4) * 8);
	}
	return __i;
}

// a = bytes(b)
INT
str_2_intb(const char * __s) {
	return str_2_intbExt(__s, strlen(__s));
}

// a = b
INT
ul_2_int(unsigned long __num) {
	INT __i;
	__i.size = 1;
	__i.chunks = (unsigned long *)MASTER_malloc(sizeof(unsigned long) * __i.size);
	__i.chunks[0] = __num;
	return __i;
}

// a => b
INT
int_copy(const INT * __o) {
	INT __i;
	__i.size = __o->size;
	__i.chunks = (unsigned long *)MASTER_calloc(__i.size, sizeof(unsigned long));
	for (unsigned long i = 0; i < __i.size; i++) 
		__i.chunks[i] = __o->chunks[i];
	return __i;
}

// ~a
void
free_int(INT * __i) {
	MASTER_free(__i->chunks);
}

// divides this number
// return reminder


// a /= b
unsigned long
int_idiv(INT * __i, unsigned long __ul) {
	unsigned long rem = 0;
	for (unsigned long i = 0; i < __i->size; i++) {
		if (rem > 0) {
			unsigned long buf = __i->chunks[i];
			__i->chunks[i] = (unsigned long long)(((unsigned long long)rem << 32) | (unsigned long long)__i->chunks[i]) / __ul;
			rem = (unsigned long long)(((unsigned long long)rem << 32) | (unsigned long long)buf) % __ul;
		} else {
			rem = __i->chunks[i] % __ul;
			__i->chunks[i] /= __ul;
		}
	}
	int_delete_empty(__i);
	return rem;
}

// a *= b
unsigned long
int_imul(INT * __i, unsigned long __ul) {
	unsigned long rem = 0;
	unsigned long i = 0;
	for (; i < __i->size; i++) {
		if (rem > 0) {
			unsigned long buf = __i->chunks[i];
			__i->chunks[i] = __i->chunks[i] * __ul + rem;
			rem = ((unsigned long long)buf * __ul + rem) >> 32;
		} else {
			rem = ((unsigned long long)__i->chunks[i] * __ul) >> 32;
			__i->chunks[i] *= __ul;
		}
	}
	if (rem > 0) {
		__i->chunks = (unsigned long *)MASTER_realloc(__i->chunks, sizeof(unsigned long) * ++__i->size);
		__i->chunks[i] = rem;
	}
	return rem;
}

// a += b
unsigned long
int_iadd(INT * __i, unsigned long __ul) {
	unsigned long rem = 0;
	unsigned long i = 0;
	do {
		if (rem > 0) {
			unsigned long buf = __i->chunks[i];
			__i->chunks[i] = (__i->chunks[i] + rem) + __ul;
			rem = ((unsigned long long)(buf + rem) + __ul) >> 32;
		} else {
			rem = ((unsigned long long)__i->chunks[i] + __ul) >> 32;
			__i->chunks[i] += __ul;
		}
		i++;
	} while (rem > 0 && i < __i->size);
	if (rem > 0) {
		__i->chunks = (unsigned long *)MASTER_realloc(__i->chunks, sizeof(unsigned long) * ++__i->size);
		__i->chunks[i] = rem;
	}
	return rem;
}

// a >>= b
unsigned long
int_irsf(INT * __i, unsigned long __ul) {
	unsigned long rem = 0;
	for (unsigned long i = __i->size - 1;; i--) {
		if (rem > 0) {
			unsigned long buf = __i->chunks[i];
			__i->chunks[i] = (unsigned long long)(((unsigned long long)rem << 32) | (unsigned long long)__i->chunks[i]) >> __ul;
			rem = (unsigned long long)(((unsigned long long)rem << 32) | (unsigned long long)buf) & ((0x1 << __ul) - 1);
		} else {
			rem = __i->chunks[i] & ((0x1 << __ul) - 1);
			__i->chunks[i] >>= __ul;
		}
		if (i == 0) break;
	}
	int_delete_empty(__i);
	return rem;
}

// a == 0
BOOL
int_iszero(INT * __i) {
	for (unsigned long i = 0; i < __i->size; i++)
		if (__i->chunks[i] != 0x0) return 0;
	return 1;
}

// a == b
BOOL
int_equ(const INT * __i1, const INT * __i2) {
	if (__i1->size != __i2->size) return FALSE;
	for (unsigned long i = 0; i < __i1->size && i < __i2->size; i++)
		if (__i1->chunks[i] != __i2->chunks[i]) return FALSE;
	return TRUE;
}

// a != b
BOOL
int_neq(const INT * __i1, const INT * __i2) {
	if (__i1->size != __i2->size) return TRUE;
	for (unsigned long i = 0; i < __i1->size && i < __i2->size; i++)
		if (__i1->chunks[i] != __i2->chunks[i]) return TRUE;
	return FALSE;
}

// a < b
BOOL
int_lss(const INT * __i1, const INT * __i2) {
	if (__i1->size < __i2->size) return TRUE;
	otherwise (__i1->size > __i2->size) return FALSE;
	for (unsigned long i = 0; i < __i1->size && i < __i2->size; i++)
		if (__i1->chunks[i] >= __i2->chunks[i]) return FALSE;
	return TRUE;
}

// a <= b
BOOL
int_leq(const INT * __i1, const INT * __i2) {
	if (__i1->size < __i2->size) return TRUE;
	otherwise (__i1->size > __i2->size) return FALSE;
	for (unsigned long i = 0; i < __i1->size && i < __i2->size; i++)
		if (__i1->chunks[i] > __i2->chunks[i]) return FALSE;
	return TRUE;
}

// a > b
BOOL
int_gtr(const INT * __i1, const INT * __i2) {
	if (__i1->size < __i2->size) return FALSE;
	otherwise (__i1->size > __i2->size) return TRUE;
	for (unsigned long i = 0; i < __i1->size && i < __i2->size; i++)
		if (__i1->chunks[i] <= __i2->chunks[i]) return FALSE;
	return TRUE;
}

// a >= b
BOOL
int_geq(const INT * __i1, const INT * __i2) {
	if (__i1->size < __i2->size) return FALSE;
	otherwise (__i1->size > __i2->size) return TRUE;
	for (unsigned long i = 0; i < __i1->size && i < __i2->size; i++)
		if (__i1->chunks[i] < __i2->chunks[i]) return FALSE;
	return TRUE;
}

#endif /* __MASTER_INT_INCLUDE_H__ */

// be master~

int mai__n() {
	INT a = ul_2_int(0xFF);
	INT b = ul_2_int(0xFF);
	printf("%s\n", int_gtr(&a, &b) ? "True" : "False");
	free_int(&a);
	free_int(&b);
	MASTER_output();
	return 0;
}