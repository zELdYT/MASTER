
/*
 * Copyright (c) 2024 zELdYT
 *
 * Licensed under the BSD 2-Clause License.
 * See the LICENSE file in the project root for more details.
 */

#ifndef __MASTER_STACK_INCLUDE_H__
#define __MASTER_STACK_INCLUDE_H__

#if !(defined(__MASTER_STACK_DEFINE_UNIDIRECTIONAL_LIST__) || defined(__MASTER_STACK_DEFINE_ONE_DIMENSIONAL_ARRAY__))
#	define __MASTER_STACK_DEFINE_UNIDIRECTIONAL_LIST__
#endif /* STACK TYPES */

#define nul NULL

#include <stdlib.h>
#include <string.h>

#ifdef __MASTER_STACK_DEFINE_UNIDIRECTIONAL_LIST__

typedef struct MASTER_stack {
	void * value;
	struct MASTER_stack * next;
} MASTER_stack;

// DOME

#elif defined(__MASTER_STACK_DEFINE_ONE_DIMENSIONAL_ARRAY__)

typedef struct MASTER_stack {
	unsigned char * __data;
	unsigned char * __ptr;
} MASTER_stack;

MASTER_stack
MASTER_stack_init( unsigned long size ) {
	MASTER_stack stack;
	stack.__data = (unsigned char *)calloc(size, sizeof(unsigned char));
	stack.__ptr = stack.__data;
	return stack;
}

unsigned char
MASTER_stack_push( MASTER_stack * stack, const void * value, const unsigned long size ) {
	if (!stack) return 1;
	memcpy(stack->__ptr, value, size);
	stack->__ptr += size;
	return 0;
}

unsigned char
MASTER_stack_pop( MASTER_stack * stack, void * value, const unsigned long size ) {
	if (!stack || stack->__ptr == stack->__data) return 1;
	stack->__ptr -= size;
	memcpy(value, stack->__ptr, size);
	return 0;
}

void
MASTER_stack_peek( MASTER_stack * stack, void * value, const unsigned long size ) {
	if (stack) memcpy(value, stack->__ptr - size, size);
}

unsigned char
MASTER_stack_isEmpty( MASTER_stack * stack ) {
	return (stack) ? (stack->__data == stack->__ptr) : 0;
}

void
MASTER_stack_end( MASTER_stack * stack ) {
	if (stack) free(stack->__data);
}

#endif /* STACK TYPES */

#endif /* __MASTER_STACK_INCLUDE_H__ */

// be master~
