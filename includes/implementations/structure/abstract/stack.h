
/*
 * Copyright (c) 2024 zELdYT
 *
 * Licensed under the BSD 2-Clause License.
 * See the LICENSE file in the project root for more details.
 */

#ifndef __MASTER_STACK_INCLUDE_H__
#define __MASTER_STACK_INCLUDE_H__

/* #! High priority !# */

#include "../../../headers/enumeration/master_enum.h"

#if !(defined(__MASTER_STACK_DEFINE_UNIDIRECTIONAL_LIST__) || defined(__MASTER_STACK_DEFINE_ONE_DIMENSIONAL_ARRAY__))
#	define __MASTER_STACK_DEFINE_UNIDIRECTIONAL_LIST__
#endif /* STACK TYPES */

#include <stdlib.h>
#include <string.h>
#include "../../../headers/enumeration/master_enum.h"

#ifdef __MASTER_STACK_DEFINE_UNIDIRECTIONAL_LIST__

typedef struct MASTER_stack {
	void * value;
	unsigned long size;
	struct MASTER_stack * next;
} MASTER_stack;

int
MASTER_stack_push(MASTER_stack **head, void *value, unsigned long value_size) {
	MASTER_stack *new_node = (MASTER_stack *)MASTER_MALLOC(sizeof(MASTER_stack));
	if (new_node == nul) return -1;
	new_node->value = MASTER_MALLOC(value_size);
	if (new_node->value == nul) {
		MASTER_FREE(new_node);
		return -1;
	}
	memcpy(new_node->value, value, value_size);
	new_node->next = *head;
	new_node->size = value_size;
	*head = new_node;
	return 0;
}

int
MASTER_stack_pop(MASTER_stack **head, void **value, unsigned long * value_size) {
	if (*head == 0) {
		*value = 0;
		return -1;
	}
	MASTER_stack *temp = *head;
	*value = MASTER_MALLOC(temp->size);
	if (*value == 0) return -1;
	memcpy(*value, temp->value, temp->size);
	*value_size = temp->size;
	*head = temp->next;
	MASTER_FREE(temp->value);
	MASTER_FREE(temp);
	return 0;
}

void
MASTER_stack_end(MASTER_stack *head) {
	while (head != nul) {
		MASTER_stack *temp = head;
		head = head->next;
		MASTER_FREE(temp->value);
		MASTER_FREE(temp);
	}
}

#elif defined(__MASTER_STACK_DEFINE_ONE_DIMENSIONAL_ARRAY__)

typedef struct MASTER_stack {
	UI1 * __data;
	UI1 * __ptr;
} MASTER_stack;

MASTER_stack
MASTER_stack_init( UI4 size ) {
	MASTER_stack stack;
	stack.__data = (UI1 *)MASTER_CALLOC(size, sizeof(UI1));
	stack.__ptr = stack.__data;
	return stack;
}

UI1
MASTER_stack_push( MASTER_stack * stack, const void * value, const UI4 size ) {
	if (!stack) return 1;
	memcpy(stack->__ptr, value, size);
	stack->__ptr += size;
	return 0;
}

UI1
MASTER_stack_pop( MASTER_stack * stack, void * value, const UI4 size ) {
	if (!stack || stack->__ptr == stack->__data) return 1;
	stack->__ptr -= size;
	memcpy(value, stack->__ptr, size);
	return 0;
}

void
MASTER_stack_peek( MASTER_stack * stack, void * value, const UI4 size ) {
	if (stack) memcpy(value, stack->__ptr - size, size);
}

UI1
MASTER_stack_isEmpty( MASTER_stack * stack ) {
	return (stack) ? (stack->__data == stack->__ptr) : 0;
}

void
MASTER_stack_end( MASTER_stack * stack ) {
	if (stack) MASTER_FREE(stack->__data);
}

#endif /* STACK TYPES */

#endif /* __MASTER_STACK_INCLUDE_H__ */

// be master~
