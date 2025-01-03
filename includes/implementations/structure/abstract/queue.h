
/*
 * Copyright (c) 2024 zELdYT
 *
 * Licensed under the BSD 2-Clause License.
 * See the LICENSE file in the project root for more details.
 */

#ifndef __MASTER_QUEUE_INCLUDE_H__
#define __MASTER_QUEUE_INCLUDE_H__

/* #! High priority !# */

#include "../../../headers/enumeration/master_enum.h"

#if !(defined(__MASTER_QUEUE_DEFINE_UNIDIRECTIONAL_LIST__) || defined(__MASTER_QUEUE_DEFINE_ONE_DIMENSIONAL_ARRAY__))
#	define __MASTER_QUEUE_DEFINE_UNIDIRECTIONAL_LIST__
#endif /* QUEUE TYPES */

#include <stdlib.h>
#include <string.h>
#include "../../../headers/enumeration/master_enum.h"

#ifdef __MASTER_QUEUE_DEFINE_UNIDIRECTIONAL_LIST__

typedef struct MASTER_queue_node {
	void * __value;
	struct MASTER_queue_node * __next;
} MASTER_queue_node;

typedef struct MASTER_queue {
	struct MASTER_queue_node * __start;
	struct MASTER_queue_node * __end;
} MASTER_queue;

MASTER_queue
MASTER_queue_init( void ) {
	MASTER_queue queue;
	queue.__start = queue.__end = 0;
	return queue;
}

int
MASTER_queue_push( MASTER_queue * const queue, const void * value, const UI4 size ) {
	if (!queue) return MASTER_GOT_NULL_ARGUMENT;
	MASTER_queue_node * node = (MASTER_queue_node *)MASTER_MALLOC(sizeof(MASTER_queue_node));
	if (!node) return MASTER_FAILED_MALLOC;
	node->__value = MASTER_MALLOC(size);
	if (!node->__value) {
		MASTER_FREE(node);
		return MASTER_FAILED_MALLOC;
	}
	memcpy(node->__value, value, size);
	node->__next = 0;
	if (queue->__start == 0) {
		// no elements
		queue->__start = queue->__end = node;
	} else {
		queue->__end->__next = node;
		queue->__end = node;
	}
	return MASTER_NO_ERROR;
}

int
MASTER_queue_pop( MASTER_queue * const queue, void * const value, const UI4 size ) {
	if (!queue) return MASTER_GOT_NULL_ARGUMENT;
	if (queue->__start == queue->__end && queue->__start == 0) return MASTER_QUEUE_IS_EMPTY;
	memcpy(value, queue->__start->__value, size);
	MASTER_queue_node * temp = queue->__start;
	if (queue->__start == queue->__end) {
		// last element
		queue->__start = queue->__end = 0;
	} else queue->__start = temp->__next;
	MASTER_FREE(temp->__value);
	MASTER_FREE(temp);
	return MASTER_NO_ERROR;
}

int
MASTER_queue_peek( const MASTER_queue * const queue, void * const value, const UI4 size ) {
	if (!queue) return MASTER_GOT_NULL_ARGUMENT;
	memcpy(value, queue->__start->__value, size);
	return MASTER_NO_ERROR;
}

UI1
MASTER_queue_isEmpty( const MASTER_queue * const queue ) {
	return (queue) ? (queue->__start == 0) : 0;
}

void
MASTER_queue_clear( MASTER_queue * const queue ) {
	if (queue) {
		if (queue->__start != 0) {
			MASTER_queue_node * node = queue->__start, * temp;
			while (node != 0) {
				temp = node->__next;
				MASTER_FREE(node->__value);
				MASTER_FREE(node);
				node = temp;
			}
		}
		queue->__start = queue->__end = 0;
	}
}

#elif defined(__MASTER_QUEUE_DEFINE_ONE_DIMENSIONAL_ARRAY__)

// DOME

#endif /* QUEUE TYPES */

#endif /* __MASTER_QUEUE_INCLUDE_H__ */

// be master~
