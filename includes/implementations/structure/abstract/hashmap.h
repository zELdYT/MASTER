
/*
 * Copyright (c) 2025 zELdYT
 *
 * Licensed under the BSD 2-Clause License.
 * See the LICENSE file in the project root for more details.
 */

#ifndef __MASTER_HASHMAP_INCLUDE_H__
#define __MASTER_HASHMAP_INCLUDE_H__

/* #! High priority !# */

#include "../../../headers/enumeration/master_enum.h"

#ifndef MASTER_HASHMAP_USE_LINKED_LIST
	#define MASTER_HASHMAP_USE_LINKED_LIST
#endif /* HASHMAP TYPES */

typedef struct MASTER_hashmap_element {
	void * key, * data;
	UI4 key_size, value_size;
#ifdef MASTER_HASHMAP_USE_LINKED_LIST
	struct MASTER_hashmap_element * next;
#endif /* HASHMAP TYPES */
} MASTER_hashmap_element;

typedef struct MASTER_hashmap {
	MASTER_hashmap_element** elements;
	UI4 count;
	UI4 (*hash_func)(const void * key, UI4 key_size);
} MASTER_hashmap;

#include <stdlib.h>

MASTER_hashmap
MASTER_hashmap_create(UI4 count, UI4 (*hash_func)(const void * key, UI4 key_size)) {
	MASTER_hashmap hm;
	hm.elements = MASTER_CALLOC(count, sizeof(MASTER_hashmap_element *));
	hm.count = count;
	hm.hash_func = hash_func;
	return hm;
}

MASTER_hashmap_element *
MASTER_hashmap_find(MASTER_hashmap * hm, const void * key, const UI4 key_size) {
	if (hm == nul || key == nul) return 0;
	UI4 hash = hm->hash_func(key, key_size) % hm->count;
	MASTER_hashmap_element * element = hm->elements[hash];
	while (element) {
		if (key_size == element->key_size && memcmp(element->key, key, key_size) == 0) return element;
		element = element->next;
	}
	return 0;
}

int
MASTER_hashmap_set(MASTER_hashmap * hm, const void * key, const UI4 key_size, const void * value, const UI4 value_size) {
	if (hm == nul || key == nul || value == nul) return -1;

	UI4 hash = hm->hash_func(key, key_size) % hm->count;
	MASTER_hashmap_element * element = hm->elements[hash];

	MASTER_hashmap_element * new_element = MASTER_MALLOC(sizeof(MASTER_hashmap_element));

	new_element->key = MASTER_MALLOC(key_size);
	memcpy(new_element->key, key, key_size);

	new_element->data = MASTER_MALLOC(value_size);
	memcpy(new_element->data, value, value_size);

	new_element->next = element;
	new_element->key_size = key_size;
	new_element->value_size = value_size;
	
	hm->elements[hash] = new_element;
	return 0;
}

void *
MASTER_hashmap_get(MASTER_hashmap * hm, const void * key, const UI4 key_size, UI4 * value_size) {
	if (hm == nul || key == nul) return 0;
	MASTER_hashmap_element * element = MASTER_hashmap_find(hm, key, key_size);
	if (element == 0) return nul;
	*value_size = element->value_size;
	return element->data;
}

void
MASTER_hashmap_clear(MASTER_hashmap * hm) {
	if (hm == nul) return;
	if (hm->elements != 0) {
		MASTER_hashmap_element * element, * next;
		UI4 i = 0;
		for (; i < hm->count; i++) {
			element = hm->elements[i];
			while (element != 0) {
				next = element->next;
				if (element->data != 0)
					MASTER_FREE(element->data);
				if (element->key != 0)
					MASTER_FREE(element->key);
				MASTER_FREE(element);
				element = next;
			}
			hm->elements[i] = 0;
		}
	}
}

void
MASTER_hashmap_MASTER_FREE(MASTER_hashmap * hm) {
	if (hm == nul) return;
	MASTER_hashmap_clear(hm);
	if (hm->elements != 0)
		MASTER_FREE(hm->elements);
}

#ifdef MASTER_HASHMAP_ENABLE_SIZES
UI4
MASTER_hashmap_to_array(MASTER_hashmap * hm, void*** keys, void*** values, UI4** key_sizes, UI4** value_sizes) {
	
}
#endif /* MASTER_HASHMAP_ENABLE_SIZES */

#endif /* __MASTER_HASHMAP_INCLUDE_H__ */

// be master~
