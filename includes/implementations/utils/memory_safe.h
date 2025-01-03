
/*
 * Copyright (c) 2024 zELdYT
 *
 * Licensed under the BSD 2-Clause License.
 * See the LICENSE file in the project root for more details.
 */

// for work need macros:
// __MASTER_MACROS_TRASHCAN__

#ifndef __MASTER_MEMORY_SAFE_INCLUDE_H__
#define __MASTER_MEMORY_SAFE_INCLUDE_H__

/* #! Low priority !# */

#warning "Warning: This library will be deprecated soon. All its functionalities will be moved to master_enum.h."

#include <stdio.h>
#include <stdlib.h>
#include "../../headers/enumeration/master_enum.h"

#ifdef __MASTER_MACROS_TRASHCAN__
typedef struct {
	void * __ptr;
	UI4 __byte_count;
} Trash;
Trash * MASTER_trashcan;
UI4 MASTER_trashcan_len = 0;
#endif /* __MASTER_MACROS_TRASHCAN__ */

#ifdef __MASTER_MACROS_TRASHCAN__
void *
MASTER_malloc(const UI4 __byte_count) {
	MASTER_trashcan = (Trash *)realloc(MASTER_trashcan, sizeof(Trash) * ++MASTER_trashcan_len);
	MASTER_trashcan[MASTER_trashcan_len - 1].__ptr = malloc(__byte_count);
	MASTER_trashcan[MASTER_trashcan_len - 1].__byte_count = __byte_count;
	return MASTER_trashcan[MASTER_trashcan_len - 1].__ptr;
}
#else
#define MASTER_malloc(__byte_count) malloc(__byte_count);
#endif /* __MASTER_MACROS_TRASHCAN__ */

#ifdef __MASTER_MACROS_TRASHCAN__
void *
MASTER_calloc(const UI4 __item_count, const UI4 __item_size) {
	MASTER_trashcan = (Trash *)realloc(MASTER_trashcan, sizeof(Trash) * ++MASTER_trashcan_len);
	MASTER_trashcan[MASTER_trashcan_len - 1].__ptr = calloc(__item_count, __item_size);
	MASTER_trashcan[MASTER_trashcan_len - 1].__byte_count = __item_count * __item_size;
	return MASTER_trashcan[MASTER_trashcan_len - 1].__ptr;
}
#else
#define MASTER_calloc(__item_count, __item_size) calloc(__item_count, __item_size);
#endif /* __MASTER_MACROS_TRASHCAN__ */

#ifdef __MASTER_MACROS_TRASHCAN__
void *
MASTER_realloc(void * const __ptr, const UI4 __byte_count) {
	UI4 i = 0;
	for (; i < MASTER_trashcan_len; i++)
		if (MASTER_trashcan[i].__ptr == __ptr) {
			MASTER_trashcan[i].__ptr = realloc(__ptr, __byte_count);
			MASTER_trashcan[i].__byte_count = __byte_count;
			return MASTER_trashcan[i].__ptr;
		}
	return 0;
}
#else
#define MASTER_realloc(__ptr, __byte_count) realloc(__ptr, __byte_count);
#endif /* __MASTER_MACROS_TRASHCAN__ */

#ifdef __MASTER_MACROS_TRASHCAN__
void
MASTER_free(void * const __ptr) {
	UI4 i = 0, j;
	for (; i < MASTER_trashcan_len; i++) {
		if (MASTER_trashcan[i].__ptr == __ptr) {
			Trash buf;
			for (j = i; j < MASTER_trashcan_len - 1; j++) {
				buf = MASTER_trashcan[j];
				MASTER_trashcan[j] = MASTER_trashcan[j+1];
				MASTER_trashcan[j+1] = buf;
			}
			MASTER_trashcan = (Trash *)realloc(MASTER_trashcan, sizeof(Trash) * --MASTER_trashcan_len);
			break;
		}
	}
	return free(__ptr);
}
#else
#define MASTER_free(__ptr) free(__ptr);
#endif /* __MASTER_MACROS_TRASHCAN__ */

#ifdef __MASTER_MACROS_TRASHCAN__
void
MASTER_output(void) {
	if (MASTER_trashcan_len > 0) {
		UI4 i;
		printf("FOUNDED UNCLEANED!\n");
		for (i = 0; i < MASTER_trashcan_len; i++) {
			if (MASTER_trashcan[i].__ptr == 0) {
				printf("[-] PTR : 0, SIZE : UNKNOWN\n");
				continue;
			}
			printf("[-] PTR : %p, SIZE : %u B\n", MASTER_trashcan[i].__ptr, MASTER_trashcan[i].__byte_count);
			free(MASTER_trashcan[i].__ptr);
		}
	} else printf("UNCLEANED GARBAGE NOT FOUND!\n");
	printf("ENDING TRASH\n");
	free(MASTER_trashcan);
}
#else
#define MASTER_output() printf("Looks like, you not used macros \"__MASTER_MACROS_TRASHCAN__\", so trashcan is not used.");
#endif /* __MASTER_MACROS_TRASHCAN__ */

#endif /* __MASTER_MEMORY_SAFE_INCLUDE_H__ */

// be master~
