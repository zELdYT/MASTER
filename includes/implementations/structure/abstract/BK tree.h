
/*
 * Copyright (c) 2025 zELdYT
 *
 * Licensed under the BSD 2-Clause License.
 * See the LICENSE file in the project root for more details.
 */

#ifndef __MASTER_BKTREE_INCLUDE_H__
#define __MASTER_BKTREE_INCLUDE_H__

#include "../../headers/enumeration/master_enum.h"
#include <stdlib.h>
#include <string.h>

typedef struct MASTER_BK_tree {
	char * data;
	UI4 *  distances;
	struct MASTER_BK_tree** children;
	UI4    child_count;
} MASTER_BK_tree;

#define MASTER_BK_tree_chunk_max 16

MASTER_BK_tree *
MASTER_BK_tree_create( const char * s ) {
	MASTER_BK_tree * bk = (MASTER_BK_tree *)MASTER_MALLOC(sizeof(MASTER_BK_tree));
	bk->children = (MASTER_BK_tree**)MASTER_CALLOC(MASTER_BK_tree_chunk_max, sizeof(MASTER_BK_tree *));
	bk->distances = (UI4 *)MASTER_CALLOC(MASTER_BK_tree_chunk_max, sizeof(UI4));
	bk->child_count = 0;
	bk->data = (char *)MASTER_CALLOC(strlen(s) + 1, sizeof(char));
	strcpy(bk->data, s);
	return bk;
}

void
MASTER_BK_tree_free( MASTER_BK_tree * bk ) {
	if (bk == 0) return;
	UI4 i = 0;
	for (; i < bk->child_count; i++)
		if (bk->children[i] != 0)
			MASTER_BK_tree_free(bk->children[i]);
	free(bk->data);
	free(bk->distances);
	free(bk->children);
	free(bk);
}

#define min(a, b) (((a) < (b)) ? (a) : (b))
#define min3(a, b, c) min(a, min(b, c))

UI4
MASTER_LevenshteinDistance( const char * const s1, const char * const s2 ) {
	if (s1 == 0 || s2 == 0) return 0;
	const UI4 l1 = strlen(s1) + 1;
	const UI4 l2 = strlen(s2) + 1;
	UI4** matrix = (UI4**)MASTER_CALLOC(l1, sizeof(UI4 *));
	UI4 i, j;
	UI1 sub_cost;
	for (i = 0; i < l1; i++) matrix[i] = (UI4 *)MASTER_CALLOC(l2, sizeof(UI4));
	for (i = 1; i < l1; i++) matrix[i][0] = i;
	for (i = 1; i < l2; i++) matrix[0][i] = i;
	for (i = 1; i < l1; i++) {
		for (j = 1; j < l2; j++) {
			sub_cost = !(s1[i - 1] == s2[j - 1]);
			matrix[i][j] = min3(matrix[i - 1][j] + 1, matrix[i][j - 1] + 1, matrix[i - 1][j - 1] + sub_cost);
		}
	}
	UI4 res = matrix[l1 - 1][l2 - 1];
	for (i = 0; i < l1; i++) free(matrix[i]);
	free(matrix);
	return res;
}

int
MASTER_BK_tree_insert( MASTER_BK_tree * bk, const char * const s ) {
	if (bk == 0 || s == 0) return -1;
	UI4 dist, i;
	MASTER_BK_tree * current = bk;
	while (1) {
		dist = MASTER_LevenshteinDistance(s, current->data);
		for (i = 0; i < current->child_count; i++) {
			if (strcmp(s, current->children[i]->data) == 0) return 1;
			if (current->distances[i] == dist) {
				current = current->children[i];
				goto next_iteration; 
			}
		}
		break; 
		next_iteration:; 
	}
	if (current->child_count > 0 && (current->child_count % MASTER_BK_tree_chunk_max == 0)) {
		current->children = (MASTER_BK_tree**)MASTER_REALLOC(current->children, (current->child_count / MASTER_BK_tree_chunk_max + 1) * MASTER_BK_tree_chunk_max * sizeof(MASTER_BK_tree *));
		current->distances = (UI4 *)MASTER_REALLOC(current->distances, (current->child_count / MASTER_BK_tree_chunk_max + 1) * MASTER_BK_tree_chunk_max * sizeof(UI4));
	}
	current->children[current->child_count] = MASTER_BK_tree_create(s);
	current->distances[current->child_count] = dist;
	current->child_count++;
	return 0;
}

char *
MASTER_BK_tree_get( const MASTER_BK_tree * bk, const char * const s, const unsigned max_dist ) {
	if (bk == 0 || s == 0) return 0;
	UI4 dist = MASTER_LevenshteinDistance(s, bk->data), i;
	char * res;
	if (dist <= max_dist) return bk->data;
	for (i = 0; i < bk->child_count; i++) {
		if (dist - max_dist <= bk->distances[i] && bk->distances[i] <= dist + max_dist) {
			res = MASTER_BK_tree_get(bk->children[i], s, max_dist);
			if (res) return res;
		}
	}
	return 0;
}

/*
 * Delete
 */

#endif /* __MASTER_BKTREE_INCLUDE_H__ */

// be master~
