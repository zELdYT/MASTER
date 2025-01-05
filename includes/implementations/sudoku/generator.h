
#ifndef __MASTER_SUDOKU_GENERATOR_INCLUDE_H__
#define __MASTER_SUDOKU_GENERATOR_INCLUDE_H__

#include "../../headers/enumeration/master_enum.h"

#ifndef MASTER_SUDOKU_FIELD_TYPE
	#define MASTER_SUDOKU_FIELD_TYPE UI1
#endif /* MASTER_SUDOKU_FIELD_TYPE */

#include <string.h>

typedef struct {
	UI4 side, side_sqrt;
	MASTER_SUDOKU_FIELD_TYPE * table;
} MASTER_sudoku;

MASTER_sudoku *
MASTER_sudoku_create( const UI4 side_sqrt ) {
	MASTER_sudoku * sudoku = MASTER_MALLOC(sizeof(MASTER_sudoku));
	sudoku->side = MASTER_SQUARE(side_sqrt);
	sudoku->side_sqrt = side_sqrt;
	sudoku->table = MASTER_CALLOC(MASTER_SQUARE(sudoku->side), sizeof(MASTER_SUDOKU_FIELD_TYPE));
	UI4 i = 0;
	for (; i < MASTER_SQUARE(sudoku->side); i++)
		sudoku->table[i] = (((i % sudoku->side) + (i / sudoku->side) * side_sqrt + ((i / sudoku->side) / side_sqrt)) % sudoku->side) + 1;
	return sudoku;
}

MASTER_sudoku *
MASTER_sudoku_create_empty( const UI4 side_sqrt ) {
	MASTER_sudoku * sudoku = MASTER_MALLOC(sizeof(MASTER_sudoku));
	sudoku->side = MASTER_SQUARE(side_sqrt);
	sudoku->side_sqrt = side_sqrt;
	sudoku->table = MASTER_CALLOC(MASTER_SQUARE(sudoku->side), sizeof(MASTER_SUDOKU_FIELD_TYPE));
	return sudoku;
}

void
MASTER_sudoku_transpose( MASTER_sudoku * const sudoku ) {
	UI4 i = 0, j;
	MASTER_SUDOKU_FIELD_TYPE temp;
	for (; i < sudoku->side; i++) {
		for (j = i + 1; j < sudoku->side; j++) {
			temp = sudoku->table[i * sudoku->side + j];
			sudoku->table[i * sudoku->side + j] = sudoku->table[j * sudoku->side + i];
			sudoku->table[j * sudoku->side + i] = temp;
		}
	}
}

void
MASTER_sudoku_swap_rows( MASTER_sudoku * const sudoku, const UI4 area_index, const UI4 row1, const UI4 row2 ) {
	UI4 i = 0;
	MASTER_SUDOKU_FIELD_TYPE temp;
	for (; i < sudoku->side; i++) {
		temp = sudoku->table[area_index * sudoku->side * sudoku->side_sqrt + row1 * sudoku->side + i];
		sudoku->table[area_index * sudoku->side * sudoku->side_sqrt + row1 * sudoku->side + i] = sudoku->table[area_index * sudoku->side * sudoku->side_sqrt + row2 * sudoku->side + i];
		sudoku->table[area_index * sudoku->side * sudoku->side_sqrt + row2 * sudoku->side + i] = temp;
	}
}

void
MASTER_sudoku_swap_cols( MASTER_sudoku * const sudoku, const UI4 area_index, const UI4 col1, const UI4 col2 ) {
	UI4 i = 0;
	MASTER_SUDOKU_FIELD_TYPE temp;
	for (; i < sudoku->side; i++) {
		temp = sudoku->table[area_index * sudoku->side_sqrt + col1 + sudoku->side * i];
		sudoku->table[area_index * sudoku->side_sqrt + col1 + sudoku->side * i] = sudoku->table[area_index * sudoku->side_sqrt + col2 + sudoku->side * i];
		sudoku->table[area_index * sudoku->side_sqrt + col2 + sudoku->side * i] = temp;
	}
}

void
MASTER_sudoku_swap_areas_rows( MASTER_sudoku * const sudoku, const UI4 area1, const UI4 area2 ) {
	UI4 i = 0, j, k;
	MASTER_SUDOKU_FIELD_TYPE temp;
	for (; i < sudoku->side_sqrt; i++) {
		for (j = 0; j < sudoku->side_sqrt; j++) {
			for (k = 0; k < sudoku->side; k++) {
				temp = sudoku->table[area1 * sudoku->side * sudoku->side_sqrt + i * sudoku->side + k];
				sudoku->table[area1 * sudoku->side * sudoku->side_sqrt + i * sudoku->side + k] = sudoku->table[area2 * sudoku->side * sudoku->side_sqrt + j * sudoku->side + k];
				sudoku->table[area2 * sudoku->side * sudoku->side_sqrt + j * sudoku->side + k] = temp;
			}
		}
	}
}

void
MASTER_sudoku_swap_areas_cols( MASTER_sudoku * const sudoku, const UI4 area1, const UI4 area2 ) {
	UI4 i = 0, j, k;
	MASTER_SUDOKU_FIELD_TYPE temp;
	for (; i < sudoku->side_sqrt; i++) {
		for (j = 0; j < sudoku->side_sqrt; j++) {
			for (k = 0; k < sudoku->side; k++) {
					temp = sudoku->table[area1 * sudoku->side_sqrt + i + sudoku->side * k];
					sudoku->table[area1 * sudoku->side_sqrt + i + sudoku->side * k] = sudoku->table[area2 * sudoku->side_sqrt + j + sudoku->side * k];
					sudoku->table[area2 * sudoku->side_sqrt + j + sudoku->side * k] = temp;
			}
		}
	}
}

void
MASTER_sudoku_hide_xy( MASTER_sudoku * const sudoku, const UI4 x, const UI4 y ) {
	sudoku->table[y * sudoku->side + x] = 0;
}

int /* Use after genering new sudoku - without empty fields */
MASTER_sudoku_hide( MASTER_sudoku * const sudoku, const UI4 count, UI4 (*rand_func)(void) ) {
	if (count > MASTER_SQUARE(sudoku->side)) return -1;
	struct { UI4 x, y; } * Coord = MASTER_MALLOC(MASTER_SQUARE(sudoku->side) * sizeof(UI4) * 2);
	UI4 Coord_count = MASTER_SQUARE(sudoku->side);
	UI4 x, y;
	for (y = 0; y < sudoku->side; y++)
		for (x = 0; x < sudoku->side; x++)
			Coord[y * sudoku->side + x].x = x, Coord[y * sudoku->side + x].y = y;
	UI4 i = 0, r;
	for (; i < count; i++) {
		r = rand_func() % Coord_count;
		sudoku->table[Coord[r].y * sudoku->side + Coord[r].x] = 0;
		if (r < Coord_count - 1) memmove(Coord + r, Coord + r + 1, (Coord_count - r - 1) * sizeof(UI4) * 2);
		Coord_count--;
	}
	MASTER_FREE(Coord);
	return 0;
}

int
MASTER_sudoku_is_correct( const MASTER_sudoku * const sudoku ) {
	UI4 i, j, block_row, block_col;
	MASTER_SUDOKU_FIELD_TYPE num;
	UI1 seen[sudoku->side + 1]; 
	for (i = 0; i < sudoku->side; i++) {
		memset(seen, 0, sizeof(seen)); 
		for (j = 0; j < sudoku->side; j++) {
			num = sudoku->table[i * sudoku->side + j];
			if (num < 1 || num > sudoku->side || seen[num]) return 0;
			seen[num] = 1;
		}
	}
	for (j = 0; j < sudoku->side; j++) {
		memset(seen, 0, sizeof(seen)); 
		for (i = 0; i < sudoku->side; i++) {
			num = sudoku->table[i * sudoku->side + j];
			if (num < 1 || num > sudoku->side || seen[num]) return 0;
			seen[num] = 1;
		}
	}
	for (block_row = 0; block_row < sudoku->side_sqrt; block_row++) {
		for (block_col = 0; block_col < sudoku->side_sqrt; block_col++) {
			memset(seen, 0, sizeof(seen)); 
			for (i = 0; i < sudoku->side_sqrt; i++) {
				for (j = 0; j < sudoku->side_sqrt; j++) {
					num = sudoku->table[(block_row * sudoku->side_sqrt + i) * sudoku->side + (block_col * sudoku->side_sqrt + j)];
					if (num < 1 || num > sudoku->side || seen[num]) return 0; 
					seen[num] = 1;
				}
			}
		}
	}
	return 1; 
}

UI1
MASTER_sudoku_find_empty_location( const MASTER_sudoku * const sudoku, UI4 * row, UI4 * col ) {
	for (*row = 0; *row < sudoku->side; (*row)++)
		for (*col = 0; *col < sudoku->side; (*col)++)
			if (sudoku->table[*row * sudoku->side + *col] == 0) return 1;
	return 0;
}

UI1
MASTER_sudoku_is_safe( const MASTER_sudoku * const sudoku, UI4 row, UI4 col, MASTER_SUDOKU_FIELD_TYPE num ) {
	UI4 i, j;
	for (i = 0; i < sudoku->side; i++)
		if (sudoku->table[row * sudoku->side + i] == num) return 0;
	for (i = 0; i < sudoku->side; i++)
		if (sudoku->table[i * sudoku->side + col] == num) return 0;
	UI4 start_row = row - row % sudoku->side_sqrt;
	UI4 start_col = col - col % sudoku->side_sqrt;
	for (i = 0; i < sudoku->side_sqrt; i++)
		for (j = 0; j < sudoku->side_sqrt; j++)
			if (sudoku->table[(start_row + i) * sudoku->side + (start_col + j)] == num) return 0;
	return 1; 
}

UI1
MASTER_sudoku_generate_backtracking( MASTER_sudoku * const sudoku, MASTER_SUDOKU_FIELD_TYPE (*rand_func)(void) ) {
	UI4 row, col;
	if (!MASTER_sudoku_find_empty_location(sudoku, &row, &col)) return 1;
	const MASTER_SUDOKU_FIELD_TYPE const_num = (rand_func() % sudoku->side) + 1;
	MASTER_SUDOKU_FIELD_TYPE num = const_num;
	do {
		if (MASTER_sudoku_is_safe(sudoku, row, col, num)) {
			sudoku->table[row * sudoku->side + col] = num;
			if (MASTER_sudoku_generate_backtracking(sudoku, rand_func)) return 1; 
		}
		if (++num > sudoku->side) num = 1;
	} while (num != const_num);
	sudoku->table[row * sudoku->side + col] = 0;
	return 0; 
}

UI1 /* sudoku must be empty (generated with MASTER_sudoku_create_empty) */
MASTER_sudoku_generate_backtracking_from_empty( MASTER_sudoku * const sudoku, UI4 row, UI4 col, MASTER_SUDOKU_FIELD_TYPE (*rand_func)(void) ) {
	if (row >= sudoku->side) return 1;
	const MASTER_SUDOKU_FIELD_TYPE const_num = (rand_func() % sudoku->side) + 1;
	MASTER_SUDOKU_FIELD_TYPE num = const_num;
	do {
		if (MASTER_sudoku_is_safe(sudoku, row, col, num)) {
			sudoku->table[row * sudoku->side + col] = num;
			if (MASTER_sudoku_generate_backtracking_from_empty(sudoku, row + (col + 1) / sudoku->side, (col + 1) % sudoku->side, rand_func)) return 1; 
		}
		if (++num > sudoku->side) num = 1;
	} while (num != const_num);
	sudoku->table[row * sudoku->side + col] = 0;
	return 0; 
}

UI1**
MASTER_sudoku_create_domains( const MASTER_sudoku * const sudoku ) {
	UI1** domains = MASTER_CALLOC(MASTER_SQUARE(sudoku->side), sizeof(UI1 *));
	if (domains == 0) return 0;
	UI4 i = 0, j;
	for (; i < MASTER_SQUARE(sudoku->side); i++) {
		domains[i] = MASTER_CALLOC(sudoku->side, sizeof(UI1));
		if (domains[i] == 0) {
			for (j = 0; j < i; j++) MASTER_FREE(domains[j]);
			MASTER_FREE(domains);
			return 0;
		}
	}
	return domains;
}

void
MASTER_sudoku_end_domains( const MASTER_sudoku * const sudoku, UI1** const domains ) {
	UI4 i = 0;
	for (; i < MASTER_SQUARE(sudoku->side); i++) {
		MASTER_FREE(domains[i]);
		domains[i] = 0;
	}
	MASTER_FREE(domains);
}

void
MASTER_sudoku_initialize_domains( const MASTER_sudoku * const sudoku, UI1** const domains ) {
	UI4 row, col, i;
	for (row = 0; row < sudoku->side; row++) {
		for (col = 0; col < sudoku->side; col++) {
			if (sudoku->table[row * sudoku->side + col] == 0) {
				for (i = 0; i < sudoku->side; i++) domains[row * sudoku->side + col][i] = 1;
			} else
				domains[row * sudoku->side + col][sudoku->table[row * sudoku->side + col] - 1] = 1;
		}
	}
}

void
MASTER_sudoku_update_domains( const MASTER_sudoku * const sudoku, UI1** const domains ) {
	MASTER_sudoku_initialize_domains(sudoku, domains);
	UI4 row, col, num, start_row, start_col, i, j;
	for (row = 0; row < sudoku->side; row++) {
		for (col = 0; col < sudoku->side; col++) {
			if (sudoku->table[row * sudoku->side + col] == 0) continue;
			num = sudoku->table[row * sudoku->side + col] - 1;
			for (i = 0; i < sudoku->side; i++) {
				domains[row * sudoku->side + i][num] = 0;
				domains[i * sudoku->side + col][num] = 0;
			}
			start_row = (row / sudoku->side_sqrt) * sudoku->side_sqrt;
			start_col = (col / sudoku->side_sqrt) * sudoku->side_sqrt;
			for (i = start_row; i < start_row + sudoku->side_sqrt; i++)
				for (j = start_col; j < start_col + sudoku->side_sqrt; j++)
					domains[i * sudoku->side + j][num] = 0;
		}
	}
}

void
MASTER_sudoku_update_domains_pos_to_not_zero( const MASTER_sudoku * const sudoku, UI1** const domains, const UI4 row, const UI4 col ) {
	UI4 num, start_row, start_col, i, j;
	num = sudoku->table[row * sudoku->side + col] - 1;
	for (i = row + 1; i < sudoku->side; i++)
		domains[i * sudoku->side + col][num] = 0;
	for (i = col + 1; i < sudoku->side; i++)
		domains[row * sudoku->side + i][num] = 0;
	start_row = (row / sudoku->side_sqrt) * sudoku->side_sqrt;
	start_col = (col / sudoku->side_sqrt) * sudoku->side_sqrt;
	for (i = start_row; i < start_row + sudoku->side_sqrt; i++)
		for (j = start_col; j < start_col + sudoku->side_sqrt; j++)
			domains[i * sudoku->side + j][num] = 0;
}

void
MASTER_sudoku_forward_check( MASTER_sudoku * const sudoku, UI1** const domains ) {
	UI4 row = 0, col, count, last_num, num, last_row = sudoku->side;
	do {
		if (row > sudoku->side) row = 0;
		for (col = 0; col < sudoku->side; col++) {
			if (sudoku->table[row * sudoku->side + col] != 0) continue;
			count = 0;
			last_num = 0;
			for (num = 0; num < sudoku->side; num++) {
				if (domains[row * sudoku->side + col][num] == 1) {
					count++;
					last_num = num;
				}
			}
			if (count == 1) {
				sudoku->table[row * sudoku->side + col] = last_num + 1;
				MASTER_sudoku_update_domains_pos_to_not_zero(sudoku, domains, row, col);
				last_row = row;
			}
		}
	} while (++row != last_row);
}

UI1 /* Good for generating sudoku's */
MASTER_sudoku_constraint_propagations_rand( MASTER_sudoku * const sudoku, UI1** const domains, MASTER_SUDOKU_FIELD_TYPE (*rand_func)(void) ) {
	UI4 row, col;
	const MASTER_SUDOKU_FIELD_TYPE const_num = (rand_func() % sudoku->side);
	MASTER_SUDOKU_FIELD_TYPE num = const_num;
	if (!MASTER_sudoku_find_empty_location(sudoku, &row, &col)) return 1;
	do {
		if (domains[row * sudoku->side + col][num] != 1) {
			if (++num > sudoku->side) num = 0;
			continue;
		}
		sudoku->table[row * sudoku->side + col] = num + 1;
		MASTER_sudoku_update_domains_pos_to_not_zero(sudoku, domains, row, col);
		if (MASTER_sudoku_constraint_propagations_rand(sudoku, domains, rand_func)) return 1;
		sudoku->table[row * sudoku->side + col] = 0;
		MASTER_sudoku_update_domains(sudoku, domains);
		if (++num > sudoku->side) num = 0;
	} while (num != const_num);
	return 0;
}

void
MASTER_sudoku_end( MASTER_sudoku * sudoku ) {
	if (sudoku == 0) return;
	if (sudoku->table != 0) MASTER_FREE(sudoku->table);
	MASTER_FREE(sudoku);
}

#endif /* __MASTER_SUDOKU_GENERATOR_INCLUDE_H__ */

// be master~
