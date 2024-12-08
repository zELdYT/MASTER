
/*
 * Copyright (c) 2024 zELdYT
 *
 * Licensed under the BSD 2-Clause License.
 * See the LICENSE file in the project root for more details.
 */

#ifndef __MASTER_PARSER_CSV_INCLUDE_H__
#define __MASTER_PARSER_CSV_INCLUDE_H__

/*
 * Supports:
 * CSV ( Comma-Separated Values )
 * TSV ( Tabulation-Separated Values )
 * USV ( User-Separated Values )
 */

typedef struct {
	char*** data;
	unsigned long width, height;
} MASTER_table;

#include <stdlib.h>
#include <string.h>
#include "../../headers/enumeration/master_enum.h"

void
MASTER_table_free( MASTER_table * const table ) {
	if (table->data != 0) {
		unsigned long i, j;
		for (i = 0; i < table->height; i++) {
			if (table->data[i] != 0) {
				for (j = 0; j < table->width; j++) {
					if (table->data[i][j] != 0) {
						free(table->data[i][j]);
						table->data[i][j] = 0;
					}
				}
				free(table->data[i]);
				table->data[i] = 0;
			}
		}
		free(table->data);
		table->data = 0;
	}
}

int
MASTER_table_toCpr( MASTER_table * const table, char * s, const char delimeter ) {
	if (table->data != 0) {
		unsigned long i, j, len;
		for (i = 0; i < table->height; i++) {
			if (table->data[i] != 0)
				for (j = 0; j < table->width; j++) {
					if (table->data[i][j] != 0) {
						*s++ = '"';
						strcpy(s, table->data[i][j]);
						s += strlen(table->data[i][j]);
						*s++ = '"';
					}
					if (j != table->width - 1) *s++ = delimeter;
				}
			*s++ = '\n';
		}
		*s = 0;
	}
	return MASTER_NO_ERROR;
}

int
MASTER_usv_parseCpr( MASTER_table * const table, const char * s, const char delimeter ) {
	const char * begin = s, * end = s;
	table->width = 1;
	table->height = 0;
	unsigned char quotes_was = 0;
	while (*begin == '\r' || *begin == '\n') begin++;
	while (*begin != '\r' && *begin != '\n' && *begin != 0) {
		if (*begin == '"') quotes_was = !quotes_was;
		else if (*begin == ',' && !quotes_was) table->width++;
		begin++;
	}
	if (table->width == 0) return MASTER_CSV_EMPTY;
	printf("wh : %d %d\n", table->width, table->height);
	table->data = (char***)malloc(0);
	begin = s;
	unsigned long column = 0, row = 0;
	char*** cprprpr;
	while (*end != 0) {
		cprprpr = (char***)realloc(table->data, sizeof(char**) * (++table->height));
		if (cprprpr == 0) {
			MASTER_table_free(table);
			return MASTER_FAILED_REALLOC;
		} else table->data = cprprpr;
		table->data[table->height - 1] = (char**)calloc(table->width, sizeof(char *));
		if (table->data[table->height - 1] == 0) {
			MASTER_table_free(table);
			return MASTER_FAILED_MALLOC;
		}
		quotes_was = 0;
		do {
			while (*end != 0 && *end != '\r' && *end != '\n') {
				if (*end == '"') quotes_was = !quotes_was;
				else if (*end == delimeter && !quotes_was) break;
				end++;
			}
			if (quotes_was) return MASTER_CSV_NOT_CLOSED_QUOTES;
			table->data[column][row] = (char *)calloc(end - begin + 1, sizeof(char));
			if (table->data[column][row] == 0) {
				MASTER_table_free(table);
				return MASTER_FAILED_MALLOC;
			}
			if (*begin == *(end - 1) && *begin == '"') {
				strncpy(table->data[column][row], begin + 1, end - begin - 2);
			} else strncpy(table->data[column][row], begin, end - begin);
			printf(" * %d %d : %s\n", column, row, table->data[column][row]);
			row++;
			end++;
			begin = end;
		} while (*(end - 1) != '\r' && *(end - 1) != '\n' && *(end - 1) != 0 && row < table->width);
		if (*end == '\r' || *end == '\n') while (*end == '\r' || *end == '\n') end++;
		
		begin = end;
		column++;
		row = 0;
	}
	return MASTER_NO_ERROR;
}

#define MASTER_csv_parseCpr( table, s ) MASTER_usv_parseCpr(table, s, ',')
#define MASTER_tsv_parseCpr( table, s ) MASTER_usv_parseCpr(table, s, '\t')

#include <stdio.h>

int
MASTER_usv_parseFile( MASTER_table * const table, const char * const filepath, const char delimeter ) {
	FILE * f = fopen(filepath, "rb");
	if (f == 0) return MASTER_FILE_NOT_FOUND;
	char * s;
	fseek(f, 0, SEEK_END);
	const unsigned long size = ftell(f);
	fseek(f, 0, SEEK_SET);
	s = malloc(size * sizeof(char) + 1);
	if (!s) {
		fclose(f);
		return MASTER_FAILED_MALLOC;
	}
	if (fread(s, sizeof(char), size, f) != size) {
		free(s);
		fclose(f);
		return MASTER_FILE_READ_FAILURE;
	}
	s[size] = 0;
	fclose(f);
	int res = MASTER_usv_parseCpr(table, s, delimeter);
	free(s);
	return res;
}

int
MASTER_usv_saveToFile( MASTER_table * const table, const char * const filepath, const char delimeter ) {
	FILE * f = fopen(filepath, "wt");
	if (table->data != 0) {
		unsigned long i, j, len = 0;
		for (i = 0; i < table->height; i++) {
			if (table->data[i] != 0) {
				for (j = 0; j < table->width; j++) {
					if (table->data[i][j] != 0) {
						len += strlen(table->data[i][j]);
					}
				}
			}
		}
		len += table->height * table->width * 2 + table->height * (table->width - 1) + table->height;
		char * s = (char *)malloc(len * sizeof(char));
		MASTER_table_toCpr(table, s, delimeter);
		if (fwrite(s, sizeof(char), len, f) != len) {
			free(s);
			fclose(f);
			return MASTER_FILE_READ_FAILURE;
		}
		free(s);
	}
	fclose(f);
	return MASTER_NO_ERROR;
}

#define MASTER_csv_parseFile( table, filepath ) MASTER_usv_parseFile(table, filepath, ',')
#define MASTER_csv_saveToFile( table, filepath ) MASTER_usv_saveToFile(table, filepath, ',')
#define MASTER_tsv_parseFile( table, filepath ) MASTER_usv_parseFile(table, filepath, '\t')
#define MASTER_tsv_saveToFile( table, filepath ) MASTER_usv_saveToFile(table, filepath, '\t')

#endif /* __MASTER_PARSER_CSV_INCLUDE_H__ */

// be master~