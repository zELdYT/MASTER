
/*
 * Copyright (c) 2024 zELdYT
 *
 * Licensed under the BSD 2-Clause License.
 * See the LICENSE file in the project root for more details.
 */

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