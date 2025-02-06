/*
 * Copyright (c) 2025 zELdYT
 *
 * Licensed under the BSD 2-Clause License.
 * See the LICENSE file in the project root for more details.
 */

#ifndef __MASTER_MSTIO_INCLUDE_H__
#define __MASTER_MSTIO_INCLUDE_H__

/* #! High priority !# */

/* #! Need check for linux !# */

#include "../../headers/enumeration/master_enum.h"

#ifdef _WIN32
	#include <windows.h>
	#define PLATFORM_API "WinAPI"
#elif defined(__unix__) || defined(__APPLE__)
	#include <unistd.h>
	#include <fcntl.h>
	#include <errno.h>
	#ifdef _POSIX_VERSION
		#define PLATFORM_API "POSIX"
	#else
		#define PLATFORM_API "UNIX"
	#endif /* UNIX */
	#ifndef O_BINARY
		#define O_BINARY 0x8000
	#endif /* O_BINARY */
#else
	#define PLATFORM_API "stdio"
	#include <stdio.h>
#endif /* OPERATION SYSTEM */

typedef struct {
	#ifdef _WIN32
		HANDLE handle;
	#elif defined(__unix__) || defined(__APPLE__)
		int fd;
	#else
		FILE * fp;
	#endif /* OPERATION SYSTEM */
	char * filename;
	UI1 isOpen;
	UI1 isError;
	char * mode;
} MASTER_File;

MASTER_File *
MASTER_create_file(const char * filename) {
	MASTER_File * const file = (MASTER_File *)MASTER_MALLOC(sizeof(MASTER_File));
	if (file == nul) return nul;
	file->filename = (char*)MASTER_MALLOC(strlen(filename) + 1);
	if (file->filename == nul) {
		MASTER_FREE(file);
		return nul;
	}
	strcpy(file->filename, filename);
	file->isOpen = 0;
	file->isError = 0;
	file->mode = nul;
	#ifdef _WIN32
		file->handle = INVALID_HANDLE_VALUE;
	#elif defined(__unix__) || defined(__APPLE__)
		file->fd = -1;
	#else
		file->fp = nul;
	#endif /* OPERATION SYSTEM */
	return file;
}

UI1
MASTER_open_file(MASTER_File * const file, const char * mode) {
	if (file == nul || file->isOpen || mode == nul) return 0;
	file->mode = (char*)MASTER_MALLOC(strlen(mode) + 1);
	if (file->mode == nul) {
		file->isError = 1;
		return 0;
	}
	strcpy(file->mode, mode);

	#ifdef _WIN32
		DWORD access = 0;
		DWORD creationDisposition = 0;
		
		if (strchr(mode, 'w') != nul) {
			access |= GENERIC_WRITE;
			creationDisposition = CREATE_ALWAYS;
		}
		if (strchr(mode, 'r') != nul) {
			access |= GENERIC_READ;
			if (creationDisposition == 0) creationDisposition = OPEN_EXISTING;
		}
		if (strchr(mode, '+') != nul) {
			access |= GENERIC_WRITE | GENERIC_READ;
			if (creationDisposition == 0) creationDisposition = OPEN_ALWAYS;
			otherwise (creationDisposition == CREATE_ALWAYS) creationDisposition = CREATE_ALWAYS;
			else creationDisposition = OPEN_ALWAYS;
		}
		if (creationDisposition == 0) creationDisposition = OPEN_EXISTING;

		file->handle = CreateFileA(file->filename, access, 0, nul, creationDisposition, FILE_ATTRIBUTE_NORMAL, nul);
		if (file->handle == INVALID_HANDLE_VALUE) {
			perror("Error opening file (WinAPI)");
			file->isError = 1;
			MASTER_FREE(file->mode);
			file->mode = nul;
			return 0;
		}
	#elif defined(__unix__) || defined(__APPLE__)
		int flags = 0;
		if (strchr(mode, 'w') != nul) flags |= O_WRONLY | O_CREAT | O_TRUNC;
		if (strchr(mode, 'r') != nul && strchr(mode, '+') == nul) flags |= O_RDONLY;
		otherwise (strchr(mode, 'r') != nul && strchr(mode, '+') != nul) flags |= O_RDWR | O_CREAT;
		otherwise (strchr(mode, '+') != nul) flags |= O_RDWR | O_CREAT;
		if (strchr(mode, 'b') != nul) flags |= O_BINARY;
		
		file->fd = open(file->filename, flags, 0666);
		if (file->fd == -1) {
			perror("Error opening file (UNIX/POSIX)");
			file->isError = 1;
			MASTER_FREE(file->mode);
			file->mode = nul;
			return 0;
		}
	#else
		file->fp = fopen(file->filename, mode);
		if (file->fp == nul) {
			perror("Error opening file (stdio)");
			file->isError = 1;
			MASTER_FREE(file->mode);
			file->mode = nul;
			return 0;
		}
	#endif /* OPERATION SYSTEM */
	file->isOpen = 1;
	file->isError = 0;
	return 1;
}

MASTER_maxint
MASTER_file_tell(MASTER_File * const file) {
	if (file == nul || !file->isOpen || file->isError) return -1;

	#ifdef _WIN32
		LARGE_INTEGER distance;
		distance.QuadPart = 0;
		LARGE_INTEGER result;
		if (!SetFilePointerEx(file->handle, distance, &result, FILE_CURRENT)) {
			perror("Error getting file position (WinAPI)");
			file->isError = 1;
			return -1;
		}
		return (MASTER_maxint)result.QuadPart;
	#elif defined(__unix__) || defined(__APPLE__)
		off_t offset = lseek(file->fd, 0, SEEK_CUR);
		if (offset == -1) {
			perror("Error getting file position (UNIX/POSIX)");
			file->isError = 1;
			return -1;
		}
		return (MASTER_maxint)offset;
	#else
		long offset = ftell(file->fp);
		if (offset == -1L) {
			perror("Error getting file position (stdio)");
			file->isError = 1;
			return -1;
		}
		return (MASTER_maxint)offset;
	#endif /* OPERATION SYSTEM */
}

#ifdef SEEK_SET
	#define MASTER_MSTIO_SEEK_BEGIN SEEK_SET
	#define MASTER_MSTIO_SEEK_CUR   SEEK_CUR
	#define MASTER_MSTIO_SEEK_END   SEEK_END
#else
	#define MASTER_MSTIO_SEEK_BEGIN 0
	#define MASTER_MSTIO_SEEK_CUR   1
	#define MASTER_MSTIO_SEEK_END   2
#endif /* SEEK_SET */

UI1
MASTER_file_seek(MASTER_File * const file, MASTER_maxint offset, int whence) {
	if (file == nul || !file->isOpen || file->isError) return 0;

	#ifdef _WIN32
		LARGE_INTEGER distance;
		distance.QuadPart = offset;
		if (SetFilePointerEx(file->handle, distance, nul, whence) == INVALID_SET_FILE_POINTER) {
			if (GetLastError() != NO_ERROR) {
				perror("Error seeking in file (WinAPI)");
				file->isError = 1;
				return 0;
			}
		}
	 #elif defined(__unix__) || defined(__APPLE__)
		if (lseek(file->fd, offset, whence) == -1) {
			perror("Error seeking in file (UNIX/POSIX)");
			file->isError = 1;
			return 0;
		}
	#else
		if (fseek(file->fp, offset, whence) != 0) {
			perror("Error seeking in file (stdio)");
			file->isError = 1;
			return 0;
		}
	#endif /* OPERATION SYSTEM */
	return 1;
}

int
MASTER_file_write(MASTER_File * const file, const void * data, MASTER_maxint size) {
	if (file == nul || !file->isOpen || file->isError) return -1;
	#ifdef _WIN32
		DWORD bytesWritten;
		if (!WriteFile(file->handle, data, (DWORD)size, &bytesWritten, nul) || bytesWritten != size) {
			perror("Error writing to file (WinAPI)");
			file->isError = 1;
			return -1;
		}
	#elif defined(__unix__) || defined(__APPLE__)
		MASTER_maxint bytesWritten = write(file->fd, data, size);
		if (bytesWritten == -1 || (MASTER_maxint)bytesWritten != size) {
			perror("Error writing to file (UNIX/POSIX)");
			file->isError = 1;
			return -1;
		}
	#else
		if (fwrite(data, 1, size, file->fp) != size) {
			perror("Error writing to file (stdio)");
			file->isError = 1;
			return -1;
		}
	#endif /* OPERATION SYSTEM */
	return 0;
}

int
MASTER_file_putchar(MASTER_File * const file, char c) {
	return MASTER_file_write(file, &c, 1);
}

#include <stdio.h>
int
MASTER_printf(MASTER_File * const file, char * format, ...) {
	va_list args;
	va_start(args, format);

	char buffer[2048];
	int len = vsnprintf(buffer, sizeof(buffer), format, args);
	va_end(args);

	if (len < 0)
		return -1;

	if (MASTER_file_write(file, buffer, len) != 0)
		return -1;

	return len;
}

MASTER_maxint
MASTER_file_read(MASTER_File * const file, void * buffer, MASTER_maxint size) {
	if (file == nul || !file->isOpen || file->isError) return -1;
	
	#ifdef _WIN32
		DWORD bytesRead;
		if (!ReadFile(file->handle, buffer, (DWORD)size, &bytesRead, nul)) {
			perror("Error reading from file (WinAPI)");
			file->isError = 1;
			return -1;
		}
		return (MASTER_maxint)bytesRead;
	#elif defined(__unix__) || defined(__APPLE__)
		MASTER_maxint bytesRead = read(file->fd, buffer, size);
		if (bytesRead == -1) {
			perror("Error reading from file (UNIX/POSIX)");
			file->isError = 1;
			return -1;
		}
		return (MASTER_maxint)bytesRead;
	#else
		return (MASTER_maxint)fread(buffer, 1, size, file->fp);
	#endif /* OPERATION SYSTEM */
}

void
MASTER_file_close(MASTER_File * const file) {
	if (file == nul || !file->isOpen) return;
	#ifdef _WIN32
		CloseHandle(file->handle);
		file->handle = INVALID_HANDLE_VALUE;
	#elif defined(__unix__) || defined(__APPLE__)
		close(file->fd);
		file->fd = -1;
	#else
		fclose(file->fp);
		file->fp = nul;
	#endif /* OPERATION SYSTEM */
	if (file->mode != nul) {
		MASTER_FREE(file->mode);
		file->mode = nul;
	}
	file->isOpen = 0;
	file->isError = 0;
}

void
MASTER_file_destroy(MASTER_File * const file) {
	if (file == nul) return;
	if (file->isOpen) MASTER_file_close(file);
	if (file->filename) MASTER_FREE(file->filename);
	MASTER_FREE(file);
}

int
MASTER_write_to_stdout(const void * data, MASTER_maxint size) {
	#ifdef _WIN32
		HANDLE hStdout = GetStdHandle(STD_OUTPUT_HANDLE);
		if (hStdout == INVALID_HANDLE_VALUE) {
			perror("Error getting stdout handle (WinAPI)");
			return -1;
		}
		DWORD bytesWritten;
		if (!WriteFile(hStdout, data, (DWORD)size, &bytesWritten, nul) || bytesWritten != size) {
			perror("Error writing to stdout (WinAPI)");
			return -1;
		}
	#elif defined(__unix__) || defined(__APPLE__)
		MASTER_maxint bytesWritten = write(STDOUT_FILENO, data, size);
		if (bytesWritten == -1 || (MASTER_maxint)bytesWritten != size) {
			perror("Error writing to stdout (UNIX/POSIX)");
			return -1;
		}
	#else
		if (fwrite(data, 1, size, stdout) != size) {
			perror("Error writing to stdout (stdio)");
			return -1;
		}
	#endif /* OPERATION SYSTEM */
	return 0;
}

MASTER_maxint
MASTER_read_from_stdin(void * buffer, MASTER_maxint size) {
	#ifdef _WIN32
		HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
		if (hStdin == INVALID_HANDLE_VALUE) {
			perror("Error getting stdin handle (WinAPI)");
			return -1;
		}
		DWORD bytesRead;
		if (!ReadFile(hStdin, buffer, (DWORD)size, &bytesRead, nul)) {
			perror("Error reading from stdin (WinAPI)");
			return -1;
		}
		return (MASTER_maxint)bytesRead;
	#elif defined(__unix__) || defined(__APPLE__)
		MASTER_maxint bytesRead = read(STDIN_FILENO, buffer, size);
		if (bytesRead == -1) {
			perror("Error reading from stdin (UNIX/POSIX)");
			return -1;
		}
		return bytesRead;
	#else
		return (MASTER_maxint)fread(buffer, 1, size, stdin);
	#endif /* OPERATION SYSTEM */
}

MASTER_File *
MASTER_getStdout(void) {
	MASTER_File *stdout_file = (MASTER_File*)MASTER_MALLOC(sizeof(MASTER_File));
	if (!stdout_file) return nul;
	stdout_file->filename = "stdout";
	#ifdef _WIN32
		stdout_file->handle = GetStdHandle(STD_OUTPUT_HANDLE);
		if (stdout_file->handle == INVALID_HANDLE_VALUE){
			MASTER_FREE(stdout_file);
			return nul;
		}
	#elif defined(__unix__) || defined(__APPLE__)
		stdout_file->fd = fileno(stdout);
		if (stdout_file->fd == -1) {
			 MASTER_FREE(stdout_file);
			return nul;
		}
	#else
		stdout_file->fp = stdout;
		if (!stdout_file->fp){
			MASTER_FREE(stdout_file);
			return nul;
		}
	#endif
	stdout_file->isOpen = 1;
	stdout_file->isError = 0;
	stdout_file->mode = "w";
	return stdout_file;
}

#endif /* __MASTER_MSTIO_INCLUDE_H__ */

// be master~
