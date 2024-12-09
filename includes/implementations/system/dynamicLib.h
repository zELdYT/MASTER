
/*
 * Copyright (c) 2024 zELdYT
 *
 * Licensed under the BSD 2-Clause License.
 * See the LICENSE file in the project root for more details.
 */

#ifndef __MASTER_DYNAMIC_LIB_INCLUDE_H__
#define __MASTER_DYNAMIC_LIB_INCLUDE_H__

#if !(defined(__WIN32) || defined(__linux__) || defined(__APPLE__) || defined(__sun))
#	error "Unknown operation system. Supported only Windows & Linux & MacOS & Solaris."
#endif /* OS */

#if defined(__WIN32)
#	include <windows.h>
#elif defined(__linux__)
#	include <dlfcn.h>
#endif /* OS */

typedef struct {
	void * handle;
} MASTER_dynamic_library;

void *
MASTER_dynamic_library_open( MASTER_dynamic_library * dl, const char * const libPath) {
#if defined(__WIN32)
	dl->handle = LoadLibraryA(libPath);
#elif defined(__linux__) || defined(__APPLE__) || defined(__sun)
	dl->handle = dlopen(libPath, RTLD_LAZY);
#endif /* OS */
	return dl->handle;
}

void
MASTER_dynamic_library_close( MASTER_dynamic_library * dl) {
#if defined(__WIN32)
	FreeLibrary((HMODULE)dl->handle);
#elif defined(__linux__) || defined(__APPLE__) || defined(__sun)
	dlclose(dl->handle);
#endif /* OS */
}

void *
MASTER_dynamic_library_getFunction( MASTER_dynamic_library * dl, const char * const funcName) {
#if defined(__WIN32)
	return (void*)GetProcAddress((HMODULE)dl->handle, funcName);
#elif defined(__linux__) || defined(__APPLE__) || defined(__sun)
	return dlsym(dl->handle, funcName);
#endif /* OS */
}

const char *
MASTER_dynamic_library_getLastError( void ) {
#if defined(__WIN32)
	static char buffer[256];
		FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, GetLastError(), 0, buffer, sizeof(buffer), NULL);
	return buffer;
#elif defined(__linux__) || defined(__APPLE__) || defined(__sun)
	return dlerror();
#endif /* OS */
}

#endif /* __MASTER_DYNAMIC_LIB_INCLUDE_H__ */

// be master~

#include <stdio.h>
#include <stdlib.h>
int main(int argc, char *argv[]) {
	MASTER_dynamic_library myLib;
	system("cp /storage/emulated/0/Documents/CxxDroid/MASTER/MyLib.so /data/data/ru.iiec.cxxdroid/files/OtherLibs/MyLib.so");
	MASTER_dynamic_library_open(&myLib, "/data/data/ru.iiec.cxxdroid/files/OtherLibs/MyLib.so");
	if (!myLib.handle) {
		printf("%s\n", MASTER_dynamic_library_getLastError());
		return 1;
	}
	unsigned long long (*fib)(int) = MASTER_dynamic_library_getFunction(&myLib, "fib");
	if (!fib) {
		printf("%s\n", MASTER_dynamic_library_getLastError());
		MASTER_dynamic_library_close(&myLib);
		return 1;
	}
	int arg = 42;
	printf("Fibonnachi %d is %llu", arg, fib(arg));

	MASTER_dynamic_library_close(&myLib);
	return 0;
}
