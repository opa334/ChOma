#ifndef MEMORY_BUFFER_H
#define MEMORY_BUFFER_H

#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <string.h>
#include <unistd.h>

/*
Memory buffer interface:
Create a MemoryBuffer object to create a readable and writable buffer of memory.
Designed to be reusable across the whole project - meaning that you can use the
same read and write methods for both a file descriptor and a memory buffer.
*/
typedef struct {
    void *buffer;
    int fd;
    uint32_t startOffset;
    size_t size;
} MemoryBuffer;

#endif // MEMORY_BUFFER_H