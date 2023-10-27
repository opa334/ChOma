#ifndef MEMORY_BUFFER_H
#define MEMORY_BUFFER_H

#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#define MEMORY_BUFFER_SIZE_AUTO 0
#define MEMORY_BUFFER_FLAG_OWNS_DATA (1 << 0)
#define MEMORY_BUFFER_FLAG_MUTABLE (1 << 1)
#define MEMORY_BUFFER_FLAG_AUTO_EXPAND (1 << 2)

/*
Memory buffer interface:
Create a MemoryBuffer object to create a readable and writable buffer of memory.
Designed to be reusable across the whole project - meaning that you can use the
same read and write methods for both a file descriptor and a memory buffer.
*/
typedef struct {
    // For data backed memory buffer
    void *data;
    size_t dataSize;

    // For file descriptor backed memory buffers
    int fd;
    size_t fileSize;

    // The actual memory inside the file / data that this memory buffer represents
    uint32_t bufferStart;
    size_t bufferSize;

    // Flags to determine how this buffer should behave
    uint32_t flags;
} MemoryBuffer;

int memory_buffer_read(MemoryBuffer *buffer, uint32_t offset, size_t size, void *output);
int memory_buffer_write(MemoryBuffer *buffer, uint32_t offset, size_t size, void *data);

int memory_buffer_init_from_file_descriptor(int fd, uint32_t bufferStart, size_t bufferSize, MemoryBuffer *bufferOut);
int memory_buffer_init_from_path(const char *path, uint32_t bufferStart, size_t bufferSize, MemoryBuffer *bufferOut);
int memory_buffer_init_from_data_nocopy(void *dataPointer, size_t dataSize, uint32_t bufferStart, size_t bufferSize, MemoryBuffer *bufferOut);
int memory_buffer_init_from_data(void *dataPointer, size_t dataSize, uint32_t bufferStart, size_t bufferSize, MemoryBuffer *bufferOut);
int memory_buffer_duplicate(MemoryBuffer *originBuffer, MemoryBuffer *newBuffer);
int memory_buffer_init_trimmed(MemoryBuffer *originBuffer, uint32_t newBufferStart, uint32_t newBufferSize, MemoryBuffer *newBuffer);

void memory_buffer_free(MemoryBuffer *buffer);

#endif // MEMORY_BUFFER_H