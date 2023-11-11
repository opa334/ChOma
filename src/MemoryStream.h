#ifndef MEMORY_STREAM_H
#define MEMORY_STREAM_H

#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#define MEMORY_STREAM_FLAG_OWNS_DATA (1 << 0)
#define MEMORY_STREAM_FLAG_MUTABLE (1 << 1)
#define MEMORY_STREAM_FLAG_AUTO_EXPAND (1 << 2)

#define MEMORY_STREAM_SIZE_INVALID (size_t)-1

// A generic memory IO interface that is used throughout this project
// Can be backed by anything, just the functions have to be implemented
typedef struct MemoryStream {
   void *context;
   uint32_t flags;

   int (*read)(struct MemoryStream *stream, uint32_t offset, size_t size, void *outBuf);
   int (*write)(struct MemoryStream *stream, uint32_t offset, size_t size, void *inBuf);
   int (*getSize)(struct MemoryStream *stream, size_t *sizeOut);

   int (*trim)(struct MemoryStream *stream, size_t trimAtStart, size_t trimAtEnd);
   int (*expand)(struct MemoryStream *stream, size_t expandAtStart, size_t expandAtEnd);

   int (*hardclone)(struct MemoryStream *output, struct MemoryStream *input);
   int (*softclone)(struct MemoryStream *output, struct MemoryStream *input);
   void (*free)(struct MemoryStream *stream);
} MemoryStream;

int memory_stream_read(MemoryStream *stream, uint32_t offset, size_t size, void *outBuf);
int memory_stream_write(MemoryStream *stream, uint32_t offset, size_t size, void *inBuf);
size_t memory_stream_get_size(MemoryStream *stream);
uint32_t memory_stream_get_flags(MemoryStream *stream);

int memory_stream_softclone(MemoryStream *output, MemoryStream *input);
int memory_stream_hardclone(MemoryStream *output, MemoryStream *input);
int memory_stream_trim(MemoryStream *stream, size_t trimAtStart, size_t trimAtEnd);
int memory_stream_expand(MemoryStream *stream, size_t expandAtStart, size_t expandAtEnd);

void memory_stream_free(MemoryStream *stream);

int memory_stream_copy_data(MemoryStream *originStream, uint32_t originOffset, MemoryStream *targetStream, uint32_t targetOffset, size_t size);
int memory_stream_find_memory(MemoryStream *stream, uint64_t searchOffset, size_t searchSize, void *bytes, void *mask, size_t nbytes, uint16_t alignment, uint64_t *foundOffsetOut);

#endif // MEMORY_STREAM_H