#ifndef FILE_STREAM_H
#define FILE_STREAM_H

#include "MemoryStream.h"

#define FILE_STREAM_SIZE_AUTO 0
#define FILE_STREAM_FLAG_WRITABLE (1 << 0)
#define FILE_STREAM_FLAG_AUTO_EXPAND (1 << 1)

typedef struct FileStreamContext {
    int fd;
    size_t fileSize;
    uint32_t bufferStart;
    size_t bufferSize;
} FileStreamContext;

int file_stream_read(MemoryStream *stream, uint64_t offset, size_t size, void *outBuf);
//int file_stream_write(MemoryStream *stream, uint64_t offset, size_t size, void *inBuf);
int file_stream_get_size(MemoryStream *stream, size_t *sizeOut);

int file_stream_clone(MemoryStream *stream, MemoryStream *streamClone);
int file_stream_trim(MemoryStream *stream, size_t trimAtStart, size_t trimAtEnd);
//int file_stream_expand(MemoryStream *stream, size_t expandAtStart, size_t expandAtEnd);

int file_stream_copy_data(MemoryStream *originStream, uint64_t originOffset, MemoryStream *targetStream, uint64_t targetOffset, size_t size);

void file_stream_free(MemoryStream *stream);

MemoryStream *file_stream_init_from_file_descriptor_nodup(int fd, uint32_t bufferStart, size_t bufferSize, uint32_t flags);
MemoryStream *file_stream_init_from_file_descriptor(int fd, uint32_t bufferStart, size_t bufferSize, uint32_t flags);
MemoryStream *file_stream_init_from_path(const char *path, uint32_t bufferStart, size_t bufferSize, uint32_t flags);

#endif // FILE_STREAM_H