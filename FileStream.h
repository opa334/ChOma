#ifndef FILE_STREAM_H
#define FILE_STREAM_H

#include "MemoryStream.h"

#define FILE_STREAM_SIZE_AUTO 0

typedef struct FileStreamContext {
    int fd;
    size_t fileSize;
    uint32_t bufferStart;
    size_t bufferSize;
} FileStreamContext;

int file_stream_read(MemoryStream *stream, uint32_t offset, size_t size, void *outBuf);
//int file_stream_write(MemoryStream *stream, uint32_t offset, size_t size, void *inBuf);
int file_stream_get_size(MemoryStream *stream, size_t *sizeOut);

int file_stream_clone(MemoryStream *stream, MemoryStream *streamClone);
int file_stream_trim(MemoryStream *stream, size_t trimAtStart, size_t trimAtEnd);
//int file_stream_expand(MemoryStream *stream, size_t expandAtStart, size_t expandAtEnd);

int file_stream_copy_data(MemoryStream *originStream, uint32_t originOffset, MemoryStream *targetStream, uint32_t targetOffset, size_t size);

void file_stream_free(MemoryStream *stream);

int file_stream_init_from_file_descriptor_nodup(MemoryStream *stream, int fd, uint32_t bufferStart, size_t bufferSize);
int file_stream_init_from_file_descriptor(MemoryStream *stream, int fd, uint32_t bufferStart, size_t bufferSize);
int file_stream_init_from_path(MemoryStream *stream, const char *path, uint32_t bufferStart, size_t bufferSize);

#endif // FILE_STREAM_H