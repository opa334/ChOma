#ifndef BUFFERED_STREAM_H
#define BUFFERED_STREAM_H

#include "MemoryStream.h"
#include <stdbool.h>

typedef struct BufferedStreamContext {
    uint8_t *buffer;
    size_t bufferSize;
    uint32_t subBufferStart;
    size_t subBufferSize;
    bool ownsBuffer;
} BufferedStreamContext;


int buffered_stream_read(MemoryStream *stream, uint32_t offset, size_t size, void *outBuf);
int buffered_stream_write(MemoryStream *stream, uint32_t offset, size_t size, void *inBuf);
int buffered_stream_get_size(MemoryStream *stream, size_t *sizeOut);
int buffered_stream_clone(MemoryStream *stream, MemoryStream *streamClone);
void buffered_stream_free(MemoryStream *stream);
int buffered_stream_init_from_buffer_nocopy(MemoryStream *stream, void *buffer, size_t bufferSize);
int buffered_stream_init_from_buffer(MemoryStream *stream, void *buffer, size_t bufferSize);

#endif // BUFFERED_STREAM_H