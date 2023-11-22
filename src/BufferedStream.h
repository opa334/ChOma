#ifndef BUFFERED_STREAM_H
#define BUFFERED_STREAM_H

#include "MemoryStream.h"
#include <stdbool.h>

typedef struct BufferedStreamContext {
    uint8_t *buffer;
    size_t bufferSize;
    uint32_t subBufferStart;
    size_t subBufferSize;
} BufferedStreamContext;

MemoryStream *buffered_stream_init_from_buffer_nocopy(void *buffer, size_t bufferSize);
MemoryStream *buffered_stream_init_from_buffer(void *buffer, size_t bufferSize);

#endif // BUFFERED_STREAM_H