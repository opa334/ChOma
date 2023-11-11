#include "BufferedStream.h"
#include "MemoryStream.h"

#include <stdlib.h>

int _buffered_stream_make_own_data(MemoryStream *stream)
{
    BufferedStreamContext *context = stream->context;
    if ((stream->flags & MEMORY_STREAM_FLAG_OWNS_DATA) == 0) {
        void *newBuffer = malloc(context->subBufferSize);
        memcpy(newBuffer, context->buffer + context->subBufferStart, context->subBufferSize);
        context->buffer = newBuffer;
        stream->flags |= MEMORY_STREAM_FLAG_OWNS_DATA;
    }
    return 0;
}

int buffered_stream_read(MemoryStream *stream, uint64_t offset, size_t size, void *outBuf)
{
    BufferedStreamContext *context = stream->context;
    if ((offset + size) > context->subBufferSize) {
        printf("Error: cannot read %zx bytes at %llx, maximum is %zx.\n", size, offset, context->bufferSize);
        return -1;
    }

    memcpy(outBuf, context->buffer + context->subBufferStart + offset, size);
    return 0;
}

int buffered_stream_write(MemoryStream *stream, uint64_t offset, size_t size, void *inBuf)
{
    BufferedStreamContext *context = stream->context;
    if ((offset + size) > context->bufferSize) {
        printf("Error: cannot write %zx bytes at %llx, maximum is %zx.\n", size, offset, context->bufferSize);
        return -1;
    }

    if ((stream->flags & MEMORY_STREAM_FLAG_OWNS_DATA) == 0) {
        int r = _buffered_stream_make_own_data(stream);
        if (r != 0) return r;
    }

    memcpy(context->buffer + context->subBufferStart + offset, inBuf, size);
    return -1;
}

int buffered_stream_get_size(MemoryStream *stream, size_t *sizeOut)
{
    BufferedStreamContext *context = stream->context;
    *sizeOut = context->bufferSize;
    return 0;
}

int buffered_stream_trim(MemoryStream *stream, size_t trimAtStart, size_t trimAtEnd)
{
    BufferedStreamContext *context = stream->context;

    // TODO: bound checks
    context->subBufferStart += trimAtStart;
    context->subBufferSize -= trimAtEnd;

    return 0;
}

int buffered_stream_expand(MemoryStream *stream, size_t expandAtStart, size_t expandAtEnd)
{
    BufferedStreamContext *context = stream->context;

    size_t newSize = context->bufferSize + expandAtStart + expandAtEnd;
    void *newBuffer = malloc(newSize);
    memset(newBuffer, 0, newSize);
    memcpy(newBuffer + expandAtEnd, context->buffer, newSize);
    if (stream->flags & MEMORY_STREAM_FLAG_OWNS_DATA) {
        free(context->buffer);
    }
    context->buffer = newBuffer;
    stream->flags |= MEMORY_STREAM_FLAG_OWNS_DATA;

    return 0;
}

int buffered_stream_softclone(MemoryStream *output, MemoryStream *input)
{
    BufferedStreamContext *context = input->context;
    BufferedStreamContext *contextCopy = malloc(sizeof(BufferedStreamContext));

    contextCopy->subBufferStart = context->subBufferStart;
    contextCopy->subBufferSize = context->subBufferSize;
    output->flags = input->flags & ~(MEMORY_STREAM_FLAG_OWNS_DATA);

    output->context = contextCopy;
    return 0;
}

int buffered_stream_hardclone(MemoryStream *output, MemoryStream *input)
{
    int r = buffered_stream_softclone(output, input);
    if (r != 0) return r;
    return _buffered_stream_make_own_data(output);
}

void buffered_stream_free(MemoryStream *stream)
{
    BufferedStreamContext *context = stream->context;
    if (context->buffer) {
        if (stream->flags & MEMORY_STREAM_FLAG_OWNS_DATA) {
            free(context->buffer);
        }
    }
    free(context);
}

int _buffered_stream_init(MemoryStream *stream)
{
    stream->read = buffered_stream_read;
    stream->write = buffered_stream_write;
    stream->getSize = buffered_stream_get_size;

    stream->trim = buffered_stream_trim;
    stream->expand = buffered_stream_expand;

    stream->softclone = buffered_stream_softclone;
    stream->hardclone = buffered_stream_hardclone;
    stream->free = buffered_stream_free;

    stream->flags = MEMORY_STREAM_FLAG_MUTABLE;
    return 0;
}

int buffered_stream_init_from_buffer_nocopy(MemoryStream *stream, void *buffer, size_t bufferSize)
{
    BufferedStreamContext *context = malloc(sizeof(BufferedStreamContext));
    context->buffer = buffer;
    context->bufferSize = bufferSize;
    context->subBufferStart = 0;
    context->subBufferSize = bufferSize;

    stream->context = context;
    return _buffered_stream_init(stream);
}

int buffered_stream_init_from_buffer(MemoryStream *stream, void *buffer, size_t bufferSize)
{
    void *copy = malloc(bufferSize);
    memcpy(copy, buffer, bufferSize);

    BufferedStreamContext *context = malloc(sizeof(BufferedStreamContext));
    context->buffer = copy;
    context->bufferSize = bufferSize;
    context->subBufferStart = 0;
    context->subBufferSize = bufferSize;
    stream->flags |= MEMORY_STREAM_FLAG_OWNS_DATA;

    stream->context = context;
    return _buffered_stream_init(stream);
}