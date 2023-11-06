#include "MemoryStream.h"

int memory_stream_read(MemoryStream *stream, uint32_t offset, size_t size, void *outBuf)
{
    if (stream->read) {
        int ret = stream->read(stream, offset, size, outBuf);
        if (ret != size) { return -1; }
        return 0;
    }
    return -1;
}

int memory_stream_write(MemoryStream *stream, uint32_t offset, size_t size, void *inBuf)
{
    if (stream->write) {
        int ret = stream->write(stream, offset, size, inBuf);
        if (ret != size) { return -1; }
        return 0;
    }
    return -1;
}

size_t memory_stream_get_size(MemoryStream *stream)
{
    if (stream->getSize) {
        size_t sizeOut;
        if (stream->getSize(stream, &sizeOut) == 0) return sizeOut;
    }
    return MEMORY_STREAM_SIZE_INVALID;
}

void _memory_stream_clone(MemoryStream *output, MemoryStream *input)
{
    output->flags = input->flags;
    output->read = input->read;
    output->write = input->write;
    output->trim = input->trim;
    output->expand = input->expand;
    output->softclone = input->softclone;
    output->hardclone = input->hardclone;
    output->free = input->free;
}

int memory_stream_softclone(MemoryStream *output, MemoryStream *input)
{
    _memory_stream_clone(output, input);
    if (input->softclone) {
        return input->softclone(output, input);
    }
    return -1;
}

int memory_stream_hardclone(MemoryStream *output, MemoryStream *input)
{
    _memory_stream_clone(output, input);
    if (input->hardclone) {
        return input->hardclone(output, input);
    }
    return -1;
}

int memory_stream_trim(MemoryStream *stream, size_t trimAtStart, size_t trimAtEnd)
{
    if (stream->trim) {
        return stream->trim(stream, trimAtStart, trimAtEnd);
    }
    return -1;
}

int memory_stream_expand(MemoryStream *stream, size_t expandAtStart, size_t expandAtEnd)
{
    if (stream->expand) {
        return stream->expand(stream, expandAtStart, expandAtEnd);
    }
    return -1;
}

void memory_stream_free(MemoryStream *stream)
{
    if (stream->free) {
        return stream->free(stream);
    }
}

#define COPY_DATA_BUFFER_SIZE 0x4000
int memory_stream_copy_data(MemoryStream *originStream, uint32_t originOffset, MemoryStream *targetStream, uint32_t targetOffset, size_t size)
{
    size_t originSize = memory_stream_get_size(originStream);
    size_t targetSize = memory_stream_get_size(targetStream);
    if (originSize == MEMORY_STREAM_SIZE_INVALID || targetSize == MEMORY_STREAM_SIZE_INVALID) return -1;

    if (originOffset + size > originSize) {
        return -1;
    }
    if (targetOffset + size > targetSize) {
        return -1;
    }

    uint8_t buffer[COPY_DATA_BUFFER_SIZE];
    for (uint32_t copiedSize = 0; copiedSize < size; copiedSize += COPY_DATA_BUFFER_SIZE) {
        uint32_t remainingSize = size - copiedSize;
        uint32_t sizeToCopy = COPY_DATA_BUFFER_SIZE;
        if (remainingSize < sizeToCopy) {
            sizeToCopy = remainingSize;
        }
        int rr = memory_stream_read(originStream, originOffset + copiedSize, sizeToCopy, buffer);
        if (rr != 0) return rr;
        int wr = memory_stream_write(targetStream, targetOffset + copiedSize, sizeToCopy, buffer);
        if (wr != 0) return wr;
    }

    return 0;
}