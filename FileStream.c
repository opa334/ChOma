#include "FileStream.h"

int file_stream_read(MemoryStream *stream, uint32_t offset, size_t size, void *outBuf)
{
    FileStreamContext *context = stream->context;
    lseek(context->fd, context->bufferStart + offset, SEEK_SET);
    return read(context->fd, outBuf, size);
}

/*int file_stream_write(MemoryStream *stream, uint32_t offset, size_t size, void *inBuf)
{

}*/

int file_stream_get_size(MemoryStream *stream, size_t *sizeOut)
{
    FileStreamContext *context = stream->context;
    *sizeOut = context->bufferSize;
    return 0;
}

int file_stream_clone(MemoryStream *output, MemoryStream *input)
{
    FileStreamContext *context = input->context;
    return file_stream_init_from_file_descriptor(output, context->fd, context->bufferStart, context->bufferSize);
}

int file_stream_trim(MemoryStream *stream, size_t trimAtStart, size_t trimAtEnd)
{
    FileStreamContext *context = stream->context;
    if ((int64_t)context->bufferSize - (trimAtStart + trimAtEnd) < 0) {
        return -1;
    }

    context->bufferStart += trimAtStart; 
    context->bufferSize -= (trimAtStart + trimAtEnd);
    return 0;
}

/*int file_stream_expand(MemoryStream *stream, size_t expandAtStart, size_t expandAtEnd)
{

}*/

void file_stream_free(MemoryStream *stream)
{
    FileStreamContext *context = stream->context;
    if (context->fd != -1) {
        close(context->fd);
    }
    free(context);
}

int file_stream_init_from_file_descriptor_nodup(MemoryStream *stream, int fd, uint32_t bufferStart, size_t bufferSize)
{
    struct stat s;
    int statRes = fstat(fd, &s);
    if (statRes != 0) {
        printf("Error: stat returned %d for %d.\n", statRes, fd);
        return -1;
    }

    FileStreamContext *context = malloc(sizeof(FileStreamContext));
    context->fd = fd;
    context->fileSize = s.st_size;

    context->bufferStart = bufferStart;
    if (bufferSize == FILE_STREAM_SIZE_AUTO) {
        context->bufferSize = context->fileSize;
    }
    else {
        context->bufferSize = bufferSize;
    }

    stream->context = context;

    stream->read = file_stream_read;
    stream->write = NULL;
    //stream->write = file_stream_write;
    stream->getSize = file_stream_get_size;

    stream->trim = file_stream_trim;
    stream->expand = NULL;
    //stream->expand = file_stream_expand;

    stream->clone = file_stream_clone;
    stream->free = file_stream_free;

    return 0;
}

int file_stream_init_from_file_descriptor(MemoryStream *stream, int fd, uint32_t bufferStart, size_t bufferSize)
{
    return file_stream_init_from_file_descriptor_nodup(stream, dup(fd), bufferStart, bufferSize);
}

int file_stream_init_from_path(MemoryStream *stream, const char *path, uint32_t bufferStart, size_t bufferSize)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        printf("Failed to open %s\n", path);
        return -1;
    }
    return file_stream_init_from_file_descriptor_nodup(stream, fd, bufferStart, bufferSize);
}