#include "MemoryBuffer.h"

int memory_buffer_init_from_file_descriptor(int fd, uint32_t bufferStart, size_t bufferSize, MemoryBuffer *bufferOut)
{
    bufferOut->data = NULL;
    bufferOut->dataSize = 0;

    struct stat s;
    int ret = fstat(fd, &s);
    if (ret != 0) {
        printf("Error: stat returned %d for %d.\n", ret, fd);
        return -1;
    }
    bufferOut->fd = fd;
    bufferOut->fileSize = s.st_size;

    bufferOut->bufferStart = bufferStart;
    if (bufferSize == MEMORY_BUFFER_SIZE_AUTO) {
        bufferOut->bufferSize = s.st_size - bufferStart;
    }
    else {
        bufferOut->bufferSize = bufferSize;
    }

    printf("Successfully initialised MemoryBuffer object, size 0x%zx, fd 0x%x.\n", bufferOut->bufferSize, bufferOut->fd);
    return 0;
}

int memory_buffer_init_from_path(const char *path, uint32_t bufferStart, size_t bufferSize, MemoryBuffer *bufferOut)
{
    int fd = open(path, O_RDONLY);
    if (fd == -1) {
        printf("Failed to open %s\n", path);
        return -1;
    }

    return memory_buffer_init_from_file_descriptor(fd, bufferStart, bufferSize, bufferOut);
}

int memory_buffer_init_from_data_nocopy(void *dataPointer, size_t dataSize, uint32_t bufferStart, size_t bufferSize, MemoryBuffer *bufferOut)
{
    bufferOut->data = dataPointer;
    bufferOut->dataSize = dataSize;

    bufferOut->fd = -1;
    bufferOut->fileSize = 0;

    bufferOut->bufferStart = bufferStart;
    bufferOut->bufferSize = bufferSize;

    bufferOut->flags = 0;
    return 0;
}

int memory_buffer_init_from_data(void *dataPointer, size_t dataSize, uint32_t bufferStart, size_t bufferSize, MemoryBuffer *bufferOut)
{
    void *dataCopy = malloc(dataSize);
    memcpy(dataCopy, dataPointer, dataSize);
    
    int r = memory_buffer_init_from_data_nocopy(dataCopy, dataSize, bufferStart, bufferSize, bufferOut);
    if (r == 0) {
        bufferOut->flags |= MEMORY_BUFFER_FLAG_OWNS_DATA;
    }
    else {
        free(dataCopy);
    }
    return r;
}

int memory_buffer_duplicate(MemoryBuffer *originBuffer, MemoryBuffer *newBuffer)
{
    memcpy(newBuffer, originBuffer, sizeof(*originBuffer));
    if (newBuffer->fd != -1) {
        return memory_buffer_init_from_file_descriptor(dup(originBuffer->fd), newBuffer->bufferStart, newBuffer->bufferSize, newBuffer);
    }
    else if(newBuffer->data) {
        return memory_buffer_init_from_data(originBuffer->data, originBuffer->dataSize, originBuffer->bufferStart, originBuffer->bufferSize, newBuffer);
    }
    return 0;
}

int memory_buffer_init_trimmed(MemoryBuffer *originBuffer, uint32_t newBufferStart, uint32_t newBufferSize, MemoryBuffer *newBuffer)
{
    int r = memory_buffer_duplicate(originBuffer, newBuffer);
    if (r != 0) return r;

    // newBufferStart is relative to the original bufferStart
    // TODO: Do proper boundary checks
    newBuffer->bufferStart += newBufferStart;
    newBuffer->bufferSize = newBufferSize;

    return 0;
}

int memory_buffer_read(MemoryBuffer *buffer, uint32_t offset, size_t size, void *output) {
    if (offset + size > buffer->bufferSize) {
        printf("Error: cannot read %zx bytes at %x, maximum is %zx.\n", size, offset, buffer->bufferSize);
        return -1;
    }

    if (buffer->fd != -1) {
        lseek(buffer->fd, buffer->bufferStart + offset, SEEK_SET);
        read(buffer->fd, output, size);
    } else {
        memcpy(output, buffer->data + buffer->bufferStart + offset, size);
    }

    return 0;
}

int memory_buffer_write(MemoryBuffer *buffer, uint32_t offset, size_t size, void *data) {

    /*if (offset + size > buffer->size) {
        printf("Error: cannot write %zx bytes, maximum is %zx.\n", size, buffer->size - offset);
        return -1;
    }

    if (buffer->fd != -1) {
        // Check if we need a new file
        if (buffer->bufferStart + offset + size > buffer->size) {
            // TODO!
        } else {
            lseek(buffer->fd, buffer->bufferStart + offset, SEEK_SET);
            write(buffer->fd, data, size);
        }
    } else {
        memcpy(buffer->data + offset, data, size);
    }*/

    return 0;
}

int memory_buffer_grow(MemoryBuffer *buffer, size_t newSize) {
    /*if (newSize <= buffer->size) {
        printf("Error: cannot grow buffer to %zu bytes, current size is %zx.\n", newSize, buffer->size);
        return -1;
    }
    if (buffer->fd != -1) {
        // TODO!

    } else {
        void *originalBuffer = buffer->data;
        void *newBuffer = realloc(buffer->data, newSize);
        if (newBuffer == NULL) {
            printf("Error: realloc returned NULL while growing buffer.\n");
            return -1;
        }
        buffer->data = newBuffer;
        buffer->size = newSize;
        free(originalBuffer);
    }*/
    return 0;
}

int memory_buffer_shrink(MemoryBuffer *buffer, size_t newSize) {
    /*if (newSize >= buffer->size) {
        printf("Error: cannot shrink buffer to %zx bytes, current size is %zx.\n", newSize, buffer->size);
        return -1;
    }
    
    if (buffer->fd != -1) {
        // TODO!
    } else {
        void *originalBuffer = buffer->data;
        void *newBuffer = realloc(buffer->data, newSize);
        if (newBuffer == NULL) {
            printf("Error: realloc returned NULL while shrinking buffer.\n");
            return -1;
        }
        buffer->data = newBuffer;
        buffer->size = newSize;
        free(originalBuffer);
    }*/
    return 0;
}

void memory_buffer_free(MemoryBuffer *buffer) {
    if (buffer->fd != -1) {
        close(buffer->fd);
    } else if (buffer->data) {
        if (buffer->flags & MEMORY_BUFFER_FLAG_OWNS_DATA) {
            free(buffer->data);
        }
    }
}