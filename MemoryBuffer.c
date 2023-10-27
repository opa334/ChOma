#include "MemoryBuffer.h"

int memory_buffer_init_from_file_descriptor(int fd, uint32_t startOffset, size_t size, MemoryBuffer *bufferOut)
{
    struct stat s;
    int ret = fstat(fd, &s);
    if (ret != 0) {
        printf("Error: stat returned %d for %d.\n", ret, fd);
        return -1;
    }
    bufferOut->fd = fd;
    bufferOut->buffer = NULL;
    bufferOut->startOffset = startOffset;
    if (size == MEMBUF_SIZE_AUTO) {
        bufferOut->size = s.st_size - startOffset;
    }
    else {
        bufferOut->size = size;
    }

    printf("Successfully initialised MemoryBuffer object, size 0x%zx, fd 0x%x.\n", bufferOut->size, bufferOut->fd);
    return 0;
}

int memory_buffer_init_from_path(const char *path, uint32_t startOffset, size_t size, MemoryBuffer *bufferOut) {
    int fd = open(path, O_RDONLY);
    if (fd == -1) {
        printf("Failed to open %s\n", path);
        return -1;
    }

    return memory_buffer_init_from_file_descriptor(fd, startOffset, size, bufferOut);
}

int memory_buffer_init_from_data(void *dataPointer, uint32_t startOffset, size_t size, MemoryBuffer *bufferOut) {
    bufferOut->buffer = dataPointer;
    bufferOut->fd = -1;
    bufferOut->startOffset = startOffset;
    bufferOut->size = size;
    return 0;
}

int memory_buffer_read(MemoryBuffer *buffer, uint32_t offset, size_t size, void *output) {
    if (offset + size > buffer->size) {
        printf("Error: cannot read %zx bytes at %x, maximum is %zx.\n", size, offset, buffer->size);
        return -1;
    }

    if (buffer->fd != -1) {
        lseek(buffer->fd, buffer->startOffset + offset, SEEK_SET);
        read(buffer->fd, output, size);
    } else {
        memcpy(output, buffer->buffer + buffer->startOffset + offset, size);
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
        if (buffer->startOffset + offset + size > buffer->size) {
            // TODO!
        } else {
            lseek(buffer->fd, buffer->startOffset + offset, SEEK_SET);
            write(buffer->fd, data, size);
        }
    } else {
        memcpy(buffer->buffer + offset, data, size);
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
        void *originalBuffer = buffer->buffer;
        void *newBuffer = realloc(buffer->buffer, newSize);
        if (newBuffer == NULL) {
            printf("Error: realloc returned NULL while growing buffer.\n");
            return -1;
        }
        buffer->buffer = newBuffer;
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
        void *originalBuffer = buffer->buffer;
        void *newBuffer = realloc(buffer->buffer, newSize);
        if (newBuffer == NULL) {
            printf("Error: realloc returned NULL while shrinking buffer.\n");
            return -1;
        }
        buffer->buffer = newBuffer;
        buffer->size = newSize;
        free(originalBuffer);
    }*/
    return 0;
}

void memory_buffer_free(MemoryBuffer *buffer) {
    if (buffer->fd != -1) {
        close(buffer->fd);
    } else {
        free(buffer->buffer);
    }
}