#include "MemoryBuffer.h"

int memory_buffer_init_from_file_path(const char *path, size_t fileOffset, MemoryBuffer *bufferOut) {
    struct stat s;
    int ret = stat(path, &s);
    if (ret != 0) {
        printf("Error: stat returned %d with %s.\n", ret, path);
        return -1;
    }
    FILE *file = fopen(path, "rb");
    if (file == NULL) {
        printf("Error: fopen returned NULL while opening %s.\n", path);
        return -1;
    }
    int fileDescriptor = fileno(file);
    if (fileDescriptor == -1) {
        printf("Error: fileno returned -1 while opening %s.\n", path);
        return -1;
    }
    bufferOut->fd = fileDescriptor;
    bufferOut->buffer = NULL;
    bufferOut->startOffset = fileOffset;
    bufferOut->size = s.st_size;
    printf("Successfully initialised MemoryBuffer object, size 0x%zx, fd 0x%x.\n", bufferOut->size, bufferOut->fd);
    return 0;
}

int memory_buffer_init_from_pointer(void *pointer, size_t size, MemoryBuffer *bufferOut) {
    bufferOut->buffer = pointer;
    bufferOut->fd = -1;
    bufferOut->startOffset = 0;
    bufferOut->size = size;
    return 0;
}

int memory_buffer_read(MemoryBuffer *buffer, uint32_t offset, size_t size, void *output) {
    if (offset + size > buffer->size) {
        printf("Error: cannot read %zx bytes, maximum is %zx.\n", size, buffer->size - offset);
        return -1;
    }

    if (buffer->fd != -1) {
        lseek(buffer->fd, buffer->startOffset + offset, SEEK_SET);
        read(buffer->fd, output, size);
    } else {
        memcpy(output, buffer->buffer + offset, size);
    }

    return 0;
}

int memory_buffer_write(MemoryBuffer *buffer, uint32_t offset, size_t size, void *data) {

    if (offset + size > buffer->size) {
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
    }

    return 0;
}

int memory_buffer_grow(MemoryBuffer *buffer, size_t newSize) {
    if (newSize <= buffer->size) {
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
    }
    return 0;
}

int memory_buffer_shrink(MemoryBuffer *buffer, size_t newSize) {
    if (newSize >= buffer->size) {
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
    }
    return 0;
}

void memory_buffer_free(MemoryBuffer *buffer) {
    if (buffer->fd != -1) {
        close(buffer->fd);
    } else {
        free(buffer->buffer);
    }
}