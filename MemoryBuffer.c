#include "MemoryBuffer.h"

int memory_buffer_init_from_file_path(char *path, MemoryBuffer *bufferOut) {
    struct stat s;
    int ret = stat(path, &s);
    if (ret != 0) {
        printf("Error: stat returned %d with %s.\n", ret, path);
        return -1;
    }
    bufferOut->size = s.st_size;
    bufferOut->buffer = malloc(bufferOut->size);
    if (bufferOut->buffer == NULL) {
        printf("Error: malloc returned NULL while allocating buffer.\n");
        return -1;
    }
    FILE *file = fopen(path, "rb");
    if (file == NULL) {
        printf("Error: fopen returned NULL while opening %s.\n", path);
        return -1;
    }
    size_t read = fread(bufferOut->buffer, 1, bufferOut->size, file);
    if (read != bufferOut->size) {
        printf("Error: fread returned %zu while reading file.\n", read);
        return -1;
    }
    fclose(file);
    return 0;
}

int memory_buffer_init_from_pointer(void *pointer, size_t size, MemoryBuffer *bufferOut) {
    bufferOut->size = size;
    bufferOut->buffer = pointer;
    return 0;
}

int memory_buffer_read(MemoryBuffer *buffer, uint32_t offset, size_t size, void *output) {
    if (offset + size > buffer->size) {
        printf("Error: cannot read %zx bytes, maximum is %zx.\n", size, buffer->size - offset);
        return -1;
    }

    memcpy(output, buffer->buffer + offset, size);

    return 0;
}

int memory_buffer_write(MemoryBuffer *buffer, uint32_t offset, size_t size, void *data) {
    if (offset + size > buffer->size) {
        printf("Error: cannot write %zx bytes, maximum is %zx.\n", size, buffer->size - offset);
        return -1;
    }

    memcpy(buffer->buffer + offset, data, size);

    return 0;
}

int memory_buffer_grow(MemoryBuffer *buffer, size_t newSize) {
    if (newSize <= buffer->size) {
        printf("Error: cannot grow buffer to %zu bytes, current size if %zx.\n", newSize, buffer->size);
        return -1;
    }
    void *tmpBuffer = malloc(buffer->size);
    if (tmpBuffer == NULL) {
        printf("Error: malloc returned NULL while creating temporary buffer.\n");
        return -1;
    }
    memcpy(tmpBuffer, buffer->buffer, buffer->size);
    free(buffer->buffer);
    buffer->buffer = malloc(newSize);
    if (buffer->buffer == NULL) {
        printf("Error: malloc returned NULL while creating new buffer.\n");
        return -1;
    }
    memcpy(buffer->buffer, tmpBuffer, buffer->size);
    free(tmpBuffer);
    buffer->size = newSize;
    return 0;
}

int memory_buffer_shrink(MemoryBuffer *buffer, size_t newSize) {
    if (newSize >= buffer->size) {
        printf("Error: cannot shrink buffer to %zx bytes, current size is %zx.\n", newSize, buffer->size);
        return -1;
    }
    void *tmpBuffer = malloc(buffer->size);
    if (tmpBuffer == NULL) {
        printf("Error: malloc returned NULL while creating temporary buffer.\n");
        return -1;
    }
    memcpy(tmpBuffer, buffer->buffer, buffer->size);
    free(buffer->buffer);
    buffer->buffer = malloc(newSize);
    if (buffer->buffer == NULL) {
        printf("Error: malloc returned NULL while creating new buffer.\n");
        return -1;
    }
    memcpy(buffer->buffer, tmpBuffer, newSize);
    free(tmpBuffer);
    buffer->size = newSize;
    return 0;
}

void memory_buffer_free(MemoryBuffer *buffer) {
    free(buffer->buffer);
}