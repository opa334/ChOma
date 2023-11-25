#include "Util.h"
#include <stdio.h>

uint64_t align_to_size(int size, int alignment)
{
    return (size + alignment - 1) & ~(alignment - 1);
}

int count_digits(int64_t num)
{
    if (num == 0) {
        return 1;
    }
    int digits = 0;
    if (num < 0) {
        num = -num;
        digits++;
    }
    while (num != 0) {
        num = num / 10;
        digits++;
    }
    return digits;
}

void print_hash(uint8_t *hash, size_t size)
{
    for (int j = 0; j < size; j++) {
        printf("%02x", hash[j]);
    }
}