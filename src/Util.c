#include "Util.h"
#include <stdio.h>

int64_t sxt64(int64_t value, uint8_t bits)
{
    value = ((uint64_t)value) << (64 - bits);
    value >>= (64 - bits);
    return value;
}

int memcmp_masked(const void *str1, const void *str2, unsigned char* mask, size_t n)
{
    const unsigned char* p = (const unsigned char*)str1;
    const unsigned char* q = (const unsigned char*)str2;

    if (p == q) return 0;
    for (int i = 0; i < n; i++) {
        unsigned char cMask = 0xFF;
        if (mask) {
            cMask = mask[i];
        }
        if((p[i] & cMask) != (q[i] & cMask)) {
            // we do not care about 1 / -1
            return -1;
        }
    }

    return 0;
}

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

void enumerate_range(uint64_t start, uint64_t end, uint16_t alignment, size_t nbytes, bool (^enumerator)(uint64_t))
{
    if (start == end) return;
    if (alignment == 0) return;
    if (nbytes == 0) return;
    if (nbytes % alignment) return;

    int dir = start < end ? 1 : -1;

    if (dir == 1) {
        end -= nbytes;
        if (start >= end) return;
    }
    else {
        start -= nbytes;
        if (start <= end) return;
    }

    for (uint64_t cur = start; (cur + (alignment * dir)) != end; cur += (dir * alignment)) {
        if (!enumerator(cur)) break;
    }
}