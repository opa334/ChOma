#include <stdio.h>

#include "CSBlob.h"

int main(int argc, char *argv[]) {
    int ret;
    if (argc != 2) {
        printf("Usage: %s <path to MachO file>\n", argv[0]);
        return 1;
    }
    MachO macho = initMachOWithPath(argv[1], &ret);
    if (ret != 0) {
        return -1;
    }
    printf("File size: 0x%zx bytes.\n", macho._fileSize);
    printf("File descriptor: %d.\n", macho._fileDescriptor);
    printf("Slice count: %zu.\n", macho._sliceCount);
    CS_SuperBlob *superblob = malloc(sizeof(CS_SuperBlob));
    parseSuperBlob(&macho, 0, superblob);
    freeMachO(&macho);
    return 0;
}