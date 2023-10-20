#include <stdio.h>

#include "CSBlob.h"

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <path to MachO file>\n", argv[0]);
        return 1;
    }
    MachO macho;
    if (initMachOWithPath(argv[1], &macho) != 0) { return -1; }
    printf("File size: 0x%zx bytes.\n", macho._fileSize);
    printf("File descriptor: %d.\n", macho._fileDescriptor);
    printf("Slice count: %zu.\n", macho._sliceCount);
    CS_SuperBlob *superblob = malloc(sizeof(CS_SuperBlob));
    parseSuperBlob(&macho, 0, superblob);
    freeMachO(&macho);
    return 0;
}