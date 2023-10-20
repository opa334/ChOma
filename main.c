#include <stdio.h>

#include "CSBlob.h"

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <path to MachO file>\n", argv[0]);
        return 1;
    }
    MachO macho;
    if (initMachOWithPath(argv[1], &macho) != 0) { return -1; }
    CS_SuperBlob *superblob = malloc(sizeof(CS_SuperBlob));
    if (parseSuperBlob(&macho, 0, superblob) != 0) { return -1; }
    freeMachO(&macho);
    return 0;
}