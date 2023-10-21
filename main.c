#include <stdio.h>

#include "CSBlob.h"

int main(int argc, char *argv[]) {
    
    // Sanity check passed arguments
    if (argc != 2) {
        printf("Usage: %s <path to MachO file>\n", argv[0]);
        return 1;
    }

    // Initialise the MachO structure
    MachO macho;
    if (initMachOWithPath(argv[1], &macho) != 0) { return -1; }

    // Parse the code signature blob
    for (int sliceIndex = 0; sliceIndex < macho._sliceCount; sliceIndex++) {
        if (parseSuperBlob(&macho, NULL, 0) != 0) { return -1; }
    }

    CS_SuperBlob superblob;
    parseSuperBlob(&macho, &superblob, 0);
    extractCMSToFile(&macho, &superblob, 0);

    // Free the MachO structure
    freeMachO(&macho);

    return 0;
}