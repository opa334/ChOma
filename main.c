#include <stdio.h>

#include "CSBlob.h"

int main(int argc, char *argv[]) {

    // Sanity check passed arguments
    if (argc != 2) {
        printf("Usage: %s <path to MachO file>\n", argv[0]);
        return 1;
    }

    // Initialise the MachO structure
    printf("Initialising MachO structure from %s.\n", argv[1]);
    MachO macho;
    if (initMachOWithPath(argv[1], &macho) != 0) { return -1; }

    // Parse the code signature blob
    printf("Parsing CMS superblobs from MachO.\n");
    for (int sliceIndex = 0; sliceIndex < macho._sliceCount; sliceIndex++) {
        if (parseSuperBlob(&macho, NULL, sliceIndex) != 0) { return -1; }
    }

    // Extract CMS data to file
    printf("Extracting CMS data from first slice to file.\n");
    CS_SuperBlob superblob;
    parseSuperBlob(&macho, &superblob, 0);
    extractCMSToFile(&macho, &superblob, 0);

    // Free the MachO structure
    freeMachO(&macho);

    printf("Done!\n");
    return 0;
    
}