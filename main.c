#include <stdio.h>

#include "CSBlob.h"
#include <libDER/asn1Types.h> // This include MUST come after libDER_config.h
#include <libDER/libDER.h>
#include <libDER/DER_Decode.h>
#include <libDER/DER_Encode.h>

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

    FILE *cmsDERFile = fopen("CMS-DER", "rb");
    fseek(cmsDERFile, 0, SEEK_END);
    size_t cmsDERLength = ftell(cmsDERFile);
    fseek(cmsDERFile, 0, SEEK_SET);
    uint8_t *cmsDERData = malloc(cmsDERLength);
    fread(cmsDERData, cmsDERLength, 1, cmsDERFile);
    fclose(cmsDERFile);

    DERByte *cmsDERDataByte = cmsDERData;
    DERSize cmsDERDataLength = cmsDERLength;
    DERItem cmsDERItem = {
        .data = cmsDERDataByte,
        .length = cmsDERDataLength
    };

    DERDecodedInfo decodedCMSData;
    DERReturn ret = DERDecodeItem(&cmsDERItem, &decodedCMSData);
    printf("DERDecodeItem returned %d.\n", ret);
    printf("DERDecodeItem decoded %d bytes.\n", decodedCMSData.content.length);
    if (cmsDERItem.data[0] != ASN1_CONSTR_SEQUENCE) {
        printf("Error: CMS content info is not a constructed sequence, first byte 0x%x\n", cmsDERItem.data[0]);
    }

    free(cmsDERData);
    // Free the MachO structure
    freeMachO(&macho);

    printf("Done!\n");
    return 0;
    
}