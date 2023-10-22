#include <stdio.h>

#include "CSBlob.h"
#include "CMSDER.h"

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
    CMSContentInfoDER contentInfo;
    DERItem cmsDERItem = {
        .data = cmsDERDataByte,
        .length = cmsDERDataLength
    };

    DERDecodedInfo decodedCMSData;
    DERReturn ret;
    ret = DERDecodeItem(&cmsDERItem, &decodedCMSData);
    if (ret != DR_Success) {
        printf("Error: DERDecodeItem returned %d.\n", ret);
        return -1;
    }
    if (decodedCMSData.tag != ASN1_CONSTR_SEQUENCE) {
        printf("Error: CMS content info tag is not a constructed sequence, first byte 0x%x.\n", decodedCMSData.tag);
        return -1;
    }
    if (cmsDERItem.data + cmsDERItem.length != decodedCMSData.content.data + decodedCMSData.content.length) {
        printf("Error: buffer overflow when decoding CMS content info.\n");
        return -1;
    }
    ret = DERParseSequenceContent(&decodedCMSData.content, sizeof(CMSContentInfoItemSpecs)/sizeof(CMSContentInfoItemSpecs[0]), CMSContentInfoItemSpecs, &contentInfo, 0);
    if (ret != DR_Success) {
        printf("Error: DERParseSequenceContent returned %d parsing ContentInfo.\n", ret);
        return -1;
    }


    // Decode content
    CMSContentDER content;
    DERItem contentDERItem = {
        .data = contentInfo.content.data,
        .length = contentInfo.content.length
    };

    DERDecodedInfo decodedContent;
    ret = DERDecodeItem(&contentDERItem, &decodedContent);
    if (ret != DR_Success) {
        printf("Error: DERDecodeItem returned %d decoding CMS content.\n", ret);
        return -1;
    }

    if (contentDERItem.data + contentDERItem.length != decodedContent.content.data + decodedContent.content.length) {
        printf("Error: buffer overflow when decoding CMS content.\n");
        return -1;
    }

    // Decode this into SignedData
    CMSSignedDataDER signedData;
    ret = DERParseSequenceContent(&decodedContent.content, sizeof(CMSSignedDataItemSpecs)/sizeof(CMSSignedDataItemSpecs[0]), CMSSignedDataItemSpecs, &signedData, 0);
    if (ret != DR_Success) {
        printf("Error: DERParseSequenceContent returned %d parsing SignedData.\n", ret);
        return -1;
    }

    if ((uint8_t)signedData.version.data[0] != 1) {
        printf("Error: CMS version is not 1, %d.\n", (uint8_t)signedData.version.data[0]);
        return -1;
    }

    printf("Successfully decoded SignedData!\n");

    free(cmsDERData);
    // Free the MachO structure
    freeMachO(&macho);

    printf("Done!\n");
    return 0;
    
}