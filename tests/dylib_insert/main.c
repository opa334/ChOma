#include <choma/Fat.h>
#include <choma/MachO.h>
#include <choma/FileStream.h>
#include <choma/CSBlob.h>
#include <choma/Host.h>
#include <choma/MachOByteOrder.h>

#include <limits.h>
#include <copyfile.h>
#include <TargetConditionals.h>

#define CPU_SUBTYPE_ARM64E_ABI_V2 0x80000000

char *extract_preferred_slice(const char *fatPath)
{
    Fat *fat = fat_init_from_path(fatPath);
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
                // If that fails, check for arm64e with ABI v2
                macho = fat_find_slice(fat, CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64E | CPU_SUBTYPE_ARM64E_ABI_V2);
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
    }
#else
    if (!macho) {
        fat_free(fat);
        return NULL;
    }
#endif // TARGET_OS_MAC && !TARGET_OS_IPHONE

    // Only re-sign MH_EXECUTE, MH_DYLIB, and MH_BUNDLE
    if (macho->machHeader.filetype != MH_EXECUTE) {
        printf("Error: MachO is not an executable! This is an unsupported MachO type for inserting a dylib.\n");
        fat_free(fat);
        return NULL;
    }
    
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
    printf("\t-r: replace input file\n");
    printf("\t-d: path to dynamic library to insert (path to where it will be when loaded)\n");
    printf("\t-w: load as a weak dynamic library (will continue execution if the library cannot be found)\n");
    printf("\t-h: print this help message\n");
    printf("Examples:\n");
    printf("\t%s -i <path to input MachO file> -d hook.dylib -o <path to output MachO file>\n", self);
    printf("\t%s -i <path to input .app bundle> -a\n", self);
    exit(-1);
}

// Check if dylib is already inserted, check for a code signature and check for enough free space
int check_load_commands(MachO *macho, bool *isInserted, bool *isSigned, bool *enoughFreeSpace, const char *dylibToInsert) {
    macho_enumerate_load_commands(macho, ^(struct load_command lc, uint64_t offset, void *cmd, bool *stop) {
        if (lc.cmd == LC_CODE_SIGNATURE) {
            if (isSigned) *isSigned = true;
        }
        if (lc.cmd == LC_LOAD_DYLIB || lc.cmd == LC_LOAD_WEAK_DYLIB) {
            struct dylib_command *command = (struct dylib_command *)cmd;
            char *dylibName = NULL;
            macho_read_string_at_offset(macho, offset + command->dylib.name.offset, &dylibName);
            if (dylibName && !strcmp(dylibName, dylibToInsert)) {
                printf("Info: found existing load command for %s, not going to insert a new one.\n", dylibToInsert);
                if (isInserted) *isInserted = true;
            }
        }
    });

    int insertionSize = sizeof(struct dylib_command) + strlen(dylibToInsert);
    struct dylib_command *emptySpace = malloc(insertionSize);
    memset(emptySpace, 0, insertionSize);

    struct dylib_command *endOfLoadCommands = malloc(insertionSize);
    macho_read_at_offset(macho, macho_get_mach_header_size(macho) + macho->machHeader.sizeofcmds, insertionSize, endOfLoadCommands);

    if (!memcmp(emptySpace, endOfLoadCommands, insertionSize)) {
        if (enoughFreeSpace) *enoughFreeSpace = true;
    }

    free(emptySpace);
    free(endOfLoadCommands);

    return 0;
}

int insert_load_command(MachO *macho, const char *dylibPath, bool weakDylib) {
    struct dylib_command command = { 0 };
    int insertionSize = sizeof(command) + strlen(dylibPath);

    // Main load command
    command.cmd = weakDylib ? LC_LOAD_WEAK_DYLIB : LC_LOAD_DYLIB;
    command.cmdsize = (HOST_TO_LITTLE(insertionSize) + 3) & ~3;

    // dylib structure
    command.dylib.name.offset = HOST_TO_LITTLE((int)sizeof(command));
    command.dylib.timestamp = 0;
    command.dylib.current_version = 0;
    command.dylib.compatibility_version = 0;

    void *insertion = malloc(insertionSize);
    memcpy(insertion, &command, sizeof(command));
    memcpy(insertion + sizeof(command), dylibPath, strlen(dylibPath));

    macho_write_at_offset(macho, macho_get_mach_header_size(macho) + macho->machHeader.sizeofcmds, insertionSize, insertion);
    free(insertion);

    struct mach_header *header = malloc(sizeof(struct mach_header));
    memcpy(header, &macho->machHeader, sizeof(struct mach_header));
    MACH_HEADER_APPLY_BYTE_ORDER(header, LITTLE_TO_HOST_APPLIER);

    header->ncmds++;
    header->sizeofcmds += (insertionSize + 3) & ~3;
    MACH_HEADER_APPLY_BYTE_ORDER(header, HOST_TO_LITTLE_APPLIER);

    macho_write_at_offset(macho, 0, sizeof(struct mach_header), header);
    memcpy(&macho->machHeader, header, sizeof(struct mach_header));

    free(header);

    return 0;
}

int main(int argc, char *argv[]) {
    const char *inputFile = get_argument_value(argc, argv, "-i");
    const char *outputFile = get_argument_value(argc, argv, "-o");
    const char *dylibPath = get_argument_value(argc, argv, "-d");

    bool replace = argument_exists(argc, argv, "-r");
    bool weakDylib = argument_exists(argc, argv, "-w");
    bool showHelp = argument_exists(argc, argv, "-h");

    if (!inputFile || (!outputFile && !replace) || !dylibPath || showHelp) {
        print_usage(argv[0]);
    }

    if (access(inputFile, F_OK) != 0) {
        printf("Error: cannot access %s.\n", inputFile);
        return 1;
    }

    char *slicePath = extract_preferred_slice(inputFile);
    if (!slicePath) {
        printf("Error: failed to extract preferred slice.\n");
        return 1;
    }

    MachO *macho = macho_init_for_writing(slicePath);
    if (!macho) {
        printf("Error: failed to initialise MachO structure.\n");
        return 1;
    }

    int r = 0;

    bool isInserted = false, isSigned = false, enoughFreeSpace = false;
    r = check_load_commands(macho, &isInserted, &isSigned, &enoughFreeSpace, dylibPath);

    if (r || isInserted) goto out;
    if (isSigned) {
        printf("Warning: binary is signed, so you will need to re-sign after inserting the library.\n");
    }
    if (!enoughFreeSpace) {
        printf("Error: no free space available for new load command.\n");
        r = 1;
        goto out;
    }

    r = insert_load_command(macho, dylibPath, weakDylib);
    if (r) goto out;
    r = copyfile(slicePath, replace ? inputFile : outputFile, 0, COPYFILE_ALL | COPYFILE_MOVE | COPYFILE_UNLINK);
    if (r == 0) {
        chmod(outputFile, 0755);
        printf("Successfully inserted new load command.\n");
    }
    else {
        perror("copyfile");
    }

out:
    macho_free(macho);

    return r;
}