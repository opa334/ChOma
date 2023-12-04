#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <math.h>
#include <sys/stat.h>
#include <choma/FAT.h>
#include <choma/FileStream.h>
#include <choma/MemoryStream.h>
#include <choma/MachO.h>
#include <choma/MachOByteOrder.h>
#include <choma/Util.h>

#define ARM64_ALIGNMENT 0xE

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

void print_usage(char *executablePath) {
    printf("Options:\n");
    printf("\t-o: Path to output file\n");
    printf("\t-r: Replace output file if it already exists\n");
    printf("\t-h: Print this message\n");
    printf("Examples:\n");
    printf("\t%s -o <path to output file> <path to first MachO> <path to second MachO> ...\n", executablePath);
    exit(-1);
}

char **get_input_paths(int argc, char *argv[], int *inputPathsCount) {
    char **inputPaths = malloc(sizeof(char *) * argc);
    int count = 0;
    for (int i = 1; i < argc; i++) {
        // Make sure this isn't a flag or the output path
        if (argv[i][0] != '-' && strcmp(argv[i], get_argument_value(argc, argv, "-o"))) {
            inputPaths[count] = argv[i];
            count++;
        }
    }
    if (count == 0) {
        free(inputPaths);
        return NULL;
    }
    *inputPathsCount = count;
    return inputPaths;
}

int main(int argc, char *argv[]) {
    if (argument_exists(argc, argv, "-h")) {
        print_usage(argv[0]);
        return -1;
    }

    char *outputPath = get_argument_value(argc, argv, "-o");
    if (!outputPath) {
        printf("Error: no output file specified.\n");
        print_usage(argv[0]);
        return -1;
    }

    // Get the input paths
    int inputPathsCount = 0;
    char **inputPaths = get_input_paths(argc, argv, &inputPathsCount);
    if (!inputPaths) {
        printf("Error: no input files specified.\n");
        print_usage(argv[0]);
        return -1;
    }

    // Create the output FAT
    struct stat st;
    if (stat(outputPath, &st) == 0) {
        if (argument_exists(argc, argv, "-r")) {
            if (remove(outputPath) != 0) {
                printf("Error: failed to remove output file.\n");
                return -1;
            }
        } else {
            printf("Error: output file already exists.\n");
            return -1;
        }
    }

    FILE *outputFile = fopen(outputPath, "w");
    if (!outputFile) {
        printf("Error: failed to create output file.\n");
        return -1;
    }
    fclose(outputFile);

    // Create an array of MachO objects
    MachO **machoArray = macho_array_create_for_paths(inputPaths, inputPathsCount);
    if (!machoArray) {
        printf("Error: failed to create FAT array.\n");
        return -1;
    }

    // Create the FAT object
    FAT *fat = fat_create_for_macho_array(inputPaths[0], machoArray, inputPathsCount);
    printf("Created FAT with %u slices.\n", fat->slicesCount);

    // Write the FAT to the output file
    struct fat_header fatHeader;
    fatHeader.magic = FAT_MAGIC;
    fatHeader.nfat_arch = fat->slicesCount;
    FAT_HEADER_APPLY_BYTE_ORDER(&fatHeader, HOST_TO_BIG_APPLIER);
    uint64_t alignment = pow(2, ARM64_ALIGNMENT);
    uint64_t paddingSize = alignment - sizeof(struct fat_header) - (sizeof(struct fat_arch) * fat->slicesCount);
    MemoryStream *stream = file_stream_init_from_path(outputPath, 0, FILE_STREAM_SIZE_AUTO, FILE_STREAM_FLAG_WRITABLE | FILE_STREAM_FLAG_AUTO_EXPAND);
    memory_stream_write(stream, 0, sizeof(struct fat_header), &fatHeader);

    uint64_t lastSliceEnd = alignment;
    for (int i = 0; i < fat->slicesCount; i++) {
        struct fat_arch archDescriptor;
        archDescriptor.cpusubtype = fat->slices[i]->archDescriptor.cpusubtype;
        archDescriptor.cputype = fat->slices[i]->archDescriptor.cputype;
        archDescriptor.size = fat->slices[i]->archDescriptor.size;
        archDescriptor.offset = align_to_size(lastSliceEnd, alignment);
        archDescriptor.align = ARM64_ALIGNMENT;
        FAT_ARCH_APPLY_BYTE_ORDER(&archDescriptor, HOST_TO_BIG_APPLIER);
        printf("Writing to offset 0x%lx\n", sizeof(struct fat_header) + (sizeof(struct fat_arch) * i));
        memory_stream_write(stream, sizeof(struct fat_header) + (sizeof(struct fat_arch) * i), sizeof(struct fat_arch), &archDescriptor);
        lastSliceEnd += align_to_size(memory_stream_get_size(fat->slices[i]->stream), alignment);
    }
    uint8_t *padding = malloc(paddingSize);
    memset(padding, 0, paddingSize);
    memory_stream_write(stream, sizeof(struct fat_header) + (sizeof(struct fat_arch) * fat->slicesCount), paddingSize, padding);
    free(padding);

    uint64_t offset = alignment;
    for (int i = 0; i < fat->slicesCount; i++) {
        MachO *macho = fat->slices[i];
        int size = memory_stream_get_size(macho->stream);
        void *data = malloc(size);
        memory_stream_read(macho->stream, 0, size, data);
        memory_stream_write(stream, offset, size, data);
        free(data);
        uint64_t alignedSize = i == fat->slicesCount - 1 ? size : align_to_size(size, alignment);;
        printf("Slice %d: 0x%x bytes, aligned to 0x%llx bytes.\n", i, size, alignedSize);
        padding = malloc(alignedSize - size);
        memset(padding, 0, alignedSize - size);   
        memory_stream_write(stream, offset + size, alignedSize - size, padding);
        free(padding);
        offset += alignedSize;
    }

    if (fat) fat_free(fat);
    if (machoArray) free(machoArray);
    if (stream) memory_stream_free(stream);
    if (inputPaths) free(inputPaths);

    return 0;
}