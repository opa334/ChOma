#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#include <choma/Fat.h>
#include <choma/MachO.h>
#include <choma/MemoryStream.h>
#include <choma/DyldSharedCache.h>

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
    printf("\t-i: Path to input DSC file (e.g. dyld_shared_cache_arm64e)\n");
    printf("\t-o: Path output file if required\n");
    printf("\t-e: Path of image to extract\n");
    printf("\t-l: List images contained in shared cache\n");
    printf("\t-d: Print dependencies of image\n");
    printf("\t-h: Print this message\n");
    printf("Examples:\n");
    printf("\t%s -i <path to DSC file> -l\n", executablePath);
    printf("\t%s -i <path to DSC file> -e <path to framework> -o <path to extracted framework>\n", executablePath);
    exit(-1);
}

int main(int argc, char *argv[]) {
    if (argument_exists(argc, argv, "-h")) {
        print_usage(argv[0]);
    }

    char *inputPath = get_argument_value(argc, argv, "-i");
    char *outputPath = get_argument_value(argc, argv, "-o");
    char *imageToExtract = get_argument_value(argc, argv, "-e");
    bool shouldListImages = argument_exists(argc, argv, "-l");
    bool shouldPrintDependencies = argument_exists(argc, argv, "-d");


    if (!inputPath) {
        printf("Error: input file required\n");
        print_usage(argv[0]);
    }

    if (!shouldListImages && !outputPath && !shouldPrintDependencies) {
        printf("Error: output file required\n");
        print_usage(argv[0]);
    }

    DyldSharedCache *dsc = dsc_init_from_path(inputPath);
    if (!dsc) {
        printf("Error: failed to parse dyld shared cache\n");
        return -2;
    }

    __block MachO *machoToExtract = NULL;
    dsc_enumerate_images(dsc, ^(const char *path, DyldSharedCacheImage *imageHandle, MachO *imageMachO, bool *stop){
        if (shouldListImages) printf("%s\n", path);
        if (imageToExtract && !strcmp(path, imageToExtract)) {
            machoToExtract = imageMachO;
        }
    });
    
    if (machoToExtract && shouldPrintDependencies) {
        printf("Dependencies of %s:\n", imageToExtract);
        macho_enumerate_dependencies(machoToExtract, ^(const char *dylibPath, uint32_t cmd, struct dylib *dylib, bool *stop) {
            printf("| %s\n", dylibPath);
        });
    } else if (!machoToExtract && imageToExtract) {
        printf("Error: failed to locate %s in shared cache\n", imageToExtract);
    } else if (machoToExtract) {
        FILE *f = fopen(outputPath, "wb+");
        if (f) {
            MemoryStream *memoryStream = macho_get_stream(machoToExtract);
            fwrite(memory_stream_get_raw_pointer(memoryStream), memory_stream_get_size(memoryStream), 1, f);
            fclose(f);
        } else {
            printf("Error: failed to open %s for writing\n", outputPath);
        }
    }

    dsc_free(dsc);

    return 0;
}
