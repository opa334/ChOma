#include <stdio.h>
#include <libkern/OSByteOrder.h>
#include <mach/mach.h>
#include <mach-o/loader.h>
#include <mach-o/fat.h>
#include <sys/stat.h>

// #include "MachOLoadCommand.h"

typedef struct MachOSlice {
    struct mach_header_64 _machHeader;
    struct fat_arch_64 _archDescriptor;
    struct load_command *_loadCommands;
} MachOSlice;

typedef struct MachO
{
    FILE *_file;
    size_t _fileSize;
    MachOSlice *_slices;
    size_t _sliceCount;
    int _fileDescriptor;
} MachO;

MachO initMachOWithPath(const char *filePath, int *ret);
int readMachOAtOffset(MachO *macho, uint64_t offset, size_t size, void *outputBuffer);
void freeMachO(MachO *macho);