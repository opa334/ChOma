#ifndef MACHO_SLICE_H
#define MACHO_SLICE_H

#include <stdbool.h>
#include <mach-o/fat.h>
#include <mach-o/loader.h>
#include "MemoryStream.h"

typedef struct MachOContainer MachOContainer;
typedef struct FilesetMachO FilesetMachO;
typedef struct MachOSegment MachOSegment;

typedef struct MachO {
    MemoryStream stream;
    bool isSupported;
    struct mach_header_64 machHeader;
    struct fat_arch_64 archDescriptor;

    uint32_t filesetCount;
    FilesetMachO *filesetMachos;

    uint32_t segmentCount;
    MachOSegment **segments;
} MachO;

// Read data from a MachOContainer slice at a specified offset
int macho_read_at_offset(MachO *macho, uint64_t offset, size_t size, void *outBuf);

int macho_enumerate_load_commands(MachO *macho, void (^enumeratorBlock)(struct load_command loadCommand, uint32_t offset, void *cmd, bool *stop));

// Initialise a MachO object from a MachOContainer and it's corresponding FAT arch descriptor
int macho_init_from_fat_arch(MachO *macho, MachOContainer *machO, struct fat_arch_64 archDescriptor);

// Initialise a MachO object from a MachOContainer object that only has one MachO contained in it
int macho_init_from_macho(MachO *macho, MachOContainer *machoContainer);

void macho_free(MachO *macho);

#endif // MACHO_SLICE_H