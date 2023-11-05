#ifndef MACHO_SLICE_H
#define MACHO_SLICE_H

#include <stdbool.h>
#include "MemoryStream.h"
typedef struct MachO MachO;
typedef struct FilesetMachO FilesetMachO;
typedef struct MachOSegment MachOSegment;

typedef struct MachOSlice {
    MemoryStream stream;
    bool isSupported;
    struct mach_header_64 machHeader;
    struct fat_arch_64 archDescriptor;

    uint32_t filesetCount;
    FilesetMachO *filesetMachos;

    uint32_t segmentCount;
    MachOSegment **segments;
} MachOSlice;

// Read data from a MachO slice at a specified offset
int macho_slice_read_at_offset(MachOSlice *slice, uint64_t offset, size_t size, void *outBuf);

int macho_slice_enumerate_load_commands(MachOSlice *slice, void (^enumeratorBlock)(struct load_command loadCommand, uint32_t offset, void *cmd, bool *stop));

// Initialise a MachOSlice object from a FAT arch descriptor
int macho_slice_init_from_fat_arch(MachOSlice *slice, MachO *machO, struct fat_arch_64 archDescriptor);

// Initialise a MachOSlice object from a MachO object
int macho_slice_init_from_macho(MachOSlice *slice, MachO *macho);

void macho_slice_free(MachOSlice *slice);

#endif // MACHO_SLICE_H