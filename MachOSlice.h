#ifndef MACHO_SLICE_H
#define MACHO_SLICE_H

#include <stdbool.h>
typedef struct MachO MachO;

typedef struct MachOSlice {
    MachO *containingMacho;
    struct mach_header_64 machHeader;
    struct fat_arch_64 archDescriptor;
    struct load_command *loadCommands;
    bool isSupported;
} MachOSlice;

// Initialise a MachOSlice object from a FAT arch descriptor
int macho_slice_init_from_fat_arch(MachO *machO, struct fat_arch_64 archDescriptor, MachOSlice *sliceOut);

// Initialise a MachOSlice object from a MachO object
int macho_slice_from_macho(MachO *machO, MachOSlice *sliceOut);

// Read data from a MachO slice at a specified offset
int macho_slice_read_at_offset(MachOSlice *slice, uint64_t offset, size_t size, void *outputBuffer);

#endif // MACHO_SLICE_H