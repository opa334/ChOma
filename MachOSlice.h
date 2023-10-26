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

int macho_slice_init_from_fat_arch(MachO *machO, struct fat_arch_64 archDescriptor, MachOSlice *sliceOut);
int macho_slice_from_macho(MachO *machO, MachOSlice *sliceOut);

#endif // MACHO_SLICE_H