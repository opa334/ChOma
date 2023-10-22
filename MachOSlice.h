#ifndef MACHO_SLICE_H
#define MACHO_SLICE_H

typedef struct MachOSlice {
    struct mach_header_64 _machHeader;
    struct fat_arch_64 _archDescriptor;
    struct load_command *_loadCommands;
} MachOSlice;

#endif // MACHO_SLICE_H