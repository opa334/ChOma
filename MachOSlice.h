typedef struct MachOSlice {
    struct mach_header_64 _machHeader;
    struct fat_arch_64 _archDescriptor;
    struct load_command *_loadCommands;
} MachOSlice;
