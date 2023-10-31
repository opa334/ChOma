#include "MachO.h"
#include "MachOSlice.h"
#include "MachOByteOrder.h"
#include "MachOLoadCommand.h"

#include <stdlib.h>

int macho_slice_read_at_offset(MachOSlice *slice, uint64_t offset, size_t size, void *outBuf)
{
    return memory_stream_read(&slice->stream, offset, size, outBuf);
}

int macho_slice_enumerate_load_commands(MachOSlice *slice, void (^enumeratorBlock)(struct load_command loadCommand, uint32_t offset, void *cmd, bool *stop))
{
    if (slice->machHeader.ncmds < 1 || slice->machHeader.ncmds > 1000) {
        printf("Error: invalid number of load commands (%d).\n", slice->machHeader.ncmds);
        return -1;
    }

    // First load command starts after mach header
    uint64_t offset = sizeof(struct mach_header_64);

    for (int j = 0; j < slice->machHeader.ncmds; j++) {
        struct load_command loadCommand;
        macho_slice_read_at_offset(slice, offset, sizeof(loadCommand), &loadCommand);
        LOAD_COMMAND_APPLY_BYTE_ORDER(&loadCommand, LITTLE_TO_HOST_APPLIER);

        if (strcmp(load_command_to_string(loadCommand.cmd), "LC_UNKNOWN") == 0)
		{
			printf("Ignoring unknown command: 0x%x", loadCommand.cmd);
		}
        else {
            // TODO: Check if cmdsize matches expected size for cmd
            uint8_t cmd[loadCommand.cmdsize];
            macho_slice_read_at_offset(slice, offset, loadCommand.cmdsize, cmd);
            bool stop = false;
            enumeratorBlock(loadCommand, offset, (void *)cmd, &stop);
            if (stop) break;

            offset += loadCommand.cmdsize;
        }
    }
    return 0;
}

// For one arch of a fat binary
int macho_slice_init_from_fat_arch(MachOSlice *slice, MachO *machO, struct fat_arch_64 archDescriptor)
{
    memset(slice, 0, sizeof(*slice));

    int r = memory_stream_softclone(&slice->stream, &machO->stream);
    if (r != 0) return r;

    size_t machOSize = 0;
    r = memory_stream_get_size(&slice->stream, &machOSize);
    if (r != 0) return r;

    r = memory_stream_trim(&slice->stream, archDescriptor.offset, machOSize - (archDescriptor.offset + archDescriptor.size));
    if (r != 0) return r;

    slice->archDescriptor = archDescriptor;
    macho_slice_read_at_offset(slice, 0, sizeof(slice->machHeader), &slice->machHeader);

    // Check the magic against the expected values
    if (slice->machHeader.magic != MH_MAGIC_64 && slice->machHeader.magic != MH_MAGIC) {
        printf("Error: invalid magic 0x%x for mach header at offset 0x%llx.\n", slice->machHeader.magic, archDescriptor.offset);
        return -1;
    }

    // Determine if this arch is supported by ChOma
    slice->isSupported = (archDescriptor.cpusubtype != 0x9);

    if (slice->isSupported) {

        // Ensure that the sizeofcmds is a multiple of 8 (it would need padding otherwise)
        if (slice->machHeader.sizeofcmds % 8 != 0) {
            printf("Error: sizeofcmds is not a multiple of 8.\n");
            return -1;
        }
    }

    return 0;
}

// For single arch MachOs
int macho_slice_init_from_macho(MachOSlice *slice, MachO *macho)
{
    // This function can skip any sanity checks as those will be done by macho_slice_init_from_fat_arch

    size_t machoSize = 0;
    int r = memory_stream_get_size(&macho->stream, &machoSize);
    if (r != 0) return r;

    struct mach_header_64 machHeader;
    memory_stream_read(&macho->stream, 0, sizeof(machHeader), &machHeader);
    MACH_HEADER_APPLY_BYTE_ORDER(&machHeader, LITTLE_TO_HOST_APPLIER);

    // Create a FAT arch structure and populate it
    struct fat_arch_64 fakeArch = {0};
    fakeArch.cpusubtype = machHeader.cpusubtype;
    fakeArch.cputype = machHeader.cputype;
    fakeArch.offset = 0;
    fakeArch.size = machoSize;
    fakeArch.align = 0x4000;

    return macho_slice_init_from_fat_arch(slice, macho, fakeArch);
}

void macho_slice_free(MachOSlice *slice)
{
    memory_stream_free(&slice->stream);
}