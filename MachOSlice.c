#include "MachO.h"
#include "MachOSlice.h"
#include "MachOByteOrder.h"
#include "MachOLoadCommand.h"

#include <stdlib.h>

int macho_slice_read_at_offset(MachOSlice *slice, uint64_t offset, size_t size, void *outBuf)
{
    return memory_stream_read(&slice->stream, offset, size, outBuf);
}

uint32_t macho_slice_get_filetype(MachOSlice *slice)
{
    return slice->machHeader.filetype;
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

int macho_slice_parse_segments(MachOSlice *slice)
{
    return macho_slice_enumerate_load_commands(slice, ^(struct load_command loadCommand, uint32_t offset, void *cmd, bool *stop) {
        if (loadCommand.cmd == LC_SEGMENT_64) {
            slice->segmentCount++;
            if (slice->segments == NULL) { slice->segments = malloc(slice->segmentCount * sizeof(*slice->segments)); }
            else { slice->segments = realloc(slice->segments, slice->segmentCount * sizeof(*slice->segments)); }
            slice->segments[slice->segmentCount-1] = malloc(loadCommand.cmdsize);
            memcpy(slice->segments[slice->segmentCount-1], cmd, loadCommand.cmdsize);
            SEGMENT_COMMAND_64_APPLY_BYTE_ORDER(&slice->segments[slice->segmentCount-1]->command, LITTLE_TO_HOST_APPLIER);
            for (uint32_t i = 0; i < slice->segments[slice->segmentCount-1]->command.nsects; i++) {
                SECTION_64_APPLY_BYTE_ORDER(&slice->segments[slice->segmentCount-1]->sections[i], LITTLE_TO_HOST_APPLIER);
            }
        }
    });
}

int macho_slice_parse_fileset_machos(MachOSlice *slice)
{
    if (macho_slice_get_filetype(slice) != MH_FILESET) return -1;
    return macho_slice_enumerate_load_commands(slice, ^(struct load_command loadCommand, uint32_t offset, void *cmd, bool *stop) {
        if (loadCommand.cmd == LC_FILESET_ENTRY) {
            uint32_t i = slice->filesetCount;
            slice->filesetCount++;

            struct fileset_entry_command *filesetCommand = cmd;
            FILESET_ENTRY_COMMAND_APPLY_BYTE_ORDER(filesetCommand, LITTLE_TO_HOST_APPLIER);

            if (slice->filesetMachos == NULL) { slice->filesetMachos = malloc(slice->filesetCount * sizeof(FilesetMachO)); }
            else { slice->filesetMachos = realloc(slice->filesetMachos, slice->filesetCount * sizeof(FilesetMachO)); }

            FilesetMachO *filesetMacho = &slice->filesetMachos[i];
            filesetMacho->entry_id = strdup((char *)cmd + filesetCommand->entry_id.offset);
            filesetMacho->vmaddr = filesetCommand->vmaddr;
            filesetMacho->fileoff = filesetCommand->fileoff;
            
            MemoryStream subStream;
            memory_stream_softclone(&subStream, &slice->stream);
            // TODO: Also cut trim to the end of the macho, but for that we would need to determine it's size
            memory_stream_trim(&subStream, filesetCommand->fileoff, 0);
            macho_init_from_memory_stream(&filesetMacho->underlyingMachO, &subStream);
        }
    });
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

        macho_slice_parse_segments(slice);
        macho_slice_parse_fileset_machos(slice);
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
    if (slice->filesetCount != 0 && slice->filesetMachos) {
        for (uint32_t i = 0; i < slice->filesetCount; i++) {
            macho_free(&slice->filesetMachos[i].underlyingMachO);
        }
        free(slice->filesetMachos);
    }
    if (slice->segmentCount != 0 && slice->segments) {
        for (uint32_t i = 0; i < slice->segmentCount; i++) {
            free(slice->segments[i]);
        }
        free(slice->segments);
    }
    memory_stream_free(&slice->stream);
}