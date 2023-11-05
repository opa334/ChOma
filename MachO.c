#include "FAT.h"
#include "MachO.h"
#include "MachOByteOrder.h"
#include "MachOLoadCommand.h"

#include <stdlib.h>

int macho_read_at_offset(MachO *macho, uint64_t offset, size_t size, void *outBuf)
{
    return memory_stream_read(&macho->stream, offset, size, outBuf);
}

uint32_t macho_get_filetype(MachO *macho)
{
    return macho->machHeader.filetype;
}

int macho_enumerate_load_commands(MachO *macho, void (^enumeratorBlock)(struct load_command loadCommand, uint32_t offset, void *cmd, bool *stop))
{
    if (macho->machHeader.ncmds < 1 || macho->machHeader.ncmds > 1000) {
        printf("Error: invalid number of load commands (%d).\n", macho->machHeader.ncmds);
        return -1;
    }

    // First load command starts after mach header
    uint64_t offset = sizeof(struct mach_header_64);

    for (int j = 0; j < macho->machHeader.ncmds; j++) {
        struct load_command loadCommand;
        macho_read_at_offset(macho, offset, sizeof(loadCommand), &loadCommand);
        LOAD_COMMAND_APPLY_BYTE_ORDER(&loadCommand, LITTLE_TO_HOST_APPLIER);

        if (strcmp(load_command_to_string(loadCommand.cmd), "LC_UNKNOWN") == 0)
		{
			printf("Ignoring unknown command: 0x%x", loadCommand.cmd);
		}
        else {
            // TODO: Check if cmdsize matches expected size for cmd
            uint8_t cmd[loadCommand.cmdsize];
            macho_read_at_offset(macho, offset, loadCommand.cmdsize, cmd);
            bool stop = false;
            enumeratorBlock(loadCommand, offset, (void *)cmd, &stop);
            if (stop) break;

            offset += loadCommand.cmdsize;
        }
    }
    return 0;
}

int macho_parse_segments(MachO *macho)
{
    return macho_enumerate_load_commands(macho, ^(struct load_command loadCommand, uint32_t offset, void *cmd, bool *stop) {
        if (loadCommand.cmd == LC_SEGMENT_64) {
            macho->segmentCount++;
            if (macho->segments == NULL) { macho->segments = malloc(macho->segmentCount * sizeof(MachOSegment*)); }
            else { macho->segments = realloc(macho->segments, macho->segmentCount * sizeof(MachOSegment*)); }
            macho->segments[macho->segmentCount-1] = malloc(loadCommand.cmdsize);
            memcpy(macho->segments[macho->segmentCount-1], cmd, loadCommand.cmdsize);
            SEGMENT_COMMAND_64_APPLY_BYTE_ORDER(&macho->segments[macho->segmentCount-1]->command, LITTLE_TO_HOST_APPLIER);
            for (uint32_t i = 0; i < macho->segments[macho->segmentCount-1]->command.nsects; i++) {
                SECTION_64_APPLY_BYTE_ORDER(&macho->segments[macho->segmentCount-1]->sections[i], LITTLE_TO_HOST_APPLIER);
            }
        }
    });
}

int macho_parse_fileset_machos(MachO *macho)
{
    if (macho_get_filetype(macho) != MH_FILESET) return -1;
    return macho_enumerate_load_commands(macho, ^(struct load_command loadCommand, uint32_t offset, void *cmd, bool *stop) {
        if (loadCommand.cmd == LC_FILESET_ENTRY) {
            uint32_t i = macho->filesetCount;
            macho->filesetCount++;

            struct fileset_entry_command *filesetCommand = cmd;
            FILESET_ENTRY_COMMAND_APPLY_BYTE_ORDER(filesetCommand, LITTLE_TO_HOST_APPLIER);

            if (macho->filesetMachos == NULL) { macho->filesetMachos = malloc(macho->filesetCount * sizeof(FilesetMachO)); }
            else { macho->filesetMachos = realloc(macho->filesetMachos, macho->filesetCount * sizeof(FilesetMachO)); }

            FilesetMachO *filesetMacho = &macho->filesetMachos[i];
            filesetMacho->entry_id = strdup((char *)cmd + filesetCommand->entry_id.offset);
            filesetMacho->vmaddr = filesetCommand->vmaddr;
            filesetMacho->fileoff = filesetCommand->fileoff;
            
            MemoryStream subStream;
            memory_stream_softclone(&subStream, &macho->stream);
            // TODO: Also cut trim to the end of the macho, but for that we would need to determine it's size
            memory_stream_trim(&subStream, filesetCommand->fileoff, 0);
            fat_init_from_memory_stream(&filesetMacho->underlyingMachO, &subStream);
        }
    });
}


// For one arch of a fat binary
int macho_init_from_fat_arch(MachO *macho, FAT *fat, struct fat_arch_64 archDescriptor)
{
    memset(macho, 0, sizeof(*macho));

    int r = memory_stream_softclone(&macho->stream, &fat->stream);
    if (r != 0) return r;

    size_t machOSize = memory_stream_get_size(&macho->stream);
    if (machOSize == MEMORY_STREAM_SIZE_INVALID) return -1;

    r = memory_stream_trim(&macho->stream, archDescriptor.offset, machOSize - (archDescriptor.offset + archDescriptor.size));
    if (r != 0) return r;

    macho->archDescriptor = archDescriptor;
    macho_read_at_offset(macho, 0, sizeof(macho->machHeader), &macho->machHeader);

    // Check the magic against the expected values
    if (macho->machHeader.magic != MH_MAGIC_64 && macho->machHeader.magic != MH_MAGIC) {
        printf("Error: invalid magic 0x%x for mach header at offset 0x%llx.\n", macho->machHeader.magic, archDescriptor.offset);
        return -1;
    }

    // Determine if this arch is supported by ChOma
    macho->isSupported = (archDescriptor.cpusubtype != 0x9);

    if (macho->isSupported) {
        // Ensure that the sizeofcmds is a multiple of 8 (it would need padding otherwise)
        if (macho->machHeader.sizeofcmds % 8 != 0) {
            printf("Error: sizeofcmds is not a multiple of 8.\n");
            return -1;
        }

        macho_parse_segments(macho);
        macho_parse_fileset_machos(macho);
    }

    return 0;
}

// For single arch MachOs
int macho_init_from_single_slice_fat(MachO *macho, FAT *fat)
{
    // This function can skip any sanity checks as those will be done by macho_init_from_fat_arch

    size_t machoSize = memory_stream_get_size(&fat->stream);
    if (machoSize == MEMORY_STREAM_SIZE_INVALID) return -1;

    struct mach_header_64 machHeader;
    memory_stream_read(&fat->stream, 0, sizeof(machHeader), &machHeader);
    MACH_HEADER_APPLY_BYTE_ORDER(&machHeader, LITTLE_TO_HOST_APPLIER);

    // Create a FAT arch structure and populate it
    struct fat_arch_64 fakeArch = {0};
    fakeArch.cpusubtype = machHeader.cpusubtype;
    fakeArch.cputype = machHeader.cputype;
    fakeArch.offset = 0;
    fakeArch.size = machoSize;
    fakeArch.align = 0x4000;

    return macho_init_from_fat_arch(macho, fat, fakeArch);
}

void macho_free(MachO *macho)
{
    if (macho->filesetCount != 0 && macho->filesetMachos) {
        for (uint32_t i = 0; i < macho->filesetCount; i++) {
            fat_free(&macho->filesetMachos[i].underlyingMachO);
        }
        free(macho->filesetMachos);
    }
    if (macho->segmentCount != 0 && macho->segments) {
        for (uint32_t i = 0; i < macho->segmentCount; i++) {
            free(macho->segments[i]);
        }
        free(macho->segments);
    }
    memory_stream_free(&macho->stream);
}