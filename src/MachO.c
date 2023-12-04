#include "FAT.h"
#include "FileStream.h"
#include "MachO.h"
#include "MachOByteOrder.h"
#include "MachOLoadCommand.h"
#include "MemoryStream.h"

#include <mach-o/loader.h>
#include <stdlib.h>

int macho_read_at_offset(MachO *macho, uint64_t offset, size_t size, void *outBuf)
{
    return memory_stream_read(macho->stream, offset, size, outBuf);
}

int macho_write_at_offset(MachO *macho, uint64_t offset, size_t size, void *inBuf)
{
    return memory_stream_write(macho->stream, offset, size, inBuf);
}

MemoryStream *macho_get_stream(MachO *macho)
{
    return macho->stream;
}

uint32_t macho_get_filetype(MachO *macho)
{
    return macho->machHeader.filetype;
}

int macho_translate_fileoff_to_vmaddr(MachO *macho, uint64_t fileoff, uint64_t *vmaddrOut, MachOSegment **segmentOut)
{
    for (uint32_t i = 0; i < macho->segmentCount; i++) {
        MachOSegment *segment = macho->segments[i];
        uint64_t segmentStartOff = segment->command.fileoff;
        uint64_t segmentEndOff = segment->command.fileoff + segment->command.filesize;
        if (fileoff >= segmentStartOff && fileoff < segmentEndOff) {
            uint64_t relativeFileoff = fileoff - segmentStartOff;
            *vmaddrOut = segment->command.vmaddr + relativeFileoff;
            return 0;
        }
    }
    return -1;
}

int macho_translate_vmaddr_to_fileoff(MachO *macho, uint64_t vmaddr, uint64_t *fileoffOut, MachOSegment **segmentOut)
{
    for (uint32_t i = 0; i < macho->segmentCount; i++) {
        MachOSegment *segment = macho->segments[i];
        uint64_t segmentVmAddr = segment->command.vmaddr;
        uint64_t segmentVmEnd = segment->command.vmaddr + segment->command.vmsize;
        if (vmaddr >= segmentVmAddr && vmaddr < segmentVmEnd) {
            uint64_t relativeVmAddr = vmaddr - segmentVmAddr;
            *fileoffOut = segment->command.fileoff + relativeVmAddr;
            if (segmentOut) *segmentOut = segment;
            return 0;
        }
    }
    return -1;
}

int macho_read_at_vmaddr(MachO *macho, uint64_t vmaddr, size_t size, void *outBuf)
{
    MachOSegment *segment;
    uint64_t fileoff = 0;
    int r = macho_translate_vmaddr_to_fileoff(macho, vmaddr, &fileoff, &segment);
    if (r != 0) return r;

    uint64_t readEnd = vmaddr + size;
    if (readEnd >= (segment->command.vmaddr + segment->command.vmsize)) {
        // prevent OOB
        return -1;
    }

    return macho_read_at_offset(macho, fileoff, size, outBuf);
}

int macho_enumerate_load_commands(MachO *macho, void (^enumeratorBlock)(struct load_command loadCommand, uint64_t offset, void *cmd, bool *stop))
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
			printf("Ignoring unknown command: 0x%x.\n", loadCommand.cmd);
		}
        else {
            // TODO: Check if cmdsize matches expected size for cmd
            uint8_t cmd[loadCommand.cmdsize];
            macho_read_at_offset(macho, offset, loadCommand.cmdsize, cmd);
            bool stop = false;
            enumeratorBlock(loadCommand, offset, (void *)cmd, &stop);
            if (stop) break;
        }
        offset += loadCommand.cmdsize;
    }
    return 0;
}

int macho_parse_segments(MachO *macho)
{
    return macho_enumerate_load_commands(macho, ^(struct load_command loadCommand, uint64_t offset, void *cmd, bool *stop) {
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
    return macho_enumerate_load_commands(macho, ^(struct load_command loadCommand, uint64_t offset, void *cmd, bool *stop) {
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
            
            MemoryStream *subStream = memory_stream_softclone(macho->stream);
            
            // TODO: Also cut trim to the end of the macho, but for that we would need to determine it's size
            memory_stream_trim(subStream, filesetCommand->fileoff, 0);
            filesetMacho->underlyingMachO = fat_init_from_memory_stream(subStream);
        }
    });
}

int _macho_parse(MachO *macho)
{
    // Determine if this arch is supported by ChOma
    macho->isSupported = (macho->archDescriptor.cpusubtype != 0x9);

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

MachO *macho_init(MemoryStream *stream, struct fat_arch_64 archDescriptor)
{
    MachO *macho = malloc(sizeof(MachO));
    if (!macho) return NULL;
    memset(macho, 0, sizeof(MachO));

    macho->stream = stream;
    macho->archDescriptor = archDescriptor;
    macho_read_at_offset(macho, 0, sizeof(macho->machHeader), &macho->machHeader);
    MACH_HEADER_APPLY_BYTE_ORDER(&macho->machHeader, LITTLE_TO_HOST_APPLIER);

    // Check the magic against the expected values
    if (macho->machHeader.magic != MH_MAGIC_64 && macho->machHeader.magic != MH_MAGIC) {
        goto fail;
    }

    if (_macho_parse(macho) != 0) goto fail;

    return macho;

fail:
    macho_free(macho);
    return NULL;
}

MachO *macho_init_for_writing(const char *filePath)
{
    MachO *macho = malloc(sizeof(MachO));
    if (!macho) return NULL;
    memset(macho, 0, sizeof(MachO));

    macho->stream = file_stream_init_from_path(filePath, 0, FILE_STREAM_SIZE_AUTO, FILE_STREAM_FLAG_WRITABLE | FILE_STREAM_FLAG_AUTO_EXPAND);
    if (!macho->stream) goto fail;

    size_t fileSize = memory_stream_get_size(macho->stream);
    memory_stream_read(macho->stream, 0, sizeof(struct mach_header_64), &macho->machHeader);
    MACH_HEADER_APPLY_BYTE_ORDER(&macho->machHeader, HOST_TO_LITTLE_APPLIER);
    if (macho->machHeader.magic != MH_MAGIC_64) goto fail;

    macho->archDescriptor.cpusubtype = macho->machHeader.cpusubtype;
    macho->archDescriptor.cputype = macho->machHeader.cputype;
    macho->archDescriptor.offset = 0;
    macho->archDescriptor.size = fileSize;
    macho->archDescriptor.align = 0x4000;

    if (_macho_parse(macho) != 0) goto fail;

    return macho;

fail:
    macho_free(macho);
    return NULL;
}

MachO **macho_array_create_for_paths(char **inputPaths, int inputPathsCount) {
    FAT **fatArray = malloc(sizeof(FAT *) * inputPathsCount);
    MachO **machoArray;
    int sliceCount = 0;
    for (int i = 0; i < inputPathsCount; i++) {
        FAT *fat = fat_init_from_path(inputPaths[i]);
        if (!fat) {
            printf("Error: failed to create FAT from file: %s\n", inputPaths[i]);
            return NULL;
        }
        sliceCount += fat->slicesCount;
        fatArray[i] = fat;
    }
    machoArray = malloc(sizeof(MachO *) * sliceCount);
    for (int i = 0; i < inputPathsCount; i++) {
        for (int j = 0; j < fatArray[i]->slicesCount; j++) {
            machoArray[i] = fatArray[i]->slices[j];
        }
    }
    return machoArray;
}

void macho_free(MachO *macho)
{
    if (macho->filesetCount != 0 && macho->filesetMachos) {
        for (uint32_t i = 0; i < macho->filesetCount; i++) {
            fat_free(macho->filesetMachos[i].underlyingMachO);
            free(macho->filesetMachos[i].entry_id);
        }
        free(macho->filesetMachos);
    }
    if (macho->segmentCount != 0 && macho->segments) {
        for (uint32_t i = 0; i < macho->segmentCount; i++) {
            free(macho->segments[i]);
        }
        free(macho->segments);
    }
    if (macho->stream) {
        memory_stream_free(macho->stream);
    }
    free(macho);
}