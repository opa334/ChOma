#include "FAT.h"
#include "FileStream.h"
#include "MachO.h"
#include "MachOByteOrder.h"
#include "MachOLoadCommand.h"
#include "CSBlob.h"
#include "MemoryStream.h"

#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <mach/machine.h>
#include <stdlib.h>

int macho_read_at_offset(MachO *macho, uint64_t offset, size_t size, void *outBuf)
{
    return memory_stream_read(macho->stream, offset, size, outBuf);
}

int macho_write_at_offset(MachO *macho, uint64_t offset, size_t size, const void *inBuf)
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

size_t macho_get_mach_header_size(MachO *macho)
{
    return macho->is32Bit ? sizeof(struct mach_header) : sizeof(struct mach_header_64);
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

int macho_write_at_vmaddr(MachO *macho, uint64_t vmaddr, size_t size, const void *inBuf)
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

    return macho_write_at_offset(macho, fileoff, size, inBuf);
}

int macho_enumerate_load_commands(MachO *macho, void (^enumeratorBlock)(struct load_command loadCommand, uint64_t offset, void *cmd, bool *stop))
{
    if (macho->machHeader.ncmds < 1 || macho->machHeader.ncmds > 1000) {
        printf("Error: invalid number of load commands (%d).\n", macho->machHeader.ncmds);
        return -1;
    }

    // First load command starts after mach header
    uint64_t offset = macho_get_mach_header_size(macho);

    for (int j = 0; j < macho->machHeader.ncmds; j++) {
        struct load_command loadCommand;
        if (macho_read_at_offset(macho, offset, sizeof(loadCommand), &loadCommand) != 0) continue;
        LOAD_COMMAND_APPLY_BYTE_ORDER(&loadCommand, LITTLE_TO_HOST_APPLIER);

        if (strcmp(load_command_to_string(loadCommand.cmd), "LC_UNKNOWN") == 0)
		{
			printf("Ignoring unknown command: 0x%x.\n", loadCommand.cmd);
		}
        else {
            // TODO: Check if cmdsize matches expected size for cmd
            uint8_t cmd[loadCommand.cmdsize];
            if (macho_read_at_offset(macho, offset, loadCommand.cmdsize, cmd) != 0) continue;
            bool stop = false;
            enumeratorBlock(loadCommand, offset, (void *)cmd, &stop);
            if (stop) break;
        }
        offset += loadCommand.cmdsize;
    }
    return 0;
}

int macho_enumerate_symbols(MachO *macho, void (^enumeratorBlock)(const char *name, uint8_t type, uint64_t vmaddr, bool *stop))
{
    macho_enumerate_load_commands(macho, ^(struct load_command loadCommand, uint64_t offset, void *cmd, bool *stop) {
        if (loadCommand.cmd == LC_SYMTAB) {
            struct symtab_command *symtabCommand = (struct symtab_command *)cmd;
            SYMTAB_COMMAND_APPLY_BYTE_ORDER(symtabCommand, LITTLE_TO_HOST_APPLIER);
            char strtbl[symtabCommand->strsize];
            if (macho_read_at_offset(macho, symtabCommand->stroff, symtabCommand->strsize, strtbl) != 0) return;

            for (int i = 0; i < symtabCommand->nsyms; i++) {
                struct nlist_64 entry;
                if (macho_read_at_offset(macho, symtabCommand->symoff + (i * sizeof(entry)), sizeof(entry), &entry) != 0) continue;
                NLIST_64_APPLY_BYTE_ORDER(&entry, LITTLE_TO_HOST_APPLIER);

                if (entry.n_un.n_strx >= symtabCommand->strsize || entry.n_un.n_strx == 0) continue;

                const char *symbolName = &strtbl[entry.n_un.n_strx];
                if (symbolName[0] == 0) continue;

                bool stopSym = false;
                enumeratorBlock(symbolName, entry.n_type, entry.n_value, &stopSym);
                if (stopSym) {
                    *stop = true;
                    break;   
                }
            }
        }
    });

    return 0;
}

int macho_enumerate_dependencies(MachO *macho, void (^enumeratorBlock)(const char *dylibPath, uint32_t cmd, struct dylib* dylib, bool *stop))
{
    macho_enumerate_load_commands(macho, ^(struct load_command loadCommand, uint64_t offset, void *cmd, bool *stop){
        if (loadCommand.cmd == LC_LOAD_DYLIB || 
            loadCommand.cmd == LC_LOAD_WEAK_DYLIB || 
            loadCommand.cmd == LC_REEXPORT_DYLIB || 
            loadCommand.cmd == LC_LAZY_LOAD_DYLIB ||
            loadCommand.cmd == LC_LOAD_UPWARD_DYLIB) {
            struct dylib_command *dylibCommand = (struct dylib_command *)cmd;
            DYLIB_COMMAND_APPLY_BYTE_ORDER(dylibCommand, LITTLE_TO_HOST_APPLIER);
            if (dylibCommand->dylib.name.offset >= loadCommand.cmdsize || dylibCommand->dylib.name.offset < sizeof(struct dylib_command)) {
                printf("WARNING: Malformed dependency at 0x%llx (Name offset out of bounds)\n", offset);
                return;
            }
            char *dependencyPath = ((char *)cmd + dylibCommand->dylib.name.offset);
            size_t dependencyLength = strnlen(dependencyPath, loadCommand.cmdsize - dylibCommand->dylib.name.offset);
            if (!dependencyLength) {
                printf("WARNING: Malformed dependency at 0x%llx (Name has zero length)\n", offset);
                return;
            }
            if (dependencyPath[dependencyLength] != 0) {
                printf("WARNING: Malformed dependency at 0x%llx (Name has non NULL end byte)\n", offset);
                return;
            }

            bool stopDepdendency = false;
            enumeratorBlock(dependencyPath, loadCommand.cmd, &dylibCommand->dylib, &stopDepdendency);
            if (stopDepdendency) {
                *stop = true;
                return;
            }
        }
    });
    return 0;
}

int macho_enumerate_rpaths(MachO *macho, void (^enumeratorBlock)(const char *rpath, bool *stop))
{
    macho_enumerate_load_commands(macho, ^(struct load_command loadCommand, uint64_t offset, void *cmd, bool *stop) {
        if (loadCommand.cmd == LC_RPATH) {
            struct rpath_command *rpathCommand = (struct rpath_command *)cmd;
            RPATH_COMMAND_APPLY_BYTE_ORDER(rpathCommand, LITTLE_TO_HOST_APPLIER);

            if (rpathCommand->path.offset >= loadCommand.cmdsize || rpathCommand->path.offset < sizeof(struct rpath_command)) {
                printf("WARNING: Malformed rpath at 0x%llx (Path offset out of bounds)\n", offset);
                return;
            }

            char *rpath = ((char *)cmd) + rpathCommand->path.offset;
            size_t rpathLength = strnlen(rpath, rpathCommand->cmdsize - rpathCommand->path.offset);
            if (!rpathLength) {
                printf("WARNING: Malformed rpath at 0x%llx (Path has zero length)\n", offset);
                return;
            }
            if (rpath[rpathLength] != 0) {
                printf("WARNING: Malformed rpath at 0x%llx (Name has non NULL end byte)\n", offset);
                return;
            }

            bool stopRpath = false;
            enumeratorBlock(rpath, &stopRpath);
            if (stopRpath) {
                *stop = true;
            }
        }
    });
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
    macho->is32Bit = (macho->archDescriptor.cpusubtype == CPU_SUBTYPE_ARM_V6 || macho->archDescriptor.cpusubtype == CPU_SUBTYPE_ARM_V7 || macho->archDescriptor.cpusubtype == CPU_SUBTYPE_ARM_V7S);
    if (macho->machHeader.sizeofcmds % (macho->is32Bit ? sizeof(uint32_t) : sizeof(uint64_t)) != 0) {
        printf("Error: sizeofcmds is not a multiple of %lu (%d).\n", macho->is32Bit ? sizeof(uint32_t) : sizeof(uint64_t), macho->machHeader.sizeofcmds);
        return -1;
    }
    macho_parse_segments(macho);
    macho_parse_fileset_machos(macho);
    return 0;
}

MachO *macho_init(MemoryStream *stream, struct fat_arch_64 archDescriptor)
{
    MachO *macho = malloc(sizeof(MachO));
    if (!macho) return NULL;
    memset(macho, 0, sizeof(MachO));

    macho->stream = stream;
    macho->archDescriptor = archDescriptor;
    if (macho_read_at_offset(macho, 0, sizeof(macho->machHeader), &macho->machHeader) != 0) goto fail;
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
    memory_stream_read(macho->stream, 0, sizeof(struct mach_header), &macho->machHeader);
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

bool macho_is_encrypted(MachO *macho)
{
    __block bool isEncrypted = false;
    macho_enumerate_load_commands(macho, ^(struct load_command loadCommand, uint64_t offset, void *cmd, bool *stop) {
        if (loadCommand.cmd == LC_ENCRYPTION_INFO_64 || loadCommand.cmd == LC_ENCRYPTION_INFO) {
            struct encryption_info_command *encryptionInfoCommand = cmd;
            ENCRYPTION_INFO_COMMAND_APPLY_BYTE_ORDER(encryptionInfoCommand, LITTLE_TO_HOST_APPLIER);
            if (encryptionInfoCommand->cryptid == 1) {
                *stop = true;
                isEncrypted = true;
            }
        }
    });
    return isEncrypted;
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