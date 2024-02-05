#include "choma/FileStream.h"
#include <choma/CSBlob.h>
#include <choma/CodeDirectory.h>
#include <choma/MachOLoadCommand.h>
#include <choma/Host.h>
#include <mach-o/nlist.h>

char *get_argument_value(int argc, char *argv[], const char *flag)
{
    for (int i = 0; i < argc; i++) {
        if (!strcmp(argv[i], flag)) {
            if (i+1 < argc) {
                return argv[i+1];
            }
        }
    }
    return NULL;
}

bool argument_exists(int argc, char *argv[], const char *flag)
{
    for (int i = 0; i < argc; i++) {
        if (!strcmp(argv[i], flag)) {
            return true;
        }
    }
    return false;
}

void print_usage(char *executablePath) {
    printf("Options:\n");
    printf("\t-i: Path to input file\n");
    printf("\t-c: Parse the CMS superblob blob of a MachO\n");
    printf("\t-e: Extract the Code Signature from a MachO\n");
    printf("\t-s: Print all page hash code slots in a CodeDirectory blob\n");
    printf("\t-v: Verify that the CodeDirectory hashes are correct\n");
    printf("\t-f: Parse an MH_FILESET MachO and output it's sub-files\n");
    printf("\t-y: Parse symbol table\n");
    printf("\t-L: Parse dependency dylibs\n");
    printf("\t-d: Parse code signature data (use with -c)\n");
    printf("\t-h: Print this message\n");
    printf("Examples:\n");
    printf("\t%s -i <path to FAT/MachO file> -c\n", executablePath);
    printf("\t%s -i <path to FAT/MachO file> -c -s -v\n", executablePath);
    printf("\t%s -i <path to kernelcache file> -f\n", executablePath);
    exit(-1);
}

int main(int argc, char *argv[]) {

    if (argument_exists(argc, argv, "-h")) {
        print_usage(argv[0]);
        return 0;
    }

    if (argc < 2) {
        print_usage(argv[0]);
        return -1;
    }

    char *inputPath = get_argument_value(argc, argv, "-i");
    if (!inputPath) {
        printf("Error: no input file specified.\n");
        print_usage(argv[0]);
        return -1;
    }

    if (!argument_exists(argc, argv, "-c") && !argument_exists(argc, argv, "-f") && !argument_exists(argc, argv, "-y") && !argument_exists(argc, argv, "-L")) {
        printf("Error: no action specified.\n");
        print_usage(argv[0]);
        return -1;
    }

    if (argument_exists(argc, argv, "-d")) {
        printf("Parsing code signature data.\n");
        MemoryStream *stream = file_stream_init_from_path(get_argument_value(argc, argv, "-i"), 0, FILE_STREAM_SIZE_AUTO, 0);
        if (!stream) {
            printf("Error: could not open file %s.\n", get_argument_value(argc, argv, "-i"));
            return -1;
        }
        CS_SuperBlob *superblob = malloc(memory_stream_get_size(stream));
        if (!superblob) {
            printf("Error: could not allocate memory for superblob.\n");
            return -1;
        }
        memory_stream_read(stream, 0, memory_stream_get_size(stream), superblob);
        CS_DecodedSuperBlob *decodedSuperBlob = csd_superblob_decode(superblob);
        csd_superblob_print_content(decodedSuperBlob, NULL, argument_exists(argc, argv, "-s"), false);
        free(superblob);
        memory_stream_free(stream);
        return 0;
    }

    // Initialise the FAT structure
    printf("Initialising FAT structure from %s.\n", inputPath);
    FAT *fat = fat_init_from_path(inputPath);
    if (!fat) return -1;

    for (int i = 0; i < fat->slicesCount; i++) {
        MachO *slice = fat->slices[i];
        printf("Slice %d (arch %x/%x, macho %x/%x):\n", i, slice->archDescriptor.cputype, slice->archDescriptor.cpusubtype, slice->machHeader.cputype, slice->machHeader.cpusubtype);
        if (argument_exists(argc, argv, "-c")) {
            CS_SuperBlob *superblob = macho_read_code_signature(slice);
            CS_DecodedSuperBlob *decodedSuperBlob = csd_superblob_decode(superblob);
            csd_superblob_print_content(decodedSuperBlob, slice, argument_exists(argc, argv, "-s"), argument_exists(argc, argv, "-v"));
            if (argument_exists(argc, argv, "-e")) {
                macho_extract_cs_to_file(slice, superblob);
            }
        }
        if (argument_exists(argc, argv, "-f")) {
            for (uint32_t i = 0; i < slice->segmentCount; i++) {
                MachOSegment *segment = slice->segments[i];
                printf("(0x%08llx-0x%08llx)->(0x%09llx-0x%09llx) | %s\n", segment->command.fileoff, segment->command.fileoff + segment->command.filesize, segment->command.vmaddr, segment->command.vmaddr + segment->command.vmsize, segment->command.segname);
                for (int j = 0; j < segment->command.nsects; j++) {
                    struct section_64 *section = &segment->sections[j];
                    printf("(0x%08x-0x%08llx)->(0x%09llx-0x%09llx) | %s.%s\n", section->offset, section->offset + section->size, section->addr, section->addr + section->size, section->segname, section->sectname);
                }
            }
            for (uint32_t i = 0; i < slice->filesetCount; i++) {
                MachO *filesetMachoSlice = slice->filesetMachos[i].underlyingMachO->slices[0];
                char *entry_id = slice->filesetMachos[i].entry_id;
                for (int j = 0; j < filesetMachoSlice->segmentCount; j++) {
                    MachOSegment *segment = filesetMachoSlice->segments[j];
                    printf("(0x%08llx-0x%08llx)->(0x%09llx-0x%09llx) | %s.%s\n", segment->command.fileoff, segment->command.fileoff + segment->command.filesize, segment->command.vmaddr, segment->command.vmaddr + segment->command.vmsize, entry_id, segment->command.segname);
                    for (int k = 0; k < segment->command.nsects; k++) {
                        struct section_64 *section = &segment->sections[k];
                        printf("(0x%08x-0x%08llx)->(0x%09llx-0x%09llx) | %s.%s.%s\n", section->offset, section->offset + section->size, section->addr, section->addr + section->size, entry_id, section->segname, section->sectname);
                    }
                }
            }
        }
        if (argument_exists(argc, argv, "-y")) {
            printf("Symbols:\n");
            macho_enumerate_symbols(slice, ^(const char *name, uint8_t type, uint64_t vmaddr, bool *stop) {
                const char *typeStr = NULL;
                switch(type & N_TYPE) {
                    case N_UNDF: typeStr = "N_UNDF"; break;
                    case N_ABS:  typeStr = "N_ABS"; break;
                    case N_SECT: typeStr = "N_SECT"; break;
                    case N_PBUD: typeStr = "N_PBUD"; break;
                    case N_INDR: typeStr = "N_INDR"; break;
                }
                uint64_t fileoff = 0;
                macho_translate_vmaddr_to_fileoff(slice, vmaddr, &fileoff, NULL);
                printf("%s (%s): 0x%llx / 0x%llx\n", name, typeStr, fileoff, vmaddr);
            });
        }
        if (argument_exists(argc, argv, "-L")) {
            __block bool firstDependency = true;
            macho_enumerate_dependencies(slice, ^(const char *dylibPath, uint32_t cmd, struct dylib* dylib, bool *stop){
                if (firstDependency) {
                    printf("Dependencies:\n");
                    firstDependency = false;
                }
                printf("| %s (%s, compatibility version: %u, current version: %u)\n", dylibPath, load_command_to_string(cmd), dylib->current_version, dylib->compatibility_version);
            });

            __block bool firstRpath = true;
            macho_enumerate_rpaths(slice, ^(const char *rpath, bool *stop){
                if (firstRpath) {
                    printf("Rpaths:\n");
                    firstRpath = false;
                }
                printf("| %s\n", rpath);
            });
        }
    }

    fat_free(fat);

    return 0;
    
}