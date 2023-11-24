#include "choma/FileStream.h"
#include <choma/CSBlob.h>
#include <choma/Host.h>

typedef enum
{
    FLAG_BOOL,
    FLAG_INT,
    FLAG_STRING
} flag_type_t;
typedef struct
{
    char *name;
    char *shortOpt;
    char *longOpt;
    char *description;
    bool boolVal;
} arg_t;

arg_t args[] = {
    // Name, short option, long option, description, value
    {"Help", "-h", "--help", "Print this message", false},
    {"Parse CMS blob", "-c", "--cms", "Parse the CMS superblob blob of a MachO", false},
    {"Extract Code Signature", "-e", "--extract", "Extract the Code Signature from a MachO", false},
    {"Print code slots", "-s", "--code-slots", "Print all page hash code slots in a CodeDirectory blob", false},
    {"Verify code slots", "-v", "--verify-hashes", "Verify that the CodeDirectory hashes are correct", false},
    {"Parse MH_FILESET", "-f", "--mh-fileset", "Parse an MH_FILESET MachO and output it's sub-files", false}
};

bool getArgumentBool(char *shortOpt) {
    for (int i = 0; i < sizeof(args) / sizeof(arg_t); i++) {
        if (strcmp(shortOpt, args[i].shortOpt) == 0) {
            return args[i].boolVal;
        }
    }
    return false;
}

int main(int argc, char *argv[]) {

    // Parse arguments
    bool unknownArgumentUsed = false;
    for (int i = 1; i < argc; i++) {
        bool unknownArg = true;
        for (int j = 0; j < sizeof(args) / sizeof(arg_t); j++) {
            if (strcmp(argv[i], args[j].shortOpt) == 0 || strcmp(argv[i], args[j].longOpt) == 0) {
                args[j].boolVal = true;
                unknownArg = false;
                break;
            }
        }
        if (unknownArg && (i != argc - 1)) {
            printf("Unknown argument: %s\n", argv[i]);
            unknownArgumentUsed = true;
        }
    }

    // Sanity check passed arguments
    if (argc < 2 || getArgumentBool("-h") || unknownArgumentUsed) {
        printf("Usage: %s [options] <path to FAT/MachO file>\n", argv[0]);
        printf("Options:\n");
        for (int i = 0; i < sizeof(args) / sizeof(arg_t); i++) {
            printf("\t%s, %s - %s\n", args[i].shortOpt, args[i].longOpt, args[i].description);
        }
        return -1;
    }

    // Make sure the last argument is the path to the FAT/MachO file
    struct stat fileStat;
    if (stat(argv[argc - 1], &fileStat) != 0 && argc > 1) {
        printf("Please ensure the last argument is the path to a FAT/MachO file.\n");
        return -1;
    }

    // Initialise the FAT structure
    printf("Initialising FAT structure from %s.\n", argv[argc - 1]);
    FAT *fat = fat_init_from_path(argv[argc - 1]);
    if (!fat) return -1;

    MachO *macho = fat_find_preferred_slice(fat);
    if (!macho) return -1;

    if (getArgumentBool("-c")) {
        for (int i = 0; i < fat->slicesCount; i++) {
            CS_SuperBlob *superblob = macho_read_code_signature(macho);
            MachO *slice = fat->slices[i];
            CS_DecodedSuperBlob *decodedSuperBlob = superblob_decode(superblob);
            decodedsuperblob_parse_blobs(macho, decodedSuperBlob, getArgumentBool("-s"), getArgumentBool("-v"));
            if (getArgumentBool("-e")) {
                macho_extract_cs_to_file(slice, superblob);
            }
        }
    }

    if (getArgumentBool("-f")) {
        for (uint32_t i = 0; i < macho->segmentCount; i++) {
            MachOSegment *segment = macho->segments[i];
            printf("(0x%08llx-0x%08llx)->(0x%09llx-0x%09llx) | %s\n", segment->command.fileoff, segment->command.fileoff + segment->command.filesize, segment->command.vmaddr, segment->command.vmaddr + segment->command.vmsize, segment->command.segname);
            for (int j = 0; j < segment->command.nsects; j++) {
                struct section_64 *section = &segment->sections[j];
                printf("(0x%08x-0x%08llx)->(0x%09llx-0x%09llx) | %s.%s\n", section->offset, section->offset + section->size, section->addr, section->addr + section->size, section->segname, section->sectname);
            }
        }
        for (uint32_t i = 0; i < macho->filesetCount; i++) {
            MachO *filesetMachoSlice = macho->filesetMachos[i].underlyingMachO->slices[0];
            char *entry_id = macho->filesetMachos[i].entry_id;
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

    fat_free(fat);

    return 0;
    
}