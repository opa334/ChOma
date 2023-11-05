#include "CSBlob.h"
#include "CMSDecoding.h"

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
    {"Parse CMS blob", "-c", "--cms", "Parse the CMS blob of a MachOContainer", false},
    {"Print code slots", "-s", "--code-slots", "Print all page hash code slots in a CMS blob", false},
    {"Verify code slots", "-v", "--verify-hashes", "Verify that the CodeDirectory hashes are correct", false},
    {"Parse MH_FILESET", "-f", "--mh-fileset", "Parse an MH_FILESET MachOContainer and output it's sub-files", false}
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
        printf("Usage: %s [options] <path to MachOContainer file>\n", argv[0]);
        printf("Options:\n");
        for (int i = 0; i < sizeof(args) / sizeof(arg_t); i++) {
            printf("\t%s, %s - %s\n", args[i].shortOpt, args[i].longOpt, args[i].description);
        }
        return -1;
    }

    // Make sure the last argument is the path to the MachOContainer file
    struct stat fileStat;
    if (stat(argv[argc - 1], &fileStat) != 0 && argc > 1) {
        printf("Please ensure the last argument is the path to a MachOContainer file.\n");
        return -1;
    }

    // Initialise the MachOContainer structure
    printf("Initialising MachOContainer structure from %s.\n", argv[argc - 1]);
    MachOContainer macho;
    if (macho_container_init_from_path(&macho, argv[argc - 1]) != 0) { return -1; }

    if (getArgumentBool("-c")) {
        CS_SuperBlob superblob;
        for (int sliceCount = 0; sliceCount < macho.sliceCount; sliceCount++) {
            macho_parse_superblob(&macho.slices[sliceCount], &superblob, getArgumentBool("-s"), getArgumentBool("-v"));
        }
    }

    if (getArgumentBool("-f")) {
        MachO *slice = &macho.slices[0];
        for (uint32_t i = 0; i < slice->segmentCount; i++) {
            MachOSegment *segment = slice->segments[i];
            printf("(0x%08llx-0x%08llx)->(0x%09llx-0x%09llx) | %s\n", segment->command.fileoff, segment->command.fileoff + segment->command.filesize, segment->command.vmaddr, segment->command.vmaddr + segment->command.vmsize, segment->command.segname);
            for (int j = 0; j < segment->command.nsects; j++) {
                struct section_64 *section = &segment->sections[j];
                printf("(0x%08x-0x%08llx)->(0x%09llx-0x%09llx) | %s.%s\n", section->offset, section->offset + section->size, section->addr, section->addr + section->size, section->segname, section->sectname);
            }
        }
        for (uint32_t i = 0; i < slice->filesetCount; i++) {
            MachO *filesetMachoSlice = &slice->filesetMachos[i].underlyingMachO.slices[0];
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
    

    // Extract CMS data to file
    // printf("Extracting CMS data from first slice to file.\n");
    // CS_SuperBlob superblob;
    // if (macho_parse_superblob(&macho, &superblob, 0) == 0) {
    //     macho_extract_cms_to_file(&macho, &superblob, 0);

    //     // TODO: Extract this from the CMS data
    //     FILE *cmsDERFile = fopen("CMS-DER", "rb");
    //     fseek(cmsDERFile, 0, SEEK_END);
    //     size_t cmsDERLength = ftell(cmsDERFile);
    //     fseek(cmsDERFile, 0, SEEK_SET);
    //     uint8_t *cmsDERData = malloc(cmsDERLength);
    //     memset(cmsDERData, 0, cmsDERLength);
    //     fread(cmsDERData, cmsDERLength, 1, cmsDERFile);
    //     fclose(cmsDERFile);

    //     cms_data_decode(cmsDERData, cmsDERLength);

    //     // Clean up
    //     free(cmsDERData);
    // } else {
    //     if (macho.sliceCount > 1) {
    //         if (macho.slices[0].isSupported) {
    //             printf("First slice does not contain a code signature.\n");
    //         } else {
    //             printf("Could not parse CMS data for ARMv7 slice.\n");
    //         }
    //     } else {
    //         printf("Binary does not contain a code signature.\n");
    //         return -1; 
    //     }
    // }
    macho_container_free(&macho);

    return 0;
    
}