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

int main(int argc, char *argv[]) {

    arg_t args[] = {
        // Name, short option, long option, description, examples, type, value
        {"Help", "-h", "--help", "Print this message", false},
        {"Parse CMS blob", "-c", "--cms", "Parse the CMS blob of a MachO", false},
        {"Print code slots", "-s", "--code-slots", "Print all page hash code slots in a CMS blob", false},
        {"Parse MH_FILESET", "-f", "--mh-fileset", "Parse an MH_FILESET MachO and output it's sub-files", false}
    };

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
    if (argc < 2 || args[0].boolVal || unknownArgumentUsed) {
        printf("Usage: %s [options] <path to MachO file>\n", argv[0]);
        printf("Options:\n");
        for (int i = 0; i < sizeof(args) / sizeof(arg_t); i++) {
            printf("\t%s, %s - %s\n", args[i].shortOpt, args[i].longOpt, args[i].description);
        }
        return -1;
    }

    // Make sure the last argument is the path to the MachO file
    struct stat fileStat;
    if (stat(argv[argc - 1], &fileStat) != 0 && argc > 1) {
        printf("Please ensure the last argument is the path to a MachO file.\n");
        return -1;
    }

    // Initialise the MachO structure
    printf("Initialising MachO structure from %s.\n", argv[argc - 1]);
    MachO macho;
    if (macho_init_from_path(&macho, argv[argc - 1]) != 0) { return -1; }

    if (args[1].boolVal) {
        CS_SuperBlob superblob;
        for (int sliceCount = 0; sliceCount < macho.sliceCount; sliceCount++) {
            macho_slice_parse_superblob(&macho.slices[sliceCount], &superblob, args[2].boolVal);
        }
    }

    if (args[3].boolVal) {
        macho_slice_enumerate_load_commands(&macho.slices[0], ^(struct load_command loadCommand, uint32_t offset, void *cmd, bool *stop) {
            if (loadCommand.cmd == LC_FILESET_ENTRY) {
                struct fileset_entry_command filesetCommand = *((struct fileset_entry_command *)cmd);
                FILESET_ENTRY_COMMAND_APPLY_BYTE_ORDER(&filesetCommand, LITTLE_TO_HOST_APPLIER);
                printf("0x%08llx->0x%llx | %s\n", filesetCommand.fileoff, filesetCommand.vmaddr, (char *)(((uint8_t*)cmd) + filesetCommand.entry_id.offset));
            }
        });
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
    macho_free(&macho);

    return 0;
    
}