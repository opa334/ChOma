#include "CSBlob.h"
#include "CMSDecoding.h"

int main(int argc, char *argv[]) {

    // Sanity check passed arguments
    if (argc != 2) {
        printf("Usage: %s <path to MachO file>\n", argv[0]);
        return 1;
    }

    // Initialise the MachO structure
    printf("Initialising MachO structure from %s.\n", argv[1]);
    MachO macho;
    if (macho_init_from_path(&macho, argv[1]) != 0) { return -1; }

    // Parse the code signature blob
    // printf("Parsing CMS superblobs from MachO.\n");
    // for (int sliceIndex = 0; sliceIndex < macho.sliceCount; sliceIndex++) {
    //     if (macho_parse_superblob(&macho, NULL, sliceIndex) != 0) {
    //         if (macho.sliceCount > 1) {
    //             if (macho.slices[sliceIndex].isSupported) {
    //                 printf("Slice %d does not contain a code signature.\n", sliceIndex + 1);
    //             }
    //         } else {
    //             printf("Binary does not contain a code signature.\n");
    //             return -1; 
    //         }
    //     }
    // }

    CS_SuperBlob superblob;
    macho_slice_parse_superblob(&macho.slices[0], &superblob);

    /*macho_slice_enumerate_load_commands(&macho.slices[0], ^(struct load_command loadCommand, uint32_t offset, void *cmd, bool *stop) {
        if (loadCommand.cmd == LC_FILESET_ENTRY) {
            struct fileset_entry_command filesetCommand = *((struct fileset_entry_command *)cmd);
            FILESET_ENTRY_COMMAND_APPLY_BYTE_ORDER(&filesetCommand, LITTLE_TO_HOST_APPLIER);
            printf("0x%08llx->0x%llx | %s\n", filesetCommand.fileoff, filesetCommand.vmaddr, (char *)(((uint8_t*)cmd) + filesetCommand.entry_id.offset));
        }
    });*/
    

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