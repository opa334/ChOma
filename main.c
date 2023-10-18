#include <stdio.h>

#include "MachO.h"
#include "MachOOrder.h"
#include "CSBlob.h"
#include "MachOLoadCommand.h"

int main(void) {
    int ret;
    MachO macho = initMachOWithPath("test", &ret);
    if (ret != 0) {
        printf("Error: %d\n", ret);
        return 1;
    }
    printf("File size: 0x%zx bytes\n", macho._fileSize);
    printf("File descriptor: %d\n", macho._fileDescriptor);
    printf("Slice count: %zu\n", macho._sliceCount);
    for (int i = 0; i < macho._sliceCount; i++) {
        printf("Slice %d mach header magic: 0x%x\n", i + 1, macho._slices[i]._machHeader.magic);
        // printf("Slice %d mach header cputype: 0x%x\n", i + 1, macho._slices[i]._machHeader.cputype);
        // printf("Slice %d mach header cpusubtype: %d\n", i + 1, macho._slices[i]._machHeader.cpusubtype);
        // printf("Slice %d mach header filetype: %d\n", i + 1, macho._slices[i]._machHeader.filetype);
        // printf("Slice %d mach header ncmds: %d\n", i + 1, macho._slices[i]._machHeader.ncmds);
        // size_t currentOffset = 0;
        for (int j = 0; j < macho._slices[i]._machHeader.ncmds; j++) {
            struct load_command loadCommand = macho._slices[i]._loadCommands[j];
            // struct load_command loadCommand = macho._slices[i]._loadCommands[j];
            // LOAD_COMMAND_APPLY_BYTE_ORDER(&loadCommand, APPLY_LITTLE_TO_HOST);
            // if (loadCommand.cmd == LC_CODE_SIGNATURE) {
            //     struct lc_code_signature *codeSignature = malloc(sizeof(struct lc_code_signature));
            //     readMachOAtOffset(&macho, sizeof(struct mach_header_64) + (currentOffset), sizeof(struct lc_code_signature), codeSignature);
            //     LC_CODE_SIGNATURE_APPLY_BYTE_ORDER(codeSignature, APPLY_LITTLE_TO_HOST);
            //     printf("Found code signature load command at load command %d\n", j + 1);
            //     printf("Code signature data offset: 0x%x\n", codeSignature->dataoff);
            //     printf("Code signature data size: 0x%x\n", codeSignature->datasize);
            //     uint32_t magic;
            //     CS_SuperBlob *superblob = malloc(sizeof(CS_SuperBlob));
            //     readMachOAtOffset(&macho, codeSignature->dataoff + __offsetof(CS_SuperBlob, magic), sizeof(uint32_t), &magic);
            //     printf("Magic at offset: 0x%x\n", OSSwapBigToHostInt32(magic));
            // }
            // currentOffset += loadCommand.cmdsize;
            printf("Load command %d: %s\n", j + 1, loadCommandToName(loadCommand.cmd));
            if (strcmp(loadCommandToName(loadCommand.cmd), "LC_UNKNOWN") == 0) {
                printf("Unknown load command at load command %d, 0x%x\n", j + 1, loadCommand.cmd);
            }
        }
    }
    freeMachO(&macho);
    return 0;
}