#ifndef MACHO_LOAD_COMMAND_H
#define MACHO_LOAD_COMMAND_H

#include <mach-o/loader.h>

// This is relevant for TrollStore

struct lc_code_signature {
    uint32_t cmd;		/* LC_CODE_SIGNATURE */
    uint32_t cmdsize;		/* sizeof(struct linkedit_data_command) */
    uint32_t dataoff;		/* file offset of data in __LINKEDIT segment */
    uint32_t datasize;		/* file size of data in __LINKEDIT segment  */
};

// Convert load command to load command name
char *load_command_to_string(int loadCommand);

#endif // MACHO_LOAD_COMMAND_H