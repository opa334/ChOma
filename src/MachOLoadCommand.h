#ifndef MACHO_LOAD_COMMAND_H
#define MACHO_LOAD_COMMAND_H

#include <mach-o/loader.h>

// This is relevant for TrollStore

// Convert load command to load command name
char *load_command_to_string(int loadCommand);

#endif // MACHO_LOAD_COMMAND_H