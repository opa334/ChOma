#ifndef MACHO_H
#define MACHO_H

#include <stdio.h>
#include <libkern/OSByteOrder.h>
#include <mach/mach.h>
#include <mach-o/loader.h>
#include <mach-o/fat.h>
#include <sys/stat.h>

#include "MachOSlice.h"
#include "MemoryBuffer.h"

// Main MachO structurre
typedef struct MachO
{
    MemoryBuffer buffer;
    MachOSlice *slices;
    size_t sliceCount;
    int fileDescriptor;
} MachO;

// Initialise a MachO structure using the path to the file
int macho_init_from_path(const char *filePath, MachO *machoOut);

// Free all elements of the MachO structure
void macho_free(MachO *macho);

#endif // MACHO_H