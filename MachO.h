#ifndef MACHO_H
#define MACHO_H

#include <stdio.h>
#include <libkern/OSByteOrder.h>
#include <mach/mach.h>
#include <mach-o/loader.h>
#include <mach-o/fat.h>
#include <sys/stat.h>

#include "MachOSlice.h"

// Main MachO structurre
typedef struct MachO
{
    FILE *_file;
    size_t _fileSize;
    MachOSlice *_slices;
    size_t _sliceCount;
    int _fileDescriptor;
} MachO;

// Initialise a MachO structure using the path to the file
int initMachOWithPath(const char *filePath, MachO *machoOut);

// Read data from the MachO file at a given offset
int readMachOAtOffset(MachO *macho, uint64_t offset, size_t size, void *outputBuffer);

// Free all elements of the MachO structure
void freeMachO(MachO *macho);

#endif // MACHO_H