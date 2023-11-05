#ifndef MACHO_H
#define MACHO_H

#include <stdio.h>
#include <libkern/OSByteOrder.h>
#include <mach/mach.h>
#include <mach-o/loader.h>
#include <mach-o/fat.h>
#include <sys/stat.h>

#include "MachOSlice.h"
#include "MemoryStream.h"

// Main MachO structurre
typedef struct MachO
{
    MemoryStream stream;
    MachOSlice *slices;
    size_t sliceCount;
    int fileDescriptor;
} MachO;

typedef struct MachOSegment MachOSegment;
typedef struct MachOSegment
{
    struct segment_command_64 command;
    struct section_64 sections[];
} __attribute__((__packed__)) MachOSegment;

typedef struct FilesetMachO {
    char *entry_id;
    uint64_t vmaddr;
    uint64_t fileoff;
	MachO underlyingMachO;
} FilesetMachO;

int macho_read_at_offset(MachO *macho, uint64_t offset, size_t size, void *outBuf);

// Initialise a MachO structure from a memory stream
int macho_init_from_memory_stream(MachO *macho, MemoryStream *stream);

// Initialise a MachO structure using the path to the file
int macho_init_from_path(MachO *macho, const char *filePath);

// Free all elements of the MachO structure
void macho_free(MachO *macho);

#endif // MACHO_H