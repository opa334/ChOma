#ifndef MACHO_H
#define MACHO_H

#include <stdio.h>
#include <libkern/OSByteOrder.h>
#include <mach/mach.h>
#include <mach-o/loader.h>
#include <mach-o/fat.h>
#include <sys/stat.h>

#include "MachO.h"
#include "MemoryStream.h"

// Main MachOContainer structurre
typedef struct MachOContainer
{
    MemoryStream stream;
    MachO *machos;
    uint32_t machoCount;
    int fileDescriptor;
} MachOContainer;

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
	MachOContainer underlyingMachO;
} FilesetMachO;

int macho_container_read_at_offset(MachOContainer *macho, uint64_t offset, size_t size, void *outBuf);

// Initialise a MachOContainer structure from a memory stream
int macho_container_init_from_memory_stream(MachOContainer *macho, MemoryStream *stream);

// Initialise a MachOContainer structure using the path to the file
int macho_container_init_from_path(MachOContainer *macho, const char *filePath);

// Free all elements of the MachOContainer structure
void macho_container_free(MachOContainer *macho);

#endif // MACHO_H