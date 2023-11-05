#ifndef MACHO_H
#define MACHO_H

#include <stdio.h>
#include <libkern/OSByteOrder.h>
#include <mach/mach.h>
#include <mach-o/loader.h>
#include <mach-o/fat.h>
#include <sys/stat.h>

#include "MemoryStream.h"
typedef struct MachO MachO;

// Main MachOContainer structurre
typedef struct MachOContainer
{
    MemoryStream stream;
    MachO *machos;
    uint32_t machoCount;
    int fileDescriptor;
} MachOContainer;

int macho_container_read_at_offset(MachOContainer *macho, uint64_t offset, size_t size, void *outBuf);

// Initialise a MachOContainer structure from a memory stream
int macho_container_init_from_memory_stream(MachOContainer *macho, MemoryStream *stream);

// Initialise a MachOContainer structure using the path to the file
int macho_container_init_from_path(MachOContainer *macho, const char *filePath);

// Find macho with cputype and cpusubtype in MachOContainer, returns NULL if not found
MachO *macho_container_find_macho_slice(MachOContainer *machoContainer, cpu_type_t cputype, cpu_subtype_t cpusubtype);

// Free all elements of the MachOContainer structure
void macho_container_free(MachOContainer *macho);

#endif // MACHO_H