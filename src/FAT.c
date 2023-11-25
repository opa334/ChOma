#include <stdbool.h>
#include <assert.h>

#include "FAT.h"
#include "MachO.h"
#include "MachOByteOrder.h"

#include "FileStream.h"
#include "MemoryStream.h"

int fat_read_at_offset(FAT *fat, uint64_t offset, size_t size, void *outBuf)
{
    return memory_stream_read(fat->stream, offset, size, outBuf);
}

MemoryStream *fat_get_stream(FAT *fat)
{
    return fat->stream;
}

int fat_parse_slices(FAT *fat)
{
    // Get size of file
    size_t fileSize = memory_stream_get_size(fat->stream);
    if (fileSize == MEMORY_STREAM_SIZE_INVALID) {
        printf("Error: Failed to parse fat slices, memory_stream_get_size returned MEMORY_STREAM_SIZE_INVALID\n");
        return -1;
    }

    // Read the FAT header
    struct fat_header fatHeader;
    fat_read_at_offset(fat, 0, sizeof(fatHeader), &fatHeader);
    FAT_HEADER_APPLY_BYTE_ORDER(&fatHeader, BIG_TO_HOST_APPLIER);

    // Check if the file is a FAT file
    if (fatHeader.magic == FAT_MAGIC || fatHeader.magic == FAT_MAGIC_64) {
        printf("FAT header found! Magic: 0x%x.\n", fatHeader.magic);
        bool is64 = fatHeader.magic == FAT_MAGIC_64;

        // Sanity check the number of machOs
        if (fatHeader.nfat_arch > 5 || fatHeader.nfat_arch < 1) {
            printf("Error: invalid number of MachO slices (%d), this likely means you are not using an iOS MachO.\n", fatHeader.nfat_arch);
            return -1;
        }

        fat->slices = malloc(sizeof(MachO*) * fatHeader.nfat_arch);
        fat->slicesCount = fatHeader.nfat_arch;

        // Iterate over all machOs
        for (uint32_t i = 0; i < fatHeader.nfat_arch; i++)  {
            struct fat_arch_64 arch64 = {0};
            if (is64) {
                // Read the arch descriptor
                fat_read_at_offset(fat, sizeof(struct fat_header) + i * sizeof(arch64), sizeof(arch64), &arch64);
                FAT_ARCH_64_APPLY_BYTE_ORDER(&arch64, BIG_TO_HOST_APPLIER);
            }
            else {
                // Read the FAT arch structure
                struct fat_arch arch = {0};
                fat_read_at_offset(fat, sizeof(struct fat_header) + i * sizeof(arch), sizeof(arch), &arch);
                FAT_ARCH_APPLY_BYTE_ORDER(&arch, BIG_TO_HOST_APPLIER);

                // Convert fat_arch to fat_arch_64
                arch64 = (struct fat_arch_64){
                    .cputype = arch.cputype,
                    .cpusubtype = arch.cpusubtype,
                    .offset = (uint64_t)arch.offset,
                    .size = (uint64_t)arch.size,
                    .align = arch.align,
                    .reserved = 0,
                };
            }

            MemoryStream *machOStream = memory_stream_softclone(fat->stream);
            int r = memory_stream_trim(machOStream, arch64.offset, fileSize - (arch64.offset + arch64.size));
            if (r == 0) {
                fat->slices[i] = macho_init(machOStream, arch64);
            }
        }
    } else {
        // Not FAT? Parse single slice

        fat->slices = malloc(sizeof(MachO));
        fat->slicesCount = 1;

        MemoryStream *machOStream = memory_stream_softclone(fat->stream);

        struct mach_header_64 machHeader;
        memory_stream_read(machOStream, 0, sizeof(machHeader), &machHeader);

        struct fat_arch_64 singleArch = {0};
        singleArch.cpusubtype = machHeader.cpusubtype;
        singleArch.cputype = machHeader.cputype;
        singleArch.offset = 0;
        singleArch.size = fileSize;
        singleArch.align = 0x4000;

        fat->slices[0] = macho_init(machOStream, singleArch);
    }
    printf("Found %u MachO slices.\n", fat->slicesCount);
    return 0;
}

MachO *fat_find_slice(FAT *fat, cpu_type_t cputype, cpu_subtype_t cpusubtype)
{
    for (uint32_t i = 0; i < fat->slicesCount; i++) {
        MachO *curMacho = fat->slices[i];
        if (curMacho) {
            if (curMacho->machHeader.cputype == cputype && curMacho->machHeader.cpusubtype == cpusubtype) {
                return curMacho;
            }
        }
    }
    return NULL;
}

void fat_free(FAT *fat)
{
    if (fat->slices != NULL) {
        for (int i = 0; i < fat->slicesCount; i++) {
            if (fat->slices[i]) {
                macho_free(fat->slices[i]);
            }
        }
        free(fat->slices);
    }
    memory_stream_free(fat->stream);
    free(fat);
}

FAT *fat_init_from_memory_stream(MemoryStream *stream)
{
    FAT *fat = malloc(sizeof(FAT));
    if (!fat) return NULL;
    memset(fat, 0, sizeof(FAT));

    fat->stream = stream;

    if (fat_parse_slices(fat) != 0) goto fail;

    size_t size = memory_stream_get_size(fat->stream);
    printf("File size 0x%zx bytes, MachO slice count %u.\n", size, fat->slicesCount);
    return fat;

fail:
    fat_free(fat);
    return NULL;
}

FAT *fat_init_from_path(const char *filePath)
{
    MemoryStream *stream = file_stream_init_from_path(filePath, 0, FILE_STREAM_SIZE_AUTO, 0);
    if (stream) {
        return fat_init_from_memory_stream(stream);
    }
    return NULL;
}

// this is not supported for the time being, as we would need to dynamically update the arch info when a macho is expanded (pain)
/*FAT *fat_init_from_path_for_writing(const char *filePath)
{
    MemoryStream *stream = file_stream_init_from_path(filePath, 0, FILE_STREAM_SIZE_AUTO, FILE_STREAM_FLAG_WRITABLE | FILE_STREAM_FLAG_AUTO_EXPAND);
    if (stream) {
        return fat_init_from_memory_stream(stream);
    }
    return NULL;
}*/