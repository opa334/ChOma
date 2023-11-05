#include <stdbool.h>
#include <assert.h>

#include "FAT.h"
#include "MachO.h"
#include "MachOByteOrder.h"

#include "FileStream.h"

int fat_read_at_offset(FAT *fat, uint64_t offset, size_t size, void *outBuf)
{
    return memory_stream_read(&fat->stream, offset, size, outBuf);
}

int fat_parse_slices(FAT *fat)
{
    // Read the FAT header
    struct fat_header fatHeader;
    fat_read_at_offset(fat, 0, sizeof(fatHeader), &fatHeader);
    FAT_HEADER_APPLY_BYTE_ORDER(&fatHeader, BIG_TO_HOST_APPLIER);

    // Check if the file is a FAT file
    if (fatHeader.magic == FAT_MAGIC || fatHeader.magic == FAT_MAGIC_64)
    {
        printf("FAT header found! Magic: 0x%x.\n", fatHeader.magic);
        bool is64 = fatHeader.magic == FAT_MAGIC_64;

        // Sanity check the number of machOs
        if (fatHeader.nfat_arch > 5 || fatHeader.nfat_arch < 1) {
            printf("Error: invalid number of MachO slices (%d), this likely means you are not using an iOS MachO.\n", fatHeader.nfat_arch);
            return -1;
        }

        MachO *allSlices = malloc(sizeof(MachO) * fatHeader.nfat_arch);
        memset(allSlices, 0, sizeof(MachO) * fatHeader.nfat_arch);

        // Iterate over all machOs
        for (uint32_t i = 0; i < fatHeader.nfat_arch; i++)
        {
            struct fat_arch_64 arch64 = {0};
            if (is64)
            {
                // Read the arch descriptor
                fat_read_at_offset(fat, sizeof(struct fat_header) + i * sizeof(arch64), sizeof(arch64), &arch64);
                FAT_ARCH_64_APPLY_BYTE_ORDER(&arch64, BIG_TO_HOST_APPLIER);
            }
            else
            {
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

            int machoInitRet = macho_init_from_fat_arch(&allSlices[i], fat, arch64);
            if (machoInitRet != 0) return machoInitRet;
        }

        // Add the machos to the FAT structure
        fat->slicesCount = fatHeader.nfat_arch;
        fat->slices = allSlices;

        printf("Found %u MachO slices.\n", fat->slicesCount);
    } else {
        // Not FAT? Try parsing it as a single slice MachO
        MachO macho;
        int machoInitRet = macho_init_from_single_slice_fat(&macho, fat);
        if (machoInitRet != 0) return machoInitRet;

        fat->slices = malloc(sizeof(MachO));
        memset(fat->slices, 0, sizeof(MachO));
        fat->slices[0] = macho;
        fat->slicesCount = 1;
    }
    return 0;
}

MachO *fat_find_slice(FAT *fat, cpu_type_t cputype, cpu_subtype_t cpusubtype)
{
    for (uint32_t i = 0; i < fat->slicesCount; i++) {
        MachO *curMacho = &fat->slices[i];
        if (curMacho->machHeader.cputype == cputype && curMacho->machHeader.cpusubtype == cpusubtype) {
            return curMacho;
        }
    }
    return NULL;
}

void fat_free(FAT *fat)
{
    memory_stream_free(&fat->stream);
    if (fat->slices != NULL) {
        for (int i = 0; i < fat->slicesCount; i++) {
            macho_free(&fat->slices[i]);
        }
        free(fat->slices);
    }
}

int fat_init_from_memory_stream(FAT *fat, MemoryStream *stream)
{
    fat->stream = *stream;

    if (fat_parse_slices(fat) != 0) {
        return -1;
    }

    size_t size = 0;
    if (file_stream_get_size(&fat->stream, &size) != 0) {
        return -1;
    }

    printf("File size 0x%zx bytes, MachO slice count %u.\n", size, fat->slicesCount);
    return 0;
}

int fat_init_from_path(FAT *fat, const char *filePath)
{
    memset(fat, 0, sizeof(*fat));

    MemoryStream stream;
    if (file_stream_init_from_path(&stream, filePath, 0, FILE_STREAM_SIZE_AUTO) != 0) return -1;

    return fat_init_from_memory_stream(fat, &stream);
}