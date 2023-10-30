#include <stdbool.h>
#include <assert.h>

#include "MachO.h"
#include "MachOByteOrder.h"

#include "FileStream.h"

int macho_read_at_offset(MachO *macho, uint64_t offset, size_t size, void *outBuf)
{
    return memory_stream_read(&macho->stream, offset, size, outBuf);
}

int macho_parse_slices(MachO *macho)
{
    // Read the FAT header
    struct fat_header fatHeader;
    macho_read_at_offset(macho, 0, sizeof(fatHeader), &fatHeader);
    FAT_HEADER_APPLY_BYTE_ORDER(&fatHeader, BIG_TO_HOST_APPLIER);

    // Check if the file is a FAT file
    if (fatHeader.magic == FAT_MAGIC || fatHeader.magic == FAT_MAGIC_64)
    {
        printf("FAT header found! Magic: 0x%x.\n", fatHeader.magic);
        bool is64 = fatHeader.magic == FAT_MAGIC_64;

        // Sanity check the number of slices
        if (fatHeader.nfat_arch > 5 || fatHeader.nfat_arch < 1) {
            printf("Error: invalid number of slices (%d), this likely means you are not using an iOS MachO.\n", fatHeader.nfat_arch);
            return -1;
        }

        MachOSlice *allSlices = malloc(sizeof(MachOSlice) * fatHeader.nfat_arch);
        memset(allSlices, 0, sizeof(MachOSlice) * fatHeader.nfat_arch);

        // Iterate over all slices
        for (uint32_t i = 0; i < fatHeader.nfat_arch; i++)
        {
            struct fat_arch_64 arch64 = {0};
            if (is64)
            {
                // Read the arch descriptor
                macho_read_at_offset(macho, sizeof(struct fat_header) + i * sizeof(arch64), sizeof(arch64), &arch64);
                FAT_ARCH_64_APPLY_BYTE_ORDER(&arch64, BIG_TO_HOST_APPLIER);
            }
            else
            {
                // Read the FAT arch structure
                struct fat_arch arch = {0};
                macho_read_at_offset(macho, sizeof(struct fat_header) + i * sizeof(arch), sizeof(arch), &arch);
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

            int sliceInitRet = macho_slice_init_from_fat_arch(&allSlices[i], macho, arch64);
            if (sliceInitRet != 0) return sliceInitRet;
        }

        // Add the new slices to the MachO structure
        macho->sliceCount = fatHeader.nfat_arch;
        printf("Found %zu slices.\n", macho->sliceCount);
        macho->slices = allSlices;

    } else {
        // Not FAT? Try parsing it as a single slice macho
        MachOSlice slice;
        int sliceInitRet = macho_slice_init_from_macho(&slice, macho);
        if (sliceInitRet != 0) return sliceInitRet;

        macho->slices = malloc(sizeof(MachOSlice));
        memset(macho->slices, 0, sizeof(MachOSlice));
        macho->slices[0] = slice;
        macho->sliceCount = 1;
    }
    return 0;
}

void macho_free(MachO *macho)
{
    memory_stream_free(&macho->stream);
    if (macho->slices != NULL) {
        for (int i = 0; i < macho->sliceCount; i++) {
            macho_slice_free(&macho->slices[i]);
        }
        free(macho->slices);
    }
}

int macho_init_from_path(MachO *macho, const char *filePath)
{
    memset(macho, 0, sizeof(*macho));

    if (file_stream_init_from_path(&macho->stream, filePath, 0, FILE_STREAM_SIZE_AUTO) != 0) {
        return -1;
    }

    if (macho_parse_slices(macho) != 0) {
        return -1;
    }

    size_t size = 0;
    if (file_stream_get_size(&macho->stream, &size) != 0) {
        return -1;
    }

    printf("File size 0x%zx bytes, slice count %zu.\n", size, macho->sliceCount);
    return 0;
}