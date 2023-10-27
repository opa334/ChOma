#include <stdbool.h>
#include <assert.h>

#include "MachO.h"
#include "MachOByteOrder.h"

int macho_parse_slices(MachO *macho)
{
    // Read the FAT header
    struct fat_header fatHeader;
    memory_buffer_read(&macho->buffer, 0, sizeof(fatHeader), &fatHeader);
    FAT_HEADER_APPLY_BYTE_ORDER(&fatHeader, BIG_TO_HOST_APPLIER);

    // Check if the file is a FAT file
    if (fatHeader.magic == FAT_MAGIC || fatHeader.magic == FAT_MAGIC_64)
    {
        printf("FAT header found! Magic: 0x%x.\n", fatHeader.magic);
        bool is64 = fatHeader.magic == FAT_MAGIC_64;
        MachOSlice *slicesM;

        // Sanity check the number of slices
        if (fatHeader.nfat_arch > 5 || fatHeader.nfat_arch < 1) {
            printf("Error: invalid number of slices (%d), this likely means you are not using an iOS MachO.\n", fatHeader.nfat_arch);
            return -1;
        }

        slicesM = malloc(sizeof(MachOSlice) * fatHeader.nfat_arch);
        memset(slicesM, 0, sizeof(MachOSlice) * fatHeader.nfat_arch);

        // Iterate over all slices
        for (uint32_t i = 0; i < fatHeader.nfat_arch; i++)
        {
            struct fat_arch_64 arch64 = {0};
            if (is64)
            {
                // Read the arch descriptor
                memory_buffer_read(&macho->buffer, sizeof(struct fat_header) + i * sizeof(arch64), sizeof(arch64), &arch64);
                FAT_ARCH_64_APPLY_BYTE_ORDER(&arch64, BIG_TO_HOST_APPLIER);
            }
            else
            {
                // Read the FAT arch structure
                struct fat_arch arch = {0};
                memory_buffer_read(&macho->buffer, sizeof(struct fat_header) + i * sizeof(arch), sizeof(arch), &arch);
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

            int sliceInitRet = macho_slice_init_from_fat_arch(macho, arch64, &slicesM[i]);
            if (sliceInitRet != 0) return sliceInitRet;
        }

        // Add the new slices to the MachO structure
        macho->sliceCount = fatHeader.nfat_arch;
        printf("Found %zu slices.\n", macho->sliceCount);
        macho->slices = slicesM;

    } else {
        // Not FAT? Try parsing it as a single slice macho
        MachOSlice slice;
        int sliceInitRet = macho_slice_init_from_macho(macho, &slice);
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
    // Free the MemoryBuffer object
    memory_buffer_free(&macho->buffer);

    // Free the slices
    if (macho->slices != NULL) {
        for (int i = 0; i < macho->sliceCount; i++) {
            macho_slice_free(&macho->slices[i]);
        }
        free(macho->slices);
    }
}

int macho_init_from_path(const char *filePath, MachO *machoOut)
{
    memset(machoOut, 0, sizeof(*machoOut));

    if (memory_buffer_init_from_path(filePath, 0, MEMORY_BUFFER_SIZE_AUTO, &machoOut->buffer) != 0) {
        memory_buffer_free(&machoOut->buffer);
    }

    // Parse the slices
    if (macho_parse_slices(machoOut) != 0) { return -1; }

    printf("File size 0x%zx bytes, slice count %zu.\n", machoOut->buffer.bufferSize, machoOut->sliceCount);

    return 0;
}