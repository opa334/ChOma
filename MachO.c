#include <stdbool.h>
#include <assert.h>

#include "MachO.h"
#include "MachOByteOrder.h"

int macho_read_at_offset(MachO *macho, uint64_t offset, size_t size, void *outputBuffer)
{
    fseek(macho->file, offset, SEEK_SET);
    fread(outputBuffer, size, 1, macho->file);
    return 0;
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
        MachOSlice *slicesM;

        // Sanity check the number of slices
        if (fatHeader.nfat_arch > 5 || fatHeader.nfat_arch < 1) {
            printf("Error: invalid number of slices (%d), this likely means you are not using an iOS MachO.\n", fatHeader.nfat_arch);
            return -1;
        }

        slicesM = malloc(sizeof(MachOSlice) * fatHeader.nfat_arch);

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
        int sliceInitRet = macho_slice_from_macho(macho, &slice);
        if (sliceInitRet != 0) return sliceInitRet;

        macho->slices = malloc(sizeof(MachOSlice));
        macho->slices[0] = slice;
        macho->sliceCount = 1;
    }
    return 0;
}

void macho_free(MachO *macho)
{
    // Close the file
    fclose(macho->file);

    // Free the slices
    if (macho->slices != NULL) {
        free(macho->slices);
    }

    // Free the load commands
    for (int i = 0; i < macho->sliceCount; i++)
    {
        if (macho->slices[i].loadCommands != NULL) {
            free(macho->slices[i].loadCommands);
        }
    }
}

int macho_init_from_path(const char *filePath, MachO *machoOut)
{
    MachO macho;
    struct stat s;

    // Get the file size
    if (stat(filePath, &s) != 0)
    {
        printf("Error: could not stat %s.\n", filePath);
        return -1;
    }
    macho.fileSize = s.st_size;

    // Open the file
    macho.file = fopen(filePath, "rb");
    if (!macho.file)
    {
        printf("Error: could not open %s.\n", filePath);
        return -1;
    }

    // Get the file descriptor
    macho.fileDescriptor = fileno(macho.file);

    // Parse the slices
    if (macho_parse_slices(&macho) != 0) { return -1; }

    printf("File size 0x%zx bytes, slice count %zu.\n", macho.fileSize, macho.sliceCount);

    // Update the output MachO structure
    *machoOut = macho;
    return 0;
}