#include <stdbool.h>
#include <assert.h>

#include "MachO.h"
#include "MachOByteOrder.h"

int macho_read_at_offset(MachO *macho, uint64_t offset, size_t size, void *outputBuffer)
{
    fseek(macho->_file, offset, SEEK_SET);
    fread(outputBuffer, size, 1, macho->_file);
    return 0;
}

int macho_fetch_slices(MachO *macho)
{
    // Read the FAT header
    struct fat_header fatHeader;
    macho_read_at_offset(macho, 0, sizeof(fatHeader), &fatHeader);
    FAT_HEADER_APPLY_BYTE_ORDER(&fatHeader, APPLY_BIG_TO_HOST);

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

        struct fat_header newFatHeader;

        // Iterate over all slices
        for (uint32_t i = 0; i < fatHeader.nfat_arch; i++)
        {
            struct fat_arch_64 arch64 = {0};
            if (is64)
            {
                // Read the arch descriptor
                macho_read_at_offset(macho, sizeof(struct fat_header) + i * sizeof(arch64), sizeof(arch64), &arch64);
                FAT_ARCH_64_APPLY_BYTE_ORDER(&arch64, APPLY_BIG_TO_HOST);

                // Read the mach header
                struct mach_header_64 machHeader;
                macho_read_at_offset(macho, arch64.offset, sizeof(machHeader), &machHeader);
                MACH_HEADER_APPLY_BYTE_ORDER(&machHeader, APPLY_LITTLE_TO_HOST);
                
                // Check the magic against the expected values
                if (machHeader.magic == MH_MAGIC_64 || machHeader.magic == MH_MAGIC)
                {
                    // Create a MachOSlice structure and populate it
                    MachOSlice slice;
                    slice._archDescriptor = arch64;
                    slice._machHeader = machHeader;
                    slice._isValid = true;
                    slicesM[i] = slice;

                } else {
                    printf("Error: invalid magic 0x%x for mach header at offset 0x%llx.\n", machHeader.magic, arch64.offset);
                    return -1;
                }

                if (machHeader.sizeofcmds % 8 != 0) {
                    printf("Error: sizeofcmds is not a multiple of 8.\n");
                    return -1;
                }
            }
            else
            {
                // Read the FAT arch structure
                struct fat_arch arch = {0};
                macho_read_at_offset(macho, sizeof(struct fat_header) + i * sizeof(arch), sizeof(arch), &arch);
                FAT_ARCH_APPLY_BYTE_ORDER(&arch, APPLY_BIG_TO_HOST);

                bool foundInvalidSlice = false;

                if (arch.cpusubtype == 0x9) {
                    printf("Ignoring ARMv7 slice, not supported!\n");
                    foundInvalidSlice = true;
                }

                // Create the arch descriptor structure
                arch64 = (struct fat_arch_64){
                    .cputype = arch.cputype,
                    .cpusubtype = arch.cpusubtype,
                    .offset = (uint64_t)arch.offset,
                    .size = (uint64_t)arch.size,
                    .align = arch.align,
                    .reserved = 0,
                };

                // Read the mach header
                struct mach_header_64 machHeader;
                macho_read_at_offset(macho, arch64.offset, sizeof(machHeader), &machHeader);
                MACH_HEADER_APPLY_BYTE_ORDER(&machHeader, APPLY_LITTLE_TO_HOST);

                // Check the magic against the expected values
                if (machHeader.magic == MH_MAGIC_64 || machHeader.magic == MH_MAGIC)
                {
                    // Create a MachOSlice structure and populate it
                    MachOSlice slice;
                    slice._archDescriptor = arch64;
                    slice._machHeader = machHeader;
                    slice._isValid = !foundInvalidSlice;
                    slicesM[i] = slice;
                } else {
                    printf("Error: invalid magic 0x%x for mach header at offset 0x%llx.\n", machHeader.magic, arch64.offset);
                    return -1;
                }
                
                // Ensure that the sizeofcmds is a multiple of 8 (it would need padding otherwise)
                if (machHeader.sizeofcmds % 8 != 0 && slicesM[i]._isValid) {
                    printf("Error: sizeofcmds is not a multiple of 8.\n");
                    return -1;
                }
                
            }
        }

        // Add the new slices to the MachO structure
        macho->_sliceCount = fatHeader.nfat_arch;
        printf("Found %zu slices.\n", macho->_sliceCount);
        macho->_slices = slicesM;

    } else {
        
        // Read the mach header
        struct mach_header_64 machHeader;
        macho_read_at_offset(macho, 0, sizeof(machHeader), &machHeader);
        MACH_HEADER_APPLY_BYTE_ORDER(&machHeader, APPLY_LITTLE_TO_HOST);

        // Check the magic against the expected values
        if (machHeader.magic == MH_MAGIC || machHeader.magic == MH_MAGIC_64) {
            printf("Mach header found! Magic: 0x%x.\n", machHeader.magic);
            
            // Create a FAT arch structure and populate it
            struct fat_arch_64 fakeArch = {0};

            if (machHeader.cpusubtype == 0x9) {
                printf("Error: binaries compiled for ARMv7 not supported!\n");
                return -1;
            }

            fakeArch.cpusubtype = machHeader.cpusubtype;
            fakeArch.cputype = machHeader.cputype;
            fakeArch.offset = 0;
            fakeArch.size = macho->_fileSize;
            fakeArch.align = 0x4000;

            // Add the new slice to the MachO structure
            macho->_slices = malloc(sizeof(MachOSlice));
            macho->_slices[0]._archDescriptor = fakeArch;
            macho->_slices[0]._machHeader = machHeader;
            macho->_slices[0]._isValid = true;
            macho->_sliceCount = 1;
        }
    }
    return 0;
}

int macho_parse_load_commands(MachO *macho) {
    // Iterate over all slices
    for (int i = 0; i < macho->_sliceCount; i++) {
        if (!macho->_slices[i]._isValid) {
            continue;
        }

        // Sanity check the number of load commands
        MachOSlice *slice = &macho->_slices[i];
        if (slice->_machHeader.ncmds < 1 || slice->_machHeader.ncmds > 1000) {
            printf("Error: invalid number of load commands (%d).\n", slice->_machHeader.ncmds);
            return -1;
        }

        printf("Parsing %d load commands for slice %d.\n", slice->_machHeader.ncmds, i + 1);
        slice->_loadCommands = malloc(slice->_machHeader.sizeofcmds);

        // Get the offset of the first load command
        uint64_t offset = macho->_slices[i]._archDescriptor.offset + sizeof(struct mach_header_64);

        // Iterate over all load commands
        for (int j = 0; j < slice->_machHeader.ncmds; j++) {
            // Read the load command
            struct load_command loadCommand;
            macho_read_at_offset(macho, offset, sizeof(loadCommand), &loadCommand);
            LOAD_COMMAND_APPLY_BYTE_ORDER(&loadCommand, APPLY_LITTLE_TO_HOST);

            // Add the load command to the slice
            slice->_loadCommands[j] = loadCommand;
            offset += loadCommand.cmdsize;
        }
    }
    return 0;
}

void macho_free(MachO *macho)
{
    // Close the file
    fclose(macho->_file);

    // Free the slices
    if (macho->_slices != NULL) {
        free(macho->_slices);
    }

    // Free the load commands
    for (int i = 0; i < macho->_sliceCount; i++)
    {
        if (macho->_slices[i]._loadCommands != NULL) {
            free(macho->_slices[i]._loadCommands);
        }
    }
}

int macho_init_with_path(const char *filePath, MachO *machoOut)
{
    MachO macho;
    struct stat s;

    // Get the file size
    if (stat(filePath, &s) != 0)
    {
        printf("Error: could not stat %s.\n", filePath);
        return -1;
    }
    macho._fileSize = s.st_size;

    // Open the file
    macho._file = fopen(filePath, "rb");
    if (!macho._file)
    {
        printf("Error: could not open %s.\n", filePath);
        return -1;
    }

    // Get the file descriptor
    macho._fileDescriptor = fileno(macho._file);

    // Fetch the slices
    if (macho_fetch_slices(&macho) != 0) { return -1; }

    // Populate the load commands
    if (macho_parse_load_commands(&macho) != 0) { return -1; }
    printf("File size 0x%zx bytes, slice count %zu.\n", macho._fileSize, macho._sliceCount);

    // Update the output MachO structure
    *machoOut = macho;
    return 0;
}