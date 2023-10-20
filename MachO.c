#include <stdbool.h>
#include <assert.h>

#include "MachO.h"
#include "MachOOrder.h"

int readMachOAtOffset(MachO *macho, uint64_t offset, size_t size, void *outputBuffer)
{
    fseek(macho->_file, offset, SEEK_SET);
    fread(outputBuffer, size, 1, macho->_file);
    return 0;
}

int fetchSlices(MachO *macho)
{
    struct fat_header fatHeader;
    readMachOAtOffset(macho, 0, sizeof(fatHeader), &fatHeader);
    FAT_HEADER_APPLY_BYTE_ORDER(&fatHeader, APPLY_BIG_TO_HOST);
    printf("FAT header magic: 0x%x.\n", fatHeader.magic);
    if (fatHeader.magic == FAT_MAGIC || fatHeader.magic == FAT_MAGIC_64)
    {
        bool is64 = fatHeader.magic == FAT_MAGIC_64;
        MachOSlice *slicesM;
        if (fatHeader.nfat_arch > 5 || fatHeader.nfat_arch < 1) {
            printf("Error: invalid number of slices (%d), this likely means you are not using an iOS MachO.\n", fatHeader.nfat_arch);
            return -1;
        }
        printf("Number of slices: %d.\n", fatHeader.nfat_arch);
        slicesM = malloc(sizeof(MachOSlice) * fatHeader.nfat_arch);
        for (uint32_t i = 0; i < fatHeader.nfat_arch; i++)
        {
            printf("Parsing slice %d.\n", i + 1);
            struct fat_arch_64 arch64 = {0};
            if (is64)
            {
                readMachOAtOffset(macho, sizeof(struct fat_header) + i * sizeof(arch64), sizeof(arch64), &arch64);
                FAT_ARCH_64_APPLY_BYTE_ORDER(&arch64, APPLY_BIG_TO_HOST);

                struct mach_header_64 machHeader;
                readMachOAtOffset(macho, arch64.offset, sizeof(machHeader), &machHeader);
                MACH_HEADER_APPLY_BYTE_ORDER(&machHeader, APPLY_BIG_TO_HOST);
                if (machHeader.magic == MH_MAGIC_64 || machHeader.magic == MH_MAGIC)
                {
                    MachOSlice slice;
                    slice._archDescriptor = arch64;
                    slice._machHeader = machHeader;
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
                struct fat_arch arch = {0};
                readMachOAtOffset(macho, sizeof(struct fat_header) + i * sizeof(arch), sizeof(arch), &arch);
                FAT_ARCH_APPLY_BYTE_ORDER(&arch, APPLY_BIG_TO_HOST);
                arch64 = (struct fat_arch_64){
                    .cputype = arch.cputype,
                    .cpusubtype = arch.cpusubtype,
                    .offset = (uint64_t)arch.offset,
                    .size = (uint64_t)arch.size,
                    .align = arch.align,
                    .reserved = 0,
                };
                struct mach_header_64 machHeader;
                readMachOAtOffset(macho, arch64.offset, sizeof(machHeader), &machHeader);
                MACH_HEADER_APPLY_BYTE_ORDER(&machHeader, APPLY_LITTLE_TO_HOST);
                if (machHeader.magic == MH_MAGIC_64 || machHeader.magic == MH_MAGIC)
                {
                    MachOSlice slice;
                    slice._archDescriptor = arch64;
                    slice._machHeader = machHeader;
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
        }
        macho->_sliceCount = fatHeader.nfat_arch;
        printf("%zu slices\n", macho->_sliceCount);
        macho->_slices = slicesM;
    } else {
        struct mach_header_64 machHeader;
        readMachOAtOffset(macho, 0, sizeof(machHeader), &machHeader);
        MACH_HEADER_APPLY_BYTE_ORDER(&machHeader, APPLY_BIG_TO_HOST);
        if (machHeader.magic == MH_MAGIC || machHeader.magic == MH_MAGIC_64) {
            struct fat_arch_64 fakeArch = {0};
            fakeArch.cpusubtype = machHeader.cpusubtype;
            fakeArch.cputype = machHeader.cputype;
            fakeArch.offset = 0;
            fakeArch.size = macho->_fileSize;
            fakeArch.align = 0x4000;
            macho->_slices = malloc(sizeof(MachOSlice));
            macho->_slices[0]._archDescriptor = fakeArch;
            macho->_slices[0]._machHeader = machHeader;
            macho->_sliceCount = 1;
        }
    }
    return 0;
}

int populateMachOLoadCommands(MachO *macho) {
    for (int i = 0; i < macho->_sliceCount; i++) {
        MachOSlice *slice = &macho->_slices[i];
        if (slice->_machHeader.ncmds < 1 || slice->_machHeader.ncmds > 1000) {
            printf("Error: invalid number of load commands (%d).\n", slice->_machHeader.ncmds);
            return -1;
        }
        printf("Parsing %d load commands for slice %d.\n", slice->_machHeader.ncmds, i + 1);
        slice->_loadCommands = malloc(slice->_machHeader.sizeofcmds);
        uint64_t offset = macho->_slices[i]._archDescriptor.offset + sizeof(struct mach_header_64);
        for (int j = 0; j < slice->_machHeader.ncmds; j++) {
            struct load_command loadCommand;
            readMachOAtOffset(macho, offset, sizeof(loadCommand), &loadCommand);
            LOAD_COMMAND_APPLY_BYTE_ORDER(&loadCommand, APPLY_LITTLE_TO_HOST);
            slice->_loadCommands[j] = loadCommand;
            offset += loadCommand.cmdsize;
        }
    }
    return 0;
}

void freeMachO(MachO *macho)
{
    fclose(macho->_file);
    if (macho->_slices != NULL) {
        free(macho->_slices);
    }
    for (int i = 0; i < macho->_sliceCount; i++)
    {
        if (macho->_slices[i]._loadCommands != NULL) {
            free(macho->_slices[i]._loadCommands);
        }
    }
}

MachO initMachOWithPath(const char *filePath, int *ret)
{
    MachO macho;
    struct stat s;
    if (stat(filePath, &s) != 0)
    {
        *ret = -1;
        printf("Error: could not stat %s.\n", filePath);
        return macho;
    }
    macho._fileSize = s.st_size;
    macho._file = fopen(filePath, "rb");
    if (!macho._file)
    {
        *ret = -1;
        return macho;
    }
    macho._fileDescriptor = fileno(macho._file);
    if (fetchSlices(&macho) != 0) { *ret = -1; return macho; }
    if (populateMachOLoadCommands(&macho) != 0) { *ret = -1; return macho; }
    *ret = 0;
    return macho;
}