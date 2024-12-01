#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#include <choma/Fat.h>
#include <choma/MachO.h>
#include <choma/MemoryStream.h>
#include <choma/DyldSharedCache.h>
#include <mach-o/dyld_images.h>
#include <mach-o/dyld.h>

int main(int argc, char *argv[]) {
    if (argc < 2) return -1;

    uint64_t premapSlide = 0;

    if (argc >= 3) {
        if (!strcmp(argv[2], "--use-premap")) {
            task_dyld_info_data_t dyldInfo;
            uint32_t count = TASK_DYLD_INFO_COUNT;
            task_info(mach_task_self_, TASK_DYLD_INFO, (task_info_t)&dyldInfo, &count);
            struct dyld_all_image_infos *allImageInfos = (void *)dyldInfo.all_image_info_addr;
            premapSlide = allImageInfos->sharedCacheSlide;
        }
    }

    printf("Loading shared cache... ");

    DyldSharedCache *dsc = dsc_init_from_path_premapped(argv[1], premapSlide);
    if (!dsc) {
        printf("❌\n");
        return -2;
    }
    printf("✅\n");

    printf("Finding libdispatch... ");

    MachO *libDispatchMachO = dsc_lookup_macho_by_path(dsc, "/usr/lib/system/libdispatch.dylib", NULL);
    if (!libDispatchMachO) {
        printf("❌\n");
        return -2;
    }
    printf("✅\n");


    printf("Finding symbols... ");

    __block bool foundPrivateSymbol = false, foundPublicSymbol = false;
    macho_enumerate_symbols(libDispatchMachO, ^(const char *name, uint8_t type, uint64_t vmaddr, bool *stop) {
        if (!strcmp(name, "__dispatch_Block_copy")) {
            foundPrivateSymbol = true;
        }
        else if (!strcmp(name, "_dispatch_sync")) {
            foundPublicSymbol = true;
        }
        if (foundPrivateSymbol && foundPublicSymbol) *stop = true;
    });

    printf("(public: %s, private %s)\n", foundPublicSymbol ? "✅" : "❌", foundPrivateSymbol ? "✅" : "❌");

    printf("Parsing chained fixups... ");

    MachO *libsystemBlocksMachO = dsc_lookup_macho_by_path(dsc, "/usr/lib/system/libsystem_blocks.dylib", NULL);

    __block uint64_t blockCopySym = 0;
    if (libsystemBlocksMachO) {
        macho_enumerate_symbols(libsystemBlocksMachO, ^(const char *name, uint8_t type, uint64_t vmaddr, bool *stop){
            if (!strcmp(name, "__Block_copy")) {
                blockCopySym = vmaddr;
                *stop = true;
            }
        });
    }

    __block bool foundBlockCopyFixup = false;

    if (blockCopySym) {
        dsc_enumerate_chained_fixups(dsc, ^(DyldSharedCachePointer *pointer, bool *stop) {
            if (pointer->target == blockCopySym) {
                foundBlockCopyFixup = true;
                *stop = true;
            }
        });
    }

    printf("%s\n", foundBlockCopyFixup ? "✅" : "❌");

    dsc_free(dsc);

    return 0;
}
