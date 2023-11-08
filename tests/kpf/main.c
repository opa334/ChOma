#include "choma/FAT.h"
#include <choma/CSBlob.h>
#include <choma/CMSDecoding.h>
#include <choma/Host.h>
#include <choma/PatchFinder.h>

int main(int argc, char *argv[]) {

    if (argc == 2) {
        FAT fat;
        int r = fat_init_from_path(&fat, argv[1]);
        if (r != 0) return r;

        MachO *macho = fat_find_preferred_slice(&fat);
        if (macho) {
            uint32_t inst = 0xD503237F;
            uint32_t mask = 0xFFFFFFFF;

            PFSection *textSection = macho_patchfinder_create_section(macho, "com.apple.kernel|__TEXT_EXEC|__text");
            BytePatternMetric *metric = macho_patchfinder_create_byte_pattern_metric(textSection, &inst, &mask, sizeof(inst), BYTE_PATTERN_ALIGN_32_BIT);
            macho_patchfinder_run_metric(macho, metric, ^(uint64_t vmaddr, bool *stop) {
                printf("PACIZA: 0x%llx\n", vmaddr);
            });

            free(textSection);
            free(metric);
        }
        
        fat_free(&fat);
    }
    

    return 0;
    
}