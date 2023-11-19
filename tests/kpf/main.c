#include "choma/FAT.h"
#include <choma/CSBlob.h>
#include <choma/Host.h>
#include <choma/PatchFinder.h>

#include <time.h>

// 1. Direct branch (b)
// 2. Direct function call (bl)
// 3. Indirect function call (adr / adrp, add)

int main(int argc, char *argv[]) {

    if (argc == 2) {
        FAT fat;
        int r = fat_init_from_path(&fat, argv[1]);
        if (r != 0) return r;

        MachO *macho = fat_find_preferred_slice(&fat);
        if (macho) {
            uint32_t inst = 0xD503237F;
            uint32_t mask = 0xFFFFFFFF;

            clock_t t;
            t = clock();

            PFSection *kernelTextSection = macho_patchfinder_create_section(macho, "com.apple.kernel", "__TEXT_EXEC", "__text");
            macho_patchfinder_cache_section(kernelTextSection, macho);
            BytePatternMetric *metric = macho_patchfinder_create_byte_pattern_metric(kernelTextSection, &inst, &mask, sizeof(inst), BYTE_PATTERN_ALIGN_32_BIT);
            macho_patchfinder_run_metric(macho, metric, ^(uint64_t vmaddr, bool *stop) {
                printf("PACIBSP: 0x%llx\n", vmaddr);
            });

            t = clock() - t; 
            double time_taken = ((double)t)/CLOCKS_PER_SEC;
            printf("KPF finished in %lf seconds\n", time_taken);

            macho_patchfinder_section_free(kernelTextSection);
            free(metric);
        }
        
        fat_free(&fat);
    }
    

    return 0;
    
}