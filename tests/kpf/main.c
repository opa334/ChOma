#include "choma/FAT.h"
#include <choma/CSBlob.h>
#include <choma/Host.h>
#include <choma/PatchFinder.h>
#include <choma/BufferedStream.h>

#include <time.h>
#include <sys/mman.h>

// 1. Direct branch (b)
// 2. Direct function call (bl)
// 3. Indirect function call (adr / adrp, add)

int main(int argc, char *argv[]) {
    if (argc != 2) return -1;

    int fd = open(argv[1], O_RDONLY);
    if (fd < 0) return -1;

    struct stat stat_buf;
    fstat(fd, &stat_buf);

    void *mapping = mmap(NULL, stat_buf.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (mapping == MAP_FAILED) return -1;

    MemoryStream *stream = buffered_stream_init_from_buffer(mapping, stat_buf.st_size);
    if (!stream) return -1;

    FAT *fat = fat_init_from_memory_stream(stream);
    if (!fat) return -1;

    /*FAT *fat = fat_init_from_path(argv[1]);
    printf("fat: %p\n", fat);
    if (!fat) return -1;*/

    MachO *macho = fat_find_preferred_slice(fat);
    printf("preferred slice: %p\n", macho);
    if (macho) {
        uint32_t inst = 0xD503237F;
        uint32_t mask = 0xFFFFFFFF;

        clock_t t;
        t = clock();

        PFSection *kernelTextSection = macho_patchfinder_create_section(macho, "com.apple.kernel", "__TEXT_EXEC", "__text");
        macho_patchfinder_cache_section(kernelTextSection, macho);
        printf("kernelTextSection: %p\n", kernelTextSection);
        BytePatternMetric *metric = macho_patchfinder_create_byte_pattern_metric(kernelTextSection, &inst, &mask, sizeof(inst), BYTE_PATTERN_ALIGN_32_BIT);
        macho_patchfinder_run_metric(macho, metric, ^(uint64_t vmaddr, bool *stop) {
            //printf("PACIBSP: 0x%llx\n", vmaddr);
        });

        t = clock() - t; 
        double time_taken = ((double)t)/CLOCKS_PER_SEC;
        printf("KPF finished in %lf seconds\n", time_taken);

        macho_patchfinder_section_free(kernelTextSection);
        free(metric);
    }
    
    fat_free(fat);
    return 0;
    
}