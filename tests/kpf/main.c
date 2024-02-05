#include "choma/FAT.h"
#include <choma/CSBlob.h>
#include <choma/Host.h>
#include <choma/BufferedStream.h>
#include <choma/PatchFinder.h>
#include <choma/PatchFinder_arm64.h>
#include <choma/arm64.h>

#include <time.h>
#include <sys/mman.h>

int main(int argc, char *argv[]) {
    if (argc != 2) return -1;

    int fd = open(argv[1], O_RDONLY);
    if (fd < 0) return -1;

    struct stat stat_buf;
    fstat(fd, &stat_buf);

    void *mapping = mmap(NULL, stat_buf.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (mapping == MAP_FAILED) return -1;

    MemoryStream *stream = buffered_stream_init_from_buffer(mapping, stat_buf.st_size, 0);
    if (!stream) return -1;

    FAT *fat = fat_init_from_memory_stream(stream);
    if (!fat) return -1;

    //FAT *fat = fat_init_from_path(argv[1]);
    //printf("fat: %p\n", fat);
    //if (!fat) return -1;

    MachO *macho = fat_find_preferred_slice(fat);
    if (macho) {
        clock_t t;
        t = clock();

        PFSection *kernelTextSection = pfsec_init_from_macho(macho, "com.apple.kernel", "__TEXT_EXEC", "__text");
        pfsec_set_cached(kernelTextSection, true);

        PFSection *kernelStringSection = pfsec_init_from_macho(macho, "com.apple.kernel", "__TEXT", "__cstring");
        pfsec_set_cached(kernelStringSection, true);

        uint32_t pacibspBytes = 0xD503237F;
        uint32_t pacibspMask = 0xFFFFFFFF;
        PFPatternMetric *pacibspMetric = pfmetric_pattern_init(&pacibspBytes, &pacibspMask, sizeof(pacibspBytes), sizeof(uint32_t));
        pfmetric_run(kernelTextSection, pacibspMetric, ^(uint64_t vmaddr, bool *stop) {
            printf("PACIBSP: 0x%llx (%x)\n", vmaddr, pfsec_read32(kernelTextSection, vmaddr+4));
        });
        pfmetric_free(pacibspMetric);

        uint32_t bBytes = 0;
        uint32_t bMask = 0;
        arm64_gen_b_l(OPT_BOOL_NONE, OPT_UINT64_NONE, OPT_UINT64_NONE, &bBytes, &bMask);
        PFPatternMetric *bMetric = pfmetric_pattern_init(&bBytes, &bMask, sizeof(bBytes), sizeof(uint32_t));
        pfmetric_run(kernelTextSection, bMetric, ^(uint64_t vmaddr, bool *stop) {
            uint64_t target = 0;
            bool isBl = false;
            if (arm64_dec_b_l(pfsec_read32(kernelTextSection, vmaddr), vmaddr, &target, &isBl) == 0) {
                if (isBl) {
                    printf("%llx: \"bl %llx\"\n", vmaddr, target);
                }
                else {
                    printf("%llx: \"b  %llx\"\n", vmaddr, target);
                }
            }
        });
        pfmetric_free(bMetric);

        uint32_t adrBytes = 0;
        uint32_t adrMask = 0;
        arm64_gen_adr_p(OPT_BOOL_NONE, OPT_UINT64_NONE, OPT_UINT64_NONE, ARM64_REG_ANY, &adrBytes, &adrMask);
        PFPatternMetric *adrMetric = pfmetric_pattern_init(&adrBytes, &adrMask, sizeof(adrBytes), sizeof(uint32_t));
        pfmetric_run(kernelTextSection, adrMetric, ^(uint64_t vmaddr, bool *stop) {
            uint64_t target = 0;
            bool isAdrp = false;
            arm64_register reg;
            if (arm64_dec_adr_p(pfsec_read32(kernelTextSection, vmaddr), vmaddr, &target, &reg, &isAdrp) == 0) {
                if (isAdrp) {
                    printf("%llx: \"adrp x%u, %llx\"\n", vmaddr, ARM64_REG_GET_NUM(reg), target);
                }
                else {
                    printf("%llx: \"adr  x%u, %llx\"\n", vmaddr, ARM64_REG_GET_NUM(reg), target);
                }
            }
        });

        uint32_t addBytes = 0;
        uint32_t addMask = 0;
        arm64_gen_add_imm(ARM64_REG_ANY, ARM64_REG_ANY, OPT_UINT64_NONE, &addBytes, &addMask);
        PFPatternMetric *addMetric = pfmetric_pattern_init(&addBytes, &addMask, sizeof(addBytes), sizeof(uint32_t));
        pfmetric_run(kernelTextSection, addMetric, ^(uint64_t vmaddr, bool *stop) {
            arm64_register destinationReg;
            arm64_register sourceReg;
            uint16_t imm = 0;
            uint32_t inst = pfsec_read32(kernelTextSection, vmaddr);
            if (arm64_dec_add_imm(inst, &destinationReg, &sourceReg, &imm) == 0) {
                printf("%llx: \"add %s%u, %s%u, 0x%x\"\n", vmaddr, arm64_reg_get_type_string(destinationReg), ARM64_REG_GET_NUM(destinationReg), arm64_reg_get_type_string(sourceReg), ARM64_REG_GET_NUM(sourceReg), imm);
            }
        });


        uint32_t ldrBytes = 0;
        uint32_t ldrMask = 0;
        arm64_gen_ldr_imm(-1, LDR_STR_TYPE_ANY, ARM64_REG_ANY, ARM64_REG_ANY, OPT_UINT64_NONE, &ldrBytes, &ldrMask);
        PFPatternMetric *ldrMetric = pfmetric_pattern_init(&ldrBytes, &ldrMask, sizeof(ldrBytes), sizeof(uint32_t));
        pfmetric_run(kernelTextSection, ldrMetric, ^(uint64_t vmaddr, bool *stop) {
            arm64_register destinationReg;
            arm64_register sourceReg;
            uint64_t imm = 0;
            uint32_t inst = pfsec_read32(kernelTextSection, vmaddr);
            char type = 0;
            arm64_ldr_str_type instType;
            if (arm64_dec_ldr_imm(inst, &destinationReg, &sourceReg, &imm, &type, &instType) == 0) {
                if (type == 0) {
                    printf("%llx: \"ldr %s%u, [%s%u, 0x%llx]%s\"\n", vmaddr, arm64_reg_get_type_string(destinationReg), ARM64_REG_GET_NUM(destinationReg), arm64_reg_get_type_string(sourceReg), ARM64_REG_GET_NUM(sourceReg), imm, instType == LDR_STR_TYPE_PRE_INDEX ? "!" : "");
                }
                else {
                    printf("%llx: \"ldr%c %s%u, [%s%u, 0x%llx]%s\"\n", vmaddr, type, arm64_reg_get_type_string(destinationReg), ARM64_REG_GET_NUM(destinationReg), arm64_reg_get_type_string(sourceReg), ARM64_REG_GET_NUM(sourceReg), imm, instType == LDR_STR_TYPE_PRE_INDEX ? "!" : "");
                }
            }
        });

        uint32_t strBytes = 0;
        uint32_t strMask = 0;
        arm64_gen_str_imm(-1, LDR_STR_TYPE_ANY, ARM64_REG_ANY, ARM64_REG_ANY, OPT_UINT64_NONE, &strBytes, &strMask);
        PFPatternMetric *strMetric = pfmetric_pattern_init(&strBytes, &strMask, sizeof(strBytes), sizeof(uint32_t));
        pfmetric_run(kernelTextSection, strMetric, ^(uint64_t vmaddr, bool *stop) {
            arm64_register destinationReg;
            arm64_register sourceReg;
            uint64_t imm = 0;
            uint32_t inst = pfsec_read32(kernelTextSection, vmaddr);
            char type = 0;
            arm64_ldr_str_type instType;
            if (arm64_dec_str_imm(inst, &destinationReg, &sourceReg, &imm, &type, &instType) == 0) {
                if (type == 0) {
                    printf("%llx: \"str %s%u, [%s%u, 0x%llx]%s\"\n", vmaddr, arm64_reg_get_type_string(destinationReg), ARM64_REG_GET_NUM(destinationReg), arm64_reg_get_type_string(sourceReg), ARM64_REG_GET_NUM(sourceReg), imm, instType == LDR_STR_TYPE_PRE_INDEX ? "!" : "");
                }
                else {
                    printf("%llx: \"str%c %s%u, [%s%u, 0x%llx]%s\"\n", vmaddr, type, arm64_reg_get_type_string(destinationReg), ARM64_REG_GET_NUM(destinationReg), arm64_reg_get_type_string(sourceReg), ARM64_REG_GET_NUM(sourceReg), imm, instType == LDR_STR_TYPE_PRE_INDEX ? "!" : "");
                }                
            }
        });

        pfsec_arm64_enumerate_xrefs(kernelTextSection, ARM64_XREF_TYPE_ALL, ^(Arm64XrefType type, uint64_t source, uint64_t target, bool *stop) {
            if (type == ARM64_XREF_TYPE_ADRP_ADD) {
                printf("ADRL %llx -> %llx\n", source, target);
            }
            else if (type == ARM64_XREF_TYPE_ADRP_LDR) {
                printf("ADRP+LDR %llx -> %llx\n", source, target);
            }
            else if (type == ARM64_XREF_TYPE_ADRP_STR) {
                printf("ADRP+STR %llx -> %llx\n", source, target);
            }
        });

        PFStringMetric *stringMetric = pfmetric_string_init("trust_cache_init");
        pfmetric_run(kernelStringSection, stringMetric, ^(uint64_t vmaddr, bool *stop1) {
            printf("\"trust_cache_init\": 0x%llx\n", vmaddr);
            PFXrefMetric *refMetric = pfmetric_xref_init(vmaddr, XREF_TYPE_MASK_REFERENCE);
            pfmetric_run(kernelTextSection, refMetric, ^(uint64_t xrefaddr, bool *stop2) {
                printf("\"trust_cache_init\" xref from %llx\n", xrefaddr);
                printf("kernel_bootstrap_thread: %llx\n", pfsec_find_function_start(kernelTextSection, xrefaddr));
                *stop1 = true;
                *stop2 = true;
            });
            pfmetric_free(refMetric);
        });
        pfmetric_free(stringMetric);

        t = clock() - t; 
        double time_taken = ((double)t)/CLOCKS_PER_SEC;
        printf("KPF finished in %lf seconds\n", time_taken);

        pfsec_free(kernelTextSection);
    }

    fat_free(fat);
    return 0;
}