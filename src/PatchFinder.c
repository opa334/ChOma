#include "PatchFinder.h"
#include "MachO.h"
#include "MemoryStream.h"
#include "Util.h"
#include "PatchFinder_arm64.h"
#include <mach/machine.h>

int raw_buffer_find_memory(uint8_t *buf, uint64_t searchOffset, size_t searchSize, void *bytes, void *mask, size_t nbytes, uint16_t alignment, uint64_t *foundOffsetOut)
{
    if (nbytes % alignment != 0) return 0;
    if (nbytes == 0) return 0;

    for (uint64_t i = 0; i < (searchSize - nbytes); i += alignment) {
        if (!memcmp_masked(&buf[searchOffset + i], bytes, mask, nbytes)) {
            *foundOffsetOut = searchOffset + i;
            return 0;
        }
    }
    return -1;
}

PFSection *pfsec_init_from_macho(MachO *macho, const char *filesetEntryId, const char *segName, const char *sectName)
{
    PFSection *pfSection = NULL;
    MachO *machoToUse = NULL;
    if (filesetEntryId) {
        // try to find a fileset macho with this identifier
        for (uint32_t i = 0; i < macho->filesetCount; i++) {
            FilesetMachO *filesetMacho = &macho->filesetMachos[i];
            if (filesetMacho->underlyingMachO->slicesCount == 1) {
                if (!strcmp(filesetMacho->entry_id, filesetEntryId)) {
                    machoToUse = filesetMacho->underlyingMachO->slices[0];
                    break;
                }
            }
        }
    }
    else {
        machoToUse = macho;
    }

    if (machoToUse) {
        MachOSegment *segment = NULL;
        for (uint32_t i = 0; i < machoToUse->segmentCount; i++) {
            MachOSegment *segmentCandidate = machoToUse->segments[i];
            if (!strcmp(segmentCandidate->command.segname, segName)) {
                segment = segmentCandidate;
                break;
            }
        }
        if (segment) {
            if (sectName) {
                struct section_64 *section = NULL;
                for (uint32_t i = 0; i < segment->command.nsects; i++) {
                    struct section_64 *sectionCandidate = &segment->sections[i];	
                    if (!strcmp(sectionCandidate->sectname, sectName)) {
                        section = sectionCandidate;
                    }
                }
                if (section) {
                    pfSection = malloc(sizeof(PFSection));
                    pfSection->fileoff = section->offset;
                    pfSection->vmaddr = section->addr;
                    pfSection->size = section->size;
                }
            }
            else {
                pfSection = malloc(sizeof(PFSection));
                pfSection->fileoff = segment->command.fileoff;
                pfSection->vmaddr = segment->command.vmaddr;
                pfSection->size = segment->command.vmsize;
            }
        }
    }

    if (pfSection) {
        pfSection->cache = NULL;
        pfSection->macho = macho;
    }

    return pfSection;
}

int pfsec_read_reloff(PFSection *section, uint64_t rel, size_t size, void *outBuf)
{
    if (rel > section->size) return -1;

    if (section->cache) {
        memcpy(outBuf, &section->cache[rel], size);
        return 0;
    }
    else {
        return macho_read_at_offset(section->macho, section->fileoff + rel, size, outBuf);
    }
}

uint32_t pfsec_read32_reloff(PFSection *section, uint64_t rel)
{
    uint32_t r = 0;
    pfsec_read_reloff(section, rel, sizeof(r), &r);
    return r;
}

int pfsec_read_string_reloff(PFSection *section, uint64_t rel, char **outString)
{
    if (rel > section->size) return -1;

    if (section->cache) {
        const char *curString = (const char *)&section->cache[rel];

        // make sure we don't end up reading OOB memory
        if ((uint8_t *)&curString[strnlen(curString, section->size - rel)] >= &section->cache[section->size]) {
            return -1;
        }

        *outString = strdup(curString);
        return 0;
    }
    else {
        return memory_stream_read_string(macho_get_stream(section->macho), section->fileoff + rel, outString);
    }
}

int pfsec_read_at_address(PFSection *section, uint64_t vmaddr, void *outBuf, size_t size)
{
    if (vmaddr < section->vmaddr) return -1;
    if (vmaddr + size > section->vmaddr + section->size) return -1;

    uint64_t rel = vmaddr - section->vmaddr;
    return pfsec_read_reloff(section, rel, size, outBuf);
}

uint32_t pfsec_read32(PFSection *section, uint64_t vmaddr)
{
    uint32_t r = 0;
    pfsec_read_at_address(section, vmaddr, &r, sizeof(r));
    return r;
}

uint64_t pfsec_read64(PFSection *section, uint64_t vmaddr)
{
    uint64_t r = 0;
    pfsec_read_at_address(section, vmaddr, &r, sizeof(r));
    return r;
}

int pfsec_set_cached(PFSection *section, bool cached)
{
    bool isCachedAlready = (bool)section->cache;
    if (cached != isCachedAlready) {
        if (cached) {
            uint8_t *rawPtr = memory_stream_get_raw_pointer(macho_get_stream(section->macho));
            if (rawPtr) {
                section->cache = &rawPtr[section->fileoff];
            }
            else {
                void *cache = malloc(section->size);
                int r = pfsec_read_reloff(section, 0, section->size, cache);
                if (r != 0) {
                    free(cache);
                    return r;
                }
                section->cache = cache;
                section->ownsCache = true;
            }
        }
        else {
            if (section->ownsCache) {
                free(section->cache);
            }
            section->cache = NULL;
        }
    }
    return 0;
}

int pfsec_find_memory(PFSection *section, uint64_t searchOffset, size_t searchSize, void *bytes, void *mask, size_t nbytes, uint16_t alignment, uint64_t *foundOffsetOut)
{
    if (section->cache) {
        return raw_buffer_find_memory(section->cache, searchOffset, searchSize, bytes, mask, nbytes, alignment, foundOffsetOut);
    }
    else {
        uint64_t foundFileoff = 0;
        int r = memory_stream_find_memory(macho_get_stream(section->macho), section->fileoff + searchOffset, searchSize, bytes, mask, nbytes, alignment, &foundFileoff);
        if (r == 0) {
            *foundOffsetOut = foundFileoff - section->fileoff;
        }
        return r;
    }
}

uint64_t pfsec_find_prev_inst(PFSection *section, uint64_t startAddr, uint32_t searchCount, uint32_t inst, uint32_t mask)
{
    for (uint64_t addr = startAddr; addr >= section->vmaddr && (searchCount > 0 ? (addr >= (startAddr - (searchCount*4))) : true); addr -= 4) {
        uint32_t curInst = pfsec_read32(section, addr);
        if ((curInst & mask) == inst) {
            return addr;
        }
    }
    return 0;
}

uint64_t pfsec_find_next_inst(PFSection *section, uint64_t startAddr, uint32_t searchCount, uint32_t inst, uint32_t mask)
{
    for (uint64_t addr = startAddr; addr < (section->vmaddr + section->size) && (searchCount > 0 ? (addr < (startAddr + (searchCount*4))) : true); addr += 4) {
        uint32_t curInst = pfsec_read32(section, addr);
        if ((curInst & mask) == inst) return addr;
    }
    return 0;
}

uint64_t pfsec_find_function_start(PFSection *section, uint64_t midAddr)
{
    if (section->macho->machHeader.cputype == CPU_TYPE_ARM64) {
        if ((section->macho->machHeader.cpusubtype & 0xff) == CPU_SUBTYPE_ARM64E) {
            uint64_t addr = midAddr;
            while (addr > section->vmaddr) {
                uint32_t curInst = pfsec_read32(section, addr);
                if (curInst == 0xd503237f) return addr;
                addr -= 4;
            }
        }
    }
    return 0;
}

void pfsec_free(PFSection *section)
{
    pfsec_set_cached(section, false);
    free(section);
}

void _pfsec_run_bytepatter_metric(PFSection *section, uint64_t customStart, PFPatternMetric *bytePatternMetric, void (^matchBlock)(uint64_t vmaddr, bool *stop))
{
    uint16_t alignment = 0;
    switch (bytePatternMetric->alignment) {
        case BYTE_PATTERN_ALIGN_8_BIT: {
            alignment = 1;
            break;
        }
        case BYTE_PATTERN_ALIGN_16_BIT: {
            alignment = 2;
            break;
        }
        case BYTE_PATTERN_ALIGN_32_BIT: {
            alignment = 4;
            break;
        }
        case BYTE_PATTERN_ALIGN_64_BIT: {
            alignment = 8;
            break;
        }
    }

    uint64_t searchOffset = 0;
    if (customStart) {
        searchOffset = customStart - section->vmaddr;
        if (searchOffset > section->size) {
            return;
        }
    }

    while (pfsec_find_memory(section, searchOffset, (section->size - searchOffset), bytePatternMetric->bytes, bytePatternMetric->mask, bytePatternMetric->nbytes, alignment, &searchOffset) == 0) {
        bool stop = false;
        matchBlock(section->vmaddr + searchOffset, &stop);
        if (stop) break;
        searchOffset += alignment;
    }
}

PFPatternMetric *pfmetric_pattern_init(void *bytes, void *mask, size_t nbytes, PFBytePatternAlignment alignment)
{
    PFPatternMetric *metric = malloc(sizeof(PFPatternMetric));

    metric->shared.type = METRIC_TYPE_PATTERN;
    metric->bytes = bytes;
    metric->mask = mask;
    metric->nbytes = nbytes;
    metric->alignment = alignment;

    return metric;
}

void pfmetric_pattern_free(PFPatternMetric *metric)
{
    free(metric);
}

void _pfsec_run_string_metric(PFSection *section, uint64_t customStart, PFStringMetric *stringMetric, void (^matchBlock)(uint64_t vmaddr, bool *stop))
{
    char *str = NULL;
    uint64_t searchOffset = 0;
    while (pfsec_read_string_reloff(section, searchOffset, &str) == 0) {
        if (!strcmp(str, stringMetric->string)) {
            bool stop = false;
            matchBlock(section->vmaddr + searchOffset, &stop);
            if (stop) break;
        }
        searchOffset += strlen(str)+1;
        free(str);
    }
}

PFStringMetric *pfmetric_string_init(const char *string)
{
    PFStringMetric *metric = malloc(sizeof(PFStringMetric));

    metric->shared.type = METRIC_TYPE_STRING;
    metric->string = strdup(string);

    return metric;
}

void pfmetric_string_free(PFStringMetric *metric)
{
    free(metric->string);
    free(metric);
}

void _pfsec_run_arm64_xref_metric(PFSection *section, uint64_t customStart, PFXrefMetric *metric, void (^matchBlock)(uint64_t vmaddr, bool *stop))
{
    Arm64XrefTypeMask arm64Types = 0;
    if (metric->typeMask == 0) return;
    if (metric->typeMask & XREF_TYPE_MASK_CALL) {
        arm64Types |= ARM64_XREF_TYPE_MASK_CALL;
    }
    if (metric->typeMask & XREF_TYPE_MASK_REFERENCE) {
        arm64Types |= ARM64_XREF_TYPE_MASK_REFERENCE;
    }

    pfsec_arm64_enumerate_xrefs(section, arm64Types, ^(Arm64XrefType type, uint64_t source, uint64_t target, bool *stop) {
        if (target == metric->address) {
            matchBlock(source, stop);
        }
    });
}

void _pfsec_run_xref_metric(PFSection *section, uint64_t customStart, PFXrefMetric *metric, void (^matchBlock)(uint64_t vmaddr, bool *stop))
{
    switch(section->macho->machHeader.cputype) {
        case CPU_TYPE_ARM64:
        _pfsec_run_arm64_xref_metric(section, customStart, metric, matchBlock);
        break;
    }
}

PFXrefMetric *pfmetric_xref_init(uint64_t address, PFXrefTypeMask types)
{
    PFXrefMetric *metric = malloc(sizeof(PFXrefMetric));

    metric->shared.type = METRIC_TYPE_XREF;
    metric->address = address;
    metric->typeMask = types;

    return metric;
}

void pfmetric_xref_free(PFXrefMetric *metric)
{
    free(metric);
}

void pfmetric_run_from(PFSection *section, uint64_t customStart, void *metric, void (^matchBlock)(uint64_t vmaddr, bool *stop))
{
    MetricShared *shared = metric;
    switch (shared->type) {
        case METRIC_TYPE_PATTERN: {
            _pfsec_run_bytepatter_metric(section, customStart, metric, matchBlock);
            break;
        }
        case METRIC_TYPE_STRING: {
            _pfsec_run_string_metric(section, customStart, metric, matchBlock);
            break;
        }
        case METRIC_TYPE_XREF: {
            _pfsec_run_xref_metric(section, customStart, metric, matchBlock);
            break;
        }
    }
}

void pfmetric_run(PFSection *section, void *metric, void (^matchBlock)(uint64_t vmaddr, bool *stop))
{
    return pfmetric_run_from(section, 0, metric, matchBlock);
}


