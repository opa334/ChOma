#include "PatchFinder.h"
#include "MachO.h"
#include "MemoryStream.h"
#include "Util.h"
#include "PatchFinder_arm64.h"
#include <mach/machine.h>

int raw_buffer_find_memory(uint8_t *buf, uint64_t searchStartOffset, uint64_t searchEndOffset, void *bytes, void *mask, size_t nbytes, uint16_t alignment, uint64_t *foundOffsetOut)
{
    __block int r = -1;
    enumerate_range(searchStartOffset, searchEndOffset, alignment, nbytes, ^bool(uint64_t cur) {
        if (!memcmp_masked(&buf[cur], bytes, mask, nbytes)) {
            *foundOffsetOut = cur;
            r = 0;
            return false;
        }
        return true;
    });
    return r;
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
                    pfSection->initprot = segment->command.initprot;
                    pfSection->maxprot = segment->command.maxprot;
                    strncpy(pfSection->segname, segment->command.segname, sizeof(pfSection->segname) / sizeof(char));
                    strncpy(pfSection->sectname, section->sectname, sizeof(section->sectname) / sizeof(char));
                }
            }
            else {
                pfSection = malloc(sizeof(PFSection));
                pfSection->fileoff = segment->command.fileoff;
                pfSection->vmaddr = segment->command.vmaddr;
                pfSection->size = segment->command.vmsize;
                pfSection->initprot = segment->command.initprot;
                pfSection->maxprot = segment->command.maxprot;
                strncpy(pfSection->segname, segment->command.segname, sizeof(pfSection->segname) / sizeof(char));
            }
        }
    }

    if (pfSection) {
        pfSection->cache = NULL;
        pfSection->ownsCache = false;
        pfSection->macho = macho;
    }

    return pfSection;
}

void pfsec_set_pointer_decoder(PFSection *section, uint64_t (*pointerDecoder)(struct s_PFSection *section, uint64_t vmaddr, uint64_t value))
{
    section->pointerDecoder = pointerDecoder;
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

int pfsec_read_string(PFSection *section, uint64_t vmaddr, char **outString)
{
    if (vmaddr < section->vmaddr) return -1;
    return pfsec_read_string_reloff(section, vmaddr - section->vmaddr, outString);
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

uint64_t pfsec_read_pointer(PFSection *section, uint64_t vmaddr)
{
    uint64_t value = pfsec_read64(section, vmaddr);
    if (section->pointerDecoder) {
        return section->pointerDecoder(section, vmaddr, value);
    }
    return value;
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
            section->ownsCache = false;
        }
    }
    return 0;
}

int pfsec_find_memory_rel(PFSection *section, uint64_t searchStartOffset, uint64_t searchEndOffset, void *bytes, void *mask, size_t nbytes, uint16_t alignment, uint64_t *foundRelOffsetOut)
{
    if (section->cache) {
        return raw_buffer_find_memory(section->cache, searchStartOffset, searchEndOffset, bytes, mask, nbytes, alignment, foundRelOffsetOut);
    }
    else {
        uint64_t foundFileoff = 0;
        int r = memory_stream_find_memory(macho_get_stream(section->macho), section->fileoff + searchStartOffset, section->fileoff + searchEndOffset, bytes, mask, nbytes, alignment, &foundFileoff);
        if (r == 0) {
            *foundRelOffsetOut = foundFileoff - section->fileoff;
        }
        return r;
    }
}

int pfsec_find_memory(PFSection *section, uint64_t searchStartAddr, uint64_t searchEndAddr, void *bytes, void *mask, size_t nbytes, uint16_t alignment, uint64_t *foundAddrOut)
{
    if (searchStartAddr < section->vmaddr || searchStartAddr > (section->vmaddr + section->size)) return -1;
    if (searchEndAddr < section->vmaddr   || searchEndAddr > (section->vmaddr + section->size)) return -1;

    uint64_t foundRelOff = 0;
    int r = pfsec_find_memory_rel(section, searchStartAddr - section->vmaddr, searchEndAddr - section->vmaddr, bytes, mask, nbytes, alignment, &foundRelOff);
    if (r == 0) {
        *foundAddrOut = section->vmaddr + foundRelOff;
    }

    return r;
}

uint64_t pfsec_find_prev_inst(PFSection *section, uint64_t startAddr, uint32_t searchCount, uint32_t inst, uint32_t mask)
{
    uint64_t out = 0;
    uint64_t endAddr = searchCount ? (startAddr - (sizeof(uint32_t) * searchCount)) : section->vmaddr;
    pfsec_find_memory(section, startAddr, endAddr, &inst, &mask, sizeof(inst), sizeof(uint32_t), &out);
    if (!out) return 0;
    return out;
}

uint64_t pfsec_find_next_inst(PFSection *section, uint64_t startAddr, uint32_t searchCount, uint32_t inst, uint32_t mask)
{
    uint64_t out = 0;
    uint64_t endAddr = searchCount ? (startAddr + (sizeof(uint32_t) * searchCount)) : (section->vmaddr + section->size);
    pfsec_find_memory(section, startAddr, endAddr, &inst, &mask, sizeof(inst), sizeof(uint32_t), &out);
    if (!out) return 0;
    return out;
}

uint64_t pfsec_find_function_start(PFSection *section, uint64_t midAddr)
{
    if (section->macho->machHeader.cputype == CPU_TYPE_ARM64) {
        if ((section->macho->machHeader.cpusubtype & ~CPU_SUBTYPE_MASK) == CPU_SUBTYPE_ARM64E) {
            uint64_t addr = midAddr;
            while (addr > section->vmaddr && addr < (section->vmaddr + section->size)) {
                uint32_t curInst = pfsec_read32(section, addr);
                if (curInst == 0xd503237f) return addr;
                addr -= 4;
            }
        }
        else if ((section->macho->machHeader.cpusubtype & ~CPU_SUBTYPE_MASK) == CPU_SUBTYPE_ARM64_ALL) {
            // Technique adapted from pongoOS
            uint64_t frameAddr = pfsec_find_prev_inst(section, midAddr, 0, 0x910003fd, 0xff8003ff); // add x29, sp, ?
            if (frameAddr) {
                uint64_t start = pfsec_find_prev_inst(section, frameAddr, 10, 0x29a003e0, 0x3be003e0); // stp ?, ?, [sp, ?]!
                if (!start) {
                    start = pfsec_find_prev_inst(section, frameAddr, 10, 0xd10003ff, 0xff8003ff); // sub sp, sp, ?
                }
                return start;
            }
        }
    }
    return 0;
}

bool pfsec_contains_vmaddr(PFSection *section, uint64_t addr)
{
    return (addr >= section->vmaddr && addr < (section->vmaddr + section->size));
}

void pfsec_free(PFSection *section)
{
    pfsec_set_cached(section, false);
    free(section);
}

void _pfsec_run_pattern_metric(PFSection *section, uint64_t startAddr, uint64_t endAddr, PFPatternMetric *patternMetric, void (^matchBlock)(uint64_t vmaddr, bool *stop))
{
    uint16_t alignment = patternMetric->alignment;

    while (pfsec_find_memory(section, startAddr, endAddr, patternMetric->bytes, patternMetric->mask, patternMetric->nbytes, alignment, &startAddr) == 0) {
        bool stop = false;
        matchBlock(startAddr, &stop);
        if (stop) break;
        startAddr += alignment;
    }
}

PFPatternMetric *pfmetric_pattern_init(void *bytes, void *mask, size_t nbytes, uint16_t alignment)
{
    PFPatternMetric *metric = malloc(sizeof(PFPatternMetric));

    metric->shared.type = PF_METRIC_TYPE_PATTERN;
    metric->bytes = bytes;
    metric->mask = mask;
    metric->nbytes = nbytes;
    metric->alignment = alignment;

    return metric;
}

void _pfsec_run_string_metric(PFSection *section, uint64_t startAddr, uint64_t endAddr, PFStringMetric *stringMetric, void (^matchBlock)(uint64_t vmaddr, bool *stop))
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

    metric->shared.type = PF_METRIC_TYPE_STRING;
    metric->string = strdup(string);

    return metric;
}

void _pfsec_run_arm64_xref_metric(PFSection *section, uint64_t startAddr, uint64_t endAddr, PFXrefMetric *metric, void (^matchBlock)(uint64_t vmaddr, bool *stop))
{
    Arm64XrefTypeMask arm64Types = 0;
    if (metric->typeMask == 0) return;
    if (metric->typeMask & XREF_TYPE_MASK_CALL) {
        arm64Types |= ARM64_XREF_TYPE_MASK_CALL;
    }
    if (metric->typeMask & XREF_TYPE_MASK_JUMP) {
        arm64Types |= ARM64_XREF_TYPE_MASK_JUMP;
    }
    if (metric->typeMask & XREF_TYPE_MASK_REFERENCE) {
        arm64Types |= ARM64_XREF_TYPE_MASK_REFERENCE;
    }
    if (metric->typeMask & XREF_TYPE_MASK_POINTER) {
        arm64Types |= ARM64_XREF_TYPE_MASK_POINTER;
    }

    pfsec_arm64_enumerate_xrefs(section, arm64Types, ^(Arm64XrefType type, uint64_t source, uint64_t target, bool *stop) {
        if (target == metric->address) {
            matchBlock(source, stop);
        }
    });
}

void _pfsec_run_xref_metric(PFSection *section, uint64_t startAddr, uint64_t endAddr, PFXrefMetric *xrefMetric, void (^matchBlock)(uint64_t vmaddr, bool *stop))
{
    switch(section->macho->machHeader.cputype) {
        case CPU_TYPE_ARM64:
        _pfsec_run_arm64_xref_metric(section, startAddr, endAddr, xrefMetric, matchBlock);
        break;
    }
}

PFXrefMetric *pfmetric_xref_init(uint64_t address, PFXrefTypeMask types)
{
    PFXrefMetric *metric = malloc(sizeof(PFXrefMetric));

    metric->shared.type = PF_METRIC_TYPE_XREF;
    metric->address = address;
    metric->typeMask = types;

    return metric;
}

void pfmetric_free(void *metric)
{
    uint32_t type = ((PFPatternMetric *)metric)->shared.type;
    if (type == PF_METRIC_TYPE_STRING) {
        free(((PFStringMetric *)metric)->string);
    }
    free(metric);
}

void pfmetric_run_in_range(PFSection *section, uint64_t startAddr, uint64_t endAddr, void *metric, void (^matchBlock)(uint64_t vmaddr, bool *stop))
{
    if (startAddr == -1ULL) startAddr = section->vmaddr;
    if (endAddr == -1ULL) endAddr = section->vmaddr + section->size;

    MetricShared *shared = metric;
    switch (shared->type) {
        case PF_METRIC_TYPE_PATTERN: {
            _pfsec_run_pattern_metric(section, startAddr, endAddr, metric, matchBlock);
            break;
        }
        case PF_METRIC_TYPE_STRING: {
            _pfsec_run_string_metric(section, startAddr, endAddr, metric, matchBlock);
            break;
        }
        case PF_METRIC_TYPE_XREF: {
            _pfsec_run_xref_metric(section, startAddr, endAddr, metric, matchBlock);
            break;
        }
    }
}

void pfmetric_run(PFSection *section, void *metric, void (^matchBlock)(uint64_t vmaddr, bool *stop))
{
    return pfmetric_run_in_range(section, -1, -1, metric, matchBlock);
}
