#include "PatchFinder.h"
#include "MachO.h"

extern int memcmp_masked(const void *str1, const void *str2, unsigned char* mask, size_t n);
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

PFSection *macho_patchfinder_create_section(MachO *macho, const char *filesetEntryId, const char *segName, const char *sectName)
{
    PFSection *pfSection = NULL;
    MachO *machoToUse = NULL;
    if (filesetEntryId) {
        // try to find a fileset macho with this identifier
        for (uint32_t i = 0; i < macho->filesetCount; i++) {
            FilesetMachO *filesetMacho = &macho->filesetMachos[i];
            if (filesetMacho->underlyingMachO.slicesCount == 1) {
                if (!strcmp(filesetMacho->entry_id, filesetEntryId)) {
                    machoToUse = &filesetMacho->underlyingMachO.slices[0];
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
                    pfSection->cache = NULL;
                }
            }
            else {
                pfSection = malloc(sizeof(PFSection));
                pfSection->fileoff = segment->command.fileoff;
                pfSection->vmaddr = segment->command.vmaddr;
                pfSection->size = segment->command.vmsize;
                pfSection->cache = NULL;
            }
        }
    }

    return pfSection;
}

int macho_patchfinder_cache_section(PFSection *section, MachO *fromMacho)
{
    section->cache = malloc(section->size);
    return macho_read_at_offset(fromMacho, section->fileoff, section->size, &section->cache[0]);
}

int macho_patchfinder_section_find_memory(MachO *macho, PFSection *section, uint64_t searchOffset, size_t searchSize, void *bytes, void *mask, size_t nbytes, uint16_t alignment, uint64_t *foundOffsetOut)
{
    if (section->cache) {
        int64_t start = section->fileoff;
        uint64_t searchOffsetTmp = searchOffset - start;
        int r = raw_buffer_find_memory(section->cache, searchOffsetTmp, searchSize, bytes, mask, nbytes, alignment, &searchOffsetTmp);
        *foundOffsetOut = searchOffsetTmp + start;
        return r;
    }
    else {
        return memory_stream_find_memory(&macho->stream, searchOffset, searchSize, bytes, mask, nbytes, alignment, foundOffsetOut);
    }
}

void macho_patchfinder_section_free(PFSection *section)
{
    if (section->cache) {
        free(section->cache);
    }
    free(section);
}

void _macho_patchfinder_run_pattern_metric(MachO *macho, BytePatternMetric *bytePatternMetric, void (^matchBlock)(uint64_t vmaddr, bool *stop))
{
    PFSection *section = bytePatternMetric->shared.section;
    uint64_t fileoff = section->fileoff;
    uint64_t fileoffEnd = section->fileoff + section->size;

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

    uint64_t searchOffset = fileoff;
    while (macho_patchfinder_section_find_memory(macho, section, searchOffset, (fileoffEnd - searchOffset), bytePatternMetric->bytes, bytePatternMetric->mask, bytePatternMetric->nbytes, bytePatternMetric->alignment, &searchOffset) == 0) {
        uint64_t vmaddr;
        MachOSegment *segment;
        if (macho_translate_fileoff_to_vmaddr(macho, searchOffset, &vmaddr, &segment) == 0) {
            bool stop = false;
            matchBlock(vmaddr, &stop);
            if (stop) break;
        }
        searchOffset += alignment;
    }
}

BytePatternMetric *macho_patchfinder_create_byte_pattern_metric(PFSection *section, void *bytes, void *mask, size_t nbytes, BytePatternAlignment alignment)
{
    BytePatternMetric *metric = malloc(sizeof(BytePatternMetric));

    metric->shared.type = METRIC_TYPE_PATTERN;
    metric->shared.section = section;
    metric->bytes = bytes;
    metric->mask = mask;
    metric->nbytes = nbytes;
    metric->alignment = alignment;

    return metric;
}

void macho_patchfinder_run_metric(MachO *macho, void *metric, void (^matchBlock)(uint64_t vmaddr, bool *stop))
{
    MetricShared *shared = metric;
    switch (shared->type) {
        case METRIC_TYPE_PATTERN: {
            _macho_patchfinder_run_pattern_metric(macho, metric, matchBlock);
            break;
        }
    }
}


