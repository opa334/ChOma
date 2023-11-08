#include "PatchFinder.h"
#include "MachO.h"

PFSection *macho_patchfinder_create_section(MachO *macho, const char *segmentIdentifier)
{
	PFSection *pfSection = NULL;
	MachO *machoToUse = macho;
	char *buf = strdup(segmentIdentifier);
	char *identifier = strtok(buf, "|");
	if (identifier) {
		// check if there is a fileset macho with this identifier
		for (uint32_t i = 0; i < macho->filesetCount; i++) {
			FilesetMachO *filesetMacho = &macho->filesetMachos[i];
			if (filesetMacho->underlyingMachO.slicesCount == 1) {
				if (!strcmp(filesetMacho->entry_id, identifier)) {
					machoToUse = &filesetMacho->underlyingMachO.slices[0];
					identifier = strtok(NULL, "|");
					break;
				}
			}
		}

		if (identifier) {
			MachOSegment *segment = NULL;
			for (uint32_t i = 0; i < machoToUse->segmentCount; i++) {
				MachOSegment *segmentCandidate = machoToUse->segments[i];
				if (!strcmp(segmentCandidate->command.segname, identifier)) {
					segment = segmentCandidate;
					break;
				}
			}
			if (segment != NULL) {
				struct section_64 *section = NULL;
				identifier = strtok(NULL, "|");
				if (identifier) {
					for (uint32_t i = 0; i < segment->command.nsects; i++) {
						struct section_64 *sectionCandidate = &segment->sections[i];	
						if (!strcmp(sectionCandidate->sectname, identifier)) {
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
				if (!section) {
					pfSection = malloc(sizeof(PFSection));
					pfSection->fileoff = segment->command.fileoff;
					pfSection->vmaddr = segment->command.vmaddr;
					pfSection->size = segment->command.vmsize;
				}
			}
		}
	}

	free(buf);
	return pfSection;
}


void _macho_patchfinder_run_pattern_metric(MachO *macho, BytePatternMetric *bytePatternMetric, void (^matchBlock)(uint64_t vmaddr, bool *stop))
{
	uint64_t fileoff = bytePatternMetric->shared.section->fileoff;
	uint64_t fileoffEnd = bytePatternMetric->shared.section->fileoff + bytePatternMetric->shared.section->size;

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

	uint32_t searchOffset = fileoff;
	while (memory_stream_find_memory(&macho->stream, searchOffset, (fileoffEnd - searchOffset), bytePatternMetric->bytes, bytePatternMetric->mask, bytePatternMetric->nbytes, bytePatternMetric->alignment, &searchOffset) == 0) {
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


