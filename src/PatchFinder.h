#ifndef PATCHFINDER_H
#define PATCHFINDER_H

#include <stdint.h>
#include "MachO.h"

#define METRIC_TYPE_PATTERN 1
#define METRIC_TYPE_STRING 2
#define METRIC_TYPE_XREF 3

typedef struct s_PFSection {
	MachO *macho;
	uint64_t fileoff;
	uint64_t vmaddr;
	uint64_t size;
	uint8_t *cache;
	bool ownsCache;
} PFSection;

PFSection *pf_section_init_from_macho(MachO *macho, const char *filesetEntryId, const char *segName, const char *sectName);
int pf_section_read_reloff(PFSection *section, uint64_t rel, size_t size, void *outBuf);
uint32_t pf_section_read32_reloff(PFSection *section, uint64_t rel);
int pf_section_read_at_address(PFSection *section, uint64_t vmaddr, void *outBuf, size_t size);
uint32_t pf_section_read32(PFSection *section, uint64_t vmaddr);
int pf_section_set_cached(PFSection *section, bool cached);
uint64_t pf_section_find_prev_inst(PFSection *section, uint64_t startAddr, uint32_t searchCount, uint32_t inst, uint32_t mask);
uint64_t pf_section_find_next_inst(PFSection *section, uint64_t startAddr, uint32_t searchCount, uint32_t inst, uint32_t mask);
uint64_t pf_section_find_function_start(PFSection *section, uint64_t midAddr);
void pf_section_free(PFSection *section);


typedef struct s_MetricShared {
	uint32_t type;
} MetricShared;


typedef enum {
	BYTE_PATTERN_ALIGN_8_BIT,
	BYTE_PATTERN_ALIGN_16_BIT,
	BYTE_PATTERN_ALIGN_32_BIT,
	BYTE_PATTERN_ALIGN_64_BIT,
} BytePatternAlignment;

typedef struct s_PFBytePatternMetric {
	MetricShared shared;

	void *bytes;
	void *mask;
	size_t nbytes;
	BytePatternAlignment alignment;
} PFBytePatternMetric;

typedef struct s_PFStringMetric {
	MetricShared shared;

	char *string;
} PFStringMetric;

typedef enum {
    XREF_TYPE_MASK_CALL  = (1 << 0),
    XREF_TYPE_MASK_REFERENCE = (1 << 1),
    XREF_TYPE_MASK_ALL = (XREF_TYPE_MASK_CALL | XREF_TYPE_MASK_REFERENCE),
} XrefTypeMask;

typedef struct s_PFXrefMetric {
	MetricShared shared;

	uint64_t address;
	XrefTypeMask typeMask;
} PFXrefMetric;

PFBytePatternMetric *pf_create_byte_pattern_metric(void *bytes, void *mask, size_t nbytes, BytePatternAlignment alignment);
void pf_byte_pattern_metric_free(PFBytePatternMetric *metric);

PFStringMetric *pf_create_string_metric(const char *string);
void pf_string_metric_free(PFStringMetric *metric);

PFXrefMetric *pf_create_xref_metric(uint64_t address, XrefTypeMask types);
void pf_xref_metric_free(PFXrefMetric *metric);

void pf_section_run_metric(PFSection *section, void *metric, void (^matchBlock)(uint64_t vmaddr, bool *stop));
#endif