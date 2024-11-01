#ifndef DYLD_SHARED_CACHE_H
#define DYLD_SHARED_CACHE_H

#include "dyld_cache_format.h"
#include "CachePatching.h"
#include <stddef.h>
#include <stdbool.h>
typedef struct MachO MachO;
typedef struct Fat Fat;

#define UUID_NULL (uuid_t){0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}

typedef struct DyldSharedCacheMapping {
	uint64_t vmaddr;
	uint64_t size;
	void *ptr;
	void *slideInfoPtr;
	uint64_t slideInfoSize;
	uint64_t flags;
	uint32_t maxProt;
	uint32_t initProt;
} DyldSharedCacheMapping;

typedef struct DyldSharedCacheFile {
	char *filepath;
	size_t filesize;
	void *mapping;
} DyldSharedCacheFile;

typedef struct DyldSharedCacheImage {
	uint64_t index;
	uuid_t uuid;
	const char *path;
	uint32_t nlistStartIndex;
	uint32_t nlistCount;
	Fat *fat;
} DyldSharedCacheImage;

typedef struct DyldSharedCache {
	unsigned fileCount;
	DyldSharedCacheFile **files;
	unsigned symbolFileIndex;

	unsigned mappingCount;
	DyldSharedCacheMapping *mappings;
	uint64_t baseAddress;

	uint64_t containedImageCount;
	DyldSharedCacheImage *containedImages;
} DyldSharedCache;

typedef struct DyldSharedCachePointer {
	uint64_t location;
	uint64_t target;

	bool authenticated;
	uint8_t key;
	uint16_t diversifier;
	bool hasAddressDiversity;
} DyldSharedCachePointer;

enum PAC_KEY {
	PAC_KEY_IA = 0,
	PAC_KEY_IB = 1,
	PAC_KEY_DA = 2,
	PAC_KEY_DB = 3,
};

DyldSharedCache *dsc_init_from_path(const char *path);
void dsc_enumerate_files(DyldSharedCache *sharedCache, void (^enumeratorBlock)(const char *filepath, size_t filesize, struct dyld_cache_header *header));

DyldSharedCacheMapping *dsc_find_mapping(DyldSharedCache *sharedCache, uint64_t vmaddr);
void *dsc_find_buffer(DyldSharedCache *sharedCache, uint64_t vmaddr, uint64_t size);
int dsc_read_from_vmaddr(DyldSharedCache *sharedCache, uint64_t vmaddr, size_t size, void *outBuf);
int dsc_read_string_from_vmaddr(DyldSharedCache *sharedCache, uint64_t vmaddr, char **outString);

Fat *dsc_get_fat_for_path(DyldSharedCache *sharedCache, const char *path);
void dsc_enumerate_images(DyldSharedCache *sharedCache, void (^enumeratorBlock)(const char *path, Fat *imageFAT, bool *stop));
DyldSharedCacheImage *dsc_find_image_for_address(DyldSharedCache *sharedCache, uint64_t address);
int dsc_image_enumerate_symbols(DyldSharedCache *sharedCache, DyldSharedCacheImage *image, void (^enumeratorBlock)(const char *name, uint8_t type, uint64_t vmaddr, bool *stop));
int dsc_image_enumerate_references(DyldSharedCache *sharedCache, DyldSharedCacheImage *image, void (^enumeratorBlock)(unsigned v, void *patchable_location, bool *stop));
int dsc_image_enumerate_chained_fixups(DyldSharedCache *sharedCache, void (^enumeratorBlock)(DyldSharedCachePointer *pointer, bool *stop));

uint64_t dsc_get_base_address(DyldSharedCache *sharedCache);

void dsc_free(DyldSharedCache *sharedCache);

#endif