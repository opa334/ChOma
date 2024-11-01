#include "DyldSharedCache.h"
#include <libgen.h>
#include <sys/syslimits.h>
#include <sys/types.h>
#include <mach-o/nlist.h>
#include <dirent.h>
#include <sys/mman.h>
#include "BufferedStream.h"
#include "MachO.h"
#include "Fat.h"

int string_comparator(void const *a, void const *b) { 
    char const *aa = *(char const **)a;
    char const *bb = *(char const **)b;

    int r = strcmp(aa, bb);
    return r;
}

DyldSharedCacheMapping *dsc_find_mapping(DyldSharedCache *sharedCache, uint64_t vmaddr)
{
    for (unsigned i = 0; i < sharedCache->mappingCount; i++) {
        DyldSharedCacheMapping *mapping = &sharedCache->mappings[i];
        uint64_t mappingEndAddr = mapping->vmaddr + mapping->size;
        if (vmaddr >= mapping->vmaddr && vmaddr < mappingEndAddr) {
            return mapping;
        }
    }
    return NULL;
}

void *dsc_find_buffer(DyldSharedCache *sharedCache, uint64_t vmaddr, uint64_t size)
{
    uint64_t endAddr = vmaddr + size;

    DyldSharedCacheMapping *mapping = dsc_find_mapping(sharedCache, vmaddr);
    uint64_t mappingEndAddr = mapping->vmaddr + mapping->size;
    if (endAddr <= mappingEndAddr) {
        return (void *)((uintptr_t)mapping->ptr + (vmaddr - mapping->vmaddr));
    }

    return NULL;
}

int dsc_read_from_vmaddr(DyldSharedCache *sharedCache, uint64_t vmaddr, size_t size, void *outBuf)
{
    uint64_t startAddr = vmaddr;
    uint64_t endAddr = vmaddr + size;
    uint64_t curAddr = startAddr;

    // This only works when sharedCache->mappings is sorted
    for (unsigned i = 0; i < sharedCache->mappingCount; i++) {
        DyldSharedCacheMapping *mapping = &sharedCache->mappings[i];
        uint64_t mappingEndAddr = mapping->vmaddr + mapping->size;
        if (vmaddr >= mapping->vmaddr && vmaddr < mappingEndAddr) {
            uint64_t copySize = endAddr - curAddr;
            uint64_t mappingRemaining = mapping->size - (vmaddr - mapping->vmaddr);
            if (copySize > mappingRemaining) copySize = mappingRemaining;
            memcpy((void *)((intptr_t)outBuf + (curAddr - startAddr)), (void *)((intptr_t)mapping->ptr + (vmaddr - mapping->vmaddr)), copySize);
            curAddr += copySize;
            if (curAddr >= endAddr) break;
        }
    }
    return !(curAddr >= endAddr);
}

int dsc_read_string_from_vmaddr(DyldSharedCache *sharedCache, uint64_t vmaddr, char **outString)
{
    uint64_t len = 0;
    char c = 0;
    do {
        if (dsc_read_from_vmaddr(sharedCache, vmaddr + (len++), sizeof(c), &c) != 0) return -1;
    } while (c != 0);

    *outString = malloc(len);
    return dsc_read_from_vmaddr(sharedCache, vmaddr, len, *outString);
}

DyldSharedCacheFile *_dsc_load_file(const char *dscPath, const char suffix[32])
{
    char filepath[strlen(dscPath) + strnlen(suffix, 32) + 1];
    strcpy(filepath, dscPath);
    strncat(filepath, suffix, 32);

    int fd = open(filepath, O_RDONLY);
    if (fd <= 0) return NULL;

    struct stat sb;
    if (fstat(fd, &sb) != 0) {
        close(fd);
        return NULL;
    }

    if (sb.st_size < sizeof(struct dyld_cache_header)) {
        close(fd);
        return NULL;
    }

    void *mapping = mmap(NULL, sb.st_size, PROT_READ, MAP_FILE | MAP_PRIVATE, fd, 0);
    close(fd);

    if (mapping == MAP_FAILED) return NULL;
    
    struct dyld_cache_header *dscHeader = mapping;
    if (strncmp(dscHeader->magic, "dyld_v", 6) != 0) {
        munmap(mapping, sb.st_size);
        return NULL;
    }

    DyldSharedCacheFile *file = malloc(sizeof(DyldSharedCacheFile));
    if (!file) {
        munmap(mapping, sb.st_size);
        return NULL;
    }

    file->filepath = strdup(filepath);
    file->filesize = sb.st_size;
    file->mapping  = mapping;
    return file;
}

DyldSharedCache *dsc_init_from_path(const char *path)
{
    if (!path) return NULL;

    DyldSharedCache *sharedCache = malloc(sizeof(DyldSharedCache));
    sharedCache->mappings = NULL;
    sharedCache->mappingCount = 0;
    sharedCache->symbolFileIndex = 0;

    // Load main DSC file
    DyldSharedCacheFile *mainFile = _dsc_load_file(path, "");
    if (!mainFile) {
        printf("ERROR: Failed to load main cache file\n");
        dsc_free(sharedCache);
        return NULL;
    }

    struct dyld_cache_header *mainHeader = mainFile->mapping;
    bool symbolFileExists = !!memcmp(mainHeader->symbolFileUUID, UUID_NULL, sizeof(UUID_NULL));
    sharedCache->fileCount = 1 + mainHeader->subCacheArrayCount + symbolFileExists;

    sharedCache->files = malloc(sizeof(struct DyldSharedCacheFile *) * sharedCache->fileCount);
    sharedCache->files[0] = mainFile;

    if (mainHeader->subCacheArrayCount > 0) {
        // If there are sub caches, load them aswell
        void *subcacheEntries = (void *)((uintptr_t)mainHeader + mainHeader->subCacheArrayOffset);
        int subCacheStructVersion = mainHeader->mappingOffset <= offsetof(struct dyld_cache_header, cacheSubType) ? 1 : 2;

        for (uint32_t i = 0; i < mainHeader->subCacheArrayCount; i++) {
            struct dyld_subcache_entry subcacheEntry;
            if (subCacheStructVersion == 1) {
                // Old format (iOS <=15) had no suffix string, here the suffix is derived from the index
                memcpy(subcacheEntry.uuid, ((struct dyld_subcache_entry_v1 *)subcacheEntries)[i].uuid, sizeof(uuid_t));
                subcacheEntry.cacheVMOffset = ((struct dyld_subcache_entry_v1 *)subcacheEntries)[i].cacheVMOffset;
                snprintf(subcacheEntry.fileSuffix, sizeof(subcacheEntry.fileSuffix), ".%u", i+1);
            }
            else {
                subcacheEntry = ((struct dyld_subcache_entry *)subcacheEntries)[i];
            }

            sharedCache->files[i+1] = _dsc_load_file(path, subcacheEntry.fileSuffix);
            if (!sharedCache->files[i+1]) {
                printf("ERROR: Failed to map subcache with suffix %s\n", subcacheEntry.fileSuffix);
                dsc_free(sharedCache);
                return NULL;
            }

            struct dyld_cache_header *header = sharedCache->files[i+1]->mapping;
            if (memcmp(header->uuid, subcacheEntry.uuid, sizeof(header->uuid)) != 0) {
                printf("ERROR: UUID mismatch on subcache with suffix %s\n", subcacheEntry.fileSuffix);
                dsc_free(sharedCache);
                return NULL;
            }
        }
    }

    if (symbolFileExists) {
        // If there is a .symbols file, load that aswell
        sharedCache->symbolFileIndex = sharedCache->fileCount - 1;

        sharedCache->files[sharedCache->symbolFileIndex] = _dsc_load_file(path, ".symbols");
        if (!sharedCache->files[sharedCache->symbolFileIndex]) {
            printf("ERROR: Failed to map symbols subcache\n");
            dsc_free(sharedCache);
            return NULL;
        }

        struct dyld_cache_header *header = sharedCache->files[sharedCache->symbolFileIndex]->mapping;
        if (memcmp(header->uuid, mainHeader->symbolFileUUID, sizeof(header->uuid)) != 0) {
            printf("ERROR: UUID mismatch on symbols subcache\n");
            dsc_free(sharedCache);
            return NULL;
        }
    }
    else {
        sharedCache->symbolFileIndex = -1;
    }

    sharedCache->baseAddress = mainHeader->sharedRegionStart;

    for (unsigned i = 0; i < sharedCache->fileCount; i++) {
        DyldSharedCacheFile *file = sharedCache->files[i];
        if (!file) continue;

        struct dyld_cache_header *header = file->mapping;

        //printf("Parsing DSC %s\n", file->filepath);

        if (file->filesize < (header->mappingOffset + header->mappingCount * sizeof(struct dyld_cache_mapping_info))) {
            printf("WARNING: Failed to parse DSC %s\n", file->filepath);
        }

        bool slideInfo = (bool)header->mappingWithSlideOffset;

        void *mappingInfosRaw = (void *)((uintptr_t)header + (slideInfo ? header->mappingWithSlideOffset : header->mappingOffset));

        unsigned prevMappingCount = sharedCache->mappingCount;
        sharedCache->mappingCount += header->mappingCount;
        sharedCache->mappings = realloc(sharedCache->mappings, sharedCache->mappingCount * sizeof(DyldSharedCacheMapping));

        for (int k = 0; k < header->mappingCount; k++) {
            DyldSharedCacheMapping *thisMapping = &sharedCache->mappings[prevMappingCount + k];

            struct dyld_cache_mapping_and_slide_info fullInfo = {};
            if (slideInfo) {
                struct dyld_cache_mapping_and_slide_info *mappingSlideInfo = mappingInfosRaw;
                fullInfo = mappingSlideInfo[k];
            }
            else {
                struct dyld_cache_mapping_info *mappingInfo = mappingInfosRaw;
                fullInfo.address = mappingInfo[k].address;
                fullInfo.size = mappingInfo[k].size;
                fullInfo.fileOffset = mappingInfo[k].fileOffset;
                fullInfo.maxProt = mappingInfo[k].maxProt;
                fullInfo.initProt = mappingInfo[k].initProt;
                fullInfo.slideInfoFileOffset = 0;
                fullInfo.slideInfoFileSize = 0;
            }

            thisMapping->ptr = (file->mapping + fullInfo.fileOffset);
            thisMapping->vmaddr = fullInfo.address;
            thisMapping->size = fullInfo.size;

            thisMapping->initProt = fullInfo.initProt;
            thisMapping->maxProt = fullInfo.maxProt;

            if (fullInfo.slideInfoFileOffset) {
                thisMapping->slideInfoPtr = (void *)((uint64_t)file->mapping + fullInfo.slideInfoFileOffset);
                thisMapping->slideInfoSize = fullInfo.slideInfoFileSize;
                thisMapping->flags = fullInfo.flags;
            }
            else {
                thisMapping->slideInfoPtr = NULL;
                thisMapping->slideInfoSize = 0;
                thisMapping->flags = 0;
            }
        }
    }

    struct dyld_cache_header *header = sharedCache->files[0]->mapping;
    struct dyld_cache_image_text_info *imagesText = (void *)((uintptr_t)header + header->imagesTextOffset);
    if (header->imagesTextCount) {
        sharedCache->containedImageCount = header->imagesTextCount;
        sharedCache->containedImages = malloc(header->imagesTextCount * sizeof(DyldSharedCacheImage));
        for (uint64_t i = 0; i < header->imagesTextCount; i++) {
            void *buffer = dsc_find_buffer(sharedCache, imagesText[i].loadAddress, imagesText[i].textSegmentSize);
            if (!buffer) {
                continue;
            }

            sharedCache->containedImages[i].index = i;

            memcpy(&sharedCache->containedImages[i].uuid, &imagesText[i].uuid, sizeof(uuid_t));
            sharedCache->containedImages[i].path = (void *)((uintptr_t)header + imagesText[i].pathOffset);

            MemoryStream *stream = buffered_stream_init_from_buffer_nocopy(buffer, imagesText[i].textSegmentSize, 0);
            sharedCache->containedImages[i].fat = fat_dsc_init_from_memory_stream(stream, sharedCache, &sharedCache->containedImages[i]);
        }
    }

    struct dyld_cache_local_symbols_info *localSymbols = NULL;
    struct dyld_cache_header *symbolCacheHeader = sharedCache->files[sharedCache->symbolFileIndex]->mapping;
    if (symbolCacheHeader->localSymbolsOffset) {
        localSymbols = (void *)((uintptr_t)symbolCacheHeader + symbolCacheHeader->localSymbolsOffset);
        if (localSymbols->entriesCount == sharedCache->containedImageCount) {
            struct dyld_cache_local_symbols_entry_64 *symbolEntries = (void *)((uintptr_t)localSymbols + localSymbols->entriesOffset);
            for (uint64_t i = 0; i < sharedCache->containedImageCount; i++) {
                sharedCache->containedImages[i].nlistStartIndex = symbolEntries[i].nlistStartIndex;
                sharedCache->containedImages[i].nlistCount = symbolEntries[i].nlistCount;
            }
        }
    }

    return sharedCache;
}

void dsc_enumerate_files(DyldSharedCache *sharedCache, void (^enumeratorBlock)(const char *filepath, size_t filesize, struct dyld_cache_header *header))
{
    for (int i = 0; i < sharedCache->fileCount; i++) {
        enumeratorBlock(sharedCache->files[i]->filepath, sharedCache->files[i]->filesize, sharedCache->files[i]->mapping);
    }
}

Fat *dsc_get_fat_for_path(DyldSharedCache *sharedCache, const char *path)
{
    for (unsigned i = 0; i < sharedCache->containedImageCount; i++) {
        if (!strcmp(sharedCache->containedImages[i].path, path)) {
            return sharedCache->containedImages[i].fat;
        }
    }
    return NULL;
}

void dsc_enumerate_images(DyldSharedCache *sharedCache, void (^enumeratorBlock)(const char *path, Fat *imageFAT, bool *stop))
{
    for (unsigned i = 0; i < sharedCache->containedImageCount; i++) {
        bool stop = false;
        enumeratorBlock(sharedCache->containedImages[i].path, sharedCache->containedImages[i].fat, &stop);
        if (stop) break;
    }
}

DyldSharedCacheImage *dsc_find_image_for_address(DyldSharedCache *sharedCache, uint64_t address)
{
    __block DyldSharedCacheImage *image = NULL;
    for (unsigned i = 0; i < sharedCache->containedImageCount; i++) {
        if (sharedCache->containedImages[i].fat->slicesCount == 1) {
            MachO *macho = sharedCache->containedImages[i].fat->slices[0];
            if (macho) {
                macho_enumerate_sections(macho, ^(struct section_64 *section, struct segment_command_64 *segment, bool *stop) {
                    if (address >= section->addr && address < (section->addr + section->size)) {
                        image = &sharedCache->containedImages[i];
                    }
                });
            }
        }
    }
    return image;
}

int dsc_image_enumerate_symbols(DyldSharedCache *sharedCache, DyldSharedCacheImage *image, void (^enumeratorBlock)(const char *name, uint8_t type, uint64_t vmaddr, bool *stop))
{
    struct dyld_cache_local_symbols_info *localSymbols = NULL;
    struct dyld_cache_header *symbolCacheHeader = sharedCache->files[sharedCache->symbolFileIndex]->mapping;
    if (symbolCacheHeader->localSymbolsOffset) {
        localSymbols = (void *)((uintptr_t)symbolCacheHeader + symbolCacheHeader->localSymbolsOffset);
        
        char *stringTable = (char *)((uintptr_t)localSymbols + localSymbols->stringsOffset);
        struct nlist_64 *nlistTable = (void *)((uintptr_t)localSymbols + localSymbols->nlistOffset);

        uint32_t firstSymIdx = image->nlistStartIndex;
        uint32_t lastSymIdx = image->nlistStartIndex + image->nlistCount - 1;
        
        if (lastSymIdx > localSymbols->nlistCount) return -1;

        for (uint32_t symIdx = firstSymIdx; symIdx <= lastSymIdx; symIdx++) {
            struct nlist_64 *nlist = &nlistTable[symIdx];
            if (nlist->n_un.n_strx > localSymbols->stringsSize) return -1;

            bool stop = false;
            enumeratorBlock(&stringTable[nlist->n_un.n_strx], nlist->n_type, nlist->n_value, &stop);
            if (stop) break;
        }
        return 0;
    }
    return -1;
}

int dsc_image_enumerate_references(DyldSharedCache *sharedCache, DyldSharedCacheImage *image, void (^enumeratorBlock)(unsigned v, void *patchable_location, bool *stop))
{
    struct dyld_cache_header *mainHeader = sharedCache->files[0]->mapping;

    struct dyld_cache_patch_info_v3 *patchInfo = dsc_find_buffer(sharedCache, mainHeader->patchInfoAddr, mainHeader->patchInfoSize);

    if (patchInfo->infoV2.patchTableVersion == 4) {
        struct dyld_cache_image_got_clients_v3 *gotClients = (void *)((uintptr_t)patchInfo + (patchInfo->gotClientsArrayAddr - mainHeader->patchInfoAddr));
        struct dyld_cache_patchable_export_v3 *clientExports = (void *)((uintptr_t)patchInfo + (patchInfo->gotClientExportsArrayAddr - mainHeader->patchInfoAddr));
        struct dyld_cache_patchable_location_v4 *locationArray = (void *)((uintptr_t)patchInfo + (patchInfo->gotLocationArrayAddr - mainHeader->patchInfoAddr));

        uint32_t patchExportsStartIndex = gotClients[image->index].patchExportsStartIndex;
        uint32_t patchExportsEndIndex = patchExportsStartIndex + gotClients[image->index].patchExportsCount;
        for (uint32_t i = patchExportsStartIndex; i < patchExportsEndIndex; i++) {
            uint32_t patchLocationsStartIndex = clientExports[i].patchLocationsStartIndex;
            uint32_t patchLocationsEndIndex = patchLocationsStartIndex + clientExports[i].patchLocationsCount;
            for (uint32_t k = clientExports[i].patchLocationsStartIndex; k < patchLocationsEndIndex; k++) {
                bool stop = false;
                enumeratorBlock(4, &locationArray[k], &stop);
                if (stop) return 0;
            }
        }
    }

    return 0;
}

int dsc_image_enumerate_chained_fixups(DyldSharedCache *sharedCache, void (^enumeratorBlock)(DyldSharedCachePointer *pointer, bool *stop))
{
    for (uint64_t i = 0; i < sharedCache->mappingCount; i++) {
        DyldSharedCacheMapping *mapping = &sharedCache->mappings[i];
        if (mapping->slideInfoPtr) {
            uint32_t version = *(uint32_t *)mapping->slideInfoPtr;
            switch (version) {
                case 5: {
                    struct dyld_cache_slide_info5 *info = mapping->slideInfoPtr;
                    uint64_t startAddr = mapping->vmaddr;
                    uint64_t endAddr = startAddr + (info->page_starts_count * info->page_size);
                    int pi = 0;
                    for (uint64_t pageAddr = startAddr; pageAddr < endAddr; pageAddr += info->page_size) {
                        uint32_t delta = info->page_starts[pi++];
                        union dyld_cache_slide_pointer5* loc = (mapping->ptr + (pageAddr - mapping->vmaddr));
                        if (delta != DYLD_CACHE_SLIDE_V5_PAGE_ATTR_NO_REBASE) {
                            delta /= 8; // The first delta is a direct offset, all further ones are (offset / 8)
                            do {
                                loc += delta;
                                delta = loc->auth.next;

                                uint64_t value = loc->regular.runtimeOffset + info->value_add;
                                if (!loc->auth.auth) {
                                    value |= ((uint64_t)loc->regular.high8 << 56);
                                }

                                DyldSharedCachePointer pointer = (DyldSharedCachePointer){
                                    .location = ((uint64_t)loc - (uint64_t)mapping->ptr) + mapping->vmaddr,
                                    .target = value,

                                    .authenticated = loc->auth.auth,
                                    .key = loc->auth.keyIsData ? PAC_KEY_DA : PAC_KEY_IA,
                                    .diversifier = loc->auth.diversity,
                                    .hasAddressDiversity = loc->auth.addrDiv,
                                };

                                bool stop = false;
                                enumeratorBlock(&pointer, &stop);
                                if (stop) return 0;
                            } while (delta != 0);
                        }
                    }
                    break;
                }
                case 3: {
                    struct dyld_cache_slide_info3 *info = mapping->slideInfoPtr;
                    uint64_t startAddr = mapping->vmaddr;
                    uint64_t endAddr = startAddr + (info->page_starts_count * info->page_size);
                    int pi = 0;
                    for (uint64_t pageAddr = startAddr; pageAddr < endAddr; pageAddr += info->page_size) {
                        uint32_t delta = info->page_starts[pi++];
                        union dyld_cache_slide_pointer3* loc = (mapping->ptr + (pageAddr - mapping->vmaddr));
                        if (delta != DYLD_CACHE_SLIDE_V3_PAGE_ATTR_NO_REBASE) {
                            delta /= 8; // The first delta is a direct offset, all further ones are (offset / 8)
                            do {
                                loc += delta;
                                delta = loc->auth.offsetToNextPointer;

                                uint64_t value = 0;
                                if (loc->auth.authenticated) {
                                    value = loc->auth.offsetFromSharedCacheBase + info->auth_value_add;
                                }
                                else {
                                    uint64_t value51 = loc->plain.pointerValue;
                                    uint64_t top8Bits = value51 & 0x0007F80000000000ULL;
                                    uint64_t bottom43Bits = value51 & 0x000007FFFFFFFFFFULL;
                                    value = (top8Bits << 13) | bottom43Bits;
                                }

                                DyldSharedCachePointer pointer = (DyldSharedCachePointer){
                                    .location = ((uint64_t)loc - (uint64_t)mapping->ptr) + mapping->vmaddr,
                                    .target = value,

                                    .authenticated = loc->auth.authenticated,
                                    .key = loc->auth.key,
                                    .diversifier = loc->auth.diversityData,
                                    .hasAddressDiversity = loc->auth.hasAddressDiversity,
                                };

                                bool stop = false;
                                enumeratorBlock(&pointer, &stop);
                                if (stop) return 0;
                            } while (delta != 0);
                        }
                    }
                    break;
                }
            }
        }
    }
    return 0;
}


uint64_t dsc_get_base_address(DyldSharedCache *sharedCache)
{
    return sharedCache->baseAddress;
}

void dsc_free(DyldSharedCache *sharedCache)
{
    if (sharedCache->fileCount > 0) {
        for (unsigned i = 0; i < sharedCache->fileCount; i++) {
            munmap(sharedCache->files[i]->mapping, sharedCache->files[i]->filesize);
            free(sharedCache->files[i]->filepath);
            free(sharedCache->files[i]);
        }
        free(sharedCache->files);
    }
    if (sharedCache->mappings) {
        free(sharedCache->mappings);
    }
    if (sharedCache->containedImages) {
        for (unsigned i = 0; i < sharedCache->containedImageCount; i++) {
            if (sharedCache->containedImages[i].fat) {
                fat_free(sharedCache->containedImages[i].fat);
            }
        }
        free(sharedCache->containedImages);
    }
    free(sharedCache);
}
