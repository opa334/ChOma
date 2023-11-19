#ifndef CS_BLOB_H
#define CS_BLOB_H

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>

#include "FAT.h"
#include "MachO.h"

// Blob index
typedef struct __BlobIndex {
	uint32_t type;
	uint32_t offset;
} CS_BlobIndex;

// CMS superblob
typedef struct __SuperBlob {
	uint32_t magic;
	uint32_t length;
	uint32_t count;
	CS_BlobIndex index[];
} CS_SuperBlob;

typedef struct __GenericBlob {
	uint32_t magic;					/* magic number */
	uint32_t length;				/* total length of blob */
	char data[];
} CS_GenericBlob;

// CMS blob magic types
enum {
    CSBLOB_REQUIREMENT = 0xfade0c00,
    CSBLOB_REQUIREMENTS = 0xfade0c01,
    CSBLOB_CODEDIRECTORY = 0xfade0c02,
    CSBLOB_EMBEDDED_SIGNATURE = 0xfade0cc0,
    CSBLOB_DETACHED_SIGNATURE = 0xfade0cc1,
    CSBLOB_ENTITLEMENTS = 0xfade7171,
    CSBLOB_DER_ENTITLEMENTS = 0xfade7172,
    CSBLOB_SIGNATURE_BLOB = 0xfade0b01
} CS_BlobType;

enum {
    CSSLOT_CODEDIRECTORY = 0,
	CSSLOT_INFOSLOT = 1,
	CSSLOT_REQUIREMENTS = 2,
	CSSLOT_RESOURCEDIR = 3,
	CSSLOT_APPLICATION = 4,
	CSSLOT_ENTITLEMENTS = 5,
    CSSLOT_DER_ENTITLEMENTS = 7,
    CSSLOT_ALTERNATE_CODEDIRECTORIES = 0x1000,
	CSSLOT_ALTERNATE_CODEDIRECTORY_MAX = 5,
	CSSLOT_ALTERNATE_CODEDIRECTORY_LIMIT = CSSLOT_ALTERNATE_CODEDIRECTORIES + CSSLOT_ALTERNATE_CODEDIRECTORY_MAX,
    CSSLOT_SIGNATURESLOT = 0x10000
} CS_SlotType;

typedef struct s_DecodedBlob {
	struct s_DecodedBlob *next;
	uint32_t type;
	MemoryStream *stream;
} DecodedBlob;

typedef struct s_DecodedSuperBlob {
	uint32_t magic;
	struct s_DecodedBlob *firstBlob;
} DecodedSuperBlob;

DecodedSuperBlob *superblob_decode(CS_SuperBlob *superblob);
CS_SuperBlob *superblob_encode(DecodedSuperBlob *decodedSuperblob);
void decoded_superblob_free(DecodedSuperBlob *decodedSuperblob);

uint8_t *macho_find_code_signature(MachO *macho);

// Convert blob magic to readable blob type string
char *cs_blob_magic_to_string(int magic);

// Retrieve superblob from macho
// int macho_parse_superblob(FAT *fat, CS_SuperBlob *superblob, int machoIndex);

// Extract Code Signature to file
int macho_extract_cs_to_file(MachO *macho, CS_SuperBlob *superblob);

CS_SuperBlob *macho_parse_superblob(MachO *macho, bool printAllSlots, bool verifySlots);

#endif // CS_BLOB_H