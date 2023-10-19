#include <stdio.h>
#include <stdlib.h>

#include "MachO.h"
#include "MachOOrder.h"
#include "MachOLoadCommand.h"

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
	CS_BlobIndex *index;
} CS_SuperBlob;

// Code directory blob header
typedef struct __CodeDirectory {
	uint32_t magic;
	uint32_t length;
	uint32_t version;
	uint32_t flags;
	uint32_t hashOffset;
	uint32_t identOffset;
	uint32_t nSpecialSlots;
	uint32_t nCodeSlots;
	uint32_t codeLimit;
	uint8_t hashSize;
	uint8_t hashType;
	uint8_t spare1;
	uint8_t	pageSize;
	uint32_t spare2;
} CS_CodeDirectory;

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

// Forward declaration
struct lc_code_signature;

// Convert blob magic to readable blob type string
char *csBlobMagicToReadableString(int magic);

// Retrieve CMS superblob from slice
void parseSuperBlob(MachO *macho, int sliceIndex, CS_SuperBlob *superblob);