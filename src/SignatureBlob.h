#ifndef SIGNATURE_BLOB_H
#define SIGNATURE_BLOB_H

#include "CSBlob.h"

#include <CommonCrypto/CommonDigest.h>

CS_DecodedBlob *superblob_find_blob(CS_DecodedSuperBlob *superblob, uint32_t type);
int update_signature_blob(CS_DecodedSuperBlob *superblob);

#endif // SIGNATURE_BLOB_H