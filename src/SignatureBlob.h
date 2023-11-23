#ifndef SIGNATURE_BLOB_H
#define SIGNATURE_BLOB_H

#include "CSBlob.h"

#include <CommonCrypto/CommonDigest.h>

DecodedBlob *superblob_find_blob(DecodedSuperBlob *superblob, uint32_t type);
int update_signature_blob(DecodedSuperBlob *superblob, const char *privateKeyPath);

#endif // SIGNATURE_BLOB_H