#ifndef SIGNATURE_BLOB_H
#define SIGNATURE_BLOB_H

#include "CSBlob.h"

#include <CommonCrypto/CommonDigest.h>

int update_signature_blob(DecodedSuperBlob *superblob);

#endif // SIGNATURE_BLOB_H