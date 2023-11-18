#ifndef SUPERBLOB_H
#define SUPERBLOB_H

#include "CSBlob.h"
#include "MachOByteOrder.h"

CS_SuperBlob *create_new_superblob(uint32_t *data, uint32_t dataLength, uint32_t count, CS_BlobIndex blobs[]);

#endif // SUPERBLOB_H