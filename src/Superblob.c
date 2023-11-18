#include "Superblob.h"

CS_SuperBlob *create_new_superblob(uint32_t *data, uint32_t dataLength, uint32_t count, CS_BlobIndex blobs[])
{
    CS_SuperBlob *superblob = malloc(sizeof(CS_SuperBlob) + (count * sizeof(CS_BlobIndex)) + dataLength);
    superblob->magic = CSBLOB_EMBEDDED_SIGNATURE;
    superblob->length = sizeof(CS_SuperBlob) + (count * sizeof(CS_BlobIndex)) + dataLength;
    superblob->count = count;

    for (int i = 0; i < count; i++) {
        CS_BlobIndex blobIndex = blobs[i];
        BLOB_INDEX_APPLY_BYTE_ORDER(&blobIndex, HOST_TO_BIG_APPLIER);
        superblob->index[i] = blobs[i];
    }
    SUPERBLOB_APPLY_BYTE_ORDER(superblob, HOST_TO_BIG_APPLIER);

    memcpy((uint8_t *)superblob + sizeof(CS_SuperBlob) + (count * sizeof(CS_BlobIndex)), data, dataLength);

    return superblob;
}

int superblob_replace_blob(CS_SuperBlob *superblob, uint32_t blobType, uint32_t *data, uint32_t dataLength)
{
    // TODO
    return 0;
}