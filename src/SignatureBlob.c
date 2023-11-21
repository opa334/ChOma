#include "SignatureBlob.h"
#include "BufferedStream.h"
#include "Base64.h"
#include <sys/types.h>

// We can use static offsets here because we use a template signature blob
#define HASHHASH_OFFSET 0x1388 // SHA256 hash SignedAttribute
#define BASEBASE_OFFSET 0x14C5 // Base64 hash SignedAttribute
#define SIGNSIGN_OFFSET 0x151A // Signature

DecodedBlob *superblob_find_blob(DecodedSuperBlob *superblob, uint32_t type) {
    DecodedBlob *blob = superblob->firstBlob;
    while (blob != NULL) {
        if (blob->type == type) {
            return blob;
        }
        blob = blob->next;
    }
    return NULL;
}

int update_signature_blob(DecodedSuperBlob *superblob) {
    DecodedBlob *sha256CD = superblob_find_blob(superblob, CSSLOT_ALTERNATE_CODEDIRECTORIES);
    if (!sha256CD) {
        printf("Could not find CodeDirectory blob!\n");
        return -1;
    }
    DecodedBlob *signatureBlob = superblob_find_blob(superblob, CSSLOT_SIGNATURESLOT);
    if (!signatureBlob) {
        printf("Could not find signature blob!\n");
        return -1;
    }

    uint8_t fullHash[CC_SHA256_DIGEST_LENGTH];
    size_t dataSizeToRead = 0;
    buffered_stream_get_size(sha256CD->stream, &dataSizeToRead);
    uint8_t *data = malloc(dataSizeToRead);
    memset(data, 0, dataSizeToRead);
    buffered_stream_read(sha256CD->stream, 0, dataSizeToRead, data);
    CC_SHA256(data, (CC_LONG)dataSizeToRead, fullHash);
    free(data);
    uint8_t secondCDSHA256Hash[CC_SHA256_DIGEST_LENGTH];
    memcpy(secondCDSHA256Hash, fullHash, CC_SHA256_DIGEST_LENGTH);
    // Print the hash
    printf("SHA256 hash: ");
    for (int i = 0; i < CC_SHA256_DIGEST_LENGTH; i++) {
        printf("%02x", secondCDSHA256Hash[i]);
    }
    printf("\n");

    size_t base64OutLength = 0;
    char *newBase64Hash = base64_encode(secondCDSHA256Hash, CC_SHA1_DIGEST_LENGTH, &base64OutLength);
    if (!newBase64Hash) {
        printf("Failed to base64 encode hash!\n");
        return -1;
    }

    // Print the base64 hash
    printf("Base64 hash: %s\n", newBase64Hash);

    int ret = buffered_stream_write(signatureBlob->stream, HASHHASH_OFFSET, CC_SHA256_DIGEST_LENGTH, secondCDSHA256Hash);
    if (ret != 0) {
        printf("Failed to write SHA256 hash to signature blob!\n");
        return -1;
    }
    
    ret = buffered_stream_write(signatureBlob->stream, BASEBASE_OFFSET, base64OutLength, newBase64Hash);
    if (ret != 0) {
        printf("Failed to write base64 hash to signature blob!\n");
        return -1;
    }

    free(newBase64Hash);
    
    return 0;
}