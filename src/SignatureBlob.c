#include "SignatureBlob.h"
#include "BufferedStream.h"
#include "Base64.h"
#include "MemoryStream.h"
#include "SignOSSL.h"
#include "DecryptedSignature.h"
#include <sys/types.h>

// We can use static offsets here because we use a template signature blob
#define SIGNED_ATTRS_OFFSET 0x12DE // SignedAttributes sequence
#define HASHHASH_OFFSET 0x1388 // SHA256 hash SignedAttribute
#define BASEBASE_OFFSET 0x14C5 // Base64 hash SignedAttribute
#define SIGNSIGN_OFFSET 0x151A // Signature

#define DECRYPTED_SIGNATURE_HASH_OFFSET 0x13

CS_DecodedBlob *superblob_find_blob(CS_DecodedSuperBlob *superblob, uint32_t type)
{
    CS_DecodedBlob *blob = superblob->firstBlob;
    while (blob != NULL) {
        if (blob->type == type) {
            return blob;
        }
        blob = blob->next;
    }
    return NULL;
}

int update_signature_blob(CS_DecodedSuperBlob *superblob, const char *privateKeyPath)
{
    CS_DecodedBlob *sha256CD = superblob_find_blob(superblob, CSSLOT_ALTERNATE_CODEDIRECTORIES);
    if (!sha256CD) {
        printf("Could not find CodeDirectory blob!\n");
        return -1;
    }
    CS_DecodedBlob *signatureBlob = superblob_find_blob(superblob, CSSLOT_SIGNATURESLOT);
    if (!signatureBlob) {
        printf("Could not find signature blob!\n");
        return -1;
    }

    uint8_t fullHash[CC_SHA256_DIGEST_LENGTH];
    size_t dataSizeToRead = memory_stream_get_size(sha256CD->stream);
    uint8_t *data = malloc(dataSizeToRead);
    memset(data, 0, dataSizeToRead);
    memory_stream_read(sha256CD->stream, 0, dataSizeToRead, data);
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
    printf("Base64 hash: %.*s\n", CC_SHA256_DIGEST_LENGTH, newBase64Hash);

    int ret = memory_stream_write(signatureBlob->stream, HASHHASH_OFFSET, CC_SHA256_DIGEST_LENGTH, secondCDSHA256Hash);
    if (ret != 0) {
        printf("Failed to write SHA256 hash to signature blob!\n");
        free(newBase64Hash);
        return -1;
    }
    
    ret = memory_stream_write(signatureBlob->stream, BASEBASE_OFFSET, base64OutLength, newBase64Hash);
    if (ret != 0) {
        printf("Failed to write base64 hash to signature blob!\n");
        free(newBase64Hash);
        return -1;
    }

    free(newBase64Hash);

    unsigned char *newSignature = NULL;
    size_t newSignatureSize = 0;

    unsigned char newDecryptedSignature[0x33];
    memset(newDecryptedSignature, 0, 0x33);
    memcpy(newDecryptedSignature, DecryptedSignature, 0x33);

    // Get the signed attributes hash
    unsigned char signedAttrs[0x229];
    memset(signedAttrs, 0, 0x229);
    memory_stream_read(signatureBlob->stream, SIGNED_ATTRS_OFFSET, 0x229, signedAttrs);
    signedAttrs[0] = 0x31;
    
    // Hash
    uint8_t fullAttributesHash[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(signedAttrs, (CC_LONG)0x229, fullAttributesHash);
    memcpy(newDecryptedSignature + DECRYPTED_SIGNATURE_HASH_OFFSET, fullAttributesHash, CC_SHA256_DIGEST_LENGTH);

    struct stat fileStat;
    if (stat(privateKeyPath, &fileStat) != 0) {
        printf("%s not found in path!\n", privateKeyPath);
        return -1;
    }
    newSignature = signWithRSA(privateKeyPath, newDecryptedSignature, DecryptedSignature_len, &newSignatureSize);

    if (!newSignature) {
        printf("Failed to sign the decrypted signature!\n");
        return -1;
    }

    if (newSignatureSize != 0x100) {
        printf("The new signature is not the correct size!\n");
        free(newSignature);
        return -1;
    }

    ret = memory_stream_write(signatureBlob->stream, SIGNSIGN_OFFSET, newSignatureSize, newSignature);
    free(newSignature);
    return ret;
}