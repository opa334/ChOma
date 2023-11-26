#include "SignOSSL.h"

unsigned char *signWithRSA(unsigned char *inputData, size_t inputDataLength, unsigned char *key, size_t key_len, size_t *outputDataLength)
{
    // Create EVP_PKEY from private key data
    FILE *privateKeyFile = fmemopen(key, key_len, "r");
    if (!privateKeyFile) return NULL;
    EVP_PKEY *privateKey = PEM_read_PrivateKey(privateKeyFile, NULL, NULL, NULL);
    fclose(privateKeyFile);
    if (!privateKey) {
        fprintf(stderr, "Error: failed to read private key file.\n");
    }

    // Get the RSA key from the private key
    RSA *rsaKey = EVP_PKEY_get1_RSA(privateKey);
    if (!rsaKey) {
        printf("Error: failed to get RSA key from private key.\n");
    }

    // Determine the size of the RSA key in bytes
    int keySize = RSA_size(rsaKey);

    // Allocate memory for the signature
    unsigned char *signature = (unsigned char *)malloc(keySize);
    if (!signature) {
        printf("Error: failed to allocate memory.\n");
    }

    // Sign the data
    int signatureLength = RSA_private_encrypt(inputDataLength, inputData, signature, rsaKey, RSA_PKCS1_PADDING);
    if (signatureLength == -1) {
        printf("Error: failed to sign the data.\n");
    }
    
    RSA_free(rsaKey);
    EVP_PKEY_free(privateKey);

    *outputDataLength = signatureLength;
    return signature;
}
