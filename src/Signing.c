#include "Signing.h"
#include "PrivateKey.h"
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <sys/_types/_null.h>

unsigned char *signWithRSA(unsigned char *inputData, size_t inputDataLength,
                           size_t *outputDataLength) {
    unsigned char *signature = (unsigned char *)malloc(2048); // check this
    
    FILE *fp = fmemopen(ca_key, ca_key_len, "r");
    fseek(fp, 0, SEEK_END);
    size_t fileSize = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    uint8_t *fileData = malloc(fileSize);
    fread(fileData, fileSize, 1, fp);
    fclose(fp);
    
    CFDataRef inPKCS12Data = CFDataCreate(NULL, fileData, fileSize);
    CFMutableDictionaryRef dataAttributes = CFDictionaryCreateMutable(
                                                                      kCFAllocatorDefault, 2, &kCFTypeDictionaryKeyCallBacks,
                                                                      &kCFTypeDictionaryValueCallBacks);
    if (dataAttributes == NULL) {
        return signature;
    }
    
    CFStringRef keySize = CFStringCreateWithCString(NULL, "password", kCFStringEncodingUTF8);
    
    CFDictionarySetValue(dataAttributes, kSecImportExportPassphrase, keySize);
    CFArrayRef raw_items = NULL;
    OSStatus securityError = SecPKCS12Import(inPKCS12Data, dataAttributes, &raw_items);
    
    if (securityError == errSecSuccess && CFArrayGetCount(raw_items) > 0) {
        printf("Successfully imported for signing!\n");
        
        // Get the Identity from the imported items array
        CFDictionaryRef pKeyDict = (CFDictionaryRef)CFArrayGetValueAtIndex(raw_items, 0);
        SecIdentityRef pKeyIdent = (SecIdentityRef)CFDictionaryGetValue(pKeyDict, kSecImportItemIdentity);
        if (pKeyIdent != NULL) {
            // get pKey from Identity
            SecKeyRef realpKey = NULL;
            OSStatus pKeyError = SecIdentityCopyPrivateKey(pKeyIdent, &realpKey);
            if (pKeyError == errSecSuccess) {
                // cast to CFDataRef
                CFDataRef inputDataDataRef = CFDataCreate(NULL, inputData, inputDataLength);

                CFErrorRef signError = NULL;
                // Sign Data!
                CFDataRef signedData = SecKeyCreateSignature(realpKey, kSecKeyAlgorithmRSASignatureRaw,inputDataDataRef, &signError);
                if (signedData != NULL) {
                    printf("Successfully signed!\n");
                } else {
                    CFStringRef errorString = CFErrorCopyDescription(signError);
                    CFIndex length = CFStringGetLength(errorString);
                    CFIndex size = CFStringGetMaximumSizeForEncoding(length, kCFStringEncodingUTF8);
                    char *errorChar = (char *)malloc(size);
                    CFStringGetCString(errorString, errorChar, size,kCFStringEncodingUTF8);
                    printf("Signing FAILED (%s)\n", errorChar);
                }
            } else {
                printf("Failed to extract pKey from SecIdentityRef!\n");
            }
        } else {
            printf("Failed to extract SecIdentityRef from Dict!\n");
        }
    } else {
        // Get human readable error string, default value "unknown"
        CFStringRef errorString;
        errorString = SecCopyErrorMessageString(securityError, NULL);
        printf("Failed to import PKCS#12 file: %s\n", CFStringGetCStringPtr(errorString, kCFStringEncodingUTF8));
        return signature; // fix this
    }
    return signature;
}
