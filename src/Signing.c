#include "Signing.h"
#include "PrivateKey.h"
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <sys/_types/_null.h>

unsigned char *signWithRSA(unsigned char *inputData, size_t inputDataLength, size_t *outputDataLength)
{
    unsigned char *signature = (unsigned char *)malloc(2048);

    CFMutableDictionaryRef dataAttributes = CFDictionaryCreateMutable(kCFAllocatorDefault, 2, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);

    if (dataAttributes == NULL)
    {
        return signature;
    }

    CFStringRef keySize = CFStringCreateWithCString(NULL, "2048", kCFStringEncodingUTF8);

    CFDictionarySetValue(dataAttributes, kSecClass, kSecClassKey);
    CFDictionarySetValue(dataAttributes, kSecAttrKeyType, kSecAttrKeyTypeRSA);
    CFDictionarySetValue(dataAttributes, kSecAttrKeyClass, kSecAttrKeyClassPrivate);
    CFDictionarySetValue(dataAttributes, kSecAttrKeySizeInBits, keySize);
    CFDataRef cfData = CFDataCreateWithBytesNoCopy(NULL, ca_key, ca_key_len, kCFAllocatorNull);
    
    CFErrorRef cfError = NULL;
    SecKeyRef privateKey = SecKeyCreateWithData(cfData, dataAttributes, &cfError);
    int err = CFErrorGetCode(cfError);
    if (privateKey == NULL) {
        printf("wtf priv key err (%d, %s)\n", err, strerror(err));
    }
    // const void *itemsArray;
    // CFArrayRef items = CFArrayCreate(kCFAllocatorDefault, &items, 1, NULL);
    // OSStatus securityError = SecPKCS12Import(inPKCS12Data, options, &items);

    // if (securityError == errSecSuccess)
    // {
    //     printf("Successfully imported %s for signing!\n", certificateFile);


    //     // Get the identity from the imported items array
    //     CFDictionaryRef identityDict = CFArrayGetValueAtIndex(items, 1);
    // }
    // else
    // {
    //     // Get human readable error string, default value "unknown"
    //     CFStringRef errorString;
    //     errorString = SecCopyErrorMessageString(securityError, NULL);
    //     printf("Failed to import PKCS#12 file: %s\n", CFStringGetCStringPtr(errorString, kCFStringEncodingUTF8));
    //     return 1;
    // }
    return signature;
}
