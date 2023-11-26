#include "Signing.h"
#include "PrivateKey.h"
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <sys/_types/_null.h>

unsigned char *signWithRSA(unsigned char *inputData, size_t inputDataLength,
                           size_t *outputDataLength) {
  unsigned char *signature = (unsigned char *)malloc(2048);

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

  if (securityError == errSecSuccess) {
    printf("Successfully imported for signing!\n");

    // Get the identity from the imported items array
    // CFDictionaryRef identityDict = CFArrayGetValueAtIndex(items, 1);
  } else {
    // Get human readable error string, default value "unknown"
    CFStringRef errorString;
    errorString = SecCopyErrorMessageString(securityError, NULL);
    printf("Failed to import PKCS#12 file: %s\n",
           CFStringGetCStringPtr(errorString, kCFStringEncodingUTF8));
    return signature;
  }
  return signature;
}
