// #include "Signing.h"

// int signWithRSA(const char *certificateFile, const char *inputFile, const char *outputFile)
// {
//     // CFBundleRef mainBundle = CFBundleGetMainBundle();
//     // if (!mainBundle) {
//     //     printf("Error: cannot import PKCS#12 file without being part of an app bundle.\n");
//     // }
    
//     // // First argument is the PKCS#12 file, we need to get a SecKeyRef from it
//     // FILE *fp = fopen(certificateFile, "rb");
//     // if (fp == NULL)
//     // {
//     //     printf("Failed to open file %s\n", certificateFile);
//     //     return 1;
//     // }
//     // fseek(fp, 0, SEEK_END);
//     // size_t fileSize = ftell(fp);
//     // fseek(fp, 0, SEEK_SET);
//     // uint8_t *fileData = malloc(fileSize);
//     // fread(fileData, fileSize, 1, fp);
//     // fclose(fp);

//     // CFDataRef inPKCS12Data = CFDataCreate(NULL, fileData, fileSize);

//     // SecKeyRef privateKey = NULL;
//     // // Import identity from PKCS#12 file
//     // const void *keys[] = { kSecImportExportPassphrase, kSecImportItemIdentity };
//     // const void *values[] = { CFSTR(""), CFSTR("") };

//     // CFDictionaryRef options = CFDictionaryCreate(kCFAllocatorDefault, keys, values, 1, NULL, NULL);
//     // const void *itemsArray;
//     // CFArrayRef items = CFArrayCreate(kCFAllocatorDefault, &items, 1, NULL);
//     // OSStatus securityError = SecPKCS12Import(inPKCS12Data, options, &items);

//     // if (securityError == errSecSuccess)
//     // {
//     //     printf("Successfully imported %s for signing!\n", certificateFile);


//     //     // Get the identity from the imported items array
//     //     CFDictionaryRef identityDict = CFArrayGetValueAtIndex(items, 1);
//     // }
//     // else
//     // {
//     //     // Get human readable error string, default value "unknown"
//     //     CFStringRef errorString;
//     //     errorString = SecCopyErrorMessageString(securityError, NULL);
//     //     printf("Failed to import PKCS#12 file: %s\n", CFStringGetCStringPtr(errorString, kCFStringEncodingUTF8));
//     //     return 1;
//     // }


//     return 0;
// }
