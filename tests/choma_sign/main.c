#include <choma/Fat.h>
#include <choma/MachO.h>
#include <choma/Host.h>
#include <choma/CSBlob.h>
#include <choma/Entitlements.h>
#include <choma/CodeDirectory.h>
#include <stdbool.h>

#ifndef DISABLE_SIGNING

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
    printf("\t-t: optional team ID to use\n");
    printf("\t-I: optional identifier to use\n");
    printf("\t-h: print this help message\n");
    printf("\t-e: path to entitlements file (XML or property list)\n");
    printf("Examples:\n");
    printf("\t%s -i <path to input MachO/Fat file> (-r) (-o <path to output MachO file>) -e entitlements.plist\n", self);
    exit(-1);
}

int sign_macho(MachO *macho, const char *entitlements, char *teamID, char *identifier) {
    CS_DecodedBlob *xmlEntitlements = NULL, *derEntitlements = NULL;
    if (entitlements) {
        // Create entitlements blobs
        xmlEntitlements = create_xml_entitlements_blob(entitlements);
        derEntitlements = create_der_entitlements_blob(entitlements);
        if (!xmlEntitlements || !derEntitlements) {
            printf("Error: failed to generate entitlements blobs\n");
            return 1;
        }
    }

    CS_DecodedBlob *codeDir = csd_code_directory_init(macho, CS_HASHTYPE_SHA256_256, false);
    if (!codeDir) {
        printf("Error: failed to generate new code directory\n");
    }

    if (identifier)  {
        if (csd_code_directory_set_identifier(codeDir, identifier) != 0) {
            printf("Error: failed to set identifier\n");
        }
    }
    if (teamID)  {
        if (csd_code_directory_set_team_id(codeDir, teamID) != 0) {
            printf("Error: failed to set team ID\n");
        }
    }

    CS_DecodedSuperBlob *decodedSuperblob = csd_superblob_init();
    csd_superblob_append_blob(decodedSuperblob, codeDir);
    if (xmlEntitlements) csd_superblob_append_blob(decodedSuperblob, xmlEntitlements);
    if (derEntitlements) csd_superblob_append_blob(decodedSuperblob, derEntitlements);

    csd_code_directory_update(codeDir, macho);
    csd_code_directory_update_special_slots(codeDir, xmlEntitlements, derEntitlements, NULL);
    csd_code_directory_print_content(codeDir, macho, true, false);

    if (xmlEntitlements) csd_blob_free(xmlEntitlements);
    if (derEntitlements) csd_blob_free(derEntitlements);
    csd_blob_free(codeDir);

    return 0;
}

int main(int argc, char *argv[]) {
    const char *inputPath = get_argument_value(argc, argv, "-i");
    const char *outputPath = get_argument_value(argc, argv, "-o");
    const char *entitlementsPath = get_argument_value(argc, argv, "-e");
    char *teamID = get_argument_value(argc, argv, "-t");
    char *identifier = get_argument_value(argc, argv, "-I");

    bool replaceFile = argument_exists(argc, argv, "-r") || argument_exists(argc, argv, "-a");
    bool printHelpMessage = argument_exists(argc, argv, "-h");

    if (!inputPath || (!outputPath && !replaceFile) || printHelpMessage) {
        print_usage(argv[0]);
    }

    if (access(inputPath, F_OK) != 0) {
        printf("Error: cannot access %s.\n", inputPath);
        return 1;
    }

    if (entitlementsPath && access(entitlementsPath, F_OK) != 0) {
        printf("Error: cannot access %s.\n", entitlementsPath);
        return 1;
    }

    Fat *fat = fat_init_from_path(inputPath);
    if (!fat) {
        printf("Error: failed to initialise fat structure.\n");
        return 1;
    }

    sign_macho(fat_find_preferred_slice(fat), entitlementsPath, teamID, identifier);

    fat_free(fat);
}

#else

int main(int argc, char *argv[]) {
    return 0;
}

#endif // DISABLE_SIGNING