#include <choma/Fat.h>
#include <choma/MachO.h>

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
    printf("\t-t: optional 10-character team ID to use\n");
    printf("\t-h: print this help message\n");
    printf("\t-e: path to entitlements file (XML or property list)\n");
    printf("Examples:\n");
    printf("\t%s -i <path to input MachO/Fat file> (-r) (-o <path to output MachO file>) -e entitlements.plist\n", self);
    exit(-1);
}

int sign_macho(MachO *macho, const char *entitlements, const char *teamID) {
    return 0;
}

int main(int argc, char *argv[]) {
    const char *inputPath = get_argument_value(argc, argv, "-i");
    const char *outputPath = get_argument_value(argc, argv, "-o");
    const char *entitlementsPath = get_argument_value(argc, argv, "-e");
    const char *teamID = get_argument_value(argc, argv, "-t");

    bool replaceFile = argument_exists(argc, argv, "-r") || argument_exists(argc, argv, "-a");
    bool printHelpMessage = argument_exists(argc, argv, "-h");

    if (!inputPath || (!outputPath && !replaceFile) || printHelpMessage) {
        print_usage(argv[0]);
    }

    if (access(inputPath, F_OK) != 0) {
        printf("Error: cannot access %s.\n", inputPath);
        return 1;
    }

    if (entitlementsPath && access(entitlementsPath, F_OK) == 0) {
        printf("Error: cannot access %s.\n", entitlementsPath);
        return 1;
    }

    Fat *fat = fat_init_from_path(inputPath);
    if (!fat) {
        printf("Error: failed to initialise fat structure.\n");
        return 1;
    }

    int r = 0;
    for (int i = 0; i < fat->slicesCount; i++) {
        r = sign_macho(fat->slices[i], entitlementsPath, teamID);
        if (r) break;
    }

    fat_free(fat);
}

#else

int main(int argc, char *argv[]) {
    return 0;
}

#endif // DISABLE_SIGNING