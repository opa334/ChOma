#include <choma/CSBlob.h>
#include <choma/Superblob.h>
#include <choma/Host.h>
#include <choma/MemoryStream.h>
#include <choma/FileStream.h>

int main(int argc, char *argv[]) {
    printf("CoreTrust bypass eta s0n!!\n");

    if (argc < 2) {
        printf("Usage: %s <path to MachO file>\n", argv[0]);
        return -1;
    }

    // Make sure the last argument is the path to the FAT/MachO file
    struct stat fileStat;
    if (stat(argv[argc - 1], &fileStat) != 0 && argc > 1) {
        printf("Please ensure the last argument is the path to a FAT/MachO file.\n");
        return -1;
    }

    char *filePath = argv[1];

    FAT *fat = fat_init_from_path(filePath);
    if (!fat) { return -1; }

    MachO *macho = fat_find_preferred_slice(fat);
    if (!macho) return -1;

    CS_SuperBlob *superblob = macho_parse_superblob(macho, false, false);
    SUPERBLOB_APPLY_BYTE_ORDER(superblob, BIG_TO_HOST_APPLIER);

    FILE *fp = fopen("blobData", "rb");
    fseek(fp, 0, SEEK_END);
    uint32_t blobDataLength = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    uint32_t *blobData = malloc(blobDataLength);
    fread(blobData, blobDataLength, 1, fp);
    fclose(fp);

    SUPERBLOB_APPLY_BYTE_ORDER(superblob, BIG_TO_HOST_APPLIER);

    CS_SuperBlob *newSuperblob = create_new_superblob(blobData, blobDataLength, superblob->count, superblob->index);

    // Write the new superblob to the file
    fp = fopen("generatedSuperblob", "wb+");
    uint32_t newSuperblobLength = BIG_TO_HOST(newSuperblob->length);
    fwrite(newSuperblob, newSuperblobLength, 1, fp);
    fclose(fp);


    fat_free(fat);
    return 0;
}