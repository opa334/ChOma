#include "CodeDirectory.h"

// TODO: Validate that hashes are correct using the application bundle
// int code_directory_verify_special_slots(MachO *macho, CS_CodeDirectory *codeDirectory, uint8_t *hashes) {
//     for (int i = 0; i < codeDirectory->nSpecialSlots; i++) {
//         uint8_t *zeroHash = malloc(codeDirectory->hashSize);
//         memset(zeroHash, 0, codeDirectory->hashSize);
//         if (memcmp(&hashes[i * codeDirectory->hashSize], zeroHash, codeDirectory->hashSize) != 0) {
//             switch (i + 1) {
//                 case 1:
//                     // Info.plist hash
                
//                 case 2:
//                     // Requirements blob hash

//                 case 3:
//                     // CodeResources hash
                
//                 case 4:
//                     // App-specific hash
                
//                 case 5:
//                     // Entitlements hash

//                 case 6:
//                     // Used for disk rep

//                 case 7:
//                     // DER entitlements hash

//                 case 8:
//                     // Process launch constraints hash

//                 case 9:
//                     // Parent process launch constraints hash

//                 case 10:
//                     // Responsible process launch constraints hash

//                 case 11:
//                     // Loaded library launch constraints hash

//                 default:
//                     // Unknown special slot
//             }
//         }
//     }
// }

int code_directory_verify_code_slots(MachO *macho, CS_CodeDirectory *codeDirectory, uint8_t *hashes) {
    bool foundIncorrectHash = false;
    uint32_t dataOffsetToRead = 0;
    __block uint32_t dataSizeToRead = (uint32_t)(pow(2.0, (double)(codeDirectory->pageSize)));
    for (int i = 0; i < codeDirectory->nCodeSlots; i++) {
        if (i == codeDirectory->nCodeSlots - 1) {
            macho_enumerate_load_commands(macho, ^(struct load_command loadCommand, uint32_t offset, void *cmd, bool *stop) {
                if (loadCommand.cmd == LC_CODE_SIGNATURE) {
                    // Create and populate the code signature load command structure
                    struct lc_code_signature csLoadCommand = *((struct lc_code_signature *)cmd);
                    LC_CODE_SIGNATURE_APPLY_BYTE_ORDER(&csLoadCommand, LITTLE_TO_HOST_APPLIER); // TODO: Move this to macho_enumerate_load_commands impl
                    dataSizeToRead = (csLoadCommand.dataoff) - (dataOffsetToRead);
                }
            });
        }
        uint8_t *data = malloc(dataSizeToRead);
        memset(data, 0, dataSizeToRead);
        macho_read_at_offset(macho, dataOffsetToRead, dataSizeToRead, data);
        uint8_t actualHash[codeDirectory->hashSize];
        bool failedToGetHash = false;
        switch (codeDirectory->hashType) {
            case CS_HASHTYPE_SHA160_160: {
                CC_SHA1(data, (CC_LONG)dataSizeToRead, actualHash);
                break;
            }

            case CS_HASHTYPE_SHA256_256:
            case CS_HASHTYPE_SHA256_160: {
                uint8_t fullHash[CC_SHA256_DIGEST_LENGTH];
                CC_SHA256(data, (CC_LONG)dataSizeToRead, fullHash);
                memcpy(actualHash, fullHash, codeDirectory->hashSize);
                break;
            }

            case CS_HASHTYPE_SHA384_384: {
                uint8_t fullHash[CC_SHA384_DIGEST_LENGTH];
                CC_SHA256(data, (CC_LONG)dataSizeToRead, fullHash);
                memcpy(actualHash, fullHash, codeDirectory->hashSize);
                break;
            }

            default: {
                failedToGetHash = true;
            }
        }

        if (!failedToGetHash) {
            uint8_t *currentHash = malloc(codeDirectory->hashSize);
            memset(currentHash, 0, codeDirectory->hashSize);
            memcpy(currentHash, &hashes[i * codeDirectory->hashSize], codeDirectory->hashSize);
            if (memcmp(&hashes[i * codeDirectory->hashSize], actualHash, codeDirectory->hashSize) != 0) {
                printf("Slot %d has incorrect hash, should be ", i);
                for (int j = 0; j < codeDirectory->hashSize; j++)
                {
                    printf("%02x", currentHash[j]);
                }
                printf("\n");
                foundIncorrectHash = true;
            }
            free(currentHash);
        } else {
            printf("Error: failed to get hash for slot %d.\n", i);
        }
        
        dataOffsetToRead += dataSizeToRead;
    }
    return foundIncorrectHash ? -1 : 0;
}


int macho_parse_code_directory_blob(MachO *macho, uint32_t codeDirectoryOffset, CS_CodeDirectory *codeDirectoryOut, bool printSlots, bool verifySlots)
{
	if (macho_read_at_offset(macho, codeDirectoryOffset, sizeof(CS_CodeDirectory), codeDirectoryOut) != 0)
	{
		printf("Error: could not read code directory blob at offset 0x%x.\n", codeDirectoryOffset);
		return -1;
	}
	CODE_DIRECTORY_APPLY_BYTE_ORDER(codeDirectoryOut, BIG_TO_HOST_APPLIER);

	uint32_t slotZeroOffset = codeDirectoryOffset + codeDirectoryOut->hashOffset;
	uint8_t *specialSlots = malloc(codeDirectoryOut->nSpecialSlots * codeDirectoryOut->hashSize);
	memset(specialSlots, 0, codeDirectoryOut->nSpecialSlots * codeDirectoryOut->hashSize);
	size_t lastSpecialSlotOffset = slotZeroOffset - (codeDirectoryOut->nSpecialSlots * codeDirectoryOut->hashSize);
	macho_read_at_offset(macho, lastSpecialSlotOffset, codeDirectoryOut->nSpecialSlots * codeDirectoryOut->hashSize, specialSlots);

	for (int i = 0; i < codeDirectoryOut->nSpecialSlots; i++)
	{

		// Print the slot number
		int slotNumber = 0 - (codeDirectoryOut->nSpecialSlots - i);
		printf("%d: ", slotNumber);

		// Print each byte of the hash
		for (int j = 0; j < codeDirectoryOut->hashSize; j++)
		{
			printf("%02x", specialSlots[(i * codeDirectoryOut->hashSize) + j]);
		}

		// Check if hash is just zeroes
		bool isZero = true;
		for (int j = 0; j < codeDirectoryOut->hashSize; j++)
		{
			if (specialSlots[(i * codeDirectoryOut->hashSize) + j] != 0)
			{
				isZero = false;
				break;
			}
		}

		// TrollStore TODO: Validate that hashes are correct
		// validateHashes(macho, specialSlots, codeDirectoryOut->nSpecialSlots * codeDirectoryOut->hashSize);
		// Don't print the special slot name if the hash is just zeroes
		if (!isZero)
		{
			// Print the special slot name (if applicable)
			if (slotNumber == -1)
			{
				printf(" (Info.plist hash)");
			}
			else if (slotNumber == -2)
			{
				printf(" (Requirements blob hash)");
			}
			else if (slotNumber == -3)
			{
				printf(" (CodeResources hash)");
			}
			else if (slotNumber == -4)
			{
				printf(" (App-specific hash)");
			}
			else if (slotNumber == -5)
			{
				printf(" (Entitlements hash)");
			}
			else if (slotNumber == -6)
			{
				printf(" (Used for disk rep)");
			}
			else if (slotNumber == -7)
			{
				printf(" (DER entitlements hash)");
			}
			else if (slotNumber == -8)
			{
				printf(" (Process launch constraints hash)");
			}
			else if (slotNumber == -9)
			{
				printf(" (Parent process launch constraints hash)");
			}
			else if (slotNumber == -10)
			{
				printf(" (Responsible process launch constraints hash)");
			}
			else if (slotNumber == -11)
			{
				printf(" (Loaded library launch constraints hash)");
			}
		}

		printf("\n");
	}

	// Clean up
	free(specialSlots);

	if (printSlots) {
		uint8_t *hashes = malloc(codeDirectoryOut->nCodeSlots * codeDirectoryOut->hashSize);
		memset(hashes, 0, codeDirectoryOut->nCodeSlots * codeDirectoryOut->hashSize);
		macho_read_at_offset(macho, slotZeroOffset, codeDirectoryOut->nCodeSlots * codeDirectoryOut->hashSize, hashes);
		for (int i = 0; i < codeDirectoryOut->nCodeSlots; i++)
		{

			// Align the slot number for cleaner output
			if (i > 9)
			{
				printf("%d: ", i);
			}
			else
			{
				printf(" %d: ", i);
			}

			// Print each byte of the hash
			for (int j = 0; j < codeDirectoryOut->hashSize; j++)
			{
				printf("%02x", hashes[(i * codeDirectoryOut->hashSize) + j]);
			}
			printf("\n");

		}
        if (verifySlots) {
            if (code_directory_verify_code_slots(macho, codeDirectoryOut, hashes) == -1) {
                printf("Error: code slot hashes are not correct!\n");
            }
        }
	}

	return 0;
}

