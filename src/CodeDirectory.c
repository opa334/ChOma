#include "CodeDirectory.h"
#include "MemoryStream.h"

int code_directory_verify_code_slots(MachO *macho, CS_CodeDirectory *codeDirectory, uint8_t *hashes) {
    bool foundIncorrectHash = false;
    uint32_t dataOffsetToRead = 0;
    __block uint32_t dataSizeToRead = (uint32_t)(pow(2.0, (double)(codeDirectory->pageSize)));
    for (int i = 0; i < codeDirectory->nCodeSlots; i++) {
        if (i == codeDirectory->nCodeSlots - 1) {
            macho_enumerate_load_commands(macho, ^(struct load_command loadCommand, uint64_t offset, void *cmd, bool *stop) {
                if (loadCommand.cmd == LC_CODE_SIGNATURE) {
                    // Create and populate the code signature load command structure
                    struct linkedit_data_command *csLoadCommand = (struct linkedit_data_command *)cmd;
                    LINKEDIT_DATA_COMMAND_APPLY_BYTE_ORDER(csLoadCommand, LITTLE_TO_HOST_APPLIER); // TODO: Move this to macho_enumerate_load_commands impl
                    dataSizeToRead = (csLoadCommand->dataoff) - (dataOffsetToRead);
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
                    printf("%02x", actualHash[j]);
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

char *cs_hash_type_to_string(int hashType)
{
	switch (hashType)
	{
	case CS_HASHTYPE_SHA160_160:
		return "SHA-1 160";
	case CS_HASHTYPE_SHA256_256:
		return "SHA-2 256";
	case CS_HASHTYPE_SHA256_160:
		return "SHA-2 160";
	case CS_HASHTYPE_SHA384_384:
		return "SHA-3 384";
	default:
		return "Unknown blob type";
	}
}

int macho_parse_code_directory_blob(MachO *macho, CS_CodeDirectory *codeDirectoryOut, uint32_t cdOffset, bool printSlots, bool verifySlots)
{
	printf("Code directory:\n");
	printf("\tMagic: 0x%X\n", codeDirectoryOut->magic);
	printf("\tLength: 0x%x\n", codeDirectoryOut->length);
	printf("\tVersion: 0x%x\n", codeDirectoryOut->version);
	printf("\tFlags: 0x%x\n", codeDirectoryOut->flags);
	printf("\tHash offset: 0x%x\n", codeDirectoryOut->hashOffset);
	printf("\tIdentity offset: 0x%x\n", codeDirectoryOut->identOffset);
	printf("\tNumber of special slots: %d\n", codeDirectoryOut->nSpecialSlots);
	printf("\tNumber of code slots: %d\n", codeDirectoryOut->nCodeSlots);
	printf("\tCode limit: 0x%x\n", codeDirectoryOut->codeLimit);
	printf("\tHash size: 0x%x\n", codeDirectoryOut->hashSize);
	printf("\tHash type: %s\n", cs_hash_type_to_string(codeDirectoryOut->hashType));
	printf("\tPage size: 0x%x\n", codeDirectoryOut->pageSize);
	printf("\tScatter offset: 0x%x\n", codeDirectoryOut->scatterOffset);
	printf("\tTeam offset: 0x%x\n", codeDirectoryOut->teamOffset);

	uint32_t slotZeroOffset = codeDirectoryOut->hashOffset;
	printf("Slot zero offset: 0x%x\n", slotZeroOffset);
	uint8_t *specialSlots = malloc(codeDirectoryOut->nSpecialSlots * codeDirectoryOut->hashSize);
	memset(specialSlots, 0, codeDirectoryOut->nSpecialSlots * codeDirectoryOut->hashSize);
	size_t lastSpecialSlotOffset = slotZeroOffset - (codeDirectoryOut->nSpecialSlots * codeDirectoryOut->hashSize);

	uint64_t csOffset = macho_find_code_signature_offset(macho);
	macho_read_at_offset(macho, csOffset + cdOffset + lastSpecialSlotOffset, codeDirectoryOut->nSpecialSlots * codeDirectoryOut->hashSize, specialSlots);

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
				printf(" (DMG signature hash)");
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
		macho_read_at_offset(macho, csOffset + cdOffset + slotZeroOffset, codeDirectoryOut->nCodeSlots * codeDirectoryOut->hashSize, hashes);
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

void update_code_directory(MachO *macho, MemoryStream *codeDirStream)
{
	CS_CodeDirectory codeDirectory;
	memory_stream_read(codeDirStream, 0, sizeof(CS_CodeDirectory), &codeDirectory);
	CODE_DIRECTORY_APPLY_BYTE_ORDER(&codeDirectory, BIG_TO_HOST_APPLIER);
	uint32_t slotZeroOffset = codeDirectory.hashOffset;

	uint64_t lastBlobOffset = macho->machHeader.sizeofcmds + sizeof(struct mach_header_64);
    uint64_t finalPageBoundary = alignToSize(lastBlobOffset, 0x1000);
    int numberOfPagesToHash = finalPageBoundary / 0x1000;

	for (int pageNumber = 0; pageNumber < numberOfPagesToHash; pageNumber++) {
		uint64_t pageOffset = pageNumber * 0x1000;
		uint64_t pageEndOffset = pageOffset + 0x1000;
		uint64_t pageLength = 0x1000;
		if (pageEndOffset > finalPageBoundary) {
			pageLength = finalPageBoundary - pageOffset;
		}

		// Read page
		uint8_t pageData[pageLength];
		memset(pageData, 0, pageLength);
		macho_read_at_offset(macho, pageOffset, pageLength, pageData);

		// Calculate hash
		uint8_t pageHash[CC_SHA256_DIGEST_LENGTH];
		CC_SHA256(pageData, (CC_LONG)pageLength, pageHash);
	
		// Write hash to CodeDirectory
		uint32_t offsetOfBlobToReplace = slotZeroOffset + (pageNumber * codeDirectory.hashSize);
		memory_stream_write(codeDirStream, offsetOfBlobToReplace, codeDirectory.hashSize, pageHash);
	}
}