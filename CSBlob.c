#include "CSBlob.h"

char *cs_blob_magic_to_string(int magic) {
	switch (magic)
	{
		case CSBLOB_REQUIREMENT:
			return "Requirement blob";
		case CSBLOB_REQUIREMENTS:
			return "Requirements blob";
		case CSBLOB_CODEDIRECTORY:
			return "Code directory blob";
		case CSBLOB_EMBEDDED_SIGNATURE:
			return "Embedded signature blob";
		case CSBLOB_DETACHED_SIGNATURE:
			return "Detached signature blob";
		case CSBLOB_ENTITLEMENTS:
			return "Entitlements blob";
		case CSBLOB_DER_ENTITLEMENTS:
			return "DER entitlements blob";
		case CSBLOB_SIGNATURE_BLOB:
			return "Signature blob";
		default:
			return "Unknown blob type";
	}
}


int macho_parse_superblob(MachO *macho, CS_SuperBlob *superblob, int sliceIndex) {

	// Get the offset of the first load command
	uint32_t offset = macho->slices[sliceIndex].archDescriptor.offset + sizeof(struct mach_header_64);

	if (!macho->slices[sliceIndex].isSupported) {
		return -1;
	}

	// Iterate over all load commands
	for (int j = 0; j < macho->slices[sliceIndex].machHeader.ncmds; j++) {

		struct load_command loadCommand = macho->slices[sliceIndex].loadCommands[j];

		// Check if the load command is unknown
		if (strcmp(load_command_to_string(loadCommand.cmd), "LC_UNKNOWN") == 0) {
			printf("Unknown load command at load command %d, 0x%x.\n", j + 1, loadCommand.cmd);
		}

		if (strcmp(load_command_to_string(loadCommand.cmd), "LC_CODE_SIGNATURE") == 0) {

			// Create and populate the code signature load command structure
			struct lc_code_signature *codeSignature = malloc(sizeof(struct lc_code_signature));
			macho_read_at_offset(macho, offset, sizeof(struct lc_code_signature), codeSignature);
			uint32_t csBlobOffset = macho->slices[sliceIndex].archDescriptor.offset + codeSignature->dataoff;
			free(codeSignature);

			// Create and populate the CMS superblob structure
			CS_SuperBlob superblobLocal;
			macho_read_at_offset(macho, csBlobOffset, sizeof(CS_SuperBlob), &superblobLocal);
			SUPERBLOB_APPLY_BYTE_ORDER(&superblobLocal, BIG_TO_HOST_APPLIER);
			if (superblobLocal.magic != CSBLOB_EMBEDDED_SIGNATURE) {
				printf("Error: incorrect superblob magic 0x%x.\n", superblobLocal.magic);
				return -1;
			}

			// Iterate over all blobs in the superblob
			for (int blobCount = 0; blobCount < superblobLocal.count; blobCount++) {

				// Create and populate the blob index structure
				CS_BlobIndex *blobIndex = malloc(sizeof(CS_BlobIndex));
				//                    Superblob      Start of index array                    Current blob
				uint32_t blobOffset = csBlobOffset + (__offsetof(CS_SuperBlob, index) - 4) + (blobCount * sizeof(CS_BlobIndex));
				macho_read_at_offset(macho, blobOffset, sizeof(CS_BlobIndex), blobIndex);
				BLOB_INDEX_APPLY_BYTE_ORDER(blobIndex, BIG_TO_HOST_APPLIER);

				// Read the blob magic
				uint32_t blobMagic = 0;
				macho_read_at_offset(macho, csBlobOffset + blobIndex->offset, sizeof(uint32_t), &blobMagic);
				blobMagic = BIG_TO_HOST(blobMagic);

				if (blobMagic == CSBLOB_CODEDIRECTORY) {

					// Create and populate the code directory structure
					CS_CodeDirectory *codeDirectory = malloc(sizeof(CS_CodeDirectory));
					macho_read_at_offset(macho, csBlobOffset + blobIndex->offset, sizeof(CS_CodeDirectory), codeDirectory);
					CODE_DIRECTORY_APPLY_BYTE_ORDER(codeDirectory, BIG_TO_HOST_APPLIER);
					// Don't print the information again if it's being extracted this time
					if (superblob != NULL) { 
						printf("%s at 0x%x (magic 0x%x).\n", cs_blob_magic_to_string(blobMagic), blobIndex->offset, codeDirectory->magic); 
					}
					size_t slotZeroOffset = csBlobOffset + blobIndex->offset + codeDirectory->hashOffset;
					// Read the special slots and print them from lowest to highest
					uint8_t *specialSlots = malloc(codeDirectory->nSpecialSlots * codeDirectory->hashSize);
					size_t lastSpecialSlotOffset = slotZeroOffset - (codeDirectory->nSpecialSlots * codeDirectory->hashSize);
					macho_read_at_offset(macho, lastSpecialSlotOffset, codeDirectory->nSpecialSlots * codeDirectory->hashSize, specialSlots);
					// for (int i = 0; i < codeDirectory->nSpecialSlots; i++) {

					// 	// Print the slot number
					// 	int slotNumber = 0 - (codeDirectory->nSpecialSlots - i);
					// 	printf("%d: ", slotNumber);

					// 	// Print each byte of the hash
					// 	for (int j = 0; j < codeDirectory->hashSize; j++) {
					// 		printf("%02x", specialSlots[(i * codeDirectory->hashSize) + j]);
					// 	}

					// 	// Check if hash is just zeroes
					// 	bool isZero = true;
					// 	for (int j = 0; j < codeDirectory->hashSize; j++) {
					// 		if (specialSlots[(i * codeDirectory->hashSize) + j] != 0) {
					// 			isZero = false;
					// 			break;
					// 		}
					// 	}

					// 	// TrollStore TODO: Validate that hashes are correct
					// 	// Don't print the special slot name if the hash is just zeroes
					// 	if (!isZero) {
					// 		// Print the special slot name (if applicable)
					// 		if (slotNumber == -1) {
					// 			printf(" (Info.plist hash)");
					// 		} else if (slotNumber == -2) {
					// 			printf(" (Requirements blob hash)");
					// 		} else if (slotNumber == -3) {
					// 			printf(" (CodeResources hash)");
					// 		} else if (slotNumber == -4) {
					// 			printf(" (App-specific hash)");
					// 		} else if (slotNumber == -5) {
					// 			printf(" (Entitlements hash)");
					// 		} else if (slotNumber == -6) {
					// 			printf(" (Used for disk rep)");
					// 		} else if (slotNumber == -7) {
					// 			printf(" (DER entitlements hash)");
					// 		} else if (slotNumber == -8) {
					// 			printf(" (Process launch constraints hash)");
					// 		} else if (slotNumber == -9) {
					// 			printf(" (Parent process launch constraints hash)");
					// 		} else if (slotNumber == -10) {
					// 			printf(" (Responsible process launch constraints hash)");
					// 		} else if (slotNumber == -11) {
					// 			printf(" (Loaded library launch constraints hash)");
					// 		}
					// 	}

					// 	printf("\n");
					// }

					// // Clean up
					// free(specialSlots);
					
					// // Don't pollute the output with hashes if there are a lot of them
					// if (codeDirectory->nCodeSlots <= 50) {
					// 	// Create an array of hashes and print them
					// 	uint8_t *hashes = malloc(codeDirectory->nCodeSlots * codeDirectory->hashSize);
					// 	macho_read_at_offset(macho, slotZeroOffset, codeDirectory->nCodeSlots * codeDirectory->hashSize, hashes);
					// 	for (int i = 0; i < codeDirectory->nCodeSlots; i++) {

					// 		// Align the slot number for cleaner output
					// 		if (i > 9) {
					// 			printf("%d: ", i);
					// 		} else {
					// 			printf(" %d: ", i);
					// 		}

					// 		// Print each byte of the hash
					// 		for (int j = 0; j < codeDirectory->hashSize; j++) {
					// 			printf("%02x", hashes[(i * codeDirectory->hashSize) + j]);
					// 		}
					// 		printf("\n");

					// 	}

					// 	// Clean up
					// 	free(hashes);
					// }

					// Clean up
					free(codeDirectory);

				} else {
					// Don't print the information again if it's being extracted this time
					if (superblob != NULL) {
						printf("%s at 0x%x (magic 0x%x).\n", cs_blob_magic_to_string(blobMagic), blobIndex->offset, blobMagic);
					}
				}

				// Clean up
				free(blobIndex);
			}

			// NULL pointer is passed when we wants to just print blob information (see main.c)
			if (superblob != NULL) {
				memcpy(superblob, &superblobLocal, sizeof(CS_SuperBlob));
			}

			// Don't continue the loop, we found the code signature load command
			return 0;
		}

		// Adjust offset to next load command
		offset += loadCommand.cmdsize;

	}
	return -1;
}

int macho_extract_cms_to_file(MachO *macho, CS_SuperBlob *superblob, int sliceIndex) {

	// Get length of CMS from superblob and allocate memory
	size_t cmsLength = superblob->length;
	void *cmsData = malloc(cmsLength);
	uint32_t csBlobOffset = 0;

	// Get the offset of the first load command
	uint32_t offset = macho->slices[sliceIndex].archDescriptor.offset + sizeof(struct mach_header_64);

	// Find the LC_CODE_SIGNATURE load command
	for (int loadCommand = 0; loadCommand < macho->slices[sliceIndex].machHeader.ncmds; loadCommand++) {
		struct load_command currentLoadCommand = macho->slices[sliceIndex].loadCommands[loadCommand];
		if (currentLoadCommand.cmd == LC_CODE_SIGNATURE) {
			// Create and populate the code signature load command structure
			struct lc_code_signature *codeSignatureLoadCommand = malloc(sizeof(struct lc_code_signature));
			macho_read_at_offset(macho, offset, sizeof(struct lc_code_signature), codeSignatureLoadCommand);
			csBlobOffset = macho->slices[sliceIndex].archDescriptor.offset + codeSignatureLoadCommand->dataoff;
			free(codeSignatureLoadCommand);
		}
		offset += currentLoadCommand.cmdsize;
	}

	if (csBlobOffset == 0) {
		printf("Error: could not find LC_CODE_SIGNATURE load command.\n");
		return -1;
	}

	// Extract the CMS data from the MachO and write to the file
	macho_read_at_offset(macho, csBlobOffset, cmsLength, cmsData);
	FILE *cmsDataFile = fopen("CMS-Data", "wb+");
	fwrite(cmsData, cmsLength, 1, cmsDataFile);
	fclose(cmsDataFile);
	free(cmsData);
	
	return 0;
}