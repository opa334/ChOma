#include "CSBlob.h"

char *cs_blob_magic_to_string(int magic)
{
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

// int macho_parse_superblob(MachO *macho, CS_SuperBlob *superblob, int sliceIndex) {

// 	// Get the offset of the first load command
// 	uint32_t offset = macho->slices[sliceIndex].archDescriptor.offset + sizeof(struct mach_header_64);

// 	if (!macho->slices[sliceIndex].isSupported) {
// 		return -1;
// 	}

// 	// Iterate over all load commands
// 	for (int j = 0; j < macho->slices[sliceIndex].machHeader.ncmds; j++) {

// 		struct load_command loadCommand = macho->slices[sliceIndex].loadCommands[j];

// 		// Check if the load command is unknown
// 		if (strcmp(load_command_to_string(loadCommand.cmd), "LC_UNKNOWN") == 0) {
// 			printf("Unknown load command at load command %d, 0x%x.\n", j + 1, loadCommand.cmd);
// 		}

// 		if (strcmp(load_command_to_string(loadCommand.cmd), "LC_CODE_SIGNATURE") == 0) {

// 			// Create and populate the code signature load command structure
// 			struct lc_code_signature *codeSignature = malloc(sizeof(struct lc_code_signature));
// 			memset(codeSignature, 0, sizeof(struct lc_code_signature));
// 			memory_buffer_read(&macho->buffer, offset, sizeof(struct lc_code_signature), codeSignature);
// 			uint32_t csBlobOffset = macho->slices[sliceIndex].archDescriptor.offset + codeSignature->dataoff;
// 			free(codeSignature);

// 			// Create and populate the CMS superblob structure
// 			CS_SuperBlob superblobLocal;
// 			memory_buffer_read(&macho->buffer, csBlobOffset, sizeof(CS_SuperBlob), &superblobLocal);
// 			SUPERBLOB_APPLY_BYTE_ORDER(&superblobLocal, BIG_TO_HOST_APPLIER);
// 			if (superblobLocal.magic != CSBLOB_EMBEDDED_SIGNATURE) {
// 				printf("Error: incorrect superblob magic 0x%x.\n", superblobLocal.magic);
// 				return -1;
// 			}

// 			// Iterate over all blobs in the superblob
// 			for (int blobCount = 0; blobCount < superblobLocal.count; blobCount++) {

// 				// Create and populate the blob index structure
// 				CS_BlobIndex *blobIndex = malloc(sizeof(CS_BlobIndex));
// 				memset(blobIndex, 0, sizeof(CS_BlobIndex));
// 				//                    Superblob      Start of index array                    Current blob
// 				uint32_t blobOffset = csBlobOffset + (__offsetof(CS_SuperBlob, index) - 4) + (blobCount * sizeof(CS_BlobIndex));
// 				memory_buffer_read(&macho->buffer, blobOffset, sizeof(CS_BlobIndex), blobIndex);
// 				BLOB_INDEX_APPLY_BYTE_ORDER(blobIndex, BIG_TO_HOST_APPLIER);

// 				// Read the blob magic
// 				uint32_t blobMagic = 0;
// 				memory_buffer_read(&macho->buffer, csBlobOffset + blobIndex->offset, sizeof(uint32_t), &blobMagic);
// 				blobMagic = BIG_TO_HOST(blobMagic);

// 				if (blobMagic == CSBLOB_CODEDIRECTORY) {

// 					// Create and populate the code directory structure
// 					CS_CodeDirectory *codeDirectory = malloc(sizeof(CS_CodeDirectory));
// 					memset(codeDirectory, 0, sizeof(CS_CodeDirectory));
// 					memory_buffer_read(&macho->buffer, csBlobOffset + blobIndex->offset, sizeof(CS_CodeDirectory), codeDirectory);
// 					CODE_DIRECTORY_APPLY_BYTE_ORDER(codeDirectory, BIG_TO_HOST_APPLIER);
// 					// Don't print the information again if it's being extracted this time
// 					if (superblob != NULL) {
// 						printf("%s at 0x%x (magic 0x%x).\n", cs_blob_magic_to_string(blobMagic), blobIndex->offset, codeDirectory->magic);
// 					}
// 					size_t slotZeroOffset = csBlobOffset + blobIndex->offset + codeDirectory->hashOffset;
// 					// Read the special slots and print them from lowest to highest
// 					uint8_t *specialSlots = malloc(codeDirectory->nSpecialSlots * codeDirectory->hashSize);
// 					memset(specialSlots, 0, codeDirectory->nSpecialSlots * codeDirectory->hashSize);
// 					size_t lastSpecialSlotOffset = slotZeroOffset - (codeDirectory->nSpecialSlots * codeDirectory->hashSize);
// 					memory_buffer_read(&macho->buffer, lastSpecialSlotOffset, codeDirectory->nSpecialSlots * codeDirectory->hashSize, specialSlots);
// 					// for (int i = 0; i < codeDirectory->nSpecialSlots; i++) {

// 					// 	// Print the slot number
// 					// 	int slotNumber = 0 - (codeDirectory->nSpecialSlots - i);
// 					// 	printf("%d: ", slotNumber);

// 					// 	// Print each byte of the hash
// 					// 	for (int j = 0; j < codeDirectory->hashSize; j++) {
// 					// 		printf("%02x", specialSlots[(i * codeDirectory->hashSize) + j]);
// 					// 	}

// 					// 	// Check if hash is just zeroes
// 					// 	bool isZero = true;
// 					// 	for (int j = 0; j < codeDirectory->hashSize; j++) {
// 					// 		if (specialSlots[(i * codeDirectory->hashSize) + j] != 0) {
// 					// 			isZero = false;
// 					// 			break;
// 					// 		}
// 					// 	}

// 					// 	// TrollStore TODO: Validate that hashes are correct
// 					// 	// Don't print the special slot name if the hash is just zeroes
// 					// 	if (!isZero) {
// 					// 		// Print the special slot name (if applicable)
// 					// 		if (slotNumber == -1) {
// 					// 			printf(" (Info.plist hash)");
// 					// 		} else if (slotNumber == -2) {
// 					// 			printf(" (Requirements blob hash)");
// 					// 		} else if (slotNumber == -3) {
// 					// 			printf(" (CodeResources hash)");
// 					// 		} else if (slotNumber == -4) {
// 					// 			printf(" (App-specific hash)");
// 					// 		} else if (slotNumber == -5) {
// 					// 			printf(" (Entitlements hash)");
// 					// 		} else if (slotNumber == -6) {
// 					// 			printf(" (Used for disk rep)");
// 					// 		} else if (slotNumber == -7) {
// 					// 			printf(" (DER entitlements hash)");
// 					// 		} else if (slotNumber == -8) {
// 					// 			printf(" (Process launch constraints hash)");
// 					// 		} else if (slotNumber == -9) {
// 					// 			printf(" (Parent process launch constraints hash)");
// 					// 		} else if (slotNumber == -10) {
// 					// 			printf(" (Responsible process launch constraints hash)");
// 					// 		} else if (slotNumber == -11) {
// 					// 			printf(" (Loaded library launch constraints hash)");
// 					// 		}
// 					// 	}

// 					// 	printf("\n");
// 					// }

// 					// // Clean up
// 					// free(specialSlots);

// 					// // Don't pollute the output with hashes if there are a lot of them
// 					// if (codeDirectory->nCodeSlots <= 50) {
// 					// 	// Create an array of hashes and print them
// 					//  uint8_t *hashes = malloc(codeDirectory->nCodeSlots * codeDirectory->hashSize);
// 					//  memset(hashes, 0 codeDirectory->nCodeSlots * codeDirectory->hashSize);
// 					//  memory_buffer_read(&macho->buffer, slotZeroOffset, codeDirectory->nCodeSlots * codeDirectory->hashSize, hashes);
// 					// 	for (int i = 0; i < codeDirectory->nCodeSlots; i++) {

// 					// 		// Align the slot number for cleaner output
// 					// 		if (i > 9) {
// 					// 			printf("%d: ", i);
// 					// 		} else {
// 					// 			printf(" %d: ", i);
// 					// 		}

// 					// 		// Print each byte of the hash
// 					// 		for (int j = 0; j < codeDirectory->hashSize; j++) {
// 					// 			printf("%02x", hashes[(i * codeDirectory->hashSize) + j]);
// 					// 		}
// 					// 		printf("\n");

// 					// 	}

// 					// 	// Clean up
// 					// 	free(hashes);
// 					// }

// 					// Clean up
// 					free(codeDirectory);

// 				} else {
// 					// Don't print the information again if it's being extracted this time
// 					if (superblob != NULL) {
// 						printf("%s at 0x%x (magic 0x%x).\n", cs_blob_magic_to_string(blobMagic), blobIndex->offset, blobMagic);
// 					}
// 				}

// 				// Clean up
// 				free(blobIndex);
// 			}

// 			// NULL pointer is passed when we wants to just print blob information (see main.c)
// 			if (superblob != NULL) {
// 				memcpy(superblob, &superblobLocal, sizeof(CS_SuperBlob));
// 			}

// 			// Don't continue the loop, we found the code signature load command
// 			return 0;
// 		}

// 		// Adjust offset to next load command
// 		offset += loadCommand.cmdsize;

// 	}
// 	return -1;
// }


int macho_slice_parse_code_directory_blob(MachOSlice *slice, uint32_t codeDirectoryOffset, CS_CodeDirectory *codeDirectoryOut, bool printSlots)
{
	if (macho_slice_read_at_offset(slice, codeDirectoryOffset, sizeof(CS_CodeDirectory), codeDirectoryOut) != 0)
	{
		return -1;
	}
	CODE_DIRECTORY_APPLY_BYTE_ORDER(codeDirectoryOut, BIG_TO_HOST_APPLIER);

	uint32_t slotZeroOffset = codeDirectoryOffset + codeDirectoryOut->hashOffset;
	uint8_t *specialSlots = malloc(codeDirectoryOut->nSpecialSlots * codeDirectoryOut->hashSize);
	memset(specialSlots, 0, codeDirectoryOut->nSpecialSlots * codeDirectoryOut->hashSize);
	size_t lastSpecialSlotOffset = slotZeroOffset - (codeDirectoryOut->nSpecialSlots * codeDirectoryOut->hashSize);
	macho_slice_read_at_offset(slice, lastSpecialSlotOffset, codeDirectoryOut->nSpecialSlots * codeDirectoryOut->hashSize, specialSlots);

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
		// validateHashes(slice, specialSlots, codeDirectoryOut->nSpecialSlots * codeDirectoryOut->hashSize);
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

	return 0;
}

int macho_slice_parse_signature_blob_to_der(MachOSlice *slice, uint32_t signatureBlobOffset, uint32_t signatureBlobLength, void *outputDER)
{
	return macho_slice_read_at_offset(slice, signatureBlobOffset + 8, signatureBlobLength - 8, outputDER);
}


int cs_superblob_parse_blobs(MachOSlice *slice, CS_SuperBlob *superblob, struct lc_code_signature csLoadCommand)
{
	for (int blobCount = 0; blobCount < superblob->count; blobCount++)
	{
		CS_BlobIndex *blobIndex = malloc(sizeof(CS_BlobIndex));
		memset(blobIndex, 0, sizeof(CS_BlobIndex));
		uint32_t blobOffset = csLoadCommand.dataoff + (__offsetof(CS_SuperBlob, index) - 4) + (blobCount * sizeof(CS_BlobIndex));

		// Blob offset is correct, but for some reason the MachO slice read always returns zeroes?

		// Read the blob index
		macho_slice_read_at_offset(slice, blobOffset, sizeof(CS_BlobIndex), blobIndex);
		BLOB_INDEX_APPLY_BYTE_ORDER(blobIndex, BIG_TO_HOST_APPLIER);

		// Read the blob magic
		uint32_t blobMagic = 0;
		
		macho_slice_read_at_offset(slice, csLoadCommand.dataoff + blobIndex->offset, sizeof(blobMagic), &blobMagic);
		blobMagic = BIG_TO_HOST(blobMagic);

		if (blobMagic == CSBLOB_CODEDIRECTORY)
		{
			printf("Blob %d: %s (offset 0x%x, magic 0x%x).\n", blobCount + 1, cs_blob_magic_to_string(blobMagic), csLoadCommand.dataoff + blobIndex->offset, blobMagic);
			CS_CodeDirectory *codeDirectory = malloc(sizeof(CS_CodeDirectory));
			macho_slice_parse_code_directory_blob(slice, csLoadCommand.dataoff + blobIndex->offset, codeDirectory, true);
		}

		// if (blobMagic == CSBLOB_SIGNATURE_BLOB)
		else
		{
			printf("Blob %d: %s (offset 0x%x, magic: 0x%x).\n", blobCount + 1, cs_blob_magic_to_string(blobMagic), csLoadCommand.dataoff + blobIndex->offset, blobMagic);
		}

	}
	return 0;
}


int macho_slice_parse_superblob(MachOSlice *slice, CS_SuperBlob *superblobOut)
{
	if (!slice->isSupported)
	{
		printf("Refusing to parse superblob for unsupported slice.\n");
		return -1;
	}

	// Get the offset of the first load command
	uint32_t readOffset = sizeof(struct mach_header_64);

	// Iterate over all load commands
	for (int loadCommandCount = 0; loadCommandCount < slice->machHeader.ncmds; loadCommandCount++)
	{

		struct load_command currentCommand = slice->loadCommands[loadCommandCount];
		if (strcmp(load_command_to_string(currentCommand.cmd), "LC_UNKNOWN") == 0)
		{
			printf("Ignoring unknown command: 0x%x", currentCommand.cmd);
		}

		// Find LC_CODE_SIGNATURE
		if (currentCommand.cmd == LC_CODE_SIGNATURE)
		{
			printf("Found code signature load command.\n");
			if (currentCommand.cmdsize != sizeof(struct lc_code_signature)) {
				printf("Code signature load command has invalid size: 0x%x (vs 0x%lx)\n", currentCommand.cmdsize, sizeof(struct lc_code_signature));
				return -1;
			}

			// Create and populate the code signature load command structure
			struct lc_code_signature csLoadCommand = { 0 };
			macho_slice_read_at_offset(slice, readOffset, sizeof(csLoadCommand), &csLoadCommand);
			LC_CODE_SIGNATURE_APPLY_BYTE_ORDER(&csLoadCommand, LITTLE_TO_HOST_APPLIER);
			printf("Code signature - offset: 0x%x, size: 0x%x.\n", csLoadCommand.dataoff, csLoadCommand.datasize);

			// Read the superblob data
			macho_slice_read_at_offset(slice, csLoadCommand.dataoff, sizeof(CS_SuperBlob), superblobOut);
			SUPERBLOB_APPLY_BYTE_ORDER(superblobOut, BIG_TO_HOST_APPLIER);
			if (superblobOut->magic != CSBLOB_EMBEDDED_SIGNATURE)
			{
				printf("Error: incorrect superblob magic 0x%x.\n", superblobOut->magic);
				return -1;
			}

			cs_superblob_parse_blobs(slice, superblobOut, csLoadCommand);

			return 0;
		}

		if (currentCommand.cmd == LC_SEGMENT_64) {
			struct segment_command_64 segmentCommand;
			macho_slice_read_at_offset(slice, readOffset, sizeof(segmentCommand), &segmentCommand);
			SEGMENT_COMMAND_64_APPLY_BYTE_ORDER(&segmentCommand, LITTLE_TO_HOST_APPLIER);
			printf("Found %s segment - offset: 0x%llx, size: 0x%llx.\n", segmentCommand.segname, segmentCommand.fileoff, segmentCommand.filesize);
		}
		readOffset += currentCommand.cmdsize;
	}
	return -1;
}

int macho_extract_cms_to_file(MachO *macho, CS_SuperBlob *superblob, int sliceIndex)
{

	// Get length of CMS from superblob and allocate memory
	size_t cmsLength = superblob->length;
	void *cmsData = malloc(cmsLength);
	memset(cmsData, 0, cmsLength);
	uint32_t csBlobOffset = 0;

	// Get the offset of the first load command
	uint32_t offset = macho->slices[sliceIndex].archDescriptor.offset + sizeof(struct mach_header_64);

	// Find the LC_CODE_SIGNATURE load command
	for (int loadCommand = 0; loadCommand < macho->slices[sliceIndex].machHeader.ncmds; loadCommand++)
	{
		struct load_command currentLoadCommand = macho->slices[sliceIndex].loadCommands[loadCommand];
		if (currentLoadCommand.cmd == LC_CODE_SIGNATURE)
		{
			// Create and populate the code signature load command structure
			struct lc_code_signature *codeSignatureLoadCommand = malloc(sizeof(struct lc_code_signature));
			memset(codeSignatureLoadCommand, 0, sizeof(struct lc_code_signature));
			memory_buffer_read(&macho->buffer, offset, sizeof(struct lc_code_signature), codeSignatureLoadCommand);
			csBlobOffset = macho->slices[sliceIndex].archDescriptor.offset + codeSignatureLoadCommand->dataoff;
			free(codeSignatureLoadCommand);
		}
		offset += currentLoadCommand.cmdsize;
	}

	if (csBlobOffset == 0)
	{
		printf("Error: could not find LC_CODE_SIGNATURE load command.\n");
		return -1;
	}

	// Extract the CMS data from the MachO and write to the file
	memory_buffer_read(&macho->buffer, csBlobOffset, cmsLength, cmsData);
	FILE *cmsDataFile = fopen("CMS-Data", "wb+");
	fwrite(cmsData, cmsLength, 1, cmsDataFile);
	fclose(cmsDataFile);
	free(cmsData);

	return 0;
}