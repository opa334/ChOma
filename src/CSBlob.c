#include "CSBlob.h"

#include "CodeDirectory.h"
#include "MachOByteOrder.h"
#include "MachOLoadCommand.h"

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

int macho_parse_signature_blob_to_der_encoded_data(MachO *macho, uint32_t signatureBlobOffset, uint32_t signatureBlobLength, void *outputDER)
{
	return macho_read_at_offset(macho, signatureBlobOffset + 8, signatureBlobLength - 8, outputDER);
}

int cs_superblob_parse_blobs(MachO *macho, CS_SuperBlob *superblob, struct lc_code_signature csLoadCommand, bool printAllSlots, bool verifySlots)
{
	for (int blobCount = 0; blobCount < superblob->count; blobCount++)
	{
		CS_BlobIndex *blobIndex = malloc(sizeof(CS_BlobIndex));
		memset(blobIndex, 0, sizeof(CS_BlobIndex));
		uint32_t blobOffset = csLoadCommand.dataoff + (__offsetof(CS_SuperBlob, index) - 4) + (blobCount * sizeof(CS_BlobIndex));

		// Read the blob index
		macho_read_at_offset(macho, blobOffset, sizeof(CS_BlobIndex), blobIndex);
		BLOB_INDEX_APPLY_BYTE_ORDER(blobIndex, BIG_TO_HOST_APPLIER);

		// Read the blob magic
		uint32_t blobMagic = 0;
		
		macho_read_at_offset(macho, csLoadCommand.dataoff + blobIndex->offset, sizeof(blobMagic), &blobMagic);
		blobMagic = BIG_TO_HOST(blobMagic);

		if (blobMagic == CSBLOB_CODEDIRECTORY)
		{
			printf("Blob %d: %s (offset 0x%x, magic 0x%x).\n", blobCount + 1, cs_blob_magic_to_string(blobMagic), csLoadCommand.dataoff + blobIndex->offset, blobMagic);
			CS_CodeDirectory *codeDirectory = malloc(sizeof(CS_CodeDirectory));
			macho_parse_code_directory_blob(macho, csLoadCommand.dataoff + blobIndex->offset, codeDirectory, printAllSlots, verifySlots);
		}

		// if (blobMagic == CSBLOB_SIGNATURE_BLOB)
		else
		{
			printf("Blob %d: %s (offset 0x%x, magic: 0x%x).\n", blobCount + 1, cs_blob_magic_to_string(blobMagic), csLoadCommand.dataoff + blobIndex->offset, blobMagic);
		}

	}
	return 0;
}


int macho_parse_superblob(MachO *macho, CS_SuperBlob *superblobOut, bool printAllSlots, bool verifySlots)
{
	if (!macho->isSupported)
	{
		printf("Refusing to parse superblob for unsupported macho.\n");
		return -1;
	}

	__block int ret = -1;
	macho_enumerate_load_commands(macho, ^(struct load_command loadCommand, uint32_t offset, void *cmd, bool *stop) {
		// Find LC_CODE_SIGNATURE
		if (loadCommand.cmd == LC_CODE_SIGNATURE)
		{
			printf("Found code signature load command.\n");
			if (loadCommand.cmdsize != sizeof(struct lc_code_signature)) {
				printf("Code signature load command has invalid size: 0x%x (vs 0x%lx)\n", loadCommand.cmdsize, sizeof(struct lc_code_signature));
				*stop = true;
				return;
			}

			// Create and populate the code signature load command structure
			struct lc_code_signature csLoadCommand = *((struct lc_code_signature *)cmd);
			LC_CODE_SIGNATURE_APPLY_BYTE_ORDER(&csLoadCommand, LITTLE_TO_HOST_APPLIER); // TODO: Move this to macho_enumerate_load_commands impl
			printf("Code signature - offset: 0x%x, size: 0x%x.\n", csLoadCommand.dataoff, csLoadCommand.datasize);

			// Read the superblob data
			macho_read_at_offset(macho, csLoadCommand.dataoff, sizeof(CS_SuperBlob), superblobOut);
			SUPERBLOB_APPLY_BYTE_ORDER(superblobOut, BIG_TO_HOST_APPLIER);
			if (superblobOut->magic != CSBLOB_EMBEDDED_SIGNATURE)
			{
				*stop = true;
				return;
			}

			cs_superblob_parse_blobs(macho, superblobOut, csLoadCommand, printAllSlots, verifySlots);

			ret = 0;
			*stop = true;
			return;
		}

		if (loadCommand.cmd == LC_SEGMENT_64) {
			struct segment_command_64 segmentCommand = *((struct segment_command_64*)cmd);
			SEGMENT_COMMAND_64_APPLY_BYTE_ORDER(&segmentCommand, LITTLE_TO_HOST_APPLIER); // TODO: Move this to macho_enumerate_load_commands impl
			printf("Found %s segment - offset: 0x%llx, size: 0x%llx.\n", segmentCommand.segname, segmentCommand.fileoff, segmentCommand.filesize);
		}
	});
	return ret;
}

int macho_extract_cms_to_file(MachO *macho, CS_SuperBlob *superblob)
{
	// Get length of CMS from superblob and allocate memory
	size_t cmsLength = superblob->length;
	void *cmsData = malloc(cmsLength);
	memset(cmsData, 0, cmsLength);
	__block uint32_t csBlobOffset = 0;

	macho_enumerate_load_commands(macho, ^(struct load_command loadCommand, uint32_t offset, void *cmd, bool *stop) {
		if (loadCommand.cmd == LC_CODE_SIGNATURE) {
			struct lc_code_signature csLoadCommand = *((struct lc_code_signature *)cmd);
			LC_CODE_SIGNATURE_APPLY_BYTE_ORDER(&csLoadCommand, LITTLE_TO_HOST_APPLIER);
			csBlobOffset = csLoadCommand.dataoff;
			*stop = true;
		}
	});

	if (csBlobOffset == 0)
	{
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