#include "CSBlob.h"

#include "CMSDecoding.h"
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

char *cs_slot_index_to_string(int magic)
{
	switch (magic)
	{
	case CSSLOT_CODEDIRECTORY:
		return "Code directory slot";
	case CSSLOT_INFOSLOT:
		return "Info slot";
	case CSSLOT_REQUIREMENTS:
		return "Requirements slot";
	case CSSLOT_RESOURCEDIR:
		return "Resource Dir slot";
	case CSSLOT_APPLICATION:
		return "Application slot";
	case CSSLOT_ENTITLEMENTS:
		return "Entitlements slot";
	case CSSLOT_DER_ENTITLEMENTS:
		return "DER entitlements slot";
	case CSSLOT_SIGNATURESLOT:
		return "Signature slot";
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
	for (int blobCount = 0; blobCount < BIG_TO_HOST(superblob->count); blobCount++)
	{
		uint32_t blobType = BIG_TO_HOST(superblob->index[blobCount].type);
    	uint32_t blobOffset = BIG_TO_HOST(superblob->index[blobCount].offset);
		printf("Slot %d: %s (offset 0x%x, type: 0x%x).\n", blobCount + 1, cs_slot_index_to_string(blobType), blobOffset + csLoadCommand.dataoff, blobType);

		if (blobType == CSSLOT_CODEDIRECTORY)
		{
			CS_CodeDirectory *codeDirectory = (CS_CodeDirectory*)((uint8_t *)superblob + blobOffset);
			printf("This is the %s, magic %#x\n", cs_blob_magic_to_string(BIG_TO_HOST(codeDirectory->magic)), BIG_TO_HOST(codeDirectory->magic));
			macho_parse_code_directory_blob(macho, blobOffset + csLoadCommand.dataoff, codeDirectory, printAllSlots, verifySlots);
		}
		else if (blobType == CSSLOT_SIGNATURESLOT) {
			CS_GenericBlob *cms_blob = (CS_GenericBlob*)((uint8_t *)superblob + blobOffset);
			printf("This is the %s, magic %#x\n", cs_blob_magic_to_string(BIG_TO_HOST(cms_blob->magic)), BIG_TO_HOST(cms_blob->magic));
			cms_data_decode((uint8_t*)cms_blob->data, cms_blob->length - 8);
		}
		else {
			CS_GenericBlob *generic_blob = (CS_GenericBlob*)((uint8_t *)superblob + blobOffset);
			printf("This is the %s, magic %#x\n", cs_blob_magic_to_string(BIG_TO_HOST(generic_blob->magic)), BIG_TO_HOST(generic_blob->magic));
		}

	}
	return 0;
}


CS_SuperBlob *macho_parse_superblob(MachO *macho, bool printAllSlots, bool verifySlots)
{
	if (!macho->isSupported)
	{
		printf("Refusing to parse superblob for unsupported macho.\n");
		return NULL;
	}
	__block CS_SuperBlob *blobOut = NULL;
	macho_enumerate_load_commands(macho, ^(struct load_command loadCommand, uint64_t offset, void *cmd, bool *stop) {
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
			//LC_CODE_SIGNATURE_APPLY_BYTE_ORDER(&csLoadCommand, LITTLE_TO_HOST_APPLIER); // TODO: Move this to macho_enumerate_load_commands impl
			printf("Code signature - offset: 0x%x, size: 0x%x.\n", csLoadCommand.dataoff, csLoadCommand.datasize);
			// Read the superblob data
			CS_SuperBlob *superblob = malloc(csLoadCommand.datasize);
			macho_read_at_offset(macho, csLoadCommand.dataoff, csLoadCommand.datasize, superblob);
			blobOut = superblob;
			//SUPERBLOB_APPLY_BYTE_ORDER(superblobOut, BIG_TO_HOST_APPLIER);
			if (BIG_TO_HOST(superblob->magic) != CSBLOB_EMBEDDED_SIGNATURE)
			{
				*stop = true;
				return;
			}
			cs_superblob_parse_blobs(macho, superblob, csLoadCommand, printAllSlots, verifySlots);
			*stop = true;
			return;
		}

		if (loadCommand.cmd == LC_SEGMENT_64) {
			struct segment_command_64 segmentCommand = *((struct segment_command_64*)cmd);
			SEGMENT_COMMAND_64_APPLY_BYTE_ORDER(&segmentCommand, LITTLE_TO_HOST_APPLIER); // TODO: Move this to macho_enumerate_load_commands impl
			printf("Found %s segment - offset: 0x%llx, size: 0x%llx.\n", segmentCommand.segname, segmentCommand.fileoff, segmentCommand.filesize);
		}
	});
	return blobOut;
}

int macho_extract_cs_to_file(MachO *macho, CS_SuperBlob *superblob)
{
	FILE *csDataFile = fopen("Code_Signature-Data", "wb+");
	fwrite(superblob, BIG_TO_HOST(superblob->length), 1, csDataFile);
	fclose(csDataFile);
	return 0;
}