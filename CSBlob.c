#include "CSBlob.h"

char *csBlobMagicToReadableString(int magic) {
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


int parseSuperBlob(MachO *macho, int sliceIndex, CS_SuperBlob *superblob) {
	uint32_t offset = macho->_slices[sliceIndex]._archDescriptor.offset + sizeof(struct mach_header_64);
	for (int j = 0; j < macho->_slices[sliceIndex]._machHeader.ncmds; j++) {
		struct load_command loadCommand = macho->_slices[sliceIndex]._loadCommands[j];
		if (strcmp(loadCommandToName(loadCommand.cmd), "LC_UNKNOWN") == 0) {
			printf("Unknown load command at load command %d, 0x%x.\n", j + 1, loadCommand.cmd);
		}
		if (strcmp(loadCommandToName(loadCommand.cmd), "LC_CODE_SIGNATURE") == 0) {
			struct lc_code_signature *codeSignature = malloc(sizeof(struct lc_code_signature));
			readMachOAtOffset(macho, offset, sizeof(struct lc_code_signature), codeSignature);
			uint32_t csBlobOffset = macho->_slices[sliceIndex]._archDescriptor.offset + codeSignature->dataoff;
			free(codeSignature);
			CS_SuperBlob superblobLocal;
			readMachOAtOffset(macho, csBlobOffset, sizeof(CS_SuperBlob), &superblobLocal);
			SUPERBLOB_APPLY_BYTE_ORDER(&superblobLocal, APPLY_BIG_TO_HOST);
			if (superblobLocal.magic != CSBLOB_EMBEDDED_SIGNATURE) {
				printf("Error: incorrect superblob magic 0x%x.\n", superblobLocal.magic);
				return -1;
			}
			for (int blobCount = 0; blobCount < superblobLocal.count; blobCount++) {
				CS_BlobIndex *blobIndex = malloc(sizeof(CS_BlobIndex));
				//                    Superblob      Start of index array                    Current blob
				uint32_t blobOffset = csBlobOffset + (__offsetof(CS_SuperBlob, index) - 4) + (blobCount * sizeof(CS_BlobIndex));
				readMachOAtOffset(macho, blobOffset, sizeof(CS_BlobIndex), blobIndex);
				BLOB_INDEX_APPLY_BYTE_ORDER(blobIndex, APPLY_BIG_TO_HOST);
				uint32_t blobMagic = 0;
				readMachOAtOffset(macho, csBlobOffset + blobIndex->offset, sizeof(uint32_t), &blobMagic);
				blobMagic = BIG_TO_HOST(blobMagic);
				if (blobMagic == CSBLOB_CODEDIRECTORY) {
					CS_CodeDirectory *codeDirectory = malloc(sizeof(CS_CodeDirectory));
					readMachOAtOffset(macho, csBlobOffset + blobIndex->offset, sizeof(CS_CodeDirectory), codeDirectory);
					CODE_DIRECTORY_APPLY_BYTE_ORDER(codeDirectory, APPLY_BIG_TO_HOST);
					printf("Blob %d: %s at 0x%x (magic 0x%x, hash offset 0x%x).\n", blobCount + 1, csBlobMagicToReadableString(blobMagic), blobIndex->offset, codeDirectory->magic, codeDirectory->hashOffset);
					free(codeDirectory);
				} else {
					printf("Blob %d: %s at 0x%x (magic 0x%x).\n", blobCount + 1, csBlobMagicToReadableString(blobMagic), blobIndex->offset, blobMagic);
				}
				free(blobIndex);
			}
            superblob = &superblobLocal;
		}
		offset += loadCommand.cmdsize;
	}
	return 0;
}