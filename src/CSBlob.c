#include "CSBlob.h"

#include "CodeDirectory.h"
#include "MachO.h"
#include "MachOByteOrder.h"
#include "MachOLoadCommand.h"
#include "BufferedStream.h"
#include "MemoryStream.h"
#include "FileStream.h"
#include <mach-o/loader.h>
#include <stddef.h>

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
	case CSSLOT_ALTERNATE_CODEDIRECTORIES:
		return "Alternate code directory slot";
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

int decodedsuperblob_parse_blobs(MachO *macho, CS_DecodedSuperBlob *decodedSuperblob, bool printAllSlots, bool verifySlots)
{
	CS_DecodedBlob *currentBlob = decodedSuperblob->firstBlob;
	int count = 0;
    while (currentBlob->next) {
		uint32_t blobType = currentBlob->type;
		printf("Slot %d: %s (offset 0x%x, type: 0x%x).\n", count++, cs_slot_index_to_string(blobType), currentBlob->offset, blobType);

		if (blobType == CSSLOT_CODEDIRECTORY || blobType == CSSLOT_ALTERNATE_CODEDIRECTORIES)
		{
			CS_CodeDirectory *codeDirectory = malloc(sizeof(CS_CodeDirectory));
			memset(codeDirectory, 0, sizeof(CS_CodeDirectory));
			memory_stream_read(currentBlob->stream, 0, sizeof(CS_CodeDirectory), codeDirectory);
			CODE_DIRECTORY_APPLY_BYTE_ORDER(codeDirectory, BIG_TO_HOST_APPLIER);
			printf("This is the %s, magic %#x.\n", cs_blob_magic_to_string(codeDirectory->magic), codeDirectory->magic);
			macho_parse_code_directory_blob(macho, codeDirectory, currentBlob->offset, printAllSlots, verifySlots);
		}
		else if (blobType == CSSLOT_SIGNATURESLOT) {
			CS_GenericBlob *cms_blob = malloc(sizeof(CS_GenericBlob));
			memset(cms_blob, 0, sizeof(CS_GenericBlob));
			memory_stream_read(currentBlob->stream, 0, sizeof(CS_GenericBlob), cms_blob);
			GENERIC_BLOB_APPLY_BYTE_ORDER(cms_blob, BIG_TO_HOST_APPLIER);
			printf("This is the %s, magic %#x.\n", cs_blob_magic_to_string(cms_blob->magic), cms_blob->magic);
		}
		else {
			CS_GenericBlob *generic_blob = malloc(sizeof(CS_GenericBlob));
			memset(generic_blob, 0, sizeof(CS_GenericBlob));
			memory_stream_read(currentBlob->stream, 0, sizeof(CS_GenericBlob), generic_blob);
			GENERIC_BLOB_APPLY_BYTE_ORDER(generic_blob, BIG_TO_HOST_APPLIER);
			printf("This is the %s, magic %#x.\n", cs_blob_magic_to_string(generic_blob->magic), generic_blob->magic);
		}
		currentBlob = currentBlob->next;
	}
	return 0;
}

void macho_find_code_signature_bounds(MachO *macho, uint32_t *offsetOut, uint32_t *sizeOut)
{
	macho_enumerate_load_commands(macho, ^(struct load_command loadCommand, uint64_t offset, void *cmd, bool *stop) {
		if (loadCommand.cmd == LC_CODE_SIGNATURE) {
			struct linkedit_data_command *csLoadCommand = ((struct linkedit_data_command *)cmd);
			LINKEDIT_DATA_COMMAND_APPLY_BYTE_ORDER(csLoadCommand, LITTLE_TO_HOST_APPLIER);
			if (offsetOut) *offsetOut = csLoadCommand->dataoff;
			if (sizeOut) *sizeOut = csLoadCommand->datasize;
			*stop = true;
		}
	});
}

CS_SuperBlob *macho_read_code_signature(MachO *macho)
{
	uint32_t offset = 0, size = 0;
	macho_find_code_signature_bounds(macho, &offset, &size);
	
	CS_SuperBlob *dataOut = malloc(size);
	macho_read_at_offset(macho, offset, size, dataOut);
	return dataOut;
}

int macho_replace_code_signature(MachO *macho, CS_SuperBlob *superblob)
{
	uint32_t csSegmentOffset = 0, csSegmentSize = 0;
	macho_find_code_signature_bounds(macho, &csSegmentOffset, &csSegmentSize);

	uint32_t sizeOfCodeSignature = 0;
	memory_stream_read(macho->stream, csSegmentOffset + offsetof(CS_SuperBlob, length), sizeof(sizeOfCodeSignature), &sizeOfCodeSignature);
	sizeOfCodeSignature = BIG_TO_HOST(sizeOfCodeSignature);

	uint64_t newCodeSignatureSize = BIG_TO_HOST(superblob->length);

    // See how much space we have to write the new code signature
    uint64_t entireFileSize = memory_stream_get_size(macho->stream);
    uint64_t freeSpace = entireFileSize - csSegmentOffset;
    uint64_t paddingSize = freeSpace - sizeOfCodeSignature;

    if (newCodeSignatureSize >= freeSpace) {
        macho_write_at_offset(macho, csSegmentOffset, newCodeSignatureSize, superblob);
        uint8_t padding[paddingSize];
        memset(padding, 0, paddingSize);
        macho_write_at_offset(macho, csSegmentOffset + newCodeSignatureSize, paddingSize, padding);
    } else if (newCodeSignatureSize < freeSpace) {
        memory_stream_trim(macho_get_stream(macho), 0, entireFileSize-csSegmentOffset);
        macho_write_at_offset(macho, csSegmentOffset, newCodeSignatureSize, superblob);
        uint8_t padding[paddingSize];
        memset(padding, 0, paddingSize);
        macho_write_at_offset(macho, csSegmentOffset + newCodeSignatureSize, paddingSize, padding);
    }

	return 0;
}

int macho_extract_cs_to_file(MachO *macho, CS_SuperBlob *superblob)
{
	FILE *csDataFile = fopen("Code_Signature-Data", "wb+");
	fwrite(superblob, BIG_TO_HOST(superblob->length), 1, csDataFile);
	fclose(csDataFile);
	return 0;
}

CS_DecodedSuperBlob *superblob_decode(CS_SuperBlob *superblob)
{
	CS_DecodedSuperBlob *decodedSuperblob = malloc(sizeof(CS_DecodedSuperBlob));
	if (!decodedSuperblob) return NULL;
	memset(decodedSuperblob, 0, sizeof(CS_DecodedSuperBlob));

	CS_DecodedBlob **nextBlob = &decodedSuperblob->firstBlob;
	decodedSuperblob->magic = BIG_TO_HOST(superblob->magic);

	for (uint32_t i = 0; i < BIG_TO_HOST(superblob->count); i++) {
		CS_BlobIndex curIndex = superblob->index[i];
		BLOB_INDEX_APPLY_BYTE_ORDER(&curIndex, BIG_TO_HOST_APPLIER);
		printf("decoding %u (type: %x, offset: 0x%x)\n", i, curIndex.type, curIndex.offset);

		CS_GenericBlob *start = (CS_GenericBlob *)(((uint8_t*)superblob) + curIndex.offset);

		MemoryStream *stream = buffered_stream_init_from_buffer(start, BIG_TO_HOST(start->length), BUFFERED_STREAM_FLAG_AUTO_EXPAND);
		if (!stream) {
			decoded_superblob_free(decodedSuperblob);
			return NULL;
		}

		*nextBlob = malloc(sizeof(CS_DecodedBlob));
		(*nextBlob)->stream = stream;
		(*nextBlob)->next = NULL;
		(*nextBlob)->type = curIndex.type;
		(*nextBlob)->offset = curIndex.offset;
		nextBlob = &(*nextBlob)->next;
	}
	return decodedSuperblob;
}

void superblob_fixup_lengths(CS_DecodedSuperBlob *decodedSuperblob)
{
	CS_DecodedBlob *nextBlob = decodedSuperblob->firstBlob;
	while (nextBlob) {
		MemoryStream *curStream = nextBlob->stream;
		uint32_t curSize = HOST_TO_BIG((uint32_t)memory_stream_get_size(curStream));
		memory_stream_write(curStream, offsetof(CS_GenericBlob, length), sizeof(curSize), &curSize);

		nextBlob = nextBlob->next;
	}
}

CS_SuperBlob *superblob_encode(CS_DecodedSuperBlob *decodedSuperblob)
{
	superblob_fixup_lengths(decodedSuperblob);
	uint32_t blobCount = 0, blobSize = 0;

	// Determine amount and size of contained blobs
	CS_DecodedBlob *nextBlob = decodedSuperblob->firstBlob;
	while (nextBlob) {
		blobCount++;
		blobSize += memory_stream_get_size(nextBlob->stream);
		nextBlob = nextBlob->next;
	}

	uint32_t superblobLength = sizeof(CS_SuperBlob) + (sizeof(CS_BlobIndex) * blobCount) + blobSize;
	CS_SuperBlob *superblob = malloc(superblobLength);

	// Populate superblob fields
	superblob->count = blobCount;
	superblob->length = superblobLength;
	superblob->magic = decodedSuperblob->magic;
	SUPERBLOB_APPLY_BYTE_ORDER(superblob, HOST_TO_BIG_APPLIER)

	// Populate indexes and write actual backing data
	uint32_t idx = 0;
	uint32_t dataStartOffset = sizeof(CS_SuperBlob) + (sizeof(CS_BlobIndex) * blobCount);
	uint8_t *superblobData = ((uint8_t*)superblob) + dataStartOffset;
	uint8_t *superblobDataCur = superblobData;
	nextBlob = decodedSuperblob->firstBlob;
	while (nextBlob) {
		CS_BlobIndex *curIndex = &superblob->index[idx];
		MemoryStream *curStream = nextBlob->stream;
		uint32_t curSize = memory_stream_get_size(curStream);

		memory_stream_read(curStream, 0, curSize, superblobDataCur);

		curIndex->offset = dataStartOffset + (superblobDataCur - superblobData);
		curIndex->type = nextBlob->type;
		BLOB_INDEX_APPLY_BYTE_ORDER(curIndex, HOST_TO_BIG_APPLIER);

		superblobDataCur += curSize;
		idx++;

		nextBlob = nextBlob->next;
	}
	return superblob;
}

void decoded_superblob_free(CS_DecodedSuperBlob *decodedSuperblob)
{
	CS_DecodedBlob *nextBlob = decodedSuperblob->firstBlob;
	while (nextBlob) {
		CS_DecodedBlob *prevBlob = nextBlob;
		nextBlob = nextBlob->next;
		if (prevBlob->stream) {
			memory_stream_free(prevBlob->stream);
		}
		free(prevBlob);
	}
	free(decodedSuperblob);
}

uint64_t alignToSize(int size, int alignment)
{
	return (size + alignment - 1) & ~(alignment - 1);
}

int update_load_commands(MachO *macho, CS_SuperBlob *superblob, uint64_t originalSize) {
	macho_enumerate_load_commands(macho, ^(struct load_command loadCommand, uint64_t offset, void *cmd, bool *stop) {
		bool foundOne = false;
		if (loadCommand.cmd == LC_SEGMENT_64) {
			struct segment_command_64 *segmentCommand = ((struct segment_command_64 *)cmd);
			SEGMENT_COMMAND_64_APPLY_BYTE_ORDER(segmentCommand, LITTLE_TO_HOST_APPLIER); // TODO: Move this to macho_enumerate_load_commands impl
			if (strcmp(segmentCommand->segname, "__LINKEDIT") != 0) return;
			uint64_t difference = segmentCommand->filesize - originalSize;
			uint64_t newFileSize = (uint64_t)(superblob->length >> 0x10) + difference;
			uint64_t newVMSize = alignToSize(newFileSize, 0x4000);
			printf("Updating %s segment - offset: 0x%llx, filesize: 0x%llx, vmsize: 0x%llx.\n", segmentCommand->segname, segmentCommand->fileoff, newFileSize, newVMSize);
			*stop = foundOne;
			foundOne = true;
		}
		if (loadCommand.cmd == LC_CODE_SIGNATURE) {
			struct linkedit_data_command *csLoadCommand = ((struct linkedit_data_command *)cmd);
			LINKEDIT_DATA_COMMAND_APPLY_BYTE_ORDER(csLoadCommand, LITTLE_TO_HOST_APPLIER);
			csLoadCommand->datasize = superblob->length;
			// LINKEDIT_DATA_COMMAND_APPLY_BYTE_ORDER(csLoadCommand, HOST_TO_LITTLE_APPLIER);
			printf("Updating code signature load command - offset: 0x%x, size: 0x%x.\n", csLoadCommand->dataoff, HOST_TO_BIG(csLoadCommand->datasize));
			*stop = foundOne;
			foundOne = true;
		}
	});
	return 0;
}