#include "CMSDecoding.h"


const DERItemSpec CMSSignedDataItemSpecs[] = {
    { DER_OFFSET(CMSSignedDataDER, version), ASN1_INTEGER },
    { DER_OFFSET(CMSSignedDataDER, digestAlgorithms), ASN1_CONSTR_SET },
    { DER_OFFSET(CMSSignedDataDER, contentInfo), ASN1_CONSTR_SEQUENCE },
    { DER_OFFSET(CMSSignedDataDER, certificates), ASN1_CONSTRUCTED | ASN1_CONTEXT_SPECIFIC },
    { DER_OFFSET(CMSSignedDataDER, signerInfos), ASN1_CONSTR_SET }
};

const DERItemSpec CMSContentItemSpecs[] = {
    { DER_OFFSET(CMSContentDER, signedData), ASN1_CONSTR_SEQUENCE }
};

const DERItemSpec CMSContentInfoItemSpecs[] = {
    { DER_OFFSET(CMSContentInfoDER, oid), ASN1_OBJECT_ID },
    { DER_OFFSET(CMSContentInfoDER, content), ASN1_CONSTRUCTED | ASN1_CONTEXT_SPECIFIC }
};

int decodeCMSData(uint8_t *cmsDERData, size_t cmsDERLength) {
    DERByte *cmsDERDataByte = cmsDERData;
    DERSize cmsDERDataLength = cmsDERLength;
    CMSContentInfoDER contentInfo;
    DERItem cmsDERItem = {
        .data = cmsDERDataByte,
        .length = cmsDERDataLength
    };

    DERDecodedInfo decodedCMSData;
    DERReturn ret;
    ret = DERDecodeItem(&cmsDERItem, &decodedCMSData);
    if (ret != DR_Success) {
        printf("Error: DERDecodeItem returned %d.\n", ret);
        return -1;
    }
    if (decodedCMSData.tag != ASN1_CONSTR_SEQUENCE) {
        printf("Error: CMS content info tag is not a constructed sequence, first byte 0x%x.\n", decodedCMSData.tag);
        return -1;
    }
    if (cmsDERItem.data + cmsDERItem.length != decodedCMSData.content.data + decodedCMSData.content.length) {
        printf("Error: buffer overflow when decoding CMS content info.\n");
        return -1;
    }
    ret = DERParseSequenceContent(&decodedCMSData.content, sizeof(CMSContentInfoItemSpecs)/sizeof(CMSContentInfoItemSpecs[0]), CMSContentInfoItemSpecs, &contentInfo, 0);
    if (ret != DR_Success) {
        printf("Error: DERParseSequenceContent returned %d parsing ContentInfo.\n", ret);
        return -1;
    }


    // Decode content
    CMSContentDER content;
    DERItem contentDERItem = {
        .data = contentInfo.content.data,
        .length = contentInfo.content.length
    };

    DERDecodedInfo decodedContent;
    ret = DERDecodeItem(&contentDERItem, &decodedContent);
    if (ret != DR_Success) {
        printf("Error: DERDecodeItem returned %d decoding CMS content.\n", ret);
        return -1;
    }

    if (contentDERItem.data + contentDERItem.length != decodedContent.content.data + decodedContent.content.length) {
        printf("Error: buffer overflow when decoding CMS content.\n");
        return -1;
    }

    // Decode this into SignedData
    CMSSignedDataDER signedData;
    ret = DERParseSequenceContent(&decodedContent.content, sizeof(CMSSignedDataItemSpecs)/sizeof(CMSSignedDataItemSpecs[0]), CMSSignedDataItemSpecs, &signedData, 0);
    if (ret != DR_Success) {
        printf("Error: DERParseSequenceContent returned %d parsing SignedData.\n", ret);
        return -1;
    }

    if ((uint8_t)signedData.version.data[0] != 1) {
        printf("Error: CMS version is not 1, %d.\n", (uint8_t)signedData.version.data[0]);
        return -1;
    }

    printf("Successfully decoded SignedData!\n");
    return 0;
}