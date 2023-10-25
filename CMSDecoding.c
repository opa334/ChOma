#include "CMSDecoding.h"

int decodeCMSData(uint8_t *cmsDERData, size_t cmsDERLength) {
    DERByte *cmsDERDataByte = cmsDERData;
    DERSize cmsDERDataLength = cmsDERLength;
    CMSContentInfoDER contentInfo;
    DERItem cmsDERItem = {
        .data = cmsDERDataByte,
        .length = cmsDERDataLength
    };

    DERDecodedInfo decodedContentInfo;
    DERReturn ret;
    ret = DERDecodeItem(&cmsDERItem, &decodedContentInfo);
    if (ret != DR_Success) {
        printf("Error: DERDecodeItem returned %d decoding ContentInfo.\n", ret);
        return -1;
    }
    if (cmsDERItem.data + cmsDERItem.length != decodedContentInfo.content.data + decodedContentInfo.content.length) {
        printf("Error: buffer overflow when decoding CMS content info.\n");
        return -1;
    }
    ret = DERParseSequenceContent(&decodedContentInfo.content, sizeof(CMSContentInfoItemSpecs)/sizeof(CMSContentInfoItemSpecs[0]), CMSContentInfoItemSpecs, &contentInfo, 0);
    if (ret != DR_Success) {
        printf("Error: DERParseSequenceContent returned %d parsing ContentInfo.\n", ret);
        return -1;
    }
    printf("Successfully decoded ContentInfo!\n");

    // Decode SignedData
    CMSSignedDataDER signedData;
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
    ret = DERParseSequenceContent(&decodedContent.content, sizeof(CMSSignedDataItemSpecs)/sizeof(CMSSignedDataItemSpecs[0]), CMSSignedDataItemSpecs, &signedData, 0);
    if (ret != DR_Success) {
        printf("Error: DERParseSequenceContent returned %d parsing SignedData.\n", ret);
        return -1;
    }
    printf("Successfully decoded SignedData!\n");

    // Decode SignerInfos (there should only be one)
    CMSSignerInfoDER signerInfo;
    DERItem signerInfosDERItem = {
        .data = signedData.signerInfos.data,
        .length = signedData.signerInfos.length
    };

    DERTag tag;
    DERSequence seq;
    ret = DERDecodeSeqInit(&signerInfosDERItem, &tag, &seq);
    if (ret != DR_Success) {
        printf("Error: DERParseSequenceContent returned %d parsing SignerInfos set.\n", ret);
        return -1;
    }
     if (tag != ASN1_CONSTR_SEQUENCE) {
        printf("SignerInfos is not a sequence.\n");
        return -1;
    }

    DERDecodedInfo decodedSignerInfo;
    ret = DERDecodeSeqNext(&seq, &decodedSignerInfo);
    if (ret != DR_Success) {
        printf("Error: DERParseSequenceContent returned %d parsing SignerInfo.\n", ret);
        return -1;
    }
    if (seq.nextItem == seq.end) {
        printf("Error: there is more than one SignerInfo - this should not happen...\n");
        return -1;
    }

    printf("Successfully decoded SignerInfo!\n");

    if (signedData.certificates.length < 1) {
        printf("Error: SignedData contains no certificates!\n");
        return -1;
    }

    printf("Done decoding DER CMS data!\n");
    return 0;
}