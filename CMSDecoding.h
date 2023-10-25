#ifndef CMS_DECODING_H
#define CMS_DECODING_H

#include "SignatureBlob.h"

static const DERItemSpec CMSContentInfoItemSpecs[] = {
    { DER_OFFSET(CMSContentInfoDER, contentType), ASN1_OBJECT_ID, 0 },
    { DER_OFFSET(CMSContentInfoDER, content), ASN1_CONSTRUCTED | ASN1_CONTEXT_SPECIFIC, 0 }
};

static const DERItemSpec CMSSignedDataItemSpecs[] = {
    { DER_OFFSET(CMSSignedDataDER, version), ASN1_INTEGER, 0 },
    { DER_OFFSET(CMSSignedDataDER, digestAlgorithms), ASN1_CONSTR_SET, 0 },
    { DER_OFFSET(CMSSignedDataDER, encapContentInfo), ASN1_CONSTR_SEQUENCE, 0 },
    { DER_OFFSET(CMSSignedDataDER, certificates), ASN1_CONSTRUCTED | ASN1_CONTEXT_SPECIFIC, DER_DEC_OPTIONAL },
    { DER_OFFSET(CMSSignedDataDER, crls), ASN1_CONSTRUCTED | ASN1_CONTEXT_SPECIFIC, DER_DEC_OPTIONAL },
    { DER_OFFSET(CMSSignedDataDER, signerInfos), ASN1_CONSTR_SET }
};

static const DERItemSpec CMSSignerInfoItemSpecs[] = {
    { DER_OFFSET(CMSSignerInfoDER, version), ASN1_INTEGER, 0 },
    { DER_OFFSET(CMSSignerInfoDER, sid), ASN1_CONSTRUCTED | ASN1_CONTEXT_SPECIFIC, 0 },
    { DER_OFFSET(CMSSignerInfoDER, digestAlgorithm), ASN1_CONSTR_SEQUENCE, 0 },
    { DER_OFFSET(CMSSignerInfoDER, signedAttrs), ASN1_CONSTRUCTED | ASN1_CONTEXT_SPECIFIC, DER_DEC_OPTIONAL },
    { DER_OFFSET(CMSSignerInfoDER, signatureAlgorithm), ASN1_CONSTR_SEQUENCE, 0 },
    { DER_OFFSET(CMSSignerInfoDER, signature), ASN1_BIT_STRING, 0 },
    { DER_OFFSET(CMSSignerInfoDER, unsignedAttrs), ASN1_CONSTRUCTED | ASN1_CONTEXT_SPECIFIC, DER_DEC_OPTIONAL }
};

int cms_data_decode(uint8_t *cmsDERData, size_t cmsDERLength);

#endif // CMS_DECODING_H