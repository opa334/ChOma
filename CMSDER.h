#include "SignatureBlob.h"

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