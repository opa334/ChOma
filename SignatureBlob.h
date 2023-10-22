#ifndef SIGNATURE_BLOB_H
#define SIGNATURE_BLOB_H

#include <stdio.h>
#include <stdint.h>
#include <libDER/asn1Types.h> // This include MUST come after libDER_config.h
#include <libDER/libDER.h>
#include <libDER/DER_Decode.h>
#include <libDER/DER_Encode.h>

typedef struct {
    DERItem version;
    DERItem digestAlgorithms;
    DERItem contentInfo;
    DERItem certificates;
    DERItem signerInfos;
} CMSSignedDataDER;

typedef struct {
    DERItem signedData;
} CMSContentDER;

typedef struct {
    DERItem oid;
    DERItem content;
} CMSContentInfoDER;

#endif // SIGNATURE_BLOB_H