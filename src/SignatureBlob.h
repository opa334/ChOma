#ifndef SIGNATURE_BLOB_H
#define SIGNATURE_BLOB_H

#include <stdio.h>
#include <stdint.h>
#include <libDER/asn1Types.h> // This include MUST come after libDER_config.h
#include <libDER/libDER.h>
#include <libDER/DER_Decode.h>
#include <libDER/DER_Encode.h>

// https://datatracker.ietf.org/doc/html/rfc5652#section-12.1

/*
ContentInfo ::= SEQUENCE {
    contentType ContentType,
    content [0] EXPLICIT ANY DEFINED BY contentType }
*/
typedef struct {
    DERItem contentType;
    DERItem content;
} CMSContentInfoDER;

// ContentType ::= OBJECT IDENTIFIER

/*
SignedData ::= SEQUENCE {
    version CMSVersion,
    digestAlgorithms DigestAlgorithmIdentifiers,
    encapContentInfo EncapsulatedContentInfo,
    certificates [0] IMPLICIT CertificateSet OPTIONAL,
    crls [1] IMPLICIT RevocationInfoChoices OPTIONAL,
    signerInfos SignerInfos }
*/
typedef struct {
    DERItem version; // CMSVersion
    DERItem digestAlgorithms; // DigestAlgorithmIdentifiers
    DERItem encapContentInfo; // EncapsulatedContentInfo
    DERItem certificates; // CertificateSet
    DERItem crls; // RevocationInfoChoices
    DERItem signerInfos; // SignerInfos
} CMSSignedDataDER;

// DigestAlgorithmIdentifiers ::= SET OF DigestAlgorithmIdentifier

// SignerInfos ::= SET OF SignerInfo

/*
EncapsulatedContentInfo ::= SEQUENCE {
    eContentType ContentType,
    eContent [0] EXPLICIT OCTET STRING OPTIONAL }
*/
typedef struct {
    DERItem eContentType; // ContentType
    DERItem eContent;
} CMSEncapsulatedContentInfoDER;

/*
SignerInfo ::= SEQUENCE {
    version CMSVersion,
    sid SignerIdentifier,
    digestAlgorithm DigestAlgorithmIdentifier,
    signedAttrs [0] IMPLICIT SignedAttributes OPTIONAL,
    signatureAlgorithm SignatureAlgorithmIdentifier,
    signature SignatureValue,
    unsignedAttrs [1] IMPLICIT UnsignedAttributes OPTIONAL }
*/
typedef struct {
    DERItem version; // CMSVersion
    DERItem sid; // SignerIdentifier
    DERItem digestAlgorithm; // DigestAlgorithmIdentifier
    DERItem signedAttrs; // SignedAttributes
    DERItem signatureAlgorithm; // SignatureAlgorithmIdentifier
    DERItem signature; // SignatureValue
    DERItem unsignedAttrs; // UnsignedAttributes
} CMSSignerInfoDER;

/*
SignerIdentifier ::= CHOICE {
    issuerAndSerialNumber IssuerAndSerialNumber,
    subjectKeyIdentifier [0] SubjectKeyIdentifier }
*/
typedef struct {
    DERItem issuerAndSerialNumber; // IssuerAndSerialNumber
    DERItem subjectKeyIdentifier; // SubjectKeyIdentifier
} CMSSignerIdentifierDER;

// SignedAttributes ::= SET SIZE (1..MAX) OF Attribute
// UnsignedAttributes ::= SET SIZE (1..MAX) OF Attribute

/*
Attribute ::= SEQUENCE {
    attrType OBJECT IDENTIFIER,
    attrValues SET OF AttributeValue }
*/
typedef struct {
    DERItem attrType; // AttributeType
    DERItem attrValues; // AttributeValues
} CMSAttributeDER;

// AttributeValue ::= ANY

// SignatureValue ::= OCTET STRING

/*
EnvelopedData ::= SEQUENCE {
    version CMSVersion,
    originatorInfo [0] IMPLICIT OriginatorInfo OPTIONAL,
    recipientInfos RecipientInfos,
    encryptedContentInfo EncryptedContentInfo,
    unprotectedAttrs [1] IMPLICIT UnprotectedAttributes OPTIONAL }
*/
typedef struct {
    DERItem version; // CMSVersion
    DERItem originatorInfo; // OriginatorInfo
    DERItem recipientInfos; // RecipientInfos
    DERItem encryptedContentInfo; // EncryptedContentInfo
    DERItem unprotectedAttrs; // UnprotectedAttributes
} CMSEnvelopedDataDER;

/*
OriginatorInfo ::= SEQUENCE {
    certs [0] IMPLICIT CertificateSet OPTIONAL,
    crls [1] IMPLICIT RevocationInfoChoices OPTIONAL }
*/
typedef struct {
    DERItem certs; // CertificateSet
    DERItem crls; // RevocationInfoChoices
} CMSOriginatorInfoDER;

// RecipientInfos ::= SET SIZE (1..MAX) OF RecipientInfo

/*
EncryptedContentInfo ::= SEQUENCE {
    contentType ContentType,
    contentEncryptionAlgorithm ContentEncryptionAlgorithmIdentifier,
    encryptedContent [0] IMPLICIT EncryptedContent OPTIONAL }
*/
typedef struct {
    DERItem contentType; // ContentType
    DERItem contentEncryptionAlgorithm; // ContentEncryptionAlgorithmIdentifier
    DERItem encryptedContent; // EncryptedContent
} CMSEncryptedContentInfoDER;

// EncryptedContent ::= OCTET STRING

// UnprotectedAttributes ::= SET SIZE (1..MAX) OF Attribute

/*
RecipientInfo ::= CHOICE {
    ktri KeyTransRecipientInfo,
    kari [1] KeyAgreeRecipientInfo,
    kekri [2] KEKRecipientInfo,
    pwri [3] PasswordRecipientInfo,
    ori [4] OtherRecipientInfo }
*/
typedef struct {
    DERItem ktri; // KeyTransRecipientInfo
    DERItem kari; // KeyAgreeRecipientInfo
    DERItem kekri; // KEKRecipientInfo
    DERItem pwri; // PasswordRecipientInfo
    DERItem ori; // OtherRecipientInfo
} CMSRecipientInfoDER;

//  EncryptedKey ::= OCTET STRING

/*
KeyTransRecipientInfo ::= SEQUENCE {
    version CMSVersion,  -- always set to 0 or 2
    rid RecipientIdentifier,
    keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
    encryptedKey EncryptedKey }
*/
typedef struct {
    DERItem version; // CMSVersion
    DERItem rid; // RecipientIdentifier
    DERItem keyEncryptionAlgorithm; // KeyEncryptionAlgorithmIdentifier
    DERItem encryptedKey; // EncryptedKey
} CMSKeyTransRecipientInfoDER;

/*
RecipientIdentifier ::= CHOICE {
    issuerAndSerialNumber IssuerAndSerialNumber,
    subjectKeyIdentifier [0] SubjectKeyIdentifier }
*/
typedef struct {
    DERItem issuerAndSerialNumber; // IssuerAndSerialNumber
    DERItem subjectKeyIdentifier; // SubjectKeyIdentifier
} CMSRecipientIdentifierDER;

/*
KeyAgreeRecipientInfo ::= SEQUENCE {
    version CMSVersion,  -- always set to 3
    originator [0] EXPLICIT OriginatorIdentifierOrKey,
    ukm [1] EXPLICIT UserKeyingMaterial OPTIONAL,
    keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
    recipientEncryptedKeys RecipientEncryptedKeys }
*/
typedef struct {
    DERItem version; // CMSVersion
    DERItem originator; // OriginatorIdentifierOrKey
    DERItem ukm; // UserKeyingMaterial
    DERItem keyEncryptionAlgorithm; // KeyEncryptionAlgorithmIdentifier
    DERItem recipientEncryptedKeys; // RecipientEncryptedKeys
} CMSKeyAgreeRecipientInfoDER;

/*
OriginatorIdentifierOrKey ::= CHOICE {
    issuerAndSerialNumber IssuerAndSerialNumber,
    subjectKeyIdentifier [0] SubjectKeyIdentifier,
    originatorKey [1] OriginatorPublicKey }
*/
typedef struct {
    DERItem issuerAndSerialNumber; // IssuerAndSerialNumber
    DERItem subjectKeyIdentifier; // SubjectKeyIdentifier
    DERItem originatorKey; // OriginatorPublicKey
} CMSOriginatorIdentifierOrKeyDER;

/*
OriginatorPublicKey ::= SEQUENCE {
    algorithm AlgorithmIdentifier,
    publicKey BIT STRING }
*/
typedef struct {
    DERItem algorithm; // AlgorithmIdentifier
    DERItem publicKey; // BIT STRING
} CMSOriginatorPublicKeyDER;

// RecipientEncryptedKeys ::= SEQUENCE OF RecipientEncryptedKey

/*
RecipientEncryptedKey ::= SEQUENCE {
    rid KeyAgreeRecipientIdentifier,
    encryptedKey EncryptedKey }
*/
typedef struct {
    DERItem rid; // KeyAgreeRecipientIdentifier
    DERItem encryptedKey; // EncryptedKey
} CMSRecipientEncryptedKeyDER;

/*
KeyAgreeRecipientIdentifier ::= CHOICE {
    issuerAndSerialNumber IssuerAndSerialNumber,
    rKeyId [0] IMPLICIT RecipientKeyIdentifier }
*/
typedef struct {
    DERItem issuerAndSerialNumber; // IssuerAndSerialNumber
    DERItem rKeyId; // RecipientKeyIdentifier
} CMSKeyAgreeRecipientIdentifierDER;

/*
RecipientKeyIdentifier ::= SEQUENCE {
    subjectKeyIdentifier SubjectKeyIdentifier,
    date GeneralizedTime OPTIONAL,
    other OtherKeyAttribute OPTIONAL }
*/
typedef struct {
    DERItem subjectKeyIdentifier; // SubjectKeyIdentifier
    DERItem date; // GeneralizedTime
    DERItem other; // OtherKeyAttribute
} CMSRecipientKeyIdentifierDER;

// SubjectKeyIdentifier ::= OCTET STRING

/*
KEKRecipientInfo ::= SEQUENCE {
    version CMSVersion,  -- always set to 4
    kekid KEKIdentifier,
    keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
    encryptedKey EncryptedKey }
*/
typedef struct {
    DERItem version; // CMSVersion
    DERItem kekid; // KEKIdentifier
    DERItem keyEncryptionAlgorithm; // KeyEncryptionAlgorithmIdentifier
    DERItem encryptedKey; // EncryptedKey
} CMSKEKRecipientInfoDER;

/*
KEKIdentifier ::= SEQUENCE {
    keyIdentifier OCTET STRING,
    date GeneralizedTime OPTIONAL,
    other OtherKeyAttribute OPTIONAL }
*/
typedef struct {
    DERItem keyIdentifier; // OCTET STRING
    DERItem date; // GeneralizedTime
    DERItem other; // OtherKeyAttribute
} CMSKEKIdentifierDER;

/*
PasswordRecipientInfo ::= SEQUENCE {
    version CMSVersion,   -- always set to 0
    keyDerivationAlgorithm [0] KeyDerivationAlgorithmIdentifier
        OPTIONAL,
    keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
    encryptedKey EncryptedKey }
*/
typedef struct {
    DERItem version; // CMSVersion
    DERItem keyDerivationAlgorithm; // KeyDerivationAlgorithmIdentifier
    DERItem keyEncryptionAlgorithm; // KeyEncryptionAlgorithmIdentifier
    DERItem encryptedKey; // EncryptedKey
} CMSPasswordRecipientInfoDER;

/*
OtherRecipientInfo ::= SEQUENCE {
    oriType OBJECT IDENTIFIER,
    oriValue ANY DEFINED BY oriType }
*/
typedef struct {
    DERItem oriType; // OBJECT IDENTIFIER
    DERItem oriValue; // ANY DEFINED BY oriType
} CMSOtherRecipientInfoDER;

/*
DigestedData ::= SEQUENCE {
    version CMSVersion,
    digestAlgorithm DigestAlgorithmIdentifier,
    encapContentInfo EncapsulatedContentInfo,
    digest Digest }
*/
typedef struct {
    DERItem version; // CMSVersion
    DERItem digestAlgorithm; // DigestAlgorithmIdentifier
    DERItem encapContentInfo; // EncapsulatedContentInfo
    DERItem digest; // Digest
} CMSDigestedDataDER;

// Digest ::= OCTET STRING

/*
EncryptedData ::= SEQUENCE {
    version CMSVersion,
    encryptedContentInfo EncryptedContentInfo,
    unprotectedAttrs [1] IMPLICIT UnprotectedAttributes OPTIONAL }
*/
typedef struct {
    DERItem version; // CMSVersion
    DERItem encryptedContentInfo; // EncryptedContentInfo
    DERItem unprotectedAttrs; // UnprotectedAttributes
} CMSEncryptedDataDER;

/*
AuthenticatedData ::= SEQUENCE {
    version CMSVersion,
    originatorInfo [0] IMPLICIT OriginatorInfo OPTIONAL,
    recipientInfos RecipientInfos,
    macAlgorithm MessageAuthenticationCodeAlgorithm,
    digestAlgorithm [1] DigestAlgorithmIdentifier OPTIONAL,
    encapContentInfo EncapsulatedContentInfo,
    authAttrs [2] IMPLICIT AuthAttributes OPTIONAL,
    mac MessageAuthenticationCode,
    unauthAttrs [3] IMPLICIT UnauthAttributes OPTIONAL }
*/
typedef struct {
    DERItem version; // CMSVersion
    DERItem originatorInfo; // OriginatorInfo
    DERItem recipientInfos; // RecipientInfos
    DERItem macAlgorithm; // MessageAuthenticationCodeAlgorithm
    DERItem digestAlgorithm; // DigestAlgorithmIdentifier
    DERItem encapContentInfo; // EncapsulatedContentInfo
    DERItem authAttrs; // AuthAttributes
    DERItem mac; // MessageAuthenticationCode
    DERItem unauthAttrs; // UnauthAttributes
} CMSAuthenticatedDataDER;

// AuthAttributes ::= SET SIZE (1..MAX) OF Attribute

// UnauthAttributes ::= SET SIZE (1..MAX) OF Attribute

// MessageAuthenticationCode ::= OCTET STRING

// DigestAlgorithmIdentifier ::= AlgorithmIdentifier

// SignatureAlgorithmIdentifier ::= AlgorithmIdentifier

// ContentEncryptionAlgorithmIdentifier ::= AlgorithmIdentifier

// MessageAuthenticationCodeAlgorithm ::= AlgorithmIdentifier

// KeyDerivationAlgorithmIdentifier ::= AlgorithmIdentifier

// RevocationInfoChoices ::= SET OF RevocationInfoChoice

/*
RevocationInfoChoice ::= CHOICE {
    crl CertificateList,
    other [1] IMPLICIT OtherRevocationInfoFormat }
*/
typedef struct {
    DERItem crl; // CertificateList
    DERItem other; // OtherRevocationInfoFormat
} CMSRevocationInfoChoiceDER;

/*
OtherRevocationInfoFormat ::= SEQUENCE {
    otherRevInfoFormat OBJECT IDENTIFIER,
    otherRevInfo ANY DEFINED BY otherRevInfoFormat }
*/
typedef struct {
    DERItem otherRevInfoFormat; // OBJECT IDENTIFIER
    DERItem otherRevInfo; // ANY DEFINED BY otherRevInfoFormat
} CMSOtherRevocationInfoFormatDER;

/*
CertificateChoices ::= CHOICE {
    certificate Certificate,
    extendedCertificate [0] IMPLICIT ExtendedCertificate,  -- Obsolete
    v1AttrCert [1] IMPLICIT AttributeCertificateV1,        -- Obsolete
    v2AttrCert [2] IMPLICIT AttributeCertificateV2,
    other [3] IMPLICIT OtherCertificateFormat }
*/
typedef struct {
    DERItem certificate; // Certificate
    DERItem extendedCertificate; // ExtendedCertificate
    DERItem v1AttrCert; // AttributeCertificateV1
    DERItem v2AttrCert; // AttributeCertificateV2
    DERItem other; // OtherCertificateFormat
} CMSCertificateChoicesDER;

// AttributeCertificateV2 ::= AttributeCertificate

/*
OtherCertificateFormat ::= SEQUENCE {
    otherCertFormat OBJECT IDENTIFIER,
    otherCert ANY DEFINED BY otherCertFormat }
*/
typedef struct {
    DERItem otherCertFormat; // OBJECT IDENTIFIER
    DERItem otherCert; // ANY DEFINED BY otherCertFormat
} CMSOtherCertificateFormatDER;

// CertificateSet ::= SET OF CertificateChoices

/*
IssuerAndSerialNumber ::= SEQUENCE {
    issuer Name,
    serialNumber CertificateSerialNumber }
*/
typedef struct {
    DERItem issuer; // Name
    DERItem serialNumber; // CertificateSerialNumber
} CMSIssuerAndSerialNumberDER;

// CMSVersion ::= INTEGER { v0(0), v1(1), v2(2), v3(3), v4(4), v5(5) }

// UserKeyingMaterial ::= OCTET STRING

/*
OtherKeyAttribute ::= SEQUENCE {
    keyAttrId OBJECT IDENTIFIER,
    keyAttr ANY DEFINED BY keyAttrId OPTIONAL }
*/
typedef struct {
    DERItem keyAttrId; // OBJECT IDENTIFIER
    DERItem keyAttr; // ANY DEFINED BY keyAttrId
} CMSOtherKeyAttributeDER;

/*
-- Content Type Object Identifiers

id-ct-contentInfo OBJECT IDENTIFIER ::= { iso(1) member-body(2)
    us(840) rsadsi(113549) pkcs(1) pkcs9(9) smime(16) ct(1) 6 }

id-data OBJECT IDENTIFIER ::= { iso(1) member-body(2)
    us(840) rsadsi(113549) pkcs(1) pkcs7(7) 1 }

id-signedData OBJECT IDENTIFIER ::= { iso(1) member-body(2)
    us(840) rsadsi(113549) pkcs(1) pkcs7(7) 2 }

id-envelopedData OBJECT IDENTIFIER ::= { iso(1) member-body(2)
    us(840) rsadsi(113549) pkcs(1) pkcs7(7) 3 }

id-digestedData OBJECT IDENTIFIER ::= { iso(1) member-body(2)
    us(840) rsadsi(113549) pkcs(1) pkcs7(7) 5 }

id-encryptedData OBJECT IDENTIFIER ::= { iso(1) member-body(2)
    us(840) rsadsi(113549) pkcs(1) pkcs7(7) 6 }

id-ct-authData OBJECT IDENTIFIER ::= { iso(1) member-body(2)
    us(840) rsadsi(113549) pkcs(1) pkcs-9(9) smime(16) ct(1) 2 }
*/

// MessageDigest ::= OCTET STRING

// SigningTime ::= Time

/*
Time ::= CHOICE {
    utcTime UTCTime,
    generalTime GeneralizedTime }
*/
typedef struct {
    DERItem utcTime; // UTCTime
    DERItem generalTime; // GeneralizedTime
} CMSTimeDER;

// Countersignature ::= SignerInfo

/*
-- Attribute Object Identifiers

id-contentType OBJECT IDENTIFIER ::= { iso(1) member-body(2)
    us(840) rsadsi(113549) pkcs(1) pkcs9(9) 3 }

id-messageDigest OBJECT IDENTIFIER ::= { iso(1) member-body(2)
    us(840) rsadsi(113549) pkcs(1) pkcs9(9) 4 }

id-signingTime OBJECT IDENTIFIER ::= { iso(1) member-body(2)
    us(840) rsadsi(113549) pkcs(1) pkcs9(9) 5 }

id-countersignature OBJECT IDENTIFIER ::= { iso(1) member-body(2)
    us(840) rsadsi(113549) pkcs(1) pkcs9(9) 6 }
*/


// -- Obsolete Extended Certificate syntax from PKCS #6

/*
ExtendedCertificateOrCertificate ::= CHOICE {
    certificate Certificate,
    extendedCertificate [0] IMPLICIT ExtendedCertificate }
*/
typedef struct {
    DERItem certificate; // Certificate
    DERItem extendedCertificate; // ExtendedCertificate
} CMSExtendedCertificateOrCertificateDER;

/*
ExtendedCertificate ::= SEQUENCE {
    extendedCertificateInfo ExtendedCertificateInfo,
    signatureAlgorithm SignatureAlgorithmIdentifier,
    signature Signature }
*/
typedef struct {
    DERItem extendedCertificateInfo; // ExtendedCertificateInfo
    DERItem signatureAlgorithm; // SignatureAlgorithmIdentifier
    DERItem signature; // Signature
} CMSExtendedCertificateDER;

/*
ExtendedCertificateInfo ::= SEQUENCE {
    version CMSVersion,  -- version is v1
    certificate Certificate,
    attributes UnauthAttributes }
*/
typedef struct {
    DERItem version; // CMSVersion
    DERItem certificate; // Certificate
    DERItem attributes; // UnauthAttributes
} CMSExtendedCertificateInfoDER;

// Signature ::= BIT STRING

// END -- of CryptographicMessageSyntax2004


// https://datatracker.ietf.org/doc/html/rfc5280#appendix-A.1

/*
Certificate  ::=  SEQUENCE  {
    tbsCertificate       TBSCertificate,
    signatureAlgorithm   AlgorithmIdentifier,
    signature            BIT STRING  }
*/
typedef struct {
    DERItem tbsCertificate; // TBSCertificate
    DERItem signatureAlgorithm; // AlgorithmIdentifier
    DERItem signature; // BIT STRING
} CMSCertificateDER;

/*
TBSCertificate  ::=  SEQUENCE  {
    version         [0]  Version DEFAULT v1,
    serialNumber         CertificateSerialNumber,
    signature            AlgorithmIdentifier,
    issuer               Name,
    validity             Validity,
    subject              Name,
    subjectPublicKeyInfo SubjectPublicKeyInfo,
    issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
                         -- If present, version MUST be v2 or v3
    subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
                         -- If present, version MUST be v2 or v3
    extensions      [3]  Extensions OPTIONAL
                         -- If present, version MUST be v3 --  }
*/


#endif // SIGNATURE_BLOB_H