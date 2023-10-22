#ifndef CMS_DECODING_H
#define CMS_DECODING_H

#include "SignatureBlob.h"

int decodeCMSData(uint8_t *cmsDERData, size_t cmsDERLength);

#endif // CMS_DECODING_H