#ifndef SIGNING_H
#define SIGNING_H

#include <stdio.h>
#include <stdlib.h>
#include <CommonCrypto/CommonCrypto.h>
#include <Security/SecKey.h>
#include <Security/Security.h>

unsigned char *signWithRSA(unsigned char *inputData, size_t inputDataLength, size_t *outputDataLength);

#endif // SIGNING_H