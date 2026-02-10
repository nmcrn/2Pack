#ifndef CRYPTO_H
#define CRYPTO_H

#include <stddef.h>

void XorCipher(unsigned char* data, size_t dataLen, char* key, size_t keyLen);

#endif