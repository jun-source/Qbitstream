#ifndef API_H
#define API_H

#include "params_ntru.h"

#define CRYPTO_SECRETKEYBYTES_NTRU NTRU_SECRETKEYBYTES
#define CRYPTO_PUBLICKEYBYTES_NTRU NTRU_PUBLICKEYBYTES
#define CRYPTO_CIPHERTEXTBYTES_NTRU NTRU_CIPHERTEXTBYTES
#define CRYPTO_BYTES_NTRU NTRU_SHAREDKEYBYTES

#define CRYPTO_ALGNAME_NTRU "NTRU-HPS2048509"

int crypto_kem_keypair(unsigned char *pk, unsigned char *sk);

int crypto_kem_enc(unsigned char *ct, unsigned char *ss, const unsigned char *pk);

int crypto_kem_dec(unsigned char *ss, const unsigned char *ct, const unsigned char *sk);


#endif
