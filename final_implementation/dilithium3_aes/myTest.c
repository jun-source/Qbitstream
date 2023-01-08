#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "rng.h"
#include "api_dil.h"
#include <openssl/rand.h>

#define KAT_SUCCESS          0
#define KAT_FILE_OPEN_ERROR -1
#define KAT_DATA_ERROR      -3
#define KAT_CRYPTO_FAILURE  -4

void print_hex(unsigned char *bytes, int n) {
	int i;

	for (i = 0; i < n; i++) {
		printf("%02x ", bytes[i]);
	}
	printf("\n\n\n");
}

int main(){
	unsigned char seed[48];
	unsigned char m[] = "This is the message";
	unsigned char *sm, *m1;
	unsigned long long mlen, smlen, mlen1;
	unsigned char pk[CRYPTO_PUBLICKEYBYTES], sk[CRYPTO_SECRETKEYBYTES];
	int ret_val;
	
	mlen = sizeof(m);
	m1 = (unsigned char *) calloc(mlen+CRYPTO_BYTES, sizeof(unsigned char));
	sm = (unsigned char *) calloc(mlen+CRYPTO_BYTES, sizeof(unsigned char));
	
	RAND_bytes(seed, sizeof(seed));
	randombytes_init(seed, NULL, 256);
	
	printf("\nOriginal message: %s\n", m);
	
    // Generate the public/private keypair
    if ( (ret_val = crypto_sign_keypair(pk, sk)) != 0) { 
        printf("crypto_sign_keypair returned <%d>\n", ret_val);
        return KAT_CRYPTO_FAILURE;
    }
	
	print_hex(pk, 50);
	print_hex(sk, 50);
	
    if ( (ret_val = crypto_sign(sm, &smlen, m, mlen, sk)) != 0) { 
        printf("crypto_sign returned <%d>\n", ret_val);
        return KAT_CRYPTO_FAILURE;
    }
    printf("\nSigned message: %s; lenght: %lld\n", sm, smlen);

    if ( (ret_val = crypto_sign_open(m1, &mlen1, sm, smlen, pk)) != 0) { //----
        printf("crypto_sign_open returned <%d>\n", ret_val);
        return KAT_CRYPTO_FAILURE;
    }

    if ( mlen != mlen1 ) {
        printf("crypto_sign_open returned bad 'mlen': Got <%llu>, expected <%llu>\n", mlen1, mlen);
        return KAT_CRYPTO_FAILURE;
    }	

    if ( memcmp(m, m1, mlen) ) {
        printf("crypto_sign_open returned bad 'm' value\n");
        return KAT_CRYPTO_FAILURE;
    }
    printf("\nResult message: %s\n", m1);
    
    free(m1);
    free(sm);
    
    return KAT_SUCCESS;
}	
	
	
