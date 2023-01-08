#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "rng.h"
#include "api.h"
#include <openssl/rand.h>

void error(const char *msg)
{
    printf("[ERROR] %s\n", msg);
    exit(-1);
}

void print_hex(unsigned char *bytes, int n) {
	int i;

	for (i = 0; i < n; i++) {
		printf("%02x ", bytes[i]);
	}
	printf("\n\n\n");
}

int main(){
	unsigned char seed[48];
	unsigned char pk[CRYPTO_PUBLICKEYBYTES_NTRU], sk[CRYPTO_SECRETKEYBYTES_NTRU];
	unsigned char pk1[CRYPTO_PUBLICKEYBYTES_NTRU], sk1[CRYPTO_SECRETKEYBYTES_NTRU];
	int ret_val;
	FILE *fp;
		
	//Key pair generation for NTRU
	RAND_bytes(seed, sizeof(seed));
    randombytes_init(seed, NULL, 256);
	
    // Generate the public/private keypair
    if ( (ret_val = crypto_kem_keypair(pk, sk)) != 0) {
		error("Keypair generation FAILURE");
    }
	
	fp = fopen("../keys/pk_ntru.bin", "w");
	if(fp == NULL){
		error("Could not create file");
	}
	if(fwrite(pk, sizeof(unsigned char), sizeof(pk), fp) != CRYPTO_PUBLICKEYBYTES_NTRU){
		error("Public key stored in file not valid");
	}	
	fclose(fp);
	
	fp = fopen("../keys/sk_ntru.bin", "w");
	if(fp == NULL){
		error("Could not create file");
	}
	if(fwrite(sk, sizeof(unsigned char), sizeof(sk), fp) != CRYPTO_SECRETKEYBYTES_NTRU){
		error("Private key stored in file not valid");
	}	
	fclose(fp);
	
	//Read
	fp = fopen("../keys/pk_ntru.bin", "r");
	if(fp == NULL){
		error("Could not open file");
	}
	if(fread(pk1, sizeof(unsigned char), sizeof(pk1), fp) != CRYPTO_PUBLICKEYBYTES_NTRU){
		error("Public key not valid");
	}	
	fclose(fp);
	
	fp = fopen("../keys/sk_ntru.bin", "r");
	if(fp == NULL){
		error("Could not open file");
	}
	if(fread(sk1, sizeof(unsigned char), sizeof(sk1), fp) != CRYPTO_SECRETKEYBYTES_NTRU){
		error("Secret key not valid");
	}	
	fclose(fp);
	
	print_hex(pk, 50);
	print_hex(sk, 50);
	print_hex(pk1, 50);
	print_hex(sk1, 50);
	
    if ( memcmp(pk, pk1, sizeof(pk)) ) {
		error("Public keys don't match\n");
	}
	
	if ( memcmp(sk, sk1, sizeof(sk)) ) {
		error("Secret keys don't match\n");
	}
    
    return 0;
}	