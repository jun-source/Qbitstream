#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h> 
#include <openssl/rand.h>
#include <openssl/evp.h>
#include "aes_gcm/aes_gcm.h"
#include "ntru_kem/api.h"
#include "dilithium3_aes/api_dil.h"
#include "ntru_kem/rng.h"

#define ERROR -1
#define NO_ERROR 0
#define BUFFER_IN_SIZE 1025
#define BUFFER_OUT_SIZE 1025
/* Digital signature */
#define RANDOM_CHALLENGE_SIZE 48
#define SECRET_MSG_SIZE (CRYPTO_BYTES + RANDOM_CHALLENGE_SIZE)
/* AES */
#define AAD_SIZE 16
#define IV_SIZE 16
#define AES_KEY_SIZE 32
#define TAG_SIZE 100 

void error(const char *msg)
{
    printf("[ERROR] %s\n", msg);
    exit(ERROR);
}

void print_hex(const unsigned char *header, const unsigned char *bytes, int n) {
	int i;
	printf("%s", header);
	for (i = 0; i < n; i++) {
		printf("%02x ", bytes[i]);
	}
	printf("\n");
}

int main(int argc, char *argv[])
{
	// Sockets parameters
    int sockfd, portno, n;
    struct sockaddr_in serv_addr;
    struct hostent *server;
	
	// Digital signature parameters
	unsigned char random_challg[RANDOM_CHALLENGE_SIZE];
	unsigned char *sm;
	unsigned long long mlen, smlen;
	unsigned char sk_ds[CRYPTO_SECRETKEYBYTES];
	int ret_val;
	
	// Key exchange parameters
    unsigned char pk_kem[CRYPTO_PUBLICKEYBYTES_NTRU];
	unsigned char cypher_key[CRYPTO_CIPHERTEXTBYTES_NTRU];
	unsigned char seed[48];
	
	//AES
	unsigned char aes_key[AES_KEY_SIZE];
	unsigned char tag[TAG_SIZE];
	unsigned char iv[IV_SIZE];
	unsigned char aad[AAD_SIZE]="abcdefghijklmnop";	//dummy
	int nEncrypted;
	
	// Buffers and others
	unsigned char buffer_in[BUFFER_IN_SIZE], buffer_out[BUFFER_OUT_SIZE];
	FILE *fp;
	unsigned int fileSize;
	unsigned char  *cipherText, *plainText, *message;
	unsigned int acum;
	
    if (argc < 3) {
	   error("Arguments in this order: ./client <IP address> <server port>");
    }
	
	/* 
	 * STEP 1: TCP synchronization 
	 */
	 
    portno = atoi(argv[2]);
    sockfd = socket(AF_INET, SOCK_STREAM, 0); 
    if (sockfd < 0){ 
        error("[sockets]: error opening socket");
	}
    server = gethostbyname(argv[1]);
    if (server == NULL) {
		error("[sockets]: error, no such host");
    }
    bzero((char *) &serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    bcopy((char *)server->h_addr, (char *)&serv_addr.sin_addr.s_addr, 
	       server->h_length);
    serv_addr.sin_port = htons(portno);
    if (connect(sockfd,(struct sockaddr *) &serv_addr,sizeof(serv_addr)) < 0){ 
        error("[sockets]: error connecting");
	}
	
	/* 
	 * STEP 2: Authentication 
	 */
	 
	printf("Starting authentication...\n"); 
	fp = fopen("keys/sk_dilith.bin", "r");
	if(fp == NULL){
		error("Could not open file");
	}
	if(fread(sk_ds, sizeof(unsigned char), CRYPTO_SECRETKEYBYTES, fp) != CRYPTO_SECRETKEYBYTES){
	error("[Authentication] Secret key not valid");
	}	
	fclose(fp);
	
	/* Generate random message */
	RAND_bytes(random_challg, RANDOM_CHALLENGE_SIZE);
	mlen = RANDOM_CHALLENGE_SIZE;
	sm = (unsigned char *) calloc(SECRET_MSG_SIZE, sizeof(unsigned char));
	
	/* Signed random message */
    if ( (ret_val = crypto_sign(sm, &smlen, random_challg, mlen, sk_ds)) != 0) { 
		error("[Authentication]: signed operation failed");
    }
	
	/* Socket 1: send secret message */
	if((n = write(sockfd, sm, smlen)) < 0){
		error("[socket 1] Error writing to socket");
	}
	
	/* Socket 2: wait for server authentication */
	bzero(buffer_in, BUFFER_IN_SIZE);
	acum = 0;
    while((n = read(sockfd, buffer_in + acum, BUFFER_IN_SIZE)) < 0){ 
        acum += n;
		if(acum >= BUFFER_IN_SIZE){
			break;
		}	
	}
	if(strcmp(buffer_in, "[from server] Authentication succeeded")){
		error(buffer_in);
	}else{
		printf("%s\n", buffer_in);
	}
	free(sm);
	
	/* 
	 * STEP 3: Key exchange 
	 */
	 
	printf("Starting key exchange...\n"); 
	do{
		printf("Do you want to update keypair for key exchange?[y/n] ");
		bzero(buffer_in, BUFFER_IN_SIZE); 
		scanf("%s", buffer_in);
	} while(strcmp(buffer_in, "y")!=0 & strcmp(buffer_in, "n")!=0);
	
	if(!strcmp(buffer_in, "y")){
		
		/* Socket 3: send request kem keypair update */
		bzero(buffer_out, BUFFER_OUT_SIZE);
		strcpy(buffer_out, "Kem keypair update");
		if((n = write(sockfd, buffer_out, BUFFER_OUT_SIZE)) < 0){
			error("ERROR writing to socket");
		}
		
		/* Socket 4: wait for kem public key  */
		acum = 0;
		while((n = read(sockfd, pk_kem + acum, CRYPTO_PUBLICKEYBYTES_NTRU)) > 0){
			acum += n;
			if(acum >= CRYPTO_PUBLICKEYBYTES_NTRU){
				break;
			}
		}
		fp = fopen("keys/pk_ntru.bin", "w");
		if(fp == NULL){
			error("Could not create file");
		}
		if(fwrite(pk_kem, sizeof(unsigned char), sizeof(pk_kem), fp) != CRYPTO_PUBLICKEYBYTES_NTRU){
			error("Public key stored in file not valid");
		}	
		fclose(fp);
	}else{
		
		/* Socket 3: send no need for kem keypair update */
		bzero(buffer_out, BUFFER_OUT_SIZE);
		strcpy(buffer_out, "Not kem keypair update");
		if((n = write(sockfd, buffer_out, BUFFER_OUT_SIZE)) < 0){
			error("ERROR writing to socket");
		}
		
		/* Socket 4: wait for confirmation about using old kem keypair */
		acum = 0;
		bzero(buffer_in, BUFFER_IN_SIZE);
		while((n = read(sockfd, buffer_in + acum, BUFFER_IN_SIZE)) > 0){
			acum += n;
			if(acum >= BUFFER_IN_SIZE){
				break;
			}
		}
		printf("%s\n", buffer_in);
		fp = fopen("keys/pk_ntru.bin", "r");
		if(fp == NULL){
			error("Could not open file");
		}
		if(fread(pk_kem, sizeof(unsigned char), CRYPTO_PUBLICKEYBYTES_NTRU, fp) != CRYPTO_PUBLICKEYBYTES_NTRU){
			error("Public key not valid");
		}	
		fclose(fp);
	}
	
	/* STEP 4: KEM encryption and AES key generation */
	RAND_bytes(seed, sizeof(seed));
	randombytes_init(seed, NULL, 256);
    crypto_kem_enc(cypher_key, aes_key, pk_kem);
	
	/* Socket 5: send cypher AES key */
	if((n = write(sockfd, cypher_key, CRYPTO_CIPHERTEXTBYTES_NTRU)) < 0){
		error("ERROR writing to socket");
	}
	
	/* Socket 6: waiting for kem sucess confirmation */
	acum = 0;
	bzero(buffer_in, BUFFER_IN_SIZE);
	while((n = read(sockfd, buffer_in + acum, BUFFER_IN_SIZE)) > 0){
		acum += n;
		if(acum >= BUFFER_IN_SIZE){
			break;
		}
	}
	printf("%s\n", buffer_in);
	
	/* 
	 * Application: bitstream encryption 
	 */
	
	printf("Starting secure bitstream distribution...\n");
	/* Generate random IV */
	while(!RAND_bytes(iv, sizeof(iv)));
	 
	/* Ask for file path */
    printf("Please enter the path of your file: ");
    bzero(buffer_in, BUFFER_IN_SIZE); //Good trick to add NULL at the end to form a string
	scanf("%s", buffer_in);
	fp = fopen(buffer_in, "r");
	if(fp == NULL){
		error("could not open file");
	}
	
	/* Guess file size */ 
	fseek(fp, 0, SEEK_END); //fseek modifies position of fp (be careful)
	fileSize = ftell(fp);
	fseek(fp, 0, SEEK_SET);
	printf("Size of file '%s': %d bytes\n", buffer_in, fileSize);
	
	/* Allocate memory for bitstream */
	plainText = (char *) calloc(fileSize, sizeof(char));
	cipherText = (char *) calloc(fileSize + EVP_MAX_BLOCK_LENGTH, sizeof(char));
	if(fread(plainText, sizeof(char), fileSize, fp) != fileSize){
		error("Bitstream not valid");
	}	
	
	/* Bitstream encryption */ 
	if((ret_val = encrypt_aes_gcm(plainText, fileSize, aad, sizeof(aad), aes_key, iv, cipherText, tag)) != fileSize){
		error("[symetric crypto]: plaintext and cyphertext size missmatch.");
	}
	free(plainText);
	fclose(fp);
	printf("Bitstream encryption succeeded\n");
	
	/* Build message: AAD + IV + TAG + CYPHERTEXT */
	unsigned int messageSize = AAD_SIZE + IV_SIZE + TAG_SIZE + fileSize + EVP_MAX_BLOCK_LENGTH;
	message = (char *) calloc(messageSize, sizeof(char));
	unsigned int i;
	for(i = 0; i < AAD_SIZE; i++){
		*(message + i) = aad[i];
	}
	for(i = 0; i < IV_SIZE; i++){
		*(message + AAD_SIZE + i) = iv[i];
	}
	for(i = 0; i < TAG_SIZE; i++){
		*(message + AAD_SIZE + IV_SIZE + i) = tag[i];
	}
	for(i = 0; i < (fileSize + EVP_MAX_BLOCK_LENGTH); i++){
		*(message + AAD_SIZE + IV_SIZE + TAG_SIZE + i) = cipherText[i];
	}
	
	/* Socket 7: Send message size for dynamic memory allocation at server */
	if ((n = write(sockfd, &messageSize, sizeof(messageSize))) < 0){ 
         error("ERROR writing to socket");
	}
	
	/* Socket 8: wait for confirmation that memory is reserved from server */
	bzero(buffer_in, BUFFER_IN_SIZE);
	acum = 0;
    while((n = read(sockfd, buffer_in + acum, BUFFER_IN_SIZE)) > 0){ 
		acum += n;
		if(acum >= BUFFER_IN_SIZE){
			break;
		}
	}
	printf("%s\n", buffer_in);

    /* Socket 9: send message */	
	if((n = write(sockfd, message, messageSize)) < 0){
		error("ERROR writing to socket");
	}
	printf("Data sent size: %d bytes\n", n);
	free(message);
	
	/* Socket 10: wait for decryption success confirmation */	
	bzero(buffer_in, BUFFER_IN_SIZE);
	acum = 0;
    while((n = read(sockfd, buffer_in + acum, BUFFER_IN_SIZE)) > 0){ 
		acum += n;
		if(acum >= BUFFER_IN_SIZE){
			break;
		}
	}
	printf("%s\n", buffer_in);
	
	/*
	 * STEP 5: FPGA reconfiguration
     */
	
	/* Socket 11: wait for reconfiguration start confirmation */	
	bzero(buffer_in, BUFFER_IN_SIZE);
	acum = 0;
    while((n = read(sockfd, buffer_in + acum, BUFFER_IN_SIZE)) > 0){ 
		acum += n;
		if(acum >= BUFFER_IN_SIZE){
			break;
		}
	}
	printf("%s\n", buffer_in);
	
	/* Socket 12: wait for reconfiguration success message */	
	bzero(buffer_in, BUFFER_IN_SIZE);
	acum = 0;
    while((n = read(sockfd, buffer_in + acum, BUFFER_IN_SIZE)) > 0){ 
		acum += n;
		if(acum >= BUFFER_IN_SIZE){
			break;
		}
	}
	printf("%s\n", buffer_in);
	
    close(sockfd);
    return 0;
}