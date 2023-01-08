/* A simple server in the internet domain using TCP
   The port number is passed as an argument */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h>
#include <openssl/rand.h>
#include <openssl/evp.h>

#define ERROR -1
#define NO_ERROR 0
#define AAD_SIZE 16
#define IV_SIZE 16
#define AES_KEY_SIZE 32
#define TAG_SIZE 100 
#define BUFF_IN_SIZE 1024
#define BUFF_OUT_SIZE 1024

void error(const char *msg)
{
    printf("[ERROR] %s\n", msg);
    exit(ERROR);
}

void print_hex(unsigned char *bytes, int n) {
	int i;

	for (i = 0; i < n; i++) {
		printf("%02x ", bytes[i]);
	}
	printf("\n");
}

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *aad,
	int aad_len, unsigned char *key, unsigned char *iv,
	unsigned char *ciphertext, unsigned char *tag)
{
	EVP_CIPHER_CTX *ctx;

	int len=0, ciphertext_len=0;

	/* Create and initialise the context */
	if(!(ctx = EVP_CIPHER_CTX_new()))
		error("[symmetric crypto]: encryption failed");

	/* Initialise the encryption operation. */
	if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
		error("[symmetric crypto]: encryption failed");

	/* Set IV length if default 12 bytes (96 bits) is not appropriate */
	if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 16, NULL))
		error("[symmetric crypto]: encryption failed");

	/* Initialise key and IV */
	if(1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv)) error("[symmetric crypto]: encryption failed");

	/* Provide any AAD data. This can be called zero or more times as
	 * required
	 */
	if(1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len))
		error("[symmetric crypto]: encryption failed");

	/* Provide the message to be encrypted, and obtain the encrypted output.
	 * EVP_EncryptUpdate can be called multiple times if necessary
	 */
	/* encrypt in block lengths of 16 bytes */
	 while(ciphertext_len<=plaintext_len-16)
	 {
	 	if(1 != EVP_EncryptUpdate(ctx, ciphertext+ciphertext_len, &len, plaintext+ciphertext_len, 16))
	 		error("[symmetric crypto]: encryption failed");
	 	ciphertext_len+=len;
	 }
	 if(1 != EVP_EncryptUpdate(ctx, ciphertext+ciphertext_len, &len, plaintext+ciphertext_len, plaintext_len-ciphertext_len))
	 	error("[symmetric crypto]: encryption failed");
	 ciphertext_len+=len;

	/* Finalise the encryption. Normally ciphertext bytes may be written at
	 * this stage, but this does not occur in GCM mode
	 */
	if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + ciphertext_len, &len)) error("[symmetric crypto]: encryption failed");
	ciphertext_len += len;

	/* Get the tag */
	if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag))
		error("[symmetric crypto]: encryption failed");

	/* Clean up */
	EVP_CIPHER_CTX_free(ctx);

	return ciphertext_len;
}


int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *aad,
	int aad_len, unsigned char *tag, unsigned char *key, unsigned char *iv,
	unsigned char *plaintext)
{
	EVP_CIPHER_CTX *ctx;
	int len=0, plaintext_len=0, ret;

	/* Create and initialise the context */
	if(!(ctx = EVP_CIPHER_CTX_new())) 
		error("[symmetric crypto]: decryption failed");

	/* Initialise the decryption operation. */
	if(!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
		error("[symmetric crypto]: decryption failed");

	/* Set IV length. Not necessary if this is 12 bytes (96 bits) */
	if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 16, NULL))
		error("[symmetric crypto]: decryption failed");

	/* Initialise key and IV */
	if(!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv)) error("[symmetric crypto]: decryption failed");

	/* Provide any AAD data. This can be called zero or more times as
	 * required
	 */
	if(!EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len))
		error("[symmetric crypto]: decryption failed");

	/* Provide the message to be decrypted, and obtain the plaintext output.
	 * EVP_DecryptUpdate can be called multiple times if necessary
	 */
	 while(plaintext_len<=ciphertext_len-16)
	 {
	 	if(1!=EVP_DecryptUpdate(ctx, plaintext+plaintext_len, &len, ciphertext+plaintext_len, 16))
	 		error("[symmetric crypto]: decryption failed");
	 	plaintext_len+=len;
	 }
	 if(1!=EVP_DecryptUpdate(ctx, plaintext+plaintext_len, &len, ciphertext+plaintext_len, ciphertext_len-plaintext_len))
	 		error("[symmetric crypto]: decryption failed");
	 plaintext_len+=len;

	/* Set expected tag value. Works in OpenSSL 1.0.1d and later */
	if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag))
		error("[symmetric crypto]: decryption failed");

	/* Finalise the decryption. A positive return value indicates success,
	 * anything else is a failure - the plaintext is not trustworthy.
	 */
	ret = EVP_DecryptFinal_ex(ctx, plaintext + plaintext_len, &len);

	/* Clean up */
	EVP_CIPHER_CTX_free(ctx);

	if(ret > 0)
	{
		/* Success */
		plaintext_len += len;
		return plaintext_len;
	}
	else
	{
		/* Verify failed */
		return -1;
	}
}

int main(int argc, char *argv[])
{
	// Sockets parameters
    int sockfd, newsockfd, portno;
    socklen_t clilen;
    char buffer[256];
    struct sockaddr_in serv_addr, cli_addr;
    int n;
	
	// Digital signature parameters
	
	// Key exchange parameters
	
	//AES
	unsigned char aesKey[AES_KEY_SIZE], tag[TAG_SIZE];
	unsigned char iv[IV_SIZE];
	unsigned char aad[AAD_SIZE];	//dummy
	int k;
	
	// Buffers and others
	char bufferIn[1024], bufferOut[1024];
	FILE *fp;
	int fileSize;
	char *initPos;
	unsigned char  *cipherText, *plainText, *message;
	int acum = 0;
	
	

    if (argc < 2) {
        fprintf(stderr,"ERROR, no port provided\n");
        return(-1);
    }
		
	/* 
	 * TCP synchronization 
	 */
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0){
       error("ERROR opening socket");
    }

    bzero((char *) &serv_addr, sizeof(serv_addr));
    portno = atoi(argv[1]);
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(portno);

    if (bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0){
        error("ERROR on binding");
    }

    listen(sockfd,5);
    clilen = sizeof(cli_addr);
    newsockfd = accept(sockfd, (struct sockaddr *) &cli_addr, &clilen);
    if (newsockfd < 0){
        error("ERROR on accept");
    }
	
	/*
	 * Authentication
	 */
	 
	/* 
	 * Key exchange
	 */
	 
	/* Socket -1: AES key */ 
	if((n = read(newsockfd, aesKey, AES_KEY_SIZE) < 0)){
		error("ERROR reading from socket");
    }
	print_hex(aesKey, AES_KEY_SIZE);

	/* 
	 * Application: bitstream decryption 
	 */
	
	/* Socket 1: allocate memory for the incoming message */
    unsigned int messageSize = 0;
    n = read(newsockfd, &messageSize, sizeof(messageSize));
    if (n < 0){
        error("ERROR reading from socket");
    }
	fileSize = messageSize - AAD_SIZE - IV_SIZE - TAG_SIZE - EVP_MAX_BLOCK_LENGTH;
    message = (char *) calloc(messageSize, sizeof(char));
	initPos = message;
	
	/* Socket 2: receive message */
    //Receive file: large messages are segmented in packets of variable
    //size. A loop is needed for receiving the whole message
    while((n = read(newsockfd, message, messageSize)) > 0){
        message += n;
        acum += n;
        if(acum >= messageSize){
           message = initPos;
           break;
        }
    }
	
	/* Split message: AAD + IV + TAG + CYPHERTEXT */
	cipherText = (char *) calloc(fileSize + EVP_MAX_BLOCK_LENGTH, sizeof(char));
	
	unsigned long long i;
	for(i = 0; i < AAD_SIZE; i++){
		aad[i] = *(message + i);
	}
	message++;
	for(i = 0; i < IV_SIZE; i++){
		iv[i] = *(message + i); 
	}
	message++;
	for(i = 0; i < TAG_SIZE; i++){
		tag[i] = *(message + i);
	}
	message++;
	for(i = 0; i < (fileSize + EVP_MAX_BLOCK_LENGTH); i++){
		cipherText[i] = *(message + i);
	}
	
	/* AES decryption */
	plainText = (char *) calloc(fileSize + EVP_MAX_BLOCK_LENGTH, sizeof(char));
	k = decrypt(cipherText, fileSize, aad, sizeof(aad), tag, aesKey, iv, plainText);
	printf("Decrypted size: %d; File size: %d\n", k, fileSize);
	if(k < fileSize){
		error("[symmetric crypto]: decrypted data size missmatch file size");
	}
	
    fp = fopen("test.bin", "w");
	if(fp == NULL){
		error("could not create file");
	}
	fwrite(plainText, sizeof(char), fileSize, fp);
    fclose(fp);
	
	/* Socket 3: Confirm bitstream arrived and decrypted */
    n = write(newsockfd,"File received!",14);
    if (n < 0){
        error("ERROR writing to socket");
    }
	
	/* 
	 * Reconfiguration
	 */

    close(newsockfd);
    close(sockfd);
    return (0);
}
	 
	 
