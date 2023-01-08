#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h> 
#include <openssl/rand.h>
#include <openssl/evp.h>

#define ERROR -1
#define NO_ERROR 0
#define AAD_SIZE 16
#define IV_SIZE 16
#define AES_KEY_SIZE 32
#define TAG_SIZE 100 

#define MAX_PATH 1025
#define BUFFER_IN_SIZE 1025
#define BUFFER_OUT_SIZE 1025

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
    int sockfd, portno, n;
    struct sockaddr_in serv_addr;
    struct hostent *server;
	
	/* Crypto related parameters and arrays of char that may contain NULL not 
	recommended to be treated as strings ("array + \0"), because the algorithm 
	would not know where the real NULL is located */
	
	// Digital signature parameters
	// Key exchange parameters
	
	//AES
	unsigned char aesKey[AES_KEY_SIZE], tag[TAG_SIZE], iv[IV_SIZE];
	unsigned char aad[AAD_SIZE]="abcdefghijklmnop";	//dummy
	int nEncrypted;
	
	// Buffers and others
	unsigned char path[MAX_PATH], bufferIn[BUFFER_IN_SIZE], bufferOut[BUFFER_OUT_SIZE];
	FILE *fp;
	unsigned int fileSize;
	unsigned char  *cipherText, *plainText, *message;
	
    if (argc < 3) {
	   error("Arguments in this order: ./client <IP address> <server port>");
    }
	
	/* 
	 * TCP synchronization 
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
	 * Authentication 
	 */
	
	/* 
	 * Key exchange (NTRU KEM generates AES key so remove below)
	 */
	 
	/* AES key generation */ 
	if(!RAND_bytes(aesKey,sizeof(aesKey))){
		error("[symmetric crypto]: key generation failed");
	}
	//print_hex(aesKey, sizeof(aesKey));
	/* Generate random IV */
	while(!RAND_bytes(iv,sizeof(iv)));
	//print_hex(iv, sizeof(iv));
	
	/* Socket -1: AES key */
	if((n = write(sockfd, aesKey, AES_KEY_SIZE)) < 0){
		error("ERROR writing to socket");
	}
	
	/* 
	 * Application: bitstream encryption 
	 */
	 
	/* Ask for file path */
    printf("Please enter the path of your file: ");
    bzero(path,1025); //Good trick to add NULL at the end to form a string
	scanf("%s",path);
	fp = fopen(path, "r");
	if(fp == NULL){
		error("could not open file");
	}
	
	/* Guess file size */ 
	fseek(fp, 0, SEEK_END); //fseek modifies position of fp (be careful)
	fileSize = ftell(fp);
	fseek(fp, 0, SEEK_SET);
	printf("Size of file '%s': %d bytes\n", path, fileSize);
	
	/* File encryption */ 
	plainText = (char *) calloc(fileSize, sizeof(char));
	cipherText = (char *) calloc(fileSize + EVP_MAX_BLOCK_LENGTH, sizeof(char));
	
	fread(plainText, sizeof(char), fileSize, fp);
	if((nEncrypted = encrypt(plainText, fileSize, aad, sizeof(aad), aesKey, iv, cipherText, tag)) != fileSize){
		error("[symetric crypto]: plaintext and cyphertext size missmatch.");
	}
	
	printf("Number of encrypted characters: %d\n", nEncrypted);
	print_hex("AAD: ",aad, AAD_SIZE);
	print_hex("AES: ", aesKey, AES_KEY_SIZE);
	print_hex("IV: ", iv, IV_SIZE);
	print_hex("TAG: ", tag, TAG_SIZE);
	print_hex("CYPHERTEXT: ", cipherText, 32);
	
	printf("Cypher text size: %d bytes\n", k);
	free(plainText);
	
	/* Build message: AAD + IV + TAG + CYPHERTEXT */
	unsigned int messageSize = AAD_SIZE + IV_SIZE + TAG_SIZE + fileSize + EVP_MAX_BLOCK_LENGTH;
	message = (char *) calloc(messageSize, sizeof(char));
	unsigned long long i;
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
	
	/* Socket 1: Send message size for dynamic memory allocation at server */ //MAYBE JUST SEND MESSAGE SIZE, AND CALCULATES file size at server
	n = write(sockfd, &messageSize, sizeof(messageSize));
	if (n < 0){ 
         error("ERROR writing to socket");
	}
	//print_hex("Message: ", message, AAD_SIZE + IV_SIZE + TAG_SIZE);
    /* Socket 2: Send message */	
	if((n = write(sockfd, message, messageSize)) < 0){
		error("ERROR writing to socket");
	}
	printf("Data sent size: %d bytes\n", n);
	free(message);
	
	/* Socket 3: Wait for confirmation from server */
	bzero(bufferIn, 256);
    n = read(sockfd, bufferIn, 255);
	printf("\n%s\n",bufferIn);
    if (n < 0){ 
         error("ERROR reading from socket");
	}
	
	fclose(fp);
    close(sockfd);
    return 0;
}

