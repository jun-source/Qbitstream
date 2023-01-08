#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h>
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
#define SECRET_MSG_SIZE CRYPTO_BYTES + RANDOM_CHALLENGE_SIZE
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


void print_hex(unsigned char *header, unsigned char *bytes, int n) {
	int i;
	printf("%s", header);
	for (i = 0; i < n; i++) {
		printf("%02x ", bytes[i]);
	}
	printf("\n");
}

int main(int argc, char *argv[])
{
	/* Sockets parameters */
    int sockfd, newsockfd, portno;
    socklen_t clilen;
    struct sockaddr_in serv_addr, cli_addr;
    int n;
	
	/* Digital signature parameters */
	unsigned char random_challg[RANDOM_CHALLENGE_SIZE]; //THINK THROUGHLY ABOUT SIZE OF MESSAGE, CURRENT CHOSEN ARBITRARY
	unsigned char *sm, *m;
	unsigned long long mlen, smlen;
	unsigned char pk_ds[CRYPTO_PUBLICKEYBYTES];
	int ret_val;
	
	/* Key exchange parameters */
	unsigned char seed[48]; 
	unsigned char sk_kem[CRYPTO_SECRETKEYBYTES_NTRU];
	unsigned char pk_kem[CRYPTO_PUBLICKEYBYTES_NTRU];
	unsigned char cypher_key[CRYPTO_CIPHERTEXTBYTES_NTRU];
	
	//AES
	unsigned char aes_key[AES_KEY_SIZE]; 
	unsigned char tag[TAG_SIZE];
	unsigned char iv[IV_SIZE];
	unsigned char aad[AAD_SIZE];	//dummy
	int k;
	
	// Buffers and others
	unsigned char buffer_in[BUFFER_IN_SIZE]; 
	unsigned char buffer_out[BUFFER_OUT_SIZE];
	FILE *fp;
	int fileSize;
	char *initPos;
	unsigned char  *cipherText, *plainText, *message;
	int acum = 0;
	char command[2048];
	
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
	
	fp = fopen("keys/pk_dilith.bin", "r");
	if(fp == NULL){
		error("Could not open file");
	}
	if(fread(pk_ds, sizeof(unsigned char), CRYPTO_PUBLICKEYBYTES, fp) != CRYPTO_PUBLICKEYBYTES){
		error("Public key not valid");
	}	
	fclose(fp);
	
	m = (unsigned char *) calloc(SECRET_MSG_SIZE, sizeof(unsigned char));
	sm = (unsigned char *) calloc(SECRET_MSG_SIZE, sizeof(unsigned char));
	acum = 0;
	
	/* Socket 1: wait for secret message */
	while((n = read(newsockfd, sm + acum, SECRET_MSG_SIZE)) > 0){
		acum += n;		
		if(acum >= SECRET_MSG_SIZE){
			acum = 0;
			break;
		}
    }
    printf("Authentication request accepted\n"); 
	
	if((ret_val = crypto_sign_open(m, &mlen, sm, SECRET_MSG_SIZE, pk_ds)) != 0){
        printf("crypto_sign_open returned <%d>\n", ret_val);
		free(m);
        free(sm);
		bzero(buffer_out, BUFFER_OUT_SIZE);
		strcpy(buffer_out, "[from server] Authentication failed");
		
		/* Socket 2: send confirmation authentication failed */
		if ((n = write(newsockfd, buffer_out, BUFFER_OUT_SIZE)) < 0){
			error("ERROR writing to socket");
		}
        return ERROR;
    }

    if(mlen != RANDOM_CHALLENGE_SIZE){
        printf("crypto_sign_open returned bad 'mlen': Got <%llu>, expected <%llu>\n", mlen, RANDOM_CHALLENGE_SIZE);
		free(m);
        free(sm);
		bzero(buffer_out, BUFFER_OUT_SIZE);
		strcpy(buffer_out, "[from server] Authentication failed");
		
		/* Socket 2: send confirm authentication failed */
		if ((n = write(newsockfd, buffer_out, BUFFER_OUT_SIZE)) < 0){
			error("ERROR writing to socket");
		}
        return ERROR;
    }

    if (memcmp(sm + CRYPTO_BYTES, m, mlen)) {
        printf("crypto_sign_open returned bad 'm' value\n");
		free(m);
        free(sm);
		bzero(buffer_out, BUFFER_OUT_SIZE);
		strcpy(buffer_out, "[from server] Authentication failed");
		
		/* Socket 2: send confirm authentication failed */
		if ((n = write(newsockfd, buffer_out, BUFFER_OUT_SIZE)) < 0){
			error("ERROR writing to socket");
		}
        return ERROR;
    }
	
    free(m);
	free(sm);
	
	/* Socket 2: send confirm authentication sucess */
	bzero(buffer_out, BUFFER_OUT_SIZE);
	strcpy(buffer_out, "[from server] Authentication succeeded");
    if ((n = write(newsockfd, buffer_out, BUFFER_OUT_SIZE)) < 0){
        error("ERROR writing to socket");
    }
	printf("Authentication completed and succeeded\n");
	 
	/* 
	 * Key exchange
	 */
	 
	printf("Starting key exchange...\n"); 
	/* Socket 3: wait for kem keypair update request */
	acum = 0;
	while((n = read(newsockfd, buffer_in + acum, BUFFER_IN_SIZE)) > 0){
		acum += n;
		if(acum >= BUFFER_IN_SIZE){
			break;
		}
	}
	
	if(!strcmp(buffer_in, "Kem keypair update")){
		
		/* Key pair generation for NTRU */
		RAND_bytes(seed, sizeof(seed));
		randombytes_init(seed, NULL, 256);
		
		/* Generate the kem keypair */
		if((ret_val = crypto_kem_keypair(pk_kem, sk_kem)) != 0){ 
			error("[KEM] Keypair generation FAILURE");
		}

		/* Storage keypair */
		fp = fopen("keys/pk_ntru.bin", "w");
		if(fp == NULL){
			error("Could not create file");
		}
		if(fwrite(pk_kem, sizeof(unsigned char), sizeof(pk_kem), fp) != CRYPTO_PUBLICKEYBYTES_NTRU){
			error("Public key stored in file not valid");
		}	
		fclose(fp);
		fp = fopen("keys/sk_ntru.bin", "w");
		if(fp == NULL){
			error("Could not create file");
		}
		if(fwrite(sk_kem, sizeof(unsigned char), sizeof(sk_kem), fp) != CRYPTO_SECRETKEYBYTES_NTRU){
			error("Private key stored in file not valid");
		}	
		fclose(fp);
		
		/* Socket 4: send kem public key */
		if((n = write(newsockfd, pk_kem, CRYPTO_PUBLICKEYBYTES_NTRU)) < 0){
			error("ERROR writing to socket");
		}	
	}else{
		fp = fopen("keys/sk_ntru.bin", "r");
		if(fp == NULL){
			error("Could not open file");
		}
		if(fread(sk_kem, sizeof(unsigned char), CRYPTO_SECRETKEYBYTES_NTRU, fp) != CRYPTO_SECRETKEYBYTES_NTRU){
			error("Secret key not valid");
		}	
		fclose(fp);
		
		/* Socket 4: send confirmation using old kem keypair */
		bzero(buffer_out, BUFFER_OUT_SIZE);
		strcpy(buffer_out, "[from server] KEM keypair not updated");
		if((n = write(newsockfd, buffer_out, BUFFER_OUT_SIZE)) < 0){
			error("ERROR writing to socket");
		}	
	}
	
	/* Socket 5: receive cipher AES key */
	acum = 0;
	while((n = read(newsockfd, cypher_key + acum, CRYPTO_CIPHERTEXTBYTES_NTRU)) > 0){
		acum += n;
		if(acum >= CRYPTO_CIPHERTEXTBYTES_NTRU){
			break;
		}
    } 
	
	/* KEM decription */
	if ((ret_val = crypto_kem_dec(aes_key, cypher_key, sk_kem)) != 0) {
		error("[KEM] Key exchange failed!");
    }
	
	/* Socket 6: send confirmation about kem sucess */
	bzero(buffer_out, BUFFER_OUT_SIZE);
	strcpy(buffer_out, "[from server] Key exchange succeeded");
	if((n = write(newsockfd, buffer_out, BUFFER_OUT_SIZE)) < 0){
		error("ERROR writing to socket");
	}	
	printf("Key exchange succeeded\n");
	
	/* 
	 * Application: bitstream decryption 
	 */
	
	printf("Starting secure bitstream distribution...\n");
	/* Socket 7: wait for allocate memory for the incoming message */
    unsigned int messageSize = 0;
	acum = 0;
	while((n = read(newsockfd, &messageSize + acum, sizeof(messageSize))) > 0){//maybe change for atoi
		acum += n;
		if(acum >= sizeof(messageSize)){
			break;
		}
	}
	fileSize = messageSize - AAD_SIZE - IV_SIZE - TAG_SIZE - EVP_MAX_BLOCK_LENGTH;
    message = (char *) calloc(messageSize, sizeof(char));
	
	/* Socket 8: send confirmation that enough memory is reserved */
	bzero(buffer_out, BUFFER_OUT_SIZE);
	strcpy(buffer_out, "[from server] Memory reserved, ready for receive large data");
	if((n = write(newsockfd, buffer_out, BUFFER_OUT_SIZE)) < 0){
		error("ERROR writing to socket");
	}	
  
	/* Socket 9: wait for message */
	acum = 0;
    while((n = read(newsockfd, message + acum, messageSize)) > 0){
        acum += n;
        if(acum >= messageSize){
           break;
        }
    }
	
	/* Split message: AAD + IV + TAG + CYPHERTEXT */
	cipherText = (char *) calloc(fileSize + EVP_MAX_BLOCK_LENGTH, sizeof(char));
	unsigned long long i;
	for(i = 0; i < AAD_SIZE; i++){
		aad[i] = *(message + i);
	}	
	for(i = 0; i < IV_SIZE; i++){
		iv[i] = *(message + AAD_SIZE + i); 
	}
	for(i = 0; i < TAG_SIZE; i++){
		tag[i] = *(message + AAD_SIZE + IV_SIZE + i);
	}
	for(i = 0; i < (fileSize + EVP_MAX_BLOCK_LENGTH); i++){
		cipherText[i] = *(message + AAD_SIZE + IV_SIZE + TAG_SIZE + i);
	}
	free(message);
	
	/* AES decryption */
	plainText = (char *) calloc(fileSize + EVP_MAX_BLOCK_LENGTH, sizeof(char));
	if((k = decrypt_aes_gcm(cipherText, fileSize, aad, sizeof(aad), tag, aes_key, iv, plainText)) != fileSize){
		free(cipherText);
        free(plainText);
		bzero(buffer_out, BUFFER_OUT_SIZE);
		strcpy(buffer_out, "[from server] Bitstream decryption failed");
		
		/* Socket 10: send confirmation decryption failed */
		if ((n = write(newsockfd, buffer_out, BUFFER_OUT_SIZE)) < 0){
			error("ERROR writing to socket");
		}
		error("[symmetric crypto]: decrypted data size missmatch file size");
	}else{
		bzero(buffer_out, BUFFER_OUT_SIZE);
		strcpy(buffer_out, "[from server] Bitstream decryption succeeded");
		
		/* Socket 10: send confirmation decryption succeeded */
		if ((n = write(newsockfd, buffer_out, BUFFER_OUT_SIZE)) < 0){
			error("ERROR writing to socket");
		}
		printf("Bitstream decryption succeeded\n");
	}
		
    fp = fopen("/lib/firmware/qbitstream.bin", "w");
	if(fp == NULL){
		error("could not create file");
	}
	if(fwrite(plainText, sizeof(char), fileSize, fp) != fileSize){
		error("Bitstream not storaged correctly");
	}	
    fclose(fp);
	

	/* 
	 * Reconfiguration NEED FOR AESTHETICS IMPROVMENT (TRY TO RECEIVE CONFIRMATION FROM TERM THAT RECONFIG EXECUTED)
	 */
	
	printf("Starting reconfiguration...\n");
	
	/* Socket 11: send ready to be reconfigured */
	bzero(buffer_out, BUFFER_OUT_SIZE);
	strcpy(buffer_out, "[from server] Starting reconfiguration...");
    if ((n = write(newsockfd, buffer_out, BUFFER_OUT_SIZE)) < 0){
        error("ERROR writing to socket");
    }
		
	/* flags values for different reconfiguration option */
	/*
	{.flag = "Full",                .value = 0x0},
	{.flag = "Partial",             .value = 0x1},
	{.flag = "AuthDDR",             .value = 0x40},
	{.flag = "AuthOCM",             .value = 0x80},
	{.flag = "EnUsrKey",            .value = 0x20},
	{.flag = "EnDevKey",            .value = 0x4},
	{.flag = "AuthEnUsrKeyDDR",     .value = 0x60},
	{.flag = "AuthEnUsrKeyOCM",     .value = 0xA0},
	{.flag = "AuthEnDevKeyDDR",     .value = 0x44},
	{.flag = "AuthEnDevKeyOCM",     .value = 0x84},
	*/
	
	/* Set up flags for Full reconfiguration */
	snprintf(command, sizeof(command), "echo 0x0 > /sys/class/fpga_manager/fpga0/flags");
	if(system(command) != 0){
		error("[reconfiguration] Command not executed");
	}
	
	/* Trigger reconfiguration */
	snprintf(command, sizeof(command), "cd /lib/firmware; echo qbitstream.bin > /sys/class/fpga_manager/fpga0/firmware");
	if(system(command) != 0){
		error("[reconfiguration] Command not executed");
	}
	
	printf("Reconfiguration SUCESS!!\n");
	
	/* Socket 12: send reconfiguration succeeded */
	bzero(buffer_out, BUFFER_OUT_SIZE);
	strcpy(buffer_out, "[from server] Reconfiguration SUCESS!!");
    if ((n = write(newsockfd, buffer_out, BUFFER_OUT_SIZE)) < 0){
        error("ERROR writing to socket");
    }

    close(newsockfd);
    close(sockfd);
    return (0);
}
	 
	 
