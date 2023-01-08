
#ifndef AES_GCM_H
#define AES_GCM_H

void error_aes(const char *msg);

int encrypt_aes_gcm(unsigned char *plaintext, int plaintext_len, unsigned char *aad,
	int aad_len, unsigned char *key, unsigned char *iv,
	unsigned char *ciphertext, unsigned char *tag);
	
int decrypt_aes_gcm(unsigned char *ciphertext, int ciphertext_len, unsigned char *aad,
	int aad_len, unsigned char *tag, unsigned char *key, unsigned char *iv,
	unsigned char *plaintext);

#endif