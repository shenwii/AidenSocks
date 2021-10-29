#ifndef _AES_H
#define _AES_H

#define AES_KEY_LEN 256
#define AES_ENCODE_LEN(s) ((s / AES_BLOCK_SIZE + 1) * AES_BLOCK_SIZE)

int aes_encrypt(__const__ unsigned char *indata, __const__ int len, unsigned char *outdata, __const__ unsigned char *key);

int aes_decrypt(__const__ unsigned char *indata, __const__ int len, unsigned char *outdata, __const__ unsigned char *key);

#endif
