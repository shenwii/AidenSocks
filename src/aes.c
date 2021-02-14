#include "aes.h"

#include <string.h>


int aes_encrypt(__const__ unsigned char *indata, __const__ int len, unsigned char *outdata, __const__ unsigned char *key)
{
    unsigned char iv[AES_BLOCK_SIZE];
    AES_KEY aes;
    memset(iv, '\0', AES_BLOCK_SIZE);
    AES_set_encrypt_key(key, AES_KEY_LEN, &aes);
    AES_cbc_encrypt(indata, outdata, len, &aes, iv, AES_ENCRYPT);
    return 0;
}

int aes_decrypt(__const__ unsigned char *indata, __const__ int len, unsigned char *outdata, __const__ unsigned char *key)
{
    unsigned char iv[AES_BLOCK_SIZE];
    AES_KEY aes;
    memset(iv, '\0', AES_BLOCK_SIZE);
    AES_set_decrypt_key(key, AES_KEY_LEN, &aes);
    AES_cbc_encrypt(indata, outdata, len, &aes, iv, AES_DECRYPT);
    return 0;
}
