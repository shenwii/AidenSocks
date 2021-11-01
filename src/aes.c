#include "aes.h"

#include <string.h>
#include <openssl/evp.h>
#include <openssl/aes.h>

int __aes_en_de_crypt(__const__ int flg_encrypt, __const__ unsigned char *indata, __const__ int len, unsigned char *outdata, __const__ unsigned char *key)
{
    int out_len = 0;
    unsigned char iv[AES_BLOCK_SIZE];
    memset(iv, '\0', AES_BLOCK_SIZE);
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if(ctx == NULL)
        return 1;
    EVP_CIPHER_CTX_init(ctx);
    EVP_CipherInit(ctx, EVP_aes_256_cbc(), key, iv, flg_encrypt);
    EVP_CipherUpdate(ctx, outdata, &out_len, indata, len);
    EVP_CipherFinal(ctx, outdata + out_len, &out_len);
    EVP_CIPHER_CTX_free(ctx);
    return 0;
}

int aes_encrypt(__const__ unsigned char *indata, __const__ int len, unsigned char *outdata, __const__ unsigned char *key)
{
    return __aes_en_de_crypt(AES_ENCRYPT, indata, len, outdata, key);
}

int aes_decrypt(__const__ unsigned char *indata, __const__ int len, unsigned char *outdata, __const__ unsigned char *key)
{
    int tmp_len = AES_ENCRYPT_LEN(len);
    unsigned char *tmp_buf = malloc(tmp_len);
    if(tmp_buf == NULL)
        return 1;
    int rtn = __aes_en_de_crypt(AES_DECRYPT, indata, tmp_len, tmp_buf, key);
    if(rtn != 0)
    {
        free(tmp_buf);
        return rtn;
    }
    memcpy(outdata, tmp_buf, len);
    free(tmp_buf);
    return rtn;
}
