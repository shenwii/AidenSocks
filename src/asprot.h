#ifndef _ASPROT_H
#define _ASPROT_H

#include <stdint.h>

#define ASP_MAX_RANDOM_LENGTH 1024
#define ASP_MAX_DATA_LENGTH(len) (AES_ENCODE_LEN(sizeof(asp_header_t)) + AES_ENCODE_LEN(len) + ASP_MAX_RANDOM_LENGTH)

typedef int (*asp_decrypt_callback_f)(void *, __const__ char, __const__ char, __const__ char *, __const__ int);

typedef struct asp_buffer_s
{
    char *buf;
    int len;
} asp_buffer_t;

typedef struct asp_header_s
{
    uint32_t crc32;
    uint32_t data_total_len;
    uint32_t data_len;
    char status;
    char type;
    char unused;
} __attribute__((__packed__)) asp_header_t;

int asp_encrypt(__const__ char type, __const__ char status, __const__ unsigned char *indata, __const__ int inlen, __const__ unsigned char *aes_key, unsigned char *outdata, int *outlen);

int asp_decrypt(__const__ void *parm, __const__ unsigned char *indata, __const__ int inlen, __const__ unsigned char *aes_key, asp_buffer_t *buf, asp_decrypt_callback_f cb);

#endif
