#include "asprot.h"
#include "aes.h"
#include "crc32.h"
#include "log.h"
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

/*
 *  +--------------------------------------------------------------+------------------+
 *  |                          HEADER                              |       BODY       |
 *  +-----+----------------+-------------+--------+------+---------+------------------+
 *  | CRC | DATA TOTAL LEN |  DATA LEN   | STATUS | TYPE | RESERVE |  INPUT RAW DATA  |
 *  +-----+----------------+-------------+--------+------+---------+------------------+
 *  |  4  |        4       |      4      |    1   |  1   |    1    |   Raw Data Len   |
 *  +-----+----------------+-------------+--------+------+---------+------------------+
 *  |                            AES CRC ENCRYPT                   | AES CRC ENCRYPT  |
 *  +--------------------------------------------------------------+------------------+-------------+
 *  |                            ENCRYPTED HEADER                  |  ENCRYPTED BODY  | RANDOM DATA |
 *  +--------------------------------------------------------------+------------------+-------------+
 *  |                                  15                          |     Variable     |   1~1024    |
 *  +--------------------------------------------------------------+------------------+-------------+
 *  data total len = encrypted body len + random data len
 *  type = 0x01: tcp connect to host request
 *         0x02: tcp send request
 *         0x11: tcp connect to host response
 *         0x21: udp send to request
 *         0x22: udp send request
 */
int asp_encrypt(__const__ char type, __const__ char status, __const__ unsigned char *indata, __const__ size_t inlen, __const__ unsigned char *aes_key, unsigned char *outdata, size_t *outlen)
{
    static char fst = 0;
    unsigned char *tmp;
    if(fst == 0)
    {
        srand((unsigned) time(NULL));
        fst = 1;
    }
    asp_header_t header;
    memset(&header, 0, sizeof(asp_header_t));
    size_t headerlen = AES_ENCODE_LEN(sizeof(asp_header_t));
    size_t mindatalen = AES_ENCODE_LEN(inlen);
    size_t randlen = rand() % ASP_MAX_RANDOM_LENGTH + 1;
    if(inlen != 0)
        header.crc32 = CRC32(indata, inlen);
    header.data_total_len = htonl(mindatalen + randlen);
    header.data_len = htonl(inlen);
    header.status = status;
    header.type = type;
    *outlen = headerlen + mindatalen + randlen;
    aes_encrypt((unsigned char *) &header, sizeof(asp_header_t), outdata, aes_key);
    if(inlen != 0)
        aes_encrypt(indata, inlen, outdata + headerlen, aes_key);
    tmp = outdata + headerlen + mindatalen;
    while(randlen--)
        *tmp++ = rand() % 256;
    return 0;
}

int asp_decrypt(__const__ void *parm, __const__ unsigned char *indata, __const__ size_t inlen, __const__ unsigned char *aes_key, asp_buffer_t *buf, asp_decrypt_callback_f cb)
{
    char is_call = 0;
    unsigned char *tbuf;
    size_t tlen;
    asp_header_t header;
    uint32_t data_total_len;
    uint32_t data_len;
    int headerlen = AES_ENCODE_LEN(sizeof(asp_header_t));
    int rtn = 0;
    if(inlen == 0)
        return rtn;
    if(buf->len == 0)
    {
        buf->buf = malloc(inlen);
        memcpy(buf->buf, indata, inlen);
        buf->len = inlen;
    }
    else
    {
        buf->buf = (unsigned char *) realloc(buf->buf, inlen + buf->len);
        unsigned char *t = buf->buf;
        t += buf->len;
        memcpy(t, indata, inlen);
        buf->len += inlen;
    }
    tbuf = buf->buf;
    tlen = buf->len;
    while(1)
    {
        if(tlen <= headerlen)
            break;
        aes_decrypt(tbuf, sizeof(asp_header_t), (unsigned char *) &header, aes_key);
        data_total_len = ntohl(header.data_total_len);
        data_len = ntohl(header.data_len);
        if(data_total_len < AES_ENCODE_LEN(data_len))
        {
            rtn = 1;
            tlen = 0;
            break;
        }
        if(tlen < headerlen + data_total_len)
            break;
        unsigned char *ucdata;
        if(data_len == 0)
        {
            ucdata = NULL;
        }
        else
        {
            ucdata = (unsigned char *) malloc(AES_ENCODE_LEN(data_len));
            if(ucdata == NULL)
            {
                LOG_ERR(MSG_NOT_ENOUGH_MEMORY);
                abort();
            }
            aes_decrypt(tbuf + headerlen, data_len, ucdata, aes_key);
        }
        if((ucdata == NULL && header.crc32 != 0)
            || (CRC32(ucdata, data_len) != header.crc32))
        {
            rtn = 2;
            tlen = 0;
            break;
        }
        if(cb == NULL)
        {
            rtn = 3;
            tlen = 0;
            break;
        }
        rtn = cb((void *) parm, header.type, header.status, ucdata, data_len);
        is_call = 1;
        free(ucdata);
        if(rtn != 0)
        {
            rtn = 4;
            tlen = 0;
            break;
        }
        tbuf += headerlen + data_total_len;
        tlen -= headerlen + data_total_len;
    }
    if(tlen == 0)
    {
        free(buf->buf);
        buf->buf = NULL;
        buf->len = 0;
    }
    if(buf->len != tlen)
    {
        unsigned char *wf_buf = buf->buf;
        buf->buf = (unsigned char *) malloc(tlen);
        memcpy(buf->buf, tbuf, tlen);
        buf->len = tlen;
        free(wf_buf);
    }
    if(rtn == 0 && is_call == 0)
        return -1;
    return rtn;
}
