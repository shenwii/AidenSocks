#include "base64.h"

static __const__ unsigned char B64_ENCODE_TABLE[64] =
{
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
    'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
    'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
    'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
    'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
    'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
    'w', 'x', 'y', 'z', '0', '1', '2', '3',
    '4', '5', '6', '7', '8', '9', '+', '/'
};

static __const__ unsigned char B64_DECODE_TABLE[256] =
{
     0,  0,  0,  0,  0,  0,  0,  0,
     0,  0,  0,  0,  0,  0,  0,  0,
     0,  0,  0,  0,  0,  0,  0,  0,
     0,  0,  0,  0,  0,  0,  0,  0,
     0,  0,  0,  0,  0,  0,  0,  0,
     0,  0,  0, 62,  0,  0,  0, 63,
    52, 53, 54, 55, 56, 57, 58, 59,
    60, 61,  0,  0,  0,255,  0,  0,
     0,  0,  1,  2,  3,  4,  5,  6,
     7,  8,  9, 10, 11, 12, 13, 14,
    15, 16, 17, 18, 19, 20, 21, 22,
    23, 24, 25,  0,  0,  0,  0,  0,
     0, 26, 27, 28, 29, 30, 31, 32,
    33, 34, 35, 36, 37, 38, 39, 40,
    41, 42, 43, 44, 45, 46, 47, 48,
    49, 50, 51,  0,  0,  0,  0,  0,
     0,  0,  0,  0,  0,  0,  0,  0,
     0,  0,  0,  0,  0,  0,  0,  0,
     0,  0,  0,  0,  0,  0,  0,  0,
     0,  0,  0,  0,  0,  0,  0,  0,
     0,  0,  0,  0,  0,  0,  0,  0,
     0,  0,  0,  0,  0,  0,  0,  0,
     0,  0,  0,  0,  0,  0,  0,  0,
     0,  0,  0,  0,  0,  0,  0,  0,
     0,  0,  0,  0,  0,  0,  0,  0,
     0,  0,  0,  0,  0,  0,  0,  0,
     0,  0,  0,  0,  0,  0,  0,  0,
     0,  0,  0,  0,  0,  0,  0,  0,
     0,  0,  0,  0,  0,  0,  0,  0,
     0,  0,  0,  0,  0,  0,  0,  0,
     0,  0,  0,  0,  0,  0,  0,  0,
     0,  0,  0,  0,  0,  0,  0,  0
};

int b64_encode(__const__ unsigned char *indata, __const__ int len, unsigned char *outdata)
{
    unsigned char *itmp = (unsigned char *) indata;
    unsigned char *otmp = outdata;
    if(len == 0) return 0;
    for(int i = 0; i < len / 3; i++)
    {
        *otmp++ = B64_ENCODE_TABLE[(*itmp++ >> 2) & 0x3f];
        *otmp++ = B64_ENCODE_TABLE[(*(itmp - 1) << 4 | *itmp >> 4) & 0x3f]; itmp++;
        *otmp++ = B64_ENCODE_TABLE[(*(itmp - 1) << 2 | *itmp >> 6) & 0x3f];
        *otmp++ = B64_ENCODE_TABLE[*itmp++ & 0x3f];
    }
    switch(len %3 )
    {
        case 0:
            break;
        case 1:
            *otmp++ = B64_ENCODE_TABLE[(*itmp >> 2) & 0x3f];
            *otmp++ = B64_ENCODE_TABLE[(*itmp << 4) & 0x3f];
            *otmp++ = '=';
            *otmp++ = '=';
            break;
        case 2:
            *otmp++ = B64_ENCODE_TABLE[(*itmp++ >> 2) & 0x3f];
            *otmp++ = B64_ENCODE_TABLE[(*(itmp - 1) << 4 | *itmp >> 4) & 0x3f];
            *otmp++ = B64_ENCODE_TABLE[(*itmp << 2) & 0x3f];
            *otmp++ = '=';
            break;
    }
    return B64_ENCODE_LEN(len);
}

int b64_decode(__const__ unsigned char *indata, __const__ int len, unsigned char *outdata)
{
    unsigned char *itmp;
    unsigned char *otmp = outdata;
    unsigned char buf[len];
    if(len == 0) return 0;
    if(len % 4 != 0)
        return -1;
    for(int i = 0; i < len; i++)
        buf[i] = B64_DECODE_TABLE[indata[i]];
    itmp = buf;
    for(int i = 0; i < len / 4 - 1; i++)
    {
        *otmp++ = (*itmp << 2) | (*(itmp + 1) >> 4); itmp++;
        *otmp++ = (*itmp << 4) | (*(itmp + 1) >> 2); itmp++;
        *otmp++ = (*itmp << 6) | *(itmp + 1); itmp += 2;
    }
    *otmp++ = (*itmp << 2) | (*(itmp + 1) >> 4); itmp++;
    if(*(itmp + 1) != 0xff)
        { *otmp++ = (*itmp << 4) | (*(itmp + 1) >> 2); itmp++; }
    else
        return len / 4 * 3 - 2;
    if(*(itmp + 1) != 0xff)
        *otmp++ = (*itmp << 6) | *(itmp + 1);
    else
        return len / 4 * 3 - 1;
    return len / 4 * 3;
}
