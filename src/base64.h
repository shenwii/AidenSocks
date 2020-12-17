#ifndef _BASE64_H
#define _BASE64_H

#define B64_ENCODE_LEN(s) (((s - 1) / 3 + 1) * 4)
#define B64_DECODE_LEN(data, s) \
    (\
        s < 4? 0: \
        (\
            data[s - 2] == '='? s / 4 * 3 - 2: \
            (\
                data[s - 1] == '='? s / 4 * 3 - 1: s / 4 * 3\
            )\
        )\
    )

int b64_encode(__const__ unsigned char *indata, __const__ int len, unsigned char *outdata);

int b64_decode(__const__ unsigned char *indata, __const__ int len, unsigned char *outdata);

#endif
