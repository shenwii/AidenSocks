#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "base64.h"
#include "aes.h"

int main(int argc, char **argv)
{
    int el;
    int l = AES_KEY_LEN / 8;
    unsigned char key[l];
    srand((unsigned) time(NULL));
    for(int i = 0; i < l; i++)
        key[i] = rand() % 256;
    el = B64_ENCODE_LEN(l);
    unsigned char b64d[el + 1];
    b64_encode(key, l, b64d);
    b64d[el] = '\0';
    printf("key = %s\n", b64d);
    fflush(stdout);
    return 0;
}
