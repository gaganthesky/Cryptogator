#include<stdio.h>
#include<stdlib.h>
#include<gcrypt.h>
#include<string.h>
#include<time.h>
#include "cryptogator.h"

#define GCRYPT_VERSION "1.5.3"
#define MAX_OPERATIONS 100

int main(int argc, char *argv[]){

char *fileName;
    fileName = argv[1];

    aes128(fileName, MAX_OPERATIONS);
    aes256(fileName, MAX_OPERATIONS);
    hmac_sha1(fileName, MAX_OPERATIONS);
    hmac_MD5(fileName, MAX_OPERATIONS);
    hmac_SHA256(fileName, MAX_OPERATIONS);

    return 0;
}
