#include<stdio.h>
#include<stdlib.h>
#include<gcrypt.h>
#include<string.h>
#include<time.h>
#include "cryptogator.h"
#define GCRYPT_VERSION "1.5.3"


void aes128(char *fileName, int numOfIte)
{

//Code for AES128_CBC Encryption


FILE *fin, *fout;                                       // Names of the files used for Encryption & Decryption
int blckSize = 16;                                      // Block Size for AES
int algoEnc = GCRY_CIPHER_AES128;                    // Defining Algo Used
char initV[16];                                   // Initializing Vector
char *buf = malloc(blckSize);                          // Declaring buffer to store file in memory before encryption
char *key;                        // Key assigned for Encryption

int keylength = 16;
int blckLength = 16;
int mode = GCRY_CIPHER_MODE_CBC;
double EncTime[100]; double DecTime[100]; //Array stroing Time for each Encryption and Decryption


clock_t start_EA128, end_EA128, start_DA128, end_DA128;  //Defining Clock Functions variables to track time

//gcrypt version check

void grcrypt_init(){

	if (!gcry_check_version (GCRYPT_VERSION))
	 {
	   printf("LibGrycpt version doesn't match\n");
	   exit(-1);
	 }
	}

//AES128_CBC Encryption Starts

gcry_cipher_hd_t hd;

int j,k;              //To run loop
int bytes;          //Scanning file BytebyByte
int padBytes;       //Add Badding to incomplete Block

//printf("Key used for this encryption is: %c\n\n",*key);

for(j=0; j<numOfIte;j++){

//Getting the value of key

key = randomKey(16);
printf("Encryption(AES128 CBC Mode) Iteration No %d : \n Key:    ",j+1);
for(k=0;k<16;k++)
{
printf("%c",key[k]);        //Printing key used for each Encryption/Decryption
}
printf("\n");




start_EA128 = clock();                                      //Clock for Encryption Starts
//printf("Started Encrypption Iteration No. %d using AES128 CBC Mode at : %ld \n ", j,start_EA128);

memset(initV, 0, 16);

fin = fopen(fileName, "rb");
fout = fopen("AES128_Encrypt", "wb");

gcry_cipher_open(&hd, algoEnc, mode, 0);
gcry_cipher_setkey(hd, key, keylength);
gcry_cipher_setiv(hd, initV, blckLength);


while(!feof(fin))
    {
    padBytes = 0;
    bytes = fread(buf, 1, blckSize, fin);
        if(!bytes){break;}
   padBytes = bytes;
    while(padBytes<blckSize)
         padBytes++;

    while(bytes < blckSize)
        buf[bytes++] = padBytes;

    gcry_cipher_encrypt(hd, buf, blckSize, NULL, 0);
    bytes = fwrite(buf, 1, blckSize, fout);
    }
end_EA128 = clock();
//printf("End of Encrypption Iteration no %d using AES128 CBC Mode at: %ld \n ", j,end_EA128);
double total_EA128 = (double)(end_EA128-start_EA128)/CLOCKS_PER_SEC*1000000;
printf("Total time taken for Encrypption : %.2lf milli-seconds \n\n", total_EA128);
EncTime[j] = total_EA128;

//}

gcry_cipher_close(hd);
fclose(fin);
fclose(fout);



    //AES128_CBC Decryption Starts

//for(j=1; j<=100;j++){
printf("Decryption(AES128 CBC Mode) Iteration No %d : \n Key:    ",j+1);
for(k=0;k<16;k++)
{
printf("%c",key[k]);
}
printf("\n");


start_DA128 = clock();
//printf("Started Decrypption Iteration No. %d using AES128 CBC Mode at : %ld \n ", j,start_DA128);

gcry_cipher_open(&hd, algoEnc, mode, 0);
gcry_cipher_setkey(hd, key, keylength);
gcry_cipher_setiv(hd, initV, blckLength);

fin = fopen("AES128_Encrypt", "rb") ;
fout = fopen("AES128_Decrypt", "wb");
        while(!feof(fin))
        {
           bytes = fread(buf, 1, blckSize, fin);
            if(!bytes){break;}

    gcry_cipher_decrypt(hd, buf, blckLength, NULL, 0);
    bytes = fwrite(buf, 1, blckSize, fout);
        }

end_DA128 = clock();
//printf("End of Decrypption Iteration no %d using AES128 CBC Mode at: %ld \n ", j,end_DA128);
double total_DA128 = (double)(end_DA128-start_DA128)/CLOCKS_PER_SEC*1000000;
printf("Total time taken for Decrypption : %.2lf milli-seconds \n\n",total_DA128);

DecTime[j] = total_DA128;

gcry_cipher_close(hd);

}
double Total_Enc_Time=0.0, Total_Dec_Time=0.0;

for(k=0;k<numOfIte;k++)
{
Total_Enc_Time = Total_Enc_Time + EncTime[k];
Total_Dec_Time = Total_Dec_Time + DecTime[k];
}

printf("Total Encryption Time (AES128) for %d iterations is: %.2lf milli-seconds \n",k, Total_Enc_Time);
printf("Total Decryption Time (AES128) for %d iterations is: %.2lf milli-seconds \n\n",k, Total_Dec_Time);

double meanEnc = Total_Enc_Time/numOfIte;
double meanDec = Total_Dec_Time/numOfIte;

printf("Mean Encryption Time for (AES128) %d iterations is: %.2lf milli-seconds \n",k, meanEnc);
printf("Mean Decryption Time for (AES128) %d iterations is: %.2lf milli-seconds \n\n",k, meanDec);



free(buf);
buf = NULL;

double medianEnc =  calculateMedian(EncTime, numOfIte);
printf("The Median value for Encryption (AES128) after %d Iterations is: %.2lf milli-seconds \n",numOfIte, medianEnc);

double medianDec =  calculateMedian(DecTime, numOfIte);
printf("The Median value for Decryption (AES128) after %d Iterations is: %.2lf milli-seconds \n\n",numOfIte, medianDec);


}

