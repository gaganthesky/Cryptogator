#include<stdio.h>
#include<stdlib.h>
#include<gcrypt.h>
#include<string.h>
#include<time.h>
#include "cryptogator.h"
#define GCRYPT_VERSION "1.5.3"











void hmac_MD5(char *fileName, int numOfIte)
{

//Code for HMAC_MD5


FILE *fin;                                      // Names of the files used for HMAC_MD5


size_t hash_size = gcry_md_get_algo_dlen(GCRY_MD_MD5);
size_t fl_rd_v;     //FIle Reading variable



double HMAC_MD5[100]; //Array stroing Time for each Encryption and Decryption


clock_t start_HMD5, end_HMD5;  //Defining Clock Functions variables to track time

//gcrypt version check

void grcrypt_init(){

	if (!gcry_check_version (GCRYPT_VERSION))
	 {
	   printf("LibGrycpt version doesn't match\n");
	   exit(-1);
	 }
	}


int j,k;              //To run loop
int bytes;          //Scanning file BytebyByte
char *key;
char *buf_HMD5;

gcry_md_hd_t handle_MD5;
gcry_md_open(&handle_MD5,GCRY_MD_MD5,GCRY_MD_FLAG_HMAC|GCRY_MD_FLAG_SECURE);



for(j=0; j<numOfIte;j++){

//Getting the value of key

key = randomKey(32);
printf("HMAC MD5 key for Iteration No %d is : %s  ",j+1, key);
//printf("The Key %s \n", key);
printf("\n\n");

gcry_md_setkey(handle_MD5, key, strlen(key));



fin = fopen(fileName, "rb");
fseek(fin,0,SEEK_END);
long int fileSize = ftell(fin);
//fseek(fin,0,SEEK_SET);
//printf("The file size is : %ld\n",fileSize);

buf_HMD5 = malloc(sizeof(char) *fileSize);
unsigned char *lenDig_HMD5 = NULL;


start_HMD5 = clock();                                      //Clock for HMAC_MD5 Starts

    int bytes = fread(buf_HMD5, sizeof(char), fileSize-1, fin);
    gcry_md_write(handle_MD5, buf_HMD5, fl_rd_v);;

    gcry_md_final(handle_MD5);

lenDig_HMD5 = gcry_md_read(handle_MD5, GCRY_MD_MD5);     //message digest length, "int algo  = 0"
int i;
printf("The Hash Generated using HMAC MD5 is: \n");
for(i=0;i<strlen(lenDig_HMD5);i++)
{
printf("%x",lenDig_HMD5[i]);
}
printf("\n");

/*while(fl_rd_v = fread(buf_HMD5, 1, fileSize-1, fin))
    {
    gcry_md_write(handle_MD5, buf, fl_rd_v);
    if()
    }*/
end_HMD5 = clock();
//printf("End of Encrypption Iteration no %d using AES128 CBC Mode at: %ld \n ", j,end_EA128);
double total_HMD5 = (double)(end_HMD5-start_HMD5)/CLOCKS_PER_SEC*1000000000;
printf("\nTotal time taken for Hash Generation : %.2lf nano-seconds \n", total_HMD5);
printf("--------------------------------------------------------------------------------\n");
HMAC_MD5[j] = total_HMD5;

//}

}

gcry_md_close(handle_MD5);

free(buf_HMD5);

double Total_HMD5_Time=0.0;

for(k=0;k<numOfIte;k++)
{
Total_HMD5_Time = Total_HMD5_Time + HMAC_MD5[k];

}

printf("Total HASH Time (HMAC_MD5) for %d iterations is: %.2lf nano-seconds \n\n",k, Total_HMD5_Time);

double meanHMD5_time = Total_HMD5_Time/numOfIte;

printf("Mean Hash Time for (HMAC_MD5) %d iterations is: %.2lf nano-seconds \n\n",k, meanHMD5_time);


double medianHMD5 =  calculateMedian(HMAC_MD5, numOfIte);
printf("The Median Hash Time for (HMAC_MD5) after %d Iterations is: %.2lf nano-seconds \n\n",numOfIte, medianHMD5);


}
