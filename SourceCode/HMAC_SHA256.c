#include<stdio.h>
#include<stdlib.h>
#include<gcrypt.h>
#include<string.h>
#include<time.h>
#include "cryptogator.h"
#define GCRYPT_VERSION "1.5.3"


//Function to generate Random Key
char * randomKey(int size) {

char *s=(char *)malloc(size) ;
char alphanum[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

int i;

int j;
 for (j = 0; j < size; j++)
    {
        s[j] = alphanum[rand() % (sizeof(alphanum) - 1)];
    }
return s;
}

/*double sortArray(double array[],int array_length)
{
int a,i,j;
for (i = 0; i < array_length; i++)
    {
        for (j = i + 1; j < array_length; j++)
        {
            if (array[i] > array[j])
            {
                a =  array[i];
                array[i] = array[j];
                array[j] = a;
            }
        }
    }

    return 0;

}*/


double calculateMedian(double array[],int array_length)
{
int a,i,j, median;
for (i = 0; i < array_length; i++)
    {
        for (j = i + 1; j < array_length; j++)
        {
            if (array[i] > array[j])
            {
                a =  array[i];
                array[i] = array[j];
                array[j] = a;
            }
        }
    }
    if (array_length % 2 == 0){
    median = ((array[array_length/2]+array[array_length/2-1])/2);
    }
    else median = array[(array_length/2)];

    return median;

}




void hmac_SHA256(char *fileName, int numOfIte)
{
FILE *fin;                                      // Names of the files used for HMAC_SHA256


size_t hash_size = gcry_md_get_algo_dlen(GCRY_MD_SHA256);
size_t fl_rd_v;     //FIle Reading variable



double HMAC_SH256[100]; //Array stroing Time for each Encryption and Decryption


clock_t start_HSH256, end_HSH256;  //Defining Clock Functions variables to track time

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
char *buf_HSH256;

gcry_md_hd_t handle_SH256;
gcry_md_open(&handle_SH256,GCRY_MD_SHA256,GCRY_MD_FLAG_HMAC|GCRY_MD_FLAG_SECURE);


for(j=0; j<numOfIte;j++){

//Getting the value of key

key = randomKey(32);
printf("HMAC SHA256 key for Iteration No %d is : %s  ",j+1, key);

//printf("The Key %s \n", key);
printf("\n\n");

gcry_md_setkey(handle_SH256, key, strlen(key));


fin = fopen(fileName, "rb");
fseek(fin,0,SEEK_END);
long int fileSize = ftell(fin);
//fseek(fin,0,SEEK_SET);
//printf("The file size is : %ld\n",fileSize);

buf_HSH256 = malloc(sizeof(char) *fileSize);
unsigned char *lenDig_HSH256 = NULL;


start_HSH256 = clock();                                      //Clock for HMAC Starts

    int bytes = fread(buf_HSH256, sizeof(char), fileSize-1, fin);
    gcry_md_write(handle_SH256, buf_HSH256, fl_rd_v);;

    gcry_md_final(handle_SH256);

lenDig_HSH256 = gcry_md_read(handle_SH256, GCRY_MD_SHA256);     //message digest length, "int algo  = 0"
int i;
printf("The Hash Generate using HMAC SHA256 is: \n");
for(i=0;i<strlen(lenDig_HSH256);i++)
{
printf("%02x",lenDig_HSH256[i]);
}
printf("\n");


end_HSH256 = clock();
//printf("End of Encrypption Iteration no %d using AES128 CBC Mode at: %ld \n ", j,end_EA128);
double total_SH256 = (double)(end_HSH256-start_HSH256)/CLOCKS_PER_SEC*1000000000;
printf("\nTotal time taken for Hash Generation : %.2lf nano-seconds \n", total_SH256);
printf("--------------------------------------------------------------------------------\n");
HMAC_SH256[j] = total_SH256;


}

gcry_md_close(handle_SH256);

free(buf_HSH256);

double Total_SH256_Time=0.0;

for(k=0;k<numOfIte;k++)
{
Total_SH256_Time = Total_SH256_Time + HMAC_SH256[k];

}

printf("Total HASH Time (HMAC_SHA256) for %d iterations is: %.2lf nano-seconds \n\n",k, Total_SH256_Time);

double meanSH256_time = Total_SH256_Time/numOfIte;

printf("Mean Hash Time for (HMAC_SHA256) %d iterations is: %.2lf nano-seconds \n\n",k, meanSH256_time);


double medianSH256 =  calculateMedian(HMAC_SH256, numOfIte);
printf("The Median Hash Time for (HMAC_SHA256) after %d Iterations is: %.2lf nano-seconds \n\n",numOfIte, medianSH256);


}
