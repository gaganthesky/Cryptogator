#Make file for Cryptogator
#Author: gagan sharma
#Run make to compile

Compiler=gcc
Cflags=
LIBS=-lgcrypt
cryptogator:
	$(Compiler) $(Cflags) cryptogator.c -o cryptogator FinalAES128.c FinalAES256.c HMAC_SHA1.c HMAC_SHA256.c HMAC_MD5.c $(LIBS)
clean:
	rm cryptogator AES128_Decrypt AES256_Decrypt AES128_Encrypt AES256_Encrypt
