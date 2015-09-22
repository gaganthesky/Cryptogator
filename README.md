# Encryption_libgcrypt
Execution and analysis of various Encryption and Hashing algorithms


Goal: To compare the performance tradeoffs of various encryption/decryption/hashing algorithms using the gcrypt libraries provided by the Linux operating system. Details of this project are given below.

The programs are written in 'C' using the libgcrypt library. The make utility was created to run the program. The file program cryptogator take the following inputs: cryptogator where cryptogator takes an input file of arbitrary size and performs the following operations on it: AES128, CBC Mode AES256, CBC Mode HMAC SHA1 HMAC SHA256 HMAC MD5

For our tests, our input file was 100MB in size.

For the four ciphers, encryption/decryption of the entire file was performed. Timed each of these operations, and perform them 100 times each. Then calculated the mean and median times for each cipher (for encryption and decryption). Generated a new key for each iteration, but timing the key generation was not considered.

For the three hash algorithms, hashed the entire file (using HMAC).

Run Commands:

make cryptogator input_file

output: < display results >
