#include <iostream>  
#include <sstream>  
#include <string>  
#include <iomanip>  
#include <stdio.h>  
#include <openssl/sha.h>  
#include "bootimg.h"
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
//#include <unistd.h>

#define SHA256_SIZE    32
#define SIGNATURE_SIZE 256
#define SIGNATURE_SIZE_BITS 2048

#define ROUND_TO_PAGE(x,y) (((x) + (y)) & (~(y)))

int get_file_size(FILE* pfile);

int check_image(char* path);
int sign_image(char* in, char* out);

int create_signature(unsigned char* hash, unsigned char* outputbuffer);

int sha256_buffer(unsigned char *image_ptr, unsigned int image_size, unsigned char* output);

int verify_image(unsigned char *image_ptr, unsigned char *signature_ptr, unsigned int image_size);
