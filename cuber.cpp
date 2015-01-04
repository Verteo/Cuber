#include "cuber.h"

#define _CRT_SECURE_NO_WARNINGS  
/*
Returns -1 if somethings fails otherwise 0
*/
int main(int argc, char* argv[])
{

	if (!(argc == 3 || argc == 4)) {
		std::cerr << "[ ERROR ] Incorrect number of arguments" << std::endl << std::endl;
		std::cerr << "[ USAGE ] cuber <option> <arguments>" << std::endl;
		std::cerr << "  -c, --check /path/to/image.img				checks if image would pass signature verification" << std::endl;
		std::cerr << "  -s, --sign /path/to/input/file.img /path/to/output/file.img	creates a signature and outputs a signed image" << std::endl;
		return -1;
	}
	
	if (strcmp(argv[1], "-check") == 0 && argc == 3){
		std::cout << "[ STATUS ] Checking image... " << argv[2] << std::endl;
		return check_image(argv[2]);
	}
	if (strcmp(argv[1], "-sign") == 0 && argc == 4) {
		if (strcmp(argv[1], argv[2]) == 0) {
			std::cerr << "[ ERROR ] Input and output paths must be different" << std::endl;
			return -1;
		}
		else {
			std::cout << "[ STATUS ] Signing image... " << argv[2] << std::endl;
			return sign_image(argv[2], argv[3]);
		}
	} else {
		std::cerr << "[ ERROR ] Correct number of arguments, but invalid" << std::endl << std::endl;
		std::cerr << "[ USAGE ] cuber <option> <arguments>" << std::endl;
		std::cerr << "  -c, --check /path/to/image.img				checks if image would pass signature verification" << std::endl;
		std::cerr << "  -s, --sign /path/to/input/file.img /path/to/output/file.img	creates a signature and outputs a signed image" << std::endl;		return -1;
	}

}

/*
Returns -1 if somethings fails otherwise 0
*/
int check_image(char* in){

	/*
	Load an image at given path
	*/
	FILE *imageinput;
	imageinput = fopen(in, "rb");

	if (imageinput == NULL){
		std::cerr << "[ ERROR ] Image does not exist at given location" << std::endl;
		return -1;
	}

	/*
	Check if file has contents
	*/
	unsigned imagefilesize = get_file_size(imageinput);
	if (imagefilesize == 0){
		std::cerr << "[ ERROR ] Image has no size" << std::endl;
		return -1;
	}

	/*
	Load image in buffer and close file
	*/
	unsigned char* image = NULL;
	image = (unsigned char*)malloc(imagefilesize);
	
	fread(image, imagefilesize, 1, imageinput);
	fclose(imageinput);

	/*
	Extract image header
	*/
	boot_img_hdr* hdr = NULL;
	hdr = (boot_img_hdr*)malloc(sizeof(boot_img_hdr));
	memcpy(hdr, image, sizeof(boot_img_hdr));

	
	/*
	Check if image is an Android bootimage
	*/
	if (memcmp((char*)hdr->magic, "ANDROID!", 8) != 0){
		std::cerr << "[ ERROR ] File is not an Android boot image" << std::endl;
		return -1;
	}

	/*
	Load necessary variables from header and delete header
	*/
	unsigned kernel_actual;
	unsigned ramdisk_actual;
	unsigned imagesize_actual;
	unsigned dt_actual;
	unsigned page_size = hdr->page_size;
	unsigned page_mask = hdr->page_size - 1;

	kernel_actual = ROUND_TO_PAGE(hdr->kernel_size, page_mask);
	ramdisk_actual = ROUND_TO_PAGE(hdr->ramdisk_size, page_mask);
	dt_actual = ROUND_TO_PAGE(hdr->dt_size, page_mask);

	free(hdr);
	/*
	Calculate size of the "real" image
	*/
	imagesize_actual = (page_size + kernel_actual + ramdisk_actual + dt_actual) ;

	/*
	If the "real" image is bigger than the file, the file is probably corrupted
	*/
	if (imagefilesize < imagesize_actual){
		std::cerr << "[ ERROR ] File is invalid (is it corrupted?)" << std::endl;
		return -1;
	}

	/*
	Verify the image.
	*/
	verify_image(image, image + imagesize_actual, imagesize_actual);
	
	return 0;
}
/*
Returns -1 if somethings fails otherwise 0
*/
int sign_image(char* in, char* out){

	/*
	An int is enough because the partitions shouldn't be bigger than 4GB
	*/
	int finalimagesize = 0;
	/*
	Load an image at given path
	*/
	FILE *imageinput;
	imageinput = fopen(in, "rb");

	if (imageinput == NULL){
		std::cerr << "[ ERROR ] Image does not exist at given location" << std::endl;
		return -1;
	}

	/*
	Check if file has contents
	*/
	unsigned imagefilesize = get_file_size(imageinput);
	if (imagefilesize == 0){
		std::cerr << "[ ERROR ] Image has no size" << std::endl;
		return -1;
	}

	/*
	Extract image header first to determine if the final image is bigger than the orignal
	*/
	boot_img_hdr* hdr = NULL;
	hdr = (boot_img_hdr*)malloc(sizeof(boot_img_hdr));
	fread(hdr, sizeof(boot_img_hdr), 1, imageinput);

	/*
	Reposition pointer at start
	*/
	fseek(imageinput, 0, SEEK_SET);


	/*
	Check if image is an Android bootimage
	*/
	if (memcmp((char*)hdr->magic, "ANDROID!", 8) != 0){
		std::cerr << "[ ERROR ] File is not an Android boot image" << std::endl;
		return -1;
	}

	/*
	Load necessary variables from header and delete header
	*/
	unsigned kernel_actual;
	unsigned ramdisk_actual;
	unsigned imagesize_actual;
	unsigned dt_actual;
	unsigned page_size = hdr->page_size;
	unsigned page_mask = hdr->page_size - 1;

	kernel_actual = ROUND_TO_PAGE(hdr->kernel_size, page_mask);
	ramdisk_actual = ROUND_TO_PAGE(hdr->ramdisk_size, page_mask);
	dt_actual = ROUND_TO_PAGE(hdr->dt_size, page_mask);
	free(hdr);

	/*
	Calculate size of the "real" image
	*/
	imagesize_actual = (page_size + kernel_actual + ramdisk_actual + dt_actual);

	/*
	If the "real" image is bigger than the file, the file is probably corrupted
	*/
	if (imagefilesize < imagesize_actual){
		std::cerr << "[ ERROR ] File is invalid (is it corrupted?)" << std::endl;
		return -1;
	}

	/*
	If the file is smaller than the "real" image + one page, a buffer with the size of the image would be too small we need allocate a new bigger one
	*/
	if (imagefilesize < imagesize_actual + page_size){
		finalimagesize = imagefilesize + page_size;
	} else {
		finalimagesize = imagefilesize;
	}

	/*
	Load image in buffer and close file
	*/
	unsigned char* image = NULL;
	image = (unsigned char*)malloc(finalimagesize);
	fread(image, 1, imagefilesize, imageinput);
	fclose(imageinput);


	/*
	Create output file
	*/
	FILE *imageoutput;
	imageoutput = fopen(out, "wb");

	if (imageoutput == NULL){
		std::cerr << "[ ERROR ] Can't write output image to disk" << std::endl;
		return -1;
	}

	/*
	Hash the real image
	*/
	unsigned char hash[65];
	unsigned char signature[SIGNATURE_SIZE];
	memset(signature, 0, SIGNATURE_SIZE);
	sha256_buffer(image, imagesize_actual, hash);

	/*
	Create signature with given hash
	*/
	int sig = create_signature(hash, signature);

	/*
	If the signature is created successfully AND the signature passes the check, the signature will be written into the image buffer, which will written to the output file
	*/
	if (sig != -1){
		std::cout << "[ STATUS ] Checking created signature... ";
		if (verify_image(image, signature, imagesize_actual) == 0){
			memcpy(image + imagesize_actual, signature, SIGNATURE_SIZE);
			fwrite(image, finalimagesize, 1, imageoutput);
		}
	} 

	/*
	Cleanup
	*/
	fclose(imageoutput);
	free(image);

	/*
	Final check of the output file
	*/
	std::cout << "[ STATUS ] Checking created image... ";
	check_image(out);

	return 0;
}

/*
Calculates the size of file
Returns size of the file
*/
int get_file_size(FILE* pfile)
{
	fseek(pfile, 0, SEEK_END);
	int Size = ftell(pfile);
	fseek(pfile, 0, SEEK_SET);
	return Size;
}


/*
Hash a buffer of given size with openssl
Always returns 0
*/
int sha256_buffer(unsigned char *image_ptr, unsigned int image_size, unsigned char* output)
{
	SHA256_CTX sha256;
	SHA256_Init(&sha256);
	SHA256_Update(&sha256, image_ptr, image_size);
	SHA256_Final(output, &sha256);
	return 0;
}

/*
Function to verify a given image and signature.
Reference implementation in the Little Kernel source in "platform/msm_shared/image_verify.c"
Returns -1 if somethings fails otherwise 0
*/
int verify_image(unsigned char *image_ptr, unsigned char *signature_ptr, unsigned int image_size)
{
	X509 *x509_certificate = NULL;
	EVP_PKEY *pub_key = NULL;
	RSA *rsa_key = NULL;
	unsigned char *plain_text = NULL;
	unsigned char digest[65];
	unsigned int hash_size = SHA256_SIZE;
	int ret = 0;

	/*
	Load certificate
	*/
	FILE *fcert;
	fcert = fopen("prodcert.pem", "rb");
	if (fcert == NULL){
		fclose(fcert);
		std::cerr << "[ ERROR ] Missing certificate" << std::endl;
		ret = -1;
		goto cleanup;
	}
	x509_certificate = PEM_read_X509(fcert, NULL, NULL, NULL);
	fclose(fcert);

	/*
	Obtain RSA key
	*/
	pub_key = X509_get_pubkey(x509_certificate);
	rsa_key = EVP_PKEY_get1_RSA(pub_key);

	if (rsa_key == NULL){
		std::cerr << "[ ERROR ] Couldn't obtain key from certificate" << std::endl;
		ret = -1;
		goto cleanup;
	}

	/*
	Create buffer for decrypted hash
	*/
	plain_text = (unsigned char *)calloc(sizeof(char), SIGNATURE_SIZE);
	if (plain_text == NULL) {
		std::cerr << "ERROR: Calloc failed during verification!" << std::endl;
		ret = -1;
		goto cleanup;
	}

	/*
	Decrypt hash
	*/
	RSA_public_decrypt(SIGNATURE_SIZE, signature_ptr, plain_text, rsa_key, RSA_PKCS1_PADDING);

	/*
	Hash the image
	*/
	sha256_buffer(image_ptr, image_size, digest);

	/*
	Check if signature is equal to the calculated hash
	*/
	if (memcmp(plain_text, digest, hash_size) != 0) {
		std::cerr << "[ ERROR ] Invalid signature..." << std::endl;
		ret = -1;
		goto cleanup;
	}
	else {
		std::cout << "[ SUCCESS ] The signature is valid!" << std::endl;
	}

	/* Cleanup after complete usage of openssl - cached data and objects */
cleanup:
	if (rsa_key != NULL)
		RSA_free(rsa_key);
	if (x509_certificate != NULL)
		X509_free(x509_certificate);
	if (pub_key != NULL)
		EVP_PKEY_free(pub_key);
	if (plain_text != NULL)
		free(plain_text);
	EVP_cleanup();
	CRYPTO_cleanup_all_ex_data();
	return 0;
}

/*
This function creates the signature
Returns -1 if somethings fails otherwise 0
*/
int create_signature(unsigned char* hash, unsigned char* outputbuffer){
	
	/*
	Create file and write the hash into it binary
	*/
	FILE *hashfile;
	hashfile= fopen("hash.abc", "wb");
	fwrite(hash, 32, 1, hashfile);
	fclose(hashfile);
	/*
	Invoke the python script
	*/
	system("python signature.py");
	/*
	Remove file with hash
	*/
	remove("hash.abc");

	/*
	Open file with bnary signature
	*/
	FILE *sigfile;
	sigfile = fopen("signature.abc", "rb");

	/*
	If there's no file, the python script failed
	*/
	if (sigfile == NULL){
		std::cerr << "[ ERROR ] No signature created..." << std::endl;
		std::cerr << "	  Ensure python and gmpy2 are installed" << std::endl;
		return -1;
	}

	/*
	Check if there's content
	*/
	int filesize = get_file_size(sigfile);
	if (filesize == 0){
		std::cerr << "[ ERROR ] No signature created..." << std::endl;
		std::cerr << "	  Ensure python and gmpy2 are installed as well as that signature.py is in the same directory" << std::endl;
		remove("signature.abc");
		return -1;
	}

	/*
	Load file into a buffer
	*/
	unsigned char* buffer = NULL;
	buffer = (unsigned char*)malloc(filesize);
	if (buffer == NULL){
		std::cerr << "[ ERROR ] Could not allocate memory" << std::endl;
		return -1;
	}
	fread(buffer, 1, filesize, sigfile);

	/*
	Calculate the offset of the given signature
	*/
	int offset = SIGNATURE_SIZE - filesize;
	/*
	Copy signature to the right position
	*/
	memcpy(outputbuffer + offset, buffer, filesize);

	/*
	cleanup
	*/
	fclose(sigfile);
	remove("signature.abc");
	return 0;
}