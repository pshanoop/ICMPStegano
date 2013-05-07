
#ifdef	__cplusplus
extern "C" {
#endif
#include "crypto.h"

int aes_encrypt_file(const char * infile, const char * outfile, const void * key, const void * iv, const EVP_CIPHER * cipher, int enc)
{
	assert(cipher != NULL);
	
	int rc = -1;
	int cipher_block_size = EVP_CIPHER_block_size(cipher);
	
	assert(cipher_block_size <= BUF_SIZE);
	
	// The output buffer size needs to be bigger to accomodate incomplete blocks
	// See EVP_EncryptUpdate documentation for explanation:
	//		http://lmgtfy.com/?q=EVP_EncryptUpdate
	int insize = BUF_SIZE;
	int outsize = insize + (cipher_block_size - 1);
	
	unsigned char inbuf[insize], outbuf[outsize];
	int ofh = -1, ifh = -1;
	int u_len = 0, f_len = 0;

	EVP_CIPHER_CTX ctx;
	EVP_CIPHER_CTX_init(&ctx);

	// Open the input and output files
	rc = AES_ERR_FILE_OPEN;
	if((ifh = open(infile, O_RDONLY)) == -1) {
		fprintf(stderr, "ERROR: Could not open input file %s, errno = %s\n", infile, strerror(errno));
		goto cleanup;
	}

	if((ofh = open(outfile, O_CREAT | O_TRUNC | O_WRONLY, 0644)) == -1) {
		fprintf(stderr, "ERROR: Could not open output file %s, errno = %s\n", outfile, strerror(errno));
		goto cleanup;
	}
	
	// Initialize the AES cipher for enc/dec
	rc = AES_ERR_CIPHER_INIT;
	if(EVP_CipherInit_ex(&ctx, cipher, NULL, key, iv, enc) == 0) {
		fprintf(stderr, "ERROR: EVP_CipherInit_ex failed. OpenSSL error: %s\n", ERR_error_string(ERR_get_error(), NULL));
		goto cleanup;
	}
	
	// Read, pass through the cipher, write.
	int read_size, len;
	while((read_size = read(ifh, inbuf, BUF_SIZE)) > 0)
	{
		dbg("Read %d bytes, passing through CipherUpdate...\n", read_size);
		if(EVP_CipherUpdate(&ctx, outbuf, &len, inbuf, read_size) == 0) {
			rc = AES_ERR_CIPHER_UPDATE;
			fprintf(stderr, "ERROR: EVP_CipherUpdate failed. OpenSSL error: %s\n", ERR_error_string(ERR_get_error(), NULL));
			goto cleanup;
		}
		dbg("\tGot back %d bytes from CipherUpdate...\n", len);
		
		dbg("Writing %d bytes to %s...\n", len, outfile);
		if(write(ofh, outbuf, len) != len) {
			rc = AES_ERR_IO;
			fprintf(stderr, "ERROR: Writing to the file %s failed. errno = %s\n", outfile, strerror(errno));
			goto cleanup;
		}
		dbg("\tWrote %d bytes\n", len);
		
		u_len += len;
	}
	
	// Check last read succeeded
	if(read_size == -1) {
		rc = AES_ERR_IO;
		fprintf(stderr, "ERROR: Reading from the file %s failed. errno = %s\n", infile, strerror(errno));
		goto cleanup;
	}
	
	// Finalize encryption/decryption
	rc = AES_ERR_CIPHER_FINAL;
	if(EVP_CipherFinal_ex(&ctx, outbuf, &f_len) == 0) {
		fprintf(stderr, "ERROR: EVP_CipherFinal_ex failed. OpenSSL error: %s\n", ERR_error_string(ERR_get_error(), NULL));
		goto cleanup;
	}
	
	dbg("u_len = %d, f_len = %d\n", u_len, f_len);
	
	// Write the final block, if any
	if(f_len) {
		dbg("Writing final %d bytes to %s...\n", f_len, outfile);
		if(write(ofh, outbuf, f_len) != f_len) {
			rc = AES_ERR_IO;
			fprintf(stderr, "ERROR: Final write to the file %s failed. errno = %s\n", outfile, strerror(errno));
			goto cleanup;
		}
		dbg("\tWrote last %d bytes\n", f_len);
	}

	rc = u_len + f_len;
int retval;
 cleanup:

 	EVP_CIPHER_CTX_cleanup(&ctx);
    if(ifh != -1) close(ifh); //chances of close fail
    if(ofh != -1) while (retval = close(ofh), retval == -1 && errno == EINTR) ; //chances of close fail

 	
	return rc;
}

int crypto_file(const char* infile, const char* outfile, const unsigned char* passwd,int mode){

    int i;
    unsigned char *siv="5e884898da28047151d0e56f8dc62923"; 
    unsigned char iv[EVP_MAX_IV_LENGTH];// 16B
    unsigned char key[EVP_MAX_KEY_LENGTH]; //64B
    
    // generate sha512 for password
    SHA512_CTX context; 
    SHA512_Init(&context);    
    SHA512_Update(&context, (unsigned char*)passwd, strlen(passwd));
    SHA512_Final(key, &context);
    
    //Printing key
    printf("Key:");
       for(i=0;i<EVP_MAX_KEY_LENGTH;i++)
             printf("%02x",key[i]);

    // Initializing the AES ciphers
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
    
    //converting string hex to binary 
    if(!hex2bin(siv,iv,EVP_MAX_IV_LENGTH))
            perror("iv error");
    
    return aes_encrypt_file(infile,outfile,key,iv,EVP_get_cipherbyname(EVP_CIPHERNAME_AES_CBC),mode);
}

int hex2bin(const char * hex, void * bin, int max_length)
{
	int rc = 1;
        int i;
	int hexlength = strlen(hex);
	
	if(hexlength % 2 == 1) {
		rc = HEX2BIN_ERR_INVALID_LENGTH;
		fprintf(stderr, "ERROR: Hex string length needs to be an even number, not %d (a byte is two hex chars)\n", hexlength);
		goto cleanup;
	}
	
	if(hexlength > max_length * 2) {
		rc = HEX2BIN_ERR_MAX_LENGTH_EXCEEDED;
		fprintf(stderr, "Hex string is too large (%d bytes) to be decoded into the specified buffer (%d bytes)\n", hexlength/2, max_length);
		goto cleanup;
	}
	
	int binlength = hexlength / 2;

	for ( i = 0; i < binlength; i++) {
		if (sscanf(hex, "%2hhx", (unsigned char *)(bin + i)) != 1) {
		    rc = HEX2BIN_ERR_NON_HEX_CHAR;
			fprintf(stderr, "A non-hex char was found in the hex string at pos. %d or %d: [%c%c]\n",
				i, i+1, hex[i], hex[i+1]);
			goto cleanup;
		}
		
		hex += 2;
	}
	
cleanup:
	return rc;	
}

#ifdef	__cplusplus
}
#endif
