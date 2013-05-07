/* 
 * File:   crypto.h
 * Author: root
 *
 * Created on April 20, 2013, 3:15 PM
 */

#ifndef CRYPTO_H
#define	CRYPTO_H

#ifdef	__cplusplus
extern "C" {
#endif
    #include <stdio.h>
    #include <stdlib.h>
    #include <string.h>
    #include <errno.h>
    #include <fcntl.h>
    #include <unistd.h>
    #include <assert.h>

    #include <openssl/crypto.h>
    #include <openssl/evp.h>
    #include <openssl/err.h>
    #include <openssl/sha.h>

    #ifdef DEBUG
    #define dbg(...) { fprintf(stderr, "   %s: ", __FUNCTION__); \
        fprintf(stderr, __VA_ARGS__); fflush(stderr); }
    #else
    #define dbg(...)
    #endif    
        
    #define AES_DEFAULT_MODE "aes-256-cbc"
    #define EVP_CIPHERNAME_AES_CBC "aes-256-cbc"
    #define EVP_CIPHERNAME_AES_CTR "aes-256-ctr"

    #define HEX2BIN_ERR_INVALID_LENGTH -2
    #define HEX2BIN_ERR_MAX_LENGTH_EXCEEDED -1
    #define HEX2BIN_ERR_NON_HEX_CHAR 0
    #define HEX2BIN_SUCCESS 1

    #define AES_ERR_FILE_OPEN -1
    #define AES_ERR_CIPHER_INIT -2 
    #define AES_ERR_CIPHER_UPDATE -3
    #define AES_ERR_CIPHER_FINAL -4
    #define AES_ERR_IO -5

    #define BUF_SIZE (1024*1024)    

    int aes_encrypt_file(const char * infile, const char * outfile, 
        const void * key, const void * iv, const EVP_CIPHER * cipher, int enc);
    int crypto_file(const char * infile,const char * outfile,const unsigned char *passwd,int mode);
    
    int hex2bin(const char * hex, void * bin, int max_length);
    
#ifdef	__cplusplus
}
#endif

#endif	/* CRYPTO_H */

