/* 
 * File:   compress.h
 * Author: root
 *
 * Created on April 18, 2013, 11:00 PM
 */

#ifndef COMPRESS_H
#define	COMPRESS_H

#ifdef	__cplusplus
extern "C" {
#endif
#include <stdio.h>    
#include <zlib.h>
#include <assert.h>
#include <fcntl.h>
#include <string.h>    

#if defined(MSDOS) || defined(OS2) || defined(WIN32) || defined(__CYGWIN__)
#  include <fcntl.h>
#  include <io.h>
#  define SET_BINARY_MODE(file) setmode(fileno(file), O_BINARY)
#else
#  define SET_BINARY_MODE(file)
#endif
#define CHUNK 16384

    int def(FILE *source,FILE *dest,int level);
    int inf(FILE *source, FILE *dest);
    void zerr(int ret);
    
    
    



#ifdef	__cplusplus
}
#endif

#endif	/* COMPRESS_H */

