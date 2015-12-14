#ifndef SSHWINCONF_H
#define SSHWINCONF_H

#ifdef SSHDIST_CRYPT_RSA
/* Enable the RSA code. */
#define WITH_RSA 1
#endif /* SSHDIST_CRYPT_RSA */












/* Define this to enable setting TCP_NODELAY for tcp sockets. */
#define ENABLE_TCP_NODELAY 1


#ifdef SSHDIST_CRYPT_ASM
/* Define these if assebler optimized functions are needed. */
#ifdef SSHDIST_CRYPT_MD5
#if defined(_WIN64) || defined(_WIN32_WCE)
/* No assembler version of Blowfish for WIN64 or WinCE */
#undef ASM_MD5
#else
#define ASM_MD5
#endif /* _WIN64 || _WIN32_WCE */
#endif /* SSHDIST_CRYPT_MD5 */ 

#ifdef SSHDIST_CRYPT_DES
/* No assembler version of DES for windows */
#undef ASM_DES
#endif /* SSHDIST_CRYPT_DES */ 

#ifdef SSHDIST_CRYPT_BLOWFISH
#if defined(_WIN64) || defined(_WIN32_WCE)
/* No assembler version of Blowfish for WIN64 or WinCE */
#undef ASM_BLOWFISH
#else 
#define ASM_BLOWFISH
#endif /* _WIN64 || _WIN32_WCE */
#endif /* SSHDIST_CRYPT_BLOWFISH */ 
#endif /* SSHDIST_CRYPT_ASM */












#include "sshwinconf_defs.h"
/* The amount of static memory for MP ints. */
#define SSH_MP_INTEGER_BIT_SIZE_STATIC 0

#endif /* not SSHWINCONF_H */
