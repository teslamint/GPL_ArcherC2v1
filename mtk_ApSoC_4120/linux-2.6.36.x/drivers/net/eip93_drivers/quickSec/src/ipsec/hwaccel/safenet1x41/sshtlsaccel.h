#ifndef SSHTLSACCEL_H
#define SSHTLSACCEL_H

/*
  sshtlsaccel.h

  Copyright (c) 2005 SFNT Finland Oy.
  All rights reserved.

  Structures and types for user-kernel mode SSL/TLS hardware acceleration
  interface.
*/

#ifndef SA_CRYPTO_DES
/* SafeNet specific codes for crypto and hash algorithms */
#define SA_CRYPTO_DES       0x00000000
#define SA_CRYPTO_TDES      0x00000001
#define SA_CRYPTO_ARC4      0x00000002
#define SA_CRYPTO_AES       0x00000003
#define SA_CRYPTO_NULL      0x0000000f
#define SA_HASH_MD5         0x00000000
#define SA_HASH_SHA1        0x00000001
#define SA_HASH_NULL        0x0000000f
#define SA_CRYPTO_MODE_ECB  0x00000000
#define SA_CRYPTO_MODE_CBC  0x00000001
#define SA_CRYPTO_MODE_OFB  0x00000002
#define SA_CRYPTO_MODE_CFB  0x00000003
#endif

/* The following data structures describe the parameters as 
   passed to the various ioctl functions in the driver.
*/

/* Parameter block for the crypto command */
typedef struct {
  void *usr_ctx;  /* user context */
  void *ctx; /* cipher/hash context */
  unsigned char *data;
  unsigned int size;
} SshTlsAccelCryptoParamRec;

/* initkey command parameters */
typedef struct {
  void *ctx; /* cipher/hash context, output param */
  int algo;
  int keylen;
  int fmode; /* feedback mode, ECB or CBC */
  const unsigned char *key;
  const unsigned char *iv;
  int dir; /* direction, 1 for encrypt, 0 for decrypt */
} SshTlsAccelInitkeyParamRec;

/* Crypto command result block */
typedef struct {
  void *usr_ctx;  /* user context */
  void *ctx; /* cipher/hash context */
  unsigned int size; /* size of the buffer encrypted/decrypted */
  unsigned int status;  /* status of crypto command, 0 == OK */
} SshTlsAccelCryptoResultRec;

#define SSH_TLS_ACCEL_IOC_MAGIC 'u'

#define SAFENET_IOCINITKEY \
  _IOWR(SSH_TLS_ACCEL_IOC_MAGIC, 3, SshTlsAccelInitkeyParamRec)
#define SAFENET_IOCCIPHER \
  _IOW(SSH_TLS_ACCEL_IOC_MAGIC, 4, SshTlsAccelCryptoParamRec)
#define SAFENET_IOCCLEANKEY _IO(SSH_TLS_ACCEL_IOC_MAGIC, 5)

#endif /* SSHTLSACCEL_H */
