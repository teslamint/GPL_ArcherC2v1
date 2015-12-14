/*

  gentest.c

  Copyright:
          Copyright (c) 2002-2004 SFNT Finland Oy.
  All rights reserved.

  Testing those gen- prefixed files.

  */
#include "sshincludes.h"
#include "sshgetput.h"
#include "sshcrypt.h"
#include "sshtimemeasure.h"
#include "readfile.h"
#include "sshmp.h"
#include "sshdsprintf.h"
#include "t-gentest.h"

#ifdef SSHDIST_IPSEC_HWACCEL_OCTEON
#ifdef ASM_PLATFORM_OCTEON
#include "octeon-cipher.h"
#endif /* ASM_PLATFORM_OCTEON */
#endif /* SSHDIST_IPSEC_HWACCEL_OCTEON */

#define SSH_DEBUG_MODULE "GenTestCipher"

/********************** Cipher tests ******************************/

#if 0
static void test_rc2(void)
{
  SshCipher cipher;
  unsigned char key[8] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
  unsigned char pt[8] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
  unsigned char st[8] = {0x27, 0x8b, 0x27, 0x84, 0x2e, 0x2f, 0x0d, 0x49};
  unsigned char ct[8];
  int i;

  if (ssh_cipher_allocate("rc2-ecb", key, 8, TRUE, &cipher) !=
      SSH_CRYPTO_OK)
    exit(1);

  ssh_cipher_transform(cipher, ct, pt, 8);

  if (memcmp(ct, st, 8) != 0)
    printf("Incorrect!\n");

  printf("ct: ");
  for (i = 0; i < 8; i++)
    {
      printf("%02x", ct[i]);
    }
  printf("\nst: ");
  for (i = 0; i < 8; i++)
    {
      printf("%02x", st[i]);
    }
  printf("\n");

  ssh_cipher_free(cipher);


  if (ssh_cipher_allocate("rc2-ecb", key, 8, FALSE, &cipher) !=
      SSH_CRYPTO_OK)
    exit(1);

  ssh_cipher_transform(cipher, st, ct, 8);

  if (memcmp(st, pt, 8) != 0)
    printf("Incorrect!\n");

  printf("st: ");
  for (i = 0; i < 8; i++)
    {
      printf("%02x", st[i]);
    }
  printf("\npt: ");
  for (i = 0; i < 8; i++)
    {
      printf("%02x", pt[i]);
    }
  printf("\n");

  ssh_cipher_free(cipher);


  exit(0);
}

static void test_3des_cipher_verify(void)
{
  /* Key */
  static unsigned char key[24] =
  { 0x7a, 0xc2, 0x98, 0xe7, 0x61, 0x05, 0x1e, 0x0d,
    0xbe, 0x13, 0xf9, 0xe0, 0x66, 0xcb, 0x46, 0x6c,
    0xbd, 0xf3, 0x35, 0xb7, 0xe9, 0xa6, 0x54, 0x0b, };

  /* 8 bytes for plaintext and 8 bytes for ciphertext about 100 both. */
  static unsigned char s_data[1600] =
  {0x20, 0xd1, 0x00, 0xef, 0x9e, 0xa3, 0x48, 0x59,
   0x37, 0x9e, 0x6c, 0x04, 0x09, 0x78, 0x76, 0xcb,
   0xc5, 0x7f, 0x69, 0xef, 0xda, 0xd6, 0x0e, 0x43,
   0x77, 0x5c, 0xdb, 0xca, 0x25, 0x04, 0x31, 0x4a,
   0x2e, 0xf2, 0x2d, 0x92, 0x78, 0x2d, 0xa4, 0x85,
   0x68, 0xf3, 0x2f, 0xda, 0x44, 0x4d, 0x4c, 0x66,
   0x44, 0xbe, 0x60, 0x37, 0x63, 0xae, 0x2f, 0xa1,
   0x4f, 0x10, 0x5e, 0x68, 0xed, 0xc0, 0x60, 0x8e,
   0xf3, 0x2c, 0xe1, 0x31, 0x74, 0xd8, 0x79, 0x70,
   0xb4, 0x9a, 0xee, 0x98, 0x99, 0x8b, 0x73, 0xe0,
   0xd0, 0xc3, 0xd0, 0x81, 0xc4, 0x69, 0x93, 0xdb,
   0x7c, 0xb4, 0x56, 0x72, 0xcf, 0x4f, 0x7f, 0x01,
   0xec, 0x4a, 0x7a, 0xee, 0xac, 0xbe, 0x24, 0x51,
   0xa4, 0xad, 0x0e, 0x15, 0x08, 0xf8, 0x8b, 0x8a,
   0xeb, 0xdf, 0x87, 0x82, 0x22, 0x33, 0x2f, 0x7b,
   0x2d, 0x19, 0x62, 0x19, 0xf5, 0x38, 0x03, 0x37,
   0x33, 0x41, 0xf8, 0x81, 0xec, 0x73, 0x43, 0x50,
   0x22, 0x29, 0x3d, 0x5c, 0x60, 0x2a, 0x3e, 0x0b,
   0x4d, 0xde, 0x47, 0x41, 0xb9, 0x0e, 0xf0, 0x68,
   0xc1, 0x6a, 0xa2, 0xf5, 0x50, 0xa0, 0xf0, 0x55,
   0x3e, 0x5d, 0xf6, 0x11, 0x8b, 0x3b, 0x4f, 0x0d,
   0xf1, 0xba, 0xa7, 0x50, 0x5b, 0xaa, 0x12, 0x66,
   0xd0, 0x12, 0x36, 0x54, 0x0a, 0x64, 0x15, 0x90,
   0xca, 0xab, 0x9e, 0x9c, 0x60, 0x6e, 0x35, 0xa9,
   0xb5, 0x9e, 0x16, 0x2b, 0x85, 0xc4, 0x71, 0xd9,
   0x2a, 0xaf, 0x82, 0x78, 0x73, 0x05, 0x54, 0x89,
   0x2e, 0x0b, 0x28, 0x6f, 0xa8, 0xef, 0xe9, 0x04,
   0x83, 0xe1, 0xb5, 0xee, 0x0f, 0x5e, 0x6d, 0x84,
   0x56, 0x2d, 0xa6, 0xbf, 0xb0, 0x97, 0xd6, 0x04,
   0x44, 0xf5, 0x3e, 0x01, 0x9f, 0x6c, 0xee, 0x40,
   0xc7, 0x3b, 0xce, 0xbd, 0x7f, 0x47, 0xb7, 0xdd,
   0xfb, 0xbb, 0x5b, 0x48, 0x40, 0x97, 0xfc, 0xac,
   0x07, 0x36, 0x6e, 0x06, 0xaa, 0xae, 0xf4, 0x50,
   0x95, 0x5d, 0xd1, 0x25, 0x3a, 0x7e, 0x89, 0xde,
   0x05, 0x72, 0xeb, 0x7a, 0x3d, 0x6e, 0xa5, 0x53,
   0xbb, 0x08, 0xd7, 0xa0, 0x48, 0x7b, 0xac, 0x4f,
   0xa9, 0xd7, 0x05, 0x83, 0x00, 0x53, 0x5c, 0x26,
   0x44, 0x12, 0x6f, 0xe4, 0x3b, 0xed, 0x70, 0x02,
   0x45, 0xd3, 0x80, 0x99, 0x85, 0x83, 0xd9, 0x3a,
   0x33, 0x08, 0x4e, 0xaa, 0x9d, 0xeb, 0x13, 0xd1,
   0xd6, 0x22, 0x82, 0x63, 0xae, 0xe5, 0x25, 0x44,
   0xcc, 0x75, 0xa0, 0x48, 0xc7, 0x27, 0x96, 0x6b,
   0xd6, 0x0c, 0x78, 0x6e, 0x99, 0x46, 0x65, 0x2a,
   0x62, 0x15, 0x49, 0x25, 0x75, 0x6b, 0x4d, 0xc9,
   0x0c, 0x6a, 0x53, 0x1e, 0xc3, 0x42, 0x14, 0xb3,
   0xeb, 0xb6, 0xe9, 0x5f, 0x31, 0x6f, 0x8c, 0xc0,
   0x98, 0xc2, 0xe9, 0xe8, 0xf4, 0xb0, 0x33, 0xe8,
   0x34, 0x00, 0x41, 0xc2, 0x1b, 0xfc, 0x10, 0x93,
   0x79, 0xc3, 0x5f, 0x3f, 0x77, 0x65, 0x3a, 0xda,
   0x17, 0xf3, 0x62, 0x9f, 0x04, 0xd6, 0x47, 0xea,
   0xcd, 0x73, 0xf4, 0xca, 0xa8, 0x58, 0x28, 0x57,
   0xde, 0xac, 0xf8, 0x94, 0x36, 0x3a, 0xd5, 0x92,
   0xb6, 0x67, 0x17, 0xea, 0xe9, 0x0b, 0xa2, 0xdc,
   0xd4, 0x1d, 0xa8, 0x5a, 0x2d, 0x92, 0x9e, 0xc6,
   0xfe, 0x48, 0x39, 0x36, 0xd7, 0x16, 0x31, 0x20,
   0xff, 0x8f, 0xd7, 0x6a, 0xd1, 0xb4, 0x58, 0xaf,
   0x76, 0xb6, 0xae, 0x01, 0x0f, 0x3e, 0x18, 0xb5,
   0xbe, 0xcd, 0xdf, 0x94, 0x26, 0xb4, 0x72, 0xd8,
   0x8e, 0x71, 0x41, 0x88, 0xce, 0xd2, 0xd2, 0xe1,
   0x19, 0xec, 0x84, 0xf6, 0xb7, 0x80, 0x01, 0xcd,
   0x6f, 0x56, 0xef, 0xdf, 0x97, 0x1e, 0xb2, 0x3c,
   0x28, 0x86, 0xd9, 0x46, 0x42, 0xf3, 0x17, 0x6c,
   0x03, 0x31, 0x04, 0x7a, 0x7d, 0xa4, 0xbd, 0x10,
   0xef, 0xeb, 0xb8, 0xc6, 0x6d, 0xa8, 0x7d, 0x9d,
   0xdc, 0x69, 0x5a, 0xc2, 0x7b, 0xf9, 0x9d, 0x08,
   0xf1, 0xec, 0xf1, 0xe5, 0x74, 0x62, 0x5a, 0x31,
   0x52, 0xed, 0x80, 0x1b, 0xe8, 0xae, 0x20, 0x3d,
   0xbd, 0xcc, 0x2a, 0xf9, 0x3f, 0xca, 0x82, 0xba,
   0xd5, 0xb2, 0xce, 0xd5, 0xfd, 0xf3, 0xb2, 0x21,
   0xdc, 0x35, 0x0b, 0xf1, 0xd8, 0x5b, 0x75, 0x94,
   0xc1, 0x9b, 0x07, 0xc5, 0xe7, 0x83, 0x0a, 0x16,
   0xcc, 0x49, 0x46, 0x1a, 0x3e, 0xd0, 0x00, 0x01,
   0x11, 0x98, 0xe0, 0x15, 0x87, 0x4f, 0x37, 0xfe,
   0xc7, 0xad, 0x60, 0x5a, 0x15, 0x65, 0x02, 0x17,
   0xda, 0x64, 0x82, 0x8d, 0x19, 0x3e, 0x7a, 0xd9,
   0x65, 0x50, 0x18, 0x2a, 0x85, 0x7e, 0xe6, 0x8f,
   0x86, 0x38, 0x3f, 0x69, 0xae, 0x56, 0xf5, 0x5e,
   0x2f, 0x26, 0xdb, 0x32, 0x39, 0xe2, 0x76, 0x64,
   0x4f, 0xb3, 0x99, 0xd0, 0xa0, 0x36, 0xc6, 0xfd,
   0x3f, 0x18, 0x09, 0xc0, 0x11, 0x18, 0xf0, 0x4b,
   0xb9, 0xf8, 0xa1, 0x15, 0x32, 0x00, 0x80, 0xde,
   0x1f, 0x63, 0xa3, 0xe2, 0x94, 0x98, 0x54, 0x2f,
   0xa3, 0xb3, 0xa2, 0xd4, 0xc2, 0x09, 0x12, 0x61,
   0xb3, 0x75, 0x64, 0xf5, 0x30, 0xd1, 0x2d, 0xed,
   0x29, 0xf9, 0xba, 0x4f, 0x6c, 0x31, 0x65, 0x63,
   0x83, 0xc8, 0xb8, 0x03, 0xbd, 0xf3, 0x85, 0xa9,
   0xdf, 0x38, 0xe3, 0x7b, 0x44, 0xe0, 0x81, 0xab,
   0x3b, 0x2b, 0x23, 0x70, 0x32, 0xa5, 0xd3, 0x33,
   0x72, 0xdd, 0xb3, 0xec, 0x7f, 0x9b, 0xcb, 0x96,
   0xfa, 0xdd, 0x32, 0x59, 0x5c, 0xe4, 0x13, 0x06,
   0x1a, 0xd2, 0xfc, 0x4f, 0x39, 0x52, 0x9f, 0x2c,
   0xdc, 0x51, 0xb7, 0xc2, 0x3a, 0x59, 0xc4, 0x77,
   0x00, 0x79, 0x92, 0xad, 0x02, 0x6f, 0xb2, 0x98,
   0xfb, 0xa0, 0xa7, 0xff, 0xf2, 0xb7, 0x68, 0x06,
   0x2a, 0x13, 0x4c, 0x3e, 0xca, 0x5b, 0x34, 0xe4,
   0x3b, 0x95, 0xc4, 0x96, 0xa9, 0x5b, 0x54, 0xfa,
   0xf4, 0x6f, 0x82, 0x06, 0xac, 0x57, 0x45, 0xdb,
   0x96, 0x7a, 0x7c, 0x43, 0xa4, 0x50, 0xd2, 0x6a,
   0xe2, 0x3e, 0xef, 0xd0, 0x7e, 0x25, 0x40, 0xd1,
   0x93, 0xdc, 0x89, 0xe5, 0xe9, 0xb4, 0x39, 0x65,
   0x96, 0xa1, 0xb1, 0x4c, 0x90, 0x5a, 0xf0, 0x7e,
   0xb5, 0x93, 0x59, 0xee, 0x5d, 0x96, 0x24, 0xf1,
   0xbe, 0x97, 0x25, 0xe4, 0x6b, 0x84, 0x33, 0x6b,
   0xfc, 0xf7, 0xe9, 0x6e, 0xfc, 0xb8, 0x10, 0x6f,
   0xd4, 0x3f, 0x81, 0xc8, 0xd1, 0xc8, 0x0e, 0x4f,
   0x69, 0xbd, 0xc6, 0x76, 0x82, 0x46, 0x07, 0x39,
   0x34, 0xc7, 0xf0, 0xbc, 0xa7, 0xec, 0x43, 0xb0,
   0x3a, 0xa4, 0x27, 0x7c, 0x73, 0x2a, 0x1b, 0x8e,
   0x6a, 0x14, 0xe9, 0x04, 0x57, 0x1f, 0x87, 0x02,
   0x75, 0x8c, 0xb3, 0x5d, 0x70, 0x79, 0xa7, 0xde,
   0x70, 0x0d, 0x76, 0x9f, 0x71, 0xe8, 0x22, 0x58,
   0xab, 0x98, 0x9a, 0x5a, 0x80, 0xfa, 0xd7, 0xf3,
   0x7b, 0xce, 0xf7, 0x51, 0x43, 0x0f, 0x00, 0x38,
   0x18, 0xa8, 0x59, 0x78, 0xc7, 0x7b, 0x5c, 0xa0,
   0x1e, 0x5e, 0x94, 0x11, 0xf0, 0x65, 0xf0, 0xc6,
   0x3c, 0x96, 0x0a, 0x75, 0xf2, 0xb1, 0x8a, 0x30,
   0xdf, 0x7c, 0xf2, 0x09, 0x85, 0x1a, 0xb5, 0x22,
   0xfd, 0xa4, 0xc3, 0xb3, 0xa7, 0x0c, 0x7a, 0x26,
   0x0c, 0x89, 0x0c, 0x68, 0xd9, 0xe7, 0x09, 0x23,
   0xc6, 0xa5, 0x50, 0xd8, 0xa3, 0xd1, 0x41, 0xc4,
   0x6f, 0xfd, 0x7f, 0x95, 0xed, 0xf9, 0xf4, 0x11,
   0x7b, 0x28, 0xc8, 0x5c, 0xa1, 0xab, 0x4c, 0x1b,
   0x93, 0x19, 0x22, 0xc0, 0xcc, 0xae, 0x2c, 0x0c,
   0xdb, 0x97, 0x8b, 0x33, 0x20, 0x82, 0x82, 0x36,
   0x35, 0xc9, 0x45, 0xfc, 0x85, 0x63, 0x98, 0x8a,
   0x45, 0x6d, 0xe9, 0x20, 0xa9, 0x2f, 0x00, 0xcd,
   0x60, 0xab, 0xfe, 0x98, 0xfc, 0x90, 0x8f, 0x68,
   0x44, 0xce, 0x87, 0xbe, 0x18, 0x95, 0xf7, 0xcc,
   0x86, 0xf3, 0x6c, 0x90, 0x0d, 0x06, 0xb2, 0xb7,
   0x00, 0x2f, 0x5f, 0x4a, 0xc7, 0xcc, 0x5a, 0x2d,
   0x46, 0xe9, 0x0f, 0xdb, 0xa1, 0xbf, 0x41, 0xc6,
   0xd6, 0x1b, 0xb8, 0x67, 0x42, 0xef, 0x52, 0x28,
   0x31, 0x73, 0xc5, 0x39, 0x8e, 0x61, 0xc5, 0x06,
   0xfb, 0x68, 0x7b, 0xb8, 0x8e, 0x99, 0x98, 0xed,
   0xfe, 0x66, 0x6b, 0xce, 0x67, 0x9e, 0xef, 0xe8,
   0x6f, 0xe5, 0x2a, 0x77, 0x52, 0x61, 0x7d, 0x14,
   0x17, 0x6c, 0xe8, 0x42, 0xde, 0xd3, 0xfd, 0xe3,
   0x60, 0xcf, 0x20, 0xdc, 0xcf, 0x52, 0x81, 0x39,
   0x5b, 0xbf, 0xd1, 0x22, 0x0b, 0xe4, 0xbc, 0xe0,
   0xa5, 0xfa, 0x03, 0x6b, 0xce, 0x34, 0x2c, 0x0b,
   0xec, 0xd0, 0xab, 0xad, 0xf4, 0x15, 0x44, 0x56,
   0xb6, 0xd3, 0x16, 0x01, 0x77, 0x57, 0x4c, 0x8b,
   0x86, 0x41, 0xdc, 0x90, 0xc6, 0x71, 0xb1, 0x4d,
   0xd1, 0xc1, 0x5f, 0x71, 0x06, 0x14, 0x57, 0xc6,
   0x9b, 0x85, 0xa2, 0x02, 0xef, 0x95, 0xa8, 0xfa,
   0x6a, 0xdc, 0x6f, 0xab, 0xe9, 0x6e, 0x18, 0x77,
   0x52, 0x4e, 0x10, 0xd7, 0xe4, 0x0b, 0x1b, 0x56,
   0x58, 0xc4, 0x7e, 0x1b, 0x12, 0x5f, 0x2f, 0xd9,
   0x5b, 0x14, 0x91, 0xf8, 0xeb, 0x2d, 0x80, 0xc9,
   0xf2, 0xaa, 0x04, 0x7b, 0x4b, 0x5c, 0x12, 0xbc,
   0x9a, 0xfa, 0xfd, 0x4e, 0x9f, 0xaa, 0x8b, 0x29,
   0xa2, 0xdc, 0x89, 0xef, 0x78, 0x8d, 0x31, 0x79,
   0x7c, 0x15, 0x61, 0x80, 0x74, 0x60, 0x72, 0xfb,
   0x93, 0x87, 0xa4, 0x28, 0x92, 0x49, 0x91, 0xec,
   0x7d, 0x0c, 0x69, 0x12, 0x58, 0x8f, 0xc3, 0xa5,
   0x95, 0x2f, 0x2c, 0xf0, 0xff, 0xa2, 0x5e, 0x52,
   0xfb, 0x8d, 0xe1, 0x96, 0xe7, 0x84, 0xc8, 0x31,
   0xea, 0x4b, 0xae, 0xbb, 0xef, 0x63, 0x45, 0xed,
   0x64, 0x6c, 0x8a, 0x03, 0xbf, 0xad, 0x37, 0xc4,
   0xaf, 0xea, 0x13, 0x1f, 0x2b, 0x75, 0x15, 0xf4,
   0x82, 0x79, 0x27, 0xc5, 0x2d, 0x36, 0x6d, 0xb9,
   0x47, 0x24, 0xbc, 0xbc, 0x58, 0x91, 0x1a, 0xad,
   0xf5, 0xda, 0xc9, 0x54, 0x00, 0x11, 0x52, 0xa9,
   0x82, 0x45, 0x12, 0xdb, 0xc3, 0x66, 0x7d, 0x0f,
   0x5d, 0xf9, 0x86, 0x10, 0x76, 0xa4, 0x67, 0x31,
   0xe6, 0x8c, 0x5e, 0xd3, 0xad, 0xef, 0x54, 0x04,
   0x1e, 0x51, 0x83, 0x2e, 0xfe, 0xd5, 0x46, 0x75,
   0xfb, 0x4d, 0xa2, 0x81, 0xe4, 0x2f, 0x30, 0x2f,
   0xff, 0x15, 0x36, 0x6e, 0x07, 0x2a, 0xd7, 0x71,
   0x56, 0xd9, 0x38, 0x4d, 0xec, 0xc0, 0x6e, 0xa1,
   0x82, 0x2b, 0xb2, 0xf1, 0xdf, 0xdd, 0x79, 0x15,
   0x7a, 0xcc, 0x25, 0x49, 0x53, 0x79, 0xd6, 0x01,
   0x30, 0x37, 0x81, 0x4b, 0x56, 0x6d, 0x76, 0x70,
   0x87, 0x6c, 0x4f, 0x8f, 0x1e, 0xc9, 0xce, 0x7c,
   0x53, 0x71, 0x83, 0x61, 0x7b, 0x03, 0xed, 0x2b,
   0x5b, 0xc4, 0x32, 0x9e, 0x1e, 0xa5, 0xf7, 0xc8,
   0xf6, 0x42, 0xff, 0xda, 0xde, 0x52, 0xa5, 0x2d,
   0x5c, 0x96, 0xd6, 0x9e, 0xe5, 0x0d, 0xe9, 0x75,
   0xc2, 0x40, 0x94, 0xb6, 0xbc, 0xb6, 0xe7, 0x52,
   0x8c, 0x05, 0x67, 0xda, 0x97, 0xfc, 0xea, 0xc1,
   0x1d, 0xe0, 0xcd, 0x05, 0x0e, 0xa2, 0x64, 0x6c,
   0xe2, 0x56, 0x93, 0x68, 0xea, 0xcc, 0x6f, 0xfb,
   0x23, 0x45, 0xc4, 0xe7, 0x78, 0xdf, 0x6b, 0x26,
   0x7f, 0xd3, 0x2e, 0x27, 0x7d, 0xc1, 0x2e, 0x74,
   0x39, 0x3d, 0x9c, 0x8c, 0xa4, 0x27, 0x0b, 0x8b,
   0xad, 0xf5, 0x9f, 0x2a, 0xc8, 0x18, 0x12, 0xf1,
   0x1b, 0x04, 0x5e, 0x83, 0x5a, 0xec, 0x86, 0xc8,
   0xfc, 0x13, 0x45, 0xfb, 0xac, 0x03, 0x24, 0xf2,
   0xce, 0x0f, 0x80, 0x7a, 0x54, 0xc6, 0x01, 0xd6,
   0x71, 0x9b, 0x61, 0x49, 0x4a, 0x14, 0xca, 0x82,
   0xae, 0x0d, 0x96, 0xe8, 0xcf, 0xb6, 0x78, 0xb1,
   0x39, 0xfc, 0x34, 0xda, 0xb0, 0xe9, 0x59, 0x5c,
   0x3d, 0xd9, 0x2e, 0xa8, 0x04, 0xc5, 0x78, 0x0d,
   0x91, 0x13, 0x66, 0x57, 0x55, 0xc6, 0xcb, 0x23,
   0x22, 0x1e, 0xbc, 0x4f, 0xb9, 0xb6, 0x2d, 0xe9,
   0x1a, 0x8d, 0xa1, 0x9d, 0xc4, 0x5a, 0xfd, 0x5a,
   0xc1, 0x45, 0x61, 0x4d, 0x2a, 0x09, 0x73, 0xf1,
   0xee, 0xce, 0x98, 0xeb, 0x0e, 0xd3, 0x97, 0x14,
   0x6c, 0x94, 0xbc, 0xd8, 0x1e, 0x74, 0x97, 0x45,
   0x49, 0x60, 0x76, 0x58, 0xc0, 0x9f, 0x15, 0xf9,
  };

  SshCipher cipher;
  unsigned char data[256];
  unsigned char ciphered[256];
  size_t datalen;
  unsigned int i, row, pos;
  unsigned int keylen;

  datalen = 8;
  keylen = 24;
  pos = 0;

  for (row = 0; row < 100; row++)
    {
      for (i = 0; i < datalen; i++)
        {
          data[i] = s_data[pos + i];
        }

      pos += datalen;

      if (ssh_cipher_allocate("3des-ecb",
                              key, keylen,
                              TRUE, &cipher) != SSH_CRYPTO_OK)
        {
          printf("Failure.\n");
          exit(1);
        }

      ssh_cipher_transform(cipher, ciphered, data, datalen);

      for (i = 0; i < datalen; i++)
        {
          if (ciphered[i] != s_data[i + pos])
            {
              printf("Error!!!\n");
            }
        }
      pos += i;

      ssh_cipher_free(cipher);
    }
}

static void test_3des_cipher(void)
{
  SshCipher cipher;
  unsigned char data[256];
  unsigned char ciphered[256];
  size_t datalen;
  unsigned int i, row;
  unsigned char key[24];
  size_t keylen;

  datalen = 8;
  keylen = 24;

  printf("unsigned char key[%d] = \n", keylen);

  printf("{");
  for (i = 0; i < keylen; i++)
    {
      key[i] = ssh_random_get_byte();
      printf("0x%02x, ", key[i]);
    }
  printf("};\n");

  printf("unsigned char data[%d] = \n", datalen * 2 * 100);
  printf("{");

  for (row = 0; row < 100; row++)
    {
      for (i = 0; i < datalen; i++)
        {
          data[i] = ssh_random_get_byte();
        }

      if (ssh_cipher_allocate("3des-ecb",
                              key, keylen,
                              TRUE, &cipher) != SSH_CRYPTO_OK)
        {
          printf("Failure.\n");
          exit(1);
        }

      ssh_cipher_transform(cipher, ciphered, data, datalen);

      for (i = 0; i < datalen; i++)
        {
          printf("0x%02x, ", data[i]);
        }

      printf("\n");

      for (i = 0; i < datalen; i++)
        {
          printf("0x%02x, ", ciphered[i]);
        }
      printf("\n");

      ssh_cipher_free(cipher);
    }

  printf("};\n");
}

#endif /* 0 */

Boolean cipher_random_tests(Boolean speed_test, int flag, size_t len)
{
  char *temp_cipher_name, *cipher_name = ssh_cipher_get_supported();
  unsigned char *key;
  SshUInt32 keylen;
  unsigned char *buf;
  unsigned char *buf2;
  int i, iters, block_len, actual_len;
  struct SshTimeMeasureRec tmit = SSH_TIME_MEASURE_INITIALIZER;
  SshCipher cipher;
  SshCryptoStatus status;

  temp_cipher_name = strtok(cipher_name, ",");

  while (temp_cipher_name)
    {
      /* skip "none" */
      if (strcmp(temp_cipher_name, "none") == 0)
        goto next_cipher;

      /* Cipher encryption & decryption tests. */
      if (((flag & MODE_ECB) == 0) && strstr(temp_cipher_name, "-ecb"))
        goto next_cipher;

      if (((flag & MODE_CBC) == 0) && strstr(temp_cipher_name, "-cbc"))
        goto next_cipher;
      if (((flag & MODE_CFB) == 0) && strstr(temp_cipher_name, "-cfb"))
        goto next_cipher;
      if (((flag & MODE_OFB) == 0) && strstr(temp_cipher_name, "-ofb"))
        goto next_cipher;

      /* Generate random key. */
      keylen = ssh_cipher_get_key_length(temp_cipher_name);
      SSH_ASSERT(keylen != 0);

      key = ssh_xmalloc(keylen);

      for (i = 0; i < keylen; i++)
        {
          key[i] = ssh_random_get_byte();
        }

      status = ssh_cipher_allocate(temp_cipher_name, key, keylen,
                                   TRUE, &cipher);

      if (status != SSH_CRYPTO_OK)
        {
          SSH_DEBUG(0, ("error: Cipher %s allocate failed: %s.",
                        temp_cipher_name, ssh_crypto_status_message(status)));
          return FALSE;
        }

      /* Round len up to the nearest multiple of the block length */
      block_len = ssh_cipher_get_block_length(temp_cipher_name);
      if (len % block_len)
	actual_len = len + (block_len - len % block_len);
      else
	actual_len = len;
      SSH_ASSERT(actual_len % block_len == 0);
      
      buf = ssh_xmalloc(actual_len);
      buf2 = ssh_xmalloc(actual_len);
      for (i = 0; i < actual_len; i++)
        buf2[i] = i & 0xff;

      iters = 1024;
    retry:
      if (speed_test)
        {
          ssh_time_measure_reset(&tmit);
          ssh_time_measure_start(&tmit);
        }

      for (i = 0; i < iters; i++)
        {
          status = ssh_cipher_transform(cipher, buf, buf2, actual_len);
          if (status != SSH_CRYPTO_OK)
            {
              SSH_DEBUG(0, ("Error: cipher %s transform failed: %s",
                            temp_cipher_name,
                            ssh_crypto_status_message(status)));
              return FALSE;
            }
        }

      if (speed_test)
        {
          ssh_time_measure_stop(&tmit);

          if (ssh_time_measure_get(&tmit,
                                   SSH_TIME_GRANULARITY_SECOND)
              <= TEST_TIME_MIN
              && iters < 10000000)
            {
              if (ssh_time_measure_get(&tmit,
                                       SSH_TIME_GRANULARITY_MILLISECOND) < 10)
                {
		  iters *= 128;
                }
              else
                {
		  iters *= 2;
                }
              if (verbose)
                printf("  - %s was too fast, retrying...%d times %d bytes\n",
		       temp_cipher_name, iters, actual_len);
              goto retry;
            }

          if (ssh_time_measure_get(&tmit,
                                   SSH_TIME_GRANULARITY_SECOND)
              >= TEST_TIME_MIN)
            printf("%s encrypt -- " TEST_FMT " KiBytes/sec ("
		   TEST_FMT " ns / call)\n",
                   temp_cipher_name, ((double)iters * actual_len) /
                   ((double)
                    ssh_time_measure_get(&tmit,
                                         SSH_TIME_GRANULARITY_MICROSECOND)
                    / 1000000.0 * 1024.0),
		   (double)
		   ssh_time_measure_get(&tmit,
					SSH_TIME_GRANULARITY_NANOSECOND)
		   / (double) iters);
          else
            printf("  - timing could not be performed for %s.\n",
                   temp_cipher_name);

        }

      ssh_cipher_free(cipher);
      status = ssh_cipher_allocate(temp_cipher_name, key, keylen,
                                   FALSE, &cipher);

      if (status != SSH_CRYPTO_OK)
        {
          SSH_DEBUG(0, ("error: Cipher %s allocate failed: %s.",
                        temp_cipher_name, ssh_crypto_status_message(status)));
          return FALSE;
        }

      if (speed_test)
        {
          ssh_time_measure_reset(&tmit);
          ssh_time_measure_start(&tmit);
        }

      for (i = 0; i < iters; i++)
        {
          status = ssh_cipher_transform(cipher, buf2, buf, actual_len);
          if (status != SSH_CRYPTO_OK)
            {
              SSH_DEBUG(0, ("error: Cipher %s transform failed: %s",
                            temp_cipher_name,
                            ssh_crypto_status_message(status)));
              return FALSE;
            }
        }

      if (speed_test)
        {
          ssh_time_measure_stop(&tmit);

          if (ssh_time_measure_get(&tmit,
                                   SSH_TIME_GRANULARITY_SECOND)
              <= TEST_TIME_MIN
              && iters < 10000000)
            {
              if (ssh_time_measure_get(&tmit,
                                       SSH_TIME_GRANULARITY_MILLISECOND) < 10)
                {
                  iters *= 128;
                }
              else
                {
		  iters *= 2;
                }
              if (verbose)
                printf("  - %s was too fast, retrying...%d times %d bytes\n",
		       temp_cipher_name, iters, actual_len);
              goto retry;
            }

          if (ssh_time_measure_get(&tmit,
                                   SSH_TIME_GRANULARITY_SECOND)
              >= TEST_TIME_MIN)
            printf("%s decrypt -- " TEST_FMT " KiBytes/sec ("
		   TEST_FMT " ns / call)\n",
                   temp_cipher_name, ((double) iters * actual_len) /
                   ((double)
                    ssh_time_measure_get(&tmit,
                                         SSH_TIME_GRANULARITY_MICROSECOND)
                    / 1000000.0 * 1024.0),
		   (double)
		   ssh_time_measure_get(&tmit,
					SSH_TIME_GRANULARITY_NANOSECOND)
		   / (double) iters);
          else
            printf("  - timing could not be performed for %s.\n",
                   temp_cipher_name);
        }

      ssh_cipher_free(cipher);

      for (i = 0; i < actual_len; i++)
        buf2[i] = (i & 0xff);

      status = ssh_cipher_allocate(temp_cipher_name, key, keylen,
                                   TRUE, &cipher);
      if (status != SSH_CRYPTO_OK)
        {
          SSH_DEBUG(0, ("error: Cipher %s allocate failed: %s",
                        temp_cipher_name, ssh_crypto_status_message(status)));
          return FALSE;
        }

      status = ssh_cipher_transform(cipher, buf, buf2, actual_len);
      if (status != SSH_CRYPTO_OK)
        {
          SSH_DEBUG(0, ("error: Cipher %s failed to encrypt: %s",
                        temp_cipher_name, ssh_crypto_status_message(status)));
          return FALSE;
        }

      ssh_cipher_free(cipher);

      if (ssh_cipher_allocate(temp_cipher_name, key, keylen,
                              FALSE, &cipher) != SSH_CRYPTO_OK)
        {
          SSH_DEBUG(0, ("error: cipher %s allocate failed.",
                        temp_cipher_name));
          return FALSE;
        }

      if (ssh_cipher_transform(cipher, buf2, buf, actual_len) != SSH_CRYPTO_OK)
        {
          SSH_DEBUG(0, ("error: cipher %s failed to encrypt.",
                        temp_cipher_name));
          return FALSE;
        }

      ssh_cipher_free(cipher);

      for (i = 0; i < actual_len; i++)
        {
          if (buf2[i] != (i & 0xff))
            {
              {
                SSH_DEBUG(0,
                          ("error: Cipher %s data check failed on %dth byte.",
                        temp_cipher_name, i));
                return FALSE;
              }
            }
        }

      ssh_xfree(buf);
      ssh_xfree(buf2);
      ssh_xfree(key);

    next_cipher:
      temp_cipher_name = strtok(NULL, ",");
    }

  ssh_free(cipher_name);

  return TRUE;
}

Boolean cipher_static_tests(const char *filename)
{
  char cipher_name[256];
  unsigned char key[1024];
  unsigned char buf1[1024], buf2[1024];
  unsigned char iv[256];
  unsigned char *str;
  size_t len, keylen = 0, buf1_len = 0;
  SshCipher cipher = NULL;
  RFStatus status;
#define CIPHER_IGNORE 0
#define CIPHER_KEY    1
#define CIPHER_INPUT1 2
#define CIPHER_INPUT2 3
#define CIPHER_OUTPUT 4
  unsigned int state = CIPHER_IGNORE;
  SshCryptoStatus cstatus;

  status = ssh_t_read_init(filename);

  if (status != RF_READ)
    {
      SSH_DEBUG(0, ("Error: `%s' could not be opened.", filename));
      return FALSE;
    }

  while (status != RF_EMPTY)
    {
      status = ssh_t_read_token(&str, &len);
      switch (status)
        {
        case RF_LABEL:
          if (cipher != NULL)
	    {
	      ssh_cipher_free(cipher);
	      cipher = NULL;
	    }

          if (len > 255)
            ssh_fatal("error: cipher name too long.");

          memcpy(cipher_name, str, len);
          cipher_name[len] = '\0';

          if (ssh_cipher_supported(cipher_name))
            state = CIPHER_KEY;
          else
            {
              ssh_debug("cipher %s not supported", cipher_name);
              state = CIPHER_IGNORE;
            }
          break;
        case RF_HEX:
        case RF_ASCII:
          switch (state)
            {
            case CIPHER_KEY:
              if (len < ssh_cipher_get_min_key_length(cipher_name))
                {
                  SSH_DEBUG(0, ("Error: key too short."));
                  return FALSE;
                }

              if (len > ssh_cipher_get_max_key_length(cipher_name))
                {
                  SSH_DEBUG(0, ("Error: key too long."));
                  return FALSE;
                }

              if (len > 1024)
                {
                  SSH_DEBUG(0, ("Error: key too long."));
                  return FALSE;
                }

              memcpy(key, str, len);
              keylen = len;

              if (ssh_cipher_allocate(cipher_name,
                                      key, keylen,
                                      TRUE, &cipher) != SSH_CRYPTO_OK)
                {
                  SSH_DEBUG(0, ("Error: Couldn't allocate `%s' cipher.",
                                cipher_name));
                  return FALSE;
                }

              state = CIPHER_INPUT1;
              break;
            case CIPHER_INPUT1:
              if (len != ssh_cipher_get_block_length(cipher_name))
                {
                  SSH_DEBUG(0, ("Error: IV too long for `%s' cipher.",
                                cipher_name));
                  return FALSE;
                }

              memcpy(iv, str, len);
              ssh_cipher_set_iv(cipher, str);

              state = CIPHER_INPUT2;
              break;
            case CIPHER_INPUT2:
              if (len > 1024)
                {
                  SSH_DEBUG(0, ("Error: Input too long."));
                  return FALSE;
                }

              memcpy(buf1, str, len);
              buf1_len = len;

              if ((cstatus = ssh_cipher_transform(cipher, buf2,
                                                  buf1, buf1_len))
                  != SSH_CRYPTO_OK)
                {
                  SSH_DEBUG(0, ("Error in transform `%s' cipher.",
                                cipher_name));
                  return FALSE;
                }

              state = CIPHER_OUTPUT;
              break;
            case CIPHER_OUTPUT:
              if (len != buf1_len)
                {
                  SSH_DEBUG(0, ("Error: Incompatible input/output lengths."));
                  return FALSE;
                }

              if (memcmp(buf2, str, len) != 0)
                {
                  SSH_DEBUG(0, ("Error: Cipher `%s' failed.", cipher_name));
                  return FALSE;
                }

              ssh_cipher_free(cipher);
	      cipher = NULL;

              if (ssh_cipher_allocate(cipher_name,
                                      key, keylen,
                                      FALSE, &cipher) != SSH_CRYPTO_OK)
                {
                  SSH_DEBUG(0, ("Error: Couldn't allocate `%s' cipher.",
                                cipher_name));
                  return FALSE;
                }

              ssh_cipher_set_iv(cipher, iv);

              if ((cstatus = ssh_cipher_transform(cipher, buf2, str, len))
                  != SSH_CRYPTO_OK)
                {
                  SSH_DEBUG(0, ("Error in transform `%s' cipher.",
                                cipher_name));
                  return FALSE;
                }

              if (memcmp(buf2, buf1, buf1_len) != 0)
                {
                  SSH_DEBUG(0, ("Error: Cipher `%s' failed.", cipher_name));
                  return FALSE;
                }

              ssh_cipher_free(cipher);
	      cipher = NULL;

              if (ssh_cipher_allocate(cipher_name,
                                      key, keylen,
                                      TRUE, &cipher) != SSH_CRYPTO_OK)
                {
                  SSH_DEBUG(0, ("Error: Couldn't allocate `%s' cipher.",
                                cipher_name));
                  return FALSE;
                }

              ssh_cipher_set_iv(cipher, iv);

              state = CIPHER_INPUT1;
              break;
            case CIPHER_IGNORE:
              break;
            default:
              ssh_fatal("error: unknown state (%d).", state);
              break;
            }
        case RF_EMPTY:
          break;
        default:
          ssh_fatal("error: file error (%d).", status);
          break;
        }
    }

  ssh_t_close();

  if (cipher)
    {
      ssh_cipher_free(cipher);
      cipher = NULL;
    }

  return TRUE;
}

Boolean cipher_static_tests_do(const char *filename)
{
  char *temp_cipher_name, *cipher_name = ssh_cipher_get_supported();
  unsigned char *key;
  size_t keylen;
  unsigned char buf[1024];
  unsigned char buf2[1024];
  unsigned char iv[256];
  int i, j, k, input_length;
  SshCipher cipher;
  RFStatus status;

  status = ssh_t_write_init(filename);
  if (status != RF_WRITE)
    ssh_fatal("error: could not create %s.", filename);

  ssh_t_write_token(RF_LINEFEED, NULL, 0);
  ssh_t_write_token(RF_COMMENT, (unsigned char*)filename, strlen(filename));
  ssh_t_write_token(RF_LINEFEED, NULL, 0);

  temp_cipher_name = strtok(cipher_name, ",");

  while (temp_cipher_name)
    {
      if (strcmp(temp_cipher_name, "none") == 0)
        goto next_cipher;

      /* Cipher encryption & decryption tests. */
      ssh_t_write_token(RF_COMMENT, (unsigned char *) temp_cipher_name,
                        strlen(temp_cipher_name));

      for (k = 0; k < 16; k++)
        {
          /* Generate random key. */
          keylen = ssh_cipher_get_key_length(temp_cipher_name);
          SSH_ASSERT(keylen != 0);

          key = ssh_xmalloc(keylen);

          for (i = 0; i < keylen; i++)
            {
              key[i] = ssh_random_get_byte();
            }

          if (ssh_cipher_allocate(temp_cipher_name,
                                  key, keylen,
                                  TRUE, &cipher) != SSH_CRYPTO_OK)
            ssh_fatal("error: cipher %s allocate failed.", temp_cipher_name);

          ssh_t_write_token(RF_LABEL, (unsigned char *) temp_cipher_name,
                            strlen(temp_cipher_name));
          ssh_t_write_token(RF_HEX, key, keylen);
          ssh_t_write_token(RF_LINEFEED, NULL, 0);

          input_length = (ssh_cipher_get_block_length(temp_cipher_name) < 8
                          ? 8 : ssh_cipher_get_block_length(temp_cipher_name));

          for (j = 0; j < 8; j++)
            {
              for (i = 0; i < input_length; i++)
                buf2[i] = ssh_random_get_byte();

              for (i = 0; i < ssh_cipher_get_block_length(temp_cipher_name);
                   i++)
                iv[i] = ssh_random_get_byte();

              ssh_cipher_set_iv(cipher, iv);

              ssh_t_write_token(RF_HEX, iv,
                                ssh_cipher_get_block_length(temp_cipher_name));
              ssh_t_write_token(RF_HEX, buf2, input_length);

              if (ssh_cipher_transform(cipher, buf,
                                       buf2, input_length) != SSH_CRYPTO_OK)
                ssh_fatal("error: cipher %s transform failed.",
                          temp_cipher_name);

              ssh_t_write_token(RF_HEX, buf, input_length);
              ssh_t_write_token(RF_LINEFEED, NULL, 0);
            }

          ssh_cipher_free(cipher);
          ssh_xfree(key);
        }

    next_cipher:

      temp_cipher_name = strtok(NULL, ",");
    }

  ssh_t_write_token(RF_LINEFEED, NULL, 0);
  ssh_t_write_token(RF_COMMENT, (unsigned char*)filename, strlen(filename));
  ssh_t_write_token(RF_LINEFEED, NULL, 0);

  /* Close and flush the stream. */
  ssh_t_close();

  ssh_free(cipher_name);

  return TRUE;
}

Boolean cipher_mac_speed_tests(const char *cipher_name, const char *mac_name,
			       int len)
{
  unsigned char *ciph_key, *mac_key;
  unsigned char iv[SSH_CIPHER_MAX_IV_SIZE], aad[16];
  SshUInt32 ciph_keylen, mac_keylen;
  unsigned char *buf, *buf2, *digest;
  size_t digest_len, iv_len;
  struct SshTimeMeasureRec tmit = SSH_TIME_MEASURE_INITIALIZER;
  SshCipher cipher;
  SshMac mac;
  SshCryptoStatus status;
  int i, iters, block_len;

  /* Generate random keys. */
  ciph_keylen = ssh_cipher_get_key_length(cipher_name);
  SSH_ASSERT(ciph_keylen != 0);
  ciph_key = ssh_xmalloc(ciph_keylen);
  for (i = 0; i < ciph_keylen; i++)
    ciph_key[i] = ssh_random_get_byte();
  
  mac_keylen = ssh_mac_get_max_key_length(mac_name);
  if (mac_keylen == 0)
    mac_keylen = 20;
  mac_key = ssh_xmalloc(mac_keylen);
  for (i = 0; i < mac_keylen; i++)
    mac_key[i] = ssh_random_get_byte();
  
  iv_len = ssh_cipher_get_iv_length(cipher_name);
  for (i = 0; i < iv_len; i++)
    iv[i] = i & 0xff;
  
  status = ssh_cipher_allocate(cipher_name, ciph_key, ciph_keylen,
			       TRUE, &cipher);
  if (status != SSH_CRYPTO_OK)
    {
      SSH_DEBUG(0, ("error: Cipher %s allocate failed: %s.",
		    cipher_name, ssh_crypto_status_message(status)));
      return FALSE;
    }

  status = ssh_mac_allocate(mac_name, mac_key, mac_keylen, &mac);
  if (status != SSH_CRYPTO_OK)
    {
      SSH_DEBUG(0, ("error: Mac %s allocate failed: %s.",
		    mac_name, ssh_crypto_status_message(status)));
      return FALSE;
    }

  /* Round len up to the nearest multiple of the block length */
  block_len = ssh_cipher_get_block_length(cipher_name);
  if (len % block_len)
    len += (block_len - len % block_len);
  SSH_ASSERT(len % block_len == 0);
  
  buf = ssh_xmalloc(len);
  buf2 = ssh_xmalloc(len);
  
  digest_len = ssh_mac_length(mac_name);
  digest = ssh_xmalloc(digest_len);
  
  iters = 1024;
 retry:
  for (i = 0; i < len; i++)
    buf2[i] = i & 0xff;
  
  /* 'aad' is data that gets MAC'ed but not encrypted. */
  for (i = 0; i < sizeof(aad); i++)
    aad[i] = i & 0xff;
  
  ssh_time_measure_reset(&tmit);
  ssh_time_measure_start(&tmit);
  
  for (i = 0; i < iters; i++)
    {
      /* MAC the 'aad' before encrypting */
      ssh_mac_reset(mac);
      ssh_mac_update(mac, aad, sizeof(aad));

      /* encrypt */
      status = ssh_cipher_set_iv(cipher, iv);
      if (status != SSH_CRYPTO_OK)
	goto error;
      status = ssh_cipher_transform(cipher, buf, buf2, len);
      if (status != SSH_CRYPTO_OK)
	{
	error:
	  SSH_DEBUG(0, ("Error: cipher or mac (%s %s) operation failed: %s",
			cipher_name, mac_name, 
			ssh_crypto_status_message(status)));
	  return FALSE;
	}
      /* MAC the encrypted data */
      ssh_mac_update(mac, buf, len);
      status = ssh_mac_final(mac, digest);
      if (status != SSH_CRYPTO_OK)
	goto error;
    }
  
  ssh_time_measure_stop(&tmit);
  
  if (ssh_time_measure_get(&tmit, SSH_TIME_GRANULARITY_SECOND) 
      <= TEST_TIME_MIN)
    {
      iters *= 2;
      if (verbose)
	printf("  - %s was too fast, retrying...%d times %d bytes\n",
	       cipher_name, iters, len);
      goto retry;
    }
  
  printf("cipher %s (encrypt), mac %s, len %d -- " SPEED_FMT 
	 " 10^6 bits/sec = " SPEED_FMT " KiBytes/sec ("
	 TEST_FMT " ns / call)\n",
	 cipher_name, mac_name, len, ((double) 8 * len * iters) /
	 ((double)
	  ssh_time_measure_get(&tmit,
			       SSH_TIME_GRANULARITY_MICROSECOND)),
	 ((double) len * iters) /
	 ((double)
	  ssh_time_measure_get(&tmit,
			       SSH_TIME_GRANULARITY_MICROSECOND)
	  / 1000000.0 * 1024.0),
	 (double)
	 ssh_time_measure_get(&tmit,
			      SSH_TIME_GRANULARITY_NANOSECOND)
	 / (double) iters);
  
  ssh_cipher_free(cipher);
  ssh_mac_free(mac);
  
  status = ssh_cipher_allocate(cipher_name, ciph_key, ciph_keylen,
			       FALSE, &cipher);
  
  if (status != SSH_CRYPTO_OK)
    {
      SSH_DEBUG(0, ("error: Cipher %s allocate failed: %s.",
		    cipher_name, ssh_crypto_status_message(status)));
      return FALSE;
    }
  
  status = ssh_mac_allocate(mac_name, mac_key, mac_keylen, &mac);
  if (status != SSH_CRYPTO_OK)
    {
      SSH_DEBUG(0, ("error: Mac %s allocate failed: %s.",
		    mac_name, ssh_crypto_status_message(status)));
      return FALSE;
    }
  
  
  iters = 1024;
 retry_decr:
  ssh_time_measure_reset(&tmit);
  ssh_time_measure_start(&tmit);
  
  for (i = 0; i < iters; i++)
    {
      ssh_mac_reset(mac);
      
      /* MAC the 'aad' first */
      ssh_mac_update(mac, aad, sizeof(aad));

      /* MAC the encrypted data */
      ssh_mac_update(mac, buf, len);
 
      /* verify the mac */     
      status = ssh_mac_final(mac, digest);
      if (status != SSH_CRYPTO_OK)
	goto error;

      /* decrypt */
      status = ssh_cipher_set_iv(cipher, iv);
      if (status != SSH_CRYPTO_OK)
	goto error;
      status = ssh_cipher_transform(cipher, buf2, buf, len);
      if (status != SSH_CRYPTO_OK)
	goto error;
     }
  
  ssh_time_measure_stop(&tmit);
  
  if (ssh_time_measure_get(&tmit,
			   SSH_TIME_GRANULARITY_SECOND) <= TEST_TIME_MIN)
    {
      iters *= 2;
      if (verbose)
	printf("  - %s was too fast, retrying...%d times %d bytes\n",
	       cipher_name, iters, len);
      goto retry_decr;
    }
  
  printf("cipher %s (decrypt), mac %s, len %d -- " SPEED_FMT 
	 " 10^6 bits/sec = " SPEED_FMT " KiBytes/sec ("
	 TEST_FMT " ns / call)\n",
	 cipher_name, mac_name, (int) len, ((double) 8 * len * iters) /
	 ((double)
	  ssh_time_measure_get(&tmit,
			       SSH_TIME_GRANULARITY_MICROSECOND)),
	 ((double) len * iters) /
	 ((double) 
	  ssh_time_measure_get(&tmit,
			       SSH_TIME_GRANULARITY_MICROSECOND)
	  / 1000000.0 * 1024.0),
	 (double)
	 ssh_time_measure_get(&tmit,
			      SSH_TIME_GRANULARITY_NANOSECOND)
	 / (double) iters);
  ssh_cipher_free(cipher);
  ssh_mac_free(mac);
  
  ssh_xfree(buf);
  ssh_xfree(buf2);
  ssh_xfree(ciph_key);
  ssh_xfree(mac_key);
  ssh_xfree(digest);
  return TRUE;
}


Boolean combined_speed_tests(int input_len)
{
  char *temp_cipher_name, *cipher_name = ssh_cipher_get_supported();
  unsigned char *key;
  unsigned char iv[SSH_CIPHER_MAX_IV_SIZE], aad[16];
  SshUInt32 keylen;
  unsigned char *buf, *buf2, *digest;
  size_t digest_len, iv_len;
  struct SshTimeMeasureRec tmit = SSH_TIME_MEASURE_INITIALIZER;
  SshCipher cipher;
  SshCryptoStatus status;
  int i, iters, block_len, actual_len;

  temp_cipher_name = strtok(cipher_name, ",");

  while (temp_cipher_name)
    {      
      if (!ssh_cipher_is_auth_cipher(temp_cipher_name))
        goto next_cipher;

      /* Generate random key. */
      keylen = ssh_cipher_get_key_length(temp_cipher_name);
      SSH_ASSERT(keylen != 0);

      key = ssh_xmalloc(keylen);

      for (i = 0; i < keylen; i++)
	key[i] = ssh_random_get_byte();

      iv_len = ssh_cipher_get_iv_length(temp_cipher_name);
      for (i = 0; i < iv_len - 4; i++)
        iv[i] = i & 0xff;

      status = ssh_cipher_allocate(temp_cipher_name, key, keylen,
                                   TRUE, &cipher);

      if (status != SSH_CRYPTO_OK)
        {
          SSH_DEBUG(0, ("error: Cipher %s allocate failed: %s.",
                        temp_cipher_name, ssh_crypto_status_message(status)));
          return FALSE;
        }

      /* Round len up to the nearest multiple of the block length */
      block_len = ssh_cipher_get_block_length(temp_cipher_name);
      if (input_len % block_len)
	actual_len = input_len + (block_len - input_len % block_len);
      else
	actual_len = input_len;
      SSH_ASSERT(actual_len % block_len == 0);
      
      buf = ssh_xmalloc(actual_len);
      buf2 = ssh_xmalloc(actual_len);

      digest_len = ssh_cipher_auth_digest_length(temp_cipher_name);
      digest = ssh_xmalloc(digest_len);

      iters = 1024;
    retry:
      for (i = 0; i < actual_len; i++)
        buf2[i] = i & 0xff;

      for (i = 0; i < sizeof(aad); i++)
        aad[i] = i & 0xff;
      
      ssh_time_measure_reset(&tmit);
      ssh_time_measure_start(&tmit);
      
      for (i = 0; i < iters; i++)
        {
	  ssh_cipher_auth_reset(cipher);
      
	  ssh_cipher_auth_update(cipher, aad, sizeof(aad));

	  SSH_PUT_32BIT(iv + iv_len - 4, 1);
	  
	  status = ssh_cipher_set_iv(cipher, iv);
	  if (status != SSH_CRYPTO_OK)
	    goto error;
	  status = ssh_cipher_transform(cipher, buf, buf2, actual_len);
	  if (status != SSH_CRYPTO_OK)
	    {
	    error:
	      SSH_DEBUG(0, ("Error: cipher %s transform failed: %s",
			    temp_cipher_name,
			    ssh_crypto_status_message(status)));
	      return FALSE;
	    }

	  status = ssh_cipher_auth_final(cipher, digest);
	  if (status != SSH_CRYPTO_OK)
	    goto error;
        }
      
      ssh_time_measure_stop(&tmit);
      
      if (ssh_time_measure_get(&tmit, SSH_TIME_GRANULARITY_SECOND) <= 
	  TEST_TIME_MIN)
	{
	  iters *= 2;
	  if (verbose)
	    printf("  - %s was too fast, retrying...%d times %d bytes\n",
		   cipher_name, iters, actual_len);
	  goto retry;
	}
      
      printf("%s (encrypt) len %d -- " SPEED_FMT " 10^6 bits/sec = "
	     SPEED_FMT " KiBytes/sec (" TEST_FMT " ns / call)\n",
	     temp_cipher_name, actual_len, 
	     ((double) 8 * actual_len * iters) /
	     ((double)
	      ssh_time_measure_get(&tmit,
				   SSH_TIME_GRANULARITY_MICROSECOND)),
	     ((double) actual_len * iters) /
	     ((double) 
	      ssh_time_measure_get(&tmit,
				   SSH_TIME_GRANULARITY_MICROSECOND)
	      / 1000000.0 * 1024.0),
	     (double)
	     ssh_time_measure_get(&tmit,
				  SSH_TIME_GRANULARITY_NANOSECOND)
	     / (double) iters);
      
      ssh_cipher_free(cipher);

      status = ssh_cipher_allocate(temp_cipher_name, key, keylen,
                                   FALSE, &cipher);
      
      if (status != SSH_CRYPTO_OK)
        {
          SSH_DEBUG(0, ("error: Cipher %s allocate failed: %s.",
                        temp_cipher_name, ssh_crypto_status_message(status)));
          return FALSE;
        }

      iters = 1024;
    retry_decr:
      ssh_time_measure_reset(&tmit);
      ssh_time_measure_start(&tmit);
      
      for (i = 0; i < iters; i++)
        {
	  ssh_cipher_auth_reset(cipher);
      
	  ssh_cipher_auth_update(cipher, aad, sizeof(aad));

	  SSH_PUT_32BIT(iv + iv_len - 4, 1);
	  
	  status = ssh_cipher_set_iv(cipher, iv);
	  if (status != SSH_CRYPTO_OK)
	    goto error;

          status = ssh_cipher_transform(cipher, buf2, buf, actual_len);
          if (status != SSH_CRYPTO_OK)
	    goto error;

	  status = ssh_cipher_auth_final(cipher, digest);
	  if (status != SSH_CRYPTO_OK)
	    goto error;
        }
      
      ssh_time_measure_stop(&tmit);
      
      if (ssh_time_measure_get(&tmit,
			       SSH_TIME_GRANULARITY_SECOND)
	  <= TEST_TIME_MIN)
	{
	  iters *= 2;
	  if (verbose)
	    printf("  - %s was too fast, retrying...%d times %d bytes\n",
		   temp_cipher_name, iters, actual_len);
	  goto retry_decr;
	}
      
      printf("%s (decrypt) len %d -- " SPEED_FMT " 10^6 bits/sec = "
	     SPEED_FMT " KiBytes/sec (" TEST_FMT " ns / call)\n",
	     temp_cipher_name, actual_len, 
	     ((double) 8 * actual_len * iters) /
	     ((double)
	      ssh_time_measure_get(&tmit,
				   SSH_TIME_GRANULARITY_MICROSECOND)),
	     ((double) actual_len * iters) /
	     ((double)
	      ssh_time_measure_get(&tmit,
				   SSH_TIME_GRANULARITY_MICROSECOND)
	      / 1000000.0 * 1024.0),
	     (double)
	     ssh_time_measure_get(&tmit,
				  SSH_TIME_GRANULARITY_NANOSECOND)
	     / (double) iters);
      ssh_cipher_free(cipher);
      
      ssh_xfree(buf);
      ssh_xfree(buf2);
      ssh_xfree(key);
      ssh_xfree(digest);
      
    next_cipher:
      temp_cipher_name = strtok(NULL, ",");
    }	  
  ssh_free(cipher_name);
  
  return TRUE;
}


/* Combined cipher and MAC speed tests */
Boolean encrypt_auth_speed_tests(size_t len)
{
  if (!combined_speed_tests(len))
    return FALSE;

  /* Just test the most common cipher nad MAC combinations for now. */
  if (!cipher_mac_speed_tests("aes-cbc", "hmac-sha1", len))
    return FALSE;
  
  if (!cipher_mac_speed_tests("aes-cbc", "hmac-md5", len))
    return FALSE;

  if (!cipher_mac_speed_tests("3des-cbc", "hmac-sha1", len))
    return FALSE;

  if (!cipher_mac_speed_tests("3des-cbc", "hmac-md5", len))
    return FALSE;

  return TRUE;
}

#ifdef SSHDIST_IPSEC_HWACCEL_OCTEON
#ifdef ASM_PLATFORM_OCTEON

/* Tests for combined cipher plus mac operations. Currently this 
   functionality is only enabled for Octeon builds. */
const SshCombinedDefStruct octeon_combined[] = 
  {
    { "aes-cbc-hmac-sha1-96", 16, 16, 20, 12,
      ssh_aes_sha1_ctxsize, ssh_aes_sha1_init, ssh_aes_sha1_transform},
    { "aes-cbc-hmac-md5-96", 16, 16, 16, 12,
      ssh_aes_md5_ctxsize, ssh_aes_md5_init, ssh_aes_md5_transform}, 
    { "3des-cbc-hmac-sha1-96", 8, 24, 20, 12,
      ssh_3des_sha1_ctxsize, ssh_3des_sha1_init, ssh_3des_sha1_transform},
    { "3des-cbc-hmac-md5-96", 8, 24, 16, 12,
      ssh_3des_md5_ctxsize, ssh_3des_md5_init, ssh_3des_md5_transform}
  };

Boolean 
combined_consistency_test(const SshCombinedDefStruct *combined, size_t len)
{
  unsigned char ciph_key[32], mac_key[32], iv[32];
  unsigned char digest_combined[20], digest_cipher_mac[20];
  unsigned char *buf_combined, *buf_cipher_mac;
  SshCryptoStatus status;
  Boolean result, sha, aes;
  SshCipher cipher = NULL;
  SshMac mac = NULL;
  void *context;
  size_t enc_ofs;
  int i;
  
  /* Assumes we have cipher aes or 3des and mac sha1 or md5. */
  sha = (combined->mac_key_len == 20) ? TRUE : FALSE;
  aes = (combined->block_len == 16) ? TRUE : FALSE;
  
  for (i = 0; i < sizeof(ciph_key); i++)
    ciph_key[i] = ssh_random_get_byte();
  
  for (i = 0; i < sizeof(mac_key); i++)
    mac_key[i] = ssh_random_get_byte();

  for (i = 0; i < sizeof(iv); i++)
    iv[i] = ssh_random_get_byte();
  
  context = ssh_xmalloc(combined->ctxsize());

  /* Make len - enc_ofs a multiple of the block length (assumes block length 
     is 8 or 16). */
  len &= ~(combined->block_len - 1);
  len += 8;

  buf_combined = ssh_xcalloc(1, len);
  buf_cipher_mac = ssh_xcalloc(1, len);

  /* Simulate ESP (encryption offset of 8 plus IV) */
  enc_ofs = 8 + combined->block_len;
  
  status = (*combined->init)(context, ciph_key, combined->cipher_key_len,
			     mac_key, sha ? 20 : 16,
			     TRUE);
  if (status != SSH_CRYPTO_OK) 
    goto fail;

  result = (*combined->transform)(context, buf_combined, buf_combined, len,
				  enc_ofs, iv, digest_combined);
  if (result != TRUE) 
    goto fail;
  
  /* Do separate cipher & mac and compare results */
  if (ssh_cipher_allocate(aes ? "aes128-cbc" : "3des-cbc", 
			  ciph_key, 
			  aes ? 16 : 24, 
			  TRUE, &cipher) != SSH_CRYPTO_OK)
    goto fail;
  
  if (ssh_mac_allocate(sha ? "hmac-sha1-96" : "hmac-md5-96", 
		       mac_key, 
		       sha ? 20 : 16, 
		       &mac) != SSH_CRYPTO_OK)
    goto fail;
  
  if (ssh_cipher_transform_with_iv(cipher, 
				   buf_cipher_mac + enc_ofs, 
				   buf_cipher_mac + enc_ofs, 
				   len - enc_ofs, 
				   iv) != SSH_CRYPTO_OK)
    return FALSE;
  
  ssh_mac_reset(mac);
  ssh_mac_update(mac, buf_cipher_mac, len);
  if (ssh_mac_final(mac, digest_cipher_mac) != SSH_CRYPTO_OK)
    goto fail;
  
  if (memcmp(buf_combined, buf_cipher_mac, len))
    {
      SSH_DEBUG_HEXDUMP(0, ("buf_combined"), buf_combined, len);
      SSH_DEBUG_HEXDUMP(0, ("buf_cipher_mac"), buf_cipher_mac, len);
      SSH_DEBUG_HEXDUMP(0, ("digest_combined"), digest_combined, 12);
      SSH_DEBUG_HEXDUMP(0, ("digest_cipher_mac"), digest_cipher_mac, 12);
      goto fail;
    }
  if (memcmp(digest_combined, digest_cipher_mac, 12))
    {
      SSH_DEBUG_HEXDUMP(0, ("digest_combined"), digest_combined, 12);
      SSH_DEBUG_HEXDUMP(0, ("digest_cipher_mac"), digest_cipher_mac, 12);
      goto fail;  
    }
  
  /* Now do the combined decryption operation */  
  ssh_cipher_free(cipher);
  ssh_mac_free(mac);
  ssh_xfree(context);
  context = ssh_xmalloc(combined->ctxsize());
  
  status = (*combined->init)(context, ciph_key, combined->cipher_key_len,
			     mac_key, sizeof(mac_key),
			     FALSE);
  if (status != SSH_CRYPTO_OK)
    goto fail;
  
  result = (*combined->transform)(context, buf_combined, buf_combined, len,
				  enc_ofs, iv, digest_combined);
  
  if (result != TRUE)
    goto fail;
  
  /* Do separate cipher & mac and compare results for decryption */
  if (ssh_cipher_allocate(aes ? "aes128-cbc" : "3des-cbc", 
			  ciph_key, 
			  aes ? 16 : 24, 
			  FALSE, 
			  &cipher) != SSH_CRYPTO_OK)
    goto fail;
  
  if (ssh_mac_allocate(sha ? "hmac-sha1-96" : "hmac-md5-96",
		       mac_key, 
		       sha ? 20 : 16, 
		       &mac) != SSH_CRYPTO_OK)
    goto fail;
  
  ssh_mac_reset(mac);
  ssh_mac_update(mac, buf_cipher_mac, len);
  
  if (ssh_mac_final(mac, digest_cipher_mac) != SSH_CRYPTO_OK)
    goto fail;
  
  if (memcmp(digest_combined, digest_cipher_mac, 12))
    {
      SSH_DEBUG_HEXDUMP(0, ("digest_combined"), digest_combined, 12);
      SSH_DEBUG_HEXDUMP(0, ("digest_cipher_mac"), digest_cipher_mac, 12);
      goto fail; 
    }
  
  if (ssh_cipher_transform_with_iv(cipher, 
				   buf_cipher_mac + enc_ofs, 
				   buf_cipher_mac + enc_ofs, 
				   len - enc_ofs, 
				   iv) != SSH_CRYPTO_OK)
    goto fail;
  
  if (memcmp(buf_combined, buf_cipher_mac, len))
    {
      SSH_DEBUG_HEXDUMP(0, ("buf_combined"), buf_combined, len);
      SSH_DEBUG_HEXDUMP(0, ("buf_cipher_mac"), buf_cipher_mac, len);
      goto fail;
    }

  if (verbose)
    printf("combined algorithm %s OK\n", combined->name);
  ssh_xfree(context);
  ssh_xfree(buf_combined);
  ssh_xfree(buf_cipher_mac);
  ssh_cipher_free(cipher);
  ssh_mac_free(mac);
  return TRUE;
  
 fail:
  ssh_xfree(context);
  ssh_xfree(buf_combined);
  ssh_xfree(buf_cipher_mac);
  ssh_cipher_free(cipher);
  ssh_mac_free(mac);
  return FALSE;
}

Boolean octeon_combined_consistency_tests(size_t len)
{
  int i;

  for (i = 0; i < sizeof(octeon_combined) / sizeof(octeon_combined[0]); i++)
    if (!combined_consistency_test(&octeon_combined[i], len))
      return FALSE;

  return TRUE;
}

void octeon_combined_speed_tests(size_t len)
{
  struct SshTimeMeasureRec tmit = SSH_TIME_MEASURE_INITIALIZER;
  const SshCombinedDefStruct *combined;
  SshCryptoStatus status;
  Boolean result, for_encryption;
  unsigned char ciph_key[32];
  unsigned char mac_key[32];
  unsigned char *buf;
  unsigned char iv[32];
  unsigned char digest[20];
  int i, j, num_ops;
  SshUInt64 seconds;
  SshUInt32 nanoseconds;
  void *context;

  len &= ~0xf;
  len += 16;
  
  for (i = 0; i < sizeof(octeon_combined) / sizeof(octeon_combined[0]); i++)
    {
      combined = &octeon_combined[i];

      for_encryption = TRUE;
    redo_for_encryption_modified:
      
      for (j = 0; j < sizeof(ciph_key); j++)
	ciph_key[j] = ssh_random_get_byte();
      
      for (j = 0; j < sizeof(mac_key); j++)
	mac_key[i] = ssh_random_get_byte();
      
      for (j = 0; j < sizeof(iv); j++)
	iv[i] = ssh_random_get_byte();
      
      ssh_time_measure_reset(&tmit);
      ssh_time_measure_start(&tmit);
      
      context = ssh_xmalloc(combined->ctxsize());
      buf = ssh_xmalloc(len);

      status = (*combined->init)(context, ciph_key, sizeof(ciph_key),
				 mac_key, sizeof(mac_key),
				 for_encryption);
      
      SSH_VERIFY(status == SSH_CRYPTO_OK);
      
      num_ops = 100000;
      for (j = 0; j < num_ops; j++)
	{
	  result = (*combined->transform)(context, buf, buf, len,
					  16, iv, digest);
	}      
      
      ssh_time_measure_stop(&tmit);
      ssh_time_measure_get_value(&tmit, &seconds, &nanoseconds);  
      
      printf("Time elapsed %d:%d sec:nanosecs for combined algorithm %s %s "
	     "with %d ops on %d "
	     "bytes speed=%f 10^6 bits/sec\n", 
	     (int)seconds, (int)nanoseconds, combined->name, 
	     for_encryption ? "encryption" : "decryption",
	     j, (int)len, 
	     (len * 8.0 * num_ops) / 
	     (1000000.0 * (seconds + nanoseconds/1000000000.0)));
      
      ssh_xfree(context);
      ssh_xfree(buf);

      if (for_encryption)
	{
	  for_encryption = FALSE;
	  goto redo_for_encryption_modified;
	}
    }
}
#endif /* ASM_PLATFORM_OCTEON */
#endif /* SSHDIST_IPSEC_HWACCEL_OCTEON */

