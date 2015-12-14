/*

  t-aes-keywrap.c

  Copyright:
          Copyright (c) 2007 SFNT Finland Oy.
  All rights reserved.

  Test vectors for AES Key Wrap from RFC 3394

 */

#include "sshincludes.h"
#include "aes_keywrap.h"

#define SSH_DEBUG_MODULE "TAesKeyWrap"

typedef struct AesKeyWrapTestDataRec {
  char *key;
  char *data;
  char *ciphertext;
} AesKeyWrapTestDataStruct, *AesKeyWrapTestData; 

AesKeyWrapTestDataStruct aes_keywrap_tests[] = {
  {
    "0x000102030405060708090A0B0C0D0E0F",
    "0x00112233445566778899AABBCCDDEEFF",
    "0x1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5"
  },
  {
    "0x000102030405060708090A0B0C0D0E0F1011121314151617",
    "0x00112233445566778899AABBCCDDEEFF",
    "0x96778B25AE6CA435F92B5B97C050AED2468AB8A17AD84E5D"
  },
  {
    "0x000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
    "0x00112233445566778899AABBCCDDEEFF",
    "0x64E8C3F9CE0F5BA263E9777905818A2A93C8191E7D6E8AE7"
  },
  {
    "0x000102030405060708090A0B0C0D0E0F1011121314151617",
    "0x00112233445566778899AABBCCDDEEFF0001020304050607",
    "0x031D33264E15D33268F24EC260743EDCE1C6C7DDEE725A936BA814915C6762D2"
  },
  {
    "0x000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
    "0x00112233445566778899AABBCCDDEEFF0001020304050607",
    "0xA8F9BC1612C68B3FF6E6F4FBE30E71E4769C8B80A32CB8958CD5D17D6B254DA1"
  },
  {
    "0x000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
    "0x00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F",
    "0x28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB"
    "988B9B7A02DD21"
  },
  { NULL },

};


#define MAX_BUF_SIZE 128

static const unsigned char hex_table[128] =
{
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
};

/* This converts the string 'str' of type found in the test vectors below
   to a buffer of unsigned char. The buffer length of the string 'str'
   converted to the buffer 'buf' is returned  in 'buf_len' */
Boolean aes_keywrap_hex_string_to_buf(const char *str,
				      unsigned char *buf,
				      size_t buf_len,
				      size_t *buf_len_return)
{
  size_t len, i;
  unsigned char *buffer = buf;

  /* The string must be of even length */
  if (strlen(str) & 1)
    return FALSE;

  /* The string must begin with "0x" */
  if (str[0] != '0' && str[1] !=  'x')
    return FALSE;

  /* Check the buffer is large enough (subtracting 2 for the 0x prefix). */
  if ((strlen(str) - 2) > 2 * buf_len)
    return FALSE;

  /* The rest of the string characters must be hexadecimal digits (with
     'a' to 'f' in lower case) */
  for (i = 2; i < strlen(str); i++)
    {
      if ((str[i] < '0' || str[i] > '9') && (str[i] < 'A' || str[i] > 'F'))
        return FALSE;
    }

  len = (strlen(str) - 2) / 2;

  /* Convert the hexadecimal digits to unsigned char */
  for (i = 0; i < len; i++)
    buffer[i] =((hex_table[(unsigned int) str[2 + 2*i]]) << 4) |
      hex_table[(unsigned int) str[2 + 2*i + 1]];

  *buf_len_return = len;
  return TRUE;
}

int main(int argc, char **argv)
{
  SshCryptoStatus status = SSH_CRYPTO_OPERATION_FAILED;
  unsigned char kek[32], src[32], dst[40], result[40];
  size_t kek_len, src_len, dst_len;
  int i;

  if (ssh_crypto_library_initialize() != SSH_CRYPTO_OK)
    exit(1);

  for (i = 0; aes_keywrap_tests[i].key; i++)
    {
      /* Convert the string to buffers */
      if (!aes_keywrap_hex_string_to_buf(aes_keywrap_tests[i].key, kek,
					 MAX_BUF_SIZE, &kek_len))
	goto fail;
      if (!aes_keywrap_hex_string_to_buf(aes_keywrap_tests[i].data, src,
					 MAX_BUF_SIZE, &src_len))
	goto fail;
      if (!aes_keywrap_hex_string_to_buf(aes_keywrap_tests[i].ciphertext, dst,
					 MAX_BUF_SIZE, &dst_len))
	goto fail;

      SSH_DEBUG_HEXDUMP(10, ("KEY"), kek, kek_len);
      SSH_DEBUG_HEXDUMP(10, ("Data"), src, src_len);

      /* Check the result buffer is large enough. */
      if (sizeof(result) < src_len + 8)
	goto fail;

      /* Do AES key wrap and compare to the expected result */
      status = ssh_aes_key_wrap_kek(kek, kek_len, 
				    NULL, 0, 
				    result, src_len + 8,
				    src, src_len);
      
      if (status != SSH_CRYPTO_OK)
	goto fail;

      if (dst_len != src_len + 8)
	goto fail;

      if (memcmp(dst, result, dst_len))
	{
	  SSH_DEBUG_HEXDUMP(0, ("Expected result"), dst, dst_len);
	  SSH_DEBUG_HEXDUMP(0, ("Actual   result"), result, dst_len);
	  goto fail;
	}

      /* Do AES key unwrap. */
      status = ssh_aes_key_unwrap_kek(kek, kek_len, 
				      NULL, 0, 
				      result, src_len,
				      dst, dst_len);
    
      if (status != SSH_CRYPTO_OK)
	goto fail;


      /* Compare to the original plaintext. */      
      if (memcmp(src, result, src_len))
	goto fail;
   }

  exit(0);


 fail:
  ssh_warning("AES Key Wrap test vectors do not match error =%s",
	      ssh_crypto_status_message(status));
  exit(1);
}
