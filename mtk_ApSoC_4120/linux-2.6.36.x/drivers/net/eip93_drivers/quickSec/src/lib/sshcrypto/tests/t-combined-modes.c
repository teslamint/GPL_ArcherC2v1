/*

t-combined-modes.c

      Copyright:
              Copyright (c)  2006 SFNT Finland Oy.

      All rights reserved.

      Test program to verify test vectors for combined encryption and 
      authentication algorithms.
*/

#include "sshincludes.h"
#include "sshglobals.h"
#include "sshdebug.h"
#include "sshgetopt.h"
#include "sshgetput.h"
#include "sshcrypt.h"
#include "sshmiscstring.h"
#include "sshregression.h"

#define SSH_DEBUG_MODULE "CombinedModesTestVectors"

typedef struct CombinedTestVectorRec {
  const char *name;
  const char *key;
  const char *plaintext;
  const char *aad;
  const char *iv;
  const char *ciphertext;
  const char *auth_tag;
} CombinedTestVectorStruct;


static CombinedTestVectorStruct combined_test_vectors[] = {
#ifdef SSHDIST_CRYPT_MODE_GCM
  {
    "gcm-aes",
    "00000000000000000000000000000000",
    "",
    "",
    "000000000000000000000000",
    "",
    "58e2fccefa7e3061367f1d57a4e7455a"
  },
  {
    "gmac-aes",
    "00000000000000000000000000000000",
    "",
    "",
    "000000000000000000000000",
    "",
    "58e2fccefa7e3061367f1d57a4e7455a"
  },
  {
    "gcm-aes",
    "00000000000000000000000000000000",
    "00000000000000000000000000000000",
    "",
    "000000000000000000000000",
    "0388dace60b6a392f328c2b971b2fe78",
    "ab6e47d42cec13bdf53a67b21257bddf"
  },
  {
    "gcm-aes",
    "feffe9928665731c6d6a8f9467308308",
    "d9313225f88406e5a55909c5aff5269a"
    "86a7a9531534f7da2e4c303d8a318a72"
    "1c3c0c95956809532fcf0e2449a6b525"
    "b16aedf5aa0de657ba637b391aafd255",
    "",
    "cafebabefacedbaddecaf888",
    "42831ec2217774244b7221b784d0d49c"
    "e3aa212f2c02a4e035c17e2329aca12e"
    "21d514b25466931c7d8f6a5aac84aa05"
    "1ba30b396a0aac973d58e091473f5985",
    "4d5c2af327cd64a62cf35abd2ba6fab4"
  },
  {
    "gcm-aes",
    "feffe9928665731c6d6a8f9467308308",

    "d9313225f88406e5a55909c5aff5269a"
    "86a7a9531534f7da2e4c303d8a318a72"
    "1c3c0c95956809532fcf0e2449a6b525"
    "b16aedf5aa0de657ba637b39",

    "feedfacedeadbeeffeedfacedeadbeef"
    "abaddad2",
    "cafebabefacedbaddecaf888",

    "42831ec2217774244b7221b784d0d49c"
    "e3aa212f2c02a4e035c17e2329aca12e"
    "21d514b25466931c7d8f6a5aac84aa05"
    "1ba30b396a0aac973d58e091",
    "5bc94fbc3221a5db94fae95ae7121a47"
  },
  {
    "gcm-aes",
    "feffe9928665731c6d6a8f9467308308",
    
    "d9313225f88406e5a55909c5aff5269a"
    "86a7a9531534f7da2e4c303d8a318a72"
    "1c3c0c95956809532fcf0e2449a6b525"
    "b16aedf5aa0de657ba637b39",
    
    "feedfacedeadbeeffeedfacedeadbeef"
    "abaddad2",
    
    "cafebabefacedbad",
    
    "61353b4c2806934a777ff51fa22a4755"
    "699b2a714fcdc6f83766e5f97b6c7423"
    "73806900e49f24b22b097544d4896b42"
    "4989b5e1ebac0f07c23f4598",
    
    "3612d2e79e3b0785561be14aaca2fccb"
  },
  {
    "gcm-aes",
    "feffe9928665731c6d6a8f9467308308",

    "d9313225f88406e5a55909c5aff5269a"
    "86a7a9531534f7da2e4c303d8a318a72"
    "1c3c0c95956809532fcf0e2449a6b525"
    "b16aedf5aa0de657ba637b39",

    "feedfacedeadbeeffeedfacedeadbeef"
    "abaddad2",

    "9313225df88406e555909c5aff5269aa"
    "6a7a9538534f7da1e4c303d2a318a728"
    "c3c0c95156809539fcf0e2429a6b5254"
    "16aedbf5a0de6a57a637b39b",

    "8ce24998625615b603a033aca13fb894"
    "be9112a5c3a211a8ba262a3cca7e2ca7"
    "01e4a9a4fba43c90ccdcb281d48c7c6f"
    "d62875d2aca417034c34aee5",

    "619cc5aefffe0bfa462af43c1699d050"
  },
  {
    "gcm-aes",
    "00000000000000000000000000000000"
    "0000000000000000",
    "",
    "",
    "000000000000000000000000",
    "",
    "cd33b28ac773f74ba00ed1f312572435"
  },
  {
    "gmac-aes",
    "00000000000000000000000000000000"
    "0000000000000000",
    "",
    "",
    "000000000000000000000000",
    "",
    "cd33b28ac773f74ba00ed1f312572435"
  },
  {
    "gcm-aes",
    "00000000000000000000000000000000"
    "0000000000000000",
    "00000000000000000000000000000000",
    "",
    "000000000000000000000000",
    "98e7247c07f0fe411c267e4384b0f600",
    "2ff58d80033927ab8ef4d4587514f0fb"
  },
  {
    "gcm-aes", 
    "feffe9928665731c6d6a8f9467308308"
    "feffe9928665731c",

    "d9313225f88406e5a55909c5aff5269a"
    "86a7a9531534f7da2e4c303d8a318a72"
    "1c3c0c95956809532fcf0e2449a6b525"
    "b16aedf5aa0de657ba637b391aafd255",
    "",
    "cafebabefacedbaddecaf888",
    "3980ca0b3c00e841eb06fac4872a2757"
    "859e1ceaa6efd984628593b40ca1e19c"
    "7d773d00c144c525ac619d18c84a3f47"
    "18e2448b2fe324d9ccda2710acade256",
    "9924a7c8587336bfb118024db8674a14"
  },
  {
    "gcm-aes", 
    "feffe9928665731c6d6a8f9467308308"
    "feffe9928665731c",

    "d9313225f88406e5a55909c5aff5269a"
    "86a7a9531534f7da2e4c303d8a318a72"
    "1c3c0c95956809532fcf0e2449a6b525"
    "b16aedf5aa0de657ba637b39",

    "feedfacedeadbeeffeedfacedeadbeef"
    "abaddad2",
    "cafebabefacedbaddecaf888",
    "3980ca0b3c00e841eb06fac4872a2757"
    "859e1ceaa6efd984628593b40ca1e19c"
    "7d773d00c144c525ac619d18c84a3f47"
    "18e2448b2fe324d9ccda2710",
    "2519498e80f1478f37ba55bd6d27618c"
  },
  {
    "gcm-aes",
    "feffe9928665731c6d6a8f9467308308"
    "feffe9928665731c",

    "d9313225f88406e5a55909c5aff5269a"
    "86a7a9531534f7da2e4c303d8a318a72"
    "1c3c0c95956809532fcf0e2449a6b525"
    "b16aedf5aa0de657ba637b39",

    "feedfacedeadbeeffeedfacedeadbeef"
    "abaddad2",
    "cafebabefacedbad",
    "0f10f599ae14a154ed24b36e25324db8"
    "c566632ef2bbb34f8347280fc4507057"
    "fddc29df9a471f75c66541d4d4dad1c9"
    "e93a19a58e8b473fa0f062f7",
    "65dcc57fcf623a24094fcca40d3533f8"
  },
  {
    "gcm-aes",
    "feffe9928665731c6d6a8f9467308308"
    "feffe9928665731c",
    
    "d9313225f88406e5a55909c5aff5269a"
    "86a7a9531534f7da2e4c303d8a318a72"
    "1c3c0c95956809532fcf0e2449a6b525"
    "b16aedf5aa0de657ba637b39",

    "feedfacedeadbeeffeedfacedeadbeef"
    "abaddad2",

    "9313225df88406e555909c5aff5269aa"
    "6a7a9538534f7da1e4c303d2a318a728"
    "c3c0c95156809539fcf0e2429a6b5254"
    "16aedbf5a0de6a57a637b39b",

    "d27e88681ce3243c4830165a8fdcf9ff"
    "1de9a1d8e6b447ef6ef7b79828666e45"
    "81e79012af34ddd9e2f037589b292db3"
    "e67c036745fa22e7e9b7373b",
    "dcf566ff291c25bbb8568fc3d376a6d9"
  },
  {  
    "gcm-aes",
    "00000000000000000000000000000000"
    "00000000000000000000000000000000",
    "",
    "",
    "000000000000000000000000",
    "",
    "530f8afbc74536b9a963b4f1c4cb738b"
  },
  {  
    "gmac-aes",
    "00000000000000000000000000000000"
    "00000000000000000000000000000000",
    "",
    "",
    "000000000000000000000000",
    "",
    "530f8afbc74536b9a963b4f1c4cb738b"
  },
  {
    "gcm-aes",
    "00000000000000000000000000000000"
    "00000000000000000000000000000000",
    "00000000000000000000000000000000",
    "",
    "000000000000000000000000",
    "cea7403d4d606b6e074ec5d3baf39d18",
    "d0d1c8a799996bf0265b98b5d48ab919"
  },
  {
    "gcm-aes",
    "feffe9928665731c6d6a8f9467308308"
    "feffe9928665731c6d6a8f9467308308",

    "d9313225f88406e5a55909c5aff5269a"
    "86a7a9531534f7da2e4c303d8a318a72"
    "1c3c0c95956809532fcf0e2449a6b525"
    "b16aedf5aa0de657ba637b391aafd255",

    "",
    "cafebabefacedbaddecaf888",
    "522dc1f099567d07f47f37a32a84427d"
    "643a8cdcbfe5c0c97598a2bd2555d1aa"
    "8cb08e48590dbb3da7b08b1056828838"
    "c5f61e6393ba7a0abcc9f662898015ad",
    "b094dac5d93471bdec1a502270e3cc6c"
  },
  {
    "gcm-aes",
    "feffe9928665731c6d6a8f9467308308"
    "feffe9928665731c6d6a8f9467308308",

    "d9313225f88406e5a55909c5aff5269a"
    "86a7a9531534f7da2e4c303d8a318a72"
    "1c3c0c95956809532fcf0e2449a6b525"
    "b16aedf5aa0de657ba637b39",

    "feedfacedeadbeeffeedfacedeadbeef"
    "abaddad2",

    "cafebabefacedbaddecaf888",

    "522dc1f099567d07f47f37a32a84427d"
    "643a8cdcbfe5c0c97598a2bd2555d1aa"
    "8cb08e48590dbb3da7b08b1056828838"
    "c5f61e6393ba7a0abcc9f662",

    "76fc6ece0f4e1768cddf8853bb2d551b"
  },
  {
    "gcm-aes", 
    "feffe9928665731c6d6a8f9467308308"
    "feffe9928665731c6d6a8f9467308308",

    "d9313225f88406e5a55909c5aff5269a"
    "86a7a9531534f7da2e4c303d8a318a72"
    "1c3c0c95956809532fcf0e2449a6b525"
    "b16aedf5aa0de657ba637b39",
    
    "feedfacedeadbeeffeedfacedeadbeef"
    "abaddad2",

    "cafebabefacedbad",

    "c3762df1ca787d32ae47c13bf19844cb"
    "af1ae14d0b976afac52ff7d79bba9de0"
    "feb582d33934a4f0954cc2363bc73f78"
    "62ac430e64abe499f47c9b1f",
    "3a337dbf46a792c45e454913fe2ea8f2"
  },
  {
    "gcm-aes",
    "feffe9928665731c6d6a8f9467308308"
    "feffe9928665731c6d6a8f9467308308",

    "d9313225f88406e5a55909c5aff5269a"
    "86a7a9531534f7da2e4c303d8a318a72"
    "1c3c0c95956809532fcf0e2449a6b525"
    "b16aedf5aa0de657ba637b39",

    "feedfacedeadbeeffeedfacedeadbeef"
    "abaddad2",

    "9313225df88406e555909c5aff5269aa"
    "6a7a9538534f7da1e4c303d2a318a728"
    "c3c0c95156809539fcf0e2429a6b5254"
    "16aedbf5a0de6a57a637b39b",
    "5a8def2f0c9e53f1f75d7853659e2a20"
    "eeb2b22aafde6419a058ab4f6f746bf4"
    "0fc0c3b780f244452da3ebf1c5d82cde"
    "a2418997200ef82e44ae7e3f",
    "a44a8266ee1c8eb0c8b5d4cf5ae9f19a"
  },
  /* Testing GMAC, ie. no plaintext specified. 
     These are from http://grouper.ieee.org/groups/1619/email/msg00544.html.
  */
  {
    "gcm-aes",
    "feffe9928665731c6d6a8f9467308308",
    "",
    "feedfacedeadbeeffeedfacedeadbeef",
    "cafebabefacedbaddecaf888",
    "",
    "54df474f4e71a9ef8a09bf30da7b1a92"
  },
  {
    "gmac-aes",
    "feffe9928665731c6d6a8f9467308308",
    "",
    "feedfacedeadbeeffeedfacedeadbeef",
    "cafebabefacedbaddecaf888",
    "",
    "54df474f4e71a9ef8a09bf30da7b1a92"
  },

  {
    "gcm-aes",
    "feffe9928665731c6d6a8f9467308308",
    "",
    "feedfacedeadbeeffeedfacedeadbeef"
    "abaddad242831ec2217774244b7221b7",
    "cafebabefacedbaddecaf888",
    "",
    "1cbe3936e553b08f25c08d7b8dc39fdb"
  },
  {
    "gmac-aes",
    "feffe9928665731c6d6a8f9467308308",
    "",
    "feedfacedeadbeeffeedfacedeadbeef"
    "abaddad242831ec2217774244b7221b7",
    "cafebabefacedbaddecaf888",
    "",
    "1cbe3936e553b08f25c08d7b8dc39fdb"
  },





































#endif /* SSHDIST_CRYPT_MODE_GCM */
    
  {NULL}
};


/* Convert from a hex string to unsigned char buffer */
static void hex_string_to_buf(const char *str,
			      unsigned char **key, 
			      size_t *keylen)
                           
{
  unsigned char *buf, c, d;
  size_t len, i;

  SSH_DEBUG(5, ("Convert %s to buffer\n", str));

  SSH_ASSERT(strlen(str) % 2 == 0);

  len = strlen(str) / 2; 
  buf = ssh_xmalloc(len); 

  for (i = 0; i < len; i++)
    {
      c = tolower(str[2*i]);
      d = tolower(str[2*i + 1]);

      SSH_ASSERT(isxdigit(c));
      SSH_ASSERT(isxdigit(d));

      if (islower(c)) 
        buf[i] = (c - 'a') + 10;
      else 
        buf[i] = (c - '0');
      
      buf[i] <<= 4; 

      if (islower(d)) 
        buf[i] += (d - 'a') + 10;
      else 
        buf[i] += (d - '0');
    }  

  *key = buf;
  *keylen = len;
  return;
}


char *debuglevel = NULL;

void test_variant(const char *postfix)
{
  SshCipher cipher;
  SshCryptoStatus status;
  unsigned char *iv, *key, *src, *plain;
  unsigned char *aad, *ciph, *auth_tag, digest_len;
  size_t key_len, iv_len, aad_len, src_len, src_len_block, ciph_len, 
    auth_tag_len, orig_len;
  unsigned char *orig;
  unsigned char iv_buf[16], *digest;
  unsigned char *ciph_name;
  size_t blocklen;
  int i;

  for (i = 0; combined_test_vectors[i].key != NULL; i++)
    {
      hex_string_to_buf(combined_test_vectors[i].key, &key, &key_len);
      hex_string_to_buf(combined_test_vectors[i].iv, &iv, &iv_len);
      hex_string_to_buf(combined_test_vectors[i].aad, &aad, &aad_len);
      hex_string_to_buf(combined_test_vectors[i].plaintext, &plain, &src_len);
      hex_string_to_buf(combined_test_vectors[i].plaintext, &src, &src_len);
      orig = ssh_xmemdup(src, src_len);
      orig_len = src_len;
      hex_string_to_buf(combined_test_vectors[i].ciphertext, &ciph, &ciph_len);
      hex_string_to_buf(combined_test_vectors[i].auth_tag, &auth_tag, 
			&auth_tag_len);
      digest = NULL;

      ciph_name = ssh_string_concat_2(combined_test_vectors[i].name, postfix);
      SSH_ASSERT(ciph_name);
      status = ssh_cipher_allocate(ciph_name,
				   key, key_len, TRUE, &cipher);
      if (status != SSH_CRYPTO_OK)
	{ 
	  fprintf(stderr, "Cannot allocate cipher \"%s\" (status is %s)\n", 
		  ciph_name, ssh_crypto_status_message(status));
	  exit(1);
	}




      if (iv_len != 12)
	{
	  SSH_DEBUG(1, ("Skipping test %d with IV not equal to 12 bytes", i));
	  goto dealloc_and_continue;
	}

      if (!ssh_cipher_is_auth_cipher(combined_test_vectors[i].name))
	{
	  SSH_DEBUG(1, ("Skipping test %d with non-auth cipher", i));
	  goto dealloc_and_continue;
	}

      digest_len = 
	ssh_cipher_auth_digest_length(combined_test_vectors[i].name);
      digest = ssh_xmalloc(digest_len);

      ssh_cipher_auth_reset(cipher);
      
      if (aad != NULL)
	ssh_cipher_auth_update(cipher, aad, aad_len);
      



      SSH_ASSERT(iv_len == 12);
      memcpy(iv_buf, iv, 12);
      SSH_PUT_32BIT(iv_buf + 12, 1);
      
      status = ssh_cipher_set_iv(cipher, iv_buf);
      SSH_VERIFY(status == SSH_CRYPTO_OK);

      blocklen = ssh_cipher_get_block_length(combined_test_vectors[i].name);

      src_len_block = src_len - (src_len % blocklen);
      status = ssh_cipher_transform(cipher, src, src, src_len_block);
	
      /* Process remaining bytes if test was not multiple of block size. */
      if (status == SSH_CRYPTO_OK && (src_len > src_len_block))
	{
	  status = ssh_cipher_transform_remaining(cipher, 
						  src + src_len_block,
						  src + src_len_block,
						  src_len - src_len_block);
	}

      SSH_VERIFY(status == SSH_CRYPTO_OK);
      
      SSH_VERIFY(ssh_cipher_auth_final(cipher, digest) == SSH_CRYPTO_OK);
      
      if (src_len != ciph_len || memcmp(src, ciph, src_len))
	{
	  fprintf(stderr, 
		  "Test vectors ciphertext (ciph=%s) do not agree test=%d\n", 
		  ciph_name, i);
	  SSH_DEBUG_HEXDUMP(1, ("cipher computed"), src, src_len);
	  SSH_DEBUG_HEXDUMP(1, ("cipher expected"), ciph, ciph_len);
	  exit(1);
	}

      if (digest_len != auth_tag_len ||
	  memcmp(digest, auth_tag, digest_len)) 
	{
	  fprintf(stderr, 
		  "Test vectors digest (ciph=%s) do not agree test=%d\n", 
		  ciph_name, i);
	  SSH_DEBUG_HEXDUMP(1, ("digest computed"), digest, digest_len);
	  SSH_DEBUG_HEXDUMP(1, ("digest expected"), auth_tag, auth_tag_len);
	  exit(1);
	}
      
      /* Redo operation, now decryption */
      ssh_cipher_free(cipher);

      status = ssh_cipher_allocate(ciph_name,
				   key, key_len, FALSE, &cipher);
      if (status != SSH_CRYPTO_OK)
	{ 
	  fprintf(stderr, "Cannot allocate cipher \"%s\" (status is %s)\n", 
		  ciph_name, ssh_crypto_status_message(status));
	  exit(1);
	}

      SSH_ASSERT(digest_len == 
		 ssh_cipher_auth_digest_length(combined_test_vectors[i].name));

      ssh_cipher_auth_reset(cipher);
      
      if (aad != NULL)
	ssh_cipher_auth_update(cipher, aad, aad_len);
      



      SSH_ASSERT(iv_len == 12);
      memcpy(iv_buf, iv, 12);
      SSH_PUT_32BIT(iv_buf + 12, 1);
      
      status = ssh_cipher_set_iv(cipher, iv_buf);
      SSH_VERIFY(status == SSH_CRYPTO_OK);

      src_len_block = src_len - (src_len % blocklen);
      status = ssh_cipher_transform(cipher, orig, src, src_len_block);
	
      /* Process remaining bytes if test was not multiple of block size. */
      if (status == SSH_CRYPTO_OK && (src_len > src_len_block))
	{
	  status = ssh_cipher_transform_remaining(cipher, 
						  orig + src_len_block,
						  src + src_len_block,
						  src_len - src_len_block);
	}

      SSH_VERIFY(status == SSH_CRYPTO_OK);
      
      SSH_VERIFY(ssh_cipher_auth_final(cipher, digest) == SSH_CRYPTO_OK);
      
      if (orig_len != ciph_len || memcmp(orig, plain, src_len))
	{
	  fprintf(stderr, 
		  "Test vectors plaintext (ciph=%s) do not agree test=%d\n", 
		  ciph_name, i);
	  SSH_DEBUG_HEXDUMP(1, ("plain computed"), orig, orig_len);
	  SSH_DEBUG_HEXDUMP(1, ("plain expected"), plain, ciph_len);
	  exit(1);
	}

      if (digest_len != auth_tag_len ||
	  memcmp(digest, auth_tag, digest_len)) 
	{
	  fprintf(stderr, 
		  "Test vectors digest (ciph=%s) do not agree test=%d\n", 
		  ciph_name, i);
	  SSH_DEBUG_HEXDUMP(1, ("digest computed"), digest, digest_len);
	  SSH_DEBUG_HEXDUMP(1, ("digest expected"), auth_tag, auth_tag_len);
	  exit(1);
	}
      
      /* Reset cipher and redo decryption */
      ssh_cipher_auth_reset(cipher);

      if (aad != NULL)
	ssh_cipher_auth_update(cipher, aad, aad_len);
      
      status = ssh_cipher_set_iv(cipher, iv_buf);
      SSH_VERIFY(status == SSH_CRYPTO_OK);

      status = ssh_cipher_transform(cipher, orig, src, src_len_block);
	
      /* Process remaining bytes if test was not multiple of block size. */
      if (status == SSH_CRYPTO_OK && (src_len > src_len_block))
	{
	  status = ssh_cipher_transform_remaining(cipher, 
						  orig + src_len_block,
						  src + src_len_block,
						  src_len - src_len_block);
	}

      SSH_VERIFY(status == SSH_CRYPTO_OK);
      
      SSH_VERIFY(ssh_cipher_auth_final(cipher, digest) == SSH_CRYPTO_OK);
      
      if (orig_len != ciph_len || memcmp(orig, plain, src_len))
	{
	  fprintf(stderr, 
		  "Test vectors plaintext (ciph=%s) do not agree test=%d\n", 
		  ciph_name, i);
	  SSH_DEBUG_HEXDUMP(1, ("plain computed"), orig, orig_len);
	  SSH_DEBUG_HEXDUMP(1, ("plain expected"), plain, ciph_len);
	  exit(1);
	}

      if (digest_len != auth_tag_len ||
	  memcmp(digest, auth_tag, digest_len)) 
	{
	  fprintf(stderr, 
		  "Test vectors digest (ciph=%s) do not agree test=%d\n", 
		  ciph_name, i);
	  SSH_DEBUG_HEXDUMP(1, ("digest computed"), digest, digest_len);
	  SSH_DEBUG_HEXDUMP(1, ("digest expected"), auth_tag, auth_tag_len);
	  exit(1);
	}
      
      SSH_DEBUG(2, ("Test %d (cipher=`%s') successful", i, 
		    combined_test_vectors[i].name));

    dealloc_and_continue:
      if (cipher) 
	ssh_cipher_free(cipher);

      ssh_xfree(digest);
      ssh_xfree(key); 
      ssh_xfree(iv);  
      ssh_xfree(aad);
      ssh_xfree(src); 
      ssh_xfree(orig); 
      ssh_xfree(plain); 
      ssh_xfree(ciph); 
      ssh_xfree(auth_tag);
      ssh_xfree(ciph_name);
    }

}

int main(int argc, char **argv)
{
  int opt;

  ssh_regression_init(&argc, &argv, "Combined modes",
                      "mnippula@safenet-inc.com");

  while ((opt = ssh_getopt(argc, argv, "d:", NULL)) != EOF)
    {
      switch (opt)
        {
        case 'd':
          debuglevel = ssh_optarg;
          break;
        default:
          fprintf(stderr, "usage: t-combined-modes [-d debuglevel] \n");
          exit(1);
        }
    }


  if (ssh_crypto_library_initialize() != SSH_CRYPTO_OK)
    ssh_fatal("Crypto library initialization failed");

  if (debuglevel)
    ssh_debug_set_level_string(debuglevel);

  test_variant("");
  test_variant("-256");
  test_variant("-4k");
  test_variant("-8k");
  test_variant("-64k");

  ssh_crypto_library_uninitialize();
  ssh_debug_uninit();
  ssh_regression_finish();
  exit(0);
}

