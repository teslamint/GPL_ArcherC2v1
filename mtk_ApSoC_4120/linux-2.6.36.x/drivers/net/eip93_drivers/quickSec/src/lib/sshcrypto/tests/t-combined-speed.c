/*

t-combined-speed.c

      Copyright:
              Copyright (c)  2008 SFNT Finland Oy.

      All rights reserved.

      Test program to measure speed of combined cipher and mac algorithms.
*/

#include "sshincludes.h"
#include "sshgetopt.h"
#include "sshcrypt.h"
#include "sshtimemeasure.h"

#define SSH_DEBUG_MODULE "CombinedModesTestVectors"

/* How many bytes to autenticate but not encrypt. This test assumes this 
   data is in a header before the encrypted data. */
#define AAD_LEN 8

typedef struct CombinedAlgorithmRec {
  const char *cipher;
  const char *mac;
  int cipherkeylen;
  int ivlen;
  int blocklen; /* Used for padding plaintext data */
  int mackeylen;
} CombinedAlgorithmStruct, *CombinedAlgorithm;

static CombinedAlgorithmStruct combined_algorithms[] = {
  { "aes-cbc", "hmac-sha1", 16, 16, 16, 20},
  { "aes-cbc", "hmac-md5", 16, 16, 16, 20},
  { "aes-cbc", "none", 16, 16, 16, 0},
  { "none", "hmac-sha1", 0, 0, 0, 20},
  { "none", "hmac-md5", 0, 0, 0, 20},
#ifdef SSHDIST_CRYPT_MODE_GCM
  { "gcm-aes-4k", NULL, 16, 8, 16, 0},
#endif /* SSHDIST_CRYPT_MODE_GCM */
};

static void usage(void)
{
  printf("\
Usage: []OPTION...\n\
  -l        Packet size\n\
  -n        Number of operations\n\
  -d        Perform decryption operation instead of encryption\n\
  -m        Use the same data buffer for all operations, this gives better\n\
            results due to better data cache locality\n\
  -D        Debug level\n\
  -h        Print this help and exit\n");
}



int main (int ac, char **av)
{
  struct SshTimeMeasureRec tmit = SSH_TIME_MEASURE_INITIALIZER;
  unsigned char digest[SSH_MAX_HASH_DIGEST_LENGTH];
  CombinedAlgorithm alg;
  SshCipher cipher;
  SshMac mac;
  SshCryptoStatus status;
  Boolean multiple_buffers = TRUE;
  Boolean for_encryption = TRUE;
  SshUInt32 usecs;
  unsigned char **dataptr;
  unsigned char *key, *data;
  size_t max_datalen,  datalen, enc_ofs;  
  int count, size;
  int i, j, c;

  size = 1024;
  count = 20000;
  while ((c = ssh_getopt(ac, av, "l:n:D:mdh", NULL)) != EOF)
    {
      switch (c)
	{
	case 'l':
	  size = atoi(ssh_optarg);
	  break;
	case 'n':
	  count = atoi(ssh_optarg);
	  break;
	case 'd':
	  for_encryption = FALSE;
	  break;
	case 'm':
	  multiple_buffers = FALSE;
	  break;
	case 'D':
	  ssh_debug_set_level_string(ssh_optarg);
	  break;
	case 'h': 
	  usage(); exit(0);
	}
    }

  if (ssh_crypto_library_initialize() != SSH_CRYPTO_OK)
    ssh_fatal("Cannot initialize the crypto library.");

  max_datalen = 
    AAD_LEN + size + SSH_CIPHER_MAX_BLOCK_SIZE + SSH_CIPHER_MAX_IV_SIZE;
  dataptr = ssh_xmalloc(count * sizeof(unsigned char *));
  for (i = 0; i < count ; i++)
    dataptr[i] = ssh_xmalloc(max_datalen);

  for (i = 0; 
       i < sizeof(combined_algorithms) / sizeof(combined_algorithms[0]); 
       i++)
    {
      alg = &combined_algorithms[i]; 
      
      cipher = NULL;
      mac = NULL;

      if (alg->cipher)
	{
	  key = ssh_xmalloc(alg->cipherkeylen);

	  for (j = 0; j < alg->cipherkeylen; j++)
	    key[j] = ssh_random_get_byte();
	  
	  if (ssh_cipher_allocate(alg->cipher, key, alg->cipherkeylen,
				  for_encryption,
				  &cipher) != SSH_CRYPTO_OK)
	    goto error;

	  ssh_xfree(key);
	}

      SSH_DEBUG(SSH_D_MY, ("Cipher allocated"));

      if (alg->mac)
	{
	  key = ssh_xmalloc(alg->mackeylen);

	  for (j = 0; j < alg->mackeylen; j++)
	    key[j] = ssh_random_get_byte();
	  
	  if (ssh_mac_allocate(alg->mac, key, alg->mackeylen,
			       &mac) != SSH_CRYPTO_OK)
	    goto error;

	  ssh_xfree(key);
	}

      SSH_DEBUG(SSH_D_MY, ("MAC allocated"));

      /* Set the correct datalen for this combined mode algorithm. It must 
	 be less than the max_datalen previously allocated. The IV is placed 
      after the ADD just before the plaintext data. */
      datalen = AAD_LEN + alg->ivlen + size;
      if (alg->blocklen) datalen += (alg->blocklen - size % alg->blocklen);
      SSH_VERIFY(datalen <= max_datalen);
      
      enc_ofs = AAD_LEN + alg->ivlen;

      ssh_time_measure_reset(&tmit);
      ssh_time_measure_start(&tmit);

      if (cipher && ssh_cipher_is_auth_cipher(alg->cipher))
	{
	  for (j = 0; j < count; j++)
	    {
	      data = multiple_buffers ? dataptr[j] : dataptr[0];

	      status = ssh_cipher_transform_with_iv(cipher, 
						    data + enc_ofs, 
						    data + enc_ofs, 
						    datalen - enc_ofs,
						    data + AAD_LEN);
	      if (status != SSH_CRYPTO_OK)
		{
		  SSH_DEBUG(SSH_D_FAIL, ("Cipher operation %d failed %s", j, 
					 ssh_crypto_status_message(status)));
		  goto error;
		}
	      
	      ssh_cipher_auth_reset(cipher);
	      ssh_cipher_auth_update(cipher, data, datalen);
	      
	      status = ssh_cipher_auth_final(cipher, digest);	
	      if (status != SSH_CRYPTO_OK)
		goto error;
	    }
	}
      else
	{
	  for (j = 0; j < count; j++)
	    {
	      data = multiple_buffers ? dataptr[j] : dataptr[0];

	      status = ssh_cipher_transform_with_iv(cipher, 
						    data + enc_ofs, 
						    data + enc_ofs, 
						    datalen - enc_ofs,
						    data + AAD_LEN);
	      if (status != SSH_CRYPTO_OK)
		{
		  SSH_DEBUG(SSH_D_FAIL, ("Cipher operation %d failed", j));
		  goto error;
		}
	      
	      ssh_mac_reset(mac);
	      ssh_mac_update(mac, data, datalen);
	      
	      status = ssh_mac_final(mac, digest);	
	      if (status != SSH_CRYPTO_OK)
		goto error;
	    }
	}

      
      ssh_time_measure_stop(&tmit);
      usecs =
	(unsigned int)ssh_time_measure_get(&tmit,
					   SSH_TIME_GRANULARITY_MICROSECOND);
      
      printf("%s%s%s: %d operations of size %d in %ld usecs -> "
	     "%f 10^6 bit/s\n",
	     alg->cipher ? alg->cipher : "",
	     alg->cipher && alg->mac ? "-" : "",
	     alg->mac ? alg->mac : "",
	     count, size, usecs, 
	     (double)(count * size * 8) / (double) usecs);

      if (cipher) ssh_cipher_free(cipher);
      if (mac) ssh_mac_free(mac);
    }
  
  for (i = 0; i < count ; i++)
    ssh_xfree(dataptr[i]);
  ssh_xfree(dataptr);
  
  ssh_crypto_library_uninitialize();
  ssh_util_uninit();
  return 0;

 error:
  printf("Cipher or mac operation failed\n");
  ssh_crypto_library_uninitialize();
  ssh_util_uninit();
  return 0;
}

