/*

t-pkcs1-implicit.c

      Copyright:
              Copyright (c)  2005 SFNT Finland Oy.

      All rights reserved.

      Test program for the RSA PKCS1 implicit scheme, where the hash 
      algorithm to use for signature verification is derived from the 
      input signature.
*/

#include "sshincludes.h"
#include "sshglobals.h"
#include "sshdebug.h"
#include "sshgetopt.h"
#include "sshcrypt.h"

#define SSH_DEBUG_MODULE "TPkcs1Implicit"


int main (int ac, char **av)
{
  SshPrivateKey prvkey;
  SshPublicKey pubkey1, pubkey2;
  SshCryptoStatus status;
  unsigned char data[1024], *signature;
  size_t i, j, signature_len, signature_len_return;
  int opt;
  char *schemes[]  = {
#ifdef SSHDIST_CRYPT_SHA
    "rsa-pkcs1-sha1",
#endif /* SSHDIST_CRYPT_SHA */
#ifdef SSHDIST_CRYPT_MD5 
    "rsa-pkcs1-md5",
#endif /* SSHDIST_CRYPT_MD5 */
#ifdef SSHDIST_CRYPT_MD2
    "rsa-pkcs1-md2", 
#endif /* SSHDIST_CRYPT_MD2 */
    NULL};

  while ((opt = ssh_getopt(ac, av, "hd:", NULL)) != EOF)
    {
      switch (opt)
	{
	case 'd':
          ssh_debug_set_level_string(ssh_optarg);
	  break;

	default:
        case 'h':
	  fprintf(stderr, "Usage: t-pkcs1implicit [-d DEBUG_LEVEL ]\n");
          exit(1);
	}

    }

  if (ssh_crypto_library_initialize() != SSH_CRYPTO_OK)
    ssh_fatal("Could not initialize crypto library");

  fprintf(stderr, "Testing PKCS1 implicit scheme\n");

#ifdef WITH_RSA
  /* Register the RSA key generation type. */
  ssh_pk_provider_register(&ssh_pk_if_modn_generator);
#endif /* WITH_RSA */

  /* Generate a private key. */
  status = ssh_private_key_generate(&prvkey,
				    "if-modn", 
                                    SSH_PKF_SIZE, 1024,
                                    SSH_PKF_END);

  /* Derive public keys */
  status = ssh_private_key_derive_public_key(prvkey, &pubkey1);
  SSH_VERIFY(status == SSH_CRYPTO_OK);
  
  status = ssh_private_key_derive_public_key(prvkey, &pubkey2);
  SSH_VERIFY(status == SSH_CRYPTO_OK);
  
  for (j = 0; schemes[j]; j++)
    {
      SSH_DEBUG(5, ("Setting the scheme to %s", schemes[j]));
      status = ssh_private_key_select_scheme(prvkey, 
					     SSH_PKF_SIGN, schemes[j],
					     SSH_PKF_END);
      SSH_VERIFY(status == SSH_CRYPTO_OK);
	
      /* Get random data to sign. */
      for (i = 0; i < sizeof(data); i++)
	data[i] = ssh_random_get_byte();
	
      signature_len = ssh_private_key_max_signature_output_len(prvkey);  
      signature = ssh_xcalloc(1, signature_len);
	
      status = ssh_public_key_select_scheme(pubkey1, 
					    SSH_PKF_SIGN, schemes[j],
					    SSH_PKF_END);
      SSH_VERIFY(status == SSH_CRYPTO_OK);
	
      status = ssh_public_key_select_scheme(pubkey2, 
					    SSH_PKF_SIGN, 
					    "rsa-pkcs1-implicit",
					    SSH_PKF_END);
      SSH_VERIFY(status == SSH_CRYPTO_OK);
	
      /* Sign the data */
      status = ssh_private_key_sign(prvkey, data, sizeof(data),
				    signature, signature_len,
				    &signature_len_return);
      SSH_VERIFY(status == SSH_CRYPTO_OK);

      status = ssh_public_key_verify_signature(pubkey2,
					       signature,
					       signature_len_return,
					       data,
					       sizeof(data));
      if (status != SSH_CRYPTO_OK)
	{
	  ssh_warning("Public key verification failed using pkcs1 implicit "
		      "scheme (%s)", schemes[j]);
	  goto fail;
	}

      /* Verify the signatures */
      status = ssh_public_key_verify_signature(pubkey1,
					       signature,
					       signature_len_return,
					       data,
					       sizeof(data));
      if (status != SSH_CRYPTO_OK)
	{
	  ssh_warning("Public key verification failed using pkcs1 scheme "
		      "%s", schemes[j]);
	  goto fail;
	}
      ssh_xfree(signature);
      signature = NULL;
   }

  /* Test was successful */    
  ssh_private_key_free(prvkey);
  ssh_public_key_free(pubkey1);
  ssh_public_key_free(pubkey2);
  ssh_crypto_library_uninitialize();
  ssh_util_uninit();
  exit(0);

 fail:
  /* Test was not successful */    
  ssh_private_key_free(prvkey);
  ssh_public_key_free(pubkey1);
  ssh_public_key_free(pubkey2);
  ssh_xfree(signature);
  ssh_crypto_library_uninitialize();
  ssh_util_uninit();
  exit(1);
}
