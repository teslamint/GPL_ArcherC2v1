/*

  pkcs-test.c

  Copyright:
     	Copyright (c) 2002-2005 SFNT Finland Oy.
	All rights reserved.

*/

#include "sshincludes.h"
#include "sshcrypt.h"
#include "sshtimemeasure.h"
#include "readfile.h"
#include "sshmp.h"
#include "sshdsprintf.h"
#include "namelist.h"
#include "t-gentest.h"

#define SSH_DEBUG_MODULE "GenTestPkcs"

/**************************** PKCS tests *******************************/

void my_progress_func(SshCryptoProgressID id,
                      unsigned int time_value, void *context)
{
  if (verbose)
    {
      switch (id)
        {
        case SSH_CRYPTO_PRIME_SEARCH:
          printf("\rPrime search: %c", "-\\|/"[time_value%4]);
          fflush(stdout);
          break;
        default:
          printf("\rOperation %d: %dth value.", id, time_value);
          fflush(stdout);
          break;
        }
    }
}

typedef struct
{
  const char *cipher;
  const char *cipherkey;
  size_t cipherkeylen;
} PkcsExportInfo;

typedef struct
{
  char *key_type;
  char *sign; char *encrypt; char *dh;
  char *predefined;
  PkcsExportInfo *exportinfo;
  int   size;
  int   entropy;
} PkcsInfo;

PkcsExportInfo aes_cbc_export = {
  "aes-cbc", "00010203040506070809101112131415", 128 / 8
};

PkcsInfo pkcs_info[] =
  {
    { "if-modn", "rsa-pkcs1-sha1", "rsa-pkcs1v2-oaep", NULL, NULL,
      &aes_cbc_export, 1024, 0 },
    { "if-modn", "rsa-pss-sha1", "rsa-pkcs1-none", NULL, NULL,
      &aes_cbc_export, 1024, 0 },
    { "if-modn", "rsa-pss-md5", "rsa-pkcs1-none", NULL, NULL,
      &aes_cbc_export, 1027, 0 },
    { "if-modn", "rsa-pkcs1-md5", "rsa-pkcs1-none", NULL, NULL,
      &aes_cbc_export, 1024, 0 },
    { "if-modn", "rsa-pkcs1-md5", "rsa-none-none", NULL, NULL,
      &aes_cbc_export, 1024, 0 },

#ifdef SSHDIST_CRYPT_MD2
    { "if-modn", "rsa-pkcs1-md2", "rsa-pkcs1-none", NULL, NULL,
      &aes_cbc_export, 1024, 0 },
#endif /* SSHDIST_CRYPT_MD2 */

#ifdef SSHDIST_CRYPT_DSA
    { "dl-modp", "dsa-nist-sha1", NULL, NULL, NULL,
      &aes_cbc_export, 1024, 0 },

    /* Combination. */
    { "dl-modp", "dsa-nist-sha1", NULL, "plain", NULL,
      &aes_cbc_export, 1024, 0 },
#endif /* SSHDIST_CRYPT_DSA */

#ifdef SSHDIST_CRYPT_GENPKCS_DH
    /* Number of DH tests. */
    { "dl-modp", NULL, NULL, "plain", NULL,
      &aes_cbc_export, 1024, 160 },
    { "dl-modp", NULL, NULL, "plain", NULL,
      &aes_cbc_export, 1024, 256 },
#endif /* SSHDIST_CRYPT_GENPKCS_DH */

#ifdef SSHDIST_CRYPT_ECP
    /* ECP */
    { "ec-modp", "dsa-none-sha1", NULL, "plain", "ssh-ec-modp-curve-175bit-1",
      &aes_cbc_export, 0, 0 },
    { "ec-modp", "elgamal-none-sha1", "elgamal-random-none",
      "plain", "ssh-ec-modp-curve-175bit-1",
      &aes_cbc_export, 0, 0 },
#endif /* SSHDIST_CRYPT_ECP */










    { NULL }
  };


SshPrivateKey pkcs_make_prvkey(Boolean print, PkcsInfo *info)
{
  unsigned char *buf, *tmp[10], *k;
  SshPrivateKey prv;
  SshCryptoStatus status;
  int i;

  ssh_dsprintf(&buf, "%s{", info->key_type);

  if (print)
    printf("  -- key type = %s\n", info->key_type);
  SSH_DEBUG(2, ("key type = %s", info->key_type));

  /* Generate the key. */
  i = 0;
  if (info->sign)
    {
      ssh_dsprintf(&tmp[i], "sign{%s}", info->sign);
      if (print)
        printf("  -- signature algorithm = %s\n", info->sign);
      SSH_DEBUG(2, ("signature algorithm = %s", info->sign));
      i++;
    }
  if (info->encrypt)
    {
      ssh_dsprintf(&tmp[i], "encrypt{%s}", info->encrypt);
      if (print)
        printf("  -- encryption algorithm = %s\n", info->encrypt);
      SSH_DEBUG(2, ("encryption algorithm = %s", info->encrypt));
      i++;
    }
  if (info->dh)
    {
      ssh_dsprintf(&tmp[i], "dh{%s}", info->dh);
      if (print)
        printf("  -- Diffie-Hellman type = %s\n", info->dh);
      SSH_DEBUG(2, ("Diffie-Hellman type = %s", info->dh));
      i++;
    }
  tmp[i] = NULL;

  for (i = 0; tmp[i]; i++)
    {
      if (i > 0)
        ssh_dsprintf(&k, "%s,%s", buf, tmp[i]);
      else
        ssh_dsprintf(&k, "%s%s", buf, tmp[i]);
      ssh_xfree(buf);
      ssh_xfree(tmp[i]);
      buf = k;
    }
  ssh_dsprintf(&k, "%s}", buf);
  ssh_xfree(buf);
  buf = k;

  if (print)
    printf("  -- combined name = %s\n", buf);
  SSH_DEBUG(2, ("combined name = %s", buf));

  if (info->predefined)
    {
      if (print)
        printf("  -- predefined parameters = %s\n", info->predefined);
      SSH_DEBUG(2, ("predefined parameters = %s", info->predefined));
      if (info->entropy)
        {
          if (print)
            printf("  -- randomizer entropy = %u bits\n", info->entropy);
          SSH_DEBUG(2, ("randomizer entropy = %u bits", info->entropy));

          if (print)
            printf("  -- generating...\n");
          SSH_DEBUG(2, ("generating..."));
          status =
            ssh_private_key_generate(&prv,
                                     buf,
                                     SSH_PKF_PREDEFINED_GROUP,
                                     info->predefined,
                                     SSH_PKF_RANDOMIZER_ENTROPY,
                                     info->entropy,
                                     SSH_PKF_END);
          goto end;
        }
      else
        {
          if (print)
            printf("  -- generating...\n");
          SSH_DEBUG(2, ("generating..."));
          status =
            ssh_private_key_generate(&prv,
                                     buf,
                                     SSH_PKF_PREDEFINED_GROUP,
                                     info->predefined,
                                     SSH_PKF_END);
          goto end;
        }
    }
  else
    {
      if (print)
        printf("  -- private key size = %u bits\n", info->size);
      SSH_DEBUG(2, ("private key size = %u bits", info->size));

      if (info->entropy)
        {
          if (print)
            printf("  -- randomizer entropy = %u bits\n", info->entropy);
          SSH_DEBUG(2, ("randomizer entropy = %u bits", info->entropy));

          if (print)
            printf("  -- searching...\n");
          SSH_DEBUG(2, ("searching..."));
          status =
            ssh_private_key_generate(&prv,
                                     buf,
                                     SSH_PKF_SIZE, info->size,
                                     SSH_PKF_RANDOMIZER_ENTROPY,
                                     info->entropy,
                                     SSH_PKF_END);
          goto end;
        }
      else
        {
          if (print)
            printf("  -- searching...\n");
          SSH_DEBUG(2, ("searching..."));
          status =
            ssh_private_key_generate(&prv,
                                     buf,
                                     SSH_PKF_SIZE, info->size,
                                     SSH_PKF_END);
          goto end;
        }
    }

 end:

  ssh_xfree(buf);

  if (status != SSH_CRYPTO_OK)
    {
      printf("Crypto library error: %s (%d)\n",
             ssh_crypto_status_message(status), status);
      return NULL;
    }

  return prv;
}

/* Tests various utility functions for private and public keys. */
Boolean pkcs_tests_utility(SshPrivateKey private_key,
                           SshPublicKey public_key,
                           PkcsInfo *info)
{
  SshCryptoStatus status;
  SshPrivateKey prv_key, prv_key_copy;
  SshPublicKey pub_key, pub_key_copy;
  SshMPInteger g, p, d, e, u, q, n, x, y, aux;
  char *type, *name;
  const char *sig_name, *enc_name, *dh_name, *key_name;
  unsigned int size;

  g = ssh_mprz_malloc();
  d = ssh_mprz_malloc();
  e = ssh_mprz_malloc();
  u = ssh_mprz_malloc();

  p = ssh_mprz_malloc();
  q = ssh_mprz_malloc();
  n = ssh_mprz_malloc();
  x = ssh_mprz_malloc();
  y = ssh_mprz_malloc();
  aux = ssh_mprz_malloc();

  /* Copy the input keys */
  if (ssh_private_key_copy(private_key, &prv_key) != SSH_CRYPTO_OK)
    {
      SSH_DEBUG(0, ("Cannot copy the public key"));
      return FALSE;
    }

  if (ssh_public_key_copy(public_key, &pub_key) != SSH_CRYPTO_OK)
    {
      SSH_DEBUG(0, ("Cannot copy the public key"));
      return FALSE;
    }

  name = ssh_private_key_name(prv_key);
  SSH_DEBUG(2, ("The private key name is %s", name));
  ssh_free(name);

  name = ssh_public_key_name(pub_key);
  SSH_DEBUG(2, ("The public key name is  %s", name));
  ssh_free(name);

  /* Get the input private key info */
  if ((status = ssh_private_key_get_info(prv_key,
                                         SSH_PKF_KEY_TYPE, &type,
                                         SSH_PKF_SIZE, &size,
                                         SSH_PKF_SIGN, &sig_name,
                                         SSH_PKF_ENCRYPT, &enc_name,
                                         SSH_PKF_DH, &dh_name,
                                         SSH_PKF_END)) != SSH_CRYPTO_OK)
    {
      SSH_DEBUG(0, ("error:ssh_private_key_get_info failed with status %d.",
                    status));
      return FALSE;
    }

  /* Check the private key info is correct */
  if (strcmp(info->key_type, type) ||
      (info->sign && strcmp(sig_name, info->sign)) ||
      (info->encrypt && strcmp(enc_name, info->encrypt)) ||
      (info->dh && strcmp(dh_name, info->dh)) ||
      (info->size && size != info->size))
    {
      printf("%s %s\n %s %s \n %s %s\n %s %s \n %d %d\n",
             info->key_type, type, info->sign, sig_name, info->encrypt,
             enc_name, info->dh, dh_name, info->size, size);
      {
        SSH_DEBUG(0, ("error: pkcs ssh_private_key_get_info has failed"));
        return FALSE;
      }
    }

  /* Get public key info */
  if ((status = ssh_public_key_get_info(pub_key,
                                        SSH_PKF_KEY_TYPE, &type,
                                        SSH_PKF_SIZE, &size,
                                        SSH_PKF_SIGN, &sig_name,
                                        SSH_PKF_ENCRYPT, &enc_name,
                                        SSH_PKF_DH, &dh_name,
                                        SSH_PKF_END)) != SSH_CRYPTO_OK)
    {
      SSH_DEBUG(0, ("error:ssh_public_key_get_info failed with status %d.",
                    status));
      return FALSE;
    }

  /* Check the public key info is correct */
  if (strcmp(info->key_type, type) ||
      (info->sign && strcmp(sig_name, info->sign)) ||
      (info->encrypt && strcmp(enc_name, info->encrypt)) ||
      (info->dh && strcmp(dh_name, info->dh)) ||
      (info->size && size != info->size))
    {
      printf("%s %s\n %s %s \n, %s %s\n %s %s \n %d %d", info->key_type, type,
             info->sign, sig_name, info->encrypt, enc_name,
             info->dh, dh_name, info->size, size);
      {
        SSH_DEBUG(0, ("error: pkcs public get info has failed"));
        return FALSE;
      }
    }

  /* RSA specific utility checks */
  if (strcmp(info->key_type, "if-modn") == 0)
    {
      /* Get private key info */
      status = ssh_private_key_get_info(prv_key,
                                        SSH_PKF_KEY_TYPE, &type,
                                        SSH_PKF_SIGN, &name,
                                        SSH_PKF_SIZE, &size,
                                        SSH_PKF_PRIME_P, p,
                                        SSH_PKF_PRIME_Q, q,
                                        SSH_PKF_MODULO_N, n,
                                        SSH_PKF_PUBLIC_E, e,
                                        SSH_PKF_INVERSE_U, u,
                                        SSH_PKF_SECRET_D, d,
                                        SSH_PKF_END);
      if (status != SSH_CRYPTO_OK)
        {
          SSH_DEBUG(0, ("error cannot get key info, status was %d", status));
          return FALSE;
        }

      if (strcmp(type, "if-modn"))
        {
          SSH_DEBUG(0, ("error: invalid key type returned by the "
                        "get info function"));
          return FALSE;
        }

      if (ssh_mprz_bit_size(n) != size || size != info->size)
        {
          SSH_DEBUG(0, ("error: invalid key size returned from "
                        "get info function"));
          return FALSE;
        }

      if (ssh_mprz_is_probable_prime(n, 20) != 0)
        {
          SSH_DEBUG(0, ("error: invalid RSA key, n appears to be prime"));
          return FALSE;
        }

      if (ssh_mprz_is_probable_prime(p, 20) == 0)
        {
          SSH_DEBUG(0, ("error: invalid RSA key, p is not prime"));
          return FALSE;
        }

      if (ssh_mprz_is_probable_prime(q, 20) == 0)
        {
          SSH_DEBUG(0, ("error: invalid RSA key, q is not prime"));
          return FALSE;
        }

      /* Check that n is indeed p times q */
      ssh_mprz_mul(aux, p, q);
      if (ssh_mprz_cmp(aux, n))
        {
          SSH_DEBUG(0, ("error: invalid RSA key, pq is not equal to n"));
          return FALSE;
        }

      /* Check that we can change the scheme */
      sig_name = enc_name = NULL;
      status =
        ssh_private_key_select_scheme(prv_key,
                                      SSH_PKF_SIGN, "rsa-pkcs1-md5",
                                      SSH_PKF_ENCRYPT, "rsa-pkcs1v2-oaep",
                                      SSH_PKF_END);

      if (status != SSH_CRYPTO_OK)
        {
          SSH_DEBUG(0, ("error cannot set the private key scheme, "
                        "status was %d", status));
          return FALSE;
        }

      status = ssh_private_key_get_info(prv_key,
                                        SSH_PKF_SIGN, &sig_name,
                                        SSH_PKF_ENCRYPT, &enc_name,
                                        SSH_PKF_END);
      if (status != SSH_CRYPTO_OK)
        {
          SSH_DEBUG(0, ("error cannot get key info, status was %d", status));
          return FALSE;
        }

      if (strcmp(sig_name, "rsa-pkcs1-md5"))
        {
          SSH_DEBUG(0, ("error: invalid signature scheme returned "
                        "by the get info function"));
          return FALSE;
        }

      if (strcmp(enc_name, "rsa-pkcs1v2-oaep"))
        {
          SSH_DEBUG(0, ("error: invalid encrypt scheme returned "
                        "by the get info function"));
          return FALSE;
        }

      /* Check we can reconstruct the private key from the MP Integers */
      if ((status = ssh_private_key_define(&prv_key_copy,
                                           type,
                                           SSH_PKF_SECRET_D, d,
                                           SSH_PKF_PUBLIC_E, e,
                                           SSH_PKF_INVERSE_U, u,
                                           SSH_PKF_PRIME_P, p,
                                           SSH_PKF_PRIME_Q, q,
                                           SSH_PKF_MODULO_N, n,
                                           SSH_PKF_SIGN, sig_name,
                                           SSH_PKF_ENCRYPT, enc_name,
                                           SSH_PKF_END)) != SSH_CRYPTO_OK)
        {
          SSH_DEBUG(0, ("error: define private key failed with status %d.",
                        status));
          return FALSE;
        }
      ssh_private_key_free(prv_key_copy);


      /* Get public key info */
      status = ssh_public_key_get_info(pub_key,
                                       SSH_PKF_KEY_TYPE, &type,
                                       SSH_PKF_SIGN, &name,
                                       SSH_PKF_SIZE, &size,
                                       SSH_PKF_MODULO_N, n,
                                       SSH_PKF_PUBLIC_E, e,
                                       SSH_PKF_END);
      if (status != SSH_CRYPTO_OK)
        {
          SSH_DEBUG(0, ("error cannot get key info, status was %d", status));
          return FALSE;
        }

      if (strcmp(type, "if-modn"))
        {
          SSH_DEBUG(0, ("error: invalid key type returned by the get "
                        "info function"));
          return FALSE;
        }

      if (ssh_mprz_bit_size(n) != size || size != info->size)
        {
          SSH_DEBUG(0, ("error: invalid key size returned from get "
                        "info function"));
          return FALSE;
        }

      if (ssh_mprz_is_probable_prime(n, 20) != 0)
        {
          SSH_DEBUG(0, ("error: invalid RSA key, n appears to be prime"));
          return FALSE;
        }

      /* Check that we can change the scheme */
      sig_name = enc_name = NULL;
      status =
        ssh_public_key_select_scheme(pub_key,
                                     SSH_PKF_SIGN, "rsa-pkcs1-sha1",
                                     SSH_PKF_ENCRYPT, "rsa-pkcs1-none",
                                     SSH_PKF_END);

      if (status != SSH_CRYPTO_OK)
        {
          SSH_DEBUG(0, ("error cannot set the public key scheme, "
                        "status was %d", status));
          return FALSE;
        }

      status = ssh_public_key_get_info(pub_key,
                                       SSH_PKF_SIGN, &sig_name,
                                       SSH_PKF_ENCRYPT, &enc_name,
                                       SSH_PKF_END);
      if (status != SSH_CRYPTO_OK)
        {
          SSH_DEBUG(0, ("error cannot get key info, status was %d", status));
          return FALSE;
        }

      if (strcmp(sig_name, "rsa-pkcs1-sha1"))
        {
          SSH_DEBUG(0, ("error: invalid signature scheme returned by the"
                        " get info function"));
          return FALSE;
        }
      if (strcmp(enc_name, "rsa-pkcs1-none"))
        {
          SSH_DEBUG(0, ("error: invalid encrypt scheme returned by "
                        "the get info function"));
          return FALSE;
        }

      /* Check we can reconstruct the public key from the MP Integers */
      if ((status = ssh_public_key_define(&pub_key_copy,
                                          type,
                                          SSH_PKF_PUBLIC_E, e,
                                          SSH_PKF_MODULO_N, n,
                                          SSH_PKF_SIGN, sig_name,
                                          SSH_PKF_ENCRYPT, enc_name,
                                          SSH_PKF_END)) != SSH_CRYPTO_OK)
        {
          SSH_DEBUG(0, ("error: define public key failed with status %d.",
                        status));
          return FALSE;
        }
      ssh_public_key_free(pub_key_copy);
    }

  /* DSA specific utility checks */
  if (strcmp(info->key_type, "dl-modp") == 0)
    {
      /* Get private key info */
      status = ssh_private_key_get_info(prv_key,
                                        SSH_PKF_KEY_TYPE, &type,
                                        SSH_PKF_SIGN, &name,
                                        SSH_PKF_SIZE, &size,
                                        SSH_PKF_PRIME_P, p,
                                        SSH_PKF_PRIME_Q, q,
                                        SSH_PKF_GENERATOR_G, g,
                                        SSH_PKF_SECRET_X, x,
                                        SSH_PKF_PUBLIC_Y, y,
                                        SSH_PKF_END);
      if (status != SSH_CRYPTO_OK)
        {
          SSH_DEBUG(0, ("error cannot get key info, status was %d", status));
          return FALSE;
        }

      if (strcmp(type, "dl-modp"))
        {
          SSH_DEBUG(0, ("error: invalid key type returned by the "
                        "get info function"));
          return FALSE;
        }

      if (ssh_mprz_bit_size(p) != size || size != info->size)
        {
          SSH_DEBUG(0, ("error: invalid key size returned from "
                        "get info function"));
          return FALSE;
        }

      if (ssh_mprz_is_probable_prime(p, 20) == 0)
        {
          SSH_DEBUG(0, ("error: invalid DSA key, p is not prime"));
          return FALSE;
        }

      if (ssh_mprz_is_probable_prime(q, 20) == 0)
        {
          SSH_DEBUG(0, ("error: invalid DSA key, q is not prime"));
          return FALSE;
        }

      /* Check that secret and public key components x and y are correctly
         related. */
      ssh_mprz_powm(aux, g, x, p);
      if (ssh_mprz_cmp(aux, y))
        {
          SSH_DEBUG(0, ("error: invalid DSA key, the public and private "
                        "exponents are incorrectly related."));
          return FALSE;
        }

      /* Check that g has order q mod p. */
      ssh_mprz_powm(aux, g, q, p);
      if (ssh_mprz_cmp_ui(aux, 1))
        {
          SSH_DEBUG(0, ("error: invalid DSA key, the generator not have order"
                        " q mod p"));
          return FALSE;
        }

      /* Check that we can change the scheme */
      sig_name = enc_name = NULL;
      status =
        ssh_private_key_select_scheme(prv_key,
                                      SSH_PKF_SIGN, "dsa-nist-sha1",
                                      SSH_PKF_END);

      if (status != SSH_CRYPTO_OK)
        {
          SSH_DEBUG(0, ("error cannot set the private key scheme, "
                        " status was %d", status));
          return FALSE;
        }

      status = ssh_private_key_get_info(prv_key,
                                        SSH_PKF_SIGN, &sig_name,
                                        SSH_PKF_END);
      if (status != SSH_CRYPTO_OK)
        {
          SSH_DEBUG(0, ("error cannot get key info, status was %d", status));
          return FALSE;
        }

      if (strcmp(sig_name, "dsa-nist-sha1"))
        {
          SSH_DEBUG(0, ("error: invalid signature scheme returned "
                        "by the get info  function"));
          return FALSE;
        }

      /* Check we can reconstruct the private key from the MP Integers */
      if ((status = ssh_private_key_define(&prv_key_copy,
                                           type,
                                           SSH_PKF_SECRET_X, x,
                                           SSH_PKF_PUBLIC_Y, y,
                                           SSH_PKF_PRIME_P, p,
                                           SSH_PKF_PRIME_Q, q,
                                           SSH_PKF_GENERATOR_G, g,
                                           SSH_PKF_SIGN, sig_name,
                                           SSH_PKF_END)) != SSH_CRYPTO_OK)
        {
          SSH_DEBUG(0, ("error: define private key failed with status %d.",
                        status));
          return FALSE;
        }
      ssh_private_key_free(prv_key_copy);

      /* Get public key info */
      status = ssh_public_key_get_info(pub_key,
                                       SSH_PKF_KEY_TYPE, &type,
                                       SSH_PKF_SIGN, &name,
                                       SSH_PKF_SIZE, &size,
                                       SSH_PKF_PRIME_P, p,
                                       SSH_PKF_PRIME_Q, q,
                                       SSH_PKF_GENERATOR_G, g,
                                       SSH_PKF_PUBLIC_Y, y,
                                       SSH_PKF_END);
      if (status != SSH_CRYPTO_OK)
        {
          SSH_DEBUG(0, ("error cannot get key info, status was %d", status));
          return FALSE;
        }

      if (strcmp(type, "dl-modp"))
        {
          SSH_DEBUG(0, ("error: invalid key type returned by the "
                        "get info function"));
          return FALSE;
        }

      if (ssh_mprz_bit_size(p) != size || size != info->size)
        {
          SSH_DEBUG(0, ("error: invalid key size returned from "
                        "get info function"));
          return FALSE;
        }

      if (ssh_mprz_is_probable_prime(p, 20) == 0)
        {
          SSH_DEBUG(0, ("error: invalid DSA key, p is not prime"));
          return FALSE;
        }

      if (ssh_mprz_is_probable_prime(q, 20) == 0)
        {
          SSH_DEBUG(0, ("error: invalid DSA key, q is not prime"));
          return FALSE;
        }

      /* Check that g has order q mod p. */
      ssh_mprz_powm(aux, g, q, p);
      if (ssh_mprz_cmp_ui(aux, 1))
        {
          SSH_DEBUG(0, ("error: invalid DSA key, the generator not have order"
                        " q mod p"));
          return FALSE;
        }

      /* Check that we can change the scheme */
      sig_name = enc_name = NULL;

      status =
        ssh_public_key_select_scheme(pub_key,
                                     SSH_PKF_SIGN, "dsa-nist-sha1",
                                     SSH_PKF_END);

      if (status != SSH_CRYPTO_OK)
        {
          SSH_DEBUG(0, ("error cannot set the private key scheme, "
                        "status was %d", status));
          return FALSE;
        }

      status = ssh_public_key_get_info(pub_key,
                                       SSH_PKF_SIGN, &sig_name,
                                       SSH_PKF_END);
      if (status != SSH_CRYPTO_OK)
        {
          SSH_DEBUG(0, ("error cannot get key info, status was %d", status));
          return FALSE;
        }

      if (strcmp(sig_name, "dsa-nist-sha1"))
        {
          SSH_DEBUG(0, ("error: invalid signature scheme returned by "
                        "the get info function"));
          return FALSE;
        }

      /* Check we can reconstruct the public key from the MP Integers */
      if ((status = ssh_public_key_define(&pub_key_copy,
                                          type,
                                          SSH_PKF_PUBLIC_Y, y,
                                          SSH_PKF_PRIME_P, p,
                                          SSH_PKF_PRIME_Q, q,
                                          SSH_PKF_GENERATOR_G, g,
                                          SSH_PKF_SIGN, sig_name,
                                          SSH_PKF_END)) != SSH_CRYPTO_OK)
        {
          SSH_DEBUG(0, ("error: define public key failed with status %d.",
                        status));
          return FALSE;
        }
      ssh_public_key_free(pub_key_copy);
    }

#ifdef SSHDIST_CRYPT_ECP



#endif /* SSHDIST_CRYPT_ECP */

  /* Free the keys */
  ssh_private_key_free(prv_key);
  ssh_public_key_free(pub_key);

  /* Test the naming of keys is ok */
  if (ssh_rand() & 0x1)
    key_name = "if-modn";
  else
    key_name = "if-modn{encrypt{rsa-pkcs1-none}}";

  if ((status = ssh_private_key_generate(&prv_key,
                                         key_name,
                                         SSH_PKF_SIZE, 1534,
                                         SSH_PKF_SIGN, "rsa-pkcs1-sha1",
                                         SSH_PKF_ENCRYPT, "rsa-pkcs1-none",
                                         SSH_PKF_END)) != SSH_CRYPTO_OK)
    {
      SSH_DEBUG(0, ("error: pkcs generate keys failed with status %d.",
                    status));
      return FALSE;
    }

  if (ssh_private_key_derive_public_key(prv_key, &pub_key) != SSH_CRYPTO_OK)
    {
      SSH_DEBUG(0, ("error: public key derivation failed."));
      return FALSE;
    }

  /* Test ssh_private_key_name */
  name = ssh_private_key_name(prv_key);
  if (strcmp(name, "if-modn{sign{rsa-pkcs1-sha1},encrypt{rsa-pkcs1-none}}"))
    {
      SSH_DEBUG(0, ("ssh_private_key_name function is broken"));
      return FALSE;
    }
  ssh_free(name);

  /* Test ssh_public_key_name */
  name = ssh_public_key_name(pub_key);
  if (strcmp(name, "if-modn{sign{rsa-pkcs1-sha1},encrypt{rsa-pkcs1-none}}"))
    {
      SSH_DEBUG(0, ("ssh_public_key_name function is broken"));
      return FALSE;
    }

  ssh_free(name);

  ssh_mprz_free(p);
  ssh_mprz_free(q);
  ssh_mprz_free(n);
  ssh_mprz_free(d);
  ssh_mprz_free(e);
  ssh_mprz_free(u);
  ssh_mprz_free(g);
  ssh_mprz_free(x);
  ssh_mprz_free(y);
  ssh_mprz_free(aux);

  ssh_private_key_free(prv_key);
  ssh_public_key_free(pub_key);

  return TRUE;
}

Boolean
pkcs_tests_export_import(SshPrivateKey private_key,
                         SshPublicKey public_key, PkcsInfo *info)
{
  /* Test pointers. */
  SshPrivateKey import_prvkey;
  SshPublicKey import_pubkey;
  unsigned char *a, *b;
  size_t a_len, b_len;
  unsigned char *signature = NULL, *signature2;
  size_t signature_len = 0, signature_len_out;
  SshCryptoStatus status;
  const char *test_vector =
    "Twice as much of nothing happens.";

  /* Export and import tests. */

  /* Sign a bit of data with the generated key. After the key has
     been imported/exported, verify the signature with the new
     keys to see if import/export really work (the keys remain the
     same, not just return proper values) .*/

  if (info->sign)
    {
      signature_len = ssh_private_key_max_signature_output_len(private_key);
      signature = ssh_xmalloc(signature_len);
      ssh_private_key_sign(private_key,
                           (unsigned char *) test_vector, strlen(test_vector),
                           signature, signature_len, &signature_len_out);
      status = ssh_public_key_verify_signature(public_key,
					       signature, signature_len_out,
					       (unsigned char *) test_vector,
					       strlen(test_vector));
      
      if (status != SSH_CRYPTO_OK)
	{
	  SSH_DEBUG(0, ("error: can not verify signature for "
			"import/export test"));
	  return FALSE;
	}
    }

  if (ssh_pk_export(&a, &a_len,
                    SSH_PKF_PUBLIC_KEY, public_key,
                    SSH_PKF_END) != SSH_CRYPTO_OK)
    {
      SSH_DEBUG(0, ("error: public key %s export failed.", info->key_type));
      return FALSE;
    }

  SSH_DEBUG(2, ("Public key exported."));

  status = ssh_pk_import(a, a_len, NULL,
                         SSH_PKF_PUBLIC_KEY, &import_pubkey,
                         SSH_PKF_END);

  if (status != SSH_CRYPTO_OK)
    {
      SSH_DEBUG(0, ("error: public key %s import failed: %s",
                    info->key_type, ssh_crypto_status_message(status)));
      return FALSE;
    }

  SSH_DEBUG(2, ("Public key imported."));

  SSH_DEBUG(3, ("Exporting %s key with cipher %s (key len %d)",
                info->key_type,
                info->exportinfo->cipher, info->exportinfo->cipherkeylen));

  status = ssh_pk_export(&b, &b_len,
                         SSH_PKF_PRIVATE_KEY, private_key,
                         SSH_PKF_CIPHER_NAME, info->exportinfo->cipher,
                         SSH_PKF_CIPHER_KEY,
                                info->exportinfo->cipherkey,
                                info->exportinfo->cipherkeylen,
                         SSH_PKF_END);

  if (status != SSH_CRYPTO_OK)
    {
      SSH_DEBUG(0, ("error: private key %s export failed: %s (%d).",
                    info->key_type, ssh_crypto_status_message(status),
                    status));
      return FALSE;
    }

  SSH_DEBUG(2, ("Private key exported with passphrase."));

  if (ssh_pk_import(b, b_len, NULL,
                    SSH_PKF_PRIVATE_KEY, &import_prvkey,
                    SSH_PKF_CIPHER_KEY,
                        info->exportinfo->cipherkey,
                        info->exportinfo->cipherkeylen,
                    SSH_PKF_END) != SSH_CRYPTO_OK)
    {
      SSH_DEBUG(0, ("error: private key %s import failed.", info->key_type));
      return FALSE;
    }

  SSH_DEBUG(2, ("Private key imported with passphrase."));

  ssh_xfree(a);
  ssh_xfree(b);

  if (info->sign)
    {
      status = ssh_public_key_select_scheme(import_pubkey,
                                            SSH_PKF_SIGN, info->sign,
                                            SSH_PKF_END);

      if (status != SSH_CRYPTO_OK)
        {
          SSH_DEBUG(0, ("error: could not set signature scheme on "
                        "imported public key: %s",
                        ssh_crypto_status_message(status)));
          return FALSE;
        }

#if 0
      {
        const char *s1, *s2;


        ssh_private_key_get_info(private_key,
                                 SSH_PKF_SIGN, &s1, SSH_PKF_END);

        ssh_public_key_get_info(import_pubkey,
                                SSH_PKF_SIGN, &s2, SSH_PKF_END);

        SSH_DEBUG(0, ("private sign=%s public sign=%s", s1, s2));
      }
#endif

      status = ssh_public_key_verify_signature(import_pubkey,
					       signature, signature_len_out,
					       (unsigned char *) test_vector,
					       strlen(test_vector));
      if (status != SSH_CRYPTO_OK)
        {
          SSH_DEBUG(0, ("error: can not verify signature using "
                        "imported public key"));
          return FALSE;
        }

      status = ssh_private_key_select_scheme(import_prvkey,
                                             SSH_PKF_SIGN, info->sign,
                                             SSH_PKF_END);

      if (status != SSH_CRYPTO_OK)
        {
          SSH_DEBUG(0, ("error: could not set signature scheme on "
                        "imported private key: %s",
                        ssh_crypto_status_message(status)));
          return FALSE;
        }

      signature2 = ssh_xmalloc(signature_len);
      ssh_private_key_sign(import_prvkey,
                           (unsigned char *) test_vector,
                           strlen(test_vector),
                           signature2, signature_len, &signature_len_out);

      status = ssh_public_key_verify_signature(import_pubkey,
					       signature2, signature_len_out,
					       (unsigned char *) test_vector,
					       strlen(test_vector));
      if (status != SSH_CRYPTO_OK)
        {
          SSH_DEBUG(0, ("error: can not verify signature "
                        "made using imported private key with "
                        "imported public key"));
          return FALSE;
        }

      ssh_xfree(signature2);
      ssh_xfree(signature);
    }

  ssh_public_key_free(import_pubkey);
  ssh_private_key_free(import_prvkey);

  return TRUE;
}

Boolean pkcs_tests(Boolean do_speed_test)
{
  struct SshTimeMeasureRec tmit = SSH_TIME_MEASURE_INITIALIZER;
  int i, info_index, cnt, total;
  SshPrivateKey private_key;
  SshPublicKey  public_key;
  SshCryptoStatus status;

  /* Test pointers. */
  unsigned char *a, *b, *c;
  size_t a_len, b_len, c_len, len;

  /* Register a progress monitoring function. */
  ssh_crypto_library_register_progress_func(my_progress_func, NULL);

  cnt = 1; /* if do_speed_test is false, this is not modified */

  for (info_index = 0; pkcs_info[info_index].key_type; info_index++)
    {
      PkcsInfo *info = &pkcs_info[info_index];

      if (do_speed_test)
        tstart(&tmit, "generating key type = %s.", info->key_type);

      private_key = pkcs_make_prvkey(do_speed_test, info);

      if (do_speed_test)
        tstop(&tmit, "key type = %s generated.", info->key_type);

      if (private_key == NULL)
        {
          SSH_DEBUG(0, ("error: key generation failed."));
          return FALSE;
        }

      if (do_speed_test)
        tstart(&tmit, "deriving public key.");

      if (ssh_private_key_derive_public_key(private_key, &public_key)
          != SSH_CRYPTO_OK)
        {
          SSH_DEBUG(0, ("error: key generation failed."));
          return FALSE;
        }

      if (do_speed_test)
        tstop(&tmit, "public key derived.");

      if (public_key == NULL)
        {
          SSH_DEBUG(0, ("error: public key derivation failed."));
          return FALSE;
        }

      if (do_speed_test)
        tstart(&tmit, "utility tests.");
      pkcs_tests_utility(private_key, public_key, info);
      if (do_speed_test)
        tstop(&tmit, "utility tests finished.");

      if (do_speed_test)
        tstart(&tmit, "export/import tests.");
      pkcs_tests_export_import(private_key, public_key, info);
      if (do_speed_test)
        tstop(&tmit, "export/import tests finished.");

      if (do_speed_test)
        tstart(&tmit, "precomputation test (private key).");
      ssh_private_key_precompute(private_key);
      if (do_speed_test)
        tstop(&tmit, "precomputation test (private key).");

      if (do_speed_test)
        tstart(&tmit, "precomputation test (public key).");
      ssh_public_key_precompute(public_key);
      if (do_speed_test)
        tstop(&tmit, "precomputation test (public key).");

      /* Encryption tests. */

      a_len = ssh_public_key_max_encrypt_input_len(public_key);
      if (a_len != 0)
        {
          b_len = ssh_public_key_max_encrypt_output_len(public_key);

          if (a_len == -1)
            a_len = 1024;
          if (b_len == -1)
            b_len = a_len;

          a = ssh_xmalloc(a_len);
          b = ssh_xmalloc(b_len);

          for (i = 0; i < a_len; i++)
            {
                a[i] = i & 0xff;
            }

          if (do_speed_test)
            cnt = PKCS_CNT;
          total = 0;
        retry1:

          tstartn(&tmit, total, "encryption test.");

          for (i = 0; i < cnt; i++)
            {
              if (ssh_public_key_encrypt(public_key, a, a_len, b, b_len,
                                         &len) != SSH_CRYPTO_OK)
                {
                  SSH_DEBUG(0, ("error: pkcs %s encryption error.",
                                info->key_type));
                  return FALSE;
                }
            }

          if (do_speed_test && tstopn(&tmit, cnt, "encryption test."))
            {
              total += cnt;
              cnt    = (cnt + cnt/2);
              goto retry1;
            }

          if (len > b_len)
            {
              SSH_DEBUG(0, ("error: pkcs %s outputed ciphertext too long.",
                            info->key_type));
              return FALSE;
            }

          if (len > ssh_private_key_max_decrypt_input_len(private_key))
            {
              SSH_DEBUG(0, ("error: pkcs %s ciphertext length incompatible.",
                            info->key_type));
              return FALSE;
            }

          c_len = ssh_private_key_max_decrypt_output_len(private_key);
          if (c_len == -1)
            c_len = b_len;
          c = ssh_xmalloc(c_len);

          if (do_speed_test)
            cnt = PKCS_CNT;
          total = 0;

        retry2:

          if (do_speed_test)
            tstartn(&tmit, total, "decryption test.");

          for (i = 0; i < cnt; i++)
            {
              if (ssh_private_key_decrypt(private_key,
                                          b, b_len, c,
                                          c_len, &len) != SSH_CRYPTO_OK)
                {
                  SSH_DEBUG(0, ("error: pkcs %s decryption error.",
                                info->key_type));
                  return FALSE;
                }

            }

          if (do_speed_test && tstopn(&tmit, cnt, "decryption test."))
            {
              total += cnt;
              cnt    = (cnt + cnt/2);
              goto retry2;
            }

          if (len > c_len)
            {
              SSH_DEBUG(0, ("error: pkcs %s outputed plaintext too long.",
                            info->key_type));
              return FALSE;
            }

          if (len != a_len)
            {
              SSH_DEBUG(0, ("error: pkcs %s plaintext length incompatible.",
                            info->key_type));
              return FALSE;
            }

          c_len = len;

          for (i = 0; i < c_len; i++)
            {
              if (c[i] != a[i])
                {
                  {
                    SSH_DEBUG(0, ("error: pkcs %s decryption failed.",
                                  info->key_type));
                    return FALSE;
                  }
                }
            }

          ssh_xfree(a);
          ssh_xfree(b);
          ssh_xfree(c);
        }

      /* Signature tests. */

      /* Randomizers! */

      a_len = ssh_private_key_max_signature_input_len(private_key);
      if (a_len != 0)
        {
          b_len = ssh_private_key_max_signature_output_len(private_key);

          if (a_len == -1)
            a_len = 1024;
          if (b_len == -1)
            b_len = a_len;

          a = ssh_xmalloc(a_len);
          b = ssh_xmalloc(b_len);

          for (i = 0; i < a_len; i++)
            {
              a[i] = i & 0xf;
            }

          if (do_speed_test)
            cnt = PKCS_CNT;
          total = 0;

        retry3:

          if (do_speed_test)
            tstartn(&tmit, total, "signature test.");

          for (i = 0; i < cnt; i++)
            {
              if (ssh_private_key_sign(private_key, a, a_len,
                                       b, b_len, &len) != SSH_CRYPTO_OK)
                {
                  SSH_DEBUG(0, ("error: pkcs %s sign error.", info->key_type));
                  return FALSE;
                }
            }

          if (do_speed_test && tstopn(&tmit, cnt, "signature test."))
            {
              total += cnt;
              cnt    = (cnt + cnt/2);
              goto retry3;
            }

          if (len > b_len)
            {
              SSH_DEBUG(0, ("error: pkcs %s outputed signature too long.",
                            info->key_type));
              return FALSE;
            }

          if (do_speed_test)
            cnt = PKCS_CNT;
          total = 0;

        retry4:

          if (do_speed_test)
            tstartn(&tmit, total, "verification test.");

          for (i = 0; i < cnt; i++)
            {
              unsigned char *b_flip, random_byte;
              size_t pos;

              /* Verify the signature */
              status = ssh_public_key_verify_signature(public_key,
						       b, len,
						       a, a_len);
	      if (status != SSH_CRYPTO_OK)
                {
                  SSH_DEBUG(0, ("error: %s signature not correct.",
                                info->key_type));
                  return FALSE;
                }

              /* Randomly flip some bits in the signature and check it
                 does not verify correctly. */
              b_flip = ssh_xmemdup(b, len);
              pos = ssh_random_get_byte() % (len - 1);

              /* Get a non-zero random byte. */
              while (1)
                {
                  random_byte = ssh_random_get_byte();

                  if (random_byte)
                    break;

                  SSH_DEBUG(7, ("Got a zero random byte"));
                };

              b_flip[pos] ^= random_byte;

              status = ssh_public_key_verify_signature(public_key,
						       b_flip, len,
						       a, a_len);
	      if (status == SSH_CRYPTO_OK)
                {
                  SSH_DEBUG(0, ("error: invalid %s signature has been "
				"validated.", info->key_type));
                  ssh_xfree(b_flip);
                  return FALSE;
                }
              ssh_xfree(b_flip);
            }

          if (do_speed_test && tstopn(&tmit, cnt, "verification test."))
            {
              total += cnt;
              cnt    = (cnt + cnt/2);
              goto retry4;
            }

          ssh_xfree(a);
          ssh_xfree(b);
        }

      /* Free contexts. */

      ssh_public_key_free(public_key);
      ssh_private_key_free(private_key);
    }

  return TRUE;
}

Boolean pkcs_random_tests(Boolean do_speed_test)
{
  char *namelist = ssh_public_key_get_supported();
  const char *tmp_namelist = namelist;
  char *pkcs_name = NULL;
  int i, cnt;
  size_t len;
  int size = 1536;
  char *cipher_key = "151413121110090807060504030201000";
  char *cipher_name = "aes-cfb";
  size_t cipher_key_len = 16;

  /* Test pointers. */
  unsigned char *a, *b, *c;
  size_t a_len, b_len, c_len;
  struct SshTimeMeasureRec tmit = SSH_TIME_MEASURE_INITIALIZER;
  unsigned char *signature, *signature2;
  size_t signature_len, signature_len_out;
  const char *signature_method;
  SshPublicKey public_key;
  SshPrivateKey private_key;
  SshCryptoStatus status;

#if 0
  static int use_randomizers = 1;
  SshPkGroupDHSecret secret_one, secret_two;
  SshPkGroup pk_group_one, pk_group_two;
#endif

  /* Register a progress monitoring function. */
  ssh_crypto_library_register_progress_func(my_progress_func,
                                            NULL);

  cnt = 1; /* if do_speed_test is false, this is not modified */

  while ((pkcs_name = ssh_name_list_get_name(tmp_namelist)) != NULL)
    {
      /* Allocation of the private key. */

      SSH_DEBUG(1, ("Public key method %s in testing.", pkcs_name));

      if (do_speed_test)
        tstart(&tmit, "key generation (private).");

      if (memcmp(pkcs_name, "e", 1) == 0)
        {
          tmp_namelist = ssh_name_list_step_forward(tmp_namelist);
          ssh_free(pkcs_name);
          continue;
        }

      if (memcmp(pkcs_name, (const unsigned char *)"dl-", 3) == 0)
        {
          if (ssh_private_key_generate(&private_key,
                                       pkcs_name,
                                       SSH_PKF_SIZE, size,
                                       SSH_PKF_RANDOMIZER_ENTROPY, 160,
                                       SSH_PKF_END) != SSH_CRYPTO_OK)
            {
              SSH_DEBUG(0,
                        ("error: pkcs %s generate keys failed.", pkcs_name));
              return FALSE;
            }
        }
      else if (memcmp(pkcs_name, (const unsigned char *)"if-", 3) == 0)
        {
          if (ssh_private_key_generate(&private_key,
                                       pkcs_name,
                                       SSH_PKF_SIZE, size,
                                       SSH_PKF_END) != SSH_CRYPTO_OK)
            {
              SSH_DEBUG(0,
                        ("error: pkcs %s generate keys failed.", pkcs_name));
              return FALSE;
            }
        }
#ifdef SSHDIST_CRYPT_ECP
      else if (memcmp(pkcs_name, (const unsigned char *)"ec-modp", 7) == 0)
        {
          if (ssh_private_key_generate(&private_key,
                                       pkcs_name,
                                       SSH_PKF_PREDEFINED_GROUP,
                                       "ssh-ec-modp-curve-155bit-1",
                                       SSH_PKF_END) != SSH_CRYPTO_OK)
            {
              SSH_DEBUG(0,
                        ("error: pkcs %s generate keys failed.", pkcs_name));
              return FALSE;
            }
        }
#endif /* SSHDIST_CRYPT_ECP */
















      else
        {
          SSH_DEBUG(0, ("error: pkcs %s key type did not match.", pkcs_name));
          return FALSE;
        }

      if (do_speed_test)
        tstop(&tmit, "key generation (private).");

      if (do_speed_test)
        tstart(&tmit, "key derivation (public)");
      if (ssh_private_key_derive_public_key(private_key, &public_key)
          != SSH_CRYPTO_OK)
        {
          SSH_DEBUG(0, ("key derivation failed"));
          return FALSE;
        }
      if (do_speed_test)
        tstop(&tmit, "key derivation (public)");

      {
        char *type;
        size_t size;
        SshMPIntegerStruct p, q;

        ssh_mprz_init(&p);
        ssh_mprz_init(&q);

        status = ssh_private_key_get_info(private_key,
                                          SSH_PKF_KEY_TYPE, &type,
                                          SSH_PKF_SIZE, &size,
                                          SSH_PKF_PRIME_Q, &q,
                                          SSH_PKF_END);

        if (status != SSH_CRYPTO_OK)
          {
            SSH_DEBUG(0, ("Can not get private key info for `%s' type",
                          pkcs_name));
            return FALSE;
          }

        status = ssh_public_key_get_info(public_key,
                                         SSH_PKF_KEY_TYPE, &type,
                                         SSH_PKF_SIZE, &size,
                                         SSH_PKF_END);

        if (status != SSH_CRYPTO_OK)
          {
            SSH_DEBUG(0, ("can not get public key info"));
            return FALSE;
          }

        ssh_mprz_clear(&p);
        ssh_mprz_clear(&q);
      }


      /* Test different signature schemes */
      if (ssh_private_key_max_signature_input_len(private_key) != 0)
        {
          char *p, *q, *r;
          unsigned char *data_buf;
          size_t data_buf_len;

          p = pkcs_name;
          while ((p = strchr(p, '{')) != NULL)
            {
              if (strncmp(p - 4, "sign{", 5) == 0)
                break;
              p++;
            }

          if (p == NULL)
            {
              SSH_DEBUG(0, ("No signature algorithms found"));
              return FALSE;
            }

          r = strchr(p, '}');
          if (r == NULL)
            {
              SSH_DEBUG(0, ("Invalid name format no '}' found"));
              return FALSE;
            }

          p++;
          q = ssh_xmemdup(p, r - p);

          p = q;
          do {
            r = strchr(p, ',');
            if (r != NULL)
              *r++ = '\0';
            else
              r = NULL;

	    /* The rsa-pkcs1-implicit scheme cannot be used for
	       generating signatures only for signature verification, so we
	       skip this case. */
	    if (!strcmp(p, "rsa-pkcs1-implicit"))
	      goto next;

            status = ssh_public_key_select_scheme(public_key,
                                                  SSH_PKF_SIGN, p,
                                                  SSH_PKF_END);
            if (status != SSH_CRYPTO_OK)
              {
                SSH_DEBUG(0, ("ssh_public_key_select_scheme failed"));
                return FALSE;
              }

            status = ssh_private_key_select_scheme(private_key,
                                                   SSH_PKF_SIGN, p,
                                                   SSH_PKF_END);
            if (status != SSH_CRYPTO_OK)
              {
                SSH_DEBUG(0, ("ssh_private_key_select_scheme failed"));
                return FALSE;
              }

            signature_len =
              ssh_private_key_max_signature_output_len(private_key);
            signature = ssh_xmalloc(signature_len);
            data_buf_len =
              ssh_private_key_max_signature_input_len(private_key);
            if (data_buf_len == -1)
              data_buf_len = 1024;
            data_buf = ssh_xmalloc(data_buf_len);
            for (i = 0; i < data_buf_len; i++)
              data_buf[i] = ssh_random_get_byte();

            if (do_speed_test)
              tstart(&tmit, "sign & verify: %s", p);
            if (ssh_private_key_max_signature_input_len(private_key) != -1)
              {
                ssh_private_key_sign_digest(private_key,
                                            data_buf, data_buf_len,
                                            signature, signature_len,
                                            &signature_len_out);

                status = ssh_public_key_verify_signature_with_digest
		  (public_key, signature, signature_len_out,
		   data_buf, data_buf_len);

		if (status != SSH_CRYPTO_OK)
                  {
                    SSH_DEBUG(0, ("error: can not verify "
                                  "signature for scheme test"));
                    return FALSE;
                  }
              }
            else
              {
                ssh_private_key_sign(private_key,
                                     data_buf, data_buf_len,
                                     signature, signature_len,
                                     &signature_len_out);

                status = ssh_public_key_verify_signature(public_key,
							 signature,
							 signature_len_out,
							 data_buf,
							 data_buf_len);
		if (status != SSH_CRYPTO_OK)
                  {
                    SSH_DEBUG(0, ("error: can not verify "
                                  "signature for scheme test"));
                    return FALSE;
                  }
              }
            if (do_speed_test)
              tstop(&tmit, "sign & verify: %s", p);

            ssh_xfree(data_buf);
            ssh_xfree(signature);
	  next:
            p = r;
          } while (p);

          status = ssh_public_key_select_scheme(public_key,
                                                SSH_PKF_SIGN, q,
                                                SSH_PKF_END);
          if (status != SSH_CRYPTO_OK)
            {
              SSH_DEBUG(0, ("ssh_public_key_select_scheme failed"));
              return FALSE;
            }

          status = ssh_private_key_select_scheme(private_key,
                                                 SSH_PKF_SIGN, q,
                                                 SSH_PKF_END);
          if (status != SSH_CRYPTO_OK)
            {
              SSH_DEBUG(0, ("ssh_private_key_select_scheme failed"));
              return FALSE;
            }
          ssh_xfree(q);
        }

      /* Test different encryption schemes */
      if (ssh_private_key_max_decrypt_input_len(private_key) != 0)
        {
          char *p, *q, *r;
          SshCryptoStatus status;
          unsigned char *data_buf, *data_buf2, *encryption_buf;
          size_t data_buf_len, data_buf2_len, encryption_buf_len, return_val;

          p = pkcs_name;
          while ((p = strchr(p, '{')) != NULL)
            {
              if (strncmp(p - 7, "encrypt{", 8) == 0)
                break;
              p++;
            }

          if (p == NULL)
            {
              SSH_DEBUG(0, ("No encryption algorithms found"));
              return FALSE;
            }

          r = strchr(p, '}');
          if (r == NULL)
            {
              SSH_DEBUG(0, ("Invalid name format no '}' found"));
              return FALSE;
            }

          p++;
          q = ssh_xmemdup(p, r - p);

          p = q;
          do {
            r = strchr(p, ',');
            if (r != NULL)
              *r++ = '\0';
            else
              r = NULL;

            status = ssh_public_key_select_scheme(public_key,
                                                  SSH_PKF_ENCRYPT, p,
                                                  SSH_PKF_END);
            if (status != SSH_CRYPTO_OK)
              {
                SSH_DEBUG(0, ("ssh_public_key_select_scheme failed"));
                return FALSE;
              }

            status = ssh_private_key_select_scheme(private_key,
                                                   SSH_PKF_ENCRYPT, p,
                                                   SSH_PKF_END);
            if (status != SSH_CRYPTO_OK)
              {
                SSH_DEBUG(0, ("ssh_private_key_select_scheme failed"));
                return FALSE;
              }

            encryption_buf_len =
              ssh_public_key_max_encrypt_output_len(public_key);
            encryption_buf = ssh_xmalloc(encryption_buf_len);

            data_buf_len =
              ssh_public_key_max_encrypt_input_len(public_key);
            data_buf = ssh_xmalloc(data_buf_len);

            data_buf2_len =
              ssh_private_key_max_decrypt_output_len(private_key);
            data_buf2 = ssh_xmalloc(data_buf2_len);

            data_buf[0] = 0;
            for (i = 1; i < data_buf_len; i++)
              data_buf[i] = ssh_random_get_byte();

            if (do_speed_test)
              tstart(&tmit, "encrypt & decrypt (public): %s", p);
            status = ssh_public_key_encrypt(public_key,
                                            data_buf, data_buf_len,
                                            encryption_buf, encryption_buf_len,
                                            &return_val);
            if (status != SSH_CRYPTO_OK)
              {
                SSH_DEBUG(0, ("ssh_public_key_encrypt failed"));
                return FALSE;
              }
            if (return_val != encryption_buf_len)
              {
                SSH_DEBUG(0, ("Invalid length returned "
                              "from ssh_public_key_encrypt"));
                return FALSE;
              }

            status = ssh_private_key_decrypt(private_key,
                                             encryption_buf,
                                             encryption_buf_len,
                                             data_buf2,
                                             data_buf2_len,
                                             &return_val);
            if (do_speed_test)
              tstop(&tmit, "encrypt & decrypt (public): %s", p);

            if (status != SSH_CRYPTO_OK)
              {
                SSH_DEBUG(0, ("ssh_private_key_decrypt failed"));
                return FALSE;
              }
            if (return_val != data_buf_len)
              {
                SSH_DEBUG(0, ("Invalid return length from "
                              "ssh_private_key_decrypt"));
                return FALSE;
              }

            if (memcmp(data_buf, data_buf2, data_buf_len) != 0)
              {
                SSH_DEBUG(0, ("Encryption failed"));
                return FALSE;
              }

            ssh_xfree(data_buf);
            ssh_xfree(data_buf2);
            ssh_xfree(encryption_buf);
            p = r;
          } while (p);

          status = ssh_public_key_select_scheme(public_key,
                                                SSH_PKF_ENCRYPT, q,
                                                SSH_PKF_END);
          if (status != SSH_CRYPTO_OK)
            {
              SSH_DEBUG(0, ("ssh_public_key_select_scheme failed"));
              return FALSE;
            }

          status = ssh_private_key_select_scheme(private_key,
                                                 SSH_PKF_ENCRYPT, q,
                                                 SSH_PKF_END);
          if (status != SSH_CRYPTO_OK)
            {
              SSH_DEBUG(0, ("ssh_private_key_select_scheme failed"));
              return FALSE;
            }
          ssh_xfree(q);
        }


      /* Export and import tests. */

      /* Sign a bit of data with the generated key. After the key has
         been imported/exported, verify the signature with the new
         keys to see if import/export really work (the keys remain the
         same, not just return proper values) .*/

      signature_len = ssh_private_key_max_signature_output_len(private_key);
      signature = ssh_xmalloc(signature_len);
      ssh_private_key_get_info(private_key,
                               SSH_PKF_SIGN, &signature_method, SSH_PKF_END);
      ssh_private_key_sign(private_key,
                           (unsigned char *) cipher_key, cipher_key_len,
                           signature, signature_len, &signature_len_out);
      status = ssh_public_key_verify_signature(public_key,
					       signature, signature_len_out,
					       (unsigned char *) cipher_key,
					       cipher_key_len);
	if (status != SSH_CRYPTO_OK)
        {
          SSH_DEBUG(0, ("error: can not verify signature for "
                        "import/export test"));
          return FALSE;
        }


      if (ssh_pk_export(&a, &a_len,
                        SSH_PKF_PUBLIC_KEY, public_key,
                        SSH_PKF_END) != SSH_CRYPTO_OK)
        {
          SSH_DEBUG(0, ("error: public key %s export failed.", pkcs_name));
          return FALSE;
        }

      SSH_DEBUG(2, ("Public key exported."));

      if (ssh_pk_export(&b, &b_len,
                        SSH_PKF_PRIVATE_KEY, private_key,
                        SSH_PKF_CIPHER_NAME, cipher_name,
                        SSH_PKF_CIPHER_KEY, cipher_key, cipher_key_len,
                        SSH_PKF_END) != SSH_CRYPTO_OK)
        {
          SSH_DEBUG(0, ("error: private key %s export failed.", pkcs_name));
          return FALSE;
        }

      SSH_DEBUG(2, ("Private key exported with encryption."));

      ssh_public_key_free(public_key);
      ssh_private_key_free(private_key);

      if (ssh_pk_import(a, a_len, NULL,
                        SSH_PKF_PUBLIC_KEY, &public_key,
                        SSH_PKF_END) != SSH_CRYPTO_OK)
        {
          SSH_DEBUG(0, ("error: public key %s import failed.", pkcs_name));
          return FALSE;
        }

      SSH_DEBUG(2, ("Public key imported."));

      if (ssh_pk_import(b, b_len, NULL,
                        SSH_PKF_PRIVATE_KEY, &private_key,
                        SSH_PKF_CIPHER_KEY, cipher_key, cipher_key_len,
                        SSH_PKF_END) != SSH_CRYPTO_OK)
        {
          SSH_DEBUG(0, ("error: private key %s import failed.", pkcs_name));
          return FALSE;
        }

      SSH_DEBUG(2, ("Private key imported with passphrase."));

      ssh_xfree(a);
      ssh_xfree(b);

      ssh_public_key_select_scheme(public_key,
                                   SSH_PKF_SIGN, signature_method,
                                   SSH_PKF_END);
      status = ssh_public_key_verify_signature(public_key,
					       signature, signature_len_out,
					       (unsigned char *) cipher_key,
					       cipher_key_len);
      if (status != SSH_CRYPTO_OK)
        {
          SSH_DEBUG(0, ("error: can not verify signature using "
                        "imported public key"));
          return FALSE;
        }

      signature2 = ssh_xmalloc(signature_len);
      ssh_private_key_select_scheme(private_key,
                                   SSH_PKF_SIGN, signature_method,
                                   SSH_PKF_END);
      ssh_private_key_sign(private_key,
                           (unsigned char *) cipher_key, cipher_key_len,
                           signature2, signature_len, &signature_len_out);
      status = ssh_public_key_verify_signature(public_key,
					       signature2, signature_len_out,
					       (unsigned char *) cipher_key,
					       cipher_key_len);
	if (status != SSH_CRYPTO_OK)
        {
          SSH_DEBUG(0, ("error: can not verify signature made using "
                        "imported private key with imported public key"));
          return FALSE;
        }

      ssh_xfree(signature2);
      ssh_xfree(signature);


      /* Do precomputation. */

      if (do_speed_test)
        printf("  -- Precomputation tests.\n");
      SSH_DEBUG(2, ("Precomputation tests."));

      if (do_speed_test)
        tstart(&tmit, "precomputation (group 1)");
      ssh_private_key_precompute(private_key);
      ssh_public_key_precompute(public_key);
      if (do_speed_test)
        tstop(&tmit, "precomputation (group 1)");

      /* Encryption tests. */

      if (do_speed_test)
        printf("  -- Encryption tests.\n");
      SSH_DEBUG(2, ("Encryption tests."));

      a_len = ssh_public_key_max_encrypt_input_len(public_key);
      if (a_len != 0)
        {
          b_len = ssh_public_key_max_encrypt_output_len(public_key);

          if (a_len == -1)
            a_len = 1024;
          if (b_len == -1)
            b_len = a_len;

          a = ssh_xmalloc(a_len);
          b = ssh_xmalloc(b_len);

          for (i = 0; i < a_len; i++)
            {
              a[i] = i & 0xff;
            }

          if (do_speed_test)
            cnt = PKCS_CNT;

        retry1:

          if (do_speed_test)
            {
              ssh_time_measure_reset(&tmit);
              ssh_time_measure_start(&tmit);
            }

          for (i = 0; i < cnt; i++)
            {
              if (ssh_public_key_encrypt(public_key, a, a_len, b, b_len,
                                         &len) != SSH_CRYPTO_OK)
                {
                  SSH_DEBUG(0, ("error: pkcs %s encryption error.",
                                pkcs_name));
                  return FALSE;
                }
            }

          if (do_speed_test)
            {
              ssh_time_measure_stop(&tmit);

              if (ssh_time_measure_get(&tmit, SSH_TIME_GRANULARITY_SECOND)
                  <= TEST_TIME_MIN && cnt < 100000)
                {
                  if (ssh_time_measure_get(&tmit,
                                           SSH_TIME_GRANULARITY_MILLISECOND)
                      < 10)
                    cnt *= 128;
                  else
                    cnt = (int)
                      (cnt * TEST_TIME_OPTIMUM /
                       ssh_time_measure_get(
                                            &tmit,
                                            SSH_TIME_GRANULARITY_MILLISECOND));
                  SSH_DEBUG(2, ("  - %s encrypt was too fast, retrying...",
                                pkcs_name));
                  goto retry1;
                }

              if (ssh_time_measure_get(&tmit, SSH_TIME_GRANULARITY_SECOND)
                  >= TEST_TIME_MIN)
                printf("%s -- " TEST_FMT " times/sec ("
                       TEST_FMT " ms/encrypt).\n",
                       pkcs_name, ((double) cnt) /
                       ((double)
                        ssh_time_measure_get(&tmit,
                                             SSH_TIME_GRANULARITY_MICROSECOND)
                        / 1000000.0),
                       ((double)
                        ssh_time_measure_get(&tmit,
                                             SSH_TIME_GRANULARITY_MICROSECOND)
                        / 1000000.0) / (double) cnt * 1000);
              else
                printf("  - timing could not be performed for %s.\n",
                       pkcs_name);
            }

          SSH_DEBUG(2, ("Encrypted with public key."));

          if (len > b_len)
            {
              SSH_DEBUG(0, ("error: pkcs %s outputed ciphertext too long.",
                            pkcs_name));
              return FALSE;
            }

          if (len > ssh_private_key_max_decrypt_input_len(private_key))
            {
              SSH_DEBUG(0, ("error: pkcs %s ciphertext length incompatible.",
                            pkcs_name));
              return FALSE;
            }

          c_len = ssh_private_key_max_decrypt_output_len(private_key);
          if (c_len == -1)
            c_len = b_len;
          c = ssh_xmalloc(c_len);

          if (do_speed_test)
            cnt = PKCS_CNT;

        retry2:

          if (do_speed_test)
            {
              ssh_time_measure_reset(&tmit);
              ssh_time_measure_start(&tmit);
            }

          for (i = 0; i < cnt; i++)
            {
              if (ssh_private_key_decrypt(private_key,
                                          b, b_len, c,
                                          c_len, &len) != SSH_CRYPTO_OK)
                {
                  SSH_DEBUG(0, ("error: pkcs %s decryption error.",
                                pkcs_name));
                  return FALSE;
                }

            }

          if (do_speed_test)
            {
              ssh_time_measure_stop(&tmit);

              if (ssh_time_measure_get(&tmit, SSH_TIME_GRANULARITY_SECOND)
                  <= TEST_TIME_MIN && cnt < 100000)
                {
                  if (ssh_time_measure_get(&tmit,
                                           SSH_TIME_GRANULARITY_MILLISECOND)
                      < 10)
                    cnt *= 128;
                  else
                    cnt = (int)
                      (cnt * TEST_TIME_OPTIMUM /
                       ssh_time_measure_get(
                                            &tmit,
                                            SSH_TIME_GRANULARITY_MILLISECOND));
                  SSH_DEBUG(2, ("  - %s decrypt was too fast, retrying...",
                                pkcs_name));
                  goto retry2;
                }

              if (ssh_time_measure_get(&tmit, SSH_TIME_GRANULARITY_SECOND)
                  >= TEST_TIME_MIN)
                printf("%s -- " TEST_FMT " times/sec ("
                       TEST_FMT " ms/decrypt).\n",
                       pkcs_name, ((double)cnt) /
                       ((double)
                        ssh_time_measure_get(&tmit,
                                             SSH_TIME_GRANULARITY_MICROSECOND)
                        / 1000000.0),
                       ((double)
                        ssh_time_measure_get(&tmit,
                                             SSH_TIME_GRANULARITY_MICROSECOND)
                        / 1000000.0) / (double) cnt * 1000);
              else
                printf("  - timing could not be performed for %s.\n",
                       pkcs_name);
            }

          SSH_DEBUG(2, ("Decrypted with the private key."));

          if (len > c_len)
            {
              SSH_DEBUG(0, ("error: pkcs %s outputed plaintext too long.",
                            pkcs_name));
              return FALSE;
            }

          if (len != a_len)
            {
              SSH_DEBUG(0, ("error: pkcs %s plaintext length incompatible.",
                            pkcs_name));
              return FALSE;
            }

          ssh_xfree(b);
          ssh_xfree(a);

          c_len = len;

          for (i = 0; i < c_len; i++)
            {
              if (c[i] != (i & 0xff))
                {
                  {
                    SSH_DEBUG(0, ("error: pkcs %s decryption failed.",
                                  pkcs_name));
                    return FALSE;
                  }
                }
            }
          ssh_xfree(c);
        }
      else
        {
          SSH_DEBUG(1, ("Method not capable for encryption."));
        }

      /* Signature tests. */

      if (do_speed_test)
        printf("  -- Signature tests.\n");
      SSH_DEBUG(2, ("Signature tests."));

      /* Randomizers! */

      a_len = ssh_private_key_max_signature_input_len(private_key);
      if (a_len != 0)
        {
          b_len = ssh_private_key_max_signature_output_len(private_key);

          if (a_len == -1)
            a_len = 1024;
          if (b_len == -1)
            b_len = a_len;

          a = ssh_xmalloc(a_len);
          b = ssh_xmalloc(b_len);

          for (i = 0; i < a_len; i++)
            {
              a[i] = i & 0xf;
            }

          if (do_speed_test)
            cnt = PKCS_CNT;

        retry3:

          if (do_speed_test)
            {
              ssh_time_measure_reset(&tmit);
              ssh_time_measure_start(&tmit);
            }

          for (i = 0; i < cnt; i++)
            {
              if (ssh_private_key_sign(private_key, a, a_len,
                                       b, b_len, &len) != SSH_CRYPTO_OK)
                {
                  SSH_DEBUG(0, ("error: pkcs %s sign error.", pkcs_name));
                  return FALSE;
                }
            }

          if (do_speed_test)
            {
              ssh_time_measure_stop(&tmit);

              if (ssh_time_measure_get(&tmit, SSH_TIME_GRANULARITY_SECOND)
                  <= TEST_TIME_MIN && cnt < 100000)
                {
                  if (ssh_time_measure_get(&tmit,
                                           SSH_TIME_GRANULARITY_MILLISECOND)
                      < 10)
                    cnt *= 128;
                  else
                    cnt = (int)
                      (cnt * TEST_TIME_OPTIMUM /
                       ssh_time_measure_get(
                                            &tmit,
                                            SSH_TIME_GRANULARITY_MILLISECOND));
                  SSH_DEBUG(2, ("  - %s signing was too fast, retrying...",
                                pkcs_name));
                  goto retry3;
                }

              if (ssh_time_measure_get(&tmit, SSH_TIME_GRANULARITY_SECOND)
                  >= TEST_TIME_MIN)
                printf("%s -- " TEST_FMT " times/sec ("
                       TEST_FMT " ms/sign).\n",
                       pkcs_name,
                       ((double)cnt) /
                       ((double)
                        ssh_time_measure_get(&tmit,
                                             SSH_TIME_GRANULARITY_MICROSECOND)
                        / 1000000.0),
                       ((double)
                        ssh_time_measure_get(&tmit,
                                             SSH_TIME_GRANULARITY_MICROSECOND)
                        / 1000000.0) / (double) cnt * 1000);
              else
                printf("  - timing could not be performed for %s.\n",
                       pkcs_name);
            }

          SSH_DEBUG(2, ("Signed with the private key."));

          if (len > b_len)
            {
              SSH_DEBUG(0, ("error: pkcs %s outputed signature too long.",
                            pkcs_name));
              return FALSE;
            }

          if (do_speed_test)
            cnt = PKCS_CNT;

        retry4:

          if (do_speed_test)
            {
              ssh_time_measure_reset(&tmit);
              ssh_time_measure_start(&tmit);
            }

          for (i = 0; i < cnt; i++)
            {
	      status = ssh_public_key_verify_signature(public_key,
						       b, len,
						       a, a_len);
	      if (status != SSH_CRYPTO_OK)
                {
                  SSH_DEBUG(0, ("error: %s signature not correct.",
                                pkcs_name));
                  return FALSE;
                }
            }

          if (do_speed_test)
            {
              ssh_time_measure_stop(&tmit);

              if (ssh_time_measure_get(&tmit, SSH_TIME_GRANULARITY_SECOND)
                  <= TEST_TIME_MIN && cnt < 100000)
                {
                  if (ssh_time_measure_get(&tmit,
                                           SSH_TIME_GRANULARITY_MILLISECOND)
                      < 10)
                    cnt *= 128;
                  else
                    cnt = (int)
                      (cnt * TEST_TIME_OPTIMUM /
                       ssh_time_measure_get(
                                            &tmit,
                                            SSH_TIME_GRANULARITY_MILLISECOND));
                  SSH_DEBUG(2, ("  - %s signing verifying was too fast, "
                                "retrying...",
                                pkcs_name));
                  goto retry4;
                }

              if (ssh_time_measure_get(&tmit, SSH_TIME_GRANULARITY_SECOND)
                  >= TEST_TIME_MIN)
                printf("%s -- " TEST_FMT " times/sec ("
                       TEST_FMT " ms/verify).\n",
                       pkcs_name, ((double)cnt) /
                       ((double)
                        ssh_time_measure_get(&tmit,
                                             SSH_TIME_GRANULARITY_MICROSECOND)
                        / 1000000.0),
                       ((double)
                        ssh_time_measure_get(&tmit,
                                             SSH_TIME_GRANULARITY_MICROSECOND)
                        / 1000000.0) / (double) cnt * 1000);
              else
                printf("  - timing could not be performed for %s.\n",
                       pkcs_name);
            }

          SSH_DEBUG(2, ("Verified with the public key."));

          ssh_xfree(a);
          ssh_xfree(b);
        }
      else
        SSH_DEBUG(2, ("Method not capable of signing."));

#if 0
      if (ssh_public_key_derive_pk_group(public_key, &pk_group_one)
          != SSH_CRYPTO_OK)
        pk_group_one = pk_group_two = NULL;
      else if (ssh_private_key_derive_pk_group(private_key, &pk_group_two)
               != SSH_CRYPTO_OK)
        {
          ssh_pk_group_free(pk_group_one);
          pk_group_one = pk_group_two = NULL;
        }

      if (pk_group_one && pk_group_two)
        {
          SSH_DEBUG(2, ("Derived groups."));

          a_len =
            ssh_pk_group_dh_setup_max_output_length(pk_group_one);
          b_len =
            ssh_pk_group_dh_setup_max_output_length(pk_group_two);

          /* Not capable for diffie hellman. */
          if (a_len == 0 || b_len == 0)
            {
              SSH_DEBUG(1,
                        ("Method `%s' not capable of performing "
                         "Diffie-Hellman.", pkcs_name));
              goto end_dh;
            }

          a = ssh_xmalloc(a_len);
          b = ssh_xmalloc(b_len);

          c_len =
            ssh_pk_group_dh_agree_max_output_length(pk_group_one);
          d_len =
            ssh_pk_group_dh_agree_max_output_length(pk_group_two);

          if (c_len == 0 || d_len == 0)
            {
              SSH_DEBUG(0, ("error: could not continue to agree."));
              return FALSE;
            }

          c = ssh_xmalloc(c_len);
          d = ssh_xmalloc(d_len);

          secret_one = NULL;


          if (ssh_pk_group_dh_setup(pk_group_two,
                                    &secret_two,
                                    b, b_len,
                                    &len) != SSH_CRYPTO_OK)
            {
              SSH_DEBUG(0, ("error: could not do Diffie-Hellman setup. (2)"));
              return FALSE;
            }

          if (do_speed_test)
            cnt = 10;

        retry_dh1:

          if (do_speed_test)
            {
              ssh_time_measure_reset(&tmit);
              ssh_time_measure_start(&tmit);
            }

          for (i = 0; i < cnt; i++)
            {
              if (ssh_pk_group_dh_setup(pk_group_one,
                                        &secret_one,
                                        a, a_len,
                                        &len) != SSH_CRYPTO_OK)
                {
                  SSH_DEBUG(0, ("error: could not do "
                                "Diffie-Hellman setup. (1)"));
                  return FALSE;
                }

              if (len != a_len)
                {
                  SSH_DEBUG(0, ("error: len != a_len!"));
                  return FALSE;
                }

              if (ssh_pk_group_dh_agree(pk_group_one,
                                        secret_one,
                                        b, b_len,
                                        c, c_len,
                                        &len) != SSH_CRYPTO_OK)
                {
                  SSH_DEBUG(0, ("error: could not do "
                                "Diffie-Hellman agree. (1)"));
                  return FALSE;
                }

              if (len != c_len)
                {
                  SSH_DEBUG(0, ("error: minor detail.\n"));
                  return FALSE;
                }
            }

          if (do_speed_test)
            {
              ssh_time_measure_stop(&tmit);

              if (ssh_time_measure_get(&tmit, SSH_TIME_GRANULARITY_SECOND)
                  <= TEST_TIME_MIN && cnt < 100000)
                {
                  if (ssh_time_measure_get(&tmit,
                                           SSH_TIME_GRANULARITY_MILLISECOND)
                      < 10)
                    cnt *= 128;
                  else
                    cnt = (int)
                      (cnt * TEST_TIME_OPTIMUM /
                       ssh_time_measure_get(&tmit,
                                            SSH_TIME_GRANULARITY_MILLISECOND));
                  SSH_DEBUG(2, ("  - %s dh setup was too fast, retrying...",
                                pkcs_name));
                  goto retry_dh1;
                }

              if (ssh_time_measure_get(&tmit, SSH_TIME_GRANULARITY_SECOND)
                  >= TEST_TIME_MIN)
                printf("%s -- " TEST_FMT " times/s ("
                       TEST_FMT " ms/dh setup).\n",
                       pkcs_name,
                       ((double)cnt) /
                       ((double)
                        ssh_time_measure_get(&tmit,
                                             SSH_TIME_GRANULARITY_MICROSECOND)
                        / 1000000.0),
                       ((double)
                        ssh_time_measure_get(&tmit,
                                             SSH_TIME_GRANULARITY_MICROSECOND)
                        / 1000000.0) / (double) cnt * 1000);
              else
                printf("  - timing could not be performed for %s.\n",
                       pkcs_name);
            }


          if (ssh_pk_group_dh_agree(pk_group_two, secret_two,
                                    a, a_len,
                                    d, d_len,
                                    &len) != SSH_CRYPTO_OK)
            {
              SSH_DEBUG(0, ("error: could not do Diffie-Hellman agree. (2)"));
              return FALSE;
            }

          if (d_len != len)
            {
              SSH_DEBUG(0, ("error: minor detail.\n"));
              return FALSE;
            }

          if (d_len != c_len)
            {
              SSH_DEBUG(0, ("error: not correct agreement.\n"));
              return FALSE;
            }

          if (memcmp(d, c, d_len) != 0)
            {
              SSH_DEBUG(0, ("error: incorrect result.\n"));
              return FALSE;
            }

          SSH_DEBUG(2, ("Diffie-Hellman key agreement was a success."));
          ssh_xfree(a);
          ssh_xfree(b);
          ssh_xfree(c);
          ssh_xfree(d);

          ssh_pk_group_free(pk_group_one);
          ssh_pk_group_free(pk_group_two);

        end_dh:
          ;                     /* OSF cc cannot compile this file if this
                                   empty statement is not here. */
        }
      else
        SSH_DEBUG(2, ("Method not capable of extracting groups."));
#endif


      /* Free contexts. */

      ssh_public_key_free(public_key);
      ssh_private_key_free(private_key);

      ssh_xfree(pkcs_name);
      tmp_namelist = ssh_name_list_step_forward(tmp_namelist);
    }

  /* Remove progress monitoring functions from use. */
  ssh_crypto_library_register_progress_func(NULL_FNPTR, NULL);

  ssh_xfree(namelist);

  return TRUE;
}
#ifdef SSHDIST_CRYPT_GENPKCS_DH
#define RANDOMIZERS_CALLS 1000

/* This function runs some basic tests on the Diffie-Hellman
   predefined groups. The Diffie-Hellman computations tests are found
   in t-dh.c. Only testing dl-modp groups. Elliptic curves groups can
   be tested later. */
Boolean predefined_groups_tests(void)
{
  char *namelist;
  const char *tmp_namelist;
  SshPkGroup group, group_copy;
  SshPkGroupDHSecret secret;
  SshMPIntegerStruct p, q, g, aux;
  char *group_name = NULL, *dh_name;
  /* Test pointers. */
  unsigned char *a, *buf;
  size_t a_len, ret_len, buf_len;
  int i, status, size;
  char *type;
  int ent, entropy, randomizers;

  tmp_namelist = namelist = ssh_public_key_get_predefined_groups("dl-modp");

  /* Register a progress monitoring function. */
  ssh_crypto_library_register_progress_func(my_progress_func,
                                            NULL);

  ssh_mprz_init(&p);
  ssh_mprz_init(&q);
  ssh_mprz_init(&g);
  ssh_mprz_init(&aux);

  while ((group_name = ssh_name_list_get_name(tmp_namelist)) != NULL)
    {
      SSH_DEBUG(1, ("Testing predefined group %s.", group_name));

      /* Allocation of the predefined group. */
      {
        /* Put the randomizer entropy to 200. */
        ent = 200;
        status = ssh_pk_group_generate(&group, "dl-modp{dh}",
                                       SSH_PKF_PREDEFINED_GROUP, group_name,
                                       SSH_PKF_RANDOMIZER_ENTROPY, ent,
                                       SSH_PKF_END);

        if (status != SSH_CRYPTO_OK)
          {
            SSH_DEBUG(0, ("Can not generate the group %s.", group_name));
            return FALSE;
          }

        status = ssh_pk_group_get_info(group,
                                       SSH_PKF_KEY_TYPE, &type,
                                       SSH_PKF_SIZE, &size,
                                       SSH_PKF_PRIME_Q, &q,
                                       SSH_PKF_PRIME_P, &p,
                                       SSH_PKF_GENERATOR_G, &g,
                                       SSH_PKF_DH, &dh_name,
                                       SSH_PKF_RANDOMIZER_ENTROPY, &entropy,
                                       SSH_PKF_END);

        if (status != SSH_CRYPTO_OK)
          {
            SSH_DEBUG(0, ("can not get the group info"));
            return FALSE;
          }

        if (dh_name && strcmp(dh_name, "plain"))
          {
            SSH_DEBUG(0, ("error in the Diffie-Hellman scheme name "));
	    return FALSE;
          }

        if (group == NULL)
          {
            SSH_DEBUG(0, ("the generated group is NULL"));
            return FALSE;
          }
        if (size == 0)
          {
            SSH_DEBUG(0, ("the group has zero elements"));
            return FALSE;
          }
      }

      /* Check the group parameters are sensible */
      if (ssh_mprz_is_probable_prime(&p, 20) == 0)
        {
          SSH_DEBUG(0, ("error: invalid DH group, p is not prime"));
          return FALSE;
        }

      if (ssh_mprz_is_probable_prime(&q, 20) == 0)
        {
          SSH_DEBUG(0, ("error: invalid DH group, q is not prime"));
          return FALSE;
        }

      /* Check that g has order q mod p. */
      ssh_mprz_powm(&aux, &g, &q, &p);
      if (ssh_mprz_cmp_ui(&aux, 1))
        {
          SSH_DEBUG(0, ("error: invalid DH group, the generator "
                        "not have order q mod p"));
          return FALSE;
        }

      /* Check that we can change the scheme */
      status =
        ssh_pk_group_select_scheme(group,
                                   SSH_PKF_DH, "plain",
                                   SSH_PKF_END);

      if (status != SSH_CRYPTO_OK)
        {
          SSH_DEBUG(0, ("error cannot set the Diffie-Hellman scheme, "
                        "status was %d", status));
          return FALSE;
        }

      status = ssh_pk_group_get_info(group,
                                     SSH_PKF_DH, &dh_name,
                                     SSH_PKF_END);
      if (status != SSH_CRYPTO_OK)
        {
          SSH_DEBUG(0, ("error cannot get group info, status was %d", status));
          return FALSE;
        }

      if (strcmp(dh_name, "plain"))
        {
          SSH_DEBUG(0, ("error: invalid DH scheme returned by the get info "
                        " function"));
          return FALSE;
        }

      /* Check we can reconstruct the group from the MP Integers */
      if ((status = ssh_pk_group_generate(&group_copy,
                                          type,
                                          SSH_PKF_PRIME_P, &p,
                                          SSH_PKF_PRIME_Q, &q,
                                          SSH_PKF_GENERATOR_G, &g,
                                          SSH_PKF_RANDOMIZER_ENTROPY, entropy,
                                          SSH_PKF_DH, dh_name,
                                          SSH_PKF_END)) != SSH_CRYPTO_OK)
        {
          SSH_DEBUG(0, ("error: generate pk group failed with status %d.",
                        status));
          return FALSE;
        }
      ssh_pk_group_free(group_copy);

      /* Randomizers. */
      SSH_DEBUG(2, ("Generating randomizers."));
      for (i = 0; i < RANDOMIZERS_CALLS; i++)
        {
          status = ssh_pk_group_generate_randomizer(group);
          if (status != SSH_CRYPTO_OK)
            {
              SSH_DEBUG(0, ("Cannot generate randomizers"));
              return FALSE;
            }
        }

      randomizers = ssh_pk_group_count_randomizers(group);
      SSH_DEBUG(1, ("generated %d randomizers with %d calls to "
		    "ssh_pk_group_generate_randomizer()",
		    randomizers, RANDOMIZERS_CALLS));

      /* Use one of the randomizers */
      buf_len = ssh_pk_group_dh_setup_max_output_length(group);
      buf = ssh_xmalloc(buf_len);

      status = ssh_pk_group_dh_setup(group, &secret,
				     buf, buf_len, &ret_len);

      if (status != SSH_CRYPTO_OK)
	{
	  SSH_DEBUG(0, ("DH Setup failed with status %s",
			ssh_crypto_status_message(status)));
	  return FALSE;
	}

      /* Check the randomizers count has decremented */
      if (ssh_pk_group_count_randomizers(group) != randomizers - 1)
	{
	  SSH_DEBUG(0, ("error: generated incorrect amount of randomizers. %d",
			ssh_pk_group_count_randomizers(group)));
	  return FALSE;
	}

      SSH_DEBUG(2, ("Returning randomizer to the group"));

      /* Return the randomizer to the group */
      ssh_pk_group_dh_return_randomizer(group, secret, buf, ret_len);

      ssh_xfree(buf);

      /* Check the randomizers count has incremented */
      if (ssh_pk_group_count_randomizers(group) != randomizers)
	{
	  SSH_DEBUG(0, ("error: generated incorrect amount of randomizers. %d",
			ssh_pk_group_count_randomizers(group)));
	  return FALSE;
	}

      SSH_DEBUG(2, ("Exporting randomizers."));

      if (ssh_pk_export(&a, &a_len,
                        SSH_PKF_PK_GROUP_RANDOMIZERS, group,
                        SSH_PKF_END) != SSH_CRYPTO_OK)
        {
          SSH_DEBUG(0, ("error: cannot export randomizers."));
          return FALSE;
        }

      if (ssh_pk_group_count_randomizers(group) != 0)
	{
	  SSH_DEBUG(0,
		    ("error: generated incorrect amount of randomizers. %d",
		     ssh_pk_group_count_randomizers(group)));
	  return FALSE;
	}


      SSH_DEBUG(2, ("Importing randomizers."));

      if (ssh_pk_import(a, a_len, NULL,
                        SSH_PKF_PK_GROUP_RANDOMIZERS, group,
                        SSH_PKF_END) != SSH_CRYPTO_OK)
        {
          SSH_DEBUG(0, ("error: cannot import randomizers."));
          return FALSE;
        }
      ssh_xfree(a);

      if (ssh_pk_group_count_randomizers(group) != randomizers)
	{
	  SSH_DEBUG(0,
		    ("error: generated incorrect amount of randomizers. %d",
		     ssh_pk_group_count_randomizers(group)));
	  return FALSE;
	}

      SSH_DEBUG(2, ("Randomizer test succeeded."));

      SSH_DEBUG(2, ("Testing the group import/export. "));

      if (ssh_pk_export(&a, &a_len,
                        SSH_PKF_PK_GROUP, group,
                        SSH_PKF_END) != SSH_CRYPTO_OK)
        {
          SSH_DEBUG(0, ("error: cannot export public key group."));
          return FALSE;
        }

      ssh_pk_group_free(group);

      if (ssh_pk_import(a, a_len, NULL,
                        SSH_PKF_PK_GROUP, &group,
                        SSH_PKF_END) != SSH_CRYPTO_OK)
        {
          SSH_DEBUG(0, ("error: cannot import public key group."));
          return FALSE;
        }

      ssh_xfree(a);
      SSH_DEBUG(2, ("Import/export test succeeded."));

      /* Do precomputation. */
      SSH_DEBUG(2, ("Precomputation tests."));

      status = ssh_pk_group_precompute(group);

      if (status != SSH_CRYPTO_OK)
        {
          printf("status is %d\n" , status);
          {
            SSH_DEBUG(0, ("Error in precomputation"));
            return FALSE;
          }
        }
      SSH_DEBUG(2, ("Precomputation test succeeded."));

      /* Diffie-Hellman tests are done in t-dh.c, here just check we
         can set the scheme. */

      status = ssh_pk_group_select_scheme(group, SSH_PKF_DH, "plain",
                                          SSH_PKF_END);
      if (status != SSH_CRYPTO_OK)
        {
          SSH_DEBUG(0, ("Cannot set the scheme"));
          return FALSE;
        }

      ssh_pk_group_free(group);
      ssh_xfree(group_name);
      tmp_namelist = ssh_name_list_step_forward(tmp_namelist);

      /* The IKE 3072, 4096 and 8192 groups are too slow, not
         really necessary to test anyway, since nobody should
         consider using them at present. */
      if (size >= 2048)
        break;
    }

  ssh_mprz_clear(&p);
  ssh_mprz_clear(&q);
  ssh_mprz_clear(&g);
  ssh_mprz_clear(&aux);

  /* Remove progress monitoring functions from use. */
  ssh_crypto_library_register_progress_func(NULL_FNPTR, NULL);

  ssh_free(namelist);

  return TRUE;
}
#endif /* SSHDIST_CRYPT_GENPKCS_DH */
