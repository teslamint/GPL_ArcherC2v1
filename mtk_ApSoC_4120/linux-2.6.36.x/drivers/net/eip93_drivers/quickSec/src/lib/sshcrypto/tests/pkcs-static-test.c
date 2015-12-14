/*

  pkcs-static-test.c

  Authors: Santeri Paavolainen <santtu@ssh.com>

  Copyright:
          Copyright (c) 2002, 2003 SFNT Finland Oy.
  All rights reserved.

  This file contains static ("known-result") regression tests for PKCS.

  Notice: Since most encryption/signature methods use random padding,
  we replace the default rng with a 'pool' version, which will be
  filled with known (from another rng) bytes. Thus we can store the
  used rng data as part of the test suite, and feed the same data back
  during regression tests.

  This of course means that if implementation of the pk routines are
  changed so that they use rng values in different order, they will
  fail this suite... so failure from this test indicate something
  might be broken, but it needs to be separately verified whether test
  failure was due to a bug or just functional-equivalent changes.

*/

#include "sshincludes.h"
#include "sshcrypt.h"
#include "sshmp.h"
#include "sshgenmp.h"
#include "sshdsprintf.h"
#include "sshtimemeasure.h"
#include "t-gentest.h"
#include "sshcrypt_i.h" /* We need ssh_crypto_set_default_rng */
#include "sshrandom_i.h" /* ssh_random_pool_get_length */
#include "parser.h"
#include "sshrgf.h"
#ifdef SSHDIST_CRYPT_ECP
#include "ecpfix.h"
#endif /* SSHDIST_CRYPT_ECP */

#define SSH_DEBUG_MODULE "GenTestPkcs"

/* Top the fake RNG to this size at reset */
#define NOMINAL_FAKE_RNG_LEN 10240
static SshRandom true_rng, fake_rng;

typedef struct PkcsPkKeyDataRec {
  const char *name;
  enum {
    PKF_SINGLE,
    PKF_DOUBLE
  } type;
  SshPkFormat pkf;
  /* The index has to match the indexes used in mp table index in
     pkcs_static_tests function, at ssh_{private,public}_key_defines
     for each pk type */
  int index;
} *PkcsPkKeyData, PkcsPkKeyDataStruct;

static PkcsPkKeyDataStruct if_modn_private_mp[] =  {
  { "p", PKF_SINGLE, SSH_PKF_PRIME_P, 0 },
  { "q", PKF_SINGLE, SSH_PKF_PRIME_Q, 1 },
  { "n", PKF_SINGLE, SSH_PKF_MODULO_N, 2 },
  { "e", PKF_SINGLE, SSH_PKF_PUBLIC_E, 3 },
  { "u", PKF_SINGLE, SSH_PKF_INVERSE_U, 4 },
  { "d", PKF_SINGLE, SSH_PKF_SECRET_D, 5 },
  { NULL }
};

static PkcsPkKeyDataStruct if_modn_public_mp[] =  {
  { "n", PKF_SINGLE, SSH_PKF_MODULO_N, 0 },
  { "e", PKF_SINGLE, SSH_PKF_PUBLIC_E, 1 },
  { NULL }
};

static PkcsPkKeyDataStruct dl_modp_private_mp[] =  {
  { "p", PKF_SINGLE, SSH_PKF_PRIME_P, 0 },
  { "q", PKF_SINGLE, SSH_PKF_PRIME_Q, 1 },
  { "g", PKF_SINGLE, SSH_PKF_GENERATOR_G, 2 },
  { "x", PKF_SINGLE, SSH_PKF_SECRET_X, 3 },
  { "y", PKF_SINGLE, SSH_PKF_PUBLIC_Y, 4 },
  { NULL }
};

static PkcsPkKeyDataStruct dl_modp_public_mp[] =  {
  { "p", PKF_SINGLE, SSH_PKF_PRIME_P, 0 },
  { "q", PKF_SINGLE, SSH_PKF_PRIME_Q, 1 },
  { "g", PKF_SINGLE, SSH_PKF_GENERATOR_G, 2 },
  { "y", PKF_SINGLE, SSH_PKF_PUBLIC_Y, 3 },
  { NULL }
};

#ifdef SSHDIST_CRYPT_ECP
static PkcsPkKeyDataStruct ec_modp_private_mp[] = {
  { "p", PKF_SINGLE, SSH_PKF_PRIME_P, 0 },
  { "g", PKF_DOUBLE, SSH_PKF_GENERATOR_G, 1 },
  { "q", PKF_SINGLE, SSH_PKF_PRIME_Q, 3 },
  { "a", PKF_SINGLE, SSH_PKF_CURVE_A, 4 },
  { "b", PKF_SINGLE, SSH_PKF_CURVE_B, 5 },
  { "c", PKF_SINGLE, SSH_PKF_CARDINALITY, 6 },
  { "x", PKF_SINGLE, SSH_PKF_SECRET_X, 7 },
  { "y", PKF_DOUBLE, SSH_PKF_PUBLIC_Y, 8 },
  { NULL }
};

static PkcsPkKeyDataStruct ec_modp_public_mp[] = {
  { "p", PKF_SINGLE, SSH_PKF_PRIME_P, 0 },
  { "g", PKF_DOUBLE, SSH_PKF_GENERATOR_G, 1 },
  { "q", PKF_SINGLE, SSH_PKF_PRIME_Q, 3 },
  { "a", PKF_SINGLE, SSH_PKF_CURVE_A, 4 },
  { "b", PKF_SINGLE, SSH_PKF_CURVE_B, 5 },
  { "c", PKF_SINGLE, SSH_PKF_CARDINALITY, 6 },
  { "y", PKF_DOUBLE, SSH_PKF_PUBLIC_Y, 7 },
  { NULL }
};
#endif /* SSHDIST_CRYPT_ECP */


























#define MP_COUNT 10 /* ec-modp, private, y is double */

typedef struct PkcsPkTypeDataRec {
  const char *type;
  PkcsPkKeyData private_key_mp_list;
  PkcsPkKeyData public_key_mp_list;
} *PkcsPkTypeData, PkcsPkTypeDataStruct;

static PkcsPkTypeDataStruct pk_data[] = {
  { "if-modn", if_modn_private_mp, if_modn_public_mp },

#ifdef SSHDIST_CRYPT_DSA
  { "dl-modp", dl_modp_private_mp, dl_modp_public_mp },
#endif /* SSHDIST_CRYPT_DSA */
#ifdef SSHDIST_CRYPT_ECP
  { "ec-modp", ec_modp_private_mp, ec_modp_public_mp },
#endif /* SSHDIST_CRYPT_ECP */



  { NULL }
};

Boolean
cmp_public_keys(SshPublicKey a, SshPublicKey b)
{
  SshMPIntegerStruct mp_a1, mp_a2, mp_b1, mp_b2;
  char *type_a, *type_b;
  SshCryptoStatus stat_a, stat_b;
  PkcsPkTypeData pk;
  PkcsPkKeyData pkd;
  Boolean ret;

  /* Get key types */
  stat_a = ssh_public_key_get_info(a, SSH_PKF_KEY_TYPE, &type_a, SSH_PKF_END);
  stat_b = ssh_public_key_get_info(b, SSH_PKF_KEY_TYPE, &type_b, SSH_PKF_END);

  if (stat_a != SSH_CRYPTO_OK || stat_b != SSH_CRYPTO_OK)
    return FALSE;

  if (strcmp(type_a, type_b) != 0)
    return FALSE;

  for (pk = pk_data; pk->type; pk++)
    if (strcmp(pk->type, type_a) == 0)
      break;

  if (!pk->type)
    {
      ssh_fatal("Cannot find information for `%s' type.", type_a);
    }

  ssh_mprz_init(&mp_a1);
  ssh_mprz_init(&mp_a2);
  ssh_mprz_init(&mp_b1);
  ssh_mprz_init(&mp_b2);

  ret = TRUE;

  for (pkd = pk->public_key_mp_list; pkd->name; pkd++)
    {
      if (pkd->type == PKF_SINGLE)
        {
          stat_a = ssh_public_key_get_info(a, pkd->pkf, &mp_a1, SSH_PKF_END);
          stat_b = ssh_public_key_get_info(b, pkd->pkf, &mp_b1, SSH_PKF_END);
        }
      else if (pkd->type == PKF_DOUBLE)
        {
          stat_a = ssh_public_key_get_info(a, pkd->pkf, &mp_a1, &mp_a2,
                                           SSH_PKF_END);
          stat_b = ssh_public_key_get_info(b, pkd->pkf, &mp_b1, &mp_b2,
                                            SSH_PKF_END);
        }

      if (stat_a != SSH_CRYPTO_OK || stat_b != SSH_CRYPTO_OK)
        {
          SSH_DEBUG(2, ("Failed to retrieve `%s' from `%s' type public keys",
                        pkd->name, pk->type));
          ret = FALSE;
          break;
        }

      if (ssh_mprz_cmp(&mp_a1, &mp_b1) != 0)
        {
          SSH_DEBUG(2, ("Different `%s' fields in `%s' type public keys",
                        pkd->name, pk->type));
          ret = FALSE;
          break;
        }

      if (pkd->type == PKF_DOUBLE)
        if (ssh_mprz_cmp(&mp_a2, &mp_b2) != 0)
          {
            SSH_DEBUG(2, ("Different `%s' fields in `%s' type public keys",
                          pkd->name, pk->type));
            ret = FALSE;
            break;
          }
    }

  ssh_mprz_clear(&mp_a1);
  ssh_mprz_clear(&mp_a2);
  ssh_mprz_clear(&mp_b1);
  ssh_mprz_clear(&mp_b2);

  return ret;
}

/* `fake_rng' is used here to feed known results to
   encryption/signature operations. However, when known rng data is
   not required, we must *still* keep the pool topped up with other
   data because during key definition, the self-tests will need random
   bytes (to generate compatible keypairs or whatever..) so the pool
   must not go empty during that or we'll get a fatal error.

   When this routine is given (NULL, 0) argument, the pool is filled
   to a minimum of NOMINAL_FAKE_RNG_LEN random bytes from the
   `true_rng' generator.

   If argument is non-NULL, then `fake_rng' is emptied, and the given
   data is entered to the pool. */
static void
feed_fake_rng(const unsigned char *buf, size_t buflen)
{
  unsigned char buf2[512];
  size_t len;
  SshCryptoStatus status;

  if (buf == NULL)
    {
      while (1)
        {
          status = ssh_random_pool_get_length(fake_rng, &len);
          SSH_ASSERT(status == SSH_CRYPTO_OK);

          if (len >= NOMINAL_FAKE_RNG_LEN)
            break;

          /* Add some true randomness */
          status = ssh_random_get_bytes(true_rng, buf2, sizeof(buf2));
          SSH_ASSERT(status == SSH_CRYPTO_OK);
          ssh_random_add_entropy(fake_rng, buf2, sizeof(buf2), 
				 7 * sizeof(buf2));
        }
    }
  else
    {
      /* Drain the fake RNG, and feed the given entropy in */
      while (1)
        {
          status = ssh_random_pool_get_length(fake_rng, &len);
          SSH_ASSERT(status == SSH_CRYPTO_OK);

          if (len < sizeof(buf2))
            break;

          status = ssh_random_get_bytes(fake_rng, buf2, sizeof(buf2));
          SSH_ASSERT(status == SSH_CRYPTO_OK);
        }

      status = ssh_random_pool_get_length(fake_rng, &len);
      SSH_ASSERT(status == SSH_CRYPTO_OK);
      status = ssh_random_get_bytes(fake_rng, buf2, len);

      SSH_ASSERT(status == SSH_CRYPTO_OK);
      status = ssh_random_pool_get_length(fake_rng, &len);
      SSH_ASSERT(status == SSH_CRYPTO_OK && len == 0);

      ssh_random_add_entropy(fake_rng, buf, buflen, 7 * buflen);
      status = ssh_random_pool_get_length(fake_rng, &len);
      SSH_ASSERT(status == SSH_CRYPTO_OK && len == buflen);
    }
}


/* Clear variables: mp & size */
#define DO_CLEAR_VARIABLES                      \
do {                                            \
  int __i;                                      \
  for (__i = 0; __i < MP_COUNT; __i++)          \
    {                                           \
      ssh_mprz_clear(&mp[__i]);                 \
      ssh_mprz_init(&mp[__i]);                  \
    }                                           \
  size = 0;                                     \
} while (0)

/* Reset (free) state: keys, key/sig/enc types */
#define DO_FREE_STATE                           \
do {                                            \
  ssh_public_key_free(public_key);              \
  ssh_public_key_free(derived_public_key);      \
  ssh_private_key_free(private_key);            \
                                                \
  public_key = derived_public_key = NULL;       \
  private_key = NULL;                           \
                                                \
  ssh_xfree(key_type);                          \
  ssh_xfree(enc_type);                          \
  ssh_xfree(sig_type);                          \
                                                \
  key_type = enc_type = sig_type = NULL;        \
  pk = NULL;                                    \
} while (0)

/* Report an error */
#define DO_ERROR(STR)                                   \
do {                                                    \
  SSH_DEBUG(0, ("%s:%d: %s", filename, line, (STR)));   \
  return FALSE;                                         \
} while (0)

/* Report we're doing some work */
#define DO_WORK(CH)                             \
do                                              \
{                                               \
  fprintf(stderr, "%c\b", (CH));                \
} while (0)

#define DO_CHECK(STATUS)                                        \
do                                                              \
{                                                               \
  if ((STATUS) != SSH_CRYPTO_OK)                                \
    {                                                           \
      SSH_DEBUG(0,                                              \
                ("%s:%d: Failed cryptographic operation: %s",   \
                 filename, line,                                \
                 ssh_crypto_status_message(STATUS)));           \
     looking_for_key_type = TRUE;                               \
     if ((STATUS) == SSH_CRYPTO_SCHEME_UNKNOWN) continue;       \
     else if ((STATUS) == SSH_CRYPTO_UNSUPPORTED) continue;     \
     else goto failure;                                         \
    }                                                           \
} while (0)

Boolean
pkcs_static_tests(const char *filename)
{
  FILE *fp;
  char *token;
  char *key_type, *enc_type, *sig_type;
  SshMPIntegerStruct mp[MP_COUNT];
  int line, size, i;
  SshPublicKey public_key, derived_public_key;
  SshPrivateKey private_key;
  SshCryptoStatus status;
  unsigned int true_size;
  size_t len;
  HexRenderStruct good, bad;
  PkcsPkTypeData pk;
  PkcsPkKeyData pkd;
  Boolean looking_for_key_type;

  line = 1;

  if (!(fp = fopen(filename, "r")))
    {
      SSH_DEBUG(0, ("Can't open `%s' for reading.\n", filename));
      return FALSE;
    }

  status = ssh_random_allocate("ssh", &true_rng);
  DO_CHECK(status);
  ssh_random_add_light_noise(true_rng);

  status = ssh_random_allocate("pool", &fake_rng);
  DO_CHECK(status);

  /* Set the `fake_rng' as the default RNG */
  status = ssh_crypto_set_default_rng(fake_rng);
  DO_CHECK(status);

  for (i = 0; i < MP_COUNT; i++)
    ssh_mprz_init(&mp[i]);

  /* BTW: we can't just fgets all input to a buffer, since verify-*
     are potentially quite huge in size. Thus a little bit better
     parser */

  sig_type = enc_type = key_type = NULL;

  private_key = NULL;
  public_key = derived_public_key = NULL;

  token = NULL;
  looking_for_key_type = FALSE;

  while (1)
    {
      ssh_free(token);

      if (!file_parser_get_string(fp, &line, &token, FALSE, NULL))
        break;

      feed_fake_rng(NULL, 0);
      /*printf("token = %s\n", token);*/

      if (looking_for_key_type && strcmp(token, "key-type"))
        continue;

      if (strcmp(token, "key-type") == 0)
        {
          DO_CLEAR_VARIABLES;
          DO_FREE_STATE;

          if (!file_parser_get_string(fp, &line, &key_type, TRUE, NULL))
            DO_ERROR("Could not parse key-type");

          for (pk = pk_data; pk->type; pk++)
            if (strcmp(pk->type, key_type) == 0)
              break;

          /* If given type is not supported in this distribution, well
             skip till the next key type, and try if that one is. */
          if (pk->type == NULL)
            {
              looking_for_key_type = TRUE;
              continue;
            }
          looking_for_key_type = FALSE;
          continue;
        }

      if (strcmp(token, "size") == 0)
        {
          if (!file_parser_get_int(fp, &line, &size))
            DO_ERROR("Unexpected EOF");
          continue;
        }

      if (strcmp(token, "signature") == 0)
        {
          ssh_xfree(sig_type);
          if (!file_parser_get_string(fp, &line, &sig_type, TRUE, NULL))
            DO_ERROR("Unexpected EOF");
          continue;
        }

      if (strcmp(token, "encryption") == 0)
        {
          ssh_xfree(enc_type);
          if (!file_parser_get_string(fp, &line, &enc_type, TRUE, NULL))
            DO_ERROR("Unexpected EOF");
          continue;
        }

      if (strcmp(token, "private-define") == 0)
        {
          SSH_DEBUG(2, ("Defining private key `%s' type", key_type));

          if (strcmp(key_type, "if-modn") == 0)
            {
              status =
                ssh_private_key_define(&private_key,
                                       key_type,
                                       SSH_PKF_PRIME_P, &mp[0],
                                       SSH_PKF_PRIME_Q, &mp[1],
                                       SSH_PKF_MODULO_N, &mp[2],
                                       SSH_PKF_PUBLIC_E, &mp[3],
                                       SSH_PKF_INVERSE_U, &mp[4],
                                       SSH_PKF_SECRET_D, &mp[5],
                                       SSH_PKF_END);
            }
#ifdef SSHDIST_CRYPT_DSA
          else if (strcmp(key_type, "dl-modp") == 0)
            {
              status =
                ssh_private_key_define(&private_key,
                                       key_type,
                                       SSH_PKF_PRIME_P, &mp[0],
                                       SSH_PKF_PRIME_Q, &mp[1],
                                       SSH_PKF_GENERATOR_G, &mp[2],
                                       SSH_PKF_SECRET_X, &mp[3],
                                       SSH_PKF_PUBLIC_Y, &mp[4],
                                       SSH_PKF_END);
            }
#endif /* SSHDIST_CRYPT_DSA */
#ifdef SSHDIST_CRYPT_ECP
          else if (strcmp(key_type, "ec-modp") == 0)
            {
              status =
                ssh_private_key_define(&private_key,
                                       key_type,
                                       SSH_PKF_PRIME_P, &mp[0],
                                       SSH_PKF_GENERATOR_G, &mp[1], &mp[2],
                                       SSH_PKF_PRIME_Q, &mp[3],
                                       SSH_PKF_CURVE_A, &mp[4],
                                       SSH_PKF_CURVE_B, &mp[5],
                                       SSH_PKF_CARDINALITY, &mp[6],
                                       SSH_PKF_SECRET_X, &mp[7],
                                       SSH_PKF_PUBLIC_Y, &mp[8], &mp[9],
                                       SSH_PKF_END);
            }
#endif /* SSHDIST_CRYPT_ECP */
#ifdef SSHDIST_CRYPT_ECP
          else if (strcmp(key_type, "ec-gf2n") == 0)
            {
              status =
                ssh_private_key_define(&private_key,
                                       key_type,
                                       SSH_PKF_IRREDUCIBLE_P, &mp[0],
                                       SSH_PKF_GENERATOR_G, &mp[1], &mp[2],
                                       SSH_PKF_PRIME_Q, &mp[3],
                                       SSH_PKF_CURVE_A, &mp[4],
                                       SSH_PKF_CURVE_B, &mp[5],
                                       SSH_PKF_CARDINALITY, &mp[6],
                                       SSH_PKF_SECRET_X, &mp[7],
                                       SSH_PKF_PUBLIC_Y, &mp[8], &mp[9],
                                       SSH_PKF_END);
            }
#endif /* SSHDIST_CRYPT_ECP */
          else
	    {
	      SSH_DEBUG(SSH_D_FAIL, ("Unknown key type"));
	      continue;
	    }

          if (status != SSH_CRYPTO_OK)
            {
              SSH_DEBUG(0,
                        ("%s:%d: Could not define private key `%s': %s",
                         filename, line, key_type,
                         ssh_crypto_status_message(status)));

              goto failure;
            }

          if (sig_type)
            {
              status =
                ssh_private_key_select_scheme(private_key,
                                              SSH_PKF_SIGN, sig_type,
                                              SSH_PKF_END);
              DO_CHECK(status);
            }

          if (enc_type)
            {
              status =
                ssh_private_key_select_scheme(private_key,
                                              SSH_PKF_ENCRYPT, enc_type,
                                              SSH_PKF_END);
              DO_CHECK(status);
            }

          status =
            ssh_private_key_get_info(private_key,
                                     SSH_PKF_SIZE, &true_size,
                                     SSH_PKF_END);

          DO_CHECK(status);

          if (size != 0 && true_size != (SshUInt32)size)
            {
              SSH_DEBUG(0,
                        ("%s:%d: Private key `%s': expected size %d bits, "
                         "true size %d bits",
                         filename, line, key_type, size, (int) true_size));

              goto failure;
            }

          if (verbose)
            {
              printf("Defined private key `%s', size %d bits.",
                     key_type, (int) true_size);
              if (enc_type)
                printf(" Encryption %s.", enc_type);
              if (sig_type)
                printf(" Signature %s.", sig_type);
              printf("\n");
            }

          DO_CLEAR_VARIABLES;
          continue;
        }

      if (strcmp(token, "public-define") == 0)
        {
          SSH_DEBUG(2, ("Defining public key `%s' type", key_type));
          SSH_ASSERT(key_type != NULL);

          if (strcmp(key_type, "if-modn") == 0)
            {
              status =
                ssh_public_key_define(&public_key, key_type,
                                      SSH_PKF_MODULO_N, &mp[0],
                                      SSH_PKF_PUBLIC_E, &mp[1],
                                      SSH_PKF_END);
            }
#ifdef SSHDIST_CRYPT_DSA
          else if (strcmp(key_type, "dl-modp") == 0)
            {
              status =
                ssh_public_key_define(&public_key, key_type,
                                      SSH_PKF_PRIME_P, &mp[0],
                                      SSH_PKF_PRIME_Q, &mp[1],
                                      SSH_PKF_GENERATOR_G, &mp[2],
                                      SSH_PKF_PUBLIC_Y, &mp[3],
                                      SSH_PKF_END);
            }
#endif /* SSHDIST_CRYPT_DSA */
#ifdef SSHDIST_CRYPT_ECP
          else if (strcmp(key_type, "ec-modp") == 0)
            {
              status =
                ssh_public_key_define(&public_key,
                                      key_type,
                                      SSH_PKF_PRIME_P, &mp[0],
                                      SSH_PKF_GENERATOR_G, &mp[1], &mp[2],
                                      SSH_PKF_PRIME_Q, &mp[3],
                                      SSH_PKF_CURVE_A, &mp[4],
                                      SSH_PKF_CURVE_B, &mp[5],
                                      SSH_PKF_CARDINALITY, &mp[6],
                                      SSH_PKF_PUBLIC_Y, &mp[7], &mp[8],
                                      SSH_PKF_END);
            }
#endif /* SSHDIST_CRYPT_ECP */
#ifdef SSHDIST_CRYPT_ECP
          else if (strcmp(key_type, "ec-gf2n") == 0)
            {
              status =
                ssh_public_key_define(&public_key,
                                      key_type,
                                      SSH_PKF_IRREDUCIBLE_P, &mp[0],
                                      SSH_PKF_GENERATOR_G, &mp[1], &mp[2],
                                      SSH_PKF_PRIME_Q, &mp[3],
                                      SSH_PKF_CURVE_A, &mp[4],
                                      SSH_PKF_CURVE_B, &mp[5],
                                      SSH_PKF_CARDINALITY, &mp[6],
                                      SSH_PKF_PUBLIC_Y, &mp[7], &mp[8],
                                      SSH_PKF_END);
            }
#endif /* SSHDIST_CRYPT_ECP */
          else
	    {
	      SSH_DEBUG(SSH_D_FAIL, ("Unknown key type"));
	      continue;
	    }

          if (status != SSH_CRYPTO_OK)
            {
              SSH_DEBUG(0,
                        ("%s:%d: Could not define public key `%s': %s",
                         filename, line, key_type,
                         ssh_crypto_status_message(status)));

              goto failure;
            }

          if (sig_type)
            {
              status =
                ssh_public_key_select_scheme(public_key,
                                              SSH_PKF_SIGN, sig_type,
                                              SSH_PKF_END);

              DO_CHECK(status);
            }

          if (enc_type)
            {
              status =
                ssh_public_key_select_scheme(public_key,
                                              SSH_PKF_ENCRYPT, enc_type,
                                              SSH_PKF_END);

              DO_CHECK(status);
            }

          status =
            ssh_public_key_get_info(public_key,
                                     SSH_PKF_SIZE, &true_size,
                                     SSH_PKF_END);

          DO_CHECK(status);

          if (size != 0 && true_size != size)
            {
              SSH_DEBUG(0,
                        ("%s:%d: Public key `%s': expected size %d bits, "
                         "true size %d bits",
                         filename, line, key_type, size, (int)true_size));

              goto failure;
            }

          if (verbose)
            {
              printf("Defined public key `%s', size %d bits.",
                     key_type, (int)true_size);

              if (enc_type)
                printf(" Encryption %s.", enc_type);
              if (sig_type)
                printf(" Signature %s.", sig_type);

              printf("\n");
            }

          status =
            ssh_private_key_derive_public_key(private_key,
                                              &derived_public_key);

          if (status == SSH_CRYPTO_OK)
            {
              if (!cmp_public_keys(public_key, derived_public_key))
                {
                  SSH_DEBUG(0,
                            ("%s:%d: Derived and defined public keys differ.",
                             filename, line));

                  goto failure;
                }

              ssh_public_key_free(derived_public_key);
              derived_public_key = NULL;
            }
          else if (status != SSH_CRYPTO_UNSUPPORTED)
            {
              SSH_DEBUG(0,
                        ("%s:%d: Could not derive public key `%s': %s",
                         filename, line, key_type,
                         ssh_crypto_status_message(status)));

              goto failure;
            }

          DO_CLEAR_VARIABLES;
          continue;
        }

      if (strcmp(token, "verify-encrypt") == 0)
        {
          unsigned char *plaintext, *ciphertext, *random;
          size_t plainlen, cipherlen, randomlen, max_in, max_out, got;
          unsigned char buf[5120];
          int buf_fudge;

          if (!file_parser_get_data(fp, &line, &random, &randomlen))
            DO_ERROR("Could not parse random data");

          if (!file_parser_get_data(fp, &line, &plaintext, &plainlen))
            DO_ERROR("Could not parse plaintext data");

          if (!file_parser_get_data(fp, &line, &ciphertext, &cipherlen))
            DO_ERROR("Could not parse ciphertext data");

          if (public_key != NULL)
            {
              /* First test encryption */
              max_in = ssh_public_key_max_encrypt_input_len(public_key);
              max_out = ssh_public_key_max_encrypt_output_len(public_key);

#if 0
              good.data = plaintext;
              good.length = plainlen;

              SSH_DEBUG(0, ("pub=%p plaintext=%d bytes, ciphertext=%d bytes, "
                            "max_in=%d, max_out=%d",
                            public_key, plainlen, cipherlen, max_in, max_out));

              SSH_DEBUG(0, ("plaintext=%@", hex_render, &good));
#endif

              SSH_ASSERT(max_in >= plainlen);
              SSH_ASSERT(max_out <= sizeof(buf));

              /* Feed random to the RNG for use in the encryption
                 function */
              feed_fake_rng(random, randomlen);

              status =
                ssh_public_key_encrypt(public_key,
                                       plaintext, plainlen,
                                       buf, sizeof(buf), &got);

              status = ssh_random_pool_get_length(fake_rng, &len);
              SSH_ASSERT(status == SSH_CRYPTO_OK && len == 0);
              feed_fake_rng(NULL, 0);

#if 0
              good.length = got;
              good.data = buf;

              SSH_DEBUG(0, ("encrypted =%@", hex_render, &good));

              good.length = cipherlen;
              good.data = ciphertext;

              SSH_DEBUG(0, ("ciphertext=%@", hex_render, &good));
#endif

              DO_CHECK(status);
              SSH_ASSERT(got == cipherlen);

              if (memcmp(ciphertext, buf, got) != 0)
                {
                  good.length = bad.length = got;
                  good.data = ciphertext;
                  bad.data = buf;

                  SSH_DEBUG(0, ("%s:%d: Encrypted data does not match: "
                                "Correct=%@, Received=%@",
                                filename, line,
                                hex_render, &good, hex_render, &bad));

                  goto failure;
                }

              DO_WORK('e');
            }

          if (private_key)
            {
              /* Test decryption */
              max_in = ssh_private_key_max_decrypt_input_len(private_key);
              max_out = ssh_private_key_max_decrypt_output_len(private_key);

              SSH_ASSERT(max_in >= cipherlen);
              SSH_ASSERT(max_out <= sizeof(buf));

              status =
                ssh_private_key_decrypt(private_key,
                                        ciphertext, cipherlen,
                                        buf, sizeof(buf), &got);

              DO_CHECK(status);

              /* Watch out rsa-none-none, since it does not have
                 encoding, it will always give maximal-length decrypt
                 with leading zero padding */
              if (strcmp(enc_type, "rsa-none-none") == 0)
                {
                  SSH_ASSERT(got == max_out);
                  buf_fudge = max_out - plainlen;
                }
              else
                {
                  SSH_ASSERT(got == plainlen);
                  buf_fudge = 0;
                }

              if (memcmp(plaintext, buf + buf_fudge, plainlen) != 0)
                {
                  good.length = bad.length = got;
                  good.data = plaintext;
                  bad.data = buf;

                  SSH_DEBUG(0, ("%s:%d: Decrypted data does not match: "
                                "Correct=%@, Decrypted=%@",
                                filename, line,
                                hex_render, &good, hex_render, &bad));

                  goto failure;
                }

              DO_WORK('d');
            }

          ssh_xfree(plaintext);
          ssh_xfree(ciphertext);
          ssh_xfree(random);

          continue;
        }

      if (strcmp(token, "verify-signature") == 0)
        {
          unsigned char *plaintext, *signature, *random;
          size_t plainlen, signaturelen, randomlen, max_in, max_out, got;
          unsigned char buf[5120];

          if (!file_parser_get_data(fp, &line, &random, &randomlen))
            DO_ERROR("Could not parse random data");

          if (!file_parser_get_data(fp, &line, &plaintext, &plainlen))
            DO_ERROR("Could not parse plaintext data");

          if (!file_parser_get_data(fp, &line, &signature, &signaturelen))
            DO_ERROR("Could not parse signature data");

          if (private_key != NULL)
            {
              max_in = ssh_private_key_max_signature_input_len(private_key);
              max_out = ssh_private_key_max_signature_output_len(private_key);

              SSH_ASSERT(max_in == (size_t)-1 || max_in >= plainlen);
              SSH_ASSERT(max_out <= sizeof(buf));

              /* Feed random to the RNG for use in the encryption
                 function */
              feed_fake_rng(random, randomlen);

              status =
                ssh_private_key_sign(private_key,
                                     plaintext, plainlen,
                                     buf, sizeof(buf), &got);

              status = ssh_random_pool_get_length(fake_rng, &len);
              SSH_ASSERT(status == SSH_CRYPTO_OK && len == 0);
              feed_fake_rng(NULL, 0);

              DO_CHECK(status);
              SSH_ASSERT(got == signaturelen);

              if (memcmp(signature, buf, got) != 0)
                {
                  good.length = bad.length = got;
                  good.data = signature;
                  bad.data = buf;

                  SSH_DEBUG(0, ("%s:%d: Signature does not match: "
                                "Correct=%@, Received=%@",
                                filename, line,
                                hex_render, &good, hex_render, &bad));

                  goto failure;
                }

              DO_WORK('s');
            }

          if (public_key)
            {
              /* Verify the signature */
              status =
                ssh_public_key_verify_signature(public_key,
                                                signature, signaturelen,
                                                plaintext, plainlen);

              if (status != SSH_CRYPTO_OK)
                {
                  SSH_DEBUG(0, ("%s:%d: Signature does not verify.",
                                filename, line));

                  goto failure;
                }

              DO_WORK('v');
            }

          ssh_xfree(plaintext);
          ssh_xfree(signature);
          ssh_xfree(random);

          continue;
        }

      /* Any other tokens: check the pk-type specific argument lists
         (both pk and private anyway) */

      /* If no private key is defined, then this must be private key
         definition */
      if (private_key == NULL)
        pkd = pk->private_key_mp_list;
      else
        pkd = pk->public_key_mp_list;

      for (; pkd->name; pkd++)
        if (strcmp(token, pkd->name) == 0)
          break;

      if (pkd->name)
        {
          if (pkd->type == PKF_SINGLE)
            {
              SSH_DEBUG(4, ("Reading single `%s' field `%s' to index %d",
                            key_type, pkd->name, pkd->index));

              if (!file_parser_get_mp(fp, &line, &mp[pkd->index]))
                DO_ERROR("Could not parse MP integer");
            }
          else if (pkd->type == PKF_DOUBLE)
            {
              SSH_DEBUG(4, ("Reading double `%s' field `%s' to "
                            "index %d and %d",
                            key_type, pkd->name, pkd->index, pkd->index + 1));

              if (!file_parser_get_mp(fp, &line, &mp[pkd->index]))
                DO_ERROR("Could not parse MP integer");

              if (!file_parser_get_mp(fp, &line, &mp[pkd->index + 1]))
                DO_ERROR("Could not parse MP integer");
            }
          else
            SSH_NOTREACHED;

          continue;
        }

      DO_ERROR("Unrecognized token");

    failure:
      if (status != SSH_CRYPTO_OK)
        SSH_DEBUG(0, ("Crypto status: %s (%d)",
                      ssh_crypto_status_message(status), status));

      if (private_key)
        {
          char *type, *sig,*enc;
          size_t size;

          ssh_private_key_get_info(private_key,
                                   SSH_PKF_KEY_TYPE, &type,
                                   SSH_PKF_SIGN, &sig,
                                   SSH_PKF_ENCRYPT, &enc,
                                   SSH_PKF_SIZE, &size,
                                   SSH_PKF_END);
          SSH_DEBUG(0,
                    ("Private key information: Type %s Size %d bits "
                     "Signature %s Encrypt %s",
                     type, size, sig ? sig : "none", enc ? enc : "none"));
        }

      fclose(fp);
      return FALSE;
    }

  DO_CLEAR_VARIABLES;
  DO_FREE_STATE;

  /* Clear mp list */
  for (i = 0; i < MP_COUNT; i++)
    ssh_mprz_clear(&mp[i]);

  status = ssh_crypto_set_default_rng(true_rng);
  DO_CHECK(status);

  fclose(fp);
  true_rng = fake_rng = NULL;

  return TRUE;
}

/************************************************************************/

/* Here starts the test vector generator routines. */

/* We have two RNGs. The `true_rng' is a type `ssh' rng. We use it to
   feed the pool-rng `fake_rng' bytes. The `fake_rng' has been set to
   be the default RNG. This way we can know what is the exact sequence
   of random bytes the oaep etc. padding uses bytes, and can reproduce
   them exactly when running the regression suite later. */

/* This is used to keep a copy of the fake rng bytes, so we can
   retrieve them after the encrypt/sign operation has finished */
static SshBuffer fake_rng_bytes;

/* How many different test vectors are generated for each keypair */
#define ENCRYPT_TEST_VECTORS_N 50
#define SIGNATURE_TEST_VECTORS_N 50
#define DH_TEST_VECTORS_N 50

typedef struct PkcsInfoRec
{
  char *key_type;
  char *sign; char *encrypt; char *dh;
  char *predefined;
  int   sizes[10]; /* max 10, "0" is terminator */
  int   entropy;
} *PkcsInfo, PkcsInfoStruct;

/* This routine performs two main tasks: it will keep the `fake_rng'
   containing at least NOMINAL_FAKE_RNG_LEN bytes generated through
   the `true_rng' generator.

   Also, if given non-NULL `buf_ret' it will return the random bytes
   consumed from the fake pool since the last call to this
   routine. Thus, by doing

   reset_fake_rng(NULL, 0);
   some operation using random bytes through ssh_random_get_byte();
   reset_fake_rng(&buf, &len);

   you can get the rng bytes used by the intervening operation. */

void reset_fake_rng(unsigned char **buf_ret, size_t *len_ret)
{
  unsigned char buf[512], *tmp;
  size_t len;
  SshCryptoStatus status;

  /* How many bytes were consumed? */
  status = ssh_random_pool_get_length(fake_rng, &len);
  SSH_ASSERT(status == SSH_CRYPTO_OK);

  len = ssh_buffer_len(fake_rng_bytes) - len;

  SSH_DEBUG(4, ("Pool has been drained of %d bytes.", len));

  tmp = NULL;

  if (len > 0)
    {
      if (buf_ret)
        {
          tmp = ssh_xmalloc(len);
          memcpy(tmp, ssh_buffer_ptr(fake_rng_bytes), len);
        }

      ssh_buffer_consume(fake_rng_bytes, len);
    }

  if (len_ret)
    *len_ret = len;

  if (buf_ret)
     *buf_ret = tmp;

  /* Top the RNG */
  while (1)
    {
      status = ssh_random_pool_get_length(fake_rng, &len);
      SSH_ASSERT(status == SSH_CRYPTO_OK);

      if (len >= NOMINAL_FAKE_RNG_LEN)
        break;

      status = ssh_random_get_bytes(true_rng, buf, sizeof(buf));
      SSH_ASSERT(status == SSH_CRYPTO_OK);
      ssh_xbuffer_append(fake_rng_bytes, buf, sizeof(buf));
      status = ssh_random_add_entropy(fake_rng, buf, sizeof(buf),
				      7 * sizeof(buf));
      SSH_ASSERT(status == SSH_CRYPTO_OK);

      status = ssh_random_pool_get_length(fake_rng, &len);
      SSH_ASSERT(status == SSH_CRYPTO_OK);
      SSH_DEBUG(5, ("Fed %d bytes to pool, now %d bytes",
                    sizeof(buf), len));
    }

  status = ssh_random_pool_get_length(fake_rng, &len);
  SSH_ASSERT(status == SSH_CRYPTO_OK);
  SSH_ASSERT(ssh_buffer_len(fake_rng_bytes) == len);
}

#define RSA_SIZES 768, 1024, 1536, 2048
#define DSA_SIZES 768, 1024

static PkcsInfoStruct pkcs_info[] =
  {
#if 0
























































#endif

#ifdef SSHDIST_CRYPT_ECP
    /* ECP */
    { "ec-modp", "dsa-none-sha1", NULL, "plain",
      "ssh-ec-modp-curve-155bit-1",
      { 155, 0 }, 0 },
    { "ec-modp", "elgamal-none-sha1", "elgamal-random-none", "plain",
      "ssh-ec-modp-curve-155bit-1",
      { 155, 0 }, 0 },

    { "ec-modp", "dsa-none-sha1", NULL, "plain",
      "ssh-ec-modp-curve-155bit-2",
      { 155, 0 }, 0 },
    { "ec-modp", "elgamal-none-sha1", "elgamal-random-none", "plain",
      "ssh-ec-modp-curve-155bit-2",
      { 155, 0 }, 0 },

    { "ec-modp", "dsa-none-sha1", NULL, "plain",
      "ssh-ec-modp-curve-175bit-1",
      { 175, 0 }, 0 },

    { "ec-modp", "elgamal-none-sha1", "elgamal-random-none", "plain",
      "ssh-ec-modp-curve-175bit-1",
      { 175, 0 }, 0 },

    { "ec-modp", "dsa-none-sha1", NULL, "plain",
      "ssh-ec-modp-curve-175bit-2",
      { 175, 0 }, 0 },
    { "ec-modp", "elgamal-none-sha1", "elgamal-random-none", "plain",
      "ssh-ec-modp-curve-175bit-2",
      { 175, 0 }, 0 },
#endif /* SSHDIST_CRYPT_ECP */

    { "if-modn", "rsa-pkcs1-none", "rsa-none-none", NULL, NULL,
      { RSA_SIZES, 0 }, 0 },
    { "if-modn", "rsa-pkcs1-sha1", "rsa-pkcs1v2-oaep", NULL, NULL,
      { RSA_SIZES, 0 }, 0 },
    { "if-modn", "rsa-pkcs1-md5", "rsa-pkcs1-none", NULL, NULL,
      { RSA_SIZES, 0 }, 0 },

#ifdef SSHDIST_CRYPT_MD2
    { "if-modn", "rsa-pkcs1-md2", "rsa-pkcs1-none", NULL, NULL,
      { RSA_SIZES, 0 }, 0 },
#endif /* SSHDIST_CRYPT_MD2 */
#ifdef SSHDIST_CRYPT_DSA
    { "dl-modp", "dsa-nist-sha1", NULL, NULL, NULL,
      { DSA_SIZES, 0 }, 0 },
#endif /* SSHDIST_CRYPT_DSA */
#if 0
    /* Combination. */
    { "dl-modp", "dsa-nist-sha1", NULL, "plain", NULL,
      { 1024, 0 }, 0 },

    /* Number of DH tests. */
    { "dl-modp", NULL, NULL, "plain", NULL,
      { 1024, 0 }, 160 },
    { "dl-modp", NULL, NULL, "plain", NULL,
      { 1024, 0 }, 256 },
#endif

    { NULL }
  };

/* Given PkcsInfo structure, generate a valid key name (for key
   generation function) */
static char*
key_name(PkcsInfo info)
{
  unsigned char *buf, *tmp[10], *k;
  int i;

  ssh_dsprintf(&buf, "%s{", info->key_type);

  /* Generate the key. */
  i = 0;
  if (info->sign)
    {
      ssh_dsprintf(&tmp[i], "sign{%s}", info->sign);
      i++;
    }
  if (info->encrypt)
    {
      ssh_dsprintf(&tmp[i], "encrypt{%s}", info->encrypt);
      i++;
    }
  if (info->dh)
    {
      ssh_dsprintf(&tmp[i], "dh{%s}", info->dh);
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

  return buf;
}

/* Given a name, and PkcsInfo structure, generate a private key of a
   given size. */
static SshCryptoStatus
key_generate(const char *name, PkcsInfo info, int size,
             SshPrivateKey *private_key)
{
  SshCryptoStatus status;
  SshPrivateKey prv;

  if (info->predefined)
    {
      if (info->entropy)
        {
          status =
            ssh_private_key_generate(&prv,
                                     name,
                                     SSH_PKF_PREDEFINED_GROUP,
                                     info->predefined,
                                     SSH_PKF_RANDOMIZER_ENTROPY,
                                     info->entropy,
                                     SSH_PKF_END);
          goto end;
        }
      else
        {
          status =
            ssh_private_key_generate(&prv,
                                     name,
                                     SSH_PKF_PREDEFINED_GROUP,
                                     info->predefined,
                                     SSH_PKF_END);
          goto end;
        }
    }
  else
    {
      if (info->entropy)
        {
          status =
            ssh_private_key_generate(&prv,
                                     name,
                                     SSH_PKF_SIZE, size,
                                     SSH_PKF_RANDOMIZER_ENTROPY,
                                     info->entropy,
                                     SSH_PKF_END);
          goto end;
        }
      else
        {
          status =
            ssh_private_key_generate(&prv,
                                     name,
                                     SSH_PKF_SIZE, size,
                                     SSH_PKF_END);
          goto end;
        }
    }

 end:

  *private_key = NULL;

  if (status != SSH_CRYPTO_OK)
    return status;

  *private_key = prv;

  return status;
}

/* This routine will generate some known-bad-case test vectors. If it
   generated such a known vector (based on the index), it must return
   a false (0) value, otherwise it must return a true value (1).

   This generates known vectors of all zeros (000..), all ones
   (111...) and alternating ones and zeros (10101...).  */

static int
make_known_vector(int i, size_t *len_ret, unsigned char *buf, size_t max)
{
  size_t len;

  if (i > 2)
    return 1;

  len = max;

  switch (i)
    {
    case 0:
      memset(buf, 0, len); break;
    case 1:
      memset(buf, 0xff, len); break;
    case 2:
      memset(buf, 0xaa, len); break;
    default:
      SSH_NOTREACHED;
    }

  *len_ret = len;

  return 0;
}

#define NOT_KNOWN_VECTOR(INDEX,LEN,BUF,MAX) \
        make_known_vector((INDEX), &(LEN), (BUF), (MAX))

static void mp_print(FILE *fp, const char *field, SshMPInteger num)
{
  unsigned char buf[5120];
  int i, len;

  len = ssh_mprz_encode_rendered(buf, sizeof(buf), num);

  fprintf(fp, "%s ", field);

  for (i = 0; i < len; i++)
    fprintf(fp, "%02x", buf[i]);

  fprintf(fp, "\n");
}

static void mp_print2(FILE *fp, const char *field,
                      SshMPInteger a, SshMPInteger b)
{
  unsigned char buf[5120];
  int i, len;

  fprintf(fp, "%s ", field);

  len = ssh_mprz_encode_rendered(buf, sizeof(buf), a);

  for (i = 0; i < len; i++)
    fprintf(fp, "%02x", buf[i]);

  fprintf(fp, " ");

  len = ssh_mprz_encode_rendered(buf, sizeof(buf), b);

  for (i = 0; i < len; i++)
    fprintf(fp, "%02x", buf[i]);

  fprintf(fp, "\n");
}

/* Generate `cnt' encryption test vectors for given private/public key
   pair. */
static Boolean
gen_encrypt_vectors(FILE *fp, SshPrivateKey private_key,
                    SshPublicKey public_key, int cnt)
{
  size_t max_in, max_out, len, got;
  unsigned char inbuf[1024], outbuf[1024], *enc_rng_buf;
  int i, k, shrink_bits;
  SshCryptoStatus status;
  size_t enc_rng_len;

  max_in = ssh_public_key_max_encrypt_input_len(public_key);
  max_out = ssh_public_key_max_encrypt_output_len(public_key);

  SSH_ASSERT(max_in > 0);
  SSH_ASSERT(max_in <= sizeof(inbuf));
  SSH_ASSERT(max_out > 0);
  SSH_ASSERT(max_out <= sizeof(outbuf)); /* increase buf size if necessary */

  for (i = 0; i < cnt; i++)
    {
      shrink_bits = 0;

    shrink_retry:

      if (NOT_KNOWN_VECTOR(i, len, inbuf, max_in))
        {
          len = (ssh_rand() % max_in) + 1;
          ssh_random_get_bytes(true_rng, inbuf, len);
        }
      else
        {
          /* Known vector -- check if we need to zero out top
             bits. This is needed for rsa-none-none, as the API gives
             us bytes, but in reality sometimes the true number of
             bits is less than bytes * 8 .. */

          if (shrink_bits > 8)
            memset(inbuf, 0, shrink_bits / 8);
          inbuf[shrink_bits / 8] &= 0xff >> (shrink_bits & 7);
        }

      /* Top RNG, reset */
      reset_fake_rng(NULL, NULL);

      status =
        ssh_public_key_encrypt(public_key,
                               inbuf, len, outbuf, sizeof(outbuf), &got);

      reset_fake_rng(&enc_rng_buf, &enc_rng_len);

      if (status == SSH_CRYPTO_DATA_TOO_LONG)
        {
          SSH_ASSERT(shrink_bits < max_in);
          shrink_bits++;
          goto shrink_retry;
        }

      if (status != SSH_CRYPTO_OK)
        {
          SSH_DEBUG(0, ("Could not encrypt %d byte buffer: %s",
                        len, ssh_crypto_status_message(status)));
          /*return FALSE;*/
          continue;
        }

      SSH_ASSERT(got <= max_out);

      fprintf(fp, "# data len=%d, cipher len=%d, rng inject=%d",
              len, got, enc_rng_len);
      if (shrink_bits)
        fprintf(fp, ", shrink_bits=%d", shrink_bits);
      fprintf(fp,"\nverify-encrypt ");
      if (enc_rng_len)
        for (k = 0; k < enc_rng_len; k++)
          fprintf(fp, "%02x", enc_rng_buf[k]);
      else
        fprintf(fp, "\"\"");
      fprintf(fp, " ");
      for (k = 0; k < len; k++)
        fprintf(fp, "%02x", inbuf[k]);
      fprintf(fp, " ");
      for (k = 0; k < got; k++)
        fprintf(fp, "%02x", outbuf[k]);
      fprintf(fp, "\n");

      ssh_free(enc_rng_buf);
    }

  return TRUE;
}

/* Generate `cnt' signature test vectors. */
static Boolean
gen_signature_vectors(FILE *fp, SshPrivateKey private_key, int cnt)
{
  size_t max_in, max_out, len, got;
  unsigned char inbuf[1024], outbuf[1024], *enc_rng_buf;
  int i, k;
  SshCryptoStatus status;
  size_t enc_rng_len;

  max_in = ssh_private_key_max_signature_input_len(private_key);
  max_out = ssh_private_key_max_signature_output_len(private_key);

  SSH_ASSERT(max_in == (size_t)-1 || max_in <= sizeof(inbuf));
  SSH_ASSERT(max_out > 0);
  SSH_ASSERT(max_out <= sizeof(outbuf)); /* increase buf size if necessary */

  if (max_in == (size_t)-1)
    max_in = sizeof(inbuf);

  for (i = 0; i < cnt; i++)
    {
      /* Always generate three known test vectors: all 0, all 1, alternating */
      if (NOT_KNOWN_VECTOR(i, len, inbuf, max_in))
        {
          len = (ssh_rand() % max_in) + 1;
          ssh_random_get_bytes(true_rng, inbuf, len);
        }

      reset_fake_rng(NULL, NULL);

      status =
        ssh_private_key_sign(private_key,
                             inbuf, len, outbuf, sizeof(outbuf), &got);

      reset_fake_rng(&enc_rng_buf, &enc_rng_len);

      if (status != SSH_CRYPTO_OK)
        {
          SSH_DEBUG(0, ("Could not sign %d byte buffer: %s",
                        len, ssh_crypto_status_message(status)));
          return FALSE;
        }

      SSH_ASSERT(got <= max_out);

      fprintf(fp, "# data len=%d, cipher len=%d, rng inject=%d\n",
              len, got, enc_rng_len);
      fprintf(fp,"verify-signature ");
      if (enc_rng_len)
        for (k = 0; k < enc_rng_len; k++)
          fprintf(fp, "%02x", enc_rng_buf[k]);
      else
        fprintf(fp, "\"\"");
      fprintf(fp, " ");
      for (k = 0; k < len; k++)
        fprintf(fp, "%02x", inbuf[k]);
      fprintf(fp, " ");
      for (k = 0; k < got; k++)
        fprintf(fp, "%02x", outbuf[k]);
      fprintf(fp, "\n");
      ssh_free(enc_rng_buf);
    }
  return TRUE;
}

/* This routine will create "pkcs.tests.created" file containing
   generated test vectors for randomly generated keys. The `pkcs_info'
   list and {ENCRYPT,SIGNATURE,DH}_TEST_VECTORS_N will determine the
   type and amount of tests generated. */

Boolean pkcs_static_tests_do(const char *filename)
{
  FILE *fp;
  int i, k, size;
  PkcsInfo info;
  SshPrivateKey private_key;
  SshPublicKey public_key;
  SshCryptoStatus status;
  char *name, *key_type, *sig_type, *enc_type;
  SshMPIntegerStruct a, b;
  PkcsPkTypeData pk;

  if (!(fp = fopen(filename, "w")))
    return FALSE;

  ssh_mprz_init(&a);
  ssh_mprz_init(&b);

  fake_rng_bytes = ssh_xbuffer_allocate();

  status = ssh_random_allocate("ssh", &true_rng);
  SSH_ASSERT(status == SSH_CRYPTO_OK);
  ssh_random_add_light_noise(true_rng);

  status = ssh_random_allocate("pool", &fake_rng);
  SSH_ASSERT(status == SSH_CRYPTO_OK);

  /* Set the `fake_rng' as the default RNG */
  status = ssh_crypto_set_default_rng(fake_rng);
  SSH_ASSERT(status == SSH_CRYPTO_OK);

  fprintf(fp, "# This file is automatically generated "
          "(generator code is in file %s)\n\n",
          __FILE__);

  for (info = &pkcs_info[0]; info->key_type; info++)
    {
      /* Keep the fake RNG topped up, we're not interested in the RNG
         data from generating primes */
      reset_fake_rng(NULL, NULL);

      name = key_name(info);

      for (i = 0; info->sizes[i] != 0; i++)
        {
          printf("Generating %s (%d bits%s%s)\n",
                 name, info->sizes[i],
                 info->predefined ? ", predefined " : "",
                 info->predefined ? info->predefined : "");

          /*fprintf(fp, "key-type %s\n", name);*/
          fprintf(fp, "key-type %s # %s\n", info->key_type, name);

          status = key_generate(name, info, info->sizes[i], &private_key);

          if (status != SSH_CRYPTO_OK)
            {
              SSH_DEBUG(0, ("Could not generate private key "
                            "(%s, %d bits): %s",
                            name, info->sizes[i],
                            ssh_crypto_status_message(status)));

              return FALSE;
            }

          status =
            ssh_private_key_derive_public_key(private_key, &public_key);

          if (status != SSH_CRYPTO_OK)
            {
              SSH_DEBUG(0, ("Could not derive public key from private key "
                            "(%s, %d bits): %s",
                            name, info->sizes[i],
                            ssh_crypto_status_message(status)));
              return FALSE;
            }

          for (pk = pk_data; pk->type; pk++)
            if (strcmp(pk->type, info->key_type) == 0)
              break;

          if (pk->type == NULL)
            ssh_fatal("Unrecognized key type `%s'", info->key_type);

          status =
            ssh_private_key_get_info(private_key,
                                     SSH_PKF_KEY_TYPE, &key_type,
                                     SSH_PKF_SIGN, &sig_type,
                                     SSH_PKF_ENCRYPT, &enc_type,
                                     SSH_PKF_SIZE, &size,
                                     SSH_PKF_END);

          if (status != SSH_CRYPTO_OK)
            {
              SSH_DEBUG(0,
                        ("Could not retrieve information from private key "
                         "(%s, %d bits): %s",
                         name, info->sizes[i],
                         ssh_crypto_status_message(status)));
              return FALSE;
            }

          SSH_ASSERT(strcmp(key_type, info->key_type) == 0);

          if (size != info->sizes[i])
            {
              SSH_DEBUG(0,
                        ("Generated and expected key sizes differ for `%s': "
                         "expected %d bits, got %d bits",
                         name, info->sizes[i], size));
              return FALSE;
            }

          for (k = 0; pk->private_key_mp_list[k].name; k++)
            {
              if (pk->private_key_mp_list[k].type == PKF_SINGLE)
                status =
                  ssh_private_key_get_info(private_key,
                                           pk->private_key_mp_list[k].pkf, &a,
                                           SSH_PKF_END);
              else if (pk->private_key_mp_list[k].type == PKF_DOUBLE)
                status =
                  ssh_private_key_get_info(private_key,
                                           pk->private_key_mp_list[k].pkf,
                                                &a, &b,
                                           SSH_PKF_END);

              if (status != SSH_CRYPTO_OK)
                {
                  SSH_DEBUG(0,
                            ("Could not retrieve information for `%s' "
                             "from private key "
                             "(%s, %d bits): %s",
                             pk->private_key_mp_list[k].name,
                             name, info->sizes[i],
                             ssh_crypto_status_message(status)));
                  return FALSE;
                }

              fprintf(fp, "  ");

              if (pk->private_key_mp_list[k].type == PKF_SINGLE)
                mp_print(fp, pk->private_key_mp_list[k].name, &a);
              else
                mp_print2(fp, pk->private_key_mp_list[k].name, &a, &b);
            }

          /* Finally put out size for verification, and use this key
             to define the private key. */
          fprintf(fp, "  size %d\n", info->sizes[i]);
          if (sig_type)
            fprintf(fp, "  signature %s\n", sig_type);
          if (enc_type)
            fprintf(fp, "  encryption %s\n", enc_type);
          fprintf(fp, "private-define\n");

          for (k = 0; pk->public_key_mp_list[k].name; k++)
            {
              if (pk->public_key_mp_list[k].type == PKF_SINGLE)
                status =
                  ssh_public_key_get_info(public_key,
                                           pk->public_key_mp_list[k].pkf, &a,
                                           SSH_PKF_END);
              else if (pk->public_key_mp_list[k].type == PKF_DOUBLE)
                status =
                  ssh_public_key_get_info(public_key,
                                           pk->public_key_mp_list[k].pkf,
                                                &a, &b,
                                           SSH_PKF_END);

              if (status != SSH_CRYPTO_OK)
                {
                  SSH_DEBUG(0,
                            ("Could not retrieve information for `%s' "
                             "from public key "
                             "(%s, %d bits): %s",
                             pk->public_key_mp_list[k].name,
                             name, info->sizes[i],
                             ssh_crypto_status_message(status)));
                  return FALSE;
                }

              fprintf(fp, "  ");

              if (pk->public_key_mp_list[k].type == PKF_SINGLE)
                mp_print(fp, pk->public_key_mp_list[k].name, &a);
              else
                mp_print2(fp, pk->public_key_mp_list[k].name, &a, &b);
            }

          fprintf(fp, "  size %d\n", size);
          if (sig_type)
            fprintf(fp, "  signature %s\n", sig_type);
          if (enc_type)
            fprintf(fp, "  encryption %s\n", enc_type);
          fprintf(fp, "public-define\n");
          fprintf(fp, "\n");

          /* Generate test vectors - encryption */
          if (info->encrypt)
            gen_encrypt_vectors(fp, private_key, public_key,
                                ENCRYPT_TEST_VECTORS_N);

          /* Generate test vectors - signature */
          if (info->sign)
            gen_signature_vectors(fp, private_key, SIGNATURE_TEST_VECTORS_N);

          /* Generate test vectors - DH */

          ssh_public_key_free(public_key);
          ssh_private_key_free(private_key);

          fprintf(fp, "\n");
        }

      ssh_free(name);
    }

  fclose(fp);

  ssh_mprz_clear(&a);
  ssh_mprz_clear(&b);

  /* Make the `ssh' rng now the default, since the fake one will drain.. */
  status = ssh_crypto_set_default_rng(true_rng);
  SSH_ASSERT(status == SSH_CRYPTO_OK);

  ssh_buffer_free(fake_rng_bytes);

  fake_rng_bytes = NULL;
  true_rng = fake_rng = NULL;

  return TRUE;
}

/*************************************************************************/


/*  This function checks OAEP test vectors. Test vectors are provided from
 *  RSA and are available at
 *  http://www.rsasecurity.com/rsalabs/rsa_algorithm/index.html
 */

Boolean oaep_static_tests(Boolean verbose)
{
  SshPrivateKey prvkey;
  SshPublicKey pubkey;
  SshMPIntegerStruct e, p, q, n, return_int;
  SshCryptoStatus status;
  Boolean success = FALSE;
  unsigned char random[20], *ciphertext, message[16], *return_str;
  size_t len, ciphertext_len, return_len, message_len = 16;
  const char *e_str = "11";
  const char *p_str =
    "eecfae81b1b9b3c908810b10a1b5600199eb"
    "9f44aef4fda493b81a9e3d84f632124ef0236e5d1e3b7e28"
    "fae7aa040a2d5b252176459d1f397541ba2a58fb6599";
  const char *q_str =
    "c97fb1f027f453f6341233eaaad1d9353f6c"
    "42d08866b1d05a0f2035028b9d869840b41666b42e92ea0d"
    "a3b43204b5cfce3352524d0416a5a441e700af461503";
  const char *encrypted_message_test_vector =
    "0x1253e04dc0a5397bb44a7ab87e9bf2a039a33d1e996fc82a"
    "94ccd30074c95df763722017069e5268da5d1c0b4f872cf6"
    "53c11df82314a67968dfeae28def04bb6d84b1c31d654a19"
    "70e5783bd6eb96a024c2ca2f4a90fe9f2ef5c9c140e5bb48"
    "da9536ad8700c84fc9130adea74e558d51a74ddf85d8b50d"
    "e96838d6063e0955";

  message[0] = 0xd4; message[1] = 0x36; message[2] = 0xe9; message[3] = 0x95;
  message[4] = 0x69; message[5] = 0xfd; message[6] = 0x32; message[7] = 0xa7;
  message[8] = 0xc8; message[9] = 0xa0; message[10]= 0x5b; message[11]= 0xbc;
  message[12]= 0x90; message[13]= 0xd3; message[14]= 0x2c; message[15]= 0x49;

  random[0] = 0xaa;  random[1] = 0xfd;  random[2] = 0x12;  random[3] = 0xf6;
  random[4] = 0x59;  random[5] = 0xca;  random[6] = 0xe6;  random[7] = 0x34;
  random[8] = 0x89;  random[9] = 0xb4;  random[10] = 0x79; random[11] = 0xe5;
  random[12] = 0x07; random[13] = 0x6d; random[14] = 0xde; random[15] = 0xc2;
  random[16] = 0xf0; random[17] = 0x6c; random[18] = 0xb5; random[19] = 0x8f;


  status = ssh_random_allocate("ssh", &true_rng);
  if (status != SSH_CRYPTO_OK) ssh_fatal("Cannot allocate a rng");

  ssh_random_add_light_noise(true_rng);

  status = ssh_random_allocate("pool", &fake_rng);
  if (status != SSH_CRYPTO_OK) ssh_fatal("Cannot allocate a rng");

  /* Set the `fake_rng' as the default RNG */
  status = ssh_crypto_set_default_rng(fake_rng);
  if (status != SSH_CRYPTO_OK) ssh_fatal("Cannot set the default rng");

  feed_fake_rng(NULL, 0);

  ssh_mprz_init(&e);
  ssh_mprz_init(&p);
  ssh_mprz_init(&q);
  ssh_mprz_init(&n);

  if (ssh_mprz_set_str(&e, e_str, 16) == 0)
    ssh_fatal("Cannot set the MP Integer e from the input string.");

  if (ssh_mprz_set_str(&p, p_str, 16) == 0)
    ssh_fatal("Cannot set the MP Integer p from the input string.");

  if (ssh_mprz_set_str(&q, q_str, 16) == 0)
    ssh_fatal("Cannot set the MP Integer q from the input string.");

  ssh_mprz_mul(&n, &p, &q);

  status =
    ssh_private_key_generate(&prvkey,
                             "if-modn{encrypt{rsa-pkcs1v2-oaep}}",
                             SSH_PKF_PUBLIC_E, &e,
                             SSH_PKF_PRIME_P, &p,
                             SSH_PKF_PRIME_Q, &q,
                             SSH_PKF_END);

  if (status != SSH_CRYPTO_OK)
    ssh_fatal("error: private key define failed with status %d.", status);

  /* Derive the public key. */
  if ((status = ssh_private_key_derive_public_key(prvkey, &pubkey))
      != SSH_CRYPTO_OK)
    ssh_fatal("error: Cannot derive a public key, error status %d, status",
	      status);

 ciphertext_len = ssh_public_key_max_encrypt_output_len(pubkey);
 ciphertext = ssh_xmalloc(ciphertext_len);

 feed_fake_rng(random, sizeof(random));
 if ((status = ssh_public_key_encrypt(pubkey,
                                      message, message_len,
                                      ciphertext, ciphertext_len,
                                      &return_len))
     != SSH_CRYPTO_OK)
   ssh_fatal("error: public key encryption failed with status %d.", status);

 status = ssh_random_pool_get_length(fake_rng, &len);
 SSH_ASSERT(status == SSH_CRYPTO_OK && len == 0);
 feed_fake_rng(NULL, 0);

 /* Convert the ciphertext buffer to an integer, and then to a hex string. */
 ssh_mprz_init(&return_int);
 ssh_mprz_set_buf(&return_int, ciphertext, return_len);
 return_str = ssh_mprz_get_str(&return_int, 16);

 /* Compare to the test vector string */
 if (strcmp(return_str, encrypted_message_test_vector))
   {
     success = FALSE;
     SSH_DEBUG(3 ,("ERROR***: The encrypted OAEP message does not agree "
                    "with the test vector.\n\n"
                    "Encrypted buffer as a string is \n%s\n\n"
                    "Expected value from the test vector is \n%s\n",
                    return_str,
                    encrypted_message_test_vector));
   }
 else
   {
     success = TRUE;
     SSH_DEBUG(6,
               ("The encrypted OAEP message agrees with the test vector.\n"));
   }

  /* Set the `true_rng' as the default RNG */
  status = ssh_crypto_set_default_rng(true_rng);
  if (status != SSH_CRYPTO_OK) ssh_fatal("Cannot set the default rng");

  true_rng = fake_rng = NULL;

 ssh_private_key_free(prvkey);
 ssh_public_key_free(pubkey);

 ssh_mprz_clear(&e);
 ssh_mprz_clear(&p);
 ssh_mprz_clear(&q);
 ssh_mprz_clear(&n);
 ssh_mprz_clear(&return_int);
 ssh_free(return_str);
 ssh_free(ciphertext);

 return success;
}

/*  This function checks PSS test vectors. Test vectors are provided from RSA.
 */

struct SshPSSTestVectors {

  char *n;
  char *e;
  char *p;
  char *q;
  char *u;
  char *message;
  char *salt;
  char *message_signature;
};

struct SshPSSTestVectors pss_test_vectors[] = {
  {
    "a2 ba 40 ee 07 e3 b2 bd 2f 02 ce 22 7f 36 a1 95 02 44 86 e4 9c 19 cb 41 "
    "bb bd fb ba 98 b2 2b 0e 57 7c 2e ea ff a2 0d 88 3a 76 e6 5e 39 4c 69 d4 "
    "b3 c0 5a 1e 8f ad da 27 ed b2 a4 2b c0 00 fe 88 8b 9b 32 c2 2d 15 ad d0 "
    "cd 76 b3 e7 93 6e 19 95 5b 22 0d d1 7d 4e a9 04 b1 ec 10 2b 2e 4d e7 75 "
    "12 22 aa 99 15 10 24 c7 cb 41 cc 5e a2 1d 00 ee b4 1f 7c 80 08 34 d2 c6 "
    "e0 6b ce 3b ce 7e a9 a5",

    "0x 01 00 01",

    "d1 7f 65 5b f2 7c 8b 16 d3 54 62 c9 05 cc 04 a2 6f 37 e2 a6 7f a9 c0 ce "
    "0d ce d4 72 39 4a 0d f7 43 fe 7f 92 9e 37 8e fd b3 68 ed df f4 53 cf 00 "
    "7a f6 d9 48 e0 ad e7 57 37 1f 8a 71 1e 27 8f 6b",

    "c6 d9 2b 6f ee 74 14 d1 35 8c e1 54 6f b6 29 87 53 0b 90 bd 15 e0 f1 49 "
    "63 a5 e2 63 5a db 69 34 7e c0 c0 1b 2a b1 76 3f d8 ac 1a 59 2f b2 27 57 "
    "46 3a 98 24 25 bb 97 a3 a4 37 c5 bf 86 d0 3f 2f",

    "a6 3f 1d a3 8b 95 0c 9a d1 c6 7c e0 d6 77 ec 29 14 cd 7d 40 06 2d f4 2a "
    "67 eb 19 8a 17 6f 97 42 aa c7 c5 fe a1 4f 22 97 66 2b 84 81 2c 4d ef c4 "
    "9a 80 25 ab 43 82 28 6b e4 c0 37 88 dd 01 d6 9f",

    "85 9e ef 2f d7 8a ca 00 30 8b dc 47 11 93 bf 55 bf 9d 78 db 8f 8a 67 2b "
    "48 46 34 f3 c9 c2 6e 64 78 ae 10 26 0f e0 dd 8c 08 2e 53 a5 29 3a f2 17 "
    "3c d5 0c 6d 5d 35 4f eb f7 8b 26 02 1c 25 c0 27 12 e7 8c d4 69 4c 9f 46 "
    "97 77 e4 51 e7 f8 e9 e0 4c d3 73 9c 6b bf ed ae 48 7f b5 56 44 e9 ca 74 "
    "ff 77 a5 3c b7 29 80 2f 6e d4 a5 ff a8 ba 15 98 90 fc",

    "e3 b5 d5 d0 02 c1 bc e5 0c 2b 65 ef 88 a1 88 d8 3b ce 7e 61",

    "8d aa 62 7d 3d e7 59 5d 63 05 6c 7e c6 59 e5 44 06 f1 06 10 12 8b aa e8 "
    "21 c8 b2 a0 f3 93 6d 54 dc 3b dc e4 66 89 f6 b7 95 1b b1 8e 84 05 42 76 "
    "97 18 d5 71 5d 21 0d 85 ef bb 59 61 92 03 2c 42 be 4c 29 97 2c 85 62 75 "
    "eb 6d 5a 45 f0 5f 51 87 6f c6 74 3d ed dd 28 ca ec 9b b3 0e a9 9e 02 c3 "
    "48 82 69 60 4f e4 97 f7 4c cd 7c 7f ca 16 71 89 71 23 cb d3 0d ef 5d 54 "
    "a2 b5 53 6a d9 0a 74 7e"
  },

  {
    "a5 6e 4a 0e 70 10 17 58 9a 51 87 dc 7e a8 41 d1 "
    "56 f2 ec 0e 36 ad 52 a4 4d fe b1 e6 1f 7a d9 91 "
    "d8 c5 10 56 ff ed b1 62 b4 c0 f2 83 a1 2a 88 a3 "
    "94 df f5 26 ab 72 91 cb b3 07 ce ab fc e0 b1 df "
    "d5 cd 95 08 09 6d 5b 2b 8b 6d f5 d6 71 ef 63 77 "
    "c0 92 1c b2 3c 27 0a 70 e2 59 8e 6f f8 9d 19 f1 "
    "05 ac c2 d3 f0 cb 35 f2 92 80 e1 38 6b 6f 64 c4 "
    "ef 22 e1 e1 f2 0d 0c e8 cf fb 22 49 bd 9a 21 37 ",

    "01 00 01",

    "e7 e8 94 27 20 a8 77 51 72 73 a3 56 05 3e a2 a1 "
    "bc 0c 94 aa 72 d5 5c 6e 86 29 6b 2d fc 96 79 48 "
    "c0 a7 2c bc cc a7 ea cb 35 70 6e 09 a1 df 55 a1 "
    "53 5b d9 b3 cc 34 16 0b 3b 6d cd 3e da 8e 64 43 ",

    "b6 9d ca 1c f7 d4 d7 ec 81 e7 5b 90 fc ca 87 4a "
    "bc de 12 3f d2 70 01 80 aa 90 47 9b 6e 48 de 8d "
    "67 ed 24 f9 f1 9d 85 ba 27 58 74 f5 42 cd 20 dc "
    "72 3e 69 63 36 4a 1f 94 25 45 2b 26 9a 67 99 fd ",

    "27 15 6a ba 41 26 d2 4a 81 f3 a5 28 cb fb 27 f5 "
    "68 86 f8 40 a9 f6 e8 6e 17 a4 4b 94 fe 93 19 58 "
    "4b 8e 22 fd de 1e 5a 2e 3b d8 aa 5b a8 d8 58 41 "
    "94 eb 21 90 ac f8 32 b8 47 f1 3a 3d 24 a7 9f 4d ",

    "cd c8 7d a2 23 d7 86 df 3b 45 e0 bb bc 72 13 26 "
    "d1 ee 2a f8 06 cc 31 54 75 cc 6f 0d 9c 66 e1 b6 "
    "23 71 d4 5c e2 39 2e 1a c9 28 44 c3 10 10 2f 15 "
    "6a 0d 8d 52 c1 f4 c4 0b a3 aa 65 09 57 86 cb 76 "
    "97 57 a6 56 3b a9 58 fe d0 bc c9 84 e8 b5 17 a3 "
    "d5 f5 15 b2 3b 8a 41 e7 4a a8 67 69 3f 90 df b0 "
    "61 a6 e8 6d fa ae e6 44 72 c0 0e 5f 20 94 57 29 "
    "cb eb e7 7f 06 ce 78 e0 8f 40 98 fb a4 1f 9d 61 "
    "93 c0 31 7e 8b 60 d4 b6 08 4a cb 42 d2 9e 38 08 "
    "a3 bc 37 2d 85 e3 31 17 0f cb f7 cc 72 d0 b7 1c "
    "29 66 48 b3 a4 d1 0f 41 62 95 d0 80 7a a6 25 ca "
    "b2 74 4f d9 ea 8f d2 23 c4 25 37 02 98 28 bd 16 "
    "be 02 54 6f 13 0f d2 e3 3b 93 6d 26 76 e0 8a ed "
    "1b 73 31 8b 75 0a 01 67 d0",


    "de e9 59 c7 e0 64 11 36 14 20 ff 80 18 5e d5 7f "
    "3e 67 76 af",

    "90 74 30 8f b5 98 e9 70 1b 22 94 38 8e 52 f9 71 "
    "fa ac 2b 60 a5 14 5a f1 85 df 52 87 b5 ed 28 87 "
    "e5 7c e7 fd 44 dc 86 34 e4 07 c8 e0 e4 36 0b c2 "
    "26 f3 ec 22 7f 9d 9e 54 63 8e 8d 31 f5 05 12 15 "
    "df 6e bb 9c 2f 95 79 aa 77 59 8a 38 f9 14 b5 b9 "
    "c1 bd 83 c4 e2 f9 f3 82 a0 d0 aa 35 42 ff ee 65 "
    "98 4a 60 1b c6 9e b2 8d eb 27 dc a1 2c 82 c2 d4 "
    "c3 f6 6c d5 00 f1 ff 2b 99 4d 8a 4e 30 cb b3 3c "
  },

  {
    "01 69 34 cd ff 48 50 b6 00 2c c0 f0 f4 01 0a 32 "
    "c6 55 e5 cf 6e 7c 89 93 7f d7 55 ef 6a be 37 9d "
    "ad de 70 cc 21 77 51 f1 4c ba 6d 90 fe 52 dc 0a "
    "f5 8b 25 2f 26 bf 72 da 57 9f da f5 7d dd 6c d6 "
    "02 18 79 94 9a 02 76 b4 43 3f f0 1e fc cc f3 5a "
    "11 e7 c7 7b 38 c1 8c ca 94 ae 01 2d 0f 37 04 21 "
    "49 1c 52 ad 15 ac 76 b1 2e cd 21 8f 52 e7 57 86 "
    "6e 08 9d d8 ad bb 48 e9 ba 89 43 36 c5 75 c4 06 "
    "55" ,

    "01 00 01",

    "01 58 c0 24 6c d1 69 fc 59 3b 25 8b bf 45 23 ab "
    "2b 55 c4 60 73 3a 7f b4 69 10 90 77 b3 0e 4d 35 "
    "f2 1a 35 b1 f4 1e 42 04 e8 1d 2e 4c 46 3c 24 11 "
    "39 34 09 8b 45 2d ab 4b e1 59 97 20 ef 68 72 83 "
    "3d",

    "01 0c 38 2d ea 5e 7d 79 29 8c 64 1f b2 e4 fa 09 "
    "f2 4f 6a 7a 45 9a 88 2c 87 a8 03 49 5f 05 6e cc "
    "3b 43 c5 37 73 1f 85 ef c8 fb 53 87 ad 67 31 a6 "
    "43 53 32 15 de cc 38 7d 96 76 12 2c 17 0e 91 e0 "
    "f9",

    "17 b0 d6 23 36 19 1e 63 bc a1 59 93 4d 06 16 cb "
    "89 97 40 9c bf ca 37 05 69 5b 14 fb 64 a0 81 c1 "
    "c9 f5 86 19 3e 52 3a bd 0b eb 8d 72 0c fe 53 7d "
    "fa 1e de c4 a6 64 37 d2 41 19 6b 7a 2c e5 56 c4 ",

    "35 39 99 7a e7 09 fe 32 c1 03 6a 13 27 57 f2 a1 "
    "66 7a 91 cc 83 be 73 3a ad a1 bd d2 17 92 4c 9a "
    "2c 9f ed 1f ec f6 1d 1c f7 9d ae 9a 83 f8 ae 3f "
    "4d 05 1b 34 fb b5 59 cb fd a4 92 f1 d8 3b 8b eb "
    "a0 45 d4 ae 1c 8f ea 15 b7 57 7a 1b 8a 3f 55 ba "
    "c1 72 7e dc a7 f8 f5 2c b4 ba 61 ca f1 fa 8f 8f "
    "d9 aa c7 79 09 5c a8 4c 79 91 52 9f b8 06 99 d0 "
    "d4 68 8d fd b1 42 ed 61 a9 5b 89 ce 33 06 bf 97 "
    "80 e1 b9 1b 84 8c 8d 20 03 97 0e 52 70 2a 1f 61 "
    "2e 2f 40 17 cf e0 a9 1d b9 e4 6d b9 dc",

    "97 5e b8 58 b6 d7 89 01 d1 3a d4 ea 31 37 6d c7"
    "4c c1 7e 70",

    "01 25 cd 8f 6c b1 46 cb 2c c8 6c 06 19 ba fe 0c "
    "a7 7a 9d c4 f3 33 4a d6 63 cb 7c bf e8 5e 93 08 "
    "72 59 7a a2 85 2d 89 87 c8 6d e5 58 49 86 db 7a "
    "df 65 03 95 70 f7 23 67 0e d8 d7 c9 87 0d eb 22 "
    "a2 f7 ee 91 f0 34 a1 4e 90 f1 b4 00 ef e1 96 7a "
    "66 79 16 54 c1 98 ef e4 f5 ee 33 05 25 25 64 51 "
    "1d f2 9a da 07 49 5c e5 de aa 65 ac 45 da 06 09 "
    "a3 76 dd 48 4c d1 ea 9e 79 90 fc 70 0b df 83 d9 "
    "c8"
  },

  {
    "01 69 34 cd ff 48 50 b6 00 2c c0 f0 f4 01 0a 32 "
    "c6 55 e5 cf 6e 7c 89 93 7f d7 55 ef 6a be 37 9d "
    "ad de 70 cc 21 77 51 f1 4c ba 6d 90 fe 52 dc 0a "
    "f5 8b 25 2f 26 bf 72 da 57 9f da f5 7d dd 6c d6 "
    "02 18 79 94 9a 02 76 b4 43 3f f0 1e fc cc f3 5a "
    "11 e7 c7 7b 38 c1 8c ca 94 ae 01 2d 0f 37 04 21 "
    "49 1c 52 ad 15 ac 76 b1 2e cd 21 8f 52 e7 57 86 "
    "6e 08 9d d8 ad bb 48 e9 ba 89 43 36 c5 75 c4 06 "
    "55" ,

    "01 00 01",

    "01 58 c0 24 6c d1 69 fc 59 3b 25 8b bf 45 23 ab "
    "2b 55 c4 60 73 3a 7f b4 69 10 90 77 b3 0e 4d 35 "
    "f2 1a 35 b1 f4 1e 42 04 e8 1d 2e 4c 46 3c 24 11 "
    "39 34 09 8b 45 2d ab 4b e1 59 97 20 ef 68 72 83 "
    "3d",

    "01 0c 38 2d ea 5e 7d 79 29 8c 64 1f b2 e4 fa 09 "
    "f2 4f 6a 7a 45 9a 88 2c 87 a8 03 49 5f 05 6e cc "
    "3b 43 c5 37 73 1f 85 ef c8 fb 53 87 ad 67 31 a6 "
    "43 53 32 15 de cc 38 7d 96 76 12 2c 17 0e 91 e0 "
    "f9",

    "17 b0 d6 23 36 19 1e 63 bc a1 59 93 4d 06 16 cb "
    "89 97 40 9c bf ca 37 05 69 5b 14 fb 64 a0 81 c1 "
    "c9 f5 86 19 3e 52 3a bd 0b eb 8d 72 0c fe 53 7d "
    "fa 1e de c4 a6 64 37 d2 41 19 6b 7a 2c e5 56 c4 ",

    "d0 db c9 6c f9 bf b1 e3 cd 6d e2 ea a0 8d 6d 79 "
    "5b ed 81 87 ce b0 85 65 80 e4 b1 42 b9 ae 60 a0 "
    "98 cd 42 98 4e 8d bf 1d 05 a0 c0 ab 83 51 54 8f "
    "0a 13 64 6f 33 39 0b 2b b0 c8 64 b3 97 cf 13 37 "
    "1f 8b 2f 67 5a 82 e4 6b f1 6c 4a fc 60 5e e3 e5 "
    "a1 46 9c ac 51 fa 73 4b 44 65 d4 c1 3d 5b 2d d1 "
    "2e ed a5 4e 7d 08 1c d9 e3 ea af 9e 57 db 42 20 "
    "20 a0 b5 a5 ec 28 ca 43 97 7a 5d 67 6f fa b6 2f "
    "78 10 71 93 59 41 59 ce bf bd 86 26 98 19 a0 f3 "
    "41 a0 f4 12 84 dd 0a 73 ca 80 14 d2 e0 b8 01 79 "
    "c6 38 0b 40 3a fb b1 1b 42 db 34 9b af d7 57 0f "
    "be cb d1 4b d0 c2 1a d6 41 68 7a 6a c3 29 25 f7 "
    "03 1a 24 a6 56 8a b9 e2 87 eb 80 75 41 10 df ba "
    "68 8a 59 63 25 bc ac 4a 39 ce 8b 84 a4 ",

    "67 4b 07 a5 42 40 d7 d9 97 3a b2 de ca 9a 3a 02 "
    "e4 13 45 1f ",

    "00 7a 1a a3 8d ea 95 ea a6 88 81 4a 91 f5 33 4e "
    "17 a2 15 d7 b7 e1 a0 33 08 03 11 57 f4 38 5b 68 "
    "32 5e 6d 51 6f 90 1b 92 e8 ce 39 c7 9f 27 97 0b "
    "49 d6 76 4c f7 b3 2a 68 c3 d2 66 7a 98 07 d4 56 "
    "de 22 1c 32 3d 26 d0 e3 e2 cd a4 28 16 b6 21 e6 "
    "8b e9 ae 07 9c 1e a9 c8 90 6d 9e e9 7e 16 ae a1 "
    "5c 27 e6 a6 94 0b e8 6b 76 5d 69 e4 fe 02 06 aa "
    "a5 38 3b b7 bf df 70 34 ac 15 f6 e5 69 2d a0 ac "
    "ac "
  },

  {
      "36 98 1a 95 ae 24 18 14 52 da 25 7c 03 8f 05 82 "
      "14 12 d8 4e b4 7a 43 fc c7 ef 12 17 95 9b a6 77 "
      "02 7f 70 86 d3 a8 5c dd 34 9f 92 0f 03 4c 02 78 "
      "79 2d c8 a8 cf 0c 00 80 e5 c6 1f 47 48 83 c6 87 "
      "9f 4d ee 0a e9 52 47 8a 5e e2 ce 4e 39 18 64 1e "
      "81 3c b3 74 f7 b2 83 2b cd 6a ea 80 9d 25 4f c2 "
      "ca 9a c5 a3 32 42 4a b6 5c 2a 26 12 75 d1 9a 41 "
      "4b 61 65 00 d5 e3 73 70 63 15 f0 63 dc 88 5d 7f "
      "b9 ",

      "01 00 01 ",

      "07 72 0f 21 cd db 92 27 45 b7 1c f8 11 6a 83 66 "
      "9a 0d db 89 e8 f3 f0 6c 34 7c a7 87 cf 10 ef 16 "
      "93 bd fe 3a 0c 36 4c 7a 7e 89 04 17 f2 af 49 47 "
      "5c 7d 07 6f 9c ee aa e7 6d bd 4e 92 15 af 45 69 "
      "4d ",

      "07 55 1c 27 e9 aa f1 1f 47 4f 1c 9a 14 bf 14 4c "
      "fa ef e2 7f ca 4f 20 79 5d ec 85 34 c9 37 bb 00 "
      "fe 16 23 5e cd 69 1f d2 3e 32 cd fb 8b 78 66 6b "
      "b7 82 84 ae 15 d5 9b e5 ca 74 73 e6 2d 46 a9 da "
      "1d ",

      "06 d2 27 72 57 42 ef 03 46 2d 1c f6 12 67 4a 78 "
      "83 1d 61 9d a3 d6 40 eb 7c 71 c8 7b 53 28 69 72 "
      "73 c5 f7 51 e1 4d 7b 81 c1 2b 6d eb 44 75 1a 92 "
      "95 cb 67 1e 81 48 4d ea a8 3b 4d f1 fd 37 e2 ff "
      "3c ",

      "e4 b2 d6 0e 3b dd 27 81 6f" ,

      "ac 02 b3 ca 61 ed 83 1a 0b 9b 19 4d 47 2b a7 4c "
      "61 27 e1 c5 ",

      "2e b1 ca 14 03 8b 57 ca 05 96 2e 7b d9 d3 89 45 "
      "0d 97 7f 87 0f d0 72 b8 eb 97 a9 f6 c6 81 ec b1 "
      "15 fd 96 44 fd 60 f8 23 58 30 fd a0 e8 23 c7 4a "
      "54 79 70 29 0e df fa 2b bd 64 e2 78 02 f2 e2 1b "
      "a2 43 c1 92 bf ba 4d 7c db 09 64 b3 61 36 0f f4 "
      "d2 be 2d bc 09 fd 7b 6f 50 ae e5 22 c1 b2 4d 6d "
      "32 0a 17 99 ce da 31 42 10 45 3c 8d 27 f9 ed fa "
      "20 b6 51 50 73 d0 27 50 d5 13 27 d8 fd 51 ba b7 "
      "c2 "
  },

  {
    "36 98 1a 95 ae 24 18 14 52 da 25 7c 03 8f 05 82 "
    "14 12 d8 4e b4 7a 43 fc c7 ef 12 17 95 9b a6 77 "
    "02 7f 70 86 d3 a8 5c dd 34 9f 92 0f 03 4c 02 78 "
    "79 2d c8 a8 cf 0c 00 80 e5 c6 1f 47 48 83 c6 87 "
    "9f 4d ee 0a e9 52 47 8a 5e e2 ce 4e 39 18 64 1e "
    "81 3c b3 74 f7 b2 83 2b cd 6a ea 80 9d 25 4f c2 "
    "ca 9a c5 a3 32 42 4a b6 5c 2a 26 12 75 d1 9a 41 "
    "4b 61 65 00 d5 e3 73 70 63 15 f0 63 dc 88 5d 7f "
    "b9 ",

    "01 00 01 ",

    "07 72 0f 21 cd db 92 27 45 b7 1c f8 11 6a 83 66 "
    "9a 0d db 89 e8 f3 f0 6c 34 7c a7 87 cf 10 ef 16 "
    "93 bd fe 3a 0c 36 4c 7a 7e 89 04 17 f2 af 49 47 "
    "5c 7d 07 6f 9c ee aa e7 6d bd 4e 92 15 af 45 69 "
    "4d ",

    "07 55 1c 27 e9 aa f1 1f 47 4f 1c 9a 14 bf 14 4c "
    "fa ef e2 7f ca 4f 20 79 5d ec 85 34 c9 37 bb 00 "
    "fe 16 23 5e cd 69 1f d2 3e 32 cd fb 8b 78 66 6b "
    "b7 82 84 ae 15 d5 9b e5 ca 74 73 e6 2d 46 a9 da "
    "1d ",

    "06 d2 27 72 57 42 ef 03 46 2d 1c f6 12 67 4a 78 "
    "83 1d 61 9d a3 d6 40 eb 7c 71 c8 7b 53 28 69 72 "
    "73 c5 f7 51 e1 4d 7b 81 c1 2b 6d eb 44 75 1a 92 "
    "95 cb 67 1e 81 48 4d ea a8 3b 4d f1 fd 37 e2 ff "
    "3c ",

    "08 4e c2 87 86 5e 8f e6 88 04 72 37 20 97 ad 5b "
    "96 4c 40 a9 35 ee d1 be a5 1a b1 b5 bc 75 c8 46 "
    "bb cb d9 54 88 e9 ec c3 63 cf 07 3a 90 b2 0b e8 "
    "b6 79 36 46 22 f3 45 e1 22 d0 56 6a cd 34 a4 ae "
    "11 24 45 25 a3 8f 47 dc 1f 92 b1 7f 89 ed e0 6d "
    "83 6b 44 26 ec bb ea 79 33 ac 0e 84 7e 55 10 33 "
    "b5 f7 ea 4e af 1f 63 f3 47 9d b7 ea f8 02 c9 96 "
    "de 92 33 86 cd 15 b1 22 de 5a 23 98 d3 f3 97 02 "
    "c3 e9 06 5c 32 73 95 b9 a9 95 fa 25 4d e9 c7 ad "
    "b4 51 ",

    "ae f9 e8 d6 59 2d d5 7f 9d c6 90 ae c4 8a 6e 39 "
    "fa 8f 65 b7 ",

    "19 4a d7 7e db c7 1c 0e fe 4d f2 01 63 a1 b4 21 "
    "7a 23 f5 0f 79 d1 ff bc 97 9b 1f b6 78 94 21 49 "
    "9f 1d 28 ed b0 89 5c f8 07 1a b1 69 02 bc ad c6 "
    "71 5e e1 e1 f8 42 27 88 48 36 6c 4c a6 38 56 2b "
    "fc 0e 64 26 66 56 e4 c0 0c 54 33 a8 cb 7b 77 08 "
    "e3 13 dc d3 dd 02 cb ad 52 57 b8 cd 5d fd 82 ac "
    "4c d1 10 42 f0 a5 b0 c5 0c c8 08 7e de 1b 32 0a "
    "ee f2 e8 e6 e0 bf 45 72 26 c5 10 4e 21 27 43 4e "
    "91 "
  },

  {
    "70 e9 23 a5 a0 cd 8e cd f9 9b be 93 d7 d0 28 82 "
    "95 5d 91 b6 ef e3 ce c8 6c 93 d2 1c 0a c3 01 b8 "
    "29 3e 51 43 5b 87 8b c6 b3 4b ed 41 11 59 0e 76 "
    "46 76 58 8b 11 6c 2a 36 a4 c7 7e d9 c9 0a 13 c1 "
    "4d 23 e1 99 47 87 fc db 8f 5c 97 41 0f ca d4 04 "
    "5b 85 85 70 2c ce 29 da 11 f9 7e 79 a9 7c 2e 5f "
    "6a 5f c0 bb 8c e7 6d 15 54 a8 bc 47 96 17 20 d3 "
    "64 05 0b f2 74 19 bf f1 68 c0 a7 ec c8 73 4c b5 "
    "a5 ",

    "01 00 01 ",

    "0a b4 64 fd 6f e3 3c 45 9a b2 dc ce 5f 78 a4 d7 "
    "4f 92 b9 97 d4 bf 54 2e 2d 85 4e 76 2c 85 86 fc "
    "43 57 cc 58 cb 33 36 33 b0 95 a5 ee 04 a0 32 48 "
    "53 64 d7 0f 67 a3 aa 04 85 4c 7a 87 a6 9c f4 c2 "
    "ad ",

    "0a 8c 3c c5 04 13 40 f4 32 fe 0a 78 73 13 57 79 "
    "16 fe 76 c0 39 f9 71 75 9e c5 0e d6 c5 b9 a7 36 "
    "9b 68 96 9e cb 52 59 fe 9c 50 d0 75 9b f8 b3 aa "
    "c1 a5 d5 b5 28 8d 67 89 e7 18 fa 37 ef 42 39 95 "
    "d9 ",

    "a8 8b f3 ff e9 3f 40 4e 06 82 1c 97 71 ea e6 08 "
    "15 71 2d 6f 94 52 71 f6 f3 6f 03 69 d9 66 c9 20 "
    "c7 f8 cb c7 84 25 ac bb 9c e0 fa 1a 03 22 f5 0c "
    "97 b8 11 5b d1 51 91 f2 24 b5 68 d1 d6 ec a6 db ",

    "b5 e8 6c 8b a3 98 5a a5 54 1d f9 5e 51 3c ff 67 "
    "61 2e af 2e 16 68 85 76 f7 d6 73 f6 f1 89 1f b7 "
    "5c 9d d2 cd ",

    "53 fa 97 fc a3 de 9d cb ff 3f cd 16 de b0 45 8e "
    "9b b2 22 92 ",


    "1f fd af 95 8d 26 ee 98 f8 b6 89 ae 84 4d 36 4c "
    "b5 e3 b8 e1 34 a8 2d 06 5f be 6f c5 94 8f ed fc "
    "80 c0 80 90 20 6e 2b f0 41 d0 7d c9 df 2b ec 59 "
    "6a ff 09 3e f8 b1 bd 6e f5 63 e3 2a b5 e1 e3 14 "
    "e5 d9 be 9b 91 a5 df 37 36 d6 d5 81 d0 0a a8 a9 "
    "06 0f 1e 82 dc 84 61 f6 ec a1 87 37 e4 a4 22 f6 "
    "01 eb 2e 18 bb b7 eb 85 f8 b8 7b 48 aa b0 52 33 "
    "02 13 f3 b1 3a 4c c0 74 72 fd 49 0b b0 b0 52 b9 "
    "0f "
  },

  {
    "70 e9 23 a5 a0 cd 8e cd f9 9b be 93 d7 d0 28 82 "
    "95 5d 91 b6 ef e3 ce c8 6c 93 d2 1c 0a c3 01 b8 "
    "29 3e 51 43 5b 87 8b c6 b3 4b ed 41 11 59 0e 76 "
    "46 76 58 8b 11 6c 2a 36 a4 c7 7e d9 c9 0a 13 c1 "
    "4d 23 e1 99 47 87 fc db 8f 5c 97 41 0f ca d4 04 "
    "5b 85 85 70 2c ce 29 da 11 f9 7e 79 a9 7c 2e 5f "
    "6a 5f c0 bb 8c e7 6d 15 54 a8 bc 47 96 17 20 d3 "
    "64 05 0b f2 74 19 bf f1 68 c0 a7 ec c8 73 4c b5 "
    "a5 ",

    "01 00 01 ",

    "0a b4 64 fd 6f e3 3c 45 9a b2 dc ce 5f 78 a4 d7 "
    "4f 92 b9 97 d4 bf 54 2e 2d 85 4e 76 2c 85 86 fc "
    "43 57 cc 58 cb 33 36 33 b0 95 a5 ee 04 a0 32 48 "
    "53 64 d7 0f 67 a3 aa 04 85 4c 7a 87 a6 9c f4 c2 "
    "ad ",

    "0a 8c 3c c5 04 13 40 f4 32 fe 0a 78 73 13 57 79 "
    "16 fe 76 c0 39 f9 71 75 9e c5 0e d6 c5 b9 a7 36 "
    "9b 68 96 9e cb 52 59 fe 9c 50 d0 75 9b f8 b3 aa "
    "c1 a5 d5 b5 28 8d 67 89 e7 18 fa 37 ef 42 39 95 "
    "d9 ",

    "a8 8b f3 ff e9 3f 40 4e 06 82 1c 97 71 ea e6 08 "
    "15 71 2d 6f 94 52 71 f6 f3 6f 03 69 d9 66 c9 20 "
    "c7 f8 cb c7 84 25 ac bb 9c e0 fa 1a 03 22 f5 0c "
    "97 b8 11 5b d1 51 91 f2 24 b5 68 d1 d6 ec a6 db ",

    "40 31 e0 de f4 f3 d1 ad 9b c0 82 77 0a 88 a1 d9 "
    "b4 b7 10 75 48 cd f8 46 2b 0b ae 3d 99 4d 8e bc "
    "4d a0 44 b9 05 dd 8e d9 1a 1d a6 76 72 78 22 36 "
    "0e e2 b6 d5 e1 2b b7 03 16 d7 9e 8a bb 82 a6 43 "
    "44 af b3 b2 25 88 5c ",

    "c9 28 98 cd 21 63 a2 80 2e bd be c7 74 29 35 5a "
    "cc a0 89 1a ",

    "13 e5 05 8d cb 4d 67 9c d7 ce ff cd 2a 6a fa 09 "
    "f2 21 78 9c 08 a5 78 54 67 8c 31 bc 2d 8f f4 d5 "
    "c4 0c 21 68 53 39 9e ec 90 68 87 e1 75 2f ad 2d "
    "1d 5d 5b 0c c3 d4 a2 29 22 90 91 fb 6c 24 09 86 "
    "ad 5e cf 4d 22 21 a7 0f de 19 ea 8b 4c 00 26 b3 "
    "97 80 a8 6b 7b b2 0c ef f8 be 12 29 e1 b1 09 9c "
    "95 e9 54 a4 2e 78 1b 6d 0d 47 c9 82 4a 34 ee af "
    "0d bb f2 29 81 45 42 7d 48 89 ad 1f 1e 78 4f 2c "
    "3f "
  },

  {NULL}
};


Boolean pss_static_tests(Boolean verbose)
{
  SshPrivateKey prvkey;
  SshPublicKey pubkey;
  SshMPIntegerStruct e, p, q, n, d, u, op1, op2;
  SshCryptoStatus status;
  Boolean success = FALSE;
  unsigned char *signature_test_vector, *signature, *message, *salt;
  size_t i, len, signature_len, return_len, salt_len, message_len;
  char *e_str, *n_str, *p_str, *q_str, *u_str, *message_str, *salt_str;

  ssh_mprz_init(&e);
  ssh_mprz_init(&p);
  ssh_mprz_init(&q);
  ssh_mprz_init(&n);
  ssh_mprz_init(&d);
  ssh_mprz_init(&u);
  ssh_mprz_init(&op1);
  ssh_mprz_init(&op2);

  status = ssh_random_allocate("ssh", &true_rng);
  if (status != SSH_CRYPTO_OK) ssh_fatal("Cannot allocate a rng");

  ssh_random_add_light_noise(true_rng);

  status = ssh_random_allocate("pool", &fake_rng);
  if (status != SSH_CRYPTO_OK) ssh_fatal("Cannot allocate a rng");

  /* Set the `fake_rng' as the default RNG */
  status = ssh_crypto_set_default_rng(fake_rng);
  if (status != SSH_CRYPTO_OK) ssh_fatal("Cannot set the default rng");

  for (i = 0; i < (sizeof(pss_test_vectors)/sizeof(pss_test_vectors[0])) - 1;
       i++)
    {
      e_str = pss_test_vectors[i].e;
      n_str = pss_test_vectors[i].n;
      p_str = pss_test_vectors[i].p;
      q_str = pss_test_vectors[i].q;
      u_str = pss_test_vectors[i].u;
      salt_str = pss_test_vectors[i].salt;
      message_str = pss_test_vectors[i].message;
      signature_test_vector = pss_test_vectors[i].message_signature;

      feed_fake_rng(NULL, 0);

      if (ssh_mprz_set_str(&e, e_str, 16) == 0)
	ssh_fatal("Cannot set the MP Integer e from the input string.");
      if (ssh_mprz_set_str(&p, p_str, 16) == 0)
	ssh_fatal("Cannot set the MP Integer p from the input string.");
      if (ssh_mprz_set_str(&q, q_str, 16) == 0)
	ssh_fatal("Cannot set the MP Integer q from the input string.");
      if (ssh_mprz_set_str(&n, n_str, 16) == 0)
	ssh_fatal("Cannot set the MP Integer n from the input string.");
      if (ssh_mprz_set_str(&u, u_str, 16) == 0)
	ssh_fatal("Cannot set the MP Integer q from the input string.");

      if (ssh_mprz_set_str(&op1, message_str, 16) == 0)
	ssh_fatal("Cannot set the Message from the input string.");
      message_len = ssh_mprz_byte_size(&op1);
      message = ssh_xmalloc(message_len);
      ssh_mprz_get_buf(message, message_len, &op1);

      if (ssh_mprz_set_str(&op1, salt_str, 16) == 0)
	ssh_fatal("Cannot set the Salt from the input string.");
      salt_len = ssh_mprz_byte_size(&op1);
      salt = ssh_xmalloc(salt_len);
      ssh_mprz_get_buf(salt, salt_len, &op1);

      /* Set d */
      ssh_mprz_sub_ui(&op1, &p, 1);
      ssh_mprz_sub_ui(&op2, &q, 1);
      ssh_mprz_mul(&op1, &op1, &op2);

      SSH_VERIFY(ssh_mprz_mod_invert(&d, &e, &op1) == 1);

      status =
	ssh_private_key_define(&prvkey,
			       "if-modn{sign{rsa-pss-sha1}}",
			       SSH_PKF_PRIME_P, &q, /* p and q are swapped */
			       SSH_PKF_PRIME_Q, &p, /* p and q are swapped */
			       SSH_PKF_MODULO_N, &n,
			       SSH_PKF_PUBLIC_E, &e,
			       SSH_PKF_INVERSE_U, &u,
			       SSH_PKF_SECRET_D, &d,
			       SSH_PKF_END);

      if (status != SSH_CRYPTO_OK)
	ssh_fatal("error: private key define (test %d) failed with status %s",
		  i, ssh_crypto_status_message(status));

      /* Derive the public key. */
      if ((status = ssh_private_key_derive_public_key(prvkey, &pubkey))
	  != SSH_CRYPTO_OK)
	ssh_fatal("error: Cannot derive a public key, error status %s",
		  ssh_crypto_status_message(status));

      signature_len = ssh_private_key_max_signature_output_len(prvkey);

      SSH_DEBUG(10, ("The max signature return length is %d", signature_len));

      signature = ssh_xcalloc(1, signature_len);

      feed_fake_rng(salt, salt_len);
      if ((status = ssh_private_key_sign(prvkey,
					 message, message_len,
					 signature, signature_len,
					 &return_len))
	  != SSH_CRYPTO_OK)
	ssh_fatal("error: private key signature failed with status %d.",
		  status);

      status = ssh_random_pool_get_length(fake_rng, &len);
      SSH_ASSERT(status == SSH_CRYPTO_OK && len == 0);
      feed_fake_rng(NULL, 0);

      ssh_mprz_clear(&op1);
      ssh_mprz_init(&op1);

      if (ssh_mprz_set_str(&op1, pss_test_vectors[i].message_signature, 16)
	  == 0)
	ssh_fatal("Cannot set the Message signature from the input string.");

      SSH_ASSERT(return_len >= ssh_mprz_byte_size(&op1));
      signature_test_vector = ssh_xcalloc(1, return_len);
      ssh_mprz_get_buf(signature_test_vector, return_len, &op1);

      /* Compare to the test vector string */
      if (memcmp(signature, signature_test_vector, return_len))
	{
	  success = FALSE;
	  SSH_DEBUG(3 ,("ERROR***:The PSS %d message signature does not agree "
			"with the test vector.\n\n", i));
	  SSH_DEBUG_HEXDUMP(3, ("Computed Signature"),
			    signature, return_len);
	  SSH_DEBUG_HEXDUMP(3, ("Expected Signature"),
			    signature_test_vector, return_len);
	}
      else
	{
	  success = TRUE;
	  SSH_DEBUG(6, ("The signed PSS message agrees with the test vector"));
	}

      status = ssh_public_key_verify_signature(pubkey,
					       signature, return_len,
					       message, message_len);
      if (status != SSH_CRYPTO_OK)
	{
	  SSH_DEBUG(3, ("Public key verification over the message fails"));
	  success = FALSE;
	}
      
      message[0] = message[0]+1;

      status = ssh_public_key_verify_signature(pubkey,
					       signature, return_len,
					       message, message_len);
      if (status == SSH_CRYPTO_OK)
	{
	  SSH_DEBUG(3,
		    ("Public key verification over modified message success"));
	  success = FALSE;
	}

      ssh_private_key_free(prvkey);
      ssh_public_key_free(pubkey);
      ssh_xfree(salt);
      ssh_xfree(message);
      ssh_xfree(signature);
      ssh_xfree(signature_test_vector);

      if (!success)
	{
	  SSH_DEBUG(SSH_D_ERROR, ("Test failed, quitting now."));
	  goto quit;
	}
   }

 quit:

  /* Set the `true_rng' as the default RNG */
  status = ssh_crypto_set_default_rng(true_rng);
  if (status != SSH_CRYPTO_OK) ssh_fatal("Cannot set the default rng");

  true_rng = fake_rng = NULL;

 ssh_mprz_clear(&e);
 ssh_mprz_clear(&p);
 ssh_mprz_clear(&q);
 ssh_mprz_clear(&n);
 ssh_mprz_clear(&d);
 ssh_mprz_clear(&u);
 ssh_mprz_clear(&op1);
 ssh_mprz_clear(&op2);
 return success;
}


 /*************************************************************************/

/*

  Test vectors for the DSS (Digital Signature Standard). The test
  vectors were generated by NIST and are avaliable from
  Digital Signature Standard Validation System (DSSVS) User's Guide
  at http://csrc.nist.gov/cryptval/dss/dsaug23.htm.
*/



static int hex_char_to_int(int ch)
{
  switch (ch)
    {
    case '0':    return 0;    /*NOTREACHED*/
    case '1':    return 1;    /*NOTREACHED*/
    case '2':    return 2;    /*NOTREACHED*/
    case '3':    return 3;    /*NOTREACHED*/
    case '4':    return 4;    /*NOTREACHED*/
    case '5':    return 5;    /*NOTREACHED*/
    case '6':    return 6;    /*NOTREACHED*/
    case '7':    return 7;    /*NOTREACHED*/
    case '8':    return 8;    /*NOTREACHED*/
    case '9':    return 9;    /*NOTREACHED*/
    case 'A':    return 10;   /*NOTREACHED*/
    case 'a':    return 10;   /*NOTREACHED*/
    case 'B':    return 11;   /*NOTREACHED*/
    case 'b':    return 11;   /*NOTREACHED*/
    case 'C':    return 12;   /*NOTREACHED*/
    case 'c':    return 12;   /*NOTREACHED*/
    case 'D':    return 13;   /*NOTREACHED*/
    case 'd':    return 13;   /*NOTREACHED*/
    case 'E':    return 14;   /*NOTREACHED*/
    case 'e':    return 14;   /*NOTREACHED*/
    case 'F':    return 15;   /*NOTREACHED*/
    case 'f':    return 15;   /*NOTREACHED*/
    default:     return -1;   /*NOTREACHED*/
    }
  /*NOTREACHED*/;
}

static Boolean hex_string_to_data(const char *str,
                                  unsigned char **data,
                                  size_t *data_len)
{
  size_t str_len, buf_len;
  unsigned char *buf;
  int i, ch, cl;

  str_len = strlen(str);
  if ((str_len == 0) || ((str_len % 2) != 0))
    return FALSE;
  buf_len = str_len / 2;
  buf = ssh_xmalloc(buf_len);
  for (i = 0; i < buf_len; i++)
    {
      ch = hex_char_to_int(str[i * 2]);
      cl = hex_char_to_int(str[(i * 2) + 1]);
      if ((ch >= 0) && (cl >= 0))
        {
          buf[i] = (unsigned char)(ch * 16 + cl);
        }
      else
        {
          ssh_xfree(buf);
          return FALSE;
        }
    }
  if (data)
    *data = buf;
  else
    ssh_xfree(buf);
  if (data_len)
    *data_len = buf_len;
  return TRUE;
}


typedef struct DssGroupDataRec {
  const char *p;
  const char *q;
  const char *g;
  const char *seed;
  unsigned int size;
  unsigned int counter;
} *DssGroupData, DssGroupDataStruct;


static DssGroupDataStruct dss_groups[] = {
  { "0x824c1c23066aeafa74b40cbfcb2ffd47baed14e5edc3c929f81e2b2fbdfec"
    "178939b8aebac70869e4ead77653ec497837ea1a201f878fc72ec609eb66eed3a9b",
    "0xe4b5d099504cf0f208ad237b1c3af79f31cf19bf",
    "0x493509dd3f575e14306aa5a3106c14dd528f2966d9dc8d2136a1b39f9ce87d5"
    "33bc756cab9faf27a828202845d44401ba453db62a28c02b42910c64fa1a9e3f2",
    "4b5f92cfde7822b28dfe1c264ec085a3b7df82ed",
    512, 123},

  { "0xfa78f57cbbfd802d1fcb743eed0cabf2648bee5d89e5b067ad8c64c55ff0b3"
    "c2f755b60a5340fbccb23c0adc8158724ec8dcd580f8c4c16f8d924c5bc1ae76cb",
    "0xbf4dc8f35bc250d2f8d95f36c95841b2616f0533",
    "0x7b669fa6609e12fab02e810a494e49db20b9bf24aa7765d5f6ac100a4801d1d"
    "667c11a7a77ea7c0cd0ec83b9ab844bc3d9a3c5d8910019ecdd2b1c8691649f7f",
    "4b5f92cfde7822b28dfe1c264ec085a3b7df8311",
    512, 109},

  { "0xabbb6aa9760c7f3671c013c1c712a2ac907f5924ebf7e3a3892c911126386428785"
    "0c585253d807654923184d7e47745ebbf001f1eac5fce88d13bc564d126a56cbff89b"
    "ddc28d69f1a00013c6bf5a63141cabadaff1850cebc0c50d40b19581",
    "0xdbd8daaacc4f27fc05508757259e27e975bfdc2f",
    "0x9ed9ab75abe9450372b95843df66a006a50097c4b6563f377882a3d8bede1b4b7fe"
    "055cf4ee62c6bc3f977ed0553a9953c21bd4901be016a4b7558311e2c409e7ad6cf66"
    "6a06f217c531a1757adb4669b2e0da82a0903d71deed11632ef131ca",
    "d5014e4b60ef2ba8b6211b4062ba3224e0427eea",
    768, 162},

  { "0xd035088552dbae1ed41fe0374471511b6b190ce1b3b1b79b5d1faf0f11ee876e02a9f"
    "66442b4694649d75cf8185908cf2ac5bda8e49aeab90f0c530ba5643b85fbca7cf3dfbb"
    "b85e572421d4123150daa05f974d38b8a0776eb0da7176601861",
    "0xe2867218b7a25fd993d0178a1b0a1ab7bfae3cd1",
    "0x9248ea5f6f59bf5c114925ad7c53ce2985c9f4c25255dd8be092932f99f950499158e"
    "d448f99e61de21ed4935e85604c412c8d88bf1f663ed5bb7f3a04ff498ccb9121007850"
    "bf46fa38cf35105e1d7fdd25c6e70352b911eb85b91f1cbcac3b",
    "c5cc4392f040af1521d166afbad4b75bf634b0e2",
    768, 153},

  { NULL }
};


Boolean dss_group_generation_test_vectors(void)
{
  DssGroupData group_data;
  SshCryptoStatus status;
  SshMPIntegerStruct p, q, g;
  Boolean failed = FALSE;
  unsigned char *seed;
  size_t seedlen;
  unsigned char random[1024];
  char *p_str, *q_str, *g_str;
  int i;

  ssh_mprz_init(&p);
  ssh_mprz_init(&q);
  ssh_mprz_init(&g);

  for (group_data = dss_groups; group_data->p; group_data++)
    {
      if (!hex_string_to_data(group_data->seed, &seed, &seedlen))
        ssh_fatal("Invalid input string.");

      memcpy(random, seed, seedlen);

      /* We need extra randomness besides that needed for the key
         generation because the self tests performed after key
         generation require random data. So we insert randomness for
         this to the 'random' buffer after the 'xkey' buffer. */
      for (i = seedlen; i < sizeof(random); i++)
        random[i] = ssh_random_get_byte();

      feed_fake_rng(random, sizeof(random));
      ssh_free(seed);

      status = ssh_mp_fips186_random_strong_prime(&p, &q,
                                                  group_data->size, 160);

      if (status != SSH_CRYPTO_OK)
        ssh_fatal("Group generation failed with status %d.", status);


      /* This assertion is not valid here for obvious reasons. */
#if 0
      ssh_random_pool_get_length(fake_rng, &len);
      SSH_ASSERT(len == 0);
#endif

      feed_fake_rng(NULL, 0);

      if (!ssh_mprz_random_generator(&g, &q, &p))
        ssh_fatal("Unable to derive a generator for the group.");

      p_str= ssh_mprz_get_str(&p, 16);
      q_str= ssh_mprz_get_str(&q, 16);
      g_str= ssh_mprz_get_str(&g, 16);

      if (strcmp(p_str, group_data->p))
        {
          printf("The generated prime p is not valid: \n"
                 "test vector : %s\ngenerated   : %s\n",
                 group_data->p, p_str);
          failed = TRUE;
        }

      if (strcmp(q_str, group_data->q))
        {
          printf("The generated prime q is not valid: \n"
                 "test vector :%s\ngenerated   :%s\n",
                 group_data->q, q_str);
          failed = TRUE;
        }

      /* This test is valid because all test vectors in the DSSVS users guide
         have h = 2, so our method of generating g is identical to the
         DSSVS one.*/
      if (strcmp(g_str, group_data->g))
        {
          printf("The group generator may not be valid: \n"
                 "test vector :%s\ngenerated   :%s\n",
                 group_data->g, g_str );
          failed = TRUE;
        }
      ssh_free(p_str);
      ssh_free(q_str);
      ssh_free(g_str);

    }

  ssh_mprz_clear(&p);
  ssh_mprz_clear(&q);
  ssh_mprz_clear(&g);

  if (failed)
    return FALSE;

  return TRUE;
}

typedef struct DssKeyDataRec {
  const char *p;
  const char *q;
  const char *g;
  const char *xkey;
  const char *x;
  const char *y;
  unsigned int size;
} *DssKeyData, DssKeyDataStruct;

static DssKeyDataStruct dss_keys[] = {
  {"0x8df2a494492276aa3d25759bb06869cbeac0d83afb8d0cf7cbb8324f0d7882e5d0"
   "762fc5b7210eafc2e9adac32ab7aac49693dfbf83724c2ec0736ee31c80291",
   "0xc773218c737ec8ee993b4f2ded30f48edace915f",
   "0x626d027839ea0a13413163a55b4cb500299d5522956cefcb3bff10f399ce2c2e71"
   "cb9de5fa24babf58e5b79521925c9cc42e9f6f464b088cc572af53e6d78802",
   "1234567890123456789012345678901234567890",
   "0x436f11fbb83ab498016c4942152a83c0090934a2",
   "0x40674ed26c82283993aa09e6081e629b668ed113b793d593b9fb39db4a550a17e0"
   "ffb421be4cf913ff0c68c66e90ed5b8f2cd9469f31d2e0f60e76e2226d18c9",
   512 },

  { NULL }
};


Boolean dss_key_generation_test_vectors(void)
{
  DssKeyData key_data;
  SshCryptoStatus status;
  SshPrivateKey prvkey;
  SshMPIntegerStruct p, q, g, x, y, aux1, aux2;
  Boolean failed = FALSE;
  char *x_str, *y_str;
  unsigned char *xkey;
  size_t xkeylen;
  unsigned char random[1024];
  int i;

  ssh_mprz_init(&p);
  ssh_mprz_init(&q);
  ssh_mprz_init(&g);
  ssh_mprz_init(&x);
  ssh_mprz_init(&y);
  ssh_mprz_init(&aux1);
  ssh_mprz_init(&aux2);

  for (key_data = dss_keys; key_data->p; key_data++)
    {

      if (!hex_string_to_data(key_data->xkey, &xkey, &xkeylen))
        ssh_fatal("Invalid input string.");

      SSH_ASSERT(xkeylen == 20);

      memcpy(random, xkey, xkeylen);

      /* We need extra randomness besides that needed for the key
         generation because the self tests performed after key
         generation require random data. So we insert randomness for
         this to the 'random' buffer after the 'xkey' buffer. */
      for (i = xkeylen; i < sizeof(random); i++)
        random[i] = ssh_random_get_byte();

      feed_fake_rng(random, sizeof(random));
      ssh_free(xkey);

      ssh_mprz_set_str(&p, key_data->p, 16);
      ssh_mprz_set_str(&q, key_data->q, 16);
      ssh_mprz_set_str(&g, key_data->g, 16);

      /* Verify that g^q mod p = 1 */
      ssh_mprz_powm(&aux1, &g, &q, &p);
      SSH_ASSERT(ssh_mprz_cmp_ui(&aux1, 1) == 0);

      status =
        ssh_private_key_generate(&prvkey,
                                 "dl-modp{sign{dsa-nist-sha1}}",
                                 SSH_PKF_PRIME_P, &p,
                                 SSH_PKF_PRIME_Q, &q,
                                 SSH_PKF_GENERATOR_G, &g,
                                 SSH_PKF_END);

      if (status != SSH_CRYPTO_OK)
        ssh_fatal("Key generation failed with status %d.", status);


      /* This assertion is not valid here for obvious reasons. */
#if 0
      ssh_random_pool_get_length(fake_rng, &len);
      SSH_ASSERT(len == 0);
#endif

      feed_fake_rng(NULL, 0);

      status = ssh_private_key_get_info(prvkey,
                                        SSH_PKF_SECRET_X, &x,
                                        SSH_PKF_PUBLIC_Y, &y,
                                        SSH_PKF_END);

      if (status != SSH_CRYPTO_OK)
        ssh_fatal("Key get info failed with status %d.", status);

      /* Verify that g^x mod p = y */
      ssh_mprz_powm(&aux1, &g, &x, &p);
      SSH_ASSERT(ssh_mprz_cmp(&aux1, &y) == 0);

      x_str= ssh_mprz_get_str(&x, 16);
      y_str= ssh_mprz_get_str(&y, 16);

      if (strcmp(x_str, key_data->x))
        {
          printf("The generated private key x is not valid: \n"
                 "test vector : %s\ngenerated   : %s\n",
                 key_data->x, x_str);
          failed = TRUE;
        }

      if (strcmp(y_str, key_data->y))
        {
          printf("The generated public key y is not valid: \n"
                 "test vector :%s\ngenerated   :%s\n",
                 key_data->y, y_str );
          failed = TRUE;
        }

      ssh_private_key_free(prvkey);
      ssh_free(x_str);
      ssh_free(y_str);
    }

  ssh_mprz_clear(&p);
  ssh_mprz_clear(&q);
  ssh_mprz_clear(&g);
  ssh_mprz_clear(&x);
  ssh_mprz_clear(&y);
  ssh_mprz_clear(&aux1);
  ssh_mprz_clear(&aux2);

  if (failed)
    return FALSE;

  return TRUE;
}


typedef struct DssSigatureDataRec {
  const char *p;
  const char *q;
  const char *g;
  const char *y;
  const char *msg;
  const char *sig;
  unsigned int size;
} *DssSignatureData, DssSignatureDataStruct;

static DssSignatureDataStruct dss_signatures[] = {
  {
    "0xbd0669882bed2f2937b74c7a34db1e607b4250915590faebc8939b60ef8e1d53c"
    "165b67019c4772e00beace035db809b059da89d5e9d6557d2332ccd29c2d00b",
    "0x9c1bae515c1a397e753ac4f8c3c389721a8ea0bf",
    "0x2d7344dfb83c1db8a23c4139b0dbfcc62df17eb56b4eaab32f2674e650ca07982"
    "3863e1954a8310808b25ea8891bf7c6b63262a029a52647557b68d3ce6094d7",
    "7f54905620066405ea62787f4512ddc2ca033106be2040d999af661375506f57f0e"
    "3594c660c2cdd216e6e167c953112b4bd4893e0672d7b3cf8fe17e5008790",
    "5ffae3a6029225f5f7deb58060b83516c11a595dedde6eaf33b42b34c464bc40684"
    "60def61ff54fe9f7de1ed27352a53bd9c1281d9e47a5bc9f80a7223ba41666e7cbb"
    "7c10bdc27b7a2519cc93c304d163859b8501f85156bf42c03f935db72ac9958685e"
    "7458923e1cef3557ed8dc480acd8ea23d920c586b88e4d3eec33743",
    "5586be9c5254d464ce9822dcdd28752236768e2d5ab5b3e9779eba87b5cf1091f51"
    "438750e3fe9e1",
    512 },

  {
    "0xbd0669882bed2f2937b74c7a34db1e607b4250915590faebc8939b60ef8e1d53c"
    "165b67019c4772e00beace035db809b059da89d5e9d6557d2332ccd29c2d00b",
    "0x9c1bae515c1a397e753ac4f8c3c389721a8ea0bf",
    "0x2d7344dfb83c1db8a23c4139b0dbfcc62df17eb56b4eaab32f2674e650ca07982"
    "3863e1954a8310808b25ea8891bf7c6b63262a029a52647557b68d3ce6094d7",
    "7f54905620066405ea62787f4512ddc2ca033106be2040d999af661375506f57f0e"
    "3594c660c2cdd216e6e167c953112b4bd4893e0672d7b3cf8fe17e5008790",

    "43d10f06aebe6fbec02aed0771bf6bca0e092a811a65c3c36427650f690b50d8ecd"
    "e92d2d46d027c46ae7aee032d58e504ba370c5351eb8d2c4abbd855c2e2b3bb4848"
    "824ecc7dd91ec5f73fb6a28c45b97433c8bbd9f782622c3cd8beea37dfe568a7afd"
    "3b3d9ed80c8db9443f5ff03678f944c0bd5e0bc3f2462a65c5d4675",
    "26e6b7441de0208f3af15217319bf0aafd913a2688cf59fe0e7423d97dc2d816d51"
    "24e800b210eac",
    512 },

  { NULL }
};


Boolean dss_signature_test_vectors(void)
{
  DssSignatureData sig_data;
  SshCryptoStatus status;
  SshPublicKey pubkey;
  SshMPIntegerStruct p, q, g, y, aux;
  Boolean failed = FALSE;
  unsigned char *msg, *sig;
  size_t msglen, siglen;

  ssh_mprz_init(&p);
  ssh_mprz_init(&q);
  ssh_mprz_init(&g);
  ssh_mprz_init(&y);
  ssh_mprz_init(&aux);

  for (sig_data = dss_signatures; sig_data->p; sig_data++)
    {
      if (!hex_string_to_data(sig_data->msg, &msg, &msglen))
        ssh_fatal("Invalid input string.");

      if (!hex_string_to_data(sig_data->sig, &sig, &siglen))
        ssh_fatal("Invalid input string.");

      ssh_mprz_set_str(&p, sig_data->p, 16);
      ssh_mprz_set_str(&q, sig_data->q, 16);
      ssh_mprz_set_str(&g, sig_data->g, 16);
      ssh_mprz_set_str(&y, sig_data->y, 16);

      /* Verify that g^q mod p = 1 */
      ssh_mprz_powm(&aux, &g, &q, &p);
      SSH_ASSERT(ssh_mprz_cmp_ui(&aux, 1) == 0);

      status = ssh_public_key_define(&pubkey,
                                     "dl-modp{sign{dsa-nist-sha1}}",
                                     SSH_PKF_PRIME_P, &p,
                                     SSH_PKF_PRIME_Q, &q,
                                     SSH_PKF_GENERATOR_G, &g,
                                     SSH_PKF_PUBLIC_Y, &y,
                                     SSH_PKF_END);

      if (status != SSH_CRYPTO_OK)
        ssh_fatal("Key generation failed with status %d.", status);

      status = ssh_public_key_verify_signature(pubkey, 
                                               sig, siglen,
					       msg, msglen);

      if (status != SSH_CRYPTO_OK)
        {
          SSH_DEBUG(3, ("Signature verification failed with status %s",
                        ssh_crypto_status_message(status)));
          failed = TRUE;
        }

      ssh_free(msg);
      ssh_free(sig);

      ssh_public_key_free(pubkey);
    }

  ssh_mprz_clear(&p);
  ssh_mprz_clear(&q);
  ssh_mprz_clear(&g);
  ssh_mprz_clear(&y);
  ssh_mprz_clear(&aux);

  if (failed)
    return FALSE;

  return TRUE;
}

Boolean fips_dss_static_tests(Boolean verbose)
{
  SshCryptoStatus status;
  Boolean rv1, rv2, rv3;

  status = ssh_random_allocate("ssh", &true_rng);
  if (status != SSH_CRYPTO_OK) ssh_fatal("Cannot allocate a rng");

  ssh_random_add_light_noise(true_rng);

  status = ssh_random_allocate("pool", &fake_rng);
  if (status != SSH_CRYPTO_OK) ssh_fatal("Cannot allocate a rng");

  /* Set the `fake_rng' as the default RNG */
  status = ssh_crypto_set_default_rng(fake_rng);
  if (status != SSH_CRYPTO_OK) ssh_fatal("Cannot set the default rng");

  feed_fake_rng(NULL, 0);

  rv1 = dss_group_generation_test_vectors();
  if (!rv1)
    printf("DSS group generation test vectors are invalid. Test failed.\n");

  rv2 = dss_key_generation_test_vectors();
  if (!rv2)
    printf("DSS key generation test vectors are invalid. Test failed.\n");

  rv3 = dss_signature_test_vectors();
  if (!rv3)
    printf("DSS signature test vectors are invalid. Test failed.\n");

  /* Set the `true_rng' as the default RNG */
  status = ssh_crypto_set_default_rng(true_rng);
  if (status != SSH_CRYPTO_OK) ssh_fatal("Cannot set the default rng");

  true_rng = fake_rng = NULL;

  if (rv1 && rv2 && rv3)
    return TRUE;

  return FALSE;
}


Boolean pkcs_rsa_e_equal_3_signature_forgery_test(Boolean verbose)
{
  SshMPIntegerStruct d, n, e, returned_e, t1, t2;
  unsigned char data[1024], forged_sig[384];
  unsigned char *buf, *output_message;
  size_t output_message_len;
  SshRGF rgf; 
  SshPrivateKey prv;
  SshPublicKey pub;
  SshCryptoStatus stat;
  int i, j, num_tests;

  num_tests = 10;

  ssh_mprz_init(&d);
  ssh_mprz_init(&n);
  ssh_mprz_init(&e);
  ssh_mprz_init(&returned_e);
  ssh_mprz_init(&t1);
  ssh_mprz_init(&t2);

 regenerate_key:
  ssh_mprz_set_ui(&e, 3);
  stat = ssh_private_key_generate(&prv,
				  "if-modn{sign{rsa-pkcs1-sha1}}",
				  SSH_PKF_SIZE, 3072,
				  SSH_PKF_PUBLIC_E, &e,
				  SSH_PKF_END);
  SSH_ASSERT(stat == SSH_CRYPTO_OK);

  /* Verify that the generated private key has public exponent 'e' = 3 */
  stat = ssh_private_key_get_info(prv,
				  SSH_PKF_PUBLIC_E, &returned_e,
				  SSH_PKF_END);
  SSH_ASSERT(stat == SSH_CRYPTO_OK);

  if (ssh_mprz_cmp(&e, &returned_e))
    {
      ssh_private_key_free(prv);
      goto regenerate_key;
    }
  
  stat = ssh_private_key_derive_public_key(prv, &pub);
 
  SSH_ASSERT(stat == SSH_CRYPTO_OK);

  for (j = 0; j < num_tests; j++)
    {
    regenerate_message:
      for (i = 0; i < sizeof(data); i++)
	data[i] = ssh_random_get_byte();
      
      rgf = ssh_rgf_allocate(&ssh_rgf_pkcs1_sha1_def);
      stat = ssh_rgf_hash_update(rgf, data, sizeof(data));
      SSH_ASSERT(stat == SSH_CRYPTO_OK);

      /* Hash and PKCS1 encode the message */
      stat = ssh_rgf_for_signature(rgf, 3072, 
				   &output_message, &output_message_len);
      SSH_ASSERT(stat == SSH_CRYPTO_OK);

      ssh_rgf_free(rgf);

      SSH_DEBUG_HEXDUMP(SSH_D_LOWOK, ("RGF output"), 
			output_message, output_message_len);
      
      SSH_ASSERT(output_message[0] == 0);
      SSH_ASSERT(output_message[1] == 0x1);
      SSH_ASSERT(output_message[2] == 0xFF);
      
      /* Extract and place into 'buf' the ASN1 encoded OID followed by 
	 the hash. */
      for (i = 2; i < output_message_len; i++)
	{
	  if (output_message[i] != 0xff)
	    break;
	}
      buf = output_message + i;
      SSH_ASSERT(buf[0] == 0);      

      SSH_DEBUG_HEXDUMP(SSH_D_LOWOK, ("buf"), buf, 36);
      
      ssh_mprz_set_buf(&d, buf, 36);
      ssh_mprz_set_ui(&n, 0);
      ssh_mprz_set_bit(&n, 288);
      ssh_mprz_sub(&n, &n, &d);
      
      ssh_free(output_message);
      
      /* Check if n is a multiple of 3 */
      ssh_mprz_set(&t1, &n);
      
      ssh_mprz_div_ui(&t2, &n, 3);
      ssh_mprz_mul_ui(&t2, &t2, 3);
      
      if (ssh_mprz_cmp(&t2, &t1))
	goto regenerate_message;
      
      /* Construct the forged signature */
      ssh_mprz_mul_2exp(&n, &n, 34);
      ssh_mprz_div_ui(&n, &n, 3);
      
      ssh_mprz_set_ui(&d, 0);
      ssh_mprz_set_bit(&d, 1019);
      ssh_mprz_sub(&d, &d, &n);
      
      memset(forged_sig, 0, sizeof(forged_sig));
      ssh_mprz_get_buf(forged_sig, sizeof(forged_sig), &d);
      
      /* Verify the signature on the original data. */
      stat = ssh_public_key_verify_signature(pub,
					   forged_sig, sizeof(forged_sig),
					   data, sizeof(data));

      /* Verification succeeded when should have failed, return failure. */
      if (stat == SSH_CRYPTO_OK)
	goto error;
    }

  ssh_mprz_clear(&d);
  ssh_mprz_clear(&n);
  ssh_mprz_clear(&e);
  ssh_mprz_clear(&returned_e);
  ssh_mprz_clear(&t1);
  ssh_mprz_clear(&t2);

  ssh_private_key_free(prv);
  ssh_public_key_free(pub);

  /* All signature verifications have failed, return success.*/
  return TRUE;

 error:
  ssh_mprz_clear(&d);
  ssh_mprz_clear(&n);
  ssh_mprz_clear(&e);
  ssh_mprz_clear(&returned_e);
  ssh_mprz_clear(&t1);
  ssh_mprz_clear(&t2);

  ssh_private_key_free(prv);
  ssh_public_key_free(pub);
  return FALSE;
}


/*************************************************************************/

#ifdef SSHDIST_CRYPT_ECP
/* Test vectors for Diffie-Hellman IETF ECP fixed groups defined in RFC 4753 */
typedef struct EcpDHDataRec {
  const char *name;     /* Group name */
  const char *i;        /* Private exponent i */
  const char *r;        /* Private exponent r */  
  const char *gi_x;       /* The x component of the point g^i */
  const char *gi_y;       /* The y component of the point g^i */
  const char *gr_x;       /* The x component of the point g^r */
  const char *gr_y;       /* The y component of the point g^r */
  const char *gir_x;      /* The x component of the shared secret g^ir */
  const char *gir_y;      /* The y component of the shared secret g^ir */
} *EcpDHData, EcpDHDataStruct;

static EcpDHDataStruct ecp_diffie_hellman[] = {
  {
    "prime256v1",
    
    "0xC88F01F510D9AC3F70A292DAA2316DE544E9AAB8AFE84049C62A9C57862D1433",
    
    "0xC6EF9C5D78AE012A011164ACB397CE2088685D8F06BF9BE0B283AB46476BEE53",
    
    "0xDAD0B65394221CF9B051E1FECA5787D098DFE637FC90B9EF945D0C3772581180",

    "0x5271A0461CDB8252D61F1C456FA3E59AB1F45B33ACCF5F58389E0577B8990BB3",
    
    "0xD12DFB5289C8D4F81208B70270398C342296970A0BCCB74C736FC7554494BF63",

    "0x56FBF3CA366CC23E8157854C13C58D6AAC23F046ADA30F8353E74F33039872AB",
    
    "0xD6840F6B42F6EDAFD13116E0E12565202FEF8E9ECE7DCE03812464D04B9442DE",

    "0x522BDE0AF0D8585B8DEF9C183B5AE38F50235206A8674ECB5D98EDB20EB153A2"
  },
  {
    "secp384r1",

    "0x099F3C7034D4A2C699884D73A375A67F7624EF7C6B3C0F160647B67414DCE655"
    "E35B538041E649EE3FAEF896783AB194",
    
    "0x41CB0779B4BDB85D47846725FBEC3C9430FAB46CC8DC5060855CC9BDA0AA2942"
    "E0308312916B8ED2960E4BD55A7448FC",

    "0x667842D7D180AC2CDE6F74F37551F55755C7645C20EF73E31634FE72B4C55EE6"
    "DE3AC808ACB4BDB4C88732AEE95F41AA",

    "0x9482ED1FC0EEB9CAFC4984625CCFC23F65032149E0E144ADA024181535A0F38E"
    "EB9FCFF3C2C947DAE69B4C634573A81C",

    "0xE558DBEF53EECDE3D3FCCFC1AEA08A89A987475D12FD950D83CFA41732BC509D"
    "0D1AC43A0336DEF96FDA41D0774A3571",

    "0xDCFBEC7AACF3196472169E838430367F66EEBE3C6E70C416DD5F0C68759DD1FF"
    "F83FA40142209DFF5EAAD96DB9E6386C",
    
    "0x11187331C279962D93D604243FD592CB9D0A926F422E47187521287E7156C5C4"
    "D603135569B9E9D09CF5D4A270F59746",

    "0xA2A9F38EF5CAFBE2347CF7EC24BDD5E624BC93BFA82771F40D1B65D06256A852"
    "C983135D4669F8792F2C1D55718AFBB4"
  },
  {
    "secp521r1",

    "0x0037ADE9319A89F4DABDB3EF411AACCCA5123C61ACAB57B5393DCE47608172A0"
    "95AA85A30FE1C2952C6771D937BA9777F5957B2639BAB072462F68C27A57382D"
    "4A52",

    "0x0145BA99A847AF43793FDD0E872E7CDFA16BE30FDC780F97BCCC3F078380201E"
    "9C677D600B343757A3BDBF2A3163E4C2F869CCA7458AA4A4EFFC311F5CB15168"
    "5EB9",

    "0x0015417E84DBF28C0AD3C278713349DC7DF153C897A1891BD98BAB4357C9ECBE"
    "E1E3BF42E00B8E380AEAE57C2D107564941885942AF5A7F4601723C4195D176C"
    "ED3E",

    "0x017CAE20B6641D2EEB695786D8C946146239D099E18E1D5A514C739D7CB4A10A"
    "D8A788015AC405D7799DC75E7B7D5B6CF2261A6A7F1507438BF01BEB6CA3926F"
    "9582",
    
    "0x00D0B3975AC4B799F5BEA16D5E13E9AF971D5E9B984C9F39728B5E5739735A21"
    "9B97C356436ADC6E95BB0352F6BE64A6C2912D4EF2D0433CED2B6171640012D9"
    "460F",

    "0x015C68226383956E3BD066E797B623C27CE0EAC2F551A10C2C724D9852077B87"
    "220B6536C5C408A1D2AEBB8E86D678AE49CB57091F4732296579AB44FCD17F0F"
    "C56A",
    
    "0x01144C7D79AE6956BC8EDB8E7C787C4521CB086FA64407F97894E5E6B2D79B04"
    "D1427E73CA4BAA240A34786859810C06B3C715A3A8CC3151F2BEE417996D19F3"
    "DDEA",

    "0x01B901E6B17DB2947AC017D853EF1C1674E5CFE59CDA18D078E05D1B5242ADAA"
    "9FFC3C63EA05EDB1E13CE5B3A8E50C3EB622E8DA1B38E0BDD1F88569D6C99BAF"
    "FA43"
  },

  { NULL }
};

Boolean ecp_ietf_groups_diffie_hellman_test(Boolean verbose)
{
  EcpDHData ecp_data;
  SshECPCurveStruct E;
  SshECPPointStruct P, R1, R2;
  SshMPIntegerStruct n, i, r, x, y;
  const char *outname;
  Boolean pc;

  ssh_mprz_init(&n);
  ssh_mprz_init(&i);
  ssh_mprz_init(&r);
  ssh_mprz_init(&x);
  ssh_mprz_init(&y);

  for (ecp_data = ecp_diffie_hellman; ecp_data->name; ecp_data++)
    {
      if (!ssh_ecp_set_param(ecp_data->name, &outname, &E, &P, &n, &pc))
	{
	  ssh_warning("Cannot set ECP curve name='%s'", ecp_data->name);
	  goto fail;
	}
      /* No point compression allowed for now. */
      if (pc == TRUE)
	goto fail;

      ssh_mprz_set_str(&i, ecp_data->i, 16);
      ssh_mprz_set_str(&r, ecp_data->r, 16);

      ssh_ecp_init_point(&R1, &E);
      ssh_ecp_init_point(&R2, &E);
      
      ssh_ecp_mul(&R1, &P, &i, &E);
      /* compare R1 with g^i */  
      ssh_mprz_set_str(&x, ecp_data->gi_x, 16);
      ssh_mprz_set_str(&y, ecp_data->gi_y, 16);

      if (ssh_mprz_cmp(&R1.x, &x) || ssh_mprz_cmp(&R1.y, &y))
	goto fail;

      ssh_ecp_mul(&R2, &P, &r, &E);
      /* compare R2 with g^2 */  
      ssh_mprz_set_str(&x, ecp_data->gr_x, 16);
      ssh_mprz_set_str(&y, ecp_data->gr_y, 16);

      if (ssh_mprz_cmp(&R2.x, &x) || ssh_mprz_cmp(&R2.y, &y))
	goto fail;

      ssh_ecp_mul(&R1, &R1, &r, &E);
      /* compare R1 with g^ir */  
      ssh_mprz_set_str(&x, ecp_data->gir_x, 16);
      ssh_mprz_set_str(&y, ecp_data->gir_y, 16);      

      if (ssh_mprz_cmp(&R1.x, &x) || ssh_mprz_cmp(&R1.y, &y))
	goto fail;

      ssh_ecp_clear_point(&R1);
      ssh_ecp_clear_point(&R2);
      ssh_ecp_clear_curve(&E);
      ssh_ecp_clear_point(&P);
      ssh_mprz_clear(&n);
    }

  ssh_mprz_clear(&x);
  ssh_mprz_clear(&y);
  ssh_mprz_clear(&i);
  ssh_mprz_clear(&r);
  return TRUE;

 fail:
  printf("ECP Diffie-Hellman tests failed for group '%s'\n", outname);
  ssh_mprz_clear(&n);
  ssh_mprz_clear(&i);
  ssh_mprz_clear(&r);
  ssh_mprz_clear(&x);
  ssh_mprz_clear(&y);
  ssh_ecp_clear_point(&P);
  ssh_ecp_clear_point(&R1);
  ssh_ecp_clear_point(&R2);
  ssh_ecp_clear_curve(&E);
  return FALSE;
}

/* Test vectors for DSA IETF ECP fixed groups defined in RFC 4754. The 
   notation used below is from RFC 4754. */
typedef struct EcpDSADataRec {
  const char *group_name; /* Group name */
  const char *scheme;     /* Signature scheme */
  const char *w;          /* Private key w */
  const char *k;          /* Epheremal key k */  
  const char *sig;        /* The signature data */
} *EcpDSAData, EcpDSADataStruct;

static EcpDSADataStruct ecp_dsa[] = {
  {
    "prime256v1",
    "dsa-none-sha256",
    "DC51D3866A15BACDE33D96F992FCA99DA7E6EF0934E7097559C27F1614C88A7F",
    "9E56F509196784D963D1C0A401510EE7ADA3DCC5DEE04B154BF61AF1D5A6DECE",
    "CB28E0999B9C7715FD0A80D8E47A77079716CBBF917DD72E97566EA1C066957C"
    "86FA3BB4E26CAD5BF90B7F81899256CE7594BB1EA0C89212748BFF3B3D5B0315"
  },
  {
    "secp384r1",
    "dsa-none-sha384", 
    "0BEB6466 34BA8773 5D77AE48 09A0EBEA 865535DE 4C1E1DCB 692E8470 8E81A5AF"
    "62E528C3 8B2A81B3 5309668D 73524D9F",
    "B4B74E44D71A13D568003D7489908D564C7761E229C58CBFA18950096EB7463B"
    "854D7FA992F934D927376285E63414FA",
    "FB017B914E29149432D8BAC29A514640B46F53DDAB2C69948084E2930F1C8F7E"
    "08E07C9C63F2D21A07DCB56A6AF56EB3"
    "B263A1305E057F984D38726A1B46874109F417BCA112674C528262A40A629AF1"
    "CBB9F516CE0FA7D2FF630863A00E8B9F"
  },
  {
    "secp521r1",
    "dsa-none-sha512",
    "0065FDA3409451DCAB0A0EAD45495112A3D813C17BFD34BDF8C1209D7DF58491"
    "20597779060A7FF9D704ADF78B570FFAD6F062E95C7E0C5D5481C5B153B48B37"
    "5FA1",
    "00C1C2B305419F5A41344D7E4359933D734096F556197A9B244342B8B62F46F9"
    "373778F9DE6B6497B1EF825FF24F42F9B4A4BD7382CFC3378A540B1B7F0C1B95"
    "6C2F",
    "0154FD3836AF92D0DCA57DD5341D3053988534FDE8318FC6AAAAB68E2E6F4339"
    "B19F2F281A7E0B22C269D93CF8794A9278880ED7DBB8D9362CAEACEE54432055"
    "2251"
    "017705A7030290D1CEB605A9A1BB03FF9CDD521E87A696EC926C8C10C8362DF4"
    "975367101F67D1CF9BCCBF2F3D239534FA509E70AAC851AE01AAC68D62F86647"
    "2660"
  },
  { NULL },
};


Boolean ecp_ietf_groups_dsa_test(Boolean verbose)
{
  EcpDSAData ecp_data;
  SshPrivateKey prvkey;
  SshPublicKey pubkey;
  SshCryptoStatus status;
  SshMPIntegerStruct w;
  unsigned char *buf, msg[3];
  size_t len, return_len;
  unsigned char *random, *signature;
  size_t randomlen, signaturelen;

  ssh_mprz_init(&w);

  /* The message to be signed is 'abc' */
  msg[0] = 0x61; msg[1] = 0x62; msg[2] = 0x63;

  status = ssh_random_allocate("ssh", &true_rng);
  if (status != SSH_CRYPTO_OK) ssh_fatal("Cannot allocate a rng");

  ssh_random_add_light_noise(true_rng);

  for (ecp_data = ecp_dsa; ecp_data->group_name; ecp_data++)
    {
      ssh_mprz_set_str(&w, ecp_data->w, 16);

      status  = ssh_private_key_define(&prvkey, "ec-modp",
				       SSH_PKF_SIGN, ecp_data->scheme,
				       SSH_PKF_SECRET_X, &w,
				       SSH_PKF_PREDEFINED_GROUP,
				       ecp_data->group_name,
				       SSH_PKF_END);
      
      if (status != SSH_CRYPTO_OK)
	{
	  SSH_DEBUG(SSH_D_ERROR, ("Private key allocation failed status '%s'",
				  ssh_crypto_status_message(status)));
	  goto fail;
	}
      
      len = ssh_private_key_max_signature_output_len(prvkey);
      SSH_DEBUG(SSH_D_MIDOK, ("The max output signature len for private key"
			      " using group %s and scheme %s is %d", 
			      ecp_data->group_name,
			      ecp_data->scheme, len));
      buf = ssh_xmalloc(len);
  
      status = ssh_random_allocate("pool", &fake_rng);
      if (status != SSH_CRYPTO_OK) ssh_fatal("Cannot allocate a rng");

      /* Set the `fake_rng' as the default RNG */
      status = ssh_crypto_set_default_rng(fake_rng);
      if (status != SSH_CRYPTO_OK) ssh_fatal("Cannot set the default rng");

      if (!hex_string_to_data(ecp_data->k, &random, &randomlen))
        ssh_fatal("Invalid input string.");

      /* Feed the fake RNG with the input from 'k' which will be used 
	 for generation of the DSA epheremal private exponent */
      feed_fake_rng(random, randomlen);
      
      status = ssh_private_key_sign(prvkey, msg, sizeof(msg),
				    buf, len, &return_len);
      
      if (status != SSH_CRYPTO_OK)
	goto fail;
      status = ssh_random_pool_get_length(fake_rng, &len);
      SSH_ASSERT(status == SSH_CRYPTO_OK && len == 0);
      feed_fake_rng(NULL, 0);
      
      if (!hex_string_to_data(ecp_data->sig, &signature, &signaturelen))
        ssh_fatal("Invalid input string.");

      if (return_len != signaturelen || memcmp(signature, buf, return_len))
	{
	  SSH_DEBUG(SSH_D_FAIL, ("Signature does not match expected value"));
      	  goto fail;
	}

      status = ssh_private_key_derive_public_key(prvkey, &pubkey);
      if (status != SSH_CRYPTO_OK)
	goto fail;
      
      status = ssh_public_key_verify_signature(pubkey,
					       signature, signaturelen,
					       msg, sizeof(msg));
      if (status != SSH_CRYPTO_OK)
      {
	SSH_DEBUG(SSH_D_FAIL, 
		  ("Cannot validate signature on derived public key"));
	ssh_xfree(signature);
	goto fail;
      }

      ssh_xfree(buf);
      ssh_xfree(signature);
      ssh_xfree(random);
      ssh_private_key_free(prvkey);
      ssh_public_key_free(pubkey);
    }

  /* Set the `true_rng' as the default RNG */
  status = ssh_crypto_set_default_rng(true_rng);
  if (status != SSH_CRYPTO_OK) ssh_fatal("Cannot set the default rng");
  true_rng = fake_rng = NULL;

  ssh_mprz_clear(&w);
  return TRUE;

 fail:
  printf("ECP DSA tests failed\n");
  ssh_xfree(buf);
  ssh_xfree(signature);
  ssh_xfree(random);
  ssh_mprz_clear(&w);
  true_rng = fake_rng = NULL;
  ssh_private_key_free(prvkey);
  ssh_public_key_free(pubkey);
  return FALSE;
}
#endif /* SSHDIST_CRYPT_ECP */
