/*
  hash-test.c

  Copyright:
          Copyright (c) 2002, 2003 SFNT Finland Oy.
  Espoo, Finland All rights reserved.

  Created: Fri Nov  1 05:37:55 1996 [mkojo]
*/

#include "sshincludes.h"
#include "sshcrypt.h"
#include "sshtimemeasure.h"
#include "readfile.h"
#include "sshmp.h"
#include "sshdsprintf.h"
#include "t-gentest.h"
#include "sshhash_i.h"

#ifdef SSHDIST_ASN1
#include "sshasn1.h"
#endif /* SSHDIST_ASN1 */

/****************** Hash tests. ***********************/

#define SSH_DEBUG_MODULE "Hash_Test"

void test(void)
{

#if 0
  int i;
  /* This short piece of test code is for our previous SHA-1 bug. It
     was cunning enough not to show up in NIST examples (even
     partitioned).  However the following test detects it.

     Bug can be detected by having 128 bytes of data to be
     hashed. This data is divided in two parts first part having 1
     byte and rest 127 bytes. These bytes should not all be the same.

     Then update the hash context with both parts in correct order
     (first the 1 byte and then the rest 127 bytes). Compare this with
     the hash output of straigh hashing of 128 original bytes. If
     result is not equal then this error (or some other) was detected.
     */

  SshHash hash;
  unsigned char digest[128];


  ssh_hash_allocate("sha1", &hash);

  ssh_hash_reset(hash);
  for (i = 0; i < 128; i++)
    digest[i] = 0;
  digest[127] = 1;

  ssh_hash_update(hash, digest, 1);
  ssh_hash_update(hash, digest + 1, 127);

  ssh_hash_final(hash, digest);

  ssh_hash_reset(hash);

  for (i = 0; i < 20; i++)
    printf("%02x", digest[i]);
  printf("\n");

  for (i = 0; i < 128; i++)
    digest[i] = 0;
  digest[127] = 1;

  ssh_hash_update(hash, digest, 128);

  ssh_hash_final(hash, digest);

  for (i = 0; i < 20; i++)
    printf("%02x", digest[i]);
  printf("\n");

  ssh_hash_free(hash);

  exit(1);

#endif
}

Boolean hash_random_tests(Boolean do_speed_test, size_t len)
{
  char *temp_hash_name, *hash_name = ssh_hash_get_supported();
  unsigned char buf[SSH_MAX_HASH_DIGEST_LENGTH], *buf2;
  SshHash hash;
  struct SshTimeMeasureRec tmit = SSH_TIME_MEASURE_INITIALIZER;
  SshCryptoStatus status;
  int i, iterations;

  temp_hash_name = strtok(hash_name, ",");

  while (temp_hash_name)
    {
      if (ssh_hash_allocate(temp_hash_name, &hash) != SSH_CRYPTO_OK)
        {
          SSH_DEBUG(0, ("error: hash allocate %s failed.",
                        temp_hash_name));
          return FALSE;
        }

      iterations = 1024;
    retry:


      buf2 = ssh_xmalloc(len);
      for (i = 0; i < len; i++)
        buf2[i] = i & 0xff;

      if (do_speed_test)
        {
          ssh_time_measure_reset(&tmit);
          ssh_time_measure_start(&tmit);
        }

      for (i = 0; i < iterations; i++)
	{
	  ssh_hash_reset(hash);
	  ssh_hash_update(hash, buf2, len);
	  ssh_hash_final(hash, buf);
	}

      if (do_speed_test)
        ssh_time_measure_stop(&tmit);

      for (i = 0; i < iterations; i++)
	{
	  status =
	    ssh_hash_compare_start(hash, buf,
				   ssh_hash_digest_length(temp_hash_name));
	  if (status != SSH_CRYPTO_OK)
	    {
	      SSH_DEBUG(0, ("error: hash compare start %s failed %s.",
			    temp_hash_name,
			    ssh_crypto_status_message(status)));
	      return FALSE;
	    }
	  
	  ssh_hash_update(hash, buf2, len / 2);
	  ssh_hash_update(hash, buf2 + len / 2, len - (len / 2));
	  
	  status = ssh_hash_compare_result(hash);
	  if (status != SSH_CRYPTO_OK)
	    {
	      SSH_DEBUG(0, ("error: hash compare result %s failed %s.",
			    temp_hash_name,
			    ssh_crypto_status_message(status)));
	      return FALSE;
	    }
	}
      
      ssh_xfree(buf2);

      if (do_speed_test)
        {
          if (ssh_time_measure_get(&tmit, SSH_TIME_GRANULARITY_SECOND)
              <= TEST_TIME_MIN && iterations < 10000000)
            {
              if (ssh_time_measure_get(&tmit, SSH_TIME_GRANULARITY_MILLISECOND)
                  < 10)
                {
                  iterations *= 128;
                }
              else
                {
                  iterations *= 2;

                }
              if (verbose)
                printf("  - %s was too fast, retrying...\n",
                       temp_hash_name);
              goto retry;
            }

          if (ssh_time_measure_get(&tmit, SSH_TIME_GRANULARITY_SECOND)
              >= TEST_TIME_MIN)
            printf("%s -- " TEST_FMT " KiBytes/sec (" TEST_FMT " ns / call)\n",
                   temp_hash_name, ((double)len * iterations) /
                   ((double)
                    ssh_time_measure_get(&tmit,
					 SSH_TIME_GRANULARITY_MICROSECOND)
		    / 1000000.0 * 1024.0),
		   (double)
		   ssh_time_measure_get(&tmit,
					SSH_TIME_GRANULARITY_NANOSECOND)
		   / (double) iterations);
          else
            printf("  - timing could not be performed for %s.\n",
                   temp_hash_name);
        }

      /* Put here some tests. */

      ssh_hash_free(hash);
      temp_hash_name = strtok(NULL, ",");
    }

  ssh_free(hash_name);
  return TRUE;
}

typedef enum {
  HASH_IGNORE = 0,
  HASH_INPUT = 1,
  HASH_OUTPUT = 2
} HashTestState;

/* Read the file. */
Boolean hash_static_tests(const char *filename)
{
  char hash_name[256];
  unsigned char *str, *str2;
  unsigned char buf[SSH_MAX_HASH_DIGEST_LENGTH];
  SshHash hash = NULL, hash2 = NULL;
  size_t len, len2;
  RFStatus status;
  SshCryptoStatus error;
  HashTestState state = HASH_IGNORE;

  status = ssh_t_read_init(filename);
  if (status != RF_READ)
    {
      SSH_DEBUG(0, ("error: %s file not available or corrupted.", filename));
      return FALSE;
    }

  while (status != RF_EMPTY)
    {
      status = ssh_t_read_token(&str, &len);
      switch (status)
        {
        case RF_LABEL:
          /* Delete the old hash context. */
          if (hash)
            {
              ssh_hash_free(hash);
              ssh_hash_free(hash2);
              hash = NULL;
              hash2 = NULL;
            }
          if (len > 255)
            {
              SSH_DEBUG(0, ("error: hash name too long."));
              return FALSE;
            }
          memcpy(hash_name, str, len);
          hash_name[len] = '\0';

          if (ssh_hash_supported(hash_name))
            {
              if (ssh_hash_allocate(hash_name, &hash) != SSH_CRYPTO_OK)
                {
                  SSH_DEBUG(0, ("error: hash allocate %s failed.", hash_name));
                  return FALSE;
                }
              if (ssh_hash_allocate(hash_name, &hash2) != SSH_CRYPTO_OK)
                {
                  SSH_DEBUG(0, ("error: hash allocate %s failed.", hash_name));
                  return FALSE;
                }
              state = HASH_INPUT;
            }
          else
            {
              SSH_DEBUG(2, ("hash %s not supported", hash_name));
              state = HASH_IGNORE;
            }
          break;
        case RF_HEX:
        case RF_ASCII:
          switch (state)
            {
            case HASH_INPUT:
              ssh_hash_reset(hash);
              ssh_hash_update(hash, str, len);
              state = HASH_OUTPUT;
	      str2 = ssh_memdup(str, len);
	      len2 = len;
              break;
            case HASH_OUTPUT:
              if (len != ssh_hash_digest_length(ssh_hash_name(hash)))
                {
                  SSH_DEBUG(0, ("error: file digest length incorrect."));
                  return FALSE;
                }

              ssh_hash_final(hash, buf);
              if (memcmp(str, buf,
                         ssh_hash_digest_length(ssh_hash_name(hash))) != 0)
                {
                  HexRenderStruct wrong, correct;

                  correct.length = wrong.length =
                    ssh_hash_digest_length(hash_name);
                  wrong.data = buf;
                  correct.data = str;

                  SSH_DEBUG(0,
                            ("Wrong digest for `%s' hash: "
                             "Wrong=%@, Correct=%@",
                             hash_name,
                             hex_render, &wrong, hex_render, &correct));

                  return FALSE;
                }

	      error = ssh_hash_compare_start(hash, str, len);
	      if (error != SSH_CRYPTO_OK)
		{
                  SSH_DEBUG(0, ("error: ssh_hash_compare_start %s failed: %s",
				hash_name, ssh_crypto_status_message(error)));
                  return FALSE;
		}

	      ssh_hash_update(hash, str2, len2);
	      ssh_free(str2);
	      str2 = NULL;

	      error = ssh_hash_compare_result(hash);
	      if (error != SSH_CRYPTO_OK)
		{
                  SSH_DEBUG(0, ("error: ssh_hash_compare_result %s failed: %s",
				hash_name, ssh_crypto_status_message(error)));
                  return FALSE;
		}

              state = HASH_INPUT;
              break;
            case HASH_IGNORE:
              break;
            default:
              {
                SSH_DEBUG(0, ("error: unknown hash flag (%d).", state));
                return FALSE;
              }
              break;
            }

          break;
        case RF_EMPTY:
          break;
        default:
          {
            SSH_DEBUG(0, ("error: file error or corrupted (%d).", status));
            return FALSE;
          }
          break;
        }
    }

  ssh_t_close();

  if (hash)
    {
      ssh_hash_free(hash);
      ssh_hash_free(hash2);
    }

  return TRUE;
}

Boolean hash_static_tests_do(const char *filename)
{
  char *temp_hash_name, *hash_name = ssh_hash_get_supported();
  unsigned char buf[SSH_MAX_HASH_DIGEST_LENGTH], *buf2;
  SshHash hash;
  int i, j, len;
  RFStatus status;

  status = ssh_t_write_init("hash.tests.created");

  if (status != RF_WRITE)
    {
      SSH_DEBUG(0, ("error: file hash.tests.created could not be created."));
      return FALSE;
    }

  ssh_t_write_token(RF_LINEFEED, NULL, 0);
  ssh_t_write_token(RF_COMMENT, (unsigned char*) filename, strlen(filename));

  temp_hash_name = strtok(hash_name, ",");

  while (temp_hash_name)
    {
      if (ssh_hash_allocate(temp_hash_name, &hash) != SSH_CRYPTO_OK)
        {
          SSH_DEBUG(0, ("error: hash allocate %s failed.", temp_hash_name));
          return FALSE;
        }

      /* Put here some tests. */

      ssh_t_write_token(RF_LINEFEED, NULL, 0);
      ssh_t_write_token(RF_LABEL, (unsigned char *) temp_hash_name,
                        strlen(temp_hash_name));
      ssh_t_write_token(RF_LINEFEED, NULL, 0);

      for (i = 0; i < 64; i++)
        {
          buf2 = (unsigned char *) "first input then digest";
          ssh_t_write_token(RF_COMMENT, buf2, strlen((char *) buf2));

          len = i + 10;
          buf2 = ssh_xmalloc(len);
          for (j = 0; j < len; j++)
            buf2[j] = ssh_random_get_byte();

          ssh_t_write_token(RF_HEX, buf2, len);
          ssh_t_write_token(RF_LINEFEED, NULL, 0);

          ssh_hash_reset(hash);
          ssh_hash_update(hash, buf2, len);
          ssh_hash_final(hash, buf);

          ssh_t_write_token(RF_HEX, buf,
                            ssh_hash_digest_length(ssh_hash_name(hash)));
          ssh_t_write_token(RF_LINEFEED, NULL, 0);

          ssh_xfree(buf2);
        }

      /* Put here some tests. */

      ssh_hash_free(hash);
      temp_hash_name = strtok(NULL, ",");
    }

  ssh_t_write_token(RF_LINEFEED, NULL, 0);
  ssh_t_write_token(RF_COMMENT, (unsigned char*) filename, strlen(filename));
  ssh_t_write_token(RF_LINEFEED, NULL, 0);

  ssh_t_close();

  ssh_free(hash_name);

  return TRUE;
}

#ifdef SSHDIST_ASN1

/* Wrap the hash OID and hash digest into BER data PKCS1 style. */
static Boolean
pkcs1_wrap_using_asn1(const unsigned char *oid,
                      const unsigned char *data,
                      size_t data_len,
                      unsigned char **ber_ret,
                      size_t *ber_len_ret)
{
  SshAsn1Context asn1_context;
  SshAsn1Status  status;
  SshAsn1Node node;

  if ((asn1_context = ssh_asn1_init()) == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Couldn't init ASN.1 context."));
      return FALSE;
    }

  status = ssh_asn1_create_node(asn1_context, &node,
                                "(sequence ()"
                                "  (sequence ()"
                                "    (object-identifier ())"
                                "    (null ()))"
                                "  (octet-string ()))",
                                oid,
                                data,
                                (size_t)data_len);

  if (status != SSH_ASN1_STATUS_OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("ASN.1 create node failed."));
      return FALSE;
    }

  status = ssh_asn1_encode_node(asn1_context, node);

  if (status != SSH_ASN1_STATUS_OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("ASN.1 encode failed."));
      return FALSE;
    }
  ssh_asn1_node_get_data(node, ber_ret, ber_len_ret);
  ssh_asn1_free(asn1_context);
  return TRUE;
}

/* Test program to check that the 'encoded_asn1_oid' buffer in the
   SshHashDef structure gives the same results as what you get from
   applying the standard ASN.1 encoding. */
Boolean hash_asn1_encode_test(void)
{
  SshHash hash;
  const SshHashDefStruct *hash_def;
  char *temp_hash_name, *hash_name = ssh_hash_get_supported();
  const unsigned char *encoded_oid;
  unsigned char *digest, *ber1, *ber2;
  size_t encoded_oid_len, digest_len, ber1_len, ber2_len;

  temp_hash_name = strtok(hash_name, ",");

  while (temp_hash_name)
    {
      if (ssh_hash_allocate(temp_hash_name, &hash) != SSH_CRYPTO_OK)
        {
          SSH_DEBUG(0, ("error: hash allocate %s failed.", temp_hash_name));
          return FALSE;
        }

      if (!(hash_def = ssh_hash_get_definition_internal(hash)))
        return FALSE;

      if (!ssh_hash_asn1_oid(temp_hash_name))
        goto next;

      if (hash_def->generate_asn1_oid == NULL)
        {
          SSH_DEBUG(0, ("No hash encoded OID is defined for "
                        "this hash function"));
          return FALSE;
        }

      /* Compute a valid hash digest. */
      digest_len = ssh_hash_digest_length(temp_hash_name);
      digest = ssh_xmalloc(digest_len);

      ssh_hash_update(hash, "something", strlen("something"));
      if (ssh_hash_final(hash, digest) != SSH_CRYPTO_OK)
        {
          SSH_DEBUG(0, ("ssh_hash_final() failed for %s.",
                        temp_hash_name));
          return FALSE;
        }
      /* Wrap the OID and digest using ASN.1 */
      if (!pkcs1_wrap_using_asn1((unsigned char*)
                                 ssh_hash_asn1_oid(temp_hash_name),
                                 digest, digest_len, &ber1, &ber1_len))
        {
          SSH_DEBUG(0, ("error: pkcs1 wrapping %s failed.", temp_hash_name));
          return FALSE;
        }

      /* Now compare to when we wrap the digest and the ASN1 encoded OID
         in the hash definition. */
        encoded_oid = (*hash_def->generate_asn1_oid)(&encoded_oid_len);

        ber2_len = digest_len + encoded_oid_len;
        ber2 = ssh_xmalloc(ber2_len);

        memcpy(ber2, encoded_oid, encoded_oid_len);
        memcpy(ber2 + encoded_oid_len, digest, digest_len);

      if (ber1_len != ber2_len)
        {
          SSH_DEBUG(0, ("error: The lengths of the pkcs1 wrapped buffers "
                        "do not agree for hash %s.", temp_hash_name));
          ssh_xfree(digest);
          ssh_xfree(ber2);
          return FALSE;
        }

      if (memcmp(ber1, ber2, ber1_len))
        {
          SSH_DEBUG(0, ("error: The pkcs1 wrapped buffers are not the "
                        "same for hash %s.", temp_hash_name));
          ssh_xfree(digest);
          ssh_xfree(ber2);
          return FALSE;
        }

      ssh_xfree(digest);
      ssh_xfree(ber1);
      ssh_xfree(ber2);
    next:
      ssh_hash_free(hash);
      temp_hash_name = strtok(NULL, ",");
    }

  ssh_free(hash_name);

  return TRUE;
}
#else /* SSHDIST_ASN1 */
Boolean hash_asn1_encode_test(void)
{
  return TRUE;
}
#endif /* SSHDIST_ASN1 */
