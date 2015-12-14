/*

mac-test.c

  Copyright:
          Copyright (c) 2002-2004 SFNT Finland Oy.
	  All rights reserved.

Testing those gen- prefixed files.

*/

#include "sshincludes.h"
#include "sshcrypt.h"
#include "sshcrypt_i.h"
#include "sshtimemeasure.h"
#include "readfile.h"
#include "sshmp.h"
#include "sshdsprintf.h"
#include "t-gentest.h"

#define SSH_DEBUG_MODULE "GenTestMac"

static size_t mac_key_len(const char *macname)
{
  size_t keylen;

  do {
    keylen = ssh_random_get_byte() & 31;
  } while (keylen == 0);

  if (strstr(macname, "cbcmac-des"))
    keylen = 8;
  if (strstr(macname, "cbcmac-3des"))
    keylen = 24;
  if (strstr(macname, "xcbcmac-aes"))
    keylen = 16;
  if (strstr(macname, "xcbcmac-rijndael"))
    keylen = 16;
  if (strstr(macname, "cmac-aes"))
    keylen = 16;
  if (strstr(macname, "cmac-rijndael"))
    keylen = 16;

  return keylen;
}

/*********************** MAC tests. *****************************/

Boolean mac_random_tests(Boolean do_speed_test, size_t len)
{
  char *temp_mac_name, *mac_name = ssh_mac_get_supported();
  unsigned char *key;
  SshUInt32 keylen;
  unsigned char *buf;
  unsigned char *buf2;
  SshMac mac;
  struct SshTimeMeasureRec tmit = SSH_TIME_MEASURE_INITIALIZER;
  int i, iterations;
  SshCryptoStatus status;

  temp_mac_name = strtok(mac_name, ",");


  if (temp_mac_name)
    {
      unsigned char *d1, *d2;
      size_t len;

      keylen = mac_key_len(temp_mac_name);
      key = ssh_xmalloc(keylen);
      for (i = 0; i < keylen; i++)
        key[i] = ssh_random_get_byte();

      if (ssh_mac_allocate(temp_mac_name, key, keylen, &mac)
          != SSH_CRYPTO_OK)
        ssh_fatal("error: mac allocate %s failed.", temp_mac_name);

      len = ssh_mac_length(ssh_mac_name(mac));
      ssh_mac_reset(mac);
      ssh_mac_update(mac, "1234567890", sizeof("1234567890"));
      d1 = ssh_xmalloc(len);
      ssh_mac_final(mac, d1);
      ssh_mac_free(mac);

      if (ssh_mac_allocate(temp_mac_name, key, keylen, &mac)
          != SSH_CRYPTO_OK)
        ssh_fatal("error: mac allocate %s failed.", temp_mac_name);

      ssh_mac_update(mac, "1234567890", sizeof("1234567890"));
      d2 = ssh_xmalloc(len);
      ssh_mac_final(mac, d2);

      if (memcmp(d1, d2, len))
        ssh_fatal("error: mac allocate did not reset mac!");

      ssh_free(d2);

      ssh_mac_reset(mac);
      ssh_mac_update(mac, "1234567890", sizeof("1234567890"));
      d2 = ssh_xmalloc(len);
      ssh_mac_final(mac, d2);
      ssh_mac_free(mac);

      if (memcmp(d1, d2, len))
        ssh_fatal("error: mac reset did not not reset mac!");

      ssh_xfree(d1);
      ssh_xfree(d2);
      ssh_xfree(key);
    }

  while (temp_mac_name)
    {
      keylen = mac_key_len(temp_mac_name);
      key = ssh_xmalloc(keylen);

      for (i = 0; i < keylen; i++)
        key[i] = ssh_random_get_byte();

      status = ssh_mac_allocate(temp_mac_name, key, keylen, &mac);

      if (status != SSH_CRYPTO_OK)
        {
          SSH_DEBUG(0, ("Error: mac allocate %s failed: %s",
                        temp_mac_name, ssh_crypto_status_message(status)));
          return FALSE;
        }

      ssh_xfree(key);

      buf = ssh_xmalloc(ssh_mac_length(ssh_mac_name(mac)));

      iterations = 1024;
    retry:
      buf2 = ssh_xmalloc(len);

      for (i = 0; i < len; i++)
        buf2[i] = (i & 0xff);

      if (do_speed_test)
        {
          ssh_time_measure_reset(&tmit);
          ssh_time_measure_start(&tmit);
        }

      for (i = 0; i < iterations; i++)
        {
	  ssh_mac_reset(mac);
          ssh_mac_update(mac, buf2, len);
	  if (ssh_mac_final(mac, buf) != SSH_CRYPTO_OK)
	    return FALSE;
	}


      if (do_speed_test)
        ssh_time_measure_stop(&tmit);

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
                printf("  - %s was too fast, retrying...\n", temp_mac_name);
              goto retry;
            }

          if (ssh_time_measure_get(&tmit, SSH_TIME_GRANULARITY_SECOND)
              >= TEST_TIME_MIN)
            printf("%s -- " TEST_FMT " KiBytes/sec (" TEST_FMT " ns / call)\n",
                   temp_mac_name, ((double)iterations * len) /
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
                   temp_mac_name);
        }

      /* Put here some tests. */

      ssh_xfree(buf);

      ssh_mac_free(mac);
      temp_mac_name = strtok(NULL, ",");
    }

  ssh_free(mac_name);

  return TRUE;
}

Boolean mac_static_tests(const char *filename)
{
  char mac_name[256];
  unsigned char *buf = NULL;
  unsigned char *str;
  size_t len;
  SshMac mac = NULL;
  RFStatus status;
#define MAC_IGNORE 0
#define MAC_READ_KEY 1
#define MAC_OUTPUT   2
#define MAC_INPUT    3
  unsigned int state = MAC_IGNORE;

  status = ssh_t_read_init(filename);

  if (status != RF_READ)
    ssh_fatal("error: file mac.tests not available.");

  while (status != RF_EMPTY)
    {
      status = ssh_t_read_token(&str, &len);
      switch (status)
        {
        case RF_LABEL:
          if (mac != NULL)
            {
              ssh_mac_free(mac);
	      mac = NULL;
              ssh_xfree(buf);
              buf = NULL;
            }

          if (len > 256)
            ssh_fatal("error: mac name too long.");

          memcpy(mac_name, str, len);
          mac_name[len] = '\0';

          if (ssh_mac_supported(mac_name))
            state = MAC_READ_KEY;
          else
            {
              ssh_debug("mac %s not supported", mac_name);
              state = MAC_IGNORE;
            }
          break;
        case RF_HEX:
        case RF_ASCII:
          switch (state)
            {
            case MAC_READ_KEY:
              if (ssh_mac_allocate(mac_name, str, len, &mac) != SSH_CRYPTO_OK)
                {
                  SSH_DEBUG(0, ("Could not allocate `%s' MAC.", mac_name));
                  return FALSE;
                }

              buf = ssh_xmalloc(ssh_mac_length(ssh_mac_name(mac)));

              state = MAC_INPUT;
              break;
            case MAC_INPUT:
              ssh_mac_reset(mac);
              ssh_mac_update(mac, str, len);
              state = MAC_OUTPUT;
              break;
            case MAC_OUTPUT:
              ssh_mac_final(mac, buf);

              if (len < ssh_mac_length(ssh_mac_name(mac)))
                {
                  SSH_DEBUG(0, ("File MAC output too short."));
                  return FALSE;
                }

              if (memcmp(str, buf, ssh_mac_length(ssh_mac_name(mac))) != 0)
                {
                  HexRenderStruct wrong, correct;

                  correct.length = wrong.length = ssh_mac_length(mac_name);
                  wrong.data = buf;
                  correct.data = str;

                  SSH_DEBUG(0,
                            ("Wrong digest for `%s' MAC: Wrong=%@, Correct=%@",
                             mac_name,
                             hex_render, &wrong, hex_render, &correct));

                  return FALSE;
                }

              state = MAC_INPUT;
              break;
            case MAC_IGNORE:
              mac = NULL;
              break;
            default:
              ssh_fatal("error: unknown state (%d).", state);
              break;
            }
        case RF_EMPTY:
          break;
        default:
          ssh_fatal("error: file corrupted (%d).", status);
          break;
        }
    }

  ssh_t_close();
  if (mac)
    {
      ssh_mac_free(mac);
      mac = NULL;
    }
  ssh_xfree(buf);

  return TRUE;
}

Boolean mac_static_tests_do(const char *filename)
{
  char *mac_names, *temp_mac_name;
  unsigned char *key;
  size_t keylen;
  unsigned char *buf;
  unsigned char *buf2;
  SshMac mac;
  int i, j, k, len;
  RFStatus status;

  status = ssh_t_write_init(filename);

  if (status != RF_WRITE)
    ssh_fatal("error: could not open %s for writing.", filename);

  ssh_t_write_token(RF_LINEFEED, NULL, 0);
  ssh_t_write_token(RF_COMMENT, (char*) filename, strlen(filename));
  ssh_t_write_token(RF_LINEFEED, NULL, 0);

  mac_names = ssh_mac_get_supported();
  temp_mac_name = strtok(mac_names, ",");


  while (temp_mac_name)
    {
      ssh_t_write_token(RF_COMMENT, (unsigned char *) temp_mac_name,
                        strlen(temp_mac_name));
      for (k = 0; k < 16; k++)
        {
          keylen = mac_key_len(temp_mac_name);
          key = ssh_xmalloc(keylen);

          for (i = 0; i < keylen; i++)
            key[i] = ssh_random_get_byte();

          if (ssh_mac_allocate(temp_mac_name, key, keylen, &mac)
              != SSH_CRYPTO_OK)
            ssh_fatal("error: mac allocate %s failed.", temp_mac_name);

          ssh_t_write_token(RF_LINEFEED, NULL, 0);
          ssh_t_write_token(RF_LABEL, (unsigned char *) temp_mac_name,
                            strlen(temp_mac_name));

          ssh_t_write_token(RF_HEX, key, keylen);
          ssh_t_write_token(RF_LINEFEED, NULL, 0);

          ssh_xfree(key);

          for (j = 0; j < 8; j++)
            {

              buf = ssh_xmalloc(ssh_mac_length(ssh_mac_name(mac)));

              len = j*2 + 10;
              buf2 = ssh_xmalloc(len);

              for (i = 0; i < len; i++)
                buf2[i] = ssh_random_get_byte();

              ssh_t_write_token(RF_HEX, buf2, len);

              /* Put here some tests. */

              ssh_mac_reset(mac);

              ssh_mac_update(mac, buf2, len);
              ssh_xfree(buf2);

              ssh_mac_final(mac, buf);

              ssh_t_write_token(RF_HEX, buf,
                                ssh_mac_length(ssh_mac_name(mac)));

              ssh_t_write_token(RF_LINEFEED, NULL, 0);

              /* Put here some tests. */

              ssh_xfree(buf);
            }
          ssh_mac_free(mac);
        }

      temp_mac_name = strtok(NULL, ",");
    }

  ssh_free(mac_names);
  ssh_t_close();

  return TRUE;
}
