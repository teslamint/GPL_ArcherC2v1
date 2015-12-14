/*
 *
 * Author: Tero Kivinen <kivinen@iki.fi>
 *
 *  Copyright:
 *          Copyright (c) 2002, 2003 SFNT Finland Oy.
 */

#include "sshincludes.h"
#include "sshcrypt.h"
#include "sshtimemeasure.h"

#define MAX_BLOCK_SIZE 1048576
#define REPEAT 10

#define SSH_DEBUG_MODULE "t-sshcrypto"

int main(int argc, char **argv)
{
  struct SshTimeMeasureRec tmit = SSH_TIME_MEASURE_INITIALIZER;
  const char *cipher_name = "3des-cbc";
  const char *mac_name = "hmac-md5";
  const char *hash_name = "md5";
  unsigned char iv[SSH_CIPHER_MAX_IV_SIZE];
  size_t key_len, block_length;
  unsigned char *key, *block;
  SshCryptoStatus cret;
  SshTimeT cipher_usec, hash_usec;
  SshTimeT mac_usec, prev_mac_usec;
  SshCipher cipher;
  SshHash hash;
  SshMac mac;
  int i;
  int number_of_blocks;

  if (ssh_crypto_library_initialize() != SSH_CRYPTO_OK)
    ssh_fatal("Cannot initialize the crypto library.");

  if (ssh_crypto_library_self_tests() != SSH_CRYPTO_OK)
    ssh_fatal("Crypto library self tests failed.");

  if (argc > 1)
    cipher_name = argv[1];
  if (argc > 2)
    mac_name = argv[2];
  if (argc > 3)
    hash_name = argv[3];

  key_len = ssh_cipher_get_key_length(cipher_name);
  SSH_ASSERT(key_len > 0);
  key = ssh_xmalloc(key_len);
  for (i = 0; i < key_len; i++)
    key[i] = ssh_random_get_byte();

  cret = ssh_hash_allocate(hash_name, &hash);
  if (cret != SSH_CRYPTO_OK)
    ssh_fatal("ssh_hash_allocate failed : %s",
              ssh_crypto_status_message(cret));

  ssh_time_measure_reset(&tmit);
  ssh_time_measure_start(&tmit);
  for (i = 0; i < 1000 * REPEAT; i++)
    {
      ssh_hash_reset(hash);
      ssh_hash_update(hash, iv, 12);
      ssh_hash_final(hash, iv);
    }
  ssh_time_measure_stop(&tmit);
  hash_usec = ssh_time_measure_get(&tmit,
                                   SSH_TIME_GRANULARITY_MICROSECOND);

  for (number_of_blocks = 1; number_of_blocks < 32; number_of_blocks++)
    {
      cret = ssh_cipher_allocate(cipher_name, key, key_len, FALSE, &cipher);
      if (cret != SSH_CRYPTO_OK)
        ssh_fatal("ssh_cipher_allocate failed : %s",
                  ssh_crypto_status_message(cret));

      block_length = ssh_cipher_get_block_length(ssh_cipher_name(cipher))
        * number_of_blocks;
      block = ssh_xmalloc(block_length);
      for (i = 0; i < block_length; i++)
        block[i] = ssh_random_get_byte();

      ssh_time_measure_reset(&tmit);
      ssh_time_measure_start(&tmit);
      for (i = 0; i < 1000 * REPEAT; i++)
        {
          cret = ssh_cipher_transform_with_iv(cipher, block,
                                              block, block_length,
                                              iv);
          if (cret != SSH_CRYPTO_OK)
            ssh_fatal("ssh_cipher_transform_with_iv failed : %s",
                      ssh_crypto_status_message(cret));
        }
      ssh_time_measure_stop(&tmit);
      cipher_usec = ssh_time_measure_get(&tmit,
                                         SSH_TIME_GRANULARITY_MICROSECOND);
      ssh_cipher_free(cipher);

      cret = ssh_mac_allocate(mac_name, key, key_len, &mac);

      if (cret != SSH_CRYPTO_OK)
        ssh_fatal("ssh_mac_allocate failed : %s",
                  ssh_crypto_status_message(cret));

      ssh_xfree(block);
      block = ssh_xmalloc(MAX_BLOCK_SIZE);

      block_length = 1;
      do {
        ssh_time_measure_reset(&tmit);
        ssh_time_measure_start(&tmit);
        for (i = 0; i < 1000 * REPEAT; i++)
          {
            ssh_mac_reset(mac);
            ssh_mac_update(mac, block, block_length);
            ssh_mac_final(mac, block);
          }
        ssh_time_measure_stop(&tmit);
        mac_usec = ssh_time_measure_get(&tmit,
                                        SSH_TIME_GRANULARITY_MICROSECOND);
        if (mac_usec > cipher_usec + hash_usec)
          break;
        prev_mac_usec = mac_usec;
        block_length *= 2;
        if (block_length > MAX_BLOCK_SIZE)
          ssh_fatal("Mac too fast, can do more than %d bytes",
                    MAX_BLOCK_SIZE);
      } while (1);
      ssh_mac_free(mac);
      ssh_free(block);

      printf("%s = %g ns / %d blocks, %s = %g ns / 12 bytes, "
             "%s = %d bytes / %d cipher blocks (%g ns)\n",
             cipher_name, cipher_usec / REPEAT, number_of_blocks,
             hash_name, hash_usec / REPEAT,
             mac_name, block_length / 2, number_of_blocks,
             mac_usec / REPEAT);
    }
  ssh_hash_free(hash);
  ssh_free(key);
  ssh_crypto_library_uninitialize();
  ssh_util_uninit();
  exit(0);
}
