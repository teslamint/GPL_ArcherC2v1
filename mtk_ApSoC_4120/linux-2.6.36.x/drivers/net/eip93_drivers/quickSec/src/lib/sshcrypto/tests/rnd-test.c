/*

  rndtest.c

  Copyright:
          Copyright (c) 2002-2005 SFNT Finland Oy.
  All rights reserved.

  Testing those gen- prefixed files.

  */
#include "sshincludes.h"
#include "sshcrypt.h"
#include "sshtimemeasure.h"
#include "readfile.h"
#include "sshmp.h"
#include "sshdsprintf.h"

#define SSH_DEBUG_MODULE "GenTestRand"

/********************** Random number tests. **********************/

/* Bit frequency tests. */

unsigned int rnd_bytes[256];
unsigned int rnd_freq[8][8];
unsigned int rnd_bits[8];

void rnd_set_freq(int i)
{
  rnd_bits[i]++;
  if (rnd_freq[i][0])
    {
      if (rnd_freq[i][0] < 7)
        rnd_freq[i][rnd_freq[i][0]]++;
      else
        rnd_freq[i][7]++;
      rnd_freq[i][0] = 0;
    }
}

void rnd_add_freq(void)
{
  int i;

  for (i = 0; i < 8; i++)
    rnd_freq[i][0]++;
}

Boolean rnd_test_bits(SshRandom rng)
{
  int i, hi, lo, average, j, byte, error = 0;
  double av;
  unsigned char buf[6];

  SSH_DEBUG(2, ("Running random number bit tests..."));

  for (i = 0; i < 8; i++)
    {
      rnd_bits[i] = 0;
      for (j = 0; j < 8; j++)
        rnd_freq[i][j] = 0;
    }

  for (j = 0; j < 256; j++)
    rnd_bytes[j] = 0;

  for (i = 0; i < 1000000; i++)
    {
      if (ssh_random_get_bytes(rng, buf, 1) != SSH_CRYPTO_OK)
        return FALSE;

      byte = buf[0] & 0xff;

      rnd_bytes[byte]++;

      if (byte & 128)
        rnd_set_freq(7);
      if (byte & 64)
        rnd_set_freq(6);
      if (byte & 32)
        rnd_set_freq(5);
      if (byte & 16)
        rnd_set_freq(4);
      if (byte & 8)
        rnd_set_freq(3);
      if (byte & 4)
        rnd_set_freq(2);
      if (byte & 2)
        rnd_set_freq(1);
      if (byte & 1)
        rnd_set_freq(0);

      rnd_add_freq();
    }

  for (j = 0, hi = 0, lo = i, average = 0; j < 256; j++)
    {
      if (rnd_bytes[j] < lo)
        lo = rnd_bytes[j];

      if (rnd_bytes[j] > hi)
        hi = rnd_bytes[j];
    }

  if (hi > 5000 || lo < 3000)
    {
      SSH_DEBUG(1, ("Note: byte distribution is off the set limits."));
      error++;
    }

  SSH_DEBUG(3, ("Plain byte distribution: %d tries: %d highest, %d lowest.",
                i, hi, lo));

  SSH_DEBUG(3, ("Single bit distributions, and counts in time."));

  for (j = 0; j < 8; j++)
    {
      av = ((double)rnd_bits[j]) / (double)i;

      SSH_DEBUG(3, ("bit %d av. %f  %5d %5d %5d %5d %5d %5d . %5d", j,
                    av,
                    rnd_freq[j][1], rnd_freq[j][2], rnd_freq[j][3],
                    rnd_freq[j][4], rnd_freq[j][5], rnd_freq[j][6],
                    rnd_freq[j][7]));

      /* Simple checks for too good results. */
      if (av == 0.5 ||
          (rnd_freq[j][1] == 250000 || rnd_freq[j][2] == 125000 ||
          rnd_freq[j][3] == 62500  || rnd_freq[j][4] == 31250 ||
          rnd_freq[j][5] == 15625))
        {
          SSH_DEBUG(0, ("Note: bit distributions are too good. "
                 "Please check these results."));
        }

      /* Checks for too poor results. */

      if (av < 0.30 || av > 0.70)
        {
          SSH_DEBUG(1, ("Note: average bit distribution is off"
                 " the set limits."));
          error++;
        }

      if ((rnd_freq[j][1] < 200000 || rnd_freq[j][1] > 290000) ||
          (rnd_freq[j][2] < 100000 || rnd_freq[j][2] > 150000) ||
          (rnd_freq[j][3] <  50000 || rnd_freq[j][3] >  70000) ||
          (rnd_freq[j][4] <  25000 || rnd_freq[j][4] >  35000) ||
          (rnd_freq[j][5] <  12000 || rnd_freq[j][5] >  18000) ||
          (rnd_freq[j][6] <   6000 || rnd_freq[j][6] >   10000) ||
          (rnd_freq[j][7] <   6000 || rnd_freq[j][7] >   10000))
        {
          SSH_DEBUG(1, ("Note: bit distributions in time are "
                 "off the set limits."));
          error++;
        }
    }

  if (error)
    return FALSE;

  return TRUE;
}

/* Missing sequence tests. */

#define TEST_LOOP_START(SIZE,LOOPS,BYTES,BUF)                           \
do {                                                                    \
  size_t __size,__loops, __bytes;                                       \
  SshUInt32 __bit;                                                      \
  unsigned char *__table;                                               \
  int __i, __m;                                                         \
  double __avg;                                                         \
  __size = (SIZE);                                                      \
  __loops = (LOOPS);                                                    \
  __bytes = (BYTES);                                                    \
  __table = ssh_xcalloc(1, __size);                                     \
  SSH_DEBUG(3,                                                          \
            ("Running test for sequences of %d "                        \
             "(table size %d bytes)",                                   \
             __bytes,__size));                                          \
                                                                        \
  for (i = 0; i < __loops; i++)                                         \
    {                                                                   \
      if (ssh_random_get_bytes(rng, (BUF), __bytes) != SSH_CRYPTO_OK)   \
        return FALSE;

#define TEST_LOOP_END(BIT,ERR)                                            \
  __bit = (BIT);                                                          \
                                                                          \
  SSH_ASSERT((__bit / 8) < __size);                                       \
  __table[__bit / 8] |= (1 << (__bit & 0x7));                             \
    }                                                                     \
 for (__i = 0, __m = 0; __i < __size * 8; __i++)                          \
   {                                                                      \
     if (!(__table[__i / 8] & (1 << (__i & 0x7))))                        \
       __m++;                                                             \
   }                                                                      \
                                                                          \
 __avg = ((double) __m / (__size * 8));                                   \
 if (__avg < 0.11 || __avg > 0.15)                                        \
   {                                                                      \
     SSH_DEBUG(1, ("Note: Possible error detected."));                    \
     (ERR)++;                                                             \
   }                                                                      \
 SSH_DEBUG(3, ("After %d runs: "                                          \
               "%d of %d missing (average %f after %d full iterations).", \
               __loops, __m, __size * 8,                                  \
               __avg, __loops / (__size * 8)));                           \
                                                                          \
 ssh_xfree(__table);                                                      \
} while (0)

Boolean rnd_test_missing_bits(SshRandom rng)
{
  unsigned char buf[256];
  unsigned int i, l;
  int error = 0;

  /* Sequence of 2, use 8 bit characters */
  TEST_LOOP_START(256 * 256 / 8, 256 * 256 / 8 * 16, 2, buf);
  l = buf[0] * 256 + buf[1];
  TEST_LOOP_END(l, error);

  /* Sequence of 3, use 7 bit characters */
  TEST_LOOP_START(128 * 128 * 128 / 8, 128 * 128 * 128 / 8 * 16, 3, buf);
  l = (buf[0] >> 1) * (128*128) + (buf[1] >> 1) * 128 + (buf[2] >> 1);
  TEST_LOOP_END(l, error);

  /* Sequence of 4, use 5 bit characters */
  TEST_LOOP_START(32 * 32 * 32 * 32 / 8, 32 * 32 * 32 * 32 / 8 * 16, 4, buf);
  l = (buf[0] >> 3) * (32*32*32) + (buf[1] >> 3) * (32*32) +
    (buf[2] >> 3) * 32 + (buf[3] >> 3);
  TEST_LOOP_END(l, error);

  /* Sequence of 5, use 4 bit characters */
  TEST_LOOP_START(16 * 16 * 16 * 16 * 16 / 8, 16 * 16 * 16 *16 * 16 / 8 * 16,
                  5, buf);
  l = (buf[0] >> 4) * (16*16*16*16) +
    (buf[1] >> 4) * (16*16*16) +
    (buf[2] >> 4) * (16*16) +
    (buf[3] >> 4) * 16 +
    (buf[4] >> 4);
  TEST_LOOP_END(l, error);

  /* Sequence of 6, use 3 bit characters */
  TEST_LOOP_START(8 * 8 * 8 * 8 * 8 * 8 / 8, 8 * 8 * 8 * 8 * 8 * 8 / 8 * 16,
                  6, buf);
  l = (buf[0] >> 5) * (8*8*8*8*8) +
    (buf[1] >> 5) * (8*8*8*8) +
    (buf[2] >> 5) * (8*8*8) +
    (buf[3] >> 5) * (8*8) +
    (buf[4] >> 5) * 8 +
    (buf[5] >> 5);
  TEST_LOOP_END(l, error);

  if (error > 2)
    {
      SSH_DEBUG(0, ("Error detected, %d mismatches in different sequences.",
                    error));
      return FALSE;
    }

  return TRUE;
}

Boolean test_random(const char *name, int flag)
{
  SshRandom rng;
  SshCryptoStatus status;
  unsigned char buf[32];
  int i;

  status = ssh_random_allocate(name, &rng);

  for (i = 0; i < sizeof(buf); i++)
    buf[i] = ssh_random_get_byte();

  ssh_random_add_entropy(rng, buf, sizeof(buf), 7 * sizeof(buf));
  if (status != SSH_CRYPTO_OK)
    {
      SSH_DEBUG(0, ("Failed allocating `%s' random number generator: "
                    "%s (%d).",
                    name, ssh_crypto_status_message(status), status));

      return FALSE;
    }

  /* Run the simple bit testing. */
  SSH_DEBUG(1, ("Starting bit tests"));

  if (!rnd_test_bits(rng))
    {
      ssh_random_free(rng);
      return FALSE;
    }

  /* Run the missing sequence tests. */
  SSH_DEBUG(1, ("Starting sequence tests"));

  if (!rnd_test_missing_bits(rng))
    {
      ssh_random_free(rng);
      return FALSE;
    }

  ssh_random_free(rng);

  /* Random tests ends. */
  return TRUE;
}
