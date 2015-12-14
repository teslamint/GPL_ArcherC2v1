/*

  t-random.c

  Copyright:
          Copyright (c) 2002-2004 SFNT Finland Oy.
  All rights reserved.

  Created Wed Jul 19 19:32:22 2000.

  */

/* This program analyzes the SSH's random number generator using
   several simple tests. */

#include <math.h>

#include "sshincludes.h"
#include "sshfileio.h"
#include "sshcrypt.h"
#include "sshtimemeasure.h"
#include "sshrand.h"
#include "sshmp.h"
#include "sshmp-kernel.h"
#include "sshgetopt.h"
#include "sshregression.h"

#define SSH_DEBUG_MODULE "TestRandom"

/* FFT is included just to get one FFT implementation into SSH's
   source tree. */
#include "fft.h"

#define MAX_ALLOC_SIZE ((size_t)1024*1024)

/* Acceptance probability for the distribution. This gives the probability
   by which we will accept good instance of the distribution. */
#define ACCEPT_HI_PROB    0.999
#define ACCEPT_LO_PROB    0.00001

/* The block sizes for block test. */
#define MIN_BLOCK_SIZE 64
#define MAX_BLOCK_SIZE 65536

/*** Generic routines for analyzing distributions. */

/* Routines for handling some distributions. */

static double chi_square_sum(double x, unsigned int n)
{
  double z, lambda, l;
  int i;

  /* If n is odd, then we cannot use the integral formula (although
     we will use it anyway!). */
  if (n & 1)
    n++;

  lambda = x/2;
  n = n/2;

  l = exp(-lambda);
  z = 1.0;

  for (i = 0; i < n; i++)
    {
      z -= l;
      l *= lambda;
      l /= (i+1);
    }

  return z;
}

#if 0
/* Compute Chi-square table for testing. */
static void chi_square_init(void)
{
  unsigned int df;
  double x[10] =
  { 6.63, 9.21, 11.3, 13.3, 15.1, 16.8, 18.5, 20.1, 21.7, 23.2 };

  for (df = 1; df < 11; df++)
    {
      printf(" %2u, %g : %g\n",
             df, x[df-1], chi_square_sum(x[df-1], df));
      printf(" %2u, %g : %g\n",
             df, x[df-1]/2.0, chi_square_sum(x[df-1]/2.0, df));
      printf(" %2u, %g : %g\n",
             df, x[df-1]*2.0, chi_square_sum(x[df-1]*2.0, df));
    }
}
#endif


/* Using Chi-square test study the input distribution against
   uniform distribution. */
static double chi_square_uniform(unsigned int *c, size_t c_len,
                                 unsigned int  number_of_samples)
{
  size_t i;
  double v, delta, d;

  delta = ((double)number_of_samples / (double)c_len);

  /* Compute the squared sum. */
  for (v = 0.0, i = 0; i < c_len; i++)
    {
      double t;
      t = c[i] - delta;
      v += t*t;
    }

  /* Finish the chi-square computation. */
  v = ((double)c_len/(double)number_of_samples)*v;

  /* Compute the probability. */
  d = chi_square_sum(v, c_len-1);

#if 0
  printf("Value c = [%u, %u]; n = %u; v = %g with df = %u with p = %g\n",
         c[0], c[1], number_of_samples,
         v, c_len-1, d);
#endif

  return d;
}


/* Chi-square (non-uniform). */
static double chi_square_statistic(unsigned int *c,
                                   double       *p,
                                   size_t c_len,
                                   unsigned int number_of_samples)
{
  size_t i;
  double v, d;

  /* Compute the squared sum. */
  for (v = 0.0, i = 0; i < c_len; i++)
    {
      double t, k;
      k = p[i]*number_of_samples;
      t = c[i] - k;
      v += t*t/k;
    }

  /* Compute the probability. */
  d = chi_square_sum(v, c_len-1);

  return d;
}

/*** Linearity tests. */

static int parity(unsigned int x)
{
  x ^= (x >> 16);
  x ^= (x >> 8);
  x ^= (x >> 4);
  x ^= (x >> 2);
  x ^= (x >> 1);
  return x & 1;
}

static int test_linearity_mask(unsigned char *s, size_t s_len,
                               unsigned char *buf, size_t b_len)
{
  size_t i, j;
  double v;
  unsigned int c[2], ns;

  /* Clear counters. */
  c[0] = c[1] = 0;
  ns = 0;
  /* Start checking. */
  for (i = 0; i + b_len < s_len; i += b_len)
    {
      int p = 0;
      for (j = 0; j < b_len; j++)
        p ^= parity(buf[j] & s[i+j]);
      c[p]++;
      ns++;
    }

  /* Now determine whether the distribution between 0 and 1 is uniform. */
  v = chi_square_uniform(c, 2, ns);
  if (v > ACCEPT_HI_PROB)
    {
      printf("Warning: unacceptable distribution (p = %g).\n", 1.0-v);
      printf("         c = [%u, %u], n = %u.\n",
             c[0], c[1], ns);

      return 1;
    }
  return 0;
}

static int test_linearity(unsigned char *s, size_t s_len)
{
#define MAX_MASK_SIZE 5
  unsigned char buf[MAX_MASK_SIZE];
  size_t i, l, m;
  int rv;

  for (l = 1; l < MAX_MASK_SIZE; l++)
    {
      if (l == 1)
        {
          /* One byte masks are handled exhaustively. */
          for (m = 1; m < 256; m++)
            {
              for (i = 0; i < l; i++)
                buf[i] = m;

              rv = test_linearity_mask(s, s_len, buf, l);
              if (rv != 0)
                {
                  printf("Warning: Mask 0x%02x detected linearity.\n", m);
                  return rv;
                }
            }
        }
      else
        {
          /* We work with 50 instances of each > 1 byte mask, using
             simple affine thing to generate the masks. */
          for (m = 0; m < 50; m++)
            {
              int k;
              for (i = 0, k = (m+1); i < l; i++)
                {
                  while (1)
                    {
                      buf[i] = (89*k + m + 1) & 0xff;
                      if (buf[i] != 0)
                        break;
                      k++;
                    }
                }

              rv = test_linearity_mask(s, s_len, buf, l);
              if (rv != 0)
                {
                  printf("Warning: Long mask (l = %u) "
                         "detected linearity.\n", l);
                  return rv;
                }
            }
        }
    }
  return 0;
}


/*** Hash test. */

/* Remark. This hash function is pretty linear, and thus not good. We
   should try other hash functions too. Observe that if the hash function
   is poor, and loses information (significantly) then the distribution
   will be biased even if the input stream is random.

   So we should make sure that the hash function is foremost surjective,
   and for given input has almost even distribution. Of course, this
   is not easy to prove (and this given hash function certainly does
   not satisfy it), but as we allow quite a lot of variance very rough
   estimates are ok.
   */


#define NUM_OF_HASHES 3
static unsigned int test_hash_adhoc(unsigned char *s, size_t bytes,
                                    unsigned int out_size)
{
  unsigned int hash = 0xabcd0123;
  unsigned int i;

  for (i = 0; i < bytes; i++)
    {
      hash ^= (((hash << 11) ^ (hash >> 23)) ^ (hash << 1)) ^ (hash << 5);
      hash ^= ((unsigned int)s[i] ^ i);
    }

  return hash % out_size;
}

#if 0
/* Remark. This hash function is not very good for our tests, as it
   works less than optimally with small "out_size". */
static unsigned long test_hash_huima(unsigned char *s, size_t bytes,
                                     unsigned int out_size)
{
  int i;
  int size = bytes;
  SshUInt32 h = 0;
  for (i = 0; i < size; i++)
    {
      h = ((h << 19) ^ (h >> 13)) + ((unsigned char *)s)[i];
    }
  return h % out_size;
}
#endif

static unsigned int test_hash_copy(unsigned char *s, size_t bytes,
                                   unsigned int out_size)
{
  unsigned int hash = 0;
  unsigned int i;

  for (i = 0; i < bytes; i++)
    hash = (hash << 8) | ((unsigned int)s[i]);

  return hash % out_size;
}

static unsigned int test_hash_copy_rot7(unsigned char *s, size_t bytes,
                                         unsigned int out_size)
{
  unsigned int hash = 0;
  unsigned int i;

  for (i = 0; i < bytes; i++)
    hash = ((hash << 8) | ((unsigned int)s[i])) ^ (hash >> 7);

  return hash % out_size;
}


static unsigned int test_block_log2(unsigned int x)
{
  unsigned int t, k;

  for (t = 1, k = 0; t < x; t <<= 1, k++)
    ;
  return k;
}

static int test_block(unsigned char *s, size_t s_len)
{
  unsigned char *block;
  size_t block_size;
  int i, hf;
  unsigned int c[2];
  double       p[2], v;

   for (hf = 0; hf < NUM_OF_HASHES; hf++)
    for (block_size = MIN_BLOCK_SIZE;  block_size < MAX_BLOCK_SIZE;
         block_size *= 2)
      {
        unsigned int bytes, nv;
        block = ssh_xcalloc(1, (block_size + 7)/8);

        for (bytes = (test_block_log2(block_size) + 7)/8;
             bytes < 10; bytes++)
          {
            memset(block, 0, (block_size + 7)/8);

            for (i = 0, nv = 0; i + bytes < s_len; i++)
              {
                unsigned int hash;
                switch (hf)
                  {
                  case 0:
                    hash = test_hash_copy(s + i, bytes, block_size);
                    break;
                  case 1:
                    hash = test_hash_copy_rot7(s + i, bytes, block_size);
                    break;
                  case 2:
                    hash = test_hash_adhoc(s + i, bytes, block_size);
                    break;
                  default:
                    printf("ERROR: hash function not available (%u).\n", hf);
                    return 2;
                  }
                block[hash/8] |= (1 << (hash % 8));
                nv++;
              }

            /* Compute the hypothetical probabilities.

               This is based on a function

               f_n(m) = m + (n - m)/n,

               which gives the expected number of ones in the table (by
               recursive evaluation).

               We write

               phi(m) = f_n(m) / n = (m + (n-m)/n)/n = m/n + (n - m)/(n^2),

               and compute phi^n(0).

               */
            p[1] = 0;
            for (i = 0; i < nv; i++)
              p[1] = p[1] + (block_size - p[1])/block_size;
            p[1] *= ((double)1.0/block_size);
            p[0] = 1.0 - p[1];

            /* Do the counting. */
            c[0] = 0;
            c[1] = 0;
            for (i = 0; i < block_size; i++)
              {
                if (block[i/8] & (1 << (i%8)))
                  c[1]++;
                else
                  c[0]++;
              }

            /* Run the Chi-square. */
            v = chi_square_statistic(c, p, 2, block_size);
            if (v > ACCEPT_HI_PROB)
              {
                printf("Warning: unacceptable distribution (p = %g).\n",
                       1.0-v);
                printf("         c = [%u, %u], p = [%g, %g], "
                       "n = %u, s = %u.\n",
                       c[0], c[1], p[0], p[1], block_size, s_len);
                printf("         hash function = %s.\n",
                       hf == 0 ? "copying hash" :
                       hf == 1 ? "copying hash with rotation" :
                       hf == 2 ? "ad hoc hash" :
                       "unnamed hash");

                ssh_xfree(block);
                return 1;
              }
          }

        /* Free the block after use. */
        ssh_xfree(block);
      }
  /* Ok. */
  return 0;
}

/*** A test utilizing FFT as a preprocessor! */


/* This test is rather ad hoc, and I must confess that I have not
   proven that the code actually works (in the sense that it would
   detect "bad" octet sequences).

   However, here is how it apparently works:

   Use FFT to transform the input sequence into complex. Map the
   things back to integers (by computing the moduli).

   The trick is to multiply by suitable constant (256.0) such that
   the result mapped to octets is uniformly distributed iff the
   modulies have uniformly distributed decimal digits. Now, it is
   true that this should happen on good generators, the strange thing
   is that e.g. ANSI C's rand doesn't pass this test.

*/


static int test_fft(unsigned char *s, size_t s_len)
{
  double *re, *im;
  unsigned char *data;
  unsigned int i, t, l, len;
  int rv = 0, pos;
  unsigned int c[16];
  double p[16], v;

  /* Use only 2^l of the input stream. */
  for (l = 1, t = 1; l < 16 && t <= s_len; t <<= 1, l++)
    ;
  l--;
  len = ((unsigned int)1 << l);

  /* We do a very simple transform octet at a time, more choices
     could be implemented. */
  re = ssh_xmalloc(sizeof(double)*len);
  im = ssh_xmalloc(sizeof(double)*len);
  data = ssh_xmalloc(sizeof(unsigned char)*len/2);

  for (pos = 0; (pos + len) <= s_len; pos += len)
    {
      for (i = 0; i < len; i++)
        {
          /* Just throw the input stream in. */
          re[i] = s[i];
          im[i] = 0.0;
        }

      /* Do the FFT. */
      fft(re, im, l, 1);

      /* Do a trick here. */
      for (i = 0; i < len/2; i++)
        {
          data[i] = (unsigned char)(256.0*sqrt(re[i]*re[i] + im[i]*im[i]));
        }

      /* Now let us compute a distribution of this. */
      for (i = 0; i < 16; i++)
        {
          c[i] = 0;
          p[i] = 1.0 - fabs((double)i/15 - 1/2);
        }
      for (i = 0; i < len/2; i++)
        c[data[i] & 15]++;

      v = chi_square_uniform(c, 16, len/2);
      if (v > ACCEPT_HI_PROB)
        {
          printf("Warning: unacceptable distribution (p = %g).\n", 1.0-v);
          rv = 1;
          break;
        }
      break;
    }
  ssh_xfree(re);
  ssh_xfree(im);
  ssh_xfree(data);

  return rv;
}

/* The FIPS 140-2 statistical randomness tests */

static int test_fips(unsigned char *s, size_t s_len)
{
  unsigned char *p;
  unsigned int errors, run_errors, bit, max, run, c, i;
  unsigned int poker[16], runs[2][7];
  double chi = 0.0;
  size_t n;
  int min_run[7] = {0, 2315, 1114, 527, 240, 103, 103};
  int max_run[7] = {0, 2685, 1386, 723, 384, 209, 209};

  unsigned char ones[] = {
    0, 1, 1, 2, 1, 2, 2, 3, 1, 2, 2, 3, 2, 3, 3, 4,
    1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5,
    1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5,
    2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
    1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5,
    2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
    2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
    3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7,
    1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5,
    2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
    2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
    3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7,
    2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
    3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7,
    3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7,
    4, 5, 5, 6, 5, 6, 6, 7, 5, 6, 6, 7, 6, 7, 7, 8
  };

#define NUM_BYTES (NUM_BITS / 8 )
#define MIN_ONES 9725
#define MAX_ONES 10275
#define MIN_POKER 2.16
#define MAX_POKER 46.17
#define MAX_RUN 26

  errors = 0;

  if (s_len != 2500)
    ssh_fatal("Need an input sample of 20000 bits");

  /* The Monobit Test */
  p = s;
  c = 0;
  for (n = 0; n < s_len; n++)
    c += ones[*(p+n)];

  if (c <= MIN_ONES || c >= MAX_ONES)
    {
      printf("Sample fails the Monobit Test: %d ones\n", c);
      errors++;
    }
  else
    {
#if 0
      printf("%d ones and %d zeros in the sample\n", c, 20000-c);
      printf("Have passed the Monobit Test.\n\n");
#endif
    }

  /* The Poker Test */
  p = s;
  for (i=0; i<16; i++)
    poker[i] = 0;

  for (n = 0; n < s_len; n++)
    {
      poker[*(p+n) & 0xf]++;
      poker[(*(p+n) >> 4) & 0xf]++;
    }

  for (i = 0; i < 16; i++)
      chi += (double) poker[i] * poker[i];

  chi = (16.0 * chi / 5000.0) - 5000.0;

  if (chi <= MIN_POKER || chi >= MAX_POKER)
    {
      printf("Sample fails the poker test: parameter chi = %g\n", chi);
      errors++;
    }
  else
    {
#if 0
      printf("The Poker test ChiSquared parameter is = %g\n", chi);
      printf("Have passed the Poker Test.\n\n");
#endif
    }

  /* The Runs Test. */
  p = s;
  for (i=0; i<7; i++)
    runs[0][i] = runs[1][i] = 0;

  bit = p[0] & 1;
  max = 1;
  run = 0;

  /* Get the run frequency of the sample. */
  for (n = 0; n < s_len; n++)
    {
      c = *(p+n);
      for (i=0; i<8; i++)
        {
          if ((c&1) == bit)
            run++;
          else
            {
              if (run > 6)
                runs[bit][6]++;
              else
                runs[bit][run]++;
              if (run > max)
                max = run;
              run = 1;
            }
          bit = c&1;
          c >>= 1;
        }
    }
  /* treat the last byte */
  if (run > 6)
    runs[bit][6]++;
  else
    runs[bit][run]++;

  if (run > max)
    max = run;

  run_errors = 0;
  for (run = 1; run < 7; run++)
    {
      for (bit = 0; bit <= 1; bit++)
        {
          if (runs[bit][run] < min_run[run])
            {
              printf("Sample fails the Runs Test: "
                     "too few runs of %d %d bits\n",
                     run, bit);
              run_errors++;
            }
          else
            if (runs[bit][run] > max_run[run])
              {
                printf("Sample fails the Runs Test: "
                       "too many runs of %d %d bits\n",
                       run, bit);
                run_errors++;
              }
        }
    }

#if 0
  printf("The maximum run is %d\n", max);
  printf("The runs frequency is\n");
  printf("%d %d %d %d %d %d\n", runs[0][1], runs[0][2], runs[0][3], runs[0][4],
         runs[0][5], runs[0][6]);
  printf("%d %d %d %d %d %d\n", runs[1][1], runs[1][2], runs[1][3], runs[1][4],
          runs[1][5], runs[1][6]);
#endif


 if (max > MAX_RUN)
    {
      run_errors++;
      printf("Sample fails the Runs Test: "
             "the maximum run is greater than %d\n", MAX_RUN);
    }

#if 0
  if (run_errors == 0)
    {
      printf("Have passed the Runs Test.\n\n");
    }
#endif

  if (errors + run_errors)
    return 2;

  return 0;
}

/*** Test engine. */

/* The test engine uses first the default sample sizes, and then
   raises the sample size by multiple of 2 if 1 is returned by the
   test method.

   This approach gives means for the test method to see whether the
   bad distribution holds as sample size grows. This should remove
   most false alarms.
   */

typedef struct
{
  char *name;
  size_t sample_size;
  int (*method)(unsigned char *s, size_t s_len);
} TestMethod;


static TestMethod test_method[] =
{
  { "linearityTest",
    1024*64,
    test_linearity },

  { "blockTest",
    1024*64,
    test_block },

  { "fftLinearityTest",
    65536,
    test_fft },

 { "fips",
    2500,
    test_fips },

  /* Terminating method. */
  { NULL, 0, NULL_FNPTR }
};

static Boolean tester(char *method, SshRandom generator)
{
  unsigned char *s;
  size_t s_len;
  unsigned int failed = 0, success = 0;
  size_t i;
  int rv;

  SSH_DEBUG(1, ("method=%s generator=%p", method, generator));

  for (i = 0; test_method[i].name; i++)
    {
      if (method)
        {
          if (strcmp(method, test_method[i].name) != 0)
            continue;
        }

      s_len = test_method[i].sample_size;

      while (1)
        {
          if (s_len > MAX_ALLOC_SIZE)
            {
              printf(" => FAILED: Test requested too big sample.\n");
              failed++;
              break;
            }

          /* Creating the sample. */
          s = ssh_xmalloc(s_len);

          if (ssh_random_get_bytes(generator, s, s_len) != SSH_CRYPTO_OK)
            {
              fprintf(stderr, "could not get %d random bytes\n", s_len);
              return FALSE;
            }

          /* Try the test. */
          rv = (*test_method[i].method)(s, s_len);
          switch (rv)
            {
            case 0:
              success++;
              break;

            case 1:
              fprintf(stderr, "(retry with larger sample) ");
              s_len *= 2;
              break;

            default:
              failed++;
              rv = 0;
              break;
            }

          ssh_xfree(s);

          if (rv == 0)
            break;
        }
    }

  if (failed)
    return FALSE;

  return TRUE;
}


static Boolean file_tester(unsigned char *buf, size_t buf_len)
{
  unsigned int failed = 0, success = 0;
  size_t i, s_len, offset;
  int rv;

  for (i = 0; test_method[i].name; i++)
    {
      offset = 0;
      s_len = test_method[i].sample_size;
      
      if (s_len > buf_len)
        {
          ssh_warning("Not performing %s because the input size is "
                      "less than the test sample size (%d)", 
                      test_method[i].name, test_method[i].sample_size);
          continue;
        }

      /* Only perform the test if the input file size 'buf_len' is as large 
         as the test sample size. If 'buf_len' is larger than the file sample 
         size, then repeat the test in linear blocks of the input file 
         as many times as the input file size allows */
      while (offset + s_len < buf_len)
        {
          /* Try the test. */
          rv = (*test_method[i].method)(buf + offset, s_len);
          switch (rv)
            {
            case 0:
              success++;
              break;
          
            case 1:
              fprintf(stderr, "Please retry with a larger sample.\n");
              break;      
              
            default:
              failed++;
              rv = 0;
              break;
            }
          offset += s_len; 
        }
    }
  
  if (failed)
    return FALSE;
  
  return TRUE;
}



static void error (SshCryptoStatus status)
{
  fprintf(stderr, "Encountered error while testing: %s (%d)\n",
          ssh_crypto_status_message(status), status);
}

static Boolean analyse (const char *name, SshRandom random)
{
  SshTimeMeasureStruct timer = SSH_TIME_MEASURE_INITIALIZER;
  size_t len;
  SshCryptoStatus status;
  double interval;
  unsigned char *buf;

  /* First, measure bit generation speed */

  /* Start from 512 bytes */
  len = 512;

  while (1)
    {
      buf = ssh_xmalloc(len);

      ssh_time_measure_reset(&timer);
      ssh_time_measure_start(&timer);

      status = ssh_random_get_bytes(random, buf, len);

      ssh_time_measure_stop(&timer);

      if (status != SSH_CRYPTO_OK)
        {
          error(status);
          return FALSE;
        }

      interval = ssh_time_measure_get(&timer,
                                      SSH_TIME_GRANULARITY_MILLISECOND);
      interval /= 1000.0;

      fprintf(stderr, "%-18s | %9d bytes in %.2lf seconds.. ",
              name, len, interval);

      if (interval < 1.0 && len < (5 * 1024 * 1024))
        {
          ssh_xfree(buf);

          fprintf(stderr, "need more.\r");

          if (interval < 0.1)
            len *= 8;
          else
            len *= 2;

          continue;
        }

      fprintf(stderr, "ok.         \r");

      break;
    }

  SSH_ASSERT(buf != NULL);

  fprintf(stderr,
          "%-18s | %9d kB | %9.1lf KiB/s |                      \n",
          name,
          len / 1024, (double) len / interval / 1024.0);

  /* Now perform some statistical analysis on `buf' */

  /* well, none */

  ssh_xfree(buf);

  return TRUE;
}

/* The number of calls to the random noise request callbacks defined below. */
int default_noise_requests = 0;
int random_noise_requests = 0;

static void default_noise_request_cb(void *context)
{
  char noise[16];

  default_noise_requests++;

  if ((unsigned long)context != 1973)
    ssh_fatal("Unexpected context parameter");

  /* Add 2 bits of "random noise" to the default PRNG */
  memset(noise, 0, sizeof(noise));
  ssh_random_add_noise(noise, sizeof(noise), 2);
}

static void random_noise_request_cb(void *context)
{
  SshRandom random = (SshRandom) context;
  char noise[16];

  random_noise_requests++;

  /* Add 1 bit of "random noise" to the random object. */
  memset(noise, 0, sizeof(noise));
  ssh_random_add_entropy(random, noise, sizeof(noise), 1);
}


static Boolean default_noise_request(void)
{
  unsigned int i, rng;

  default_noise_requests = 0;

  /* Register a noise callback for the global PRNG. */
  if (!ssh_crypto_library_register_noise_request(default_noise_request_cb, 
						 (void *)1973))
    {
      fprintf(stderr, "Cannot register random noise function.\n");
      return FALSE;
    }

  /* Get 128kb of random bytes from the default PRNG. Currently for 
     each of the defined RNG implementation we decrement the number 
     of entropy bits by at MINIMUM 1 for every 16kb of random 
     data output. This implies that the default_noise_request 
     callback must be called at least 4 times (we add 2 bits of 
     entropy for each invocation of default_noise_request. 
     */
  for (i = 0; i < 131072 + 1; i++)
    rng = ssh_random_get_byte();

  /* Check we got at least 4 calls to the noise callback. This check 
     will need to be modified if a RNG is added so that it is defined
     to leak entropy at a rate of less than 1 bit per 16kb. */
  if (default_noise_requests < 4)
    {
      fprintf(stderr, "Less than 4 (%d) calls to default_noise_request\n",
	      default_noise_requests);
      return FALSE;
    }

  SSH_DEBUG(3, ("Default noise requests called %d times", 
		default_noise_requests));

  /* Unregister a noise callback for the global PRNG with a different 
     'context' parameter originally specified. It should fail. */
  if (ssh_crypto_library_unregister_noise_request(default_noise_request_cb, 
						 (void *)1974))
    {
      fprintf(stderr, "Unregister random noise function succeeded when "
	      "should have failed\n");
      return FALSE;
    }

  /* Unregister a noise callback for the global PRNG. */
  if (!ssh_crypto_library_unregister_noise_request(default_noise_request_cb, 
						 (void *)1973))
    {
      fprintf(stderr, "Cannot unregister random noise function.\n");
      return FALSE;
    }
  return TRUE;
}

static Boolean random_noise_request(SshRandom random)
{
  unsigned char buf[128];
  unsigned int i;

  random_noise_requests = 0;

  /* Register a noise callback for the current random object. */
  if (!ssh_crypto_library_register_noise_request(random_noise_request_cb, 
						 random))
    {
      fprintf(stderr, "Cannot register random noise function.\n");
      return FALSE;
    }
  
  /* Get 128kb of random bytes from the random object. Currently for 
     each of the defined RNG implementation we decrement the number 
     of entropy bits by at MINIMUM 1 for every 16kb of random 
     data output. This implies that the random_noise_request 
     callback must be called at least 8 times (we add 1 bit of 
     entropy for each invocation of random_noise_request. 
     */
  for (i = 0; i < 1024 + 1; i++)
    (void)ssh_random_get_bytes(random, buf, sizeof(buf));

  /* Check we got at least 8 calls to the noise callback. This check 
     will need to be modified if a RNG is added so that it is defined
     to leak entropy at a rate of less than 1 bit per 16kb. */
  if (random_noise_requests < 8)
    {
      fprintf(stderr, "Less than 8 (%d) calls to random_noise_request\n",
	      random_noise_requests);
      return FALSE;
    }
  SSH_DEBUG(3, ("Random noise requests called %d times", 
		random_noise_requests));

  /* Unregister a noise callback for the current random object. */
  if (!ssh_crypto_library_unregister_noise_request(random_noise_request_cb, 
						   random))
    {
      fprintf(stderr, "Cannot unregister random noise function.\n");
      return FALSE;
    }
  
  return TRUE;
}

int main(int ac, char *av[])
{
  char *generators, *gen;
  char *random_file = NULL;
  unsigned char *buf;
  size_t buf_len;
  SshRandom random;
  SshCryptoStatus status;
  int opt;
  Boolean analysis, user_generators;

  if (ssh_crypto_library_initialize() != SSH_CRYPTO_OK)
    ssh_fatal("Cannot initialize the crypto library.");

  ssh_regression_init(&ac, &av, "Random number generator tests",
                      "kivinen@safenet-inc.com");

  generators = NULL;
  analysis = FALSE;
  user_generators = FALSE;

  while ((opt = ssh_getopt(ac, av, "g:af:", NULL)) != EOF)
    {
      switch (opt)
        {
        case 'g':
          generators = ssh_xstrdup(ssh_optarg);
          user_generators = TRUE;
          break;
        case 'a':
          analysis = TRUE;
          break;
        case 'f':
          random_file = ssh_optarg;
          break;
        default:
          exit(2);
        }
    }

  if (random_file)
    {
      if (!ssh_read_file(random_file, &buf, &buf_len))
        {
          fprintf(stderr, "Cannot read the file %s", random_file);
          exit(1);
        }
      
      file_tester(buf, buf_len);
      ssh_xfree(buf);
      ssh_crypto_library_uninitialize();
      ssh_regression_finish();
      return 0;
    }


  if (!generators)
    generators = ssh_random_get_supported();

  SSH_DEBUG(2, ("supported = %s", generators));

  if (analysis)
    {
      fprintf(stderr,
              "Type               | Sample size  | Speed          |\n");
      fprintf(stderr,
              "----------------------------------------------------\n");
    }

  for (gen = strtok(generators, ","); gen != NULL; gen = strtok(NULL, ","))
    {
      char buf[512];

      /* Skip 'device' on automatic tests, since it can take a long
         time to get entropy */
      /* `pool' is just a random pool where all entropy must be
         manually entered, not really for us to test */
      if ((strcmp(gen, "device") == 0 ||
           strcmp(gen, "pool") == 0) &&
          !user_generators)
        {
          SSH_DEBUG(2, ("Skipping generator `%s' ", gen));
          continue;
        }

      status = ssh_random_allocate(gen, &random);

      if (status != SSH_CRYPTO_OK)
        {
          if (status == SSH_CRYPTO_UNSUPPORTED)
            {
              fprintf(stderr, "`%s' not supported, skipping.\n", gen);
              continue;
            }

          fprintf(stderr, "Failed to allocate RNG `%s': %s\n",
                  gen, ssh_crypto_status_message(status));

          exit(1);
        }

      ssh_random_add_light_noise(random);
      
      if (!analysis)
        {
          ssh_snprintf(buf, sizeof(buf), "Generator `%s'", gen);
          ssh_regression_section(buf);

          SSH_REGRESSION_TEST("Linearity test",
                              tester, ("linearityTest", random));

          SSH_REGRESSION_TEST("Block test",
                              tester, ("blockTest", random));

          SSH_REGRESSION_TEST("FFT linearity test",
                              tester, ("fftLinearityTest", random));





          SSH_REGRESSION_TEST("Noise request test",
                              random_noise_request, (random));
        }
      else
        {
          ssh_snprintf(buf, sizeof(buf), "%s", gen);
          analyse(buf, random);








        }

      ssh_random_free(random);
    }

  SSH_REGRESSION_TEST("Default PRNG noise request test", 
		      default_noise_request, ());

  ssh_free(generators);
  ssh_crypto_library_uninitialize();
  ssh_regression_finish();

  return 0;
}
