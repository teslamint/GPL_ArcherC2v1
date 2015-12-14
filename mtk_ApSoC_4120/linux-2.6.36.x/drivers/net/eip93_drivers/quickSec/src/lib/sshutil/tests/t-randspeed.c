/*

  t-randspeed.c

  Author: Mika Kojo <mkojo@ssh.fi>

  Copyright:
          Copyright (c) 2002, 2003 SFNT Finland Oy.
  All rights reserved.

  Created Fri Oct 20 22:07:14 2000.

  */

/* Simple test for testing random number generation speed, and
   producing at the side a large quantity or pseudo-random numbers. */

#include "sshincludes.h"

#ifdef HAVE_MATH_H
#include <math.h>
#endif /* HAVE_MATH_H */

#include "sshrand.h"
#include "sshtimemeasure.h"

static double chi_square_sum(double x, unsigned int n)
{
  double z, lambda, l = 0;
  int i;

  /* If n is odd, then we cannot use the integral formula (although
     we will use it anyway!). */
  if (n & 1)
    n++;

  lambda = x/2;
  n = n/2;

#ifdef HAVE_MATH_H
  l = exp(-lambda);
#endif /* HAVE_MATH_H */
  z = 1.0;

  for (i = 0; i < n; i++)
    {
      z -= l;
      l *= lambda;
      l /= (i+1);
    }

  return z;
}

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

int quick_test_1(void)
{
  unsigned int bucket[1024], i, r;
  double d;

  ssh_rand_seed(1234);

  for (i = 0; i < 1024; i++)
    bucket[i] = 0;

  for (i = 0; i < 1024*1024; i++)
    {
      r = ssh_rand();
      bucket[r % 1024]++;
    }

  d = chi_square_uniform(bucket, 1024, 1024 * 1024);

  if (d > 0.999)
    return 0;
  return 1;
}

int quick_test_2(void)
{
  unsigned int bucket[1024], i, r, lo, hi, ll;
  double d;

  ssh_rand_seed(1234);
  lo = (ssh_rand() % 50) + 10;
  hi = (ssh_rand() % 50) + lo + 1;
  ll = hi - lo + 1;

  for (i = 0; i < ll; i++)
    bucket[i] = 0;

  for (i = 0; i < ll*1024*16; i++)
    {
      r = ssh_rand_range(lo,hi);
      if (r < lo || r > hi)
        ssh_fatal("sshrand failed in ssh_rand_range ([%u,%u] produced %u)!",
                  lo, hi, r);
      bucket[r - lo]++;
    }

  d = chi_square_uniform(bucket, ll, ll * 1024 * 16);

  if (d > 0.999)
    return 0;
  return 1;
}

void tstart(SshTimeMeasure tmit, char *fmt, ...)
{
  va_list ap;
  char buffer[1024];

  va_start(ap, fmt);
  ssh_vsnprintf(buffer, 1024, fmt, ap);
  va_end(ap);

  printf("Timing start: %s\n", buffer);

  ssh_time_measure_reset(tmit);
  ssh_time_measure_start(tmit);
}

void tstop(SshTimeMeasure tmit, char *fmt, ...)
{
  va_list ap;
  char buffer[1024];
  ssh_time_measure_stop(tmit);

  va_start(ap, fmt);
  ssh_vsnprintf(buffer, 1024, fmt, ap);
  va_end(ap);

  printf("Timing stop @ %f sec : %s\n",
         (double) ssh_time_measure_get(tmit,
                                       SSH_TIME_GRANULARITY_MILLISECOND) /
         1000.0,
         buffer);
}


void tstartn(SshTimeMeasure tmit, int total, char *fmt, ...)
{
  va_list ap;
  char buffer[1024];

  if (total > 0)
    {
      ssh_time_measure_reset(tmit);
      ssh_time_measure_start(tmit);
      return;
    }

  va_start(ap, fmt);
  ssh_vsnprintf(buffer, 1024, fmt, ap);
  va_end(ap);

  printf("Timing start: %s\n", buffer);

  ssh_time_measure_reset(tmit);
  ssh_time_measure_start(tmit);
}

int tstopn(SshTimeMeasure tmit, int total, char *fmt, ...)
{
  va_list ap;
  char buffer[1024];
  ssh_time_measure_stop(tmit);

  /* Just check that the operation takes at least some time. */
  if (ssh_time_measure_get(tmit, SSH_TIME_GRANULARITY_MILLISECOND) < 100.0)
    {
      return 1;
    }

  va_start(ap, fmt);
  ssh_vsnprintf(buffer, 1024, fmt, ap);
  va_end(ap);

  printf("Timing stop @ %6.3f sec / %u ops = %6.4f sec / op: \n  %s\n",
         (double) ssh_time_measure_get(tmit,
                                       SSH_TIME_GRANULARITY_MILLISECOND) /
         1000.0, total,
         ((double) ssh_time_measure_get(tmit,
                                       SSH_TIME_GRANULARITY_MILLISECOND) /
         1000.0)/(double)total,
         buffer);
  return 0;
}

int main(int ac, char *av[])
{
  size_t i, t, f, prnd;
  struct SshTimeMeasureRec tmit = SSH_TIME_MEASURE_INITIALIZER;

#if !defined(HAVE_LIBM) && !defined(HAVE_MATH_H)
  exit(0);
#endif

  /* Initialize the number of failures. */
  f = 0;

  printf("Running quick tests for sshrand.\n");
  if (quick_test_1() == 0) f++, printf(" ** test 1 failed.\n");
  if (quick_test_2() == 0) f++, printf(" ** test 2 failed.\n");

  printf("Running timing tests for sshrand "
         "(and for other available generators).\n");

  /* Generating a megawords of randomness. */
  prnd = 1024 * 1024;

#define OK_CRAND   0x01d80000
#define OK_GNURAND 0x3e17b13d
#define OK_SSHRAND 0x2405164b

  tstart(&tmit, "Initialization of C rand.");
  srand(1001);
  tstop(&tmit, "C rand initialized.");

  tstart(&tmit, "Generating %u bytes of prandom data with C rand.",
         prnd);

  for (i = 0, t = 0; i < prnd; i++)
    {
      t += rand();
    }

  tstop(&tmit, "C rand stopped with checksum %s (%08x)",
        (t == OK_CRAND) ? "ok" : "failed",
        t);

  if (t != OK_CRAND) f++;

  tstart(&tmit, "Initialization of GNU random.");
  ssh_rand_seed(1001);
  tstop(&tmit, "GNU random initialized.");

  tstart(&tmit, "Generating %u bytes of prandom data with GNU random.",
         prnd);

  for (i = 0, t = 0; i < prnd; i++)
    {
      t += ssh_rand();
    }

  tstop(&tmit, "GNU random stopped with checksum %s (%08x).",
        (t == OK_GNURAND) ? "ok" : "failed",
        t);

  if (t != OK_GNURAND) f++;

  tstart(&tmit, "Initialization of SSH rand.");
  ssh_rand_seed(1001);
  tstop(&tmit, "SSH random initialized.");

  tstart(&tmit, "Generating %u bytes of prandom data with SSH rand.",
         prnd);

  for (i = 0, t = 0; i < prnd; i++)
    {
      t += ssh_rand();
    }

  tstop(&tmit, "SSH rand stopped with checksum %s (%08x).",
        (t == OK_SSHRAND) ? "ok" : "failed",
        t);

  if (t != OK_SSHRAND) f++;

  printf("%u failures.\n", f);

  if (f > 0)
    {
      printf(""
"Caution. This program has detected a failure(s). Any of the following may\n"
"         be the cause of this failure (more exact indication of error\n"
"         might have appeared above);\n"
"          1. the C rand or GNU random libraries may have generated\n"
"             checksum that was not verified.\n"
"          2. the sshrand library may have generated a checksum that\n"
"             did not match. This is a fatal error and should be\n"
"             investigated carefully.\n"
"          3. one or more of the quick tests failed. These indicate\n"
"             statistical weakness in the generator. Such problems can\n"
"             be due to compilation, platform or even inherent error in\n"
"             the sshrand library. This is a fatal error and should be\n"
"             investigated carefully.\n"
"\n"
"        In case of an fatal error you may wish to consult the support at\n"
"        SFNT Finland Oy.\n");
    }

  ssh_util_uninit();
  return f;
}
