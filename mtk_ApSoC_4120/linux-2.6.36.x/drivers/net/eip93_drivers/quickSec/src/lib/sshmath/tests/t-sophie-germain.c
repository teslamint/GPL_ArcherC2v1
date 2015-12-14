/*

  t-sophie-germain.c

  Author: Mika Kojo <mkojo@ssh.fi>

  Copyright:
          Copyright (c) 2002, 2003 SFNT Finland Oy.
  All rights reserved.

  Created: Wed Jul 23 22:36:43 1997 [mkojo]

  This program tries to find safe primes, and thus Sophie Germain primes,
  using arithmetic progression.

  As an extra feature this program can also generate the starting values
  for the IKE prime searches. Further it is possible search a range of
  IKE primes using this programs batch mode.

  */

#include "sshincludes.h"
#include "sshglobals.h"
#include "sshmp.h"
#include "sshtimemeasure.h"

/* Out integer to a stream. */
void ssh_mprz_out_str(FILE *fp, unsigned int base,
                      SshMPIntegerConst op)
{
  char *str;

  str = ssh_mprz_get_str(op, base);
  if (fp == NULL)
    fputs(str, stdout);
  else
    fputs(str, fp);
  ssh_free(str);
}


/*
  This implementation uses a slightly different sieving idea, which might
  be less good.

  Take the arithmetic sequence with a and b. That is, we have a recursive
  procedure

  x_0 = a, x_n+1 = x_n + b = a + nb.

  Hence, we want to detect when a small prime number divides either
  x_n or (x_n-1)/2. To check this we could as well look at x_n*(x_n-1)/2
  modulo the small prime p_i. We need to compute the arithmetic sequence
  modulo p_i then.

  Clearly

    x_(n+1)*(x_(n+1)-1)/2 = (a + (n+1)b)(a + (n+1)b - 1)/2 =
                            (a + nb + b)(a + nb - 1 + b)/2 =
                            (a + nb)(a + nb - 1 + b)/2 + b(a + nb - 1 + b)/2 =
                            (a + nb)(a + nb - 1)/2 + b(2*a + 2*nb - 1 + b)/2.

  Now it is easy to see that

  y_0   = a(a-1)/2 (mod p_i),
  y_n+1 = y_n + b(2*a + b - 1)/2 + nb^2 (mod p_i),

  satisfies y_n == 0 (mod p_i) when x_n or (x_n-1)/2 is divisible by p_i.

  We need to compute these sequences fast. Thus having tables for all
  y_n (mod p_i), b(2*a + b - 1) (mod p_i) and nb^2 (mod p_i) seems
  necessary.
 */

unsigned long find_safe_prime(unsigned int sieve_size,
                              SshMPInteger a, SshMPInteger b,
                              SshMPInteger prime, long steps,
                              int id, int num)
{
  unsigned long *y_table, *b_table, *b2_table;
  unsigned long *primes;
  unsigned int len, p, i, j, mult_k;
  SshMPIntegerStruct v, s, ret, aux;
  SshMPIntegerStruct b2, ba;
  SshSieveStruct sieve;
  Boolean rv;

  ssh_sieve_allocate_ui(&sieve, sieve_size, 5000000);
  for (len = 0, p = 2; p; p = ssh_sieve_next_prime(p, &sieve), len++)
    ;
  len--;

  ssh_mprz_init(&v);
  ssh_mprz_init(&s);
  ssh_mprz_init(&ret);
  ssh_mprz_init(&aux);

  ssh_mprz_init(&b2);
  ssh_mprz_init(&ba);

  /* Compute b2 = b^2. */
  ssh_mprz_square(&b2, b);

  /* Compute ba = b(2*a + b - 1)/2. */
  ssh_mprz_mul_ui(&ba, a, 2);
  ssh_mprz_add(&ba, &ba, b);
  ssh_mprz_sub_ui(&ba, &ba, 1);
  ssh_mprz_mul(&ba, &ba, b);
  ssh_mprz_divrem_ui(&ba, &ba, 2);

  /* Compute a*(a-1)/2. */
  ssh_mprz_sub_ui(&aux, a, 1);
  ssh_mprz_mul(&aux, &aux, a);
  ssh_mprz_divrem_ui(&aux, &aux, 2);

  printf("Initializing tables.\n");

  y_table   = ssh_xmalloc(len*sizeof(*y_table));
  b_table   = ssh_xmalloc(len*sizeof(*b_table));
  b2_table  = ssh_xmalloc(len*sizeof(*b2_table));
  primes    = ssh_xmalloc(len * sizeof(*primes));
  for (i = 0, p = 2; i < len ; i++,
         p = ssh_sieve_next_prime(p, &sieve))
    {
      y_table [i] = ssh_mprz_mod_ui(&aux, p);
      b_table [i] = ssh_mprz_mod_ui(&ba,  p);
      b2_table[i] = ssh_mprz_mod_ui(&b2,  p);
      primes  [i] = p;
    }

  ssh_sieve_free(&sieve);

  printf("Starting to search.\n");

  /* Initialize the return table. */
  ssh_mprz_set(&ret, a);

  /* We assume that only 2^30 choices are needed. */
  for (i = 0, mult_k = 0; i < steps; i++)
    {
      if (i > 0 && (i & 0x0f) == 0)
        {
          if ((i & 0xffff) == 0)
            {
              printf("\n");
              printf("-- pass %u no prime found.\n", i);
            }
          /* Doing something. */
          if ((i & 0xff) == 0)
            printf("[%u]", i*num+id);
          else
            printf(".");
          fflush(stdout);
        }
      rv = TRUE;
      for (j = 0; j < len; j++)
        {
          p = primes[j];

          /* First check the situation. */
          if (y_table[j] == 0)
            rv = FALSE;

          /* Start doing the addition for the next check. */

          /* Handle first the computation of y_n + b(...) + nb^2. */
          y_table[j] += b_table[j];
          if (y_table[j] >= p)
            y_table[j] -= p;

          /* Now add the new b^2 to make the (n+1)b^2. */
          b_table[j] += b2_table[j];
          if (b_table[j] >= p)
            b_table[j] -= p;
        }
      if (rv == FALSE)
        continue;

      /* Inform the user. */
      printf("x");
      fflush(stdout);

      /* Compute the actual prime candidate. */
      ssh_mprz_mul_ui(&s, b, i - mult_k);
      ssh_mprz_add(&ret, &ret, &s);
      ssh_mprz_set(&v, &ret);

      /* Remember the last try. */
      mult_k = i;

      /* This is the slow part... We would like to find a method to verify
         the compositeness faster than using exponentiation. However, there
         probably won't be anything like that available. */
      ssh_mprz_powm_ui_g(&aux, 2, &ret, &ret);
      if (ssh_mprz_cmp_ui(&aux, 2) == 0)
        {
          printf("1");
          fflush(stdout);
          ssh_mprz_sub_ui(&v, &v, 1);
          ssh_mprz_divrem_ui(&v, &v, 2);

          if (ssh_mprz_get_ui(&v) & 1)
            {
              ssh_mprz_powm_ui_g(&aux, 2, &v, &v);
              if (ssh_mprz_cmp_ui(&aux, 2) == 0)
                {
                  printf("2");
                  fflush(stdout);
                  if (ssh_mprz_is_probable_prime(&ret, 200))
                    {
                      printf("3");
                      fflush(stdout);
                      if (ssh_mprz_is_probable_prime(&v, 200))
                        break;
                    }
                }
            }
        }
    }

  ssh_xfree(y_table);
  ssh_xfree(b_table);
  ssh_xfree(b2_table);
  ssh_xfree(primes);

  if (i >= steps)
    {
      printf("\nThe final index %d was reached without a solution.\n",
             (i*num+id));
    }
  else
    {
      printf("\nThe index is: %d\n", (i*num+id));
      printf("Safe prime: \n");
      ssh_mprz_out_str(NULL, 10, &ret);
      ssh_mprz_set(prime, &ret);
      printf("\nThe Sophie Germain prime:\n");
      ssh_mprz_out_str(NULL, 10, &v);
      printf("\n");
    }

  ssh_mprz_clear(&ba);
  ssh_mprz_clear(&b2);

  ssh_mprz_clear(&v);
  ssh_mprz_clear(&s);
  ssh_mprz_clear(&ret);
  ssh_mprz_clear(&aux);

  if (i >= steps)
    return ~(unsigned long)0;
  return (i*num+id);
}

/* Proof based on Pocklington's theorem. This does not try to factor
   only assumes that the given values are nicely chosen. That is,
   you can call this with p and (p-1)/2 and check that p is prime if (p-1)/2
   is a prime number.

   Useful in a way such that one needs to do ECPP for only (p-1)/2, although
   in practice ECPP seems to do this itself. (Which is nice.)

   The table should contain the factors that are provably prime.

   */

int primality_proof(SshMPInteger n, SshMPInteger table, unsigned int table_n)
{
  SshMPIntegerStruct f, u, g;
  int i, rv;

  /* Assume that the number n is not a prime number. */
  rv = 0;

  printf("Pocklington's primality proof initiated.\n");

  /* Check with traditional methods. */
  if (ssh_mprz_is_probable_prime(n, 10) == 0)
    {
      printf(" -- given input was definitely composite.\n");
      return 0;
    }

  ssh_mprz_init(&f);
  ssh_mprz_init(&u);
  ssh_mprz_init(&g);

  ssh_mprz_set_ui(&f, 1);
  ssh_mprz_sub_ui(&u, n, 1);

  for (i = 0; i < table_n; i++)
    {
      printf(" -- prime factor no. %u is = ", i+1);
      ssh_mprz_out_str(NULL, 10, &table[i]);
      printf("\n");

      if (ssh_mprz_is_probable_prime(&table[i], 10) == 0)
        {
          printf(" -- given factor was definitely composite.\n");
          continue;
        }

      ssh_mprz_mod(&g, &u, &table[i]);
      if (ssh_mprz_cmp_ui(&g, 0) == 0)
        {
          printf(" -- divides.\n");
          do
            {
              printf(" -- multiplied.\n");
              ssh_mprz_mul(&f, &f, &table[i]);
              ssh_mprz_div(&u, &u, &table[i]);
              ssh_mprz_mod(&g, &u, &table[i]);
            }
          while (ssh_mprz_cmp_ui(&g, 0) == 0);
        }
    }

  ssh_mprz_sqrt(&g, n);
  if (ssh_mprz_cmp(&f, &g) <= 0)
    {
      printf(" -- proof impossible due to lack of prime factors.\n");
      /* Proof impossible. */
      rv = 0;
    }
  else
    {
      SshMPIntegerStruct a, aux, b1, b2, c, d;
      /* Find a good base. */
      ssh_mprz_init(&a);
      ssh_mprz_init(&b1);
      ssh_mprz_init(&b2);
      ssh_mprz_init(&c);
      ssh_mprz_init(&d);
      ssh_mprz_init(&aux);

      ssh_mprz_sub_ui(&d, n, 1);

      printf(" -- proceeding to find the suitable proving elements.\n");

      for (i = 0; i < table_n; i++)
        {
          int j;
#define MAX_TESTS 1000
          for (j = 0; j < MAX_TESTS; j++)
            {
              ssh_mprz_rand(&a, ssh_mprz_get_size(n, 2));

              /* Do the Pocklington's test. */

              /* Handle the first Fermat test. */
              ssh_mprz_powm(&b1, &a, &d, n);

              /* Now the "reduced" Fermat test. */
              ssh_mprz_div(&c, &d, &table[i]);
              ssh_mprz_powm(&b2, &a, &c, n);

              /* Subtract one, and keep positive. */
              ssh_mprz_sub_ui(&b2, &b2, 1);
              if (ssh_mprz_cmp_ui(&b2, 0) < 0)
                ssh_mprz_add(&b2, &b2, n);

              /* Now gcd. */
              ssh_mprz_gcd(&b2, &b2, n);

              /* Check that the comparisons are correct. */
              if (ssh_mprz_cmp_ui(&b1, 1) == 0 &&
                  ssh_mprz_cmp_ui(&b2, 1) == 0)
                {
                  /* Match happens! */
                  rv = 1;
                  break;
                }
            }
          if (j < MAX_TESTS)
            {
              printf(" -- for prime no. %u a proving element found.\n", i + 1);
              printf("    a_p = ");
              ssh_mprz_out_str(NULL, 10, &a);
              printf("\n");
            }
          else
            {
              printf(" -- proof failed for prime no. %u.\n", i+1);
              rv = 0;
              break;
            }
        }

      ssh_mprz_clear(&a);
      ssh_mprz_clear(&b1);
      ssh_mprz_clear(&b2);
      ssh_mprz_clear(&c);
      ssh_mprz_clear(&d);
      ssh_mprz_clear(&aux);
    }

  if (rv == 1)
    printf(" -- Pocklington's primality proof was a success.\n");

  ssh_mprz_clear(&f);
  ssh_mprz_clear(&u);
  ssh_mprz_clear(&g);

  return rv;
}



/* IKE prime search set up. */

/* Generate n bits of Pi. This method doesn't need floating point computation
   as it uses the Bailey-Plouffe algorithm. This code is based on the
   implementation by David Bailey. */

/* This is not fastest possible implementation of base 16 modular
   exponentiation! However, due to small size of e this might work ok. */
long fastmodexp_base16(long e, long m)
{
  long t = 1, x = 16;

  while (e)
    {
      if (e & 1)
        {
          t = t * x;
          t = (t % m);
        }
      x = x * x;
      x = (x % m);
      e >>= 1;
    }
  return t;
}

double mypow_base16(long e)
{
  double t = 1, x = 16.0;
  int sign = 0;

  if (e < 0)
    {
      sign = 1;
      e = -e;
    }

  while (e)
    {
      if (e & 1)
        t = t * x;
      x = x * x;
      e >>= 1;
    }

  if (sign)
    return 1.0/t;
  return t;
}

double f_series(long m, long c)
{
  long k, ak, p, t;
  double s;

  /* Take a small enough epsilon. */
#define EPSILON 1e-16

  s = 0.0;

  /* Sum the series up to c. */
  for (k = 0; k < c; k++)
    {
      double tmp;
      ak  = 8*k + m;
      p   = c - k;
      t   = fastmodexp_base16(p, ak);
      tmp = (double)t / (double)ak;
      s   = s + tmp;
      s   = s - ((long)s);
    }

  /* Compute few extra terms. */
  for (k = c; k <= c + 100; k++)
    {
      double tmp;
      ak  = 8*k + m;
      p   = c - k;
      tmp = mypow_base16(p) / (double)ak;
      if (tmp < EPSILON)
        break;
      s   = s + tmp;
      s   = s - ((long)s);
    }
  return s;
}

/* Get 4 bits of Pi at a time (this is not perhaps the fastest approach). */
long pi_digit(long c)
{
  double s1, s2, s3, s4, d;

  s1 = f_series(1, c);
  s2 = f_series(4, c);
  s3 = f_series(5, c);
  s4 = f_series(6, c);

  /* Combine the information. */
  d = 4.0 * s1 - 2.0 * s2 - s3 - s4;
  d = d - ((long)d) + 1;

  /* Return the compute digit. */
  return (long)((d - ((long)d)) * 16.0);
}

void pi_comp_bbp(SshMPInteger ret, int bits)
{
  int i, k;
  ssh_mprz_set_ui(ret, 0);

  if (bits < 2)
    {
      printf("error: try with more bits.\n");
      exit(1);
    }

  /* Set the first two bits. */
  ssh_mprz_set_ui(ret, 3);

  for (i = 2; i < bits; i += 4)
    {
      long d;

      d = pi_digit((i-2)/4);

      ssh_mprz_mul_ui(ret, ret, 16);
      ssh_mprz_add_ui(ret, ret, d);
    }

  /* Remove the extra bits. */
  k = i - bits;
  for (i = 0; i < k; i++)
    ssh_mprz_divrem_ui(ret, ret, 2);
}

/* A quadratically convergent algorithm for computing the Pi applying
   the algorithm by Borwein and Borwein (it is related to the AGM). This
   is slightly easier to write than the Gauss-Legendre method by
   Brent-Salamin.

   The function returns the asked number of bits of the Pi in the integer
   such that the decimal point is at the position bits
   */

void pi_comp_agm(SshMPInteger ret, int bits)
{
  SshMPIntegerStruct a, b, p, an, bn, pn;
  SshMPIntegerStruct prev_p, t1, t2, t3;
  int dp, guard;

  /* Let us take some precaution in computing large number digits for the
     Pi. */
  guard = bits / 50;
  if (guard < 32)
    guard = 32;

  dp    = bits - 2 + guard;

  if (dp <= 0)
    {
      printf("error: pi was not computed due to too few bits asked.\n");
      exit(1);
    }

  ssh_mprz_init(&a);
  ssh_mprz_init(&b);
  ssh_mprz_init(&p);

  ssh_mprz_init(&an);
  ssh_mprz_init(&bn);
  ssh_mprz_init(&pn);

  ssh_mprz_init(&prev_p);
  ssh_mprz_init(&t1);
  ssh_mprz_init(&t2);
  ssh_mprz_init(&t3);

  /* Compute the initial values. */

  /* The fixed precision operations:

     real variables a, b are presented as

     a * R and b * R then

     a + b -> a * R + b * R = (a + b) * R,

     a * b -> a * R * b * R = a * b * R^2 must be divided by R

     a / b -> a * R^2 / b * R = a/b * R

     sqrt(a) -> sqrt(a*R^2) = sqrt(a)*R

     */

  /* a_0 = sqrt(2) */
  ssh_mprz_set_bit(&a, dp + 1 + dp);
  ssh_mprz_sqrt(&a, &a);

  /* b_0 = 0 */
  ssh_mprz_set_ui(&b, 0);

  /* p_0 = 2 + sqrt(2) */
  ssh_mprz_set_bit(&p, dp + 1);
  ssh_mprz_add(&p, &p, &a);

  do
    {
      /* Remember the value of p for termination checking. */
      ssh_mprz_set(&prev_p, &p);

      /* Compute sqrt(a) */
      ssh_mprz_mul_2exp(&t1, &a, dp);
      ssh_mprz_sqrt(&t1, &t1);

      /* Compute 1/sqrt(a) (large position) */
      ssh_mprz_set_ui(&t2, 0);
      ssh_mprz_set_bit(&t2, 2*dp);
      ssh_mprz_div(&t2, &t2, &t1);

      /* Compute a_k+1 */
      ssh_mprz_add(&an, &t1, &t2);
      ssh_mprz_div_2exp(&an, &an, 1);

      /* Compute sqrt(a)*(1 + b) */
      ssh_mprz_set_ui(&t2, 0);
      ssh_mprz_set_bit(&t2, dp);
      ssh_mprz_add(&t2, &t2, &b);
      ssh_mprz_mul(&t2, &t2, &t1);
      /* Note: t2 is now in large position! */
      ssh_mprz_add(&t3, &a, &b);
      /* Division works as t2 is in large position. We get the b_k+1. */
      ssh_mprz_div(&bn, &t2, &t3);

      /* Compute p*b(1 + a) which is in very large position. Notice that
         we are now using the an and bn. */
      ssh_mprz_set_ui(&t2, 0);
      ssh_mprz_set_bit(&t2, dp);
      ssh_mprz_add(&t2, &t2, &an);
      ssh_mprz_mul(&t2, &t2, &bn);
      ssh_mprz_mul(&t2, &t2, &p);
      /* Down to large position. */
      ssh_mprz_div_2exp(&t2, &t2, dp);
      /* The divisor. */
      ssh_mprz_set_ui(&t3, 0);
      ssh_mprz_set_bit(&t3, dp);
      ssh_mprz_add(&t3, &t3, &bn);
      ssh_mprz_div(&pn, &t2, &t3);

      /* Now copy to the start values. */
      ssh_mprz_set(&a, &an);
      ssh_mprz_set(&b, &bn);
      ssh_mprz_set(&p, &pn);

      /* Check for the convergence. */
      ssh_mprz_sub(&t1, &p, &prev_p);
      ssh_mprz_abs(&t1, &t1);
    }
  while (ssh_mprz_cmp_ui(&t1, 0x10000) > 0);

  /* Remove the guard bits and copy. */
  ssh_mprz_div_2exp(&p, &p, guard);
  ssh_mprz_set(ret, &p);

  /* Clean up. */
  ssh_mprz_clear(&a);
  ssh_mprz_clear(&b);
  ssh_mprz_clear(&p);
  ssh_mprz_clear(&an);
  ssh_mprz_clear(&bn);
  ssh_mprz_clear(&pn);

  ssh_mprz_clear(&prev_p);
  ssh_mprz_clear(&t1);
  ssh_mprz_clear(&t2);
  ssh_mprz_clear(&t3);
}

/*
  Here is a Pari/GP program for generating an IKE prime. This is useful
  for checking purposes.

  { ikeprime(b, k) =
    \\ Enough of Pi.
    epi = floor(Pi*2^(b-2*fixedbits-2)) + k;
    \\ Generate the number
    2^(b) - 2^(b-fixedbits) - 1 + epi*2^fixedbits
  }
*/
void ike_start(SshMPInteger ret, int bits, long my_index, int fixed_bits)
{
  SshMPIntegerStruct pi;

  if (bits < 2*fixed_bits + 2)
    {
      printf("error: more than %u bits are needed for IKE primes.\n",
             2*fixed_bits + 2);
      exit(1);
    }

  ssh_mprz_init(&pi);

#ifdef PI_VERIFY
  {
    SshMPIntegerStruct tmp;
    ssh_mprz_init(&tmp);
    pi_comp_agm(&pi, bits - 2*fixed_bits);
    pi_comp_bbp(&tmp, bits - 2*fixed_bits);
    if (ssh_cmp(&tmp, &pi) != 0)
      {
        printf("error: Pi computation mismatch.\n");
        printf("AGM: ");
        ssh_mprz_out_str(NULL, 16, &pi);
        printf("\n");
        printf("BBP: ");
        ssh_mprz_out_str(NULL, 16, &tmp);
        printf("\n");
        exit(1);
      }
  }
#else
  pi_comp_agm(&pi, bits - 2*fixed_bits);
#endif

  ssh_mprz_add_ui(&pi, &pi, my_index);

  ssh_mprz_set_ui(ret, 0);
  ssh_mprz_set_bit(ret, fixed_bits);
  ssh_mprz_sub_ui(ret, ret, 1);
  ssh_mprz_mul_2exp(ret, ret, bits - fixed_bits);
  ssh_mprz_sub_ui(ret, ret, 1);

  ssh_mprz_mul_2exp(&pi, &pi, fixed_bits);
  ssh_mprz_add(ret, ret, &pi);

  ssh_mprz_clear(&pi);
}

unsigned long ike_find(SshMPInteger ret, int bits, long my_index,
                       int max_steps, int sieve_size, int id, int num,
                       int fixed_bits)
{
  SshMPIntegerStruct start, add;
  unsigned long rv;

  ssh_mprz_init(&start);
  ssh_mprz_init(&add);
  ike_start(&start, bits, my_index + id, fixed_bits);
  ssh_mprz_set_ui(&add, num);
  ssh_mprz_mul_2exp(&add, &add, fixed_bits);

  printf("IKE start value (%u bits): \n", bits);
  ssh_mprz_out_str(NULL, 10, &start);
  printf("\n");

  rv =  find_safe_prime(sieve_size, &start, &add, ret, max_steps,
                        id + my_index, num);

  ssh_mprz_clear(&start);
  ssh_mprz_clear(&add);
  return rv;
}


void ike_batch(char *filename, int from_bits, int to_bits, int step_bits,
               int sieve_size, int max_steps, int start_index,
               int fixed_bits)
{
  FILE *fp;
  SshMPIntegerStruct prime;
  int *status;
  unsigned long rv;
  unsigned long status_len, my_index;
  unsigned long i, done;
  struct SshTimeMeasureRec tmit = SSH_TIME_MEASURE_INITIALIZER;  

  if (to_bits <= from_bits)
    {
      printf("error: batch mode demands larger range.\n");
      exit(1);
    }

  /* Open the file in such a mode that the file is not destroyed. */
  fp = fopen(filename, "a+");
  if (fp == NULL)
    {
      printf("error: file could not be written.\n");
      exit(1);
    }
  printf("Output to '%s'.\n", filename);

  status_len = (to_bits - from_bits)/step_bits;

  status = ssh_xmalloc(sizeof(*status) * status_len);
  for (i = 0; i < status_len; i++)
    status[i] = 0;

  ssh_mprz_init(&prime);

  fprintf(fp, "SOPHIE GERMAIN PRIME SEARCH\n");
  fprintf(fp, "FIXED %u bits.\n", fixed_bits);
  fflush(fp);

  done = 0;
  for (my_index = start_index; my_index < ((unsigned long)1 << 30);
       my_index += max_steps)
    {
      done = 0;
      fprintf(fp, "INDEX %lu: \n", my_index);
      fflush(fp);
      for (i = 0; i < status_len; i++)
        {
          long bits;

          /* Check if a prime found. */
          if (status[i] != 0)
            {
              done++;
              continue;
            }

          fprintf(fp, ".");
          fflush(fp);

          /* Compute the bits for this status. */
          bits = from_bits + step_bits*i;

          ssh_time_measure_reset(&tmit);
          ssh_time_measure_start(&tmit);
          rv = ike_find(&prime, bits, my_index, max_steps, sieve_size,
                        0, 1,
                        fixed_bits);
          ssh_time_measure_stop(&tmit);
          if (rv != ~(unsigned long)0)
            {
              printf("A prime was found.\n");
              fprintf(fp, "\nPRIME (bits %lu), index = %ld, %g seconds: \n",
                      bits, rv,
                      ssh_time_measure_get(&tmit,
                                           SSH_TIME_GRANULARITY_SECOND));
              ssh_mprz_out_str(fp, 16, &prime);
              fprintf(fp, "\n");
              fflush(fp);
              status[i] = 1;
            }
        }
      fprintf(fp, "\n");
      fflush(fp);
      if (done >= status_len)
        break;
    }

  fprintf(fp, "FINISHED (%lu primes found in the interval %u to %u).\n",
          done, from_bits, to_bits);
  fflush(fp);

  fclose(fp);

  printf("Finished the range searching.\n");
}

void gather(char *av[], int len, int pock)
{
  FILE *fp;
  SshMPInteger *table;
  int *ptable;
  int table_n, table_used;
  char *buffer, *buf;
  size_t buf_len;
  int i, j, fixed_bits;

  table_n    = 10;
  table      = ssh_xmalloc(sizeof(*table)*table_n);
  table_used = 0;

  fixed_bits = 64;

  buf_len = 100000;
  buffer = ssh_xmalloc(sizeof(char) * buf_len);

  for (i = 0; i < len; i++)
    {
      int bits;
      fp = fopen(av[i], "r");
      while ((buf = fgets(buffer, buf_len, fp)) != NULL)
        {
          if (sscanf(buf, "FIXED %u bits.", &fixed_bits) == 1)
            {
              continue;
            }
          if (sscanf(buf, "PRIME (bits %u): ", &bits) == 1)
            {
              SshMPInteger mp;

              printf("Prime with bits %u found.\n", bits);

              buf = fgets(buffer, buf_len, fp);
              if (buf == NULL)
                break;
              mp = ssh_xmalloc(sizeof(*mp));
              ssh_mprz_init(mp);
              ssh_mprz_set_str(mp, buf, 0);

              if (table_n <= table_used + 1)
                {
                  table_n += 10;
                  table = ssh_xrealloc(table, sizeof(*table) * table_n);
                }

              for (j = 0; j < table_used; j++)
                {
                  /* They should not be equal. */
                  if (ssh_mprz_cmp(table[j], mp) == 0)
                    {
                      ssh_mprz_clear(mp);
                      ssh_xfree(mp);
                      break;
                    }

                  /* They should not be of equal size. */
                  if (ssh_mprz_get_size(table[j], 2)
                      == ssh_mprz_get_size(mp, 2))
                    {
                      ssh_mprz_clear(mp);
                      ssh_xfree(mp);
                      break;
                    }

                  /* Verify that the order is correct. */
                  if (ssh_mprz_cmp(table[j], mp) > 0)
                    {
                      SshMPInteger tmp;

                      /* Swap. */
                      tmp = table[j];
                      table[j] = mp;
                      mp = tmp;
                    }
                }

              if (j == table_used)
                {
                  printf("Added to the list.\n");
                  table[table_used] = mp;
                  table_used++;
                }
              printf("Finished with it.\n");
            }
        }
      fclose(fp);
    }

  /* Do other processing. */
  printf("Running checks:\n");

  /* Allocate a prime verification/info table. */
  ptable     = ssh_xmalloc(sizeof(*ptable)*table_used);

  for (i = 0; i < table_used; i++)
    {
      SshMPIntegerStruct p,p1, mtab[10];
      int j;
      printf(" Prime %u:\n", i+1);

      ssh_mprz_init(&p);
      ssh_mprz_init(&p1);
      for (j = 0; j < 10; j++)
        ssh_mprz_init(&mtab[j]);

      /* Do the verification. */
      ssh_mprz_sub_ui(&p, table[i], 1);
      ssh_mprz_divrem_ui(&p1, &p, 2);
      ssh_mprz_set(&mtab[0], &p1);

      if (pock)
        ptable[i] = primality_proof(table[i], &mtab[0], 1);

      ssh_mprz_clear(&p);
      ssh_mprz_clear(&p1);
      for (j = 0; j < 10; j++)
        ssh_mprz_clear(&mtab[j]);
    }


  /* Now printout the stuff. */

  printf("Table for IKE primes in <bits, index> convention:\n");
  for (i = 0; i < table_used; i++)
    {
      SshMPIntegerStruct tmp;
      unsigned int bits, ike_index;

      ssh_mprz_init(&tmp);
      ike_start(&tmp, ssh_mprz_get_size(table[i], 2), 0, fixed_bits);
      ssh_mprz_sub(&tmp, table[i], &tmp);
      ssh_mprz_div_2exp(&tmp, &tmp, fixed_bits);


      bits = ssh_mprz_get_size(table[i], 2);
      ike_index = ssh_mprz_get_ui(&tmp);

      if (pock)
        {
          printf(" < %u, %u > (%s)\n", bits, ike_index,
                 (ptable[i] == 1 ? "p" : "*"));
        }
      else
        printf(" < %u, %u >\n", bits, ike_index);
      ssh_mprz_clear(&tmp);
    }
  printf("Table done [%u entries].\n", table_used);

  for (i = 0; i < table_used; i++)
    {
      ssh_mprz_clear(table[i]);
      ssh_xfree(table[i]);
    }
  ssh_xfree(ptable);
  ssh_xfree(table);
}

void expand(char *av[], int len, int pock)
{
  FILE *fp;
  SshMPInteger *table;
  int *ptable;
  int table_n, table_used;
  int failures;
  char *buffer, *buf;
  size_t buf_len;
  int i, fixed_bits;

  table_n = 10;
  table      = ssh_xmalloc(sizeof(*table)*table_n);
  table_used = 0;

  buf_len = 100000;
  buffer = ssh_xmalloc(sizeof(char) * buf_len);
  failures = 0;

  fixed_bits = 64;

  printf("Trying to find suitable expandable IKE primes (based on pi).\n");

  for (i = 0; i < len; i++)
    {
      printf("Handling file '%s':\n", av[i]);
      fp = fopen(av[i], "r");
      while ((buf = fgets(buffer, buf_len, fp)) != NULL)
        {
          unsigned long bits, pindex;
          if (sscanf(buf, "(Fixed %u bits.)", &fixed_bits) == 1)
            {
              continue;
            }

          if (sscanf(buf, " < %lu , %lu > ", &bits, &pindex) == 2)
            {
              SshMPInteger mp;
              printf(" -- possible IKE prime < %lu, %lu > found.\n",
                     bits, pindex);

              mp = ssh_xmalloc(sizeof(*mp));
              ssh_mprz_init(mp);

              /* Compute the prime. */
              ike_start(mp, bits, pindex, fixed_bits);

              /* Throw to the list/array. */
              if (table_n <= table_used+1)
                {
                  table_n += 10;
                  table = ssh_xrealloc(table, sizeof(*table) * table_n);
                }

              table[table_used] = mp;
              table_used++;

              printf(" ---- added to the list.\n");
            }
        }
    }





  /* Same as with gathering. */

  /* Do other processing. */
  printf("Running checks:\n");

  /* Allocate a prime verification/info table. */
  ptable     = ssh_xmalloc(sizeof(*ptable)*table_used);

  for (i = 0; i < table_used; i++)
    {
      SshMPIntegerStruct p,p1, mtab[10];
      int j;
      printf(" Prime %u:\n", i+1);

      ssh_mprz_init(&p);
      ssh_mprz_init(&p1);
      for (j = 0; j < 10; j++)
        ssh_mprz_init(&mtab[j]);

      /* Do the verification. */
      ssh_mprz_sub_ui(&p, table[i], 1);
      ssh_mprz_divrem_ui(&p1, &p, 2);
      ssh_mprz_set(&mtab[0], &p1);

      if (pock)
        ptable[i] = primality_proof(table[i], &mtab[0], 1);

      ssh_mprz_clear(&p);
      ssh_mprz_clear(&p1);
      for (j = 0; j < 10; j++)
        ssh_mprz_clear(&mtab[j]);
    }


  /* Now printout the stuff. */

  printf("Table for IKE primes in <bits, index> convention:\n");

  printf("(Fixed %u bits.)\n", fixed_bits);

  for (i = 0; i < table_used; i++)
    {
      SshMPIntegerStruct tmp;
      unsigned int bits, ike_index;

      ssh_mprz_init(&tmp);
      ike_start(&tmp, ssh_mprz_get_size(table[i], 2), 0, fixed_bits);
      ssh_mprz_sub(&tmp, table[i], &tmp);
      ssh_mprz_div_2exp(&tmp, &tmp, fixed_bits);


      bits = ssh_mprz_get_size(table[i], 2);
      ike_index = ssh_mprz_get_ui(&tmp);

      if (pock)
        {
          printf(" < %u, %u > (%s)\n", bits, ike_index,
                 (ptable[i] == 1 ? "p" : "*"));
        }
      else
        printf(" < %u, %u >\n", bits, ike_index);
      ssh_mprz_clear(&tmp);
    }
  printf("Table done [%u entries].\n", table_used);

  for (i = 0; i < table_used; i++)
    {
      ssh_mprz_clear(table[i]);
      ssh_xfree(table[i]);
    }
  ssh_xfree(ptable);
  ssh_xfree(table);
}

int main(int ac, char *av[])
{
  SshMPIntegerStruct input, add, prime;
  unsigned int sieve_size;
  int pos;
  int from_bits, to_bits, step_bits, ike, pi_bits, pock,
    ike_id, ike_num, ike_fixed_bits;
  unsigned long max_steps, my_index;
  char *filename;

  ssh_global_init();

  if (!ssh_math_library_initialize())
    ssh_fatal("Cannot initialize the math library.");

  if (!ssh_math_library_self_tests())
    ssh_fatal("Math library self tests failed.");

  ssh_mprz_init(&input);
  ssh_mprz_init(&add);
  ssh_mprz_init(&prime);

  from_bits = 512;
  to_bits   = 1024;
  step_bits = 128;

  ike = 0;
  pock = 0;

  ike_fixed_bits = 64;
  ike_id  = 0;
  ike_num = 1;

  pi_bits = 0;

  sieve_size = 20000;

  filename = NULL;

  my_index = 0;
  max_steps = ((unsigned long)1 << 30);

  ssh_mprz_set_ui(&input, 1);
  ssh_mprz_set_ui(&add, 2);

  for (pos = 1; pos < ac; pos++)
    {
      if (strcmp(av[pos], "-fb") == 0)
        {
          if (pos + 1 < ac)
            {
              from_bits = atoi(av[pos+1]);
              pos++;
            }
          else
            printf("error: argument assumed.\n");
          continue;
        }
      if (strcmp(av[pos], "-tb") == 0)
        {
          if (pos + 1 < ac)
            {
              to_bits = atoi(av[pos+1]);
              pos++;
            }
          else
            printf("error: argument assumed.\n");
          continue;
        }
      if (strcmp(av[pos], "-sb") == 0)
        {
          if (pos + 1 < ac)
            {
              step_bits = atoi(av[pos+1]);
              pos++;
            }
          else
            printf("error: argument assumed.\n");
          continue;
        }
      if (strcmp(av[pos], "-ike") == 0)
        {
          ike = 1 - ike;
          continue;
        }
      if (strcmp(av[pos], "-pock") == 0)
        {
          pock = 1 - pock;
          continue;
        }
      if (strcmp(av[pos], "-a") == 0)
        {
          if (pos + 1 < ac)
            {
              ssh_mprz_set_str(&input, av[pos+1], 0);
              pos++;
            }
          else
            printf("error: argument assumed.\n");
          continue;
        }
      if (strcmp(av[pos], "-fixed") == 0)
        {
          if (pos + 1 < ac)
            {
              ike_fixed_bits = atoi(av[pos+1]);
              pos++;
            }
          else
            printf("error: argument assumed.\n");
          continue;
        }
      if (strcmp(av[pos], "-par") == 0)
        {
          if (pos + 2 < ac)
            {
              ike_id = atoi(av[pos+1]);
              ike_num = atoi(av[pos+2]);
              pos += 2;
            }
          else
            printf("error: two arguments assumed.\n");
          continue;
        }
      if (strcmp(av[pos], "-b") == 0)
        {
          if (pos + 1 < ac)
            {
              ssh_mprz_set_str(&add, av[pos+1], 0);
              pos++;
            }
          else
            printf("error: argument assumed.\n");
          continue;
        }
      if (strcmp(av[pos], "-i") == 0)
        {
          if (pos + 1 < ac)
            {
              my_index = atoi(av[pos+1]);
              pos++;
            }
          else
            printf("error: argument assumed.\n");
          continue;
        }

      if (strcmp(av[pos], "-s") == 0)
        {
          if (pos + 1 < ac)
            {
              sieve_size = atoi(av[pos+1]);
              pos++;
            }
          else
            printf("error: argument assumed.\n");
          continue;
        }
      if (strcmp(av[pos], "-f") == 0)
        {
          if (pos + 1 < ac)
            {
              filename = av[pos+1];
              pos++;
            }
          else
            printf("error: argument assumed.\n");
          continue;
        }
      if (strcmp(av[pos], "-ms") == 0)
        {
          if (pos + 1 < ac)
            {
              max_steps = atoi(av[pos+1]);
              pos++;
            }
          else
            printf("error: argument assumed.\n");
          continue;
        }
      if (strcmp(av[pos], "-pi") == 0)
        {
          if (pos + 1 < ac)
            {
              pi_bits = atoi(av[pos+1]);
              pos++;
            }
          else
            printf("error: argument assumed.\n");
          continue;
        }
      if (strcmp(av[pos], "-g") == 0)
        {
          if (pos + 1 < ac)
            {
              gather(&av[pos+1], ac - pos - 1, pock);
              pos = ac;
            }
          else
            printf("error: argument assumed.\n");
          exit(0);
        }

      if (strcmp(av[pos], "-e") == 0)
        {
          if (pos + 1 < ac)
            {
              expand(&av[pos+1], ac - pos - 1, pock);
              pos = ac;
            }
          else
            printf("error: argument assumed.\n");
          exit(0);
        }

      if (strcmp(av[pos], "-h") == 0)
        {
          printf("Program for finding Sophie Germain primes.\n");
          printf("usage: t-sophie-germain [options]\n"
                 "options: \n"
                 "  -h        this help\n"
                 "  -a xx     the start integer\n"
                 "  -b xx     the addition integer\n"
                 "  -s xx     the sieve size (larger the better usually)\n"
                 "  -fb xx    the bits for IKE primes (from bits)\n"
                 "  -tb xx    the to bits.\n"
                 "  -i  xx    index\n"
                 "  -ms xx    max steps\n"
                 "  -ike      toggle for IKE primes\n"
                 "  -fixed xx number of fixed bits at top for IKE\n"
                 "  -par a b  'a' denoted the id. num. and 'b' total num. "
                        "of processors\n"
                 "  -pock     if gathering do Pocklington's test with "
                        "(p-1)/2\n"
                 "  -f xx     file for the IKE batch mode\n"
                 "  -sb xx    step for range of IKE primes\n"
                 "  -pi xx    computes xx bits of Pi for verification "
                        "purposes\n"
                 "  -g files  gather information from the output files.\n"
                 "  -e files  expand/verify primes from the gathered files.\n"
                 "\n");
          exit(1);
        }
    }

  if (ssh_mprz_cmp_ui(&add, 1) <= 0)
    {
      printf("The add value (b) is not valid for this program.\n");
      exit(1);
    }

  if (pi_bits > 0)
    {
      SshMPIntegerStruct pi_agm, pi_bbp;
      struct SshTimeMeasureRec tmit = SSH_TIME_MEASURE_INITIALIZER;

      ssh_mprz_init(&pi_agm);
      ssh_mprz_init(&pi_bbp);

      printf("Computing %u bits of Pi for your pleasure...\n", pi_bits);

      printf("Using AGM class algorithm Borwein-Borwein:\n");

      ssh_time_measure_reset(&tmit);
      ssh_time_measure_start(&tmit);

      pi_comp_agm(&pi_agm, pi_bits);

      ssh_time_measure_stop(&tmit);

      printf("Time spend: %g seconds\n",
             ssh_time_measure_get(&tmit, SSH_TIME_GRANULARITY_SECOND));

      ssh_mprz_out_str(NULL, 16, &pi_agm);
      printf("\n");
      if (pi_bits < 4000)
        {
          printf("Using bit extraction algorithm by "
                 "Bailey-Borwein-Plouffe:\n");

          ssh_time_measure_reset(&tmit);
          ssh_time_measure_start(&tmit);

          pi_comp_bbp(&pi_bbp, pi_bits);

          ssh_time_measure_stop(&tmit);

          printf("Time spend: %g seconds\n",
                 ssh_time_measure_get(&tmit, SSH_TIME_GRANULARITY_SECOND));
          ssh_mprz_out_str(NULL, 16, &pi_bbp);
          printf("\n");

          if (ssh_mprz_cmp(&pi_bbp, &pi_agm) == 0)
            {
              printf("Results match, both algorithms are hence correct.\n");
            }
          else
            {
              printf("Mismatch in the result, either of the methods is "
                     "incorrect.\n");
            }
        }
      else
        {
          unsigned int digits;
          int pos, start;

          printf("The Bailey-Borwein-Plouffe digit extraction algorithm is\n"
                 "too slow to be used for full Pi computation for your\n"
                 "requested bit amount.\n"
                 "Using the digit extraction to give few last bits for \n"
                 "verification purposes.\n");

          pos = (pi_bits - 2) / 4;
          pos *= 4;
          pos -= 4*4;
          start = pos;
          printf("Using BBP to bits %u to %u\n",
                 start+2, pi_bits);
          for (digits = 0; pos < pi_bits-2; pos += 4)
            {
              digits *= 16;
              digits += pi_digit(pos/4);
            }
          if (pos - (pi_bits-2) > 0)
            digits >>= (pos - (pi_bits-2));
          pos = (pi_bits-2) - start;

          if ((ssh_mprz_get_ui(&pi_agm) & ((1 << pos) - 1)) == digits)
            {
              printf("Last digits match with the BBP algorithm (%x).\n",
                     digits);
            }
          else
            {
              printf("Last digits do not match, BBP gives %x.\n", digits);
            }
        }
      exit(1);
    }

  /* Compute GCD. */
  {
    SshMPIntegerStruct g;

    ssh_mprz_init(&g);
    ssh_mprz_gcd(&g, &input, &add);
    if (ssh_mprz_cmp_ui(&g, 1) == 0)
      {
        printf("  The start value a and add value b are relatively prime.\n"
               "  A prime number of form a + b * k must exists.\n"
               "  The current state of the art doesn't know whether\n"
               "  there exists infinitely many Sophie Germain primes\n"
               "  in arithmetic progression. E.g. the prime a + b * k\n"
               "  may never have (a + b*k - 1)/2 also prime. Beware.\n");
      }
    else
      {
        printf("The start value a and add value b have common factor, hence\n"
               "it is useless to continue. No prime found.\n");
        exit(1);
      }
  }

  if (ike && step_bits && from_bits && to_bits && filename)
    {
      /* The range searching. */
      printf("Running the IKE batch prime search.\n");
      ike_batch(filename, from_bits, to_bits, step_bits, sieve_size,
                max_steps, my_index,
                ike_fixed_bits);
      printf("Batch mode finished.\n");
    }
  else
    {
      if (ike && from_bits)
        {
          printf("Searching for the IKE prime (%u bits).\n", from_bits);
          ike_find(&prime, from_bits, my_index, max_steps, sieve_size,
                   ike_id, ike_num,
                   ike_fixed_bits);
          printf("IKE prime search finished.\n");
        }
      else
        {
          find_safe_prime(sieve_size, &input, &add, &prime, max_steps,
                          0, 1);

          if (ssh_mprz_cmp_ui(&input, 1) == 0 &&
              ssh_mprz_cmp_ui(&add, 2) == 0)
            {
              if (ssh_mprz_cmp_ui(&prime, 39983) == 0)
                printf("OK\n");
              else
                printf("Find_safe_prime returned wrong number, it should "
                       "have returned 39983\n");
            }
        }
    }

  ssh_mprz_clear(&prime);
  ssh_mprz_clear(&input);
  ssh_mprz_clear(&add);
  ssh_math_library_uninitialize();

  ssh_util_uninit();
  exit(0);
}
