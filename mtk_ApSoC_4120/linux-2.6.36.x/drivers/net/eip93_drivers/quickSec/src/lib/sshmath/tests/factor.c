/*

  factor.c

  Author: Mika Kojo <mkojo@ssh.fi>

  Copyright:
          Copyright (c) 2002, 2003 SFNT Finland Oy.
  All rights reserved.

  Created: Sat May 30 22:32:59 1998 [mkojo]

  Factorization code for sshmath libraries. This might be useful
  for some computational problems.

  TODO:

    fix all the code modified to work with montgomery representation
    is possible. Fix the curve initialization. Fix the factor detections
    etc.

    This should be good test bed for speed against GMP and for correction
    of implementation.

  */

#include "sshincludes.h"
#include "sshmp.h"
#include "pollard.h"
#include "sshbuffer.h"
#include "sshglobals.h"


/* ECM code. */

/* Montgomery parameterization, that is we are using the curve

   By^2 = x^3 + Ax^2 + x.

   Following gives the basic arithmetic needed. */

typedef struct SshECMPointRec
{
  SshMPIntModStruct x, z;
  /* These are here just to speed things up in addition. However,
     the speed-up is so small it is unlikely that it matters. */
  SshMPIntModStruct xpz, xmz;
} SshECMPoint;

typedef struct SshECMCurveRec
{
  SshMPIntIdealStruct mont_q;
  SshMPIntegerStruct q;
  SshMPIntModStruct a, A, B;
  SshMPIntModStruct t1, t2, t3, t4;
  SshECMPoint q1, q2;
} SshECMCurve;

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

void ssh_ecm_init_point(SshECMPoint *n, const SshECMCurve *E)
{
  ssh_mprzm_init(&n->x, &E->mont_q);
  ssh_mprzm_init(&n->z, &E->mont_q);
  ssh_mprzm_init(&n->xpz, &E->mont_q);
  ssh_mprzm_init(&n->xmz, &E->mont_q);
}

void ssh_ecm_clear_point(SshECMPoint *n)
{
  ssh_mprzm_clear(&n->x);
  ssh_mprzm_clear(&n->z);
  ssh_mprzm_clear(&n->xpz);
  ssh_mprzm_clear(&n->xmz);
}

void ssh_ecm_copy_point(SshECMPoint *a, const SshECMPoint *b)
{
  ssh_mprzm_set(&a->x, &b->x);
  ssh_mprzm_set(&a->z, &b->z);
  ssh_mprzm_set(&a->xpz, &b->xpz);
  ssh_mprzm_set(&a->xmz, &b->xmz);
}

Boolean ssh_ecm_init_curve(SshECMCurve *E, SshMPIntegerConst q)
{
  if (!ssh_mprzm_init_ideal(&E->mont_q, q))
    return FALSE;

  ssh_mprzm_init(&E->a, &E->mont_q);
  ssh_mprzm_init(&E->A, &E->mont_q);
  ssh_mprzm_init(&E->B, &E->mont_q);

  ssh_mprz_init(&E->q);
  ssh_mprz_set(&E->q, q);

  /* Temps */
  ssh_mprzm_init(&E->t1, &E->mont_q);
  ssh_mprzm_init(&E->t2, &E->mont_q);
  ssh_mprzm_init(&E->t3, &E->mont_q);
  ssh_mprzm_init(&E->t4, &E->mont_q);

  ssh_ecm_init_point(&E->q1, E);
  ssh_ecm_init_point(&E->q2, E);

  return TRUE;
}

void ssh_ecm_clear_curve(SshECMCurve *E)
{
  ssh_mprzm_clear(&E->a);
  ssh_mprzm_clear_ideal(&E->mont_q);
  ssh_mprzm_clear(&E->A);
  ssh_mprzm_clear(&E->B);
  ssh_mprz_clear(&E->q);

  /* Temps */
  ssh_mprzm_clear(&E->t1);
  ssh_mprzm_clear(&E->t2);
  ssh_mprzm_clear(&E->t3);
  ssh_mprzm_clear(&E->t4);

  ssh_ecm_clear_point(&E->q1);
  ssh_ecm_clear_point(&E->q2);
}

void ssh_ecm_addition(const SshECMPoint *n,
                      const SshECMPoint *m,
                      const SshECMPoint *mmn,
                      SshECMPoint *mpn, SshECMCurve *E)
{

  /* This addition formula is from Montgomery's paper. It computes

     x_m+n = z_m-n * ((x_m - z_m)(x_n + z_n) + (x_m + z_m)(x_n - z_n))^2
     z_m+n = x_m-n * ((x_m - z_m)(x_n + z_n) - (x_m + z_m)(x_n - z_n))^2

     */

  ssh_mprzm_mul(&E->t1, &m->xmz, &n->xpz);
  ssh_mprzm_mul(&E->t2, &m->xpz, &n->xmz);
  ssh_mprzm_add(&E->t3, &E->t1, &E->t2);
  ssh_mprzm_square(&E->t3, &E->t3);
  ssh_mprzm_mul(&mpn->x, &E->t3, &mmn->z);

  ssh_mprzm_sub(&E->t3, &E->t1, &E->t2);
  ssh_mprzm_square(&E->t3, &E->t3);
  ssh_mprzm_mul(&mpn->z, &E->t3, &mmn->x);

  ssh_mprzm_add(&mpn->xpz, &mpn->x, &mpn->z);
  ssh_mprzm_sub(&mpn->xmz, &mpn->x, &mpn->z);
}

void ssh_ecm_duplication(const SshECMPoint *n, SshECMPoint *n2, SshECMCurve *E)
{
  /* This is the computation of

     4*x_n*z_n = (x_n + z_n)^2 - (x_n - z_n)^2
     x_2n = (x_n + z_n)^2 * (x_n - z_n)^2
     z_2n = (4 * x_n *z_n) * ((x_n - z_n)^2 + ((a + 2)/4)*(4*x_n*z_n))

   */

  ssh_mprzm_square(&E->t1, &n->xpz);
  ssh_mprzm_square(&E->t2, &n->xmz);
  ssh_mprzm_sub(&E->t3, &E->t1, &E->t2);

  ssh_mprzm_mul(&n2->x, &E->t1, &E->t2);

  ssh_mprzm_mul(&E->t1, &E->a, &E->t3);
  ssh_mprzm_add(&E->t1, &E->t1, &E->t2);
  ssh_mprzm_mul(&n2->z, &E->t1, &E->t3);

  ssh_mprzm_add(&n2->xpz, &n2->x, &n2->z);
  ssh_mprzm_sub(&n2->xmz, &n2->x, &n2->z);
}

/* Following function is rarely called and thus we can use slower
   arithmetics inside. */
Boolean ssh_ecm_correct(const SshECMPoint *n, SshECMCurve *E)
{
  int i;
  Boolean rv = TRUE;
  SshMPIntegerStruct t1, t2, t3, t4;

  /* This is used to verify that no error has occurred, which is
     something we'd like to know when doing very long runs.

     In princible this says whether we are still on the curve, and thus
     have not failed by some computation cause.
     */

  ssh_mprz_init(&t1);
  ssh_mprz_init(&t2);
  ssh_mprz_init(&t3);
  ssh_mprz_init(&t4);

  ssh_mprz_set_mprzm(&t1, &n->z);
  /* We compute Jacobi(B(x^3 + Ax^2 + x), N). */
  if (ssh_mprz_invert(&t2, &t1, &E->q) == FALSE)
    {
      rv = FALSE;
      goto failed;
    }

  /* Place x back to affine coordinates. */
  ssh_mprz_set_mprzm(&t1, &n->x);
  ssh_mprz_mul(&t2, &t2, &t1);

  /* x = t2 */

  /* Compute x^3 + Ax^2 + x */

  /* t3 = x^2 */
  ssh_mprz_mul(&t3, &t2, &t2);

  /* t4 = x^2 * A */
  ssh_mprz_set_mprzm(&t1, &E->A);
  ssh_mprz_mul(&t4, &t3, &t1);

  /* t4 = x^2 * A + x */
  ssh_mprz_add(&t4, &t4, &t2);

  /* t3 = x^3 */
  ssh_mprz_mul(&t3, &t3, &t2);
  /* x^3 + A*x^2 + x */
  ssh_mprz_add(&t4, &t4, &t3);
  ssh_mprz_mod(&t4, &t4, &E->q);

  /* B... */
  ssh_mprz_set_mprzm(&t1, &E->B);
  ssh_mprz_mul(&t4, &t4, &t1);
  ssh_mprz_mod(&t4, &t4, &E->q);

  /* Compute jacobi symbol. */
  i = ssh_mprz_kronecker(&t4, &E->q);
  switch (i)
    {
    case -1:
      rv =  FALSE;
      break;
    case 0:
      rv = FALSE;
      break;
    case 1:
      rv = TRUE;
      break;
    default:
      break;
    }

failed:
  ssh_mprz_clear(&t1);
  ssh_mprz_clear(&t2);
  ssh_mprz_clear(&t3);
  ssh_mprz_clear(&t4);

  return rv;
}


/*
  Multiplication

  nP ja m = n+1 at start. n and m are changed during multiplication.

  */

void ssh_ecm_factorization_mul_ui(SshECMPoint *n, SshECMPoint *m,
                                  SshWord k,
                                  SshECMCurve *E)
{
  SshWord mask = ((SshWord)1 << (sizeof(SshWord) * 8 - 1));
  SshECMPoint *q1, *q2;

  if (k == 0)
    return;
  if (k == 1)
    {
      ssh_ecm_copy_point(n, m);
      return;
    }

  /* Use the temporary points in E. */
  q1 = &E->q1;
  q2 = &E->q2;

  /* Set the m to be the base point. */

  ssh_ecm_copy_point(q1, m);
  ssh_ecm_copy_point(q2, m);

  ssh_ecm_duplication(q2, q2, E);

  /* Find the first bit of k (msb). */
  while ((mask & k) == 0)
    mask >>= 1;
  mask >>= 1;

  while (mask)
    {
      if ((mask & k) == 0)
        {
          ssh_ecm_addition(q1, q2, m, q2, E);
          ssh_ecm_duplication(q1, q1, E);
        }
      else
        {
          ssh_ecm_addition(q1, q2, m, q1, E);
          ssh_ecm_duplication(q2, q2, E);
        }
      mask >>= 1;
    }
  ssh_ecm_copy_point(n, q1);
}

/* For history's sake lets give here also a function of generating a curve
   in spirit of Richard P. Brent. */

void
ssh_ecm_generate_curve_with_known_subgroup_12_brent(SshMPInteger factor,
                                                    SshECMCurve *E,
                                                    SshECMPoint *n)
{
  SshMPIntegerStruct theta, u, v, x, y, z, t1, t2, t3, t4;

  ssh_mprz_init(&theta);
  ssh_mprz_init(&u);
  ssh_mprz_init(&v);
  ssh_mprz_init(&x);
  ssh_mprz_init(&y);
  ssh_mprz_init(&z);

  ssh_mprz_init(&t1);
  ssh_mprz_init(&t2);
  ssh_mprz_init(&t3);
  ssh_mprz_init(&t4);

  while (1)
    {
      /* Find a random theta. */
      do
        {
          ssh_mprz_rand(&theta, ssh_mprz_get_size(&E->q, 2));
          ssh_mprz_mod(&theta, &theta, &E->q);
        }
      while (ssh_mprz_cmp_ui(&theta, 6) < 0);

      ssh_mprz_mul(&u, &theta, &theta);
      ssh_mprz_sub_ui(&u, &u, 5);
      ssh_mprz_mod(&u, &u, &E->q);

      ssh_mprz_mul_ui(&v, &theta, 4);
      ssh_mprz_mod(&v, &v, &E->q);

      /* u^3 */
      ssh_mprz_mul(&x, &u, &u);
      ssh_mprz_mul(&x, &x, &u);
      ssh_mprz_mod(&x, &x, &E->q);

      /* v^3 */
      ssh_mprz_mul(&z, &v, &v);
      ssh_mprz_mul(&z, &z, &v);
      ssh_mprz_mod(&z, &z, &E->q);

      ssh_mprzm_set_mprz(&n->x, &x);
      ssh_mprzm_set_mprz(&n->z, &z);

      /* Compute for later use the x-z and x+z */
      ssh_mprzm_add(&n->xpz, &n->x, &n->z);
      ssh_mprzm_sub(&n->xmz, &n->x, &n->z);

      /* Compute a + 2:

         ((3u + v)(v - u)^3, 3vu^3)

         */
      ssh_mprz_sub(&t1, &v, &u);

      /* t1^3 */
      ssh_mprz_mul(&t3, &t1, &t1);
      ssh_mprz_mul(&t1, &t1, &t3);
      ssh_mprz_mod(&t1, &t1, &E->q);

      ssh_mprz_mul_ui(&t2, &u, 3);
      ssh_mprz_add(&t2, &t2, &v);
      ssh_mprz_mul(&t1, &t1, &t2);
      ssh_mprz_mod(&t1, &t1, &E->q);

      /* u^3 */
      ssh_mprz_set(&t2, &x);
      ssh_mprz_mul(&t2, &t2, &v);
      ssh_mprz_mul_ui(&t2, &t2, 4);
      ssh_mprz_mod(&t2, &t2, &E->q);

      /* Check for factorization. */
      if (ssh_mprz_invert(&t3, &t2, &E->q) == 0)
        {
          ssh_mprz_gcd(factor, &t2, &E->q);
          if (ssh_mprz_cmp_ui(factor, 1) > 1)
            goto finish;
          continue;
        }

      ssh_mprz_mul(&t1, &t1, &t3);
      ssh_mprz_mod(&t1, &t1, &E->q);

      /* Now a can be computed as. */

      /* A = x B = z a = y in the following.
       */
      ssh_mprz_sub_ui(&x, &t1, 2);
      ssh_mprz_mod(&x, &x, &E->q);
      ssh_mprzm_set_mprz(&E->A, &x);

      /* Generate a random value for B. */
      do
        {
          ssh_mprz_rand(&z, ssh_mprz_get_size(&E->q, 2));
          ssh_mprz_mod(&z, &z, &E->q);
        }
      while (ssh_mprz_cmp_ui(&z, 1) < 0);
      ssh_mprzm_set_mprz(&E->B, &z);

      /* Compute the rest. */

      /* a = (A + 2)/4 */
      ssh_mprz_set_ui(&t1, 4);
      if (ssh_mprz_invert(&t2, &t1, &E->q) == 0)
        {
          ssh_mprz_gcd(factor, &t1, &E->q);
          if (ssh_mprz_cmp_ui(factor, 1) > 1)
            goto finish;
          continue;
        }
      ssh_mprz_add_ui(&t1, &x, 2);
      ssh_mprz_mul(&y, &t1, &t2);
      ssh_mprz_mod(&y, &y, &E->q);
      ssh_mprzm_set_mprz(&E->a, &y);

      /* Verify that this indeed is an elliptic curve. */
      ssh_mprz_mul(&t1, &x, &x);
      ssh_mprz_sub_ui(&t1, &t1, 4);
      ssh_mprz_mul(&t1, &t1, &z);
      ssh_mprz_gcd(&t2, &t1, &E->q);
      if (ssh_mprz_cmp_ui(&t2, 1) != 0)
        {
          ssh_mprz_set(factor, &t2);
          goto finish;
        }

      /* Check that this curve (and point) is correct. */
      if (ssh_ecm_correct(n, E) == FALSE)
        {
          ssh_mprz_set_mprzm(&z, &n->z);
          ssh_mprz_gcd(factor, &z, &E->q);
          if (ssh_mprz_cmp_ui(factor, 1) > 0
              && ssh_mprz_cmp(factor, &E->q) < 0)
            goto finish;
          continue;
        }

      printf("Curve parameters generated \n"
             "  (with torsion subgroup of order 12)\n");

      printf("  A = ");
      ssh_mprz_set_mprzm(&x, &E->A);
      ssh_mprz_out_str(NULL, 10, &x);
      printf("\n  B = ");
      ssh_mprz_set_mprzm(&x, &E->B);
      ssh_mprz_out_str(NULL, 10, &x);
      printf("\n  X = ");
      ssh_mprz_set_mprzm(&x, &n->x);
      ssh_mprz_out_str(NULL, 10, &x);
      printf("\n  Z = ");
      ssh_mprz_set_mprzm(&x, &n->z);
      ssh_mprz_out_str(NULL, 10, &x);
      printf("\n");

      break;
    }

  /* Finished ok. */
  ssh_mprz_set_ui(factor, 1);
finish:
  ssh_mprz_clear(&theta);
  ssh_mprz_clear(&u);
  ssh_mprz_clear(&v);
  ssh_mprz_clear(&x);
  ssh_mprz_clear(&y);
  ssh_mprz_clear(&z);
  ssh_mprz_clear(&t1);
  ssh_mprz_clear(&t2);
  ssh_mprz_clear(&t3);
  ssh_mprz_clear(&t4);
}

/* With projective coordinates you cannot say anything about two points without
   converting back to affine. */
Boolean ssh_ecm_same(SshECMPoint *a, SshECMPoint *b, SshECMCurve *E)
{
  SshMPIntModStruct inv1, inv2;

  ssh_mprzm_init(&inv1, &E->mont_q);
  ssh_mprzm_init(&inv2, &E->mont_q);

  if (ssh_mprzm_invert(&inv1, &a->z) == 0)
    goto failed;

  ssh_mprzm_mul(&inv1, &a->x, &inv1);

  if (ssh_mprzm_invert(&inv2, &b->z) == 0)
    goto failed;

  ssh_mprzm_mul(&inv2, &b->x, &inv2);

  if (ssh_mprzm_cmp(&inv2, &inv1) == 0)
    {
      ssh_mprzm_clear(&inv2);
      ssh_mprzm_clear(&inv1);
      return TRUE;
    }

failed:
  ssh_mprzm_clear(&inv1);
  ssh_mprzm_clear(&inv2);
  return FALSE;
}

/* Factorization algorithm. This one should be even better than the above
   one, because the second step should be much faster.

   The outer side will be later able to give a context which will tell
   all information needed to set the parameters in much nicer way. At the
   moment many things are just fixed so and so.
   */

Boolean ssh_ecm(SshMPInteger factor, SshMPIntegerConst composite,
                SshSieve sieve,
                SshWord b1, SshWord b2)
{
  SshMPIntegerStruct b, c, t1, t2, t3, t4;
  SshMPIntModStruct g, prod, *xz;
  SshECMCurve E;
  unsigned int keep_going;
  unsigned int passes, max_passes, maxi, ik, tempi, l;
  Boolean rv = TRUE;

  SshWord bits, table_size, step_size;

  SshECMPoint n, m, s, p1, *t, cur, prev, diff;
  SshWord final;
  unsigned int i, j;
  double percent;

  if (ssh_mprz_cmp_ui(composite, 1) == 0)
    {
      ssh_mprz_set(factor, composite);
      return TRUE;
    }

  if (ssh_mprz_is_probable_prime(composite, 20))
    {
      ssh_mprz_set(factor, composite);
      return TRUE;
    }

  if (!ssh_ecm_init_curve(&E, composite))
    ssh_fatal("Cannot initialize elliptic curve");

  ssh_ecm_init_point(&n, &E);
  ssh_ecm_init_point(&m, &E);
  ssh_ecm_init_point(&p1, &E);
  ssh_ecm_init_point(&s, &E);
  ssh_ecm_init_point(&cur, &E);
  ssh_ecm_init_point(&prev, &E);
  ssh_ecm_init_point(&diff, &E);

  ssh_mprz_init(&t1);
  ssh_mprz_init(&t2);
  ssh_mprz_init(&t3);
  ssh_mprz_init(&t4);

  /* Optimal table size is of form:

     phi(2 * 3 * 5 * 7 * 11 * 13 * ...)

     that is the product of smallest prime numbers up to some
     limit. See Montgomery's article if not obvious otherwise. */

  /* Much larger might take too much space? We use primes upto 13. */
  table_size = 5760;
  step_size = 30030;

  /* Allocating space. */
  xz = ssh_xmalloc(sizeof(SshMPIntModStruct) * table_size);
  t = ssh_xmalloc(sizeof(SshECMPoint) * table_size);

  ssh_mprz_set_ui(&t1, 0);
  for (i = 0; i < table_size; i++)
    {
      ssh_ecm_init_point(&t[i], &E);
      ssh_mprzm_init(&xz[i], &E.mont_q);
      ssh_mprzm_set_mprz(&xz[i], &t1);
    }

  ssh_mprzm_init(&g, &E.mont_q);
    ssh_mprzm_init(&prod, &E.mont_q);

  ssh_mprz_init(&c);
  ssh_mprz_init(&b);

  /* Is the sieve a good thing? */
  final = ssh_sieve_last_prime(sieve);

  /* Compute c, the higher bound c = q + 1 + 2*sqrt(q) and b = sqrt(c). */
  ssh_mprz_add_ui(&c, composite, 1);
  ssh_mprz_sqrt(&b, composite);
  ssh_mprz_mul_ui(&b, &b, 2);
  ssh_mprz_add(&c, &c, &b);

  ssh_mprz_sqrt(&b, &c);

  /* Select the smaller. */
  if (ssh_mprz_cmp_ui(&b, b1) < 0)
    b1 = ssh_mprz_get_ui(&b);

  /* Factoring loop. */
  for (keep_going = 0; keep_going < 10; keep_going++)
    {
      ssh_mprz_set(factor, composite);
      ssh_ecm_generate_curve_with_known_subgroup_12_brent(factor,
                                                          &E, &s);
      if (ssh_mprz_cmp_ui(factor, 1) != 0)
        goto factor_found;

      ssh_ecm_copy_point(&m, &s);

#if 0
      /* Testing the multiplication. */

      ssh_ecm_copy_point(&prev, &s);
      ssh_ecm_copy_point(&cur, &s);
      ssh_ecm_duplication(&cur, &cur, &E);
      /* We now have prev = 1, cur = 2. */

      for (i = 1; i < 100; i++)
        {
          ssh_ecm_factorization_mul_ui(&m, &s, i, &E);

          if (ssh_ecm_same(&prev, &m, &E))
            {
              printf("i = %d\n", i);
            }

          ssh_ecm_copy_point(&p1, &cur);
          ssh_ecm_addition(&s, &cur, &prev, &cur, &E);
          ssh_ecm_copy_point(&prev, &p1);
        }

      printf("The multiplication says:\n");
      ssh_mprz_out_str(NULL, 10, &m.x);
      printf("\n");
      ssh_mprz_out_str(NULL, 10, &m.z);
      printf("\n");

      printf("The addition says:\n");
      ssh_mprz_out_str(NULL, 10, &prev.x);
      printf("\n");
      ssh_mprz_out_str(NULL, 10, &prev.z);
      printf("\n");
      exit(1);

#endif

      bits = ssh_mprz_get_size(&c, 2) + 1;
      max_passes = bits / (sizeof(SshWord) * 8 - 1);
      if (max_passes == 0)
        max_passes = 1;

      printf("Run standard phase 1 passes.\n");

      for (passes = 0; passes < max_passes; passes++)
        {
          if (passes > 0)
            printf(" : %u\n", passes);
          if (bits > (sizeof(SshWord) * 8 - 1))
            {
              maxi = (SshWord)1 << (sizeof(SshWord) * 8 - 1);
              bits -= (sizeof(SshWord) * 8 - 1);
            }
          else
            {
              maxi = (SshWord)1 << bits;
              bits = 0;
            }

          /* Run through all the small primes. */
          for (i = 2, j = 0, percent = 0.0; i < b1 && i != 0;
               i = ssh_sieve_next_prime(i, sieve),
                 j++)
            {
              /* We try to do it as fast as possible thus we use
                 small integers. */
              ik = i;
              while (ik < maxi)
                {
                  tempi = ik*i;
                  if (tempi < ik)
                    break;
                  if (tempi >= maxi)
                    break;
                  ik = tempi;
                }

              /* Compute powers of the current prime. */

              ssh_ecm_factorization_mul_ui(&m, &m, ik, &E);

              if ((j % 1000) == 0)
                {
                  if (ssh_ecm_correct(&m, &E) == FALSE)
                    {
                      ssh_mprz_set_mprzm(&t1, &m.z);
                      ssh_mprz_gcd(factor, &t1, &E.q);
                      if (ssh_mprz_cmp_ui(factor, 1) > 0 &&
                          ssh_mprz_cmp(factor, &E.q) < 0)
                        goto factor_found;

                      printf("*\nComputation error: "
                             "Please check the following values.\n");

                      printf("  X = ");
                      ssh_mprz_set_mprzm(&t1, &m.x);
                      ssh_mprz_out_str(NULL, 10, &t1);
                      printf("\n  Z = ");
                      ssh_mprz_set_mprzm(&t1, &m.z);
                      ssh_mprz_out_str(NULL, 10, &t1);
                      printf("\n  A = ");
                      ssh_mprz_set_mprzm(&t1, &E.A);
                      ssh_mprz_out_str(NULL, 10, &t1);
                      printf("\n  B = ");
                      ssh_mprz_set_mprzm(&t1, &E.B);
                      ssh_mprz_out_str(NULL, 10, &t1);
                      printf("\n  N = ");
                      ssh_mprz_out_str(NULL, 10, &E.q);
                      printf("\n");
                      printf("Prime %d.\n", i);

                      exit(1);
                    }

                  while (percent < ((double)i/(double)b1)*20)
                    {
                      printf(".");
                      fflush(stdout);
                      percent++;
                    }

                  ssh_mprz_set_mprzm(&t1, &m.z);
                  ssh_mprz_gcd(factor, &t1, &E.q);
                  if (ssh_mprz_cmp_ui(factor, 1) > 0 &&
                      ssh_mprz_cmp(factor, &E.q) < 0)
                    goto factor_found;
                }
            }
        }
      ssh_mprz_set_mprzm(&t1, &m.z);
      ssh_mprz_gcd(factor, &t1, &E.q);
      if (ssh_mprz_cmp_ui(factor, 1) > 0 &&
          ssh_mprz_cmp(factor, &E.q) < 0)
        goto factor_found;

      printf("\n");

      /* The second step is a very simple one. This one is basically
         equivalent to what Brent and Crandall have used.

         Enhanced to use Montgomery's ideas, this uses more efficiently
         memory and thus allows more primes to be checked.
         */

      printf("Engage the phase 2.\n");

      /* Starting to compute. */
      l = b1 / step_size;

      /* Make sure that we can compute prev. */
      if (l == 0)
        l = 1;

      /* It is useful to keep these exponents odd, might be prime? */
      ssh_ecm_factorization_mul_ui(&prev, &m, l * step_size + 1, &E);
      ssh_ecm_factorization_mul_ui(&cur, &m, (l + 1)*step_size + 1, &E);
      ssh_ecm_factorization_mul_ui(&diff, &m, step_size, &E);

      if (ssh_ecm_correct(&prev, &E) == FALSE)
          printf("Computation error: in prev, trying anyway.\n");
      if (ssh_ecm_correct(&cur, &E) == FALSE)
          printf("Computation error: in cur, trying anyway.\n");
      if (ssh_ecm_correct(&diff, &E) == FALSE)
        printf("Computation error: in diff, trying anyway.\n");

      ssh_mprz_set_ui(&t1, 1);
      ssh_mprzm_set_mprz(&g, &t1);
      /* Accumulate the diff - prev here. */
      ssh_mprzm_mul(&g, &g, &diff.x);
      ssh_mprzm_mul(&g, &g, &diff.z);

      /* Generate the table of phi(step_size) elements. If the step_size
         is altered remember to alter this also. */
      for (j = 3, i = 0; j < step_size; j += 2)
        {
          if (j % 3  == 0 ||
              j % 5  == 0 ||
              j % 7  == 0 ||
              j % 11 == 0 ||
              j % 13 == 0)
            continue;

          if (i < table_size - 1)
            {
              /* Compute t[i] as j*P, where gcd(j, 2*3*5*7*11*13) = 1. */
              ssh_ecm_factorization_mul_ui(&t[i], &m, j - 1, &E);

              if (i % 100 == 0)
                {
                  if (ssh_ecm_correct(&t[i], &E) == FALSE)
                    {
                      printf("error: operation failed.\n");
                      exit(1);
                    }
                }
              /* Lets accumulate. */
              ssh_mprzm_set(&xz[i], &t[i].z);
              ssh_mprzm_mul(&xz[i], &xz[i], &t[i].x);

              /* Move to the next index. */
              i++;
              if (i % 1000 == 0)
                {
                  /* Do nothing. */
                }
            }
          else
            {
              printf("error: table size wrongly approximated.\n");
              exit(1);
            }
        }

      /* Simple acknowledgment that error might appear. */
      if (i != table_size - 1)
        {
          printf("error: table size wrongly computed.\n");
          exit(1);
        }

      printf("Running the seeking of phase 2.\n");

      /* Is limit * 100 too low? Should we try to seek for more? */
      for (i = 0; l*step_size < b2; l ++, i++)
        {
          ssh_mprzm_set(&prod, &prev.z);
          ssh_mprzm_mul(&prod, &prod, &prev.x);

          /* Accumulate. */
          ssh_mprzm_mul(&g, &prod, &g);

          for (j = 0; j < table_size - 1; j++)
            {
              /* We do it anyway, a prime or not a prime. We are not very
                 well equipped to check for primality of

                 l*step_size + i, where i is the jth value where
                    gcd(i, step_size) = 1, i = 1, 2, ...

                 We could keep a table for i's but that seems like some
                 wasted memory to me. However, it would certainly speed
                 things a bit to test always that

                 l*step_size + i is a prime number.

                 One could to that by having a table of primes up to

                 sqrt(limit*100), and trying to divide by those. However,
                 this is not very fast (but perhaps its fast enough).

                 Also one could use a sieve of some sort here.
                 */

              /* Compute (x_0 - x_j)*(z_0 + z_j) - x_0*z_0 + x_j*z_j */

              /*
                x0*z0 + x0*zj - xj*z0 - xj*zj - x0*z0 + xj*zj
                = x0*zj - xj*z0

                Why does this work? This equation multiplied to g gives the
                same value as (l + j)P.z multiplied to g, because all of
                the other work. Check Montgomery's paper for instant
                understanding.
               */

              ssh_mprzm_set(&E.t1, &prev.x);
              ssh_mprzm_sub(&E.t1, &E.t1, &t[j].x);
              ssh_mprzm_set(&E.t2, &prev.z);
              ssh_mprzm_add(&E.t2, &E.t2, &t[j].z);
              ssh_mprzm_mul(&E.t1, &E.t2, &E.t1);

              ssh_mprzm_sub(&E.t1, &E.t1, &prod);
              ssh_mprzm_add(&E.t1, &E.t1, &xz[j]);

              ssh_mprzm_mul(&g, &g, &E.t1);
            }

          ssh_ecm_copy_point(&p1, &cur);

          /* Step forward. */
          ssh_ecm_addition(&diff, &cur, &prev, &cur, &E);

          if ((i % 500) == 0)
            {
              ssh_mprz_set_mprzm(&t1, &g);
              ssh_mprz_gcd(factor, &t1, &E.q);
              if (ssh_mprz_cmp_ui(factor, 1) > 0 &&
                  ssh_mprz_cmp(factor, &E.q) < 0)
                goto factor_found;

              if (ssh_ecm_correct(&cur, &E) == FALSE)
                {
                  ssh_mprz_set_mprzm(&t1, &cur.z);
                  ssh_mprz_gcd(factor, &t1, &E.q);
                  if (ssh_mprz_cmp_ui(factor, 1) > 0 &&
                      ssh_mprz_cmp(factor, &E.q) < 0)
                    goto factor_found;

                  printf("*\nComputation error: "
                         "Please check following values.\n");

                  printf("X_m+n and Z_m+n\n");
                  ssh_mprz_set_mprzm(&t1, &cur.x);
                  ssh_mprz_out_str(NULL, 10, &t1);
                  printf("\n");
                  ssh_mprz_set_mprzm(&t1, &cur.z);
                  ssh_mprz_out_str(NULL, 10, &t1);
                  printf("\n");

                  printf("X_n and Z_n\n");
                  ssh_mprz_set_mprzm(&t1, &t[table_size - 1].x);
                  ssh_mprz_out_str(NULL, 10, &t1);
                  printf("\n");
                  ssh_mprz_set_mprzm(&t1, &t[table_size - 1].z);
                  ssh_mprz_out_str(NULL, 10, &t1);
                  printf("\n");

                  printf("X_m-n and Z_m-n\n");
                  ssh_mprz_set_mprzm(&t1, &prev.x);
                  ssh_mprz_out_str(NULL, 10, &t1);
                  printf("\n");
                  ssh_mprz_set_mprzm(&t1, &prev.z);
                  ssh_mprz_out_str(NULL, 10, &t1);
                  printf("\n");

                  printf("X_m and Z_m\n");
                  ssh_mprz_set_mprzm(&t1, &p1.x);
                  ssh_mprz_out_str(NULL, 10, &t1);
                  printf("\n");
                  ssh_mprz_set_mprzm(&t1, &p1.z);
                  ssh_mprz_out_str(NULL, 10, &t1);
                  printf("\n");

                  printf("A, B and N\n");
                  ssh_mprz_set_mprzm(&t1, &E.A);
                  ssh_mprz_out_str(NULL, 10, &t1);
                  printf("\n");
                  ssh_mprz_set_mprzm(&t1, &E.B);
                  ssh_mprz_out_str(NULL, 10, &t1);
                  printf("\n");
                  ssh_mprz_out_str(NULL, 10, &E.q);
                  printf("\n");

                  exit(1);
                }
            }
          ssh_ecm_copy_point(&prev, &p1);
        }
      ssh_mprzm_mul(&g, &g, &cur.z);

      ssh_mprz_set_mprzm(&t1, &g);
      ssh_mprz_gcd(factor, &t1, &E.q);
      if (ssh_mprz_cmp_ui(factor, 1) > 0 &&
          ssh_mprz_cmp(factor, &E.q) < 0)
        goto factor_found;

      printf("Unlucky, retrying.\n");
    }

  rv = FALSE;

factor_found:

  ssh_mprz_clear(&b);
  ssh_mprz_clear(&c);

  ssh_mprzm_clear(&prod);
  ssh_mprzm_clear(&g);

  ssh_mprz_clear(&t1);
  ssh_mprz_clear(&t2);
  ssh_mprz_clear(&t3);
  ssh_mprz_clear(&t4);

  ssh_ecm_clear_point(&n);
  ssh_ecm_clear_point(&m);
  ssh_ecm_clear_point(&s);
  ssh_ecm_clear_point(&p1);
  ssh_ecm_clear_point(&cur);
  ssh_ecm_clear_point(&prev);
  ssh_ecm_clear_curve(&E);
  ssh_ecm_clear_point(&diff);

  /* Clean up the tables. */
  for (i = 0; i < table_size; i++)
    {
      ssh_mprzm_clear(&xz[i]);
      ssh_ecm_clear_point(&t[i]);
    }
  ssh_xfree(t);
  ssh_xfree(xz);

  return rv;
}

void sieve_allocate_mp(SshSieve sieve, SshMPInteger c,
                       unsigned int max_memory)
{
  SshMPIntegerStruct t;
  unsigned int max;

  ssh_mprz_init(&t);
  ssh_mprz_sqrt(&t, c);

  if (ssh_mprz_get_size(&t, 2) < 32)
    {
      max = ssh_mprz_get_ui(&t);
      ssh_sieve_allocate_ui(sieve, max,
                            max_memory);
    }
  else
    ssh_sieve_allocate(sieve, max_memory);
}

void initialize_random(char *str)
{
  unsigned int t, i, len;

  len = strlen(str);

  /* Really awful way of hashing. */
  for (i = 0, t = 0xff02fe03; i < len; i++)
    {
      t ^= str[i];
      t = (t << 9) ^ (t >> (32 - 7));
    }

  ssh_rand_seed(t);
}

void usage(void)
{
  fprintf(stderr,
          "usage: ecm -b1 bound -b2 bound -id unique-id [-f bigfile] "
          "[large composite number]\n");
}

int main(int ac, char *av[])
{
  SshMPIntegerStruct c, t, factor;
  SshSieveStruct sieve;
  char *unique, *bigfile;
  unsigned long i, e, round, pos, b1, b2, max_memory;
  Boolean show_usage = TRUE;

  ssh_global_init();

  if (!ssh_math_library_initialize())
    ssh_fatal("Cannot initialize the math library.");

  if (!ssh_math_library_self_tests())
    ssh_fatal("Math library self tests failed.");

  /* defaults. */
  unique = NULL;
  b1 = 0;
  b2 = 0;
  max_memory = 1024*1024;
  bigfile = NULL;

  /* Read the input. */

  ssh_mprz_init(&c);


  for (pos = 1; pos < ac; pos++)
    {
      if (strcmp(av[pos], "-b1") == 0)
        {
          /* Bound1 */
          b1 = atol(av[pos + 1]);
          pos++;
          continue;
        }
      if (strcmp(av[pos], "-b2") == 0)
        {
          /* Bound2 */
          b2 = atol(av[pos + 1]);
          pos++;
          continue;
        }
      if (strcmp(av[pos], "-mem") == 0)
        {
          /* Maximum memory. */
          max_memory = atol(av[pos + 1]);
          pos++;
          continue;
        }
      if (strcmp(av[pos], "-id") == 0)
        {
          /* Unique id. */
          unique = av[pos + 1];
          pos++;
          continue;
        }
      if (strcmp(av[pos], "-f") == 0)
        {
          bigfile = av[pos+1];
          pos++;
          show_usage = FALSE;
          continue;
        }

      ssh_mprz_set_str(&c, av[pos], 0);
      show_usage = FALSE;
      break;
    }

  if (bigfile)
    {
      FILE *fp;
      SshBufferStruct buffer;
      unsigned char blob[256];
      fp = fopen(bigfile, "r");
      if (fp == NULL)
        {
          printf("error: could not open the file %s.\n",
                 bigfile);
          exit(1);
        }
      ssh_buffer_init(&buffer);
      while (fgets(blob, 255, fp) != NULL)
        {
          int i, pos, len = strlen(blob);
          /* Move to the front... no really, just remove whitespace. */
          for (i = 0, pos = 0; i < len; i++)
            {
              if (isspace(blob[i]))
                continue;
              blob[pos] = blob[i];
              pos++;
            }
          /* Make the end. */
          blob[pos] = '\0';
          /* Append the buffer. */
          ssh_buffer_append(&buffer, blob, strlen(blob));
        }
      if (ssh_mprz_set_str(&c, ssh_buffer_ptr(&buffer), 0) == 0)
        {
          printf("error: could not parse file %s.\n", bigfile);
          exit(1);
        }
      ssh_buffer_clear(&buffer);
    }

  if (show_usage)
    {
      ssh_mprz_clear(&c);
      usage();
      exit(1);
    }

  if (unique == NULL)
    unique = "ECMInitValue";

  /* Initialize with an unique identifier. */
  initialize_random(unique);

  /* Check that the number is valid. */
  if (ssh_mprz_cmp_ui(&c, 2) <= 0)
    {
      fprintf(stderr, "error: integer must be greater than 2.\n");
      exit(1);
    }

  printf("ECM factoring program starting.\n"
         "Generate a number of small primes upto a predefined maximum.\n");

  /* First generate a reasonably large number of small primes. */
  sieve_allocate_mp(&sieve, &c, max_memory);

  printf("Trivial division to find out small factors.\n");
  for (i = 2; i; i = ssh_sieve_next_prime(i, &sieve))
    {
      if (ssh_mprz_mod_ui(&c, i) == 0)
        {
          /* Divisor found. */
          e = 0;
          do
            {
              ssh_mprz_divrem_ui(&c, &c, i);
              e++;
            }
          while (ssh_mprz_mod_ui(&c, i) == 0);

          if (e > 1)
            printf("  Factor: %ld^%ld\n", i, e);
          else
            printf("  Factor: %ld\n", i);

          if (ssh_mprz_cmp_ui(&c, 1) == 0)
            {
              printf("Factorization finished.\n"
                     "All factors found by trivial division.\n");
              ssh_sieve_free(&sieve);
              ssh_mprz_clear(&c);
              exit(0);
            }
        }
    }

  if (ssh_mprz_is_probable_prime(&c, 20))
    {
      printf("  Factor: ");
      ssh_mprz_out_str(NULL, 10, &c);
      printf("\n");
      printf("Factorization finished.\n"
             "All factors found by trivial division, and "
             "probabilistic primality test.\n");
      ssh_sieve_free(&sieve);
      ssh_mprz_clear(&c);
      exit(0);
    }

  /* Free the trial division sieve. */
  ssh_sieve_free(&sieve);

  /* Now running the Pollard rho algorithm. */
  ssh_mprz_init(&factor);
  printf("Pollard rho to find out medium size factors.\n");
  while (1)
    {
      if (ssh_pollard_rho(&factor, &c,
                          1600000, 1) == FALSE)
        {
          printf("Pollard rho failed.\n");
          break;
        }

      if (ssh_mprz_is_probable_prime(&factor, 20))
        {
          printf("  Factor: ");
          ssh_mprz_out_str(NULL, 10, &factor);
          printf("\n");

          ssh_mprz_div(&c, &c, &factor);
        }
      else
        {
          printf("  Compositive Factor: ");
          ssh_mprz_out_str(NULL, 10, &t);
          printf("\n");

          ssh_mprz_div(&c, &c, &factor);
        }

      if (ssh_mprz_cmp_ui(&c, 1) == 0)
        {
          printf("Given integer has now been fully factored.\n"
                 "Check all the composite factors using separate runs.\n");
          ssh_mprz_clear(&c);
          ssh_mprz_clear(&t);
          exit(0);
        }
    }
  ssh_mprz_clear(&factor);



  /* Check if b1 is set. */
  if (b1 == 0)
    {
      /* Assume that c = p*q, where p and q are primes. */
      i = ssh_mprz_get_size(&c, 10)/2;

      /* These shall be sharpened with some tests. */
      switch (i/10)
        {
        case 0:
        case 1:
          b1 = 20000;
          b2 = 2000000;
          break;
        case 2:
          b1 = 50000;
          b2 = 2000000;
          break;
        case 3:
          b1 = 500000;
          b2 = 20000000;
          break;
        case 4:
          b1 = 3000000;
          b2 = 100000000;
          break;
        default:
          b1 = 5000000;
          b2 = 200000000;
          break;
        }
    }

  /* Allocate a new sieve. */
  ssh_sieve_allocate_ui(&sieve, b1 + 2, max_memory);
  b1 = ssh_sieve_last_prime(&sieve);

  ssh_mprz_init(&t);

  printf("Starting to iterate the fast ECM method.\n");

  for (round = 0; ; round++)
    {
      printf("Starting %ld. round:\n", round + 1);

      if (ssh_ecm(&t, &c, &sieve, b1, b2))
        {
          if (ssh_mprz_is_probable_prime(&t, 20))
            {
              printf("  Factor: ");
              ssh_mprz_out_str(NULL, 10, &t);
              printf("\n");

              ssh_mprz_div(&c, &c, &t);
            }
          else
            {
              printf("  Composite Factor: ");
              ssh_mprz_out_str(NULL, 10, &t);
              printf("\n");

              ssh_mprz_div(&c, &c, &t);
            }

          if (ssh_mprz_cmp_ui(&c, 1) == 0)
            {
              printf("Given integer has now been fully factored.\n"
                     "Check all the composite factors using separate runs.\n");
              ssh_mprz_clear(&c);
              ssh_mprz_clear(&t);
              ssh_sieve_free(&sieve);
              exit(0);
            }
        }
    }
  ssh_mprz_clear(&t);
  ssh_mprz_clear(&c);
  ssh_sieve_free(&sieve);
  ssh_math_library_uninitialize();
  return 0;
}
