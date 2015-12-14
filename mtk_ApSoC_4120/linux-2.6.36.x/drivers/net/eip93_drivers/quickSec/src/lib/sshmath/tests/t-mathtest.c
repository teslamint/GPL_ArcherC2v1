/*

  t-mathtest.c

  Author: Mika Kojo <mkojo@ssh.fi>

  Copyright:
          Copyright (c) 2002, 2003 SFNT Finland Oy.
  All rights reserved.

  Created: Wed Apr 29 02:10:22 1998 [mkojo]

  Testing utility for math libraries. This program tries as many cases
  as possible to ensure that the math libraries are working correctly.

  Nevertheless, every application that uses these libraries should
  be tested thoroughly after changes to math libraries. This is because,
  although test here are reasonably good, they are not perfect. Also
  there might be changes to things that are "undocumented" but which
  previously worked.

  */

#include "sshincludes.h"
#include "sshglobals.h"
#include "sshmp.h"
#include "sshmp-xuint.h"



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


/* Printing of different types to the screen, these are helpful when
   trying to figure out what was wrong. And also, sometimes to compare
   results with other systems. */

void print_int(char *str, SshMPInteger op)
{
  char *mstr;

  mstr = ssh_mprz_get_str(op, 16);
  printf("%s %s\n", str, mstr);
  ssh_xfree(mstr);
}

void print_mont(char *str, SshMPIntMod op)
{
  char *mstr;
  SshMPIntegerStruct a;

  ssh_mprz_init(&a);
  ssh_mprz_set_mprzm(&a, op);

  mstr = ssh_mprz_get_str(&a, 16);
  printf("%s %s\n", str, mstr);
  ssh_xfree(mstr);

  ssh_mprz_clear(&a);
}

int check_mod(SshMPIntMod b, SshMPInteger a)
{
  SshMPIntegerStruct t;
  int rv;

  ssh_mprz_init(&t);
  ssh_mprz_set_mprzm(&t, b);
  rv = ssh_mprz_cmp(a, &t);
  ssh_mprz_clear(&t);
  return rv;
}

void my_rand_mod(SshMPIntMod a, SshMPInteger b, int bits)
{
  int n = ssh_rand() % bits;
  ssh_mprz_rand(b, n);
  ssh_mprzm_set_mprz(a, b);
}

void true_rand(SshMPInteger op, int bits)
{
  ssh_mprz_rand(op, ssh_rand() % bits);

  /* Occasionally make also negative. */
  if (ssh_rand() & 0x1)
    ssh_mprz_neg(op, op);
}

/* Tests the ssh_mprz_get_ui_[32,64] and ssh_mprz_set_ui_[32,64] routines */
void test_int_get_and_set(int flag, int bits)
{
  SshMPIntegerStruct op, oq;
  SshUInt32 a_1, a_2;
  SshUInt64 b_1, b_2;
  SshInt32 c_1, c_2;
  SshInt64 d_1, d_2;
  int j;

  ssh_mprz_init(&op);
  ssh_mprz_init(&oq);

  ssh_rand_seed((SshUInt32)ssh_time());

  /* Test the basic conversions work */
  for (j = 0; j < 10000; j++)
    {
      a_1 = ssh_rand();

      ssh_mprz_set_ui32(&op, a_1);
      a_2 = ssh_mprz_get_ui32(&op);

      if (a_1 != a_2)
        ssh_fatal("Error in get/set for SshUInt32");

      c_1 = ssh_rand();

      ssh_mprz_set_si32(&op, c_1);
      c_2 = ssh_mprz_get_si32(&op);

      if (c_1 != c_2)
        ssh_fatal("Error in get/set for SshInt32");

      b_1 = ssh_rand();
      b_1 = (b_1 << 32);
      b_1 += ssh_rand();

      ssh_mprz_set_ui64(&op, b_1);
      b_2 = ssh_mprz_get_ui64(&op);

      if (b_1 != b_2)
        ssh_fatal("Error in get/set for SshUInt64");

     d_1 = ssh_rand();
     d_1 = (d_1 << 32);
     d_1 += ssh_rand();

      ssh_mprz_set_si64(&op, d_1);
      d_2 = ssh_mprz_get_si64(&op);

      if (d_1 != d_2)
        ssh_fatal("Error in get/set for SshInt64");
    }


  /* Test the ssh_mprz_get_ui32 and ssh_mprz_get_ui64
     functions are compatible. */
  for (j = 0; j < 10000; j++)
    {
      true_rand(&op, 65);

      b_1 = ssh_mprz_get_ui64(&op);
      a_1 = ssh_mprz_get_ui32(&op);

      ssh_mprz_div_2exp(&op, &op, 32);
      a_2 = ssh_mprz_get_ui32(&op);

      b_2 = (((SshUInt64) a_2) << 32) + a_1;

      if (b_1 != b_2)
        ssh_fatal("The get functions for SshUInt32/SshUInt64 "
                  "are incompatible");
    }


  /* Test the ssh_mprz_set_[su]i32 and ssh_mprz_set_[su]i64
     functions are compatible. */
  for (j = 0; j < 10000; j++)
    {
      a_1 = ssh_rand();
      c_1 = ssh_rand();

      ssh_mprz_set_ui32(&op, a_1);
      ssh_mprz_set_ui64(&oq, (SshUInt64) a_1);

      if (ssh_mprz_cmp(&op, &oq))
        ssh_fatal("The set functions for SshUInt32/SshUInt64 "
                  "are incompatible");

      ssh_mprz_set_si32(&op, c_1);
      ssh_mprz_set_si64(&oq, (SshInt64) c_1);

      if (ssh_mprz_cmp(&op, &oq))
        ssh_fatal("The set functions for SshInt32/SshInt64 are incompatible");
    }


  /* Test the ssh_mprz_get_ui32 and ssh_mprz_get_ui64
     functions are compatible. */
  for (j = 0; j < 10000; j++)
    {
      true_rand(&op, 65);

      a_1 = ssh_mprz_get_ui32(&op);
      a_2 = (SshUInt32)ssh_mprz_get_ui64(&op);

      if (a_1 != a_2)
        ssh_fatal("The get functions for SshUInt32/SshUInt64 "
                  "are incompatible");
    }


  /* Test the ssh_mprz_get_ui32 and ssh_mprz_get_si32
     functions are compatible. */
  for (j = 0; j < 10000; j++)
    {
      true_rand(&op, 33);

      a_1 = ssh_mprz_get_ui32(&op);
      c_1 = ssh_mprz_get_si32(&op);

      /* Set the highest order bit of a_1 to zero */
      a_1 = a_1 & ((~((SshUInt32)0)) >> 1);

      if ((ssh_mprz_signum(&op) < 0) && ((SshInt32) a_1 != -c_1))
        ssh_fatal("The get functions for SshUInt32/SshInt32 are incompatible");

      if ((ssh_mprz_signum(&op) > 0) && ((SshInt32) a_1 != c_1))
        ssh_fatal("The get functions for SshUInt32/SshInt32 are incompatible");
    }

  /* Test the ssh_mprz_get_ui64 and ssh_mprz_get_si64
     functions are compatible. */
  for (j = 0; j < 10000; j++)
    {
      true_rand(&op, 65);

      b_1 = ssh_mprz_get_ui64(&op);
      d_1 = ssh_mprz_get_si64(&op);

      /* Set the highest order bit of a_1 to zero */
      b_1 = b_1 & ((~((SshUInt64)0)) >> 1);

      if ((ssh_mprz_signum(&op) < 0) && ((SshInt64) b_1 != -d_1))
        ssh_fatal("The get functions for SshUInt64/SshInt64 are incompatible");

      if ((ssh_mprz_signum(&op) > 0) && ((SshInt64) b_1 != d_1))
        ssh_fatal("The get functions for SshUInt64/SshInt64 are incompatible");
    }

  ssh_mprz_clear(&op);
  ssh_mprz_clear(&oq);
}

void test_int(int flag, int bits)
{
  SshMPIntegerStruct a, b, c, d, e, f, g;
  int j, k, i, l;

  ssh_mprz_init(&a);
  ssh_mprz_init(&b);
  ssh_mprz_init(&c);
  ssh_mprz_init(&d);
  ssh_mprz_init(&e);
  ssh_mprz_init(&f);
  ssh_mprz_init(&g);

  printf("Running integer tests (%u bits):\n", bits);

  printf(" * addition/subtraction test\n");
  for (j = 0; j < 1000; j++)
    {
      true_rand(&a, bits);
      true_rand(&b, bits);

      ssh_mprz_sub(&c, &a, &b);
      ssh_mprz_add(&d, &c, &b);
      if (ssh_mprz_cmp(&d, &a) != 0)
        {
          printf("error: subtraction/addition failed.\n");
          print_int("a = ", &a);
          print_int("a' = ", &d);
          exit(1);
        }
    }

  printf(" * addition/multiplication test\n");
  for (j = 0; j < 1000; j++)
    {
      true_rand(&a, bits);
      ssh_mprz_set_ui(&b, 0);
      k = ssh_rand() % 1000;
      for (i = 0; i < k; i++)
        ssh_mprz_add(&b, &b, &a);
      ssh_mprz_mul_ui(&c, &a, k);
      if (ssh_mprz_cmp(&c, &b) != 0)
        {
          printf("error: addition/multiplication failed.\n");
          print_int("a = ", &a);
          print_int("b = ", &b);
          print_int("c = ", &c);
          printf("k = %u\n", k);
          exit(1);
        }
    }

  printf(" * subtraction/multiplication test\n");
  for (j = 0; j < 1000; j++)
    {
      true_rand(&a, bits);
      ssh_mprz_set_ui(&b, 0);
      k = ssh_rand() % 1000;
      for (i = 0; i < k; i++)
        ssh_mprz_sub(&b, &b, &a);
      ssh_mprz_neg(&c, &a);
      ssh_mprz_mul_ui(&c, &c, k);
      if (ssh_mprz_cmp(&c, &b) != 0)
        {
          printf("error: subtraction/multiplication failed.\n");
          print_int("a = ", &a);
          print_int("b = ", &b);
          print_int("c = ", &c);
          printf("k = -%u\n", k);
          exit(1);
        }
    }

  printf(" * division test\n");
  for (j = 0; j < 1000; j++)
    {
      true_rand(&a, bits);
      true_rand(&b, bits);
      if (ssh_mprz_cmp_ui(&b, 0) == 0 ||
          ssh_mprz_cmp_ui(&a, 0) == 0)
        continue;
      ssh_mprz_mul(&c, &a, &b);
      ssh_mprz_divrem(&d, &e, &c, &b);
      ssh_mprz_divrem(&e, &f, &c, &a);

      if (ssh_mprz_cmp(&d, &a) != 0 ||
          ssh_mprz_cmp(&e, &b) != 0)
        {
          printf("error: division/multiplication failed.\n");

          print_int("c = ", &c);
          print_int("a = ", &a);
          print_int("a' = ", &d);
          print_int("b = ", &b);
          print_int("b' = ", &e);
          exit(1);
        }
    }

  for (j = 0; j < 1000; j++)
    {
      true_rand(&a, bits);
      true_rand(&b, bits);
      if (ssh_mprz_cmp_ui(&b, 0) == 0)
        continue;

      ssh_mprz_divrem(&c, &d, &a, &b);
      ssh_mprz_mul(&e, &c, &b);
      ssh_mprz_add(&e, &e, &d);

      if (ssh_mprz_cmp(&e, &a) != 0)
        {
          printf("error: division/multiplication failed (in second test).\n");
          print_int("a = ", &a);
          print_int("a' = ", &e);
          exit(1);
        }
    }

  printf(" * multiplication test\n");
  for (j = 0; j < 1000; j++)
    {
      true_rand(&a, bits);

      ssh_mprz_mul(&b, &a, &a);
      ssh_mprz_square(&c, &a);

      if (ssh_mprz_cmp(&c, &b) != 0)
        {
          printf("error: multiplication/squaring failed.\n");
          print_int("a = ", &a);
          print_int("b = ", &b);
          print_int("c = ", &c);

          print_int("a*a = ", &b);
          print_int("a^2 = ", &c);
          exit(1);
        }
    }

  printf(" * multiplication/gcd tests.\n");
  for (j = 0; j < 1000; j++)
    {
      true_rand(&a, bits);
      true_rand(&b, bits);
      if (ssh_mprz_cmp_ui(&a, 0) == 0 ||
          ssh_mprz_cmp_ui(&b, 0) == 0)
        continue;

      /* Make positive. */
      ssh_mprz_abs(&a, &a);
      ssh_mprz_abs(&b, &b);

      ssh_mprz_mul(&c, &a, &b);
      ssh_mprz_gcd(&d, &c, &a);
      ssh_mprz_gcd(&e, &c, &b);

      if (ssh_mprz_cmp(&d, &a) != 0 ||
          ssh_mprz_cmp(&e, &b) != 0)
        {
          printf("error: multiplication/gcd failed.\n");
          print_int("d = ", &d);
          print_int("a = ", &a);
          print_int("e = ", &e);
          print_int("b = ", &b);
          exit(1);
        }
    }

  printf(" * squaring test\n");
  for (j = 0; j < 1000; j++)
    {
      true_rand(&a, bits);

      ssh_mprz_square(&b, &a);
      ssh_mprz_sqrt(&c, &b);

      ssh_mprz_abs(&a, &a);

      if (ssh_mprz_cmp(&a, &c) != 0)
        {
          printf("error: square root/squaring failed.\n");
          print_int("a = ", &a);
          print_int("a' = ", &c);
          exit(1);
        }
    }

  printf(" * exponentiation test\n");
  for (j = 0; j < 100; j++)
    {
      true_rand(&a, bits);
      ssh_mprz_abs(&a, &a);

      if (ssh_mprz_cmp_ui(&a, 3) < 0)
        continue;









      k = ssh_rand();
      ssh_mprz_set_ui(&b, k);
      ssh_mprz_mod(&b, &b, &a);
      ssh_mprz_set(&c, &b);

      for (i = 1; i < 100; i++)
        {
          ssh_mprz_set_ui(&e, i);
          ssh_mprz_powm_ui_g(&d, k, &e, &a);
          if (ssh_mprz_cmp(&d, &c) != 0)
            {
              printf("error: powm ui/multiplication failed.\n");
              print_int("mod = ", &a);
              printf("g   = %u\n", k);
              printf("exp = %u\n", i);
              print_int("1   = ", &d);
              print_int("2   = ", &c);
              exit(1);
            }

          ssh_mprz_mul(&c, &c, &b);
          ssh_mprz_mod(&c, &c, &a);
        }
    }

  if (flag)
    {
      printf(" * base 2 verification\n");
      for (j = 0; j < 100; j++)
        {
          true_rand(&a, bits);
          if (ssh_mprz_cmp_ui(&a, 3) < 0)
            continue;









          true_rand(&b, bits);
          ssh_mprz_abs(&b, &b);

          ssh_mprz_powm_ui_g(&c, 2, &b, &a);
          ssh_mprz_powm_ui_g(&d, 2, &b, &a);
          if (ssh_mprz_cmp(&c, &d) != 0)
            {
              printf("error: powm ui/powm base2 failed.\n");
              print_int("mod = ", &a);
              print_int("exp = ", &b);
              print_int("powm ui    = ", &c);
              print_int("powm base2 = ", &d);
              exit(1);
            }
        }
    }


  printf(" * full exponentiation test\n");
  for (j = 0; j < 1000; j++)
    {
      true_rand(&a, bits);
      ssh_mprz_abs(&a, &a);

      if (ssh_mprz_cmp_ui(&a, 3) < 0)
        continue;









      k = ssh_rand();

      ssh_mprz_set_ui(&b, k);
      ssh_mprz_mod(&b, &b, &a);
      ssh_mprz_set(&c, &b);

      for (i = 1; i < 10; i++)
        {
          ssh_mprz_set_ui(&e, i);
          ssh_mprz_powm(&d, &b, &e, &a);
          if (ssh_mprz_cmp(&d, &c) != 0)
            {
              printf("error: powm/multiplication failed.\n");
              print_int("mod = ", &a);
              print_int("g   = ", &b);
              print_int("exp = ", &e);
              print_int("1   = ", &d);
              print_int("2   = ", &c);
              exit(1);
            }

          ssh_mprz_mul(&c, &c, &b);
          ssh_mprz_mod(&c, &c, &a);
        }
    }

  if (flag)
    {
      printf(" * gg exponentiation test\n");
      for (j = 0; j < 100; j++)
        {
          true_rand(&a, bits);
          ssh_mprz_abs(&a, &a);

          if (ssh_mprz_cmp_ui(&a, 3) < 0)
            continue;









          true_rand(&b, bits);
          ssh_mprz_mod(&b, &b, &a);
          true_rand(&c, bits);
          ssh_mprz_abs(&c, &c);

          true_rand(&d, bits);
          ssh_mprz_mod(&d, &d, &a);
          true_rand(&e, bits);
          ssh_mprz_abs(&e, &e);

          ssh_mprz_powm(&f, &b, &c, &a);
          ssh_mprz_powm(&g, &d, &e, &a);
          ssh_mprz_mul(&f, &f, &g);
          ssh_mprz_mod(&f, &f, &a);

          ssh_mprz_powm_gg(&g, &b, &c, &d, &e, &a);
          if (ssh_mprz_cmp(&f, &g) != 0)
            {
              printf("error: gg exp failed.\n");
              print_int("mod = ", &a);
              print_int("g   = ", &b);
              print_int("exp = ", &c);
              print_int("g   = ", &d);
              print_int("exp = ", &e);
              print_int("r1  = ", &f);
              print_int("r2  = ", &g);
              exit(1);

            }
        }

    }

  for (j = 0; j < 100; j++)
    {
      true_rand(&a, bits);
      ssh_mprz_abs(&a, &a);

      if (ssh_mprz_cmp_ui(&a, 3) < 0)
        continue;

      if ((ssh_mprz_get_ui(&a) & 0x1) == 0)
        ssh_mprz_add_ui(&a, &a, 1);

      k = ssh_rand();

      ssh_mprz_set_ui(&b, k);
      true_rand(&e, bits);
      ssh_mprz_abs(&e, &e);

      ssh_mprz_powm(&c, &b, &e, &a);
      ssh_mprz_powm_ui_g(&d, k, &e, &a);

      if (ssh_mprz_cmp(&c, &d) != 0)
        {
          printf("error: powm/powm_ui failed!\n");
          print_int("mod = ", &a);
          print_int("exp = ", &e);
          print_int("g   = ", &b);
          print_int("1   = ", &c);
          print_int("2   = ", &d);

          exit(1);
        }
    }

  printf(" * kronecker-jacobi-legendre symbol tests\n");
  for (j = 0; j < 100; j++)
    {
      static int table[100] =
      {1,1,1,1,-1,1,1,1,1,1,-1,-1,1,1,-1,1,1,1,-1,1,1,1,1,-1,1,-1,-1,
       1,-1,1,1,-1,-1,1,1,1,-1,1,-1,-1,1,1,1,1,1,1,1,1,-1,-1,-1,1,1,-1,
       1,-1,1,1,-1,-1,-1,1,-1,1,1,-1,1,-1,-1,1,1,1,1,1,-1,-1,-1,1,1,-1,
       1,-1,-1,1,-1,1,1,1,1,1,-1,1,1,1,1,1,1,1,-1,-1};
      ssh_mprz_set_ui(&a, j + 3);
      ssh_mprz_set_ui(&b, 7919);

      if (ssh_mprz_kronecker(&a, &b) != table[j])
        {
          printf("error: kronecker-jacobi-legendre symbol failed.\n");
          print_int(" a =", &a);
          print_int(" b =", &b);
          printf(" assumed %d got %d\n",
                 table[j], ssh_mprz_kronecker(&a, &b));
          exit(1);
        }
    }

  if (flag)
    {
      printf(" * prime tests\n");
      for (j = 0; j < 10; j++)
        {
          true_rand(&a, bits);
          ssh_mprz_abs(&a, &a);

          printf("    - searching... [%u bit prime]\n",
                 ssh_mprz_get_size(&a, 2));

          if (ssh_mprz_next_prime(&a, &a) == FALSE)
            continue;

          printf("    - probable prime found\n");
          print_int("      =", &a);

          printf("    - testing modular sqrt\n");
          for (l = 0; l < 10; l++)
            {
              true_rand(&b, bits);
              ssh_mprz_abs(&b, &b);

              if (ssh_mprz_mod_sqrt(&d, &b, &a) == FALSE)
                continue;
              ssh_mprz_mod(&b, &b, &a);
              ssh_mprz_square(&c, &d);
              ssh_mprz_mod(&c, &c, &a);
              if (ssh_mprz_cmp(&c, &b) != 0)
                {
                  printf("error: modular sqrt failed.\n");
                  print_int(" b =", &b);
                  print_int(" c =", &c);
                  print_int(" d =", &d);
                  printf(" Kronecker says: %d\n",
                         ssh_mprz_kronecker(&b, &a));
                  exit(1);
                }
            }
        }
    }


#ifndef SSHMATH_MINIMAL
  if (flag)
    {
      printf(" * full exponentiation test with base\n");
      for (j = 0; j < 10; j++)
        {
	  SshMPIntModPowPrecompStruct base;
          true_rand(&a, bits);
          ssh_mprz_abs(&a, &a);

          printf("     - searching for a prime.\n");

          if (ssh_mprz_next_prime(&a, &a) == FALSE)
            continue;

          true_rand(&b, bits);
          ssh_mprz_abs(&b, &b);
          ssh_mprz_set_bit(&b, bits);

          ssh_mprz_sub_ui(&c, &a, 1);
          if (!ssh_mprz_powm_precomp_init(&base, &b, &a, &c))
	    exit(1);

          true_rand(&e, bits);
          ssh_mprz_abs(&e, &e);
          ssh_mprz_powm_with_precomp(&c, &e, &base);
          ssh_mprz_powm(&d, &b, &e, &a);
          ssh_mprz_powm_precomp_clear(&base);

          if (ssh_mprz_cmp(&c, &d) != 0)
            {
              printf("error: powm/multiplication failed.\n");
              print_int("mod = ", &a);
              print_int("g   = ", &b);
              print_int("exp = ", &e);
              print_int("1   = ", &d);
              print_int("2   = ", &c);
              exit(1);
            }
        }
    }
#endif /* SSHMATH_MINIMAL */

  if (flag)
    {
      printf(" * square tests\n");
      for (j = 0; j < 1000; j++)
        {
          true_rand(&a, bits);

          ssh_mprz_square(&b, &a);

          if (ssh_mprz_is_perfect_square(&b) == 0)
            {
              printf("error: square/perfect square failed.\n");
              print_int("a = ", &a);
              print_int("a^2 = ", &b);
              ssh_mprz_sqrt(&c, &b);
              print_int("a' = ", &c);
              exit(1);
            }
        }
    }

  if (flag)
    {
      printf(" * gcd/gcdext tests\n");
      for (j = 0; j < 1000; j++)
        {
          true_rand(&a, bits);
          true_rand(&b, bits);

          if (ssh_mprz_cmp_ui(&a, 0) == 0 ||
              ssh_mprz_cmp_ui(&b, 0) == 0)
            continue;

          ssh_mprz_abs(&a, &a);
          ssh_mprz_abs(&b, &b);

          ssh_mprz_gcd(&c, &a, &b);
          if (ssh_mprz_cmp_ui(&c, 1) == 0)
            {
              ssh_mprz_gcdext(&d, &e, &f, &a, &b);

              if (ssh_mprz_cmp(&d, &c) != 0)
                {
                  printf("error: gcd/gcdext failed.\n");
                  exit(1);
                }

              ssh_mprz_mul(&e, &a, &e);
              ssh_mprz_mul(&f, &b, &f);
              ssh_mprz_add(&f, &f, &e);
              if (ssh_mprz_cmp(&f, &d) != 0)
                {
                  printf("error: gcdext failed.\n");
                  exit(1);
                }
            }
        }
    }

  printf(" * testing mod 2exp.\n");
  for (i = 0; i < 1000; i++)
    {
      true_rand(&a, bits/2);
      ssh_mprz_abs(&a, &a);
      true_rand(&b, bits/2);
      ssh_mprz_abs(&b, &b);
      ssh_mprz_mul_2exp(&c, &a, bits/2);
      ssh_mprz_add(&a, &c, &b);

      ssh_mprz_mod_2exp(&c, &a, bits/2);

      if (ssh_mprz_cmp(&c, &b) != 0)
        {
          printf("error: mod 2exp failed (case 1).\n");
          print_int("a = ", &a);
          print_int("b = ", &b);
          print_int("c = ", &c);
          exit(1);
        }

      ssh_mprz_mod_2exp(&c, &a, bits*2);
      if (ssh_mprz_cmp(&c, &a) != 0)
        {
          printf("error: mod 2exp failed (case 2).\n");
          print_int("a = ", &a);
          print_int("b = ", &b);
          print_int("c = ", &c);
          exit(1);
        }
    }

  printf(" * buffer testing.\n");
  for (i = 0; i < 1000; i++)
    {
      unsigned char *buffer, *buffer1;
      size_t i, buffer_len;

      true_rand(&a, bits);
      ssh_mprz_abs(&a, &a);

      buffer_len = (bits+7)/8;
      buffer = ssh_xmalloc(buffer_len);
      buffer1 = ssh_xmalloc(buffer_len);

      ssh_mprz_get_buf(buffer, buffer_len, &a);
      ssh_mprz_set_buf(&b, buffer, buffer_len);

      if (ssh_mprz_cmp(&a, &b) != 0)
        {
          printf("error: buffer <-> integer failed (%u bytes).\n", buffer_len);
          print_int("a = ", &a);
          print_int("b = ", &b);
          ssh_xfree(buffer);
          ssh_xfree(buffer1);
          exit(1);
        }

      ssh_mprz_get_buf_lsb_first(buffer1, buffer_len, &a);
      ssh_mprz_set_buf_lsb_first(&b, buffer1, buffer_len);

      if (ssh_mprz_cmp(&a, &b) != 0)
        {
          printf("error: buffer lsb first <-> integer failed (%u bytes).\n",
                 buffer_len);
          print_int("a = ", &a);
          print_int("b = ", &b);
          ssh_xfree(buffer);
          ssh_xfree(buffer1);
          exit(1);
        }

      for (i = 0; i < buffer_len; i++)
        {
          if (buffer[i] != buffer1[buffer_len - 1 - i])
            {
              printf("error: mp to buffer and mp to buffer lsb first "
                     "are incompatible at index %d: %d %d",
                     i, buffer[i], buffer1[buffer_len - 1 - i]);
              ssh_xfree(buffer);
              ssh_xfree(buffer1);
              exit(1);
            }
        }

      ssh_xfree(buffer);
      ssh_xfree(buffer1);



      /* Small buffer. */
      buffer_len = ssh_mprz_get_size(&a, 256) + 4;
      /* (ssh_rand() % buffer_len) + 1; */
      buffer     = ssh_xmalloc(buffer_len);

      ssh_mprz_get_buf(buffer, buffer_len, &a);
      ssh_mprz_set_buf(&b, buffer, buffer_len);

      /* Now compute suitable matching value. */
      ssh_mprz_mod_2exp(&c, &a, buffer_len * 8);

      if (ssh_mprz_cmp(&c, &b) != 0)
        {
          printf("error: buffer <-> integer failed (%u bytes / %u).\n",
                 buffer_len, ssh_mprz_get_size(&a, 256));
          print_int("a = ", &a);
          print_int("c = ", &c);
          print_int("b = ", &b);
          ssh_xfree(buffer);
          exit(1);
        }
      ssh_xfree(buffer);
    }

  printf(" * conversion testing.\n");
  for (i = 0; i < 1000; i++)
    {
      char *str;
      int base;

      do
        {
          base = ssh_rand() % 65;
        }
      while (base < 2);

      true_rand(&a, bits);

      str = ssh_mprz_get_str(&a, base);
      ssh_mprz_set_str(&b, str, base);

      if (ssh_mprz_cmp(&a, &b) != 0)
        {
          printf("error: conversion to integer failed in base %d.\n", base);
          print_int("a = ", &a);
          print_int("b = ", &b);
          printf("Output: %s\n", str);
          ssh_xfree(str);
          exit(1);
        }

      ssh_xfree(str);

      /* Test for automatic recognition. */

      switch (ssh_rand() % 3)
        {
        case 0:
          base = 8;
          break;
        case 1:
          base = 10;
          break;
        case 2:
          base = 16;
          break;
        }

      str = ssh_mprz_get_str(&a, base);
      ssh_mprz_set_str(&b, str, 0);

      if (ssh_mprz_cmp(&a, &b) != 0)
        {
          printf("error: automatic recognition of base %d.\n", base);
          print_int("a = ", &a);
          print_int("b = ", &b);
          printf("Output: %s\n", str);
          ssh_xfree(str);
          exit(1);
        }
      ssh_xfree(str);

    }

  ssh_mprz_clear(&a);
  ssh_mprz_clear(&b);
  ssh_mprz_clear(&c);
  ssh_mprz_clear(&d);
  ssh_mprz_clear(&e);
  ssh_mprz_clear(&f);
  ssh_mprz_clear(&g);
}

void test_mod(int flag, int bits)
{
  /* Montgomery testing. */
  SshMPIntModStruct a0, b0, c0;
  SshMPIntegerStruct  a1, b1, c1, m1, d;
  SshMPIntIdealStruct m0;
  int i;
  Boolean rv1, rv2;

  ssh_mprz_init(&a1);
  ssh_mprz_init(&b1);
  ssh_mprz_init(&c1);
  ssh_mprz_init(&m1);
  ssh_mprz_init(&d);

  printf(" * random moduli search\n");

  ssh_mprz_rand(&m1, bits);
#if 0
  while (ssh_mprz_next_prime(&m1, &m1) == FALSE)
    ssh_mprz_rand(&m1, bits);
#endif

  if (!ssh_mprzm_init_ideal(&m0, &m1))
    ssh_fatal("Cannot initialize Montgomory ideal");

  ssh_mprzm_init(&a0, &m0);
  ssh_mprzm_init(&b0, &m0);
  ssh_mprzm_init(&c0, &m0);

  print_int ("m1 = ", &m1);

  /* Additions. */
  printf(" * addition test\n");
  for (i = 0; i < 1000; i++)
    {
      my_rand_mod(&a0, &a1, bits);
      my_rand_mod(&b0, &b1, bits);

      ssh_mprzm_add(&c0, &a0, &b0);

      ssh_mprz_add(&c1, &a1, &b1);
      ssh_mprz_mod(&c1, &c1, &m1);

      if (check_mod(&c0, &c1) != 0)
        {
          printf("error: mismatch at iteration %u\n", i);
          print_int ("  a1      = ", &a1);
          print_int ("  b1      = ", &b1);
          print_int ("  a1 + b1 = ", &c1);
          print_mont("  a0      = ", &a0);
          print_mont("  b0      = ", &b0);
          print_mont("  a0 + b0 = ", &c0);
          exit(1);
        }
    }

  /* Subtractions. */
  printf(" * subtraction test\n");
  for (i = 0; i < 1000; i++)
    {
      my_rand_mod(&a0, &a1, bits);
      my_rand_mod(&b0, &b1, bits);

      ssh_mprzm_sub(&c0, &a0, &b0);

      ssh_mprz_sub(&c1, &a1, &b1);
      ssh_mprz_mod(&c1, &c1, &m1);

      if (check_mod(&c0, &c1) != 0)
        {
          printf("error: mismatch at iteration %u\n", i);
          print_int ("  a1      = ", &a1);
          print_int ("  b1      = ", &b1);
          print_int ("  a1 - b1 = ", &c1);
          print_mont("  a0      = ", &a0);
          print_mont("  b0      = ", &b0);
          print_mont("  a0 - b0 = ", &c0);
          exit(1);
        }
    }

  /* Multiplications. */
  printf(" * multiplication test\n");
  for (i = 0; i < 1000; i++)
    {
      my_rand_mod(&a0, &a1, bits);
      my_rand_mod(&b0, &b1, bits);

      ssh_mprzm_mul(&c0, &a0, &b0);

      ssh_mprz_mul(&c1, &a1, &b1);
      ssh_mprz_mod(&c1, &c1, &m1);

      if (check_mod(&c0, &c1) != 0)
        {
          printf("error: mismatch at iteration %u\n", i);
          print_int ("  a1      = ", &a1);
          print_int ("  b1      = ", &b1);
          print_int ("  a1 * b1 = ", &c1);
          print_mont("  a0      = ", &a0);
          print_mont("  b0      = ", &b0);
          print_mont("  a0 * b0 = ", &c0);
          exit(1);
        }
    }

  /* Squarings. */
  printf(" * squaring test\n");
  for (i = 0; i < 1000; i++)
    {
      my_rand_mod(&a0, &a1, bits);

      ssh_mprzm_square(&c0, &a0);

      ssh_mprz_square(&c1, &a1);
      ssh_mprz_mod(&c1, &c1, &m1);

      if (check_mod(&c0, &c1) != 0)
        {
          printf("error: mismatch at iteration %u\n", i);
          print_int ("  a1   = ", &a1);
          print_int ("  a1^2 = ", &c1);
          print_mont("  a0   = ", &a0);
          print_mont("  a0^2 = ", &c0);
          exit(1);
        }
    }

  printf(" * inversion test\n");
  for (i = 0; i < 1000; i++)
    {
      my_rand_mod(&a0, &a1, bits);

      rv1 = ssh_mprzm_invert(&c0, &a0);
      rv2 = ssh_mprz_invert(&c1, &a1, &m1);

      if (rv1 == FALSE && rv2 == FALSE)
        continue;

      if (check_mod(&c0, &c1) != 0)
        {
          printf("error: mismatch at iteration %u\n", i);
          print_int ("  a1    = ", &a1);
          print_int ("  a1^-1 = ", &c1);
          print_mont("  a0    = ", &a0);
          print_mont("  a0^-1 = ", &c0);
          exit(1);
        }
    }

  printf(" * mul ui test\n");
  for (i = 0; i < 1000; i++)
    {
      my_rand_mod(&a0, &a1, bits);

      ssh_mprzm_mul_ui(&c0, &a0, i + 1);

      ssh_mprz_mul_ui(&c1, &a1, i + 1);
      ssh_mprz_mod(&c1, &c1, &m1);

      if (check_mod(&c0, &c1) != 0)
        {
          printf("error: mismatch at iteration %u\n", i);
          print_int ("  a1     = ", &a1);
          print_int ("  a1 * u = ", &c1);
          print_mont("  a0     = ", &a0);
          print_mont("  a0 * u = ", &c0);
          exit(1);
        }
    }

  printf(" * mul 2exp test\n");
  for (i = 0; i < 1000; i++)
    {
      my_rand_mod(&a0, &a1, bits);

      ssh_mprzm_mul_2exp(&c0, &a0, (i % 50) + 1);

      ssh_mprz_mul_2exp(&c1, &a1, (i % 50) + 1);
      ssh_mprz_mod(&c1, &c1, &m1);

      if (check_mod(&c0, &c1) != 0)
        {
          printf("error: mismatch at iteration %u\n", i);
          print_int ("  a1       = ", &a1);
          print_int ("  a1 * 2^u = ", &c1);
          print_mont("  a0       = ", &a0);
          print_mont("  a0 * 2^u = ", &c0);
          exit(1);
        }
    }

#if 0
  printf(" * div 2exp test\n");
  for (i = 0; i < 1000; i++)
    {
      my_rand_mod(&a0, &a1, bits);

      ssh_mprzm_div_2exp(&c0, &a0, (i % 5));

      ssh_mprz_set_ui(&d, 1 << (i % 5));
      ssh_mprz_invert(&d, &d, &m1);
      ssh_mprz_mul(&c1, &a1, &d);
      ssh_mprz_mod(&c1, &c1, &m1);

      if (check_mod(&c0, &c1) != 0)
        {
          printf("error: mismatch at iteration %u\n", i);
          print_int ("  a1     = ", &a1);
          print_int ("  a1 * u = ", &c1);
          print_mont("  a0     = ", &a0);
          print_mont("  a0 * u = ", &c0);
          exit(1);
        }
    }
#endif



  ssh_mprzm_clear(&a0);
  ssh_mprzm_clear(&b0);
  ssh_mprzm_clear(&c0);
  ssh_mprzm_clear_ideal(&m0);

  ssh_mprz_clear(&a1);
  ssh_mprz_clear(&b1);
  ssh_mprz_clear(&c1);
  ssh_mprz_clear(&m1);
  ssh_mprz_clear(&d);
}




















#ifdef SSHDIST_MATH_ECP

/* Elliptic curve stuff. First the prime case. */

void print_ecp_point(const char *str, const SshECPPoint P)
{
  printf("%s \n{   ", str);
  ssh_mprz_out_str(NULL, 10, &P->x);
  printf(", \n    ");
  ssh_mprz_out_str(NULL, 10, &P->y);
  printf(", %u }\n", P->z);
}


/* Table of parameters. */

typedef struct
{
  const char *q;
  const char *a;
  const char *b;
  const char *c;
  const char *px, *py;
  const char *n;
} SshECPFixedParams;

/* This set of parameters is intented for testing purposes only. */
const SshECPFixedParams ssh_ecp_fixed_params[] =
{
  {
    /* 155 bits */
    "31407857097127860965216287356072559134859825543",
    "2731256435122317801261871679028549091389013906",
    "10714317566020843022911894761291265613594418240",
    "31407857097127860965216427618348169229298502938",
    "16392655484387136812157475999461840857228033620",
    "2799086322187201568878931628895797117411224036",
    "402664834578562320066877277158309861914083371"
  },
  {
    /* 155 bits */
    "36297272659662506860980360407302074284133162871",
    "27124701431231299400484722496484295443330204918",
    "30301737350042067130127502794912132619158043000",
    "36297272659662506860980147341067393239091873883",
    "11711116373547979507936212029780235644179397805",
    "32762560063802500788917178597259173957396445450",
    "33640575491381625732043477771053949671671",
  },
  {
    /* 175 bits */
    "40950177705606685781046242922154881607956178336371883",
    "24746273018219762494198595506743299332378325756031886",
    "6503278719366954296567774236884439158775557920331547",
    "40950177705606685781046243158324028591251169648712266",
    "6408402137441767794969170236925842559451119808358974",
    "39032544798419387403330432854399185547513580950826190",
    "2750918830149582546086674940099692905498533497831",
  },
  {
    /* 175 bits */
    "25133914800611099026082727697808480710160935689515477",
    "17146225641958545872320149903955451167573508624853931",
    "21261641208097867800497328477718361404177050434117193",
    "25133914800611099026082727581231133979322149086167579",
    "8738002582171225345779025855668373615175447647735275",
    "6530642698522393684297998663212006319191306125962008",
    "474718057534367152656837489904956793301367209",
  },
  { NULL },
};

void ssh_ecp_set_param(const SshECPFixedParams *params,
                       SshECPCurve E, SshECPPoint P, SshMPInteger n)
{
  SshMPIntegerStruct a, b, c, q, px, py;

  ssh_mprz_init(&a);
  ssh_mprz_init(&b);
  ssh_mprz_init(&c);
  ssh_mprz_init(&q);
  ssh_mprz_init(&px);
  ssh_mprz_init(&py);

  ssh_mprz_set_str(&q, params->q, 0);
  ssh_mprz_set_str(&a, params->a, 0);
  ssh_mprz_set_str(&b, params->b, 0);
  ssh_mprz_set_str(&px, params->px, 0);
  ssh_mprz_set_str(&py, params->py, 0);
  ssh_mprz_set_str(n, params->n, 0);
  ssh_mprz_set_str(&c, params->c, 0);

  ssh_ecp_set_curve(E, &q, &a, &b, &c);

  ssh_ecp_init_point(P, E);
  ssh_ecp_set_point(P, &px, &py, 1);

  ssh_mprz_clear(&a);
  ssh_mprz_clear(&b);
  ssh_mprz_clear(&c);
  ssh_mprz_clear(&q);
  ssh_mprz_clear(&px);
  ssh_mprz_clear(&py);
}

void test_ecp(int flag, int bits)
{
  SshECPCurveStruct E;
  SshECPPointStruct P, Q, R, T;
  SshMPIntegerStruct n, k;
  int i, j, s;

  printf(" * elliptic curves over finite field (mod p) tests\n");

  for (i = 0; ssh_ecp_fixed_params[i].q != NULL; i++)
    {
      printf("  # Curve %u\n", i + 1);

      ssh_mprz_init(&n);
      ssh_mprz_init(&k);
      ssh_ecp_set_param(&ssh_ecp_fixed_params[i],
                        &E, &P, &n);
      ssh_ecp_init_point(&R, &E);
      ssh_ecp_init_point(&Q, &E);
      ssh_ecp_init_point(&T, &E);

      /* Testing the generic multiplication routine. */
      ssh_ecp_set_identity(&Q);
      for (j = 1; j < 100; j++)
        {
          ssh_ecp_add(&Q, &Q, &P, &E);
          ssh_mprz_set_ui(&k, j);
          ssh_ecp_generic_mul(&R, &P, &k, &E);

          if (ssh_ecp_compare_points(&Q, &R) == FALSE)
            {
              printf("error: points did not match in multiplication by %u\n",
                     j);
              print_ecp_point(" Q = ", &Q);
              print_ecp_point(" R = ", &R);
              print_ecp_point(" P = ", &P);
              exit(1);
            }
        }

      /* Now verify that the order is correct. */
      ssh_ecp_generic_mul(&R, &P, &n, &E);
      if (R.z != 0)
        {
          printf("error: failed at ecp values, index %u. "
                 "Cardinality did not match.\n", i);
          exit(1);
        }

      /* Test the another multiplier if n is prime. */
      if (ssh_mprz_is_probable_prime(&n, 10))
        {
          printf("  # Testing the efficient multiply routine\n");

          for (j = 0; j < 100; j++)
            {
              ssh_mprz_rand(&k, ssh_mprz_get_size(&n, 2));
              ssh_mprz_mod(&k, &k, &n);
              ssh_ecp_generic_mul(&Q, &P, &k, &E);
              ssh_ecp_mul(&T, &P, &k, &E);
              if (ssh_ecp_compare_points(&Q, &T) == FALSE)
                {
                  printf("error: "
                         "multiplication routines are not equivalent.\n");
                  exit(1);
                }
            }
        }

      printf("  # Random point tests\n");

      /* Now do some additional testing. */
      ssh_mprz_div(&k, &E.c, &n);
      if (ssh_mprz_cmp_ui(&k, 0) <= 0)
        {
          printf("error: parameters in correct.\n");
          exit(1);
        }

      for (s = 0; s < 10; s++)
        {
          for (j = 0; j < 1000; j++)
            {
              ssh_ecp_random_point(&Q, &E);
              ssh_ecp_generic_mul(&R, &Q, &k, &E);
              if (R.z == 1)
                break;
            }

          if (j >= 1000)
            {
              printf("error: looped %i times, did not find a point.\n", i);
              exit(1);
            }

          ssh_ecp_generic_mul(&Q, &R, &n, &E);
          if (Q.z != 0)
            {
              printf("error: did not find point of correct order.\n");
              exit(1);
            }

          /* Do a addition.
           */
          ssh_ecp_negate_point(&T, &P, &E);
          ssh_ecp_add(&Q, &P, &T, &E);
          if (Q.z != 0)
            {
              printf("error: when added P and -P together.\n");
              exit(1);
            }

          ssh_ecp_add(&Q, &R, &P, &E);
          ssh_ecp_add(&T, &P, &R, &E);
          if (ssh_ecp_compare_points(&T, &Q) == FALSE)
            {
              printf("error: addition order is meaningful.\n");
              exit(1);
            }

          ssh_ecp_negate_point(&T, &P, &E);
          ssh_ecp_add(&Q, &R, &T, &E);
          ssh_ecp_add(&Q, &Q, &T, &E);
          ssh_ecp_add(&Q, &Q, &P, &E);
          ssh_ecp_add(&Q, &Q, &P, &E);

          if (ssh_ecp_compare_points(&Q, &R) == FALSE)
            {
              printf("error: points are not equal.\n");
              print_ecp_point(" P = ", &P);
              print_ecp_point(" Q = ", &Q);
              print_ecp_point(" T = ", &T);
              print_ecp_point(" R = ", &R);
              ssh_ecp_add(&T, &Q, &R, &E);
              print_ecp_point(" T = ", &T);
              exit(1);
            }
        }

      ssh_ecp_clear_curve(&E);
      ssh_ecp_clear_point(&P);
      ssh_ecp_clear_point(&R);
      ssh_ecp_clear_point(&Q);
      ssh_ecp_clear_point(&T);

      ssh_mprz_clear(&n);
      ssh_mprz_clear(&k);
    }
}
#endif /* SSHDIST_MATH_ECP */















































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































/* Speed tests of some sort. */

void timing_int(int bits)
{
  SshMPIntegerStruct a, b, c, d, e, f[100];
  struct SshTimeMeasureRec tmit = SSH_TIME_MEASURE_INITIALIZER;
  unsigned int i, j;

#ifndef SSHMATH_MINIMAL
  SshMPIntModPowPrecompStruct base;
#endif


  ssh_mprz_init(&a);
  ssh_mprz_init(&b);
  ssh_mprz_init(&c);
  ssh_mprz_init(&d);
  ssh_mprz_init(&e);

  printf("Timing integer arithmetic.\n");

  printf("Bits = %u\n", bits);

  for (i = 0; i < 100; i++)
    {
      ssh_mprz_init(&f[i]);
      ssh_mprz_rand(&f[i], bits);
      if ((ssh_mprz_get_ui(&f[i]) & 0x1) == 0)
        ssh_mprz_add_ui(&f[i], &f[i], 1);
    }

  printf("Timing multiplication [%u * %u = %u] \n",
         bits, bits, bits + bits);
  ssh_time_measure_reset(&tmit);
  ssh_time_measure_start(&tmit);
  for (i = 0; i < 50; i++)
    {
      ssh_mprz_rand(&b, bits);
      for (j = 0; j < 100; j++)
        ssh_mprz_mul(&a, &f[j], &b);
    }
  ssh_time_measure_stop(&tmit);

  printf("  * %g multiplications per sec\n",
         ((double)50*100) /
         ((double) ssh_time_measure_get(&tmit,
                                        SSH_TIME_GRANULARITY_MICROSECOND) /
          1000000.0));

  printf("Timing divisions [%u / %u = %u] \n",
         bits + bits, bits, bits);
  ssh_time_measure_reset(&tmit);
  ssh_time_measure_start(&tmit);
  for (i = 0; i < 50; i++)
    {
      ssh_mprz_rand(&b, bits*2);
      for (j = 0; j < 100; j++)
        ssh_mprz_divrem(&a, &c, &b, &f[j]);
    }
  ssh_time_measure_stop(&tmit);

  printf("  * %g divisions per sec\n",
         ((double)50*100) /
         ((double) ssh_time_measure_get(&tmit,
                                        SSH_TIME_GRANULARITY_MICROSECOND) /
          1000000.0));


  printf("Timing modular reductions [%u %% %u = %u] \n",
         bits + bits, bits, bits);
  ssh_time_measure_reset(&tmit);
  ssh_time_measure_start(&tmit);
  for (i = 0; i < 50; i++)
    {
      ssh_mprz_rand(&b, bits*2);
      for (j = 0; j < 100; j++)
        ssh_mprz_mod(&a, &b, &f[j]);
    }
  ssh_time_measure_stop(&tmit);

  printf("  * %g modular reductions per sec\n",
         ((double)50*100) /
         ((double) ssh_time_measure_get(&tmit,
                                        SSH_TIME_GRANULARITY_MICROSECOND) /
          1000000.0));

  printf("Timing squarings [%u^2 = %u] \n",
         bits, bits + bits);
  ssh_time_measure_reset(&tmit);
  ssh_time_measure_start(&tmit);
  for (i = 0; i < 50; i++)
    {
      ssh_mprz_rand(&b, bits);
      for (j = 0; j < 100; j++)
        ssh_mprz_square(&a, &b);
    }
  ssh_time_measure_stop(&tmit);

  printf("  * %g squarings per sec\n",
         ((double)50*100) /
         ((double) ssh_time_measure_get(&tmit,
                                        SSH_TIME_GRANULARITY_MICROSECOND) /
          1000000.0));

  printf("Timing modexp [%u^%u %% %u = %u] \n",
         bits, bits, bits, bits);
  ssh_time_measure_reset(&tmit);
  ssh_time_measure_start(&tmit);
  for (j = 0, i = 0; i < 10; i++, j += 2)
    {
      ssh_mprz_rand(&b, bits);
      ssh_mprz_powm(&a, &f[j + 1], &b, &f[j + 2]);
    }
  ssh_time_measure_stop(&tmit);

  printf("  * %g modexps per sec\n",
         ((double)10) /
         ((double) ssh_time_measure_get(&tmit,
                                        SSH_TIME_GRANULARITY_MICROSECOND) /
          1000000.0));

  /* Generate the fixed base. */
  do
    {
      ssh_mprz_rand(&b, bits);
    }
  while (ssh_mprz_get_size(&b, 2) < bits-1);


#ifndef SSHMATH_MINIMAL

  /* Create the base. */
  ssh_mprz_sub_ui(&a, &f[2], 1);
  if (!ssh_mprz_powm_precomp_init(&base, &b, &f[2], &a))
    exit(1);

  printf("Timing modexp with fixed base [%u^%u %% %u = %u] \n",
         bits, bits, bits, bits);

  ssh_time_measure_reset(&tmit);
  ssh_time_measure_start(&tmit);
  for (j = 0, i = 0; i < 10; i++, j += 2)
    ssh_mprz_powm_with_precomp(&a, &f[j + 1], &base);
  ssh_time_measure_stop(&tmit);


  printf("  * %g modexps per sec\n",
         ((double)10) /
         ((double) ssh_time_measure_get(&tmit,
                                        SSH_TIME_GRANULARITY_MICROSECOND) /
          1000000.0));

  ssh_mprz_powm_precomp_clear(&base);
#endif /* SSHMATH_MINIMAL */


#define ENTROPY_BITS 256

  printf("Timing modexp [%u^%u %% %u = %u] \n",
         bits, ENTROPY_BITS, bits, bits);
  ssh_time_measure_reset(&tmit);
  ssh_time_measure_start(&tmit);
  for (j = 0, i = 0; i < 10; i++, j += 2)
    {
      ssh_mprz_rand(&b, ENTROPY_BITS);
      ssh_mprz_set_bit(&b, ENTROPY_BITS);
      ssh_mprz_powm(&a, &f[j+1], &b, &f[j + 2]);
    }
  ssh_time_measure_stop(&tmit);

  printf("  * %g modexps per sec\n",
         ((double)10) /
         ((double) ssh_time_measure_get(&tmit,
                                        SSH_TIME_GRANULARITY_MICROSECOND) /
          1000000.0));

  printf("Timing gg modexp [%u^%u %% %u = %u] \n",
         bits, ENTROPY_BITS, bits, bits);
  ssh_time_measure_reset(&tmit);
  ssh_time_measure_start(&tmit);
  for (j = 0, i = 0; i < 10; i++, j += 2)
    {
      ssh_mprz_rand(&b, ENTROPY_BITS);
      ssh_mprz_rand(&c, ENTROPY_BITS);
      ssh_mprz_set_bit(&b, ENTROPY_BITS);
      ssh_mprz_set_bit(&c, ENTROPY_BITS);
      ssh_mprz_powm_gg(&a, &f[j+1], &b, &f[j+2], &c, &f[j + 3]);
    }
  ssh_time_measure_stop(&tmit);

  printf("  * %g gg modexps per sec\n",
         ((double)10) /
         ((double) ssh_time_measure_get(&tmit,
                                        SSH_TIME_GRANULARITY_MICROSECOND) /
          1000000.0));


  /* Time the buffer routines. */

  printf("Timing buffer conversion [%u = %u] \n",
         bits, bits);
  ssh_time_measure_reset(&tmit);
  ssh_time_measure_start(&tmit);
  {
    unsigned char *buffer;
    size_t buffer_len;

    buffer_len = (bits + 7)/8;
    buffer     = ssh_xmalloc(buffer_len);

    for (j = 0, i = 0; i < 10000; i++, j += 2)
      {
        ssh_mprz_get_buf(buffer, buffer_len, &f[j % 20]);
        ssh_mprz_set_buf(&f[j % 20], buffer, buffer_len);
      }
    ssh_xfree(buffer);
  }
  ssh_time_measure_stop(&tmit);

  printf("  * %g buffer conversions / sec\n",
         ((double)10000) /
         ((double) ssh_time_measure_get(&tmit,
                                        SSH_TIME_GRANULARITY_MICROSECOND) /
          1000000.0));



  ssh_mprz_clear(&a);
  ssh_mprz_clear(&b);
  ssh_mprz_clear(&c);
  ssh_mprz_clear(&d);
  ssh_mprz_clear(&e);

  for (i = 0; i < 100; i++)
    ssh_mprz_clear(&f[i]);
}

void timing_modular(int bits)
{
  SshMPIntModStruct b, c, d, e, f[100];
  SshMPIntIdealStruct m;
  SshMPIntegerStruct a;
  int i, j;
  struct SshTimeMeasureRec tmit = SSH_TIME_MEASURE_INITIALIZER;

  ssh_mprz_init(&a);

  do
    {
      ssh_mprz_rand(&a, bits);
      while (ssh_mprz_next_prime(&a, &a) == FALSE)
        ssh_mprz_rand(&a, bits);
    }
  while (ssh_mprz_get_size(&a, 2) < bits - 1);

  printf("Timing modular arithmetic.\n");

  /* Deal with NaN faliure. */
  if (!ssh_mprzm_init_ideal(&m, &a))
    return;

  printf("Bits = %u\n", bits);

  ssh_mprzm_init(&b, &m);
  ssh_mprzm_init(&c, &m);
  ssh_mprzm_init(&d, &m);
  ssh_mprzm_init(&e, &m);

  for (i = 0; i < 100; i++)
    {
      ssh_mprzm_init(&f[i], &m);
      ssh_mprz_rand(&a, bits);
      ssh_mprzm_set_mprz(&f[i], &a);
    }

  printf("Timing multiplication [%u * %u = %u] \n",
         bits, bits, bits);
  ssh_time_measure_reset(&tmit);
  ssh_time_measure_start(&tmit);
  for (i = 0; i < 50; i++)
    {
      ssh_mprzm_set(&b, &f[i]);
      for (j = 0; j < 100; j++)
        ssh_mprzm_mul(&c, &f[j], &b);
    }
  ssh_time_measure_stop(&tmit);

  printf("  * %g multiplications per sec\n",
         ((double)50*100) /
         ((double) ssh_time_measure_get(&tmit,
                                        SSH_TIME_GRANULARITY_MICROSECOND) /
          1000000.0));

  printf("Timing squarings [%u^2 = %u] \n",
         bits, bits);
  ssh_time_measure_reset(&tmit);
  ssh_time_measure_start(&tmit);
  for (i = 0; i < 50; i++)
    for (j = 0; j < 100; j++)
      ssh_mprzm_square(&b, &f[j]);
  ssh_time_measure_stop(&tmit);

  printf("  * %g squarings per sec\n",
         ((double)50*100) /
         ((double) ssh_time_measure_get(&tmit,
                                        SSH_TIME_GRANULARITY_MICROSECOND) /
          1000000.0));

  ssh_mprzm_clear(&b);
  ssh_mprzm_clear(&c);
  ssh_mprzm_clear(&d);
  ssh_mprzm_clear(&e);

  for (i = 0; i < 100; i++)
    ssh_mprzm_clear(&f[i]);
  ssh_mprzm_clear_ideal(&m);
  ssh_mprz_clear(&a);
}


























































































































































































































































































































































































































































































































































































/* Routines for handling the arguments etc. */

typedef struct CommandRec
{
  char *name;
  int  type;
  int  args;
} Command;

#define C_NONE    -1
#define C_HELP    0
#define C_ALL     1
#define C_ITR     2
#define C_GF2N    3
#define C_INT     4
#define C_MOD     5
#define C_BIN     6
#define C_POLY2N  7
#define C_ECP     8
#define C_EC2N    9
#define C_FEC2N   10
#define C_OEF     11
#define C_ECOEF   12

#define C_BITS     20
#define C_BITS_ADV 21

#define C_TIMING   30

#define C_FATALCB  99

const Command commands[] =
{
  { "-h", C_HELP, 0 },
  { "--help", C_HELP, 0 },

  { "-a", C_ALL, 0 },
  { "--all", C_ALL, 0 },

  { "-i", C_ITR, 1 },
  { "--iterations", C_ITR, 1 },

  { "-b", C_BITS, 1 },
  { "--bits", C_BITS, 1 },
  { "-ba", C_BITS_ADV, 1 },
  { "--bits-advance", C_BITS_ADV, 1 },

  { "-t", C_TIMING, 0 },
  { "--timing", C_TIMING, 0 },

  /* Fatal callback used. */
  { "--fatalcb", C_FATALCB, 0 },

  /* General classes of tests. */
  { "--integer", C_INT, 1 },
  { "--modular", C_MOD, 1 },








#ifdef SSHDIST_MATH_ECP
  { "--ecp", C_ECP, 1 },
#endif /* SSHDIST_MATH_ECP */






  { NULL }
};

int check_arg(char *str, int *args)
{
  int i;

  for (i = 0; commands[i].name; i++)
    if (strcmp(str, commands[i].name) == 0)
      {
        *args = commands[i].args;
        return commands[i].type;
      }

  *args = 0;
  return C_NONE;
}

void usage(void)
{
  printf("usage: t-mathtest [options]\n"
         "options:\n"
         " -a     run all tests (might take longer)\n"
         " -t     run also timings for modules\n"
         " -i xx  run all tests xx times (will use different random seeds)\n"
         " -h     this help.\n"
         " -b     initial bits of the test parameters.\n"
         "advanced options: \n"
         " --integer [on|off] sets the integer arithmetic testing on/off.\n"
         " --modular [on|off] sets the (mod p) arithmetic testing on/off.\n"






#ifdef SSHDIST_MATH_ECP
         " --ecp     [on|off] sets the elliptic curve (mod p) testing "
                "on/off.\n"
#endif /* SSHDIST_MATH_ECP */





         );
  exit(1);
}

int on_off(char *str)
{
  if (strcmp(str, "on") == 0)
    return 1;
  if (strcmp(str, "off") == 0)
    return 0;

  printf("error: '%s' should be 'on' or 'off'.\n", str);
  exit(1);
}

void my_fatal_cb(const char *message, void *context)
{
  printf("t-mathtest fatal handler called.\n"
         "message:\n"
         "  %s\n"
         "Aborting.\n", message);
  abort();
}

int main(int ac, char *av[])
{
  int i, all, itr, type, args;
  int gf2n, mod, oef, integer, ecp, ecoef, ec2n, fec2n, poly2n, bpoly,
    bits, bits_advance, timing;
  int fatal_cb;

  ssh_global_init();

  if (!ssh_math_library_initialize())
    ssh_fatal("Cannot initialize the math library.");

  if (!ssh_math_library_self_tests())
    ssh_fatal("Math library self tests failed.");

  printf("Arithmetic library test suite\n"
         "Copyright (C) 2002, 2003 SFNT Finland Oy\n"
         "              All rights reserved.\n"
         "\n"
         "Features: \n"
         "  - integer arithmetic\n"
         "  - finite field arithmetic (mod p)\n"





#ifdef SSHDIST_MATH_ECP
         "  - elliptic curves over GF(2^n) arithmetic\n"
         "  - elliptic curves over OEF arithmetic\n"
#endif /* SSHDIST_MATH_ECP */



         "\n");

  /* Randomize the random number generator. */
  ssh_rand_seed((unsigned int)(ssh_time()));

  /* Don't use this if you want to test the mathlibrary :) */
  /*extra_test(); */
  /*test_rsa_kphi(); */

  all = 0;
  itr = 1;

  fatal_cb = FALSE;

  timing = 0;

  bits = 512;
  bits_advance = 128;

  gf2n     = 0;
  integer  = 1;
  oef      = 0;
  mod      = 0;
  bpoly    = 0;
  ecp      = 0;
  ecoef    = 0;
  ec2n     = 0;
  fec2n    = 0;
  poly2n   = 0;

  for (i = 1; i < ac; i++)
    {
      type = check_arg(av[i], &args);
      if (args >= ac - i)
        {
          printf("error: not enough arguments for '%s'.\n",
                 av[i]);
          exit(1);
        }

      switch (type)
        {
        case C_FATALCB:
          fatal_cb = TRUE;
          break;
        case C_INT:
          integer = on_off(av[i + 1]);
          i++;
          break;
        case C_MOD:
          mod = on_off(av[i + 1]);
          i++;
          break;


















#ifdef SSHDIST_MATH_ECP
        case C_ECP:
          ecp = on_off(av[i + 1]);
          i++;
          break;
#endif /* SSHDIST_MATH_ECP */















        case C_BITS:
          bits = atoi(av[i + 1]);
          i++;
          break;
        case C_BITS_ADV:
          bits_advance = atoi(av[i + 1]);
          i++;
          break;

        case C_HELP:
          usage();
          break;
        case C_ALL:
          all = 1;
          break;
        case C_TIMING:
          timing = 1;
          break;
        case C_ITR:
          itr = atoi(av[i + 1]);
          i++;
          break;
        case C_NONE:
          printf("error: '%s' not a valid option.\n",
                 av[i]);
          usage();
          break;
        }
    }

  if (fatal_cb)
    {
      printf("Registering a new fatal handler.\n");
      ssh_debug_register_callbacks(my_fatal_cb, NULL_FNPTR, NULL_FNPTR, NULL);
    }

  if (itr <= 0)
    itr = 1;

  if (bits < 10)
    bits = 10;

  for (i = 0; i < itr; i++, bits += bits_advance)
    {
      if (bits < 10)
        bits = 512;

      if (integer)
        {
          test_int_get_and_set(all, bits);
          test_int(all, bits);
          if (timing)
            timing_int(bits);
        }
      if (mod)
        {
          test_mod(all, bits);
          if (timing)
            timing_modular(bits);
        }


























#ifdef SSHDIST_MATH_ECP
      if (ecp)
        {
          test_ecp(all, bits);
          if (timing)
            printf("No timing code for EC(F_p).\n");
        }
#endif /* SSHDIST_MATH_ECP */




















    }

  ssh_math_library_uninitialize();
  ssh_util_uninit();
  return 0;
}
