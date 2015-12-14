/*
 *
 * Author: Tero Kivinen <kivinen@iki.fi>
 *
*  Copyright:
*          Copyright (c) 2002, 2003 SFNT Finland Oy.
*  Copyright:
*          Copyright (c) 2002, 2003 SFNT Finland Oy.
 */

#include "sshincludes.h"
#include "sshglobals.h"
#include "sshmp-types.h"
#include "sshmp.h"
#include "sshtimemeasure.h"


void speed_test(int bits)
{
  SshMPIntegerStruct a, b, c, g, r, q;
  SshMPIntModStruct am, bm, gm, rm, qm;
  SshMPIntIdealStruct m;
  SshWord ee, gg;

  int i, cnt;
  struct SshTimeMeasureRec tmit = SSH_TIME_MEASURE_INITIALIZER;

  ssh_mprz_init(&a);
  ssh_mprz_init(&b);
  ssh_mprz_init(&c);
  ssh_mprz_init(&g);
  ssh_mprz_init(&r);
  ssh_mprz_init(&q);

  ssh_rand_seed((SshUInt32)ssh_time());
  ee = ssh_rand();
  gg = ssh_rand();

  ssh_mprz_rand(&a, bits);
  ssh_mprz_rand(&b, bits);
  ssh_mprz_set_bit(&b, 0);
  ssh_mprz_rand(&c, bits);
  ssh_mprz_set_bit(&c, 0);
  ssh_mprz_set_ui(&g, 2);

  /* Set the highest bit of all the important values. */
  ssh_mprz_set_bit(&a, bits);
  ssh_mprz_set_bit(&b, bits);
  ssh_mprz_set_bit(&c, bits);
  ssh_mprz_set_bit(&g, bits);

  if (!ssh_mprzm_init_ideal(&m, &c))
    ssh_fatal("Cannot initialize Montgomory ideal");

  ssh_mprzm_init(&am, &m);
  ssh_mprzm_init(&bm, &m);
  ssh_mprzm_init(&gm, &m);
  ssh_mprzm_init(&rm, &m);
  ssh_mprzm_init(&qm, &m);

  ssh_mprzm_set_mprz(&am, &a);
  ssh_mprzm_set_mprz(&bm, &b);
  ssh_mprzm_set_mprz(&gm, &g);

  ssh_mprz_mul(&c, &a, &b);


#define TEST_IT(test_name,label_name,operation,init_count)                   \
  printf("%s test...", (test_name));                                         \
  cnt = init_count;                                                          \
label_name:                                                                  \
  fflush(stdout);                                                            \
  ssh_time_measure_reset(&tmit);                                             \
  ssh_time_measure_start(&tmit);                                             \
  for (i = 0; i < cnt; i++)                                                  \
    {                                                                        \
      operation;                                                             \
    }                                                                        \
  ssh_time_measure_stop(&tmit);                                              \
  if (ssh_time_measure_get(&tmit, SSH_TIME_GRANULARITY_SECOND) < 1.0)        \
    {                                                                        \
      if (ssh_time_measure_get(&tmit, SSH_TIME_GRANULARITY_MILLISECOND) < 10)\
        cnt *= 128;                                                          \
      else                                                                   \
        cnt = (int) (cnt * 1400.0 /                                          \
              ssh_time_measure_get(&tmit, SSH_TIME_GRANULARITY_MILLISECOND));\
      printf("%d...", cnt);                                                  \
      goto label_name;                                                       \
    }                                                                        \
  printf("done, %s speed = %f us\n", (test_name),                            \
         (double) ssh_time_measure_get(&tmit,                                \
                                       SSH_TIME_GRANULARITY_MICROSECOND)     \
         / cnt);

  TEST_IT("Addition", add_label, ssh_mprz_add(&r, &a, &b), 10000);
  TEST_IT("Subraction", sub_label, ssh_mprz_sub(&r, &a, &b), 10000);
  TEST_IT("Multiplication", mul_label, ssh_mprz_mul(&r, &a, &b), 500);
  TEST_IT("Square", sqr_label, ssh_mprz_square(&r, &a), 500);
  TEST_IT("Division", div_label, ssh_mprz_divrem(&q, &r, &c, &a), 500);
  TEST_IT("Division q", div_q_label, ssh_mprz_div(&q, &c, &a), 500);
  TEST_IT("Modulo", mod_label, ssh_mprz_mod(&r, &c, &b), 500);
  TEST_IT("Gcd", gcd_label, ssh_mprz_gcd(&r, &a, &b), 10);

  /* Ensure the modulus in powm computations is large enough. */
  ssh_mprz_add(&b, &g, &q);

  TEST_IT("Powm", powm_label,
          ssh_mprz_powm(&r, &g, &a, &b), 1);
  TEST_IT("Powm gg", powm_gg_label,
          ssh_mprz_powm_gg(&r, &g, &c, &q, &a, &b), 1);
  TEST_IT("Powm ui g", powm_ui_g_label,
          ssh_mprz_powm_ui_g(&r, gg, &a, &b), 1);
  TEST_IT("Powm ui exp", powm_ui_exp,
          ssh_mprz_powm_ui_exp(&r, &g, ee, &b), 1);

  TEST_IT("Mod add", madd_label, ssh_mprzm_add(&rm, &am, &bm), 10000);
  TEST_IT("Mod sub", msub_label, ssh_mprzm_sub(&rm, &am, &bm), 10000);
  TEST_IT("Mod mul", mmul_label, ssh_mprzm_mul(&rm, &am, &bm), 1000);
  TEST_IT("Mod square", msqr_label, ssh_mprzm_square(&rm, &am), 1000);

  ssh_mprzm_clear(&am);
  ssh_mprzm_clear(&bm);
  ssh_mprzm_clear(&gm);
  ssh_mprzm_clear(&rm);
  ssh_mprzm_clear(&qm);

  ssh_mprzm_clear_ideal(&m);
  ssh_mprz_clear(&a);
  ssh_mprz_clear(&b);
  ssh_mprz_clear(&c);
  ssh_mprz_clear(&g);
  ssh_mprz_clear(&r);
  ssh_mprz_clear(&q);
}

void usage(void)
{
  printf("usage: t-mathspeed [bits]\n");
  exit(1);
}

int main(int argc, char **argv)
{
  int bits;

  ssh_global_init();

  if (!ssh_math_library_initialize())
    ssh_fatal("Cannot initialize the math library.");

  if (!ssh_math_library_self_tests())
    ssh_fatal("Math library self tests failed.");

  /* Randomize the random number generator. */
  ssh_rand_seed((SshUInt32) ssh_time());

  bits = 1024;

  if (argc == 2)
    {
      bits = atoi(argv[1]);
    }
  else if (argc != 1)
    usage();
  speed_test(bits);

  ssh_math_library_uninitialize();

  ssh_util_uninit();
  return 0;
}
