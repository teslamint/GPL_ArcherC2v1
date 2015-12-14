/*

  t-montgomery.c

  Copyright:
        Copyright (c) 2004 SFNT Finland Oy.
  	All rights reserved.

  Additional tests for montgomery related routines.

  */

#include "sshincludes.h"
#include "sshglobals.h"
#include "sshmp.h"

#define SSH_DEBUG_MODULE "tMontgomery"

#define TEST_ITERTIONS 20
#define BIT_SIZE 1024

void test_mont_pow_state(void)
{
  SshMPMontPowState state = NULL;
  SshMPMontIntModStruct g, result, expected;
  SshMPMontIntIdealStruct ideal;
  SshMPInteger op, e = NULL, base = NULL;
  SshUInt32 i;

  /* Get an odd BIT_SIZE bit integer */
  op = ssh_mprz_malloc();
  ssh_mprz_rand(op, BIT_SIZE);
  ssh_mprz_set_bit(op, 0);

  /* Init the modular integers */
  if (!ssh_mpmzm_init_ideal(&ideal, op))
    {
      SSH_DEBUG(SSH_D_FAIL, ("Cannot allocate an ideal"));
      goto fail;
    }
  ssh_mpmzm_init(&g, &ideal);
  ssh_mpmzm_init(&result, &ideal);
  ssh_mpmzm_init(&expected, &ideal);

  /* Get a random modular integer 'g' */
  base = ssh_mprz_malloc();
  ssh_mprz_rand(base, BIT_SIZE - 1);

  if (ssh_mprz_cmp(base, op) > 0)
    ssh_mprz_sub(base, base, op);

  ssh_mpmzm_set_mprz(&g, base);

  /* Allocate the state from g */
  state = ssh_mpmzm_pow_state_alloc(&g);
  if (!state)
    goto fail;

  e = ssh_mprz_malloc();

  for (i = 0; i < TEST_ITERTIONS; i++)
    {
      ssh_mprz_rand(e, BIT_SIZE - 1);

      if (ssh_mprz_cmp(e, op) > 0)
	ssh_mprz_sub(e, e, op);

      if (!ssh_mpmzm_pow_state_init(state, e))
	{
	  SSH_DEBUG(SSH_D_FAIL, ("Cannot initialize the pow state"));
	  goto fail;
	}

      /* Perform the pow operation iteratively */
      while (1)
	{
	  if (ssh_mpmzm_pow_state_iterate(state))
	    break;
	}
      ssh_mpmzm_pow_state_set_result(&result, state);

      /* Perform the pow operation in a single pass */
      ssh_mpmzm_pow(&expected, &g, e);

      /* Verify they agree. */
      if (ssh_mpmzm_cmp(&result, &expected))
	{
	  SshMPInteger tmp;
	  char *str;

	  tmp = ssh_mprz_malloc();

	  SSH_DEBUG(SSH_D_FAIL, ("The values do not agree on test %d", i));

	  ssh_mprz_set_mpmzm(tmp, &result);
	  str = ssh_mprz_get_str(tmp, 10);
	  SSH_DEBUG (3, ("The returned integer is %s", str));
	  ssh_free(str);

	  ssh_mprz_set_mpmzm(tmp, &expected);
	  str = ssh_mprz_get_str(tmp, 10);
	  SSH_DEBUG (3, ("The expected integer is %s", str));
	  ssh_free(str);

	  ssh_mprz_free(tmp);
	  goto fail;
	}
    }

  fprintf(stderr, "POW state test succeeded\n");
  ssh_mprz_free(op);
  ssh_mprz_free(e);
  ssh_mprz_free(base);
  ssh_mpmzm_clear(&g);
  ssh_mpmzm_clear(&result);
  ssh_mpmzm_clear(&expected);
  ssh_mpmzm_clear_ideal(&ideal);
  ssh_mpmzm_pow_state_free(state);
  return;

 fail:
  fprintf(stderr, "POW state test failed\n");
  ssh_mprz_free(op);
  ssh_mprz_free(e);
  ssh_mprz_free(base);
  ssh_mpmzm_clear(&g);
  ssh_mpmzm_clear(&result);
  ssh_mpmzm_clear(&expected);
  ssh_mpmzm_clear_ideal(&ideal);
  ssh_mpmzm_pow_state_free(state);
  ssh_math_library_uninitialize();
  ssh_util_uninit();
  exit(1);
}


int main(int ac, char *av[])
{
  ssh_global_init();

  ssh_debug_set_level_string("3");

  if (!ssh_math_library_initialize())
    ssh_fatal("Cannot initialize the math library.");

  test_mont_pow_state();

  ssh_math_library_uninitialize();
  ssh_util_uninit();
  return 0;
}
