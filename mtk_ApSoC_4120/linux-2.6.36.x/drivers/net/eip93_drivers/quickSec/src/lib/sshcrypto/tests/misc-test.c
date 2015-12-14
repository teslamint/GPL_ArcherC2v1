/*

  misc-test.c

  Copyright:
          Copyright (c) 2002, 2003 SFNT Finland Oy.
  All rights reserved.

  Created: Wed Aug  6 10:06:58 2003, santtu@ssh.com

*/

#include "sshincludes.h"
#include "sshcrypt.h"
#include "sshtimemeasure.h"
#include "readfile.h"
#include "sshmp.h"
#include "sshdsprintf.h"
#include "t-gentest.h"

#define SSH_DEBUG_MODULE "GenTestMisc"


static Boolean nonfips_test(char *(*get)(void), Boolean (*check)(const char *))
{
  char *name, *list = (*get)();

  SSH_ASSERT(list);

  for (name = strtok(list, ","); name; name = strtok(NULL, ","))
    {
      if ((*check)(name) != FALSE)
        {
          ssh_free(list);
          return FALSE;
        }
    }

  ssh_free(list);
  return TRUE;
}

Boolean misc_nonfips_tests(void)
{
  return nonfips_test(ssh_hash_get_supported, ssh_hash_is_fips_approved) &&
    nonfips_test(ssh_mac_get_supported, ssh_mac_is_fips_approved) &&
    nonfips_test(ssh_cipher_get_supported, ssh_cipher_is_fips_approved) &&
    nonfips_test(ssh_random_get_supported, ssh_random_is_fips_approved) &&
    nonfips_test(ssh_public_key_get_supported,
                 ssh_public_key_is_fips_approved) &&
    nonfips_test(ssh_public_key_get_supported,
                 ssh_private_key_is_fips_approved);
}


/* This file might be empty, so put something in here to prevent warnings. */
static const int ssh_misc_test_dummy_variable = 0;
