/*

  pollard.c

  Author: Mika Kojo <mkojo@ssh.fi>

  Copyright:
          Copyright (c) 2002, 2003 SFNT Finland Oy.
  All rights reserved.

  Created Fri Jan 14 21:11:09 2000.

  */

/* Some simple factorization methods due to Pollard. */


#include "sshincludes.h"
#include "sshmp.h"
#include "pollard.h"

/* This Pollard rho implementation is written to follow the description given
   by Cohen in CCANT. */
Boolean ssh_pollard_rho(SshMPInteger factor, SshMPIntegerConst composite,
                        SshWord steps, SshWord coefficient)
{
  SshMPIntegerStruct x, x1, y, p, c, g;
  SshMPIntModStruct xp, x1p, yp, cp, pp, tp;
  SshMPIntIdealStruct m;
  Boolean rv = FALSE;
  SshWord counter, accumulate, k, l;

  /* Initialize the needed variables. */
  ssh_mprz_init(&x);
  ssh_mprz_init(&x1);
  ssh_mprz_init(&y);
  ssh_mprz_init(&p);
  ssh_mprz_init(&c);
  ssh_mprz_init(&g);

  /* Define the Montgomery representation stuff. */
  if (!ssh_mprzm_init_ideal(&m, composite))
    ssh_fatal("Cannot initialize Montgomory ideal");

  ssh_mprzm_init(&xp, &m);
  ssh_mprzm_init(&x1p, &m);
  ssh_mprzm_init(&yp, &m);
  ssh_mprzm_init(&cp, &m);
  ssh_mprzm_init(&pp, &m);
  ssh_mprzm_init(&tp, &m);

  /* Setup the values. */
  accumulate = 0;
  ssh_mprz_set_ui(&y,  2);
  ssh_mprz_set_ui(&x,  2);
  ssh_mprz_set_ui(&x1, 2);
  ssh_mprz_set_ui(&p,  1);
  ssh_mprz_set_ui(&c,  coefficient);
  k = 1;
  l = 1;
  
  /* Set the Monty. */
  ssh_mprzm_set_mprz(&yp,  &y);
  ssh_mprzm_set_mprz(&xp,  &x);
  ssh_mprzm_set_mprz(&x1p, &x1);
  ssh_mprzm_set_mprz(&cp,  &c);
  ssh_mprzm_set_mprz(&pp,  &p);
  ssh_mprzm_set_mprz(&tp,  &x);
  
  for (counter = 0; counter < steps; counter++)
    {
      /* Compute: x = x^2 + c (mod n) */
      ssh_mprzm_square(&xp, &xp);
      ssh_mprzm_add(&xp, &xp, &cp);

      /* Now accumulate. */
      ssh_mprzm_sub(&tp, &x1p, &xp);
      ssh_mprzm_mul(&pp, &pp, &tp);

      accumulate++;
      /* Accumulate until suitable bound has been reached. */
      if (accumulate > 200)
        {
          /* Now check the GCD. */
          ssh_mprz_set_mprzm(&p, &pp);
          ssh_mprz_gcd(&g, &p, composite);
          if (ssh_mprz_cmp_ui(&g, 1) > 0)
            {
            backtrack:
              if (ssh_mprz_cmp(&g, composite) == 0)
                goto finished;
              
              /* Backtrack. */
              ssh_mprz_set_mprzm(&y, &yp);
              ssh_mprz_set_mprzm(&x1, &x1p);
              ssh_mprz_set_mprzm(&c, &cp);
              
              while (1)
                {
                  /* Compute y = y^2 + c (mod n) */
                  ssh_mprz_square(&y, &y);
                  ssh_mprz_add(&y, &y, &c);
                  ssh_mprz_mod(&y, &y, composite);

                  /* Compute gcd(x1 - y, n) */
                  ssh_mprz_sub(&p, &x1, &y);
                  ssh_mprz_gcd(&g, &p, composite);

                  /* Check the gcd, this must happen. */
                  if (ssh_mprz_cmp_ui(&g, 1) > 0)
                    {
                      if (ssh_mprz_cmp(&g, composite) == 0)
                        goto finished;

                      ssh_mprz_set(factor, &g);
                      rv = TRUE;
                      goto finished;
                    }
                }
            }
          ssh_mprzm_set(&yp, &xp);
          accumulate = 0;
        }

      k--;
      if (k == 0)
        {
          SshWord i;
          
          ssh_mprz_set_mprzm(&p, &pp);
          ssh_mprz_gcd(&g, &p, composite);
          if (ssh_mprz_cmp_ui(&g, 1) > 0)
            goto backtrack;

          ssh_mprzm_set(&x1p, &xp);

          k  = l;
          l *= 2;
          
          for (i = 0; i < k; i++)
            {
              ssh_mprzm_square(&xp, &xp);
              ssh_mprzm_add(&xp, &xp, &cp);
            }
          ssh_mprzm_set(&yp, &xp);
          accumulate = 0;
        }
    }
finished:
  
  /* Clear the variables. */
  ssh_mprz_clear(&x);
  ssh_mprz_clear(&x1);
  ssh_mprz_clear(&y);
  ssh_mprz_clear(&p);
  ssh_mprz_clear(&c);
  ssh_mprz_clear(&g);

  /* Clear the Montgomery stuff. */
  ssh_mprzm_clear_ideal(&m);
  ssh_mprzm_clear(&xp);
  ssh_mprzm_clear(&x1p);
  ssh_mprzm_clear(&yp);
  ssh_mprzm_clear(&cp);
  ssh_mprzm_clear(&pp);
  ssh_mprzm_clear(&tp);
  
  return rv;
}


/* pollard.c */
