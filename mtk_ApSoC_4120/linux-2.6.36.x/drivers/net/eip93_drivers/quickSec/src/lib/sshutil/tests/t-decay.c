/*
 *
 * Author: Tero Kivinen <kivinen@iki.fi>
 *
 *  Copyright:
 *          Copyright (c) 2002, 2003 SFNT Finland Oy.
 *                  All rights reserved.
 */
/*
 *        Program: Sshutil
 *
 *        Creation          : 02:40 Apr 13 2000 kivinen
 *        Last Modification : 04:47 Apr 13 2000 kivinen
 *        Version           : 1.182
 *        
 *
 *        Description       : Decaying counter calculations
 *
 */

#include "sshincludes.h"
#include "sshdecay.h"
#include "ssheloop.h"
#include "sshtimeouts.h"

typedef void (*AddCB)(void *ctx);

#define DECLARE_ADD(n,x) \
void add_##n(void *ctx) \
{ \
  ssh_decay_counter_add(ctx, (x)); \
  ssh_xregister_timeout(1, 0, add_##n, ctx); \
}

DECLARE_ADD(1, 100)
DECLARE_ADD(2, 1000)
DECLARE_ADD(3, 10000)
DECLARE_ADD(4, 100000)
DECLARE_ADD(5, 1234567)

AddCB add[5] = { add_1, add_2, add_3, add_4, add_5 };

char *k_table[5] = { "vfast", "fast", "normal", "slow", "vslow" };
char *j_table[5] = { "100", "1000", "10000", "100000", "1234567" };
char *i_table[6] = { "10 s", "30 s", "60 s", "120 s", "300 s", "600 s" };

void show(void *ctx)
{
  SshDecayCounter *c = ctx;
  int i, j, k;
  static int counter = 0;

  printf("\033[H\033[J");
  for (k = 0; k < 5; k++)
    {
      printf("%s\t", k_table[k]);
      for (j = 0; j < 5; j++)
        {
          printf("%s\t", j_table[j]);
        }
      printf("\n");
      for (i = 0; i < 6; i++)
        {
          printf("%s\t", i_table[i]);
          for (j = 0; j < 5; j++)
            {
              printf("%ld\t", (unsigned long)
                     ssh_decay_counter_get(c[k * 30 + i * 5 + j]));
            }
          printf("\n");
        }
      printf("\n");
    }
  counter++;

  if (counter > 300)
    {
      for (k = 0; k < 5; k++)
        for (i = 0; i < 6; i++)
          for (j = 0; j < 5; j++)
            {
              ssh_decay_counter_delete(c[k * 30 + i * 5 + j]);
              ssh_cancel_timeouts(add[j], c[k * 30 + i * 5 + j]);
            }
      return;
    }
  ssh_xregister_timeout(2, 0, show, ctx);
}

int main(int argc, char **argv)
{
  SshDecayCounter c[6*5*5];
  const char *debug_string = "*=3,Main=6";
  int i, j, k;

  ssh_debug_set_level_string(debug_string);
  ssh_event_loop_initialize();

  for (k = 0; k < 5; k++)
    {
      for (i = 0; i < 6; i++)
        {
          for (j = 0; j < 5; j++)
            {
              c[k * 30 + i * 5 + j] =
                ssh_decay_counter_allocate(k,
                                           (i == 0 ? 10 :
                                            (i == 1 ? 30 :
                                             (i == 2 ? 60 :
                                              (i == 3 ? 120 :
                                               (i == 4 ? 300 : 600))))));

              if (c[k * 30 + i * 5 + j] == NULL)
		ssh_fatal("Cannot allocate decay counter");
	      
              ssh_xregister_timeout(1, 0, add[j], c[k * 30 + i * 5 + j]);
            }
        }
    }

  ssh_xregister_timeout(2, 0, show, c);

  ssh_event_loop_run();

  ssh_event_loop_uninitialize();
  ssh_util_uninit();
  return 0;
}
