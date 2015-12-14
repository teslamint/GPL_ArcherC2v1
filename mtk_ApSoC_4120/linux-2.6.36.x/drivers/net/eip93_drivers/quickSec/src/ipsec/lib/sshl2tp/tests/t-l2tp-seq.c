/*
 *
 * t-l2tp-seq.c
 *
 * Author: Markku Rossi <mtr@ssh.fi>
 *
*  Copyright:
*          Copyright (c) 2002, 2003 SFNT Finland Oy.
*  Copyright:
*          Copyright (c) 2002, 2003 SFNT Finland Oy.
 *               All rights reserved.
 *
 * Test program for L2TP's control channel sequence numbers.
 *
 */

#include "sshincludes.h"
#include "sshl2tp_internal.h"

int
main(int argc, char *argv[])
{
  SshUInt16 current = 0, seq;
  Boolean first = TRUE;

  while (1)
    {
      if (current == 0)
        {
          if (first)
            first = 0;
          else
            break;
        }

      seq = (SshUInt16) (current - 32767);
      if (!SSH_L2TP_SEQ_LT(seq, current))
        {
        fail:
          fprintf(stderr, "%d is not less than %d\n",
                  (int) seq, (int) current);
          exit(1);
        }
      if (SSH_L2TP_SEQ_LT(seq - 1, current))
        {
        fail_gt:
          fprintf(stderr, "%d is not greater than %d\n",
                  (int) seq, (int) current);
          exit(1);
        }
      if (seq > current)
        {
          seq = 0xffff;
          if (!SSH_L2TP_SEQ_LT(seq, current))
            goto fail;
        }
      if (seq > current && current > 0)
        {
          seq = 0;
          if (!SSH_L2TP_SEQ_LT(seq, current))
            goto fail;
        }

      seq = (SshUInt16) (current + 32768);
      if (SSH_L2TP_SEQ_LT(seq, current))
        goto fail_gt;

      current++;
    }

  return 0;
}
