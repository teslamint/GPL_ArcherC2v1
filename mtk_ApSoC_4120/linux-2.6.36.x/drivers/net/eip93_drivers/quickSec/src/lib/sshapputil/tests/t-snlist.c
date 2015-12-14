/*

  t-snlist.c
  
  Author: Sami Lehtinen <sjl@ssh.com>

  Copyright:
          Copyright (c) 2002, 2003 SFNT Finland Oy.
  All rights reserved
  
*/

#include "sshincludes.h"
#include "sshsnlist.h"

#if 0
#define TA(type,src,expect)                                             \
  buf = ssh_snlist_intersection_##type(src);                            \
  if (strcmp(buf, expect) != 0)                                         \
    ssh_fatal("%.100s '%.100s' yields '%.100s', expected '%.100s'",     \
          #type, src, buf, expect);                                     \
  ssh_xfree(buf);
#endif

int main(int ac, char **av)
{



  return 0;
}
