/*

  t-inet_ntoa.c

  Author: Sami Lehtinen <sjl@ssh.fi>


  Copyright:
          Copyright (c) 2002, 2003 SFNT Finland Oy.
  All rights reserved.

 */

#include "sshincludes.h"

#ifdef HAVE_INET_ATON

struct in_addr {
  unsigned long s_addr;
};

char *inet_ntoa(struct in_addr in);
int inet_aton(const char *cp, struct in_addr *addr);

int main(int ac, char **av)
{
   char *addr;
   struct in_addr in;

#ifdef sun
   in.s_addr = inet_addr("127.0.0.1");
#else
   inet_aton("127.0.0.1", &in);
#endif
   addr = inet_ntoa(in);

   if (strcmp(addr, "127.0.0.1"))
      return 1;

   return 0;
}

#else /* HAVE_INET_ATON */

int main(int ac, char **av)
{
  ssh_warning("t-inet_ntoa: Test is defunct, because "
              "of missing inet_aton(3).");
  ssh_util_uninit();
  return 0;
}

#endif /* HAVE_INET_ATON */
