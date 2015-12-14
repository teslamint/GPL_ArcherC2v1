/*

strerror.c

Author: Tatu Ylonen <ylo@cs.hut.fi>

  Copyright:
          Copyright (c) 2002, 2003 SFNT Finland Oy.
                   All rights reserved

Created: Wed Mar 22 18:18:21 1995 ylo

Replacement for strerror for systems that don't have it.

*/

#ifndef VXWORKS
#include <stdio.h>
#include <errno.h>

extern int sys_nerr;
extern char *sys_errlist[];

char *strerror(int error_number)
{
  if (error_number >= 0 && error_number < sys_nerr)
    return sys_errlist[error_number];
  else
    return "Bad error code";
}
#endif /* VXWORKS */
