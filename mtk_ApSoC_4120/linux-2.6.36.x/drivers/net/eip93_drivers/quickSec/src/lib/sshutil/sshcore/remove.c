/*
  remove.c

  Author: Antti Huima <huima@ssh.fi>

  Copyright:
          Copyright (c) 2002, 2003 SFNT Finland Oy.
  All rights reserved

  date: 1999/10/20 17:29:57;  author: huima;  state: Exp;
        Util library split part I: moved files to their directories.
        Created also misc/ to contain files that should disappear with
        all due haste.
*/

#ifndef VXWORKS
#include <stdio.h>

int remove(const char *filename)
{
  return unlink(filename);
}
#endif /* VXWORKS */
