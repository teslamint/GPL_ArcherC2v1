/*
  File: sshutil.c

  Description:
        Utility library unitialization routines

  Copyright:
          Copyright (c) 2002, 2003 SFNT Finland Oy.
        All rights reserved.
*/

#include "sshincludes.h"
#include "sshglobals.h"

void
ssh_util_uninit(void)
{
  ssh_debug_uninit();
  ssh_global_uninit();






}

/* eof */
