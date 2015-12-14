/*

  t-xuint.h

  Copyright:
          Copyright (c) 2007 SFNT Finland Oy.
  All rights reserved.

  Created: Mon Feb  5 13:23:18 EET 2007 [mnippula]

  Testing implementation of 128/64-bit extended integer type.
  Same as t-xuint2, but on every 32bit platform this tests
  32+32bit implementation of 64bit mathematics instead of using
  compiler generated real 64bit mathematics. This is useful to
  ensure code written for smallest no-64bit instructions available
  machines works on all platforms correctly.
  */

#include "sshincludes.h"
#include "sshmp-kernel.h"

#if SIZEOF_LONG == 4
#define SSH_XUINT64_FORCE_32BIT_OPERATIONS
#include "sshmp-xuint.h"
/* Implement helper functions applicable for 2x32 bit implementation. */
#include "../sshmp-xuint.c"
/* Do tests, the same ones as usual. */
#include "t-xuint.c"
#else
/* Always succeed on 64bit platforms */
int main(void) { return 0; }
#endif
