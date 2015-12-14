/*

  Copyright:
          Copyright (c) 2002-2005 SFNT Finland Oy.
    All rights reserved.
*/


#include "sshincludes.h"
#include "sshglobals.h"
#include "sshmp.h"

#define SSH_DEBUG_MODULE "SshMPInit"

#ifdef SSHDIST_MATH
Boolean ssh_math_library_initialize(void)
{
  return TRUE;
}

void ssh_math_library_uninitialize(void)
{
  return;
}

Boolean ssh_math_library_is_initialized(void)
{
  return TRUE;
}
#endif /* SSHDIST_MATH */
