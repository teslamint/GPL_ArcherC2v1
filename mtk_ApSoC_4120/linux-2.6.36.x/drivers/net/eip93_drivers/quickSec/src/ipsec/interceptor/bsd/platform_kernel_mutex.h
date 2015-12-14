/*

  platform_kernel_mutex.h

  Author: Lauri Tarkkala <ltarkkal@ssh.com>

  Copyright:
          Copyright (c) 2002, 2003 SFNT Finland Oy.
  All rights reserved

  Additional platform-dependent thinngs. This file is included from
  engine-interface/kernel_mutex.h

*/

#ifndef PLATFORM_KERNEL_MUTEX_H
#define PLATFORM_KERNEL_MUTEX_H

#ifndef VXWORKS

typedef struct SshKernelMutexRec
{
  int taken;
} SshKernelMutexStruct;

typedef struct SshKernelRWMutexRec
{
  int taken;
} SshKernelRWMutexStruct;

typedef struct SshKernelCriticalSectionRec
{
  int taken;
} SshKernelCriticalSectionStruct;

#else /* VXWORKS */

#include "icept_mutex_vxworks.h"

#endif /* VXWORKS */

#endif /* PLATFORM_KERNEL_MUTEX_H */
