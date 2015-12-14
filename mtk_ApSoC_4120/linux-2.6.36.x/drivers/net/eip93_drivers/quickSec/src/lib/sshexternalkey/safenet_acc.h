/*
  Copyright:
          Copyright (c) 2002-2005 SFNT Finland Oy.
                  All rights reserved.

  File: safenet_acc.h

*/

#ifndef SAFENET_ACC_H
#define SAFENET_ACC_H

#include "genaccprov.h"
#if defined(HAVE_SAFENET) || defined(HAVE_SAFENET_SLAD)
extern struct SshAccDeviceDefRec ssh_acc_dev_safenet_ops;
#endif /* HAVE_SAFENET */
#endif /* not SAFENET_ACC_H */
