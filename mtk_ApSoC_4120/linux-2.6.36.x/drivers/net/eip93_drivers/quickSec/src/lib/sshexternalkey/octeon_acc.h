/*
  Copyright:
          Copyright (c) 2006 SFNT Finland Oy.
          All rights reserved.

  File: octeon_acc.h

*/

#ifndef OCTEON_ACC_H
#define OCTEON_ACC_H

#include "genaccprov.h"

#ifdef SSHDIST_IPSEC_HWACCEL_OCTEON
#ifdef ENABLE_CAVIUM_OCTEON
extern struct SshAccDeviceDefRec ssh_octeon_dev_ops;
#endif /* ENABLE_CAVIUM_OCTEON */
#endif /* SSHDIST_IPSEC_HWACCEL_OCTEON */

#endif /* ! OCTEON_ACC_H */
