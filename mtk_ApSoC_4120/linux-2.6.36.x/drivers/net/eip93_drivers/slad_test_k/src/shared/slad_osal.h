/*h*
* File:        slad_osal.h
*
* Security Look-aside Driver Module for SafeNet crypto hardware.
* Target-dependent functions and definitions for osal.
*
*

     Copyright 2007-2008 SafeNet Inc


*
*
* Edit History:
*
*Initial revision
*    Created.
*/

#ifndef  SLAD_OSAL_H
#define  SLAD_OSAL_H




// Define below to configure OSAL to not alloc bounce buffers when
// you are sure that buffers provided are already DMA-SAFE.

        // #define SLAD_OSAL_DO_NOT_ALLOC_BOUNCE_BUFFERS_FOR_KERNEL_MODE_BUFFERS


#include "osal_common_defs.h"
#include "linux/target_linux.h"

#ifdef MODULE
#include "slad_osal_kernel.h"
#else
#include "slad_osal_usr.h"
#endif

#endif
