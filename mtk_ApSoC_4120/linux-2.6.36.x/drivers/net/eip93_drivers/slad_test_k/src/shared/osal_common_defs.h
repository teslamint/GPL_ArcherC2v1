/****************************************************************


     Copyright 2007-2008 SafeNet Inc


*
* Edit History:
*
*Initial revision
* Created.
**************************************************************/

#ifndef SLAD_OSAL_COMMON_DEFS_H

#define  SLAD_OSAL_COMMON_DEFS_H
#include "std.h"

typedef struct
{
  UINT32 process_id;
  UINT32 signal_number;
  void (*callback) (int);
}
OSAL_NOTIFY;

#define SLAD_ALLOCATE_BUFFER_NOCACHE     1

#define SLAD_CACHE_COHERENT                SLAD_ALLOCATE_BUFFER_NOCACHE
#define SLAD_NON_CACHE_COHERENT         !SLAD_CACHE_COHERENT

#endif
