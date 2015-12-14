/** 

Shared definitions between the QuickSec Engine and Policy Manager.
(This header file consists of include directives.)

File: quicksec_pm_shared.h

@copyright
Copyright (c) 2002 - 2006 SFNT Finland Oy, all rights reserved. 

*/

#ifndef VPN_PM_SHARED_H
#define VPN_PM_SHARED_H


/* Shared core functionality between QuickSec engine and policy manager. */
#include "core_pm_shared.h"

/* Shared IPSec definitions between QuickSec engine and policy manager. */
#ifdef SSHDIST_IPSEC_TRANSFORM
#include "ipsec_pm_shared.h"
#endif /* SSHDIST_IPSEC_TRANSFORM */




#endif /* VPN_PM_SHARED_H */
