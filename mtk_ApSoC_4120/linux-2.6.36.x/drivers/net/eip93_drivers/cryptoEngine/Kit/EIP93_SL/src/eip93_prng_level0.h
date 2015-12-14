/* eip93_prng_level0.h
 *
 * This file contains all the macros and  functions that allow
 * access to the PRNG registers and to build the values
 * read or written to the registers.
 *
 */

/*****************************************************************************
*                                                                            *
*         Copyright (c) 2008-2009 SafeNet Inc. All Rights Reserved.          *
*                                                                            *
* This confidential and proprietary software may be used only as authorized  *
* by a licensing agreement from SafeNet.                                     *
*                                                                            *
* The entire notice above must be reproduced on all authorized copies that   *
* may only be made to the extent permitted by a licensing agreement from     *
* SafeNet.                                                                   *
*                                                                            *
* For more information or support, please go to our online support system at *
* https://oemsupport.safenet-inc.com or e-mail to oemsupport@safenet-inc.com *
*                                                                            *
*****************************************************************************/
#ifndef INCLUDE_GUARD_EIP93_PRNG_LEVEL0_H
#define INCLUDE_GUARD_EIP93_PRNG_LEVEL0_H

#include "basic_defs.h"             // BIT definitions, bool, uint32_t
#include "hw_access.h"              // Read32, Write32, HWPAL_Device_t
#include "hw_access_dma.h"          // Read32, Write32, HWPAL_DMAResource_t
#include "eip93_hw_interface.h"   // the HW interface (register map)



/*-----------------------------------------------------------------------------
 * PRNG register routines
 *
 * These routines write/read register values in PRNG register
 * in HW specific format.
 *
 * Note: if a function argument implies a flag ('f' is a prefix),
 *       then only the values 0 or 1 are allowed for this argument.
 */

static inline void
EIP93_Read32_PRNG_STATUS(
        HWPAL_Device_t Device,
        uint8_t * const fBusy,
        uint8_t * const fResultReady)
{
    uint32_t word = EIP93_Read32(Device, EIP93_REG_PRNG_STAT);
    if(fBusy)
        *fBusy = (word) & 1;
    if(fResultReady)
        *fResultReady = (word >> 1) & 1;
}

/*-----------------------------------------------------------------------------
 * PRNG_CTRL - Read/Write
 */
static inline void
EIP93_Write32_PRNG_CTRL(
        HWPAL_Device_t Device,
        const uint8_t fEnableManual,
        const uint8_t fAuto,
        const uint8_t fResult128)
{
    EIP93_Write32(Device, EIP93_REG_PRNG_CTRL,
            ((fEnableManual & 1) << 0) |
            ((fAuto & 1) << 1) |
            ((fResult128 & 1) << 2));
}


static inline void
EIP93_Read32_PRNG_CTRL(
        HWPAL_Device_t Device,
        uint8_t * const fEnableManual,
        uint8_t * const fAuto,
        uint8_t * const fResult128)
{
    uint32_t word = EIP93_Read32(Device, EIP93_REG_PRNG_CTRL);
    if(fEnableManual)
        *fEnableManual = word & BIT_0;
    if(fAuto)
        *fAuto = (word >> 1) & 1;
    if(fResult128)
        *fResult128 = (word >> 2) & 1;
}


#endif //INCLUDE_GUARD_EIP93_PRNG_LEVEL0_H

/* end of file eip93_prng_level0.h */


