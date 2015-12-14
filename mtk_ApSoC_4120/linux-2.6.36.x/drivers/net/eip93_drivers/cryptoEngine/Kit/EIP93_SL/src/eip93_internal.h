/* eip93_internal.h
 *
 * EIP93 Driver Library internal interfaces
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

#ifndef INCLUDE_GUARD_EIP93_INTERNAL_H
#define INCLUDE_GUARD_EIP93_INTERNAL_H

#include "hw_access.h"
#include "hw_access_dma.h"
#include "eip93.h"
#include "eip93_arm.h"
#include "ringhelper.h"
#include "cs_eip93.h"

#define VALID_INTERRUPT_MASK (  \
                      (EIP93_INT_PE_CDRTHRESH_REQ ) | \
                          (EIP93_INT_PE_RDRTHRESH_REQ ) | \
                          (EIP93_INT_PE_OPERATION_DONE) | \
                              (EIP93_INT_PE_INBUFTHRESH_REQ)| \
                              (EIP93_INT_PE_OUTBURTHRSH_REQ)| \
                              (EIP93_INT_PE_ERR_REG) \
                     )

typedef enum
{
    EIP93_MODE_RESET = 0,
    EIP93_MODE_INITIALIZED,
    EIP93_MODE_ARM,
    EIP93_MODE_DHM
} EIP93_Mode_t;



// ARM fields
typedef struct
{
    HWPAL_DMAResource_Handle_t CommandRingHandle;
    HWPAL_DMAResource_Handle_t ResultRingHandle;
    RingHelper_t RingHelper;
    RingHelper_CallbackInterface_t RingHelperCallbacks;
    EIP93_ARM_Settings_t Settings;
} EIP93_ARM_Mode_t;

// DHM fields
typedef struct
{
    unsigned int OutBufferCyclicCounter;
    unsigned int InBufferCyclicCounter;
} EIP93_DHM_Mode_t;



typedef struct
{
    // common fields:

    HWPAL_Device_t Device;
    EIP93_Mode_t CurrentMode;
    // etc

    union
    {
        // ARM fields
        EIP93_ARM_Mode_t ARM_mode;

        // DHM fields
        EIP93_DHM_Mode_t DHM_mode;

    } extras;

} EIP93_Device_t;


#ifdef EIP93_STRICT_ARGS

#define EIP93_CHECK_DEVICE_IS_READY \
    EIP93_CHECK_POINTER(Device_p); \
    if (Device_p->CurrentMode != EIP93_MODE_INITIALIZED) \
    { \
        res = EIP93_ERROR_UNSUPPORTED_IN_THIS_STATE; \
        goto FUNC_RETURN; \
    }

#define EIP93_CHECK_DEVICE_IS_RESET \
    EIP93_CHECK_POINTER(Device_p); \
    if (Device_p->CurrentMode != EIP93_MODE_RESET) \
    { \
        res = EIP93_ERROR_UNSUPPORTED_IN_THIS_STATE; \
        goto FUNC_RETURN; \
    }

#define EIP93_CHECK_DEVICE_IS_NOT_RESET \
    EIP93_CHECK_POINTER(Device_p); \
    if (Device_p->CurrentMode == EIP93_MODE_RESET) \
    { \
        res = EIP93_ERROR_UNSUPPORTED_IN_THIS_STATE; \
        goto FUNC_RETURN; \
    }

#define EIP93_CHECK_POINTER(_p) \
    if (NULL == (_p)) \
    { \
        res = EIP93_ERROR_BAD_ARGUMENT; \
        goto FUNC_RETURN; \
    }

#define EIP93_CHECK_HANDLE(_p) \
    if (!HWPAL_DMAResource_IsValidHandle(_p)) \
    { \
        res = EIP93_ERROR_BAD_ARGUMENT; \
        goto FUNC_RETURN; \
    }
#define EIP93_CHECK_INT_ATLEAST(_i,_min) \
    if ((_i) < (_min)) \
    { \
        res =  EIP93_ERROR_BAD_ARGUMENT; \
        goto FUNC_RETURN; \
    }
#define EIP93_CHECK_INT_INRANGE(_i, _min, _max) \
    if ((_i) < (_min) || (_i) > (_max)) \
        return EIP93_ERROR_BAD_ARGUMENT;
#define EIP93_CHECK_VALID_INTERRUPT(_i) \
    if ((_i) & (~VALID_INTERRUPT_MASK))  \
        return EIP93_ERROR_BAD_ARGUMENT;


#else

#define EIP93_CHECK_ARM_IS_READY
#define EIP93_CHECK_DEVICE_IS_READY
#define EIP93_CHECK_DEVICE_IS_RESET
#define EIP93_CHECK_DEVICE_IS_NOT_RESET
#define EIP93_CHECK_POINTER(_p)                  IDENTIFIER_NOT_USED(_p)
#define EIP93_CHECK_HANDLE(_p)                   IDENTIFIER_NOT_USED(_p)
#define EIP93_CHECK_INT_ATLEAST(_i,_min)         IDENTIFIER_NOT_USED(_i)
#define EIP93_CHECK_INT_INRANGE(_i, _min, _max)  IDENTIFIER_NOT_USED(_i)
#define EIP93_CHECK_VALID_INTERRUPT(_i)          IDENTIFIER_NOT_USED(_i)

#endif


#define EIP93_INSERTCODE_FUNCTION_EXIT_CODE \
    goto FUNC_RETURN; \
    FUNC_RETURN: \
        return res;


/*-----------------------------------------------------------------------------
 * PRNG Internal Required Defines
 */
#define EIP93_PRNG_MANUAL_OFF   0
#define EIP93_PRNG_MANUAL_ON    1

#define EIP93_PRNG_AUTO_ON      1

#define EIP93_PRNG_RESULT64     0


#endif /* INCLUDE_GUARD_EIP93_INTERNAL_H */

/* end of file eip93_internal.h */


