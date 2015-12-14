/* c_adapter.h
 *
 * EIP93-V-Driver Adapter
 * Internal Configuration File
 */

/*****************************************************************************
* Copyright (c) 2008-2010 AuthenTec B.V. All Rights Reserved.
*
* This confidential and proprietary software may be used only as authorized
* by a licensing agreement from AuthenTec.
*
* The entire notice above must be reproduced on all authorized copies that
* may only be made to the extent permitted by a licensing agreement from
* AuthenTec.
*
* For more information or support, please go to our online support system at
* https://oemsupport.authentec.com. In case you do not have an account for
* this system, please send an e-mail to EmbeddedHW-Support@authentec.com.
*****************************************************************************/

#ifndef INCLUDE_GUARD_C_ADAPTER_H
#define INCLUDE_GUARD_C_ADAPTER_H

#include "cs_adapter.h"

#ifndef ADAPTER_MAX_DMARESOURCE_HANDLES
#define ADAPTER_MAX_DMARESOURCE_HANDLES  256
#endif

#ifndef ADAPTER_EIP93_RINGSIZE_BYTES
#define ADAPTER_EIP93_RINGSIZE_BYTES 1024
#endif

#ifndef ADAPTER_PACKETSIDECHANNEL_MAX_RECORDS
#ifdef ADAPTER_EIP93_SEPARATE_RINGS
#define ADAPTER_PACKETSIDECHANNEL_MAX_RECORDS  (2 * \
             (ADAPTER_EIP93_RINGSIZE_BYTES / (8*4)))
#else
#define ADAPTER_PACKETSIDECHANNEL_MAX_RECORDS  (\
                    ADAPTER_EIP93_RINGSIZE_BYTES /(8*4))
#endif
#endif

#ifndef ADAPTER_MAX_EIP93LOGICDESCR
#define ADAPTER_MAX_EIP93LOGICDESCR 32
#endif

#ifndef ADAPTER_EIP93_DESCRIPTORDONETIMEOUT
#define ADAPTER_EIP93_DESCRIPTORDONETIMEOUT  0
#endif



#ifndef ADAPTER_EIP93_DMATHRESHOLD_INPUT
#define ADAPTER_EIP93_DMATHRESHOLD_INPUT  128
#endif

#ifndef ADAPTER_EIP93_DMATHRESHOLD_OUTPUT
#define ADAPTER_EIP93_DMATHRESHOLD_OUTPUT  128
#endif

#ifndef ADAPTER_EIP93_DHM_THRESHOLD_INPUT
#define ADAPTER_EIP93_DHM_THRESHOLD_INPUT  128
#endif

#ifndef ADAPTER_EIP93_DHM_THRESHOLD_OUTPUT
#define ADAPTER_EIP93_DHM_THRESHOLD_OUTPUT 128
#endif

// ensure only one of the packet engine modes is activated
#ifdef ADAPTER_EIP93_PE_MODE_DHM
#ifdef ADAPTER_EIP93_PE_MODE_ARM
#error "Multiple ADAPTER_EIP93_PE_MODE_ defined in cs_adapter.h"
#endif
#endif



#ifndef ADAPTER_DRIVER_NAME
#define ADAPTER_DRIVER_NAME "safenet_eip93_vdriver"
#endif

#ifndef ADAPTER_INTERRUPTS_TRACEFILTER
#define ADAPTER_INTERRUPTS_TRACEFILTER BIT_31
#endif

#ifndef ADAPTER_EIP75_ALARMINTERRUPTTHRESHOLD
#define ADAPTER_EIP75_ALARMINTERRUPTTHRESHOLD 10
#endif


#endif /* Include Guard */

/* end of file c_adapter.h */
