/* adapter_internal.h
 *
 * EIP93-V-Driver Adapter Internal
 * Data types and Interfaces
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

#ifndef INCLUDE_GUARD_ADAPTER_INTERNAL_H
#define INCLUDE_GUARD_ADAPTER_INTERNAL_H

#include "basic_defs.h"
#include "clib.h"
#include "hw_access_dma.h"          // HWPAL_DMAResource_t
#include "api_dmabuf.h"             // DMABuf_Handle_t
#include "eip93.h"                // EIP93_IOArea_t
#include "c_adapter.h"


/*----------------------------------------------------------------------------
 *                           Implementation helper macros
 *----------------------------------------------------------------------------
 */

#define ZEROINIT(_x)  memset(&_x, 0, sizeof(_x))


/*----------------------------------------------------------------------------
 *                           Logging
 *----------------------------------------------------------------------------
 */

#include "log.h"


/*----------------------------------------------------------------------------
 *                           Global
 *----------------------------------------------------------------------------
 */

bool
Adapter_Init(void);

void
Adapter_UnInit(void);

void
Adapter_Report_Build_Params(void);




/*----------------------------------------------------------------------------
 *                           Adapter_EIP93
 *----------------------------------------------------------------------------
 */

extern EIP93_IOArea_t Adapter_EIP93_IOArea;
extern unsigned int Adapter_EIP93_MaxDescriptorsInRing;

bool
Adapter_EIP93_Init(void);

bool
Adapter_EIP93_SetMode_Idle(void);

bool
Adapter_EIP93_SetMode_ARM(
        const bool fEnableDynamicSA);

bool
Adapter_EIP93_SetMode_DHM(void);



void
Adapter_EIP93_UnInit(void);


void
Adapter_GetEIP93PhysAddr(
        DMABuf_Handle_t Handle,
        HWPAL_DMAResource_Handle_t * const DMAHandle_p,
        EIP93_DeviceAddress_t * const EIP93PhysAddr_p);
/*----------------------------------------------------------------------------
 * Adapter_EIP93_InterruptHandler_DescriptorDone
 *
 * This function is invoked when the EIP93 has activated the descriptor done
 * interrupt.
 */
extern void
Adapter_EIP93_InterruptHandler_DescriptorDone(void);

void
Adapter_EIP93_InterruptHandler_DescriptorPut(void) ;


extern void
Adapter_EIP93_BH_Handler_ResultGet(
        unsigned long data);


/*----------------------------------------------------------------------------
 *                           Adapter_Interrupts
 *----------------------------------------------------------------------------
 */

bool
Adapter_Interrupts_Init(
        const int nIRQ);

void
Adapter_Interrupts_UnInit(void);

typedef void (* Adapter_InterruptHandler_t)(void);

// nIRQ is defined in adapter_interrupts_eip93.h
void
Adapter_Interrupt_SetHandler(
        const int nIRQ,
        Adapter_InterruptHandler_t HandlerFunction);

void
Adapter_Interrupt_Enable(
        const int nIRQ);

void
Adapter_Interrupt_ClearAndEnable(
        const int nIRQ);

void
Adapter_Interrupt_Disable(
        const int nIRQ);

void
Adapter_EIP93_BH_Handler_PktPut(unsigned long data) ;
void
Adapter_EIP93_BH_Handler_ResultGet(
        unsigned long data) ;




/*----------------------------------------------------------------------------
 *                           Adapter_DMABuf
 *----------------------------------------------------------------------------
 */

#define ADAPTER_DMABUF_ALLOCATORREF_KMALLOC 'k'   /* kmalloc */

extern const DMABuf_Handle_t Adapter_DMABuf_NullHandle;

bool
Adapter_DMABuf_IsValidHandle(
        DMABuf_Handle_t Handle);

HWPAL_DMAResource_Handle_t
Adapter_DMABuf_Handle2DMAResourceHandle(
        DMABuf_Handle_t Handle);

bool
Adapter_DMABuf_IsForeignAllocated(
        DMABuf_Handle_t Handle);

bool
Adapter_DMABuf_IsSameHandle(
        const DMABuf_Handle_t * const Handle1_p,
        const DMABuf_Handle_t * const Handle2_p);

/*----------------------------------------------------------------------------
 *                           VTBAL Global device
 *----------------------------------------------------------------------------
 */
extern void *  GlobalVTBALDevice ;

#endif /* Include Guard */

/* end of file adapter_internal.h */
