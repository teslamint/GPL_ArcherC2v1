/* adapter_interrupts_eip93.h
 *
 * This header file describes the interrupt sources.
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


#ifndef INCLUDE_GUARD_ADAPTER_INTERRUPTS_EIP93_H
#define INCLUDE_GUARD_ADAPTER_INTERRUPTS_EIP93_H

// EIP93 interrupt signals
// assigned values represent interrupt source bit numbers
enum
{
    IRQ_CDR_THRESH_IRQ = 0,
    IRQ_RDR_THRESH_IRQ = 1,
    IRQ_OPERATION_DONE_IRQ = 9,
    IRQ_INBUF_THRESH_IRQ = 10,
    IRQ_OUTBUF_THRESH_IRQ = 11,
    IRQ_PRNG_IRQ=12,
    IQ_PE_ERR_IRQ = 13
};



#endif /* Include Guard */

/* end of file adapter_interrupts_eip93.h */
