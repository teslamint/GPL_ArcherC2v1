/* cs_driver.h
 *
 * Top-level Product Configuration Settings.
 * See also cs_adapter.h
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

#ifndef INCLUDE_GUARD_CS_DRIVER_H
#define INCLUDE_GUARD_CS_DRIVER_H

// Define this when there is no actual device installed
//#define ADAPTER_EIP93_NO_ACTUAL_DEVICE


//Define if building for Simulator
//#define ADAPTER_USER_DOMAIN_BUILD

// enable for big-endian CPU
//#define ADAPTER_EIP93_ARMRING_ENABLE_SWAP


// activates DMA-enabled autonomous ring mode (ARM)
// or CPU-managed direct host mode (DHM)
// ARM can use overlapping command/result rings, or separate
#define VDRIVER_PE_MODE_ARM
//#define VDRIVER_PE_MODE_DHM

// when defined, two memory block of the size ADAPTER_EIP93_RINGSIZE_BYTES will be allocated
// one for commands, the other for results
#define ADAPTER_EIP93_SEPARATE_RINGS


// activates interrupts for EIP,
// when disabled, polling will be used
#define VDRIVER_INTERRUPTS


// if not activated, this will switch on bounce-buffer support for all DMA services
// if activated, then bounce buffers will not be created
//#define ADAPTER_REMOVE_BOUNCEBUFFERS

// when activated, disables all strict-args checking
// and reduces logging to a Critical-only
//#define VDRIVER_PERFORMANCE




#endif /* Include Guard */

/* end of file cs_driver.h */
