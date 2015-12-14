/* cs_adapter.h
 * 
 * Configuration Settings for the Verfication Driver Adapter module.
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

// we accept a few settings from the top-level configuration file
#include "cs_driver.h"

#define ADAPTER_DRIVER_NAME "safenet-vdriver-eip93"

// log level for the entire adapter (for now)
// choose from LOG_SEVERITY_INFO, LOG_SEVERITY_WARN, LOG_SEVERITY_CRIT
#ifdef VDRIVER_PERFORMANCE
#define LOG_SEVERITY_MAX LOG_SEVERITY_CRITICAL
#else
#define LOG_SEVERITY_MAX  LOG_SEVERITY_INFO
#endif


// enable only one of the two PE modes
#ifdef VDRIVER_PE_MODE_ARM
#define ADAPTER_EIP93_PE_MODE_ARM
#endif

//#define ADAPTER_REMOVE_BOUNCEBUFFERS

#ifdef VDRIVER_PE_MODE_DHM
#define ADAPTER_EIP93_PE_MODE_DHM
#endif

// maximum number of commands accepted in one call to PEC_Packet_Put
// maximum number of results by one call to PEC_Packet_Get
// Number of Logical descripors in the ring
#define ADAPTER_MAX_EIP93LOGICDESCR     32

// size of the ring(s) in bytes
//#define ADAPTER_EIP93_RINGSIZE_BYTES   /*20 * 10 */ /*32 * 10*/ 32 * 800 /*for integration*/
#define ADAPTER_EIP93_RINGSIZE_BYTES 32 * 128 //trey

#define ADAPTER_EIP93_DESCRIPTORDONECOUNT    0

// This parameter allows configuring the number of descriptors that must
// be completed (minus one) before issuing an interrupt to collect packets 

#define ADAPTER_EIP93_DESCRIPTORPENDINGCOUNT    0

#ifdef VDRIVER_INTERRUPT_COALESC_COUNT
#if VDRIVER_INTERRUPT_COALESC_COUNT > 0
#undef ADAPTER_EIP93_DESCRIPTORPENDINGCOUNT
#define ADAPTER_EIP93_DESCRIPTORPENDINGCOUNT  \
    (VDRIVER_INTERRUPT_COALESC_COUNT-1) 
#endif
#endif



// wanted maximum time a packet is in the result ring: T milliseconds
// calculate configuration value N as follows:
//   N  = T(sec) * f(engine_Hz) / 1024
//   N ~= T(ms)  * f(engine_Hz)          (2,3% error)
// example: f(engine)=100MHz, T=2ms ==> N=2*100M
#define ADAPTER_EIP93_DESCRIPTORDONETIMEOUT  15


#define ADAPTER_EIP93_RINGPOLLDIVISOR 1 

// descriptor spacing in words, allowing cache line alignment
// ring memory start alignment will use same value
#define ADAPTER_SYSTEM_DCACHE_LINE_SIZE_BYTES  32



#define ADAPTER_EIP93_DMATHRESHOLD_INPUT   0x20 //Gives optimal performance 
#define ADAPTER_EIP93_DMATHRESHOLD_OUTPUT  0x20 //Gives optimal performance 


#define ADAPTER_EIP93_DHM_THRESHOLD_INPUT  128
#define ADAPTER_EIP93_DHM_THRESHOLD_OUTPUT 127

// enable debug checks
#ifndef VDRIVER_PERFORMANCE
#define ADAPTER_PEC_DEBUG
#define ADAPTER_PEC_STRICT_ARGS
#endif


// Global options
#define ADAPTER_MAX_DMARESOURCE_HANDLES  256


// filter for printing interrupts
#define ADAPTER_INTERRUPTS_TRACEFILTER (0x0007FFFF - BIT_17 - BIT_13)

#ifdef VDRIVER_INTERRUPTS
#define ADAPTER_EIP93PE_INTERRUPTS_ENABLE
#endif

/* end of file cs_adapter.h */
