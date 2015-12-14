/* cs_hwpal_linux_pci_amcc.h
 *
 * Config file for HWPAL implementation for Linux to use PCI devices.
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


//use rt_dump_register(0xfff) to dump all registers
//use rt_dump_register(register_offset) to dump a specific register
#define RT_DUMP_REGISTER


// Define this to appropriate device ID
#define HWPAL_PCI_DEVICE_ID 0x93

// Name string for the driver, used while loading the module
#define HWPAL_PCI_DRIVER_NAME "SafeXcel_EIP_93"

// Set the correct address space size of the PCI device
#define HWPAL_PCI_DEVICE_ADDRESS_SPACE_SIZE 0x7ffff

// definition of static resources inside the PCI device
// Refer to the data sheet of device for the correct values
//                   Name        Start     Last     Flags (see below)
#define HWPAL_DEVICES \
    HWPAL_DEVICE_ADD("eip93",  0x00000,  0xFFC, 3)
  
// Flags:
//   bit0 = Trace reads  (requires HWPAL_TRACE_DEVICE_READ)
//   bit1 = Trace writes (requires HWPAL_TRACE_DEVICE_WRITE)
//   bit2 = Swap word endianess (requires HWPAL_DEVICE_ENABLE_SWAP)

#ifndef VDRIVER_PERFORMANCE
#define HWPAL_DEVICE_MAGIC   54333
#endif

#define HWPAL_REMAP_ADDRESSES \
    HWPAL_REMAP_ONE(0x71004, 0x71204);

// logging / tracing control
#ifndef VDRIVER_PERFORMANCE
//#define HWPAL_TRACE_DEVICE_FIND
//#define HWPAL_TRACE_DEVICE_READ
//#define HWPAL_TRACE_DEVICE_WRITE
#define HWPAL_TRACE_DMARESOURCE_LEAKS
//#define HWPAL_TRACE_DMARESOURCE_READ
//#define HWPAL_TRACE_DMARESOURCE_WRITE
//#define HWPAL_TRACE_DMARESOURCE_PREPOSTDMA
#endif

// enable code that looks at flag bit2 and performs actual endianess swap
//#define HWPAL_DEVICE_ENABLE_SWAP

// define the logging level
// choose from LOG_SEVERITY_INFO, LOG_SEVERITY_WARN, LOG_SEVERITY_CRIT
#ifdef VDRIVER_PERFORMANCE
#define LOG_SEVERITY_MAX  LOG_SEVERITY_CRIT
#else
#define LOG_SEVERITY_MAX  LOG_SEVERITY_INFO
#endif

/*Define this for verbose output of log information*/
#define HWPAL_ENABLE_INFO_LOGS

// Use sleepable or non-sleepable lock ?
//#define HWPAL_LOCK_SLEEPABLE

/* end of file cs_hwpal_linux_pci_amcc.h */
