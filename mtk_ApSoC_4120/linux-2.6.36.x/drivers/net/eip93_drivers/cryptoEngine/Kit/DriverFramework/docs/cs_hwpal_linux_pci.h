/* cs_hwpal_linux_pci.h
 *
 * Configuration file for HWPAL implementation for PCI devices under Linux.
 */

/*****************************************************************************
*                                                                            *
*         Copyright (c) 2007-2009 SafeNet Inc. All Rights Reserved.          *
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

// Define this to appropriate device ID
#define HWPAL_PCI_DEVICE_ID 0x1742

// Name string for the driver, used while loading the module
#define HWPAL_PCI_DRIVER_NAME "SafeXcel_1742"

// Set the correct address space size of the PCI device
#define HWPAL_PCI_DEVICE_ADDRESS_SPACE_SIZE 0x7ffff

// definition of static resources inside the PCI device
// Refer to the data sheet of device for the correct values
//                   Name        Start     Last     Flags (see below)
#define HWPAL_DEVICES \
    HWPAL_DEVICE_ADD("EIP94v2",  0x00000,  0x70FFF, 0), \
    HWPAL_DEVICE_ADD("EIP75",    0x71000,  0x713FF, 0), \
    HWPAL_DEVICE_ADD("EIP201",   0x71400,  0x71414, 0), \
    HWPAL_DEVICE_ADD("CLK",      0x71800,  0x7180F, 0), \
    HWPAL_DEVICE_ADD("RESET",    0x71C00,  0x71C0F, 0), \
    HWPAL_DEVICE_ADD("EIP28",    0x72000,  0x7FFFF, 0)
// Flags:
//   bit0 = Trace reads  (requires HWPAL_TRACE_DEVICE_READ)
//   bit1 = Trace writes (requires HWPAL_TRACE_DEVICE_WRITE)
//   bit2 = Swap word endianess (requires HWPAL_DEVICE_ENABLE_SWAP)

#define HWPAL_DEVICE_MAGIC   54333

#define HWPAL_REMAP_ADDRESSES \
    HWPAL_REMAP_ONE(0x71004, 0x71200);

// logging / tracing control
#define HWPAL_STRICT_ARGS_CHECK
//#define HWPAL_TRACE_DEVICE_FIND
//#define HWPAL_TRACE_DEVICE_READ
//#define HWPAL_TRACE_DEVICE_WRITE
#define HWPAL_TRACE_DMARESOURCE_LEAKS
//#define HWPAL_TRACE_DMARESOURCE_READ
//#define HWPAL_TRACE_DMARESOURCE_WRITE
//#define HWPAL_TRACE_DMARESOURCE_PREPOSTDMA

// enable code that looks at flag bit2 and performs actual endianess swap
//#define HWPAL_DEVICE_ENABLE_SWAP

// define the logging level
// choose from LOG_SEVERITY_INFO, LOG_SEVERITY_WARN, LOG_SEVERITY_CRIT
#define LOG_SEVERITY_MAX  LOG_SEVERITY_INFO

// Use sleepable or non-sleepable lock ?
//#define HWPAL_LOCK_SLEEPABLE

/* end of file cs_hwpal_linux_pci.h */
