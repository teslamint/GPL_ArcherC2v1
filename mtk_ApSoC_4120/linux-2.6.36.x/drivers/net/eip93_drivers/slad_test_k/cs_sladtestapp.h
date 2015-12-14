/* cs_sladtestapp.h
 *
 * Product Configuration Settings for the SLAD Test Application
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


#ifndef CS_SLAD_TEST_APP_EIP93_H
#define CS_SLAD_TEST_APP_EIP93_H

//#define RT_DUMP_REGISTER

#include "cs_sladtestapp_eip93_systemtestconfig.h"
//Set for EIP93 - Build
#define SLAD_TEST_EIP93_BUILD

// Set this flag to build the test application for Simulator
//#define SLAD_TEST_BUILD_FOR_VDRIVER_VSIM

#define SLAD_TEST_BUILD_FOR_PE
#define USE_NEW_API


//C1
#ifdef SLAD_TEST_EIP93_SYSTEMTEST_CONFIGURATION_C1
#define USE_POLLING

// Set this flag to enable the use of log warnings
#define SLAD_TEST_APP_ENABLE_INFO_LOGS


// Set this flag to build the test application for RNG
//#define SLAD_TEST_BUILD_FOR_RNG
#define SLAD_TEST_DEFS_ONLY_FROM_SLAD_API_INTERFACE_FOLDER

// Configure the busywait sleepcount
#define TEST_DELAY_TIMER 1000

// Configure busywait loopcount
#define TEST_BUSYWAIT_COUNT 1000

//set this flag to test interrupt coalescing
#ifndef USE_POLLING
//#define TEST_INTERRUPT_COALESCING
#endif 

#ifdef TEST_INTERRUPT_COALESCING
#define INTERRUPT_COALESCING_COUNT 4
#endif

// set this flag to support bounce buffer for PE
//#define TEST_BOUNCEBUFFERS

// Set this flag to support bounce buffers for PE in usermode
#ifdef TEST_BOUNCEBUFFERS
#define TEST_BOUNCEBUFFERS_USER_MODE
#endif

#define MAX_HANDLES 5

#endif // SLAD_TEST_EIP93_SYSTEMTEST_CONFIGURATION_C1

//C2
#ifdef SLAD_TEST_EIP93_SYSTEMTEST_CONFIGURATION_C2
//#define USE_POLLING

// Set this flag to enable the use of log warnings
#define SLAD_TEST_APP_ENABLE_INFO_LOGS


// Set this flag to build the test application for RNG
//#define SLAD_TEST_BUILD_FOR_RNG
#define SLAD_TEST_DEFS_ONLY_FROM_SLAD_API_INTERFACE_FOLDER

// Configure the busywait sleepcount
#define TEST_DELAY_TIMER 1000

// Configure busywait loopcount
#define TEST_BUSYWAIT_COUNT 1000

//set this flag to test interrupt coalescing
#ifndef USE_POLLING
//#define TEST_INTERRUPT_COALESCING
#endif 

#ifdef TEST_INTERRUPT_COALESCING
#define INTERRUPT_COALESCING_COUNT 4
#endif

// set this flag to support bounce buffer for PE
//#define TEST_BOUNCEBUFFERS

// Set this flag to support bounce buffers for PE in usermode
#ifdef TEST_BOUNCEBUFFERS
#define TEST_BOUNCEBUFFERS_USER_MODE
#endif

#define MAX_HANDLES 5

#endif // SLAD_TEST_EIP93_SYSTEMTEST_CONFIGURATION_C2

// C3
#ifdef SLAD_TEST_EIP93_SYSTEMTEST_CONFIGURATION_C3
#define USE_POLLING

// Set this flag to enable the use of log warnings
#define SLAD_TEST_APP_ENABLE_INFO_LOGS


// Set this flag to build the test application for RNG
//#define SLAD_TEST_BUILD_FOR_RNG
#define SLAD_TEST_DEFS_ONLY_FROM_SLAD_API_INTERFACE_FOLDER

// Configure the busywait sleepcount
#define TEST_DELAY_TIMER 1000

// Configure busywait loopcount
#define TEST_BUSYWAIT_COUNT 1000

//set this flag to test interrupt coalescing
#ifndef USE_POLLING
//#define TEST_INTERRUPT_COALESCING
#endif 

#ifdef TEST_INTERRUPT_COALESCING
#define INTERRUPT_COALESCING_COUNT 4
#endif

// set this flag to support bounce buffer for PE
//#define TEST_BOUNCEBUFFERS

// Set this flag to support bounce buffers for PE in usermode
#ifdef TEST_BOUNCEBUFFERS
#define TEST_BOUNCEBUFFERS_USER_MODE
#endif

#define MAX_HANDLES 5
#endif // SLAD_TEST_EIP93_SYSTEMTEST_CONFIGURATION_C3

/// C4

#ifdef SLAD_TEST_EIP93_SYSTEMTEST_CONFIGURATION_C4

#define USE_POLLING

// Set this flag to enable the use of log warnings
#define SLAD_TEST_APP_ENABLE_INFO_LOGS


// Set this flag to build the test application for RNG
//#define SLAD_TEST_BUILD_FOR_RNG
#define SLAD_TEST_DEFS_ONLY_FROM_SLAD_API_INTERFACE_FOLDER

// Configure the busywait sleepcount
#define TEST_DELAY_TIMER 1000

// Configure busywait loopcount
#define TEST_BUSYWAIT_COUNT 1000

//set this flag to test interrupt coalescing
#ifndef USE_POLLING
//#define TEST_INTERRUPT_COALESCING
#endif 

#ifdef TEST_INTERRUPT_COALESCING
#define INTERRUPT_COALESCING_COUNT 4
#endif

// set this flag to support bounce buffer for PE
#define TEST_BOUNCEBUFFERS

// Set this flag to support bounce buffers for PE in usermode 
#ifdef TEST_BOUNCEBUFFERS
#define TEST_BOUNCEBUFFERS_USER_MODE
#endif

#define MAX_HANDLES 5

#endif // SLAD_TEST_EIP93_SYSTEMTEST_CONFIGURATION_C4

/// C5

#ifdef SLAD_TEST_EIP93_SYSTEMTEST_CONFIGURATION_C5
//#define USE_POLLING

// Set this flag to enable the use of log warnings
#define SLAD_TEST_APP_ENABLE_INFO_LOGS


// Set this flag to build the test application for RNG
//#define SLAD_TEST_BUILD_FOR_RNG
#define SLAD_TEST_DEFS_ONLY_FROM_SLAD_API_INTERFACE_FOLDER

// Configure the busywait sleepcount
#define TEST_DELAY_TIMER 1000

// Configure busywait loopcount
#define TEST_BUSYWAIT_COUNT 1000

//set this flag to test interrupt coalescing
#ifndef USE_POLLING
#define TEST_INTERRUPT_COALESCING
#endif 

#ifdef TEST_INTERRUPT_COALESCING
#define INTERRUPT_COALESCING_COUNT 4
#endif

// set this flag to support bounce buffer for PE
//#define TEST_BOUNCEBUFFERS

// Set this flag to support bounce buffers for PE in usermode 
#ifdef TEST_BOUNCEBUFFERS
#define TEST_BOUNCEBUFFERS_USER_MODE
#endif

#define MAX_HANDLES 5
#endif // SLAD_TEST_EIP93_SYSTEMTEST_CONFIGURATION_C5


/// C6
#ifdef SLAD_TEST_EIP93_SYSTEMTEST_CONFIGURATION_C6
#define USE_POLLING

// Set this flag to enable the use of log warnings
#define SLAD_TEST_APP_ENABLE_INFO_LOGS


// Set this flag to build the test application for RNG
//#define SLAD_TEST_BUILD_FOR_RNG
#define SLAD_TEST_DEFS_ONLY_FROM_SLAD_API_INTERFACE_FOLDER

// Configure the busywait sleepcount
#define TEST_DELAY_TIMER 1000

// Configure busywait loopcount
#define TEST_BUSYWAIT_COUNT 1000

//set this flag to test interrupt coalescing
#ifndef USE_POLLING
//#define TEST_INTERRUPT_COALESCING
#endif 

#ifdef TEST_INTERRUPT_COALESCING
#define INTERRUPT_COALESCING_COUNT 4
#endif

// set this flag to support bounce buffer for PE
#define TEST_BOUNCEBUFFERS

// Set this flag to support bounce buffers for PE in usermode 
#ifdef TEST_BOUNCEBUFFERS
#define TEST_BOUNCEBUFFERS_USER_MODE
#endif

#define MAX_HANDLES 5

#endif // SLAD_TEST_EIP93_SYSTEMTEST_CONFIGURATION_C6


//// C7
#ifdef SLAD_TEST_EIP93_SYSTEMTEST_CONFIGURATION_C7

//#define USE_POLLING

// Set this flag to enable the use of log warnings
#define SLAD_TEST_APP_ENABLE_INFO_LOGS


// Set this flag to build the test application for RNG
//#define SLAD_TEST_BUILD_FOR_RNG
#define SLAD_TEST_DEFS_ONLY_FROM_SLAD_API_INTERFACE_FOLDER

// Configure the busywait sleepcount
#define TEST_DELAY_TIMER 1000

// Configure busywait loopcount
#define TEST_BUSYWAIT_COUNT 1000

//set this flag to test interrupt coalescing
#ifndef USE_POLLING
//#define TEST_INTERRUPT_COALESCING
#endif 

#ifdef TEST_INTERRUPT_COALESCING
#define INTERRUPT_COALESCING_COUNT 4
#endif

// set this flag to support bounce buffer for PE
//#define TEST_BOUNCEBUFFERS

// Set this flag to support bounce buffers for PE in usermode 
#ifdef TEST_BOUNCEBUFFERS
#define TEST_BOUNCEBUFFERS_USER_MODE
#endif

#define MAX_HANDLES 5


#endif // SLAD_TEST_EIP93_SYSTEMTEST_CONFIGURATION_C7

/// C8

#ifdef SLAD_TEST_EIP93_SYSTEMTEST_CONFIGURATION_C8
#define USE_POLLING

// Set this flag to enable the use of log warnings
#define SLAD_TEST_APP_ENABLE_INFO_LOGS


// Set this flag to build the test application for RNG
//#define SLAD_TEST_BUILD_FOR_RNG
#define SLAD_TEST_DEFS_ONLY_FROM_SLAD_API_INTERFACE_FOLDER

// Configure the busywait sleepcount
#define TEST_DELAY_TIMER 1000

// Configure busywait loopcount
#define TEST_BUSYWAIT_COUNT 1000

//set this flag to test interrupt coalescing
#ifndef USE_POLLING
//#define TEST_INTERRUPT_COALESCING
#endif 

#ifdef TEST_INTERRUPT_COALESCING
#define INTERRUPT_COALESCING_COUNT 4
#endif

// set this flag to support bounce buffer for PE
//#define TEST_BOUNCEBUFFERS

// Set this flag to support bounce buffers for PE in usermode 
#ifdef TEST_BOUNCEBUFFERS
#define TEST_BOUNCEBUFFERS_USER_MODE
#endif

#define MAX_HANDLES 5

#endif // SLAD_TEST_EIP93_SYSTEMTEST_CONFIGURATION_C8


#endif //CS_SLAD_TEST_APP_EIP93_H



