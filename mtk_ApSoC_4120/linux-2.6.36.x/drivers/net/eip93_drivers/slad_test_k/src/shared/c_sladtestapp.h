/* c_sladtestapp.h
 *
 * Configuration options for the VDriver Test Module
 * The project-specific cs_sladtestapp.h file is included.
 */
/*****************************************************************************
*                                                                            *
*         Copyright (c) 2007-2008 SafeNet Inc. All Rights Reserved.          *
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


/*----------------------------------------------------------------
 * inclusion of cs_sladtestapp.h
 */
#include "cs_sladtestapp.h"

#define NR_TEST_PACKETS 10
#define PKA_MAX_HANDLES 15
#define DATA_ALIGN_BYTECOUNT 64
#define PKA_BUSY_LIMIT 3

#define PKA_MAX_DESCR_HANDLES 2
#define PKA_MAX_RECORDS 5

// Set this to add appropriate delay while fetching
// packets in interrupt mode. By default this is set at 10.
// This value is arrived at during benchmark testing of pe.
// Similarly for PKA tests this should be defined at 100.
#ifndef TEST_DELAY_TIMER 
#define TEST_DELAY_TIMER 10
#endif

#ifndef TEST_BUSYWAIT_COUNT 
#define TEST_BUSYWAIT_COUNT 10000
#endif

#ifndef  TEST_INTERRUPT_COALESCING
#define INTERRUPT_COALESCING_COUNT 5 
#endif



#ifndef MAX_HANDLES
#define MAX_HNALDES 5
#endif


#ifndef MAX_PKA_PACKETS 
#define MAX_PKA_PACKETS 10
#endif

#ifndef PKA_RINGINORDER_RECORDS 
#define PKA_RINGINORDER_RECORDS 7
#endif

#if !defined(PKA_TEST_DELAY_TIMER) || !defined(PKA_TEST_BUSYWAIT_COUNT)
#undef PKA_TEST_DELAY_TIMER
#undef PKA_TEST_BUSYWAIT_COUNT

#ifdef SLAD_TEST_APP_DISABLE_LOGS_FOR_PERF_TEST
// Configure the busywait sleepcount
#define PKA_TEST_DELAY_TIMER 5000
// Configure busywait loopcount
#define PKA_TEST_BUSYWAIT_COUNT 10000
#else
// Configure the busywait sleepcount
#define PKA_TEST_DELAY_TIMER 1000
// Configure busywait loopcount
#define PKA_TEST_BUSYWAIT_COUNT 1000
#endif

#endif

/* end of file c_sladtestapp.h */
