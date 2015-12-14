/***********************************************************
*
* SLAD Test Application
*
*

     Copyright 2007-2008 SafeNet Inc


*
* Edit History:
*
*Initial revision
* Created.
**************************************************************/

#include "c_sladtestapp.h"
#ifndef USE_NEW_API
#ifndef SLAD_TEST_DEVICE_SEPCIFICS_H
#define SLAD_TEST_DEVICE_SEPCIFICS_H

#ifdef SLAD_TEST_BUILD_FOR_PE

#include "slad_test_pe_eip9422.h"
#include "slad.h"

BOOL slad_test_is_sram_supported (SLAD_DEVICEINFO * di);
BOOL slad_test_is_programmable_interrupt_timer_supported (SLAD_DEVICEINFO *
                                                          di);

BOOL slad_test_set_programmable_interrupt_timer (SLAD_DEVICEINFO * di,
                                                 unsigned int num_clk_cycles);



#endif //
#endif
#endif
