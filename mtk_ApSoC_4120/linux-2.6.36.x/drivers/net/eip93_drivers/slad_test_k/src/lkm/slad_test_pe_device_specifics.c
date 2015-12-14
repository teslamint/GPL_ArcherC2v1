/***********************************************************
*
* SLAD Test Application
*
*

     Copyright 2007-2008 SafeNet Inc


*
*
* Edit History:
*
*Initial revision
* Created.
**************************************************************/
#include "c_sladtestapp.h"
#ifndef USE_NEW_API
#ifdef SLAD_TEST_BUILD_FOR_PE
#include "slad_test_pe_device_specifics.h"
#include "slad.h"

BOOL
slad_test_is_sram_supported (SLAD_DEVICEINFO * di)
{
  BOOL st;
  switch (di->device_type)
    {
    case PE_DEVICETYPE_EIP93:
      st = FALSE;
      break;
    default:
      st = FALSE;

    }
  return st;
}

BOOL
slad_test_is_programmable_interrupt_timer_supported (SLAD_DEVICEINFO * di)
{
  BOOL st;

  switch (di->device_type)
    {
    case PE_DEVICETYPE_EIP93:
      st = TRUE;
      break;
    default:
      st = FALSE;

    }
  return st;

}

BOOL
slad_test_set_programmable_interrupt_timer (SLAD_DEVICEINFO * di,
                                            unsigned int num_clk_cycles)
{
  BOOL st;
  st = slad_test_is_programmable_interrupt_timer_supported (di);

  if (st)
    {
      switch (di->device_type)
        {
        case PE_DEVICETYPE_EIP93:
          st =
            slad_test_set_programmable_interrupt_timer_4_eip94v22 (
                di->device_num, num_clk_cycles);

          break;

        default:
          LOG_INFO ("\n Programmable Interrupt Timer setting function \
                        not defined for this device \n");

          st = FALSE;

        }

    }
  else
    {
      LOG_INFO
        ("\n Programmable Interrupt Timer is not supported for this device \n");
    }

  return st;



}
#endif
#endif
