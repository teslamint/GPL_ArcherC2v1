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

#include "slad_test_pe.h"
#ifdef SLAD_TEST_BUILD_FOR_PE
//#include "pe_devices.h"
#include "api_pec.h"
#include "slad_test_parser_op_defs.h"
#include "slad_test.h"
#include "slad_test_pe_debug.h"
#include "slad_osal.h"


/*************************************************************
* Global variables.
**************************************************************/
// NEW PE APIs
PEC_Capabilities_t device_info;
PEC_InitBlock_t initblock;

slad_app_id_type_new app_id_g[1];


/*************************************************************
* Local variables.
**************************************************************/


int
slad_test_init_pe (pe_conf_data * pe_conf)
{
  int status;
  int ok;
  PEC_Status_t PE_Status = PEC_STATUS_OK;

  PEC_Capabilities_t *di;

  di = &device_info;
  status = PEC_Capabilities_Get (di);

  if (status == PEC_STATUS_OK)
    {
      osal_bzero ((void *) &initblock, sizeof (PEC_InitBlock_t));

      // Fill Initblock structure
      if (pe_conf->use_dynamic_sa)
        {
          initblock.fUseDynamicSA = 1;
        }

      #ifdef TEST_PEC_SCATTER
        initblock.FixedScatterFragSizeInBytes = 
            TEST_PEC_SCATTER_PARTICLE_SIZE_IN_BYTES ;
      #endif

      PE_Status = PEC_Init (&initblock);
      if (PE_Status != PEC_STATUS_OK)
        {
          LOG_CRIT ("\n PEC_Init failed, returned : %d \n", PE_Status);
        }
      else
        LOG_INFO ("\n PEC_Init passed \n");

    }
  else
    LOG_CRIT ("\n PEC_Capabilities_Get failed \n");

  ok = (PE_Status == PEC_STATUS_OK ? TRUE : FALSE);
  return ok;
}

void
slad_test_uninit_pe (void)
{
  PEC_Status_t status;

  status = PEC_UnInit ();

  if (status != PEC_STATUS_OK)
    {
      LOG_CRIT ("\n Can't uninit device ");
    }
  else
    LOG_INFO ("\n PE uninitialized \n");

}
#endif
