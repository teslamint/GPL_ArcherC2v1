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

#ifndef __SLAD_TEST_H__
#define __SLAD_TEST_H__

#include "slad.h"
#include "slad_test_parser_op_defs.h"
#include "slad_test.h"
#include "slad_test_interface_to_parser.h"

#ifdef RT_EIP93_DRIVER_DEBUG
/*----------------------------------------------------------------------------
 * rt_dump_register
 *
 * This function dumps an Crypto Engine's register.
 * (define RT_DUMP_REGISTER in cs_sladtestapp.h before use it!)
 *
 * Use rt_dump_register(0xfff) to dump all registers.
 * Use rt_dump_register(register_offset) to dump a specific register.
 * The register_offset can be referred in Programmer-Manual.pdf
 */
void
rt_dump_register(
        unsigned int offset)
/*----------------------------------------------------------------------*/
#endif

/* This structure is a "wrapper" for all user-mode driver interface calls. */

//typedef unsigned int UINT32;
// typedef void *VPTR;

typedef struct
{
  UINT32 cmd;
#ifdef SLAD_TEST_BUILD_FOR_PE
  pe_conf_data *pe_confs;
#endif
#if defined (SLAD_TEST_BUILD_FOR_EIP28PKA) || defined (SLAD_TEST_BUILD_FOR_EIP154PKA)
  pka_conf *pka_confs;
#endif
#ifdef SLAD_TEST_BUILD_FOR_RNG
  rng_conf *rng_confs;
#endif
#ifdef SLAD_TEST_BUILD_FOR_PE
  test_conf_data *test_confs;
  pe_test_record *pe_tr;
#endif
  test_device *test_device_params;

#if defined (SLAD_TEST_BUILD_FOR_EIP28PKA) || defined (SLAD_TEST_BUILD_FOR_EIP154PKA)
  parsed_pka_pkt *pka_record;
  unsigned int num_pka_pkts;
#endif
#ifdef SLAD_TEST_BUILD_FOR_RNG
  parsed_rng_pkt *rng_record;
#endif

  UINT32 status;               
   /* returned status of driver call (SLAD_DRVSTAT_xxxx) */
}
SLAD_TEST_DRVCMD;

#define TRUE 1
#define FALSE 0


#endif /* __SLAD_TEST_H__ */
