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

#include "slad_test_parser_op_defs.h"
#include "slad_test_interface_to_parser.h"


/* Status return codes for the SLAD API function calls. */

#define SLAD_TEST_OK                        0

#define SLAD_TEST_CMD_CONFIGURE_PE          1
#define SLAD_TEST_CMD_CONFIGURE_PKA         2
#define SLAD_TEST_CMD_CONFIGURE_RNG         3

#define SLAD_TEST_CMD_CONFIGURE_TEST        4
#define SLAD_TEST_CMD_NOTE_TESTS_N_DEVICE     5
#define SLAD_TEST_CMD_NOTE_PE_TEST_RECORD     6
#define SLAD_TEST_CMD_NOTE_PKA_RECORD    7
#define SLAD_TEST_CMD_NOTE_RNG_RECORD       9
#define SLAD_TEST_UNINIT_DEVICES            10


#define SLAD_TEST_STAT_COMMAND_INVALID      -1
#define  SLAD_TEST_STAT_USERMODE_API_ERR    -2



/*************************************************************
* User-mode API data objects and definitions.
**************************************************************/

/* Commands for the user-mode driver interface 
(placed in cmd of SLAD_TEST_DRVCMD structure). */



/* This structure is a "wrapper" for all user-mode 
driver interface calls. */


typedef struct
{
  unsigned int cmd;
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
#endif
  test_device *test_device_params;
#ifdef SLAD_TEST_BUILD_FOR_PE
  pe_test_record *pe_tr;
#endif

#if defined (SLAD_TEST_BUILD_FOR_EIP28PKA) || defined (SLAD_TEST_BUILD_FOR_EIP154PKA)
  parsed_pka_pkt *pka_record;
  unsigned int num_pka_pkts;
#endif

#ifdef SLAD_TEST_BUILD_FOR_RNG
  parsed_rng_pkt *rng_record;
#endif

  unsigned int status;          
  /* returned status of driver call (SLAD_DRVSTAT_xxxx) */
}
SLAD_TEST_DRVCMD;

#ifndef IDENTIFIER_NOT_USED
#define IDENTIFIER_NOT_USED(_v) if(_v){}
#endif

#endif /* __SLAD_TEST_H__ */
