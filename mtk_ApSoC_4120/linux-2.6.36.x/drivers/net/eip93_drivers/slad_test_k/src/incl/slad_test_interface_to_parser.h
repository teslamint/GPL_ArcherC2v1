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


#ifndef SLAD_TEST_INTERFACE_TO_PARSER_H

#define SLAD_TEST_INTERFACE_TO_PARSER_H

#include "c_sladtestapp.h"
#include "slad_test_parser_op_defs.h"


extern test_device device_n_test_info_g;

#ifdef SLAD_TEST_BUILD_FOR_PE
extern pe_conf_data pe_conf_data_g;
extern test_conf_data test_config_g;
extern pe_test_record pe_test_record_g;
#endif

#if defined (SLAD_TEST_BUILD_FOR_EIP28PKA) || defined (SLAD_TEST_BUILD_FOR_EIP154PKA)
extern pka_conf pka_conf_g;
typedef struct 
{
  unsigned int buf_len[PKA_MAX_HANDLES];
  uint8_t *databuf[PKA_MAX_HANDLES]; 
  
#if defined (SLAD_TEST_BUILD_FOR_EIP28PKA)
  unsigned int pkcp_shiftval;
  uint32_t pkcp_command;
#endif

#if defined (SLAD_TEST_BUILD_FOR_EIP154PKA)
  uint32_t *commres_buf[5]; 
  unsigned int commres_len[5];
#endif 
  unsigned int num_pka_datablk;
} pka_pkt;
extern pka_pkt pka_rec_g[PKA_MAX_RECORDS];
#endif

#ifdef SLAD_TEST_BUILD_FOR_RNG
extern rng_conf rng_conf_g;
extern parsed_rng_pkt rng_rec_g;
#endif


#ifdef SLAD_TEST_BUILD_FOR_PE
int _slad_test_configure_pe (int userland, pe_conf_data * pe_conf);
int _slad_test_configure_test (int userland, test_conf_data * tc);
#endif

int _slad_test_note_tests_n_device (int userland, test_device * dev);


#ifdef SLAD_TEST_BUILD_FOR_PE
int _slad_test_note_pe_test_record (int userland, pe_test_record * tr);
#endif

#if defined (SLAD_TEST_BUILD_FOR_EIP28PKA) || defined (SLAD_TEST_BUILD_FOR_EIP154PKA)
int _slad_test_note_pka_record (int userland, parsed_pka_pkt * pkt, unsigned int num_pkts);
#endif

#ifdef SLAD_TEST_BUILD_FOR_RNG
int _slad_test_note_rng_record (int userland, parsed_rng_pkt * pkt);
#endif


#if defined (SLAD_TEST_BUILD_FOR_EIP28PKA) || defined (SLAD_TEST_BUILD_FOR_EIP154PKA)
int _slad_test_configure_pka (int userland, pka_conf * pc);
#endif


#ifdef SLAD_TEST_BUILD_FOR_RNG
int _slad_test_configure_rng (int userland, rng_conf * rc);
#endif




//////////////////////////////////////////////////////////

#ifdef SLAD_TEST_BUILD_FOR_PE
int slad_test_configure_pe (pe_conf_data * pe_conf);
#endif


#if defined (SLAD_TEST_BUILD_FOR_EIP28PKA) || defined (SLAD_TEST_BUILD_FOR_EIP154PKA)
int slad_test_configure_pka (pka_conf * pc);
#endif


#ifdef SLAD_TEST_BUILD_FOR_RNG
int slad_test_configure_rng (rng_conf * rc);
#endif


#ifdef SLAD_TEST_BUILD_FOR_PE
int slad_test_configure_test (test_conf_data * tc);
#endif


int slad_test_note_tests_n_device (test_device * dev);


#ifdef SLAD_TEST_BUILD_FOR_PE
int slad_test_note_pe_test_record (pe_test_record * tr);
#endif

#if defined (SLAD_TEST_BUILD_FOR_EIP28PKA) || defined (SLAD_TEST_BUILD_FOR_EIP154PKA)
int slad_test_note_pka_record (parsed_pka_pkt * pkt, unsigned int num_pkts);
#endif

#ifdef SLAD_TEST_BUILD_FOR_RNG
int slad_test_note_rng_record (parsed_rng_pkt * pkt);
#endif


#ifdef SLAD_TEST_BUILD_FOR_PE
int slad_test_uninit_devices (void);
#endif

////////////////////////////////////////////////////////////




#endif
