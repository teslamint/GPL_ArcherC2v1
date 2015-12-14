/***********************************************************
*
* SLAD Test Application
*
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


#ifndef SLAD_TEST_PARSER_OP_PRINT_H
#define SLAD_TEST_PARSER_OP_PRINT_H

#include "slad_test_parser_op_defs.h"



void slad_test_print_memalloc_method (memalloc_method * mam);


#ifdef SLAD_TEST_BUILD_FOR_PE
void slad_test_print_configure_pe (pe_conf_data * pe_conf);
void slad_test_print_configure_test (test_conf_data * tc);
#endif

void slad_test_print_test_device (test_device * dev);

#ifdef SLAD_TEST_BUILD_FOR_PE
void slad_test_print_parsed_sa_n_srec (parsed_sa_n_srec * sa);
void slad_test_print_parsed_pkt (parser_pkt_data * pkt);
void slad_test_print_test_record (pe_test_record * tr);
#endif


#if defined (SLAD_TEST_BUILD_FOR_EIP28PKA) || defined (SLAD_TEST_BUILD_FOR_EIP154PKA)
void slad_test_print_pka_pkt (parsed_pka_pkt * blk);
#endif

#ifdef SLAD_TEST_BUILD_FOR_RNG
void slad_test_print_rng_pkt (parsed_rng_pkt * pkt);
#endif

#endif
