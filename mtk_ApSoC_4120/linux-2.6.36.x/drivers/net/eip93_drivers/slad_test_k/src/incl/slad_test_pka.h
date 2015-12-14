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

#ifndef SLAD_TEST_PKA_H
#define SLAD_TEST_PKA_H

#include "c_sladtestapp.h"

#ifdef SLAD_TEST_BUILD_FOR_PKA

#include "slad_osal.h"
#include "slad_test_parser_op_defs.h"

//extern slad_app_id_type pka_app_id_g;
extern int pka_app_id_g;        // was in slad.h
extern int pka_device_num_g;

int slad_test_pka_initialize (pka_conf * pc);


int slad_test_pka_kat (int device_num, parsed_pka_pkt * pka_pkt);

int slad_test_pka_stress (int device_num, parsed_pka_pkt * pka_pkt);


int slad_test_pka_benchmark (int device_num, parsed_pka_pkt * pka_pkt);


#endif // #ifdef SLAD_TEST_BUILD_FOR_PKA

#endif
