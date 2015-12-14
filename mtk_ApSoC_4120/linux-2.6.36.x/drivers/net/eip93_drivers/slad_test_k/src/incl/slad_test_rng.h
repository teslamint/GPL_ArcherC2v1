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

#ifndef SLAD_TEST_RNG_H
#define SLAD_TEST_RNG_H
#include "c_sladtestapp.h"

#ifdef SLAD_TEST_BUILD_FOR_RNG

#include "slad.h"


extern int rng_device_num_g;
//extern RNG_INIT_BLOCK rng_iblk_g ;
extern slad_app_id_type rng_app_id_g;

int slad_test_rng_initialize (rng_conf * pc);

int slad_test_random (int device_num, RANDOM_PARAM_BLK * blk);

#endif // #ifdef SLAD_TEST_BUILD_FOR_RNG

#endif
