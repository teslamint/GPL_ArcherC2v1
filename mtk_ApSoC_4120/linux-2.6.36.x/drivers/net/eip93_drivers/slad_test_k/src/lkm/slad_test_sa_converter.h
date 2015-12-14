/***********************************************************
*
* SLAD Test SA Converter
*
*     Copyright 2007-2008 SafeNet Inc
*
* Edit History:
*
*Initial revision
* Created.
**************************************************************/

#ifndef SLAD_TEST_SA_CONVERTER_H
#define SLAD_TEST_SA_CONVERTER_H

#include "c_sladtestapp.h"

#ifdef SLAD_TEST_BUILD_FOR_PE
#include "slad_test_parser_op_defs.h"
#include "slad_osal.h"

#define WORDS_IN_SA               32
#define WORDS_IN_SREC             14
#define WORDS_IN_SREC_ARC4        64
#define WORDS_IN_SREC_WITH_ARC4   WORDS_IN_SREC + WORDS_IN_SREC_ARC4
#define WORD_SIZE                 4

int
slad_convert_sa (unsigned int *generic_sa, int *sa_len,
                 device_type_conf dev_type);

int
slad_convert_srec (unsigned int *generic_srec, int *srec_len,
                   device_type_conf dev_type);

#endif
#endif /* SLAD_TEST_SA_CONVERTER_H */
