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
#ifdef SLAD_TEST_BUILD_FOR_PE
#ifndef __SLAD_TEST_DBG_H__
#define __SLAD_TEST_DBG_H__

#ifndef USE_NEW_API
#include "slad.h"
#endif


/****************************************************************
* Function prototypes.
*****************************************************************/

void slad_test_print_hex (void *s, int len_in_bytes);
void slad_test_print_word_in_bits (unsigned int word);

void slad_test_print_descriptor_rev0 (void *pd_or_rd);
void slad_test_print_descriptor_rev1 (void *pd_or_rd);

void slad_test_print_descriptor (void *pd_or_rd, int rev);

void slad_test_print_sa_rev1 (void *sa_rev1);
void slad_test_print_sa_rev2 (void *sa_rev2);
void slad_test_print_sa_dynamic (void *sa_dynamic);

void slad_test_print_sa (void *sa, int size_in_words);

void slad_test_print_srec_rev1 (void *srec_rev1);
void slad_test_print_srec_rev2 (void *srec_rev2);

void slad_test_print_srec (void *srec, int size_in_words);

void slad_test_print_arc4_state_record (void *arc4_srec);

void slad_test_print_decode_sa_command0 (unsigned int cmd);
void slad_test_print_decode_sa_command1 (unsigned int cmd);

void slad_test_print_decode_register_pe_control_status (unsigned int cs);

void slad_test_get_srec_offset (void *sa, int sa_size_in_words,
                                int *srec_offset_in_words,
                                int *arc4_offset_in_words);

void slad_test_zeroize_srec_pointers (void *sa, int sa_size_in_words);
#endif /* __SLAD_TEST_DBG_H__ */
#endif
