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
#ifndef  SLAD_TEST_PE_H
#define SLAD_TEST_PE_H

#ifdef SLAD_TEST_BUILD_FOR_PE


#include "slad_test_parser_op_defs.h"
#ifndef USE_NEW_API
#include "slad.h"
#include "initblk.h"
#else
#include "api_pec.h"
#endif
#include "slad_test_pe_device_specifics.h"

//////////////////////////////////////////////
// Define this to test packet sync
//      #define SLAD_TEST_PKT_SYNC
//////////////////////////////////////////////


#define SLAD_TEST_ERR_INAVLID_PARSED_SA 1
#define SLAD_TEST_ERR_MALLOC        2
#define SLAD_TEST_ERR_SREC_REQUIRED     3
#define SLAD_TEST_ERR_INVALID_PARSED_SA 4
#define SLAD_TEST_ERR_INVALID_SREC_LEN  5
#define SLAD_TEST_ERR_INVALID_LEN_SA  6


#define SLAD_TEST_ZERO_LEN_SA     7
#define SLAD_TEST_ZERO_LEN_SREC   8

#define SIZE_OF_DYNAMIC_SA_SREC_IN_WORDS 22
#define SIZE_OF_ARC4_SREC_IN_WORDS     64

#define SIZE_OF_REV1_SA_IN_WORDS    32
#define SIZE_OF_REV1_SREC_IN_WORDS    10

#define SIZE_OF_REV2_SA_IN_WORDS    58
#define SIZE_OF_REV2_SREC_IN_WORDS    22

#define MAX_SIZE_OF_DYNAMIC_SA      59


#define INVALID_SA_REVISION -1
#define REVISION1_SA 1
#define REVISION2_SA 2
#define DYNAMIC_SA   10

#define REVISION1_SREC 1
#define REVISION2_SREC 2
#define REVISON_ARC4   10


#define SREC 0
#define ARC4_SREC 1

#define STATE_PTR_OFFEST_IN_REV1_SA         27
#define ARC4_STATE_PTR_OFFEST_IN_REV1_SA    29

#define STATE_PTR_OFFEST_IN_REV2_SA         55
#define ARC4_STATE_PTR_OFFEST_IN_REV2_SA    57


#define NR_GDR_ENTRIES        256
#define NR_SDR_ENTRIES        512
#define GATHER_PARTICLE_SIZE    64
#define SCATTER_PARTICLE_SIZE   64

//#define PKA_PKT_EXPO_SIZE   2
//#define PKA_PKT_RES_SIZE    10


#define SLAD_TEST_BUFFER_CACHED              0
#define SLAD_TEST_BUFFER_NON_CACHED       1
#define SLAD_TEST_BUFFER_CACHED_ALIGNED   2



#define get_cached_sa_bit( control_status ) \
((control_status >> 5) & 0x1)


#define set_pe_mode_to_dhm( dma_config_reg ) \
do{ \
   dma_config_reg |= 0x01000000 ; \
   dma_config_reg &= 0xfffffeff ; \
}while(0)

#define set_pe_mode_to_arm( dma_config_reg ) \
do{ \
   dma_config_reg |= 0x00000100 ; \
   dma_config_reg &= 0xfeffffff ; \
}while(0)


/////////////////////

#ifdef SLAD_OSAL_DO_NOT_ALLOC_BOUNCE_BUFFERS_FOR_KERNEL_MODE_BUFFERS
        //#error "cache aligned"
#define slad_test_malloc(n)     osal_malloc_cache_aligned(n)
#define slad_test_free(p, n)     osal_free_cache_aligned(p, n)
#else
        //#error "not cache aligned"
#define slad_test_malloc(n)     osal_malloc(n)
#define slad_test_free(p, n)     osal_free(p, n)
#endif


///////////////////

typedef union
{
  SLAD_PKT pkt;
  SLAD_PKT_BITS pktb;
}
SPKT;

extern int target_requires_swap;

#define MAX_DEVICES         1


extern slad_app_id_type app_id_g[MAX_DEVICES];
extern int is_device_initialized_g[MAX_DEVICES];

extern int target_requires_swap;
extern int master_requires_swap;

extern SLAD_DEVICEINFO device_info[MAX_DEVICES];
extern INIT_BLOCK initblock;


extern void *gdr_handle_g, *gdr_bus_addr_g;
extern void *sdr_handle_g, *sdr_bus_addr_g;
extern void *sdr_dst_handle_g, *sdr_dst_bus_addr_g;
extern int gdr_idx_g, sdr_idx_g, scatter_block_size_g;
extern void *gdr_vaddr_g, *sdr_vaddr_g, *sdr_dst_vaddr_g;


extern void (*pdr_notification_function) (void);
extern unsigned long callback_cnt;
extern unsigned long signal_cnt;





int slad_test_init_pe (pe_conf_data * pe_conf);

void slad_test_uninit_pe (void);


int
slad_test_pe_kat_run_test (slad_app_id_type app_id,
                           SLAD_DEVICEINFO * di, pe_test_record * tr,
                           int notification);

int
slad_test_pe_run_benchmark_test (slad_app_id_type app_id,
                                 SLAD_DEVICEINFO * di, pe_test_record * tr,
                                 int notification);


int
slad_test_pe_run_stress_test (slad_app_id_type app_id,
                              SLAD_DEVICEINFO * di, pe_test_record * tr,
                              int notification);
int
slad_test_pe_run_intr_coal_test (slad_app_id_type app_id,
                                 SLAD_DEVICEINFO * di, pe_test_record * tr,
                                 int notification);

int
slad_test_pe_sg (slad_app_id_type app_id,
                 SLAD_DEVICEINFO * di, pe_test_record * tr);

int
slad_test_make_sa_n_srec (parsed_sa_n_srec * parsed_sa,
                          SLAD_SA * sa,
                          SLAD_STATE_RECORD * srec,
                          int *sa_revision,
                          void *dynamic_sa,
                          void *dynamic_srec, void *dynamic_arc4_srec,
                          int *sa_len);




void
slad_test_populate_notify_objects (SLAD_NOTIFY * pdr, SLAD_NOTIFY * cdr,
                                   int use_notification);

void slad_test_got_callback (int device_num);

void slad_test_print_callback_stat (void);

void slad_test_reset_callback_stat (void);

void *slad_test_malloc_generic (int len, int flags, void **phy_addr);

void slad_test_free_generic (void *p, int len, int flags, void *phy_addr);

int slad_test_is_scatter_set (void *sa, int sa_len_in_words);

int slad_test_is_gather_set (void *sa, int sa_len_in_words);

int slad_test_is_prng_used (void *sa, int sa_len_in_words);

void slad_test_print_device_revision (int device_num);


#endif
#endif

#else

#include "slad_test_parser_op_defs.h"
#include "api_pec.h"
#include "slad_test_pe_device_specifics.h"

#define SIZE_OF_REV2_SA_IN_WORDS    58
#define SIZE_OF_REV2_SREC_IN_WORDS    22

typedef int slad_app_id_type_new;
extern slad_app_id_type_new app_id_g[1];
int slad_test_init_pe (pe_conf_data * pe_conf);

void slad_test_uninit_pe (void);

int
slad_test_pe_kat_run_test (int app_id,
                           PEC_Capabilities_t * di, pe_test_record * tr,
                           int notification);
int
slad_test_pe_run_stress_test (int app_id,
                              PEC_Capabilities_t * di, pe_test_record * tr,
                              int notification);
int
slad_test_pe_run_benchmark_test (int app_id, PEC_Capabilities_t * di,
                                 pe_test_record * tr, int notification);

int
slad_test_pe_run_interruptthrott_test (int app_id,
                                 PEC_Capabilities_t * di, pe_test_record * tr,
                                 int notification);
int
slad_test_pe_cmd_notify_run_test (int app_id,
                           PEC_Capabilities_t * di, pe_test_record * tr ) ;


#endif
