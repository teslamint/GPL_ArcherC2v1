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


#ifndef SLAD_TEST_PARSER_OP_DEFS_H
#define SLAD_TEST_PARSER_OP_DEFS_H

#include "c_sladtestapp.h"

#ifdef USE_NEW_API
#include "api_pec.h"
#else
#include "slad.h"
#include "slad_pka.h"
#endif

#define SLAD_TEST_PARSER_PE_MODE_ARM    0
#define SLAD_TEST_PARSER_PE_MODE_DHM    ( !SLAD_TEST_PARSER_PE_MODE_ARM )

#define SLAD_TEST_PARSER_USER_DMA_OFF   0
#define SLAD_TEST_PARSER_USER_DMA_ON    ( !SLAD_TEST_PARSER_USER_DMA_OFF )




#define SLAD_TEST_PARSER_DEVICE_BYTE_SWAP_PD_SA   0
#define SLAD_TEST_PARSER_DEVICE_BYTE_SWAP_PD      1

#define SLAD_TEST_PARSER_ALLOC_FROM_SDRAM   0
#define SLAD_TEST_PARSER_ALLOC_FROM_SRAM  ( !SLAD_TEST_PARSER_ALLOC_FROM_SDRAM )



#define SLAD_TEST_PARSER_DEVICE_CRYPTO  0
#define SLAD_TEST_PARSER_DEVICE_PKA   1
#define SLAD_TEST_PARSER_DEVICE_RNG   2



#define SLAD_TEST_PARSER_MEMALLOC_FROM_SDRAM  0
#define SLAD_TEST_PARSER_MEMALLOC_FROM_SRAM    \
    ( !SLAD_TEST_PARSER_MEMALLOC_FROM_SDRAM )

typedef struct memalloc_method
{
  unsigned int is_sram:1;
  unsigned int is_cached:1;

  //slad_bus_addr sram_start_addr;
  unsigned int sram_start_addr;
  int sram_len_in_bytes;


} memalloc_method;

#ifdef SLAD_TEST_BUILD_FOR_PE
typedef struct pe_conf_data
{
  unsigned int pe_mode:1;
  unsigned int user_dma_flag:1;
  unsigned int use_interrupts:1;

  unsigned int byte_swap_settings:1;
  unsigned int use_dynamic_sa:1;

  unsigned int dscr_cnt;

  memalloc_method pdr_alloc_method;

} pe_conf_data;
#endif

#if defined (SLAD_TEST_BUILD_FOR_EIP28PKA) || defined (SLAD_TEST_BUILD_FOR_EIP154PKA)
typedef struct pka_conf
{
  unsigned int dummy;
} pka_conf;
#endif

#ifdef SLAD_TEST_BUILD_FOR_RNG
typedef struct rng_conf
{
  unsigned int dummy;
} rng_conf;
#endif

#ifdef SLAD_TEST_BUILD_FOR_PE
typedef struct test_conf_data
{
  memalloc_method sa_alloc_method;
  memalloc_method data_alloc_method;

  unsigned int is_user_mode:1;
  unsigned int explicit_dma_buffers:1;


} test_conf_data;
#endif


typedef struct tests_2_exec
{
  unsigned int kat:1;
  unsigned int benchmark:1;
  unsigned int stress:1;
  unsigned int intr_coal:1;
  unsigned int scatter_gather:1; // Only for backward compatibility
  unsigned int use_pit:1;       // Programmable Interrupt Timer
  unsigned int fLinked:1;       // EIP154 flinked bit test
  unsigned int intr_throttle:1;  // Input Throttling Test

  unsigned int scatter:1 ;
  unsigned int gather:1 ;

  int scatter_particle_size ;
  int gather_particle_size ;
  int num_max_scatter_particles ;
  int sg_mixed_test_num_total_pkts ;
  int sg_mixed_test_num_sg_pkts ;
    
  unsigned int benchmark_time_in_seconds;
  unsigned int stress_time_in_seconds;

  unsigned int print_in_tests;
  unsigned int print_in_tests_detailed;

  unsigned int intr_coal_time_in_seconds;

  unsigned int ringinorder;
  unsigned int ringinorder_stat; 

  unsigned int multiple_rings;
  unsigned int fixed_priority;
  unsigned int rotating_priority;
  unsigned int fixed_restrotating;
  unsigned int test_kdk ;

  unsigned int command_notify ;

#define SLAD_TEST_CASE_ID_STRING_SIZE 1024

  char test_case_id_string[SLAD_TEST_CASE_ID_STRING_SIZE];

} tests_2_exec;


typedef struct test_device
{
  unsigned char device;
  tests_2_exec tests;

} test_device;


#define SLAD_TEST_MAX_SA_BUFFER_SIZE_IN_WORDS     64
#define SLAD_TEST_MAX_STATE_RECORD_SIZE_IN_WORDS    32
#define SLAD_TEST_MAX_ARC4_STATE_RECORD_SIZE_IN_WORDS 64

#define SLAD_TEST_PARSER_MAX_TOTAL_STATE_RECORD_SIZE  \
(SLAD_TEST_MAX_STATE_RECORD_SIZE_IN_WORDS + \
 SLAD_TEST_MAX_ARC4_STATE_RECORD_SIZE_IN_WORDS )

typedef enum
{
  EIP_93_I = 1,
  EIP_93_IE,
  EIP_93_IS,
  EIP_93_IW,
  EIP_93_IESW
} device_type_conf;

#ifdef SLAD_TEST_BUILD_FOR_PE
typedef struct parsed_sa_n_srec
{
  unsigned int sa_index;
  unsigned int sa_len;
  unsigned int srec_len;
  unsigned int total_srec_len;

  unsigned int sa_words[SLAD_TEST_MAX_SA_BUFFER_SIZE_IN_WORDS];
  unsigned int state_record[SLAD_TEST_PARSER_MAX_TOTAL_STATE_RECORD_SIZE];

  unsigned int arc4_srec_offset;
  unsigned int arc4_srec_len;
  unsigned int is_srec_used;
  unsigned int is_arc4_srec_used;
  unsigned int sa_rev;

  device_type_conf device_conf;
} parsed_sa_n_srec;


typedef struct parser_pkt_data
{
  unsigned int sa_index;

  unsigned int pd_words[3];
  unsigned int rd_words[3];

  unsigned int gather_len;
  unsigned int *gather_buffer;

  unsigned char *ip_buffer;
  unsigned int ip_buffer_len;
  unsigned int ip_len_b;

  unsigned char *op_buffer;
  unsigned int op_buffer_len;
  unsigned int op_len_b;

} parser_pkt_data;

typedef struct parservp_pkt_data
{
  unsigned int sa_index;
  unsigned int pd_words[3];
  unsigned int rd_words[3];
  unsigned int gather_len;
  unsigned int *gather_buffer;
  unsigned int *ip_buffer; 
  unsigned int ip_buffer_len;
  unsigned int ip_len_b;
  unsigned int *op_buffer; 
  unsigned int op_buffer_len;
  unsigned int op_len_b;

} parservp_pkt_data;


#endif

#if defined (SLAD_TEST_BUILD_FOR_EIP28PKA) || defined (SLAD_TEST_BUILD_FOR_EIP154PKA)
typedef struct parsed_pka_pkt
{
  unsigned int buf_len[PKA_MAX_HANDLES];
  uint32_t *data_buf[PKA_MAX_HANDLES];
#ifdef SLAD_TEST_BUILD_FOR_EIP28PKA
  unsigned int pkcp_command;
  unsigned int pkcp_shiftval;
#endif  
#ifdef SLAD_TEST_BUILD_FOR_EIP154PKA
  uint32_t *commres_buf[5]; 
  unsigned int commres_len[5];
#endif
  unsigned int num_pka_datablk;
} parsed_pka_pkt;
#endif

#define RANDOM_BUFFER_SIZE 128

#ifdef SLAD_TEST_BUILD_FOR_RNG
typedef struct parsed_rng_pkt
{
  uint8_t *out_buf;
  unsigned int size;
  uint8_t info_buf[RANDOM_BUFFER_SIZE];
} parsed_rng_pkt;
#endif

#ifdef SLAD_TEST_BUILD_FOR_PE
typedef struct pe_test_record
{
  unsigned int record_number;
  parsed_sa_n_srec ip_sa_record;
  parser_pkt_data pkt_data;
  parsed_sa_n_srec op_sa_record;
  unsigned int is_op_sa_record_used;
} pe_test_record;
#endif



#endif // SLAD_TEST_PARSER_OP_DEFS_H
