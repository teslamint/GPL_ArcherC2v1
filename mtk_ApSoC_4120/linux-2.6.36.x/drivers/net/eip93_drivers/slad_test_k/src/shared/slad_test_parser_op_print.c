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

#include "slad_test_parser_op_defs.h"
#ifndef USE_NEW_API
#include "slad.h"
#else
#include "api_pec.h"
#endif

#include "slad_osal.h"
//#include <../../SLAD_API/incl/slad.h>
//#include "slad_test_parser_op_defs.h"

#if 0
#ifndef MODULE
#define osal_printf printf
#else
#define osal_printf printk
#endif
#endif


void
slad_test_print_memalloc_method (memalloc_method * mam)
{
  LOG_INFO ("\n\t{ Memory Allocation Properties \n");

  if (!mam->is_sram)
    LOG_INFO ("\n\t\t Using SDRAM ");
  else
    LOG_INFO ("\n\t\t Using SRAM  ");

  if (!mam->is_cached)
    LOG_INFO ("\n\t\t Non Cached ");
  else
    LOG_INFO ("\n\t\t Cached ");

  if (mam->is_sram)
    {
      LOG_INFO ("\n\t\t SRAM Start address : %x ", mam->sram_start_addr);
      LOG_INFO ("\n\t\t SRAM Length in Bytes : %x ", mam->sram_len_in_bytes);
    }

  LOG_INFO ("\n\n\t}:<- Memory Allocation Properties \n\n");

}

#ifdef SLAD_TEST_BUILD_FOR_PE
void
slad_test_print_configure_pe (pe_conf_data * pe_conf)
{
  LOG_INFO ("\n{ PE Configuration Data \n");

  LOG_INFO ("\n\t PE Mode : ");
  if (pe_conf->pe_mode == SLAD_TEST_PARSER_PE_MODE_ARM)
    LOG_INFO (" ARM ");
  else
    LOG_INFO (" DHM ");

  if (pe_conf->user_dma_flag == SLAD_TEST_PARSER_USER_DMA_OFF)
    LOG_INFO ("\n\t User DMA : OFF ");
  else
    LOG_INFO ("\n\t User DMA : ON ");


  if (!pe_conf->use_interrupts)
    LOG_INFO ("\n\t Using Polling Mode ");
  else
    LOG_INFO ("\n\t Using Interrupt Mode ");



  if (pe_conf->byte_swap_settings == SLAD_TEST_PARSER_DEVICE_BYTE_SWAP_PD_SA)
    LOG_INFO ("\n\t Device Byte Swap for : PD and SA ");
  else
    LOG_INFO ("\n\t Device Byte Swap for : PD ");


  LOG_INFO ("\n\t PDR Memory Allocation properties : \n");
  slad_test_print_memalloc_method (&pe_conf->pdr_alloc_method);

  LOG_INFO ("\n\n}<- PE Configuration Data \n\n");

}

void
slad_test_print_configure_test (test_conf_data * tc)
{
  LOG_INFO ("\n{ Test Configuration Data \n");

  LOG_INFO ("\n\t SA Alloc Properties \n");
  slad_test_print_memalloc_method (&tc->sa_alloc_method);
  LOG_INFO ("\n\t Data Alloc Properties \n");
  slad_test_print_memalloc_method (&tc->data_alloc_method);

  if (tc->explicit_dma_buffers)
    LOG_INFO ("\n\t Explicit DMA buffers to be used by Test App. \n");
  else
    LOG_INFO ("\n\t NO explicit DMA buffers to be used by Test App. \n");

  LOG_INFO ("\n}:<- Test Configuration Data \n\n");

}
#endif


void
slad_test_print_test_device (test_device * dev)
{
  LOG_INFO ("\n{ Device and Tests to execute  \n");

  if (dev->device == SLAD_TEST_PARSER_DEVICE_CRYPTO)
    LOG_INFO ("\n\t Device : Crypto Accelerator / Packet Engine ");
  else if (dev->device == SLAD_TEST_PARSER_DEVICE_PKA)
    LOG_INFO ("\n\t Device : PKA ");
  else
    LOG_INFO ("\n\t Device : RNG ");

  LOG_INFO ("\n\t Tests to execute : ");

  if (dev->tests.kat)
    {
      LOG_INFO ("\t kat");

    }

  if (dev->tests.benchmark)
    {
      LOG_INFO ("\t benchmark");
    }

  if (dev->tests.stress)
    {
      LOG_INFO ("\t stress ");
    }

  LOG_INFO ("\n");

  LOG_INFO ("\n}:<- Device and Tests to execute  \n");

}


#ifdef SLAD_TEST_BUILD_FOR_PE
void
slad_test_print_parsed_sa_n_srec (parsed_sa_n_srec * sa)
{
  int i;
  LOG_INFO ("\n\t{ Parsed SA \n");
  LOG_INFO ("\n\t\t SA Index : %d ", sa->sa_index);
  LOG_INFO ("\n\t\t SA Length(32 bit Words) : %d ", sa->sa_len);
  LOG_INFO ("\n\t\t SA Words : \n");

  for (i = 0; i < sa->sa_len; i++)
    {
      if (i % 4 == 0)
        LOG_INFO ("\n\t");

      LOG_INFO ("\t%8x", sa->sa_words[i]);

    }

  LOG_INFO ("\n\n\t\t State Record Length ( 32-bit Words ) : %d ",
            sa->srec_len);

  if (sa->srec_len)
    LOG_INFO ("\n\t\t State Record Words :\n");


  for (i = 0; i < sa->srec_len; i++)
    {
      if (i % 4 == 0)
        LOG_INFO ("\n\t");

      LOG_INFO ("\t%8x", sa->state_record[i]);

    }

  LOG_INFO ("\n\t}:<- Parsed SA \n");

}

void
slad_test_print_parsed_pkt (parser_pkt_data * pkt)
{
  int i = 0;

  LOG_INFO ("\n\t{ Parsed Packet \n");
  LOG_INFO ("\n\t\t Length of Buffers are in Words \n");
  LOG_INFO ("\n\t\t SA Index : %d ", pkt->sa_index);

  LOG_INFO ("\n\t\t PD Words : \n\t");

  for (i = 0; i < 3; i++)
    LOG_INFO ("\t %x", pkt->pd_words[i]);

  LOG_INFO ("\n\t\t RD Words : \n\t");

  for (i = 0; i < 3; i++)
    LOG_INFO ("\t %x", pkt->rd_words[i]);

  LOG_INFO ("\n\t\t Gather Length : %d ", pkt->gather_len);
  if (pkt->gather_len)
    LOG_INFO ("\n\t\t Gather Words : \n\t");

  for (i = 0; i < pkt->gather_len; i++)
    LOG_INFO ("\t %x", pkt->gather_buffer[i]);

  LOG_INFO ("\n\n\t\t Input Buffer Length : %d ", pkt->ip_buffer_len);
  LOG_INFO ("\n\t\t Input Buffer Words : \n\t");

  for (i = 0; i < pkt->ip_buffer_len; i++)
    {
      if (i % 4 == 0)
        LOG_INFO ("\t %x", pkt->ip_buffer[i]);

    }

  LOG_INFO ("\n\n\t\t Output Buffer Length : %d ", pkt->op_buffer_len);
  LOG_INFO ("\n\t\t Output Buffer Words : \n\t");

  for (i = 0; i < pkt->op_buffer_len; i++)
    {
      if (i % 4 == 0)
        LOG_INFO ("\n\t");
      LOG_INFO ("\t %x", pkt->op_buffer[i]);

    }

  LOG_INFO ("\n\t}:<- Parsed Packet \n");

}


void
slad_test_print_test_record (pe_test_record * tr)
{
  LOG_INFO ("\n{ Test Record \n");
  LOG_INFO ("\n\t Record Number : %d ", tr->record_number);
  LOG_INFO ("\n\t Input SA Record \n");
  slad_test_print_parsed_sa_n_srec (&tr->ip_sa_record);
  LOG_INFO ("\n\t Packet Data \n");
  slad_test_print_parsed_pkt (&tr->pkt_data);

  if (tr->is_op_sa_record_used)
    LOG_INFO ("\n\t Output SA Record is being Used \n");
  else
    LOG_INFO ("\n\t Output SA Record is NOT being Used \n");

  LOG_INFO ("\n\t Output SA Record \n");
  slad_test_print_parsed_sa_n_srec (&tr->op_sa_record);

  LOG_INFO ("\n}:<- Test Record \n");

}
#endif

#if defined (SLAD_TEST_BUILD_FOR_EIP28PKA) || defined (SLAD_TEST_BUILD_FOR_EIP154PKA)
void
slad_test_print_pka_pkt (parsed_pka_pkt * blk)
{
  int i=0;
  int j;

  LOG_CRIT ("\n{  PKA Packet \n");
  LOG_CRIT ("\n\t Sizes are in words \n");


  for (j = 0; j < PKA_MAX_HANDLES; j++)
    {
      LOG_CRIT ("\n\t %d Buffer size : %d ", j, blk->buf_len[j]);
      LOG_CRIT ("\n\t %d Buffer data is : \n\t\t", j);
      if (blk->buf_len[j])
        {
          for (i = 0; i < (blk->buf_len[j] * sizeof (int)); i++)
            {
              if (i % 4 == 0)
                LOG_CRIT ("\n\t\t");
              LOG_CRIT ("%8x\t", blk->data_buf[j][i]);
            }
        }
    }

#if defined (SLAD_TEST_BUILD_FOR_EIP154PKA)
    for (j = 0; j < 2; j++)
    {
         if (blk->commres_len[i])
         {
            for (i = 0; i < (blk->commres_len[j] * sizeof (int)); i++)
            {
                if (i % 4 == 0)
                    LOG_CRIT ("\n\t\t");
                LOG_CRIT ("%8x\t", blk->commres_buf[j][i]);
            }
     }
    }
               
#endif
  LOG_CRIT ("\n} PKA Packet \n");

}
#endif


#ifdef SLAD_TEST_BUILD_FOR_RNG
void
slad_test_print_rng_pkt (parsed_rng_pkt * pkt)
{
  int i;
  LOG_INFO ("\n Requested size of random number : %d\n", pkt->size);
  LOG_INFO ("\n The number is : \n");
  for (i = 0; i < pkt->size; i++)
    {
      if (i % 8 == 0)
        LOG_INFO ("\n");
      LOG_INFO ("\t%x", pkt->out_buf[i]);
    }
  LOG_INFO ("\n");

}
#endif
