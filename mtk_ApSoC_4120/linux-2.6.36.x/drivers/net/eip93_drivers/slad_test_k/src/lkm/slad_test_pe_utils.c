/***********************************************************
*
* SLAD Test Application
*
*

     Copyright 2007-2008 SafeNet Inc


* Edit History:
*
*Initial revision
* Created.
**************************************************************/
#include "c_sladtestapp.h"
#ifndef USE_NEW_API
#ifdef SLAD_TEST_BUILD_FOR_PE
#include "slad.h"
#include "slad_test.h"
#include "slad_test_pe.h"

#include "slad_test_parser_op_defs.h"




int
slad_test_get_ptrs_offset_in_dynamic_sa (unsigned int sa_contents,
                                         int *state_ptr_offset,
                                         int *arc4_state_ptr_offset)
{
  int i, offset = 1;

  *state_ptr_offset = *arc4_state_ptr_offset = 0;

  // Size of Commands
  offset += (sa_contents & 0xf);
  // KeySize
  offset += ((sa_contents & 0xf0) >> 4);
  // Inner Digest Size
  offset += ((sa_contents & 0x1f00) >> 8);
  // Outer Digest Size
  offset += ((sa_contents & 0x3e000) >> 13);

  sa_contents >>= 18;

  for (i = 18; i <= 31; i++)
    {
      if (sa_contents & 0x1)
        {
          if (i == 29)          //  State Ptr
            {
              *state_ptr_offset = offset;
              offset++;         // for reserved 64-bit addressing field
            }
          if (i == 30)          //  ARC4 ij ptr
            {
              //*arc4_ij_ptr_offset = offset;

            }
          if (i == 31)          //  ARC4 State Ptr
            {
              *arc4_state_ptr_offset = offset;
              offset++;         // // for reserved 64-bit addressing field
            }

          offset++;
        }

      sa_contents >>= 1;

    }
  return offset;                // Size of Dynamic SA

}

/*

static int
slad_test_make_dynamic_sa_n_srec (parsed_sa_n_srec * parsed_sa_srec,
                                  void *dynamic_sa,
                                  void *srec, void *arc4_srec, int *sa_len)
{
  int state_ptr_offset;
  int arc4_ij_ptr_offset;
  int arc4_state_ptr_offset;

  *sa_len = 0;

  if (parsed_sa_srec == NULL)
    return SLAD_TEST_ERR_INVALID_PARSED_SA;

  srec = arc4_srec = NULL;

  if (parsed_sa_srec->sa_len == 0)
    return SLAD_TEST_OK;

  get_ptrs_offset_in_dynamic_sa (parsed_sa_srec->sa_words[0],
                                 &state_ptr_offset, &arc4_ij_ptr_offset,
                                 &arc4_state_ptr_offset);

  if ((parsed_sa_srec->srec_len == 0) &&
      (state_ptr_offset || arc4_state_ptr_offset || arc4_ij_ptr_offset))
    return SLAD_TEST_ERR_SREC_REQUIRED;

  if (parsed_sa_srec->srec_len == 0)
    return SLAD_TEST_OK;

  if ((parsed_sa_srec->srec_len != SIZE_OF_DYNAMIC_SA_SREC_IN_WORDS) &&
      (parsed_sa_srec->srec_len !=
       (SIZE_OF_DYNAMIC_SA_SREC_IN_WORDS + SIZE_OF_ARC4_SREC_IN_WORDS)))
    return SLAD_TEST_ERR_INVALID_SREC_LEN;


  dynamic_sa = osal_malloc (parsed_sa_srec->sa_len * sizeof (int));


  if (dynamic_sa == NULL)
    return SLAD_TEST_ERR_MALLOC;

  *sa_len = parsed_sa_srec->sa_len * sizeof (int);

  memcpy (dynamic_sa, parsed_sa_srec->sa_words,
          parsed_sa_srec->sa_len * sizeof (int));

  if (state_ptr_offset)
    {
      srec =
        (unsigned int *)
        osal_malloc (SIZE_OF_DYNAMIC_SA_SREC_IN_WORDS * sizeof (int));
      if (srec == NULL)
        return SLAD_TEST_ERR_MALLOC;

      memcpy (srec, parsed_sa_srec->state_record,
              SIZE_OF_DYNAMIC_SA_SREC_IN_WORDS * sizeof (int));
      ((unsigned int *) dynamic_sa)[state_ptr_offset] = (unsigned int) srec;
    }
  if (arc4_state_ptr_offset)
    {
      arc4_srec =
        (unsigned int *) osal_malloc (SIZE_OF_ARC4_SREC_IN_WORDS *
                                      sizeof (int));
      if (arc4_srec == NULL)
        return SLAD_TEST_ERR_MALLOC;

      memcpy (arc4_srec,
              parsed_sa_srec->state_record + SIZE_OF_DYNAMIC_SA_SREC_IN_WORDS,
              SIZE_OF_ARC4_SREC_IN_WORDS * sizeof (int));

      ((unsigned int *) dynamic_sa)[arc4_state_ptr_offset] =
        (unsigned int) arc4_srec;

    }

  return SLAD_TEST_OK;

}

*/

int
slad_test_get_sa_n_srec (parsed_sa_n_srec * parsed_sa, void *sa, 
    void *srec, int *sa_revision, int *sa_len, 
    int *srec_len, int *srec_type       // Is it Srec or ARC4-Srec ?
  )
{

  int srec_offset = 0;
  *sa_revision = INVALID_SA_REVISION;
  sa = srec = 0;

  if (parsed_sa->sa_len == 0)
    return SLAD_TEST_ZERO_LEN_SA;

  if (parsed_sa->sa_len == SIZE_OF_REV1_SA_IN_WORDS)
    *sa_revision = REVISION1_SA;
  else if (parsed_sa->sa_len == SIZE_OF_REV2_SA_IN_WORDS)
    *sa_revision = REVISION2_SA;
  else if (parsed_sa->sa_len < MAX_SIZE_OF_DYNAMIC_SA)
    *sa_revision = DYNAMIC_SA;
  else
    {
      return SLAD_TEST_ERR_INVALID_LEN_SA;
    }


  switch (*sa_revision)
    {
    case REVISION1_SA:
      {

        *sa_len = sizeof (SLAD_SA_REV1);

        if (parsed_sa->srec_len)
          {
            if (parsed_sa->srec_len ==
                (sizeof (SLAD_STATE_RECORD_REV1) / sizeof (int)))
              {
                *srec_len = sizeof (SLAD_STATE_RECORD_REV1);
                *srec_type = SREC;
              }
            else if (parsed_sa->srec_len >=
                     (sizeof (SLAD_STATE_RECORD_ARC4) / sizeof (int)))
              {
                *srec_len = sizeof (SLAD_STATE_RECORD_ARC4);
                srec_offset =
                  parsed_sa->srec_len -
                  (sizeof (SLAD_STATE_RECORD_ARC4) / sizeof (int));
                *srec_type = ARC4_SREC;
              }
            else
              {
                LOG_CRIT ("\n Invalid State Record Length \n");
                *srec_len = 0;
              }
          }

      }
      break;

    case REVISION2_SA:
      {
        *sa_len = sizeof (SLAD_SA_REV2);
        if (parsed_sa->srec_len)
          {
            if (parsed_sa->srec_len ==
                (sizeof (SLAD_STATE_RECORD_REV2) / sizeof (int)))
              {
                *srec_len = sizeof (SLAD_STATE_RECORD_REV2);
                *srec_type = SREC;
              }
            else if (parsed_sa->srec_len >=
                     (sizeof (SLAD_STATE_RECORD_ARC4) / sizeof (int)))
              {
                *srec_len = sizeof (SLAD_STATE_RECORD_ARC4);
                srec_offset =
                  parsed_sa->srec_len -
                  (sizeof (SLAD_STATE_RECORD_ARC4) / sizeof (int));
                *srec_type = ARC4_SREC;
              }
            else
              {
                LOG_CRIT ("\n Invalid State Record Length \n");
                *srec_len = 0;
              }
          }
      }
      break;

    case DYNAMIC_SA:
      {
        *sa_len = MAX_SIZE_OF_DYNAMIC_SA;

        if (parsed_sa->srec_len)
          {
            if (parsed_sa->srec_len ==
                (sizeof (SLAD_STATE_RECORD_REV2) / sizeof (int)))
              {
                *srec_len = sizeof (SLAD_STATE_RECORD_REV2);
                *srec_type = SREC;
              }
            else if (parsed_sa->srec_len >=
                     (sizeof (SLAD_STATE_RECORD_ARC4) / sizeof (int)))
              {
                *srec_len = sizeof (SLAD_STATE_RECORD_ARC4);
                srec_offset =
                  parsed_sa->srec_len -
                  (sizeof (SLAD_STATE_RECORD_ARC4) / sizeof (int));
                *srec_type = ARC4_SREC;
              }
            else
              {
                LOG_CRIT ("\n Invalid State Record Length \n");
                *srec_len = 0;
              }
          }

      }

      break;

    default:
      LOG_CRIT ("\n Invalid SA Revision \n");

    }

  sa = (SLAD_SA *) osal_malloc (*sa_len);
  memcpy (sa, parsed_sa->sa_words, *sa_len);
  srec = osal_malloc (*srec_len);
  memcpy (srec, parsed_sa->state_record + srec_offset, *srec_len);

  return SLAD_TEST_OK;

}


void
slad_test_got_callback (int device_num)
{
  if (pdr_notification_function != NULL)
    {
      (pdr_notification_function) ();
    }

#ifdef SLAD_OSAL_IS_IN_USER_MODE
  signal_cnt++;
#else
  callback_cnt++;
#endif

}

void
slad_test_print_callback_stat (void)
{
  LOG_INFO ("Number of callback count is: %lu\n", callback_cnt);
  LOG_INFO ("Number of signal count is: %lu\n", signal_cnt);
}

void
slad_test_reset_callback_stat (void)
{
  signal_cnt = 0;
  callback_cnt = 0;
}

void
slad_test_populate_notify_objects (SLAD_NOTIFY * pdr, SLAD_NOTIFY * cdr,
                                   int use_notification)
{

#if !defined(SLAD_OSAL_IS_IN_USER_MODE )
  {
    if (use_notification)
      {

        cdr->callback = slad_test_got_callback;
        pdr->callback = slad_test_got_callback;

      }
    else
      {

        cdr->callback = NULL;
        pdr->callback = NULL;
      }

    cdr->process_id = 0;
    cdr->signal_number = 0;

    pdr->process_id = 0;
    pdr->signal_number = 0;
  }
#else
  {

    if (use_notification)
      {

        /* Install signal handler. */
        slad_osal_install_notifier (slad_test_got_callback);

        cdr->process_id = slad_osal_get_pid ();
        cdr->signal_number = slad_osal_user_signal ();

        pdr->process_id = slad_osal_get_pid ();
        pdr->signal_number = slad_osal_user_signal ();



      }
    else
      {

        cdr->process_id = 0;
        cdr->signal_number = 0;

        pdr->process_id = 0;
        pdr->signal_number = 0;
      }

    cdr->callback = 0;
    pdr->callback = 0;

  }
#endif

}

/*
BOOL slad_test_get_dma_buffer_with_properties(
  void **handle, void **buf_addr, void **bus_addr, int len,
  memalloc_method * mam,
  SLAD_DEVICEINFO * di
  )
{
    int flags, st ;

    *handle = *buf_addr = *bus_addr = 0 ;


    if( mam->sram_or_sdram == SLAD_TEST_PARSER_MEMALLOC_FROM_SDRAM )
    {
        flags = ( 
     mam->is_cached == 1 ? SLAD_NON_CACHE_COHERENT : SLAD_CACHE_COHERENT ) ;
        st =  slad_allocate_buffer( handle, buf_addr, bus_addr, len );

        if( st != SLAD_DRVSTAT_SUCCESS )
        {
            osal_printf("\n DMA Buffer Allocation Failed \n");
            return FALSE ;
        }

    }
    else // SRAM
    {
      st = slad_test_is_sram_supported ( di );
      if( st == FALSE )
      {
          osal_printf("\n SRAM is not supported for this device \n");
          return FALSE ;

      }

      if( mam->sram_len_in_bytes  < len )
      {
          osal_printf(
          "\n SRAM Mapping Size is less than requested buffer size \n");
          return FALSE ;
      }

      if( mam->_current_offset == 0 )
      {
          st = slad_map_addr_range( 
          mam->sram_start_addr, mam->sram_len_in_bytes, buf_addr );
          mem->_mapped_vaddr = *buf_addr ;

      }

      if( st != SLAD_DRVSTAT_SUCCESS)
      {
          osal_printf("\n SRAM could not be mapped \n");
          return FALSE ;
      }

      if( mam->_current_offset  >= mam->sram_len_in_bytes )
      {
          osal_printf("\n Exhausted of SRAM \n");
          return FALSE ;

      }

      *bus_addr = mam->sram_start_addr + mam->_current_offset ;
      *buf_addr = ( UINT32 ) mem->_mapped_vaddr + mam->_current_offset ;

      mam->_current_offset += len ;

      *handle = 0 ;

    }

}


BOOL slad_test_free_dma_buffer_with_properties(
  void **handle, int len,
  memalloc_method * mam,
  SLAD_DEVICEINFO * di
  )
{
    int flags, st ;

    if( mam->sram_or_sdram == SLAD_TEST_PARSER_MEMALLOC_FROM_SDRAM )
    {
        flags = ( mam->is_cached == 1 ? 
            SLAD_NON_CACHE_COHERENT : SLAD_CACHE_COHERENT ) ;
        st =  slad_free_buffer( handle, flags );

        if( st != SLAD_DRVSTAT_SUCCESS )
        {
            osal_printf("\n DMA Buffer Freeing Failed \n");
            return FALSE ;
        }

    }
    else // SRAM
    {
      st = slad_test_is_sram_supported ( di );

      if( st == FALSE )
      {
          osal_printf("\n SRAM is not supported for this device \n");
          return FALSE ;

      }

      mam->_current_offset -= len ;

      if( mam->_current_offset <= 0 )
      {
          st = slad_unmap_addr_range( mam->sram_start_addr );

          if( st != SLAD_DRVSTAT_SUCCESS)
          {
            osal_printf("\n SRAM could not be un-mapped \n");
            return FALSE ;
          }
          mem->_mapped_vaddr = 0 ;
      }

    }// else

  return TRUE ;
}

BOOL
slad_test_copy_in_2_dma_buf_with_properties(
  void *handle, void *in_buf, int offset, int len,
  memalloc_method * mam,
  SLAD_DEVICEINFO * di
)
{
      if( mam->sram_or_sdram == SLAD_TEST_PARSER_MEMALLOC_FROM_SDRAM )
      {
          st = slad_buffer_copy_in( handle, in_buf, offset, len ) ;

          if( st != SLAD_DRVSTAT_SUCCESS )
          {
              osal_printf("\n slad_buffer_copy_in() failed \n");
              return FALSE ;
          }

      }
      else // SRAM
      {
        st = slad_test_is_sram_supported ( di );

        if( st == FALSE )
        {
            osal_printf("\n SRAM is not supported for this device \n");
            return FALSE ;

        }

         // TBD : Driver should also provide copy_in and copy_out for
         // mapped memory as well.

      }

  return TRUE ;

}

BOOL
slad_test_copy_out_from_dma_buf_with_properties(
  void *handle, void *out_buf, int offset, int len,
  memalloc_method * mam,
  SLAD_DEVICEINFO * di
)
{
      if( mam->sram_or_sdram == SLAD_TEST_PARSER_MEMALLOC_FROM_SDRAM )
      {
          st = slad_buffer_copy_out( handle, out_buf, offset, len ) ;

          if( st != SLAD_DRVSTAT_SUCCESS )
          {
              osal_printf("\n slad_buffer_copy_out() failed \n");
              return FALSE ;
          }

      }
      else // SRAM
      {
        st = slad_test_is_sram_supported ( di );

        if( st == FALSE )
        {
            osal_printf("\n SRAM is not supported for this device \n");
            return FALSE ;

        }

         // TBD : Driver should also provide copy_in and copy_out for
         // mapped memory as well.

      }

  return TRUE ;

}
*/


void *
slad_test_malloc_generic (int len, int flags, void **phy_addr)
{
  void *p;

  *((UINT32 *) phy_addr) = 0;

  if (len <= 0)
    return NULL;

  switch (flags)
    {
    default:                   // Fall through
    case SLAD_TEST_BUFFER_CACHED:
      p = osal_malloc (len);
      break;

    case SLAD_TEST_BUFFER_CACHED_ALIGNED:
      p = osal_malloc_cache_aligned (len);
      break;

    case SLAD_TEST_BUFFER_NON_CACHED:  // CACHE-Coherent
      p = osal_malloc_coherent (&p, phy_addr, len);
      break;

    }

  return p;
}

void
slad_test_free_generic (void *p, int len, int flags, void *phy_addr)
{
  if (len <= 0)
    return;

  switch (flags)
    {
    default:                   // Fall through
    case SLAD_TEST_BUFFER_CACHED:
      osal_free (p, len);
      break;

    case SLAD_TEST_BUFFER_CACHED_ALIGNED:
      osal_free_cache_aligned (p, len);
      break;

    case SLAD_TEST_BUFFER_NON_CACHED:  // CACHE-Coherent
      osal_free_coherent (p, (dma_addr_t) phy_addr, len);
      break;

    }

}

#define slad_test_pe_get_command0_of_sa( command0, sa, sa_len_in_words ) \
    do{ \
        if(  ( sa_len_in_words  == SIZE_OF_REV1_SA_IN_WORDS )  ||  \
              ( sa_len_in_words  == SIZE_OF_REV2_SA_IN_WORDS )             \
        )        \
                command0 = ((UINT32 *) sa)[0] ;     \
        else     \
                command0 = ((UINT32 *) sa)[1] ;     \
        \
    }while(0)

int
slad_test_is_scatter_set (void *sa, int sa_len_in_words)
{
  int command0;

  slad_test_pe_get_command0_of_sa (command0, sa, sa_len_in_words);

  // osal_printf("\n scatter: Command 0 : %x \n", command0 );
  if (command0 >> 31)
    return TRUE;
  else
    return FALSE;

}

int
slad_test_is_gather_set (void *sa, int sa_len_in_words)
{
  int command0;

  slad_test_pe_get_command0_of_sa (command0, sa, sa_len_in_words);

  // osal_printf("\n gather: Command 0 : %x \n", command0 );

  if ((command0 >> 30) & 0x1)
    return TRUE;
  else
    return FALSE;

}

int
slad_test_is_prng_used (void *sa, int sa_len_in_words)
{
  int command0;
  int load_iv;

  slad_test_pe_get_command0_of_sa (command0, sa, sa_len_in_words);

  load_iv = (command0 >> 24) & 0x3;

  if (load_iv == 0x3)
    return TRUE;
  else
    return FALSE;

}

void
slad_test_print_device_revision (int device_num)
{
  UINT32 rev = 0;

#define SLAD_TEST_DC_DEV_INFO_REGISTER_OFFSET 0x60088
  slad_bus_read (device_num, &rev, SLAD_TEST_DC_DEV_INFO_REGISTER_OFFSET,
                 sizeof (rev));

  rev = rev & 0xff;

  LOG_INFO
("\n Device ( EIP-94 chip ) MajorVersionNumber:%d,minornumber : %d  \n",
     rev >> 4, rev & 0xf);

}
#endif

#endif
