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
#include "slad.h"
#endif
#include "slad_test_parser_op_defs.h"
#include "slad_test_parser_op_print.h"
#include "slad_test_interface_to_parser.h"

#ifdef SLAD_TEST_BUILD_FOR_PE
#include "slad_test_pe.h"
#endif


#if defined (SLAD_TEST_BUILD_FOR_EIP28PKA) || defined (SLAD_TEST_BUILD_FOR_EIP154PKA)
#ifdef USE_NEW_API
#include "slad_test_pka_newapi.h"
#endif
#endif

#ifdef SLAD_TEST_BUILD_FOR_RNG
#ifdef USE_NEW_API
#include "slad_test_rng_newapi.h"
#else
#include "slad_test_rng.h"
#endif
#endif

#include "slad_osal.h"

#ifdef SLAD_TEST_BUILD_FOR_PE
#include "slad_test_sa_converter.h"
#endif

#ifdef SLAD_TEST_BUILD_FOR_PE
pe_conf_data pe_conf_data_g;
test_conf_data test_config_g;
#endif

#if defined (SLAD_TEST_BUILD_FOR_EIP28PKA) || defined (SLAD_TEST_BUILD_FOR_EIP154PKA)
pka_conf pka_conf_g;
#endif
#ifdef SLAD_TEST_BUILD_FOR_RNG
rng_conf rng_conf_g;
#endif

test_device device_n_test_info_g;

#ifdef SLAD_TEST_BUILD_FOR_PE
pe_test_record pe_test_record_g;
#endif

#if defined (SLAD_TEST_BUILD_FOR_EIP28PKA) || defined (SLAD_TEST_BUILD_FOR_EIP154PKA)
pka_pkt  pka_rec_g[PKA_MAX_RECORDS];
#endif

#ifdef SLAD_TEST_BUILD_FOR_RNG
parsed_rng_pkt rng_rec_g;
#endif



//#define SLAD_TEST_MAX_DEVICES 5
#ifdef SLAD_TEST_BUILD_FOR_PE
#ifndef USE_NEW_API
SLAD_DEVICEINFO devices_info_g[MAX_DEVICES];
#else
PEC_Capabilities_t devices_info_g[1];
#endif
#endif

#ifdef SLAD_TEST_BUILD_FOR_PE
int
_slad_test_configure_pe (int userland, pe_conf_data * pe_conf)
{
    int ok = TRUE;

    osal_copy_from_app (userland, &pe_conf_data_g, pe_conf,
                        sizeof (pe_conf_data));
    ok = slad_test_init_pe (&pe_conf_data_g);

    return ok;
}

int
_slad_test_configure_test (int userland, test_conf_data * tc)
{
    int ok = TRUE;
    osal_copy_from_app (userland, &test_config_g, tc,
                        sizeof (test_conf_data));



    return ok;
}
#endif

int
_slad_test_note_tests_n_device (int userland, test_device * dev)
{
    osal_copy_from_app (userland, &device_n_test_info_g, dev,
                        sizeof (test_device));

    return TRUE;
}


#ifdef SLAD_TEST_BUILD_FOR_PE
static void
purge_pe_test_record (pe_test_record * tr)
{
    if (tr->pkt_data.ip_buffer)
        osal_free (tr->pkt_data.ip_buffer,
                   tr->pkt_data.ip_buffer_len * sizeof (int));

    if (tr->pkt_data.op_buffer)
        osal_free (tr->pkt_data.op_buffer,
                   tr->pkt_data.op_buffer_len * sizeof (int));

    if (tr->pkt_data.gather_buffer)
        osal_free (tr->pkt_data.gather_buffer,
                   tr->pkt_data.gather_len * sizeof (int));

    osal_bzero (tr, sizeof (pe_test_record));
}

static int
copy_pe_test_record (int userland, pe_test_record * dst, pe_test_record * src)
{
    int ok = 1;

    osal_copy_from_app (userland, dst, src, sizeof (pe_test_record));

    dst->pkt_data.gather_buffer = NULL;
    dst->pkt_data.ip_buffer = dst->pkt_data.op_buffer = NULL;

    if (dst->pkt_data.ip_buffer_len)
      {
          dst->pkt_data.ip_buffer = (unsigned char *)
              osal_malloc (dst->pkt_data.ip_buffer_len * sizeof (int));

          ok = ok && (dst->pkt_data.ip_buffer ? 1 : 0);
      }

    if (dst->pkt_data.op_buffer_len)
      {
          dst->pkt_data.op_buffer = (unsigned char *)
              osal_malloc (dst->pkt_data.op_buffer_len * sizeof (int));

          ok = ok && (dst->pkt_data.op_buffer ? 1 : 0);

      }

    if (dst->pkt_data.gather_len)
      {
          dst->pkt_data.gather_buffer = (unsigned int *)
              osal_malloc (dst->pkt_data.gather_len * sizeof (int));

          ok = ok && (dst->pkt_data.gather_buffer ? 1 : 0);
      }

    if (!ok)
      {
          LOG_CRIT ("\n Memory allocation failed \n");
          return FALSE;
      }
      
    osal_copy_from_app (userland, dst->pkt_data.ip_buffer,
                        src->pkt_data.ip_buffer,
                        dst->pkt_data.ip_buffer_len * sizeof (int)); 
                       
    osal_copy_from_app (userland, dst->pkt_data.op_buffer,
                        src->pkt_data.op_buffer,
                        dst->pkt_data.op_buffer_len * sizeof (int));

    osal_copy_from_app (userland, dst->pkt_data.gather_buffer,
                        src->pkt_data.gather_buffer,
                        dst->pkt_data.gather_len * sizeof (int));

    return TRUE;
}


static void
slad_test_pe_exec_tests (tests_2_exec * tests, pe_test_record * tr,
                         int notification)
{
    int i;
    int ok;
#ifndef USE_NEW_API
    SLAD_DEVICEINFO *di;
    int status;
#else
    PEC_Capabilities_t *di;
    PEC_Status_t status;
#endif

    for (i = 0; i < 1 /*MAX_DEVICES */ ; i++)
      {
          di = &devices_info_g[i];
#ifndef USE_NEW_API
          status = slad_device_info (i, di);
#else
          status = PEC_Capabilities_Get (di);
#endif

#ifndef USE_NEW_API
          if ((status == SLAD_DRVSTAT_SUCCESS) && is_device_initialized_g[i])
#else
          if (status == PEC_STATUS_OK)
#endif
            {

                if (tests->kat)
                  {
                      ok = slad_test_pe_kat_run_test (app_id_g[i], di, tr,
                                                      notification);
                      if (!ok)
                          LOG_CRIT ("\n Packet Engine : KAT failed \n");
                  }
				
				 if (tests->command_notify)
                  {
#ifdef SLAD_TEST_EIP93_BUILD				  
                      ok = slad_test_pe_cmd_notify_run_test(app_id_g[i], di, tr ) ;
                                                      
                      if (!ok)
                          LOG_CRIT ("\n Packet Engine : Command Notify Test failed \n");
#endif // SLAD_TEST_EIP93_BUILD
                  }
				 
                if (tests->benchmark)
                  {
                      ok = slad_test_pe_run_benchmark_test (app_id_g[i], di,
                                                            tr, notification);
                      if (!ok)
                          LOG_CRIT
                              ("\n Packet Engine : Benchmark Test failed \n");
                  }
                if (tests->stress)
                  {
                      ok = slad_test_pe_run_stress_test (app_id_g[i], di, tr,
                                                         notification);
                      if (!ok)
                          LOG_CRIT
                              ("\n Packet Engine : Stress Test failed \n");
                  }

                if (tests->intr_throttle)
                {
                   ok = slad_test_pe_run_interruptthrott_test (app_id_g[i], di, tr,
                                                               notification);
                   if (!ok)
                       LOG_CRIT
                              ("\n Packet Engine : Input Throttling Test failed \n");
               }
                   
                    
#ifndef USE_NEW_API
                if (tests->intr_coal)
                  {
                      ok = slad_test_pe_run_intr_coal_test (app_id_g[i], di,
                                                            tr, notification);
                      if (!ok)
                          LOG_CRIT
                              ("\n Packet Engine : Interrupt coalescing Test failed \n");
                  }
                if (tests->scatter_gather)
                  {
                      ok = slad_test_pe_sg (app_id_g[i], di, tr);
                      if (!ok)
                          LOG_CRIT
                              ("\n Packet Engine : Scatter-Gather Test failed \n");
                  }
#endif
            }
      }

}

#ifndef  SIZE_OF_REV1_SA_IN_WORDS

#define  SIZE_OF_REV1_SA_IN_WORDS   32
#define  SIZE_OF_REV1_SREC_IN_WORDS    10

#define SIZE_OF_EIP93_I_SREC_IN_WORDS_IN_VP_FILES  14

#define  SIZE_OF_REV2_SA_IN_WORDS    58
#define  SIZE_OF_REV2_SREC_IN_WORDS    22
#define  MAX_SIZE_OF_DYNAMIC_SA      59
#define INVALID_SA_REVISION -1
#define REVISION1_SA 1
#define REVISION2_SA 2
#define DYNAMIC_SA   10

#define REVISION1_SREC 1
#define REVISION2_SREC 2
#define REVISON_ARC4   10

#define SIZE_OF_DYNAMIC_SA_SREC_IN_WORDS 22
#define SIZE_OF_ARC4_SREC_IN_WORDS     64

#define SIZE_OF_REV1_SA_IN_WORDS    32
#define SIZE_OF_REV1_SREC_IN_WORDS    10

#define SIZE_OF_REV2_SA_IN_WORDS    58
#define SIZE_OF_REV2_SREC_IN_WORDS    22

#define MAX_SIZE_OF_DYNAMIC_SA      59


#endif
/*
  State Record filter
*/
static int
sa_state_record_set_revision (parsed_sa_n_srec * sa_n_srec)
{
    switch (sa_n_srec->sa_len)
      {
      case SIZE_OF_REV1_SA_IN_WORDS:
          sa_n_srec->sa_rev = REVISION1_SA;
          break;

      case SIZE_OF_REV2_SA_IN_WORDS:
          sa_n_srec->sa_rev = REVISION2_SA;
          break;

      default:
          if (sa_n_srec->sa_len <= MAX_SIZE_OF_DYNAMIC_SA)
              sa_n_srec->sa_rev = DYNAMIC_SA;
          else
            {
                LOG_CRIT ("\n FATAL error Invalid SA size: %d  words. \n",
                          sa_n_srec->sa_len);
                return FALSE;
            }
      }

    if (sa_n_srec->total_srec_len)
      {
          sa_n_srec->is_srec_used = 1;
          switch (sa_n_srec->sa_rev)
            {
            case REVISION1_SA:
#ifndef SLAD_TEST_EIP93_BUILD
                sa_n_srec->srec_len = SIZE_OF_REV1_SREC_IN_WORDS;

                LOG_INFO ("\n sa_n_srec->total_srec_len : %d \n",
                          sa_n_srec->total_srec_len);

                if ((sa_n_srec->total_srec_len > SIZE_OF_REV1_SREC_IN_WORDS)
                    && (sa_n_srec->total_srec_len !=
                        SIZE_OF_EIP93_I_SREC_IN_WORDS_IN_VP_FILES))
                  {
                      if (sa_n_srec->total_srec_len >
                          SIZE_OF_ARC4_SREC_IN_WORDS)
                        {
                            sa_n_srec->arc4_srec_len =
                                sa_n_srec->total_srec_len -
                                SIZE_OF_REV1_SREC_IN_WORDS;
                            sa_n_srec->arc4_srec_offset =
                                SIZE_OF_REV1_SREC_IN_WORDS;
                        }
                      else
                        {
                            sa_n_srec->arc4_srec_len =
                                SIZE_OF_ARC4_SREC_IN_WORDS;
                            sa_n_srec->arc4_srec_offset = 0;
                        }
                      sa_n_srec->is_arc4_srec_used = 1;
                  }
                else
                  {
                      sa_n_srec->arc4_srec_len = 0;
                      sa_n_srec->is_arc4_srec_used = 0;
                      sa_n_srec->arc4_srec_offset = 0;
                  }
#else
// EIP-93 specific
				sa_n_srec->srec_len = sa_n_srec->total_srec_len ;

                LOG_INFO ("\n sa_n_srec->total_srec_len : %d \n",
                          sa_n_srec->total_srec_len);

                if ( sa_n_srec->total_srec_len >  SIZE_OF_ARC4_SREC_IN_WORDS )
                	{
                        sa_n_srec->arc4_srec_len =
                                SIZE_OF_ARC4_SREC_IN_WORDS ;
						sa_n_srec->srec_len = sa_n_srec->total_srec_len -
								SIZE_OF_ARC4_SREC_IN_WORDS ;
							
                        sa_n_srec->arc4_srec_offset =
                               sa_n_srec->srec_len ;
                        
                     
                        sa_n_srec->is_arc4_srec_used = 1;
                  }
                else
                  {
                      sa_n_srec->arc4_srec_len = 0;
                      sa_n_srec->is_arc4_srec_used = 0;
                      sa_n_srec->arc4_srec_offset = 0;
                  }
				  
#endif // SLAD_TEST_EIP93_BUILD				  
                break;

            case DYNAMIC_SA:   /* Fall through */
            case REVISION2_SA:
                sa_n_srec->srec_len = SIZE_OF_REV2_SREC_IN_WORDS;
                if (sa_n_srec->total_srec_len > SIZE_OF_REV2_SREC_IN_WORDS)
                  {
                      if (sa_n_srec->total_srec_len >
                          SIZE_OF_ARC4_SREC_IN_WORDS)
                        {
                            sa_n_srec->arc4_srec_len =
                                sa_n_srec->total_srec_len -
                                SIZE_OF_REV2_SREC_IN_WORDS;
                            sa_n_srec->arc4_srec_offset =
                                SIZE_OF_REV2_SREC_IN_WORDS;
                        }
                      else
                        {
                            sa_n_srec->arc4_srec_len =
                                SIZE_OF_ARC4_SREC_IN_WORDS;
                            sa_n_srec->arc4_srec_offset = 0;
                        }
                      sa_n_srec->is_arc4_srec_used = 1;
                  }
                else
                  {
                      sa_n_srec->arc4_srec_len = 0;
                      sa_n_srec->is_arc4_srec_used = 0;
                      sa_n_srec->arc4_srec_offset = 0;
                  }
                break;
            }
      }
    else
      {
          sa_n_srec->srec_len = 0;
          sa_n_srec->arc4_srec_len = 0;
          sa_n_srec->is_srec_used = 0;
          sa_n_srec->is_arc4_srec_used = 0;
          sa_n_srec->arc4_srec_offset = 0;
      }

    return TRUE;

}


int
_slad_test_note_pe_test_record (int userland, pe_test_record * tr)
{
    int ok = FALSE;


    ok = copy_pe_test_record (userland, &pe_test_record_g, tr);

    if (!ok)
        return FALSE;

#define SA_REVISION_FILTER


#ifdef SA_REVISION_FILTER
    sa_state_record_set_revision (&pe_test_record_g.ip_sa_record);
#endif


    /*
       int
       slad_convert_sa (unsigned int *generic_sa, int *sa_len, 
       device_type_conf dev_type);

       int
       slad_convert_srec (unsigned int *generic_srec, int *srec_len, 
       device_type_conf dev_type);
     */

    ok = slad_convert_sa (pe_test_record_g.ip_sa_record.sa_words,
                          &pe_test_record_g.ip_sa_record.sa_len,
                          pe_test_record_g.ip_sa_record.device_conf);
    if (!ok)
        return FALSE;

    if (pe_test_record_g.ip_sa_record.is_srec_used)
      {
          if (pe_test_record_g.ip_sa_record.is_arc4_srec_used)
            {
                ok = slad_convert_srec (pe_test_record_g.ip_sa_record.
                                        state_record,
                                        &pe_test_record_g.ip_sa_record.
                                        total_srec_len,
                                        pe_test_record_g.ip_sa_record.
                                        device_conf);
                if (!ok)
                    return FALSE;
            }
          else
            {
                ok = slad_convert_srec (pe_test_record_g.ip_sa_record.
                                        state_record,
                                        &pe_test_record_g.ip_sa_record.
                                        srec_len,
                                        pe_test_record_g.ip_sa_record.
                                        device_conf);
                if (!ok)
                    return FALSE;
            }
      }

    slad_test_pe_exec_tests (&device_n_test_info_g.tests,
                             &pe_test_record_g,
                             pe_conf_data_g.use_interrupts);


    purge_pe_test_record (&pe_test_record_g);
    return TRUE;
}
#endif


#if defined (SLAD_TEST_BUILD_FOR_EIP28PKA) || defined (SLAD_TEST_BUILD_FOR_EIP154PKA)
static int
copy_pka_record (int userland, pka_pkt * dst, parsed_pka_pkt * src)
{
    int ok = 1;
    int i;
    unsigned short a = 0x0102;
    unsigned char *p;
    int j, k;

    //osal_copy_from_app (userland, dst, src, sizeof (parsed_pka_pkt));    
    dst->num_pka_datablk = src->num_pka_datablk;

    // Initialize the buffers to NULL
    for (i = 0; i < PKA_MAX_HANDLES; i++)
      {
          dst->buf_len[i] = src->buf_len[i];
          if (dst->buf_len[i])
              dst->databuf[i] = NULL;
      }

    for (i = 0; i < PKA_MAX_HANDLES; i++)
      {
          if (dst->buf_len[i])
            {
                dst->databuf[i] =
                    (unsigned char *) osal_malloc (dst->buf_len[i] *
                                                   sizeof (int));
                ok = ok && (dst->databuf[i] ? 1 : 0);
            }
      }

    if (!ok)
    {
          LOG_CRIT ("\n Memory allocation failed \n");
          return FALSE;
    }

    // Copy data to allocated buffers
    for (i = 0; i < PKA_MAX_HANDLES; i++)
      {
          if (dst->buf_len[i])
            {
                p = (unsigned char *) &a;
                if (*p == 0x01) // Big-Endian
                  {
                      for (j = 0, k = 0; j < dst->buf_len[i]; j++)
                        {
                            dst->databuf[i][k++] =
                                (unsigned char) (src->
                                                 data_buf[i][j] & 0x000000FF);
                            dst->databuf[i][k++] =
                                (unsigned
                                 char) ((src->
                                         data_buf[i][j] & 0x0000FF00) >> 8);
                            dst->databuf[i][k++] =
                                (unsigned
                                 char) ((src->
                                         data_buf[i][j] & 0x00FF0000) >> 16);
                            dst->databuf[i][k++] =
                                (unsigned
                                 char) ((src->
                                         data_buf[i][j] & 0xFF000000) >> 24);
                        }
                  }
                else
                  {
                      // Liitle-Endian
                      osal_copy_from_app (userland, dst->databuf[i],
                                          src->data_buf[i],
                                          dst->buf_len[i] * sizeof (int));
                  }
            }
      }

#if defined (SLAD_TEST_BUILD_FOR_EIP154PKA)
    // Copy the command and result descriptor
    for (i = 0; i < PKA_MAX_DESCR_HANDLES; i++)
      {
          dst->commres_len[i] = src->commres_len[i];
          if (dst->commres_len[i])
              dst->commres_buf[i] = NULL;
      }

    for (i = 0; i < PKA_MAX_DESCR_HANDLES; i++)
      {
          if (dst->commres_len[i])
            {
                dst->commres_buf[i] =
                    (unsigned int *) osal_malloc (dst->commres_len[i] *
                                                  sizeof (int));
                ok = ok && (dst->commres_buf[i] ? 1 : 0);
            }
      }

    for (i = 0; i < PKA_MAX_DESCR_HANDLES; i++)
      {
          if (dst->commres_len[i])
            {
                osal_copy_from_app (userland, dst->commres_buf[i],
                                    src->commres_buf[i],
                                    dst->commres_len[i] * sizeof (int));
            }
      }

#endif

#if defined (SLAD_TEST_BUILD_FOR_EIP28PKA)
    if (src->pkcp_shiftval)
        dst->pkcp_shiftval = src->pkcp_shiftval;

    dst->pkcp_command = src->pkcp_command;
#endif

    //LOG_CRIT ("\n interface_to_parser pkt data\n");
    //slad_test_print_pka_pkt (dst);

    return TRUE;
}
#endif


#if defined (SLAD_TEST_BUILD_FOR_EIP28PKA) || defined (SLAD_TEST_BUILD_FOR_EIP154PKA)
static void
purge_pka_record (pka_pkt * blk)
{
    unsigned int i;

    for (i = 0; i < PKA_MAX_HANDLES; i++)
      {
          if (blk->databuf[i])
              osal_free (blk->databuf[i], blk->buf_len[i] * sizeof (int));
      }

#if defined (SLAD_TEST_BUILD_FOR_EIP154PKA)
    for (i = 0; i < PKA_MAX_DESCR_HANDLES; i++)
      {
          if (blk->commres_buf[i])
              osal_free (blk->commres_buf[i],
                         blk->commres_len[i] * sizeof (int));
      }
#endif

    osal_bzero (blk, sizeof (pka_pkt));

}
#endif


#if defined (SLAD_TEST_BUILD_FOR_EIP28PKA) || defined (SLAD_TEST_BUILD_FOR_EIP154PKA)
static void
slad_test_pka_exec_tests (tests_2_exec * tests, pka_pkt * pkt)
{
    int ok;
    int device_num = 1;

    // Known-Answer Test
    if (tests->kat)
    {
          LOG_CRIT ("\n KAT Test Execution starts \n");
          ok = slad_test_pka_kat (device_num, pkt);
          if (!ok)
             LOG_CRIT ("\n\t>> PKA : KAT failed \n");

    }

#if defined (SLAD_TEST_BUILD_FOR_EIP154PKA)
    if (tests->fLinked)
    {
      // flinked bit test
      LOG_CRIT ("\n Callinh pka_postflinked test\n");
      ok = slad_test_pka_posflinked (pkt);
          if (!ok)
             LOG_CRIT ("\n\t>> PKA : fLinked Bit KAT failed \n");
    }

    if (tests->ringinorder)
    {
       // Ringinorder Test
       LOG_CRIT ("\n Calling fRingInOrder Test \n");
       ok = slad_test_pka_ringinorder (pkt);
       if (!ok)
           LOG_CRIT ("\n \t>> PKA : Ringinorder KAT Failed \n");
    }  

    if (tests->intr_coal)
    {
       // Interrupt Coalescing Test
       LOG_CRIT ("\n Calling Interrupt Coalescing Test \n");
       ok = slad_test_pka_intercoalescing (device_num, pkt);
       if (!ok)
           LOG_CRIT ("\n \t>> PKA : Interrupt Coalescing Test Failed \n");
    }  

    if ((tests->multiple_rings && tests->fixed_priority) 
        || (tests->multiple_rings && tests->fixed_restrotating))
    {
       // Interrupt Coalescing Test
       LOG_CRIT ("\n Calling Multiple Ring Test with Fixed Priority \n");
       ok = slad_test_pka_multirings_ringprio_fixed (device_num, pkt);
       if (!ok)
           LOG_CRIT ("\n \t>> PKA : Multiple Ring Test with Fixed Priority Test Failed \n");
    }  
    if (tests->multiple_rings && tests->rotating_priority) 
    {
       // Interrupt Coalescing Test
       LOG_CRIT ("\n Calling Multiple Ring Test with Rotating Priority \n");
       ok = slad_test_pka_multirings_ringprio_rotating (device_num, pkt);
       if (!ok)
           LOG_CRIT ("\n \t>> PKA : Multiple Ring Test with Rotating Priority Test Failed \n");
    }  

    if ( tests->test_kdk )
    {
       // KDK test
       LOG_CRIT ("\n Calling KDK Test \n");
       ok = slad_test_pka_kdk( pkt ) ; 
       if (!ok)
           LOG_CRIT ("\n \t>> PKA : KDK Test Failed \n");
    }

    // Benchmark Test
    if (tests->benchmark)
    {
        LOG_CRIT ("\n Benchmark Test Execution starts \n");
        ok = slad_test_pka_benchmark (device_num, pkt);
        if (!ok)
           LOG_CRIT ("\n\t>> PKA : Benchmark Test failed \n");
    }

    // Stress Test
    if (tests->stress)
    {
        LOG_CRIT ("\n Stress Test Execution starts \n");
        ok = slad_test_pka_stress (device_num, pkt);
        if (!ok)
           LOG_CRIT ("\n\t>> PKA : Stress Test failed \n");
    }

#endif
}
#endif


#if defined (SLAD_TEST_BUILD_FOR_EIP28PKA) || defined (SLAD_TEST_BUILD_FOR_EIP154PKA)
int
_slad_test_note_pka_record (int userland, parsed_pka_pkt * pkt, unsigned int num_pkts)
{
    int ok = FALSE;
    int i;

    for (i=0; i<num_pkts; i++)
    {
         if (pkt+i)    
         {
            ok = copy_pka_record (userland, pka_rec_g+i, pkt+i);
         }
    }

    if (!ok)
        return FALSE;

    // Do Tests here
    slad_test_pka_exec_tests (&device_n_test_info_g.tests, pka_rec_g);

    for (i=0; i<num_pkts; i++)
    {
         if (pka_rec_g + i)    
            purge_pka_record (pka_rec_g + i);
    }

    return TRUE;

}

#endif


#ifdef SLAD_TEST_BUILD_FOR_RNG
int
_slad_test_note_rng_record (int userland, parsed_rng_pkt * pkt)
{
    int ok = TRUE;
    int device_num = rng_device_num_g;  // To do
    osal_copy_from_app (userland, &rng_rec_g, pkt, sizeof (parsed_rng_pkt));

    if (rng_rec_g.size)
      {
          rng_rec_g.out_buf = (unsigned char *)
              osal_malloc (rng_rec_g.size * sizeof (int));
          if (!rng_rec_g.out_buf)
              return FALSE;

          ok = slad_test_random (device_num, &rng_rec_g);
      }


    if (rng_rec_g.out_buf)
        osal_free (rng_rec_g.out_buf, rng_rec_g.size * sizeof (int));

    rng_rec_g.size = 0;
    return ok;
}

#endif


#if defined (SLAD_TEST_BUILD_FOR_EIP28PKA) || defined (SLAD_TEST_BUILD_FOR_EIP154PKA)
int
_slad_test_configure_pka (int userland, pka_conf * pc)
{
    int ok = TRUE;
    osal_copy_from_app (userland, &pka_conf_g, pc, sizeof (pka_conf));

    ok = slad_test_pka_initialize (&pka_conf_g);

    return ok;
}
#endif

#ifdef SLAD_TEST_BUILD_FOR_RNG

int
_slad_test_configure_rng (int userland, rng_conf * rc)
{
    int ok = TRUE;
    osal_copy_from_app (userland, &rng_conf_g, rc, sizeof (rng_conf));

    ok = slad_test_rng_initialize (&rng_conf_g);

    return ok;
}

#endif

//////////////////////////////////////////////////////////


#ifdef SLAD_TEST_BUILD_FOR_PE
int
slad_test_configure_pe (pe_conf_data * pe_conf)
{
    int status;
    status = _slad_test_configure_pe (TRUE, pe_conf);
    return status;
}
#endif


#if defined (SLAD_TEST_BUILD_FOR_EIP28PKA) || defined (SLAD_TEST_BUILD_FOR_EIP154PKA)
int
slad_test_configure_pka (pka_conf * pc)
{
    int status;
    status = _slad_test_configure_pka (TRUE, pc);
    return status;
}
#endif


#ifdef SLAD_TEST_BUILD_FOR_RNG
int
slad_test_configure_rng (rng_conf * rc)
{
    int status;
    status = _slad_test_configure_rng (TRUE, rc);
    return status;

}
#endif


#ifdef SLAD_TEST_BUILD_FOR_PE
int
slad_test_configure_test (test_conf_data * tc)
{
    int status;
    status = _slad_test_configure_test (TRUE, tc);
    return status;
}
#endif


int
slad_test_note_tests_n_device (test_device * dev)
{
    int status;
    status = _slad_test_note_tests_n_device (TRUE, dev);

    return status;
}


#ifdef SLAD_TEST_BUILD_FOR_PE
int
slad_test_note_pe_test_record (pe_test_record * tr)
{
    int status;
    status = _slad_test_note_pe_test_record (TRUE, tr);
    return status;
}
#endif


#if defined (SLAD_TEST_BUILD_FOR_EIP28PKA) || defined (SLAD_TEST_BUILD_FOR_EIP154PKA)
int
slad_test_note_pka_record (parsed_pka_pkt * pkt, unsigned int num_pkts)
{
    int status;
    status = _slad_test_note_pka_record (TRUE, pkt, num_pkts);
    return status;
}
#endif


#ifdef SLAD_TEST_BUILD_FOR_RNG
int
slad_test_note_rng_record (parsed_rng_pkt * pkt)
{
    int status;
    status = _slad_test_note_rng_record (TRUE, pkt);
    return status;
}
#endif



int
slad_test_uninit_devices (void)
{
    int ok = TRUE;
#ifdef SLAD_TEST_BUILD_FOR_PE
    slad_test_uninit_pe ();
#endif

    return ok;
}


////////////////////////////////////////////////////////////
