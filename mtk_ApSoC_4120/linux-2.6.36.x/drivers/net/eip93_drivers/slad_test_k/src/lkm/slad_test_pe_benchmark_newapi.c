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
#include "slad_test_pe.h"
#ifdef SLAD_TEST_BUILD_FOR_PE
#include "api_pec.h"
#include "slad_test_parser_op_defs.h"
#include "slad_test_interface_to_parser.h"
#include "slad_test.h"
#include "slad_test_pe_debug.h"
#include "slad_osal.h"
/**************************************************************
* Definitions and macros.
***************************************************************/

#define TEST_BENCHMARK_INTERVAL     1

/***************************************************************
* Local variables.
****************************************************************/

extern test_conf_data test_config_g;
extern pe_conf_data pe_conf_data_g;
extern test_device device_n_test_info_g;

static int benchmark_notification = 0;
static unsigned head = 0;

static UINT32 cnt_loop = 0;
static UINT32 cnt_put = 0;
static UINT32 cnt_put_ok = 0;
static UINT32 cnt_get = 0;
static UINT32 cnt_get_ok = 0;
static UINT32 cnt_get_n_get_ok_diff = 0;

static int app_id_s;
static int failed;

static DMABuf_Handle_t Handles[NR_TEST_PACKETS][MAX_HANDLES];
static DMABuf_HostAddress_t Buffer_p[NR_TEST_PACKETS][MAX_HANDLES];
static PEC_ResultDescriptor_t PE_ResultDescr[NR_TEST_PACKETS];

typedef struct
{
  DMABuf_HostAddress_t DstBuf;
} Priv_Admin;

static Priv_Admin User[NR_TEST_PACKETS];
static void *User_p[NR_TEST_PACKETS];

#ifndef USE_POLLING
static int intr_received = FALSE;
static int wait_timeout_notification = FALSE;
#endif

/****************************************************************
*****************************************************************/
static void
slad_test_pe_benchmark_pkt_get (void)
{
  UINT32 cnt, i;
  PEC_Status_t st;
  uint8_t Status;
#ifndef USE_POLLING
  if (wait_timeout_notification)
    {
      LOG_CRIT ("\n Callback not executed \n");
      failed = TRUE;
      return;
    }
#endif



  /* Try to get all processed packets from the driver. */
  cnt = NR_TEST_PACKETS;
  st = PEC_STATUS_OK;

  st = PEC_Packet_Get (&PE_ResultDescr[0], cnt, &cnt);

  /* Were any processed packets ready? */
  if (st == PEC_STATUS_OK)
    {
      if (cnt)
        {
          /* Increment count of how many packets were processed 
          (good or bad) by the device. */
          cnt_get += cnt;

          /* Check packet engine return status of all gotten packets. */
          for (i = 0; i < cnt; i++)
            {

              Status = (PE_ResultDescr[i].Status1 >> 16) & (0xFF);
              /* Packet processed without error? */
              if (!Status)
                {
                  /* Increment count of how many packets were 
                  processed ok by the device. */
                  cnt_get_ok++;

                }
              else
                {
                  LOG_CRIT
                    ("Benchmark Test : in pkt_get : Error Pkt Status 0x%x\n",
                     Status);
                  failed = TRUE;

                }

              cnt_get_n_get_ok_diff = cnt_get - cnt_get_ok;

            }
        }
    }
  else
    {
      LOG_CRIT
        ("Benchmark Test : failed to get packet, pkt_get status =0x%04x\n",
         st);
      failed = TRUE;

    }
#ifndef USE_POLLING
  intr_received = TRUE;
#endif

}


/***********************************************************
* Return value
* TRUE if everything seems ok, FALSE if gross error.
************************************************************/

static int
slad_test_pe_benchmark1 (int app_id,
                         PEC_Capabilities_t * di, pe_test_record * tr)
{
  UINT32 cnt, t, mbps, t_printed;
  int src_alloc_len, src_len, max_data_len, dst_alloc_len, sa_len, srec_len;
  int ok = TRUE;
  void *src_copy = NULL, *sa_copy = NULL, *srec_copy = NULL;
  UINT32 i, pkt_count;
  DMABuf_Properties_t RequestedProp[NR_TEST_PACKETS][MAX_HANDLES];
  DMABuf_Status_t dma_status;
  PEC_CommandDescriptor_t PE_CommandDescr[NR_TEST_PACKETS];
  PEC_Status_t PE_Status;
#ifndef USE_POLLING
  PEC_NotifyFunction_t CBFunc;
#endif
  DMABuf_Handle_t NULL_Handle1 = { 0 };
  DMABuf_Handle_t NULL_Handle2 = { 0 };
  bool SREC_IN_USE = false, ARC4_IN_USE = false;

  // Initialize the Command Descr
  memset (PE_CommandDescr, 0,
          sizeof (PEC_CommandDescriptor_t) * NR_TEST_PACKETS);

  LOG_CRIT ("\n Record no : %d \n", tr->record_number);

  src_alloc_len = tr->pkt_data.ip_buffer_len * sizeof (int);
  src_copy = osal_malloc (src_alloc_len);
  src_len = tr->pkt_data.ip_len_b;

  dst_alloc_len = tr->pkt_data.op_buffer_len * sizeof (int);

  sa_len = tr->ip_sa_record.sa_len * sizeof (int);
  sa_copy = osal_malloc (sa_len);

  if (!tr->ip_sa_record.is_arc4_srec_used)
    {
      srec_len = tr->ip_sa_record.srec_len * sizeof (int);
      if (srec_len)
        SREC_IN_USE = true;
    }
  else
    {
      srec_len = tr->ip_sa_record.arc4_srec_len * sizeof (int);
      if (srec_len)
        ARC4_IN_USE = true;
    }


  if (SREC_IN_USE || ARC4_IN_USE)
    srec_copy = osal_malloc (srec_len);

  if (src_copy == NULL || sa_copy == NULL)
    {
      LOG_CRIT ("\n\t Alloc failure \n");
      return FALSE;
    }
  else
    {
      memcpy (sa_copy, tr->ip_sa_record.sa_words, sa_len);

      if (pe_conf_data_g.byte_swap_settings ==
          SLAD_TEST_PARSER_DEVICE_BYTE_SWAP_PD)
        {
          for (i = 0; i < tr->ip_sa_record.sa_len; i++)
            ((unsigned int *) sa_copy)[i] =
              osal_swap_endian (((unsigned int *) sa_copy)[i]);
        }

      if (sa_len == 128)
        {
          LOG_INFO ("\n\t This is Revision 1 SA \n");
        }
      else if (sa_len == 232)
        {
          LOG_INFO ("\n\t This is Revision 2 SA \n");
        }
      else
        {
          LOG_INFO ("\n\t Size of SA is : %d \n", sa_len);
        }

      if (device_n_test_info_g.tests.print_in_tests)
        {
          LOG_CRIT ("\n SA is :\n");
          Log_HexDump ("", 0, sa_copy, sa_len);
        }
      if (device_n_test_info_g.tests.print_in_tests_detailed)
        slad_test_print_sa (sa_copy, sa_len / sizeof (UINT32));

      if (SREC_IN_USE)
        memcpy (srec_copy, tr->ip_sa_record.state_record, srec_len);

      if (ARC4_IN_USE)
        memcpy (srec_copy, tr->ip_sa_record.state_record +
                tr->ip_sa_record.arc4_srec_offset, srec_len);

      if (pe_conf_data_g.byte_swap_settings ==
          SLAD_TEST_PARSER_DEVICE_BYTE_SWAP_PD)
        {
          for (i = 0; i < tr->ip_sa_record.srec_len; i++)
            ((unsigned int *) srec_copy)[i] =
              osal_swap_endian (((unsigned int *) srec_copy)[i]);
        }

      if (device_n_test_info_g.tests.print_in_tests)
        {
          LOG_CRIT ("\n State Record \n");
          Log_HexDump ("", 0, srec_copy, srec_len);
        }

      memcpy (src_copy, tr->pkt_data.ip_buffer, src_alloc_len);
#if 0
      for (i = 0; i < tr->pkt_data.ip_buffer_len; i++)
        ((unsigned int *) src_copy)[i] =
          osal_swap_endian (((unsigned int *) src_copy)[i]);
#endif
      if (device_n_test_info_g.tests.print_in_tests)
        {
          LOG_CRIT ("\n Source data :\n");
          Log_HexDump ("", 0, src_copy, tr->pkt_data.ip_len_b);
        }

    }


  max_data_len = (tr->pkt_data.ip_len_b > tr->pkt_data.op_len_b ?
                  tr->pkt_data.ip_len_b : tr->pkt_data.op_len_b);


  for (i = 0; i < NR_TEST_PACKETS; i++)
    {
      // src
      RequestedProp[i][0].Size = src_alloc_len;
      RequestedProp[i][0].Alignment = 4;
      RequestedProp[i][0].Bank = 0;
      RequestedProp[i][0].fCached = true;

      // dst
      RequestedProp[i][1].Size = dst_alloc_len;
      RequestedProp[i][1].Alignment = 4;
      RequestedProp[i][1].Bank = 0;
      RequestedProp[i][1].fCached = true;

      // SA
      RequestedProp[i][2].Size = sa_len;
      RequestedProp[i][2].Alignment = 4;
      RequestedProp[i][2].Bank = 0;
      RequestedProp[i][2].fCached = true;

      // Srec
      if (SREC_IN_USE || ARC4_IN_USE)
        {
          RequestedProp[i][3].Size = srec_len;
          RequestedProp[i][3].Alignment = 4;
          RequestedProp[i][3].Bank = 0;
          RequestedProp[i][3].fCached = true;
        }
    }

  for (pkt_count = 0; pkt_count < NR_TEST_PACKETS; pkt_count++)
    {

      // allocate src buffer
      dma_status = DMABuf_Alloc (RequestedProp[pkt_count][0],
                                 &Buffer_p[pkt_count][0],
                                 &Handles[pkt_count][0]);

      memcpy (Buffer_p[pkt_count][0].p, src_copy, src_alloc_len);

      // allocate destination buffer
      dma_status = DMABuf_Alloc (RequestedProp[pkt_count][1],
                                 &Buffer_p[pkt_count][1],
                                 &Handles[pkt_count][1]);


      // allocate sa buffer
      dma_status = DMABuf_Alloc (RequestedProp[pkt_count][2],
                                 &Buffer_p[pkt_count][2],
                                 &Handles[pkt_count][2]);

      memcpy (Buffer_p[pkt_count][2].p, sa_copy, sa_len);


      // allocate srec buffer
      if (SREC_IN_USE || ARC4_IN_USE)
        {
          dma_status = DMABuf_Alloc (RequestedProp[pkt_count][3],
                                     &Buffer_p[pkt_count][3],
                                     &Handles[pkt_count][3]);

          memcpy (Buffer_p[pkt_count][3].p, srec_copy, srec_len);
          // Register SA (Handle[2]), Srec  (Handle[3])
          if (SREC_IN_USE)
            PEC_SA_Register (Handles[pkt_count][2], Handles[pkt_count][3],
                             NULL_Handle1);

          if (ARC4_IN_USE)
            PEC_SA_Register (Handles[pkt_count][2], NULL_Handle1,
                             Handles[pkt_count][3]);

        }
      else
        {
          Buffer_p[pkt_count][3].p = NULL;
          // Register SA (Handle[2])
          PEC_SA_Register (Handles[pkt_count][2], NULL_Handle1, NULL_Handle2);
        }

      if (dma_status != DMABUF_STATUS_OK)
        {
          LOG_CRIT ("\n DMABuf_Alloc failed with error code %d: i:%d",
                    dma_status, i);
          return FALSE;
        }

      // Store the address of the dest DMA buffer for priv administration
      User[pkt_count].DstBuf = Buffer_p[pkt_count][0];
      User_p[pkt_count] = &User[pkt_count];

    }

  for (i = 0; i < NR_TEST_PACKETS; i++)
    {
      if (device_n_test_info_g.tests.print_in_tests)
        {
          LOG_CRIT ("\n SA is :\n");
          Log_HexDump ("", 0, sa_copy, sa_len);
          LOG_CRIT ("\n State Record \n");
          Log_HexDump ("", 0, srec_copy, srec_len);
          LOG_CRIT ("\n Source data :\n");
          Log_HexDump ("", 0, src_copy, src_alloc_len);
        }

      // Fill in Command Descr
      PE_CommandDescr[i].User_p = User_p[i];
      PE_CommandDescr[i].SrcPkt_Handle = Handles[i][0];
      PE_CommandDescr[i].DstPkt_Handle = Handles[i][1];
      PE_CommandDescr[i].SrcPkt_ByteCount = src_alloc_len;

      PE_CommandDescr[i].SA_WordCount = sa_len / sizeof (UINT32);
      PE_CommandDescr[i].SA_Handle1 = Handles[i][2];

      if (SREC_IN_USE || ARC4_IN_USE)
        PE_CommandDescr[i].SA_Handle2 = Handles[i][3];
      else
        PE_CommandDescr[i].SA_Handle2 = NULL_Handle1;

      PE_CommandDescr[i].Control1 = tr->pkt_data.pd_words[0];
      PE_CommandDescr[i].Control2 = tr->pkt_data.pd_words[2];
      PE_CommandDescr[i].Bypass_WordCount = tr->pkt_data.pd_words[2] >> 24 ;
    }


  {
#ifndef USE_POLLING
    {
      // Register Notify Function
      CBFunc = slad_test_pe_benchmark_pkt_get;
      PEC_ResultNotify_Request (CBFunc, 1);
    }
#endif

    /* Init all of our timing variables. */
    head = 0;
    cnt_loop = cnt_put = cnt_put_ok = cnt_get = cnt_get_ok = 0;

    /* Wait for transition to new whole second. */
    t = osal_get_time ();
    while (osal_get_time () == t);

    /* Set the expiration time and begin the test. */
    t =
      osal_get_time () + device_n_test_info_g.tests.benchmark_time_in_seconds;
    //TEST_BENCHMARK_INTERVAL;

    t_printed = 0;
    while (t > osal_get_time () && !failed)
      {
        {
          UINT32 t_now = osal_get_time ();
          if (t_now != t_printed)
            {
              t_printed = t_now;
              LOG_CRIT ("%d.. ", t - t_now);
            }
        }

        /* Advance head (in temp variable). */
        cnt = NR_TEST_PACKETS;

        if (head >= NR_TEST_PACKETS)
          {
            head = 0;
          }


        {
          /* Increment count of how many packets we tried to submit. */
          cnt = NR_TEST_PACKETS - head;
          cnt_put += cnt;

          /* Put the packet to the driver. */
          PE_Status = PEC_Packet_Put (&PE_CommandDescr[head], cnt, &cnt);

          /* Was the packet accepted by the driver? */
          if (PE_Status == PEC_STATUS_OK)
            {
              if (cnt)
                {
                  /* Advance actual head index. */
                  head = head + cnt;

                  /* Increment count of how many packets 
                  were successfully submitted to the driver. */
                  cnt_put_ok += cnt;
                }
            }
          else
            LOG_CRIT ("\n PEC_Packet_Put failed: status returned %d \n",
                      PE_Status);
        }


        /* If not using notification, get packets by polling here. */
#ifdef USE_POLLING
        //if (!benchmark_notification)
        {
          slad_test_pe_benchmark_pkt_get ();
        }
#else
        {
          int TIMEOUT_VALUE;

          TIMEOUT_VALUE = TEST_BUSYWAIT_COUNT;
          do
            {
              osal_delay (TEST_DELAY_TIMER);
              TIMEOUT_VALUE--;
            }
          while (!intr_received && TIMEOUT_VALUE >= 0);


          if (!intr_received)
            {
              wait_timeout_notification = TRUE; // buffers can be freed safely
              LOG_CRIT ("\n Interrupt not received \n");
              failed = failed & TRUE;
            }
          else
            {
              // Register Notify Function
              intr_received=FALSE; 
              CBFunc = slad_test_pe_benchmark_pkt_get;
              PEC_ResultNotify_Request (CBFunc, 1);
              //LOG_CRIT ("\n Interrupt received \n");
              //LOG_CRIT ("\n Put one more packet \n");
            }

        }
#endif
        cnt_loop++;

      }

    /* Calculate throughput, in mega-bits per second. */
    mbps =
      ((max_data_len * cnt_get_ok) /
       (UINT32) device_n_test_info_g.tests.benchmark_time_in_seconds) /
      (UINT32) (1000000 / 8);


    /* Remove any outstanding packets from the PDR. */
    LOG_CRIT ("\nGathering for 1 seconds\n");
    t = osal_get_time () + 1;
    do
      {
        cnt = 1;
        PE_Status = PEC_Packet_Get (&PE_ResultDescr[0], 1, &cnt);
      }
    while (t > osal_get_time ());

    /* Check for any kind of failures */
    if ((cnt_get != cnt_get_ok) || !cnt_get_ok || failed || !cnt_put_ok)
      {
        ok = FALSE;
      }
    else
      ok = TRUE;
  }

  LOG_CRIT
    ("\n------------------------------------------------------------------");
  LOG_CRIT ("\n%-5s %-10s %-8s %-10s %-8s %-6s %-4s %-4s %1s", "PKT",
            "PKTS", "PKTS", "PKTS", "PKTS", "PPS", "MbPS", "LEFT", "");
  LOG_CRIT ("\n%-5s %-10s %-8s %-10s %-8s %-6s %-4s %-4s %1s", "SIZE",
            "PUT", "PUT-OK", "GOT", "GOT-OK", "", "", "OVER", "");

  LOG_CRIT
    ("\n------------------------------------------------------------------");

  LOG_CRIT ("\n%-5d %-8d%2s %-8d %-8d%2s %-8d %-6d %-4d %-4d %1s\n",
            src_len, cnt_put,
            ((cnt_put == cnt_put_ok) ? "" : "!="),
            cnt_put_ok,
            cnt_get,
            ((cnt_get == cnt_get_ok) ? "" : "!="),
            cnt_get_ok,
            cnt_get_ok /
            device_n_test_info_g.tests.benchmark_time_in_seconds, mbps,
            (cnt_put_ok - cnt_get), ((cnt_put_ok == cnt_get) ? "" : "*"));

  LOG_CRIT
    ("\n------------------------------------------------------------------\n");

//free_buffers:

  osal_free (src_copy, src_alloc_len);
  osal_free (sa_copy, sa_len);
  if (SREC_IN_USE || ARC4_IN_USE)
    osal_free (srec_copy, srec_len);


  for (i = 0; i < NR_TEST_PACKETS; i++)
    {
      if (SREC_IN_USE)
        PEC_SA_UnRegister (Handles[i][2], Handles[i][3], NULL_Handle1);
      else if (ARC4_IN_USE)
        PEC_SA_UnRegister (Handles[i][2], NULL_Handle1, Handles[i][3]);
      else
        PEC_SA_UnRegister (Handles[i][2], NULL_Handle1, NULL_Handle2);

      /* Free all allocated items. */
      DMABuf_Release (Handles[i][0]);
      DMABuf_Release (Handles[i][1]);
      DMABuf_Release (Handles[i][2]);

      if (SREC_IN_USE || ARC4_IN_USE)
        DMABuf_Release (Handles[i][3]);

    }

  return ok;
}




/**********************************************************************
*
***********************************************************************/
int
slad_test_pe_run_benchmark_test (int app_id,
                                 PEC_Capabilities_t * di, pe_test_record * tr,
                                 int notification)
{
  int r = 0;

  //benchmark_notification = notification;
  benchmark_notification = FALSE;       // It is selected at compile time now.
  failed = FALSE;

  app_id_s = app_id;

  if (device_n_test_info_g.tests.test_case_id_string[0] != 0)
    LOG_CRIT ("\n Test Case : %s \n",
              device_n_test_info_g.tests.test_case_id_string);

  LOG_CRIT ("\n { :-> Benchmark test ----------------\n");

#ifdef USE_POLLING
  LOG_INFO ("\n  Polling Mode \n");
#else
  LOG_INFO ("\n Interrupt Mode \n");
#endif

  r = slad_test_pe_benchmark1 (app_id_s, di, tr);

  /* Print a pass/fail result. */
  LOG_CRIT ("\n %s  %s\n", device_n_test_info_g.tests.test_case_id_string,
                           r ? "PASSED" : "FAILED");

  LOG_CRIT ("\n } :<- ENDS Benchmark test ----------------\n");

  return r;
}
#endif
