/***********************************************************
*
* SLAD Test Application
*
*

*
* Copyright 2007-2010 AuthenTec B.V.
*
* Edit History:
*
* Initial revision created.
**************************************************************/


/********************************************************
* Definitions and macros.
*********************************************************/
#include "c_sladtestapp.h"
#ifdef SLAD_TEST_BUILD_FOR_PE
#include "api_pec.h"


#include "slad_test_parser_op_defs.h"
#include "slad_test_interface_to_parser.h"
#include "slad_test.h"
#include "slad_test_pe.h"
#include "slad_test_pe_debug.h"
#include "slad_osal.h"

extern test_conf_data test_config_g;
extern pe_conf_data pe_conf_data_g;
extern test_device device_n_test_info_g;
extern PEC_InitBlock_t initblock;

static int packet_notification = 0;

//typedef unsigned char BYTE ;

static BYTE *result;
static int result_len;
static void *dst_copy;

static int failed;

//typedef int slad_app_id_type;

static int app_id_s;
static DMABuf_Handle_t Handles[MAX_HANDLES];



static DMABuf_HostAddress_t Buffer_p[MAX_HANDLES];

static PEC_ResultDescriptor_t PE_ResultDescr;
static unsigned int GetCount;

typedef struct
{
    void *DstBuf;
} Priv_Admin;

static Priv_Admin User;
static void *User_p;


static int pkt_get_intr_received = FALSE;
static int pkt_put_intr_received = FALSE ;

static int wait_timeout_notification = FALSE;
static bool IsPktPut ;

PEC_CommandDescriptor_t PE_CommandDescr = { 0 };





/************************************************************
*
*************************************************************/
static void
pe_validate_after_pkt_get (PEC_ResultDescriptor_t * Results_p, int cnt, // Packet Count after packet get
                           PEC_Status_t st)     // Status of Packet get
{
    int compare_len;
    uint8_t Status;

    if (User_p == Results_p->User_p)
      {

          /* Was packet gotten ok? */
          if (cnt)
            {
                if (device_n_test_info_g.tests.print_in_tests)
                  {
                      LOG_CRIT
                          ("\n\t Device returned the processed packet to the driver\n");
                  }

                // Copy the result to local buffer
                memcpy (dst_copy, Results_p->DstPkt_p,
                        Results_p->DstPkt_ByteCount);


                if (st == PEC_STATUS_OK)
                  {
                      // Pkt get was sucessful
                      compare_len =
                          (result_len <
                           Results_p->
                           DstPkt_ByteCount ? result_len : Results_p->
                           DstPkt_ByteCount);

                      /* Compare the processed packet data to the expected result. */
                      if ((memcmp
                           ((void *) dst_copy, (void *) result,
                            compare_len) == 0) && compare_len)
                        {
                            LOG_CRIT
                                ("\n\t <-: Result data matches expected data :-> \n");
                            if (device_n_test_info_g.tests.print_in_tests)
                              {
                                  LOG_CRIT ("\n\t Received Data:\n");
                                  Log_HexDump ("", 0,
                                               (unsigned char *) dst_copy,
                                               compare_len);
                                  LOG_CRIT ("\n");
                              }

                            if (Results_p->DstPkt_ByteCount != result_len)
                              {
                                  LOG_CRIT
                                      ("\n\t Warning : Received len [%d] did not match expected len [%d]\n",
                                       Results_p->DstPkt_ByteCount,
                                       result_len);

                                  failed = TRUE;

                              }

                        }
                      else
                        {
                            if (compare_len)
                              {
                                  LOG_CRIT
                                      ("\n\t <-: Result data did not match expected data :-> \n");
                                  if (device_n_test_info_g.tests.
                                      print_in_tests)
                                    {
                                        LOG_CRIT
                                            ("\n\t Anyway, Received Data is :\n");
                                        Log_HexDump ("", 0,
                                                     (unsigned char *)
                                                     dst_copy, compare_len);
                                        LOG_CRIT ("\n");
                                    }
                              }

                            if ((int) Results_p->DstPkt_ByteCount !=
                                result_len)
                              {
                                  LOG_CRIT
                                      ("\n\t  Received len [%d] did not match expected len [%d]\n",
                                       Results_p->DstPkt_ByteCount,
                                       result_len);
                              }


                            Status = (Results_p->Status1 >> 16) & (0xFF);
                            if (!Status)
                                LOG_CRIT
                                    ("\n\t KAT : packet processing pdr status=0x%04x\n",
                                     Status);

                            if (result_len == 0)
                              {
                                  LOG_CRIT ("\n\t len of output is 0 \n");
                              }
                            else
                                failed = TRUE;
                        }
                  }
                else
                  {
                      LOG_CRIT
                          ("\n\t KAT : failed to get packet, pkt_get status =0x%04x\n",
                           st);
                      failed = TRUE;
                  }
            }
          else
            {
                LOG_CRIT
                    ("\n\t No packet was received on calling slad_pkt_get() \n");
                failed = TRUE;
            }
      }
    else
      {
          LOG_CRIT ("\n\t Result mismatch with command \n");
          failed = TRUE;
      }

    pkt_get_intr_received = TRUE;


}


static void
pe_result_notify_pkt_get(void)
{
    PEC_Status_t st;

	LOG_CRIT("\n Result notify callback called \n");
    if (wait_timeout_notification)
      {
          LOG_CRIT ("\n Callback not executed \n");
          failed = TRUE;
          return;
      }

    st = PEC_Packet_Get (&PE_ResultDescr, 1, &GetCount);
    pe_validate_after_pkt_get (&PE_ResultDescr, GetCount, st);

}

static void
pe_cmd_notify_pkt_put(void)
{
    PEC_Status_t PE_Status ;
    int cnt ;

    LOG_CRIT("\n CmdNotify callback called \n");

    PE_Status  = PEC_Packet_Put (&PE_CommandDescr, 1, &cnt);

    if ((PE_Status == PEC_STATUS_OK) && cnt)
      {
          LOG_INFO ("\n Packet submitted to the device \n");
          IsPktPut = TRUE ;
      }
    else
      {
          LOG_CRIT ("\n\t Failed to put  packet, drvstat=0x%08x\n",
                    PE_Status);
          IsPktPut = FALSE;
      }
    pkt_put_intr_received = TRUE;


}


static int
pe_kat (int app_id, PEC_Capabilities_t * di, pe_test_record * tr)
{
    int i;
    int src_alloc_len, dst_alloc_len, sa_len, srec_len = 0;
    int ok = TRUE ;

    void *src_copy = NULL, *sa_copy = NULL, *srec_copy = NULL;

    DMABuf_Properties_t Properties[MAX_HANDLES];
    DMABuf_Status_t dma_status;


    PEC_NotifyFunction_t CBFunc;
    DMABuf_Handle_t NULL_Handle1 = { 0 };
    DMABuf_Handle_t NULL_Handle2 = { 0 };
    bool SREC_IN_USE = false, ARC4_IN_USE = false;
    unsigned int handle_count;


    IDENTIFIER_NOT_USED (CBFunc);

    LOG_CRIT ("Record no : %d \n", tr->record_number);

    // src
    src_alloc_len = tr->pkt_data.ip_buffer_len * sizeof (int);

    Properties[0].Size = src_alloc_len;
    Properties[0].Alignment = 4;
    Properties[0].Bank = 0;
    Properties[0].fCached = true;

    // dst
    dst_alloc_len = tr->pkt_data.op_buffer_len * sizeof (int);
    Properties[1].Size = dst_alloc_len ;
    Properties[1].Alignment = 4;
    Properties[1].Bank = 0;
    Properties[1].fCached = true;

    // SA
    sa_len = tr->ip_sa_record.sa_len * sizeof (int);
    Properties[2].Size = sa_len;
    Properties[2].Alignment = 4;
    Properties[2].Bank = 0;
    Properties[2].fCached = true;

    // Srec
    if (!tr->ip_sa_record.is_arc4_srec_used)
      {
          if (tr->ip_sa_record.srec_len != 0)
            {
                LOG_INFO ("\n\t State Record being used \n");
                LOG_INFO ("\n State record len : %d \n",
                          tr->ip_sa_record.srec_len * sizeof (int));

                srec_len = tr->ip_sa_record.srec_len * sizeof (int);
                SREC_IN_USE = true;

                Properties[3].Size = srec_len;
                Properties[3].Alignment = 4;
                Properties[3].Bank = 0;
                Properties[3].fCached = true;
            }
          else
            {
                LOG_INFO ("\n STATE RECORD not in use\n");
            }
      }
    else
      {
          if (tr->ip_sa_record.arc4_srec_len != 0)
            {

                LOG_INFO ("\n\t ARC4 State Record is being used \n");
                srec_len = tr->ip_sa_record.arc4_srec_len * sizeof (int);
                ARC4_IN_USE = true;

                Properties[3].Size = srec_len;
                Properties[3].Alignment = 4;
                Properties[3].Bank = 0;
                Properties[3].fCached = true;
            }
          else
            {
                LOG_INFO ("\n STATE RECORD not in use\n");
            }
      }

    handle_count = MAX_HANDLES - 1;

    for (i = 0; i < handle_count; i++)
      {
          if (i == 3)
            {
                if (SREC_IN_USE || ARC4_IN_USE)
                  {

                      // allocate dma buffer for state record
                      dma_status = DMABuf_Alloc (Properties[i],
                                                 &Buffer_p[i], &Handles[i]);


                  }
            }
          else
           {

               // allocate dma buffer for Src, Dst and SA
                dma_status = DMABuf_Alloc (Properties[i],
                                           &Buffer_p[i], &Handles[i]);
            }

          if (dma_status != DMABUF_STATUS_OK)
            {
                LOG_CRIT ("\n DMABuf_Alloc failed with error code %d: i:%d",
                          dma_status, i);
                return FALSE;
            }
      }

	User.DstBuf = Buffer_p[1].p;        //Dst Buf
    User_p = &User;

    if (device_n_test_info_g.tests.print_in_tests)
      {
          LOG_CRIT ("\n\t Source data size : %d : bytes \n",
                    tr->pkt_data.ip_len_b);
          LOG_CRIT ("\n\t Expected Output data size : %d  : bytes  \n",
                    tr->pkt_data.op_len_b);
      }


    ///////////////////////////////////////////////////////////////////
    sa_copy = osal_malloc (sa_len);
    memcpy (sa_copy, tr->ip_sa_record.sa_words, sa_len);

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
          LOG_CRIT ("\n\t SA is :\n");
          Log_HexDump ("", 0, (unsigned char *) sa_copy, sa_len);

          if (device_n_test_info_g.tests.print_in_tests_detailed)
              slad_test_print_sa (sa_copy, sa_len / sizeof (UINT32));
      }

    if (pe_conf_data_g.byte_swap_settings ==
        SLAD_TEST_PARSER_DEVICE_BYTE_SWAP_PD)
      {

          for (i = 0; i < tr->ip_sa_record.sa_len; i++)
              ((unsigned int *) sa_copy)[i] =
                  osal_swap_endian (((unsigned int *) sa_copy)[i]);

      }

    // Copy sa to DMA buffer
    memcpy (Buffer_p[2].p, sa_copy, sa_len);


    //////////////////////////////////////////////////////////////////

    if (SREC_IN_USE || ARC4_IN_USE)
      {

          srec_copy = osal_malloc (srec_len);

          if (!tr->ip_sa_record.is_arc4_srec_used)
            {
                memcpy (srec_copy, tr->ip_sa_record.state_record, srec_len);
            }
          else
            {
                memcpy (srec_copy, tr->ip_sa_record.state_record +
                        tr->ip_sa_record.arc4_srec_offset, srec_len);
            }

          if (pe_conf_data_g.byte_swap_settings ==
              SLAD_TEST_PARSER_DEVICE_BYTE_SWAP_PD)
            {
                for (i = 0; i < tr->ip_sa_record.srec_len; i++)
                    ((unsigned int *) srec_copy)[i] =
                        osal_swap_endian (((unsigned int *) srec_copy)[i]);
            }

          if (device_n_test_info_g.tests.print_in_tests)
            {
                if (srec_len)
                  {
                      LOG_INFO
                          ("\n\t State Record of length : %d : bytes, %d words\n",
                           srec_len, srec_len / sizeof (UINT32));
                      Log_HexDump ("", 0, (unsigned char *) srec_copy,
                                   srec_len);

                      if (device_n_test_info_g.tests.print_in_tests_detailed)
                          slad_test_print_srec (srec_copy,
                                                srec_len / sizeof (UINT32));
                  }
                else
                    LOG_INFO ("\n\t State Record length is 0 \n");
            }

          // copy srec to dma buffer

          memcpy (Buffer_p[3].p, srec_copy, srec_len);

          if (ARC4_IN_USE)
            {
                // Register SA and ARC4 state record
                PEC_SA_Register (Handles[2], NULL_Handle1, Handles[3]);
            }

          if (SREC_IN_USE)
            {
                // Register SA and State record
                PEC_SA_Register (Handles[2], Handles[3], NULL_Handle1);
            }


      }
    else
      {
          // Register SA (Handle[2]), Srec  (Handle[3])
          PEC_SA_Register (Handles[2], NULL_Handle1, NULL_Handle2);
      }

    //////////////////////////////////////////////////////////////////////

    src_copy = osal_malloc (src_alloc_len);
    memcpy (src_copy, tr->pkt_data.ip_buffer, src_alloc_len);

#define NO_SWAP_FOR_DATA

#ifndef NO_SWAP_FOR_DATA
    for (i = 0; i < tr->pkt_data.ip_buffer_len; i++)
        ((unsigned int *) src_copy)[i] =
            osal_swap_endian (((unsigned int *) src_copy)[i]);
#endif

    if (device_n_test_info_g.tests.print_in_tests)
      {
          if (device_n_test_info_g.tests.print_in_tests_detailed)
            {
                LOG_CRIT ("\n\t Control / Status Word : \n");
                slad_test_print_decode_register_pe_control_status (tr->
                                                                   pkt_data.
                                                                   pd_words
                                                                   [0]);
            }

          LOG_INFO ("\n\t Source data :\n");
          Log_HexDump ("", 0, src_copy, tr->pkt_data.ip_len_b);

      }
    // Copy src to dma buffer

    memcpy (Buffer_p[0].p, src_copy, src_alloc_len);

    // Allocate buffer for local result buffer
    dst_copy = osal_malloc (dst_alloc_len);

    //////////////////////////////////////////////////////////////////////

    // known result
    result_len = tr->pkt_data.op_len_b;
    result = osal_malloc (tr->pkt_data.op_buffer_len * sizeof (int));
    // copy known result 
    memcpy (result, tr->pkt_data.op_buffer,
            tr->pkt_data.op_buffer_len * sizeof (int));

#ifndef NO_SWAP_FOR_DATA

    for (i = 0; i < tr->pkt_data.op_buffer_len; i++)
        ((unsigned int *) result)[i] =
            osal_swap_endian (((unsigned int *) result)[i]);
#endif

    // Prepare PE Command Descriptor
    PE_CommandDescr.User_p = User_p;
    PE_CommandDescr.SrcPkt_Handle = Handles[0];

  // PE_CommandDescr.SrcPkt_ByteCount = src_alloc_len;
     PE_CommandDescr.SrcPkt_ByteCount = tr->pkt_data.ip_len_b ;


    PE_CommandDescr.DstPkt_Handle = Handles[1];
    PE_CommandDescr.SA_WordCount = sa_len / sizeof (UINT32);
    PE_CommandDescr.SA_Handle1 = Handles[2];

    if (SREC_IN_USE || ARC4_IN_USE)
        PE_CommandDescr.SA_Handle2 = Handles[3];
    else
        PE_CommandDescr.SA_Handle2 = NULL_Handle1;

    PE_CommandDescr.Control1 = tr->pkt_data.pd_words[0];
    PE_CommandDescr.Control2 = tr->pkt_data.pd_words[2];


    {
        // Register Notify Function
        CBFunc = pe_result_notify_pkt_get;
        PEC_ResultNotify_Request (CBFunc, 1);

		CBFunc = pe_cmd_notify_pkt_put ;
		PEC_CommandNotify_Request(CBFunc, 1);
    }

    
    {
        int TIMEOUT_VALUE;

        osal_delay (TEST_DELAY_TIMER);
        TIMEOUT_VALUE = TEST_BUSYWAIT_COUNT;
        do
          {
              osal_delay (TEST_DELAY_TIMER);
              TIMEOUT_VALUE--;
          }
        while ( !(pkt_put_intr_received && pkt_get_intr_received) && TIMEOUT_VALUE >= 0);


        if ( !pkt_get_intr_received )
          {
              wait_timeout_notification = TRUE; // buffers can be freed safely
              LOG_CRIT ("\n Interrupt not received \n");
              failed = TRUE;
          }
        else
          {
              LOG_CRIT ("\n Interrupts received \n");              
          }
    }
	

    // Unregister SA 
    if (SREC_IN_USE)
        PEC_SA_UnRegister (Handles[2], Handles[3], NULL_Handle1);
    else if (ARC4_IN_USE)
        PEC_SA_UnRegister (Handles[2], NULL_Handle1, Handles[3]);
    else
        PEC_SA_UnRegister (Handles[2], NULL_Handle1, NULL_Handle2);

    if (device_n_test_info_g.tests.print_in_tests)
      {
          LOG_CRIT ("\n\t Expected Data :\n");
          Log_HexDump ("", 0, (unsigned char *) result, result_len);
          LOG_CRIT ("\n");
      }


    /* Free all allocated items. */
    if (src_copy)
      {
          osal_free (src_copy, src_alloc_len);
      }

    if (dst_copy)
      {
          osal_free (dst_copy, dst_alloc_len);
      }

    if (sa_copy)
      {
          osal_free (sa_copy, sa_len);
      }

    if (srec_copy)
      {
          osal_free (srec_copy, sizeof (srec_len));
      }

    if (result)
      {
          osal_free (result, result_len);
      }

    // Release DMA Buffers

    DMABuf_Release (Handles[0]);
    DMABuf_Release (Handles[1]);
 
    DMABuf_Release (Handles[2]);
    if (SREC_IN_USE || ARC4_IN_USE)
      {
          DMABuf_Release (Handles[3]);
      }

     
    return ok;
}



/***********************************************************************
*
************************************************************************/
int
slad_test_pe_cmd_notify_run_test (int app_id,
                           PEC_Capabilities_t * di, pe_test_record * tr )
                           
{
    int r = 0;

    packet_notification = TRUE ; 

    app_id_s = app_id;

    LOG_CRIT ("\n");

    if (device_n_test_info_g.tests.test_case_id_string[0] != 0)
        LOG_CRIT ("Test Case : %s \n",
                  device_n_test_info_g.tests.test_case_id_string);

    LOG_CRIT ("\n{ :->Command Notify Test \n");
   

    failed = FALSE;

    r = pe_kat (app_id_s, di, tr);

    LOG_CRIT ("\n");
    LOG_CRIT ("Command Notify Test: %-9s\n", (r && !failed) ? "PASSED" : "FAILED");
    LOG_CRIT ("\n} <-: ENDS Command Notify Test \n");

    return r;
}
#endif
