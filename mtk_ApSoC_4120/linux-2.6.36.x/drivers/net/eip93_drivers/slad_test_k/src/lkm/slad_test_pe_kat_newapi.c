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


/********************************************************
* Definitions and macros.
*********************************************************/
#include "c_sladtestapp.h"
#ifdef SLAD_TEST_BUILD_FOR_PE
#include "api_pec.h"
#if defined(TEST_PEC_GATHER) || defined(TEST_PEC_SCATTER) 
#include "api_pec_sg.h"
#endif // (TEST_PEC_GATHER) || (TEST_PEC_SCATTER) 

#include "slad_test_parser_op_defs.h"
#include "slad_test_interface_to_parser.h"
#include "slad_test.h"
#include "slad_test_pe.h"
#include "slad_test_pe_debug.h"
#include "slad_osal.h"

#ifdef RT_EIP93_DRIVER
#define VPint *(volatile unsigned int *)
#endif

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
DMABuf_Handle_t Handles[MAX_HANDLES];

#ifdef TEST_PEC_GATHER
static DMABuf_Handle_t GatherSrcHandles
        [TEST_PEC_GATHER_MAX_DESCRIPTORS];
static DMABuf_HostAddress_t GatherSrcBuffers
        [TEST_PEC_GATHER_MAX_DESCRIPTORS] ;
#endif

#ifdef TEST_PEC_SCATTER
static DMABuf_Handle_t ScatterDstHandles
        [TEST_PEC_SCATTER_MAX_DESCRIPTORS];
static DMABuf_HostAddress_t ScatterDstBuffers
        [TEST_PEC_SCATTER_MAX_DESCRIPTORS] ;
#endif 




#ifndef TEST_BOUNCEBUFFERS
static DMABuf_HostAddress_t Buffer_p[MAX_HANDLES];
#endif
static PEC_ResultDescriptor_t PE_ResultDescr;
static unsigned int GetCount;

typedef struct
{
    void *DstBuf;
} Priv_Admin;

Priv_Admin User;
void *User_p;

#ifndef USE_POLLING
static int intr_received = FALSE;
static int wait_timeout_notification = FALSE;
#endif

#ifdef TEST_BOUNCEBUFFERS
void *testbuf[MAX_HANDLES];
#endif

/************************************************************
*
*************************************************************/
static void
pe_validate_after_pkt_get (PEC_ResultDescriptor_t * Results_p, int cnt, // Packet Count after packet get
                           PEC_Status_t st)     // Status of Packet get
{
    int compare_len;
    uint8_t Status;
#ifdef TEST_PEC_SCATTER    
    unsigned int PreloadAcceptedCount ;
#endif    


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
                
#ifndef TEST_PEC_SCATTER
                // Copy the result to local buffer
                memcpy (dst_copy, Results_p->DstPkt_p,
                        Results_p->DstPkt_ByteCount);
#else
                {
                    int NumParticlesRead=0 ;                   
                    PEC_Status_t St ;
                    int ParticleLen=0, TotalReadLen=0 ;
                    DMABuf_Handle_t FragmentHandle ;
                    uint8_t * FragmentPtr_p ;
                    DMABuf_Handle_t SGList_Scatter_Handle_Received ;
                    SGList_Scatter_Handle_Received = 
                            Results_p->DstPkt_Handle ;

                    do
                    {
                        St = PEC_SGList_Read(
                                SGList_Scatter_Handle_Received,
                                NumParticlesRead,
                                &FragmentHandle,
                                &ParticleLen,
                                &FragmentPtr_p);
                        
                        if(St != PEC_STATUS_OK )
                        {
                           LOG_CRIT(
                            "Scatter:PEC_SGList_Read: failed: %d\n",
                             St );
                           failed = TRUE ;
                           break ;
                           
                        }
                       
                        memcpy(
                            (unsigned char * )dst_copy + TotalReadLen,
                             FragmentPtr_p,
                             ParticleLen );

                         LOG_INFO("\n Scatter Particle pointer:%p \n ", 
                            FragmentPtr_p );
                         
                         LOG_INFO("\nParticleLen:%d\n ", 
                            ParticleLen );
                         //Log_HexDump("ScatterParticle dump", 0, FragmentPtr_p,
                          // ParticleLen );
                            
                        TotalReadLen+= ParticleLen ;

                        if(ParticleLen)
                            PEC_Scatter_Preload(
                                &FragmentHandle, 1, &PreloadAcceptedCount ) ;

                        NumParticlesRead++ ;
                        
                        LOG_INFO(
                        "Scatter:NumParticlesRead:%d, data len for this particle:%d \n", 
                         NumParticlesRead,
                         ParticleLen);
                        
                    }while( ParticleLen != 0 );
                    
                
                }
#endif

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
#ifndef USE_POLLING
    intr_received = TRUE;
#endif

}


static void
pe_kat_pkt_get (void)
{
    PEC_Status_t st;
#ifdef USE_POLLING
    unsigned int LoopCount = TEST_BUSYWAIT_COUNT;
    int wait_ms = TEST_DELAY_TIMER;
    while (LoopCount > 0)
    {
          /* Try to get the processed packet from the driver. */
          st = PEC_Packet_Get (&PE_ResultDescr, 1, &GetCount);
          if (!GetCount)
            {
                osal_delay (wait_ms);
                LoopCount--;
                continue;
            }
          break;
      }

#ifdef RT_EIP93_DRIVER_DEBUG
    LOG_CRIT("\n[pe_kat_pkt_get] function:\n");
    LOG_CRIT("\tstatus:%d, GetCount:%d\n\n", st, GetCount);  
#endif
          
    if (GetCount)
        pe_validate_after_pkt_get (&PE_ResultDescr, GetCount, st);
    else
      {
          LOG_CRIT
              ("\n No packet received from device, pkt get count zero, PEC_Status: %d\n", st);
          failed = TRUE;
      }
#else
    if (wait_timeout_notification)
      {
          LOG_CRIT ("\n Callback not executed \n");
          failed = TRUE;
          return;
      }

    st = PEC_Packet_Get (&PE_ResultDescr, 1, &GetCount);
    pe_validate_after_pkt_get (&PE_ResultDescr, GetCount, st);
#endif
}



static int
pe_kat (int app_id, PEC_Capabilities_t * di, pe_test_record * tr)
{
    UINT32 cnt, i;
    int src_alloc_len, dst_alloc_len, sa_len, srec_len = 0;
    int ok = FALSE;

    void *src_copy = NULL, *sa_copy = NULL, *srec_copy = NULL;

    DMABuf_Properties_t Properties[MAX_HANDLES];
    DMABuf_Status_t dma_status = DMABUF_STATUS_OK;
    PEC_CommandDescriptor_t PE_CommandDescr = { 0 };
    PEC_Status_t PE_Status;
    PEC_NotifyFunction_t CBFunc;
    DMABuf_Handle_t NULL_Handle1 = { 0 };
    DMABuf_Handle_t NULL_Handle2 = { 0 };
    bool SREC_IN_USE = false, ARC4_IN_USE = false;
    unsigned int handle_count;
#ifdef TEST_PEC_GATHER
    DMABuf_Handle_t SGList_Gather_Handle ;
    int  NumGatherParticles=0 ;
#endif 

#ifdef TEST_PEC_SCATTER
    static DMABuf_Handle_t SGList_Scatter_Handle ;
    static int NumScatterParticles=0 ;
    static int NumPreloadAccepted = 0 ;
#endif


    IDENTIFIER_NOT_USED (CBFunc);

    LOG_CRIT ("Record no : %d \n", tr->record_number);

    // src packet buffer
    src_alloc_len = tr->pkt_data.ip_buffer_len * sizeof (int);
    
    if (0 == src_alloc_len)
        src_alloc_len = 4;


#ifndef TEST_PEC_GATHER
    Properties[0].Size = src_alloc_len;
#else
    Properties[0].Size = TEST_PEC_GATHER_PARTICLE_SIZE_IN_BYTES ;
    NumGatherParticles = src_alloc_len / 
                TEST_PEC_GATHER_PARTICLE_SIZE_IN_BYTES ;

    if(src_alloc_len % 
        TEST_PEC_GATHER_PARTICLE_SIZE_IN_BYTES )
        NumGatherParticles++ ;  
    
    if(NumGatherParticles > TEST_PEC_GATHER_MAX_DESCRIPTORS )
        {
            LOG_CRIT("Number of gather particles required:%d, greater than configred:%d\n",
                NumGatherParticles, TEST_PEC_GATHER_MAX_DESCRIPTORS );
            LOG_CRIT("SG Test failed\n");
            return false;
        }
#endif

    Properties[0].Alignment = 4;
    Properties[0].Bank = 0;
    Properties[0].fCached = true;

    // dst packet buffer
    dst_alloc_len = tr->pkt_data.op_buffer_len * sizeof (int);
    if (0 == dst_alloc_len)
        dst_alloc_len = 4;
    
#ifndef TEST_PEC_SCATTER
        Properties[1].Size = dst_alloc_len ;
#else
        Properties[1].Size = TEST_PEC_SCATTER_PARTICLE_SIZE_IN_BYTES ;
#if 0
        NumScatterParticles = dst_alloc_len / 
                             TEST_PEC_SCATTER_PARTICLE_SIZE_IN_BYTES ;

        if (dst_alloc_len % 
            TEST_PEC_SCATTER_PARTICLE_SIZE_IN_BYTES )
        NumScatterParticles++ ;
#endif
        NumScatterParticles = TEST_PEC_SCATTER_MAX_DESCRIPTORS ;
        
        if(NumScatterParticles > TEST_PEC_SCATTER_MAX_DESCRIPTORS )
        {
            LOG_CRIT("Number of scatter particles required:%d, greater than configred:%d\n",
                NumScatterParticles, TEST_PEC_SCATTER_MAX_DESCRIPTORS );
            LOG_CRIT("\n SG Test failed\n");
            return false;
        }
            
#endif


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
#ifdef TEST_BOUNCEBUFFERS
#ifdef TEST_BOUNCEBUFFERS_USER_MODE
                    testbuf[i] =
                        osal_malloc (Properties[i].Size);
#else
                    testbuf[i] =
                        kmalloc (Properties[i].Size, GFP_KERNEL | GFP_DMA);
#endif 
                      // register the buffer 
                      dma_status = DMABuf_Register (Properties[i],
                                                    testbuf[i],
                                                    testbuf[i],
                                                    0, &Handles[i]);
#else
                      // allocate dma buffer for state record 
                      dma_status = DMABuf_Alloc (Properties[i],
                                                 &Buffer_p[i], &Handles[i]);

#endif
                  }
            }
          else
           {
#ifdef TEST_BOUNCEBUFFERS
#ifdef TEST_BOUNCEBUFFERS_USER_MODE
                testbuf[i] =
                    osal_malloc (Properties[i].Size);
#else
                testbuf[i] =
                    kmalloc (Properties[i].Size, GFP_KERNEL | GFP_DMA);
#endif 
            // register the buffer 
                dma_status = DMABuf_Register (Properties[i],
                                              testbuf[i],
                                              testbuf[i], 0, &Handles[i]);
#else
                // allocate dma buffer for Src, Dst and SA 
                dma_status = DMABuf_Alloc (Properties[i],
                                           &Buffer_p[i], &Handles[i]);

#endif
            }

          if (dma_status != DMABUF_STATUS_OK)
            {
                LOG_CRIT ("\n DMABuf_Alloc failed with error code %d: i:%d",
                          dma_status, i);
                return FALSE;
            }
      }
      
    
#ifdef TEST_PEC_GATHER
        DMABuf_Release (Handles[0]);
        // Create PEC_SGList
       {
         PEC_Status_t St ;
         
         St = PEC_SGList_Create(
                NumGatherParticles,
                &SGList_Gather_Handle );
         if(St !=  PEC_STATUS_OK )
            {
                LOG_CRIT("Gather: PEC_SGList_Create failed:%d\n", St);
                return false ;
            }
       
         // Allocate gather particles and add to SG list
         for( i = 0 ; i < NumGatherParticles ; i++)
         {
            if( i == (NumGatherParticles -1) )
            {
              if( src_alloc_len % 
                  TEST_PEC_GATHER_PARTICLE_SIZE_IN_BYTES )

                    Properties[0].Size = 
                        src_alloc_len % 
                        TEST_PEC_GATHER_PARTICLE_SIZE_IN_BYTES ;
             }
               
            dma_status = DMABuf_Alloc( Properties[0],
                            &GatherSrcBuffers[i],
                            &GatherSrcHandles[i] );
            if(dma_status != DMABUF_STATUS_OK)
            {
                LOG_CRIT("Gather: DMABuf_Alloc failed:%d\n",
                    dma_status );
                return false ;
            }
            St = PEC_SGList_Write(
                    SGList_Gather_Handle,
                    i,
                    GatherSrcHandles[i],
                    Properties[0].Size );
            
            if(St !=  PEC_STATUS_OK )
            {
                LOG_CRIT("Gather:PEC_SGList_Write failed:%d\n", St);
                return false ;
            }
        
         }
    }  
       
#endif //TEST_PEC_GATHER 

#ifdef TEST_PEC_SCATTER
       DMABuf_Release (Handles[1]);
        // Create SG List
        {
           PEC_Status_t St ;
           St = PEC_SGList_Create(
                        NumScatterParticles,
                        &SGList_Scatter_Handle );
           
           if(St !=  PEC_STATUS_OK )            
           {
               LOG_CRIT("scatter: PEC_SGList_Create failed:%d\n", St);
               return false ;
                   
           }

            // Allocate scatter particles
            for( i = 0 ; i < NumScatterParticles; i++)
            {
                dma_status = DMABuf_Alloc( Properties[1],
                            &ScatterDstBuffers[i],
                            &ScatterDstHandles[i] );
                if(dma_status != DMABUF_STATUS_OK)
                {
                    LOG_CRIT("Scatter: DMABuf_Alloc failed:%d\n",
                    dma_status );
                    return false ;
                }
            }

           St =  PEC_Scatter_Preload(
                    ScatterDstHandles,
                    NumScatterParticles, 
                    &NumPreloadAccepted
                );

           LOG_INFO("\n PEC_Scatter_Preload : NumPreloadAccepted: %d \n", 
                NumPreloadAccepted);
           
           if(St !=  PEC_STATUS_OK )            
           {
               LOG_CRIT("scatter: PEC_Scatter_Preload failed:%d\n", St);
               return false ;
                   
           }
           
          // No PEC_SGList_Write call required       
      }
#endif //TEST_PEC_SCATTER 


#ifndef TEST_BOUNCEBUFFERS
    User.DstBuf = Buffer_p[1].p;        //Dst Buf
#else

#ifndef TEST_PEC_SCATTER
    User.DstBuf = testbuf[1];   //Dst Buf
#else
    User.DstBuf = SGList_Scatter_Handle.p ;
#endif //TEST_PEC_SCATTER

#endif

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
#ifdef TEST_BOUNCEBUFFERS
    memcpy (testbuf[2], sa_copy, sa_len);
#else
    memcpy (Buffer_p[2].p, sa_copy, sa_len);
#endif

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
#ifdef TEST_BOUNCEBUFFERS
          memcpy (testbuf[3], srec_copy, srec_len);
#else
          memcpy (Buffer_p[3].p, srec_copy, srec_len);
#endif

          if (ARC4_IN_USE)
            {
         
                LOG_INFO("\nTest App: ARC4 in Use \n");
                // Register SA and ARC4 state record
                PEC_SA_Register (Handles[2], NULL_Handle1, Handles[3]);
            }

          if (SREC_IN_USE)
            {
                 LOG_INFO("\nTest App: Srec in Use \n");
                // Register SA and State record
                PEC_SA_Register (Handles[2], Handles[3], NULL_Handle1);
            }


      }
    else
      {
            LOG_CRIT("\nTest App: Neither of State record in Use \n");
          // Register SA (Handle[2]), Srec  (Handle[3])
          PEC_SA_Register (Handles[2], NULL_Handle1, NULL_Handle2);
      }

    //////////////////////////////////////////////////////////////////////

    src_copy = osal_malloc (src_alloc_len);
    if (tr->pkt_data.ip_buffer_len != 0)
    	memcpy (src_copy, tr->pkt_data.ip_buffer, src_alloc_len);

/* RT_EIP93_DRIVER_DEBUG
 * After C.L.'s new POF for fixing no_word_alignment, we don't
 * have to comment out "#define NO_SWAP_FOR_DATA"
 */        
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
                slad_test_print_decode_register_pe_control_status(tr->pkt_data.pd_words[0]);
            }

          LOG_INFO ("\n\t Source data :\n");
          Log_HexDump ("", 0, src_copy, tr->pkt_data.ip_len_b);

      }
    // Copy src to dma buffer
#ifdef TEST_BOUNCEBUFFERS
    memcpy (testbuf[0], src_copy, src_alloc_len);
#else
#ifndef TEST_PEC_GATHER
    memcpy (Buffer_p[0].p, src_copy, src_alloc_len);
#else
    {
        int i , size ;
        size = TEST_PEC_GATHER_PARTICLE_SIZE_IN_BYTES ;
        
        for(i = 0 ; i < NumGatherParticles ; i++)
        {           
            if( i == (NumGatherParticles -1) )
            {                
              if( src_alloc_len % 
                  TEST_PEC_GATHER_PARTICLE_SIZE_IN_BYTES )              
                size = src_alloc_len % 
                  TEST_PEC_GATHER_PARTICLE_SIZE_IN_BYTES ;
            }              
             
            memcpy(GatherSrcBuffers[i].p, 
                    (unsigned char *)src_copy + i * TEST_PEC_GATHER_PARTICLE_SIZE_IN_BYTES,
                    size );

            LOG_INFO("\n Gather Particle index:%d \n ", i );
           // Log_HexDump("GatherParticle dump", 0, GatherSrcBuffers[i].p,
             //   size );  

        }
    }
#endif
#endif

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

#ifndef TEST_PEC_GATHER
    PE_CommandDescr.SrcPkt_Handle = Handles[0];
#else
    PE_CommandDescr.SrcPkt_Handle = SGList_Gather_Handle ;
#endif
  // PE_CommandDescr.SrcPkt_ByteCount = src_alloc_len;
     PE_CommandDescr.SrcPkt_ByteCount = tr->pkt_data.ip_len_b ;

#ifndef TEST_PEC_SCATTER
    PE_CommandDescr.DstPkt_Handle = Handles[1];
#else
    PE_CommandDescr.DstPkt_Handle = SGList_Scatter_Handle ;
#endif

    PE_CommandDescr.SA_WordCount = sa_len / sizeof (UINT32);
    PE_CommandDescr.SA_Handle1 = Handles[2];

    if (SREC_IN_USE || ARC4_IN_USE)
        PE_CommandDescr.SA_Handle2 = Handles[3];
    else
        PE_CommandDescr.SA_Handle2 = NULL_Handle1;

    PE_CommandDescr.Control1 = tr->pkt_data.pd_words[0];
    PE_CommandDescr.Control2 = tr->pkt_data.pd_words[2];
    PE_CommandDescr.Bypass_WordCount = tr->pkt_data.pd_words[2] >> 24;

#ifndef USE_POLLING
    {
        // Register Notify Function
        CBFunc = pe_kat_pkt_get;
        PEC_ResultNotify_Request (CBFunc, 1);
    }
#endif

    cnt = 1;

    PE_Status = PEC_Packet_Put (&PE_CommandDescr, 1, &cnt);

    
    if ((PE_Status == PEC_STATUS_OK) && cnt)
      {
          LOG_CRIT ("\n[kat_newapi] Packet submitted to the device, cnt:%d\n", cnt);
          ok = TRUE;
      }
    else
      {
          LOG_CRIT ("\n\t Failed to put  packet, drvstat=0x%08x\n",
                    PE_Status);
          ok = FALSE;
          goto free_buffers;
      }

    //if (!packet_notification)
#ifdef USE_POLLING
    {
        // Poll the device
        pe_kat_pkt_get ();
    }
#else

#if 0
    //EndianSwap Setting for C.L.'s new POF for fix no_word_alignment  (put right b4 kick CryptoEngine)
    VPint(0xbfb70100) = 0x00040700;
    VPint(0xbfb701d0) = 0x00e4001b;
    //trigger Crypto Engine here, instead of in EIP93_WriteCB
    VPint(0xbfb70090) = (uint32_t)cnt;
#endif

    {
        int TIMEOUT_VALUE;

        osal_delay (TEST_DELAY_TIMER); //udelay()
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
              failed = TRUE;
          }
        else
          {
              LOG_CRIT ("\n Interrupt received \n");
              LOG_CRIT ("\n Put one more packet \n");
#ifdef RT_EIP93_DRIVER
              //reset intr_received, otherwise the second time you execute the script, tasklet pe_kat_pkt_get will not run.
              intr_received = FALSE;
#endif
#if 0
              PE_Status = PEC_Packet_Put (&PE_CommandDescr, 1, &cnt);

              if (PE_Status == PEC_STATUS_OK)
                {
                    if (cnt)
                      {
                          LOG_CRIT ("\n Packet submitted to the device \n");
                          ok = TRUE;
                      }
                }
              else
                {
                    LOG_CRIT ("\n\t Failed to put  packet, drvstat=0x%08x\n",
                              PE_Status);
                    ok = FALSE;
                    goto free_buffers;
                }

              while (LoopCount > 0)
                {
                    /* Try to get the processed packet from the driver. */
                    PE_Status =
                        PEC_Packet_Get (&PE_ResultDescr, 1, &GetCount);
                    if (!GetCount)
                      {
                          osal_delay (wait_ms);
                          LoopCount--;
                          continue;
                      }
                    break;
                }

              if (GetCount)
                  pe_validate_after_pkt_get (&PE_ResultDescr, GetCount,
                                             PE_Status);
              else
                {
                    LOG_CRIT
                        ("\n No packet received from device, pkt get count zero\n");
                    failed = FALSE;
                }

#endif
          }
    }
#endif

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


  free_buffers:

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
 #ifndef TEST_PEC_GATHER
    DMABuf_Release (Handles[0]);
 #else
    PEC_SGList_Destroy(SGList_Gather_Handle ); 
        // Free gather particles 
    for( i = 0 ; i < NumGatherParticles ; i++)
    {
        DMABuf_Release(GatherSrcHandles[i] );           
    }    
 #endif //  TEST_PEC_GATHER

 #ifndef TEST_PEC_SCATTER
    DMABuf_Release (Handles[1]);
 #else
    PEC_SGList_Destroy(SGList_Scatter_Handle); 
    // Free scatter particles 
     for( i = 0 ; i < NumScatterParticles; i++)
     {
       DMABuf_Release(ScatterDstHandles[i] );           
     }    
 #endif
 
    DMABuf_Release (Handles[2]);
    if (SREC_IN_USE || ARC4_IN_USE)
      {
          DMABuf_Release (Handles[3]);
      }

    PEC_UnInit() ;

     #ifdef TEST_PEC_SCATTER
        initblock.FixedScatterFragSizeInBytes = 
            TEST_PEC_SCATTER_PARTICLE_SIZE_IN_BYTES ;
      #endif
        {
            PE_Status = PEC_Init (&initblock);
            if (PE_Status != PEC_STATUS_OK)
            {
                LOG_CRIT ("\n PEC_Init failed, returned : %d \n", PE_Status);
            }
        }
        
    
    return ok;
}


int
slad_test_pe_int_coalescing_run_test (
        int app_id,
        PEC_Capabilities_t * di, 
        pe_test_record * tr,
        int notification);


/***********************************************************************
*
************************************************************************/
int
slad_test_pe_kat_run_test (int app_id,
                           PEC_Capabilities_t * di, pe_test_record * tr,
                           int notification)
{
    int r = 0;

    packet_notification = notification;

    app_id_s = app_id;

    LOG_CRIT ("\n");

    if (device_n_test_info_g.tests.test_case_id_string[0] != 0)
        LOG_CRIT ("Test Case : %s \n",
                  device_n_test_info_g.tests.test_case_id_string);

    LOG_CRIT ("\n{ :-> Known-result-test (KAT) \n");

    if (packet_notification)
        LOG_CRIT ("\n Interrupt Mode \n");
    else
        LOG_CRIT ("\n Polling Mode \n");


    failed = FALSE;
#ifdef TEST_INTERRUPT_COALESCING
    r = (int)(&pe_kat); // just to get rid of 'defined but not used' warning
    r = slad_test_pe_int_coalescing_run_test(app_id, di, tr, notification);
#else
    r = pe_kat (app_id_s, di, tr);
#endif //TEST_INTERRUPT_COALESCING
    LOG_CRIT ("\n");
    LOG_CRIT ("%s : %-9s\n", device_n_test_info_g.tests.test_case_id_string,
                             (r && !failed) ? "PASSED" : "FAILED");
    LOG_CRIT ("\n} <-: ENDS Known-result-test (KAT) \n");

    return (r & !failed);
}
#endif
