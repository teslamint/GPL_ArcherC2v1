/* safenet_pe_pec.c
 *
 * Safenet Look-Aside Accelerator Packet Engine Interface implementation
 * for SafeXcel chips with the use of the PEC APIs.
 */

/*****************************************************************************
 *                                                                            *
 *          Copyright (c) 2009-2010 SafeNet Inc. All Rights Reserved.         *
 *                                                                            *
 * This confidential and proprietary software may be used only as authorized  *
 * by a licensing agreement from SafeNet.                                     *
 *                                                                            *
 * The entire notice above must be reproduced on all authorized copies that   *
 * may only be made to the extent permitted by a licensing agreement from     *
 * SafeNet.                                                                   *
 *                                                                            *
 * For more information or support, please go to our online support system at *
 * https://oemsupport.safenet-inc.com or e-mail to oemsupport@safenet-inc.com *
 *                                                                            *
 *****************************************************************************/

#include "sshincludes.h"
#include "ipsec_params.h"
#include "kernel_mutex.h"


#include "safenet_pe.h"               /*  API we implement */
#include "safenet_la_params.h"
#include "safenet_pe_utils.h"

#include "basic_defs.h"
#include "api_dmabuf.h" /*  DMA buf API we use */
#include "api_pec.h" /*  PEC API we use */

#if defined(SAFENET_PE_PLATFORM_1742)
  #include "safenet_pe_pec.h"
#elif defined(SAFENET_PE_PLATFORM_1746)
#include "safenet_pe_pec.h"     /*  the same as for 1742 */
#elif defined(SAFENET_PE_PLATFORM_EIP93)
#include "safenet_pe_pec.h" /*for integration*/
#else
  #error "Safenet Packet Engine API platform is not defined !!!"
#endif /*SAFENET_PE_PLATFORM_1742*/


/******** Debug stuff ***********/
#undef SSH_DEBUG_MODULE
#define SSH_DEBUG_MODULE "SshSafenetPePec"

/*  Move them to appropriate place */
#define SAFENETPEC_MAX_HANDLES SSH_ENGINE_MAX_TRANSFORM_CONTEXTS

static PEC_CommandDescriptor_t Descriptors[2*SSH_SAFENET_PDR_GET_COUNT];
static PEC_ResultDescriptor_t ResultDescriptors[2*SSH_SAFENET_PDR_GET_COUNT];

/*  Globals */

typedef struct SafenetPECDeviceCB
{
    void (* CBFunc)(unsigned int);
    uint32_t PacketPutCount;
}SafenetPECDeviceCB_t;

static SafenetPECDeviceCB_t SafenetPEC_Callbacks[PE_MAX_DEVICES];

typedef struct
{
    DMABuf_HostAddress_t SA_HostAddr;
    DMABuf_Handle_t SAHandle;
    size_t SA_Size;
    DMABuf_HostAddress_t Srec_HostAddr;
    DMABuf_Handle_t SrecHandle;
    size_t SRecSize;
} SafenetPEC_SARecord_t;


#ifndef SSH_SAFENET_POLLING
static void
SafenetPEC_CBFunc(void)
{
    SafenetPEC_Callbacks[0].CBFunc(0);
}
#endif



/*----------------------------------------------------------------------------
 * safenet_pe_uninit
 *
 * Accelerator-specific de-initialization function.
 */
void
safenet_pe_uninit(
        uint32_t device_num)
{
    PEC_UnInit();

    #ifdef SAFENET_DEBUG
    SSH_DEBUG(SSH_D_LOWOK, ("safenet_pe_uninit: PEC un-initialized."));
    #endif

}


/*----------------------------------------------------------------------------
 * safenet_pe_init
 *
 * Accelerator-specific initialization function.
 * Finds all accelerators, builds corresponding init blocks and initializes
 * the driver.
 *
 * device_callbacks - an array of glue layer callback functions, which should
 * be called when packets are processed by the Packet Engine and ready to be
 * received.
 *
 * device_count - as input is an expected number of accelerator devices and
 * the size of the device_callbacks[]. This value should be big enough to
 * possibly provide callbacks for a maximum number of devices.
 *
 * device_count - as output is a number of actually found accelerator devices.
*/
bool
safenet_pe_init(
        PE_DEVICE_INIT device_init[],
    uint32_t* device_count)
{
    uint32_t i;
    PEC_InitBlock_t InitBlock;
    PEC_Status_t status;

    SSH_ASSERT(device_init != NULL);
    SSH_ASSERT(device_count != NULL);

    if (*device_count  < 1)
        return false;

    SSH_ASSERT(*device_count <= PE_MAX_DEVICES);

    for (i = 0; i < *device_count; i++)
    {
      device_init[i].found = false;
      device_init[i].device_number = i;
        SafenetPEC_Callbacks[i].CBFunc =
                (void *)device_init[i].device_callback.callback;
        SafenetPEC_Callbacks[i].PacketPutCount = 0;
    }

    *device_count = 0;
    InitBlock.fUseDynamicSA = false;
    if ((status = PEC_Init(&InitBlock)) == PEC_STATUS_OK)
    {
        device_init[0].found = true;
        device_init[0].device_number = 0;
        *device_count = 1; /* Since we have only one device */
    }
    else
    {
        #ifdef SAFENET_DEBUG
      SSH_DEBUG(SSH_D_FAIL,
        ("safenet_pe_init: PEC_Init FAILED, status=%d", status));
        #endif
        return false;
    }

    {
        PEC_Capabilities_t Capabilities;
        status = PEC_Capabilities_Get(&Capabilities);

        if (status != PEC_STATUS_OK)
        {
#ifdef SAFENET_DEBUG
      SSH_DEBUG(SSH_D_FAIL,
            ("safenet_pe_init: "
                    "PEC_Capabilities_Get FAILED, status = %d", status));
#endif
            return false;
        }

#ifdef SAFENET_DEBUG
        SSH_DEBUG(SSH_D_LOWOK,
          ("safenet_pe_init: \n"
                 "Packet engine capabilities info - %s\n",
           Capabilities.szTextDescription));
#endif
    }

#ifndef SSH_SAFENET_POLLING
    {
        PEC_ResultNotify_Request((PEC_NotifyFunction_t)SafenetPEC_CBFunc,1);
    }
#endif

    #ifdef SAFENET_DEBUG
    SSH_DEBUG(SSH_D_LOWOK,( "safenet_pe_init: PEC sucessfully initialized."));
    #endif

    return true; /* Device is always present */
}


/* ---------------------------------------------------------------------------
 * safenet_pe_build_sa
 *
 * Allocates memory and builds SAs and related data for AH or ESP transforms
 *
 * type        - in: for which transforms to build the SA (AH, ESP)
 * flags     - in: transform options for building the SA
 * sa_params - in: parameters for building the SA (algorithms, keys,
                   other items), see PE_SA_PARAMS
 * sa_data   - out: pointer to a memory block with initialized SA data
 */
bool
safenet_pe_build_sa(
        int device_num,
        PE_SA_TYPE type,
        PE_FLAGS flags,
        PE_SA_PARAMS *sa_params,
        void** sa_data)
{
    PEC_Status_t Status;
    DMABuf_Properties_t RequestedPropSA, RequestedPropSrec;
    DMABuf_Handle_t NULL_Handle1 = {0};
    DMABuf_Handle_t LocalSAHandle = {0};
    DMABuf_Handle_t LocalSrecHandle = {0};
    DMABuf_HostAddress_t SABuffer, SrecBuffer;
    DMABuf_Status_t DMAStatus;
    SafenetPEC_SARecord_t * SARecord_p = NULL;
    uint32_t seq;

    SSH_ASSERT(sa_data != NULL);

    /* we have to decrement seq because Packet Engine
       initially increments the received initial value of the sequence number
       for Outbound transforms
       so we have to compensate for that initial increment */
    seq = (sa_params->seq > 0) ? sa_params->seq - 1 : 0;

    *sa_data = NULL;

    SARecord_p = ssh_kernel_alloc(sizeof(SafenetPEC_SARecord_t),
                  SSH_KERNEL_ALLOC_NOWAIT);
    if (SARecord_p == NULL)
    {
        #ifdef SAFENET_DEBUG
        SSH_DEBUG(SSH_D_FAIL,
          ( "safenet_pe_build_sa: SafenetPEC_SARecord_t allocation FAILED"));
        #endif
        return false;
    }

    /*  Fill properties for SA */
    RequestedPropSA.Size = sizeof (SafenetPEC_SA_t);
    RequestedPropSA.Alignment = 4;
    RequestedPropSA.Bank = 0;
    RequestedPropSA.fCached = true;

    /*  Fill properties for state record */
    RequestedPropSrec.Size = sizeof(SafenetPEC_StateRecord_t);
    RequestedPropSrec.Alignment = 4;
    RequestedPropSrec.Bank = 0;
    RequestedPropSrec.fCached = true;

    /*  Allocate DMA buffer for SA and state record. */
    DMAStatus = DMABuf_Alloc(
                        RequestedPropSA,
                        &SABuffer,
                        &LocalSAHandle);
    if (DMAStatus != DMABUF_STATUS_OK)
    {

        #ifdef SAFENET_DEBUG
      SSH_DEBUG(SSH_D_FAIL,
       ( "safenet_pe_build_sa: SA allocation FAILED. DMABuf_Alloc status %d",
     DMAStatus));
        #endif
        goto FAIL;
    }

    DMAStatus = DMABuf_Alloc(
                        RequestedPropSrec,
                        &SrecBuffer,
                        &LocalSrecHandle);
    if (DMAStatus != DMABUF_STATUS_OK)
    {
        #ifdef SAFENET_DEBUG
      SSH_DEBUG(SSH_D_FAIL,
       ("safenet_pe_build_sa: SRec allocation FAILED. DMABuf_Alloc status %d",
    DMAStatus));
        #endif
        goto FAIL;
    }

    /* Fill SA */
    memset (SABuffer.p, 0x0, sizeof(SafenetPEC_SA_t));
    memset (SrecBuffer.p, 0x0, sizeof(SafenetPEC_StateRecord_t));

    /*  Implement safenet_pe_populate_sa */
    if (!SafenetPEC_PopulateSA(
                type,
                flags,
                SABuffer.p,
                SrecBuffer.p,
                sa_params->spi,
                seq,
                sa_params->hash_alg,
                sa_params->ciph_alg,
                sa_params->ciph_key,
                sa_params->ciph_key_len,
                sa_params->mac_key,
                sa_params->mac_key_len,
                sa_params->esp_iv,
                sa_params->esp_ivlen))
    {
        #ifdef SAFENET_DEBUG
      SSH_DEBUG(SSH_D_FAIL,("safenet_pe_build_sa: Failed to populate SA."));
        #endif
        goto FAIL;
    }

    /*  register SA and state record. */
    Status = PEC_SA_Register(LocalSAHandle, LocalSrecHandle, NULL_Handle1);
    if (Status != PEC_STATUS_OK)
    {
        #ifdef SAFENET_DEBUG
            SSH_DEBUG(SSH_D_FAIL,("safenet_pe_build_sa : "
                      " PEC_SA_Register failed with error %x",
                       Status));
        #endif
        goto FAIL;
    }

    /*  Get a valid handle for storing SA and state record's
        DMA buffer pointers and handles.*/
    {
     memset (SARecord_p, 0x0, sizeof (SafenetPEC_SARecord_t));
        SARecord_p->SA_HostAddr = SABuffer;
        SARecord_p->Srec_HostAddr = SrecBuffer;
        SARecord_p->SA_Size = sizeof (SafenetPEC_SA_t);
        SARecord_p->SAHandle =  LocalSAHandle;
        SARecord_p->SrecHandle = LocalSrecHandle;
        SARecord_p->SRecSize = sizeof(SafenetPEC_StateRecord_t);
    }

    *sa_data = SARecord_p;

    #ifdef SAFENET_DEBUG
   SSH_DEBUG(SSH_D_LOWOK,("safenet_pe_build_sa: successfully installed SA "));
    #endif

    return true;

FAIL:

    #ifdef SAFENET_DEBUG
        SSH_DEBUG(SSH_D_FAIL, ("safenet_pe_build_sa FAILED!"));
    #endif

    if (LocalSAHandle.p)
        DMABuf_Release(LocalSAHandle);
    if (LocalSrecHandle.p)
        DMABuf_Release(LocalSrecHandle);
    if (SARecord_p)
    ssh_kernel_free(SARecord_p);

    return false;
}


/*---------------------------------------------------------------------------
 * safenet_pe_destroy_sa
 *
 * Frees any memory allocated with safenet_pe_build_sa for SAs and related
 * data for AH or ESP transforms
 *
 * sa_data - in: pointer to a memory block with SA data
 */
void
safenet_pe_destroy_sa(
        const void* sa_data)
{
    PEC_Status_t Status;
    DMABuf_Handle_t NULL_Handle1 = {0};
    SafenetPEC_SARecord_t * SARecord_p = (SafenetPEC_SARecord_t *)sa_data;

    SSH_ASSERT(SARecord_p != NULL);

    if (SARecord_p == NULL)
    {
#ifdef SAFENET_DEBUG
        SSH_DEBUG(SSH_D_FAIL,
               ("safenet_pe_destroy_sa: Invalid SA handle received."));
#endif
        return;
    }

    /*  unregister SA and state record. */
    Status = PEC_SA_UnRegister(SARecord_p->SAHandle, SARecord_p->SrecHandle,
                               NULL_Handle1);
    if (Status != PEC_STATUS_OK)
    {
        #ifdef SAFENET_DEBUG
            SSH_DEBUG(SSH_D_FAIL,("safenet_pe_destroy_sa : "
                      " PEC_SA_Unregister failed with error %x",
                       Status));
        #endif
    }


    /* Release the SA and state record handles allocated during
       safenet_pe_build_sa */
    Status = DMABuf_Release(SARecord_p->SAHandle);
    if (Status != PEC_STATUS_OK)
    {
        #ifdef SAFENET_DEBUG
            SSH_DEBUG(SSH_D_FAIL,("safenet_pe_destroy_sa : "
                      " DMABuf_Release of SA failed with error %x",
                       Status));
        #endif
    }

    Status=DMABuf_Release(SARecord_p->SrecHandle);
    if (Status != PEC_STATUS_OK)
    {
        #ifdef SAFENET_DEBUG
            SSH_DEBUG(SSH_D_FAIL,("safenet_pe_destroy_sa : "
                      " DMABuf_Release of Srec failed with error %x",
                       Status));
        #endif
    }

    ssh_kernel_free(SARecord_p);

    #ifdef SAFENET_DEBUG
        SSH_DEBUG(SSH_D_LOWOK,("safenet_pe_destroy_sa: destroyed SA."));
    #endif
}


#if defined(SAFENET_PE_PLATFORM_1746)
/*----------------------------------------------------------------------------
 * SafenetPEC_PEPacketDescr_BlockSize_Sanity_Check
 *
 *Checks a if a inbound packet could be decapsulated with current selected
  algorithms. !Only checked for esp inbound AES_CBC or (3)DES_CBC!

  pkt - in: pointer to a PE_PKT_DESCRIPTOR.

  Return: False when encrypted payload not a multiple of algorithms.

 */
static bool
SafenetPEC_PEPacketDescr_BlockSize_Sanity_Check(
    PE_PKT_DESCRIPTOR *pkt)
{
    size_t block_size;


    /*esp and inbound AES-CBC or (3)DES-CBC*/
    if((pkt->flags & PE_FLAGS_ESP) &&
      !(pkt->flags & PE_FLAGS_OUTBOUND) &&
       (pkt->flags & (PE_FLAGS_AES_CBC | PE_FLAGS_DES_CBC)))
    {
        block_size = (pkt->flags & PE_FLAGS_AES_CBC)? 16 : 8;

        if((pkt->src_len-pkt->iv_size-8-pkt->icv_size) & (block_size-1))
        {
            SSH_DEBUG(SSH_D_FAIL,("Inbound blocksize error prevention: "
            "pkt->src_len:0x%x "
            "pkt->iv_size:0x%x "
            "pkt->icv_size:0x%x "
            "block_size:0x%x",
            pkt->src_len,pkt->iv_size,pkt->icv_size,block_size));
            return false;
        }
    }
    return true;
}
#endif

/*----------------------------------------------------------------------------
 * safenet_pe_pktput
 *
 * Use this to put a packet to be processed to the Packet Engine
 * pkt is a points to a PE_PKT_DESCRIPTOR object for the packet
 * to be sent to the Packet Engine for processing.
 *
 * Returns a number of packets sucessfully sent to the Packet Engine.
*/
int
safenet_pe_pktput(
        int device_num,
        PE_PKT_DESCRIPTOR pkt[],
        uint32_t Count)
{
    PEC_Status_t Status;
    int i;
    int PacketDone = 0;

    SSH_ASSERT(pkt != NULL && Count > 0);
    SSH_DEBUG(SSH_D_HIGHOK,
              ("safenet_pe_pktput: Try to put %d packets ", Count));

    /* note:
       following only works when packets are serviced in sequence
    */

    for (i = 0; i < Count; i++)
    {
        SafenetPEC_SARecord_t *SA_p = pkt[i].sa_data;
        SSH_ASSERT(SA_p != NULL);
        /*  Fill PEC command descriptors for each packet received. */

        if (!SafenetPEC_PEPacketDescr_To_PECCommandDescr(
                &Descriptors[i],
                &pkt[i],
                SA_p->SAHandle,
                SA_p->SA_Size,
                SA_p->SrecHandle)
            )
        {
            #ifdef SAFENET_DEBUG
               SSH_DEBUG(SSH_D_FAIL, ("safenet_pe_pktput: "
                                      "Could not convert packet %d/%d.",
                         i, Count));
            #endif

          /* the packet causing the error may not be freed since it
             has not been been registered */
          while(i>0)
          {
              i--;
              safenet_peccmddesc_free(Descriptors[i].DstPkt_Handle);
          };

          return 0;
        }
    }

    SSH_DEBUG(SSH_D_HIGHOK,
              ("safenet_pe_pktput: Converted %d packets.\n",
               Count));

    /* send packets to the accelerator */
    {
        Status = PEC_Packet_Put(Descriptors, Count, &PacketDone);
        if (Status != PEC_STATUS_OK)
        {
            /* No packets should be sent if an error was set... */
          SSH_ASSERT(PacketDone == 0);
          SSH_DEBUG(SSH_D_FAIL, ("safenet_pe_pktput: "
                                 "Failed to put packets, error %d.", Status));

          for (i = 0; i < Count; i++)
            safenet_peccmddesc_free(Descriptors[i].DstPkt_Handle);

          return 0;
        }
        else if (PacketDone < Count)
        {
        #ifdef SAFENET_DEBUG
          SSH_DEBUG(SSH_D_FAIL, ("safenet_pe_pktput: PACKET LOSS!.\n"
                      "PEC_Packet_Put: \n"
                      "Status = %d\n"
                      " PacketDone returned by PE - %d, "
                      " NumPackets sent to packet engine- %d\n",
                      Status,
                      PacketDone,
                      Count));
        #endif
          for (i = PacketDone; i < Count; i++)
            safenet_peccmddesc_free(Descriptors[i].DstPkt_Handle);
        }
    }

    SSH_DEBUG(SSH_D_HIGHOK,
              ("safenet_pe_pktput: Done putting %d packets.\n",
               PacketDone));

    return PacketDone;
}


/*---------------------------------------------------------------------------
 *  safenet_pe_pktget
 *
 *  Use this to get completed packets from the Packet Engine
 *  The function returns PE_PKT_DESCRIPTOR objects in pkt if the
 *  packets were successfully processed by the Packet Engine and available for
 *  receiving.
 *
 *  pcount is an output parameter and is the number of packets received.
 *
 *  Returns FALSE if the packets cannot be received because of the Packet
 *  Engine  error
 */

bool
safenet_pe_pktget(

        int device_num,
        PE_PKT_DESCRIPTOR pkt[],
        uint32_t* Count_p)
{
    PEC_Status_t Status;
    int i;
    unsigned int ResultLimit = SSH_SAFENET_PDR_GET_COUNT;

    SSH_ASSERT(pkt != NULL && Count_p != NULL);

#ifndef SSH_SAFENET_POLLING
    {
        PEC_ResultNotify_Request((PEC_NotifyFunction_t)SafenetPEC_CBFunc,1);
    }
#endif

    *Count_p = 0;
    Status = PEC_Packet_Get(ResultDescriptors, ResultLimit, Count_p);
    if (Status != PEC_STATUS_OK)
    {
        #ifdef SAFENET_DEBUG
            SSH_DEBUG(SSH_D_FAIL,
              ("safenet_pe_pktget: Failed to retrieve packets.\n"
                      "PEC_Packet_Get: \n"
                      "Status = %d\n"
                      " ResultCount returned by PE - %d, "
                      " ResultLimit sent to packet engine- %d\n",
                      Status,
                      *Count_p,
                      ResultLimit));
        #endif
        return false;
    }

    
    if (*Count_p > 0)
        SSH_DEBUG(SSH_D_HIGHOK,
                  ("safenet_pe_pktget: Done getting %d packets.\n",
                  *Count_p));

    for (i = 0; i < *Count_p; i++)
    {
        SafenetPEC_PECResultDescr_To_PEPacketDescr(&ResultDescriptors[i],
                           &pkt[i]);
    }

    return true;
}

/* end of safenet_pe_pec.c */
