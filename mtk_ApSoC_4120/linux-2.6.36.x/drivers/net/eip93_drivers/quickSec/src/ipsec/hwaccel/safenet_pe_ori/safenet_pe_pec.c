/* safenet_pe_pec.c
 *
 * Safenet Look-Aside Accelerator Packet Engine Interface implementation
 * for SafeXcel chips with the use of the PEC APIs.
 */

/*****************************************************************************
 *                                                                            *
 *            Copyright (c) 2009 SafeNet Inc. All Rights Reserved.            *
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
  #include "safenet_pe_pec_eip93.h"
#else
  #error Safenet Packet Engine API platform is not defined !!!
#endif /*SAFENET_PE_PLATFORM_1742*/


/******** Debug stuff ***********/
#ifndef KERNEL
  #define printk printf
#endif
#undef KERN_NOTICE
#define KERN_NOTICE ".. "
#undef SSH_DEBUG_MODULE
#define SSH_DEBUG_MODULE "SshSafenet1x41"
/* #define SSH_TRACE_ENABLED(level)  (level <= 10) */


#undef SSH_ASSERT
#define SSH_ASSERT(_expr) \
    if (!(_expr)) \
    { \
        printk("\nPEC ASSERT: Line: %d, %s\n", __LINE__ , #_expr); \
    }


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
        printk(KERN_NOTICE "safenet_pe_uninit: PEC un-initialized.\n");
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
            printk(KERN_NOTICE  
                  "safenet_pe_init: PEC_Init FAILED, status=%d\n", status);
        #endif
        return false;
    }

    {
        PEC_Capabilities_t Capabilities;
        status = PEC_Capabilities_Get(&Capabilities);

        if (status != PEC_STATUS_OK)
        {
#ifdef SAFENET_DEBUG
            printk(KERN_NOTICE
                  "safenet_pe_init: "
                  "PEC_Capabilities_Get FAILED, status = %d\n", status);
#endif
            return false;
        }

#ifdef SAFENET_DEBUG
        printk (KERN_NOTICE
               "safenet_pe_init: \n"
               "Packet engine capabilities info - %s\n",
               Capabilities.szTextDescription);
#endif
    }

#ifndef SSH_SAFENET_POLLING
    {
        PEC_ResultNotify_Request((PEC_NotifyFunction_t)SafenetPEC_CBFunc,1);
    }
#endif

    #ifdef SAFENET_DEBUG
        printk(KERN_NOTICE "safenet_pe_init: PEC sucessfully initialized.\n");
    #endif

    return true; /* Device is always present */
}


/* ---------------------------------------------------------------------------
 * safenet_pe_build_sa
 *
 * Allocates memory and builds SAs and related data for AH or ESP transforms
 *
 * type	    - in: for which transforms to build the SA (AH, ESP)
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
     	PE_SA_PARAMS sa_params,
        void** sa_data)
{
    PEC_Status_t Status;
    DMABuf_Properties_t RequestedPropSA, RequestedPropSrec;
    DMABuf_Handle_t NULL_Handle1 = {0};
    DMABuf_Handle_t LocalSAHandle, LocalSrecHandle;
    DMABuf_HostAddress_t SABuffer, SrecBuffer;
    DMABuf_Status_t DMAStatus;
    SafenetPEC_SARecord_t * SARecord_p = NULL;
    uint32_t seq;

    SSH_ASSERT(sa_data != NULL);

    /* we have to decrement seq because Packet Engine
       initially increments the received initial value of the sequence number
       for Outbound transforms
       so we have to compensate for that initial increment */
    seq = (sa_params.seq > 0) ? sa_params.seq - 1 : 0;

    *sa_data = NULL;

    SARecord_p = ssh_kernel_alloc(sizeof(SafenetPEC_SARecord_t), 
				  SSH_KERNEL_ALLOC_NOWAIT);
    if (SARecord_p == NULL)
        return false;

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
            printk(KERN_NOTICE 
                  "safenet_pe_build_sa: SA allocation FAILED."
                  " DMABuf_Alloc status %d\n",
                  DMAStatus);
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
            printk(KERN_NOTICE 
                  "safenet_pe_build_sa: SRec allocation FAILED."
                  " DMABuf_Alloc status %d\n",
                  DMAStatus);
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
                sa_params.spi,
                seq,
                sa_params.hash_alg,
                sa_params.ciph_alg,
                sa_params.ciph_key,
                sa_params.ciph_key_len,
                sa_params.mac_key,
                sa_params.mac_key_len,
                sa_params.esp_iv,
                sa_params.esp_ivlen))
    {
        #ifdef SAFENET_DEBUG
           printk(KERN_NOTICE "safenet_pe_build_sa: Failed to populate SA\n");
        #endif
        goto FAIL;
    }

    /*  register SA and state record. */
    Status = PEC_SA_Register(LocalSAHandle, LocalSrecHandle, NULL_Handle1);
    if (Status != PEC_STATUS_OK)
    {
        #ifdef SAFENET_DEBUG
            printk(KERN_NOTICE "safenet_pe_build_sa : "
                  " PEC_SA_Register failed with error %x\n",
                  Status);
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
        printk(KERN_NOTICE "safenet_pe_build_sa:"
              " successfully installed SA.\n");
    #endif

    return true;

FAIL:

    #ifdef SAFENET_DEBUG
        printk(KERN_NOTICE "safenet_pe_build_sa FAILED!\n");
    #endif

    if (LocalSAHandle.p)
        DMABuf_Release(LocalSAHandle);
    if (LocalSrecHandle.p)
        DMABuf_Release(LocalSrecHandle);

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

    SafenetPEC_SARecord_t * SARecord_p = (SafenetPEC_SARecord_t *)sa_data;

    SSH_ASSERT(SARecord_p != NULL);

    if (SARecord_p == NULL)
    {
#ifdef SAFENET_DEBUG
        printk(KERN_NOTICE
              "safenet_pe_destroy_sa: Invalid SA handle received.\n");
#endif
        return;
    }

    /* Release the SA and state record handles allocated during
       safenet_pe_build_sa */
    DMABuf_Release(SARecord_p->SAHandle);
    DMABuf_Release(SARecord_p->SrecHandle);

    ssh_kernel_free(SARecord_p);

    #ifdef SAFENET_DEBUG
        printk(KERN_NOTICE "safenet_pe_destroy_sa: destroyed SA.\n");
    #endif
}

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
              ("safenet_pe_pktput:  TRY put %d packets.\n", Count));

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
                printk(KERN_NOTICE "safenet_pe_pktput:"
                      " CANNOT convert packet %d/%d.\n",
                      i,Count);
            #endif
            return 0;
        }
    }

    /*  start sending packet to the engine. */
    {
        Status = PEC_Packet_Put(Descriptors, Count, &PacketDone);
        if (Status != PEC_STATUS_OK)
        {
            PacketDone = 0;
            #ifdef SAFENET_DEBUG
                printk(KERN_NOTICE "safenet_pe_pktput:"
                      " Failed to put packets.\n"
                      "PEC_Packet_Put: \n"
                      "Status = %d\n"
                      " PacketDone returned by PE - %d, "
                      " NumPackets sent to packet engine- %d\n",
                      Status,
                      PacketDone,
                      Count);
            #endif
        }
        #ifdef SAFENET_DEBUG
        else if (PacketDone < Count)
        {
                printk(KERN_NOTICE "safenet_pe_pktput: PACKET LOSS!.\n"
                      "PEC_Packet_Put: \n"
                      "Status = %d\n"
                      " PacketDone returned by PE - %d, "
                      " NumPackets sent to packet engine- %d\n",
                      Status,
                      PacketDone,
                      Count);
        }
        #endif
    }

    SSH_DEBUG(SSH_D_HIGHOK,
              ("safenet_pe_pktput: DONE put %d packets.\n",
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
            printk(KERN_NOTICE "safenet_pe_pktget:"
                  " Failed to retrieve packets.\n"
                  "PEC_Packet_Get: \n"
                  "Status = %d\n"
                  " ResultCount returned by PE - %d, "
                  " ResultLimit sent to packet engine- %d\n",
                  Status,
                  *Count_p,
                  ResultLimit);
        #endif
        return false;
    }

    if (*Count_p > 0)
        SSH_DEBUG(SSH_D_HIGHOK,
                  ("safenet_pe_pktget:  DONE get %d packets.\n",
                  *Count_p));

    for (i = 0; i < *Count_p; i++)
    {
        SafenetPEC_PECResultDescr_To_PEPacketDescr(&ResultDescriptors[i], 
						   &pkt[i]);
    }

    return true;
}

/* end of safenet_pe_pec.c */
