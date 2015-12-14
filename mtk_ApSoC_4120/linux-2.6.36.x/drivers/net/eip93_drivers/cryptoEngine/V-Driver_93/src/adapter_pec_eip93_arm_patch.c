/* adapter_pec_eip93_arm.c
 *
 * Packet Engine Control (PEC) API Implementation
 * supporting the EIP93 in Autonomous Ring Mode (ARM)
 * using the EIP93 Driver Library.
 */

/*****************************************************************************
*                                                                            *
*         Copyright (c) 2008-2009 SafeNet Inc. All Rights Reserved.          *
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

#include "c_adapter.h"
#ifdef ADAPTER_EIP93_PE_MODE_ARM

#include "basic_defs.h"         // uint32_t
#include "api_pec.h"            // PEC_* (the API we implement here)
#include "api_dmabuf.h"         // DMABuf_*
#include "hw_access_dma.h"      // HWPAL_Resource_*
#include "clib.h"               // memcpy
#include "adapter_internal.h"
#include "eip93.h"
#include "adapter_interrupts_eip93.h"
#include "eip93_arm.h"        // driver library API we will use

static bool PEC_IsInitialized = false;

// static allocation of logical descriptors for translating
// between PEC and EIP93 APIs in PEC_Packet_Put/Get
static EIP93_ARM_CommandDescriptor_t PEC_Cmds[ADAPTER_MAX_EIP93LOGICDESCR];
static EIP93_ARM_ResultDescriptor_t PEC_Results[ADAPTER_MAX_EIP93LOGICDESCR];
#ifndef ADAPTER_REMOVE_BOUNCEBUFFERS
static DMABuf_Handle_t PEC_BounceHandles[ADAPTER_MAX_EIP93LOGICDESCR];
#endif

typedef struct
{
    void * User_p;
    DMABuf_Handle_t SrcPkt_Handle;
    DMABuf_Handle_t DstPkt_Handle;
#ifndef ADAPTER_REMOVE_BOUNCEBUFFERS
    DMABuf_Handle_t Bounce_Handle;
#endif
} Adapter_PacketSideChannelRecord_t;

typedef struct
{
    int Size;
    int ReadIndex;
    int WriteIndex;
    Adapter_PacketSideChannelRecord_t Records
        [ADAPTER_PACKETSIDECHANNEL_MAX_RECORDS];
} Adapter_PacketSideChannelFIFO_t;

static Adapter_PacketSideChannelFIFO_t Adapter_SideChannelFIFO;

static struct
{
    PEC_NotifyFunction_t ResultNotifyCB_p;
    unsigned int ResultsCount;

    PEC_NotifyFunction_t CommandNotifyCB_p;
    unsigned int CommandsCount;
} PEC_Notify;


/*----------------------------------------------------------------------------
 * PEC_Capabilities_Get
 */
static const PEC_Capabilities_t Capabilities =
{
    "EIP-93v_._p_ Packet Engine (ARM,"        // szTextDescription
#ifdef ADAPTER_EIP93PE_INTERRUPTS_ENABLE
    "Int)"
#else
    "Poll)"
#endif
};

PEC_Status_t
PEC_Capabilities_Get(
        PEC_Capabilities_t * const Capabilities_p)
{
    uint8_t Versions[3];

    if (Capabilities_p == NULL)
        return PEC_ERROR_BAD_PARAMETER;

    memcpy(Capabilities_p, &Capabilities, sizeof(Capabilities));

    // now replace the version number in the text string
    {
        EIP93_Capabilities_t Capabilities;
        EIP93_Status_t res93;

        res93 = EIP93_HWRevision_Get(
                        &Adapter_EIP93_IOArea,
                        &Capabilities);

        if (res93 != EIP93_STATUS_OK)
        {
            LOG_WARN(
                "PEC_Capabilities_Get: "
                "Unexpected error from EIP93: %d\n",
                res93);

            return PEC_ERROR_INTERNAL;
        }

        // copy the three version numbers from the capabilities
        Versions[0] = Capabilities.MajHWRevision;
        Versions[1] = Capabilities.MinHWRevision;
        Versions[2] = Capabilities.HWPatchLevel;
    }

    {
        char * p = Capabilities_p->szTextDescription;
        int VerIndex = 0;
        int i = 0;

        while(p[i])
        {
            if (p[i] == '_')
            {
                if (Versions[VerIndex] > 9)
                    p[i] = '?';
                else
                    p[i] = '0' + Versions[VerIndex++];
            }

            i++;
        }
    }

    return PEC_STATUS_OK;
}


/*----------------------------------------------------------------------------
 * Adapter_EIP93_InterruptHandler_DescriptorDone
 *
 * This function is invoked when the EIP93 has activated the descriptor done
 * interrupt.
 */
#ifdef ADAPTER_EIP93PE_INTERRUPTS_ENABLE
extern void
Adapter_EIP93_InterruptHandler_DescriptorDone(void);
extern void
Adapter_EIP93_InterruptHandler_DescriptorPut(void) ;

#endif /* ADAPTER_EIP93PE_INTERRUPTS_ENABLE */


/*----------------------------------------------------------------------------
 * Adapter_SanityTest_Poll
 *
 * This function tests the behavior of ARM mode.
 *
 * 1) get a result descriptor while the ring is supposed to be empty
 *
 * 2) put a number of empty commands and verify that we get a result
 *    this does not require any valid dma buffers (except for the ring)
 *
 * Return Value
 *      true Functionality is sane (OK)
 *     false Errors occured in the sanity check
 */
static bool
Adapter_SanityTest_Poll(void)
{
#if 0
    EIP93_Status_t res93;

    // test 1: get result from empty ring
    {
        unsigned int GetCount = 0;

        res93 = EIP93_ARM_PacketGet(
                    &Adapter_EIP93_IOArea,
                    PEC_Results,
                    ADAPTER_MAX_EIP93LOGICDESCR,
                    &GetCount);

        if (res93 != EIP93_STATUS_OK)
        {
            LOG_WARN(
                "Adapter_SanityTest_Poll: "
                "EIP93_ARM_PacketGet returned %d\n", res93);

            return false;       // test failed
        }

        if (GetCount !=  0)
        {
            LOG_WARN(
                "Adapter_SanityTest_Poll: "
                "EIP93_ARM_PacketGet returned a %d descriptors!\n",
                GetCount);

            return false;       // test failed
        }
    }

    // test 2: put a few dummy descriptors and get the answers
    {
        unsigned int PutCount = 0;

        ZEROINIT(PEC_Cmds);
        {
            int i;
            // for dynamicSA we must provide the SA length
            for (i = 0; i < ADAPTER_MAX_EIP93LOGICDESCR; i++)
                PEC_Cmds[i].SADataWordCount = 1;
        }

        res93 = EIP93_ARM_PacketPut(
                    &Adapter_EIP93_IOArea,
                    PEC_Cmds,
                    ADAPTER_MAX_EIP93LOGICDESCR,
                    &PutCount);

        if (res93 != EIP93_STATUS_OK)
        {
            LOG_WARN(
                "Adapter_SanityTest_Poll: "
                "EIP93_ARM_PacketPut returned %d\n", res93);

            return false;       // test failed
        }

        if (PutCount < ADAPTER_MAX_EIP93LOGICDESCR)
        {
            LOG_INFO(
                "Adapter_SanityTest_Poll: "
                "EIP93_ARM_PacketPut accepted %d out of %d"
                " descriptors (=OK)\n",
                PutCount,
                ADAPTER_MAX_EIP93LOGICDESCR);

            // can get < ADAPTER_MAX_EIP93LOGICDESCR when ring is small
            // but zero is definately a "fail"
            if (PutCount == 0)
                return false;       // test failed
        }

        // now wait for the same number of results
        // normally this will we get the result descriptors in no-time
        {
            int LoopLimiter = 1000;

            while(PutCount > 0 && LoopLimiter-- > 0)
            {
                unsigned int GetCount = 0;

                res93 = EIP93_ARM_PacketGet(
                            &Adapter_EIP93_IOArea,
                            PEC_Results,
                            ADAPTER_MAX_EIP93LOGICDESCR,
                            &GetCount);

                if (res93 != EIP93_STATUS_OK)
                {
                    LOG_WARN(
                        "Adapter_SanityTest_Poll: "
                        "EIP93_ARM_PacketGet returned %d\n", res93);

                    return false;       // test failed
                }

                if (GetCount > 0)
                {
                    if (GetCount > PutCount)
                    {
                        LOG_WARN(
                            "Adapter_SanityTest_Poll: "
                            "EIP93_ARM_PacketGet returned too many"
                            " descriptors (%d vs %d)\n",
                            GetCount,
                            PutCount);

                        return false;       // test failed
                    }

                    PutCount -= GetCount;
                }

                // note: we might not be in a sleepable context
                // so no sleep call here!
            } // while

            if (LoopLimiter <= 0)
                return false;       // failure
        }
    }
#endif
    // success
    return true;
}


/*----------------------------------------------------------------------------
 * PEC_Init
 */
PEC_Status_t
PEC_Init(
     const   PEC_InitBlock_t * const InitBlock_p)
{
    // ensure we init only once
    if (PEC_IsInitialized)
        return PEC_ERROR_BAD_USE_ORDER;

    Adapter_SideChannelFIFO.Size = ADAPTER_PACKETSIDECHANNEL_MAX_RECORDS;
    Adapter_SideChannelFIFO.WriteIndex = 0;
    Adapter_SideChannelFIFO.ReadIndex = 0;

    ZEROINIT(PEC_Notify);

    if (!Adapter_EIP93_SetMode_ARM(InitBlock_p->fUseDynamicSA))
        return PEC_ERROR_INTERNAL;      // ## RETURN ##

    // before we enable interrupts,
    // do a santify test of the ARM mode in polling mode.
    if (!Adapter_SanityTest_Poll())
    {
        // test failed, so shutdown and return an error code
        LOG_CRIT("PEC_Init: Sanity test failed!\n");
        Adapter_EIP93_SetMode_Idle();
        return PEC_ERROR_INTERNAL;
    }
    else
    {
        LOG_INFO("PEC_Init: Sanity test passed\n");
    }


    PEC_IsInitialized = true;

    return PEC_STATUS_OK;
}


/*----------------------------------------------------------------------------
 * PEC_UnInit
 */
PEC_Status_t
PEC_UnInit(void)
{
    // ensure we un-init only once
    if (PEC_IsInitialized)
    {
        Adapter_EIP93_SetMode_Idle();

#ifdef ADAPTER_EIP93PE_INTERRUPTS_ENABLE
        Adapter_Interrupt_Disable(IRQ_RDR_THRESH_IRQ);
        Adapter_Interrupt_Disable(IRQ_CDR_THRESH_IRQ);
#endif

        PEC_IsInitialized = false;
    }

    return PEC_STATUS_OK;
}


/*----------------------------------------------------------------------------
 * Adapter_CalulateEmptySlotCount
 */
static inline int
Adapter_CalulateEmptySlotCount(void)
{
    int ReadIndex;
    int WriteIndex;
    int PacketSlotsEmptyCount;


    ReadIndex =  Adapter_SideChannelFIFO.ReadIndex;
    WriteIndex = Adapter_SideChannelFIFO.WriteIndex;

    if (ReadIndex > WriteIndex)
        PacketSlotsEmptyCount = ReadIndex - WriteIndex;
    else
        PacketSlotsEmptyCount = Adapter_EIP93_MaxDescriptorsInRing -
                                (WriteIndex - ReadIndex);

    return PacketSlotsEmptyCount;

}


/*----------------------------------------------------------------------------
 * Adapter_MakeCommandNotify_CallBack
 */
static inline void
Adapter_MakeCommandNotify_CallBack(void)
{
    unsigned int PacketSlotsEmptyCount;

    if (PEC_Notify.CommandNotifyCB_p != NULL)
    {
        PacketSlotsEmptyCount = Adapter_CalulateEmptySlotCount();

        if (PEC_Notify.CommandsCount <= PacketSlotsEmptyCount)
        {
            PEC_NotifyFunction_t CBFunc_p;

            // Keep the callback on stack to allow registeration
            // of another result notify request from callback
            CBFunc_p = PEC_Notify.CommandNotifyCB_p;

            PEC_Notify.CommandNotifyCB_p = NULL;
            PEC_Notify.CommandsCount = 0;
            CBFunc_p();
        }
    }
}


/*----------------------------------------------------------------------------
 * Adapter_GetBounceBuf_SA_State
 *
 * Returns false in case of error.
 * Replaces the handle when it bounces the buffer.
 */
#ifndef ADAPTER_REMOVE_BOUNCEBUFFERS
static bool
Adapter_PECRegisterSA_BounceIfRequired(
        DMABuf_Handle_t * Handle_p)
{
    HWPAL_DMAResource_Handle_t DMAHandle;
    HWPAL_DMAResource_Record_t * Rec_p;
    HWPAL_DMAResource_Record_t * BounceRec_p;
    DMABuf_Status_t dmares;

    // skip null handles
    if (!Adapter_DMABuf_IsValidHandle(*Handle_p))
        return true;    // no error

    // skip proper buffers
    if (!Adapter_DMABuf_IsForeignAllocated(*Handle_p))
        return true;    // no error

    DMAHandle = Adapter_DMABuf_Handle2DMAResourceHandle(*Handle_p);
    Rec_p = HWPAL_DMAResource_Handle2RecordPtr(DMAHandle);

    {
        DMABuf_HostAddress_t BounceHostAddr;
        DMABuf_Properties_t BounceProperties;

        BounceProperties.Alignment = 4;        // used as uint32_t array
        BounceProperties.Bank = 0;
        BounceProperties.fCached = false;
        BounceProperties.Size = Rec_p->host.BufferSize;

        dmares = DMABuf_Alloc(
                     BounceProperties,
                     &BounceHostAddr,
                     &Rec_p->bounce.Bounce_Handle);

        // bounce buffer handle is stored in the DMA Resource Record
        // of the original buffer, which links the two
        // this will be used when freeing the buffer
        // but also when the SA is referenced in packet put

        if (dmares != DMABUF_STATUS_OK)
        {
            LOG_CRIT(
                "PEC_Register_SA: "
                "Failed to alloc bounce buffer (error %d)\n",
                dmares);
            return false;   // error!
        }
        LOG_INFO(
            "PEC_Register_SA: "
            "Bouncing SA: %p to %p\n",
            Handle_p->p,
            Rec_p->bounce.Bounce_Handle.p);

        // replace the caller-provided handle
        *Handle_p = Rec_p->bounce.Bounce_Handle;
    }

    DMAHandle = Adapter_DMABuf_Handle2DMAResourceHandle(*Handle_p);
    BounceRec_p = HWPAL_DMAResource_Handle2RecordPtr(DMAHandle);

    // copy the data to the bounce buffer
    memcpy(
        BounceRec_p->host.HostAddr_p,
        Rec_p->host.HostAddr_p,
        Rec_p->host.BufferSize);


    return true;        // no error
}
#endif /* ADAPTER_REMOVE_BOUNCEBUFFERS */


/*----------------------------------------------------------------------------
 * PEC_SA_Register
 */
PEC_Status_t
PEC_SA_Register(
        DMABuf_Handle_t SA_Handle1,
        DMABuf_Handle_t SA_Handle2,
        DMABuf_Handle_t SA_Handle3)
{
    HWPAL_DMAResource_Handle_t DMAHandle1 = NULL;
    HWPAL_DMAResource_Handle_t DMAHandle2 = NULL;
    HWPAL_DMAResource_Handle_t DMAHandle3 = NULL;
    EIP93_DeviceAddress_t EIP93PhysAddress1 = {0};
    EIP93_DeviceAddress_t EIP93PhysAddress2 = {0};
    EIP93_DeviceAddress_t EIP93PhysAddress3 = {0};

    if (!PEC_IsInitialized)
        return PEC_ERROR_BAD_USE_ORDER;

    if (!Adapter_DMABuf_IsValidHandle(SA_Handle1))
        return PEC_ERROR_BAD_HANDLE;

#ifndef ADAPTER_REMOVE_BOUNCEBUFFERS
    if (!Adapter_PECRegisterSA_BounceIfRequired(&SA_Handle1))
        return PEC_ERROR_INTERNAL;

    if (!Adapter_PECRegisterSA_BounceIfRequired(&SA_Handle2))
        return PEC_ERROR_INTERNAL;

    if (!Adapter_PECRegisterSA_BounceIfRequired(&SA_Handle3))
        return PEC_ERROR_INTERNAL;
#endif

    Adapter_GetEIP93PhysAddr(SA_Handle1, &DMAHandle1, &EIP93PhysAddress1);
    Adapter_GetEIP93PhysAddr(SA_Handle2, &DMAHandle2, &EIP93PhysAddress2);
    Adapter_GetEIP93PhysAddr(SA_Handle3, &DMAHandle3, &EIP93PhysAddress3);

    // the SA, State Record and ARC4 State Record are arrays of uint32_t
    // the caller provides them in host-native format
    // we must now convert it to device-native format
    // using HWPAL_DMAResource and in-place operations
    {
        HWPAL_DMAResource_Record_t * const Rec_p =
            HWPAL_DMAResource_Handle2RecordPtr(DMAHandle1);

        HWPAL_DMAResource_Write32Array(
                    DMAHandle1,
                    0,
                    Rec_p->host.BufferSize / 4,
                    Rec_p->host.HostAddr_p);
    }

    if (EIP93PhysAddress2.Addr != 0)
    {
        HWPAL_DMAResource_Record_t * const Rec_p =
            HWPAL_DMAResource_Handle2RecordPtr(DMAHandle2);



        HWPAL_DMAResource_Write32Array(
                    DMAHandle2,
                    0,
                    Rec_p->host.BufferSize / 4,
                    Rec_p->host.HostAddr_p);
    }

    if (EIP93PhysAddress3.Addr != 0)
    {
        HWPAL_DMAResource_Record_t * const Rec_p =
            HWPAL_DMAResource_Handle2RecordPtr(DMAHandle3);

        HWPAL_DMAResource_Write32Array(
                    DMAHandle3,
                    0,
                    Rec_p->host.BufferSize / 4,
                    Rec_p->host.HostAddr_p);
    }

    // ask the EIP93 DrvLib to finalize the SA
    // (fill in some fields it is responsible for)
    {
        EIP93_Status_t res;

        res = EIP93_ARM_FinalizeSA(
                    &Adapter_EIP93_IOArea,
                    DMAHandle1);//,
//                    EIP93PhysAddress2,
//                    EIP93PhysAddress3);

        if (res != EIP93_STATUS_OK)
        {
            LOG_WARN(
                "PEC_SA_Register: "
                "EIP93_ARM_FinalizeSA returned %d\n",
                res);
            return PEC_ERROR_INTERNAL;
        }
    }

    // now use DMAResource to ensure the engine
    // can read the memory blocks using DMA
    HWPAL_DMAResource_PreDMA(DMAHandle1, 0, 0);     // 0,0 = "entire buffer"

    if (EIP93PhysAddress2.Addr != 0)
        HWPAL_DMAResource_PreDMA(DMAHandle2, 0, 0);

    if (EIP93PhysAddress3.Addr != 0)
        HWPAL_DMAResource_PreDMA(DMAHandle3, 0, 0);

    return PEC_STATUS_OK;
}


/*----------------------------------------------------------------------------
 * PEC_SA_UnRegister
 */
PEC_Status_t
PEC_SA_UnRegister(
        DMABuf_Handle_t SA_Handle1,
        DMABuf_Handle_t SA_Handle2,
        DMABuf_Handle_t SA_Handle3)
{
    DMABuf_Handle_t SA_Handle[3];
    int i;

    if (!PEC_IsInitialized)
        return PEC_ERROR_BAD_USE_ORDER;

    SA_Handle[0] = SA_Handle1;
    SA_Handle[1] = SA_Handle2;
    SA_Handle[2] = SA_Handle3;

    for (i = 0; i < 3; i++)
    {
        if (Adapter_DMABuf_IsValidHandle(SA_Handle[i]))
        {
            HWPAL_DMAResource_Handle_t DMAHandle =
                Adapter_DMABuf_Handle2DMAResourceHandle(SA_Handle[i]);
            HWPAL_DMAResource_Record_t * Rec_p =
                HWPAL_DMAResource_Handle2RecordPtr(DMAHandle);

            // check if a bounce buffer is in use
#ifndef ADAPTER_REMOVE_BOUNCEBUFFERS
            HWPAL_DMAResource_Record_t * HostRec_p = Rec_p;

            if (Adapter_DMABuf_IsForeignAllocated(SA_Handle[i]))
            {
                DMAHandle = Adapter_DMABuf_Handle2DMAResourceHandle(
                                Rec_p->bounce.Bounce_Handle);
                Rec_p = HWPAL_DMAResource_Handle2RecordPtr(DMAHandle);
            }
#endif /* ADAPTER_REMOVE_BOUNCEBUFFERS */

            // ensure we look at valid engine-written data
            HWPAL_DMAResource_PostDMA(DMAHandle, 0, 0);
             // 0,0 = "entire buffer"

            // convert to host format
            HWPAL_DMAResource_Read32Array(
                    DMAHandle,
                    0,
                    Rec_p->host.BufferSize / 4,
                    Rec_p->host.HostAddr_p);

            // copy from bounce buffer to original buffer
#ifndef ADAPTER_REMOVE_BOUNCEBUFFERS
            if (Adapter_DMABuf_IsForeignAllocated(SA_Handle[i]))
            {
                // copy the data from bounce to original buffer
                memcpy(
                    HostRec_p->host.HostAddr_p,
                    Rec_p->host.HostAddr_p,
                    HostRec_p->host.BufferSize);

                // free the bounce handle
                DMABuf_Release(HostRec_p->bounce.Bounce_Handle);
                HostRec_p->bounce.Bounce_Handle = Adapter_DMABuf_NullHandle;
            }
#endif /* ADAPTER_REMOVE_BOUNCEBUFFERS */
        } // if handle vadlid
    } // for

    return PEC_STATUS_OK;
}


/*----------------------------------------------------------------------------
 * Adapter_PECPacketPut_PreparePKT
 *
 * Returns true in case of error
 */
static bool
Adapter_PECPacketPut_PreparePKT(
        const PEC_CommandDescriptor_t * const Cmd_p,
        EIP93_ARM_CommandDescriptor_t * const p,
        DMABuf_Handle_t * const BounceHandle_p)
{
    DMABuf_Handle_t SrcHandle = Cmd_p->SrcPkt_Handle;
    DMABuf_Handle_t DstHandle = Cmd_p->DstPkt_Handle;
    HWPAL_DMAResource_Handle_t SrcDMAHandle =
        Adapter_DMABuf_Handle2DMAResourceHandle(SrcHandle);
    HWPAL_DMAResource_Handle_t DstDMAHandle =
        Adapter_DMABuf_Handle2DMAResourceHandle(DstHandle);

    // Bounce packet data, if required
#ifndef ADAPTER_REMOVE_BOUNCEBUFFERS
    *BounceHandle_p = Adapter_DMABuf_NullHandle;

    if (Adapter_DMABuf_IsForeignAllocated(SrcHandle) ||
        Adapter_DMABuf_IsForeignAllocated(DstHandle))
    {
        HWPAL_DMAResource_Record_t * SrcDMARec_p =
                HWPAL_DMAResource_Handle2RecordPtr(SrcDMAHandle);
        HWPAL_DMAResource_Record_t * DstDMARec_p =
                HWPAL_DMAResource_Handle2RecordPtr(DstDMAHandle);
        DMABuf_Properties_t BounceProperties;
        DMABuf_HostAddress_t BounceHostAddr;
        DMABuf_Status_t dmares;

        BounceProperties.Alignment = 1;     // packet data is byte stream
        BounceProperties.Bank = 0;
        BounceProperties.fCached = false;
        BounceProperties.Size = MAX(
                        SrcDMARec_p->host.BufferSize,
                        DstDMARec_p->host.BufferSize);

        dmares = DMABuf_Alloc(
                        BounceProperties,
                        &BounceHostAddr,
                        BounceHandle_p);
        if (dmares != DMABUF_STATUS_OK)
        {
            LOG_CRIT(
                "PEC_Packet_Put: "
                "Failed to alloc bounce buffer (error %d)\n",
                dmares);
            return true;    // error
        }

        LOG_INFO(
            "PEC_Packet_Put: "
            "Bouncing packet: %p, %p to %p\n",
            SrcHandle.p,
            DstHandle.p,
            BounceHandle_p->p);

        // copy the useful data from the src to bounce
        memcpy(
            BounceHostAddr.p,
            SrcDMARec_p->host.HostAddr_p,
            Cmd_p->SrcPkt_ByteCount);

        // replace the source and destination handles (DMABuf and DMAResource)
        // to allow common code for the remainder of the conversion
        SrcHandle = *BounceHandle_p;
        DstHandle = SrcHandle;
        SrcDMAHandle = Adapter_DMABuf_Handle2DMAResourceHandle(SrcHandle);
        DstDMAHandle = SrcDMAHandle;
    }
#endif /* ADAPTER_REMOVE_BOUNCEBUFFERS */

    Adapter_GetEIP93PhysAddr(SrcHandle, NULL, &p->SrcPacketAddr);
    HWPAL_DMAResource_PreDMA(SrcDMAHandle, 0, 0);  // 0,0=whole buffer

    if (Adapter_DMABuf_IsSameHandle(&SrcHandle, &DstHandle))
    {
        // in-place operation
        p->DstPacketAddr = p->SrcPacketAddr;
    }
    else
    {
        Adapter_GetEIP93PhysAddr(DstHandle, NULL, &p->DstPacketAddr);

        // make sure we are not caching soon to be replaced data
        HWPAL_DMAResource_PreDMA(DstDMAHandle, 0, 0);  // 0,0=whole buffer
    }

    p->SrcPacketByteCount = Cmd_p->SrcPkt_ByteCount;
    p->BypassWordLength = Cmd_p->Bypass_WordCount;

    IDENTIFIER_NOT_USED(BounceHandle_p);

    return false;       // no error
}


/*----------------------------------------------------------------------------
 * Adapter_PECPacketPut_PrepareSA
 */
static void
Adapter_PECPacketPut_PrepareSA(
        const PEC_CommandDescriptor_t * const Cmd_p,
        EIP93_ARM_CommandDescriptor_t * const p)
{
    DMABuf_Handle_t SAHandle1 = Cmd_p->SA_Handle1;
    DMABuf_Handle_t SAHandle2 = Cmd_p->SA_Handle2;
    // support for bounced SA
#ifndef ADAPTER_REMOVE_BOUNCEBUFFERS
    if (Adapter_DMABuf_IsForeignAllocated(SAHandle1))
    {
        HWPAL_DMAResource_Handle_t SADMAHandle1 =
            Adapter_DMABuf_Handle2DMAResourceHandle(SAHandle1);
        HWPAL_DMAResource_Record_t * SARec_p1 =
            HWPAL_DMAResource_Handle2RecordPtr(SADMAHandle1);

        SAHandle1 = SARec_p1->bounce.Bounce_Handle;
    }
    if (Adapter_DMABuf_IsForeignAllocated(SAHandle2))
    {
        HWPAL_DMAResource_Handle_t SADMAHandle2 =
            Adapter_DMABuf_Handle2DMAResourceHandle(SAHandle2);
        HWPAL_DMAResource_Record_t * SARec_p2 =
            HWPAL_DMAResource_Handle2RecordPtr(SADMAHandle2);
        SAHandle2 = SARec_p2->bounce.Bounce_Handle;
    }

#endif /* ADAPTER_REMOVE_BOUNCEBUFFERS */

    Adapter_GetEIP93PhysAddr(
                SAHandle1,
                NULL,
                &p->SADataAddr);
    Adapter_GetEIP93PhysAddr(
                SAHandle2,
                NULL,
                &p->SAStateDataAddr);
    //p->SADataWordCount = Cmd_p->SA_WordCount;
}


/*----------------------------------------------------------------------------
 * PEC_Packet_Put
 */
PEC_Status_t
PEC_Packet_Put(
        const PEC_CommandDescriptor_t * Commands_p,
        const unsigned int CommandsCount,
        unsigned int * const PutCount_p)
{
    unsigned int CmdLp;
    unsigned int CmdDescriptorCount;

#ifdef ADAPTER_PEC_STRICT_ARGS
    if (Commands_p == NULL ||
        CommandsCount == 0 ||
        PutCount_p == NULL)
    {
        return PEC_ERROR_BAD_PARAMETER;
    }
#endif

    // initialize the output parameters
    *PutCount_p = 0;

#ifdef ADAPTER_PEC_STRICT_ARGS
    if (!PEC_IsInitialized)
        return PEC_ERROR_BAD_USE_ORDER;

    // validate the descriptors
    // (error out before bounce buffer allocation)
    for (CmdLp = 0; CmdLp < CommandsCount; CmdLp++)
        if (Commands_p[CmdLp].Bypass_WordCount > 255)
            return PEC_ERROR_BAD_PARAMETER;
#endif /* ADAPTER_PEC_STRICT_ARGS */

#ifndef ADAPTER_REMOVE_BOUNCEBUFFERS
    ZEROINIT(PEC_BounceHandles);
#endif

    CmdDescriptorCount = MIN(ADAPTER_MAX_EIP93LOGICDESCR, CommandsCount);

    // convert all the descriptors to EIP93 logical descriptors
    for (CmdLp = 0; CmdLp < CmdDescriptorCount; CmdLp++)
    {
        const PEC_CommandDescriptor_t * const Cmd_p = Commands_p + CmdLp;
        EIP93_ARM_CommandDescriptor_t * const p = PEC_Cmds + CmdLp;
        DMABuf_Handle_t * BounceHandle_p = NULL;

#ifndef ADAPTER_REMOVE_BOUNCEBUFFERS
        BounceHandle_p = PEC_BounceHandles + CmdLp;
#endif

        if (Adapter_PECPacketPut_PreparePKT(
                    Cmd_p,
                    p,
                    BounceHandle_p))
        {
            goto BAIL_OUT;
        }

        Adapter_PECPacketPut_PrepareSA(Cmd_p, p);

        p->ControlWord = Cmd_p->Control1;
    } // for

    // now call PacketPut
    {
        unsigned int DoneCount = 0;
        unsigned int TmpWriteIndex;
        EIP93_Status_t res;

        // Add the side channel information to the side channel FIFO
        // speculatively. If this would be done after Packet_Put, we
        // risk that the corresponding Packet_Get attempts to
        // retrieve these descriptors from the side channel
        // FIFO before they are added.
        TmpWriteIndex = Adapter_SideChannelFIFO.WriteIndex;
        for (CmdLp = 0; CmdLp < CmdDescriptorCount; CmdLp++)
        {
            const PEC_CommandDescriptor_t * const Cmd_p = Commands_p + CmdLp;
            Adapter_PacketSideChannelRecord_t * SideRec_p;

            SideRec_p = Adapter_SideChannelFIFO.Records +
                        Adapter_SideChannelFIFO.WriteIndex++;

            if (Adapter_SideChannelFIFO.WriteIndex ==
                Adapter_SideChannelFIFO.Size)
                Adapter_SideChannelFIFO.WriteIndex = 0;

            SideRec_p->User_p = Cmd_p->User_p;
            SideRec_p->SrcPkt_Handle = Cmd_p->SrcPkt_Handle;
            SideRec_p->DstPkt_Handle = Cmd_p->DstPkt_Handle;
#ifndef ADAPTER_REMOVE_BOUNCEBUFFERS
            SideRec_p->Bounce_Handle = PEC_BounceHandles[CmdLp];
#endif
        } // for

        res = EIP93_ARM_PacketPut(
                    &Adapter_EIP93_IOArea,
                    PEC_Cmds,
                    CmdDescriptorCount,
                    &DoneCount);

        if (res != EIP93_STATUS_OK)
            goto BAIL_OUT;

        *PutCount_p = DoneCount;

        // We may have put too many descriptors in the side channel FIFO
        // Adjust the write index to remove any excess records.
        if(DoneCount < CmdDescriptorCount)
        {
            TmpWriteIndex = TmpWriteIndex + DoneCount;

            if(TmpWriteIndex >= Adapter_SideChannelFIFO.Size)
                TmpWriteIndex -= Adapter_SideChannelFIFO.Size;

            Adapter_SideChannelFIFO.WriteIndex = TmpWriteIndex;
        }

#ifndef ADAPTER_REMOVE_BOUNCEBUFFERS
        // release bounce buffers not put successfully
        for (CmdLp = DoneCount; CmdLp < CmdDescriptorCount; CmdLp++)
            DMABuf_Release(PEC_BounceHandles[CmdLp]);
#endif
    }

    return PEC_STATUS_OK;

BAIL_OUT:

#ifndef ADAPTER_REMOVE_BOUNCEBUFFERS
    for (CmdLp = 0; CmdLp < ADAPTER_MAX_EIP93LOGICDESCR; CmdLp++)
        if (Adapter_DMABuf_IsValidHandle(PEC_BounceHandles[CmdLp]))
            DMABuf_Release(PEC_BounceHandles[CmdLp]);
#endif /* ADAPTER_REMOVE_BOUNCEBUFFERS */

    return PEC_ERROR_INTERNAL;
}


/*----------------------------------------------------------------------------
 * PEC_Packet_Get
 */
PEC_Status_t
PEC_Packet_Get(
        PEC_ResultDescriptor_t * Results_p,
        const unsigned int ResultsLimit,
        unsigned int * const GetCount_p)
{
#ifdef ADAPTER_PEC_STRICT_ARGS
    if (Results_p == NULL ||
        GetCount_p == NULL ||
        ResultsLimit == 0)
    {
        return PEC_ERROR_BAD_PARAMETER;
    }
#endif

    // initialize the output parameter
    *GetCount_p = 0;

#ifdef ADAPTER_PEC_STRICT_ARGS
    if (!PEC_IsInitialized)
        return PEC_ERROR_BAD_USE_ORDER;
#endif

    // read descriptors from EIP93
    {
        EIP93_Status_t res;
        unsigned int Limit = MIN(ResultsLimit, ADAPTER_MAX_EIP93LOGICDESCR);
        unsigned int DoneCount = 0;

#ifdef ADAPTER_PEC_DEBUG
        ZEROINIT(PEC_Results);
#endif

        res = EIP93_ARM_PacketGet(
                    &Adapter_EIP93_IOArea,
                    PEC_Results,
                    Limit,
                    &DoneCount);

        if (res != EIP93_STATUS_OK)
        {
            LOG_WARN(
                "PEC_Packet_Get: "
                "EIP93_ARM_PacketGet returned %d\n",
                res);
            return PEC_ERROR_INTERNAL;
        }

        // now transform these result descriptors from EIP93 to PEC format
        // and add the information from the result-command matcher FIFO
        {
            Adapter_PacketSideChannelRecord_t * SideRec_p;
            EIP93_ARM_ResultDescriptor_t * Res_p;
            unsigned int ResLp;

            for (ResLp = 0; ResLp < DoneCount; ResLp++)
            {
                Res_p = PEC_Results + ResLp;

#ifdef ADAPTER_PEC_DEBUG
                if (Res_p->BypassWordLength == 0 &&
                    Res_p->DstPacketByteCount == 0 &&
                    Res_p->StatusWord == 0)
                {
                    LOG_CRIT(
                        "PEC_Packet_Get: "
                        "Detected NULL descriptor (%u)!\n",
                        ResLp);
                }
#endif

                if (Adapter_SideChannelFIFO.ReadIndex ==
                    Adapter_SideChannelFIFO.WriteIndex)
                {
                    LOG_CRIT("PEC_Packet_Get: Side-channel is empty!\n");
                }

                SideRec_p = Adapter_SideChannelFIFO.Records +
                            Adapter_SideChannelFIFO.ReadIndex++;

                if (Adapter_SideChannelFIFO.ReadIndex ==
                    Adapter_SideChannelFIFO.Size)
                    Adapter_SideChannelFIFO.ReadIndex = 0;

                Results_p->User_p = SideRec_p->User_p;
                Results_p->SrcPkt_Handle = SideRec_p->SrcPkt_Handle;
                Results_p->DstPkt_Handle = SideRec_p->DstPkt_Handle;

                // find the destination buffer host address
                {
                    HWPAL_DMAResource_Handle_t DMAHandle =
                            Adapter_DMABuf_Handle2DMAResourceHandle(
                                        SideRec_p->DstPkt_Handle);
                    HWPAL_DMAResource_Record_t * Rec_p =
                        HWPAL_DMAResource_Handle2RecordPtr(DMAHandle);

                    if (Rec_p)
                    {
#ifndef ADAPTER_REMOVE_BOUNCEBUFFERS
                        if (Adapter_DMABuf_IsValidHandle(
                            SideRec_p->Bounce_Handle))
                        {
                            HWPAL_DMAResource_Handle_t BounceDMAHandle =
                                Adapter_DMABuf_Handle2DMAResourceHandle(
                                        SideRec_p->Bounce_Handle);
                            HWPAL_DMAResource_Record_t * BounceRec_p =
                                HWPAL_DMAResource_Handle2RecordPtr(
                                        BounceDMAHandle);

                            HWPAL_DMAResource_PostDMA(
                                   BounceDMAHandle, 0, 0);

                            // copy bounce to destination
                            memcpy(
                                Rec_p->host.HostAddr_p,
                                BounceRec_p->host.HostAddr_p,
                                Rec_p->host.BufferSize);

                            // free the bounce buffer
                            DMABuf_Release(SideRec_p->Bounce_Handle);
                        }
                        else
                        {
                            HWPAL_DMAResource_PostDMA(DMAHandle, 0, 0);
                        }
#else
                        HWPAL_DMAResource_PostDMA(DMAHandle, 0, 0);
#endif /* ADAPTER_REMOVE_BOUNCEBUFFERS */
                        Results_p->DstPkt_p = Rec_p->host.HostAddr_p;
                    }
                    else
                    {
                        Results_p->DstPkt_p = NULL;

                        LOG_WARN(
                                "PEC_Packet_Get: "
                                "Failed to find DstPkt_p for handle %p\n",
                                SideRec_p->DstPkt_Handle.p);
                    }
                }

                Results_p->Bypass_WordCount = Res_p->BypassWordLength;
                Results_p->DstPkt_ByteCount = Res_p->DstPacketByteCount;
                Results_p->Status1 = Res_p->StatusWord;
                Results_p->Status2 = 0;     // not used in this driver

                Results_p++;
            } // for
        }

        *GetCount_p = DoneCount;

        // To help CommandNotifyCB
        Adapter_MakeCommandNotify_CallBack();

    }

    return PEC_STATUS_OK;
}


/*----------------------------------------------------------------------------
 * PEC_CommandNotify_Request
 */
PEC_Status_t
PEC_CommandNotify_Request(
        PEC_NotifyFunction_t CBFunc_p,
        const unsigned int CommandsCount)
{
    unsigned int PacketSlotsEmptyCount;

    if (CBFunc_p == NULL ||
        CommandsCount == 0 ||
        CommandsCount > Adapter_EIP93_MaxDescriptorsInRing)
    {
        return PEC_ERROR_BAD_PARAMETER;
    }

    if (!PEC_IsInitialized)
        return PEC_ERROR_BAD_USE_ORDER;

    // check if callback was already installed
    if (PEC_Notify.CommandNotifyCB_p)
        return PEC_ERROR_BAD_USE_ORDER;

    PacketSlotsEmptyCount = Adapter_CalulateEmptySlotCount();

    if (PEC_Notify.CommandsCount <= PacketSlotsEmptyCount)
    {
        CBFunc_p();
    }
    else
    {
        PEC_Notify.CommandsCount = CommandsCount;
        PEC_Notify.CommandNotifyCB_p = CBFunc_p;
    }

#ifdef ADAPTER_EIP93PE_INTERRUPTS_ENABLE
    Adapter_Interrupt_Enable(IRQ_CDR_THRESH_IRQ);
    Adapter_Interrupt_SetHandler(
            IRQ_CDR_THRESH_IRQ,
            Adapter_EIP93_InterruptHandler_DescriptorPut);

    LOG_WARN("Adapter_EIP93_InterruptHandler_DescriptorPut registered.\n");
#endif //  ADAPTER_EIP93PE_INTERRUPTS_ENABLE

    return PEC_STATUS_OK;
}


#ifdef ADAPTER_EIP93PE_INTERRUPTS_ENABLE

/*----------------------------------------------------------------------------
 * Adapter_EIP93_BH_Handler
 *
 */
void
Adapter_EIP93_BH_Handler_ResultGet(
        unsigned long data)
{
    IDENTIFIER_NOT_USED(data);

    if (PEC_Notify.ResultNotifyCB_p != NULL)
    {
        PEC_NotifyFunction_t CBFunc_p;

        // Keep the callback on stack to allow registeration
        // of another result notify request from callback
        CBFunc_p = PEC_Notify.ResultNotifyCB_p;

        PEC_Notify.ResultNotifyCB_p = NULL;
        PEC_Notify.ResultsCount = 0;

        // disable interrupt in top half now.


        Adapter_Interrupt_Disable(IRQ_RDR_THRESH_IRQ );


        LOG_INFO(
            "Adapter_EIP93_BH_Handler_ResultGet: "
            "Making PEC_ResultNotify_Request callback.\n");

        CBFunc_p();
    }
}

void
Adapter_EIP93_BH_Handler_PktPut(
        unsigned long data)
{
    IDENTIFIER_NOT_USED(data);

    if (PEC_Notify.CommandNotifyCB_p != NULL)
    {
        PEC_NotifyFunction_t CBFunc_p;

        // Keep the callback on stack to allow registeration
        // of another result notify request from callback
        CBFunc_p = PEC_Notify.CommandNotifyCB_p;

        PEC_Notify.CommandNotifyCB_p = NULL;
        PEC_Notify.CommandsCount = 0;

        // disable interrupt in top half now.


        Adapter_Interrupt_Disable(IRQ_CDR_THRESH_IRQ );


        LOG_INFO(
            "Adapter_EIP93_BH_Handler_PktPut: "
            "Making PEC_CommandNotify_Request callback.\n");

        CBFunc_p();
    }
}



#endif /* ADAPTER_EIP93PE_INTERRUPTS_ENABLE */


/*----------------------------------------------------------------------------
 * PEC_ResultNotify_Request
 */
PEC_Status_t
PEC_ResultNotify_Request(
        PEC_NotifyFunction_t CBFunc_p,
        const unsigned int ResultsCount)
{
    if (CBFunc_p == NULL ||
        ResultsCount == 0 ||
        ResultsCount > Adapter_EIP93_MaxDescriptorsInRing)
    {
        return PEC_ERROR_BAD_PARAMETER;
    }

    if (!PEC_IsInitialized)
        return PEC_ERROR_BAD_USE_ORDER;

    // check if callback was already installed
    if (PEC_Notify.ResultNotifyCB_p)
        return PEC_ERROR_BAD_USE_ORDER;

    // install it
    PEC_Notify.ResultsCount = ResultsCount;
    PEC_Notify.ResultNotifyCB_p = CBFunc_p;

#ifdef ADAPTER_EIP93PE_INTERRUPTS_ENABLE

    Adapter_Interrupt_Enable(IRQ_RDR_THRESH_IRQ);
    LOG_WARN("Adapter_EIP93_InterruptHandler_DescriptorDone registered.\n");

    Adapter_Interrupt_SetHandler(
                IRQ_RDR_THRESH_IRQ,
                Adapter_EIP93_InterruptHandler_DescriptorDone);


#endif /* ADAPTER_EIP93PE_INTERRUPTS_ENABLE */

    return PEC_STATUS_OK;
}

#else
;       // avoids "empty translation unit" warning
#endif /* ADAPTER_EIP93_PE_MODE_ARM */

/* end of file adapter_pec_eip93_arm.c */
