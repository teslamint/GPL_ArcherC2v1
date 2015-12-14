/* adapter_pec_eip93_dhm.c
 *
 * Packet Engine Control (PEC) API Implementation
 * supporting the EIP93 in Direct Host Mode (DHM)
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

#ifdef ADAPTER_EIP93_PE_MODE_DHM


#include "basic_defs.h"         // uint32_t
#include "hw_access_dma.h"      // HWPAL_Resource_*
#include "api_pec.h"            // PEC_* (the API we implement here)
#include "api_dmabuf.h"         // DMABuf_*
#include "adapter_internal.h"
#include "eip93_dhm.h"        // driver library API we will use

//#include <linux/delay.h>        // msleep


static bool PEC_IsInitialized = false;

static struct
{
    // registered SA
    DMABuf_Handle_t SA_Handle;
    DMABuf_Handle_t SA_State_Handle;
    DMABuf_Handle_t SA_ARC4State_Handle;

    // details to remember between Packet_Put and Packet_Get
    void * User_p;
    DMABuf_Handle_t SrcPkt_Handle;
    DMABuf_Handle_t DstPkt_Handle;
    uint8_t * DstPkt_HostAddr_p;

    uint32_t * SARecord_p;
    unsigned int SARecordLength;
    uint32_t * SAState_p;
    unsigned int  SAStateLength;
    uint32_t * ARC4State_p;
    unsigned int ARC4StateLength;

    EIP93_DHM_Buffer_t SrcData;
    EIP93_DHM_Buffer_t DstData;

} Adapter_DHM_Work;

static struct
{
    PEC_NotifyFunction_t ResultNotifyCB_p;
    unsigned int ResultsCount;

    PEC_NotifyFunction_t CommandNotifyCB_p;
    unsigned int CommandsCount;
} Adapter_DHM_PEC_Notify;



/*----------------------------------------------------------------------------
 * PEC_Capabilities_Get
 */
static const PEC_Capabilities_t Capabilities =
{
    // note: no interrupt support, so always polling
    "EIP-93v_._p_ Packet Engine (DHM,Poll)"        // szTextDescription
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
 * PEC_Init
 */
PEC_Status_t
PEC_Init(
        const PEC_InitBlock_t * const InitBlock_p)
{
    // ensure we init only once
    if (PEC_IsInitialized == false)
    {
        // dynamic SA is not support in DHM mode
        if (InitBlock_p->fUseDynamicSA)
            return PEC_ERROR_BAD_PARAMETER;

        ZEROINIT(Adapter_DHM_PEC_Notify);
        ZEROINIT(Adapter_DHM_Work);

        if (!Adapter_EIP93_SetMode_DHM())
            return PEC_ERROR_INTERNAL;      // ## RETURN ##
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

        PEC_IsInitialized = false;
    }

    return PEC_STATUS_OK;
}


/*----------------------------------------------------------------------------
 * PEC_SA_Register
 *
 * SA_Handle1 = SA
 * SA_Handle2 = State (optional)
 * SA_Handle3 = ARC4 State (optional)
 */
PEC_Status_t
PEC_SA_Register(
        DMABuf_Handle_t SA_Handle1,
        DMABuf_Handle_t SA_Handle2,
        DMABuf_Handle_t SA_Handle3)
{
    IDENTIFIER_NOT_USED(&SA_Handle1 > &SA_Handle2);
    IDENTIFIER_NOT_USED(&SA_Handle2 > &SA_Handle3);

    LOG_INFO(
        "PEC_SA_Register: "
        "SA_Handle1,2,3 = %p, %p, %p\n",
        SA_Handle1.p,
        SA_Handle2.p,
        SA_Handle3.p);

    // reset the previous handles
    Adapter_DHM_Work.SA_Handle = Adapter_DMABuf_NullHandle;
    Adapter_DHM_Work.SA_State_Handle = Adapter_DMABuf_NullHandle;
    Adapter_DHM_Work.SA_ARC4State_Handle = Adapter_DMABuf_NullHandle;

    if (!Adapter_DMABuf_IsValidHandle(SA_Handle1))
        return PEC_ERROR_BAD_HANDLE;

    // accepted as the SA Handle
    Adapter_DHM_Work.SA_Handle = SA_Handle1;

    if (Adapter_DMABuf_IsValidHandle(SA_Handle2))
    {
        // make sure it is not identical to SA_Handle1
        if (Adapter_DMABuf_IsSameHandle(&SA_Handle1, &SA_Handle2))
            return PEC_ERROR_BAD_HANDLE;

        // State record is of variable size, but depends on the SA format
        // SA_Rev1: 10 words = 40 bytes
        // SA_Rev2: 22 words = 88 bytes
        // DynSA: 4, 18 or 22 bytes = 16, 72 or 88 bytes
        // verify the buffer is large enough
        // by checking it here, we can assume the fixed size in Packet_Put
        {
            HWPAL_DMAResource_Handle_t DMAHandle;
            HWPAL_DMAResource_Record_t * DMARec_p;

            DMAHandle = Adapter_DMABuf_Handle2DMAResourceHandle(SA_Handle2);
            DMARec_p = HWPAL_DMAResource_Handle2RecordPtr(DMAHandle);
            if (DMARec_p == NULL)
            {
                LOG_WARN(
                    "PEC_Register_SA: "
                    "Address look-up for SA_Handle2 failed\n");

                return PEC_ERROR_BAD_HANDLE;
            }

            if (DMARec_p->host.BufferSize < 16)
            {
                LOG_CRIT(
                    "PEC_Register_SA: "
                 "Rejecting SA_Handle2 for State Record because size %d < 16\n",
                    DMARec_p->host.BufferSize);

                return PEC_ERROR_BAD_HANDLE;
            }
        }

        // accepted as the SA State Record buffer
        Adapter_DHM_Work.SA_State_Handle = SA_Handle2;
    }

    if (Adapter_DMABuf_IsValidHandle(SA_Handle3))
    {
        // make sure it is not identical to SA_Handle1 or SA_Handle2
        if (Adapter_DMABuf_IsSameHandle(&SA_Handle1, &SA_Handle3) ||
            Adapter_DMABuf_IsSameHandle(&SA_Handle2, &SA_Handle3))
        {
            return PEC_ERROR_BAD_HANDLE;
        }

        // ARC4 State record is fixed size 256 bytes
        // verify the buffer is large enough
        // by checking it here, we can assume the fixed size in Packet_Put
        {
            HWPAL_DMAResource_Handle_t DMAHandle;
            HWPAL_DMAResource_Record_t * DMARec_p;

            DMAHandle = Adapter_DMABuf_Handle2DMAResourceHandle(SA_Handle3);
            DMARec_p = HWPAL_DMAResource_Handle2RecordPtr(DMAHandle);
            if (DMARec_p == NULL)
            {
                LOG_WARN(
                    "PEC_Register_SA: "
                    "Address look-up for SA_Handle3 failed\n");

                return PEC_ERROR_BAD_HANDLE;
            }

            if (DMARec_p->host.BufferSize < 256)
            {
                LOG_CRIT(
                    "PEC_Register_SA: "
                 "Rejecting SA_Handle3 for ARC4 State because size %d < 256\n",
                    DMARec_p->host.BufferSize);

                return PEC_ERROR_BAD_HANDLE;
            }
        }

        // accept it as the SA ARC4 State buffer
        Adapter_DHM_Work.SA_ARC4State_Handle = SA_Handle3;
    }

    // this call is not required, so we fake it is OK
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
    IDENTIFIER_NOT_USED(&SA_Handle1 > &SA_Handle2);
    IDENTIFIER_NOT_USED(&SA_Handle2 > &SA_Handle3);

    if (!Adapter_DMABuf_IsValidHandle(SA_Handle1))
        return PEC_ERROR_BAD_HANDLE;

    // this call is not required, so we fake it is OK
    if (!Adapter_DMABuf_IsSameHandle(&SA_Handle1, &Adapter_DHM_Work.SA_Handle))
    {
        LOG_WARN(
        "PEC_SA_UnRegister: SA_Handle1 mismatch with registered handle\n");
    }

    // handle2 is optional
    if (Adapter_DMABuf_IsValidHandle(SA_Handle2))
    {
        if (!Adapter_DMABuf_IsSameHandle(&SA_Handle2,
            &Adapter_DHM_Work.SA_State_Handle))
        {
            LOG_WARN(
            "PEC_SA_UnRegister:SA_Handle2 mismatch with registered handle\n");
        }
    }

    // handle 3 is optional
    if (Adapter_DMABuf_IsValidHandle(SA_Handle3))
    {
        if (!Adapter_DMABuf_IsSameHandle(&SA_Handle3,
            &Adapter_DHM_Work.SA_ARC4State_Handle))
        {
            LOG_WARN(
            "PEC_SA_UnRegister:SA_Handle3 mismatch with registered handle\n");
        }
    }

    Adapter_DHM_Work.SA_Handle = Adapter_DMABuf_NullHandle;
    Adapter_DHM_Work.SA_State_Handle = Adapter_DMABuf_NullHandle;
    Adapter_DHM_Work.SA_ARC4State_Handle = Adapter_DMABuf_NullHandle;

    return PEC_STATUS_OK;
}


/*----------------------------------------------------------------------------
 * Adapter_DHM_Work_Fill
 *
 * This function fills the Adapter_DHM_Work fields based on the command
 * descriptor received in Packet_Put. These fields are needed during
 * PEC_Packet_Put as well as PEC_Packet_Get, hence remembering them in Work.
 *
 * Returns PEC_STATUS_OK or one of PEC_ERROR_xxx.
 */
static PEC_Status_t
Adapter_DHM_Work_Fill(
        const PEC_CommandDescriptor_t * const Cmd_p)
{
    HWPAL_DMAResource_Handle_t DMAHandle;
    HWPAL_DMAResource_Record_t * DMARec_p;

    // SA is mandatory, so verify handle
    if (!Adapter_DMABuf_IsValidHandle(Cmd_p->SA_Handle1))
    {
        LOG_WARN(
            "PEC_Packet_Put: "
            "Invalid SA_Handle1\n");
        return PEC_ERROR_BAD_HANDLE;        // ## RETURN ##
    }

    DMAHandle = Adapter_DMABuf_Handle2DMAResourceHandle(Cmd_p->SA_Handle1);
    DMARec_p = HWPAL_DMAResource_Handle2RecordPtr(DMAHandle);
    if (DMARec_p == NULL)
    {
        LOG_WARN(
            "PEC_Packet_Put: "
            "Address lookup for SA_Handle1 failed\n");
        return PEC_ERROR_BAD_HANDLE;
    }

    Adapter_DHM_Work.SARecord_p = DMARec_p->host.HostAddr_p;
    Adapter_DHM_Work.SARecordLength = Cmd_p->SA_WordCount;

    // initialize the State Record and ARC4 State buffer fields
    Adapter_DHM_Work.SAState_p = NULL;
    Adapter_DHM_Work.SAStateLength = 0;
    Adapter_DHM_Work.ARC4State_p = NULL;
    Adapter_DHM_Work.ARC4StateLength = 0;


    // now figure out if the SA_Handle2 is valid and fill in the
    // State Record or ARC4 State Buffer fields
    if (Adapter_DMABuf_IsValidHandle(Cmd_p->SA_Handle2))
    {
        DMAHandle = Adapter_DMABuf_Handle2DMAResourceHandle(
                Cmd_p->SA_Handle2);
        DMARec_p = HWPAL_DMAResource_Handle2RecordPtr(DMAHandle);
        if (DMARec_p == NULL)
        {
            LOG_WARN(
                "PEC_Packet_Put: "
                "Address lookup for SA_Handle2 failed\n");
            return PEC_ERROR_BAD_HANDLE;
        }

        // we accepts SA_Handle2 if it matches the State or ARC4State
        // handle that was provided to PEC_Register_SA
        if (Adapter_DMABuf_IsSameHandle(
                    &Cmd_p->SA_Handle2,
                    &Adapter_DHM_Work.SA_State_Handle))
        {
            // SA_Handle2 provided in the command descriptor
            // is for the State record

            // get the size of the DMA buffer, in bytes
            unsigned int Len = DMARec_p->host.BufferSize;
            Len = MIN(Len, 22*4);

            Adapter_DHM_Work.SAState_p = DMARec_p->host.HostAddr_p;
            Adapter_DHM_Work.SAStateLength = Len / 4;     // in words
        }

        if (Adapter_DMABuf_IsSameHandle(
                    &Cmd_p->SA_Handle2,
                    &Adapter_DHM_Work.SA_ARC4State_Handle))
        {
            // SA_Handle2 provided in the command descriptor
            // is for the ARC4 State record
            // size is fixed, 256 bytes
            Adapter_DHM_Work.ARC4State_p = DMARec_p->host.HostAddr_p;
            Adapter_DHM_Work.ARC4StateLength = 256 / 4;   // in words
        }
    }

    // initialize the data plane structures
    // source packet
    if (!Adapter_DMABuf_IsValidHandle(Cmd_p->SrcPkt_Handle))
    {
        LOG_WARN(
            "PEC_Packet_Put: "
            "Invalid source data handle!\n");
        return PEC_ERROR_BAD_HANDLE;
    }

    DMAHandle = Adapter_DMABuf_Handle2DMAResourceHandle(
                    Cmd_p->SrcPkt_Handle);
    DMARec_p = HWPAL_DMAResource_Handle2RecordPtr(DMAHandle);
    if (DMARec_p == NULL)
    {
        LOG_WARN(
            "PEC_Packet_Put: "
            "Address lookup for Source Packet Handle failed\n");
        return PEC_ERROR_BAD_HANDLE;
    }

    Adapter_DHM_Work.SrcPkt_Handle = Cmd_p->SrcPkt_Handle;
    EIP93_DHM_Data_Init(
            &Adapter_DHM_Work.SrcData,
            DMARec_p->host.HostAddr_p,
            DMARec_p->host.BufferSize);

    // destination packet
    if (!Adapter_DMABuf_IsValidHandle(Cmd_p->DstPkt_Handle))
    {
        LOG_WARN(
            "PEC_Packet_Put: "
            "Invalid source data handle!\n");
        return PEC_ERROR_BAD_HANDLE;
    }

    DMAHandle = Adapter_DMABuf_Handle2DMAResourceHandle(
                    Cmd_p->DstPkt_Handle);
    DMARec_p = HWPAL_DMAResource_Handle2RecordPtr(DMAHandle);
    if (DMARec_p == NULL)
    {
        LOG_WARN(
            "PEC_Packet_Put: "
            "Address lookup for Destination Packet Handle failed\n");
        return PEC_ERROR_BAD_HANDLE;
    }

    Adapter_DHM_Work.DstPkt_Handle = Cmd_p->DstPkt_Handle;
    Adapter_DHM_Work.DstPkt_HostAddr_p = DMARec_p->host.HostAddr_p;
    EIP93_DHM_Data_Init(
            &Adapter_DHM_Work.DstData,
            DMARec_p->host.HostAddr_p,
            DMARec_p->host.BufferSize);

    Adapter_DHM_Work.User_p = Cmd_p->User_p;

    return PEC_STATUS_OK;
}


/*----------------------------------------------------------------------------
 * Adapter_DHM_Work_Put
 *
 * This function takes the information in Adapter_DHM_Work and calls
 * EIP93_DHM_Packet_Put. Remaining fields of the command descriptor not
 * looked at by Adapter_DHM_Work_Fill are validated here.
 *
 * Returns PEC_STATUS_OK or one of PEC_ERROR_xxx.
 */
PEC_Status_t
Adapter_DHM_Work_Put(
        const PEC_CommandDescriptor_t * const Cmd_p)
{

    EIP93_DHM_CommandDescriptor_t CD = {0};
    EIP93_Status_t res93;

    if (Cmd_p->Bypass_WordCount > 255)
        return PEC_ERROR_BAD_PARAMETER;

    CD.BypassWordsCount = (uint8_t)Cmd_p->Bypass_WordCount;
    CD.SrcPacketByteCount = Cmd_p->SrcPkt_ByteCount;
    CD.ControlWord = Cmd_p->Control1;

    CD.SARecord_p = Adapter_DHM_Work.SARecord_p;
    CD.SARecordLength = Adapter_DHM_Work.SARecordLength;
    CD.SAState_p = Adapter_DHM_Work.SAState_p;
    CD.SAStateLength = Adapter_DHM_Work.SAStateLength;
      CD.ARC4State_p = Adapter_DHM_Work.ARC4State_p;
    CD.ARC4StateLength = Adapter_DHM_Work.ARC4StateLength;

    LOG_INFO("Adapter_DHM: Calling EIP93_DHM_Packet_Put\n");

    res93 = EIP93_DHM_Packet_Put(
                &Adapter_EIP93_IOArea,
                &CD);

    if (res93 != EIP93_STATUS_OK)
    {
        LOG_CRIT(
            "PEC_Packet_Put: "
            "EIP93_DHM_Packet_Put returned %d\n",
            res93);
        return PEC_ERROR_INTERNAL;
    }


    return PEC_STATUS_OK;
}


/*----------------------------------------------------------------------------
 * PEC_Packet_Put
 *
 * This implementation is non-blocking. It starts the operation and provides
 * the first input data and then returns. PEC_Packet_Get must be polled to
 * pump more data and get the final result (no busy-wait loops in here).
 */
PEC_Status_t
PEC_Packet_Put(
        const PEC_CommandDescriptor_t * Commands_p,
        const unsigned int CommandsCount,
        unsigned int * const PutCount_p)
{
    PEC_Status_t res;

    if (Commands_p == NULL ||
        CommandsCount == 0 ||
        PutCount_p == NULL)
    {
        return PEC_ERROR_BAD_PARAMETER;
    }

    // initialize the output parameter
    *PutCount_p = 0;

    // now validate the command descriptor parameters
    // and fill in the static Work structure
    res = Adapter_DHM_Work_Fill(Commands_p);
    if (res != PEC_STATUS_OK)
        return res;

    // now start the operation by calling EIP93_DHM_Packet_Put
    // providing the information we have in the static Work structure
    res = Adapter_DHM_Work_Put(Commands_p);
    if (res != PEC_STATUS_OK)
        return res;

    *PutCount_p = 1;

    // write the first data to the input buffer
    {
        EIP93_Status_t res93;

        LOG_INFO("Adapter_DHM: Calling EIP93_PE_DHM_PktFragment_Put\n");

        res93 = EIP93_DHM_Data_Put(
                    &Adapter_EIP93_IOArea,
                    &Adapter_DHM_Work.SrcData);

        if (res93 != EIP93_STATUS_OK)
        {
            LOG_WARN(
                "PEC_Packet_Put: "
                "EIP93_PE_DHM_PktFragment_Put returned %d\n",
                res93);

            return PEC_ERROR_INTERNAL;      // ## RETURN ##
        }
    }

    // remainder of data pumping will be done in PEC_Packet_Get
    // (or on interrupt)

    return PEC_STATUS_OK;
}


/*----------------------------------------------------------------------------
 * Adapter_DHM_Work_Get
 *
 * This routine fills the result descriptor and reads the SA parts once the
 * operation has completed.
 *
 * Returns PEC_STATUS_OK or one of the PEC_ERROR_xxx.
 */
static PEC_Status_t
Adapter_DHM_Work_Get(
        PEC_ResultDescriptor_t * const Res_p)
{

    EIP93_DHM_ResultDescriptor_t RD = { 0 };
    EIP93_Status_t res93;

    RD.SARecord_p = Adapter_DHM_Work.SARecord_p;
    RD.SARecordLength = Adapter_DHM_Work.SARecordLength;
    RD.SAState_p = Adapter_DHM_Work.SAState_p;
    RD.SAStateLength = Adapter_DHM_Work.SAStateLength;
    RD.ARC4State_p = Adapter_DHM_Work.ARC4State_p;
    RD.ARC4StateLength = Adapter_DHM_Work.ARC4StateLength;

    // read the result descriptor from EIP93
    res93 = EIP93_DHM_Packet_Get(
                &Adapter_EIP93_IOArea,
                &RD);

    if (res93 != EIP93_STATUS_OK)
    {
        LOG_WARN(
            "PEC_Packet_Get: "
            "EIP93_DHM_Packet_Get returned %d\n",
            res93);

        return PEC_ERROR_INTERNAL;
    }

    // now transform result descriptor from EIP93 to PEC format
    Res_p->DstPkt_ByteCount = RD.DstPacketByteCount;
    Res_p->Bypass_WordCount = RD.BypassWordsCount;
    Res_p->Status1 = RD.StatusWord;
    Res_p->Status2 = 0;     // not used in this driver

    // Other params from saved side channel record
    Res_p->User_p = Adapter_DHM_Work.User_p;
    Res_p->SrcPkt_Handle = Adapter_DHM_Work.SrcPkt_Handle;
    Res_p->DstPkt_Handle = Adapter_DHM_Work.DstPkt_Handle;

    // as a courtesy, also return the destination data buffer host address
    Res_p->DstPkt_p = Adapter_DHM_Work.DstPkt_HostAddr_p;

    return PEC_STATUS_OK;
}


/*----------------------------------------------------------------------------
 * PEC_Packet_Get
 *
 * This implementation is non-blocking. It pumps some data and returns whether
 * the operation has finished or not (no busy-wait loops in here).
 */
PEC_Status_t
PEC_Packet_Get(
        PEC_ResultDescriptor_t * Results_p,
        const unsigned int ResultsLimit,
        unsigned int * const GetCount_p)
{
    EIP93_Status_t res93;
    EIP93_DHM_Progress_t Progress;

    if (Results_p == NULL ||
        GetCount_p == NULL ||
        ResultsLimit == 0)
    {
        return PEC_ERROR_BAD_PARAMETER;
    }

    // initialize the output parameters
    *GetCount_p = 0;

    // get the progress
    res93 = EIP93_DHM_Progress_Get(
                &Adapter_EIP93_IOArea,
                &Progress);
    if (res93 != EIP93_STATUS_OK)
    {
        LOG_WARN(
            "PEC_Packet_Get: "
            "EIP93_DHM_Progress_Get returned %d\n",
            res93);
        return PEC_ERROR_INTERNAL;      // ## RETURN ##
    }

    LOG_INFO("Adapter_DHM: Progress = 0x%x\n", Progress);

    // provide more input data, if needed
    if (Progress & EIP93_DHM_INT_INPUT_BUFFER)
    {
        LOG_INFO(
            "PEC_Packet_Get: "
            "Calling EIP93_DHM_Data_Put (Length=%u)\n",
            Adapter_DHM_Work.SrcData.Length);

        res93 = EIP93_DHM_Data_Put(
                    &Adapter_EIP93_IOArea,
                    &Adapter_DHM_Work.SrcData);

        if (res93 != EIP93_STATUS_OK)
        {
            LOG_WARN(
                "PEC_Packet_Get: "
                "EIP93_DHM_Data_Put returned %d\n",
                res93);
            return PEC_ERROR_INTERNAL;      // ## RETURN ##
        }
    }

    // read output data (upon threshold)
    // read output data (last part) when operation has completed
    if (Progress & EIP93_DHM_INT_OPERATION_DONE ||
        Progress & EIP93_DHM_INT_OUTPUT_BUFFER)
    {
        LOG_INFO(
            "PEC_Packet_Get: "
            "Calling EIP93_DHM_Data_Get (Length=%u)\n",
            Adapter_DHM_Work.DstData.Length);

        res93 = EIP93_DHM_Data_Get(
                    &Adapter_EIP93_IOArea,
                    &Adapter_DHM_Work.DstData);

        if (res93 != EIP93_ERROR_NO_MORE_DATA)
        {
            if (res93 != EIP93_STATUS_OK)
            {
                LOG_WARN(
                    "PEC_Packet_Get: "
                    "EIP93_DHM_Data_Get returned %d\n",
                    res93);
                return PEC_ERROR_INTERNAL;      // ## RETURN ##
            }
        }
    }

    // check if the operation has completed
    if (Progress &  EIP93_DHM_INT_OPERATION_DONE)
    {
        PEC_Status_t res;

        LOG_INFO(
            "PEC_Packet_Get: "
            "Operation done!\n");

        res = Adapter_DHM_Work_Get(Results_p);
        if (res != PEC_STATUS_OK)
            return res;     // ## RETURN ##

        *GetCount_p = 1;
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
    IDENTIFIER_NOT_USED(CBFunc_p);
    IDENTIFIER_NOT_USED(CommandsCount);

    return PEC_ERROR_NOT_IMPLEMENTED;
}


/*----------------------------------------------------------------------------
 * PEC_ResultNotify_Request
 */
PEC_Status_t
PEC_ResultNotify_Request(
        PEC_NotifyFunction_t CBFunc_p,
        const unsigned int ResultsCount)
{
    IDENTIFIER_NOT_USED(CBFunc_p);
    IDENTIFIER_NOT_USED(ResultsCount);

    return PEC_ERROR_NOT_IMPLEMENTED;
}

#else

;       // avoids "empty translation unit" warning
#endif /* ADAPTER_EIP93_PE_MODE_DHM */

/* end of file adapter_pec_eip93_dhm.c */
