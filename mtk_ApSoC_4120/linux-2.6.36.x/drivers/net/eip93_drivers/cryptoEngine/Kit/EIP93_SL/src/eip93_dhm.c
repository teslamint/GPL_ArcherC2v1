/* eip93_dhm.c
 *
 * Driver for the EIP93 packet Engine.
 *
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

#include "basic_defs.h"        // uint8_t, IDENTIFIER_NOT_USED, etc.
#include "hw_access.h"         // HW access API
#include "eip93_dhm.h"          // the API we will implement
#include "c_eip93.h"           // configration options
#include "eip93_hw_interface.h"   // the HW interface (register map)
#include "eip93_level0.h"
#include "eip93_dhm_level0.h"      // macros and functions to access EIP93 reg
#include "eip93_internal.h"


#ifdef EIP93_STRICT_ARGS


#define EIP93_INSERTCODE_FUNCTION_ENTRY_CODE_DHM \
    EIP93_Status_t res = EIP93_STATUS_OK; \
    EIP93_Device_t* Device_p = NULL; \
    EIP93_DHM_Mode_t* DHM_p = NULL; \
    EIP93_CHECK_POINTER(IOArea_p); \
    Device_p = (EIP93_Device_t*)IOArea_p; \
    DHM_p = &Device_p->extras.DHM_mode; \
    IDENTIFIER_NOT_USED(DHM_p);
#else

#define EIP93_INSERTCODE_FUNCTION_ENTRY_CODE_DHM \
    EIP93_Status_t res = EIP93_STATUS_OK; \
    EIP93_Device_t* Device_p = (EIP93_Device_t*)IOArea_p; \
    EIP93_DHM_Mode_t* DHM_p = &Device_p->extras.DHM_mode; \
    IDENTIFIER_NOT_USED(DHM_p);
#endif

#define EIP93_INSERTCODE_FUNCTION_EXIT_CODE_DHM \
    goto FUNC_RETURN; \
    FUNC_RETURN: \
        return res;


/*----------------------------------------------------------------------------
 * EIP93_DHM_Activate
 * configures the operational mode to  DHM and  Allows the PE to run by
 * releasing the reset.
 *
 */
EIP93_Status_t
EIP93_DHM_Activate(
        EIP93_IOArea_t * const IOArea_p,
        unsigned int nPEInputThreshold,
        unsigned int nPEOutputThreshold,
        bool fEnableAutoSwapForRegisterData)
{
    bool fEnableSwap_Reg_Data = false;
    EIP93_INSERTCODE_FUNCTION_ENTRY_CODE_DHM

    EIP93_CHECK_INT_INRANGE(
            nPEInputThreshold,
            EIP93_MIN_PE_INPUT_THRESHOLD,
            EIP93_MAX_PE_INPUT_THRESHOLD)
    EIP93_CHECK_INT_INRANGE(
            nPEOutputThreshold,
            EIP93_MIN_PE_OUTPUT_THRESHOLD,
            EIP93_MAX_PE_OUTPUT_THRESHOLD)


    //configure IN and OUT RAM buffer threshold

    EIP93_Write32_PE_IO_THRESHOLD(
            Device_p->Device,
            (uint16_t)nPEOutputThreshold,
            (uint16_t)nPEInputThreshold);

#ifdef EIP93_ENABLE_SWAP_REG_DATA
        fEnableSwap_Reg_Data = true;
#endif //EIP93_ENABLE_SWAP_REG_DATA


   EIP93_Write32_PE_CFG(Device_p->Device,
                             0, // Rst PE: no
                             0, // Reset PDR: no
                             0, // DHM mode on
                             0,
                             0,
                             0,
                             0, // PDR Update is on
                             fEnableSwap_Reg_Data );


    // now PE is running and we are ready to accept
    // and process packet data

    Device_p->CurrentMode = EIP93_MODE_DHM;

    EIP93_INSERTCODE_FUNCTION_EXIT_CODE_DHM
}




/*----------------------------------------------------------------------------
 * EIP93_WriteBytes
 */
static inline void
EIP93_WriteBytes(
        uint8_t * Bytes_p,
        unsigned int * const BytesDone_p,
        const unsigned int BytesCount,
        uint32_t WordToWrite)
{
    unsigned int BytesDone = *BytesDone_p;
    unsigned int i;

    for(i=0; i<4; i++)
    {
        if (BytesDone < BytesCount)
        {

            Bytes_p[BytesDone++] = (uint8_t)WordToWrite;
            WordToWrite = (WordToWrite >> 8);
        }
    }
    *BytesDone_p = BytesDone;
}


/*----------------------------------------------------------------------------
 * EIP93_ReadBytes
 */
static inline uint32_t
EIP93_ReadBytes(
        const uint8_t * Data_p,
        const unsigned int DataCount,
        unsigned int * const ReadIndex_p)
{
    unsigned int ReadIndex = *ReadIndex_p;
    unsigned int i;
    uint32_t w = 0;

    for(i=0; i<4; i++)
    {
        w |= Data_p[ReadIndex++] << 8 * i;
        if (ReadIndex >= DataCount)
            break;
    }

    *ReadIndex_p = ReadIndex;

    return w;
}


/*----------------------------------------------------------------------------
 * EIP93_DHM_Packet_Put
 *
 * This API Loads command siscriptor,SA and SA State directly in to
 * packet engine registers.
 *
 * Returns EIP93_BUSY_RETRY_LATER  when  PE is busy to carry out the request.
 *
 */
EIP93_Status_t
EIP93_DHM_Packet_Put(
        EIP93_IOArea_t * const IOArea_p,
        const EIP93_DHM_CommandDescriptor_t * const PktPut_p)
{
    uint32_t CmdDR[2];
    int SAReadyOffset ;

    EIP93_INSERTCODE_FUNCTION_ENTRY_CODE_DHM
    EIP93_CHECK_POINTER(PktPut_p)
    EIP93_CHECK_POINTER(PktPut_p->SARecord_p)
    EIP93_CHECK_INT_INRANGE(PktPut_p->SAStateLength,0,14)
    EIP93_CHECK_INT_INRANGE(PktPut_p->SARecordLength,0,32)
    EIP93_CHECK_INT_INRANGE(PktPut_p->ARC4StateLength, 0, 64)

   if(PktPut_p->SAStateLength)
    {
        EIP93_CHECK_POINTER(PktPut_p->SAState_p);
    }

   if(PktPut_p->ARC4StateLength)
    {
        EIP93_CHECK_POINTER(PktPut_p->ARC4State_p)
    }


    //build command descriptor
    EIP93_Reg_PE_CTRL_Make(
            PktPut_p->ControlWord,
            &CmdDR[0]);

    EIP93_Reg_PE_Length_Make(
            PktPut_p->BypassWordsCount,
            PktPut_p->SrcPacketByteCount,
            &CmdDR[1]);

    //hand off to packet engine
    EIP93_Write32(
            Device_p->Device,
            EIP93_REG_PE_CTRL_STAT,
            CmdDR[0]|EIP93_DESP_CRTL_REG_HOSTREADY);

    EIP93_Write32(
            Device_p->Device,
            EIP93_REG_PE_LENGTH,
            CmdDR[1]|EIP93_DESP_LEN_REG_HOSTREADY);

    //increment Command descriptor count
    EIP93_Write32(Device_p->Device,EIP93_REG_PE_CD_COUNT,(uint32_t)1);

    //SA state record fill
    EIP93_Write32Array(
            Device_p->Device,
            EIP93_REG_STATE_IV_0,
            PktPut_p->SAState_p,
            PktPut_p->SAStateLength);

     // fill SA ARC4
    EIP93_Write32Array(
                Device_p->Device,
                EIP93_PE_ARC4STATE_BASEADDR_REG,
                PktPut_p->ARC4State_p,
                PktPut_p->ARC4StateLength);

    //SA Record Fill
    EIP93_Write32Array(
            Device_p->Device,
            EIP93_REG_SA_CMD_0,
            PktPut_p->SARecord_p,
            PktPut_p->SARecordLength);

    if( PktPut_p->SARecordLength == 32 )
        SAReadyOffset =  SA_BASE + ( 31 * EIP93_REG_WIDTH ) ; // for IESW conf
    else
        SAReadyOffset =  SA_BASE + ( 23 * EIP93_REG_WIDTH ) ; // for I conf


    EIP93_Write32(
            Device_p->Device,
            SAReadyOffset,
            0xabbadead);


    //reset both the counters
    DHM_p->InBufferCyclicCounter=0;
    DHM_p->OutBufferCyclicCounter=0;

    EIP93_INSERTCODE_FUNCTION_EXIT_CODE_DHM

}

/*----------------------------------------------------------------------------
 * EIP93_DHM_Packet_Get
 *
 * Should be called after EIP93_OPERATION_DONE_INT interrupt.
 *
 * Returns EIP93_BUSY_RETRY_LATER  if  PE busy to carry out the
 * request, in such situation call again after the above said criteria
 * is meet.
 *
 */
EIP93_Status_t
EIP93_DHM_Packet_Get(
        EIP93_IOArea_t * const IOArea_p,
        EIP93_DHM_ResultDescriptor_t * const Pktget_p)

{
    uint32_t ResDR[2];

    EIP93_INSERTCODE_FUNCTION_ENTRY_CODE_DHM
    EIP93_CHECK_POINTER(Pktget_p)
    EIP93_CHECK_POINTER(Pktget_p->SARecord_p)
    EIP93_CHECK_INT_INRANGE(Pktget_p->SAStateLength,0,14)
    EIP93_CHECK_INT_INRANGE(Pktget_p->SARecordLength,0,32)

    if(Pktget_p->SAStateLength)
    {
        EIP93_CHECK_POINTER(Pktget_p->SAState_p);
    }

    //copy SA record
    EIP93_Read32Array(
            Device_p->Device,
            EIP93_REG_SA_CMD_0,
            Pktget_p->SARecord_p,
            Pktget_p->SARecordLength);

    //store SA state record
    EIP93_Read32Array(
            Device_p->Device,
            EIP93_REG_STATE_IV_0,
            Pktget_p->SAState_p,
            Pktget_p->SAStateLength);


    //read result descriptor
    ResDR[0]= EIP93_Read32(
                    Device_p->Device,
                    EIP93_REG_PE_CTRL_STAT);
    ResDR[1]= EIP93_Read32(
                    Device_p->Device,
                    EIP93_REG_PE_LENGTH);

    //decrement Result descriptor count
    EIP93_Write32(Device_p->Device,EIP93_REG_PE_RD_COUNT,(uint32_t)1);

    // parse descriptor
    // extract processed packet length
    EIP93_Reg_PE_Length_DataCntExtract(ResDR[1],&Pktget_p->DstPacketByteCount);

    //extract Bypass counts
    EIP93_Reg_PE_Length_BypassedCntExtract(
            ResDR[1],
            &Pktget_p->BypassWordsCount);

    //extract status word field
    EIP93_Reg_PE_STAT_StatusExtract(
            ResDR[0],
            &Pktget_p->StatusWord);


    EIP93_INSERTCODE_FUNCTION_EXIT_CODE_DHM
}

/*----------------------------------------------------------------------------
 * EIP93_DHM_Data_Init
 *
 * This intialize the  EIP93_DHM_Buffer_t data structure which will be
 * subsequently used by EIP93_DHM_Data_Get and EIP93_DHM_Data_Put APIs.
 *
 * Should be called once before EIP93_DHM_Data_Put and
 * EIP93_DHM_Data_Get,each, are called for the first time for a packet.
 *
 * (input)Frag_p-pointer of type  EIP93_DHM_Buffer_t , whose
 *               members will intialized.
 *
 * (input) Buffer_p-Adrress of caller provided  in/out buffer.
 *
 * (input)Size-size  of buffer in bytes.
 *
 */
EIP93_Status_t
EIP93_DHM_Data_Init(
        EIP93_DHM_Buffer_t * const Frag_p,
        uint8_t * const Buffer_p,
        const unsigned int Size)
{
    Frag_p->Buffer_p = Buffer_p;
    Frag_p->Length = Size;

    return EIP93_STATUS_OK;
}



/*----------------------------------------------------------------------------
 * EIP93_DHM_Data_Put
 *
 * Should be called immediately  after EIP93_INPUT_BUFFER_INT interrupt.
 *
 * In polled mode call EIP93_INT_ActiveStatus_get and check
 * for EIP93_INPUT_BUFFER_INT flag to be set before calling this function.
 *
 */

EIP93_Status_t
EIP93_DHM_Data_Put(
        EIP93_IOArea_t * const IOArea_p,
        EIP93_DHM_Buffer_t * const InputFrag_p)
{

    uint32_t  StatusRegVal;
    unsigned int PaddedWordsCount;
    unsigned int AvailableRAMWordsCount;
    unsigned int WordsToWriteCount;
    bool fIsShortFragment;
    uint32_t w;
    unsigned int i;
    unsigned int ReadIndex = 0;

    EIP93_INSERTCODE_FUNCTION_ENTRY_CODE_DHM
    EIP93_CHECK_POINTER(InputFrag_p)
    EIP93_CHECK_POINTER(InputFrag_p->Buffer_p)

    StatusRegVal=EIP93_Read32(Device_p->Device,EIP93_REG_PE_STATUS);


    fIsShortFragment = false;

    //don't over write RAM buffer if input  completed.
    if(StatusRegVal & EIP93_STATUS_PE_INPUT_DONE)
    {
        res = EIP93_ERROR_TOO_MUCH_DATA;
    }
    else
    {

        //Round off length  to nearest word
        PaddedWordsCount = (InputFrag_p->Length + (sizeof(uint32_t)-1))
                          /sizeof(uint32_t);

        //get free space to fill
        AvailableRAMWordsCount = EIP93_Read_Available_Cnt(StatusRegVal);

        if(AvailableRAMWordsCount > (EIP93_RAM_BUFFERSIZE_BYTES/4) )
        {
            AvailableRAMWordsCount =
                (EIP93_RAM_BUFFERSIZE_BYTES/4)-
                DHM_p->InBufferCyclicCounter/4 ;
        }

        //can input fit into freespace of RAM In-buffer
        if(PaddedWordsCount <= AvailableRAMWordsCount )
        {
            WordsToWriteCount= PaddedWordsCount ;
            fIsShortFragment=1;

        }
        else //fill how much ever possible
        {
            WordsToWriteCount = AvailableRAMWordsCount ;
        }



        //no address wraping required, fill RAM In-Buffer
        for(i=0;i< WordsToWriteCount;i++)

        {
            w = EIP93_ReadBytes(
                        InputFrag_p->Buffer_p,
                        InputFrag_p->Length,
                        &ReadIndex);

            EIP93_Write32(
                    Device_p->Device,
                    EIP93_INPUT_BUFFER +  DHM_p->InBufferCyclicCounter,
                    w);
             DHM_p->InBufferCyclicCounter += EIP93_REG_WIDTH;

            //wrap on reaching buffer end
            if( DHM_p->InBufferCyclicCounter == EIP93_RAM_BUFFERSIZE_BYTES)
            {
                 DHM_p->InBufferCyclicCounter =0;
            }

        }


        // update written count
        EIP93_Write32(
                Device_p->Device,
                EIP93_REG_PE_INBUF_COUNT,
                (uint32_t)ReadIndex);

        InputFrag_p->Length -=  ReadIndex;
        InputFrag_p->Buffer_p += ReadIndex;

    }

    EIP93_INSERTCODE_FUNCTION_EXIT_CODE_DHM

}
/*----------------------------------------------------------------------------
 * EIP93_DHM_Data_Get
 *
 * Should be called immediately  after EIP93_OUTPUT_BUFFER_INT  or
 * EIP93_INT_OPERATION_DONE  interrupt.
 *
 * In polled mode call EIP93_INT_ActiveStatus_get and check
 * for EIP93_OUT_BUFFER_INT  or EIP93_INT_OPERATION_DONE flag to be set
 * before calling this function.
 *
 */
EIP93_Status_t
EIP93_DHM_Data_Get(
        EIP93_IOArea_t * const IOArea_p,
        EIP93_DHM_Buffer_t * const OutputFrag_p)
{

    unsigned int AvailableDataBytesCount;
    unsigned int BytesToReadCount;
    uint32_t  StatusRegVal;
    unsigned int LoopCount;
    unsigned int BytesDone=0;
    unsigned int i;
    uint32_t r;
    bool Is_Lastfragment;

    EIP93_INSERTCODE_FUNCTION_ENTRY_CODE_DHM
    EIP93_CHECK_POINTER(OutputFrag_p)
    EIP93_CHECK_POINTER(OutputFrag_p->Buffer_p)


    Is_Lastfragment = false;

    //check is last fragment.
    StatusRegVal=EIP93_Read32(Device_p->Device,EIP93_REG_PE_STATUS);


    if(StatusRegVal & EIP93_STATUS_PE_OUTPUT_DONE)
    {
        Is_Lastfragment = true;

    }

    // fetch ready to read count
    AvailableDataBytesCount =
        EIP93_Read32(Device_p->Device,EIP93_REG_PE_OUTBUF_COUNT)
        & EIP93_12BITS_MASK;

    //is provided buffer big enough
    if(AvailableDataBytesCount <= OutputFrag_p->Length)
    {
        BytesToReadCount = AvailableDataBytesCount;

    }
    else
    {

        BytesToReadCount = OutputFrag_p->Length;
    }

    LoopCount = BytesToReadCount / sizeof(uint32_t);

    for(i=0;i< LoopCount ;i++)

    {
        r = EIP93_Read32(
                    Device_p->Device,
                    EIP93_OUTPUT_BUFFER
                    +  DHM_p->OutBufferCyclicCounter);
         DHM_p->OutBufferCyclicCounter += EIP93_REG_WIDTH;

        //warp at end of buffer
        if( DHM_p->OutBufferCyclicCounter == EIP93_RAM_BUFFERSIZE_BYTES)
       {
            DHM_p->OutBufferCyclicCounter =0;
       }
        // write to destination buffer
        EIP93_WriteBytes(
                OutputFrag_p->Buffer_p,
                &BytesDone,
                BytesToReadCount,
                r);
    }

    //update read count
    EIP93_Write32(
            Device_p->Device,
            EIP93_REG_PE_OUTBUF_COUNT,
            (uint32_t)BytesToReadCount);


    OutputFrag_p->Length -= BytesToReadCount;
    OutputFrag_p->Buffer_p += BytesToReadCount;

    EIP93_INSERTCODE_FUNCTION_EXIT_CODE_DHM
}

/*----------------------------------------------------------------------------
 * EIP93_DHM_Progress_Get
 *
 * retunrs  status  of  interrupts valid in DHM.
 */
EIP93_Status_t
EIP93_DHM_Progress_Get(
        EIP93_IOArea_t * const IOArea_p,
        EIP93_DHM_Progress_t * const ProgressStatusMask_p)
{
    uint32_t ProgressStatus = 0;
    EIP93_INSERTCODE_FUNCTION_ENTRY_CODE_DHM
    EIP93_CHECK_POINTER(ProgressStatusMask_p)

    ProgressStatus = EIP93_Read32(Device_p->Device,EIP93_REG_PE_STATUS)
                  & EIP93_PE_DHM_VALIDINTERRUPT_MASK;


    *ProgressStatusMask_p = ProgressStatus;
    EIP93_INSERTCODE_FUNCTION_EXIT_CODE_DHM
}


/* end of file eip93_dhm.c */

