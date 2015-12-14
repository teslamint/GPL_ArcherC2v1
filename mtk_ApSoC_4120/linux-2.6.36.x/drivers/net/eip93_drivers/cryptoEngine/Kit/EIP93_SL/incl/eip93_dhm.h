/* eip93_dhm.h
 *
 * EIP93 Driver Library Public Interface for
 * Direct Host Mode
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

#ifndef INCLUDE_GUARD_EIP93_DHM_H
#define INCLUDE_GUARD_EIP93_DHM_H

#include "eip93.h"


/*----------------------------------------------------------------------------
 * Interrupts of  EIP93 Valid in DHM
 */
typedef enum
{
    EIP93_DHM_INT_OUTPUT_BUFFER =  BIT_11,
    EIP93_DHM_INT_INPUT_BUFFER =   BIT_10,
    EIP93_DHM_INT_OPERATION_DONE =   BIT_9
} EIP93_DHM_InterruptSource_t;


/*----------------------------------------------------------------------------
 * Bitmask for a set of interrupts of EIP93 valid for DHM
 * This represents an 'OR'-ed combination of EIP93_DHM_InterruptSource_t
 * values
 */
typedef uint32_t EIP93_DHM_Progress_t;


/*----------------------------------------------------------------------------
 *  Logical Command Descriptor for PacketPut
 */
typedef struct
{
    // (input) source count, in bytes, of the packet to be processed(MAX 1MB).
    unsigned int  SrcPacketByteCount;

    // (input)address SA record
    uint32_t * SARecord_p;

    //(input) SA record SIZE in words
    unsigned int SARecordLength;

    // (input) address SA state record
    uint32_t * SAState_p;

    //(input) SA state Record size in words
    unsigned int  SAStateLength;

     //(input) address ARC4State record
    uint32_t * ARC4State_p;

    //(input) ARC4 state record size in words
    //set to 0, if unused.
    unsigned int ARC4StateLength;

    // (input) Control field of command descriptor.
    uint32_t ControlWord;

    // (input)bypass words, from source to destination buffer.
    uint8_t BypassWordsCount;
} EIP93_DHM_CommandDescriptor_t;


/*----------------------------------------------------------------------------
 *  Logical Command Descriptor for PacketGet
 */
typedef struct
{
    // (output) processed packet data count, in bytes.
    unsigned int  DstPacketByteCount;

    // (input)address SA record
    uint32_t * SARecord_p;

    //(input) SA record SIZE in words
    unsigned int SARecordLength;

    // (input) address SA state record
    uint32_t * SAState_p;

    //(input) SA state Record size in words
    unsigned int  SAStateLength;

     //(input) address ARC4State record
    uint32_t * ARC4State_p;

    //(input) ARC4 state record size in words
    //set to 0, if unused.
    unsigned int ARC4StateLength;

    // (output)status field of result descriptor
    uint32_t StatusWord;

    // (output)bypassed words from source to destination buffer.
    uint8_t BypassWordsCount;
} EIP93_DHM_ResultDescriptor_t;


/*----------------------------------------------------------------------------
 *
 * When  packet in/out data are bigger than IN/OUT Buffer RAM supported than
 * user may need to call EIP93_DHM_Data_Put/EIP93_DHM_Data_Get API
 * more than once.
 *
 */
typedef struct
{
    //(input) start address for load/store data to/from in/out
    //RAM buffer. Advances  by CopiedCount value for every call.
    uint8_t * Buffer_p;

    //(input)length of the packet fragment to fill IN
    //RAM Buffer(EIP93_DHM_Data_Put).
    //size of the buffer for copying content out
    //RAM buffer (EIP93_DHM_Data_Get).
    //Decremented  by CopiedCount value for every call.
    unsigned int Length;
} EIP93_DHM_Buffer_t;



/*----------------------------------------------------------------------------
 *                      DHM specific PE APIs
 *----------------------------------------------------------------------------
 */
/*----------------------------------------------------------------------------
 * EIP93_DHM_Activate
 * configures the operational mode to  DHM and  Allows the PE to run by
 * releasing the reset.
 *
 * (input)nPEInputThreshold-Indicate how many 32-bit words of free space
 *                          (1-508) must be available in the PE input Data
 *                           RAM buffer before a DMA input  transfer starts.
 *                           The maximum threshold is 508 words,not 511 words,
 *                           as the buffer is also used to redirect the ICV
 *                           for IPSec AH operations.
 *                           A value of 0x20 .. 0x80 generally gives a good
 *                           performance but the optimal value depends on
 *                           the system and application.
 *(input)nPEOutputThreshold- Indicates how many 32-bit words of data (1-432)
 *                           must be available in the PE output Data RAM
 *                           buffer before a DMA output transfer starts and
 *                           the exact burst length that is actually used for
 *                           the transfer.
 *                           The maximum threshold is 432 words, not 511
 *                           words, as this buffer  is also used to store up
 *                           to 256 pad bytes and a possible 64 bytes
 *                           ICV that can be stripped for decrypt operations.
 *                           The last data  transfer that completes the packet
 *                           processing can differ to this  transfer size.
 *                           A value of 0x20 .. 0x80 generally gives a good
 *                           performance butthe optimal value depends on the
 *                           system and application.
 */
EIP93_Status_t
EIP93_DHM_Activate(
        EIP93_IOArea_t * const IOArea_p,
        unsigned int nPEInputThreshold,
        unsigned int nPEOutputThreshold,
        bool fEnableAutoSwapForRegisterData);


/*----------------------------------------------------------------------------
 * EIP93_DHM_Packet_Put
 *
 * This API Loads command discriptor,SA , ARC4 and SA State directly in
 * to packet engine registers. To be called after the previous processed
 * packet was read out or immediatly after EIP93_DHM_Activate call.
 *
 */
EIP93_Status_t
EIP93_DHM_Packet_Put(
        EIP93_IOArea_t * const IOArea_p,
        const EIP93_DHM_CommandDescriptor_t * const PktPut_p);


/*----------------------------------------------------------------------------
 * EIP93_DHM_Packet_Get
 *
 * Should be called immediately  after EIP93_DHM_INT_CONTEXT_DONE interrupt.
 *
 *
 */
EIP93_Status_t
EIP93_DHM_Packet_Get(
        EIP93_IOArea_t * const IOArea_p,
        EIP93_DHM_ResultDescriptor_t * const Pktget_p);


/*----------------------------------------------------------------------------
 * EIP93_DHM_Data_Init
 *
 * This intialize the EIP93_DHM_Fragment_Data_t data structure which will be
 * subsequently used by EIP93_DHM_Data_Get and EIP93_DHM_Data_Put APIs.
 *
 * Should be called once before EIP93_DHM_Data_Put and
 * EIP93_DHM_Data_Get,each, are called for the first time for a packet.
 *
 * (input)Frag_p-pointer of type EIP93_DHM_Fragment_Data_t , whose
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
        const unsigned int Size);


/*----------------------------------------------------------------------------
 * EIP93_DHM_Data_Put
 *
 * Should be called immediately  after EIP93_INPUT_BUFFER_INT interrupt.
 *
 * In polled mode call EIP93_INT_ActiveStatus_get and check
 * for EIP93_DHM_INT_INPUT_BUFFER flag to be set before calling this function.
 *
 */
EIP93_Status_t
EIP93_DHM_Data_Put(
        EIP93_IOArea_t * const IOArea_p,
        EIP93_DHM_Buffer_t * const InputFrag_p);


/*----------------------------------------------------------------------------
 * EIP93_DHM_Data_Get
 *
 * Should be called immediately  after EIP93_INT_PE_OUTPUT_BUFFER  or
 * EIP93_INT_PE_OPERATION_DONE  interrupt.
 *
 * In polled mode call EIP93_INT_ActiveStatus_get and check
 * for EIP93_DHM_INT_OUTPUT_BUFFER  or EIP93_DHM_INT_OPERATION_DONE flag to
 * be set before calling this function.
 *
 */
EIP93_Status_t
EIP93_DHM_Data_Get(
        EIP93_IOArea_t * const IOArea_p,
        EIP93_DHM_Buffer_t * const OutputFrag_p);


/*----------------------------------------------------------------------------
 * EIP93_DHM_Progress_Get
 *
 * retunrs  status  of active interrupts.
 */
EIP93_Status_t
EIP93_DHM_Progress_Get(
        EIP93_IOArea_t * const IOArea_p,
        EIP93_DHM_Progress_t * const ProgressStatusMask_p);


#endif /* INCLUDE_GUARD_EIP93_DHM_H */

/* end of file eip93_dhm.h */
