/* api_pec.h
 *
 * Packet Engine Control API (PEC)
 *
 * This API can be used to perform transforms on security protocol packets
 * for a set of security network protocols like IPSec, MACSec, sRTP, SSL,
 * DTLS, etc.
 *
 * Please note that this is a generic API that can be used for many transform
 * engines. A separate document will detail the exact fields and parameters
 * required for the SA and Descriptors.
 */

/*****************************************************************************
*                                                                            *
*         Copyright (c) 2007-2009 SafeNet Inc. All Rights Reserved.          *
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

#ifndef INCLUDE_GUARD_API_PEC_H
#define INCLUDE_GUARD_API_PEC_H

#include "basic_defs.h"
#include "api_dmabuf.h"         // DMABuf_Handle_t

/*----------------------------------------------------------------------------
 *         Dependency on DMA Buffer Allocat API (api_dmabuf.h)
 *
 * This API requires the use of the DMA Buffer Allocation API. All buffers
 * are passed through this API as handles.
 */


/*----------------------------------------------------------------------------
 * PEC_Status_t
 */
typedef enum
{
    PEC_STATUS_OK = 0,
    PEC_ERROR_BAD_PARAMETER,
    PEC_ERROR_BAD_HANDLE,
    PEC_ERROR_BAD_USE_ORDER,
    PEC_ERROR_INTERNAL,
    PEC_ERROR_NOT_IMPLEMENTED

} PEC_Status_t;


/*----------------------------------------------------------------------------
 * PEC_InitBlock_t
 *
 * This structure contains service initialization parameters that are passed
 * to the PEC_Init call.
 *
 * For forward-compatibility with future extensions, please zero-init the
 * data structure before setting the fields and providing it to PEC_Init.
 * Example: PEC_InitBlock_t InitBlock = {0};
 */
typedef struct
{
    bool fUseDynamicSA;             // true = use variable-size SA format

    // the following fields are related to Scatter/Gather
    // not all engines support this
    unsigned int FixedScatterFragSizeInBytes;

} PEC_InitBlock_t;


/*----------------------------------------------------------------------------
 * PEC_CommandDescriptor_t
 *
 * This data structure describes a transform request that will be queued up
 * for processing by the transform engine. It refers to the input and output
 * data buffers, the SA buffer(s) and contains parameters that describe the
 * transform, like the length of the data.
 */
typedef struct
{
    // the pointer that will be returned in the related result descriptor
    void * User_p;

    // data buffers
    DMABuf_Handle_t SrcPkt_Handle;
    DMABuf_Handle_t DstPkt_Handle;
    unsigned int SrcPkt_ByteCount;
    unsigned int Bypass_WordCount;

    // SA reference
    uint32_t SA_WordCount;
    DMABuf_Handle_t SA_Handle1;
    DMABuf_Handle_t SA_Handle2;

    // Engine specific control fields
    // with Transform specific values
    uint32_t Control1;
    uint32_t Control2;

} PEC_CommandDescriptor_t;


/*----------------------------------------------------------------------------
 * PEC_ResultDescriptor_t
 *
 * This data structure contains the result of the transform request. The user
 * can match the result to a command using the User_p field.
 *
 * A number of parameters from the command descriptor are also returned, as a
 * courtesy service.
 */
typedef struct
{
    // the pointer that from the related command descriptor
    void * User_p;

    // data buffers
    DMABuf_Handle_t SrcPkt_Handle;
    DMABuf_Handle_t DstPkt_Handle;
    uint32_t DstPkt_ByteCount;
    void * DstPkt_p;

    unsigned int Bypass_WordCount;

    // Engine specific status fields
    // with Transform specific values
    uint32_t Status1;
    uint32_t Status2;

} PEC_ResultDescriptor_t;


/*----------------------------------------------------------------------------
 * PEC_NotifyFunction_t
 *
 * This type specifies the callback function prototype for the function
 * PEC_CommandNotify_Request and PEC_ResultNotify_Request.
 * The notification will occur only once.
 *
 * NOTE: The exact context in which the callback function is invoked and the
 *       allowed actions in that callback are implementation specific. The
 *       intention is that all API functions can be used, except PEC_UnInit.
 */
typedef void (* PEC_NotifyFunction_t)(void);


/*----------------------------------------------------------------------------
 * PEC_Capabilities_t
 *
 * szTextDescription[]
 *     Zero-terminated descriptive text of the available services.
 */
#define PEC_MAXLEN_TEXT  128

typedef struct
{
    char szTextDescription[PEC_MAXLEN_TEXT];
} PEC_Capabilities_t;


/*----------------------------------------------------------------------------
 * PEC_Capabilities_Get
 *
 * This routine returns a structure that describes the capabilities of the
 * implementation. See description of PEC_Capabilities_t for details.
 *
 * Capabilities_p
 *     Pointer to the capabilities structure to fill in.
 *
 * This function is re-entrant.
 */
PEC_Status_t
PEC_Capabilities_Get(
        PEC_Capabilities_t * const Capabilities_p);


/*----------------------------------------------------------------------------
 * PEC_Init
 *
 * This function must be used to initialize the service. No API function may
 * be used before this function has returned.
 */
PEC_Status_t
PEC_Init(
        const PEC_InitBlock_t * const InitBlock_p);


/*----------------------------------------------------------------------------
 * PEC_UnInit
 *
 * This call un-initializes the service. Use only when there are no pending
 * transforms. The caller must make sure that no API function is used while or
 * after this function executes.
 */
PEC_Status_t
PEC_UnInit(void);


/*----------------------------------------------------------------------------
 * PEC_SA_Register
 *
 * This function must be used to register an SA so it can be used for
 * transforms. The caller is responsible for filling in the SA fields
 * according to the specification of the engine, with the exception of any
 * fields that are designated to hold addresses of the other SA memory blocks.
 * The buffers are considered arrays of 32bit words in host-native byte order.
 *
 * When this call returns it is no longer allowed to access these SA memory
 * blocks directly.
 *
 * SA_Handle1 (input)
 *     Handle for the main SA memory block. This memory block contains all the
 *     static material and is typically read completely for every transform
 *     but only selective parts are written back after the transform.
 *
 * SA_Handle2 (input)
 * SA_Handle3 (input)
 *     Handles for the optional second and third memory blocks. These are
 *     typically used to remember state information and are therefore
 *     required only for certain types of SA's. These blocks are typically
 *     read and written for every transform. Putting them in a separate memory
 *     blocks allows these to be put in more high performance memory.
 *     Provide zero for unused handles.
 *
 * The exact number of handles required depends on the transform engine and on
 * the SA parameters and is specified in a separate document. The exact size
 * of each memory block is known to the service through the handle.
 */
PEC_Status_t
PEC_SA_Register(
        DMABuf_Handle_t SA_Handle1,
        DMABuf_Handle_t SA_Handle2,
        DMABuf_Handle_t SA_Handle3);


/*----------------------------------------------------------------------------
 * PEC_SA_UnRegister
 *
 * This function must be used to remove an SA from the system, which means it
 * can no longer be used to perform transforms with the engine. When this
 * function returns the caller is allowed to access the SA memory blocks again.
 *
 * SA_Handle1 (input)
 * SA_Handle2 (input)
 * SA_Handle3 (input)
 *     The same handles as we provided in the PEC_SA_Register call.
 *     Provide zero for unused handles.
 */
PEC_Status_t
PEC_SA_UnRegister(
        DMABuf_Handle_t SA_Handle1,
        DMABuf_Handle_t SA_Handle2,
        DMABuf_Handle_t SA_Handle3);


/*----------------------------------------------------------------------------
 * PEC_Packet_Put
 *
 * This function must be put transform requests into a queue. It is possible
 * to queue up just one request, or an array of requests (these do not have to
 * be related). In case the queue is full, none or only a few of the requests
 * might be queued up.
 *
 * Commands_p (input)
 *     Pointer to one (or an array of command descriptors, each describe one
 *     transform request.
 *
 * CommandsCount (input)
 *     The number of command descriptors pointed to by Commands_p.
 *
 * PutCount_p (output)
 *     This parameter is used to return the actual number of descriptors that
 *     was queued up for processing (0..CommandsCount).
 */
PEC_Status_t
PEC_Packet_Put(
        const PEC_CommandDescriptor_t * Commands_p,
        const unsigned int CommandsCount,
        unsigned int * const PutCount_p);


/*----------------------------------------------------------------------------
 * PEC_Packet_Get
 *
 * This function must be used to retrieve the results for the requested
 * transform operations. Every request generates one result, whether it is
 * successful or failed. The caller is able to retrieve one result or an
 * array of results.
 *
 * Results_p (input)
 *     Pointer to the result descriptor, or array of result descriptors, that
 *     will be populated by the service based on completed transform requests.
 *
 * ResultsLimit (input)
 *     The number of result descriptors available from Results_p and onwards.
 *
 * GetCount_p (output)
 *     The actual number of result descriptors that were populated is returned
 *     in this parameter.
 */
PEC_Status_t
PEC_Packet_Get(
        PEC_ResultDescriptor_t * Results_p,
        const unsigned int ResultsLimit,
        unsigned int * const GetCount_p);


/*----------------------------------------------------------------------------
 * PEC_CommandNotify_Request
 *
 * This routine can be used to request a one-time notification of space
 * available for new commands. It is typically used after PEC_PacketPut
 * returned fewer packets added than requested (could be zero) and the caller
 * does not want to poll for new results.
 *
 * Once the requested number of spaces are available, the implementation will
 * invoke the callback one time to notify the user of the available results.
 * The notification is then immediately disabled.
 *
 * CBFunc_p
 *     Address of the callback function.
 *
 * CommandsCount
 *     The number of commands that must be possible to add with
 *     PEC_PacketPut before the notification function will be invoked.
 */
PEC_Status_t
PEC_CommandNotify_Request(
        PEC_NotifyFunction_t CBFunc_p,
        const unsigned int CommandsCount);


/*----------------------------------------------------------------------------
 * PEC_ResultNotify_Request
 *
 * This routine can be used to request a one-time notification of available
 * results. It is typically used after PEC_PacketGet returned zero results
 * and the caller does not want to poll for new results.
 *
 * Once the requested transforms have completed, the implementation will
 * invoke the callback one time to notify this fact.
 * The notification is then immediately disabled.
 *
 * CBFunc_p
 *     Address of the callback function.
 *
 * ResultsCount
 *     The requested number of results that should be available the next
 *     time PEC_Packet_Get is called after the callback function has occured.
 */
PEC_Status_t
PEC_ResultNotify_Request(
        PEC_NotifyFunction_t CBFunc_p,
        const unsigned int ResultsCount);

#endif /* Include Guard */

/* end of file api_pec.h */

