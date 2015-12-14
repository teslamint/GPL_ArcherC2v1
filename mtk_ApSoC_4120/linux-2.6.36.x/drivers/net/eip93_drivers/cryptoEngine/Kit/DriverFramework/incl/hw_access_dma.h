/* hw_access_dma.h
 *
 * EIP Driver Framework, DMAResource API (subset of HW Access API)
 *
 * The document "Driver Framework Porting Guide" contains the detailed
 * specification of this API. The information contained in this header file
 * is for reference only.
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

#ifndef INCLUDE_GUARD_HW_ACCESS_DMA_H
#define INCLUDE_GUARD_HW_ACCESS_DMA_H

#include "basic_defs.h"         // bool, uint32_t, inline


/*****************************************************************************
 * HWPAL_DMAResource
 *
 * These functions are related to management of memory buffers that can be
 * accessed by the host as well as a device, using Direct Memory Access (DMA).
 * A driver must typically support many of these shared resources. This API
 * helps with administrating these resources, but does not allocate the actual
 * memory buffer.
 *
 * This API maintains administration records that the caller can read and
 * write directly. A handle is also provided, to abstract the record.
 * The handle cannot be used to directly access the buffer and is therefore
 * considered safe to pass around in the system, even to applications.
 *
 * Another important aspect of this API is to provide a point where buffers
 * can be handed over between the host and the device. The driver library or
 * adapter must call the PreDMA and PostDMA functions to indicate the hand over
 * of access right between the host and the device for an entire buffer,or
 * part thereof. The implementation can use these calls to manage the
 * data coherency for the buffer, for example in a cached system.
 *
 * Memory buffers are different from HWPAL_Device resources, which represent
 * static device-internal resources with possible read and write side-effects.
 *
 * On the fly endianess swapping for words is supported for DMA Resources by
 * means of the Read32 and Write32 functions.
 *
 * Note: If multiple devices with a different memory view need to use the same
 * DMAResource, then the caller should consider separate records for each
 * device (for the same buffer).
 */

typedef void * HWPAL_DMAResource_Handle_t;


/*----------------------------------------------------------------------------
 * HWPAL_DMAResource_Record_t
 *
 * This type is the record that describes a DMAResource. The caller shall use
 * HWPAL_DMAResource_Create to instantiate a record and get a handle to that
 * record.
 * Use HWPAL_DMAResource_Handle2RecordPtr to get a pointer to the actual
 * record (as shown below) and to manipulate the fields in the record.
 */

#include "hw_access_dma_record.h"   // HWPAL_DMAResource_Record_t definition


/*----------------------------------------------------------------------------
 * HWPAL_DMAResource_Init
 *
 * This function must be used to initialize the DMAResource administration.
 * It must be called before any of the other HWPAL_DMAResource_* functions may
 * be called. It may be called anew only after HWPAL_DMAResource_UnInit has
 * been called.
 *
 * MaxHandles (input)
 *     Maximum number of handles that must be possible to administrate. The
 *     implementation will allocate enough memory to fulfill this requirement.
 *     Set to 0 to force the implementation to use the memory provided via
 *     AdminMemory_p and AdminMemorySize.
 *
 * AdminMemory_p (input)
 *     This parameter is used only when MaxHandles is 0.
 *     Pointer to the block of memory this implementation may use for the
 *     records.
 *
 * AdminMemorySize (input)
 *     This parameter is used only when MaxHandles is 0.
 *     Size of the memory block pointed to by AdminMemory_p.
 *     The implementation will calculate the maximum number of handles it can
 *     administrate.
 *
 * Return Value
 *     true   Initialization successfully, rest of the API may now be used.
 *     false  Initialization failed.
 */
bool
HWPAL_DMAResource_Init(
        const unsigned int MaxHandles,
        void * AdminMemory_p,
        const unsigned int AdminMemorySize);


/*----------------------------------------------------------------------------
 * HWPAL_DMAResource_UnInit
 *
 * This function can be used to uninitialize the DMAResource administration.
 * The caller must make sure that handles will not be used after this function
 * returns. If memory was allocated by HWPAL_DMAResource_Init, this function
 * will free it.
 */
void
HWPAL_DMAResource_UnInit(void);


/*----------------------------------------------------------------------------
 * HWPAL_DMAResource_Create
 *
 * This function can be used to create a record. The function returns a handle
 * for the record. Use HWPAL_DMAResource_Handle2RecordPtr to access the record.
 * Destroy the record when no longer required, see HWPAL_DMAResource_Destroy.
 * This function initializes the record to all zeros.
 *
 * Return Values
 *     Handle for the DMA Resource.
 *     NULL is returned when the creation failed.
 */
HWPAL_DMAResource_Handle_t
HWPAL_DMAResource_Create(void);


/*----------------------------------------------------------------------------
 * HWPAL_DMAResource_Destroy
 *
 * This function can be used to delete a record. This deletes all the fields
 * and invalidates the handle.
 *
 * Handle
 *     A valid handle that was once returned by HWPAL_DMAResource_Create.
 *
 * Return Values
 *     None
 */
void
HWPAL_DMAResource_Destroy(
        HWPAL_DMAResource_Handle_t Handle);


/*----------------------------------------------------------------------------
 * HWPAL_DMAResource_IsValidHandle
 *
 * This function validates a handle.
 *
 * Handle
 *     A valid handle that was once returned by HWPAL_DMAResource_Create.
 *
 * Return Value
 *     true  The handle is valid
 *     false The handle is NOT valid
 */
bool
HWPAL_DMAResource_IsValidHandle(
        HWPAL_DMAResource_Handle_t Handle);


/*----------------------------------------------------------------------------
 * HWPAL_DMAResource_Handle2RecordPtr
 *
 * This function can be used to get a pointer to the DMA Resource record
 * (HWPAL_DMAResourceRecord_t) for the handle. The pointer is valid until
 * the handle is destroyed with HWPAL_DMAResource_Destroy.
 *
 * Handle
 *     A valid handle that was once returned by HWPAL_DMAResource_Create.
 *
 * Return Value
 *     Pointer to the HWPAL_DMAResource_Record_t memory for this handle.
 *     NULL is returned if the handle is invalid.
 */
HWPAL_DMAResource_Record_t *
HWPAL_DMAResource_Handle2RecordPtr(
        HWPAL_DMAResource_Handle_t Handle);


/*----------------------------------------------------------------------------
 * HWPAL_DMAResource_Read32
 *
 * This function can be used to read one 32bit word from the DMA Resource
 * buffer.
 * If required (decided by HWPAL_DMAResource_Record_t.device.fSwapEndianess),
 * on the fly endianess swapping of the value read will be performed before it
 * is returned to the caller.
 *
 * Handle (input)
 *     Handle for the DMA Resource to access.
 *
 * WordOffset (input)
 *     Offset in 32bit words, from the start of the DMA Resource to read from.
 *
 * Return Value
 *     The value read.
 *
 * When the Handle and WordOffset parameters are not valid, the implementation
 * will return an unspecified value.
 */
uint32_t
HWPAL_DMAResource_Read32(
        HWPAL_DMAResource_Handle_t Handle,
        const unsigned int WordOffset);


/*----------------------------------------------------------------------------
 * HWPAL_DMAResource_Write32
 *
 * This function can be used to write one 32bit word to the DMA Resource.
 * If required (decided by HWPAL_DMAResource_Record_t.device.fSwapEndianess),
 * on the fly endianess swapping of the value to be written will be performed.
 *
 * Handle (input)
 *     Handle for the DMA Resource to access.
 *
 * WordOffset (input)
 *     Offset in 32bit words, from the start of the DMA Resource to write to.
 *
 * Value (input)
 *     The 32bit value to write.
 *
 * Return Value
 *     None
 *
 * The write can only be successful when the Handle and WordOffset
 * parameters are valid.
 */
void
HWPAL_DMAResource_Write32(
        HWPAL_DMAResource_Handle_t Handle,
        const unsigned int WordOffset,
        const uint32_t Value);


/*----------------------------------------------------------------------------
 * HWPAL_DMAResource_Read32Array
 *
 * This function perform the same task as HWPAL_DMAResource_Read32 for a
 * consecutive array of 32bit words.
 *
 * See HWPAL_DMAResource_Read32 for a more detailed description.
 *
 * Handle (input)
 *     Handle for the DMA Resource to access.
 *
 * WordOffset (input)
 *     Offset in 32bit words, from the start of the DMA Resource to start
 *     reading from.
 *
 * WordCount (input)
 *     The number of 32bit words to transfer.
 *
 * Values_p (input)
 *     Memory location to write the retrieved values to.
 *     Note the ability to let Values_p point inside the DMAResource that is
 *     being read from, allowing for in-place endianess conversion.
 *
 * Return Value
 *     None.
 *
 * The read can only be successful when the Handle and WordOffset
 * parameters are valid.
 */
void
HWPAL_DMAResource_Read32Array(
        HWPAL_DMAResource_Handle_t Handle,
        const unsigned int WordOffset,
        const unsigned int WordCount,
        uint32_t * Values_p);


/*----------------------------------------------------------------------------
 * HWPAL_DMAResource_Write32Array
 *
 * This function perform the same task as HWPAL_DMAResource_Write32 for a
 * consecutive array of 32bit words.
 *
 * See HWPAL_DMAResource_Write32 for a more detailed description.
 *
 * Handle (input)
 *     Handle for the DMA Resource to access.
 *
 * WordOffset (input)
 *     Offset in 32bit words, from the start of the DMA Resource to start
 *     writing from.
 *
 * WordCount (input)
 *     The number of 32bit words to transfer.
 *
 * Values_p (input)
 *     Pointer to the memory where the values to be written are located.
 *     Note the ability to let Values_p point inside the DMAResource that is
 *     being written to, allowing for in-place endianess conversion.
 *
 * Return Value
 *     None.
 *
 * The write can only be successful when the Handle and WordOffset
 * parameters are valid.
 */
void
HWPAL_DMAResource_Write32Array(
        HWPAL_DMAResource_Handle_t Handle,
        const unsigned int WordOffset,
        const unsigned int WordCount,
        const uint32_t * Values_p);


/*----------------------------------------------------------------------------
 * HWPAL_DMAResource_PreDMA
 *
 * This function must be called when the host has finished accessing the
 * DMA Resource and the device (using its DMA) is the next to access it.
 * It is possible to hand off the entire DMA Resource, or only a selected part
 * of it by describing the part with a start offset and count.
 *
 * Handle (input)
 *     Handle for the DMA Resource to (partially) hand off.
 *
 * ByteOffset (input)
 *     Start offset within the DMA resource for the selected part to hand off
 *     to the device.
 *
 * ByteCount (input)
 *     Number of bytes from ByteOffset for the part of the DMA Resource to
 *     hand off to the device.
 *     Set to zero to hand off the entire DMA Resource.
 *
 * The driver framework implementation must use this call to ensure the data
 * coherency of the DMA Resource.
 */
void
HWPAL_DMAResource_PreDMA(
        HWPAL_DMAResource_Handle_t Handle,
        const unsigned int ByteOffset,
        const unsigned int ByteCount);


/*----------------------------------------------------------------------------
 * HWPAL_DMAResource_PostDMA
 *
 * This function must be calle when the device has finished accessing the
 * DMA Resource and the host can reclaim ownership and access it.
 * It is possible to reclaim ownership for the entire DMA Resource, or only a
 * selected part of it by describing the part with a start offset and count.
 *
 * Handle (input)
 *     Handle for the DMA Resource to (partially) hand off.
 *
 * ByteOffset (input)
 *     Start offset within the DMA resource for the selected part to reclaim.
 *
 * ByteCount (input)
 *     Number of bytes from ByteOffset for the part of the DMA Resource to
 *     reclaim.
 *     Set to zero to reclaim the entire DMA Resource.
 *
 * The driver framework implementation must use this call to ensure the data
 * coherency of the DMA Resource.
 */
void
HWPAL_DMAResource_PostDMA(
        HWPAL_DMAResource_Handle_t Handle,
        const unsigned int ByteOffset,
        const unsigned int ByteCount);


#endif /* Include Guard */

/* end of file hw_access_dma.h */
