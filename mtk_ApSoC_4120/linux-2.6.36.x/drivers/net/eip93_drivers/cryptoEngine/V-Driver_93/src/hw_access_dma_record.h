/* hw_access_dma_record.h
 *
 * EIP Driver Framework, DMAResource Record Definition
 *
 * The document "Driver Framework Porting Guide" contains the detailed
 * specification of this API. The information contained in this header file
 * is for reference only.
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

#include "api_dmabuf.h"

typedef struct
{
    uint32_t Magic;     // signature used to validate handles

    struct
    {
        // for freeing the buffer
        void * AllocatedAddr_p;
        unsigned int AllocatedSize;     // in bytes

        void * Alternative_p;
        char AllocatorRef;

        // for separating SoC memory from main memory
        uint8_t MemoryBank;

    } alloc;

    struct
    {
        // alignment used for HostAddr_p
        uint8_t Alignment;

        // aligned start-address, data starts here
        void * HostAddr_p;

        // maximum data amount that can be stored from HostAddr_p
        unsigned int BufferSize;        // in bytes

        // true = memory is cached
        bool fCached;
    } host;

    struct
    {
        // used by Read/Write32[Array]
        bool fSwapEndianess;

        // address as seen by device
        // (must point to same buffer as HostAddr_p)
        // 0 = not yet translated
        uint32_t DeviceAddr32;

    } device;

#ifndef ADAPTER_REMOVE_BOUNCEBUFFERS
    struct
    {
        // bounce buffer for DMABuf_Register'ed buffers
        // note: used only when concurrency is impossible
        //       (PE source packets allow concurrency!!)
        DMABuf_Handle_t Bounce_Handle;
    } bounce;
#endif

} HWPAL_DMAResource_Record_t;


/* end of file hw_access_dma_record.h */
