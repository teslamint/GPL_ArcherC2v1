/* adapter_addrtrans.c
 *
 * Implementation of the DMA Buffer Allocation API.
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

#include "adapter_internal.h"
#include "api_addrtrans.h"          // the API to implement

//#include <asm/io.h>                 // for virt_to_bus


/*----------------------------------------------------------------------------
 * AddrTrans_Translate
 */
AddrTrans_Status_t
AddrTrans_Translate(
        const AddrTrans_Pair_t PairIn,
        const unsigned int AlternativeRef,
        AddrTrans_Domain_t DestDomain,
        AddrTrans_Pair_t * const PairOut_p)
{
    // we only support 1:1 translation from driver to device domain
    if (PairOut_p == NULL)
        return ADDRTRANS_ERROR_BAD_ARGUMENT;

    if (DestDomain != ADDRTRANS_DOMAIN_DEVICE_PE)
        return ADDRTRANS_ERROR_CANNOT_TRANSLATE;

    PairOut_p->Domain = DestDomain;

    if (PairIn.Domain == ADDRTRANS_DOMAIN_ALTERNATIVE &&
        AlternativeRef == ADAPTER_DMABUF_ALLOCATORREF_KMALLOC)
    {
        // linux kmalloc allocated address
        // we can use virt_to_bus on this one
        // PairOut_p->Address_p = (void *)virt_to_bus(PairIn.Address_p);
        VTBAL_TranslateAddr_Host2Bus(
        (uint32_t)PairIn.Address_p, &PairOut_p->Address_p);
//        printf ("Address Translated (AddrTrans_Translate).\n");
        return ADDRTRANS_STATUS_OK;
    }

    PairOut_p->Domain = ADDRTRANS_DOMAIN_UNKNOWN;
    PairOut_p->Address_p = 0;

    return ADDRTRANS_ERROR_CANNOT_TRANSLATE;
}


/* end of file adapter_addrtrans.c */
