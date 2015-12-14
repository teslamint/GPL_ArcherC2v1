/* api_addrtrans.h
 *
 * Address Translation between Memory Domains.
 *
 * Translates an address in given domain to an address in a requested domain.
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

#ifndef INCLUDE_GUARD_API_ADDRTRANS_H
#define INCLUDE_GUARD_API_ADDRTRANS_H

#include "basic_defs.h"


/*----------------------------------------------------------------------------
 * AddrTrans_Domain_t
 *
 * This is a list of domains that can be supported by the implementation. The
 * exact meaning can be different for different EIP devices and different
 * environments.
 */
typedef enum
{
    ADDRTRANS_DOMAIN_UNKNOWN,
    ADDRTRANS_DOMAIN_DRIVER,
    ADDRTRANS_DOMAIN_DEVICE_PE,
    ADDRTRANS_DOMAIN_DEVICE_PKA,
    ADDRTRANS_DOMAIN_BUS,
    ADDRTRANS_DOMAIN_INTERHOST,
    ADDRTRANS_DOMAIN_ALTERNATIVE
} AddrTrans_Domain_t;


/*----------------------------------------------------------------------------
 * AddrTrans_Pair_t
 *
 * Address coupled with domain. The caller is encouraged to store the address
 * with the domain information. The type also avoid unsafe void pointer
 * output parameters.
 */
typedef struct
{
    void * Address_p;
    AddrTrans_Domain_t Domain;
} AddrTrans_Pair_t;


/*----------------------------------------------------------------------------
 * AddrTrans_Status_t
 *
 * Return values for all the API functions.
 */
typedef enum
{
    ADDRTRANS_STATUS_OK,
    ADDRTRANS_ERROR_BAD_ARGUMENT,
    ADDRTRANS_ERROR_CANNOT_TRANSLATE
} AddrTrans_Status_t;


/*----------------------------------------------------------------------------
 * AddrTrans_Translate
 *
 * Attempts to translates an address from one domain to a new domain.
 *
 * PairIn
 *     Source address and domain to covert from.
 *
 * AlternativeRef
 *     When PairIn.Domain equals ADDRTRANS_DOMAIN_ALTERNATIVE, this value is
 *     used as the domain indicator. It is typically provided directly from
 *     the application through the DMA Buffer Allocation API.
 *
 * DestDomain
 *     The requested domain to translate PairIn to.
 *
 * PairOut_p
 *     Pointer to the memory location when the converted address plus domain
 *     will be written.
 *
 * Return Values
 *     ADDRTRANS_STATUS_OK:
 *         Translation was successful.
 *     ADDRTRANS_ERROR_BAD_ARGUMENT:
 *         Invalid parameter.
 *     ADDRTRANS_ERROR_CANNOT_TRANSLATE:
 *         Domain (-combination) not supported, or address not in domain.
 */
AddrTrans_Status_t
AddrTrans_Translate(
        const AddrTrans_Pair_t PairIn,
        const unsigned int AlternativeRef,
        AddrTrans_Domain_t DestDomain,
        AddrTrans_Pair_t * const PairOut_p);


#endif /* Include Guard */

/* end of file api_addrtrans.h */
