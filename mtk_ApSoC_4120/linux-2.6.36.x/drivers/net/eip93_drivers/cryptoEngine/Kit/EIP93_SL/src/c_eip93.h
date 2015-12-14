/* c_eip93.h
 *
 * Configuration options for the EIP93 module.
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

/*---------------------------------------------------------------------------
 * Defines that can be used in cs_eip93.h.
 * Defaults that should be set if not defined in cs_eip93.h
 */
#include "cs_eip93.h"

/*---------------------------------------------------------------------------
 * flag to control paramater check
 */

//#define EIP93_STRICT_ARGS 1  //uncomment when paramters check needed
//  Enable these flags for swapping PD, SA, DATA or register read/writes
//  by packet engine

//#define  EIP93_ENABLE_SWAP_PD
//#define  EIP93_ENABLE_SWAP_SA
//#define  EIP93_ENABLE_SWAP_DATA
//#define  EIP93_ENABLE_SWAP_REG_DATA

// Size of buffer for Direct Host Mode

#ifndef EIP93_RAM_BUFFERSIZE_BYTES
#define EIP93_RAM_BUFFERSIZE_BYTES 256 //for EIP93-IESW
// #define EIP93_RAM_BUFFERSIZE_BYTES 2048 - for EIP93-I
#endif


/* end of file c_eip93.h */

