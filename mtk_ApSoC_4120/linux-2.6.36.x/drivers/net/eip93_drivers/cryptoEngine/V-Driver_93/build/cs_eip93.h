/* cs_eip93.h
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
 * flag to control paramater check 
 */
#ifndef VDRIVER_PERFORMANCE
#define EIP93_STRICT_ARGS 1  //uncomment when paramters check needed
#endif



//  Enable these flags for swapping PD, SA, DATA or register read/writes
//  by packet engine

//#define  EIP93_ENABLE_SWAP_PD
//#define  EIP93_ENABLE_SWAP_SA
//#define  EIP93_ENABLE_SWAP_DATA
//#define  EIP93_ENABLE_SWAP_REG_DATA

// Size of buffer for Direct Host Mode
#define EIP93_RAM_BUFFERSIZE_BYTES 256 //for EIP93-IESW
// #define EIP93_RAM_BUFFERSIZE_BYTES 2048 - for EIP93-I

/* end of file cs_eip93.h */
