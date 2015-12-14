/* cs_sladtestapp_eip93_systemtestconfig.h
 *
 * Selects the system test configuration through a single define.
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

//[USE POLLING] -- should comment out VDRIVER_INTERRUPTS in modules/eip93_drivers/cryptoEngine/V-Dri                   ver_93/build/cs_driver.h
//#define SLAD_TEST_EIP93_SYSTEMTEST_CONFIGURATION_C4
//#define SLAD_TEST_EIP93_SYSTEMTEST_CONFIGURATION_C1
//#define SLAD_TEST_EIP93_SYSTEMTEST_CONFIGURATION_C3
//#define SLAD_TEST_EIP93_SYSTEMTEST_CONFIGURATION_C6
//#define SLAD_TEST_EIP93_SYSTEMTEST_CONFIGURATION_C8

//[USE INTERRUPRTS] -- should define VDRIVER_INTERRUPTS in modules/eip93_drivers/cryptoEngine/V-Driv                       er_93/build/cs_driver.h
#define SLAD_TEST_EIP93_SYSTEMTEST_CONFIGURATION_C2
//#define SLAD_TEST_EIP93_SYSTEMTEST_CONFIGURATION_C7
//#define SLAD_TEST_EIP93_SYSTEMTEST_CONFIGURATION_C5  //INTERRUPT_COALESCING

/* end of file cs_sladtestapp_eip93_systemtestconfig.h */

