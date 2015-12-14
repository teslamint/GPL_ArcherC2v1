/* adapter_linuxkernelmodule.c
 *
 * This is the wrapper that makes the driver a Linux Kernel Loadable Module.
 */

/*****************************************************************************
*                                                                            *
*       Copyright (c) 2008-2009 SafeNet Inc. All Rights Reserved.            *
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

#include "basic_defs.h"
#include "hw_access.h"
#include "adapter_internal.h"

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>

#define VPint *(volatile unsigned int *)

/*----------------------------------------------------------------------------
 * VDriver_Init
 */
int
VDriver_Init(void)
{
#ifndef ADAPTER_EIP93_NO_ACTUAL_DEVICE
    LOG_INFO("EIP93-V-Driver: Initializing here\n");

    if (!Adapter_Init())
    {
        return -1;
    }
#else
    LOG_CRIT("\n This is to test that Driver Inserts successfully \n");
    LOG_CRIT(" There is no actual device installed \n");

#endif

    Adapter_Report_Build_Params();
    
    return 0;   // success
}


/*----------------------------------------------------------------------------
 * VDriver_Exit
 */
void
VDriver_Exit(void)
{
    Adapter_UnInit();
    LOG_INFO("EIP93-V-Driver: UnInitialized\n");
}


MODULE_LICENSE("Proprietary");

module_init(VDriver_Init);
module_exit(VDriver_Exit);

#include "api_pec.h"
EXPORT_SYMBOL(PEC_Capabilities_Get);
EXPORT_SYMBOL(PEC_Init);
EXPORT_SYMBOL(PEC_UnInit);
EXPORT_SYMBOL(PEC_SA_Register);
EXPORT_SYMBOL(PEC_SA_UnRegister);
EXPORT_SYMBOL(PEC_Packet_Put);
EXPORT_SYMBOL(PEC_Packet_Get);
EXPORT_SYMBOL(PEC_CommandNotify_Request);
EXPORT_SYMBOL(PEC_ResultNotify_Request);

#include "api_dmabuf.h"
//EXPORT_SYMBOL(DMABuf_Alloc); /*for integration*/
//EXPORT_SYMBOL(DMABuf_Register); /*for integration*/
//EXPORT_SYMBOL(DMABuf_Release); /*for integration*/


/* end of file adapter_linuxkernelmodule.c */
