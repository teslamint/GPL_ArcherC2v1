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
#include "adapter_internal.h"


/*----------------------------------------------------------------------------
 * VDriver_Init
 */
int
VDriver_Init(void)
{
    LOG_INFO("EIP93-V-Driver: Initializing\n");

    if (!Adapter_Init())
    {
        return -1;
    }

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



/* end of file adapter_linuxkernelmodule.c */
