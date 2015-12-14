/* adapter_global.c
 *
 * Adapter module responsible for adapter-wide (global) tasks.
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
#include <linux/init.h>
#include <linux/version.h>
#include <linux/module.h>
#include <linux/config.h>
//#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,35)
//#include <linux/sched.h>
//#endif
//#include <linux/ioctl.h>
#include <linux/kernel.h>
#include <linux/interrupt.h>
//#include <linux/fs.h>
//#include <asm/uaccess.h>
#include <asm/rt2880/rt_mmap.h>
#include <asm/rt2880/surfboardint.h>
//#include <linux/pci.h>
//#include <linux/delay.h>

#define RT2880_REG(x)                   (*((volatile u32 *)(x)))
#define RT2880_RSTCTRL_REG              (RALINK_SYSCTL_BASE+0x34)


#include "basic_defs.h"
#include "adapter_internal.h"
#include "hw_access.h"
#include "hw_access_dma.h"

static bool Adapter_IsInitialized = false;
//static HWPAL_Device_t Adapter_Device_CLOCK;
//static HWPAL_Device_t Adapter_Device_RESET;
//static HWPAL_Device_t Adapter_Device_PCIConfigSpace;

void * GlobalVTBALDevice ;
/*----------------------------------------------------------------------------
 * Adapter_Init
 *
 * Return Value
 *     true   Success
 *     false  Failure (fatal!)
 */
bool
Adapter_Init(void)
{
int i;
     // int nIRQ = -1;
//Qwert: reset cryptoengine IP
RT2880_REG(RALINK_SYSCTL_BASE+0x30)|=0x1<<29;
RT2880_REG(RT2880_RSTCTRL_REG)|=0x1<<29;
for(i=0;i<100000;i++);
RT2880_REG(RT2880_RSTCTRL_REG)=0;


    if (Adapter_IsInitialized != false)
    {
        LOG_WARN("Adapter_Init: Already initialized\n");
        return true;
    }

    // trigger first-time initialization of the adapter
#ifndef RT_EIP93_DRIVER
    //register, enable as a PCI device; GlobalVTBALDevice is returned as irq number.
    if (!HWPAL_Initialize( &GlobalVTBALDevice))
        return false;
#endif

#if 0
    if (!HWPAL_Device_Find("RESET", &Adapter_Device_RESET))
    {
        LOG_CRIT("Adapter_Init: Failed to locate RESET\n");
        return false;
    }

    if (!HWPAL_Device_Find("CLK", &Adapter_Device_CLOCK))
    {
        LOG_CRIT("Adapter_Init: Failed to locate CLK\n");
        return false;
    }
#endif

    if (!HWPAL_DMAResource_Init(1024, NULL, 0))
    {
#ifndef RT_EIP93_DRIVER
        HWPAL_UnInitialize(); //unregister pci
#endif
        return false;
    }

    if (!Adapter_EIP93_Init())
    {
        LOG_CRIT("Adapter_Init: Adapter_EIP93_Init failed\n");
    }

#ifdef ADAPTER_EIP93PE_INTERRUPTS_ENABLE
#ifdef RT_EIP93_DRIVER
    Adapter_Interrupts_Init(SURFBOARDINT_CRYPTO);
#else
    Adapter_Interrupts_Init(0);
#endif
#endif /* ADAPTER_EIP93PE_INTERRUPTS_ENABLE */

    Adapter_IsInitialized = true;

    return true;    // success
}


/*----------------------------------------------------------------------------
 * Adapter_UnInit
 */
void
Adapter_UnInit(void)
{
    if (!Adapter_IsInitialized)
    {
        LOG_WARN("Adapter_UnInit: Adapter is not initialized\n");
        return;
    }


    Adapter_IsInitialized = false;



    Adapter_EIP93_UnInit();

#ifdef ADAPTER_EIP93PE_INTERRUPTS_ENABLE
    Adapter_Interrupts_UnInit();
#endif


    // following call reports leaks in some implementations
    HWPAL_DMAResource_UnInit();
#ifndef RT_EIP93_DRIVER
    HWPAL_UnInitialize();  //unregister pci
#endif
}


/*----------------------------------------------------------------------------
 * Adapter_Report_Build_Params
 */
void
Adapter_Report_Build_Params(void)
{
    // This function is dependent on config file cs_adapter.h.
    // Please update this when Config file for Adapter is changed.
    LOG_INFO("Adapter build configuration:\n");

#define REPORT_SET(_X) \
    LOG_INFO("\t" #_X "\n")

#define REPORT_STR(_X) \
    LOG_INFO("\t" #_X ": %s\n", _X)

#define REPORT_INT(_X) \
    LOG_INFO("\t" #_X ": %d\n", _X)

#define REPORT_HEX32(_X) \
    LOG_INFO("\t" #_X ": 0x%08X\n", _X)

#define REPORT_EQ(_X, _Y) \
    LOG_INFO("\t" #_X " == " #_Y "\n")

#define REPORT_EXPL(_X, _Y) \
    LOG_INFO("\t" #_X _Y "\n")

    LOG_INFO("PEC / EIP93 DHM/ARM:\n");
#ifdef ADAPTER_PEC_DEBUG
    REPORT_SET(ADAPTER_PEC_DEBUG);
#endif
#ifdef ADAPTER_EIP93_PE_MODE_DHM
    REPORT_EXPL(ADAPTER_EIP93_PE_MODE_DHM, " => Direct Host Mode");
#endif
#ifdef ADAPTER_EIP93_PE_MODE_ARM
    REPORT_EXPL(ADAPTER_EIP93_PE_MODE_ARM, " => Autonomous Ring Mode");
#endif
#ifdef ADAPTER_EIP93_SEPARATE_RINGS
    REPORT_SET(ADAPTER_EIP93_SEPARATE_RINGS);
#else
    REPORT_EXPL(ADAPTER_EIP93_SEPARATE_RINGS, " is NOT set => Overlapping");
#endif
    REPORT_INT(ADAPTER_EIP93_RINGSIZE_BYTES);
    REPORT_INT(ADAPTER_EIP93_DESCRIPTORDONECOUNT);
    REPORT_INT(ADAPTER_EIP93_DESCRIPTORDONETIMEOUT);
    REPORT_INT(ADAPTER_EIP93_DMATHRESHOLD_INPUT);
    REPORT_INT(ADAPTER_EIP93_DMATHRESHOLD_OUTPUT);
    REPORT_INT(ADAPTER_EIP93_DHM_THRESHOLD_INPUT);
    REPORT_INT(ADAPTER_EIP93_DHM_THRESHOLD_OUTPUT);





    // Other
    LOG_INFO("Other:\n");
    REPORT_STR(ADAPTER_DRIVER_NAME);
    REPORT_INT(ADAPTER_MAX_DMARESOURCE_HANDLES);


    REPORT_HEX32(ADAPTER_INTERRUPTS_TRACEFILTER);
#if (LOG_SEVERITY_MAX == LOG_SEVERITY_INFO)
    REPORT_EQ(LOG_SEVERITY_MAX, LOG_SEVERITY_INFO);
#elif (LOG_SEVERITY_MAX == LOG_SEVERITY_WARNING)
    REPORT_EQ(LOG_SEVERITY_MAX, LOG_SEVERITY_WARNING);
#elif (LOG_SEVERITY_MAX == LOG_SEVERITY_CRITICAL)
    REPORT_EQ(LOG_SEVERITY_MAX, LOG_SEVERITY_CRITICAL);
#else
    REPORT_EXPL(LOG_SEVERITY_MAX, " - Unknown (not info/warn/crit)");
#endif
}


/* end of file adapter_global.c */

