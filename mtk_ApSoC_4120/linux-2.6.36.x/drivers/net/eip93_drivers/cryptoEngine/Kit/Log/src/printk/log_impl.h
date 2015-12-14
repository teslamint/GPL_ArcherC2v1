/* log_impl_linux_kernel.h
 *
 * Log Module, implementation for Linux Kernel Mode
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

#ifndef INCLUDE_GUARD_LINUX_KERNEL_H
#define INCLUDE_GUARD_LINUX_KERNEL_H

#include <linux/kernel.h>   // printk

#define Log_Message           printk
#define Log_FormattedMessage  printk

#endif /* Include Guard */

/* end of file log_impl_linux_kernel.h */
