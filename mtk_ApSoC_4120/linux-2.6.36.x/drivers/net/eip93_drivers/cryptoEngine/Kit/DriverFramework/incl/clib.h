/* clib.h
 *
 * C Library Abstraction
 *
 * This header function guarantees the availability of a select list of
 * Standard C APIs. This makes the user of this API compiler independent.
 * It also gives a single customization point for these functions.
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

#ifndef INCLUDE_GUARD_CLIB_H
#define INCLUDE_GUARD_CLIB_H

/* guaranteed APIs:

    memcpy
    memmove
    memset
    memcmp
    offsetof

*/


/* Note: This is a template. Copy and customize according to your needs! */
#if defined(linux) && defined(MODULE)

#include <linux/string.h>     // memmove and memcpy
#include <linux/stddef.h>     // offsetof

#else

#include <string.h>     // memmove
#include <memory.h>     // memcpy, etc.
#include <stddef.h>     // offsetof

#endif

#endif /* Inclusion Guard */

/* end of file clib.h */
