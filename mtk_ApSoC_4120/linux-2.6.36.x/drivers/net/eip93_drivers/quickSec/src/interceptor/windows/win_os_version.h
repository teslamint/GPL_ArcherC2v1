/**
   
   @copyright
   Copyright (c) 2002 - 2010, AuthenTec Oy.  All rights reserved.
   
   win_os_version.c
   
   Enumerated type for differentiating Windows operating systems.
   
*/


#ifndef SSH_WIN_OS_VERSION_H
#define SSH_WIN_OS_VERSION_H

/*--------------------------------------------------------------------------
  INCLUDE FILES
  --------------------------------------------------------------------------*/


/*--------------------------------------------------------------------------
  DEFINITIONS
  --------------------------------------------------------------------------*/

/* Well-known OS versions */
typedef enum
{
  /* Desktop platforms */
  SSH_OS_VERSION_NT4 = 0x40,       /* Windows NT 4.0 */
  SSH_OS_VERSION_W2K = 0x50,       /* Windows 2000 */
  SSH_OS_VERSION_WXP = 0x51,       /* Windows XP */
  SSH_OS_VERSION_S2003 = 0x52,     /* Windows Server 2003 */
  SSH_OS_VERSION_VISTA = 0x60,     /* Windows Vista */
  SSH_OS_VERSION_WINDOWS_7 = 0x61, /* Windows 7 */
  /* Mobile platforms */
  SSH_OS_VERSION_CE_42 = 0x10042,  /* Windows CE 4.2 */
  SSH_OS_VERSION_CE_50 = 0x10050,  /* Windows CE 5.0 */
  SSH_OS_VERSION_CE_51 = 0x10051,  /* Windows CE 5.1 (Windows Mobile 5.0) */
  SSH_OS_VERSION_CE_52 = 0x10052,  /* Windows CE 5.2 (Windows Mobile 6.x) */
  SSH_OS_VERSION_MOBILE_5 = SSH_OS_VERSION_CE_51,
  SSH_OS_VERSION_MOBILE_6 = SSH_OS_VERSION_CE_52
} SshOsVersion;


#endif /* SSH_WIN_OS_VERSION_H */

