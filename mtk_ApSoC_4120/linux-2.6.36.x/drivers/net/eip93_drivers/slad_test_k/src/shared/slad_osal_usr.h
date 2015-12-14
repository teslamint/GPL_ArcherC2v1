/*h*
* File:   slad_osal_usr.h
*
* Security Look-aside Driver Module for AuthenTec crypto hardware.
* Functions and definitions for User Mode
*

     Copyright 2007-2008 AuthenTec B.V.


*
*
* Edit History:
*
*Initial revision
* Created.
*/

#ifndef SLAD_OSAL_USR_H
#define SLAD_OSAL_USR_H

#ifndef MODULE

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define osal_malloc( len )  calloc( 1, len )
#define osal_malloc_cache_aligned( len )    calloc( 1, len )

#ifdef SLAD_TEST_APP_ENABLE_INFO_LOGS
#define LOG_SEVERITY_MAX LOG_SEVERITY_INFO
#else
#define LOG_SEVERITY_MAX LOG_SEVERITY_WARNING
#endif

#include "log.h"


#define osal_free(ptr, len ) \
do{  \
    if( ptr )    free(ptr) ; \
}while(0)

#define osal_free_cache_aligned( ptr, len )    \
do{  \
    if( ptr )    free(ptr) ; \
}while(0)

#define osal_free_coherent( ptr, phy_addr,  len )  \
do{  \
    if( ptr )    free(ptr) ; \
}while(0)

#define osal_malloc_coherent( p_buf_addr, p_bus_addr, len )  calloc( 1, len )


#define osal_delay(n) sleep( n < 1000000 ? 1 : (n/1000000) )

#define osal_copy_from_app( userland, dst, src, len ) \
    memcpy ( dst, src, len )

#define osal_memset(buff,val,len) memset(buff,val,len)
#define osal_bzero(buff,len) memset(buff,0,len)

#define osal_get_time() ((UINT32) time (NULL))

#define osal_sleep(n) sleep(n)



#define osal_target_sleep(n) sleep(n)

#define osal_printf  printf
#define osal_debug_printf  osal_printf




#define slad_osal_get_pid() getpid()

#include <signal.h>

#define slad_osal_user_signal() SIGUSR1

void osal_install_notifier (void (*fn) (int));
unsigned int osal_swap_endian (unsigned int num);
#define SLAD_OSAL_IS_IN_USER_MODE

#endif // MODULE

#endif // SLAD_OSAL_USR_H
