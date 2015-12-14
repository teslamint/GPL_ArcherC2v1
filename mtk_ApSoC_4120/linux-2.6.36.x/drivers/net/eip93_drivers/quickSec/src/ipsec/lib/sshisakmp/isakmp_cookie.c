/*
 *
 * Author: Tero Kivinen <kivinen@iki.fi>
 *
*  Copyright:
*          Copyright (c) 2002, 2003 SFNT Finland Oy.
 */
/*
 *        Program: sshisakmp
 *        $Source: /home/user/socsw/cvs/cvsrepos/tclinux_phoenix/modules/eip93_drivers/quickSec/src/ipsec/lib/sshisakmp/Attic/isakmp_cookie.c,v $
 *        $Author: bruce.chang $
 *        $Author: bruce.chang $
 *
 *        Creation          : 14:48 Jul 30 1997 kivinen
 *        Last Modification : 20:47 Mar  5 2002 kivinen
 *        Last check in     : $Date: 2012/09/28 $
 *        Revision number   : $Revision: #1 $
 *        State             : $State: Exp $
 *        Version           : 1.96
 *        
 *
 *        Description       : Isakmp anti-cloggin token (cookie) module
 *
 *        $Log: isakmp_cookie.c,v $
 *        Revision 1.1.2.1  2011/01/31 03:29:39  treychen_hc
 *        add eip93 drivers
 * *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        $EndLog$
 */

#include "sshincludes.h"
#include "isakmp.h"
#include "isakmp_internal.h"
#include "sshdebug.h"
#include "sshtimeouts.h"

#define SSH_DEBUG_MODULE "SshIkeCookie"

/*                                                              shade{0.9}
 * Create isakmp cookie. Generate completely random
 * cookie, as checking the cookie from the hash table is
 * about as fast or faster than hashing stuff together.
 * This also makes cookies movable against multiple machines
 * (high availability or checkpointing systems).
 * The return_buffer must be SSH_IKE_COOKIE_LENGTH
 * bytes long.                                                  shade{1.0}
 */
void ike_cookie_create(SshIkeContext isakmp_context,
                       unsigned char *cookie)
{
  int i;

  for (i = 0; i < SSH_IKE_COOKIE_LENGTH; i++)
    cookie[i] = ssh_random_get_byte();

  SSH_DEBUG_HEXDUMP(SSH_D_LOWOK, ("Cookie create"), cookie, 8);
}
