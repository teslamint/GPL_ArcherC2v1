/*
 * Author: Tero Kivinen <kivinen@iki.fi>
 *
*  Copyright:
*          Copyright (c) 2002, 2003 SFNT Finland Oy.
*  Copyright:
*          Copyright (c) 2002, 2003 SFNT Finland Oy.
 */
/*
 *        Program: sshisakmp
 *        $Source: /home/user/socsw/cvs/cvsrepos/tclinux_phoenix/modules/eip93_drivers/quickSec/src/ipsec/lib/sshisakmp/tests/Attic/xauth_demo.h,v $
 *        $Author: bruce.chang $
 *
 *        Creation          : 16:04 Jun 14 1998 kivinen
 *        Last Modification : 01:46 Jul 31 1998 kivinen
 *        Last check in     : $Date: 2012/09/28 $
 *        Revision number   : $Revision: #1 $
 *        State             : $State: Exp $
 *        Version           : 1.18
 *        
 *
 *        Description       : Isakmp xauth test module
 *
 *
 *        $Log: xauth_demo.h,v $
 *        Revision 1.1.2.1  2011/01/31 03:29:52  treychen_hc
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
 *        $EndLog$
 */

#ifndef XAUTH_DEMO_H
#define XAUTH_DEMO_H

#include "isakmp.h"

#ifdef SSHDIST_ISAKMP_CFG_MODE

/* Xauth password handler callback */
typedef void (*SshIkeXauthPasswordHandler)(SshIkeNegotiation negotiation,
                                           SshIkePMPhaseII pm_info,
                                           SshIkeNotifyMessageType error_code,
                                           SshIkeXauthType type,
                                           const unsigned char *username,
                                           size_t username_len, 
                                           const unsigned char *password,
                                           size_t password_len,
                                           void *callback_context);

/* Start xauth negotiation using authentication type that returns username and
   password. */
SshIkeErrorCode ssh_ike_connect_xauth_password(SshIkeServerContext context,
                                               SshIkeNegotiation *negotiation,
                                               SshIkeNegotiation
                                               isakmp_sa_negotiation,
                                               const char *remote_name,
                                               const char *remote_port,
                                               SshIkeXauthType type,
                                               void *policy_manager_data,
                                               int connect_flags,
                                               SshIkeXauthPasswordHandler
                                               handler_callback,
                                               void *handler_callback_context);

/* Policy manager function that will process xauth version of cfg fill attrs.
   This is called from the ssh_policy_cfg_fill_attrs function */
void ssh_policy_xauth_fill_attrs(SshIkePMPhaseII pm_info,
                                 SshIkePayloadAttr return_attributes,
                                 SshPolicyCfgFillAttrsCB callback_in,
                                 void *callback_context_in);

#endif /* SSHDIST_ISAKMP_CFG_MODE */

#endif /* XAUTH_DEMO_H */
