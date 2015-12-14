/*
 *
 * Author: Tero Kivinen <kivinen@iki.fi>
 *
 *  Copyright:
 *          Copyright (c) 2004 SFNT Finland Oy.
 */
/*
 *        Program: sshikev2
 *        $Author: bruce.chang $
 *
 *        Creation          : 21:58 Nov 11 2004 kivinen
 *        Last Modification : 17:21 Nov 24 2004 kivinen
 *        Last check in     : $Date: 2012/09/28 $
 *        Revision number   : $Revision: #1 $
 *        State             : $State: Exp $
 *        Version           : 1.22
 *        
 *
 *        Description       : IKEv2 Auth method type table and print function
 *
 *
 *        $Log: ikev2-string-auth-method.c,v $
 *        Revision 1.1.2.1  2011/01/31 03:29:21  treychen_hc
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
 *        $EndLog$
 */

#include "sshincludes.h"
#include "sshikev2-initiator.h"
#include "sshikev2-util.h"

#define SSH_DEBUG_MODULE "SshIkev2StringAuthMethod"

/* Auth method to string mapping.  */
const SshKeywordStruct ssh_ikev2_auth_method_to_string_table[] = {
  { "RSA Sig", SSH_IKEV2_AUTH_METHOD_RSA_SIG },
  { "DSA Sig", SSH_IKEV2_AUTH_METHOD_DSS_SIG },
  { "Shared key", SSH_IKEV2_AUTH_METHOD_SHARED_KEY },
#ifdef SSHDIST_CRYPT_ECP
  { "ECDSA Sig with SHA-256", SSH_IKEV2_AUTH_METHOD_ECP_DSA_256 },
  { "ECDSA Sig with SHA-384", SSH_IKEV2_AUTH_METHOD_ECP_DSA_384 },
  { "ECDSA Sig with SHA-512", SSH_IKEV2_AUTH_METHOD_ECP_DSA_521 },
#endif /* SSHDIST_CRYPT_ECP */
  { NULL, 0 }
};

const char *ssh_ikev2_auth_method_to_string(SshIkev2AuthMethod auth_method)
{
  const char *name;

  name = ssh_find_keyword_name(ssh_ikev2_auth_method_to_string_table,
			       auth_method);
  if (name == NULL)
    return "unknown";
  return name;
}
