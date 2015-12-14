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
 *        Version           : 1.24
 *        
 *
 *        Description       : IKEv2 Auth method type table and print function
 *
 *
 *        $Log: ikev2-string-protocol.c,v $
 *        Revision 1.1.2.1  2011/01/31 03:29:22  treychen_hc
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
 *        $EndLog$
 */

#include "sshincludes.h"
#include "sshikev2-initiator.h"
#include "sshikev2-util.h"

#define SSH_DEBUG_MODULE "SshIkev2StringProtocol"

/* Protocol number to string mapping.  */
const SshKeywordStruct ssh_ikev2_protocol_to_string_table[] = {
  { "None", SSH_IKEV2_PROTOCOL_ID_NONE },
  { "IKE", SSH_IKEV2_PROTOCOL_ID_IKE },
  { "AH", SSH_IKEV2_PROTOCOL_ID_AH },
  { "ESP", SSH_IKEV2_PROTOCOL_ID_ESP },
  { NULL, 0 }
};

const char *ssh_ikev2_protocol_to_string(SshIkev2ProtocolIdentifiers protocol)
{
  const char *name;

  name = ssh_find_keyword_name(ssh_ikev2_protocol_to_string_table,
			       protocol);
  if (name == NULL)
    return "unknown";
  return name;
}
