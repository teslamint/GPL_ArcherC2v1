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
 *        Version           : 1.17
 *        
 *
 *        Description       : IKEv2 CERT Encoding type table and print function
 *
 *
 *        $Log: ikev2-string-cert-encoding.c,v $
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

#define SSH_DEBUG_MODULE "SshIkev2StringCertEncoding"

#ifdef SSHDIST_IKE_CERT_AUTH

/* Cert encoding to string mapping.  */
const SshKeywordStruct ssh_ikev2_cert_encoding_to_string_table[] = {
  { "PKCS7", SSH_IKEV2_CERT_PKCS7_WRAPPED_X_509 },
  { "PGP", SSH_IKEV2_CERT_PGP },
  { "DNS", SSH_IKEV2_CERT_DNS_SIGNED_KEY },
  { "X509", SSH_IKEV2_CERT_X_509 },
  { "Kerberos", SSH_IKEV2_CERT_KERBEROS_TOKEN },
  { "CRL", SSH_IKEV2_CERT_CRL },
  { "ARL", SSH_IKEV2_CERT_ARL },
  { "SPKI", SSH_IKEV2_CERT_SPKI },
  { "X509 Attr", SSH_IKEV2_CERT_X_509_ATTRIBUTE },
  { "RAW RSA", SSH_IKEV2_CERT_RAW_RSA_KEY },
  { "HASH & URL X509", SSH_IKEV2_CERT_HASH_AND_URL_X509 },
  { "HASH & URL X509 BUNDLE", SSH_IKEV2_CERT_HASH_AND_URL_X509_BUNDLE },
  { NULL, 0 }
};

const char *ssh_ikev2_cert_encoding_to_string(SshIkev2CertEncoding cert_type)
{
  const char *name;

  name = ssh_find_keyword_name(ssh_ikev2_cert_encoding_to_string_table,
			       cert_type);
  if (name == NULL)
    return "unknown";
  return name;
}

#endif /* SSHDIST_IKE_CERT_AUTH */
