/*
  tls_util.c

  Copyright:
          Copyright 2002-2007, SafeNet Inc. All rights reserved.
  All rights reserved.
*/

#include "sshincludes.h"
#include "sshdebug.h"
#include "sshtlsi.h"

#define SSH_DEBUG_MODULE "SshTlsUtil"

void ssh_tls_free_cert_chain(SshTlsBerCert chain)
{
  SshTlsBerCert temp;

  while (chain != NULL)
    {
      temp = chain->next;
      ssh_free(chain->ber_data);
      ssh_free(chain);
      chain = temp;
    }
}

SshTlsBerCert ssh_tls_create_ber_cert(unsigned char *data, size_t len)
{
  SshTlsBerCert newp;

  if ((newp = ssh_calloc(1, sizeof(*newp))) != NULL)
    {
      if ((newp->ber_data = ssh_memdup(data, len)) != NULL)
        {
          newp->ber_data_len = len;
          newp->next = NULL;
        }
      else
        {
          ssh_free(newp);
          newp = NULL;
        }
    }
  return newp;
}

SshTlsBerCert ssh_tls_duplicate_ber_cert_chain(SshTlsBerCert cert)
{
  SshTlsBerCert next, duplicated;

  if (cert == NULL) return NULL;

  next = ssh_tls_duplicate_ber_cert_chain(cert->next);
  if ((duplicated =
       ssh_tls_create_ber_cert(cert->ber_data, cert->ber_data_len))
      != NULL)
    duplicated->next = next;

  return duplicated;
}


#define MAP(r, s) case r: return s; break
const char *ssh_tls_failure_str(SshTlsFailureReason reason)
{
  switch (reason)
    {
      MAP(SSH_TLS_NO_FAILURE, "no_failure");
      MAP(SSH_TLS_FAIL_UNEXPECTED_MESSAGE, "unexpected_message");
      MAP(SSH_TLS_FAIL_BAD_RECORD_MAC, "bad_record_mac");

      MAP(SSH_TLS_FAIL_DECRYPTION_FAILED, "decryption_failed");
      MAP(SSH_TLS_FAIL_RECORD_OVERFLOW, "record_overflow");
      MAP(SSH_TLS_FAIL_DECOMPRESSION_FAILURE, "decompression_failure");
      MAP(SSH_TLS_FAIL_HANDSHAKE_FAILURE, "handshake_failure");
      MAP(SSH_TLS_FAIL_BAD_CERTIFICATE, "bad_certificate");
      MAP(SSH_TLS_FAIL_UNSUPPORTED_CERTIFICATE, "unsupported_certificate");
      MAP(SSH_TLS_FAIL_CERTIFICATE_REVOKED, "certificate_revoked");
      MAP(SSH_TLS_FAIL_CERTIFICATE_EXPIRED, "certificate_expired");
      MAP(SSH_TLS_FAIL_CERTIFICATE_UNKNOWN, "certificate_unknown");
      MAP(SSH_TLS_FAIL_ILLEGAL_PARAMETER, "illegal_parameter");
      MAP(SSH_TLS_FAIL_UNKNOWN_CA, "unknown_ca");
      MAP(SSH_TLS_FAIL_ACCESS_DENIED, "access_denied");
      MAP(SSH_TLS_FAIL_DECODE_ERROR, "decode_error");
      MAP(SSH_TLS_FAIL_DECRYPT_ERROR, "decrypt_error");
      MAP(SSH_TLS_FAIL_EXPORT_RESTRICTION, "export_restriction");
      MAP(SSH_TLS_FAIL_PROTOCOL_VERSION, "protocol_version");
      MAP(SSH_TLS_FAIL_INSUFFICIENT_SECURITY, "insufficient_security");
      MAP(SSH_TLS_FAIL_INTERNAL_ERROR, "internal_error");
      MAP(SSH_TLS_FAIL_USER_CANCELED, "user_canceled");

      MAP(SSH_TLS_FAIL_REMOTE_BUG, "remote_bug");

      MAP(SSH_TLS_FAIL_REMOTE_CERT_BAD, "remote_cert_bad");
      MAP(SSH_TLS_FAIL_REMOTE_CERT_EXPIRED, "remote_cert_expired");
      MAP(SSH_TLS_FAIL_REMOTE_CERT_REVOKED, "remote_cert_revoked");
      MAP(SSH_TLS_FAIL_REMOTE_CERT_CA, "remote_cert_ca");
      MAP(SSH_TLS_FAIL_REMOTE_CERT_UNSUPPORTED, "remote_cert_unsupported");
      MAP(SSH_TLS_FAIL_REMOTE_CERT_UNKNOWN, "remote_cert_unknown");

      MAP(SSH_TLS_FAIL_REMOTE_DENY_ACCESS, "remote_deny_access");
      MAP(SSH_TLS_FAIL_REMOTE_INSUFFICIENT_SECURITY,
          "remote_insufficient_security");

      MAP(SSH_TLS_FAIL_PREMATURE_EOF, "premature_eof");
      MAP(SSH_TLS_FAIL_KEX_TIMEOUT, "kex_timeout");
    default:
      return "unknown"; /* Hopefully not reached. */
    }
}
