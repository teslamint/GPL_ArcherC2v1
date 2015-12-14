/*
 *
 * Author: Tero Kivinen <kivinen@iki.fi>
 *
*  Copyright:
*          Copyright (c) 2002, 2003 SFNT Finland Oy.
*  Copyright:
*          Copyright (c) 2002, 2003 SFNT Finland Oy.
 */
/*
 *        Program: sshisakmp
 *        $Source: /home/user/socsw/cvs/cvsrepos/tclinux_phoenix/modules/eip93_drivers/quickSec/src/ipsec/lib/sshisakmp/tests/Attic/cert_policy.c,v $
 *        $Author: bruce.chang $
 *
 *        Creation          : 10:04 Sep 16 1997 kivinen
 *        Last Modification : 11:54 Feb  3 2005 kivinen
 *        Last check in     : $Date: 2012/09/28 $
 *        Revision number   : $Revision: #1 $
 *        State             : $State: Exp $
 *        Version           : 1.894
 *        
 *
 *        Description       : Isakmp policy manager functions
 *
 *        $Log: cert_policy.c,v $
 *        Revision 1.1.2.1  2011/01/31 03:29:48  treychen_hc
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
#include "sshdebug.h"
#include "sshtimeouts.h"
#include "sshtcp.h"
#include "test_policy.h"

#ifdef SSHDIST_IKE_CERT_AUTH
#include "sshasn1.h"
#include "x509.h"
#include "cmi.h"
#endif /* SSHDIST_IKE_CERT_AUTH */

#define SSH_DEBUG_MODULE "SshIkePolicy"

#ifdef SSHDIST_IKE_CERT_AUTH

/*
 * Context structure for the find public key function
 */
typedef struct SshPolicyFindPublicKeyContextRec {
  SshIkePMPhaseI pm_info;
  SshPolicyKeyType key_type_in;
  const unsigned char *hash_alg_in;
  SshPolicyFindPublicKeyCB callback_in;
  void *callback_context_in;
} *SshPolicyFindPublicKeyContext;

/*                                                              shade{0.9}
 * Start cmi search.                                            shade{1.0}
 */
void ssh_policy_find_public_key_search(SshPolicyFindPublicKeyContext context,
                                       SshCertDBKey *keys,
                                       SshCMSearchResult callback)
{
  SshCMSearchConstraints search_constraints;
  SshBerTimeStruct start_time, end_time;
  SshIkePMPhaseI pm_info = context->pm_info;
  SshIkePMContext pm = pm_info->pm;
  SshCMContext cm = ((SshIkePMCertCache) pm->certificate_cache)->cert_cache;
  SshCMStatus ret;

  search_constraints = ssh_cm_search_allocate();
  if (search_constraints == NULL)
    {
      SSH_DEBUG(3, ("Out of memory when allocating search_constraints"));
      (*callback)(context, NULL, NULL);
      return;
    }


  ssh_ber_time_set_from_unix_time(&start_time, pm_info->sa_start_time);
  ssh_ber_time_set_from_unix_time(&end_time, pm_info->sa_expire_time);

  ssh_cm_search_set_time(search_constraints, &start_time, &end_time);

  switch (context->key_type_in)
    {
    case SSH_IKE_POLICY_KEY_TYPE_RSA_SIG:
      ssh_cm_search_set_key_type(search_constraints, SSH_X509_PKALG_RSA);
      ssh_cm_search_set_key_usage(search_constraints,
                                  SSH_X509_UF_DIGITAL_SIGNATURE);
      break;
    case SSH_IKE_POLICY_KEY_TYPE_RSA_ENC:
      ssh_cm_search_set_key_type(search_constraints, SSH_X509_PKALG_RSA);
      ssh_cm_search_set_key_usage(search_constraints,
                                  SSH_X509_UF_KEY_ENCIPHERMENT);
      break;
    case SSH_IKE_POLICY_KEY_TYPE_DSS_SIG:
      ssh_cm_search_set_key_type(search_constraints, SSH_X509_PKALG_DSA);
      ssh_cm_search_set_key_usage(search_constraints,
                                  SSH_X509_UF_DIGITAL_SIGNATURE);
      break;
#ifdef SSHDIST_CRYPT_ECP
    case SSH_IKE_POLICY_KEY_TYPE_ECP_DSA_SIG:
      ssh_cm_search_set_key_type(search_constraints, SSH_X509_PKALG_ECDSA);
      ssh_cm_search_set_key_usage(search_constraints,
                                  SSH_X509_UF_DIGITAL_SIGNATURE);
      break;
#endif /* SSHDIST_CRYPT_ECP */
    }

  ssh_cm_search_set_keys(search_constraints, keys);

  ssh_cm_search_set_group_mode(search_constraints);

  ret = ssh_cm_find(cm, search_constraints, callback, context);

  if (ret != SSH_CM_STATUS_OK && ret != SSH_CM_STATUS_SEARCHING)
    {
      SSH_DEBUG(3,
                ("Initializing certificate search failed directly, error = %d",
                 ret));
      (*callback)(context, NULL, NULL);
    }
}

/*                                                              shade{0.9}
 * Found public key for remote host.                            shade{1.0}
 */
void ssh_policy_find_public_key_found(SshPolicyFindPublicKeyContext context,
                                      SshCMCertificate certificate,
                                      Boolean multiple)
{
  SshX509Certificate x509_cert;
  SshPublicKey public_key_out;
  unsigned char *hash_out = NULL;
  size_t hash_out_len = 0;
  unsigned char *exported = NULL;
  size_t exported_len = 0;

  if (ssh_cm_cert_get_x509(certificate, &x509_cert) != SSH_CM_STATUS_OK)
    {
      SSH_DEBUG(3, ("Getting x509 certificate from cm certificate failed"));
      (*context->callback_in)(NULL, NULL, 0, context->callback_context_in);
      ssh_xfree(context);
      return;
    }

  if (ssh_cm_cert_get_ber(certificate, &exported, &exported_len) !=
      SSH_CM_STATUS_OK)
    {
      SSH_DEBUG(3, ("Getting ber from cm certificate failed"));
      (*context->callback_in)(NULL, NULL, 0, context->callback_context_in);
      ssh_x509_cert_free(x509_cert);
      ssh_xfree(context);
      return;
    }

  if (!ssh_x509_cert_get_public_key(x509_cert, &public_key_out))
    {
      SSH_DEBUG(3, ("Getting public key from x509 certificate failed"));
      (*context->callback_in)(NULL, NULL, 0, context->callback_context_in);
      ssh_x509_cert_free(x509_cert);
      ssh_xfree(context);
      return;
    }

  ssh_x509_cert_free(x509_cert);

  if (multiple && context->hash_alg_in)
    {
      /* Block cipher */
      SshHash hash_ctx;
      SshCryptoStatus cret;

      cret = ssh_hash_allocate(context->hash_alg_in, &hash_ctx);
      if (cret != SSH_CRYPTO_OK)
        {
          SSH_DEBUG(3, ("ssh_policy_find_public_key_found: "
                        "ssh_hash_allocate failed: %.200s",
                        ssh_crypto_status_message(cret)));
          ssh_public_key_free(public_key_out);
          (*context->callback_in)(NULL, NULL, 0, context->callback_context_in);
          ssh_xfree(context);
          return;
        }

      hash_out_len = ssh_hash_digest_length(ssh_hash_name(hash_ctx));
      hash_out = ssh_xmalloc(hash_out_len);
      ssh_hash_reset(hash_ctx);
      ssh_hash_update(hash_ctx, exported, exported_len);
      ssh_hash_final(hash_ctx, hash_out);
      ssh_hash_free(hash_ctx);
    }

  if (context->pm_info->auth_data)
    ssh_xfree(context->pm_info->auth_data);
  context->pm_info->auth_data = ssh_xmemdup(exported, exported_len);
  context->pm_info->auth_data_len = exported_len;
  (*context->callback_in)(public_key_out, hash_out, hash_out_len,
                          context->callback_context_in);
  ssh_xfree(context);
  return;
}

/*                                                              shade{0.9}
 * Find public key for remote host. Secondary
 * selector find done, check result.                            shade{1.0}
 */
void ssh_policy_find_public_key_reply_2(void *ctx,
                                        SshCMSearchInfo info,
                                        SshCMCertList list)
{
  SshPolicyFindPublicKeyContext context = ctx;
  SshIkePMPhaseI pm_info = context->pm_info;
  SshIkePMContext pm = pm_info->pm;
  SshCMContext cm = ((SshIkePMCertCache) pm->certificate_cache)->cert_cache;

  if (info && info->status == SSH_CM_STATUS_OK &&
      !ssh_cm_cert_list_empty(list))
    {
      ssh_policy_find_public_key_found(ctx, ssh_cm_cert_list_last(list),
                                       ssh_cm_cert_list_first(list) !=
                                       ssh_cm_cert_list_last(list));
      ssh_cm_cert_list_free(cm, list);
      return;
    }
  /* Return error */
  (*context->callback_in)(NULL, NULL, 0, context->callback_context_in);
  ssh_xfree(context);
}

/*                                                              shade{0.9}
 * Find public key for remote host. Primary
 * selector find done, check result.                            shade{1.0}
 */
void ssh_policy_find_public_key_reply_1(void *ctx,
                                        SshCMSearchInfo info,
                                        SshCMCertList list)
{
  SshPolicyFindPublicKeyContext context = ctx;
  SshIkePMPhaseI pm_info = context->pm_info;
  SshIkePMContext pm = pm_info->pm;
  SshCMContext cm = ((SshIkePMCertCache) pm->certificate_cache)->cert_cache;
  unsigned char buf[16];
  size_t len;

  if (info && info->status == SSH_CM_STATUS_OK &&
      !ssh_cm_cert_list_empty(list))
    {
      ssh_policy_find_public_key_found(ctx, ssh_cm_cert_list_last(list),
                                       ssh_cm_cert_list_first(list) !=
                                       ssh_cm_cert_list_last(list));
      ssh_cm_cert_list_free(cm, list);
      return;
    }

  len = sizeof(buf);
  if (!ssh_inet_strtobin(pm_info->remote_ip, buf, &len))
    {
      ssh_policy_find_public_key_reply_2(context, NULL, NULL);
    }
  else
    {
      SshCertDBKey *keys;

      keys = NULL;
      ssh_cm_key_set_ip(&keys, buf, len);

      /* Start the search */
      ssh_policy_find_public_key_search(context, keys,
                                        ssh_policy_find_public_key_reply_2);
    }
}

/*                                                              shade{0.9}
 * Find public key for remote host. The primary
 * selector is the id fields if they are given, and
 * if they are NULL then the ip and port numbers
 * are used as selector.
 *
 * If hash_alg_in is not NULL and there is
 * multiple keys for the host, then return hash of
 * the selected key in the hash_out buffer. The
 * length of hash is hash_len_out. The isakmp
 * library will free the buffer, after it is no
 * longer needed. If the isakmp/oakley should't
 * send hash of key to remote end then, then
 * hash_len_out is set to zero, and hash_out to
 * NULL.
 *
 * Call callback_in when the data is available (it
 * can also be called immediately).                             shade{1.0}
 */
void ssh_policy_find_public_key(SshIkePMPhaseI pm_info,
                                SshPolicyKeyType key_type_in,
                                const unsigned char *hash_alg_in,
                                SshPolicyFindPublicKeyCB callback_in,
                                void *callback_context_in)
{
  SshCertDBKey *keys;
  SshPolicyFindPublicKeyContext context;

  SSH_DEBUG(5, ("Start, Key type = %d, local = %s:%s, remote = %s:%s",
                key_type_in, pm_info->local_ip, pm_info->local_port,
                pm_info->remote_ip, pm_info->remote_port));

  keys = NULL;
  if (pm_info->remote_id)
    {
      switch (pm_info->remote_id->id_type)
        {
        case IPSEC_ID_IPV4_ADDR:
          ssh_cm_key_set_ip(&keys, pm_info->remote_id->
                            identification.ipv4_addr,
                            sizeof(pm_info->remote_id->
                                   identification.ipv4_addr));
          break;
        case IPSEC_ID_FQDN:
          ssh_cm_key_set_dns(&keys, (char *) pm_info->remote_id->
                             identification.fqdn,
                             pm_info->remote_id->identification_len);
          break;
        case IPSEC_ID_USER_FQDN:
          ssh_cm_key_set_email(&keys, (char *) pm_info->remote_id->
                               identification.fqdn,
                               pm_info->remote_id->identification_len);
          break;
        case IPSEC_ID_IPV6_ADDR:
          ssh_cm_key_set_ip(&keys, pm_info->remote_id->
                            identification.ipv6_addr,
                            sizeof(pm_info->remote_id->
                                   identification.ipv6_addr));
          break;
        case IPSEC_ID_IPV4_ADDR_SUBNET:
        case IPSEC_ID_IPV6_ADDR_SUBNET:
        case IPSEC_ID_IPV4_ADDR_RANGE:
        case IPSEC_ID_IPV6_ADDR_RANGE:
          break;
        case IPSEC_ID_DER_ASN1_DN:
          ssh_cm_key_set_dn(&keys, pm_info->remote_id->
                            identification.asn1_data,
                            pm_info->remote_id->
                            identification_len);
          break;
        case IPSEC_ID_DER_ASN1_GN:
          break;
        case IPSEC_ID_KEY_ID:
          break;
        default:
          break;
        }
    }

  context = ssh_xmalloc(sizeof(*context));
  context->pm_info = pm_info;
  context->key_type_in = key_type_in;
  context->hash_alg_in = ssh_csstr(hash_alg_in);
  context->callback_in = callback_in;
  context->callback_context_in = callback_context_in;

  if (keys == NULL)
    {
      /* Directly call the first reply function to start trying to the other
         keys */
      ssh_policy_find_public_key_reply_1(context, NULL, NULL);
    }
  else
    {
      /* Start the search */
      ssh_policy_find_public_key_search(context, keys,
                                        ssh_policy_find_public_key_reply_1);
    }
  return;
}


/*                                                              shade{0.9}
 * Process certificate data. Add the certificate
 * to certificate tables, and if we can trust new
 * keys, add them to public key database. If we do
 * not trust the keys then just ignore the
 * certificate. The certificate encoding can be
 * any of supported certificate types found in
 * isakmp.h.                                                    shade{1.0}
 */
void ssh_policy_new_certificate(SshIkePMPhaseI pm_info,
                                SshIkeCertificateEncodingType cert_encoding,
                                unsigned char *certificate_data,
                                size_t certificate_data_len)
{
  SshIkePMContext pm = pm_info->pm;
  SshCMContext cm = ((SshIkePMCertCache) pm->certificate_cache)->cert_cache;

  SSH_DEBUG(5, ("Start, encoding = %d, data[0..%d] = %08x %08x",
                cert_encoding, certificate_data_len,
                SSH_GET_32BIT(certificate_data),
                SSH_GET_32BIT(certificate_data + 4)));

  if (pm_info->number_of_allocated_certificates == 0)
    {
      pm_info->number_of_allocated_certificates = 5;
      pm_info->certificates =
        ssh_xcalloc(pm_info->number_of_allocated_certificates,
                    sizeof(const char *));
      pm_info->certificate_lens =
        ssh_xcalloc(pm_info->number_of_allocated_certificates,
                    sizeof(size_t));
      pm_info->certificate_encodings =
        ssh_xcalloc(pm_info->number_of_allocated_certificates,
                    sizeof(SshIkeCertificateEncodingType));
    }
  else if (pm_info->number_of_allocated_certificates ==
           pm_info->number_of_certificates)
    {
      int i, new_size;

      new_size = pm_info->number_of_allocated_certificates + 5;

      pm_info->certificates =
        ssh_xrealloc(pm_info->certificates, new_size * sizeof(const char *));
      pm_info->certificate_lens =
        ssh_xrealloc(pm_info->certificate_lens, new_size * sizeof(size_t));
      pm_info->certificate_encodings =
        ssh_xrealloc(pm_info->certificate_encodings,
                     new_size * sizeof(SshIkeCertificateEncodingType));
      for (i = pm_info->number_of_allocated_certificates; i < new_size; i++)
        {
          pm_info->certificates[i] = NULL;
          pm_info->certificate_lens[i] = 0;
          pm_info->certificate_encodings[i] = 0;
        }
      pm_info->number_of_allocated_certificates = new_size;
    }
  pm_info->certificates[pm_info->number_of_certificates] =
    ssh_xmemdup(certificate_data, certificate_data_len);
  pm_info->certificate_lens[pm_info->number_of_certificates] =
    certificate_data_len;
  pm_info->certificate_encodings[pm_info->number_of_certificates] =
    cert_encoding;
  pm_info->number_of_certificates++;

  switch (cert_encoding)
    {
      /* At the moment only X.509 certificates are supported. */
    case SSH_IKE_CERTIFICATE_ENCODING_NONE: /* None */
    case SSH_IKE_CERTIFICATE_ENCODING_PGP: /* PGP */
    case SSH_IKE_CERTIFICATE_ENCODING_DNS: /* DNS signed key */
    case SSH_IKE_CERTIFICATE_ENCODING_KERBEROS: /* Kerberos tokens */
    default:
      SSH_DEBUG(3, ("Unsupported certificate encoding = %d", cert_encoding));
      return;
    case SSH_IKE_CERTIFICATE_ENCODING_PKCS7: /* PKCS #7 wrapped X.509  */
      {
        SshCMStatus ret;

        ret = ssh_cm_add_pkcs7_ber(cm, certificate_data,
                                   certificate_data_len);

        if (ret == SSH_CM_STATUS_OK)
          return;
        if (ret != SSH_CM_STATUS_ALREADY_EXISTS)
          SSH_DEBUG(3, ("ssh_cm_add failed"));
        break;
      }
    case SSH_IKE_CERTIFICATE_ENCODING_CRL: /* Certificate revocation list */
    case SSH_IKE_CERTIFICATE_ENCODING_ARL: /* Authority revocation list */
      {
        SshCMCrl crl;
        SshCMStatus ret;

        crl = ssh_cm_crl_allocate(cm);

        if (crl == NULL)
          {
            SSH_DEBUG(3, ("Ssh_cm_crl_allocate failed"));
            return;
          }
        if (ssh_cm_crl_set_ber(crl, certificate_data,
                               certificate_data_len) != SSH_CM_STATUS_OK)
          {
            SSH_DEBUG(3, ("Ssh_cm_crl_set_ber failed"));
            ssh_cm_crl_free(crl);
            return;
          }

        ret = ssh_cm_add_crl(crl);
        if (ret == SSH_CM_STATUS_OK)
          return;
        if (ret != SSH_CM_STATUS_ALREADY_EXISTS)
        SSH_DEBUG(3, ("ssh_cm_add_crl failed"));
        ssh_cm_crl_free(crl);
        break;
      }
    case SSH_IKE_CERTIFICATE_ENCODING_X509_SIG: /* X.509 - signature */
    case SSH_IKE_CERTIFICATE_ENCODING_X509_KE:  /* X.509 - key exchange */
      {
        SshCMCertificate cert;
        SshCMStatus ret;

        cert = ssh_cm_cert_allocate(cm);
        if (cert == NULL)
          {
            SSH_DEBUG(3, ("ssh_cm_cert_allocate failed"));
            return;
          }
        if (ssh_cm_cert_set_ber(cert, certificate_data,
                                certificate_data_len) != SSH_CM_STATUS_OK)
          {
            SSH_DEBUG(3, ("Ssh_cm_cert_set_ber failed"));
            ssh_cm_cert_free(cert);
            return;
          }

        if (((SshIkePMCertCache) pm->certificate_cache)->
            trust_all_certificates)
          {
            if (ssh_cm_cert_force_trusted(cert) != SSH_CM_STATUS_OK)
              {
                SSH_DEBUG(3, ("Ssh_cm_cert_set_trusted failed"));
                ssh_cm_cert_free(cert);
                return;
              }
          }
        ret = ssh_cm_add(cert);

        if (ret == SSH_CM_STATUS_OK)
          return;
        if (ret != SSH_CM_STATUS_ALREADY_EXISTS)
          SSH_DEBUG(3, ("ssh_cm_add failed: %d", ret));

        ssh_cm_cert_free(cert);
        break;
      }
    }
  return;
}

/*
 * Context structure for the find public key function
 */
typedef struct SshPolicyRequestCertificatesContextRec {
  SshIkePMPhaseI pm_info;
  int number_of_cas;
  SshIkeCertificateEncodingType *ca_encodings;
  unsigned char **certificate_authorities;
  size_t *certificate_authority_lens;
  SshPolicyRequestCertificatesCB callback_in;
  void *callback_context_in;

  int current_cas;
  int *number_of_certificates;
  SshIkeCertificateEncodingType **tmp_cert_encodings;
  unsigned char ***tmp_certs;
  size_t **tmp_certs_len;
} *SshPolicyRequestCertificatesContext;

/*                                                              shade{0.9}
 * Get one chain of certificates with given encoding
 * and to given certificate authority.                          shade{1.0}
 */
void ssh_policy_request_certificates_one(void *ctx,
                                         SshCMSearchInfo info,
                                         SshCMCertList list)
{
  SshPolicyRequestCertificatesContext context = ctx;
  SshCMSearchConstraints search_constraints;
  SshCMSearchConstraints ca_search_constraints;
  SshBerTimeStruct start_time, end_time;
  SshIkePMPhaseI pm_info = context->pm_info;
  SshIkePMContext pm = pm_info->pm;
  SshCMContext cm = ((SshIkePMCertCache) pm->certificate_cache)->cert_cache;
  SshCertDBKey *keys;
  SshCMStatus ret;





  /* Must be valid for next 2 minutes */
  ssh_ber_time_set_from_unix_time(&start_time, pm_info->sa_start_time);
  ssh_ber_time_set_from_unix_time(&end_time, pm_info->sa_start_time + 120);




  if (context->current_cas != -1)
    {
      if (info == NULL || info->status != SSH_CM_STATUS_OK ||
          ssh_cm_cert_list_empty(list))
        {
          /* Not found */
          SSH_DEBUG(3, ("Could not retrieve certificate list, ca=%d.",
                        context->current_cas));
          context->number_of_certificates[context->current_cas] = 0;
          context->tmp_cert_encodings[context->current_cas] = NULL;
          context->tmp_certs[context->current_cas] = NULL;
          context->tmp_certs_len[context->current_cas] = NULL;

          if (list)
            ssh_cm_cert_list_free(cm, list);
        }
      else
        {
          int allocated, cnt;
          SshCMCertificate cert;
          SshCMCrlList crl_list;
          SshCMSearchConstraints crl_search_constraints;
          Boolean first;
          unsigned char *ber;
          size_t ber_length;

          allocated = 10;
          cnt = 0;
          context->tmp_cert_encodings[context->current_cas] =
            ssh_xmalloc(allocated * sizeof(SshIkeCertificateEncodingType));
          context->tmp_certs[context->current_cas] =
            ssh_xmalloc(allocated * sizeof(unsigned char *));
          context->tmp_certs_len[context->current_cas] =
            ssh_xmalloc(allocated * sizeof(size_t));
          first = TRUE;

          cert = ssh_cm_cert_list_first(list);
          do {
            if (first)
              {
                first = FALSE;
              }
            else
              {
                if (ssh_cm_cert_get_ber(cert, &ber, &ber_length) !=
                    SSH_CM_STATUS_OK)
                  {
                    SSH_DEBUG(3, (" ca %d, cert %d failed",
                                  context->current_cas, cnt));
                  }
                else
                  {
                    if (cnt == allocated)
                      {
                        allocated += 10;
                        context->tmp_cert_encodings[context->current_cas] =
                          ssh_xrealloc(context->tmp_cert_encodings[context->
                                                                  current_cas],
                                       allocated *
                                       sizeof(SshIkeCertificateEncodingType));
                        context->tmp_certs[context->current_cas] =
                          ssh_xrealloc(context->tmp_certs[context->
                                                        current_cas],
                                      allocated * sizeof(unsigned char *));
                        context->tmp_certs_len[context->current_cas] =
                          ssh_xrealloc(context->tmp_certs_len[context->
                                                            current_cas],
                                      allocated * sizeof(size_t));
                      }
                    context->tmp_cert_encodings[context->current_cas][cnt] =
                      SSH_IKE_CERTIFICATE_ENCODING_X509_SIG;
                    context->tmp_certs[context->current_cas][cnt] =
                      ssh_xmemdup(ber, ber_length);
                    context->tmp_certs_len[context->current_cas][cnt] =
                      ber_length;
                    SSH_DEBUG(5, (" ca %d, cert %d", context->current_cas,
                                  cnt));
                    cnt++;
                  }
              }

            crl_list = NULL;

            crl_search_constraints = ssh_cm_search_allocate();
            if (crl_search_constraints == NULL)
              {
                SSH_DEBUG(3, ("Out of memory when allocating "
                              "search_constraints"));

                (*context->callback_in)(context->number_of_certificates,
                                        context->tmp_cert_encodings,
                                        context->tmp_certs,
                                        context->tmp_certs_len,
                                        context->callback_context_in);
                ssh_xfree(context);
                return;
              }
            ssh_cm_search_set_time(crl_search_constraints, &start_time,
                                   &end_time);
            keys = NULL;
            ssh_cm_key_set_from_cert(&keys,
                                     SSH_CM_KEY_CLASS_SUBJECT,
                                     ssh_cm_cert_list_current(list));

            ssh_cm_search_set_keys(crl_search_constraints, keys);
            ret = ssh_cm_find_local_crl(cm, crl_search_constraints,
                                        &crl_list);

            if (ret == SSH_CM_STATUS_OK && !ssh_cm_crl_list_empty(crl_list))
              {
                SshCMCrl crl;

                crl = ssh_cm_crl_list_first(crl_list);
                do {
                  if (ssh_cm_crl_get_ber(crl, &ber, &ber_length) !=
                      SSH_CM_STATUS_OK)
                    {
                      SSH_DEBUG(3, (" ca %d, crl %d failed",
                                    context->current_cas, cnt));
                    }
                  else
                    {
                      if (cnt == allocated)
                        {
                          allocated += 10;
                          context->tmp_cert_encodings[context->current_cas] =
                            ssh_xrealloc(context->
                                         tmp_cert_encodings[context->
                                                           current_cas],
                                         allocated *
                                         sizeof(SshIkeCertificateEncodingType)
                                         );
                          context->tmp_certs[context->current_cas] =
                            ssh_xrealloc(context->tmp_certs[context->
                                                          current_cas],
                                        allocated * sizeof(unsigned char *));
                          context->tmp_certs_len[context->current_cas] =
                            ssh_xrealloc(context->tmp_certs_len[context->
                                                              current_cas],
                                        allocated * sizeof(size_t));
                        }
                      context->tmp_cert_encodings[context->current_cas][cnt] =
                        SSH_IKE_CERTIFICATE_ENCODING_CRL;
                      context->tmp_certs[context->current_cas][cnt] =
                        ssh_xmemdup(ber, ber_length);
                      context->tmp_certs_len[context->current_cas][cnt] =
                        ber_length;
                      SSH_DEBUG(5, (" ca %d, crl %d", context->current_cas,
                                    cnt));
                      cnt++;
                    }
                } while ((crl = ssh_cm_crl_list_next(crl_list)) != NULL);
              }
            ssh_cm_crl_list_free(cm, crl_list);
          } while ((cert = ssh_cm_cert_list_next(list)) != NULL);









































          SSH_DEBUG(5, (" returning %d certificates and crls", cnt));
          context->number_of_certificates[context->current_cas] = cnt;

          ssh_cm_cert_list_free(cm, list);
        }
    }

  context->current_cas++;

  /* Ignore unsupported encodings */
  while (context->current_cas != context->number_of_cas &&
         (context->ca_encodings[context->current_cas] !=
          SSH_IKE_CERTIFICATE_ENCODING_X509_SIG &&
          context->ca_encodings[context->current_cas] !=
          SSH_IKE_CERTIFICATE_ENCODING_X509_KE))
    {
      SSH_DEBUG(7, ("Unsupported encoding for %d", context->current_cas));
      context->number_of_certificates[context->current_cas] = 0;
      context->tmp_cert_encodings[context->current_cas] = NULL;
      context->tmp_certs[context->current_cas] = NULL;
      context->tmp_certs_len[context->current_cas] = NULL;
      context->current_cas++;
    }

  if (context->current_cas == context->number_of_cas)
    {
      (*context->callback_in)(context->number_of_certificates,
                              context->tmp_cert_encodings, context->tmp_certs,
                              context->tmp_certs_len,
                              context->callback_context_in);
      ssh_xfree(context);
      return;
    }

  search_constraints = ssh_cm_search_allocate();
  if (search_constraints == NULL)
    {
      SSH_DEBUG(3, ("Out of memory when allocating search_constraints"));
      (*context->callback_in)(context->number_of_certificates,
                              context->tmp_cert_encodings,
                              context->tmp_certs,
                              context->tmp_certs_len,
                              context->callback_context_in);
      ssh_xfree(context);
      return;
    }

  ssh_cm_search_set_time(search_constraints, &start_time, &end_time);

  switch (pm_info->auth_method)
    {
    case SSH_IKE_VALUES_AUTH_METH_DSS_SIGNATURES:
      ssh_cm_search_set_key_type(search_constraints, SSH_X509_PKALG_DSA);
      ssh_cm_search_set_key_usage(search_constraints,
                                  SSH_X509_UF_DIGITAL_SIGNATURE);
      break;
    case SSH_IKE_VALUES_AUTH_METH_RSA_SIGNATURES:
      ssh_cm_search_set_key_type(search_constraints, SSH_X509_PKALG_RSA);
      ssh_cm_search_set_key_usage(search_constraints,
                                  SSH_X509_UF_DIGITAL_SIGNATURE);
      break;
    case SSH_IKE_VALUES_AUTH_METH_RSA_ENCRYPTION:
    case SSH_IKE_VALUES_AUTH_METH_RSA_ENCRYPTION_REVISED:
      ssh_cm_search_set_key_type(search_constraints, SSH_X509_PKALG_RSA);
      ssh_cm_search_set_key_usage(search_constraints,
                                  SSH_X509_UF_KEY_ENCIPHERMENT);
      break;
#ifdef SSHDIST_CRYPT_ECP
    case SSH_IKE_VALUES_AUTH_METH_ECP_DSA_256:
    case SSH_IKE_VALUES_AUTH_METH_ECP_DSA_384:
    case SSH_IKE_VALUES_AUTH_METH_ECP_DSA_521:
      ssh_cm_search_set_key_type(search_constraints, SSH_X509_PKALG_ECDSA);
      ssh_cm_search_set_key_usage(search_constraints,
                                  SSH_X509_UF_DIGITAL_SIGNATURE);
      break;
#endif /* SSHDIST_CRYPT_ECP */
    default:
      ssh_fatal("Internal error, auth_method not rsa or dss");
      break;
    }

  keys = NULL;
  ssh_cm_key_set_public_key(&keys, pm_info->public_key);
  ssh_cm_search_set_keys(search_constraints, keys);

  ca_search_constraints = ssh_cm_search_allocate();
  if (ca_search_constraints == NULL)
    {
      SSH_DEBUG(3, ("Out of memory when allocating ca_search_constraints"));
      (*context->callback_in)(context->number_of_certificates,
                              context->tmp_cert_encodings,
                              context->tmp_certs,
                              context->tmp_certs_len,
                              context->callback_context_in);
      ssh_xfree(context);
      return;
    }
  ssh_cm_search_set_time(ca_search_constraints, &start_time, &end_time);
  keys = NULL;

  ssh_cm_key_set_dn(&keys,
                    context->certificate_authorities[context->current_cas],
                    context->certificate_authority_lens[context->current_cas]);

  SSH_DEBUG_HEXDUMP(7,
            ("Looking for CA len=%d",
             context->certificate_authority_lens[context->current_cas]),
                    context->certificate_authorities[context->current_cas],
                    context->certificate_authority_lens[context->current_cas]);

  ssh_cm_search_set_keys(ca_search_constraints, keys);

  ret = ssh_cm_find_path(cm, ca_search_constraints, search_constraints,
                         ssh_policy_request_certificates_one, context);
  if (ret != SSH_CM_STATUS_OK && ret != SSH_CM_STATUS_SEARCHING)
    {
      SSH_DEBUG(3, ("Initializing path search failed directly, error = %d",
                    ret));
      ssh_policy_request_certificates_one(ctx, NULL, NULL);
    }
}

/*                                                              shade{0.9}
 * Get chain of certificates with given encoding
 * and to given certificate authority. Call
 * callback_in when the data is available (it can
 * also be called immediately).                                 shade{1.0}
 */
void ssh_policy_request_certificates(SshIkePMPhaseI pm_info,
                                     int number_of_cas,
                                     SshIkeCertificateEncodingType
                                     *ca_encodings,
                                     unsigned char **certificate_authorities,
                                     size_t *certificate_authority_lens,
                                     SshPolicyRequestCertificatesCB
                                     callback_in,
                                     void *callback_context_in)
{
  SshPolicyRequestCertificatesContext context;

  SSH_DEBUG(5, ("Start"));

  switch (pm_info->auth_method)
    {
    case SSH_IKE_VALUES_AUTH_METH_DSS_SIGNATURES:
    case SSH_IKE_VALUES_AUTH_METH_RSA_SIGNATURES:
    case SSH_IKE_VALUES_AUTH_METH_RSA_ENCRYPTION:
    case SSH_IKE_VALUES_AUTH_METH_RSA_ENCRYPTION_REVISED:
      break;
    default:
      (*callback_in)(0, NULL, NULL, NULL, callback_context_in);
      return;
    }

  context = ssh_xmalloc(sizeof(*context));

  context->pm_info = pm_info;
  context->number_of_cas = number_of_cas;
  context->ca_encodings = ca_encodings;
  context->certificate_authorities = certificate_authorities;
  context->certificate_authority_lens = certificate_authority_lens;
  context->callback_in = callback_in;
  context->callback_context_in = callback_context_in;

  context->current_cas = -1;
  context->number_of_certificates =
    ssh_xcalloc(sizeof(*context->number_of_certificates), number_of_cas);
  context->tmp_cert_encodings =
    ssh_xcalloc(sizeof(*context->tmp_cert_encodings), number_of_cas);
  context->tmp_certs = ssh_xcalloc(sizeof(*context->tmp_certs), number_of_cas);
  context->tmp_certs_len =
    ssh_xcalloc(sizeof(*context->tmp_certs_len), number_of_cas);

  SSH_DEBUG(5, ("Requesting certs for %d CA's", context->number_of_cas));
  ssh_policy_request_certificates_one(context, NULL, NULL);
}

/*                                                              shade{0.9}
 * Get certificate authority list to be sent to
 * other end. Call callback_in when the data is
 * available (it can also be called immediately).               shade{1.0}
 */
void ssh_policy_get_certificate_authorities(SshIkePMPhaseI pm_info,
                                            SshPolicyGetCAsCB callback_in,
                                            void *callback_context_in)
{
  SshIkePMContext pm = pm_info->pm;
  SshIkePMCertCache certificate_cache =
    (SshIkePMCertCache) pm->certificate_cache;
  SshIkeCertificateEncodingType *ca_encodings;
  unsigned char **ca_names;
  size_t *ca_name_lens;
  int cnt, i;

  if (certificate_cache->number_of_master_cas > 0)
    {
      cnt = certificate_cache->number_of_master_cas;
      ca_encodings = ssh_xcalloc(cnt, sizeof(SshIkeCertificateEncodingType));
      ca_names = ssh_xcalloc(cnt, sizeof(unsigned char *));
      ca_name_lens = ssh_xcalloc(cnt, sizeof(size_t));
      for (i = 0; i < cnt; i++)
        {
          ca_encodings[i] = SSH_IKE_CERTIFICATE_ENCODING_X509_SIG;
          ca_names[i] = ssh_xmemdup(certificate_cache->master_cas[i],
                                    certificate_cache->master_ca_lens[i]);
          ca_name_lens[i] = certificate_cache->master_ca_lens[i];
        }
    }
  else
    {
      cnt = 0;
      ca_encodings = NULL;
      ca_names = NULL;
      ca_name_lens = NULL;
    }
  (*callback_in)(cnt, ca_encodings, ca_names, ca_name_lens,
                 callback_context_in);
  return;
}

#endif /* SSHDIST_IKE_CERT_AUTH */
