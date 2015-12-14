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
 *        $Source: /home/user/socsw/cvs/cvsrepos/tclinux_phoenix/modules/eip93_drivers/quickSec/src/ipsec/lib/sshisakmp/tests/Attic/test_policy.c,v $
 *        $Author: bruce.chang $
 *
 *        Creation          : 10:04 Sep 16 1997 kivinen
 *        Last Modification : 11:54 Feb  3 2005 kivinen
 *        Last check in     : $Date: 2012/09/28 $
 *        Revision number   : $Revision: #1 $
 *        State             : $State: Exp $
 *        Version           : 1.808
 *        
 *
 *        Description       : Isakmp policy manager functions, this
 *                            implements the simple policy manager for the
 *                            isakmp-test.ssh.fi web server.
 *
 *
 *        $Log: test_policy.c,v $
 *        Revision 1.1.2.1  2011/01/31 03:29:51  treychen_hc
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
 *        $EndLog$
 */


#include "sshincludes.h"
#include "isakmp.h"
#include "sshdebug.h"
#include "sshtcp.h"
#include "sshgetput.h"

#ifdef SSHDIST_IKE_CERT_AUTH
#include "sshasn1.h"
#include "x509.h"
#endif /* SSHDIST_IKE_CERT_AUTH */

#include "test_policy.h"
#ifdef SSHDIST_ISAKMP_CFG_MODE
#include "xauth_demo.h"
#endif /* SSHDIST_ISAKMP_CFG_MODE */

#define SSH_DEBUG_MODULE "SshIkePolicy"

int phase_i = 0;
int phase_qm = 0;
int phase_ii = 0;

/*                                                              shade{0.9}
 * Get initial config data for the new isakmp
 * connection. This will be called immediately
 * when a new phase I negotiation is received
 * before any processing is done for the payload
 * itself. The compatibility flags can only be set
 * at this point. The pm_info only have following
 * fields: cookies, local_ip, local_port,
 * remote_ip, remote_port, major_version,
 * minor_version, and exchange_type.
 *
 * Call callback_in when the data is available (it
 * can also be called immediately).                             shade{1.0}
 */
void ssh_policy_new_connection(SshIkePMPhaseI pm_info,
                               SshPolicyNewConnectionCB callback_in,
                               void *callback_context_in)
{
  SshIkePMContext pm = pm_info->pm;
  UpperPolicyManagerContext upper_context =
    (UpperPolicyManagerContext) pm->upper_context;

  SSH_DEBUG(5, ("Start"));
  /* We allow the connection without any flags, and use default retry limit and
     timer settings. */
  if (upper_context->test_context->flags & 0x8000)
    (*callback_in)(TRUE, SSH_IKE_IKE_FLAGS_MAIN_ALLOW_CLEAR_TEXT_CERTS,
                   -1, -1, -1, -1, -1, -1, -1, callback_context_in);
  else
    (*callback_in)(TRUE, SSH_IKE_FLAGS_USE_DEFAULTS,
                   -1, -1, -1, -1, -1, -1, -1, callback_context_in);
  phase_i++;
}


/*                                                              shade{0.9}
 * Get initial config data for the new phase II
 * negotiation. This will be called immediately
 * when a new phase II negotiation packet is
 * received before any processing is done for the
 * payload itself. The compatibility flags can
 * only be set at this point. The pm_info only
 * have following fields: phase_i, local_ip,
 * local_port, remote_ip, remote_port,
 * exchange_type, and message_id.
 *
 * Call callback_in when the data is available (it
 * can also be called immediately).                             shade{1.0}
 */
void ssh_policy_new_connection_phase_ii(SshIkePMPhaseII pm_info,
                                        SshPolicyNewConnectionCB
                                        callback_in,
                                        void *callback_context_in)
{
  SSH_DEBUG(5, ("Start"));
  /* We allow the connection without any flags, and use default retry limit and
     timer settings. */
  (*callback_in)(TRUE, SSH_IKE_FLAGS_USE_DEFAULTS,
                 -1, -1, -1, -1, -1, -1, -1, callback_context_in);
  phase_ii++;
}


/*                                                              shade{0.9}
 * Get initial config data for the new quick mode
 * negotiation. This will be called immediately
 * when a new quick mode negotiation packet is
 * received before any processing is done for the
 * payload itself. The compatibility flags can
 * only be set at this point. The pm_info only
 * have following fields: phase_i, local_ip,
 * local_port, remote_ip, remote_port,
 * exchange_type, and message_id.
 *
 * Call callback_in when the data is available (it
 * can also be called immediately).                             shade{1.0}
 */
void ssh_policy_new_connection_phase_qm(SshIkePMPhaseQm pm_info,
                                        SshPolicyNewConnectionCB
                                        callback_in,
                                        void *callback_context_in)
{
  SSH_DEBUG(5, ("Start"));
  /* We allow the connection without any flags, and use default retry limit and
     timer settings. */
  (*callback_in)(TRUE, SSH_IKE_FLAGS_USE_DEFAULTS,
                 -1, -1, -1, -1, -1, -1, -1, callback_context_in);
  phase_qm++;
}


#ifdef SSHDIST_IKE_CERT_AUTH
/*                                                              shade{0.9}
 * Find private key for local host. The primary
 * selector is the hash of the certificate of the
 * key if it is given. The secondary selector is
 * the id fields if they are given, and if they
 * are NULL then the ip and port numbers are used
 * as selector. Call callback_in when the data is
 * available (it can also be called immediately).               shade{1.0}
 */
void ssh_policy_find_private_key(SshIkePMPhaseI pm_info,
                                 SshPolicyKeyType key_type,
                                 const unsigned char *hash_alg_in,
                                 const unsigned char *hash_in,
                                 size_t hash_len_in,
                                 SshPolicyFindPrivateKeyCB callback_in,
                                 void *callback_context_in)
{
  SshIkePMContext pm = pm_info->pm;
  SshIkePMPrivateKeyCache private_key_cache =
    ((SshIkePMPrivateKeyCache) pm->private_key_cache);
  struct SshIkePayloadIDRec id;
  SshIkePMPrivateKeyItem item;
  SshPrivateKey private_key;
  SshADTContainer mapping = NULL;
  char id_buffer[256];
  SshADTHandle h;

  SSH_DEBUG(5, ("Start, Key type = %d, local = %s:%s, remote = %s:%s",
                key_type, pm_info->local_ip, pm_info->local_port,
                pm_info->remote_ip, pm_info->remote_port));

  switch (key_type)
    {
    case SSH_IKE_POLICY_KEY_TYPE_RSA_SIG:
    case SSH_IKE_POLICY_KEY_TYPE_RSA_ENC:
      mapping = private_key_cache->rsa_mapping;
      break;
    case SSH_IKE_POLICY_KEY_TYPE_DSS_SIG:
      mapping = private_key_cache->dss_mapping;
      break;

#ifdef SSHDIST_CRYPT_ECP
    case SSH_IKE_POLICY_KEY_TYPE_ECP_DSA_SIG:



      SSH_NOTREACHED;
#endif /* SSHDIST_CRYPT_ECP */
    }

  if (hash_in)
    {
      SshHash hash_ctx;
      unsigned char hash[SSH_MAX_HASH_DIGEST_LENGTH];
      SshCryptoStatus cret;

      cret = ssh_hash_allocate(ssh_csstr(hash_alg_in), &hash_ctx);

      if (cret != SSH_CRYPTO_OK)
        {
          SSH_DEBUG(3, ("ssh_policy_find_private_key: "
                        "ssh_hash_allocate failed: %.200s",
                        ssh_crypto_status_message(cret)));
          (*callback_in)(NULL, callback_context_in);
          return;
        }
      if (ssh_hash_digest_length(ssh_hash_name(hash_ctx)) != hash_len_in)
        {
          SSH_DEBUG(3, ("ssh_policy_find_private_key: "
                        "invalid hash buffer length : %d bytes, "
                        "should be %d bytes",
                        hash_len_in,
                        ssh_hash_digest_length(ssh_hash_name(hash_ctx))));
          (*callback_in)(NULL, callback_context_in);
          return;
        }

      for (h = ssh_adt_enumerate_start(mapping);
          h != SSH_ADT_INVALID;
          h = ssh_adt_enumerate_next(mapping, h))
        {
          item = ssh_adt_map_lookup(mapping, h);
          ssh_hash_reset(hash_ctx);
          ssh_hash_update(hash_ctx, item->certificate, item->certificate_len);
          ssh_hash_final(hash_ctx, hash);
          if (memcmp(hash, hash_in, hash_len_in) == 0)
            {
              ssh_hash_free(hash_ctx);
              ssh_private_key_copy(item->key, &private_key);
              pm_info->own_auth_data = ssh_xmemdup(item->certificate,
                                                   item->certificate_len);
              pm_info->own_auth_data_len = item->certificate_len;
              ssh_private_key_derive_public_key(private_key,
                                                &pm_info->public_key);
              (*callback_in)(private_key, callback_context_in);
              return;
            }
        }
      ssh_hash_free(hash_ctx);
      /* Not found using the hash, return error */
      (*callback_in)(NULL, callback_context_in);
      return;
    }

  /* No hash given, try to find using the id as a key. */
  if (pm_info->local_id)
    {
      if (ssh_ike_id_copy(pm_info->local_id, &id))
        {
          id.protocol_id = 0;
          id.port_number = 0;
          id.port_range_end = 0;

          ssh_ike_id_to_string(id_buffer, sizeof(id_buffer), &id);

          item = ssh_adt_strmap_get(mapping, id_buffer);
          if (item != NULL)
            {
              ssh_private_key_copy(item->key, &private_key);
              pm_info->own_auth_data = ssh_xmemdup(item->certificate,
                                                   item->certificate_len);
              pm_info->own_auth_data_len = item->certificate_len;
              ssh_private_key_derive_public_key(private_key,
                                                &pm_info->public_key);
              (*callback_in)(private_key, callback_context_in);
              return;
            }
        }
    }
  if (pm_info->local_ip)
    {
      unsigned char buf[32];

      id.protocol_id = 0;
      id.port_number = 0;
      id.port_range_end = 0;
      id.identification_len = sizeof(buf);

      if (ssh_inet_strtobin(pm_info->local_ip, buf, &id.identification_len))
        {
          if (id.identification_len == 4)
            {
              id.id_type = IPSEC_ID_IPV4_ADDR;
              memcpy(id.identification.ipv4_addr, buf, id.identification_len);
            }
          else if (id.identification_len == 16)
            {
              id.id_type = IPSEC_ID_IPV6_ADDR;
              memcpy(id.identification.ipv6_addr, buf, id.identification_len);
            }
          else
            ssh_fatal("Invalid length returned from ssh_inet_strtobin");

          ssh_ike_id_to_string(id_buffer, sizeof(id_buffer), &id);

          item = ssh_adt_strmap_get(mapping, id_buffer);
          if (item != NULL)
            {
              ssh_private_key_copy(item->key, &private_key);
              pm_info->own_auth_data = ssh_xmemdup(item->certificate,
                                                   item->certificate_len);
              pm_info->own_auth_data_len = item->certificate_len;
              ssh_private_key_derive_public_key(private_key,
                                                &pm_info->public_key);
              (*callback_in)(private_key, callback_context_in);
              return;
            }
        }
    }
  /* No private key found, return error */
  (*callback_in)(NULL, callback_context_in);
  return;
}
#endif /* SSHDIST_IKE_CERT_AUTH */


/*                                                              shade{0.9}
 * Find pre shared secret for host. The primary
 * selector is the id fields if they are given and
 * if they are NULL then ip and port numbers are
 * used instead. Call callback_in when the data is
 * available (it can also be called immediately).                shade{1.0}
 */
void ssh_policy_find_pre_shared_key(SshIkePMPhaseI pm_info,
                                    SshPolicyFindPreSharedKeyCB callback_in,
                                    void *callback_context_in)
{
  SshIkePMContext pm = pm_info->pm;
  SshIkePMPreSharedKeyCache pre_shared_key_cache =
    ((SshIkePMPreSharedKeyCache) pm->pre_shared_key_cache);
  struct SshIkePayloadIDRec id;
  SshIkePMPreSharedKeyItem item;
  unsigned char buf[32];
  char id_buffer[256];

  SSH_DEBUG(5, ("Start, local = %s:%s, remote = %s:%s",
                pm_info->local_ip, pm_info->local_port,
                pm_info->remote_ip, pm_info->remote_port));

  /* Try to find using the id as a key. */
  if (pm_info->remote_id)
    {
      if (ssh_ike_id_copy(pm_info->remote_id, &id))
        {
          id.protocol_id = 0;
          id.port_number = 0;
          id.port_range_end = 0;

          ssh_ike_id_to_string(id_buffer, sizeof(id_buffer), &id);

          item = ssh_adt_strmap_get(pre_shared_key_cache->mapping, id_buffer);
          if (item != NULL)
            {
              if (pm_info->auth_data)
                ssh_xfree(pm_info->auth_data);

              pm_info->auth_data = ssh_xmemdup(item->data, item->data_len);
              pm_info->auth_data_len = item->data_len;
              (*callback_in)(ssh_xmemdup(item->data, item->data_len),
                             item->data_len, callback_context_in);
              return;
            }
        }
    }
  if (pm_info->remote_ip)
    {
      id.protocol_id = 0;
      id.port_number = 0;
      id.port_range_end = 0;
      id.identification_len = sizeof(buf);

      if (ssh_inet_strtobin(pm_info->remote_ip, buf, &id.identification_len))
        {
          if (id.identification_len == 4)
            {
              id.id_type = IPSEC_ID_IPV4_ADDR;
              memcpy(id.identification.ipv4_addr, buf, id.identification_len);
            }
          else if (id.identification_len == 16)
            {
              id.id_type = IPSEC_ID_IPV6_ADDR;
              memcpy(id.identification.ipv6_addr, buf, id.identification_len);
            }
          else
            ssh_fatal("Invalid length returned from ssh_inet_strtobin");

          ssh_ike_id_to_string(id_buffer, sizeof(id_buffer), &id);

          item = ssh_adt_strmap_get(pre_shared_key_cache->mapping, id_buffer);
          if (item != NULL)
            {
              if (pm_info->auth_data)
                ssh_xfree(pm_info->auth_data);

              pm_info->auth_data = ssh_xmemdup(item->data, item->data_len);
              pm_info->auth_data_len = item->data_len;
              (*callback_in)(ssh_xmemdup(item->data, item->data_len),
                             item->data_len, callback_context_in);
              return;
            }
        }
    }
  id.protocol_id = 0;
  id.port_number = 0;
  id.port_range_end = 0;
  id.id_type = IPSEC_ID_IPV4_ADDR;
  id.identification_len = 4;
  memset(id.identification.ipv4_addr, 0, sizeof(id.identification.ipv4_addr));

  item = ssh_adt_strmap_get(pre_shared_key_cache->mapping, id_buffer);
  if (item != NULL)
    {
      if (pm_info->auth_data)
        ssh_xfree(pm_info->auth_data);

      pm_info->auth_data = ssh_xmemdup(item->data, item->data_len);
      pm_info->auth_data_len = item->data_len;
      (*callback_in)(ssh_xmemdup(item->data, item->data_len),
                     item->data_len, callback_context_in);
      return;
    }
  /* No private key found, return error */
  (*callback_in)(NULL, 0, callback_context_in);
  return;
}


/*                                                              shade{0.9}
 * Ask how many bytes of nonce data should we
 * create for this connection. Call callback_in
 * when the data is available (it can also be
 * called immediately).                                         shade{1.0}
 */
void ssh_policy_isakmp_nonce_data_len(SshIkePMPhaseI pm_info,
                                      SshPolicyNonceDataLenCB callback_in,
                                      void *callback_context_in)
{
  SshIkePMContext pm = pm_info->pm;
  UpperPolicyManagerContext upper_context =
    (UpperPolicyManagerContext) pm->upper_context;

  SSH_DEBUG(5, ("Start, local = %s:%s, remote = %s:%s",
                pm_info->local_ip, pm_info->local_port,
                pm_info->remote_ip, pm_info->remote_port));
  (*callback_in)(upper_context->nonce_len, callback_context_in);
  return;
}

/*                                                              shade{0.9}
 * Ask our own local id for isakmp_sa negotiation.
 * Call callback_in when the data is available (it
 * can also be called immediately).                             shade{1.0}
 */
void ssh_policy_isakmp_id(SshIkePMPhaseI pm_info,
                          SshPolicyIsakmpIDCB callback_in,
                          void *callback_context_in)
{
  SshIkePayloadID local_id;
  unsigned char buf[16];
  size_t len;

  SSH_DEBUG(5, ("Start, local = %s:%s, remote = %s:%s",
                pm_info->local_ip, pm_info->local_port,
                pm_info->remote_ip, pm_info->remote_port));

  len = sizeof(buf);
  if (!ssh_inet_strtobin(pm_info->local_ip, buf, &len) ||
      (len != 4 && len != 16))
    {
      SSH_DEBUG(3, ("Error, invalid local_ip number"));
      (*callback_in)(NULL, callback_context_in);
      return;
    }
  local_id = ssh_xcalloc(1, sizeof(struct SshIkePayloadIDRec));

  if (len == 4)
    {
      local_id->id_type = IPSEC_ID_IPV4_ADDR;
      memcpy(local_id->identification.ipv4_addr, buf, len);
    }
  else if (len == 16)
    {
      local_id->id_type = IPSEC_ID_IPV6_ADDR;
      memcpy(local_id->identification.ipv6_addr, buf, len);
    }
  local_id->protocol_id = 0;
  local_id->identification_len = len;
  local_id->port_number = 0;
  (*callback_in)(local_id, callback_context_in);
  return;
}

/*                                                              shade{0.9}
 * Request policy manager to process vendor id
 * information.                                                 shade{1.0}
 */
void ssh_policy_isakmp_vendor_id(SshIkePMPhaseI pm_info,
                                 unsigned char *vendor_id,
                                 size_t vendor_id_len)
{
  SSH_DEBUG(5, ("Start, local = %s:%s, remote = %s:%s, "
                "vendor_id[%d] = %08x %08x",
                pm_info->local_ip, pm_info->local_port,
                pm_info->remote_ip, pm_info->remote_port,
                vendor_id_len, SSH_GET_32BIT(vendor_id),
                SSH_GET_32BIT(vendor_id + 4)));
  /* We could here set all kind of flags etc in
     the pm_info, but now we just ignore the
     vendor id payload */
  return;
}

/*                                                              shade{0.9}
 * Get vendor id payloads. Call callback_in when
 * the data is available (it can also be called
 * immediately).                                                shade{1.0}
 */
void ssh_policy_isakmp_request_vendor_ids(SshIkePMPhaseI pm_info,
                                          SshPolicyRequestVendorIDsCB
                                          callback_in,
                                          void *callback_context_in)
{
  SshIkePMContext pm = pm_info->pm;
  UpperPolicyManagerContext upper_context =
    (UpperPolicyManagerContext) pm->upper_context;

  if (upper_context->vendor_id_len)
    {
      unsigned char **table;
      size_t *len_table;

      table = ssh_xcalloc(1, sizeof(unsigned char *));
      table[0] = ssh_xmemdup(upper_context->vendor_id,
                             upper_context->vendor_id_len);
      len_table = ssh_xcalloc(1, sizeof(size_t));
      len_table[0] = upper_context->vendor_id_len;
      (callback_in)(1, table, len_table, callback_context_in);
    }
  else
    (callback_in)(0, NULL, NULL, callback_context_in);
  return;
}

#ifdef SSHDIST_ISAKMP_CFG_MODE
/*                                                              shade{0.9}
 * Request policy manager to process configuration
 * mode exchange values. It should fill in all
 * values to newly allocated table of attributes
 * and call SshPolicyCfgFillAttrsCB callback with
 * that table.                                                  shade{1.0}
 */
void ssh_policy_cfg_fill_attrs(SshIkePMPhaseII pm_info,
                               int number_of_attrs,
                               SshIkePayloadAttr *return_attributes,
                               SshPolicyCfgFillAttrsCB callback_in,
                               void *callback_context_in)
{
  int i, j, k;
  SshIkePayloadAttr *attrs;
  unsigned char *p;

  if (number_of_attrs == 1 &&
      return_attributes[0]->type == SSH_IKE_CFG_MESSAGE_TYPE_CFG_REQUEST)
    {
      for (i = 0; i < return_attributes[0]->number_of_attributes; i++)
        {
          if (return_attributes[0]->attributes[i].attribute_type >=
              SSH_IKE_CFG_ATTR_XAUTH_TYPE &&
              return_attributes[0]->attributes[i].attribute_type <=
              SSH_IKE_CFG_ATTR_XAUTH_DOMAIN)
            {
              ssh_policy_xauth_fill_attrs(pm_info,
                                          return_attributes[0],
                                          callback_in,
                                          callback_context_in);
              return;
            }
        }
    }

  attrs = ssh_xcalloc(number_of_attrs, sizeof(*attrs));

  for (i = 0; i < number_of_attrs; i++)
    {
      attrs[i] = ssh_xmemdup(return_attributes[i],
                             sizeof(struct SshIkePayloadAttrRec));
      /* Allocate attributes table, keep room for
         attribute structure and 4 bytes of data */
      attrs[i]->attributes = ssh_xcalloc(attrs[i]->number_of_attributes,
                                         sizeof(struct SshIkeDataAttributeRec)
                                         + 4);
      p = (unsigned char *)
        (&attrs[i]->attributes[attrs[i]->number_of_attributes]);
      if (attrs[i]->type == SSH_IKE_CFG_MESSAGE_TYPE_CFG_REQUEST)
        attrs[i]->type = SSH_IKE_CFG_MESSAGE_TYPE_CFG_REPLY;
      else if (attrs[i]->type == SSH_IKE_CFG_MESSAGE_TYPE_CFG_SET)
        attrs[i]->type = SSH_IKE_CFG_MESSAGE_TYPE_CFG_ACK;
      else
        SSH_DEBUG(3, ("Invalid configuration type %d",
                      attrs[i]->type));

      /* Update attributes */
      for (j = 0, k = 0; j < attrs[i]->number_of_attributes; j++)
        {
          switch (return_attributes[i]->attributes[j].attribute_type)
            {
            case SSH_IKE_CFG_ATTR_INTERNAL_IPV4_ADDRESS:
            case SSH_IKE_CFG_ATTR_INTERNAL_IPV4_NETMASK:
            case SSH_IKE_CFG_ATTR_INTERNAL_IPV4_DNS:
            case SSH_IKE_CFG_ATTR_INTERNAL_IPV4_NBNS:
            case SSH_IKE_CFG_ATTR_INTERNAL_IPV4_DHCP:
              if (return_attributes[i]->type ==
                  SSH_IKE_CFG_MESSAGE_TYPE_CFG_REQUEST)
                {
                  attrs[i]->attributes[k].attribute_type =
                    return_attributes[i]->attributes[k].attribute_type;
                  attrs[i]->attributes[k].attribute_length = 4;
                  attrs[i]->attributes[k].attribute = p;
                  *p++ = 127; *p++ = 0; *p++ = 0; *p++ = 1;
                  k++;
                }
              else if (return_attributes[i]->type ==
                       SSH_IKE_CFG_MESSAGE_TYPE_CFG_SET)
                {
                  attrs[i]->attributes[k].attribute_type =
                    return_attributes[i]->attributes[k].attribute_type;
                  attrs[i]->attributes[k].attribute_length = 0;
                  attrs[i]->attributes[k].attribute = p;
                  k++;
                }
              else
                {
                  SSH_DEBUG(3, ("Invalid configuration type %d",
                                return_attributes[i]->type));
                }
              break;
            case SSH_IKE_CFG_ATTR_INTERNAL_ADDRESS_EXPIRY:
              if (return_attributes[i]->type ==
                  SSH_IKE_CFG_MESSAGE_TYPE_CFG_REQUEST)
                {
                  attrs[i]->attributes[k].attribute_type =
                    return_attributes[i]->attributes[k].attribute_type;
                  attrs[i]->attributes[j].attribute_length = 2;
                  attrs[i]->attributes[j].attribute = p;
                  SSH_PUT_16BIT(p, 3600);
                  p += 2;
                  k++;
                }
              else if (return_attributes[i]->type ==
                       SSH_IKE_CFG_MESSAGE_TYPE_CFG_SET)
                {
                  attrs[i]->attributes[k].attribute_type =
                    return_attributes[i]->attributes[k].attribute_type;
                  attrs[i]->attributes[k].attribute_length = 0;
                  attrs[i]->attributes[k].attribute = p;
                  k++;
                }
              else
                {
                  SSH_DEBUG(3, ("Invalid configuration type %d",
                                return_attributes[i]->type));
                }
              break;
            case SSH_IKE_CFG_ATTR_APPLICATION_VERSION:
            case SSH_IKE_CFG_ATTR_INTERNAL_IPV6_ADDRESS:
            case SSH_IKE_CFG_ATTR_INTERNAL_IPV6_NETMASK:
            case SSH_IKE_CFG_ATTR_INTERNAL_IPV6_DNS:
            case SSH_IKE_CFG_ATTR_INTERNAL_IPV6_NBNS:
            case SSH_IKE_CFG_ATTR_INTERNAL_IPV6_DHCP:
              break;
            }
        }
      attrs[i]->number_of_attributes = k;
    }
  (*callback_in)(number_of_attrs, attrs, callback_context_in);
  return;
}

/* Inform policy manager about configuration mode exchange values
   received from remote side. This occurs when we already have local
   variables, and no query for them is necessary. */
void ssh_policy_cfg_notify_attrs(SshIkePMPhaseII pm_info,
                                 int number_of_attrs,
                                 SshIkePayloadAttr *attributes)
{
  SshUInt32 value;
  int i, j;

  SSH_DEBUG(3, ("Configuration mode values returned from the other side"));
  for (i = 0; i < number_of_attrs; i++)
    {
      SSH_DEBUG(3,
                ("attribute[%d], type = %d, identifier = %d, # attrs = %d",
                 i,
                 attributes[i]->type,
                 attributes[i]->identifier,
                 attributes[i]->number_of_attributes));
      for (j = 0; j < attributes[i]->number_of_attributes; j++)
        {
          if (attributes[i]->attributes[j].attribute_length == 0)
            {
              SSH_DEBUG(3, ("Attribute %d not set",
                            attributes[i]->attributes[j].attribute_type));
            }
          else if (ssh_ike_get_data_attribute_int(&(attributes[i]->
                                                    attributes[j]),
                                                  &value,
                                                  0))
            {
              SSH_DEBUG(3, ("Attribute %d = %08x",
                            attributes[i]->attributes[j].attribute_type,
                            value));
            }
          else
            {
              SSH_DEBUG(3, ("Variable length attribute %d",
                            attributes[i]->attributes[j].attribute_type));
            }
        }
    }
}
#endif /* SSHDIST_ISAKMP_CFG_MODE */

/*                                                              shade{0.9}
 * Send query to policy manager that will select
 * one proposal isakmp sa, and select one
 * transform from each protocol in proposal. When
 * it is ready it will call callback_in and give
 * information of selected sa to it. This can also
 * call callback immediate if the answer can be
 * given immediately.                                           shade{1.0}
 */
void ssh_policy_isakmp_select_sa(SshIkePMPhaseI pm_info,
                                 SshIkeNegotiation negotiation,
                                 SshIkePayload sa_in,
                                 SshPolicySACB callback_in,
                                 void *callback_context_in)
{
  SshIkePMContext pm = pm_info->pm;
  SshIkeNotifyMessageType ret;
  int i;
  int selected_proposal, *selected_transform = NULL;
  SshIkePayloadSA pl;
  int prop, proto, trans;

  SSH_DEBUG(5, ("Start, local = %s:%s, remote = %s:%s",
                pm_info->local_ip, pm_info->local_port,
                pm_info->remote_ip, pm_info->remote_port));

  pl = &(sa_in->pl.sa);
  selected_proposal = -1;



  for (prop = 0; prop < pl->number_of_proposals; prop++)
    {
      for (proto = 0;
          proto < pl->proposals[prop].number_of_protocols;
          proto++)
        {
          SSH_DEBUG(7, ("Proposal[%d] = %d, proposal_number = %d (0x%x), "
                        "#transforms = %d",
                        prop, pl->proposals[prop].proposal_number,
                        pl->proposals[prop].protocols[proto].protocol_id,
                        pl->proposals[prop].protocols[proto].protocol_id,
                        pl->proposals[prop].protocols[proto].
                        number_of_transforms));
          if (pl->proposals[prop].protocols[proto].protocol_id !=
              SSH_IKE_PROTOCOL_ISAKMP)
            {
              SSH_DEBUG(3, ("Invalid protocol id = %d",
                            pl->proposals[prop].protocols[proto].protocol_id));
              goto error;
            }
          for (i = 0; i < proto; i++)
            if (pl->proposals[prop].protocols[proto].protocol_id ==
                pl->proposals[prop].protocols[i].protocol_id)
              break;
          if (i != proto)
            {
              SSH_DEBUG(3, ("Same protocol given twice"));
              goto error;
            }
          /* Check spi value */
          ret = ssh_ike_check_isakmp_spi(pl->proposals[prop].
                                         protocols[proto].spi_size,
                                         pl->proposals[prop].
                                         protocols[proto].spi,
                                         pm_info->cookies->initiator_cookie);
          if (ret != 0)
            {
              SSH_DEBUG(4, ("Cookie doesn't match"));
            }

          selected_transform = NULL;
          for (trans = 0;
              trans <
                pl->proposals[prop].protocols[proto].number_of_transforms;
              trans++)
            {
              struct SshIkeAttributesRec attrs;

              ssh_ike_clear_isakmp_attrs(&attrs);

              /* Check transform id */
              if (pl->proposals[prop].protocols[proto].
                  transforms[trans].transform_id.generic !=
                  SSH_IKE_ISAKMP_TRANSFORM_KEY_IKE)
                {
                  SSH_DEBUG(3,("Invalid transform id"));
                  goto error;
                }
              /* Read attributes */
              if (ssh_ike_read_isakmp_attrs(negotiation,
                                            &(pl->proposals[prop].
                                              protocols[proto].
                                              transforms[trans]),
                                            &attrs))
                {
                  /* Transform was supported, check that it contains all
                     mandatory information */
                  if (attrs.encryption_algorithm != 0 &&
                      attrs.hash_algorithm != 0 &&
                      attrs.auth_method != 0 &&
                      ((attrs.group_desc != NULL && !attrs.group_parameters) ||
                       (attrs.group_desc == NULL && attrs.group_parameters)))
                    {
                      Boolean ok;

                      ok = TRUE;
                      if (attrs.group_parameters)
                        {
                          struct SshIkeGrpAttributesRec grp_attrs;

                          ssh_ike_clear_grp_attrs(&grp_attrs);

                          if (!ssh_ike_read_grp_attrs(negotiation,
                                                      &(pl->proposals[prop].
                                                        protocols[proto].
                                                        transforms[trans]),
                                                      &grp_attrs))
                            ok = FALSE;

                          ssh_ike_free_grp_attrs(&grp_attrs);
                        }
                      if (pm->upper_context != NULL &&
                          ((UpperPolicyManagerContext) (pm->upper_context))->
                          test_context != NULL &&
                          ((UpperPolicyManagerContext) (pm->upper_context))->
                          test_context->test ==
                          TEST_SERVER_ISAKMP)
                        {
                          unsigned long *args;

                          args = &(((UpperPolicyManagerContext)
                                    (pm->upper_context))->test_context->
                                   argv[0]);
                          if (!((1U << (attrs.encryption_algorithm - 1)) &
                                args[1]))
                            {
                              SSH_IKE_DEBUG(8, negotiation,
                                           ("Transform[%d][%d] rejected, "
                                            "encryption algorightm "
                                            "not accepted : "
                                            "bit %d not set in %x",
                                            prop, trans,
                                            attrs.encryption_algorithm - 1,
                                            args[1]));

                              ok = FALSE;
                            }
                          if (!((1U << (attrs.hash_algorithm - 1)) & args[2]))
                            {
                              SSH_IKE_DEBUG(8, negotiation,
                                           ("Transform[%d][%d] rejected, "
                                            "hash algorightm not accepted : "
                                            "bit %d not set in %x",
                                            prop, trans,
                                            attrs.hash_algorithm - 1,
                                            args[2]));

                              ok = FALSE;
                            }
                          if (attrs.group_parameters && !(args[3] & 1))
                            {
                              SSH_IKE_DEBUG(8, negotiation,
                                           ("Transform[%d][%d] rejected, "
                                            "no private group accepted",
                                            prop, trans));
                              ok = FALSE;
                            }
                          if (!attrs.group_parameters &&
                              attrs.group_desc != NULL &&
                              !((1U << (attrs.group_desc->descriptor)) &
                                args[3]))
                            {
                              SSH_IKE_DEBUG(8, negotiation,
                                           ("Transform[%d][%d] rejected, "
                                            "group not accpeted : "
                                            "bit %d not set in %x",
                                            prop, trans,
                                            attrs.group_desc->descriptor,
                                            args[3]));
                              ok = FALSE;
                            }
                          if (args[4] != 0 &&
                              args[4] != attrs.key_length)
                            {
                              SSH_IKE_DEBUG(8, negotiation,
                                           ("Transform[%d][%d] rejected, "
                                            "key length not accpeted : "
                                            "%d != %d",
                                            prop, trans,
                                            attrs.key_length,
                                            args[2]));

                              ok = FALSE;
                            }
                        }
                      if (ok)
                        {
                          selected_transform = ssh_xcalloc(1, sizeof(int));
                          selected_transform[0] = trans;
                          SSH_DEBUG(7, ("Transform selected, encr = %d, "
                                        "hash = %d, auth_meth = %d, "
                                        "prf = %d, life = %d kb, %d sec, "
                                        "key_len = %d",
                                        attrs.encryption_algorithm,
                                        attrs.hash_algorithm,
                                        attrs.auth_method,
                                        attrs.prf_algorithm,
                                        attrs.life_duration_kb,
                                        attrs.life_duration_secs,
                                        attrs.key_length));
                          /* Break out from the tranform loop,
                             this means we will select first transform
                             that we support */
                          pm_info->sa_start_time = ssh_time();
                          if (attrs.life_duration_secs == 0)
                            {
                              pm_info->sa_expire_time =
                                pm_info->sa_start_time +
                                SSH_IKE_DEFAULT_LIFE_DURATION;
                            }
                          else
                            {
                              pm_info->sa_expire_time =
                                pm_info->sa_start_time +
                                attrs.life_duration_secs;
                            }
                          break;
                        }
                    }
                  else
                    {
                      SSH_DEBUG(7, ("Transform rejected, because one of "
                                    "the mandatory attributes was missing "
                                    "(encr,hash,auth,grp)"));
                    }
                }
            }
          if (selected_transform != NULL)
            break;
        }
      if (proto != pl->proposals[prop].number_of_protocols)
        {
          /* Yes, we found transform for each protocol, so select this
             proposal */
          selected_proposal = prop;
          break;
        }
    }
  if (selected_proposal == -1)
    SSH_DEBUG(3, ("No proposal selected"));
error:
  (*callback_in)(selected_proposal, 1, selected_transform,
                 callback_context_in);
  return;
}

/*                                                              shade{0.9}
 * Send query to policy manager that will select
 * one proposal ngm sa, and select one transform
 * from each protocol in proposal. When it is
 * ready it will call callback_in and give
 * information of selected sa to it. This can also
 * call callback immediate if the answer can be
 * given immediately.                                           shade{1.0}
 */
void ssh_policy_ngm_select_sa(SshIkePMPhaseII pm_info,
                              SshIkeNegotiation negotiation,
                              SshIkePayload sa_in,
                              SshPolicySACB callback_in,
                              void *callback_context_in)
{
  SshIkeNotifyMessageType ret;
  int i;
  int selected_proposal, *selected_transform = NULL;
  SshIkePayloadSA pl;
  int prop, proto, trans;

  SSH_DEBUG(5, ("Start, local = %s:%s, remote = %s:%s",
                pm_info->local_ip, pm_info->local_port,
                pm_info->remote_ip, pm_info->remote_port));

  pl = &(sa_in->pl.sa);
  selected_proposal = -1;
  for (prop = 0; prop < pl->number_of_proposals; prop++)
    {
      for (proto = 0;
          proto < pl->proposals[prop].number_of_protocols;
          proto++)
        {
          SSH_DEBUG(7, ("Proposal[%d] = %d, proposal_number = %d (0x%x), "
                        "#transforms = %d",
                        prop, pl->proposals[prop].proposal_number,
                        pl->proposals[prop].protocols[proto].protocol_id,
                        pl->proposals[prop].protocols[proto].protocol_id,
                        pl->proposals[prop].protocols[proto].
                        number_of_transforms));
          if (pl->proposals[prop].protocols[proto].protocol_id !=
              SSH_IKE_PROTOCOL_ISAKMP)
            {
              SSH_DEBUG(3, ("Invalid protocol id = %d",
                            pl->proposals[prop].protocols[proto].protocol_id));
              goto error;
            }
          for (i = 0; i < proto; i++)
            if (pl->proposals[prop].protocols[proto].protocol_id ==
                pl->proposals[prop].protocols[i].protocol_id)
              break;
          if (i != proto)
            {
              SSH_DEBUG(3, ("Same protocol given twice"));
              goto error;
            }
          /* Check spi value */
          ret = ssh_ike_check_isakmp_spi(pl->proposals[prop].
                                         protocols[proto].spi_size,
                                         pl->proposals[prop].
                                         protocols[proto].spi,
                                         pm_info->phase_i->
                                         cookies->initiator_cookie);
          if (ret != 0)
            {
              SSH_DEBUG(7, ("Cookie doesn't match"));
            }

          selected_transform = NULL;
          for (trans = 0;
              trans <
                pl->proposals[prop].protocols[proto].number_of_transforms;
              trans++)
            {
              struct SshIkeGrpAttributesRec attrs;

              ssh_ike_clear_grp_attrs(&attrs);

              /* Check transform id */
              if (pl->proposals[prop].protocols[proto].
                  transforms[trans].transform_id.generic !=
                  SSH_IKE_ISAKMP_TRANSFORM_KEY_IKE)
                {
                  SSH_DEBUG(3,("Invalid transform id"));
                  goto error;
                }
              /* Read attributes */
              if (ssh_ike_read_grp_attrs(negotiation,
                                         &(pl->proposals[prop].
                                           protocols[proto].
                                           transforms[trans]),
                                         &attrs))
                {
                  /* Transform was supported, check that it contains all
                     mandatory information */
                  if (attrs.group_type != 0 && attrs.group_descriptor != 0)
                    {
                      selected_transform = ssh_xcalloc(1, sizeof(int));
                      selected_transform[0] = trans;
                      SSH_DEBUG(7, ("Transform selected %d", trans));
                      /* Break out from the tranform loop,
                         this means we will select first transform
                         that we support */
                      ssh_ike_free_grp_attrs(&attrs);
                      break;
                    }
                  else
                    {
                      SSH_DEBUG(7, ("Transform rejected, because one of "
                                    "the mandatory attributes was missing "
                                    "(type)"));
                    }
                }
              ssh_ike_free_grp_attrs(&attrs);
            }
          if (selected_transform != NULL)
            break;
        }
      if (proto != pl->proposals[prop].number_of_protocols)
        {
          /* Yes, we found transform for each protocol, so select this
             proposal */
          selected_proposal = prop;
          break;
        }
    }
  if (selected_proposal == -1)
    SSH_DEBUG(3, ("No proposal selected"));
error:
  (*callback_in)(selected_proposal, 1, selected_transform,
                 callback_context_in);
  return;
}


/*                                                              shade{0.9}
 * Send query to policy manager that will select
 * one proposal for each sa, and select one
 * transform from each protocol in proposal. It
 * will also fill in the return spi sizes and
 * values. When it is ready it will call
 * callback_in and give IpsecSelectedSAIndexes
 * structure in. This can also call callback
 * immediate if the answer can be given
 * immediately.                                                 shade{1.0}
 */

void ssh_policy_qm_select_sa(SshIkePMPhaseQm pm_info,
                             SshIkeNegotiation negotiation,
                             int number_of_sas_in,
                             SshIkePayload *sa_table_in,
                             SshPolicyQmSACB callback_in,
                             void *callback_context_in)
{
  SshIkePMContext pm = pm_info->pm;
  int i;
  SshIkeIpsecSelectedSAIndexes ind;
  SshIkeAttributeLifeDurationValues min_life_duration_secs,
    min_life_duration_kb;
  Boolean multiple_different_second_values = FALSE;
  Boolean multiple_different_kb_values = FALSE;

  SSH_DEBUG(5, ("Start, local = %s:%s, remote = %s:%s, # sas = %d",
                pm_info->local_ip, pm_info->local_port,
                pm_info->remote_ip, pm_info->remote_port,
                number_of_sas_in));

  ind = ssh_xcalloc(number_of_sas_in,
                    sizeof(struct SshIkeIpsecSelectedSAIndexesRec));
  for (i = 0; i < number_of_sas_in; i++)
    {
      SshIkePayloadSA pl;
      int prop, proto, trans;
      int *selected_trans;
      int max_trans = 5;

      selected_trans = ssh_xcalloc(max_trans, sizeof(int));
      pl = &(sa_table_in[i]->pl.sa);
      min_life_duration_secs = -1;
      min_life_duration_kb = -1;
      for (prop = 0; prop < pl->number_of_proposals; prop++)
        {
          if (max_trans < pl->proposals[prop].number_of_protocols)
            {
              max_trans = pl->proposals[prop].number_of_protocols;
              selected_trans = ssh_xrealloc(selected_trans, max_trans *
                                            sizeof(int));
            }
          multiple_different_second_values = FALSE;
          multiple_different_kb_values = FALSE;
          for (proto = 0;
              proto < pl->proposals[prop].number_of_protocols;
              proto++)
            {
              selected_trans[proto] = -1;
              for (trans = 0;
                  trans <
                    pl->proposals[prop].protocols[proto].number_of_transforms;
                  trans++)
                {
                  struct SshIkeIpsecAttributesRec attrs;
                  ssh_ike_clear_ipsec_attrs(&attrs);
                  if (ssh_ike_read_ipsec_attrs(negotiation,
                                               &(pl->proposals[prop].
                                                 protocols[proto].
                                                 transforms[trans]),
                                               &attrs))
                    {
                      Boolean ok = TRUE;

                      if (pm->upper_context != NULL &&
                          ((UpperPolicyManagerContext) (pm->upper_context))->
                          test_context != NULL &&
                          ((UpperPolicyManagerContext) (pm->upper_context))->
                          test_context->test ==
                          TEST_SERVER_ISAKMP)
                        {
                          unsigned long *args;

                          args = &(((UpperPolicyManagerContext)
                                    (pm->upper_context))->test_context->
                                   argv[0]);

                          if (pl->proposals[prop].protocols[proto].
                              protocol_id == SSH_IKE_PROTOCOL_IPSEC_ESP)
                            {
                              if (!((1U << (pl->proposals[prop].
                                            protocols[proto].transforms[trans].
                                            transform_id.generic + 1))
                                    & args[5]))
                                {
                                  SSH_IKE_DEBUG(8, negotiation,
                                               ("ESP transform[%d][%d] "
                                                "rejected, protocol accepted "
                                                ": bit %d not set in %x",
                                                prop, trans,
                                                pl->proposals[prop].
                                                protocols[proto].
                                                transforms[trans].
                                                transform_id.generic + 1,
                                                args[5]));
                                  ok = FALSE;
                                }
                              if (!((1U << attrs.auth_algorithm) & args[7]))
                                {
                                  SSH_IKE_DEBUG(8, negotiation,
                                               ("ESP transform[%d][%d] "
                                                "rejected, authentication "
                                                "algorightm not accepted : "
                                                "bit %d not set in %x",
                                                prop, trans,
                                                attrs.auth_algorithm,
                                                args[7]));
                                  ok = FALSE;
                                }
                            }
                          else if (pl->proposals[prop].protocols[proto].
                                   protocol_id == SSH_IKE_PROTOCOL_IPSEC_AH)
                            {
                              if (!((1U << (pl->proposals[prop].
                                            protocols[proto].transforms[trans].
                                            transform_id.generic - 1))
                                    & args[6]))
                                {
                                  SSH_IKE_DEBUG(8, negotiation,
                                               ("AH transform[%d][%d] "
                                                "rejected, protocol not "
                                                "accepted : bit %d not set "
                                                "in %x",
                                                prop, trans,
                                                pl->proposals[prop].
                                                protocols[proto].
                                                transforms[trans].
                                                transform_id.generic - 1,
                                                args[6]));
                                  ok = FALSE;
                                }
                            }
                          if (attrs.group_desc == 0 && !(args[8] & 1))
                            {
                              SSH_IKE_DEBUG(8, negotiation,
                                           ("Transform[%d][%d] rejected, "
                                            "no group given",
                                            prop, trans));
                              ok = FALSE;
                            }
                          if (attrs.group_desc != 0)
                            {
                              if (attrs.group_desc < 31 &&
                                  !((1U << attrs.group_desc) & args[8]))
                                {
                                  SSH_IKE_DEBUG(8, negotiation,
                                                ("Transform[%d][%d] rejected, "
                                                 "group not accepted : "
                                                 "bit %d not set in %x",
                                                 prop, trans,
                                                 attrs.group_desc,
                                                 args[8]));
                                  ok = FALSE;
                                }
                              else
                                {
                                  if (attrs.group_desc >= 31 &&
                                      attrs.group_desc != args[9])
                                    {
                                      SSH_IKE_DEBUG(8, negotiation,
                                                    ("Transform[%d][%d] "
                                                     "rejected, private "
                                                     "group %d not accepted "
                                                     "(%d is accepted)",
                                                     prop, trans,
                                                     attrs.group_desc,
                                                     args[9]));
                                      ok = FALSE;
                                    }
                                }
                            }
                          if (args[10] != 0 && args[10] != attrs.key_length)
                            {
                              SSH_IKE_DEBUG(8, negotiation,
                                           ("Transform[%d][%d] rejected, "
                                            "key length not accpeted : "
                                            "%d != %d",
                                            prop, trans,
                                            attrs.key_length,
                                            args[10]));
                              ok = FALSE;
                            }
                        }
                      if (ok)
                        {
                          selected_trans[proto] = trans;
                          if (attrs.life_duration_secs != 0)
                            {
                              if (min_life_duration_secs != -1 &&
                                  min_life_duration_secs !=
                                  attrs.life_duration_secs)
                                multiple_different_second_values = TRUE;
                              if (attrs.life_duration_secs <
                                  min_life_duration_secs)
                                {
                                  min_life_duration_secs =
                                    attrs.life_duration_secs;
                                }
                            }
                          if (attrs.life_duration_kb != 0)
                            {
                              if (min_life_duration_kb != -1 &&
                                  min_life_duration_kb !=
                                  attrs.life_duration_kb)
                                multiple_different_kb_values = TRUE;
                              if (attrs.life_duration_kb <
                                  min_life_duration_kb)
                                {
                                  min_life_duration_kb =
                                    attrs.life_duration_kb;
                                }
                            }
                          break;
                        }
                    }
                }
              if (selected_trans[proto] == -1)
                break;
            }



          if (proto == pl->proposals[prop].number_of_protocols)
            break;
        }
      if (prop == pl->number_of_proposals)
        {
          SSH_DEBUG(7, ("Could not select proposal for sa %d", i));
          ind[i].proposal_index = -1;
          continue;
        }

      if (min_life_duration_secs == -1)
        pm_info->sa_expire_timer_sec = 0;
      else
        pm_info->sa_expire_timer_sec = min_life_duration_secs;
      if (min_life_duration_kb == -1)
        pm_info->sa_expire_timer_kb = 0;
      else
        pm_info->sa_expire_timer_kb = min_life_duration_kb;

      SSH_DEBUG(7, ("Selected proposal[%d] = %d, # proto = %d",
                    prop, pl->proposals[prop].proposal_number,
                    pl->proposals[prop].number_of_protocols));
      ind[i].proposal_index = prop;
      ind[i].number_of_protocols = pl->proposals[prop].number_of_protocols;
      ind[i].transform_indexes = ssh_xcalloc(ind[i].number_of_protocols,
                                         sizeof(int));
      ind[i].spi_sizes = ssh_xcalloc(ind[i].number_of_protocols,
                                 sizeof(size_t));
      ind[i].spis = ssh_xcalloc(ind[i].number_of_protocols,
                           sizeof(unsigned char *));
      if (multiple_different_second_values)
        ind[i].expire_secs = min_life_duration_secs;
      else
        ind[i].expire_secs = 0;

      if (multiple_different_kb_values)
        ind[i].expire_kb = min_life_duration_kb;
      else
        ind[i].expire_kb = 0;

      for (proto = 0; proto < ind[i].number_of_protocols; proto++)
        {
          trans = selected_trans[proto];
          ind[i].transform_indexes[proto] = trans;
          ind[i].spi_sizes[proto] =
            pl->proposals[prop].protocols[proto].spi_size;
          ind[i].spis[proto] = ssh_xmalloc(ind[i].spi_sizes[proto]);
          memcpy(ind[i].spis[proto],
                 pl->proposals[prop].protocols[proto].spi,
                 ind[i].spi_sizes[proto]);
          SSH_DEBUG(8, ("Proto[%d] = %d, selected transform[%d] = %d, "
                        "spi[0..%d] = %08x ....",
                        proto,
                        pl->proposals[prop].protocols[proto].protocol_id,
                        trans,
                        pl->proposals[prop].protocols[proto].transforms[trans].
                        transform_id.generic,
                        ind[i].spi_sizes[proto],
                        SSH_GET_32BIT(ind[i].spis[proto])));
        }
      ssh_xfree(selected_trans);
    }
  (*callback_in)(ind, callback_context_in);
  return;
}

/*                                                              shade{0.9}
 * Ask how many bytes of nonce data should we
 * create for this connection. Call callback_in
 * when the data is available (it can also be
 * called immediately).                                         shade{1.0}
 */
void ssh_policy_qm_nonce_data_len(SshIkePMPhaseQm pm_info,
                                  SshPolicyNonceDataLenCB callback_in,
                                  void *callback_context_in)
{
  SshIkePMContext pm = pm_info->pm;
  UpperPolicyManagerContext upper_context =
    (UpperPolicyManagerContext) pm->upper_context;

  SSH_DEBUG(5, ("Start, local = %s:%s, remote = %s:%s",
                pm_info->local_ip, pm_info->local_port,
                pm_info->remote_ip, pm_info->remote_port));
  (*callback_in)(upper_context->qm_nonce_len, callback_context_in);
  return;
}

/*                                                              shade{0.9}
 * Ask our own local id for quick mode negotiation.
 * Call callback_in when the data is available (it
 * can also be called immediately).                             shade{1.0}
 */
void ssh_policy_qm_local_id(SshIkePMPhaseQm pm_info,
                            SshPolicyIsakmpIDCB callback_in,
                            void *callback_context_in)
{
  SshIkePMContext pm = pm_info->pm;
  UpperPolicyManagerContext upper_context =
    (UpperPolicyManagerContext) pm->upper_context;
  SshIkePayloadID local_id;
  unsigned char buf[16];
  size_t len;
  SSH_DEBUG(5, ("Start, local = %s:%s, remote = %s:%s",
                pm_info->local_ip, pm_info->local_port,
                pm_info->remote_ip, pm_info->remote_port));

  if (upper_context->local_name)
    {
      len = sizeof(buf);
      if (!ssh_inet_strtobin(upper_context->local_name, buf, &len) ||
          len != 4 || len != 16)
        {
          SSH_DEBUG(3, ("Error, invalid local_ip number"));
        }
      else
        {
          local_id = ssh_xcalloc(1, sizeof(struct SshIkePayloadIDRec));

          SSH_DEBUG(9, ("Sending local hosts ip address"));
          if (len == 4)
            {
              local_id->id_type = IPSEC_ID_IPV4_ADDR;
              memcpy(local_id->identification.ipv4_addr, buf, len);
            }
          else if (len == 16)
            {
              local_id->id_type = IPSEC_ID_IPV6_ADDR;
              memcpy(local_id->identification.ipv6_addr, buf, len);
            }
          local_id->protocol_id = SSH_IPPROTO_ANY;
          local_id->identification_len = len;
          local_id->port_number = 0;
          (*callback_in)(local_id, callback_context_in);
          return;
        }
    }
  if (pm_info->local_i_id)
    {
      SSH_DEBUG(9, ("Copying local ends entry"));

      local_id = ssh_xcalloc(1, sizeof(struct SshIkePayloadIDRec));

      memcpy(local_id, pm_info->local_i_id,
             sizeof(struct SshIkePayloadIDRec));
      if (local_id->id_type == IPSEC_ID_FQDN)
        local_id->identification.fqdn =
          ssh_xmemdup(local_id->identification.fqdn,
                  local_id->identification_len);
      else if (local_id->id_type == IPSEC_ID_USER_FQDN)
        local_id->identification.user_fqdn =
          ssh_xmemdup(local_id->identification.user_fqdn,
                      local_id->identification_len);
      else if (local_id->id_type == IPSEC_ID_DER_ASN1_DN)
        local_id->identification.asn1_data =
          ssh_xmemdup(local_id->identification.asn1_data,
                      local_id->identification_len);
      else if (local_id->id_type == IPSEC_ID_DER_ASN1_GN)
        local_id->identification.asn1_data =
          ssh_xmemdup(local_id->identification.asn1_data,
                      local_id->identification_len);
      (*callback_in)(local_id, callback_context_in);
      return;
    }
  SSH_DEBUG(9, ("Returning null"));
  (*callback_in)(NULL, callback_context_in);
  return;
}

/*                                                              shade{0.9}
 * Ask our own remote id for quick mode negotiation.
 * Call callback_in when the data is available (it
 * can also be called immediately).                             shade{1.0}
 */
void ssh_policy_qm_remote_id(SshIkePMPhaseQm pm_info,
                             SshPolicyIsakmpIDCB callback_in,
                             void *callback_context_in)
{
  SshIkePMContext pm = pm_info->pm;
  UpperPolicyManagerContext upper_context =
    (UpperPolicyManagerContext) pm->upper_context;
  SshIkePayloadID remote_id;
  unsigned char buf[16];
  size_t len;
  SSH_DEBUG(5, ("Start, local = %s:%s, remote = %s:%s",
                pm_info->local_ip, pm_info->local_port,
                pm_info->remote_ip, pm_info->remote_port));

  if (upper_context->remote_name)
    {
      len = sizeof(buf);
      if (!ssh_inet_strtobin(upper_context->remote_name, buf, &len) ||
          len != 4 || len != 16)
        {
          SSH_DEBUG(3, ("Error, invalid remote_ip number"));
        }
      else
        {
          remote_id = ssh_xcalloc(1, sizeof(struct SshIkePayloadIDRec));

          SSH_DEBUG(9, ("Sending remote hosts ip address"));
          if (len == 4)
            {
              remote_id->id_type = IPSEC_ID_IPV4_ADDR;
              memcpy(remote_id->identification.ipv4_addr, buf, len);
            }
          else if (len == 16)
            {
              remote_id->id_type = IPSEC_ID_IPV6_ADDR;
              memcpy(remote_id->identification.ipv6_addr, buf, len);
            }
          remote_id->protocol_id = SSH_IPPROTO_ANY;
          remote_id->identification_len = len;
          remote_id->port_number = 0;
          (*callback_in)(remote_id, callback_context_in);
          return;
        }
    }
  if (pm_info->remote_i_id)
    {
      SSH_DEBUG(9, ("Copying remote ends entry"));

      remote_id = ssh_xcalloc(1, sizeof(struct SshIkePayloadIDRec));

      memcpy(remote_id, pm_info->remote_i_id,
             sizeof(struct SshIkePayloadIDRec));
      if (remote_id->id_type == IPSEC_ID_FQDN)
        remote_id->identification.fqdn =
          ssh_xmemdup(remote_id->identification.fqdn,
                  remote_id->identification_len);
      else if (remote_id->id_type == IPSEC_ID_USER_FQDN)
        remote_id->identification.user_fqdn =
          ssh_xmemdup(remote_id->identification.user_fqdn,
                      remote_id->identification_len);
      else if (remote_id->id_type == IPSEC_ID_DER_ASN1_DN)
        remote_id->identification.asn1_data =
          ssh_xmemdup(remote_id->identification.asn1_data,
                      remote_id->identification_len);
      else if (remote_id->id_type == IPSEC_ID_DER_ASN1_GN)
        remote_id->identification.asn1_data =
          ssh_xmemdup(remote_id->identification.asn1_data,
                      remote_id->identification_len);
      (*callback_in)(remote_id, callback_context_in);
      return;
    }
  SSH_DEBUG(9, ("Returning null"));
  (*callback_in)(NULL, callback_context_in);
  return;
}

/*                                                              shade{0.9}
 * Request policy manager to delete following spi
 * values. Note that if pm_info->phase_i is not
 * NULL then this negotiation was authenticated.                shade{1.0}
 */
void ssh_policy_delete(SshIkePMPhaseII pm_info,
                       Boolean authenticated,
                       SshIkeProtocolIdentifiers protocol_id,
                       int number_of_spis,
                       unsigned char **spis,
                       size_t spi_size)
{
  SSH_DEBUG(9, ("Start, local = %s:%s, remote = %s:%s, proto = %d, "
                "#spis = %d,%s spi[0][0..%d] = %08x ...",
                pm_info->local_ip, pm_info->local_port,
                pm_info->remote_ip, pm_info->remote_port,
                protocol_id, number_of_spis,
                (authenticated ? " authenticated," : ""),
                spi_size, SSH_GET_32BIT(spis[0])));
  return;
}

/*                                                              shade{0.9}
 * Request policy manager to process notification
 * message. Note that if pm_info->phase_i is not
 * NULL then this negotiation was authenticated.                shade{1.0}
 */
void ssh_policy_notification(SshIkePMPhaseII pm_info,
                             Boolean authenticated,
                             SshIkeProtocolIdentifiers protocol_id,
                             unsigned char *spi,
                             size_t spi_size,
                             SshIkeNotifyMessageType notify_message_type,
                             unsigned char *notification_data,
                             size_t notification_data_size)
{
  SSH_DEBUG(9, ("Start, local = %s:%s, remote = %s:%s, proto = %d, "
                "msg = %d,%s spi[0..%d] = %08x ...",
                pm_info->local_ip, pm_info->local_port,
                pm_info->remote_ip, pm_info->remote_port,
                protocol_id, notify_message_type,
                (authenticated ? " authenticated," : ""),
                spi_size, SSH_GET_32BIT(spi)));
  return;
}

/*                                                              shade{0.9}
 * Request policy manager to process phase I
 * status notification message. Status
 * notification is always with the phase I
 * packets, so the pm_info is for PhaseI.                       shade{1.0}
 */
void ssh_policy_phase_i_notification(SshIkePMPhaseI pm_info,
                                     Boolean encrypted,
                                     SshIkeProtocolIdentifiers protocol_id,
                                     unsigned char *spi,
                                     size_t spi_size,
                                     SshIkeNotifyMessageType
                                     notify_message_type,
                                     unsigned char *notification_data,
                                     size_t notification_data_size)
{
  SSH_DEBUG(9, ("Start, local = %s:%s, remote = %s:%s, proto = %d, msg = %d, "
                "spi[0..%d] = %08x ...",
                pm_info->local_ip, pm_info->local_port,
                pm_info->remote_ip, pm_info->remote_port,
                protocol_id, notify_message_type,
                spi_size, SSH_GET_32BIT(spi)));

  if (notify_message_type == SSH_IKE_NOTIFY_MESSAGE_INITIAL_CONTACT &&
      encrypted)
    {
      /* Payload was encrypted, trust it, and remove all other isakmp sas */
      ssh_ike_remove_other_isakmp_sas(pm_info->negotiation, 0);

      /* Here we should send the notification to the ipsec telling that it
         should also remove all ipsec sa's from its tables */
    }
  return;
}

/*                                                              shade{0.9}
 * Request policy manager to process phase QM
 * status notification message. Status
 * notification is always with the quick mode
 * packets, so the pm_info is for quick mode.                   shade{1.0}
 */
void ssh_policy_phase_qm_notification(SshIkePMPhaseQm pm_info,
                                      SshIkeProtocolIdentifiers protocol_id,
                                      unsigned char *spi,
                                      size_t spi_size,
                                      SshIkeNotifyMessageType
                                      notify_message_type,
                                      unsigned char *notification_data,
                                      size_t notification_data_size)
{
  SSH_DEBUG(9, ("Start, local = %s:%s, remote = %s:%s, proto = %d, msg = %d, "
                "spi[0..%d] = %08x ...",
                pm_info->local_ip, pm_info->local_port,
                pm_info->remote_ip, pm_info->remote_port,
                protocol_id, notify_message_type,
                spi_size, SSH_GET_32BIT(spi)));
  if (notify_message_type == SSH_IKE_NOTIFY_MESSAGE_RESPONDER_LIFETIME)
    {
      int i;
      SshUInt32 *life;
      SshUInt32 kb, sec;

      life = NULL;
      kb = 0;
      sec = 0;

      i = 0;
      while (i + 4 <= notification_data_size)
        {
          SshUInt16 type;
          SshUInt32 value;

          if (!ssh_ike_decode_data_attribute_int(notification_data + i,
                                                 notification_data_size - i,
                                                 &type, &value, 0L))
            {
              SSH_IKE_DEBUG(3, pm_info->negotiation,
                            ("ssh_ike_decode_data_attribute_int "
                             "returned error"));



              return;
            }
          switch (type)
            {
            case IPSEC_CLASSES_SA_LIFE_TYPE: /* Life type selector */
              if (life != NULL)
                {
                  SSH_IKE_DEBUG(3, pm_info->negotiation,
                                ("Two life types, without duration"));



                  return;
                }
              if (value == IPSEC_VALUES_LIFE_TYPE_SECONDS)
                {
                  life = &sec;
                }
              else if (value == IPSEC_VALUES_LIFE_TYPE_KILOBYTES)
                {
                  life = &kb;
                }
              else
                {
                  SSH_IKE_DEBUG(3, pm_info->negotiation,
                                ("Invalid life type"));



                  return;
                }
              break;
            case IPSEC_CLASSES_SA_LIFE_DURATION: /* Life type value */
              if (life == NULL)
                {
                  SSH_IKE_DEBUG(3, pm_info->negotiation,
                                ("Life duration without type"));



                  return;
                }
              if (*life != 0)
                {
                  SSH_IKE_DEBUG(3, pm_info->negotiation,
                                ("Same life duration value given twice"));



                  return;
                }
              *life = value;
              life = NULL;
            }
          i += ssh_ike_decode_data_attribute_size(notification_data + i, 0L);
        }

      if (sec != 0)
        {
          if (pm_info->sa_expire_timer_sec == 0 ||
              pm_info->sa_expire_timer_sec > sec)
            pm_info->sa_expire_timer_sec = sec;
        }
      if (kb != 0)
        {
          if (pm_info->sa_expire_timer_kb == 0 ||
              pm_info->sa_expire_timer_kb > kb)
            pm_info->sa_expire_timer_kb = kb;
        }
    }
  return;
}


/*                                                              shade{0.9}
 * Tell the policy manager that isakmp sa is now
 * freed.                                                       shade{1.0}
 */
void ssh_policy_isakmp_sa_freed(SshIkePMPhaseI pm_info)
{
  SSH_DEBUG(5, ("Start"));
  return;
}


/*                                                              shade{0.9}
 * Tell the policy manager that quick mode
 * negotiation is now freed.                                    shade{1.0}
 */
void ssh_policy_qm_sa_freed(SshIkePMPhaseQm pm_info)
{
  SSH_DEBUG(5, ("Start"));
  return;
}


/*                                                              shade{0.9}
 * Tell the policy manager that other phase II
 * negotiation is now freed.                                    shade{1.0}
 */
void ssh_policy_phase_ii_sa_freed(SshIkePMPhaseII pm_info)
{
  SSH_DEBUG(5, ("Start"));
  return;
}


/*                                                              shade{0.9}
 * Tell the policy manager that ISAKMP SA is now
 * finished. This is always called before the
 * ssh_policy_isakmp_sa_freed, and before
 * notify_callback if it is registered.                         shade{1.0}
 */
void ssh_policy_negotiation_done_isakmp(SshIkePMPhaseI pm_info,
                                        SshIkeNotifyMessageType code)
{
  SSH_DEBUG(5, ("Start"));
  SSH_ASSERT(phase_i > 0);
  phase_i--;
  return;
}


/*                                                              shade{0.9}
 * Tell the policy manager that quick mode
 * negotiation is now finished. This is always
 * called before ssh_policy_qm_sa_freed, and
 * before notify_callback if it is registered.
 * This is called after sa handler callback.                    shade{1.0}
 */
void ssh_policy_negotiation_done_qm(SshIkePMPhaseQm pm_info,
                                    SshIkeNotifyMessageType code)
{
  SSH_DEBUG(5, ("Start"));
  SSH_ASSERT(phase_qm > 0);
  phase_qm--;
  return;
}


/*                                                              shade{0.9}
 * Tell the policy manager that other phase II
 * negotiation is now freed. This is always called
 * before ssh_policy_phase_ii_sa_freed, and before
 * notify_callback if it is registered.                         shade{1.0}
 */
void ssh_policy_negotiation_done_phase_ii(SshIkePMPhaseII pm_info,
                                          SshIkeNotifyMessageType code)
{
  SSH_DEBUG(5, ("Start"));
  SSH_ASSERT(phase_ii > 0);
  phase_ii--;
  return;
}

/* Policy manager function called when source and destination ip or ports does
   not match the ones stored to the negotiation. Note, that any of the
   new_server, new_remote_ip, new_remote_port can stay same, but at least one
   of them has been changed when this is called. This call should call the
   ssh_ike_sa_change_server if it wants the change to new address to take
   effect. Note, that this information is never really authenticated, the ip
   address and port numbers are not covered by the any authentication inside
   the IKE. If the packet contained authentication HASH or was encrypted that
   processing is done before that. */
void ssh_policy_phase_i_server_changed(SshIkePMPhaseI pm_info,
                                       SshIkeServerContext new_server,
                                       const unsigned char *new_remote_ip,
                                       const unsigned char *new_remote_port)
{
  SSH_DEBUG(5, ("Start"));

  if (!ssh_ike_sa_change_server(pm_info->negotiation, new_server,
                                new_remote_ip, new_remote_port))
    ssh_fatal("ssh_ike_sa_change_server failed");
}

/* Policy manager function called when source and destination ip or ports does
   not match the ones stored to the negotiation. Note, that any of the
   new_server, new_remote_ip, new_remote_port can stay same, but at least one
   of them has been changed when this is called. This call should call the
   ssh_ike_sa_change_server if it wants the change to new address to take
   effect. Note, that this information is never really authenticated, the ip
   address and port numbers are not covered by the any authentication inside
   the IKE. This is called before any authentication checks is done, thus it
   might be better to postpone the actual changing of the server to the
   private_payload_phase_qm_output function.

   This is not called if new quick mode exchange initially starts using
   different ip or port than the IKE SA. This is called if the initial quick
   mode exchange initially starts using different server than the IKE SA. In
   that case this is called after the new_connection callback. */
void ssh_policy_phase_qm_server_changed(SshIkePMPhaseQm pm_info,
                                        SshIkeServerContext new_server,
                                        const unsigned char *new_remote_ip,
                                        const unsigned char *new_remote_port)
{
  SSH_DEBUG(5, ("Start"));

  if (!ssh_ike_sa_change_server(pm_info->negotiation, new_server,
                                new_remote_ip, new_remote_port))
    ssh_fatal("ssh_ike_sa_change_server failed");

  if (!ssh_ike_sa_change_server(pm_info->phase_i->negotiation, new_server,
                                new_remote_ip, new_remote_port))
    ssh_fatal("ssh_ike_sa_change_server failed");
}

/* Policy manager function called when source and destination ip or ports does
   not match the ones stored to the negotiation. Note, that any of the
   new_server, new_remote_ip, new_remote_port can stay same, but at least one
   of them has been changed when this is called. This call should call the
   ssh_ike_sa_change_server if it wants the change to new address to take
   effect. Note, that this information is never really authenticated, the ip
   address and port numbers are not covered by the any authentication inside
   the IKE. This is called before any authentication checks is done.

   This is not called if new phase ii exchange initially starts using different
   ip or port than the IKE SA. This is called if the initial phase ii exchange
   initially starts using different server than the IKE SA. In that case this
   is called after the new_connection callback. */
void ssh_policy_phase_ii_server_changed(SshIkePMPhaseII pm_info,
                                        SshIkeServerContext new_server,
                                        const unsigned char *new_remote_ip,
                                        const unsigned char *new_remote_port)
{
  SSH_DEBUG(5, ("Start"));

  if (!ssh_ike_sa_change_server(pm_info->negotiation, new_server,
                                new_remote_ip, new_remote_port))
    ssh_fatal("ssh_ike_sa_change_server failed");

  if (!ssh_ike_sa_change_server(pm_info->phase_i->negotiation, new_server,
                                new_remote_ip, new_remote_port))
    ssh_fatal("ssh_ike_sa_change_server failed");
}
