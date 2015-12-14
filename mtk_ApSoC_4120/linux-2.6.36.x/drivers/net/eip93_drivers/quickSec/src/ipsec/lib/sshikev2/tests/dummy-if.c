/*
  File: dummy-if.c

  Copyright:
        Copyright 2004 SFNT Finland Oy.
	All rights reserved.

  Description:
	Collect SAD, PAD and SPD implementations into one confiugration
	data structure.
*/

#include "sshincludes.h"

#include "sshadt.h"
#include "sshadt_bag.h"

#include "sshikev2-initiator.h"
#include "sshikev2-exchange.h"
#include "sshikev2-payloads.h"
#include "sshikev2-util.h"
#include "sshsad.h"

#include "sad-dummy.h"
#include "pad-dummy.h"
#include "spd-dummy.h"
#include "dummy-if.h"

SshSADInterfaceStruct dummy_if =
  {
    d_sad_ike_sa_allocate,
    d_sad_ipsec_spi_allocate,
    d_sad_ike_sa_delete,
    d_sad_ipsec_spi_delete,
    d_sad_ipsec_spi_delete_received,
    d_sad_ike_sa_rekey,
    d_sad_ike_sa_get,
    d_sad_ike_sa_take_ref,
    d_sad_ike_sa_free_ref,
    d_sad_exchange_data_alloc,
    d_sad_exchange_data_free,
    d_sad_ike_enumerate,
    d_sad_ipsec_sa_install,
    d_sad_ipsec_sa_update,
    d_sad_ike_sa_done,
    d_sad_ipsec_sa_done,

    d_pad_new_connection,
    d_pad_id,
#ifdef SSHDIST_IKE_CERT_AUTH
    d_pad_get_cas,
    d_pad_get_certificates,
    d_pad_new_certificate_request,
    d_pad_public_key,
#endif /* SSHDIST_IKE_CERT_AUTH */
    d_pad_shared_key,
#ifdef SSHDIST_IKE_CERT_AUTH
    d_pad_new_certificate,
#endif /* SSHDIST_IKE_CERT_AUTH */
#ifdef SSHDIST_IKE_EAP_AUTH
    d_pad_eap_received,
    d_pad_eap_request,
    d_pad_eap_key,
#endif /* SSHDIST_IKE_EAP_AUTH */
    d_pad_conf_received,
    d_pad_conf_request,
    d_pad_vendor_id_received,
    d_pad_vendor_id_request,
#ifdef SSHDIST_IKE_MOBIKE
    d_pad_get_address_pair,
    d_pad_get_additional_address_list,
#endif /* SSHDIST_IKE_MOBIKE */

    d_spd_fill_ike_sa,
    d_spd_fill_ipsec_sa,
    d_spd_select_ike_sa,
    d_spd_select_ipsec_sa,
    d_spd_narrow_ipsec_selector,
    d_spd_notify_request,
    d_spd_notify_received,
    d_spd_responder_exchange_done
  };

#define KEYSIZE(_bytes) ((_bytes == 0) ? 0 : ((0x800e << 16) | (8 * _bytes)))


struct TransformDefRec d_sad_ciphers[] =
  {
    { SSH_IKEV2_TRANSFORM_ENCR_AES_CBC,  16 },
    { SSH_IKEV2_TRANSFORM_ENCR_AES_CBC,  32 },
    { SSH_IKEV2_TRANSFORM_ENCR_AES_CBC,  24 },
    { SSH_IKEV2_TRANSFORM_ENCR_3DES,      0 }
  };
size_t d_sad_ciphers_num = sizeof(d_sad_ciphers)/sizeof(d_sad_ciphers[0]);

struct TransformDefRec d_sad_prfs[] =
  {
    { SSH_IKEV2_TRANSFORM_PRF_HMAC_SHA1,  0 },
    { SSH_IKEV2_TRANSFORM_PRF_HMAC_MD5,   0 },
    { SSH_IKEV2_TRANSFORM_PRF_AES128_CBC, 0 }
  };
size_t d_sad_prfs_num = sizeof(d_sad_prfs)/sizeof(d_sad_prfs[0]);

struct TransformDefRec d_sad_integs[] =
  {
    { SSH_IKEV2_TRANSFORM_AUTH_HMAC_SHA1_96, 0 },
    { SSH_IKEV2_TRANSFORM_AUTH_HMAC_MD5_96,  0 },
    { SSH_IKEV2_TRANSFORM_AUTH_AES_XCBC_96,  0 }
  };
size_t d_sad_integs_num = sizeof(d_sad_integs)/sizeof(d_sad_integs[0]);

struct TransformDefRec d_sad_dhs[] =
  {
    { SSH_IKEV2_TRANSFORM_D_H_MODP_1024, 0 },
    { SSH_IKEV2_TRANSFORM_D_H_MODP_2048, 0 }
#if 0
    { SSH_IKEV2_TRANSFORM_D_H_MODP_1536, 0 },
    { SSH_IKEV2_TRANSFORM_D_H_MODP_3072, 0 },
    { SSH_IKEV2_TRANSFORM_D_H_MODP_4096, 0 },
    { SSH_IKEV2_TRANSFORM_D_H_MODP_6144, 0 },
    { SSH_IKEV2_TRANSFORM_D_H_MODP_8192, 0 },
    { SSH_IKEV2_TRANSFORM_D_H_MODP_768,  0 }
#endif
  };
size_t d_sad_dhs_num = sizeof(d_sad_dhs)/sizeof(d_sad_dhs[0]);

struct TransformDefRec d_sad_esns[] =
  {
    { SSH_IKEV2_TRANSFORM_ESN_NO_ESN, 0 },
    { SSH_IKEV2_TRANSFORM_ESN_ESN, 0 }
  };
size_t d_sad_esns_num = sizeof(d_sad_esns)/sizeof(d_sad_esns[0]);

Boolean d_sad_fill_default_policy(SshSADHandle sad_handle)
{

  if ((sad_handle->default_ike_sa = ssh_ikev2_sa_allocate(sad_handle))
      != NULL)
    {
      int i;
      SshIkev2PayloadSA sa = sad_handle->default_ike_sa;

      for (i = 0; i < d_sad_ciphers_num; i++)
	ssh_ikev2_sa_add(sa,
			 0,
			 SSH_IKEV2_TRANSFORM_TYPE_ENCR,
			 d_sad_ciphers[i].transform,
			 KEYSIZE(d_sad_ciphers[i].keylen));
      for (i = 0; i < d_sad_prfs_num; i++)
	ssh_ikev2_sa_add(sa,
			 0,
			 SSH_IKEV2_TRANSFORM_TYPE_PRF,
			 d_sad_prfs[i].transform,
			 KEYSIZE(d_sad_prfs[i].keylen));
      for (i = 0; i < d_sad_integs_num; i++)
	ssh_ikev2_sa_add(sa,
			 0,
			 SSH_IKEV2_TRANSFORM_TYPE_INTEG,
			 d_sad_integs[i].transform,
			 KEYSIZE(d_sad_integs[i].keylen));
      for (i = 0; i < d_sad_dhs_num; i++)
	ssh_ikev2_sa_add(sa,
			 0,
			 SSH_IKEV2_TRANSFORM_TYPE_D_H,
			 d_sad_dhs[i].transform, KEYSIZE(d_sad_dhs[i].keylen));

      sa->protocol_id[0] = SSH_IKEV2_PROTOCOL_ID_IKE;
    }

  if ((sad_handle->default_ike_nosa = ssh_ikev2_sa_allocate(sad_handle))
      != NULL)
    {
      int i;
      SshIkev2PayloadSA sa = sad_handle->default_ike_nosa;

      ssh_ikev2_sa_add(sa,
		       0,
		       SSH_IKEV2_TRANSFORM_TYPE_ENCR,
		       SSH_IKEV2_TRANSFORM_ENCR_IDEA, 0);
      for (i = 0; i < d_sad_prfs_num; i++)
	ssh_ikev2_sa_add(sa,
			 0,
			 SSH_IKEV2_TRANSFORM_TYPE_PRF,
			 d_sad_prfs[i].transform,
			 KEYSIZE(d_sad_prfs[i].keylen));
      for (i = 0; i < d_sad_integs_num; i++)
	ssh_ikev2_sa_add(sa,
			 0,
			 SSH_IKEV2_TRANSFORM_TYPE_INTEG,
			 d_sad_integs[i].transform,
			 KEYSIZE(d_sad_integs[i].keylen));
      for (i = 0; i < d_sad_dhs_num; i++)
	ssh_ikev2_sa_add(sa,
			 0,
			 SSH_IKEV2_TRANSFORM_TYPE_D_H,
			 d_sad_dhs[i].transform, KEYSIZE(d_sad_dhs[i].keylen));

      sa->protocol_id[0] = SSH_IKEV2_PROTOCOL_ID_IKE;
    }

  if ((sad_handle->default_ipsec_sa = ssh_ikev2_sa_allocate(sad_handle))
      != NULL)
    {
      int i;
      SshIkev2PayloadSA sa = sad_handle->default_ipsec_sa;

      for (i = 0; i < d_sad_ciphers_num; i++)
	ssh_ikev2_sa_add(sa,
			 0,
			 SSH_IKEV2_TRANSFORM_TYPE_ENCR,
			 d_sad_ciphers[i].transform,
			 KEYSIZE(d_sad_ciphers[i].keylen));
      for (i = 0; i < d_sad_integs_num; i++)
	ssh_ikev2_sa_add(sa,
			 0,
			 SSH_IKEV2_TRANSFORM_TYPE_INTEG,
			 d_sad_integs[i].transform,
			 KEYSIZE(d_sad_integs[i].keylen));
      /* Remove if no ipsec pfs ... */
#if 0
      for (i = 0; i < d_sad_dhs_num; i++)
	ssh_ikev2_sa_add(sa,
			 0,
			 SSH_IKEV2_TRANSFORM_TYPE_D_H,
			 d_sad_dhs[i].transform, KEYSIZE(d_sad_dhs[i].keylen));
#endif
      for (i = 0; i < d_sad_esns_num; i++)
	ssh_ikev2_sa_add(sa,
			 0,
			 SSH_IKEV2_TRANSFORM_TYPE_ESN,
			 d_sad_esns[i].transform,
			 KEYSIZE(d_sad_esns[i].keylen));

      sa->protocol_id[0] = SSH_IKEV2_PROTOCOL_ID_ESP;
    }

  if ((sad_handle->default_ipsec_nosa = ssh_ikev2_sa_allocate(sad_handle))
      != NULL)
    {
      int i;
      SshIkev2PayloadSA sa = sad_handle->default_ipsec_nosa;

      ssh_ikev2_sa_add(sa,
		       0,
		       SSH_IKEV2_TRANSFORM_TYPE_ENCR,
		       SSH_IKEV2_TRANSFORM_ENCR_IDEA, 0);

      for (i = 0; i < d_sad_integs_num; i++)
	ssh_ikev2_sa_add(sa,
			 0,
			 SSH_IKEV2_TRANSFORM_TYPE_INTEG,
			 d_sad_integs[i].transform,
			 KEYSIZE(d_sad_integs[i].keylen));
      /* Remove if no ipsec pfs ... */
#if 0
      for (i = 0; i < d_sad_dhs_num; i++)
	ssh_ikev2_sa_add(sa,
			 0,
			 SSH_IKEV2_TRANSFORM_TYPE_D_H,
			 d_sad_dhs[i].transform, KEYSIZE(d_sad_dhs[i].keylen));
#endif
      for (i = 0; i < d_sad_esns_num; i++)
	ssh_ikev2_sa_add(sa,
			 0,
			 SSH_IKEV2_TRANSFORM_TYPE_ESN,
			 d_sad_esns[i].transform,
			 KEYSIZE(d_sad_esns[i].keylen));

      sa->protocol_id[0] = SSH_IKEV2_PROTOCOL_ID_ESP;
    }
  return TRUE;
}

static SshUInt32 d_sad_ike_sa_hash(const void *p, void *context)
{
  SshIkev2Sa sa = (SshIkev2Sa) p;
  SshUInt32 hash = 0;
  unsigned char *spi;
  int i;

  if (sa->flags & SSH_IKEV2_IKE_SA_FLAGS_INITIATOR)
    spi = sa->ike_spi_i;
  else
    spi = sa->ike_spi_r;

  for (i = 0; i < sizeof(sa->ike_spi_i); i++)
    {
      hash += spi[i];
      hash += hash << 10;
      hash ^= hash >> 6;
    }
  hash += hash << 3;
  hash ^= hash >> 11;
  hash += hash << 15;

  return hash;
}

static int d_sad_ike_sa_compare(const void *p1, const void *p2, void *context)
{
  SshIkev2Sa sa1 = (SshIkev2Sa) p1;
  SshIkev2Sa sa2 = (SshIkev2Sa) p2;

  if ((sa1->flags & SSH_IKEV2_IKE_SA_FLAGS_INITIATOR) !=
      (sa2->flags & SSH_IKEV2_IKE_SA_FLAGS_INITIATOR))
    return 1;

  if (sa1->flags & SSH_IKEV2_IKE_SA_FLAGS_INITIATOR)
    return memcmp(sa1->ike_spi_i, sa2->ike_spi_i, sizeof(sa1->ike_spi_i));
  else
    return memcmp(sa1->ike_spi_r, sa2->ike_spi_r, sizeof(sa1->ike_spi_r));
}

SshSADHandle d_sad_allocate(const char *policy)
{
  SshSADHandle sad_handle;

  if (policy)
    ssh_fatal("policy content reading not implemented");

  if ((sad_handle = ssh_calloc(1, sizeof(*sad_handle))) == NULL)
    return NULL;

  if (!ssh_ikev2_sa_freelist_create(sad_handle) ||
      !ssh_ikev2_ts_freelist_create(sad_handle) ||
      !ssh_ikev2_conf_freelist_create(sad_handle))
    {
    failed:
      ssh_ikev2_sa_freelist_destroy(sad_handle);
      ssh_ikev2_ts_freelist_destroy(sad_handle);
      ssh_ikev2_conf_freelist_destroy(sad_handle);
      ssh_free(sad_handle);
      return NULL;
    }

  if ((sad_handle->ike_sa_by_spi =
       ssh_adt_create_generic(SSH_ADT_BAG,
			      SSH_ADT_HEADER,
			      SSH_ADT_OFFSET_OF(SshIkev2SaStruct, sa_header),
			      SSH_ADT_HASH, d_sad_ike_sa_hash,
			      SSH_ADT_COMPARE, d_sad_ike_sa_compare,
			      SSH_ADT_ARGS_END)) == NULL)
    goto failed;

  sad_handle->ipsec_spi_counter = 1024;

  if (!policy)
    d_sad_fill_default_policy(sad_handle);

  return sad_handle;
}

void d_sad_destroy(SshSADHandle sad_handle)
{
  if (sad_handle)
    {
      ssh_ikev2_sa_free(sad_handle, sad_handle->default_ike_sa);
      ssh_ikev2_sa_free(sad_handle, sad_handle->default_ipsec_sa);
      ssh_ikev2_sa_free(sad_handle, sad_handle->default_ike_nosa);
      ssh_ikev2_sa_free(sad_handle, sad_handle->default_ipsec_nosa);

      ssh_ikev2_sa_freelist_destroy(sad_handle);
      ssh_ikev2_ts_freelist_destroy(sad_handle);
      ssh_ikev2_conf_freelist_destroy(sad_handle);

      if (sad_handle->ike_sa_by_spi)
	ssh_adt_destroy(sad_handle->ike_sa_by_spi);
      ssh_free(sad_handle);
    }
}

/* eof */
