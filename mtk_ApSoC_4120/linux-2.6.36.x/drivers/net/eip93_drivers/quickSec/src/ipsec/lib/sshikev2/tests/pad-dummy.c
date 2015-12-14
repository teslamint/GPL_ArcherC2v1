/*
  File: pad-dummy.c

  Copyright:
        Copyright 2004 SFNT Finland Oy.
	All rights reserved.

  Description:
  	Dummy PAD module
*/

#include "sshincludes.h"
#include "sshikev2-initiator.h"
#include "sshikev2-payloads.h"
#include "sshikev2-exchange.h"
#include "sshikev2-pad.h"
#include "pad-dummy.h"
#include "sshikev2-util.h"
#include "sshasn1.h"
#include "x509.h"
#include "cmi.h"
#include "sshbase64.h"
#include "sshadt_strmap.h"
#include "sshtimemeasure.h"
#include "sshfileio.h"
#include "sshmiscstring.h"

#define SSH_DEBUG_MODULE "TestIkev2PAD"

/****************************** Definitions **********************************/

/* Private key mapping item */
typedef struct SshIkev2PMPrivateKeyItemRec {
  unsigned char *certificate;   /* Certificate data */
  size_t certificate_len;       /* Length of certificate data */
  SshPrivateKey key;            /* Private key */
} *SshIkev2PMPrivateKeyItem;

/* Private key cache context */
typedef struct SshIkev2PMPrivateKeyCacheRec {
  /* Private key mappings. The key is in format understood by
     ssh_ike_string_to_id. The data item is SshIkePMPrivateKeyItem
     (pointer). */
  SshADTContainer rsa_mapping;
  SshADTContainer dss_mapping;
  SshADTContainer ecdss_mapping;
} *SshIkev2PMPrivateKeyCache;

/* Pre shared key mapping item */
typedef struct SshIkev2PMPreSharedKeyItemRec {
  unsigned char *data;   /* Pre shared key */
  size_t data_len;       /* Length of pre shared key */
} *SshIkev2PMPreSharedKeyItem;

/* Pre shared key cache context */
typedef struct SshIkev2PMPreSharedKeyCacheRec {
  /* Pre shared key mappings. The key is in format understood by
     ssh_ike_string_to_id. If mapping for remote host is not found then
     "ipv4(0.0.0.0)" is used as a key and if it is found it is used as a
     general key for all remote hosts. Insert that key to mapping only if you
     want to have default key for all remote hosts. The data item is
     SshIkePMPreSharedKeyCache. */
  SshADTContainer mapping;
} *SshIkev2PMPreSharedKeyCache;

/**************************** Global variables *******************************/

extern Boolean use_eap;
extern Boolean use_certs;

#ifdef SSH_IKEV2_MULTIPLE_AUTH
extern Boolean use_multiple_auth;
#endif /* SSH_IKEV2_MULTIPLE_AUTH */

#ifdef SSHDIST_IKE_MOBIKE
extern unsigned int num_servers;
extern SshIkev2Server server[];
int server_index = 0;
#endif /* SSHDIST_IKE_MOBIKE */

SshCMContext global_cert_cache;             /* Certificate cache context */
SshIkev2PMPrivateKeyCache private_key_cache;
SshIkev2PMPreSharedKeyCache pre_shared_key_cache;

#ifdef SSHDIST_IKE_CERT_AUTH
SshIkev2CertEncoding d_pad_ca_encoding = 0;
unsigned char *d_pad_certificate_authority = NULL;
size_t d_pad_certificate_authority_len = 0;
#endif /* SSHDIST_IKE_CERT_AUTH */

#define MAX_KEYS 64

unsigned char *d_pad_local_id_data[MAX_KEYS];
size_t d_pad_local_id_data_size[MAX_KEYS];
SshIkev2IDType d_pad_local_id_type[MAX_KEYS];
int d_pad_local_id_count = 0;


/**************************** Helper functions *******************************/

Boolean d_pad_pid_to_key(SshIkev2PayloadID pid,
			 char *id_buffer,
			 size_t id_buffer_size)
{
  SshIpAddrStruct ip[1];

  switch (pid->id_type)
    {
    case SSH_IKEV2_ID_TYPE_IPV4_ADDR:
    case SSH_IKEV2_ID_TYPE_IPV6_ADDR:
      SSH_IP_DECODE(ip, pid->id_data, pid->id_data_size);
      ssh_snprintf(id_buffer, id_buffer_size,
		   "%s(%@)", ssh_ikev2_id_to_string(pid->id_type),
		   ssh_ipaddr_render, ip);
      break;
    case SSH_IKEV2_ID_TYPE_FQDN:
    case SSH_IKEV2_ID_TYPE_RFC822_ADDR:
    case SSH_IKEV2_ID_TYPE_KEY_ID:
      ssh_snprintf(id_buffer, id_buffer_size,
		   "%s(%.*@)", ssh_ikev2_id_to_string(pid->id_type),
		   pid->id_data_size,
		   ssh_safe_text_render, pid->id_data);
      break;
    default:
      return FALSE;
    }
  return TRUE;
}

Boolean d_pad_str_to_key(const char *type, const char *value,
			 char *id_buffer, size_t id_buffer_size)
{
  SshIkev2IDType id_type;
  SshIpAddrStruct ip[1];

  id_type = ssh_find_keyword_number(ssh_ikev2_id_to_string_table, type);
  if (id_type == -1)
    {
      if (strcmp(type, "ip") == 0)
	id_type = SSH_IKEV2_ID_TYPE_IPV4_ADDR;
      else if (strcmp(type, "hash") == 0)
	{
	  ssh_snprintf(id_buffer, id_buffer_size, "hash(%.20@)",
		       ssh_hex_render, value);
	  return TRUE;
	}
      else
	{
	  SSH_DEBUG(SSH_D_LOWSTART, ("Unknown type: %s", type));
	  return FALSE;
	}
    }
  switch (id_type)
    {
    case SSH_IKEV2_ID_TYPE_IPV4_ADDR:
    case SSH_IKEV2_ID_TYPE_IPV6_ADDR:
      if (!ssh_ipaddr_parse(ip, value))
	{
	  SSH_DEBUG(SSH_D_ERROR, ("Error parsing IP address: %s", value));
	  return FALSE;
	}
      ssh_snprintf(id_buffer, id_buffer_size,
		   "%s(%@)",
		   ssh_ikev2_id_to_string(SSH_IP_IS4(ip) ?
					  SSH_IKEV2_ID_TYPE_IPV4_ADDR :
					  SSH_IKEV2_ID_TYPE_IPV6_ADDR),
		   ssh_ipaddr_render, ip);
      break;
    case SSH_IKEV2_ID_TYPE_FQDN:
    case SSH_IKEV2_ID_TYPE_RFC822_ADDR:
    case SSH_IKEV2_ID_TYPE_KEY_ID:
      ssh_snprintf(id_buffer, id_buffer_size,
		   "%s(%@)", ssh_ikev2_id_to_string(id_type),
		   ssh_safe_text_render, value);
      break;
    default:
      SSH_DEBUG(SSH_D_ERROR, ("Unknown type: %s", type));
      return FALSE;
    }
  return TRUE;
}

unsigned char *d_pad_compute_key_id(SshCMCertificate cert)
{
  size_t kid_len = 20;
  SshX509Certificate x509;
  unsigned char *kid;

  if (ssh_cm_cert_get_x509(cert, &x509) != SSH_CM_STATUS_OK ||
      x509 == NULL)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Unable to get x509 certificate"));
      return NULL;
    }

  kid = ssh_x509_cert_compute_key_identifier_ike(x509, "sha1", &kid_len);
  if (kid == NULL || kid_len != 20)
    {
      SSH_DEBUG(SSH_D_ERROR,
		("Unable to compute key identifier for x509 certificate"));
      ssh_x509_cert_free(x509);
      return NULL;
    }

  ssh_x509_cert_free(x509);
  return kid;
}

/**************************** Config file parsing ****************************/

Boolean ikev2_add_string(SshADTContainer mapping,
			 const char *type, const char *value,
			 const char *data, size_t data_len)
{
  SshIkev2PMPreSharedKeyItem item;
  char id_buffer[128];

  memset(id_buffer, 0, sizeof(id_buffer));

  if (!d_pad_str_to_key(type, value, id_buffer, sizeof(id_buffer)))
    return FALSE;

  if (ssh_adt_strmap_exists(mapping, id_buffer))
    {
      SshADTHandle h;
      SshIkev2PMPreSharedKeyItem old_item;

      SSH_DEBUG(SSH_D_UNCOMMON, ("Overwriting old key %s", id_buffer));

      h = ssh_adt_get_handle_to_equal(mapping, id_buffer);
      SSH_ASSERT(h != SSH_ADT_INVALID);
      old_item = ssh_adt_map_lookup(mapping, h);
      ssh_xfree(old_item->data);
      ssh_xfree(old_item);
      ssh_adt_strmap_remove(mapping, id_buffer);
    }
  SSH_DEBUG(SSH_D_LOWOK, ("Adding key %s with value %s, len = %d",
			  id_buffer, data, data_len));
  item = ssh_xcalloc(1, sizeof(*item));
  item->data = ssh_xmemdup(data, data_len);
  item->data_len = data_len;
  ssh_adt_strmap_add(mapping, id_buffer, item);
  return TRUE;
}

Boolean ikev2_add_item(SshADTContainer mapping,
		       const char *type, char *value,
		       const char *certificate, size_t certificate_len,
		       SshPrivateKey private_key)
{
  SshIkev2PMPrivateKeyItem item;
  char id_buffer[128];

  memset(id_buffer, 0, sizeof(id_buffer));

  if (!d_pad_str_to_key(type, value, id_buffer, sizeof(id_buffer)))
    return FALSE;

  if (ssh_adt_strmap_exists(mapping, id_buffer))
    {
      SshIkev2PMPrivateKeyItem old_item;
      SshADTHandle h;

      SSH_DEBUG(SSH_D_UNCOMMON, ("Overwriting old key %s", id_buffer));

      h = ssh_adt_get_handle_to_equal(mapping, id_buffer);
      SSH_ASSERT(h != SSH_ADT_INVALID);
      old_item = ssh_adt_map_lookup(mapping, h);
      ssh_xfree(old_item->certificate);
      ssh_private_key_free(old_item->key);
      ssh_xfree(old_item);
      ssh_adt_strmap_remove(mapping, id_buffer);
    }
  SSH_DEBUG(SSH_D_LOWOK, ("Adding key %s", id_buffer));
  item = ssh_xcalloc(1, sizeof(*item));
  item->certificate = ssh_xmemdup(certificate, certificate_len);
  item->certificate_len = certificate_len;
  if (ssh_private_key_copy(private_key, &item->key) != SSH_CRYPTO_OK)
    ssh_fatal("ssh_private_key_copy failed");

  ssh_adt_strmap_add(mapping, id_buffer, item);
  return TRUE;
}

void ikev2_destroy_strings(SshADTContainer mapping)
{
  SshIkev2PMPreSharedKeyItem item;
  SshADTHandle h;

  for (h = ssh_adt_enumerate_start(mapping);
      h != SSH_ADT_INVALID;
      h = ssh_adt_enumerate_next(mapping, h))
    {
      item = ssh_adt_map_lookup(mapping, h);
      ssh_xfree(item->data);
      ssh_xfree(item);
    }
  ssh_adt_destroy(mapping);
}

void ikev2_destroy_items(SshADTContainer mapping)
{
  SshIkev2PMPrivateKeyItem item;
  SshADTHandle h;

  for (h = ssh_adt_enumerate_start(mapping);
      h != SSH_ADT_INVALID;
      h = ssh_adt_enumerate_next(mapping, h))
    {
      item = ssh_adt_map_lookup(mapping, h);
      ssh_xfree(item->certificate);
      ssh_private_key_free(item->key);
      ssh_xfree(item);
    }
  ssh_adt_destroy(mapping);

  return;
}

void d_pad_destroy_pre_shared_key_item(void *key, void *value)
{
  if (value)
    ssh_xfree(((SshIkev2PMPreSharedKeyItem) value)->data);
}

void d_pad_destroy_private_key_item(void *key, void *value)
{
  if (value)
    {
      ssh_xfree(((SshIkev2PMPrivateKeyItem) value)->certificate);
      ssh_private_key_free(((SshIkev2PMPrivateKeyItem) value)->key);
    }
}

void d_pad_save_local_id(const char *type, char *value)
{
  /* Save local id */
  if (strcmp(type, "ip") == 0 ||
      strcmp(type, ssh_ikev2_id_to_string(SSH_IKEV2_ID_TYPE_IPV4_ADDR)) == 0 ||
      strcmp(type, ssh_ikev2_id_to_string(SSH_IKEV2_ID_TYPE_IPV6_ADDR)) == 0)
    {
      unsigned char buf[32];
      d_pad_local_id_data_size[d_pad_local_id_count] = sizeof(buf);
      if (!ssh_inet_strtobin(value, buf,
			     &d_pad_local_id_data_size[d_pad_local_id_count]))
	return;
      if (d_pad_local_id_data_size[d_pad_local_id_count] == 4)
	d_pad_local_id_type[d_pad_local_id_count] =
	  SSH_IKEV2_ID_TYPE_IPV4_ADDR;
      else if (d_pad_local_id_data_size[d_pad_local_id_count] == 16)
	d_pad_local_id_type[d_pad_local_id_count] =
	  SSH_IKEV2_ID_TYPE_IPV6_ADDR;
      else
	return;

      d_pad_local_id_data[d_pad_local_id_count] =
	ssh_xmemdup(buf, d_pad_local_id_data_size[d_pad_local_id_count]);
    }
  else if (strcmp(type, ssh_ikev2_id_to_string(SSH_IKEV2_ID_TYPE_RFC822_ADDR))
	   == 0)
    {
      d_pad_local_id_type[d_pad_local_id_count] =
	SSH_IKEV2_ID_TYPE_RFC822_ADDR;
      d_pad_local_id_data_size[d_pad_local_id_count] = strlen(value);
      d_pad_local_id_data[d_pad_local_id_count] = ssh_xstrdup(value);
    }
  else if (strcmp(type, ssh_ikev2_id_to_string(SSH_IKEV2_ID_TYPE_FQDN)) == 0)
    {
      d_pad_local_id_type[d_pad_local_id_count] = SSH_IKEV2_ID_TYPE_FQDN;
      d_pad_local_id_data_size[d_pad_local_id_count] = strlen(value);
      d_pad_local_id_data[d_pad_local_id_count] = ssh_xstrdup(value);
    }
  else if (strcmp(type, ssh_ikev2_id_to_string(SSH_IKEV2_ID_TYPE_KEY_ID)) == 0)
    {
      d_pad_local_id_type[d_pad_local_id_count] = SSH_IKEV2_ID_TYPE_KEY_ID;
      d_pad_local_id_data_size[d_pad_local_id_count] = strlen(value);
      d_pad_local_id_data[d_pad_local_id_count] = ssh_xstrdup(value);
    }
  else
    return;
  d_pad_local_id_count++;
  return;
}

#define BUF_SIZE 1024

Boolean read_config_file(const char *file,
                         const char *local_ip_txt,
                         Boolean no_crls,
                         const char *ldap_server)
{
  FILE *fp = NULL;
  int i;
  char *buffer;
  char *key, *p, *value;
  char *environment_name = NULL;
  char **keys;
  char **values;
  int number_of_keys;
#ifdef SSHDIST_IKE_CERT_AUTH
  unsigned char *tmp;
  size_t len;
  SshCMLocalNetworkStruct local_network;
  SshCMConfig cm_config = NULL;
#endif /* SSHDIST_IKE_CERT_AUTH */

  buffer = ssh_xmalloc(BUF_SIZE);
  keys = ssh_xmalloc(MAX_KEYS * sizeof(char *));
  values = ssh_xmalloc(MAX_KEYS * sizeof(char *));

  number_of_keys = 0;

  /* XXX: the following strmaps are initialized so that the map values
     will never be destroyed properly.  if this is a problem,
     ssh_adt_xcreate_strmap() must be used instead (see
     "sshadt_{strmap,conf}.h").  */

  pre_shared_key_cache->mapping =
    ssh_adt_xcreate_strmap(NULL, d_pad_destroy_pre_shared_key_item);
  private_key_cache->rsa_mapping =
    ssh_adt_xcreate_strmap(NULL, d_pad_destroy_private_key_item);
  private_key_cache->dss_mapping =
    ssh_adt_xcreate_strmap(NULL, d_pad_destroy_private_key_item);
  private_key_cache->ecdss_mapping =
    ssh_adt_xcreate_strmap(NULL, d_pad_destroy_private_key_item);

#ifdef SSHDIST_IKE_CERT_AUTH
  cm_config = ssh_cm_config_allocate();
  if (cm_config == NULL)
    {
    error:
      if (global_cert_cache) ssh_cm_free(global_cert_cache);
      return FALSE;
    }
#if 0
  ssh_cm_config_set_notify_callbacks(cm_config,
                                     ssh_ike_revoke_notify_cb,
                                     NULL);
#endif
  ssh_cm_config_set_default_time_lock(cm_config, 300);
  ssh_cm_config_set_max_path_length(cm_config, 100);
  ssh_cm_config_set_max_restarts(cm_config, 300);
  ssh_cm_config_set_validity_secs(cm_config, 300);
  ssh_cm_config_set_crl_validity_secs(cm_config, 300, 300);
  ssh_cm_config_set_nega_cache_invalid_secs(cm_config, 300);

  global_cert_cache = ssh_cm_allocate(cm_config);
  cm_config = NULL;
  if (global_cert_cache == NULL)
    goto error;

  memset(&local_network, 0, sizeof(local_network));
  local_network.socks = getenv("SSH_SOCKS_SERVER");
  if (getenv("http_proxy"))
    local_network.proxy = getenv("http_proxy");
  local_network.timeout_msecs = 10*1000; /* 10 seconds. */

  ssh_cm_edb_set_local_network((void *) global_cert_cache,
                               &local_network);
  ssh_cm_edb_ldap_init((void *) global_cert_cache, ldap_server);
  ssh_cm_edb_http_init((void *) global_cert_cache);
#endif /* SSHDIST_IKE_CERT_AUTH */

  SSH_DEBUG(SSH_D_HIGHSTART,
	    ("Reading certificate cache config from %s", file));
  fp = fopen(file, "rb");
  if (fp == NULL)
    {
      char filename[128], *srcdir;

      srcdir = getenv("srcdir");
      if (srcdir == NULL)
	ssh_fatal("Cannot perform testing: $srcdir undefined.");
      ssh_snprintf(filename, sizeof(filename), "%s/%s", srcdir, file);
      fp = fopen(filename, "rb");
      if (fp == NULL)
	{
	  printf("read_cert_cache_file: cannot read non-existing file %s.\n",
		 file);
	  ssh_xfree(buffer);
	  ssh_xfree(keys);
	  ssh_xfree(values);
	  return TRUE;
	}
    }

  while (1)
    {
      fgets(buffer, BUF_SIZE, fp);

      if (feof(fp))
        {
          strcpy(buffer, "[end]");
        }

      for (key = buffer; *key && isspace((unsigned char) *key); key++)
        ;
      if (*key == '#' || !*key)
        continue;
      for (p = key; *p && !isspace((unsigned char) *p); p++)
        ;
      if (*p)
        {
          *p++ = '\0';
          for (; *p && isspace((unsigned char) *p); p++)
            ;
        }
      if (*key == '[')
        {
          /* New environment */
          if (environment_name)
            {
              /* Store previous environment */
              if (strcmp(environment_name, "[ca]") == 0)
                {
#ifdef SSHDIST_IKE_CERT_AUTH
                  SshCMCertificate cert;

                  for (i = 0; i < number_of_keys; i++)
                    {
                      char *filename;

                      filename = values[i];

                      SSH_DEBUG(SSH_D_LOWOK,
				("Adding ca certificate %s", filename));
                      if (strcmp(keys[i], "certificate") == 0)
                        {
                          if (!ssh_read_gen_file(filename, &tmp, &len))
			    ssh_fatal("Could not read file %s", filename);
                        }
		      else
			{
			  ssh_fatal("Unknown key %s in [ca] environment",
				    keys[i]);
			}

                      if (len == 0)
			ssh_fatal("read returned error");

                      cert = ssh_cm_cert_allocate(global_cert_cache);
                      if (cert == NULL)
			ssh_fatal("ssh_cm_cert_allocate failed");
                      if (ssh_cm_cert_set_ber(cert, tmp, len) !=
                          SSH_CM_STATUS_OK)
			ssh_fatal("ssh_cm_cert_set_ber failed");

                      if (ssh_cm_cert_force_trusted(cert) != SSH_CM_STATUS_OK)
			ssh_fatal("ssh_cm_cert_force_trusted failed");

                      if (no_crls)
                        if (ssh_cm_cert_non_crl_issuer(cert) !=
                            SSH_CM_STATUS_OK)
			  ssh_fatal("ssh_cm_cert_non_crl_issuer failed");

                      if (ssh_cm_cert_set_locked(cert) != SSH_CM_STATUS_OK)
			ssh_fatal("ssh_cm_cert_set_locked failed");

                      if (ssh_cm_add(cert) != SSH_CM_STATUS_OK)
			ssh_fatal("ssh_cm_add failed");

                      ssh_xfree(tmp);
                    }
#endif /* SSHDIST_IKE_CERT_AUTH */
                }
              else if (strcmp(environment_name, "[rsa-key]") == 0 ||
#ifdef SSHDIST_CRYPT_ECP
                       strcmp(environment_name, "[dsa-key]") == 0 ||
#endif /* SSHDIST_CRYPT_ECP */
		       strcmp(environment_name, "[ecdsa-key]") == 0)
                {
#ifdef SSHDIST_IKE_CERT_AUTH
                  char *filename, *certificate;
                  SshADTContainer mapping;
                  SshPrivateKey private_key;
                  SshCMCertificate cert;
		  unsigned char *kid;

                  if (strcmp(environment_name, "[rsa-key]") == 0)
                    mapping = private_key_cache->rsa_mapping;
                  else if (strcmp(environment_name, "[dsa-key]") == 0)
                    mapping = private_key_cache->dss_mapping;
#ifdef SSHDIST_CRYPT_ECP
		  else if (strcmp(environment_name, "[ecdsa-key]") == 0)
                    mapping = private_key_cache->ecdss_mapping;
#endif /* SSHDIST_CRYPT_ECP */
                  else
                    mapping = NULL;

                  filename = NULL;
                  certificate = NULL;
                  for (i = 0; i < number_of_keys; i++)
                    {
                      if (strcmp(keys[i], "private-key") == 0)
                        {
                          if (filename)
                            ssh_fatal("Private key given twice in "
                                      "the %s environment", environment_name);
                          filename = values[i];
                        }
                      else if (strcmp(keys[i], "certificate") == 0)
                        {
                          if (certificate)
                            ssh_fatal("certificate given twice in "
                                      "the %s environment", environment_name);
                          certificate = values[i];
                        }
                    }
                  if (!filename)
                    ssh_fatal("No private key given for %s environment",
                              environment_name);

                  if (!certificate)
                    ssh_fatal("No certificate given for %s environment",
                              environment_name);

                  SSH_DEBUG(SSH_D_LOWOK, ("Adding private key %s", filename));
		  if (!ssh_read_gen_file(filename, &tmp, &len))
		    ssh_fatal("Could not read file %s", filename);
                  if (len == 0)
		    ssh_fatal("read returned error");
                  private_key = ssh_x509_decode_private_key(tmp, len);
                  if (private_key == NULL)
		    ssh_fatal("ssh_x509_decode_private_key failed");
                  ssh_xfree(tmp);

                  SSH_DEBUG(SSH_D_LOWOK,
			    ("Adding certificate %s", certificate));
		  if (!ssh_read_gen_file(certificate, &tmp, &len))
		    ssh_fatal("Could not read binary file %s", filename);
                  if (len == 0)
		    ssh_fatal("read returned error");

                  cert = ssh_cm_cert_allocate(global_cert_cache);
                  if (cert == NULL)
		    ssh_fatal("ssh_cm_cert_allocate failed");

                  if (ssh_cm_cert_set_ber(cert, tmp, len) != SSH_CM_STATUS_OK)
		    ssh_fatal("ssh_cm_cert_set_ber failed");

                  if (ssh_cm_cert_set_locked(cert) != SSH_CM_STATUS_OK)
		    ssh_fatal("ssh_cm_cert_set_locked failed");

		  kid = d_pad_compute_key_id(cert);
		  if (kid == NULL)
		    ssh_fatal("d_pad_compute_key_id failed");

		  ikev2_add_item(mapping, "hash", kid, tmp, len, private_key);
		  ssh_free(kid);

                  if (ssh_cm_add(cert) != SSH_CM_STATUS_OK)
		    ssh_fatal("ssh_cm_add failed");


                  for (i = 0; i < number_of_keys; i++)
                    {
                      /* This will add the valid keys to the database, rest
                         are ignored. */
                      ikev2_add_item(mapping, keys[i], values[i],
				     tmp, len, private_key);
		      d_pad_save_local_id(keys[i], values[i]);
		    }

                  ssh_private_key_free(private_key);
                  ssh_xfree(tmp);
#endif /* SSHDIST_IKE_CERT_AUTH */
                }
              else if (strcmp(environment_name, "[pre-shared-key]") == 0)
                {
                  char *pre_shared_key;
		  size_t pre_shared_key_len = 0;

                  pre_shared_key = NULL;
                  for (i = 0; i < number_of_keys; i++)
                    {
                      if (strcmp(keys[i], "key") == 0)
                        {
                          if (pre_shared_key)
                            ssh_fatal("Pre shared key given twice in "
                                      "the %s environment", environment_name);
                          pre_shared_key = values[i];
			  pre_shared_key_len = strlen(pre_shared_key);
                        }
                      if (strcmp(keys[i], "hexkey") == 0)
                        {
			  int j;
                          if (pre_shared_key)
                            ssh_fatal("Pre shared key given twice in "
                                      "the %s environment", environment_name);
			  pre_shared_key_len = strlen(values[i]);
			  if (pre_shared_key_len % 2 == 1)
                            ssh_fatal("Pre shared hexkey has invalid "
				      "length %d in "
                                      "the %s environment",
				      pre_shared_key_len,
				      environment_name);
#define HEX(CH)                                                          \
      (((CH) >= '0' && (CH) <= '9') ? ((CH) - '0' ) : \
         (tolower((unsigned char) (CH)) - 'a' + 10))
			  for(j = 0; j < pre_shared_key_len / 2; j++)
			    {
			      values[i][j] = HEX(values[i][j * 2]) << 4 |
				HEX(values[i][j * 2 + 1]);
			    }
			  pre_shared_key = values[i];
			  pre_shared_key_len /= 2;

			}
                    }
                  if (!pre_shared_key)
                    ssh_fatal("No pre shared key key given for %s environment",
                              environment_name);

                  for (i = 0; i < number_of_keys; i++)
                    {
                      /* This will add valid keys to the db, rest are
                         ignored. */
                      ikev2_add_string(pre_shared_key_cache->mapping,
				       keys[i], values[i], pre_shared_key,
				       pre_shared_key_len);
		      d_pad_save_local_id(keys[i], values[i]);
		    }
                }
              else if (strcmp(environment_name, "[certificates]") == 0)
                {
#ifdef SSHDIST_IKE_CERT_AUTH
                  for (i = 0; i < number_of_keys; i++)
                    {
                      SshCMCertificate cert;

                      SSH_DEBUG(SSH_D_LOWOK,
				("Adding certificate %s", values[i]));
                      if (strcmp(keys[i], "certificate") == 0)
                        {
                          if (!ssh_read_gen_file(values[i], &tmp, &len))
			    ssh_fatal("Could not binary file %s",
				      values[i]);
                        }
		      else
			{
			  ssh_fatal("Unknown key %s in [certificates] "
				    "environment",
				    keys[i]);
                        }

                      if (len == 0)
			ssh_fatal("read returned error");

                      cert = ssh_cm_cert_allocate(global_cert_cache);
                      if (cert == NULL)
			ssh_fatal("ssh_cm_cert_allocate failed");

                      if (ssh_cm_cert_set_ber(cert, tmp, len) !=
			  SSH_CM_STATUS_OK)
			ssh_fatal("ssh_cm_cert_set_ber failed");

                      if (ssh_cm_cert_set_locked(cert) != SSH_CM_STATUS_OK)
			ssh_fatal("ssh_cm_cert_set_locked failed");

                      if (ssh_cm_add(cert) != SSH_CM_STATUS_OK)
			ssh_fatal("ssh_cm_add failed");
                      ssh_xfree(tmp);
		    }
#endif /* SSHDIST_IKE_CERT_AUTH */
		}
              else
                {
                  ssh_fatal("Unknown environment name : %s", environment_name);
                }
              ssh_xfree(environment_name);
              environment_name = NULL;
            }
          for (i = 0; i < number_of_keys; i++)
            {
              ssh_xfree(keys[i]);
              ssh_xfree(values[i]);
            }
          number_of_keys = 0;
          if (feof(fp))
            break;
          environment_name = ssh_xstrdup(key);
          continue;
        }
      if (*p++ != '=')
        ssh_fatal("Syntax error in cert config file waiting for '='");
      for (; *p && isspace((unsigned char) *p); p++)
        ;
      for (value = p; *p && !isspace((unsigned char) *p); p++)
        ;
      *p = '\0';
      keys[number_of_keys] = ssh_xstrdup(key);
      values[number_of_keys] = ssh_xstrdup(value);
      number_of_keys++;
    }
  fclose(fp);
  ssh_xfree(buffer);
  ssh_xfree(keys);
  ssh_xfree(values);
  return TRUE;
}

/************************ Initialisation & destruction ***********************/

int d_pad_allocate(const unsigned char *cert_config)
{
  pre_shared_key_cache = ssh_xcalloc(1, sizeof(*pre_shared_key_cache));
  private_key_cache = ssh_xcalloc(1, sizeof(*private_key_cache));

  if (cert_config && !read_config_file(cert_config, NULL, TRUE, NULL))
    {
      SSH_DEBUG(SSH_D_ERROR, ("Could not read certificate config file %s\n",
			      cert_config));
      return FALSE;
    }

  return TRUE;
}

void d_pad_destroy()
{
  SSH_DEBUG(SSH_D_HIGHSTART, ("d_pad_destroy"));

  if (private_key_cache)
    {
      if (private_key_cache->rsa_mapping)
	ikev2_destroy_items(private_key_cache->rsa_mapping);
      if (private_key_cache->dss_mapping)
	ikev2_destroy_items(private_key_cache->dss_mapping);
      if (private_key_cache->ecdss_mapping)
	ikev2_destroy_items(private_key_cache->ecdss_mapping);
      ssh_xfree(private_key_cache);
    }

  if (pre_shared_key_cache)
    {
      if (pre_shared_key_cache->mapping)
	ikev2_destroy_strings(pre_shared_key_cache->mapping);
      ssh_xfree(pre_shared_key_cache);
    }

#ifdef SSHDIST_IKE_CERT_AUTH
  if (global_cert_cache)
    ssh_cm_free(global_cert_cache);

  if (d_pad_certificate_authority)
    ssh_xfree(d_pad_certificate_authority);
#endif /* SSHDIST_IKE_CERT_AUTH */

  for (; d_pad_local_id_count > 0; d_pad_local_id_count--)
    {
      if (d_pad_local_id_data[d_pad_local_id_count-1])
	ssh_xfree(d_pad_local_id_data[d_pad_local_id_count-1]);
    }
}

/******************************** PAD functions ******************************/

/* Connection processing */
SshOperationHandle
d_pad_new_connection(SshSADHandle sad_handle,
		     SshIkev2Server server,
		     SshUInt8 major, SshUInt8 minor,
		     SshIpAddr remote_address,
		     SshUInt16 port,
		     SshIkev2PadNewConnectionCB reply_callback,
		     void *reply_callback_context)
{
  SshIkev2Error status = SSH_IKEV2_ERROR_OK;

  SSH_DEBUG(SSH_D_HIGHSTART, ("Enter"));

  (*reply_callback)(status,
		    reply_callback_context);

  return NULL;
}

#ifdef SSH_IKEV2_MULTIPLE_AUTH
/* Hard-coded second authentication identity */
SshIkev2IDType second_id_type = SSH_IKEV2_ID_TYPE_FQDN;
unsigned char second_id_data[6] = 
  {0x73, 0x65, 0x63, 0x6f, 0x6e, 0x64}; /* "second"*/
size_t second_id_data_size = 6;
#endif /* SSH_IKEV2_MULTIPLE_AUTH */

/* ID processing */

SshOperationHandle
d_pad_id(SshSADHandle sad_handle,
	 SshIkev2ExchangeData ed,
	 Boolean local,
#ifdef SSH_IKEV2_MULTIPLE_AUTH
         SshUInt32 authentication_round,
#endif /* SSH_IKEV2_MULTIPLE_AUTH */
	 SshIkev2PadIDCB reply_callback,
	 void *reply_callback_context)
{
  SshIkev2Error status = SSH_IKEV2_ERROR_OK;
  SshIkev2PayloadIDStruct id, *pid;
#ifdef SSH_IKEV2_MULTIPLE_AUTH
  Boolean another_id_follows;

  if (use_multiple_auth && authentication_round == 1)
    another_id_follows = TRUE;
  else
    another_id_follows = FALSE;

#endif /* SSH_IKEV2_MULTIPLE_AUTH */

  SSH_DEBUG(SSH_D_HIGHSTART, ("Enter SA %p ED %p", ed->ike_sa, ed));

  if (local)
    {
#ifdef SSH_IKEV2_MULTIPLE_AUTH
      if (authentication_round == 2)
        {
          id.id_type = second_id_type;
          id.id_data = second_id_data;
          id.id_data_size = second_id_data_size;
        }
      else
#endif /* SSH_IKEV2_MULTIPLE_AUTH */
        {
          id.id_type = d_pad_local_id_type[0];
          id.id_data = d_pad_local_id_data[0];
          id.id_data_size = d_pad_local_id_data_size[0];
        }

      pid = &id;
    }

  else
    {
      pid = NULL;
    }

  (*reply_callback)(status,
		    local,
#ifdef SSH_IKEV2_MULTIPLE_AUTH
                    another_id_follows,
#endif /* SSH_IKEV2_MULTIPLE_AUTH */
                    pid,
		    reply_callback_context);

  return NULL;
}

#ifdef SSHDIST_IKE_CERT_AUTH
void d_pad_cert_get_cas_enumerate_cb(SshCMCertificate cert,
				     void *context)
{
  SshBuffer buffer = context;
  unsigned char *kid;

  kid = d_pad_compute_key_id(cert);
  if (kid == NULL)
    return;

  ssh_buffer_append(buffer, kid, 20);
  ssh_xfree(kid);
}

SshOperationHandle
d_pad_get_cas(SshSADHandle sad_handle,
	      SshIkev2ExchangeData ed,
	      SshIkev2PadGetCAsCB reply_callback,
	      void *reply_callback_context)
{
  SshIkev2Error status = SSH_IKEV2_ERROR_OK;
  SshIkev2CertEncoding enc = SSH_IKEV2_CERT_X_509;
  const unsigned char *ca_authority_data;
  size_t ca_authority_size;
  SshBufferStruct buffer[1];

  SSH_DEBUG(SSH_D_HIGHSTART, ("Enter SA %p ED %p", ed->ike_sa, ed));

  if (!use_certs)
    {
      (*reply_callback)(status,
			0,
			NULL,
			NULL,
			NULL,
			reply_callback_context);
      return NULL;
    }

  ssh_buffer_init(buffer);

  if (ssh_cm_cert_enumerate_class(global_cert_cache,
				  SSH_CM_CCLASS_TRUSTED,
				  d_pad_cert_get_cas_enumerate_cb,
				  buffer) != SSH_CM_STATUS_OK)
    {
      ssh_buffer_uninit(buffer);
      return NULL;
    }
  ca_authority_data = ssh_buffer_ptr(buffer);
  ca_authority_size = ssh_buffer_len(buffer);

  (*reply_callback)(status,
		    1,
		    &enc,
		    &ca_authority_data,
		    &ca_authority_size,
		    reply_callback_context);
  ssh_buffer_uninit(buffer);

  return NULL;
}

#define D_PAD_MAX_CERTS         256

struct DPadFindCertsContextData
{
  SshCMContext cm;
  SshIkev2Error error_code;
  SshPrivateKey private_key_out;
  int number_of_certificates;
  SshIkev2CertEncoding cert_encs[D_PAD_MAX_CERTS];
  unsigned char *certs[D_PAD_MAX_CERTS];
  size_t cert_lengths[D_PAD_MAX_CERTS];
};



#ifdef SSHDIST_CRYPT_ECP
Boolean get_ecp_key_scheme(void * key,
			   Boolean is_public,
			   const char ** scheme)
{
  const char *sig_scheme = NULL;
  Boolean rv = FALSE;
  SshMPIntegerStruct p;
  size_t field_len;
  ssh_mprz_init(&p);

  if (is_public)
    {
      if (ssh_public_key_get_info((SshPublicKey)key,
                                  SSH_PKF_PRIME_P, &p,
                                  SSH_PKF_END) != SSH_CRYPTO_OK)
        goto fail;
    }
  else
    {
      if (ssh_private_key_get_info((SshPrivateKey)key,
                                   SSH_PKF_PRIME_P, &p,
                                   SSH_PKF_END) != SSH_CRYPTO_OK)
        goto fail; 
    }

  field_len = ssh_mprz_byte_size(&p);
  if (field_len == 32) /* 256 bit curve */
    {
#ifdef SSHDIST_CRYPT_SHA256
      sig_scheme = "dsa-none-sha256";
#endif /* SSHDIST_CRYPT_SHA256 */
    }
  else if (field_len == 48) /* 384 bit curve */ 
    {
#ifdef SSHDIST_CRYPT_SHA512
      sig_scheme = "dsa-none-sha384";
#endif /* SSHDIST_CRYPT_SHA512 */
    }
  else if (field_len == 66) /* 521 bit curve */
    {
#ifdef SSHDIST_CRYPT_SHA512
      sig_scheme = "dsa-none-sha512";
#endif /* SSHDIST_CRYPT_SHA512 */
    }
  *scheme = sig_scheme;
  if (sig_scheme != NULL)
    rv = TRUE;
fail:
  ssh_mprz_clear(&p);
  return rv;
}
#endif /* SSHDIST_CRYPT_ECP */


void d_pad_get_certificates_find_path_cb(void *context,
					 SshCMSearchInfo info,
					 SshCMCertList list)
{
  SshCMCertificate cert = NULL;
  unsigned char *ber;
  size_t ber_len = 0;
  struct DPadFindCertsContextData *find_data =
    (struct DPadFindCertsContextData *) context;

  if (list == NULL)
    {
      SSH_DEBUG(SSH_D_ERROR, ("list is NULL"));
      return;
    }

  if (!ssh_cm_cert_list_empty(list))
    {
      unsigned char *kid, keybuffer[64];
      SshADTContainer mapping;
      SshADTHandle h;
      SshIkev2PMPrivateKeyItem item;
      int key_type = 0; /* 1 = rsa, 2 = dsa, 3 = ecdsa */

      /* Lookup private key for end user certificate */
      cert = ssh_cm_cert_list_last(list);
      kid = d_pad_compute_key_id(cert);
      if (!d_pad_str_to_key("hash", kid, keybuffer, sizeof(keybuffer)))
	{
	  ssh_xfree(kid);
	  goto error;
	}
      ssh_xfree(kid);
      mapping = private_key_cache->rsa_mapping;
      key_type = 1;
      h = ssh_adt_get_handle_to_equal(mapping, keybuffer);
      if (h == SSH_ADT_INVALID)
	{
	  mapping = private_key_cache->dss_mapping;
	  key_type = 2;
	}
      h = ssh_adt_get_handle_to_equal(mapping, keybuffer);
      if (h == SSH_ADT_INVALID)
	{
	  mapping = private_key_cache->ecdss_mapping;
	  key_type = 3;
	}
      h = ssh_adt_get_handle_to_equal(mapping, keybuffer);
      if (h == SSH_ADT_INVALID)
	{
	  SSH_DEBUG(SSH_D_ERROR,
		    ("Unable to find private key for x509 certificate %s",
		     kid));
	  goto error;
	}
      item = ssh_adt_map_lookup(mapping, h);
      if (ssh_private_key_copy(item->key, &find_data->private_key_out)
	  != SSH_CRYPTO_OK)
	{
	  SSH_DEBUG(SSH_D_ERROR, ("Unable to copy private key"));
	  goto error;
	}
      if (key_type == 1) /* rsa */
	{
	  if (ssh_private_key_select_scheme(find_data->private_key_out,
					    SSH_PKF_SIGN,
					    "rsa-pkcs1-sha1",
					    SSH_PKF_END) != SSH_CRYPTO_OK)
	    {
	      SSH_DEBUG(SSH_D_ERROR, ("Unable to set scheme for private key"));
	      goto error;
	    }
	}
      else if (key_type == 2) /* dsa */
	{
	  if (ssh_private_key_select_scheme(find_data->private_key_out,
					    SSH_PKF_SIGN,
					    "dsa-nist-sha1",
					    SSH_PKF_END) != SSH_CRYPTO_OK)
	    {
	      SSH_DEBUG(SSH_D_ERROR, ("Unable to set scheme for private key"));
	      goto error;
	    }
	}
      else if (key_type == 3) /* ecdsa */
	{
	  const char *scheme;
	  if (!get_ecp_key_scheme(find_data->private_key_out, FALSE, &scheme))
	    {
	      SSH_DEBUG(SSH_D_FAIL,
			("Unable to get the applicable private key scheme"));
	      goto error;
	    }
	  if (ssh_private_key_select_scheme(find_data->private_key_out,
					    SSH_PKF_SIGN,
					    scheme,
					    SSH_PKF_END) != SSH_CRYPTO_OK)
	    {
	      SSH_DEBUG(SSH_D_ERROR, ("Unable to set scheme for private key"));
	      goto error;
	    }
	}
    }

  while (cert != NULL && find_data->number_of_certificates < D_PAD_MAX_CERTS)
    {
      if (ssh_cm_cert_get_ber(cert, &ber, &ber_len) != SSH_CM_STATUS_OK)
	{
	  SSH_DEBUG(SSH_D_ERROR,
		    ("unable to convert certificate to x509 ber format"));
	  find_data->error_code = SSH_IKEV2_ERROR_CRYPTO_FAIL;
	  break;
	}

      if (ber_len > 0)
	{
	  find_data->cert_encs[find_data->number_of_certificates] =
	    SSH_IKEV2_CERT_X_509;
	  find_data->certs[find_data->number_of_certificates] =
	    ssh_xmemdup(ber, ber_len);
	  find_data->cert_lengths[find_data->number_of_certificates] =
	    ber_len;
	  find_data->number_of_certificates++;
	}
      cert = ssh_cm_cert_list_prev(list);
    }

  /* Remove CA from the list */
  if (find_data->number_of_certificates > 1)
    {
      find_data->number_of_certificates--;
      ssh_xfree(find_data->certs[find_data->number_of_certificates]);
      find_data->certs[find_data->number_of_certificates] = NULL;
    }

 error:
  ssh_cm_cert_list_free(find_data->cm, list);
}

struct DPadFindCAContextData
{
  unsigned char *dn;
  size_t dn_len;
};

void d_pad_get_certificates_enumerate_cb(SshCMCertificate cert,
					 void *context)
{
  struct DPadFindCAContextData *find_data = context;
  unsigned char *kid = NULL;
  SshX509Certificate x509 = NULL;

  kid = d_pad_compute_key_id(cert);
  if (kid == NULL)
    return;

  if (memcmp(kid, d_pad_certificate_authority,
	     d_pad_certificate_authority_len) == 0)
    {
      ssh_cm_cert_get_x509(cert, &x509);
      ssh_x509_cert_get_subject_name_der(x509, &find_data->dn,
					 &find_data->dn_len);
    }

  if (find_data->dn == NULL)
    SSH_DEBUG(SSH_D_ERROR, ("Unable to find a suitable ca"));

  if (kid)
    ssh_xfree(kid);

  if (x509)
    ssh_x509_cert_free(x509);
}

SshOperationHandle
d_pad_get_certificates(SshSADHandle sad_handle,
		       SshIkev2ExchangeData ed,
		       SshIkev2PadGetCertificatesCB reply_callback,
		       void *reply_callback_context)
{
  struct DPadFindCertsContextData find_data;
  struct DPadFindCAContextData ca_find_data;
  SshCMSearchConstraints local_search;
  SshCertDBKey *local_key = NULL;
  SshCMSearchConstraints ca_search = NULL;
  SshCertDBKey *ca_key = NULL;
  SshIkev2PayloadID pid;
  SshIkev2Error error_code = SSH_IKEV2_ERROR_OK;
  int i;

  memset(&find_data, 0, sizeof(find_data));
  memset(&ca_find_data, 0, sizeof(ca_find_data));

  SSH_DEBUG(SSH_D_HIGHSTART, ("Enter SA %p ED %p", ed->ike_sa, ed));

  if (!use_certs)
    {
      (*reply_callback)(error_code,
			0,
			0,
			NULL,
			NULL,
			NULL,
			reply_callback_context);
      return NULL;
    }

  /* Fill in end certificate search constraints */

  local_search = ssh_cm_search_allocate();
  if (local_search == NULL)
    {
      error_code = SSH_IKEV2_ERROR_OUT_OF_MEMORY;
      goto error;
    }


  /* Check if we are initiator */
  if ((ed->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_INITIATOR) ==
      SSH_IKEV2_IKE_SA_FLAGS_INITIATOR)
    {
      pid = ed->ike_ed->id_i;
    }
  else
    {
      pid = ed->ike_ed->id_r;
    }

  if (pid->id_type == SSH_IKEV2_ID_TYPE_IPV4_ADDR ||
      pid->id_type == SSH_IKEV2_ID_TYPE_IPV6_ADDR)
    {
      SSH_DEBUG(SSH_D_MIDOK, ("SSH_IKEV2_ID_TYPE_IP_ADDR %p", pid->id_data));
      if (!ssh_cm_key_set_ip(&local_key, pid->id_data, pid->id_data_size))
	{
	  SSH_DEBUG(SSH_D_ERROR,
		    ("Unable to set search key for certificate lookup"));
	  error_code = SSH_IKEV2_ERROR_INVALID_ARGUMENT;
	  goto error;
	}
    }
  else if (pid->id_type == SSH_IKEV2_ID_TYPE_RFC822_ADDR)
    {
      SSH_DEBUG(SSH_D_MIDOK, ("SSH_IKEV2_ID_TYPE_RFC822_ADDR %.*s",
			      pid->id_data_size, pid->id_data));
      if (!ssh_cm_key_set_email(&local_key, pid->id_data, pid->id_data_size))
	{
	  SSH_DEBUG(SSH_D_ERROR,
		    ("Unable to set search key for certificate lookup"));
	  error_code = SSH_IKEV2_ERROR_INVALID_ARGUMENT;
	  goto error;
	}
    }
  else if (pid->id_type == SSH_IKEV2_ID_TYPE_FQDN)
    {
      SSH_DEBUG(SSH_D_MIDOK, ("SSH_IKEV2_ID_TYPE_FQDN %.*s",
			      pid->id_data_size, pid->id_data));
      if (!ssh_cm_key_set_dns(&local_key, pid->id_data, pid->id_data_size))
	{
	  SSH_DEBUG(SSH_D_ERROR,
		    ("Unable to set search key for certificate lookup"));
	  error_code = SSH_IKEV2_ERROR_INVALID_ARGUMENT;
	  goto error;
	}
    }
  else
    {
      SSH_DEBUG(SSH_D_ERROR,
		("Invalid payload id type in local certificate lookup"));
      error_code = SSH_IKEV2_ERROR_INVALID_ARGUMENT;
      goto error;
    }
  ssh_cm_search_set_keys(local_search, local_key);

  /* Fill in ca certificate search constraints */

  ca_search = ssh_cm_search_allocate();
  if (ca_search == NULL)
    {
      error_code = SSH_IKEV2_ERROR_OUT_OF_MEMORY;
      goto error;
    }

  if (d_pad_ca_encoding != SSH_IKEV2_CERT_X_509)
    {
      SSH_DEBUG(SSH_D_ERROR, ("XXX unable to lookup ca certificate"));
      error_code = SSH_IKEV2_ERROR_INVALID_ARGUMENT;
      goto error;
    }

  if (ssh_cm_cert_enumerate_class(global_cert_cache,
				  SSH_CM_CCLASS_TRUSTED,
				  d_pad_get_certificates_enumerate_cb,
				  &ca_find_data) != SSH_CM_STATUS_OK)
    {
      SSH_DEBUG(SSH_D_ERROR,
		("XXX unable to get ca cert dn for certificate lookup"));
      error_code = SSH_IKEV2_ERROR_INVALID_ARGUMENT;
      goto error;
    }

  ssh_cm_key_set_dn(&ca_key, ca_find_data.dn, ca_find_data.dn_len);
  ssh_cm_search_set_keys(ca_search, ca_key);

  /* Fill in context data for find_path callback */
  find_data.cm = global_cert_cache;
  find_data.error_code = SSH_IKEV2_ERROR_OK;

  /* Perform lookup */
  ssh_cm_find_path(global_cert_cache,
		   ca_search, local_search,
		   d_pad_get_certificates_find_path_cb, &find_data);

  SSH_DEBUG(SSH_D_MIDOK, ("private_key_out %p", find_data.private_key_out));

  /* Call cb func and cleanup */
  (*reply_callback)(find_data.error_code,
		    find_data.private_key_out,
		    find_data.number_of_certificates,
		    find_data.cert_encs,
		    (const unsigned char **) find_data.certs,
		    find_data.cert_lengths,
		    reply_callback_context);

  for (i = 0; i < D_PAD_MAX_CERTS; i++)
    {
      if (find_data.certs[i])
	ssh_xfree(find_data.certs[i]);
    }
  if (ca_find_data.dn)
    ssh_xfree(ca_find_data.dn);
  if (find_data.private_key_out)
    ssh_private_key_free(find_data.private_key_out);

  return NULL;

 error:
  if (local_search)
    ssh_cm_search_free(local_search);
  if (ca_search)
    ssh_cm_search_free(ca_search);
  if (ca_find_data.dn)
    ssh_xfree(ca_find_data.dn);
  if (find_data.private_key_out)
    ssh_private_key_free(find_data.private_key_out);

  (*reply_callback)(error_code,
		    0,
		    0,
		    NULL,
		    NULL,
		    NULL,
		    reply_callback_context);

  return NULL;
}

void
d_pad_new_certificate_request(SshSADHandle sad_handle,
			      SshIkev2ExchangeData ed,
			      SshIkev2CertEncoding ca_encoding,
			      const unsigned char *certificate_authority,
			      size_t certificate_authority_len)
{
  SSH_DEBUG(SSH_D_HIGHSTART, ("Enter SA %p ED %p", ed->ike_sa, ed));

  if (!use_certs)
    return;

  SSH_DEBUG(SSH_D_MIDOK, ("ca_encoding %d len %d certificate_authority %p",
			  ca_encoding,
			  certificate_authority_len,
			  certificate_authority));

  if (d_pad_certificate_authority)
    ssh_xfree(d_pad_certificate_authority);
  d_pad_certificate_authority =
    ssh_xmemdup(certificate_authority, certificate_authority_len);
  d_pad_certificate_authority_len = certificate_authority_len;
  d_pad_ca_encoding = ca_encoding;

  return;
}

 void d_pad_public_key_cb(void *context,
			  SshCMSearchInfo info,
			  SshCMCertList list)
{
  SshPublicKey *public_key = context;
  SshCMCertificate cert;
  SshX509Certificate x509 = NULL;
  const char * key_type;

  if (list == NULL)
    {
      SSH_DEBUG(SSH_D_ERROR, ("list is NULL"));
      return;
    }
  if (ssh_cm_cert_list_empty(list))
    {
      SSH_DEBUG(SSH_D_UNCOMMON, ("No certificate found"));
      goto error;
    }
  cert = ssh_cm_cert_list_last(list);
  if (cert == NULL)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Hummm..."));
      goto error;
    }
  if (ssh_cm_cert_get_x509(cert, &x509) != SSH_CM_STATUS_OK || x509 == NULL)
    {
      SSH_DEBUG(SSH_D_ERROR, ("cmi error"));
      goto error;
    }
  if (!ssh_x509_cert_get_public_key(x509, public_key))
    {
      SSH_DEBUG(SSH_D_ERROR,
		("Unable to get the public key from certificate"));
      goto error;
    }

  if (ssh_public_key_get_info(*public_key, 
                              SSH_PKF_KEY_TYPE, &key_type,
                              SSH_PKF_END) != SSH_CRYPTO_OK)
    {
      goto error;
    }

  if (strstr(key_type, "if-modn") != NULL)
    {
  if (ssh_public_key_select_scheme(*public_key,
				   SSH_PKF_SIGN,
				   "rsa-pkcs1-implicit",
				   SSH_PKF_END) != SSH_CRYPTO_OK)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Unable to set scheme for public key"));
          goto error;
        }
    }
  else if (strstr(key_type,"dl-modp") != NULL)
    { 
      if (ssh_public_key_select_scheme(*public_key,
				       SSH_PKF_SIGN,
				       "dsa-nist-sha1",
				       SSH_PKF_END) != SSH_CRYPTO_OK)
	{
	  SSH_DEBUG(SSH_D_ERROR, ("Unable to set scheme for public key"));
          goto error;
	}
    }
#ifdef SSHDIST_CRYPT_ECP
  else if (strstr(key_type, "ec-modp") != NULL)
    {
      const char * scheme;
      if ((!get_ecp_key_scheme(*public_key, TRUE, &scheme))
           || (ssh_public_key_select_scheme(*public_key,
                                            SSH_PKF_SIGN,
                                            scheme,
                                            SSH_PKF_END) != SSH_CRYPTO_OK))
        {
	  SSH_DEBUG(SSH_D_ERROR, ("Unable to set scheme for public key"));
          goto error;
        }
    }
#endif /* SSHDIST_CRYPT_ECP */

  /* cleanup */
 error:
  if (x509)
      ssh_x509_cert_free(x509);
  if (list)
    ssh_cm_cert_list_free(global_cert_cache, list);
}

SshOperationHandle
d_pad_public_key(SshSADHandle sad_handle,
		 SshIkev2ExchangeData ed,
		 SshIkev2PadPublicKeyCB reply_callback,
		 void *reply_callback_context)
{
  SshIkev2Error error_code = SSH_IKEV2_ERROR_OK;
  SshCMSearchConstraints search;
  SshCertDBKey *key = NULL;
  SshIkev2PayloadID pid;
  SshPublicKey public_key = NULL;

  SSH_DEBUG(SSH_D_HIGHSTART, ("Enter SA %p ED %p", ed->ike_sa, ed));

  if (!use_certs)
    {
      (*reply_callback)(error_code,
			NULL,
			reply_callback_context);
      return NULL;
    }

  /* fill in search constraints */
  search = ssh_cm_search_allocate();
  if (search == NULL)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Unable to allocate search constraints"));
      error_code = SSH_IKEV2_ERROR_OUT_OF_MEMORY;
      goto error;
    }

  /* Check if we are initiator */
  if ((ed->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_INITIATOR) ==
      SSH_IKEV2_IKE_SA_FLAGS_INITIATOR)
    {
      /* Yes, check if we have remote id set. */
      pid = ed->ike_ed->id_r;
      if (pid == NULL)
	{
	  /* No, we do not know yet to whom we are
	     talking to, so use our own local ID to
	     select our pre shared key.  */
	  pid = ed->ike_ed->id_i;
	}
    }
  else
    {
      /* For the responder we always use the remote
	 ID when selecting the key. */
      pid = ed->ike_ed->id_i;
    }

  if (pid->id_type == SSH_IKEV2_ID_TYPE_IPV4_ADDR ||
      pid->id_type == SSH_IKEV2_ID_TYPE_IPV6_ADDR)
    {
      SSH_DEBUG(SSH_D_MIDOK, ("SSH_IKEV2_ID_TYPE_IP_ADDR %p", pid->id_data));
      if (!ssh_cm_key_set_ip(&key, pid->id_data, pid->id_data_size))
        {
          SSH_DEBUG(SSH_D_ERROR,
		    ("Unable to set search key for certificate lookup"));
          error_code = SSH_IKEV2_ERROR_INVALID_ARGUMENT;
          goto error;
        }
    }
  else if (pid->id_type == SSH_IKEV2_ID_TYPE_RFC822_ADDR)
    {
      SSH_DEBUG(SSH_D_MIDOK, ("SSH_IKEV2_ID_TYPE_RFC822_ADDR %.*s",
			      pid->id_data_size, pid->id_data));
      if (!ssh_cm_key_set_email(&key, pid->id_data, pid->id_data_size))
        {
          SSH_DEBUG(SSH_D_ERROR,
		    ("Unable to set search key for certificate lookup"));
          error_code = SSH_IKEV2_ERROR_INVALID_ARGUMENT;
          goto error;
        }
    }
  else if (pid->id_type == SSH_IKEV2_ID_TYPE_FQDN)
    {
      SSH_DEBUG(SSH_D_MIDOK, ("SSH_IKEV2_ID_TYPE_FQDN %.*s",
			      pid->id_data_size, pid->id_data));
      if (!ssh_cm_key_set_dns(&key, pid->id_data, pid->id_data_size))
        {
          SSH_DEBUG(SSH_D_ERROR,
		    ("Unable to set search key for certificate lookup"));
          error_code = SSH_IKEV2_ERROR_INVALID_ARGUMENT;
          goto error;
        }
    }
  else
    {
      SSH_DEBUG(SSH_D_ERROR,
		("Invalid payload id type in local certificate lookup"));
      error_code = SSH_IKEV2_ERROR_INVALID_ARGUMENT;
      goto error;
    }
  ssh_cm_search_set_keys(search, key);

  /* Perform lookup */
  ssh_cm_find(global_cert_cache,
	      search,
	      d_pad_public_key_cb, &public_key);

  SSH_DEBUG(SSH_D_MIDOK, ("public_key %p", public_key));

  (*reply_callback)(error_code,
		    public_key,
		    reply_callback_context);

  if (public_key)
    ssh_public_key_free(public_key);

  return NULL;

 error:
  if (public_key)
    ssh_public_key_free(public_key);

  (*reply_callback)(error_code,
		    NULL,
		    reply_callback_context);

  return NULL;
}

void
d_pad_new_certificate(SshSADHandle sad_handle,
		      SshIkev2ExchangeData ed,
		      SshIkev2CertEncoding cert_encoding,
		      const unsigned char *cert_data,
		      size_t cert_data_len)
{
  SshCMCertificate cert;

  SSH_DEBUG(SSH_D_HIGHSTART, ("Enter SA %p ED %p", ed->ike_sa, ed));

  if (!use_certs)
    return;

  cert = ssh_cm_cert_allocate(global_cert_cache);
  if (cert == NULL)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Unable to allocate new certificate"));
      return;
    }
  if (cert_encoding != SSH_IKEV2_CERT_X_509)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Unable to handle new certificate"));
      ssh_cm_cert_free(cert);
      return;
    }
  if (ssh_cm_cert_set_ber(cert, cert_data, cert_data_len) != SSH_CM_STATUS_OK)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Unable to ssh_cm_set_ber on new certificate"));
      ssh_cm_cert_free(cert);
      return;
    }
  if (ssh_cm_add(cert) != SSH_CM_STATUS_OK)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Unable to add new certificate to cache"));
      ssh_cm_cert_free(cert);
    }
  return;
}
#endif /* SSHDIST_IKE_CERT_AUTH */

/* PSK processing */
SshOperationHandle
d_pad_shared_key(SshSADHandle sad_handle,
		 SshIkev2ExchangeData ed,
		 Boolean local,
		 SshIkev2PadSharedKeyCB reply_callback,
		 void *reply_callback_context)
{
  SshIkev2Error status = SSH_IKEV2_ERROR_OK;
  const char *psk = NULL;

  SSH_DEBUG(SSH_D_HIGHSTART, ("Enter SA %p ED %p", ed->ike_sa, ed));

#ifdef SSHDIST_IKE_EAP_AUTH
#ifdef SSHDIST_EAP
  if (use_eap && local 
      && (ed->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_INITIATOR))
    {
      /* To use EAP, the initiator omits the AUTH payload by
	 returning a NULL PSK. */
	psk = NULL;
    }
  else
#endif /* SSHDIST_EAP */
#endif /* SSHDIST_IKE_EAP_AUTH */
    {
      /* Lookup psk in the key cache */
      if (!use_certs || !local)
	{
	  SshIkev2PayloadID pid;
	  char id_buffer[128];
	  SshADTHandle h;
	  SshIkev2PMPreSharedKeyItem key_item;

	  /* Check if we are initiator */
	  if ((ed->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_INITIATOR) ==
	      SSH_IKEV2_IKE_SA_FLAGS_INITIATOR)
	    {
	      /* Yes, check if we have remote id set. */
	      pid = ed->ike_ed->id_r;
	      if (pid == NULL)
		{
		  /* No, we do not know yet to whom we are
		     talking to, so use our own local ID to
		     select our pre shared key.  */
		  pid = ed->ike_ed->id_i;
		}
	    }
	  else
	    {
	      /* For the responder we always use the remote
		 ID when selecting the key. */
	      pid = ed->ike_ed->id_i;
	    }

	  if (d_pad_pid_to_key(pid, id_buffer, sizeof(id_buffer)) == FALSE)
	    {
	      SSH_DEBUG(SSH_D_ERROR, ("Unable to find a matching shared key"));
	      goto error;
	    }
	  h = ssh_adt_get_handle_to_equal(pre_shared_key_cache->mapping,
					  id_buffer);
	  if (h == SSH_ADT_INVALID)
	    {
	      SSH_DEBUG(SSH_D_ERROR, ("Unable to find a matching shared key"));
	      goto error;
	    }
	  key_item = ssh_adt_map_lookup(pre_shared_key_cache->mapping, h);
	  (*reply_callback)(status,
			    key_item->data, key_item->data_len,
			    reply_callback_context);
	  return NULL;
	}
      else
	{
	  psk = NULL;
	}
    }

 error:
  (*reply_callback)(status,
		    psk, psk ? strlen(psk) : 0,
		    reply_callback_context);
  return NULL;
}

/* Configuration payload processing */
void
d_pad_conf_received(SshSADHandle sad_handle,
		    SshIkev2ExchangeData ed,
		    SshIkev2PayloadConf conf_payload_in)
{
  SSH_DEBUG(SSH_D_HIGHSTART, ("Enter SA %p ED %p", ed->ike_sa, ed));
  return;
}

SshOperationHandle
d_pad_conf_request(SshSADHandle sad_handle,
		   SshIkev2ExchangeData ed,
		   SshIkev2PadConfCB reply_callback,
		   void *reply_callback_context)
{
  SshIkev2Error status = SSH_IKEV2_ERROR_OK;

  SSH_DEBUG(SSH_D_HIGHSTART, ("Enter SA %p ED %p", ed->ike_sa, ed));

  (*reply_callback)(status,
		    NULL,
		    reply_callback_context);

  return NULL;
}

/* Vendor ID processing */
void
d_pad_vendor_id_received(SshSADHandle sad_handle,
			 SshIkev2ExchangeData ed,
			 const unsigned char *vendor_id,
			 size_t vendor_id_len)
{
  SSH_DEBUG(SSH_D_HIGHSTART, ("Enter SA %p ED %p", ed->ike_sa, ed));
  return;
}

SshOperationHandle
d_pad_vendor_id_request(SshSADHandle sad_handle,
			SshIkev2ExchangeData ed,
			SshIkev2PadAddVendorIDCB reply_callback,
			void *reply_callback_context)
{
  SshIkev2Error status = SSH_IKEV2_ERROR_OK;

  SSH_DEBUG(SSH_D_HIGHSTART, ("Enter SA %p ED %p", ed->ike_sa, ed));

  if (ed->ike_sa->initial_ed != ed &&
      ed->ike_ed != NULL &&
      ed->ike_ed->ni != NULL)
    {
      (*reply_callback)(status,
			"\xf7\x58\xf2\x26\x68\x75\x0f\x03"
			"\xb0\x8d\xf6\xeb\xe1\xd0\x03\x00", 16,
			reply_callback_context);
    }
  (*reply_callback)(status,
		    NULL, 0,
		    reply_callback_context);

  return NULL;
}

#ifdef SSHDIST_IKE_MOBIKE
SshOperationHandle
d_pad_get_address_pair(SshSADHandle sad_handle,
		       SshIkev2ExchangeData ed,
		       SshUInt32 address_index, 
		       SshIkev2PadGetAddressPairCB reply_callback,
		       void *reply_callback_context)
{
  SshIkev2Error status = SSH_IKEV2_ERROR_OK;

  SSH_DEBUG(SSH_D_HIGHSTART, ("Enter SA %p ED %p", ed->ike_sa, ed));
  
  SSH_ASSERT(server_index < num_servers);

  if (++server_index  == num_servers)
    server_index = 0;

  /* Move to the local IP address on the next available server. */
  (*reply_callback)(status, 
		    server[server_index],
		    ed->ike_sa->remote_ip,
		    reply_callback_context);
  return NULL;
}

SshOperationHandle
d_pad_get_additional_address_list(SshSADHandle sad_handle,
			     SshIkev2ExchangeData ed,
			     SshIkev2PadGetAdditionalAddressListCB
			     reply_callback,
			     void *reply_callback_context)
{
  SshIkev2Error status = SSH_IKEV2_ERROR_OK;
  SshIpAddr ip_addr = NULL;
  int i;

  SSH_DEBUG(SSH_D_HIGHSTART, ("Enter SA %p ED %p", ed->ike_sa, ed));

  if (num_servers - 1)
    {
      ip_addr = ssh_xcalloc(num_servers - 1, sizeof(SshIpAddrStruct));
      
      for (i = 0; i < num_servers - 1; i++)
	ip_addr[i] = server[i + 1]->ip_address[0];
    }      

  (*reply_callback)(status, num_servers - 1, ip_addr, reply_callback_context);
  
  ssh_xfree(ip_addr);
  return NULL;
}
#endif /* SSHDIST_IKE_MOBIKE */
