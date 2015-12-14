/*
 * pad_ike_certs.c
 *
 * Copyright:
 *       Copyright (c) 2005-2006 SFNT Finland Oy.
 *       All rights reserved.
 *
 * IKE policy manager function calls related to certificates.
 *
 */

#include "sshincludes.h"
#include "quicksecpm_internal.h"

#define SSH_DEBUG_MODULE "SshPmIkeCerts"

#ifdef SSHDIST_IKE_CERT_AUTH
#ifdef SSHDIST_CERT

/***************************** Internal utility functions ********************/

typedef struct SshPmIkeCMParamRec *SshPmIkeCMParam;
typedef struct SshPmIkeCMParamRec  SshPmIkeCMParamStruct;

struct SshPmIkeCMParamRec
{
  SshSADHandle sad_handle;
  SshPmP1 p1;

  /* Authentication domain used for this search. When validating local 
     cert this is default one, on remote case this can be any. */
  SshPmAuthDomain ad;

  /* Validate certificate chain from a CA to the end entity cert */
  Boolean create_path;
  /* Return intermediate CA certs */
  Boolean return_path;

  SshCMSearchConstraints ca_constraints;
  SshCMSearchConstraints ee_constraints;
  SshIkev2PayloadID ee_key;

  SshPublicKey public_key;

  SshFSMThread thread;

  SshIkev2Error error_code;
  Boolean search_done;

  /* The user certificate we are currently finding a path to. */
  int user_index;

  /* The CA we are currently finding a path to. */
  int ca_index;

#ifdef SSHDIST_IKEV1
  SshX509PkAlgorithm key_type;
#endif /* SSHDIST_IKEV1 */

  SshCMSearchResult result_callback;
};


static unsigned char*
ssh_pm_ike_certs_compute_key_id(SshPmCa ca, size_t *kid_len)
{
  unsigned char *kid;
  SshX509Certificate x509;

  if (ssh_cm_cert_get_x509(ca->cert, &x509) != SSH_CM_STATUS_OK ||
      x509 == NULL)
    return NULL;

  kid = ssh_x509_cert_compute_key_identifier_ike(x509, "sha1", kid_len);

  ssh_x509_cert_free(x509);

  return kid;
}

void pm_ike_cm_operation_start(SshPmIkeCMParam param)
{
  if (param->create_path)
    ssh_cm_find_path(param->ad->cm,
		     param->ca_constraints,
		     param->ee_constraints,
		     param->result_callback,
		     param);
  else
    ssh_cm_find(param->ad->cm,
		param->ee_constraints,
		param->result_callback,
		param);
}


/***************************** PAD Certificate Handling **********************/

/***************************** Get Certificate Authorities *******************/

SshOperationHandle
ssh_pm_ike_get_cas(SshSADHandle sad_handle,
		   SshIkev2ExchangeData ed,
		   SshIkev2PadGetCAsCB reply_callback,
		   void *reply_callback_context)
{
  SshPm pm = sad_handle->pm;
  SshPmP1 p1 = (SshPmP1)ed->ike_sa;
  SshPmAuthDomain ad = NULL;
  SshIkev2Error error_code = SSH_IKEV2_ERROR_OK;
  SshIkev2CertEncoding ca_encoding = SSH_IKEV2_CERT_X_509;
  const unsigned char *ca_authority_data;
  size_t ca_authority_size;
  SshBufferStruct buffer[1];
  unsigned char *kid;
  size_t kid_len;
  int i;

  /* If policymanager is not in active state, we wan't to reject this. */
  if (ssh_pm_get_status(pm) == SSH_PM_STATUS_SUSPENDED)
    {
      SSH_DEBUG(SSH_D_FAIL, ("PM is not active when trying to get CAs"));
      error_code = SSH_IKEV2_ERROR_SUSPENDED;
      goto error;
    }

  if (ssh_pm_get_status(pm) == SSH_PM_STATUS_DESTROYED)
    {
      SSH_DEBUG(SSH_D_FAIL, ("PM is going down when trying to get CAs"));
      error_code = SSH_IKEV2_ERROR_GOING_DOWN;
      goto error;
    }

  /* Ignore request if not in IKE SA negotiation phase. */
  if (p1->n == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL,
		("Ignoring get certificate authorities request received "
		 "outside IKE negotiation"));
      goto error;
    }

  SSH_DEBUG(SSH_D_HIGHSTART, ("Enter SA %p ED %p", ed->ike_sa, ed));
  SSH_PM_ASSERT_P1N(p1);

  if (p1->n->ed == NULL)
    p1->n->ed = ed;

  /* Verify correct authentication domain */
  if (!ssh_pm_auth_domain_check_by_ed(pm, ed))
    goto error;
  else
    ad = p1->auth_domain;

  if (ad->num_cas == 0)
    goto error;
  
#ifdef SSHDIST_IKEV1
  /* For IKEv1 SA's return the Distinguished Name encoding of the Issuer 
     Name of the X.509 certificate authority to the IKE library. */
  if (p1->ike_sa->flags & SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_IKEV1)
    {
      SshIkev2CertEncoding *ca_encodings = NULL;
      unsigned char **ca = NULL;
      size_t *ca_len = NULL;
      
      ca_encodings = ssh_calloc(ad->num_cas, sizeof(SshIkev2CertEncoding));
      ca = ssh_calloc(ad->num_cas, sizeof(unsigned char *));
      ca_len = ssh_calloc(ad->num_cas, sizeof(size_t));
      
      if (!ca_encodings || !ca || !ca_len)
	{
	  ssh_free(ca_encodings);
	  ssh_free(ca);
	  ssh_free(ca_len);
	  goto error;
	}
      
      for (i = 0; i < ad->num_cas; i++)
	{
	  SshPmCa authority = ad->cas[i];

	  ca_encodings[i] = SSH_IKEV2_CERT_X_509;
	  ca[i] = authority->cert_issuer_dn;
	  ca_len[i] = authority->cert_issuer_dn_len;
	}
      
      SSH_DEBUG(SSH_D_MIDOK, ("Returning %d CA's for IKEv1 SA to the IKE "
			      "library", ad->num_cas));
      
      (*reply_callback)(SSH_IKEV2_ERROR_OK,
			ad->num_cas,
			ca_encodings,
			(const unsigned char **)ca, ca_len,
			reply_callback_context);

      ssh_free(ca_encodings);
      ssh_free(ca);
      ssh_free(ca_len);
      return NULL;
    }
#endif /* SSHDIST_IKEV1 */


  /* Compute authority data */
  ssh_buffer_init(buffer);
  for (i = 0; i < ad->num_cas; i++)
    {
      kid = ssh_pm_ike_certs_compute_key_id(ad->cas[i], &kid_len);
      if (kid == NULL)
	{
	  ssh_buffer_uninit(buffer);
	  error_code = SSH_IKEV2_ERROR_CRYPTO_FAIL;
	  goto error;
	}

      if (ssh_buffer_append(buffer, kid, kid_len) != SSH_BUFFER_OK)
        goto error;

      ssh_free(kid);
    }
  ca_authority_data = ssh_buffer_ptr(buffer);
  ca_authority_size = ssh_buffer_len(buffer);

  if (ca_authority_size == 0)
    {
      ssh_buffer_uninit(buffer);
      error_code = SSH_IKEV2_ERROR_OK;
      goto error;
    }

  (*reply_callback)(SSH_IKEV2_ERROR_OK,
		    1,
		    &ca_encoding,
		    &ca_authority_data,
		    &ca_authority_size,
		    reply_callback_context);
  ssh_buffer_uninit(buffer);
  return NULL;

 error:
  (*reply_callback)(error_code, 0, NULL, NULL, NULL,
		    reply_callback_context);

  return NULL;
}

/***************************** Get Certificates ******************************/

SSH_FSM_STEP(pm_st_ike_get_certs_find_path);
SSH_FSM_STEP(pm_st_ike_get_certs_failed);
SSH_FSM_STEP(pm_st_ike_get_certs_finish);




#define MAX_CERT_PATH_LEN 16

#ifdef SSHDIST_HTTP_SERVER

struct SshPmCertAccessEntryRec
{
  SshADTMapHeaderStruct adt_header;
  int ttl;
  unsigned char *data;
  size_t len;
  char pattern[8];
};

typedef struct SshPmCertAccessEntryRec  SshPmCertAccessEntryStruct;
typedef struct SshPmCertAccessEntryRec *SshPmCertAccessEntry;


static void pm_cert_access_timer(void *context)
{
  SshPm pm = context;
  SshADTHandle handle;
  SshPmCertAccessEntry entry, next;

  for (handle = ssh_adt_enumerate_start(pm->cert_access.server_db);
       handle != SSH_ADT_INVALID;
       handle = next)
    {
      next = ssh_adt_enumerate_next(pm->cert_access.server_db, handle);

      entry = ssh_adt_get(pm->cert_access.server_db, handle);
      if (--entry->ttl > 0)
	continue;

      SSH_DEBUG(SSH_D_NICETOKNOW,
		("Unregistered pattern \"%@\"",
		 ssh_safe_text_render, entry->pattern));

      ssh_adt_delete(pm->cert_access.server_db, handle);
    }

  if (ssh_adt_num_objects(pm->cert_access.server_db) != 0)
    ssh_register_timeout(&pm->cert_access.timeout, 10L, 0L,
			 pm_cert_access_timer, pm);
}

/* Provide access to 'data' behind url path 'pattern' for some
   time. */
Boolean pm_cert_access_register_object(SshPm pm,
				       char *pattern,
				       const unsigned char *data, size_t len)
{
  SshPmCertAccessEntry entry;
  SshPmCertAccessEntryStruct probe;
  Boolean rv = FALSE;
  SshADTHandle handle;

  /* Probe for pattern. If found, set full lifetime. If not found, add
     with full lifetime. */

  SSH_DEBUG(SSH_D_NICETOKNOW,
	    ("Register pattern \"%@\" with %d bytes of data",
	     ssh_safe_text_render, pattern,
	     len));

  memcpy(probe.pattern, pattern, sizeof(probe.pattern));
  if ((handle = ssh_adt_get_handle_to_equal(pm->cert_access.server_db, &probe))
      != SSH_ADT_INVALID)
    {
      entry = ssh_adt_get(pm->cert_access.server_db, handle);
      entry->ttl = 6;
      rv = TRUE;
    }
  else if ((entry = ssh_calloc(1, sizeof(*entry))) != NULL)
    {
      memcpy(entry->pattern, pattern, sizeof(entry->pattern));
      entry->ttl = 6;
      entry->len = len;

      if ((entry->data = ssh_memdup(data, len)) != NULL)
	{
	  if (ssh_adt_num_objects(pm->cert_access.server_db) == 0)
	    ssh_register_timeout(&pm->cert_access.timeout, 10L, 0L,
				 pm_cert_access_timer, pm);
	  ssh_adt_insert(pm->cert_access.server_db, entry);
	  rv = TRUE;
	}
      else
	ssh_free(entry);
    }
  return rv;
}

static Boolean
pm_cert_access_http_handler(SshHttpServerContext http,
			    SshHttpServerConnection connection,
			    SshStream stream, void *context)
{
  const char *uri;
  SshPmCertAccessEntryStruct probe, *entry;
  SshBuffer buffer;
  SshADTHandle handle;
  SshPm pm = context;

  uri = ssh_http_server_get_uri(connection);

  SSH_DEBUG(SSH_D_NICETOKNOW,
	    ("Request for URL \"%@\"", ssh_safe_text_render, uri));

  if (uri && *uri == '/') uri++;

  if (strlen(uri) != sizeof(probe.pattern))
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Invalid length %d, expected %d",
				   strlen(uri), sizeof(probe.pattern)));
      ssh_http_server_error_not_found(connection);
      ssh_stream_destroy(stream);
      return TRUE;
    }

  memcpy(probe.pattern, uri, sizeof(probe.pattern));
  if ((handle = ssh_adt_get_handle_to_equal(pm->cert_access.server_db, &probe))
      != SSH_ADT_INVALID)
    {
      if ((buffer = ssh_buffer_allocate()) != NULL)
	{
	  entry = ssh_adt_get(pm->cert_access.server_db, handle);

	  if (ssh_buffer_append(buffer, entry->data, entry->len) 
              == SSH_BUFFER_OK)
            {
              ssh_http_server_set_content_length(connection, entry->len);
              ssh_http_server_send_buffer(connection, buffer);
            }
          else
            {
              SSH_DEBUG(SSH_D_NICETOKNOW, ("Buffer append failed. "
                                           "Cannot send buffer"));
            }
	}
    }
  else
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Resource not found"));
      ssh_http_server_error_not_found(connection);
      ssh_stream_destroy(stream);
    }

  return TRUE;
}

static int pm_cert_access_compare(const void *p1, const void *p2,
				  void *context)
{
  SshPmCertAccessEntry e1 = (SshPmCertAccessEntry)p1;
  SshPmCertAccessEntry e2 = (SshPmCertAccessEntry)p2;

  return memcmp(e1->pattern, e2->pattern, sizeof(e1->pattern));
}


static SshUInt32 pm_cert_access_hash(const void *p, void *context)
{
  SshPmCertAccessEntry e = (SshPmCertAccessEntry)p;
  SshUInt32 hash = 0, i;

  for (i = 0; i < sizeof(e->pattern); i++)
    {
      hash += e->pattern[i];
      hash += hash << 10;
      hash ^= hash >> 6;
    }

  hash += hash << 3;
  hash ^= hash >> 11;
  hash += hash << 15;

  return hash;
}

static void pm_cert_access_destroy(void *p, void *context)
{
  SshPmCertAccessEntry e = (SshPmCertAccessEntry)p;
  ssh_free(e->data);
  ssh_free(e);
}

static void pm_cert_access_server_stop(SshPm pm)
{
  ssh_cancel_timeout(&pm->cert_access.timeout);

  if (pm->cert_access.server_db)
    ssh_adt_destroy(pm->cert_access.server_db);
  pm->cert_access.server_db = NULL;

  if (pm->cert_access.server)
    ssh_http_server_stop(pm->cert_access.server, NULL_FNPTR, NULL);
  pm->cert_access.server = NULL;
}

Boolean 
ssh_pm_cert_access_server_start(SshPm pm, SshUInt16 port, SshUInt32 flags)
{
  SshHttpServerParams params;
  char portbuf[8];
  
  /* If port has changed, restart server and flush all pending
     entries. The remote can no longer find them as she has wrong
     port. */
  if (pm->cert_access.server != NULL
      && pm->cert_access.server_port != port)
    {
      pm_cert_access_server_stop(pm);
    }

  if (pm->cert_access.server == NULL)
    {
      if ((pm->cert_access.server_db =
	   ssh_adt_create_generic(SSH_ADT_BAG,
				  SSH_ADT_HEADER,
				  SSH_ADT_OFFSET_OF(SshPmCertAccessEntryStruct,
						    adt_header),
				  SSH_ADT_HASH, pm_cert_access_hash,
				  SSH_ADT_COMPARE, pm_cert_access_compare,
				  SSH_ADT_DESTROY, pm_cert_access_destroy,
				  SSH_ADT_ARGS_END))
	  == NULL)
	{
	  return FALSE;
	}

      memset(&params, 0, sizeof(params));
      ssh_snprintf(portbuf, sizeof(portbuf), "%d", (unsigned int)port);
      params.port = portbuf;
      if ((pm->cert_access.server = ssh_http_server_start(&params))
	  == NULL)
	{
	  pm_cert_access_server_stop(pm);
	  return FALSE;
	}

      ssh_http_server_set_handler(pm->cert_access.server,
				  "*", 0,
				  pm_cert_access_http_handler, pm);
      pm->cert_access.server_port = port;

      if (flags & SSH_PM_CERT_ACCESS_SERVER_FLAGS_SEND_BUNDLES)
	pm->cert_access.send_certificate_bundles = TRUE;
    }
  return TRUE;
}

void 
ssh_pm_cert_access_server_stop(SshPm pm)
{
  pm_cert_access_server_stop(pm);
  return;
}

static int
pm_ike_get_certificates_makeurl(char *url, size_t url_len,
				SshPm pm, SshPmP1 p1, const char *path)
{
  Boolean is6 = SSH_IP_IS6(p1->ike_sa->server->ip_address);
  SshIpAddrStruct ip;
  SshPmCertAccessEntryStruct probe;
  int rv;
  
  ip = p1->ike_sa->server->ip_address[0];
#ifdef WITH_IPV6
  if (is6)
    SSH_IP6_SCOPE_ID(&ip) = 0;
#endif /* WITH_IPV6 */

  /* Truncate the hash into N first characters (the amount derived
     from the SshPmCertAccessEntryStruct definition */
  rv = ssh_snprintf(url, url_len,
		    "http://%s%@%s:%d/%*s",
		    is6 ? "[" : "",
		    ssh_ipaddr_render, &ip,
		    is6 ? "]" : "",
		    pm->cert_access.server_port,
		    sizeof(probe.pattern), path);
  return rv;
}


/* This function finalizes the certificate payload. It considers the
   local configuration and peers capabilities, and either sends
   certificates within IKE packets, or publishes them separately / or
   as a bundle on a local web server (and modifies the inputs
   accordingly).

   If memory allocation fails here, indicate it up to the caller, so
   recovery (drop of this negotiation likely) can be taken. */
static Boolean
pm_ike_get_certificates_finalize(SshPm pm, SshPmP1 p1,
				 size_t *nof_certs,
				 SshIkev2CertEncoding *cert_encodings,
				 unsigned char **cert_bers,
				 size_t *cert_lens)
{
  SshHash sha1 = NULL;
  unsigned char digest[20], *data;
  char url[256], path[2 * sizeof(digest)];
  size_t len;
  int url_len, i;

  /* If http access is not supported by either end, we are already
     done */
  if (!p1->n->cert_access_supported || !pm->cert_access.server)
    return TRUE;

  if (ssh_hash_allocate("sha1", &sha1) != SSH_CRYPTO_OK)
    goto error;

  if (pm->cert_access.send_certificate_bundles)
    {
      SshAsn1Context asn1 = NULL;
      SshAsn1Node datanode, node, list;

      if ((asn1 = ssh_asn1_init()) == NULL)
	goto error;

      list = NULL;
      for (i = 0; i < *nof_certs; i++)
	{
	  if (ssh_asn1_decode_node(asn1, cert_bers[i], cert_lens[i], &datanode)
	      == SSH_ASN1_STATUS_OK)
	    {
	      if (ssh_asn1_create_node(asn1, &node, "(any (e 0))", datanode)
		  == SSH_ASN1_STATUS_OK)
		list = ssh_asn1_add_list(list, node);
	    }
	  ssh_free(cert_bers[i]);
	  cert_bers[i] = NULL; /* must be cleared for error */
	}

      if (list)
	{
	  data = NULL;
	  if (ssh_asn1_create_node(asn1, &node, "(sequence () (any ()))", list)
	      != SSH_ASN1_STATUS_OK
	      || ssh_asn1_encode_node(asn1, node) != SSH_ASN1_STATUS_OK
	      || ssh_asn1_node_get_data(node, &data, &len)
	      != SSH_ASN1_STATUS_OK)
	    {
	    bundle_error:
	      ssh_free(data);
	      ssh_asn1_free(asn1);
	      goto error;
	    }

	  ssh_hash_update(sha1, data, len);
          if (ssh_hash_final(sha1, digest) != SSH_CRYPTO_OK)
            goto error;

	  ssh_snprintf(path, sizeof(path), "%.*@",
		       sizeof(digest), ssh_hex_render, digest);
	  path[8] = '\0';

	  if ((url_len =
	       pm_ike_get_certificates_makeurl(url, sizeof(url),
					       pm, p1, path)) == -1)
	    goto bundle_error;

	  cert_encodings[0] = SSH_IKEV2_CERT_HASH_AND_URL_X509_BUNDLE;
	  cert_lens[0] = sizeof(digest) + url_len;
	  if ((cert_bers[0] = ssh_malloc(sizeof(digest) + url_len)) == NULL)
	    goto bundle_error;

	  memcpy(cert_bers[0], digest, sizeof(digest));
	  memcpy(cert_bers[0] + sizeof(digest), url, url_len);

	  if (!pm_cert_access_register_object(pm, path, data, len))
	    goto bundle_error;

	  ssh_free(data);

	  *nof_certs = 1;
	}
      ssh_asn1_free(asn1);
    }
  else
    {
      for (i = 0; i < *nof_certs; i++)
	{
	  ssh_hash_reset(sha1);
	  ssh_hash_update(sha1, cert_bers[i], cert_lens[i]);
	  if (ssh_hash_final(sha1, digest) != SSH_CRYPTO_OK)
            goto error;

	  ssh_snprintf(path, sizeof(path), "%.*@",
		       sizeof(digest), ssh_hex_render,
		       digest);
	  path[8] = '\000';

	  if ((url_len =
	       pm_ike_get_certificates_makeurl(url, sizeof(url),
					       pm, p1, path)) == -1)
	    goto error;

	  data = cert_bers[i];
	  len = cert_lens[i];

	  cert_encodings[i] = SSH_IKEV2_CERT_HASH_AND_URL_X509;
	  cert_lens[i] = sizeof(digest) + url_len;

	  if ((cert_bers[i] = ssh_malloc(sizeof(digest) + url_len)) == NULL)
	    {
	      ssh_free(data);
	      goto error;
	    }

	  memcpy(cert_bers[i], digest, sizeof(digest));
	  memcpy(cert_bers[i] + sizeof(digest), url, url_len);

	  if (!pm_cert_access_register_object(pm, path, data, len))
	    {
	      ssh_free(data);
	      goto error;
	    }
	  ssh_free(data);
	}
    }

  ssh_hash_free(sha1);
  return TRUE;

 error:
  if (sha1)
    ssh_hash_free(sha1);

  for (i = 0; i < *nof_certs; i++)
    ssh_free(cert_bers[i]);
  *nof_certs = 0;
  return FALSE;
}
#endif /* SSHDIST_HTTP_SERVER */

/* Callback function for find_path operation */
static void
pm_ike_get_certificates_find_path_cb(void *context,
				     SshCMSearchInfo info,
				     SshCMCertList list)
{
  SshPmIkeCMParam param = context;
  SshPmEk ek = NULL;
  SshPrivateKey private_key_out = NULL;
  SshIkev2CertEncoding cert_encodings[MAX_CERT_PATH_LEN];
  unsigned char *cert_bers[MAX_CERT_PATH_LEN];
  size_t cert_lens[MAX_CERT_PATH_LEN], nof_certs = 0;
  SshCMCertificate cert = NULL;
  SshPmP1 p1 = param->p1;
  SshPmTunnel tunnel = NULL;

  /* We have tried one more CA. */
  param->ca_index++;

  if (ssh_pm_get_status(param->sad_handle->pm) == SSH_PM_STATUS_DESTROYED)
    {
      SSH_DEBUG(SSH_D_FAIL, ("PM is going down when receiving validator CB"));
      param->error_code = SSH_IKEV2_ERROR_GOING_DOWN;
      goto error;
    }

  /* An error occurred */
  if (info->status != SSH_CM_STATUS_OK)
    {
      SSH_DEBUG(SSH_D_FAIL,
		("Certificate path construction failed"));
      if (p1->n)
	p1->n->cmi_failure_mask = info->state;

      param->error_code = SSH_IKEV2_ERROR_OK;
      goto error;
    }

  if ((tunnel = ssh_pm_p1_get_tunnel(param->sad_handle->pm, p1)) == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("No tunnel available."));
      param->error_code = SSH_IKEV2_ERROR_AUTHENTICATION_FAILED;
      goto error;
    }

  if (tunnel->u.ike.local_cert_kid != NULL)
    {
      SshCMCertificate cmcert;

      cmcert = ssh_pm_get_certificate_by_kid(param->sad_handle-> pm,
					     tunnel->u.ike.local_cert_kid,
					     tunnel->u.ike.local_cert_kid_len);
      
      ek = NULL;
      /* Get the private key for end entity. Lookup by the given
	 certificate. */
      if (cmcert)
	ek = ssh_pm_ek_get_by_cert(param->sad_handle->pm, cmcert);
    }
  else 
    {
      /* Get the private key for end entity. Lookup by local id. */
      ek = ssh_pm_ek_get_by_identity(param->sad_handle->pm,
                                     param->ee_key);
    }

  /* No private key available */
  if (ek == NULL || (ek->accel_private_key == NULL && ek->private_key == NULL))
    {
      SSH_DEBUG(SSH_D_FAIL, ("No private key available"));
      param->error_code = SSH_IKEV2_ERROR_CRYPTO_FAIL;
      goto error;
    }

  /* Use accelerated private key if available, otherwise use software key. */
  if (!ek->accel_private_key ||
      ssh_private_key_copy(ek->accel_private_key,
			   &private_key_out) != SSH_CRYPTO_OK)
    {
      if (!ek->private_key ||
	  ssh_private_key_copy(ek->private_key, &private_key_out)
	  != SSH_CRYPTO_OK)
	{
	  SSH_DEBUG(SSH_D_FAIL,
		    ("Unable to copy private key"));
	  param->error_code = SSH_IKEV2_ERROR_CRYPTO_FAIL;
	  goto error;
	}
    }

  /* Set proper scheme */
  if (ek->rsa_key) 
    {
      if(ssh_private_key_select_scheme(private_key_out,
                                       SSH_PKF_SIGN,
                                       "rsa-pkcs1-sha1",
                                       SSH_PKF_END) != SSH_CRYPTO_OK)
        {
          SSH_DEBUG(SSH_D_FAIL,
                    ("Unable to set private key scheme"));
          param->error_code = SSH_IKEV2_ERROR_CRYPTO_FAIL;
          goto error;
        }
      p1->local_auth_method = SSH_PM_AUTH_RSA;
    }
  else if (ek->dsa_key)
    {
      if (ssh_private_key_select_scheme(private_key_out,
                                        SSH_PKF_SIGN,
                                        "dsa-nist-sha1",
                                        SSH_PKF_END) != SSH_CRYPTO_OK)
        {
          SSH_DEBUG(SSH_D_FAIL,
                    ("Unable to set private key scheme"));
          param->error_code = SSH_IKEV2_ERROR_CRYPTO_FAIL;
          goto error;
        }
      p1->local_auth_method = SSH_PM_AUTH_DSA;
    }
#ifdef SSHDIST_CRYPT_ECP
  else if (ek->ecdsa_key)
    {
      const char *scheme;
      if (!ssh_pm_get_key_scheme(private_key_out,
                                 FALSE,
                                 &scheme))
        {
          SSH_DEBUG(SSH_D_FAIL,
                      ("Unable to get the applicable private key scheme"));
          param->error_code = SSH_IKEV2_ERROR_CRYPTO_FAIL;
          goto error;
        }
      if (ssh_private_key_select_scheme(private_key_out,
                                        SSH_PKF_SIGN,
                                        scheme,
                                        SSH_PKF_END) != SSH_CRYPTO_OK)
        {
          SSH_DEBUG(SSH_D_FAIL,
                      ("Unable to set private key scheme"));
          param->error_code = SSH_IKEV2_ERROR_CRYPTO_FAIL;
          goto error;
        }
      p1->local_auth_method = SSH_PM_AUTH_ECP_DSA;
    }
#endif /* SSHDIST_CRYPT_ECP */
  else
    {
      SSH_DEBUG(SSH_D_FAIL, ("Invalid private key"));
      param->error_code = SSH_IKEV2_ERROR_CRYPTO_FAIL;
      goto error;
    }

  /* Handle end entity certificate and intermediate CA certificates */
  if (list != NULL && !ssh_cm_cert_list_empty(list))
    {
      unsigned char *ber;
      size_t ber_len;
      SshCMCertificate prev;

      cert = ssh_cm_cert_list_last(list);
      while (cert)
	{
	  prev = ssh_cm_cert_list_prev(list);

	  if ((prev == NULL && nof_certs > 0)
	      || nof_certs > MAX_CERT_PATH_LEN)
	    {
	      /* Do allow certificate list to expand too much and do
		 not put the trust anchor certificate into the list. */
	      break;
	    }

	  ber = NULL;
	  ber_len = 0;
	  if (ssh_cm_cert_get_ber(cert, &ber, &ber_len) != SSH_CM_STATUS_OK)
	    {
	      SSH_DEBUG(SSH_D_FAIL,
			("Unable to convert certificate to x509 ber format"));
	      param->error_code = SSH_IKEV2_ERROR_CRYPTO_FAIL;
	      goto error;
	    }

	  SSH_ASSERT(ber_len > 0);
	  cert_encodings[nof_certs] = SSH_IKEV2_CERT_X_509;
	  if ((cert_bers[nof_certs] = ssh_memdup(ber, ber_len)) != NULL)
	    {
	      cert_lens[nof_certs] = ber_len;
	      nof_certs++;
	    }
	  else
	    {
	      param->error_code = SSH_IKEV2_ERROR_OUT_OF_MEMORY;
	      goto error;
	    }

	  /* Break if we are looking for only our end certificate */
	  if (!param->create_path || !param->return_path)
	    break;

	  cert = prev;
	}

#ifdef SSHDIST_HTTP_SERVER
      /* Finalize encodings. */
      if (!pm_ike_get_certificates_finalize(param->sad_handle->pm, p1,
					    &nof_certs,
					    cert_encodings,
					    cert_bers,
					    cert_lens))
	{
	  param->error_code = SSH_IKEV2_ERROR_OUT_OF_MEMORY;
	  goto error;
	}
#endif /* SSHDIST_HTTP_SERVER */
    }
  else
    {
      /* No certificates found, which is perfectly ok */
      SSH_DEBUG(SSH_D_NICETOKNOW, ("No certificates found"));
      param->error_code = SSH_IKEV2_ERROR_OK;
      goto error;
    }

  SSH_DEBUG(SSH_D_NICETOKNOW, ("nof_certs = %lu",
			       (long unsigned int)nof_certs));

  /* Mark that the search has succeeded */
  param->search_done = TRUE;

  /* Return the certificates and private key to the IKE library. */
  if (!p1->callbacks.aborted)
    {
      if (p1->callbacks.u.get_certificates_cb)
	(*p1->callbacks.u.get_certificates_cb)(SSH_IKEV2_ERROR_OK,
					   private_key_out,
					   nof_certs,
					   cert_encodings,
					   (const unsigned char **) &cert_bers,
					   cert_lens,
					   p1->callbacks.callback_context);

      ssh_operation_unregister(p1->callbacks.operation);
    }

  /* fall-through to error */
 error:

  while (nof_certs > 0)
    {
      nof_certs--;
      if (cert_bers[nof_certs])
	ssh_free(cert_bers[nof_certs]);
    }

  if (list != NULL)
    ssh_cm_cert_list_free(param->ad->cm, list);
  if (private_key_out != NULL)
    ssh_private_key_free(private_key_out);

  if (ek != NULL)
    ssh_pm_ek_unref(param->sad_handle->pm, ek);

  SSH_FSM_CONTINUE_AFTER_CALLBACK(param->thread);
  return;
}

static void pm_ike_certificate_find_aborted(void *context)
{
  SshPmIkeCMParam param = context;

  param->p1->callbacks.u.get_certificates_cb = NULL_FNPTR;
  /* Can not abort CM right now... It will complete and release its
     reference to P1 eventually. Mark operation aborted.  */
  param->p1->callbacks.aborted = TRUE;
}

static void pm_st_ike_get_certs_destructor(SshFSM fsm, void *context)
{
  SshPmIkeCMParam param = context;
  SshPmP1 p1 = param->p1;

  ssh_pm_ike_sa_free_ref(param->sad_handle, p1->ike_sa);
  ssh_pm_ikev2_payload_id_free(param->ee_key);
  ssh_pm_auth_domain_destroy(param->sad_handle->pm, param->ad);
  ssh_free(param);
}

SSH_FSM_STEP(pm_st_ike_get_certs_find_path)
{
  SshPmIkeCMParam param = thread_context;
  SshPm pm = param->sad_handle->pm;
  SshCMSearchConstraints local_search_constraints = NULL;
  SshCMSearchConstraints ca_search_constraints = NULL;
  SshCertDBKey *local_keys = NULL, *ca_keys = NULL;
  SshBerTimeStruct start_time, end_time;
  SshIkev2PayloadID pid;
  SshPmP1 p1 = param->p1;
  SshPmTunnel tunnel;
  SshPmAuthDomain ad = param->ad;
  SshTime now;
  unsigned char *kid;
  size_t kid_len;
  int i;

  /* Check for errors from the pm_ike_get_certificates_find_path_cb
     callback. */
  if (param->error_code != SSH_IKEV2_ERROR_OK)
    goto error;

  tunnel = ssh_pm_p1_get_tunnel(pm, p1);
  if (tunnel == NULL)
    goto error;

  /* Has the search operation completed successfully? */
  if (param->search_done)
    {
      SSH_FSM_SET_NEXT(pm_st_ike_get_certs_finish);
      return SSH_FSM_CONTINUE;
    }

  /* Have we tried all available CA's? */
  if (param->ca_index == ad->num_cas)
    {
      param->error_code = SSH_IKEV2_ERROR_OK;
      goto error;
    }

  /* Set up search constraints for local certificate */
  local_search_constraints = ssh_cm_search_allocate();
  if (local_search_constraints == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Could not allocate search constraints"));
      param->error_code = SSH_IKEV2_ERROR_OUT_OF_MEMORY;
      goto error;
    }

  pid = param->ee_key;

  SSH_DEBUG(SSH_D_NICETOKNOW,
	    ("local identity %@", ssh_pm_ike_id_render, pid));
  switch (pid->id_type)
    {
    case SSH_IKEV2_ID_TYPE_IPV4_ADDR:
    case SSH_IKEV2_ID_TYPE_IPV6_ADDR:
      ssh_cm_key_set_ip(&local_keys,
			pid->id_data, pid->id_data_size);
      break;
    case SSH_IKEV2_ID_TYPE_RFC822_ADDR:
      ssh_cm_key_set_email(&local_keys,
			   pid->id_data, pid->id_data_size);
      break;
    case SSH_IKEV2_ID_TYPE_FQDN:
      ssh_cm_key_set_dns(&local_keys,
			 pid->id_data, pid->id_data_size);
      break;
    case SSH_IKEV2_ID_TYPE_ASN1_DN:
      ssh_cm_key_set_dn(&local_keys,
			pid->id_data, pid->id_data_size);
      break;
    case SSH_IKEV2_ID_TYPE_ASN1_GN:
    case SSH_IKEV2_ID_TYPE_KEY_ID:
    default:
      SSH_DEBUG(SSH_D_FAIL, ("Unknown payload id type %d", pid->id_type));
      param->error_code = SSH_IKEV2_ERROR_INVALID_ARGUMENT;
      goto error;
      break;
    }

  if (tunnel->u.ike.local_cert_kid != NULL)
    ssh_cm_key_set_x509_key_identifier(&local_keys, 
				       tunnel->u.ike.local_cert_kid, 
				       tunnel->u.ike.local_cert_kid_len);
  
  ssh_cm_search_set_keys(local_search_constraints, local_keys);

  /* Require our certificate to be valid now and in near future */
  now = ssh_time();
  ssh_ber_time_set_from_unix_time(&start_time, now);
  ssh_ber_time_set_from_unix_time(&end_time, now + 120);
  ssh_cm_search_set_time(local_search_constraints, &start_time, &end_time);
#ifdef SSHDIST_IKEV1
  ssh_cm_search_set_key_type(local_search_constraints, param->key_type);
#endif /* SSHDIST_IKEV1 */

  /* Set up search constraints for ca certificate */
  ca_search_constraints = ssh_cm_search_allocate();

  if (ca_search_constraints == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Could not allocate search constraints"));
      param->error_code = SSH_IKEV2_ERROR_OUT_OF_MEMORY;
      goto error;
    }

  SSH_ASSERT(param->ca_index < ad->num_cas);

  /* Select the proper CA from the certificate request the peer sent
     us.  If the peer did not send a certificate request, we try to
     use psk.  If a matching CA is not found or psk is not configured,
     we send only our end certificate to the other end. */
  if ((kid =
       ssh_pm_ike_certs_compute_key_id(ad->cas[param->ca_index], &kid_len))
      == NULL)
    {
      param->error_code = SSH_IKEV2_ERROR_OUT_OF_MEMORY;
      goto error;
    }

  SSH_ASSERT(kid_len == 20); /* Length of SHA1 hash */

  param->create_path = FALSE;

  for (i = 0; i < p1->n->crs.num_cas; i++)
    {
      if (memcmp(kid, p1->n->crs.cas[i], kid_len) == 0)
	{
	  /* Matching CA found */
	  SSH_DEBUG(SSH_D_NICETOKNOW,
		    ("Found matching CA"));
	  ssh_cm_key_set_dn(&ca_keys, 
			    ad->cas[param->ca_index]->cert_subject_dn,
			    ad->cas[param->ca_index]->cert_subject_dn_len);
	  param->create_path = TRUE;
	  break;
	}
    }
  ssh_free(kid);
  ssh_cm_search_set_keys(ca_search_constraints, ca_keys);

  /* Free CA seach constraints if they are not to be used. */
  if (!param->create_path && ca_search_constraints)
    {
      ssh_cm_search_free(ca_search_constraints);
      ca_search_constraints = NULL;
    }

  param->ca_constraints = ca_search_constraints;
  param->ee_constraints = local_search_constraints;
  param->result_callback = pm_ike_get_certificates_find_path_cb;

  SSH_FSM_ASYNC_CALL(pm_ike_cm_operation_start(param));
  SSH_NOTREACHED;

  /* Error handling. */

 error:

  if (local_search_constraints)
    ssh_cm_search_free(local_search_constraints);
  if (ca_search_constraints)
    ssh_cm_search_free(ca_search_constraints);

  SSH_FSM_SET_NEXT(pm_st_ike_get_certs_failed);
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(pm_st_ike_get_certs_failed)
{
  SshPmIkeCMParam param = thread_context;
  SshPmP1 p1 = param->p1;

  /* Inform the IKE library that certificate lookup did not succeed. */
  if (!p1->callbacks.aborted)
    {
      if (p1->callbacks.u.get_certificates_cb)
	(*p1->callbacks.u.get_certificates_cb)(param->error_code,
					       NULL, 0, NULL, NULL, NULL,
					       p1->callbacks.callback_context);
      ssh_operation_unregister(p1->callbacks.operation);
    }

  return SSH_FSM_FINISH;
}

SSH_FSM_STEP(pm_st_ike_get_certs_finish)
{
  return SSH_FSM_FINISH;
}


SshOperationHandle
ssh_pm_ike_get_certificates(SshSADHandle sad_handle,
			    SshIkev2ExchangeData ed,
			    SshIkev2PadGetCertificatesCB reply_callback,
			    void *reply_callback_context)
{
  SshPm pm = sad_handle->pm;
  SshIkev2Error error_code = SSH_IKEV2_ERROR_OK;
  SshIkev2PayloadID pid = NULL;
  SshPmIkeCMParam param = NULL;
  SshPmTunnel tunnel;
  SshPmAuthDomain ad = NULL;
  SshPmP1 p1 = (SshPmP1) ed->ike_sa;

  SSH_DEBUG(SSH_D_HIGHSTART, ("Enter SA %p ED %p", ed->ike_sa, ed));

  SSH_PM_ASSERT_P1(p1);

  /* If policymanager is not in active state, we wan't to reject this. */
  if (ssh_pm_get_status(pm) == SSH_PM_STATUS_SUSPENDED)
    goto error;

  /* Ignore request if not in IKE SA negotiation phase. */
  if (p1->n == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL,
		("Ignoring get certificates request received outside IKE "
		 "negotiation"));
      goto error;
    }
  
  if (!p1->n->tunnel)
    {
      error_code = SSH_IKEV2_ERROR_SA_UNUSABLE;
      goto error;
    }

  /* Verify correct authentication domain */
  if (!ssh_pm_auth_domain_check_by_ed(pm, ed))
    goto error;
  else
    ad = p1->auth_domain;

  tunnel = p1->n->tunnel;
  SSH_ASSERT(ad != NULL);

#ifdef SSHDIST_IKE_EAP_AUTH
  if ((p1->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_INITIATOR) &&
      ad->eap_protocols)
    {
      SSH_DEBUG(SSH_D_LOWOK, ("EAP configured for IKE initiator, "
			      "omitting certificate lookup"));
      error_code = SSH_IKEV2_ERROR_OK;
      goto error;
    }
#endif /* SSHDIST_IKE_EAP_AUTH */

  /* Check if raw RSA authentication is configured for the tunnel. */
  if (ad->private_key)
    {
      unsigned char *cert;
      size_t cert_len;
      SshPublicKey public_key;
      SshPrivateKey private_key;
      SshIkev2CertEncoding cert_enc;

      cert_enc = SSH_IKEV2_CERT_RAW_RSA_KEY;      
      private_key = ad->private_key;

      /* Derive the public key and get its PKCS1 decoding */
      if (ssh_private_key_derive_public_key(private_key, &public_key) 
	  != SSH_CRYPTO_OK)
	{
	  SSH_DEBUG(SSH_D_FAIL, ("Unable to derive public key"));
	  error_code = SSH_IKEV2_ERROR_OUT_OF_MEMORY;
	  goto error;
	}	  
      if (!ssh_pkcs1_encode_public_key(public_key, &cert, &cert_len))
	{
	  SSH_DEBUG(SSH_D_FAIL, 
		    ("Unable to get PKCS1 encoding of public key"));
	  error_code = SSH_IKEV2_ERROR_OUT_OF_MEMORY;
	  ssh_public_key_free(public_key);
	  goto error;
	}

      p1->local_auth_method = SSH_PM_AUTH_RSA;

      (*reply_callback)(SSH_IKEV2_ERROR_OK, 
			private_key, 
			1,
			&cert_enc,			
			(const unsigned char **) &cert, &cert_len,
			reply_callback_context);

      ssh_public_key_free(public_key);
      ssh_free(cert);
      return NULL;
    }

  if (ad->num_cas == 0)
    goto error;
  
  /* Allocate context for callback */
  param = ssh_calloc(1, sizeof(*param));
  if (param == NULL)
    {
      error_code = SSH_IKEV2_ERROR_OUT_OF_MEMORY;
      goto error;
    }
  param->sad_handle = sad_handle;
  param->p1 = p1;

  param->ad = ad;
  ssh_pm_auth_domain_take_ref(ad);

#ifdef SSHDIST_IKEV1
  if ((ed->ike_ed->auth_method ==
      SSH_IKE_VALUES_AUTH_METH_RSA_SIGNATURES)
#ifdef SSHDIST_IKE_XAUTH
     || (ed->ike_ed->auth_method ==
	 SSH_IKE_VALUES_AUTH_METH_XAUTH_I_RSA_SIGNATURES)
     || (ed->ike_ed->auth_method ==
	 SSH_IKE_VALUES_AUTH_METH_XAUTH_R_RSA_SIGNATURES)
#endif /* SSHDIST_IKE_XAUTH */
     )
    param->key_type = SSH_X509_PKALG_RSA;
  else if ((ed->ike_ed->auth_method ==
	 SSH_IKE_VALUES_AUTH_METH_DSS_SIGNATURES)
#ifdef SSHDIST_IKE_XAUTH
	|| (ed->ike_ed->auth_method ==
	    SSH_IKE_VALUES_AUTH_METH_XAUTH_I_DSS_SIGNATURES)
	|| (ed->ike_ed->auth_method ==
	    SSH_IKE_VALUES_AUTH_METH_XAUTH_R_DSS_SIGNATURES)
#endif /* SSHDIST_IKE_XAUTH */
	)
    param->key_type = SSH_X509_PKALG_DSA;
#ifdef SSHDIST_CRYPT_ECP
  else if ((ed->ike_ed->auth_method == 
              SSH_IKE_VALUES_AUTH_METH_ECP_DSA_256)
           || (ed->ike_ed->auth_method == 
              SSH_IKE_VALUES_AUTH_METH_ECP_DSA_384)
           || (ed->ike_ed->auth_method == 
              SSH_IKE_VALUES_AUTH_METH_ECP_DSA_521))
    param->key_type = SSH_X509_PKALG_ECDSA;
#endif /* SSHDIST_CRYPT_ECP */
  else
    param->key_type = SSH_X509_PKALG_UNKNOWN;
#endif /* SSHDIST_IKEV1 */

  /* Get the local id from the tunnel */

  /* Return only end entity cert or the whole path with intermediate CAs */
  param->return_path = TRUE;
  if ((tunnel->flags & SSH_PM_T_NO_CERT_CHAINS) ||
      (p1->compat_flags & SSH_PM_COMPAT_NO_CERT_CHAINS))
    param->return_path = FALSE;

  /* Get the identity */
  pid = ssh_pm_ike_get_identity(pm, p1, tunnel, FALSE);
  if (pid == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Local identity not defined; need to be given "
			     "as 'identity' or 'certificate' at tunnel "
			      "object"));
      error_code = SSH_IKEV2_ERROR_OK;
      goto error;
    }
  param->ee_key = pid;

  /* Lookup the preshared key based on our tunnel's local identity if the
     peer has not sent us any certificate requests. If we have a pre-shared
     key available we will use it, if not we will attempt certificate
     lookup. */
  if (p1->n->crs.num_cas == 0)
    {
      size_t key_len;

      if (ssh_pm_ike_preshared_keys_get_secret(p1->auth_domain,
					       p1->n->tunnel->local_identity,
					       &key_len) != NULL)
	{
	  /* Yes, psk is configured. Fall back to psk. */
	  SSH_DEBUG(SSH_D_NICETOKNOW, ("Pre shared key found"));
	  error_code = SSH_IKEV2_ERROR_OK;
	  goto error;
	}
      SSH_DEBUG(SSH_D_NICETOKNOW, ("No pre shared key found"));
    }

  SSH_DEBUG(SSH_D_NICETOKNOW, ("Prepare for certificate lookup"));

  /* Take a reference to the IKE SA. */
  ssh_pm_ike_sa_take_ref(param->sad_handle, p1->ike_sa);

  ssh_fsm_thread_init(&pm->fsm, &p1->n->sub_thread,
		      pm_st_ike_get_certs_find_path,
		      NULL_FNPTR,
		      pm_st_ike_get_certs_destructor,
		      param);

  ssh_fsm_set_thread_name(&p1->n->sub_thread, "IKE get certs");

  param->thread = &p1->n->sub_thread;

  p1->callbacks.aborted = FALSE;
  p1->callbacks.u.get_certificates_cb = reply_callback;
  p1->callbacks.callback_context = reply_callback_context;

  ssh_operation_register_no_alloc(p1->callbacks.operation,
				  pm_ike_certificate_find_aborted,
				  param);
  return p1->callbacks.operation;

 error:
  (*reply_callback)(error_code, 0, 0, NULL, NULL, NULL,
		    reply_callback_context);

  if (pid != NULL)
    ssh_pm_ikev2_payload_id_free(pid);
  if (param != NULL)
    {
      ssh_pm_auth_domain_destroy(param->sad_handle->pm, param->ad);
      ssh_free(param);
    }
  return NULL;
}

/***************************** Get Public Key ********************************/

SSH_FSM_STEP(pm_st_ike_get_public_key_find_path);
SSH_FSM_STEP(pm_st_ike_get_public_key_failed);
SSH_FSM_STEP(pm_st_ike_get_public_key_finish);

static void pm_certs_acc_public_key_cb(SshEkStatus status,
				       SshPublicKey public_key_return,
				       void *context)
{
  SshPmIkeCMParam param = context;
  
  if (public_key_return && (status == SSH_EK_OK))
    {
      ssh_public_key_free(param->public_key);
      param->public_key = public_key_return;
    }
  
  SSH_ASSERT(param->public_key != NULL);
  
  /* Mark that the search has succeeded */
  param->search_done = TRUE;
  
  SSH_FSM_CONTINUE_AFTER_CALLBACK(param->thread);
}

/* Callback function for find_path operation */
static void
pm_ike_public_key_find_path_cb(void *context,
			       SshCMSearchInfo info,
			       SshCMCertList list)
{
  SshPmIkeCMParam param = context;
  SshPublicKey public_key = NULL;
  SshPmP1 p1 = (SshPmP1) param->p1;
  SshPm pm = param->sad_handle->pm;
  SshCMCertificate ee_cert;
  SshCMCertificate ca_cert;
  SshX509Certificate x509 = NULL;
  int i;
  unsigned int ee_cert_id;
  const char * key_type;

  SSH_ASSERT(param != NULL);

  /* Try next search with the next certificate cache id (or without cache
     id constraint if already looped through all cache ids). */
  param->user_index++;
  if (param->user_index > p1->n->num_user_certificate_ids)
    {
      /* We have tried searching with all certificates the peer sent us
	 and without the certificate cache id constraint. Restart from the
	 first cache id. */
      param->user_index = 0;
      
      /* We have tried this CA. Move to next CA. */
      param->ca_index++;
    }

  if (ssh_pm_get_status(pm) == SSH_PM_STATUS_DESTROYED)
    {
      SSH_DEBUG(SSH_D_FAIL, ("PM is going down when receiving validator CB"));
      param->error_code = SSH_IKEV2_ERROR_GOING_DOWN;
      ssh_cm_cert_list_free(param->ad->cm, list);
      goto error;
    }

  /* An error occurred */
  if (info->status != SSH_CM_STATUS_OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Certificate path construction failed, "
			      "status %d", info->status));
      param->error_code = SSH_IKEV2_ERROR_OK;
      ssh_cm_cert_list_free(param->ad->cm, list);

      if (p1->n)
	p1->n->cmi_failure_mask = info->state;
      goto error;
    }

  if (ssh_cm_cert_list_empty(list))
    {
      /* Empty list */
      SSH_DEBUG(SSH_D_FAIL, ("No suitable certificate path found"));
      param->error_code = SSH_IKEV2_ERROR_OK;
      ssh_cm_cert_list_free(param->ad->cm, list);
      goto error;
    }

  /* Store CA certificate */
  ca_cert = ssh_cm_cert_list_first(list);
  SSH_ASSERT(ca_cert != NULL);
  SSH_ASSERT(p1->auth_ca_cert == NULL);
  ssh_cm_cert_take_reference(ca_cert);
  p1->auth_ca_cert = ca_cert;

  /* Store end entity certificate */
  ee_cert = ssh_cm_cert_list_last(list);
  SSH_ASSERT(ee_cert != NULL);
  SSH_ASSERT(p1->auth_cert == NULL);
  ssh_cm_cert_take_reference(ee_cert);
  p1->auth_cert = ee_cert;

  /* Does the chosen ee cert match one of the ee certs the peer sent us? */
  ee_cert_id = ssh_cm_cert_get_cache_id(ee_cert);
  SSH_ASSERT(p1->n->num_user_certificate_ids <= SSH_PM_P1N_NUM_USER_CERT_IDS);
  for (i = 0; i < p1->n->num_user_certificate_ids; i++)
    {
      if (ee_cert_id == p1->n->user_certificate_ids[i])
	break;
    }
  if (i > 0 && i == p1->n->num_user_certificate_ids)
    {



      SSH_DEBUG(SSH_D_NICETOKNOW,
		("Chosen end entity certificate "
		 "is not the one the peer sent us!"));
    }

  /* Extract the public key from ee certificate */
  if (ssh_cm_cert_get_x509(ee_cert, &x509) != SSH_CM_STATUS_OK
      || x509 == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("cmi error"));
      param->error_code = SSH_IKEV2_ERROR_INVALID_ARGUMENT;
      ssh_cm_cert_list_free(param->ad->cm, list);
      goto error;
    }
  if (!ssh_x509_cert_get_public_key(x509, &public_key))
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Unable to get the public key from certificate"));
      param->error_code = SSH_IKEV2_ERROR_INVALID_ARGUMENT;
      ssh_cm_cert_list_free(param->ad->cm, list);
      goto error;
    }

  ssh_cm_cert_list_free(param->ad->cm, list);
  ssh_x509_cert_free(x509);
  x509 = NULL;

  if (ssh_public_key_get_info(public_key, 
                              SSH_PKF_KEY_TYPE, &key_type,
                              SSH_PKF_END) != SSH_CRYPTO_OK)
    {
      param->error_code = SSH_IKEV2_ERROR_CRYPTO_FAIL;
      ssh_cm_cert_list_free(param->ad->cm, list);
      goto error;
    }
  
  if (strstr(key_type, "if-modn") != NULL)
    {
      if (ssh_public_key_select_scheme(public_key,
				       SSH_PKF_SIGN,
				       "rsa-pkcs1-implicit",
				       SSH_PKF_END) != SSH_CRYPTO_OK)
        {
          SSH_DEBUG(SSH_D_FAIL, ("Unable to set scheme for public key"));
          param->error_code = SSH_IKEV2_ERROR_CRYPTO_FAIL;
          ssh_cm_cert_list_free(param->ad->cm, list);
          goto error;
        }
      p1->remote_auth_method = SSH_PM_AUTH_RSA;
    }
  else if (strstr(key_type,"dl-modp") != NULL)
    { 
      if (ssh_public_key_select_scheme(public_key,
				       SSH_PKF_SIGN,
				       "dsa-nist-sha1",
				       SSH_PKF_END) != SSH_CRYPTO_OK)
	{
	  SSH_DEBUG(SSH_D_FAIL, ("Unable to set scheme for public key"));
	  param->error_code = SSH_IKEV2_ERROR_CRYPTO_FAIL;
	  ssh_cm_cert_list_free(param->ad->cm, list);
	  goto error;
	}
      /* Record the remote authentication method */
      p1->remote_auth_method = SSH_PM_AUTH_DSA;
    }
#ifdef SSHDIST_CRYPT_ECP
  else if (strstr(key_type, "ec-modp") != NULL)
    {
      const char * scheme;
      if ((!ssh_pm_get_key_scheme(public_key, TRUE, &scheme))
	  || (ssh_public_key_select_scheme(public_key,
					   SSH_PKF_SIGN,
					   scheme,
					   SSH_PKF_END) != SSH_CRYPTO_OK))
        {
	  SSH_DEBUG(SSH_D_FAIL, ("Unable to set scheme for public key"));
	  param->error_code = SSH_IKEV2_ERROR_CRYPTO_FAIL;
	  ssh_cm_cert_list_free(param->ad->cm, list);
	  goto error;
        }
      /* Record the remote authentication method */
      p1->remote_auth_method = SSH_PM_AUTH_ECP_DSA;
    }
#endif /* SSHDIST_CRYPT_ECP */
  else
    {
      param->error_code = SSH_IKEV2_ERROR_CRYPTO_FAIL;
      ssh_cm_cert_list_free(param->ad->cm, list);
      goto error;
    }

  param->public_key = public_key;

  /* Try to accelerate the public key if possible */
  if (pm->accel_short_name)
    {
      ssh_ek_generate_accelerated_public_key(pm->externalkey,
					     pm->accel_short_name,
					     param->public_key,
					     pm_certs_acc_public_key_cb,
					     param);
      return;
    }
  else
    {
      /* Cannot use acceleration */
      pm_certs_acc_public_key_cb(SSH_EK_OK, NULL, param);
      return;
    }
  SSH_NOTREACHED;

 error:
  if (p1->auth_cert)
    {
      ssh_cm_cert_remove_reference(p1->auth_cert);
      p1->auth_cert = NULL;
    }
  if (p1->auth_ca_cert)
    {
      ssh_cm_cert_remove_reference(p1->auth_ca_cert);
      p1->auth_ca_cert = NULL;
    }

  if (x509)
    ssh_x509_cert_free(x509);
  if (public_key)
    ssh_public_key_free(public_key);

 SSH_FSM_CONTINUE_AFTER_CALLBACK(param->thread);
}

static void pm_ike_pubkey_find_aborted(void *context)
{
  SshPmIkeCMParam param = context;

  param->p1->callbacks.u.public_key_cb = NULL_FNPTR;
  /* Can not abort CM right now... It will complete and release its
     reference to P1 eventually. Mark operation aborted. */
  param->p1->callbacks.aborted = TRUE;
}

static void pm_st_ike_get_public_key_destructor(SshFSM fsm, void *context)
{
  SshPmIkeCMParam param = context;
  SshPmP1 p1 = param->p1;

  ssh_pm_ike_sa_free_ref(param->sad_handle, p1->ike_sa);
  ssh_pm_ikev2_payload_id_free(param->ee_key);
  ssh_pm_auth_domain_destroy(param->sad_handle->pm, param->ad);
  ssh_free(param);
}

SSH_FSM_STEP(pm_st_ike_get_public_key_find_path)
{
  SshPmIkeCMParam param = thread_context;
  SshCMSearchConstraints ee_search_constraints = NULL;
  SshCMSearchConstraints ca_search_constraints = NULL;
  SshCertDBKey *ee_keys = NULL, *ca_keys = NULL;
  SshBerTimeStruct start_time, end_time;
  SshIkev2PayloadID pid;
  SshPmCa ca = NULL;
  SshTime now;
  SshPmP1 p1 = param->p1;
  int i;

  /* Check for errors from the pm_ike_get_certificates_find_path_cb
     callback. */
  if (param->error_code != SSH_IKEV2_ERROR_OK)
    goto error;

  /* Is the search operation completed successfully? */
  if (param->search_done)
    {
      SSH_FSM_SET_NEXT(pm_st_ike_get_public_key_finish);
      return SSH_FSM_CONTINUE;
    }

  /* Have we tried all available CA's? */
  if (param->ca_index == param->ad->num_cas)
    {
      param->error_code = SSH_IKEV2_ERROR_OK;
      goto error;
    }

  /* Set up search constraints for remote end certificate */
  ee_search_constraints = ssh_cm_search_allocate();
  if (ee_search_constraints == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Could not allocate search constraints"));
      param->error_code = SSH_IKEV2_ERROR_OUT_OF_MEMORY;
      goto error;
    }

  /* Get remote identity */
  pid = param->ee_key;
  SSH_ASSERT(pid != NULL);
  SSH_DEBUG(SSH_D_NICETOKNOW,
	    ("Remote identity %@", ssh_pm_ike_id_render, pid));

  switch (pid->id_type)
    {
    case SSH_IKEV2_ID_TYPE_IPV4_ADDR:
    case SSH_IKEV2_ID_TYPE_IPV6_ADDR:
      ssh_cm_key_set_ip(&ee_keys,
                        pid->id_data, pid->id_data_size);
      break;
    case SSH_IKEV2_ID_TYPE_RFC822_ADDR:
      ssh_cm_key_set_email(&ee_keys,
                           pid->id_data, pid->id_data_size);
      break;
    case SSH_IKEV2_ID_TYPE_FQDN:
      ssh_cm_key_set_dns(&ee_keys,
                         pid->id_data, pid->id_data_size);
      break;
    case SSH_IKEV2_ID_TYPE_ASN1_DN:
      ssh_cm_key_set_dn(&ee_keys,
                        pid->id_data, pid->id_data_size);
      break;
    case SSH_IKEV2_ID_TYPE_KEY_ID:
      ssh_cm_key_set_x509_key_identifier(&ee_keys,
					 pid->id_data, pid->id_data_size);
      break;
    case SSH_IKEV2_ID_TYPE_ASN1_GN:
    default:
      SSH_DEBUG(SSH_D_FAIL, ("Unknown payload id type %d", pid->id_type));
      param->error_code = SSH_IKEV2_ERROR_INVALID_ARGUMENT;
      goto error;
      break;
    }

  /* Add cache id of the certificate the peer has sent us. Note that the
     search is performed first with all known cache ids and finally without
     the cache id constraint if no matches are found. */
  if (param->user_index < p1->n->num_user_certificate_ids)
    ssh_cm_key_set_cache_id(&ee_keys,
			    p1->n->user_certificate_ids[param->user_index]);
  
  ssh_cm_search_set_keys(ee_search_constraints, ee_keys);
  
  /* Add certificate/Crl access hints received from the peer with
     hash-and-url of cert. */
  for (i = 0; i < p1->n->num_cert_access_urls; i++)
    ssh_cm_search_add_access_hints(ee_search_constraints,
				   p1->n->cert_access_urls[i]);

  /* Require end entity certificate to be valid now and in the near future */
  now = ssh_time();
  ssh_ber_time_set_from_unix_time(&start_time, now);
  ssh_ber_time_set_from_unix_time(&end_time, now + 120);
  ssh_cm_search_set_time(ee_search_constraints, &start_time, &end_time);

#ifdef SSHDIST_IKEV1
  ssh_cm_search_set_key_type(ee_search_constraints, param->key_type);
#endif /* SSHDIST_IKEV1 */

  /* Set up search constraints for ca certificate */
  ca_search_constraints = ssh_cm_search_allocate();
  if (ca_search_constraints == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Could not allocate search constraints"));
      param->error_code = SSH_IKEV2_ERROR_OUT_OF_MEMORY;
      goto error;
    }

  /* Select the next available CA. */
  SSH_ASSERT(param->ca_index < param->ad->num_cas);
  ca = param->ad->cas[param->ca_index];

  ssh_cm_key_set_dn(&ca_keys, ca->cert_subject_dn, ca->cert_subject_dn_len);

  ssh_cm_search_set_keys(ca_search_constraints, ca_keys);

  param->ca_constraints = ca_search_constraints;
  param->ee_constraints = ee_search_constraints;
  param->result_callback = pm_ike_public_key_find_path_cb;

  SSH_FSM_ASYNC_CALL(pm_ike_cm_operation_start(param));
  SSH_NOTREACHED;

  /* Error handling. */

 error:

  if (ee_search_constraints)
    ssh_cm_search_free(ee_search_constraints);
  if (ca_search_constraints)
    ssh_cm_search_free(ca_search_constraints);

  SSH_FSM_SET_NEXT(pm_st_ike_get_public_key_failed);
  return SSH_FSM_CONTINUE;
}


SSH_FSM_STEP(pm_st_ike_get_public_key_failed)
{
  SshPmIkeCMParam param = thread_context;
  SshPmP1 p1 = param->p1;

  /* Inform the IKE library that public key lookup did not succeed. */
  if (!p1->callbacks.aborted)
    {
      if (p1->callbacks.u.public_key_cb)
	(*p1->callbacks.u.public_key_cb)(param->error_code,
					 NULL,
					 p1->callbacks.callback_context);  
      ssh_operation_unregister(p1->callbacks.operation);
    }

  return SSH_FSM_FINISH;
}

SSH_FSM_STEP(pm_st_ike_get_public_key_finish)
{
  SshPmIkeCMParam param = thread_context;
  SshPmP1 p1 = param->p1;
  
  /* Return the public key to the IKE library. */
  if (!p1->callbacks.aborted)
    {
      if (p1->callbacks.u.public_key_cb)
	(*p1->callbacks.u.public_key_cb)(SSH_IKEV2_ERROR_OK,
					 param->public_key,
					 p1->callbacks.callback_context);
      ssh_operation_unregister(p1->callbacks.operation);
    }
  ssh_public_key_free(param->public_key);

  return SSH_FSM_FINISH;
}


SshOperationHandle
ssh_pm_ike_public_key(SshSADHandle sad_handle,
		      SshIkev2ExchangeData ed,
		      SshIkev2PadPublicKeyCB reply_callback,
		      void *reply_callback_context)
{
  SshIkev2Error error_code = SSH_IKEV2_ERROR_OK;
  SshPmIkeCMParam param = NULL;
  SshPm pm = sad_handle->pm;
  SshPmAuthDomain ad = NULL;
  SshPmP1 p1;

  SSH_DEBUG(SSH_D_HIGHSTART, ("Enter SA %p ED %p", ed->ike_sa, ed));

  p1 = (SshPmP1)ed->ike_sa;

  SSH_PM_ASSERT_P1(p1);

  /* If policymanager is not in active state, we wan't to reject this. */
  if (ssh_pm_get_status(pm) == SSH_PM_STATUS_SUSPENDED)
    {
      error_code = SSH_IKEV2_ERROR_SUSPENDED;
      goto error;
    }

  /* Fail request if not in IKE SA negotiation phase. */
  if (p1->n == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Failing public key request received outside IKE "
		 "negotiation"));
      error_code = SSH_IKEV2_ERROR_SA_UNUSABLE;
      goto error;
    }

  /* Select a tunnel for the reponder if not already done */
  if (!(p1->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_INITIATOR) &&
      !ssh_pm_select_ike_responder_tunnel(sad_handle->pm, p1, ed))
    {
      error_code = SSH_IKEV2_ERROR_NO_PROPOSAL_CHOSEN;
      goto error;
    }

  /* If the IKE initiator has used the "me Tarzan, you Jane" option, then
     check here that that responder has replied with an acceptable identity. */
  if (!ssh_pm_ike_check_requested_identity(sad_handle->pm, p1,
					   ed->ike_ed->id_r))
    {
      error_code = SSH_IKEV2_ERROR_AUTHENTICATION_FAILED;
      p1->n->failure_mask |= SSH_PM_E_REMOTE_ID_MISMATCH;
      goto error;
    }

  /* Verify correct authentication domain */
  if (!ssh_pm_auth_domain_check_by_ed(pm, ed))
    goto error;
  else
    ad = p1->auth_domain;

  /* Check if raw RSA authentication is configured for the tunnel. */
  if (p1->n->tunnel && ad->public_key)
    {
      /* Record the remote authentication method */
      p1->remote_auth_method = SSH_PM_AUTH_RSA;
      
      /* First check the tunnel's public key matches that in the certificate */
      
      (*reply_callback)(SSH_IKEV2_ERROR_OK, ad->public_key,
			reply_callback_context);
      return NULL;
    }

  /* Are we using certs? */
  if (ad->num_cas == 0)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Authentication domain has no CAs set"));
      p1->n->failure_mask |= SSH_PM_E_AUTH_METHOD_MISMATCH;
      goto error;
    }

  /* Allocate context for callback */
  param = ssh_calloc(1, sizeof(*param));
  if (param == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Could not allocate callback context"));
      error_code = SSH_IKEV2_ERROR_OUT_OF_MEMORY;
      goto error;
    }

  /* Prepare for remote end certificate lookup. */
  param->sad_handle = sad_handle;
  param->p1 = p1;
  param->create_path = TRUE;

  param->ad = ad;
  ssh_pm_auth_domain_take_ref(ad);

#ifdef SSHDIST_IKEV1
  if ((ed->ike_ed->auth_method ==
      SSH_IKE_VALUES_AUTH_METH_RSA_SIGNATURES)
#ifdef SSHDIST_IKE_XAUTH
     || (ed->ike_ed->auth_method ==
	 SSH_IKE_VALUES_AUTH_METH_XAUTH_I_RSA_SIGNATURES)
     || (ed->ike_ed->auth_method ==
	 SSH_IKE_VALUES_AUTH_METH_XAUTH_R_RSA_SIGNATURES)
#endif /* SSHDIST_IKE_XAUTH */
     )
    param->key_type = SSH_X509_PKALG_RSA;
  else if ((ed->ike_ed->auth_method ==
	 SSH_IKE_VALUES_AUTH_METH_DSS_SIGNATURES)
#ifdef SSHDIST_IKE_XAUTH
	|| (ed->ike_ed->auth_method ==
	    SSH_IKE_VALUES_AUTH_METH_XAUTH_I_DSS_SIGNATURES)
	|| (ed->ike_ed->auth_method ==
	    SSH_IKE_VALUES_AUTH_METH_XAUTH_R_DSS_SIGNATURES)
#endif /* SSHDIST_IKE_XAUTH */
	)
    param->key_type = SSH_X509_PKALG_DSA;
#ifdef SSHDIST_CRYPT_ECP
  else if ((ed->ike_ed->auth_method == 
              SSH_IKE_VALUES_AUTH_METH_ECP_DSA_256)
           || (ed->ike_ed->auth_method == 
              SSH_IKE_VALUES_AUTH_METH_ECP_DSA_384)
           || (ed->ike_ed->auth_method == 
              SSH_IKE_VALUES_AUTH_METH_ECP_DSA_521))
    param->key_type = SSH_X509_PKALG_ECDSA;
#endif /* SSHDIST_CRYPT_ECP */
  else
    param->key_type = SSH_X509_PKALG_UNKNOWN;
#endif /* SSHDIST_IKEV1 */

  if (p1->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_INITIATOR)
    param->ee_key = ssh_pm_ikev2_payload_id_dup(ed->ike_ed->id_r);
  else
    param->ee_key = ssh_pm_ikev2_payload_id_dup(ed->ike_ed->id_i);

  if (param->ee_key == NULL)
    goto error;

  ssh_pm_ike_sa_take_ref(param->sad_handle, p1->ike_sa);

  ssh_fsm_thread_init(&pm->fsm, &p1->n->sub_thread,
                      pm_st_ike_get_public_key_find_path,
                      NULL_FNPTR,
                      pm_st_ike_get_public_key_destructor,
                      param);

  ssh_fsm_set_thread_name(&p1->n->sub_thread, "IKE find public key");
  param->thread = &p1->n->sub_thread;

  ssh_operation_register_no_alloc(p1->callbacks.operation,
				  pm_ike_pubkey_find_aborted,
				  param);

  p1->callbacks.aborted = FALSE;
  p1->callbacks.u.public_key_cb = reply_callback;
  p1->callbacks.callback_context = reply_callback_context;
  return p1->callbacks.operation;

 error:
  (*reply_callback)(error_code, NULL, reply_callback_context);

  if (param != NULL)
    {
      ssh_pm_ikev2_payload_id_free(param->ee_key);
      ssh_pm_auth_domain_destroy(param->sad_handle->pm, param->ad);
      ssh_free(param);
    }
  return NULL;
}

/***************************** New Certificate Request ***********************/

void
ssh_pm_ike_new_certificate_request(SshSADHandle sad_handle,
				   SshIkev2ExchangeData ed,
				   SshIkev2CertEncoding ca_encoding,
				   const unsigned char *certificate_authority,
				   size_t certificate_authority_len)
{
  SshPm pm = sad_handle->pm;
  SshPmP1 p1 = (SshPmP1) ed->ike_sa;
  SshPmAuthDomain ad = NULL;
  SshIkev2CertEncoding *ca_encodings = NULL;
  unsigned char *ca, *kid = NULL, **cas = NULL;
  size_t ca_len, *ca_lens = NULL;
#ifdef SSHDIST_IKEV1
  size_t kid_len;
#endif /* SSHDIST_IKEV1 */
  int num_cas = 1;
  size_t real_len = certificate_authority_len;
  int i;

  SSH_DEBUG(SSH_D_HIGHSTART, ("Enter SA %p ED %p", ed->ike_sa, ed));

  /* If policymanager is not in active state, we wan't to reject this. */
  if (ssh_pm_get_status(pm) == SSH_PM_STATUS_SUSPENDED)
    goto error;

  /* Ignore request if not in IKE SA negotiation phase. */
  if (p1->n == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Ignoring new certificate request received outside IKE "
		 "negotiation"));
      goto error;
    }

  /* Verify correct authentication domain */
  if (!ssh_pm_auth_domain_check_by_ed(pm, ed))
    goto error;
  else
    ad = p1->auth_domain;

#ifdef SSHDIST_IKEV1
  /* Convert the certificate request data received from the IKEv1 library
     (which contains the the Distinguished Name encoding of the Issuer Name
     of the X.509 certificate authority) into the format the policy manager
     expects (for IKEv2 certificate requests). Lookup the CA certificate
     from the CMI and extract the KID from the certificate. */
  if (p1->ike_sa->flags & SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_IKEV1)
    {
      SshX509Certificate x509cert = NULL;
      SshCMSearchConstraints search = NULL;
      SshCertDBKey *search_keys = NULL;
      SshCMCertList cert_list = NULL;
      SshCMCertificate cmcert = NULL;
      SshCMStatus status;
      
      search = ssh_cm_search_allocate();
      if (search == NULL)
	return;
      
      if (!ssh_cm_key_set_dn(&search_keys, certificate_authority,
			     certificate_authority_len))
	{
	  SSH_DEBUG(SSH_D_ERROR,
		    ("Could not set DER DN for a certificate search"));
	  ssh_cm_search_free(search);
	  return;
	}
      
      ssh_cm_search_set_keys(search, search_keys);
      
      /* Find the certificate. */
      status = ssh_cm_find_local_cert(ad->cm, 
                                      search, &cert_list);
      if (status != SSH_CM_STATUS_OK)
	{
	  SSH_DEBUG(SSH_D_ERROR, ("Search failed: %d", status));
	  return;
	}
      
      /* And use the first one. */
      cmcert = ssh_cm_cert_list_first(cert_list);
      ssh_cm_cert_list_free(ad->cm, cert_list);
      
      /* Convert it into an X.509 certificate. */
      if (ssh_cm_cert_get_x509(cmcert, &x509cert) != SSH_CM_STATUS_OK)
	{
	  ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_WARNING,
			"Could not convert CMi certificate to X.509 "
			"certificate");
	  return;
	}
      
      ssh_cm_cert_free(cmcert);
      
      kid = ssh_x509_cert_compute_key_identifier_ike(x509cert, "sha1", 
						     &kid_len);
      
      ssh_x509_cert_free(x509cert);
      
      if (kid == NULL)
	return;
      
      SSH_DEBUG_HEXDUMP(SSH_D_LOWOK, ("The CA's KEY ID is"), kid, kid_len);
      
      ca = kid;
      ca_len = kid_len;
    }
  else
#endif /* SSHDIST_IKEV1 */
    {
      ca = (unsigned char *)certificate_authority;
      ca_len = certificate_authority_len;
    }
  
  switch (ca_encoding)
    {
    case SSH_IKEV2_CERT_X_509:
      if ((ca_len % 20) != 0)
	{
	  SSH_DEBUG(SSH_D_FAIL, ("Invalid CA public key hash length %d",
				 ca_len));
	  return;
	}
      real_len = 20;
      num_cas = ca_len / real_len;
      break;

    default:
      SSH_DEBUG(SSH_D_FAIL, ("Unsupported CA encoding %d", ca_encoding));
      return;
      break;
    }

  ca_encodings =
    ssh_realloc(p1->n->crs.ca_encodings,
		p1->n->crs.num_cas * sizeof(*p1->n->crs.ca_encodings),
		(p1->n->crs.num_cas + num_cas) 
		* sizeof(*p1->n->crs.ca_encodings));
  cas =
    ssh_realloc(p1->n->crs.cas,
		p1->n->crs.num_cas * sizeof(*p1->n->crs.cas),
		(p1->n->crs.num_cas + num_cas) * sizeof(*p1->n->crs.cas));
  ca_lens =
    ssh_realloc(p1->n->crs.ca_lens,
		p1->n->crs.num_cas * sizeof(*p1->n->crs.ca_lens),
		(p1->n->crs.num_cas + num_cas) * sizeof(*p1->n->crs.ca_lens));

  if (ca_encodings == NULL || cas == NULL || ca_lens == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Could not add new certificate request"));
      /* Sorry, we must free also the old ones since the ssh_realloc()
         API requires us to know the old length and now some of our
         arrays might use the old length and some the new length. */

      goto error;
    }

  /* Add new certificate request. */
  for (i = 0; i < num_cas; i++)
    {
      ca_encodings[p1->n->crs.num_cas + i] = ca_encoding;

      if ((cas[p1->n->crs.num_cas + i] =
	   ssh_memdup(ca + (i * real_len), real_len))
	  == NULL)
	goto error;

      ca_lens[p1->n->crs.num_cas + i] = real_len;
    }
  p1->n->crs.ca_encodings = ca_encodings;
  p1->n->crs.cas = cas;
  p1->n->crs.ca_lens = ca_lens;
  p1->n->crs.num_cas += num_cas;
  if (kid)
    ssh_free(kid);
  return;

 error:
  if (kid)
    ssh_free(kid);
  if (ca_encodings)
    ssh_free(ca_encodings);
  if (cas)
    ssh_free(cas);
  if (ca_lens)
    ssh_free(ca_lens);
  
  if (p1->n != NULL)
    {
      if (p1->n->crs.cas)
	{
	  for (i = 0; i < p1->n->crs.num_cas; i++)
	    ssh_free(p1->n->crs.cas[i]);
	}
      
      ssh_free(p1->n->crs.ca_encodings);
      ssh_free(p1->n->crs.cas);
      ssh_free(p1->n->crs.ca_lens);
      memset(&p1->n->crs, 0, sizeof(p1->n->crs));
    }
}

/***************************** New Certificate *******************************/

void
ssh_pm_ike_new_certificate(SshSADHandle sad_handle,
			   SshIkev2ExchangeData ed,
			   SshIkev2CertEncoding cert_encoding,
			   const unsigned char *cert_data,
			   size_t cert_data_len)
{
  SshPm pm = sad_handle->pm;
  SshPmP1 p1 = (SshPmP1) ed->ike_sa;
  SshX509Certificate x509 = NULL;
  SshCMCertificate cert;
  Boolean ca, critical;
  size_t pathlength = 0;

  SSH_DEBUG(SSH_D_MIDSTART,
            ("New certificate: encoding=%s(%d)",
             ssh_ikev2_cert_encoding_to_string(cert_encoding),
	     cert_encoding));
  SSH_DEBUG_HEXDUMP(SSH_D_PCKDMP, ("Certificate:"),
                    cert_data, cert_data_len);






  if (ssh_pm_get_status(pm) == SSH_PM_STATUS_DESTROYED)
    {
      SSH_DEBUG(SSH_D_FAIL, ("PM is going down, failing certificate install"));
      return;
    }

  /* Ignore certificate if not in IKE SA negotiation phase. */
  if (p1->n == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL,
		("Ignoring new certificate received outside IKE negotiation"));
      return;
    }

  /* Verify correct authentication domain */
  if (!ssh_pm_auth_domain_check_by_ed(pm, ed))
    {
      SSH_DEBUG(SSH_D_FAIL, ("Unable to get authentication domain, failed "
                             "to install certificate."));
      return;
    }

  switch (cert_encoding)
    {
    case SSH_IKEV2_CERT_ARL:
    case SSH_IKEV2_CERT_CRL:
      /* Add the CRL to the Certificate Manager. */
      if (!ssh_pm_cm_new_crl(p1->auth_domain->cm, 
                             cert_data, cert_data_len, TRUE))
        SSH_DEBUG(SSH_D_FAIL, ("Could not add CRL into certificate manager"));
      break;

    case SSH_IKEV2_CERT_PKCS7_WRAPPED_X_509:
      {
        SshCMStatus ret;

        ret = ssh_cm_add_pkcs7_ber(p1->auth_domain->cm,
				   (unsigned char*)cert_data,
                                   cert_data_len);
        if (ret != SSH_CM_STATUS_ALREADY_EXISTS)
          SSH_DEBUG(SSH_D_FAIL, ("ssh_cm_add failed: %d", ret));
      }
      break;

    case SSH_IKEV2_CERT_RAW_RSA_KEY:
      break;

    case SSH_IKEV2_CERT_X_509:
      {
	/* Add certificate to cache */
        SSH_ASSERT(p1->auth_domain != NULL);
	cert = ssh_pm_auth_domain_add_cert_internal(sad_handle->pm, 
                                                    p1->auth_domain,
                                                    cert_data, cert_data_len, 
                                                    TRUE);
	if (cert == NULL)
	  {
	    SSH_DEBUG(SSH_D_FAIL, ("Unable to add certificate to cache"));

	    return;
	  }
	SSH_ASSERT(cert != NULL);

	/* Classify certificate and store certificate id */
	ca = FALSE;
	if (ssh_cm_cert_get_x509(cert, &x509) != SSH_CM_STATUS_OK)
	  {
	    SSH_DEBUG(SSH_D_FAIL, ("Could not get x509 certificate"));
	    return;
	  }
	ssh_x509_cert_get_basic_constraints(x509, &pathlength, &ca, &critical);
	if (ca)
	  {
	    if (p1->n->num_ca_certificate_ids < SSH_PM_P1N_NUM_CA_CERT_IDS)
	      {
		p1->n->ca_certificate_ids[p1->n->num_ca_certificate_ids]
		  = ssh_cm_cert_get_cache_id(cert);
		p1->n->num_ca_certificate_ids++;
	      }
	  }
	else
	  {
	    if (p1->n->num_user_certificate_ids < SSH_PM_P1N_NUM_USER_CERT_IDS)
	      {
		p1->n->user_certificate_ids[p1->n->num_user_certificate_ids]
		  = ssh_cm_cert_get_cache_id(cert);
		p1->n->num_user_certificate_ids++;   
	      }
	  }
	if (x509)
	  ssh_x509_cert_free(x509);
      }
      break;

    case SSH_IKEV2_CERT_HASH_AND_URL_X509:
    case SSH_IKEV2_CERT_HASH_AND_URL_X509_BUNDLE:
      /* Bundle identifier is stored into negotiation to be used
	 later, when the search is made. */
      if (cert_data_len > 28) /* 20 + 'http://x/' */
	{
	  void *tmp;

	  if ((tmp = ssh_realloc(p1->n->cert_access_urls,
				 p1->n->num_cert_access_urls *
				 sizeof(char *),
				 (1 + p1->n->num_cert_access_urls) *
				 sizeof(char *)))
	      != NULL)
	    {
	      p1->n->cert_access_urls = tmp;
	      if ((p1->n->cert_access_urls[p1->n->num_cert_access_urls] =
                   ssh_memdup(cert_data + 20, cert_data_len - 20)) != NULL)
                p1->n->num_cert_access_urls += 1;
	    }
	}
      break;

    default:
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Unsupported certificate encoding `%s' (%d)",
		 ssh_ikev2_cert_encoding_to_string(cert_encoding),
                 cert_encoding));
      break;

    }
}
#endif /* SSHDIST_CERT */
#endif /* SSHDIST_IKE_CERT_AUTH */
