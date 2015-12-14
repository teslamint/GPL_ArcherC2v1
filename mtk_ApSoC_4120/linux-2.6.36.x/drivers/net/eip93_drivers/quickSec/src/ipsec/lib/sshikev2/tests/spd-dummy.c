/*
  File: spd-dummy.c

  Copyright:
        Copyright 2004 SFNT Finland Oy.
	All rights reserved.

  Description:
  	Dummy SPD module
*/

#include "sshincludes.h"
#include "sshikev2-initiator.h"
#include "sshikev2-util.h"
#include "sshikev2-spd.h"
#include "sshikev2-exchange.h"
#include "spd-dummy.h"
#include "dummy-if.h"

#define SSH_DEBUG_MODULE "TestIkev2SPD"

#ifdef SSHDIST_IKE_MOBIKE
Boolean peer_supports_mobike = FALSE;
extern Boolean mobike_supported;
#endif /* SSHDIST_IKE_MOBIKE */

#ifdef SSH_IKEV2_MULTIPLE_AUTH
extern Boolean use_multiple_auth;
#endif /* SSH_IKEV2_MULTIPLE_AUTH */

/* IKE SA */

extern Boolean g_ike_nomatch, g_ipsec_nomatch;

SshOperationHandle
d_spd_fill_ike_sa(SshSADHandle sad_handle,
		  SshIkev2ExchangeData ed,
		  SshIkev2SpdFillSACB reply_callback,
		  void *reply_callback_context)
{
  SshIkev2Error status = SSH_IKEV2_ERROR_OK;
  SshIkev2PayloadSA ike_sa_payload = NULL;

  SSH_DEBUG(SSH_D_HIGHSTART, ("Enter SA %p ED %p", ed->ike_sa, ed));

  if (g_ike_nomatch)
    {
      if ((ike_sa_payload =
	   ssh_ikev2_sa_dup(sad_handle, sad_handle->default_ike_nosa)) == NULL)
	status = SSH_IKEV2_ERROR_OUT_OF_MEMORY;
    }
  else
    {
      if ((ike_sa_payload =
	   ssh_ikev2_sa_dup(sad_handle, sad_handle->default_ike_sa)) == NULL)
	status = SSH_IKEV2_ERROR_OUT_OF_MEMORY;
    }

  (*reply_callback)(status,
		    ike_sa_payload,
		    reply_callback_context);

  return NULL;
}

Boolean supported(SshIkev2TransformID id,
		  struct TransformDefRec *supported,
		  size_t num_supported)
{
  int i;
  for (i = 0; i < num_supported; i++)
    {
      if (id == supported[i].transform)
	return TRUE;
    }
  return FALSE;
}

SshOperationHandle
d_spd_select_ike_sa(SshSADHandle sad_handle,
		    SshIkev2ExchangeData ed,
		    SshIkev2PayloadSA sa_in,
		    SshIkev2SpdSelectSACB reply_callback,
		    void *reply_callback_context)
{
  SshIkev2PayloadTransform selected_transforms[SSH_IKEV2_TRANSFORM_TYPE_MAX];
  SshIkev2Error status;
  int proposal_index;
  SshIkev2SaSelectionError ike_sa_selection_failure_mask = 0;

  SSH_DEBUG(SSH_D_HIGHSTART, ("Enter SA %p ED %p", ed->ike_sa, ed));
  if (ssh_ikev2_sa_select(sa_in, sad_handle->default_ike_sa,
			  &proposal_index,
			  selected_transforms,
			  &ike_sa_selection_failure_mask))
    status = SSH_IKEV2_ERROR_OK;
  else
    {
      SSH_DEBUG(SSH_D_FAIL, ("SA selection failed error mask %x",
			     (unsigned int) ike_sa_selection_failure_mask));
      status = SSH_IKEV2_ERROR_NO_PROPOSAL_CHOSEN;
    }

  (*reply_callback)(status, proposal_index, selected_transforms,
		    reply_callback_context);
  return NULL;
}

/* Notifications */

extern int opt_client;

SshOperationHandle
d_spd_notify_request(SshSADHandle sad_handle,
		     SshIkev2ExchangeData ed,
		     SshIkev2SpdNotifyCB reply_callback,
		     void *reply_callback_context)
{
  SshIkev2Error status = SSH_IKEV2_ERROR_OK;
  SshIkev2ProtocolIdentifiers protocol = SSH_IKEV2_PROTOCOL_ID_IKE;
  unsigned char *spi = NULL, *notify_data = NULL;
  size_t spi_size = 0, notify_data_size = 0;
  SshIkev2NotifyMessageType notify_type = SSH_IKEV2_NOTIFY_RESERVED;

  SSH_DEBUG(SSH_D_HIGHSTART, ("Enter SA %p ED %p", ed->ike_sa, ed));

#if 1
  if (!opt_client &&
      (ed->state == SSH_IKEV2_STATE_REKEY_IKE
       || ((ed->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_INITIATOR)
	   && ed->state == SSH_IKEV2_STATE_IKE_AUTH_1ST)
#ifdef SSH_IKEV2_MULTIPLE_AUTH
       || (!(ed->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_INITIATOR)
           && ed->ike_ed
           && !(ed->ike_ed->second_eap_auth)
	   && ed->state == SSH_IKEV2_STATE_IKE_AUTH_LAST)
       || (!(ed->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_INITIATOR)
           && ed->ike_ed
           && ed->ike_ed->second_eap_auth
           && ed->ike_ed->first_auth_done
           && ed->ike_ed->eap_state == SSH_IKEV2_EAP_DONE
	   && ed->state == SSH_IKEV2_STATE_IKE_AUTH_LAST)
#else /* SSH_IKEV2_MULTIPLE_AUTH */
       || (!(ed->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_INITIATOR)
	   && ed->state == SSH_IKEV2_STATE_IKE_AUTH_LAST)
#endif /* SSH_IKEV2_MULTIPLE_AUTH */
       )
      )
    {
      unsigned char buffer[4];

      SSH_PUT_32BIT(buffer, 2);
      (*reply_callback)(SSH_IKEV2_ERROR_OK,
			0, NULL, 0,
			SSH_IKEV2_NOTIFY_SET_WINDOW_SIZE,
			buffer, sizeof(buffer),
			reply_callback_context);
    }
#endif
  
#ifdef SSHDIST_IKE_MOBIKE
  /* Responder indicates MOBIKE supported in the IKE_AUTH exchange if MOBIKE 
     is locally supported and a MOBIKE supported notify was received from 
     the initiator. */
  if (!(ed->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_INITIATOR) &&
      (ed->state == SSH_IKEV2_STATE_IKE_AUTH_LAST) && 
      mobike_supported && peer_supports_mobike)
    {
      SSH_DEBUG(SSH_D_MIDOK, ("Indicating support for MOBIKE"));
      (*reply_callback)(SSH_IKEV2_ERROR_OK,
			0, NULL, 0,
			SSH_IKEV2_NOTIFY_MOBIKE_SUPPORTED,
			NULL, 0,
			reply_callback_context);
    }
#endif /* SSHDIST_IKE_MOBIKE */

#ifdef SSH_IKEV2_MULTIPLE_AUTH
  if (!(ed->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_INITIATOR) &&
      (ed->state == SSH_IKEV2_STATE_IKE_INIT_SA) && 
      use_multiple_auth)
    {
      SSH_DEBUG(SSH_D_MIDOK, ("Indicating support for multiple "
                              "authentications"));
      (*reply_callback)(SSH_IKEV2_ERROR_OK,
			0, NULL, 0,
			SSH_IKEV2_NOTIFY_MULTIPLE_AUTH_SUPPORTED,
			NULL, 0,
			reply_callback_context);
    }
#endif /* SSH_IKEV2_MULTIPLE_AUTH */


  (*reply_callback)(status,
		    protocol, spi, spi_size,
		    notify_type, notify_data, notify_data_size,
		    reply_callback_context);

  return NULL;
}

void
d_spd_notify_received(SshSADHandle sad_handle,
		      SshIkev2NotifyState notify_state,
		      SshIkev2ExchangeData ed,
		      SshIkev2ProtocolIdentifiers protocol_id,
		      unsigned char *spi,
		      size_t spi_size,
		      SshIkev2NotifyMessageType notify_message_type,
		      unsigned char *notification_data,
		      size_t notification_data_size)
{
  SshIkev2Error status;

  SSH_DEBUG(SSH_D_HIGHSTART, ("Enter SA %p ED %p", ed->ike_sa, ed));

#ifdef SSHDIST_IKE_MOBIKE
  if (!(ed->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_INITIATOR))
    {
      if (notify_message_type == SSH_IKEV2_NOTIFY_MOBIKE_SUPPORTED)
	{
	  SSH_DEBUG(SSH_D_MIDOK, 
		    ("Received MOBIKE supported notify from initiator"));
	  peer_supports_mobike = TRUE;
	}

      if (notify_message_type == SSH_IKEV2_NOTIFY_UPDATE_SA_ADDRESSES)
	{
	  SshIkev2Server server;
	  SshIpAddrStruct remote_ip;
	  SshUInt16 remote_port;

	  remote_ip = *(ed->remote_ip);
	  remote_port = ed->remote_port;
	  server = ed->server;
	  
	  SSH_DEBUG(SSH_D_MIDOK, ("Updating IP addresses in IKE SA %p "
				  "from %@:%@ to %@ %@",
				  ed->ike_sa,
				  ssh_ipaddr_render, 
				  ed->ike_sa->server->ip_address,
				  ssh_ipaddr_render, 
				  ed->ike_sa->remote_ip,
				  ssh_ipaddr_render, server->ip_address,
				  ssh_ipaddr_render, &remote_ip));

	  /* Update the addresses in the IKE SA. We omit the RR check. */
	  status = ssh_ikev2_ike_sa_change_addresses(ed->ike_sa,
						     server,
						     &remote_ip,
						     remote_port, 0);
	  
	  SSH_DEBUG(status ? SSH_D_FAIL : SSH_D_MIDOK, 
		    ("IKE SA %p addresses updated with status %d", 
		     ed->ike_sa, status));
	}
    }
#endif /* SSHDIST_IKE_MOBIKE */

  return;
}

/* IPSEC */

SshOperationHandle
d_spd_fill_ipsec_sa(SshSADHandle sad_handle,
		    SshIkev2ExchangeData ed,
		    SshIkev2SpdFillSACB reply_callback,
		    void *reply_callback_context)
{
  SshIkev2Error status = SSH_IKEV2_ERROR_OK;
  SshIkev2PayloadSA ipsec_sa_payload = NULL;

  SSH_DEBUG(SSH_D_HIGHSTART, ("Enter SA %p ED %p", ed->ike_sa, ed));

  if (g_ipsec_nomatch)
    {
      if ((ipsec_sa_payload =
	   ssh_ikev2_sa_dup(sad_handle, sad_handle->default_ipsec_nosa))
	  == NULL)
	status = SSH_IKEV2_ERROR_OUT_OF_MEMORY;
    }
  else
    {
      if ((ipsec_sa_payload =
	   ssh_ikev2_sa_dup(sad_handle, sad_handle->default_ipsec_sa)) == NULL)
	status = SSH_IKEV2_ERROR_OUT_OF_MEMORY;
    }

  (*reply_callback)(status,
		    ipsec_sa_payload,
		    reply_callback_context);

  return NULL;
}

SshOperationHandle
d_spd_select_ipsec_sa(SshSADHandle sad_handle,
		      SshIkev2ExchangeData ed,
		      SshIkev2PayloadSA sa_in,
		      SshIkev2SpdSelectSACB reply_callback,
		      void *reply_callback_context)
{
  SshIkev2PayloadTransform selected_transforms[SSH_IKEV2_TRANSFORM_TYPE_MAX];
  SshIkev2SaSelectionError ipsec_sa_selection_failure_mask = 0;
  SshIkev2Error status;
  int proposal_index;

  SSH_DEBUG(SSH_D_HIGHSTART, ("Enter SA %p ED %p", ed->ike_sa, ed));
  if (ssh_ikev2_sa_select(sa_in, sad_handle->default_ipsec_sa,
			  &proposal_index,
			  selected_transforms,
			  &ipsec_sa_selection_failure_mask))
    status = SSH_IKEV2_ERROR_OK;
  else
    {
      SSH_DEBUG(SSH_D_FAIL, ("SA selection failed error mask %x",
			     (unsigned int) ipsec_sa_selection_failure_mask));
      status = SSH_IKEV2_ERROR_NO_PROPOSAL_CHOSEN;
    }

  (*reply_callback)(status, proposal_index, selected_transforms,
		    reply_callback_context);
  return NULL;
}

/* From t-ikev2.c. */
extern SshIkev2PayloadTS tsi_local, tsi_remote;

SshOperationHandle
d_spd_narrow_ipsec_selector(SshSADHandle sad_handle,
			    SshIkev2ExchangeData ed,
			    SshIkev2PayloadTS ts_in_local,
			    SshIkev2PayloadTS ts_in_remote,
			    SshIkev2SpdNarrowCB reply_callback,
			    void *reply_callback_context)
{
  SshIkev2Error status = SSH_IKEV2_ERROR_OK;
  SshIkev2PayloadTS ts_local, ts_remote;

  ts_local = NULL;
  ts_remote = NULL;

  SSH_DEBUG(SSH_D_HIGHSTART, ("Enter SA %p ED %p", ed->ike_sa, ed));
  SSH_DEBUG(SSH_D_HIGHOK, ("TS proposal = %@ <-> %@",
			   ssh_ikev2_ts_render, ts_in_local,
			   ssh_ikev2_ts_render, ts_in_remote));
  SSH_DEBUG(SSH_D_HIGHOK, ("TS policy   = %@ <-> %@",
			   ssh_ikev2_ts_render, tsi_local,
			   ssh_ikev2_ts_render, tsi_remote));

  /* Return what she wants, we do not have policy */
  if (!ssh_ikev2_ts_narrow(sad_handle,
                           FALSE,
			   &ts_local,
			   ts_in_local,
			   tsi_local) ||
      !ssh_ikev2_ts_narrow(sad_handle,
                           FALSE,
			   &ts_remote,
			   ts_in_remote,
			   tsi_remote))
    {
      SSH_DEBUG(SSH_D_ERROR, ("Could not narrow traffic selectors SA %p ED %p",
			      ed->ike_sa, ed));
      status = SSH_IKEV2_ERROR_TS_UNACCEPTABLE;
    }
  else
    {
      SSH_DEBUG(SSH_D_HIGHOK, ("TS narrowed = %@ <-> %@",
			       ssh_ikev2_ts_render, ts_local,
			       ssh_ikev2_ts_render, ts_remote));
    }

  (*reply_callback)(status,
		    ts_local, ts_remote,
		    reply_callback_context);

  if (ts_local)
    ssh_ikev2_ts_free(sad_handle, ts_local);
  if (ts_remote)
    ssh_ikev2_ts_free(sad_handle, ts_remote);
  return NULL;
}


void
d_spd_responder_exchange_done(SshSADHandle sad_handle,
			      SshIkev2Error error,
			      SshIkev2ExchangeData ed)
{
  SSH_DEBUG(SSH_D_HIGHSTART, ("Enter SA %p ED %p", ed->ike_sa, ed));
}

/* eof */
