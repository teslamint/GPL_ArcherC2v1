/*
 * spd_ike_delete.c
 *
 * Copyright:
 *       Copyright (c) 2002-2006 SFNT Finland Oy.
 *       All rights reserved.
 *
 * Utility functions related to deletion of IKE/IPSec SA's.
 * Initial contact notification processing is also handled here.
 */

#include "sshincludes.h"
#include "quicksecpm_internal.h"
#include "sshnameserver.h"
#include "sshadt.h"
#include "sshadt_bag.h"

#define SSH_DEBUG_MODULE "SshPmUtilIke"

/*-----------------------------------------------------------------------*/
/* Notify callbacks for ssh_ikev2_ike_sa_delete().                       */
/*-----------------------------------------------------------------------*/

void pm_ike_sa_delete_done_callback(SshSADHandle sad_handle,
				    SshIkev2Sa sa,
				    SshIkev2ExchangeData ed,
				    SshIkev2Error error)
{
  SshPmP1 p1 = (SshPmP1) sa;

  if (p1 != NULL)
    p1->initiator_ops[PM_IKE_INITIATOR_OP_DELETE] = NULL;




  if (ed != NULL)
    {
      if (p1 && p1->n && (error == SSH_IKEV2_ERROR_OK))
	{
	  /* Wake up the thread controlling this negotiation.  We do this
	     both for initiator and responder case. */
	  SSH_DEBUG(SSH_D_LOWOK, ("Waking up Phase-1 thread"));
	  p1->done = 1;
	  p1->failed = 1;
	  ssh_fsm_continue(&p1->n->thread);
	}
    }

  SSH_DEBUG(SSH_D_LOWSTART,  ("IKE SA delete done callback, ike error %s",
			      ssh_ikev2_error_to_string(error)));
}

/* Notify callback for ssh_ikev2_ike_sa_delete(). If 'error' indicates that
   the sending of delete notification failed, then this function will call
   ssh_ikev2_ike_sa_delete() with SSH_IKEV2_IKE_DELETE_FLAGS_NO_NOTIFICATION
   to delete the IKE SA. */
void pm_ike_sa_delete_notification_done_callback(SshSADHandle sad_handle,
						 SshIkev2Sa sa,
						 SshIkev2ExchangeData ed,
						 SshIkev2Error error)
{
  SshPmP1 p1 = (SshPmP1) sa;

  if (p1 != NULL)
    p1->initiator_ops[PM_IKE_INITIATOR_OP_DELETE] = NULL;

  switch (error)
    {
    case SSH_IKEV2_ERROR_WINDOW_FULL:
      /* IKE SA was not deleted because sending of SA delete
	 notification failed. Redelete IKE SA with
	 SSH_IKEV2_IKE_DELETE_FLAGS_NO_NOTIFICATION */

      if (p1)
	{
	  SSH_PM_IKEV2_IKE_SA_DELETE(p1,
				    SSH_IKEV2_IKE_DELETE_FLAGS_NO_NOTIFICATION,
				    pm_ike_sa_delete_done_callback);
	}
      break;

    default:
      /* Complete SA deletion */
      pm_ike_sa_delete_done_callback(sad_handle, sa, ed, error);
      break;
    }
}


/*-----------------------------------------------------------------------*/
/* Sending delete notifications                                          */
/*-----------------------------------------------------------------------*/

/* Internal utility function for sending out IPsec delete notifications.
   This returns the success of the operation using SshIkev2Error (for 
   conviniency). */
SshIkev2Error
pm_p1_send_ipsec_delete_notifications(SshPm pm,
				      SshPmP1 p1,
				      SshUInt32 *esp_spis,
				      SshUInt32 num_esp_spis,
				      SshUInt32 *ah_spis,
				      SshUInt32 num_ah_spis,
				      SshIkev2NotifyCB callback)
{
  SshIkev2ExchangeData ed = NULL;
  int slot;

  SSH_PM_ASSERT_P1(p1);

  SSH_DEBUG(SSH_D_LOWOK,
	    ("Sending delete notification for %d ESP, %d AH SPIs",
	     (int) num_esp_spis, (int) num_ah_spis));

  if ((num_esp_spis + num_ah_spis) == 0)    
    return SSH_IKEV2_ERROR_INVALID_ARGUMENT;
  
  if (!pm_ike_async_call_possible(p1->ike_sa, &slot))
    {
      SSH_DEBUG(SSH_D_NICETOKNOW,
		("Cannot use this IKE SA for sending delete notify"));
      return SSH_IKEV2_ERROR_WINDOW_FULL;
    }
  
  ed = ssh_ikev2_info_create(p1->ike_sa, 0);
  if (ed == NULL)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, 
		("Could not allocate exchange data for sending delete "
		 "notifications"));
      goto error;
    }

  ed->application_context = NULL;

  if (num_esp_spis)
    {
      if (ssh_ikev2_info_add_delete(ed, SSH_IKEV2_PROTOCOL_ID_ESP,
				    num_esp_spis, esp_spis, 0)
	  != SSH_IKEV2_ERROR_OK)
	goto error;
    }
  
  if (num_ah_spis)
    {
      if (ssh_ikev2_info_add_delete(ed, SSH_IKEV2_PROTOCOL_ID_AH,
				    num_ah_spis, ah_spis, 0)
	  != SSH_IKEV2_ERROR_OK)
	goto error;
    }
  
  PM_IKE_ASYNC_CALL(p1->ike_sa, ed, slot, ssh_ikev2_info_send(ed, callback));
  
  return SSH_IKEV2_ERROR_OK;
  
 error:
  SSH_DEBUG(SSH_D_NICETOKNOW, ("failed"));
  if (ed)
    ssh_ikev2_info_destroy(ed);
  return SSH_IKEV2_ERROR_OUT_OF_MEMORY;
}

/* Either p1 or tunnel, rule, dst and port. Note that p1 may be unusable.
   If p1 is not given, then p1 lookup (using tunnel, rule and dst) will 
   ignore unusable p1's. This expects that PM is not suspended. */
void
ssh_pm_send_ipsec_delete_notification(SshPm pm,
				      SshUInt32 peer_handle,
                                      SshPmTunnel tunnel,
                                      SshPmRule rule,
                                      SshInetIPProtocolID ipproto,
                                      SshUInt32 spi)
{
  SshPmPeer peer;
  SshPmP1 p1;
  int slot;
  SshPmStatus pm_status = ssh_pm_get_status(pm);
  
  if (ipproto != SSH_IPPROTO_AH && ipproto != SSH_IPPROTO_ESP)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW,
		("Cannot send delete notification for IP protocol %d",
		 (int) ipproto));
      return;
    }

  if (pm_status == SSH_PM_STATUS_DESTROYED)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW,
		("Cannot send delete notification, pm shutting down"));
      return;
    }

  /* Lookup peer. */
  peer = ssh_pm_peer_by_handle(pm, peer_handle);
  if (peer == NULL)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW,
		("No peer object found for peer handle 0x%lx",
		 (unsigned long) peer_handle));
      return;
    }

  if (peer->manual_key)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW,
		("No delete notification sent for manually keyed IPsec SA"));
      return;
    }

  /* Fetch IKE SA for peer. */
  p1 = ssh_pm_p1_by_peer_handle(pm, peer_handle);

  /* If there is no IKE SA or IKE SA is marked unusable, try to find
     a more usable IKE SA. */
  if (p1 == NULL || p1->unusable)
    {
      if (rule != NULL && tunnel != NULL && peer != NULL)
	{
	  /* Lookup a matching usable IKE SA. */ 
	  p1 = ssh_pm_lookup_p1(pm, rule, tunnel, peer_handle, NULL, NULL, 
				TRUE);
	  if (p1 == NULL || p1->unusable)
	    {
	      /* Fallback to using the possibly unusable IKE SA. */
	      p1 = ssh_pm_p1_by_peer_handle(pm, peer_handle);
	    }
	}
    }
  
  if (p1 == NULL)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW,
		("No IKE SA to protect IPsec SPI delete notify"));
      return;
    }
  SSH_PM_ASSERT_P1(p1);
  
  /* Check if IKE window is full and request delayed delete notification
     if so. Also if we are suspended or suspending, request delayed delete
     notificatin. */
  if (!pm_ike_async_call_possible(p1->ike_sa, &slot) ||
      pm_status == SSH_PM_STATUS_SUSPENDING ||
      pm_status == SSH_PM_STATUS_SUSPENDED)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW,
		("Cannot use this IKE SA for sending IPsec SPI delete notify, "
		 "requesting delayed IPsec delete notification."));

      ssh_pm_request_ipsec_delete_notification(pm, p1, ipproto, spi);
      return;
    }

  switch (ipproto)
    {
    case SSH_IPPROTO_ESP:
      pm_p1_send_ipsec_delete_notifications(pm, p1, &spi, 1, NULL, 0,
					    pm_ike_info_done_callback);
      break;
      
    case SSH_IPPROTO_AH:
      pm_p1_send_ipsec_delete_notifications(pm, p1, NULL, 0, &spi, 1,
					    pm_ike_info_done_callback);
      break;

    default:
      SSH_NOTREACHED;
    }
}


/****************** Delayed delete notification requests ********************/

static void
pm_free_ipsec_delete_notification_reqs(SshPmIPsecDeleteNotificationRequest n)
{
  SshPmIPsecDeleteNotificationRequest n_next;
  
  while (n)
    {
      n_next = n->next;
      ssh_free(n);
      n = n_next;
    }
}

void 
ssh_pm_free_ipsec_delete_notification_requests(SshPmP1 p1)
{
  SSH_PM_ASSERT_P1(p1);
  pm_free_ipsec_delete_notification_reqs(p1->delete_notification_requests);
  p1->delete_notification_requests = NULL;
}

/* Internal utility function for sending the delayed delete notification
   requests from a zero timeout. */
static void
pm_send_ipsec_delete_notification_requests(void *context)
{
  SshPmP1 p1 = context;
  SshPmIPsecDeleteNotificationRequest delete_notification_requests, n, n_next;
  SshUInt32 esp_spis[10];
  SshUInt32 ah_spis[10];
  SshUInt8 num_esp_spis = 0;
  SshUInt8 num_ah_spis = 0;
  SshPmStatus status;

  SSH_PM_ASSERT_P1(p1);

  /* If the pm is suspended / suspending, these 
     messages will be handled after suspend ends. */
  status = ssh_pm_get_status(p1->pm);
  if (status == SSH_PM_STATUS_SUSPENDING ||
      status == SSH_PM_STATUS_SUSPENDED)
    goto out;

  delete_notification_requests = p1->delete_notification_requests;
  for (n = delete_notification_requests; n != NULL; n = n_next)
    {
      n_next = n->next;

      if (n->ipproto == SSH_IPPROTO_ESP)
	esp_spis[num_esp_spis++] = n->spi;
      else if (n->ipproto == SSH_IPPROTO_AH)
	ah_spis[num_ah_spis++] = n->spi;
      
      /* Send delete notification if maximum number of SPIs per delete
	 notification is reached, or if this is the last SPI delete
	 request. */
      if (n->next == NULL || ((num_esp_spis + num_ah_spis) >= 10))
	{
	  p1->delete_notification_requests = n_next;
	  
	  if (pm_p1_send_ipsec_delete_notifications(p1->pm, p1,
						    esp_spis, num_esp_spis,
						    ah_spis, num_ah_spis,
						    pm_ike_info_done_callback)
	      == SSH_IKEV2_ERROR_WINDOW_FULL)
	    {
	      /* Put requests back in the list for later processing. */
	      p1->delete_notification_requests = delete_notification_requests;
	      goto out;
	    }
	  
	  /* Free processed requests. */
	  n->next = NULL;
	  pm_free_ipsec_delete_notification_reqs(delete_notification_requests);

	  num_esp_spis = 0;
	  num_ah_spis = 0;

	  delete_notification_requests = p1->delete_notification_requests;
	}
    }

  /* Assert that all requests were processed. */
  SSH_ASSERT(p1->delete_notification_requests == NULL);

 out:
  ssh_pm_ike_sa_free_ref(p1->pm->sad_handle, p1->ike_sa);
}

void
ssh_pm_send_ipsec_delete_notification_requests(SshPm pm, SshPmP1 p1)
{
  SSH_PM_ASSERT_P1(p1);

  if (p1->delete_notification_requests == NULL)
    return;

  /* Send delete notifications from a zero timeout. Take a reference to
     protect the p1 from disappearing. */
  ssh_pm_ike_sa_take_ref(pm->sad_handle, p1->ike_sa);
  if (ssh_register_timeout(NULL, 0, 0,
			   pm_send_ipsec_delete_notification_requests, p1)
      == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL,
		("Failed to send delayed delete notifications for p1 %p", p1));
      ssh_pm_free_ipsec_delete_notification_requests(p1);
      ssh_pm_ike_sa_free_ref(pm->sad_handle, p1->ike_sa);
    }
}

/* Register a delayed delete notification request. */
Boolean
ssh_pm_request_ipsec_delete_notification(SshPm pm,
					 SshPmP1 p1,
					 SshInetIPProtocolID ipproto,
					 SshUInt32 spi)
{
  SshPmIPsecDeleteNotificationRequest n;

  SSH_PM_ASSERT_P1(p1);

  if (ipproto != SSH_IPPROTO_AH && ipproto != SSH_IPPROTO_ESP)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW,
		("Cannot send delete notification for IP protocol %d",
		 (int) ipproto));
      return FALSE;
    }

  /* Allocate a delayed delete notification request. */
  n = ssh_calloc(1, sizeof(*n));
  if (n == NULL)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW,
		("Failed to allocate delayed delete notification request"));
      return FALSE;
    }
  
  n->ike_sa_handle = SSH_PM_IKE_SA_INDEX(p1);
  n->spi = spi;
  n->ipproto = ipproto;

  /* Add request to p1. */
  n->next = p1->delete_notification_requests;
  p1->delete_notification_requests = n;

  SSH_DEBUG(SSH_D_NICETOKNOW,
	    ("Added delayed delete notification for p1 %p for %s SPI 0x%08lx",
	     p1,
	     (ipproto == SSH_IPPROTO_ESP ? "ESP" : "AH"),
	     (unsigned long) spi));

  return TRUE;
}


/**************** Sending delete notifications for deleted IPsec SAs ********/

/** This is a callback function for ssh_pm_delete_by_spi(). This function
    sends a delete notification for the SPI value `spi_in'. It 
    expects that the context is a valid p1 that is protected by a IKE SA 
    reference. This will release that IKE SA reference. */
void
ssh_pm_delete_by_spi_send_notifications_cb(SshPm pm,
                                           SshUInt32 transform_index,
                                           SshUInt32 outbound_spi,
                                           SshUInt32 inbound_spi,
                                           SshUInt8 ipproto,
                                           void *context)
{
  SshPmP1 p1 = context;
  SshIkev2ExchangeData ed = NULL;
  SshIkev2ProtocolIdentifiers proto_id = SSH_IKEV2_PROTOCOL_ID_NONE;
  int slot = 0;
  SshPmStatus pm_status = ssh_pm_get_status(pm);

  SSH_PM_ASSERT_P1(p1);

  if (transform_index == SSH_IPSEC_INVALID_INDEX)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("No matching IPsec SA found"));
      goto error;
    }

  if (p1->unusable)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW,
		("Cannot use unusable IKE SA for sending IPsec "
		 "delete notify"));
      goto error;
    }    
  
  if (!pm_ike_async_call_possible(p1->ike_sa, &slot) ||
      pm_status == SSH_PM_STATUS_SUSPENDED ||
      pm_status == SSH_PM_STATUS_SUSPENDING)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW,
		("Cannot use this IKE SA for sending IPsec delete notify, "
		 "requesting delayed IPsec delete notification"));

      ssh_pm_request_ipsec_delete_notification(pm, p1, ipproto, inbound_spi);
      goto error;
    }

  ed = ssh_ikev2_info_create(p1->ike_sa, 0);
  if (ed == NULL)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW,
		("Could not allocate exchange data for sending IPsec "
		 "delete notify"));
      goto error;
    }

  ed->application_context = NULL;

  if (ipproto == SSH_IPPROTO_ESP)
    proto_id = SSH_IKEV2_PROTOCOL_ID_ESP;
  else if (ipproto == SSH_IPPROTO_AH)
    proto_id = SSH_IKEV2_PROTOCOL_ID_AH;
  
  if (ssh_ikev2_info_add_delete(ed, proto_id, 1, &inbound_spi, 0)
      != SSH_IKEV2_ERROR_OK)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW,
		("Could not add delete notification payload"));
      goto error;
    }
  
  SSH_DEBUG(SSH_D_LOWOK,
	    ("Sending delete notification for IPsec %s SPI 0x%08lx",
	     (ipproto == SSH_IPPROTO_ESP ? "ESP" : "AH"),
	     (unsigned long) inbound_spi));

  PM_IKE_ASYNC_CALL(p1->ike_sa, ed, slot,
		    ssh_ikev2_info_send(ed, pm_ike_info_done_callback));
  
  ssh_pm_ike_sa_free_ref(pm->sad_handle, p1->ike_sa);
  return;
  
 error:
  if (ed != NULL)
    ssh_ikev2_info_destroy(ed);
  ssh_pm_ike_sa_free_ref(pm->sad_handle, p1->ike_sa);
}


/************************** Invalidating old inbound SPIs ********************/

/* Completion callback for invalidating old SPIs from engine. */
static void
pm_spi_invalidate_old_cb(SshPm pm,
			 SshEngineTransform tr,
			 void *context)
{
  if (tr == NULL)
    {
      /* With IKEv2 the old SPI value may have been invalidated simultaneously
	 via ssh_pm_delete_by_spi(). Thus it is ok if this function fails, as
	 the SPI has been already invalidated from engine. */
      SSH_DEBUG(SSH_D_LOWOK, ("Failed to invalidate old SPIs"));
      return;
    }

  /* Remove old SPIs from SPI database. */
  ssh_pm_spi_in_remove_by_trd(pm, &tr->data, TRUE);
  ssh_pm_spi_out_remove_by_trd(pm, &tr->data, TRUE);
}

/* Invalidate old inbound and outbound SPIs from engine. */
static void
pm_invalidate_old_inbound_spi(SshPm pm,
			      SshUInt32 tr_index,
			      SshUInt32 inbound_spi)
{
  SSH_DEBUG(SSH_D_HIGHOK,
	    ("Invalidating old SPI from transform index 0x%x with "
	     "inbound SPI 0x%08lx",
	     (unsigned int) tr_index,
	     (unsigned long) inbound_spi));

  ssh_pme_transform_invalidate_old_inbound(pm->engine,
					   tr_index,
					   inbound_spi,
					   pm_spi_invalidate_old_cb,
					   NULL);
}

/* Completion callback for old inbound SPI delete notification sending. */
static void
pm_ike_old_spi_delete_done_cb(SshSADHandle sad_handle,
			      SshIkev2Sa sa,
			      SshIkev2ExchangeData ed,
			      SshIkev2Error error)
{
  SshPmInfo info;
  
  if (ed != NULL)
    {
      SSH_ASSERT(sa == ed->ike_sa);

      PM_IKE_ASYNC_CALL_COMPLETE(sa, ed);
      info = ed->application_context;

      if (info != NULL)
	{
	  switch (info->type)
	    {
	    case SSH_PM_ED_DATA_INFO_OLD_SPI:
	      pm_invalidate_old_inbound_spi(sad_handle->pm,
					    info->u.old_spi.tr_index,
					    info->u.old_spi.inbound_spi);
	      break;

	    default:
	      /* This completion callback is not called for xauth, mobike
		 or normal delete info exchanges. */
	      SSH_NOTREACHED;
	      break;
	    }

	  SSH_PM_ASSERT_ED(ed);
	  ed->application_context = NULL;
	}
    }

  /* Call common information exchange completion callback. */
  pm_ike_info_done_common(sad_handle->pm, (SshPmP1) sa, ed, error);
}


/* Send delete notification for old inbound SPI and invalidate SPI from
   engine. */
void
ssh_pm_send_old_inbound_spi_delete_notification(SshPm pm,
						SshUInt32 peer_handle,
						SshPmTunnel tunnel,
						SshPmRule rule,
						SshInetIPProtocolID ipproto,
						SshUInt32 inbound_spi,
						SshUInt32 outbound_spi,
						SshUInt32 tr_index)
{
  SshPmInfo info = NULL;
  SshIkev2ExchangeData ed = NULL;
  int slot;
  SshPmPeer peer;
  SshPmP1 p1;
  SshPmStatus pm_status = ssh_pm_get_status(pm);

  /* Sanity check. */
  if (ipproto != SSH_IPPROTO_ESP && ipproto != SSH_IPPROTO_AH)
    {
      SSH_DEBUG(SSH_D_ERROR,
		("Cannot send delete notification for IP protocol %d",
		 (int) ipproto));
      return;
    }

  /* Lookup peer. */
  peer = ssh_pm_peer_by_handle(pm, peer_handle);
  if (peer == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL,
		("No peer object found for peer handle 0x%lx",
		 (unsigned long) peer_handle));
      return;
    }

  if (peer->manual_key)
    {
      SSH_DEBUG(SSH_D_ERROR,
		("No delete notification sent for manually keyed IPsec SA"));
      return;
    }

  /* Fetch IKE SA for peer. */
  p1 = ssh_pm_p1_by_peer_handle(pm, peer_handle);

  /* If there is no IKE SA or IKE SA is marked unusable, try to find
     a more usable IKE SA. */
  if (p1 == NULL || p1->unusable)
    {
      if (rule != NULL && tunnel != NULL && peer != NULL)
	{
	  /* Lookup a matching usable IKE SA. */ 
	  p1 = ssh_pm_lookup_p1(pm, rule, tunnel, peer_handle, NULL, NULL, 
				TRUE);
	  if (p1 == NULL || p1->unusable)
	    {
	      /* Fallback to using the possibly unusable IKE SA. */
	      p1 = ssh_pm_p1_by_peer_handle(pm, peer_handle);
	    }
	}
    }
  
  if (p1 == NULL)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW,
		("No IKE SA to protect IPsec SPI delete notify"));
      goto error;
    }
  SSH_PM_ASSERT_P1(p1);

  /* Check if IKE window is full and request delayed delete notification
     if so. Also if we are suspended or suspending, request the delayed 
     notification. */
  if (!pm_ike_async_call_possible(p1->ike_sa, &slot) ||
      pm_status == SSH_PM_STATUS_SUSPENDING ||
      pm_status == SSH_PM_STATUS_SUSPENDED)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Cannot use this IKE SA for sending IPsec SPI delete notify, "
		 "requesting delayed IPsec delete notification."));
      
      ssh_pm_request_ipsec_delete_notification(pm, p1, ipproto, inbound_spi);
      goto error;
    }

  ed = ssh_ikev2_info_create(p1->ike_sa, 0);
  if (ed == NULL)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Could not allocate exchange data for sending delete "
                 "notifications"));
      goto error;
    }

  info = ssh_pm_info_alloc(pm, ed, SSH_PM_ED_DATA_INFO_OLD_SPI);
  if (info == NULL)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW,
		("Could not allocate info exchange context."));
      goto error;
    }

  info->u.old_spi.inbound_spi = inbound_spi;
  info->u.old_spi.tr_index = tr_index;

  ed->application_context = info;

  if (ipproto == SSH_IPPROTO_ESP)
    {
      if (ssh_ikev2_info_add_delete(ed, SSH_IKEV2_PROTOCOL_ID_ESP,
				    1, &inbound_spi, 0) != SSH_IKEV2_ERROR_OK)
	{
	  SSH_DEBUG(SSH_D_NICETOKNOW, ("Could not add delete payload"));
	  goto error;
	}
    }
  else
    {
      if (ssh_ikev2_info_add_delete(ed, SSH_IKEV2_PROTOCOL_ID_AH,
				    1, &inbound_spi, 0) != SSH_IKEV2_ERROR_OK)
	{
	  SSH_DEBUG(SSH_D_NICETOKNOW, ("Could not add delete payload"));
	  goto error;
	}
    }

  /* Mark the SPI having an ongoing negotiation. */
  if (ssh_pm_mark_outbound_spi_neg_started(pm, outbound_spi, inbound_spi)
      == FALSE)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("spi 0x%08lx disappeared from SPI table",
				   (unsigned long) outbound_spi));
      goto error;
    }

  PM_IKE_ASYNC_CALL(p1->ike_sa, ed, slot,
		    ssh_ikev2_info_send(ed, pm_ike_old_spi_delete_done_cb));
  return;

 error:
  SSH_DEBUG(SSH_D_LOWOK,
	    ("Failed sending delete notification, "
	     "invalidating old inbound SPI 0x%08lx silently",
	     (unsigned long) inbound_spi));
  if (ed != NULL)
    ssh_ikev2_info_destroy(ed);

  pm_invalidate_old_inbound_spi(pm, tr_index, inbound_spi);
}


/*************************** Deleting IPsec SAs *****************************/

/* Completion callback for ssh_pme_delete_by_peer_handle. This function
   indicates that the IPsec SA has been destroyed. This function gathers
   the SPIs of the deleted SAs into the SshPmDeleteByIkeSaCBCtx in context,
   and continues deleting SAs by peer handle. When all SAs are deleted this
   sends out the delete notification for the deleted SPIs, and finally deletes
   the IKE SA. */
static void
pm_delete_sas_by_peer_handle_cb(SshPm pm, Boolean done,
				const SshIpAddr peer_addr,
				SshUInt16 peer_port,
				SshUInt8 ipproto,
				SshUInt32 outbound_spi,
				SshUInt32 inbound_spi,
				SshUInt32 peer_handle,
				void *policy_context,
				void *context)
{
  SshUInt32 stored_peer_handle = SSH_PM_PTR_TO_UINT32(context);
  SshPmP1 p1;
  SshPmStatus pm_status;
  SshPmPeer peer;

  /* We have a reference to the IKE peer to make sure it does not disappear. */
  peer = ssh_pm_peer_by_handle(pm, stored_peer_handle);
  SSH_ASSERT(peer != NULL);

  if (!done)
    {
      /* Sanity check ike_sa_handle */
      SSH_ASSERT(stored_peer_handle == peer_handle);
      
      /* Indicate that the SA has been destroyed. */
      ssh_pm_ipsec_sa_event_deleted(pm, outbound_spi, inbound_spi, ipproto);

      /* Send delete notification for IPSec SA */
      SSH_DEBUG(SSH_D_LOWOK, ("Pending delete notification for SPI 0x%08lx",
			      (unsigned long) inbound_spi));


      p1 = ssh_pm_p1_from_ike_handle(pm, peer->ike_sa_handle, FALSE);
      if (p1 == NULL || SSH_PM_P1_DELETED(p1))
        SSH_DEBUG(SSH_D_HIGHOK, ("IKE SA is deleted, cannot set pending"
                                 " IPsec SA delete notifications."));
      else
        ssh_pm_request_ipsec_delete_notification(pm, p1, ipproto, inbound_spi);

      /* There are still IPSec SAs for this peer, continue deleting even
         though we could not set pending delete notifications... */
      ssh_pme_delete_by_peer_handle(pm->engine, stored_peer_handle,
				    pm_delete_sas_by_peer_handle_cb, context);
    }

  /* All done */
  else
    {
      SshTime expire_time = ssh_time() + SSH_PM_IKE_EXPIRE_TIMER_SECONDS;

      /* Check if the IKE SA has been freed */
      p1 = ssh_pm_p1_from_ike_handle(pm, peer->ike_sa_handle, FALSE);
      if (p1 == NULL || SSH_PM_P1_DELETED(p1))
	{
	  SSH_DEBUG(SSH_D_HIGHOK, ("IKE SA is already deleted"));
	  
	  /* Free the IKE peer reference. */
	  ssh_pm_peer_handle_destroy(pm, stored_peer_handle);
	  return;
	}

      p1->delete_childless_sa = 1;
      
      pm_status = ssh_pm_get_status(pm);
      if ((pm_status == SSH_PM_STATUS_ACTIVE) ||
          (pm_status == SSH_PM_STATUS_DESTROYED))
        {
          ssh_pm_send_ipsec_delete_notification_requests(pm, p1);
        }
      /* In suspended / suspending pm status, just make sure IKE SA 
         won't live too long. */
  
      /* Manually set the expire_time, so that the IKE SA gets
         deleted in near future in case the sending of IPSec SA delete
         notification fails. */
      if ((p1->expire_time > expire_time) && !SSH_PM_P1_DELETED(p1))
        {
          SSH_DEBUG(SSH_D_MIDOK,
                    ("Marking IKE SA %p for deletion", p1->ike_sa));

          p1->expire_time = expire_time;
        }

      /* Free the IKE peer reference. */
      ssh_pm_peer_handle_destroy(pm, stored_peer_handle);
    }
}

/* This function deletes all IPsec SAs and IKE SAs with peer identified by
   `peer_handle'. On immediate error this returns FALSE. Otherwise this
   starts deleting the IPsec SAs from the engine and returns TRUE. Note that
   the deletion is asynchronous. */
static Boolean
pm_delete_sas_by_peer_handle(SshPm pm, SshUInt32 peer_handle)
{
  void *ctx;

  ctx = SSH_PM_UINT32_TO_PTR(peer_handle);
  
  ssh_pm_peer_handle_take_ref(pm, peer_handle);
  
  SSH_DEBUG(SSH_D_LOWOK, 
	    ("Deleting IPsec SAs by peer handle 0x%lx",
	     (unsigned long) peer_handle));

  /* The IKE SA is deleted in the callback. */  
  ssh_pme_delete_by_peer_handle(pm->engine, peer_handle,
				pm_delete_sas_by_peer_handle_cb, ctx);
  
  return TRUE;
}

/********************** Deleting IPsec SAs Silently *************************/

/* Completion callback for ssh_pme_delete_by_peer_handle. This function 
   indicates that the SA has been deleted and continues deleting SAs by peer 
   handle. No delete notifications are sent for the deleted SAs. */
static void
pm_delete_ipsec_sas_silently_by_peer_handle_cb(SshPm pm, Boolean done,
					       const SshIpAddr peer_addr,
					       SshUInt16 peer_port,
					       SshUInt8 ipproto,
					       SshUInt32 outbound_spi,
					       SshUInt32 inbound_spi,
					       SshUInt32 peer_handle,
					       void *policy_context,
					       void *context)
{
  if (!done)
    {
      ssh_pm_ipsec_sa_event_deleted(pm, outbound_spi, inbound_spi, ipproto);
      ssh_pme_delete_by_peer_handle(pm->engine, peer_handle, 
				pm_delete_ipsec_sas_silently_by_peer_handle_cb,
				NULL);

    }
  else
    {
      SSH_DEBUG(SSH_D_LOWOK, ("IPsec SAs deleted by peer handle 0x%lx",
			      (unsigned long) peer_handle));      
    }
}

/* This functions deletes silently all IPsec SAs with peer defined by 
   `peer_handle'. */
static void
pm_delete_ipsec_sas_silently_by_peer_handle(SshPm pm, SshUInt32 peer_handle)
{
  SSH_DEBUG(SSH_D_LOWOK, ("Deleting silently IPsec SAs by peer handle 0x%lx",
			  (unsigned long) peer_handle));

  ssh_pme_delete_by_peer_handle(pm->engine, peer_handle, 
				pm_delete_ipsec_sas_silently_by_peer_handle_cb,
				NULL);
}

/************ Deleting IPsec SAs due to notification from other end *********/

void ssh_pm_delete_by_spi(SshPm pm,
			  SshUInt32 spi,
			  SshUInt8 ipproto,
			  const SshIpAddr remote_ip,
			  SshUInt16 remote_ike_port,
			  SshPmSpiDeleteCB callback,
			  void *context)
{
  SshUInt32 tr_index, outbound_spi, inbound_spi;
  SshPmSpiOut spi_out;

  spi_out = ssh_pm_lookup_outbound_spi(pm, TRUE, spi, ipproto, 
				       remote_ip, remote_ike_port);
  if (spi_out == NULL)
    {
      /* Notify user about the success of the operation. */
      if (callback)
	(*callback)(pm, SSH_IPSEC_INVALID_INDEX, 0, 0, 0, context);      
      return;
    }
  
  tr_index = spi_out->trd_index;
  inbound_spi = spi_out->inbound_spi;
  outbound_spi = spi_out->outbound_spi;

  /* If the SA has not been rekeyed we should delete the transform in
     the engine. This will generate a destroyed event immediately or later
     which causes the SPIs to be freed from the SPI database. Note that 
     spi_out may get freed synchronously if usermode engine is used. */
  if (!spi_out->rekeyed)
    {
      SSH_DEBUG(SSH_D_HIGHOK,
		("Deleting engine transform index 0x%x with outbound "
		 "SPI 0x%08lx inbound SPI 0x%08lx",
		 (unsigned int) tr_index,
		 (unsigned long) outbound_spi,
		 (unsigned long) inbound_spi));      
      ssh_pme_delete_by_spi(pm->engine, tr_index, NULL_FNPTR, NULL);
    }

  /* If the SA has been rekeyed we should invalidate the old inbound SPI and
     activate the new outbound SPI and key material for the transform. The 
     SPIs are freed in the completion callback. Note that spi_out may get 
     freed synchronously if usermode engine is used. */
  else
    {
      SSH_DEBUG(SSH_D_HIGHOK,
		("Invalidating old SPI from transform index 0x%x with "
		 "outbound SPI 0x%08lx inbound SPI 0x%08lx",
		 (unsigned int) tr_index,
		 (unsigned long) outbound_spi,
		 (unsigned long) inbound_spi));
      ssh_pme_transform_invalidate_old_inbound(pm->engine,
					       tr_index,
					       inbound_spi,
					       pm_spi_invalidate_old_cb,
					       SSH_PM_UINT32_TO_PTR(tr_index));
    }
  
  if (callback)
    (*callback)(pm, tr_index, outbound_spi, inbound_spi, ipproto, context);

  return;
}

/****************** Initial contact notification processing *****************/

/* The number of seconds an IKE SA is considered to be recently negotiated */
#define SSH_PM_IKE_SA_NEW_LIFETIME 3

/* Process initial contact notification from peer.
   This function is called before SA installation on the responder */
void
ssh_pm_process_initial_contact_notification(SshPm pm, SshPmP1 peer_p1)
{
  SshPmP1 p1, next_p1;
  SshPmPeer peer, next_peer;
  SshUInt32 hash, peer_handle;
  SshTime current_time;
  SshUInt32 flags;

  if (ssh_pm_get_status(pm) == SSH_PM_STATUS_DESTROYED)
    return;

  SSH_PM_ASSERT_P1(peer_p1);

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("Initial contact notification from %@:%d ID %@",
             ssh_ipaddr_render, peer_p1->ike_sa->remote_ip,
	     peer_p1->ike_sa->remote_port,
             ssh_pm_ike_id_render, peer_p1->remote_id));

#ifdef SSHDIST_IPSEC_NAT_TRAVERSAL
  if (peer_p1->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_THIS_END_BEHIND_NAT ||
      peer_p1->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_OTHER_END_BEHIND_NAT)
    {
      if (peer_p1->remote_id->id_type == SSH_IKEV2_ID_TYPE_IPV4_ADDR ||
	  peer_p1->remote_id->id_type == SSH_IKEV2_ID_TYPE_IPV6_ADDR)
	{
	  ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_WARNING,
			"NAT-T initial contact notification with IP "
			"identity %@",
			ssh_pm_ike_id_render, peer_p1->remote_id);
	  ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_WARNING,
			"It is recommended to use non-IP identities with "
			"NAT-T to avoid ID collisions");
	}
    }
#endif /* SSHDIST_IPSEC_NAT_TRAVERSAL */

  /* Delete all IKE SA's (except for `peer_p1') that have the same local 
     and remote identities as `peer_p1'.
     
     Send delete notification to remote end only if the deleted SA is
     reasonably new, and we suspect that the other end might end up
     being out of sync. */
  current_time = ssh_time();

  /* Compute the hash value from IKE remote ID. */
  hash = SSH_PM_IKE_ID_HASH(peer_p1->remote_id);

  for (p1 = pm->ike_sa_id_hash[hash]; p1; p1 = next_p1)
    {
      next_p1 = p1->hash_id_next;

      /* Do not delete 'p1' */
      if (peer_p1 == p1)
	continue;

      /* The local identities must agree */
      if (!ssh_pm_ikev2_id_compare(peer_p1->local_id, p1->local_id))
	continue;

      /* The remote identities must agree */
      if (!ssh_pm_ikev2_id_compare(peer_p1->remote_id, p1->remote_id))
	continue;

      /* Deletion is already ongoing. */
      if (SSH_PM_P1_DELETED(p1))
	continue;

      /* Delete immediately all IPsec SA's belonging to this Phase-I. */

      /* If the SA has been negotiated recently, then send a delete
	 notification to ensure that both ends are in sync.
	 The SA we are deleting might have been negotiated simultaneously
	 with the SA that included the initial contact notification. If so,
	 then we should make sure that the SA we are deleting does not exist
	 in the other end. */
      if ((p1->expire_time - p1->lifetime) >
	  (current_time - SSH_PM_IKE_SA_NEW_LIFETIME))
	{
	  peer_handle = ssh_pm_peer_handle_by_p1(pm, p1);

	  /* This IKE SA has no associated IPsec SAs, continue with IKE SA
	     deletion. */
	  if (peer_handle == SSH_IPSEC_INVALID_INDEX)
	    goto delete_ike_sa;

	  /* Do not use p1 for new negotiations. */
	  p1->unusable = 1;
  
	  /* Start deleting all IPsec SAs and the IKE SA. */
	  if (pm_delete_sas_by_peer_handle(pm, peer_handle) == FALSE)
	    goto delete_ike_sa;
	}

      /* Old SA, assume the other end has rebooted, and do not bother
	 to send a delete notification. */
      else
	{
	delete_ike_sa:
	  /* Now delete the IKE SA and child SAs. */
	  SSH_DEBUG(SSH_D_MIDOK, ("Deleting the IKE SA %p", p1->ike_sa));
	  
	  flags = SSH_IKEV2_IKE_DELETE_FLAGS_NO_NOTIFICATION;
#ifdef SSHDIST_IKEV1
	  flags |= SSH_IKEV2_IKE_DELETE_FLAGS_FORCE_DELETE_NOW;
#endif /* SSHDIST_IKEV1 */
	  
	  /* Request child SA deletion. */
	  p1->delete_child_sas = 1;
	  
	  SSH_ASSERT(p1->initiator_ops[PM_IKE_INITIATOR_OP_DELETE] == NULL);
	  SSH_PM_IKEV2_IKE_SA_DELETE(p1, flags, 
				     pm_ike_sa_delete_done_callback);
	}
    }

  /* Delete IPsec SAs, that have no parent IKEv1 SA. */
  for (peer = ssh_pm_peer_by_ike_sa_handle(pm, SSH_IPSEC_INVALID_INDEX);
       peer != NULL;
       peer = next_peer)
    {
      SSH_ASSERT(peer->ike_sa_handle == SSH_IPSEC_INVALID_INDEX);      
      next_peer = ssh_pm_peer_next_by_ike_sa_handle(pm, peer);

      /* Skip manually keyed SA's. */
      if (peer->manual_key)
	continue;
      
      /* Use IP addresses if no identity information is present in the peer */
      if (!peer->local_id || !peer->remote_id)
	{
	  if (SSH_IP_CMP(peer->remote_ip, peer_p1->ike_sa->remote_ip)
	      || peer->remote_port != peer_p1->ike_sa->remote_port)
	    continue;

	  if (SSH_IP_CMP(peer->local_ip, peer_p1->ike_sa->server->ip_address)
	      || peer->local_port != SSH_PM_IKE_SA_LOCAL_PORT(peer_p1->ike_sa))
	    continue;	    
	}
      else
	{
	  /* The local identities must agree */
	  if (!ssh_pm_ikev2_id_compare(peer->local_id, peer_p1->local_id))
	    continue;
	  
	  /* The remote identities must agree */
	  if (!ssh_pm_ikev2_id_compare(peer->remote_id, peer_p1->remote_id))
	    continue;
	}	  

      /* Do not send delete notifications, as there is no IKE SA. */      
      pm_delete_ipsec_sas_silently_by_peer_handle(pm, peer->peer_handle);
    }
}


/********************** Deletion of SAs by IKE peer handle ******************/















/* Delete all IKE and IPsec SAs with IKE peer `peer_handle'. */
void
ssh_pm_delete_by_peer_handle(SshPm pm, SshUInt32 peer_handle, SshUInt32 flags,
			     SshPmStatusCB callback, void *context)
{
  SshPmP1 p1;
  SshPmPeer peer;
  Boolean sa_deletion_started = FALSE;

  SSH_DEBUG(SSH_D_MIDOK, ("Deleting SAs by peer handle 0x%lx", peer_handle));

  if (peer_handle == SSH_IPSEC_INVALID_INDEX)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failed: Invalid peer_handle"));  
      goto error;
    }

  peer = ssh_pm_peer_by_handle(pm, peer_handle);
  if (peer == NULL)
    goto out;
  
  p1 = ssh_pm_p1_from_ike_handle(pm, peer->ike_sa_handle, FALSE);  
  if (p1 && !SSH_PM_P1_DELETED(p1))
    {
      /* Delete IKE SAs, the child SAs will be deleted automatically */
      p1->delete_child_sas = 1;
      
      sa_deletion_started = TRUE;

#ifdef SSHDIST_IKEV1
      /* IKEv1 SA needs special handling. */
      if (p1->ike_sa->flags & SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_IKEV1)
	{
	  /* Do not use p1 for new negotiations. */
	  p1->unusable = 1;

	  /* Start deleting the IPsec SAs and the IKE SA. */
	  if (pm_delete_sas_by_peer_handle(pm, peer_handle) == FALSE)
	    goto delete_ike_sa;
	}
      else /* IKEv2 SA's can just be deleted. */
#endif /* SSHDIST_IKEV1 */
	{
#ifdef SSHDIST_IKEV1
	delete_ike_sa:
#endif /* SSHDIST_IKEV1 */
	  SSH_DEBUG(SSH_D_LOWOK, ("Deleting the IKE SA %p", p1->ike_sa));

#ifdef SSHDIST_IKEV1	      
	  flags |= SSH_IKEV2_IKE_DELETE_FLAGS_FORCE_DELETE_NOW;	      
#endif /* SSHDIST_IKEV1 */
	  
	  SSH_ASSERT(p1->initiator_ops[PM_IKE_INITIATOR_OP_DELETE] == NULL);
	  SSH_PM_IKEV2_IKE_SA_DELETE(p1, flags,
			((flags & SSH_IKEV2_IKE_DELETE_FLAGS_NO_NOTIFICATION) ?
			 pm_ike_sa_delete_done_callback :
			 pm_ike_sa_delete_notification_done_callback));
	}
    }
  
  /* Delete IPsec SAs, that have no usable parent IKE SA. */
  else
    {
      sa_deletion_started = TRUE;
      
      /* Do not send delete notifications, as there is no usable IKE SA. */
      pm_delete_ipsec_sas_silently_by_peer_handle(pm, peer_handle);
    }
  
 out:
  if (callback)
    (*callback)(pm, sa_deletion_started, context);
  return;

 error:
  if (callback)
    (*callback)(pm, FALSE, context);
}

/********************** Deletion of IPsec SAs on interface change ************/

void
ssh_pm_delete_by_local_address(SshPm pm, SshIpAddr local_ip)
{
  SshPmPeer peer, next_peer;

  if (local_ip == NULL || !SSH_IP_DEFINED(local_ip))
    return;

  /* Delete IPsec SAs, that have no parent IKE SA (i.e. manual key or IKEv1).*/
  for (peer = ssh_pm_peer_by_local_address(pm, local_ip);
       peer != NULL;
       peer = next_peer)
    {
      SSH_ASSERT(SSH_IP_EQUAL(local_ip, peer->local_ip));
      next_peer = ssh_pm_peer_next_by_local_address(pm, peer);

      /* Delete only IKEv1 and manual keyed SA's. IKEv2 keyed child SA's 
	 are deleted with the IKEv2 SA. */
      if (peer->use_ikev1 == FALSE && peer->manual_key == FALSE)
	continue;
      
      /* Do not send delete notifications, as there is no IKE SA. */
      pm_delete_ipsec_sas_silently_by_peer_handle(pm, peer->peer_handle);
    }
}

/********************** Deletion of SAs on PM shutdown ***********************/

/* Delete all IKE and IPsec SAs with peer whose address matches `ip'. */
void
ssh_pm_delete_by_peer(SshPm pm, SshIpAddr ip, SshUInt32 flags,
		      SshPmStatusCB callback, void *context)
{
  SshPmP1 p1, next_p1;
  SshUInt32 i;
  SshPmPeer peer, next_peer;
#ifdef SSHDIST_IKEV1
  SshUInt32 peer_handle;
#endif /* SSHDIST_IKEV1 */
  Boolean sa_deletion_started = FALSE;
  SshUInt32 ike_sa_delete_flags;

  SSH_DEBUG(SSH_D_MIDOK, ("Deleting SAs by peer %@", ssh_ipaddr_render, ip));

  if (ip && !SSH_IP_DEFINED(ip))
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failed: Invalid peer ip"));
      goto error;
    }

  /* Delete IKE SAs, the child SAs will be deleted automatically */
  for (i = 0; i < SSH_PM_IKE_SA_HASH_TABLE_SIZE; i++)
    {
      for (p1 = pm->ike_sa_hash[i]; p1; p1 = next_p1)
	{
	  next_p1 = p1->hash_next;

	  /* IKE peer address does not match. */
	  if (ip != NULL && !SSH_IP_EQUAL(p1->ike_sa->remote_ip, ip))
	    continue;
	  
	  sa_deletion_started = TRUE;

	  /* IKE SA is already deleted. */
	  if (SSH_PM_P1_DELETED(p1))
	    continue;

	  /* Request child SA deletion also. */
	  p1->delete_child_sas = 1;

#ifdef SSHDIST_IKEV1
	  /* IKEv1 SA needs special handling. */
	  if (p1->ike_sa->flags & SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_IKEV1)
	    {
	      peer_handle = ssh_pm_peer_handle_by_p1(pm, p1);

	      /* This IKE SA has no associated IPsec SAs, continue with 
		 IKE SA deletion. */	      
	      if (peer_handle == SSH_IPSEC_INVALID_INDEX)
		goto delete_ike_sa;
	      
	      /* Do not use p1 for new negotiations. */
	      p1->unusable = 1;
	      
	      /* Start deleting all IPsec SAs and the IKE SA. */
	      if (pm_delete_sas_by_peer_handle(pm, peer_handle) == FALSE)
		goto delete_ike_sa;
	    }

	  /* IKEv2 SA's can just be deleted. */
	  else
#endif /* SSHDIST_IKEV1 */
	    {
#ifdef SSHDIST_IKEV1 
	    delete_ike_sa:
#endif /* SSHDIST_IKEV1 */
	      SSH_DEBUG(SSH_D_LOWOK, ("Deleting the IKE SA %p", p1->ike_sa));
	      
	      ike_sa_delete_flags = flags;
#ifdef SSHDIST_IKEV1      
	      ike_sa_delete_flags |= 
		SSH_IKEV2_IKE_DELETE_FLAGS_FORCE_DELETE_NOW;	      
#endif /* SSHDIST_IKEV1 */
	      SSH_ASSERT(p1->initiator_ops[PM_IKE_INITIATOR_OP_DELETE]
			 == NULL);
	      SSH_PM_IKEV2_IKE_SA_DELETE(p1, ike_sa_delete_flags,
		       ((flags & SSH_IKEV2_IKE_DELETE_FLAGS_NO_NOTIFICATION) ?
			 pm_ike_sa_delete_done_callback :
			 pm_ike_sa_delete_notification_done_callback));
	    }
	}
    }

  /* Delete IPsec SAs, that have no parent IKEv1 SA. */
  for (peer = ssh_pm_peer_by_ike_sa_handle(pm, SSH_IPSEC_INVALID_INDEX);
       peer != NULL;
       peer = next_peer)
    {
      SSH_ASSERT(peer->ike_sa_handle == SSH_IPSEC_INVALID_INDEX);
      next_peer = ssh_pm_peer_next_by_ike_sa_handle(pm, peer);

      /* IKE peer address does not match. */
      if (ip != NULL && !SSH_IP_EQUAL(peer->remote_ip, ip))
	continue;
      
      sa_deletion_started = TRUE;

      /* Do not send delete notifications, as there is no IKE SA. */
      pm_delete_ipsec_sas_silently_by_peer_handle(pm, peer->peer_handle);
    }
  
  if (callback)
    (*callback)(pm, sa_deletion_started, context);

  return;

 error:
  if (callback)
    (*callback)(pm, FALSE, context);
}


















