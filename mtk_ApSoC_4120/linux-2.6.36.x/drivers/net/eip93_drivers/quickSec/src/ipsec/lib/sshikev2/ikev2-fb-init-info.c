/**
   File:	ikev2-fb-init-info.c

   @copyright:	Copyright (c) 2005, 2006 SFNT Finland Oy
   All rights reserved.

   Initiator Informational exchange for IKEv1 fallback.

*/

#include "sshincludes.h"
#include "sshikev2-initiator.h"
#include "sshikev2-exchange.h"
#include "ikev2-internal.h"
#include "sshikev2-util.h"

#ifdef SSHDIST_IKEV1
#include "isakmp.h"
#include "ikev2-fb.h"
#include "ikev2-fb-st.h"

#define SSH_DEBUG_MODULE "SshIkev2FallbackInitInfo"

/*--------------------------------------------------------------------*/
/* Initiator information exchanges, except ssh_ikev2_ike_sa_delete    */
/*--------------------------------------------------------------------*/

void ikev2_fb_info_negotiation_destructor(SshFSM fsm, void *context)
{
  SshIkev2FbNegotiation neg = (SshIkev2FbNegotiation) context;

  SSH_DEBUG(SSH_D_LOWOK, ("Freeing fallback negotiation context"));

  /* Free the references to fallback negotiation. */
  ikev2_fb_negotiation_clear_pm_data(neg);
  ikev2_fallback_negotiation_free(neg->fb, neg);
  return;
}

void ikev2_fb_info_p1_negotiation_destructor(SshFSM fsm, void *context)
{
  SshIkev2FbNegotiation neg = (SshIkev2FbNegotiation) context;

  SSH_DEBUG(SSH_D_LOWOK, ("Freeing fallback negotiation context"));
  
  /* IKE SA is protected by the reference taken in ikev2_fb_initiate_info(). 
     Clear the `p1_negotiation_context' pointer as the fallback negotiation
     is going to get freed. */
  SSH_ASSERT(neg->ike_sa != NULL);
  neg->ike_sa->p1_negotiation_context = NULL;

  /* Free the references to fallback negotiation. */
  ikev2_fb_negotiation_clear_pm_data(neg);
  ikev2_fallback_negotiation_free(neg->fb, neg);
  return;
}

static void ikev2_fb_info_abort(void *context)
{
  SshIkev2FbNegotiation neg = context;

  SSH_DEBUG(SSH_D_MIDOK, ("Aborting informational negotiation %p", neg));

  /* Mark the negotiation context aborted. We'll need this information
     as IKEv1 library will call callbacks after
     ssh_ike_abort_negotiation has been called, but we must not call
     neither PM, nor IKE from the sub state machines. */
  neg->aborted = 1;
  neg->ike_error = SSH_IKEV2_ERROR_SA_UNUSABLE;
  if (neg->ed)
    {
      neg->ed->callback = NULL_FNPTR;
      if (neg->ed->info_ed)
	neg->ed->info_ed->flags &= ~SSH_IKEV2_INFO_OPERATION_REGISTERED;
    }

  /* Abort any PM policy function calls */
  if (neg->sub_operation)
    {
      ssh_operation_abort(neg->sub_operation);
      neg->sub_operation = NULL;

      if (SSH_FSM_THREAD_EXISTS(neg->sub_thread))
	{
	  SSH_ASSERT(!SSH_FSM_IS_THREAD_RUNNING(neg->sub_thread));
	  if (!SSH_FSM_IS_THREAD_DONE(neg->sub_thread))
	    ssh_fsm_kill_thread(neg->sub_thread);
	}
    }
  
#ifdef SSHDIST_ISAKMP_CFG_MODE
  ssh_cancel_timeout(neg->cfgmode_timeout);

  if (neg->cfg_negotiation)
    { 
      SSH_DEBUG(SSH_D_LOWOK, ("Aborting XAUTH negotiation %p (neg %p)",
			      neg->cfg_negotiation, neg));

      if (neg->ike_sa->v1_sa)
        ssh_ike_abort_negotiation(neg->cfg_negotiation, 0L);
      neg->cfg_negotiation = NULL;
    }
#endif /* SSHDIST_ISAKMP_CFG_MODE */

  ssh_cancel_timeout(neg->dpd_timeout);

  if (neg->ike_sa->v1_sa &&
      !(neg->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_IKE_SA_DONE))
    {
      /* We have ongoing P1 SA negotiation. */
      SSH_DEBUG(SSH_D_LOWOK, ("Aborting IKE SA negotiation %p (neg %p)",
			      neg->ike_sa->v1_sa, neg));
      
      /* Free ED now, as after this function returns the caller may
	 free the SA */
      ssh_ike_abort_negotiation(neg->ike_sa->v1_sa, 0L);
      ikev2_free_exchange_data(neg->ike_sa, neg->ed);
      neg->ed = NULL;
    }
  else
    {
      /* We are either about to start P1 or QM */
      if (neg->ike_sa->v1_sa == NULL)
	{
	  SSH_DEBUG(SSH_D_LOWOK, ("Finishing IKE SA negotiation (neg %p)",
				  neg));
	  ssh_fsm_set_next(neg->thread, ikev2_fb_i_p1_negotiation_result);
	}
      else
	{
	  SSH_DEBUG(SSH_D_LOWOK, ("Finishing info negotiation (neg %p)", neg));
	  ssh_fsm_set_next(neg->thread, ikev2_fb_i_info_negotiation_result);
	}
    }
  ssh_fsm_continue(neg->thread);
}

/* DPD */
static Boolean ikev2_fb_info_is_dpd(SshIkev2FbNegotiation neg)
{
  SSH_ASSERT(neg != NULL);

  if (neg->ed->info_ed->del == NULL &&
      neg->ed->info_ed->notify == NULL &&
      neg->ed->info_ed->conf == NULL)
    return TRUE;
  
  return FALSE;
}

static void fb_i_dpd_timer(void *context)
{
  SshIkev2FbNegotiation neg = context;

  ssh_fsm_continue(neg->thread);
}

SSH_FSM_STEP(ikev2_fb_i_dpd_negotiation_start)
{
  SshIkev2FbNegotiation neg = (SshIkev2FbNegotiation) thread_context;
  unsigned char data[4], spi[2 * SSH_IKE_COOKIE_LENGTH];

  /* We have received data for this SA after we started. No use
     continuing DPD */
  if (neg->ed->ike_sa->last_input_stamp > neg->dpd_timer_start)
    {
      neg->ike_error = SSH_IKEV2_ERROR_OK;
      SSH_FSM_SET_NEXT(ikev2_fb_i_info_negotiation_result);
      return SSH_FSM_CONTINUE;
    }

  /* SA has disappeared */
  if (neg->ed->ike_sa->v1_sa == NULL)
    {
      neg->ike_error = SSH_IKEV2_ERROR_SA_UNUSABLE;
      SSH_FSM_SET_NEXT(ikev2_fb_i_info_negotiation_result);
      return SSH_FSM_CONTINUE;
    }

  /* DPD timer expires, notify timeout */
  if (neg->dpd_timer_total_sec > neg->dpd_timer_expire)
    {
      neg->ike_error = SSH_IKEV2_ERROR_TIMEOUT;
      SSH_FSM_SET_NEXT(ikev2_fb_i_info_negotiation_result);
      return SSH_FSM_CONTINUE;
    }

  neg->dpd_timer_total_sec += neg->dpd_timer_sec;
  neg->dpd_timer_sec += neg->dpd_timer_prev_sec;
  neg->dpd_timer_prev_sec = neg->dpd_timer_sec - neg->dpd_timer_prev_sec;

  memcpy(spi,
	 neg->ike_sa->ike_spi_i, sizeof(neg->ike_sa->ike_spi_i));
  memcpy(spi + SSH_IKE_COOKIE_LENGTH,
	 neg->ike_sa->ike_spi_r, sizeof(neg->ike_sa->ike_spi_r));

  SSH_PUT_32BIT(data, neg->ike_sa->dpd_cookie);

  /* Ignore other errors, as they are not fatal for dpd. */
  if (ssh_ike_connect_notify((SshIkeServerContext)neg->server,
			     neg->ed->ike_sa->v1_sa,
			     NULL, NULL,
			     SSH_IKE_NOTIFY_FLAGS_WANT_ISAKMP_SA,
			     SSH_IKE_DOI_IPSEC,
			     SSH_IKE_PROTOCOL_ISAKMP,
			     spi, sizeof(spi),
			     SSH_IKE_NOTIFY_MESSAGE_R_U_THERE,
			     data, sizeof(data)) 
      == SSH_IKE_ERROR_NO_ISAKMP_SA_FOUND)
    {
      neg->ike_error = SSH_IKEV2_ERROR_SA_UNUSABLE;

      SSH_FSM_SET_NEXT(ikev2_fb_i_info_negotiation_result);
      return SSH_FSM_CONTINUE;
    }
  else
    {
      ssh_register_timeout(neg->dpd_timeout,
			   neg->dpd_timer_sec, 0L, fb_i_dpd_timer, neg);
    }

  return SSH_FSM_SUSPENDED;
}


SshIkev2Error ikev2_fb_send_notifications(SshIkev2FbNegotiation neg)
{
  SshIkev2PayloadDelete del;
  SshIkev2PayloadNotify notify;
  SshIkeErrorCode error = SSH_IKE_ERROR_OK;

  /* DPD should never end up here. */
  SSH_ASSERT(!ikev2_fb_info_is_dpd(neg));

  if (neg->ed->ike_sa->v1_sa == NULL)
    {
      SSH_DEBUG(SSH_D_MIDOK,
		("Dropping notifications due to missing IKE SA (neg %p)",
		 neg));
      return SSH_IKEV2_ERROR_SA_UNUSABLE;
    }

  del = neg->ed->info_ed->del;
  while (del && error == SSH_IKE_ERROR_OK)
    {
      unsigned char *spibuf = NULL, **spis = NULL;
      int i;

      spibuf = ssh_calloc(del->spi_size, del->number_of_spis);
      spis = ssh_calloc(del->number_of_spis, sizeof(unsigned char *));

      if (spibuf == NULL || spis == NULL)
	{
	  if (spibuf)
	    ssh_free(spibuf);
	  if (spis)
	    ssh_free(spis);

	  SSH_DEBUG(SSH_D_LOWOK,
		    ("Memory allocation failed for delete notification."));
	  return SSH_IKEV2_ERROR_OUT_OF_MEMORY;
	}
      
      for (i = 0; i < del->number_of_spis; i++)
	{
	  SSH_PUT_32BIT(spibuf + i * del->spi_size, del->spi.spi_array[i]);
	  spis[i] = spibuf + i * del->spi_size;
	}

      error = ssh_ike_connect_delete((SshIkeServerContext)neg->server,
				     neg->ed->ike_sa->v1_sa,
				     NULL, NULL,
				     SSH_IKE_DELETE_FLAGS_WANT_ISAKMP_SA,
				     SSH_IKE_DOI_IPSEC,
				     del->protocol, del->number_of_spis, 
				     spis, del->spi_size);

      ssh_free(spis);
      ssh_free(spibuf);

      del = del->next_delete;
    }

  notify = neg->ed->info_ed->notify;
  while (notify && error == SSH_IKE_ERROR_OK)
    {
      /* Skip initial contact notify because it is already sent by isakmp
	 library in ssh_ike_connect(). */
      if (notify->notify_message_type == SSH_IKEV2_NOTIFY_INITIAL_CONTACT)
	{
	  notify = notify->next_notify;
	  continue;
	}

      error = ssh_ike_connect_notify((SshIkeServerContext)neg->server,
				     neg->ed->ike_sa->v1_sa,
				     NULL, NULL,
				     SSH_IKE_NOTIFY_FLAGS_WANT_ISAKMP_SA,
				     SSH_IKE_DOI_IPSEC,
				     notify->protocol,
				     notify->spi_data, notify->spi_size,
				     notify->notify_message_type,
				     notify->notification_data,
				     notify->notification_size);
      notify = notify->next_notify;
    }

  switch (error)
    {
    case SSH_IKE_ERROR_OK:
      return SSH_IKEV2_ERROR_OK;

    case SSH_IKE_ERROR_NO_ISAKMP_SA_FOUND:
      return SSH_IKEV2_ERROR_SA_UNUSABLE;

    case SSH_IKE_ERROR_OUT_OF_MEMORY:
      return SSH_IKEV2_ERROR_OUT_OF_MEMORY;

    case SSH_IKE_ERROR_ISAKMP_SA_NEGOTIATION_IN_PROGRESS:
    case SSH_IKE_ERROR_INVALID_ARGUMENTS:
    case SSH_IKE_ERROR_INTERNAL:
    default:
      return SSH_IKEV2_ERROR_INVALID_ARGUMENT;
    }
}

SSH_FSM_STEP(ikev2_fb_i_info_negotiation_start)
{
  SshIkev2FbNegotiation neg = (SshIkev2FbNegotiation) thread_context;

#ifdef SSHDIST_IKE_XAUTH
  /* Extended authentication is hidden inside informational
     exchange. Their paths separate here. */
  if (neg->ed->info_ed->flags & SSH_IKEV2_INFO_CREATE_FLAGS_XAUTH)
    {
      SSH_FSM_SET_NEXT(ikev2_fb_st_i_xauth_start);
      return SSH_FSM_CONTINUE;
    }
#endif /* SSHDIST_IKE_XAUTH */

  SSH_FSM_SET_NEXT(ikev2_fb_i_info_negotiation_result);

  if (ikev2_fb_info_is_dpd(neg))
    {
      /* We are already working on this SA */
      if (neg->ike_sa->dpd_context != NULL)
	return SSH_FSM_CONTINUE;

      neg->ike_sa->dpd_context = neg;

      neg->dpd_timer_prev_sec = 0;
      neg->dpd_timer_sec = 1;
      neg->dpd_timer_total_sec = 0;
      neg->dpd_timer_expire = 32; /* XXX: configurable? */
      neg->dpd_timer_start = ssh_time();
      
      SSH_FSM_SET_NEXT(ikev2_fb_i_dpd_negotiation_start);
    }
  else
    {
      neg->ike_error = ikev2_fb_send_notifications(neg);
    }

  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ikev2_fb_i_info_negotiation_result)
{
  SshIkev2FbNegotiation neg = (SshIkev2FbNegotiation) thread_context;

  SSH_DEBUG(SSH_D_LOWOK, ("Info negotiation result error %d (neg %p)",
			  neg->ike_error, neg));

  neg->ike_sa->dpd_context = NULL;

  ssh_cancel_timeout(neg->dpd_timeout);

  if (!neg->aborted)
    {
      if (neg->ed->callback != NULL_FNPTR)
	(*neg->ed->callback)(neg->server->sad_handle,
			     neg->ike_sa, neg->ed,
			     neg->ike_error);
      neg->ed->callback = NULL_FNPTR;

      ssh_operation_unregister(neg->ed->info_ed->operation_handle);
      neg->ed->info_ed->flags &= ~SSH_IKEV2_INFO_OPERATION_REGISTERED;

      if (neg->ike_error == SSH_IKEV2_ERROR_TIMEOUT
	  && neg->ike_sa->v1_sa)
	{
	  ssh_ike_remove_isakmp_sa(neg->ike_sa->v1_sa,
				   (SSH_IKE_REMOVE_FLAGS_SEND_DELETE |
				    SSH_IKE_REMOVE_FLAGS_FORCE_DELETE_NOW));
	}
    }
  if (neg->ed)
    {
      ikev2_free_exchange_data(neg->ed->ike_sa, neg->ed);
      neg->ed = NULL;
    }
  return SSH_FSM_FINISH;
}


SshOperationHandle
ikev2_fb_initiate_info(SshIkev2ExchangeData ed)
{
  SshIkev2FbNegotiation neg;
  SshIkev2Fb fb;
  SshIkev2Error error;

  if ((fb = ed->ike_sa->server->context->fallback) == NULL)
    {
    immediate_error:
      (*ed->callback)(ed->ike_sa->server->sad_handle,
		      ed->ike_sa,
		      ed,
		      SSH_IKEV2_ERROR_INVALID_ARGUMENT);
      ed->callback = NULL_FNPTR;

      if (!(ed->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_IKE_SA_DONE))
	{
	  SSH_DEBUG(SSH_D_LOWSTART,
		    ("FB; Calling v2 policy function ike_sa_delete"));
	  (*ed->ike_sa->server->sad_interface->ike_sa_delete)
	    (ed->ike_sa->server->sad_handle, ed->ike_sa, NULL_FNPTR, NULL);
	}
      ssh_ikev2_info_destroy(ed);
      return NULL;
    }

  if ((neg = ikev2_fallback_negotiation_alloc(fb)) == NULL)
    goto immediate_error;

  neg->server = ed->ike_sa->server;
  neg->ed = ed;
  neg->ike_sa = ed->ike_sa;
  ssh_ikev2_ike_sa_take_ref(neg->ike_sa);
  neg->initiator = 1;

  if (ed->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_IKE_SA_DONE)
    {
      /* Free the ref taken by the actual IKEv2 ED allocation code */
      ssh_ikev2_ike_sa_free(ed->ike_sa);

      /* Send the notifications (except dpd) synchronously */
      if (ikev2_fb_info_is_dpd(neg))
	{
	  ssh_fsm_thread_init(fb->fsm, neg->thread,
			      ikev2_fb_i_info_negotiation_start,
			      NULL_FNPTR,
			      ikev2_fb_info_negotiation_destructor,
			      neg);
	}
      else
	{
	  error = ikev2_fb_send_notifications(neg);

	  (*ed->callback)(ed->ike_sa->server->sad_handle,
			  ed->ike_sa,
			  ed,
			  error);
	  ed->callback = NULL_FNPTR;

	  ikev2_fallback_negotiation_free(neg->fb, neg);
	  return NULL;
	}
    }
  else
    {
      if (neg->ed->ike_ed->exchange_type == SSH_IKE_XCHG_TYPE_NONE)
	{
	  SSH_DEBUG(SSH_D_ERROR,
		    ("Initiator has not specified exchange type"));
	  ssh_ikev2_ike_sa_free(neg->ike_sa);
	  neg->ike_sa = NULL;
	  goto immediate_error;
	}
      neg->ed->ike_ed->auth_method = SSH_IKE_AUTH_METHOD_ANY;

      /* Set `p1_negotiation_context' pointer, it is cleared in thread
	 destructor. */
      neg->ed->ike_sa->p1_negotiation_context = neg;

      ssh_fsm_thread_init(fb->fsm, neg->thread,
			  ikev2_fb_i_p1_negotiation_start,
			  NULL_FNPTR,
			  ikev2_fb_info_p1_negotiation_destructor,
			  neg);
    }

  ssh_operation_register_no_alloc(ed->info_ed->operation_handle,
				  ikev2_fb_info_abort,
				  neg);
  ed->info_ed->flags |= SSH_IKEV2_INFO_OPERATION_REGISTERED;
  return ed->info_ed->operation_handle;
}

#endif /* SSHDIST_IKEV1 */
