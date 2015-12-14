/*
 * sad_ike_spis.c
 *
 * Copyright:
 *       Copyright (c) 2005, 2006 SFNT Finland Oy.
 *       All rights reserved.
 *
 * IPSec SPI allocator
 *
 */

#include "sshincludes.h"
#include "quicksecpm_internal.h"

#define SSH_DEBUG_MODULE "SshPmIkeSpis"

static void pm_ipsec_spi_abort(void *context)
{
  SshPmQm qm = context;

  SSH_DEBUG(SSH_D_HIGHOK, ("Aborting Spi allocate call for QM %p", qm));

  qm->callbacks.aborted = TRUE;
  qm->callbacks.u.ipsec_spi_allocate_cb = NULL_FNPTR;
  qm->error = SSH_IKEV2_ERROR_SA_UNUSABLE;

  ssh_fsm_set_next(&qm->sub_thread, pm_ipsec_spi_allocate_done);
  return;
}

/* SPI allocation result callback.  This copies the SPIs from `spis'
   to `qm->spis' and continues the Quick-Mode thread. */
static void
pm_qm_thread_spi_cb(SshPm pm,
		    SshUInt32 transform_index, SshUInt32 reverse_spi,
		    const SshUInt32 spis[3],
		    void *context)
{
  SshFSMThread thread = (SshFSMThread) context;
  SshPmQm qm = (SshPmQm) ssh_fsm_get_tdata(thread);
  int i;

  memcpy(qm->spis, spis, 3 * sizeof(SshUInt32));

  /* Do not overwrite possibly valid intitiator transform index with
     invalid index for the initiator. */
  if (transform_index != SSH_IPSEC_INVALID_INDEX)
    qm->trd_index = transform_index;

  if (qm->old_inbound_spi == 0)
    qm->old_inbound_spi = reverse_spi;

  for (i = 0; i < 3; i++)
    if (qm->spis[i] != 0)
      break;

  if (i >= 3)
    {
      SSH_DEBUG(SSH_D_FAIL, ("SPI allocation failed"));
      qm->error = SSH_IKEV2_ERROR_OUT_OF_MEMORY;
    }
  else
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Allocated SPIs: %@",
                                   ssh_pm_spis_render, qm->spis));
    }

  SSH_FSM_CONTINUE_AFTER_CALLBACK(thread);
}

/******************** FSM state functions ***************************/



SSH_FSM_STEP(pm_ipsec_set_authorization_groups)
{
  SshPm pm = fsm_context;
  SshPmQm qm = thread_context;
  SshPmP1 p1 = qm->p1;

  if (ssh_pm_check_qm_error(qm, thread, pm_ipsec_spi_allocate_done))
    return SSH_FSM_CONTINUE;

  SSH_FSM_SET_NEXT(pm_ipsec_set_authorization_groups_done);

  /* We resolve the group constraints for responder Phase-I's. For IKEv1 
     the Phase-I is already finished here, but not for IKEv2. */
  if (!(p1->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_INITIATOR) && 
      !p1->auth_group_ids_set)
    {
      SSH_DEBUG(SSH_D_LOWSTART, ("Resolving authorization group ID"));
      SSH_FSM_ASYNC_CALL(ssh_pm_authorization_p1(pm, p1,
						 ssh_pm_authorization_cb,
						 thread));
      SSH_NOTREACHED;
    }

  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(pm_ipsec_set_authorization_groups_done)
{
  SshPmQm qm = thread_context;

  if (!qm->initiator)
    {
      SSH_FSM_SET_NEXT(pm_ipsec_select_policy_rule);
      return SSH_FSM_CONTINUE;
    }
  else
    {
      SSH_FSM_SET_NEXT(pm_ipsec_spi_allocate);
      return SSH_FSM_CONTINUE;
    }
}

SSH_FSM_STEP(pm_ipsec_select_policy_rule)
{
  SshPm pm = fsm_context;
  SshPmQm qm = thread_context;
  SshPmP1 p1 = qm->p1;
  Boolean forward;
  SshPmTunnel tunnel = NULL;
  Boolean transport_mode_requested;

  if (ssh_pm_check_qm_error(qm, thread, pm_ipsec_spi_allocate_done))
    return SSH_FSM_CONTINUE;

  SSH_PM_ASSERT_P1(p1);
  SSH_ASSERT(qm->rule == NULL);
  
  if (p1->n && p1->n->rule)
    {
      if (p1->n->forward)
	tunnel = p1->n->rule->side_to.tunnel;
      else
	tunnel = p1->n->rule->side_from.tunnel;
    }

  /* If we have a rule selected from the IKE SA negotiation then check its
     authorization. If that fails we perform rule lookup again to see if
     a matching rule with the correct authorization can be found. However,
     for IKEv1 SA's we must always do rule lookup again, since the rule
     selection in the Phase-I has not considered the traffic selectors,
     or transport mode notifications. */
  if (
#ifdef SSHDIST_IKEV1
      !(p1->ike_sa->flags & SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_IKEV1) &&
#endif /* SSHDIST_IKEV1 */
      p1->n && p1->n->rule && ssh_pm_check_rule_authorization(p1, p1->n->rule)
      && tunnel 
      && ssh_pm_ike_tunnel_match_encapsulation(tunnel, qm->ed, 
					       &transport_mode_requested))
    {
      SSH_ASSERT(qm->rule == NULL);
      qm->rule = p1->n->rule;
      p1->n->rule = NULL;

      qm->forward = p1->n->forward;

      qm->tunnel = tunnel;
      SSH_PM_TUNNEL_TAKE_REF(qm->tunnel);
    }

  if (qm->rule == NULL)
    {
      qm->rule = ssh_pm_ike_responder_rule_lookup(pm, qm->p1, qm->ed,
						  TRUE, TRUE, FALSE,
						  &forward,
						  NULL,
						  &qm->failure_mask);

      if (qm->rule)
	SSH_PM_RULE_LOCK(qm->rule);
      
#ifdef SSHDIST_IKEV1
      if (qm->rule && qm->rule->ike_in_progress && 
	  (qm->p1->ike_sa->flags & SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_IKEV1))
	{
	  SSH_DEBUG(SSH_D_FAIL, ("Dropping IKEv1 responder request as policy "
				 "rule is already in use"));
	  SSH_PM_RULE_UNLOCK(pm, qm->rule);
	  qm->rule = NULL;
	  qm->error = SSH_IKEV2_ERROR_NO_PROPOSAL_CHOSEN;
	  SSH_FSM_SET_NEXT(pm_ipsec_spi_allocate);
	  return SSH_FSM_CONTINUE;
	}
#endif /* SSHDIST_IKEV1 */

      if (qm->rule)
	{
	  if (forward)
	    {
	      qm->forward = 1;
	      qm->tunnel = qm->rule->side_to.tunnel;
	      SSH_PM_TUNNEL_TAKE_REF(qm->tunnel);
	    }
	  else
	    {
	      qm->forward = 0;
	      qm->tunnel = qm->rule->side_from.tunnel;
	      SSH_PM_TUNNEL_TAKE_REF(qm->tunnel);
	    }
	}

      if (qm->rule == NULL)
	{
#ifdef SSHDIST_IPSEC_XAUTH_SERVER
#ifdef SSHDIST_IKEV1
	  /* If rule lookup failed because of access group denial and XAUTH
	     is ongoing then wait for XAUTH to complete. After XAUTH 
	     completes, we check again if a suitable rule is available. */
	  if ((qm->failure_mask & SSH_PM_E_ACCESS_GROUP_MISMATCH) &&
	      (p1->ike_sa->flags & SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_IKEV1) &&
	      !(p1->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_INITIATOR) &&
	      p1->ike_sa->xauth_enabled && !p1->ike_sa->xauth_done)
	    {
	      SSH_DEBUG(SSH_D_HIGHOK, ("Rule lookup failed due to XAUTH "
                                       "access group mismatch. Waiting for "
                                       "Xauth to complete"));
	      qm->waiting_xauth = 1;
              SSH_FSM_SET_NEXT(pm_ipsec_xauth_wait);
              return SSH_FSM_CONTINUE;
	    }
#endif /* SSHDIST_IKEV1 */
#endif /* SSHDIST_IPSEC_XAUTH_SERVER */

	  SSH_DEBUG(SSH_D_FAIL, ("No suitable policy rule found, failing "
				 "negotiation"));
	  SSH_FSM_SET_NEXT(pm_ipsec_spi_allocate);
	  qm->error = SSH_IKEV2_ERROR_NO_PROPOSAL_CHOSEN;
	  return SSH_FSM_CONTINUE;
	}
    }

  /* Verify we have selected a tunnel. */
  SSH_ASSERT(qm->tunnel != NULL);
  qm->transform = qm->tunnel->transform;

  /* Update the tunnel used for the Phase-I negotiation. */
  SSH_PM_ASSERT_P1(qm->p1);
  if (qm->p1->n &&
      qm->tunnel != qm->p1->n->tunnel)
    {
      SSH_DEBUG(SSH_D_HIGHOK, ("IKE Responder is changing tunnels from %s "
			       "to %s",
			       qm->p1->n->tunnel->tunnel_name,
			       qm->tunnel->tunnel_name));

      if (qm->p1->n->tunnel)
	SSH_PM_TUNNEL_DESTROY(pm, qm->p1->n->tunnel);

      qm->p1->tunnel_id = qm->tunnel->tunnel_id;
      qm->p1->n->tunnel = qm->tunnel;
      SSH_PM_TUNNEL_TAKE_REF(qm->p1->n->tunnel);
    }

  /* Set encapsulation mode for the negotiation. */
  ssh_pm_qm_thread_compute_tunneling_attribute(qm);

  SSH_FSM_SET_NEXT(pm_ipsec_spi_allocate);
  return SSH_FSM_CONTINUE;
}

#ifdef SSHDIST_IPSEC_XAUTH_SERVER
#ifdef SSHDIST_IKEV1
SSH_FSM_STEP(pm_ipsec_xauth_wait)
{
  SshPmQm qm = thread_context;
  SshPmP1 p1 = qm->p1;

  if (ssh_pm_check_qm_error(qm, thread, pm_ipsec_spi_allocate_done))
    return SSH_FSM_CONTINUE;

  SSH_DEBUG(SSH_D_LOWOK, ("Xauth wait"));

  /* Handle the case where 'p1' is unlinked from 'qm' which may happen after 
     aborting of the Quick-Mode negotiation or IKE SA deletion. */




  if (p1 == NULL)
    {
      qm->error = SSH_IKEV2_ERROR_AUTHENTICATION_FAILED;
      SSH_FSM_SET_NEXT(pm_ipsec_spi_allocate_done);
      return SSH_FSM_CONTINUE;
    }

#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_SERVER
  if (!p1->ike_sa->xauth_done)
    {
      SSH_DEBUG(SSH_D_HIGHOK,
		("Suspending QM thread until XAUTH is done,qm=%p", qm));

      SSH_FSM_CONDITION_WAIT(&p1->xauth_wait_condition);
    }
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_SERVER */

  qm->waiting_xauth = 0;

 SSH_DEBUG(SSH_D_LOWOK, ("Xauth operation done"));

  if (p1->failed)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Xauth has failed"));
      qm->error = SSH_IKEV2_ERROR_AUTHENTICATION_FAILED;
    }
    
  SSH_FSM_SET_NEXT(pm_ipsec_select_policy_rule);
  return SSH_FSM_CONTINUE;
}


#endif /* SSHDIST_IKEV1 */
#endif /* SSHDIST_IPSEC_XAUTH_SERVER */


SSH_FSM_STEP(pm_ipsec_spi_allocate)
{
  SshPm pm = fsm_context;
  SshPmQm qm = thread_context;
  SshIpAddrStruct remote_address;
  SshUInt16 remote_port;
  SshUInt32 spibits = 0;
  Boolean initiator;
  Boolean match_address = TRUE;

  if (ssh_pm_check_qm_error(qm, thread, pm_ipsec_spi_allocate_done))
    return SSH_FSM_CONTINUE;

  if (qm->spis[0] != SSH_IPSEC_SPI_IKE_ERROR_RESERVED)
    {
      /* Reusing unused SPI left from previous try (when doing
	 initiator side initial try for rekey with invalid KE */
      SSH_FSM_SET_NEXT(pm_ipsec_spi_allocate_done);
      return SSH_FSM_CONTINUE;
    }

  /* AH and ESP share the SPI (can't configure bundles) */
  if (qm->transform & SSH_PM_IPSEC_AH)
    spibits |= (1 << SSH_PME_SPI_AH_IN);
  else if (qm->transform & SSH_PM_IPSEC_ESP)
    spibits |= (1 << SSH_PME_SPI_ESP_IN);

  if (qm->transform & SSH_PM_IPSEC_IPCOMP)
    spibits |= (1 << SSH_PME_SPI_IPCOMP_IN);

  SSH_FSM_SET_NEXT(pm_ipsec_spi_allocate_done);

  if (qm->error != SSH_IKEV2_ERROR_OK)
    {
      return SSH_FSM_CONTINUE;
    }

  if (qm->rekey)
    {
      SSH_PM_ASSERT_P1(qm->p1);
      remote_address = *qm->p1->ike_sa->remote_ip;
      remote_port = qm->p1->ike_sa->remote_port;
    }
  else
    {
      SSH_IP_UNDEFINE(&remote_address);
      remote_port = 0;
    }

  initiator = qm->initiator ? TRUE : FALSE;
#ifdef SSHDIST_IKE_MOBIKE
  if (qm->p1 
      && (qm->p1->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_MOBIKE_ENABLED))
    match_address = FALSE;
#endif /* SSHDIST_IKE_MOBIKE */

  if (!initiator)
    qm->old_outbound_spi = qm->ed->ipsec_ed->rekeyed_spi;

  SSH_FSM_ASYNC_CALL({
    ssh_pm_allocate_spis(pm, initiator, match_address, spibits,
			 qm->ed->ipsec_ed->rekeyed_spi,
			 &remote_address, remote_port,
			 pm_qm_thread_spi_cb,
			 thread);
  });
  SSH_NOTREACHED;
}

SSH_FSM_STEP(pm_ipsec_spi_allocate_done)
{
  SshPmQm qm = thread_context;
  unsigned int spi_index = 0;

  if (qm->error == SSH_IKEV2_ERROR_OK
      && qm->ed->ipsec_ed->rekeyed_spi != 0
      && qm->trd_index == SSH_IPSEC_INVALID_INDEX)
    qm->error = SSH_IKEV2_ERROR_NO_PROPOSAL_CHOSEN;

  if (qm->error != SSH_IKEV2_ERROR_OK)
    goto error;

  /* Simultaneous IPsec rekey handling.  Principle here is that IPsec
     rekeys initiated by original IKE SA initiator are preferred (just
     an arbitrary decision, as well we could do as is done on IKE SA
     rekeys where the smaller nonce wins).

     Things go like this...

     If this QM is a initiator side, then do nothing as is still too early
     If this QM is a responder rekey and I've initiated rekey for the same SPI
      If I'm the initiator of IKE SA in question then this QM loses
      If I'm the responder of IKE SA in question then this SA wins

     The QM is considered as initiated if the ED in question is found from
     p1->initiator_eds.

     So, we'll mark the lost SA into QM, and later we'll return
     recoverable error, like no-proposal-chosen when selecting the
     IPsec SA. */
  if (qm->rekey)
    {
      SshPmQm loser;
      int i;
      SshPmP1 p1 = qm->p1;

      for (i = 0; i < PM_IKE_MAX_WINDOW_SIZE; i++)
	{
	  if (p1->initiator_eds[i]
	      && p1->initiator_eds[i] != qm->ed
	      && p1->initiator_eds[i]->ipsec_ed
	      && qm->old_inbound_spi ==
	      p1->initiator_eds[i]->ipsec_ed->rekeyed_spi)
	    {
	      SshPmQm other = p1->initiator_eds[i]->application_context;

	      if (other)
		SSH_PM_ASSERT_QM(other);

	      /* We have initiated IPsec rekey for this SPI and this
		 is not the one we've initiated, so there is a
		 simultaneous rekey going on.*/

	      SSH_DEBUG(SSH_D_HIGHOK, ("Simultaneous IPsec SA rekey; %p "
				       "competing against %p", qm, other));

	      if (p1->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_INITIATOR)
		loser = qm;
	      else
		loser = other;

	      SSH_DEBUG(SSH_D_HIGHOK,
			("Simutaneus IPsec SA rekey; %p lost", loser));

	      loser->error = SSH_IKEV2_ERROR_NO_PROPOSAL_CHOSEN;
	      loser->failure_mask |= SSH_PM_E_SIMULTANEUS_LOSER;
	      break;
	    }
	}
    }

  if (qm->transform & SSH_PM_IPSEC_AH)
    {
      spi_index = SSH_PME_SPI_AH_IN;
      SSH_ASSERT(qm->spis[spi_index] != 0);
    }
  else if (qm->transform & SSH_PM_IPSEC_ESP)
    {
      spi_index = SSH_PME_SPI_ESP_IN;
      SSH_ASSERT(qm->spis[spi_index] != 0);
    }
  else
    SSH_NOTREACHED;

  if (!qm->callbacks.aborted)
    {
      if (qm->callbacks.u.ipsec_spi_allocate_cb)
	(*qm->callbacks.u.ipsec_spi_allocate_cb)(SSH_IKEV2_ERROR_OK,
					       qm->spis[spi_index],
					       qm->callbacks.callback_context);
      ssh_operation_unregister(qm->callbacks.operation);
    }

  return SSH_FSM_FINISH;

 error:
  SSH_DEBUG(SSH_D_FAIL, ("SPI allocation failed with error %d", qm->error));

  SSH_ASSERT(qm->error != SSH_IKEV2_ERROR_OK);

  if (!qm->callbacks.aborted)
    { 
      if (qm->callbacks.u.ipsec_spi_allocate_cb)
	(*qm->callbacks.u.ipsec_spi_allocate_cb)(qm->error, 0,
					       qm->callbacks.callback_context);
      ssh_operation_unregister(qm->callbacks.operation);
    }

  /* Wake up the main Quick-Mode thread. This is done to clean up the state
     if the negotiation has been aborted. */
  if (qm->initiator)
    {
      SSH_DEBUG(SSH_D_MIDOK, ("Continuing Quick Mode thread"));
      ssh_fsm_continue(&qm->thread);
    }

  return SSH_FSM_FINISH;
}

SshOperationHandle
ssh_pm_ipsec_spi_allocate(SshSADHandle sad_handle,
			  SshIkev2ExchangeData ed,
			  SshIkev2SadIPsecSpiAllocateCB reply_callback,
			  void *reply_context)
{
  SshPmQm qm;
  SshPm pm = sad_handle->pm;
  SshPmP1 p1 = (SshPmP1)ed->ike_sa;

  SSH_PM_ASSERT_P1(p1);

  if (ssh_pm_get_status(pm) == SSH_PM_STATUS_SUSPENDED)
    {
      (*reply_callback)(SSH_IKEV2_ERROR_SUSPENDED, 0, reply_context);
      return NULL;
    }

  if (ssh_pm_get_status(pm) == SSH_PM_STATUS_DESTROYED)
    {
      (*reply_callback)(SSH_IKEV2_ERROR_GOING_DOWN, 0, reply_context);
      return NULL;
    }

  /* Reconfigure might have got rid of the used tunnel in P1, so we'll
     have to check that the tunnel still exists in the current policy. */
  if (ssh_pm_tunnel_get_by_id(pm, p1->tunnel_id) == NULL)
    {
      (*reply_callback)(SSH_IKEV2_ERROR_SA_UNUSABLE, 0, reply_context);

      SSH_DEBUG(SSH_D_NICETOKNOW, ("Tried to allocate IPsec SPI while for "
                                   "P1 with nonexistent tunnel"));

      /* Mark the P1 to be removed really soon and unusable. */
      p1->tunnel_id = SSH_IPSEC_INVALID_INDEX;
      p1->expire_time = ssh_time();
      p1->unusable = 1;
      return NULL;
    }

#if (SSH_PM_MAX_CHILD_SAS > 0)
  /* Check if this peer is allowed to create another child SA with us. */
  if (ssh_pm_peer_num_child_sas_by_p1(pm, p1) >= SSH_PM_MAX_CHILD_SAS)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW,
		("Maximum number of child SAs per peer reached %d: "
		 "terminating",
		 (int) SSH_PM_MAX_CHILD_SAS));
      (*reply_callback)(SSH_IKEV2_NOTIFY_NO_ADDITIONAL_SAS, 0, reply_context);
      return NULL;
    }
#endif /* (SSH_PM_MAX_CHILD_SAS > 0) */

  if (p1->n != NULL && p1->n->ed == NULL)
    p1->n->ed = ed;

  if (ed->application_context == NULL)
    {
      Boolean rekey = ed->ipsec_ed->rekeyed_spi ? TRUE : FALSE;

      qm = ssh_pm_qm_alloc(pm, rekey);

      if (qm)
	{
	  qm->p1 = p1;

	  SSH_PM_ASSERT_P1(qm->p1);

	  /* Verify that the IKE SA can be used. */
	  if (!SSH_PM_P1_USABLE(qm->p1))
	    {
	      SSH_DEBUG(SSH_D_FAIL,("SPI allocation failed, IKE SA %p cannot "
				    "be used", qm->p1->ike_sa));

	      ssh_pm_qm_free(pm, qm);
	      (*reply_callback)(SSH_IKEV2_ERROR_SA_UNUSABLE, 0, reply_context);
	      return NULL;
	    }
	  
	  /* Set peer handle. For IKEv1 responder rekeys it might change
	     in SA handler. */
	  qm->peer_handle = ssh_pm_peer_handle_by_p1(pm, qm->p1);

	  qm->ed = ed;
	  qm->initiator = (ed->ipsec_ed->flags &
			   SSH_IKEV2_IPSEC_CREATE_SA_FLAGS_INITIATOR) ? 1 : 0;
	  qm->rekey = rekey;
	  ed->application_context = qm;
	}
    }
  else
    {
      qm = ed->application_context;
    }

  if (qm == NULL)
    {
      (*reply_callback)(SSH_IKEV2_ERROR_OUT_OF_MEMORY, 0, reply_context);
      return NULL;
    }
  SSH_ASSERT(qm != NULL);
  SSH_PM_ASSERT_QM(qm);

  if (qm->p1->initiator_ops[PM_IKE_INITIATOR_OP_REKEY] != NULL)
    {
      (*reply_callback)(SSH_IKEV2_NOTIFY_NO_ADDITIONAL_SAS, 0, reply_context);
      return NULL;
    }

  /* Parse notify payloads. */
  ssh_pm_ike_parse_notify_payloads(ed, qm);

  qm->callbacks.aborted = FALSE;
  qm->callbacks.u.ipsec_spi_allocate_cb = reply_callback;
  qm->callbacks.callback_context = reply_context;

  ssh_operation_register_no_alloc(qm->callbacks.operation,
				  pm_ipsec_spi_abort, qm);

  ssh_fsm_thread_init(&pm->fsm, &qm->sub_thread,
		      pm_ipsec_set_authorization_groups,
		      NULL_FNPTR,
		      pm_qm_sub_thread_destructor,
		      qm);
  ssh_fsm_set_thread_name(&qm->sub_thread, "SPI allocate");
  return qm->callbacks.operation;
}

void ssh_pm_ipsec_spi_delete(SshSADHandle sad_handle, SshUInt32 spi)
{
  SSH_DEBUG(SSH_D_LOWOK, ("Received IPsec SPI delete for SPI 0x%08lx from "
			  "the IKE library",
			  (unsigned long) spi));
}
