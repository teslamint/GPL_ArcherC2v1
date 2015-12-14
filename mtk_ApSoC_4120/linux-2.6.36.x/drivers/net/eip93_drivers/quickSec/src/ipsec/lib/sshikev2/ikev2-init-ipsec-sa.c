/*
 *
 * Author: Tero Kivinen <kivinen@iki.fi>
 *
 *  Copyright:
 *          Copyright (c) 2004, 2005 SFNT Finland Oy.
 */
/*
 *        Program: sshikev2
 *        $Author: bruce.chang $
 *
 *        Creation          : 14:38 Oct 15 2004 kivinen
 *        Last Modification : 14:04 Mar  6 2009 kivinen
 *        Last check in     : $Date: 2012/09/28 $
 *        Revision number   : $Revision: #1 $
 *        State             : $State: Exp $
 *        Version           : 1.229
 *        
 *
 *        Description       : IKEv2 IPsec SA initiator init functions.
 *
 *
 *        $Log: ikev2-init-ipsec-sa.c,v $
 *        Revision 1.1.2.1  2011/01/31 03:29:13  treychen_hc
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
 *        $EndLog$
 */

#include "sshincludes.h"
#include "sshikev2-initiator.h"
#include "sshikev2-exchange.h"
#include "sshikev2-util.h"
#include "ikev2-internal.h"
#ifdef SSHDIST_IKEV1
#include "ikev2-fb.h"
#endif /* SSHDIST_IKEV1 */

#define SSH_DEBUG_MODULE "SshIkev2InitIPsecSa"

/* Aborting the operation. */
void ikev2_ike_sa_abort(void *context)
{
  SshIkev2Sa ike_sa = context;

  SSH_DEBUG(SSH_D_MIDSTART,
	    ("Initial IKE SA %p exchange aborted %@;%d",
	     ike_sa,
	     ssh_ipaddr_render, ike_sa->remote_ip,
	     ike_sa->remote_port));

  /* Clear the callback so the free_exchange_data will not call it. */
  ike_sa->initial_ed->callback = NULL_FNPTR;

  /* Mark that we do not have operation registered anymore, as the abort
     callback was called. */
  ike_sa->initial_ed->ipsec_ed->flags &= ~SSH_IKEV2_IPSEC_OPERATION_REGISTERED;

  /* First we need to stop the retransmissions as otherwise
     we cannot delete the SA, as there is references to it. */
  ikev2_udp_window_stop(ike_sa);

  /* Mark ike sa so that is has been aborted, thus drop all packets
     immediately. */
  ike_sa->flags |= SSH_IKEV2_IKE_SA_FLAGS_ABORTED;

  /* We need to abort the lower level operation here, as after we remove the
     ike_sa->initial_ed from the ike_sa, we cannot set the handle NULL anymore
     at the completion callback, and it will get aborted twice. */
  if (ike_sa->initial_ed->operation != NULL)
    ssh_operation_abort(ike_sa->initial_ed->operation);
  ike_sa->initial_ed->operation = NULL;

  /* Then we destroy the IKE SA */
  ikev2_free_exchange_data(ike_sa, ike_sa->initial_ed);
  ike_sa->initial_ed = NULL;

  if (ike_sa->waiting_for_delete == NULL)
    {
      /* And then we destroy the IKE SA. Note, that we have
	 one reference which we took when installing the
	 operation, and this will consume that one. */
      /* OK, Added to the ssh_ikev2_ipsec_send  */
      SSH_IKEV2_POLICY_NOTIFY(ike_sa, ike_sa_delete)
	(ike_sa->server->sad_handle, ike_sa, NULL, NULL);
    }
  else
    {
      /* The IKE SA has already been deleted, so we simply
	 decrement the reference used by the operation
	 handle. */
      ssh_ikev2_ike_sa_free(ike_sa);
    }
}

/* Aborting the IPsec SA operation. */
void ikev2_ipsec_sa_abort(void *context)
{
  SshIkev2ExchangeData ed = context;
  SshIkev2Sa ike_sa = ed->ike_sa;

  SSH_DEBUG(SSH_D_MIDSTART,
	    ("Create child SA exchange for SA %p aborted %@;%d",
	     ike_sa, ssh_ipaddr_render, ike_sa->remote_ip,
	     ike_sa->remote_port));

  /* Clear the callback so the free_exchange_data will not call it. */
  ed->callback = NULL_FNPTR;

  /* Mark that we do not have operation registered anymore, as the abort
     callback was called. */
  ed->ipsec_ed->flags &= ~SSH_IKEV2_IPSEC_OPERATION_REGISTERED;

  /* First we need to stop the retransmissions as otherwise
     we cannot delete the SA, as there is references to it. */
  ikev2_udp_window_stop(ike_sa);

  /* Mark ike sa so that is has been aborted, thus drop all packets
     immediately. */
  ike_sa->flags |= SSH_IKEV2_IKE_SA_FLAGS_ABORTED;

  /* Then we destroy the IKE SA */

  /* Free references to IKE SA and ED. They were taken in ipsec_send. */
  ikev2_free_exchange_data(ike_sa, ed);

  if (ike_sa->waiting_for_delete == NULL)
    {
      /* And then we destroy the IKE SA. Note, that we have one
	 reference which we took when installing the operation, and
	 this will consume that one. */
      /* OK, Added to the ssh_ikev2_ipsec_send  */
      SSH_IKEV2_POLICY_NOTIFY(ike_sa, ike_sa_delete)
	(ike_sa->server->sad_handle, ike_sa, NULL, NULL);
    }
  else
    {
      /* The IKE SA has already been deleted, so we simply
	 decrement the reference used by the operation
	 handle. */
      ssh_ikev2_ike_sa_free(ike_sa);
    }
}

/* Create IPsec exchange, this just allocates memory
   structures to store the payloads, the actual operation
   happens in the ipsec_send. This will take its own
   reference to the ike sa, so the caller can free his own
   reference immediately after this returns (or if this is
   called directly from SshIkev2IkeSaAllocatedCB then no
   need to take extra reference). The created ed must be
   passed to either ssh_ikev2_ipsec_send or ssh_ikev2_ipsec_destroy. */
SshIkev2ExchangeData
ssh_ikev2_ipsec_create_sa(SshIkev2Sa ike_sa,
			  SshUInt32 flags)
{
  SshIkev2ExchangeData ed;
  SshIkev2Error error;

  SSH_ASSERT(ike_sa->server->context->ikev2_suspended == FALSE);
  if (ike_sa->server->server_stopped_flags)
    {
      return NULL;
    }
  if (ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_RESPONDER_DELETED)
    {
      return NULL;
    }

  ed = ikev2_allocate_exchange_data(ike_sa);
  if (ed == NULL)
    {
      return NULL;
    }
  if (ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_IKE_SA_DONE)
    {
      SSH_DEBUG(SSH_D_LOWSTART, ("State = CREATE_CHILD"));
      ed->state = SSH_IKEV2_STATE_CREATE_CHILD;
    }
  else
    {
      SSH_DEBUG(SSH_D_LOWSTART, ("State = IKE_INIT_SA"));
      ed->state = SSH_IKEV2_STATE_IKE_INIT_SA;
      error = ikev2_allocate_exchange_data_ike(ed);
      if (error != SSH_IKEV2_ERROR_OK)
	{
	  ikev2_free_exchange_data(ike_sa, ed);
	  return NULL;
	}
    }

  error = ikev2_allocate_exchange_data_ipsec(ed);
  if (error != SSH_IKEV2_ERROR_OK)
    {
      ikev2_free_exchange_data(ike_sa, ed);
      return NULL;
    }
  ed->ipsec_ed->flags = flags | SSH_IKEV2_IPSEC_CREATE_SA_FLAGS_INITIATOR;
  ssh_ikev2_ike_sa_take_ref(ike_sa);

  /* At this point we have references to IKE SA and to ED. Those
     references are stolen to packet in ipsec_send or freed in
     ipsec_destroy. */

  return ed;
}

/* This is not real FSM state, but we add this here, so we get state machine
   pictures to include this state too. 
SSH_FSM_STEP(ssh_ikev2_ipsec_send) */

/* Negotiate IPsec SA with the remote host. This will also
   create the IKE SA if it is not yet ready (and this will
   be the first Child SA created at the initial exchange).

   Traffic selector structures must remain constant during
   the exchange and the caller can modify them only after
   the done callback is called. This function does take
   reference to them, and does NOT modify them. Because of
   its own reference, the caller can immediately release its
   reference if it is not needed anymore.

   Use ssh_ikev2_ts_allocate / ssh_ikev2_ts_item_add /
   ssh_ikev2_ts_free functions to work with traffic
   selectors.

   The triggering_packet should contain an information from
   the actual packet triggering the creation of this IPsec
   SA, or NULL in case there is no such packet. The
   information from the triggering_packet is copied out
   during this call. This call will fail with
   SSH_IKEV2_ERROR_WINDOW_FULL error if there is no space
   in the window to start new negotiations now, meaning it
   will call the callback and then destroy the exchange
   data. */

SshOperationHandle
ssh_ikev2_ipsec_send(SshIkev2ExchangeData ed,
		     SshIkev2TriggeringPacket triggering_packet,
		     SshIkev2PayloadTS tsi_local,
		     SshIkev2PayloadTS tsi_remote,
		     SshIkev2NotifyCB callback)
{
  Boolean create_child_sa;
  SshIkev2Packet packet;
  SshIkev2Error error;
  SshIkev2Sa ike_sa;

  ike_sa = ed->ike_sa;

  SSH_ASSERT(ike_sa->server->context->ikev2_suspended == FALSE);
  if (ike_sa->server->server_stopped_flags)
    {
      if (callback)
	(*callback)(ike_sa->server->sad_handle,
		    ike_sa, ed,
		    SSH_IKEV2_ERROR_GOING_DOWN);
      ssh_ikev2_ipsec_exchange_destroy(ed);
      return NULL;
    }

  if (ike_sa->waiting_for_delete != NULL)
    {
      if (callback)
	(*callback)(ike_sa->server->sad_handle,
		    ike_sa, ed,
		    SSH_IKEV2_ERROR_SA_UNUSABLE);
      ssh_ikev2_ipsec_exchange_destroy(ed);
      return NULL;
    }

  /* Store args into exchange. */
  ed->ipsec_ed->ts_local = tsi_local;
  ssh_ikev2_ts_take_ref(ike_sa->server->sad_handle,
			ed->ipsec_ed->ts_local);
  ed->ipsec_ed->ts_remote = tsi_remote;
  ssh_ikev2_ts_take_ref(ike_sa->server->sad_handle,
			ed->ipsec_ed->ts_remote);
  /* After this we must make sure we clear the ed->callback in case
     we call the callback directly.  */
  ed->callback = callback;

  if (triggering_packet)
    {
      ed->ipsec_ed->source_ip =
	ssh_obstack_calloc(ed->obstack, sizeof(SshIpAddrStruct));
      ed->ipsec_ed->destination_ip =
	ssh_obstack_calloc(ed->obstack, sizeof(SshIpAddrStruct));
      if (ed->ipsec_ed->source_ip == NULL ||
	  ed->ipsec_ed->destination_ip == NULL)
	{
	  if (callback)
	    (*callback)(ike_sa->server->sad_handle,
			ike_sa, ed,
			SSH_IKEV2_ERROR_OUT_OF_MEMORY);
	  /* Clear the callback so it will not be called twice. */
	  ed->callback = NULL_FNPTR;
	  ssh_ikev2_ipsec_exchange_destroy(ed);
	  return NULL;
	}
      if (triggering_packet->source_ip)
	*(ed->ipsec_ed->source_ip) =
	  *(triggering_packet->source_ip);
      if (triggering_packet->destination_ip)
	*(ed->ipsec_ed->destination_ip) =
	  *(triggering_packet->destination_ip);
      ed->ipsec_ed->protocol = triggering_packet->protocol;
      ed->ipsec_ed->source_port = triggering_packet->source_port;
      ed->ipsec_ed->destination_port =
	triggering_packet->destination_port;
    }

#ifdef SSHDIST_IKEV1
  if (ike_sa->flags & SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_IKEV1)
    return ikev2_fb_initiate_ipsec_sa(ed);
#endif /* SSHDIST_IKEV1 */

  if (ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_IKE_SA_DONE)
    {
      /* We have up and running IKE SA, start new create child exchange. */
      create_child_sa = TRUE;
    }
  else
    {
      create_child_sa = FALSE;
      if (ike_sa->initial_ed != NULL)
	{
	  if (callback)
	    (*callback)(ike_sa->server->sad_handle,
			ike_sa, ed,
			SSH_IKEV2_ERROR_SA_UNUSABLE);
	  /* Clear the callback so it will not be called twice. */
	  ed->callback = NULL_FNPTR;
	  ssh_ikev2_ipsec_exchange_destroy(ed);
	  return NULL;
	}
    }

  SSH_DEBUG(SSH_D_MIDSTART, ("Creating %sIPsec SA %@;%d",
			     !create_child_sa ? "IKE and " : "",
			     ssh_ipaddr_render, ike_sa->remote_ip,
			     ike_sa->remote_port));

  packet = ikev2_packet_allocate(ike_sa->server->context,
				 create_child_sa ?
				 ikev2_state_child_initiator_out :
				 ikev2_state_init_initiator_out);

  if (packet == NULL)
    {
      if (callback)
	(*callback)(ike_sa->server->sad_handle,
		    ike_sa, ed,
		    SSH_IKEV2_ERROR_OUT_OF_MEMORY);
      /* Clear the callback so it will not be called twice. */
      ed->callback = NULL_FNPTR;
      ssh_ikev2_ipsec_exchange_destroy(ed);
      return NULL;
    }

  memcpy(packet->ike_spi_i, ike_sa->ike_spi_i, 8);
  memcpy(packet->ike_spi_r, ike_sa->ike_spi_r, 8);
  packet->first_payload = SSH_IKEV2_PAYLOAD_TYPE_NONE;
  packet->major_version = 2;
  packet->minor_version = 0;

  error = ikev2_udp_window_allocate_id(ike_sa, &packet->message_id);
  if (error != SSH_IKEV2_ERROR_OK)
    {
      packet->ed = NULL;
      ssh_fsm_kill_thread(packet->thread);
      if (callback)
	(*callback)(ike_sa->server->sad_handle, ike_sa, ed, error);
      /* Clear the callback so it will not be called twice. */
      ed->callback = NULL_FNPTR;
      ssh_ikev2_ipsec_exchange_destroy(ed);
      return NULL;
    }

  if (create_child_sa)
    {
      /* Allocate abort handle, and take references to IKE SA and ED. */
      ssh_ikev2_ike_sa_take_ref(ike_sa);
      ikev2_reference_exchange_data(ed);
      /** Called if delete operation is aborted */
      /* SSH_IKEV2_POLICY_NOTIFY(ike_sa, ike_sa_delete) */
      ssh_operation_register_no_alloc(ed->ipsec_ed->operation_handle,
				      ikev2_ipsec_sa_abort,
				      ed);
      packet->exchange_type = SSH_IKEV2_EXCH_TYPE_CREATE_CHILD_SA;
    }
  else
    {
      /* Allocate abort handle, and take references to IKE SA. */
      ssh_ikev2_ike_sa_take_ref(ike_sa);

      /* Take a reference to ED and store it in the IKE SA as initial ED. */
      ikev2_reference_exchange_data(ed);
      ike_sa->initial_ed = ed;

      ssh_operation_register_no_alloc(ed->ipsec_ed->operation_handle,
				      ikev2_ike_sa_abort,
				      ike_sa);
      packet->exchange_type = SSH_IKEV2_EXCH_TYPE_IKE_SA_INIT;
      SSH_ASSERT(packet->message_id == 0);
    }

  /* The references to IKE SA and ED (taken in ipsec_create) are from this
     point on associated to the packet. */
  packet->ike_sa = ike_sa;
  packet->ed = ed;

  ed->ipsec_ed->flags |= SSH_IKEV2_IPSEC_OPERATION_REGISTERED;
  if (ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_INITIATOR)
    packet->flags = SSH_IKEV2_PACKET_FLAG_INITIATOR;
  else
    packet->flags = 0;
  packet->encoded_packet_len = 0;
  packet->encoded_packet = NULL;
  *(packet->remote_ip) = *(ike_sa->remote_ip);
  packet->remote_port = ike_sa->remote_port;
  packet->server = ike_sa->server;
  if (ike_sa->flags &
      (SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_START_WITH_NAT_T |
       SSH_IKEV2_IKE_SA_FLAGS_NAT_T_FLOAT_DONE))
    packet->use_natt = 1;
  else
    packet->use_natt = 0;
  ikev2_udp_window_update(packet);

  SSH_DEBUG(SSH_D_MIDOK, ("Started IPsec SA creation %@;%d",
			  ssh_ipaddr_render, ike_sa->remote_ip,
			  ike_sa->remote_port));

  return ed->ipsec_ed->operation_handle;

}

/* Free the ipsec sa exchange data without starting the
   exchange. */
void
ssh_ikev2_ipsec_exchange_destroy(SshIkev2ExchangeData ed)
{
  /* Free references to IKE SA and ED. They were taken in ipsec_create. */
  ssh_ikev2_ike_sa_free(ed->ike_sa);
  ikev2_free_exchange_data(ed->ike_sa, ed);
}


/* Rekey old SA. This will tell the other end that this
   exchange is a rekey of the old IPsec SA. Note, that this
   does not do anything else than store the old spi in the
   ed->ipsec_ed->rekeyed_spi, and automatically add REKEY_SA
   notification to be sent to the other end. It does not
   delete the old SA. The triggering packet of the
   ipsec_send will most likely be NULL, and the traffic
   selectors should include everything that was included in
   the old IPsec SA (unless policy has changed). The traffic
   selectors can be wider than from the old SA. */
void ssh_ikev2_ipsec_rekey(SshIkev2ExchangeData ed,
			   SshUInt32 old_spi)
{
  ed->ipsec_ed->rekeyed_spi = old_spi;
}
