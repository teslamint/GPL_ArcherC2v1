/*
 *
 *  Copyright:
 *          Copyright (c) 2008 SFNT Finland Oy.
 */

#include "sshincludes.h"
#include "sshikev2-initiator.h"
#include "sshikev2-exchange.h"
#include "sshikev2-util.h"
#include "ikev2-internal.h"

#define SSH_DEBUG_MODULE "SshIkev2StateAuthRespIn"

#ifdef SSH_IKEV2_MULTIPLE_AUTH

/* Responder side second IKE AUTH packet in. */
SSH_FSM_STEP(ikev2_state_second_auth_responder_in)
{
  SshIkev2Packet packet = thread_context;

  /** We have AUTH payload. */
  SSH_FSM_SET_NEXT(ikev2_state_second_auth_responder_in_check_auth);

  if (SSH_IKEV2_EAP_ENABLED(packet->ed->ike_ed) == FALSE)
    {
      if (packet->ed->ike_ed->id_i == NULL)
	{
	  SSH_IKEV2_DEBUG(SSH_D_NETGARB,
			  ("Error: Mandatory payload (IDi) "
			   "missing"));

	  ikev2_audit(packet->ike_sa,
		      SSH_AUDIT_IKE_BAD_PAYLOAD_SYNTAX,
                      "Second IKE_AUTH packet is missing mandatory payload "
		      "(IDi");
			
	  ikev2_error(packet, SSH_IKEV2_ERROR_INVALID_SYNTAX);
	}
      else
        {
          /* This is a valid start for the second auth round */
          packet->ed->ike_ed->authentication_round = 2;
        }
    }
  ikev2_process_notify(packet);
  return SSH_FSM_CONTINUE;
}

/* Responder side IKE AUTH packet, check if we have AUTH
   payload, and its type. */
SSH_FSM_STEP(ikev2_state_second_auth_responder_in_check_auth)
{
  SshIkev2Packet packet = thread_context;
  SshIkev2SaExchangeData ed = packet->ed->ike_ed;

  if (packet->ed->ike_ed->second_auth_remote == NULL)
    {
      SSH_IKEV2_DEBUG(SSH_D_LOWSTART, ("No AUTH, Enabling EAP for remote"));

      packet->ed->ike_ed->eap_state = SSH_IKEV2_EAP_STARTED;

      /** No auth payload ==> EAP enabled for remote. */
      /*SSH_FSM_SET_NEXT(ikev2_state_second_auth_responder_in_alloc_sa);*/
      SSH_FSM_SET_NEXT(ikev2_state_second_auth_responder_in_end);
  
    }
  else
    {
      SSH_IKEV2_DEBUG(SSH_D_LOWSTART, ("State = AUTH_LAST"));
      packet->ed->state = SSH_IKEV2_STATE_IKE_AUTH_LAST;
      ed->data_to_signed =
	ikev2_auth_data(packet, FALSE, FALSE, TRUE, &ed->data_to_signed_len);
      if (ed->data_to_signed == NULL)
	{
	  SSH_IKEV2_DEBUG(SSH_D_ERROR,
			  ("Error: Out of memory allocating data_to_signed"));
	  return ikev2_error(packet, SSH_IKEV2_ERROR_OUT_OF_MEMORY);
	}

      if (SSH_IKEV2_EAP_ENABLED(packet->ed->ike_ed))
	{
	  if (packet->ed->ike_ed->second_auth_remote->auth_method ==
	      SSH_IKEV2_AUTH_METHOD_SHARED_KEY)
	    {
	      SSH_FSM_SET_NEXT(ikev2_state_second_auth_responder_in_shared_key);
	      return SSH_FSM_CONTINUE;
	    }
	  else
	    {
	      SSH_IKEV2_DEBUG(SSH_D_NETGARB,
			      ("Error: Invalid second EAP auth_method type : %d",
			       packet->ed->ike_ed->second_auth_remote->
			       auth_method));
	      return ikev2_error(packet, SSH_IKEV2_ERROR_INVALID_SYNTAX);
	    }
	}

      switch (packet->ed->ike_ed->second_auth_remote->auth_method)
	{
	case SSH_IKEV2_AUTH_METHOD_SHARED_KEY:
	  /** Auth_method == SHARED_KEY */
	  SSH_FSM_SET_NEXT(ikev2_state_second_auth_responder_in_shared_key);
	  break;
	default:
	  SSH_IKEV2_DEBUG(SSH_D_NETGARB,
			  ("Error: Invalid second auth_method type : %d",
			   packet->ed->ike_ed->second_auth_remote->
			   auth_method));

	  ikev2_audit(packet->ike_sa,
		      SSH_AUDIT_IKE_INVALID_AUTHETICATION_METHOD,
		      "Invalid authentication method proposed, only"
		      "EAP is allowed for second authentication.");

	  ikev2_error(packet, SSH_IKEV2_ERROR_INVALID_SYNTAX);
	  break;
	}
    }
  return SSH_FSM_CONTINUE;
}

/* Verify shared key AUTH payload. */
SSH_FSM_STEP(ikev2_state_second_auth_responder_in_shared_key)
{
  SshIkev2Packet packet = thread_context;

  /* This can be either the EAP shared key packet or normal
     pre shared key  packet. */
  SSH_IKEV2_DEBUG(SSH_D_LOWSTART, ("Verify shared key AUTH payload"));

  /** Check EAP shared key auth payload */
  SSH_FSM_SET_NEXT(ikev2_state_second_auth_responder_in_end);
  
  SSH_FSM_ASYNC_CALL(ikev2_check_auth_eap(packet));
}

void 
ikev2_reply_cb_second_auth_resp_ipsec_spi_allocate(SshIkev2Error error_code,
                                                   SshUInt32 spi, 
                                                   void *context) 
{
  SshIkev2Packet packet = context;

  packet->operation = NULL;
  SSH_FSM_CONTINUE_AFTER_CALLBACK(packet->thread);
  ikev2_ipsec_error(packet, error_code);
  if (error_code == SSH_IKEV2_ERROR_OK)
    {
      SSH_IKEV2_DEBUG(SSH_D_LOWOK, ("IPsec SA allocated successfully"));
      packet->ed->ipsec_ed->spi_inbound = spi;
    }
  else
    {
      SSH_IKEV2_DEBUG(SSH_D_FAIL, ("Error: IPsec SA allocate failed: %d",
				   error_code));
    }
}

/* Allocate IPsec SA. */
SSH_FSM_STEP(ikev2_state_second_auth_responder_in_alloc_sa)
{
  SshIkev2Packet packet = thread_context;
  SshIkev2Sa ike_sa = packet->ike_sa;

  if (packet->use_natt)
    {
      packet->ed->ike_sa->flags |= SSH_IKEV2_IKE_SA_FLAGS_NAT_T_FLOAT_DONE;
      packet->ed->ike_sa->remote_port = packet->remote_port;
    }

  SSH_FSM_SET_NEXT(ikev2_state_second_auth_responder_in_end);
  SSH_FSM_ASYNC_CALL(SSH_IKEV2_POLICY_CALL(packet, ike_sa, ipsec_spi_allocate)
		     (ike_sa->server->sad_handle, packet->ed,
		      ikev2_reply_cb_second_auth_resp_ipsec_spi_allocate, 
                      packet));
}

/* Input processing done, start output processing. */
SSH_FSM_STEP(ikev2_state_second_auth_responder_in_end)
{
  SshIkev2Packet packet = thread_context;
  SshIkev2Packet reply_packet;

  /** Send reply IKE_AUTH packet. */
  /* SSH_FSM_SET_NEXT(ikev2_state_auth_responder_out); */
  reply_packet =
    ikev2_reply_packet_allocate(packet, 
                                ikev2_state_second_auth_responder_out);
  if (reply_packet == NULL)
    return SSH_FSM_CONTINUE;

  ikev2_udp_window_update(reply_packet);
  return SSH_FSM_FINISH;
}
#endif /* SSH_IKEV2_MULTIPLE_AUTH */
