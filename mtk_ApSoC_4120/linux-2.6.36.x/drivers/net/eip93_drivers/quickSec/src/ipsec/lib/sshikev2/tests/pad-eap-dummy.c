/*
  File: pad-dummy-eap.c

  Copyright:
        Copyright 2004 SFNT Finland Oy.
	All rights reserved.

  Description:
  	Dummy PAD module for EAP interface.
*/

#include "sshincludes.h"
#include "sshikev2-initiator.h"
#include "sshikev2-exchange.h"
#include "sshikev2-pad.h"
#include "pad-dummy.h"
#include "ssheap.h"
#include "sshmp.h"

#define SSH_DEBUG_MODULE "TestIkev2PADEap"

#ifdef SSHDIST_IKE_EAP_AUTH
#ifdef SSHDIST_EAP

/* XXX Temporary global variables until context data exists in SshSADHandle 
   or similar. */
#ifdef SSHDIST_RADIUS
extern SshEapRadiusConfiguration radius_config;
#endif /* SSHDIST_RADIUS */

extern Boolean use_eap;

typedef struct SshIkeEapStateRec {

  SshEap eap;
  SshEapConnection connection;
  SshEapConfiguration config;

#ifdef SSHDIST_RADIUS
  SshEapRadiusConfigurationStruct radius_config;
#endif /* SSHDIST_RADIUS */

#ifdef SSHDIST_RADIUS
  unsigned int radius_enabled : 1;  /* Using Radius */  
#endif /* SSHDIST_RADIUS */
  unsigned int destroyed : 1;       /* Waiting for destroy */
  unsigned int client : 1;          /* Client or server ? */
  unsigned int protocol_done : 1;   /* EAP protocol has completed. */
  unsigned int peer_ok : 1;         /* Client has authenticated */
  unsigned int auth_ok : 1;         /* Server has authenticated */
  unsigned int request_pending : 1; /* Has the IKE layer requested a packet? */
  unsigned int packet_ready : 1;    /* Is there a packet ready for IKE ?*/

  /* linearized EAP packet */
  unsigned char *packet;
  size_t packet_len;

  unsigned char *user;
  size_t user_len;

  unsigned char *salt;
  size_t salt_len;

  unsigned char *secret;
  size_t secret_len;

  SshIkev2PadEapRequestCB reply_callback;
  void *reply_callback_context;

  /* How many times IKE has asked for the EAP key */
  SshUInt8 key_requests; 

  SshOperationHandle op;
  
} *SshIkeEapState;


/* Forward declarations */
static void eap_output_cb(SshEapConnection con, void *ctx, 
			  const SshBuffer buf);
static void eap_signal_cb(SshEap eap, SshUInt8 type, SshEapSignal signal,
			  SshBuffer buf, void *ctx);
static void eap_schedule_destroy(void *ctx);
static void eap_destroy(void *ctx);



/**************** Initialization and Shutdown functions ***************/


/* This is called when the first EAP packet is received. It sets up any 
   state required for handling the EAP exchange. */
static SshIkeEapState eap_setup(Boolean client)
{
  SshIkeEapState eap_ctx;
  SshEapConfiguration config;

  SSH_DEBUG(SSH_D_LOWOK, ("Setup EAP state"));

  eap_ctx = ssh_xcalloc(1, sizeof(*eap_ctx));

  config = ssh_eap_config_create();

  if (!config)
    ssh_fatal("Cannot allocate an EAP configuration");
  
  config->auth_timeout_sec = 120;
  config->re_auth_delay_sec = 0;
  config->retransmit_delay_sec = 0;
  config->num_retransmit = 0;
  config->signal_cb = eap_signal_cb;
#ifdef SSHDIST_RADIUS
  config->radius_buffer_identity = TRUE;  
#endif /* SSHDIST_RADIUS */
  eap_ctx->client = client;

  eap_ctx->config = config;

#ifdef SSHDIST_RADIUS
  if (radius_config)
    {
      eap_ctx->radius_config = *radius_config;
      eap_ctx->radius_enabled = 1;
    }
#endif /* SSHDIST_RADIUS */

  /* Create the connection object for passing EAP packets to the lower 
     layer, which is the IKE library. */
  eap_ctx->connection = ssh_eap_connection_create_cb(eap_output_cb, eap_ctx);
  
  if (!eap_ctx->connection)
    ssh_fatal("Cannot allocate an EAP connection");
  
  if (client)
    eap_ctx->eap = ssh_eap_create_client(eap_ctx, config, eap_ctx->connection);
  else
    eap_ctx->eap = ssh_eap_create_server(eap_ctx, config, eap_ctx->connection);
  
  /* Accept MD5 challenge authentication. */
  ssh_eap_accept_auth(eap_ctx->eap, SSH_EAP_TYPE_MD5_CHALLENGE, 32);





  return eap_ctx;
}

/* XXX This should be used to signal errors to the IKE layer and arrange 
   to destroy EAP state. */
static void eap_schedule_destroy(void *context)
{
  SshIkeEapState ctx = context;

  ctx->destroyed = 1;
}

static void eap_destroy(void *context)
{
  SshIkeEapState ctx = context;

  SSH_ASSERT(ctx->destroyed == 1);

  ssh_eap_destroy(ctx->eap);
  ssh_eap_connection_destroy(ctx->connection);
  ssh_eap_config_destroy(ctx->config);

  if (ctx->packet)
    ssh_xfree(ctx->packet);

  if (ctx->user)
    ssh_xfree(ctx->user);

  if (ctx->salt)
    ssh_xfree(ctx->salt);

  if (ctx->secret)
    ssh_xfree(ctx->secret);
  
  if (ctx->op)
    ssh_operation_unregister(ctx->op);

  ssh_xfree(ctx);
}

/* XXX What should this do? */
static void eap_abort_cb(void *context)
{
  SSH_DEBUG(SSH_D_HIGHSTART, ("Entered"));
}


/******************** EAP Signal handling ***********************/


static void
handle_token_request(SshIkeEapState state, SshUInt8 sig_type, SshBuffer buf)
{
  SshEapTokenStruct token;
  SshEapTokenType token_type;
  SshMPInteger v;
  unsigned int i;

  v = NULL;

  SSH_ASSERT(buf != NULL);

  token_type = ssh_eap_get_token_type_from_buf(buf);

  switch (token_type)
    {
    case SSH_EAP_TOKEN_USERNAME:
      {
	/* XXX read from policy */
	char *user = "Joe Bloggs";
	
	state->user_len = strlen(user);
	state->user = ssh_xstrdup(user);
	
	ssh_eap_init_token_username(&token, (unsigned char *)user, 
				    strlen(user));
	break;
      }
    case SSH_EAP_TOKEN_SALT:

      state->salt_len = 20;
      state->salt = ssh_xmalloc(state->salt_len);
      for (i = 0; i < state->salt_len; i++)
	state->salt[i] = ssh_random_get_byte();

      ssh_eap_init_token_salt(&token, state->salt, state->salt_len);
      break;

    case SSH_EAP_TOKEN_SHARED_SECRET:

      /* XXX read from policy */
      state->secret = ssh_xstrdup("secret");
      state->secret_len = strlen("secret");;

      ssh_eap_init_token_secret(&token, state->secret, state->secret_len);

      break;












    default:
      token_type = SSH_EAP_TOKEN_NONE;
      break;
    }

  if (token_type != SSH_EAP_TOKEN_NONE)
    ssh_eap_token(state->eap, sig_type, &token);
  
  if (v != NULL)
    ssh_mprz_free(v);
  
  return;
}

static void begin_authentication(void *ctx)
{
  SshIkeEapState state = ctx;

#ifdef SSHDIST_RADIUS
  if (state->radius_enabled && state->radius_config.radius_client != NULL)
    ssh_eap_radius_attach(state->eap, &state->radius_config);
#endif /* SSHDIST_RADIUS */

  ssh_eap_authenticate(state->eap, SSH_EAP_AUTH_CONTINUE);
}

static void eap_signal_cb(SshEap eap, SshUInt8 type, SshEapSignal signal,
			  SshBuffer buf, void *ctx)
{
  SshIkeEapState state = ctx;
  unsigned char *buffer;
  size_t buffer_len;

  SSH_DEBUG(SSH_D_MIDOK, ("received signal %d type %d buf %s",
			  signal, type, (buf == NULL ? "<no>" : "<yes>")));
  
  switch (signal)
    {
    case SSH_EAP_SIGNAL_IDENTITY:
      if (state->client == FALSE)
        {
          if (buf != NULL)
            {
              unsigned char *strbuf = ssh_xmalloc(ssh_buffer_len(buf) + 1);

              strncpy(strbuf, ssh_buffer_ptr(buf), ssh_buffer_len(buf));
              strbuf[ssh_buffer_len(buf)] = '\0';

              SSH_DEBUG(SSH_D_MIDOK, ("received id: %s",strbuf));
              ssh_xfree(strbuf);
            }
	  ssh_xregister_timeout(0, 0, begin_authentication, state);
        }
      else
	SSH_NOTREACHED;
 
     break;
      
    case SSH_EAP_SIGNAL_NEED_TOKEN:

      SSH_ASSERT(buf != NULL);
      handle_token_request(state, type, buf);

      break;

    case SSH_EAP_SIGNAL_AUTH_FAIL_USERNAME:
    case SSH_EAP_SIGNAL_AUTH_FAIL_REPLY:
    case SSH_EAP_SIGNAL_AUTH_FAIL_NEGOTIATION:

      SSH_DEBUG(SSH_D_FAIL, ("EAP Authentication failed"));

      eap_schedule_destroy(state);
      break;

    case SSH_EAP_SIGNAL_AUTH_OK_USERNAME:

      SSH_DEBUG(SSH_D_HIGHOK, ("username authentication ok"));

      break;

    case SSH_EAP_SIGNAL_AUTH_AUTHENTICATOR_OK:

      SSH_DEBUG(SSH_D_HIGHOK, ("EAP authentication ok"));

      state->auth_ok = 1;
      break;

    case SSH_EAP_SIGNAL_AUTH_PEER_OK: 

      SSH_DEBUG(SSH_D_HIGHOK, ("peer authentication ok"));

      state->peer_ok = 1;      
      break;

    case SSH_EAP_SIGNAL_PACKET_DISCARDED:

      SSH_DEBUG(SSH_D_FAIL, ("Received packet discarded signal"));
      
      buffer_len = ssh_buffer_len(buf);
      buffer = ssh_buffer_ptr(buf);

      SSH_DEBUG_HEXDUMP(SSH_D_FAIL, ("Received packet"), buffer, buffer_len);

      eap_schedule_destroy(state);

    case SSH_EAP_SIGNAL_AUTH_FAIL_TIMEOUT:
      SSH_DEBUG(SSH_D_FAIL, ("Authentication failure timeout received"));
      eap_schedule_destroy(state);
      break;

    default:
      break;
    }
}


/******************** EAP output function ***********************/

/* The function outputs EAP packets to the lower layer. */
static void
eap_output_cb(SshEapConnection con, void *ctx, const SshBuffer buf)
{
  SshIkeEapState eap_ctx = ctx;
  unsigned char *packet;
  size_t packet_len;

  SSH_ASSERT(eap_ctx != NULL);

  packet_len = ssh_buffer_len(buf);
  packet = ssh_buffer_ptr(buf);

  if (eap_ctx->request_pending)
    {
      SSH_TRACE_HEXDUMP(SSH_D_LOWOK, ("Send packet, length %d", packet_len), 
			packet, packet_len);
      
      /* Output the packet immediately */
      (*eap_ctx->reply_callback)(SSH_IKEV2_ERROR_OK, 
				 packet, 
				 packet_len,
				 eap_ctx->reply_callback_context);
      
      eap_ctx->reply_callback_context = NULL_FNPTR;
      eap_ctx->reply_callback = NULL_FNPTR;
      eap_ctx->request_pending = 0;
    }
  else
    {
      SSH_ASSERT(eap_ctx->packet_ready == 0);
      
      SSH_TRACE_HEXDUMP(SSH_D_LOWOK, ("Saving packet, length %d", packet_len), 
			packet, packet_len);
      
      /* Save the packet data. */
      eap_ctx->packet_len = packet_len;
      eap_ctx->packet = ssh_xmemdup(packet, packet_len);

      eap_ctx->packet_ready = 1;
    }
  return;
}


/**************** Policy Manager Functions ****************************/

/* EAP payload processing */
void
d_pad_eap_received(SshSADHandle sad_handle,
		   SshIkev2ExchangeData ed,
		   const unsigned char *eap,
		   size_t eap_length)
{
  SshIkeEapState eap_ctx = ed->application_context;
  SshBuffer buf;
  Boolean client;

  SSH_DEBUG(SSH_D_HIGHSTART, ("Enter SA %p ED %p", ed->ike_sa, ed));

  /* Check if this is the first EAP packet. */
  if (eap_ctx == NULL)
    {
      /* Yes it is, setup the EAP state. */    
      client =
	(ed->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_INITIATOR) ? TRUE : FALSE;
      eap_ctx = eap_setup(client);
      ed->application_context = eap_ctx;
    }
  SSH_ASSERT(eap_ctx != NULL);    

  SSH_DEBUG(SSH_D_HIGHSTART, ("Received EAP payload of length %d", 
			      eap_length));

  /* XXX Reduce excess copying */
  buf = ssh_xbuffer_allocate();
  ssh_xbuffer_append(buf, (unsigned char *)eap, eap_length);
  
  SSH_DEBUG_HEXDUMP(SSH_D_FAIL, ("Received packet"), eap, eap_length);

  /* Pass the buffer to the EAP connection. */
  ssh_eap_connection_input_packet(eap_ctx->connection, buf);

  ssh_buffer_free(buf);
  return;
}

SshOperationHandle
d_pad_eap_request(SshSADHandle sad_handle,
		  SshIkev2ExchangeData ed,
		  SshIkev2PadEapRequestCB reply_callback,
		  void *reply_callback_context)
{
  SshIkeEapState eap_ctx = ed->application_context;
  Boolean client;

  SSH_DEBUG(SSH_D_HIGHSTART, ("Enter SA %p ED %p", ed->ike_sa, ed));

  /* Check if this is the first EAP packet. */
  if (eap_ctx == NULL)
    {
      /* Yes it is, set up the EAP state. */    
      client =
	(ed->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_INITIATOR) ? TRUE : FALSE;
      eap_ctx = eap_setup(client);
      ed->application_context = eap_ctx;

      if (!client)
	ssh_eap_send_identification_request(eap_ctx->eap, 
					  "Please identify yourself",
					  strlen("Please identify yourself"));
    }
  SSH_ASSERT(eap_ctx != NULL);    
  
  /* Verify we do not already have a request pending */
  SSH_ASSERT(eap_ctx->request_pending == FALSE);

  /* If the EAP library is ready, then send the packet out immediately. 
     Otherwise we wait until the EAP library indicates it is ready (by 
     calling the connection output callback). */  
  if (eap_ctx->packet_ready)
    {
      SSH_ASSERT(eap_ctx->packet != NULL);
      
      SSH_DEBUG_HEXDUMP(SSH_D_LOWSTART, ("Sending EAP packet"), 
			eap_ctx->packet, eap_ctx->packet_len);
      
      (*reply_callback)(SSH_IKEV2_ERROR_OK, 
			eap_ctx->packet, 
			eap_ctx->packet_len,
			reply_callback_context);
      
      ssh_xfree(eap_ctx->packet);
      eap_ctx->packet = NULL;
      eap_ctx->packet_len = 0;
      eap_ctx->packet_ready = 0;
      return NULL;
    }

  /* Check if the EAP layer is done, if so signal this to the IKE layer. 
     
  The initiator is done if and only if the signal 
  SSH_EAP_SIGNAL_AUTH_PEER_OK has been received i.e. eap_ctx->peer_ok = 1. 
  
  The responder is done if the signal SSH_EAP_SIGNAL_AUTH_AUTHENTICATOR_OK
  has been received i.e. eap_ctx->auth_ok = 1.  */
  
  if (eap_ctx->peer_ok || eap_ctx->auth_ok)
    {
      SSH_DEBUG(SSH_D_HIGHSTART, ("Signal that EAP is done"));
      
      SSH_ASSERT(eap_ctx->packet_ready == 0);
      SSH_ASSERT(eap_ctx->packet == NULL);
      
      (*reply_callback)(SSH_IKEV2_ERROR_OK, 
			NULL, 0,
			reply_callback_context);
      
      eap_ctx->protocol_done = 1;
      
      /* XXX Hack for destroying EAP state. The state can be destroyed 
	 when we indicate to the IKE layer that EAP is finished and the PSK 
	 has been returned to IKE (for the initiator the key is returned twice 
	 to IKE). */
      if (!eap_ctx->destroyed)
	{
	  if ((!eap_ctx->client && eap_ctx->key_requests == 2) || 
	      eap_ctx->key_requests == 2)
	    {
	      /* Destroying the EAP state. */
	      SSH_DEBUG(SSH_D_HIGHSTART, ("Destroying EAP state %d",
					  eap_ctx->key_requests));
	      
	      eap_ctx->destroyed = 1;
	      ssh_xregister_timeout(0, 0, eap_destroy, eap_ctx);
	      ed->application_context = NULL;
	    }
	}
      
      return NULL;
    }
  
  SSH_DEBUG(SSH_D_LOWOK, 
	    ("EAP packet not ready yet, saving this request"));

  SSH_ASSERT(eap_ctx->packet_ready == 0);  
  eap_ctx->request_pending = 1;
  eap_ctx->reply_callback = reply_callback;
  eap_ctx->reply_callback_context = reply_callback_context;
  
  eap_ctx->op = ssh_operation_register(eap_abort_cb, eap_ctx);
  return eap_ctx->op;
}

SshOperationHandle
d_pad_eap_key(SshSADHandle sad_handle,
	      SshIkev2ExchangeData ed,
	      SshIkev2PadSharedKeyCB reply_callback,
	      void *reply_callback_context)
{
  SshIkeEapState eap_ctx = ed->application_context;
  SshIkev2Error status = SSH_IKEV2_ERROR_OK;
  unsigned char *buf = NULL;
  size_t buf_len = 0;

  SSH_DEBUG(SSH_D_HIGHSTART, ("Enter SA %p ED %p", ed->ike_sa, ed));

  SSH_ASSERT(eap_ctx != NULL);

  /* XXX We should check that we have completed the EAP negotiation 
     before calling this. If not return with an error. */
  
  ssh_eap_master_session_key(eap_ctx->eap, &buf, &buf_len, NULL, NULL);

  if (buf == NULL)
    SSH_DEBUG(SSH_D_HIGHSTART, ("This EAP method does not return a key"));
  else
    SSH_DEBUG_HEXDUMP(SSH_D_LOWSTART, ("Returning EAP KEY"), buf, buf_len);
  
  (*reply_callback)(status, buf, buf_len, reply_callback_context);

  eap_ctx->key_requests++;

  /* XXX Hack for destroying EAP state. The state can be destroyed 
     when we indicate to the IKE layer that EAP is finished and the PSK 
     has been returned to IKE (the key is returned twice to IKE). */
  if (eap_ctx->protocol_done && !eap_ctx->destroyed)
    {
      if (eap_ctx->key_requests == 2)
	{
	  /* Destroying the EAP state. */
	  SSH_DEBUG(SSH_D_HIGHSTART, ("Destroying EAP state"));
	  
	  eap_ctx->destroyed = 1;
	  ssh_xregister_timeout(0, 0, eap_destroy, eap_ctx);
	  ed->application_context = NULL;
	}
    }

  ssh_free(buf);
  return NULL;
}

void d_pad_eap_destroy(SshSADHandle sad_handle,
		       SshIkev2ExchangeData ed)
{
  SshIkeEapState eap_ctx = ed->application_context;
  eap_ctx->destroyed = 1;
  ssh_xregister_timeout(0, 0, eap_destroy, eap_ctx);
  ed->application_context = NULL;
}

#endif /* SSHDIST_EAP */
#endif /* SSHDIST_IKE_EAP_AUTH */
