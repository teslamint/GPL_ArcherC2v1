/*
  File: appgw_sip.c

  Copyright:
  	Copyright (c) 2003, 2005 SFNT Finland Oy.
	All rights reserved.

  Description:

  References:

	RFC3261 	SIP: Session Initiation Protocol.
	RFC2327 	SDP: Session Description Protocol
	RFC1889   	RTP: A Transport Protocol for Real-Time Applications

	draft-rosenberg-sipping-nat-scenarios-00.txt
			NAT Scenarios for SIP, section 4.1, section 5.1

*/

/* Alg does the following changes on the SIP headers.

   -    do nothing
   l->a change local address to algs address
   a->l change algs address to local address

   type             initiated           type              initiated
     fields         from-in from-out      fields          from-in from-out

   inbound-req    	                 outbound-req
     from	    a->l    -	           from           l->a    -
     call-id	    a->l    - 	           call-id        l->a    -
     via	    -	    -	           via            l->a    l->a
     request-uri    -	    -	           request-uri    l->a    l->a
     contact	    -	    -	           contact        l->a    l->a

   inbound-rep	    		         outbound-rep
     from	    a->l    -	           from           l->a    -
     call-id	    a->l    -	           call-id        l->a    -
     via	    a->l    a->l           via            -       -
     request-uri    -	    -	           request-uri    -       -
     contact	    a->l    a->l           contact        l->a    l->a

   The following is done on the SDP, (delayed to when SIP ack is
   received), ACK may be used to change the session description, thus
   use the last values received.

                    IP      port
   inbound          -       -
   outbound         l->a    for each media;
                             open two consecutive ports for rtp and rtcp
                             and change ports to these. if /2 is present
                             open four ports.
			    if fail reply "busy here"
*/

#include "sshincludes.h"
#include "sshinet.h"
#include "sshtimeouts.h"
#include "sshadt.h"
#include "sshurl.h"
#include "sshadt_bag.h"
#include "appgw_api.h"

#ifdef SSHDIST_IPSEC_FIREWALL

#include "appgw_sip.h"

#define SSH_APPGW_IDENT   "alg-sip@ssh.com"
#define SSH_APPGW_NAME    "SIPALG"
#define SSH_APPGW_VERSION 1

#define SSH_DEBUG_MODULE  "SshAppgwSIP"


struct AlgSipCurrentPacketRec
{
  SshAppgwSipConnection session;
  SshSipHdr siphdr;
  SshFSMThreadStruct thread;
};
typedef struct AlgSipCurrentPacketRec *AlgSipCurrentPacket;
typedef struct AlgSipCurrentPacketRec  AlgSipCurrentPacketStruct;


/***************************************************************************
 * Internal utility functions
 */

static void alg_sip_destroy_timeout(void *context)
{
  SshAppgwSip sipalg = context;


  SSH_DEBUG(SSH_D_LOWOK, ("Alg destroyed at timeout."));

  ssh_appgw_unregister_local(sipalg->pm,
			     SSH_APPGW_IDENT,
			     SSH_APPGW_VERSION,
			     SSH_IPPROTO_TCP);

  ssh_appgw_unregister_local(sipalg->pm,
			     SSH_APPGW_IDENT,
			     SSH_APPGW_VERSION,
			     SSH_IPPROTO_UDP);

  if (sipalg->config)
    ssh_appgw_sip_destroy_config(sipalg->config);

  if (sipalg->sessions)
    ssh_adt_destroy(sipalg->sessions);

  ssh_free(sipalg->portmap_handles);
  ssh_free(sipalg->portmap);

  ssh_fsm_uninit(&sipalg->fsm);
  ssh_free(sipalg);
}

static void
alg_sip_destroy(SshAppgwSip sipalg)
{
  SSH_DEBUG(SSH_D_LOWOK, ("Alg destroy timeout registered."));
  ssh_xregister_timeout(0L, 100000L, alg_sip_destroy_timeout, sipalg);
}


static unsigned long
alg_sip_string_hash(unsigned char *str, size_t str_len)
{
  unsigned long hash = 0;
  size_t i;

  for (i = 0; i < str_len; i++)
    hash = (((hash << 19) ^ (hash >> 13)) + str[i]);
  return hash;
}

static unsigned long alg_sip_session_hash(void *ptr, void *context)
{
  unsigned long hash;
  SshAppgwSipConnection conn = ptr;

  hash = alg_sip_string_hash(conn->call_id, strlen(conn->call_id));









  return hash;
}

static int alg_sip_session_cmp(void *ptr1, void *ptr2, void *context)
{
  int rv;
  SshAppgwSipConnection c1 = ptr1;
  SshAppgwSipConnection c2 = ptr2;

  if ((rv = strcmp(c1->call_id, c2->call_id)) != 0)
    return rv;
#if 0
  if ((rv = strcmp(c1->from, c2->from)) != 0)
    return rv;
  if ((rv = strcmp(c1->to, c2->to)) != 0)
    return rv;
#endif
  return 0;
}

static void alg_sip_session_destroy(void *ptr, void *context)
{
  SshAppgwSipConnection session = ptr;

  if (session)
    {
      ssh_free(session->call_id);
      ssh_free(session->to);
      ssh_free(session->from);
      ssh_free(session->appgwaddr);
      ssh_free(session->localaddr);

      ssh_free(session);
    }
  return;
}

/***************************************************************************
 * State machines
 */

static SshADTHandle
alg_sip_session_get_handle(SshAppgwSip sipalg, SshSipHdr siphdr)
{
  SshAppgwSipConnectionStruct probe;
  SshADTHandle handle;

  if (siphdr->num_call_id == 0)
    return SSH_ADT_INVALID;

  probe.call_id = siphdr->call_id[0];

#if 0
  probe.to = siphdr->to[0];
  probe.from = siphdr->from[0];
#endif

  handle = ssh_adt_get_handle_to_equal(sipalg->sessions, &probe);

  return handle;
}

static SshADTHandle
alg_sip_session_get_handle_by_dst(SshAppgwSip sipalg,
				  SshIpAddr addr, SshUInt16 port)
{
  SshADTHandle handle;
  char addrport[72];

  ssh_snprintf(addrport, sizeof(addrport), "%@:%d",
	       ssh_ipaddr_render, addr,
	       port);

  for (handle = ssh_adt_enumerate_start(sipalg->sessions);
       handle != SSH_ADT_INVALID;
       handle = ssh_adt_enumerate_next(sipalg->sessions, handle))
    {
      SshAppgwSipConnection session = ssh_adt_get(sipalg->sessions, handle);

      if (session->appgwaddr &&
	  !strcmp(session->appgwaddr, addrport))
	break;
    }
  return handle;
}

static SshADTHandle
alg_sip_session_get_handle_by_src(SshAppgwSip sipalg,
				  SshIpAddr addr, SshUInt16 port)
{
  SshADTHandle handle;
  char addrport[72];

  ssh_snprintf(addrport, sizeof(addrport), "%@:%d",
	       ssh_ipaddr_render, addr,
	       port);

  for (handle = ssh_adt_enumerate_start(sipalg->sessions);
       handle != SSH_ADT_INVALID;
       handle = ssh_adt_enumerate_next(sipalg->sessions, handle))
    {
      SshAppgwSipConnection session = ssh_adt_get(sipalg->sessions, handle);

      if (session->localaddr && !strcmp(session->localaddr, addrport))
	break;
    }
  return handle;
}

SshAppgwSipConnection
alg_sip_session_create(SshAppgwSip sipalg, SshSipHdr siphdr)
{
  SshAppgwSipConnection session;

  if (siphdr->num_to != 1 || siphdr->num_from != 1 || siphdr->num_call_id != 1)
    {
      SSH_DEBUG(SSH_D_NETGARB,
		("Invalid SIP message, data missing from identifier."));
      return NULL;
    }

  if ((session = ssh_calloc(1, sizeof(*session))) == NULL)
    {
      return NULL;
    }

  session->to = ssh_strdup(siphdr->to[0]);
  session->from = ssh_strdup(siphdr->from[0]);
  session->call_id = ssh_strdup(siphdr->call_id[0]);

  if (session->to == NULL || session->from == NULL || session->call_id == NULL)
    {
      alg_sip_session_destroy(session, NULL);
    }
  return session;
}

Boolean
alg_sip_packet_from_internal(SshAppgwSip sipalg,
			     Boolean from_initiator,
			     SshAppgwContext instance)
{
  int i;
  Boolean from_internal = FALSE;
  SshIpAddr internal_networks;
  size_t num_internal_networks;

  internal_networks =
    ssh_appgw_sip_get_internal_networks(sipalg->config,
					&num_internal_networks);

  for (i = 0; i < num_internal_networks; i++)
    {
      SshIpAddr ip;

      if (from_initiator)
	ip = &instance->initiator_ip;
      else
	ip = &instance->responder_ip;

      if (ssh_ipaddr_mask_equal(ip, &internal_networks[i]))
	{
	  from_internal = TRUE;
	  break;
	}
    }
  return from_internal;
}

SSH_FSM_STEP(sip_packet_start);
SSH_FSM_STEP(sip_packet_change_from);
SSH_FSM_STEP(sip_packet_change_to);
SSH_FSM_STEP(sip_packet_change_callid);
SSH_FSM_STEP(sip_packet_change_via);
SSH_FSM_STEP(sip_packet_change_request_uri);
SSH_FSM_STEP(sip_packet_change_contact);
SSH_FSM_STEP(sip_packet_change_sdp);
SSH_FSM_STEP(sip_packet_open_ports);
SSH_FSM_STEP(sip_packet_done);
SSH_FSM_STEP(sip_session_start);
SSH_FSM_STEP(sip_session_wait);
SSH_FSM_STEP(sip_session_done);


SSH_FSM_STEP(sip_packet_start)
{
  SSH_FSM_SET_NEXT(sip_packet_change_from);
  return SSH_FSM_CONTINUE;
}




char *alg_sip_map_address(SshAppgwSip sipalg,
			  SshAppgwSipConnection session, char *host,
			  Boolean initiated_inside, Boolean packet_from_inside)
{
  /* outbound packet; l->a, inbound packet ; a->l */
  if (packet_from_inside)
    {
      return ssh_strdup(session->appgwaddr);
    }
  else
    {
      return ssh_strdup(session->localaddr);
    }
}

static void sip_packet_thread_destroy(SshFSM fsm, void *context)
{
  AlgSipCurrentPacket cp = context;

  if (cp->siphdr)
    alg_sip_free_header(cp->siphdr);
  ssh_free(cp);
}

#define SHUTDOWN(sipalg)			\
do {						\
  if (sipalg->shutdown)				\
    {						\
      SSH_DEBUG(SSH_D_LOWOK, ("Shutting down, going to done state.")); \
      SSH_FSM_SET_NEXT(sip_packet_done);	\
      return SSH_FSM_CONTINUE;			\
    }						\
} while (0)

/* This state changes 'From:' field contained IP or DNS information
   and enters next change state. It records the chages made into the
   connection. */
SSH_FSM_STEP(sip_packet_change_from)
{
  SshAppgwSip sipalg = fsm_context;
  AlgSipCurrentPacket cp = thread_context;
  SshSipHdr siphdr = cp->siphdr;
  SshAppgwSipConnection session = cp->session;
  char *dname, *user, *host, *params;
  char *nhost;

  SHUTDOWN(sipalg);

  SSH_FSM_SET_NEXT(sip_packet_change_to);
  if (siphdr->change.from)
    {
      if (siphdr->num_from &&
	  alg_sip_parse_sip_address(siphdr->from[0],
				    &dname, &user, &host, &params))
	{
	  if ((nhost =
	       alg_sip_map_address(sipalg, session,
				   host,
				   session->initiated_from_inside,
				   siphdr->from_internal)) != NULL)
	    {
	      ssh_free(siphdr->from[0]);
	      siphdr->from[0] = alg_sip_write_sip_address(dname, user, nhost,
							  params, FALSE);
	      ssh_free(nhost);
	    }
	  ssh_free(dname); ssh_free(user); ssh_free(host);
	  ssh_free(params);
	}
      else
	{
	  SSH_FSM_SET_NEXT(sip_packet_done);
	}
    }
  return SSH_FSM_CONTINUE;
}

/* This state changes 'From:' field contained IP or DNS information
   and enters next change state. It records the chages made into the
   connection. */
SSH_FSM_STEP(sip_packet_change_to)
{
  SshAppgwSip sipalg = fsm_context;
  AlgSipCurrentPacket cp = thread_context;
  SshSipHdr siphdr = cp->siphdr;
  SshAppgwSipConnection session = cp->session;
  char *dname, *user, *host, *params;
  char *nhost;

  SHUTDOWN(sipalg);

  SSH_FSM_SET_NEXT(sip_packet_change_callid);
  if (siphdr->change.to)
    {
      if (siphdr->num_to &&
	  alg_sip_parse_sip_address(siphdr->to[0],
				    &dname, &user, &host, &params))
	{
	  if ((nhost =
	       alg_sip_map_address(sipalg, session,
				   host,
				   session->initiated_from_inside,
				   siphdr->from_internal)) != NULL)
	    {
	      ssh_free(siphdr->to[0]);
	      siphdr->to[0] = alg_sip_write_sip_address(dname, user, nhost,
							params, FALSE);
	      ssh_free(nhost);
	    }
	  ssh_free(dname); ssh_free(user); ssh_free(host);
	  ssh_free(params);
	}
      else
	{
	  SSH_FSM_SET_NEXT(sip_packet_done);
	}
    }
  return SSH_FSM_CONTINUE;
}


SSH_FSM_STEP(sip_packet_change_callid)
{
  SshAppgwSip sipalg = fsm_context;
  AlgSipCurrentPacket cp = thread_context;
  SshSipHdr siphdr = cp->siphdr;
  SshAppgwSipConnection session = cp->session;
  unsigned char *id = NULL, *host = NULL;
  char *nhost;

  SHUTDOWN(sipalg);

  SSH_FSM_SET_NEXT(sip_packet_change_via);

  if (siphdr->change.callid)
    {
      if (siphdr->num_call_id &&
	  ssh_url_parse_authority(siphdr->call_id[0], &id, NULL, &host, NULL))
	{
	  if ((nhost = alg_sip_map_address(sipalg, session,
					   host,
					   session->initiated_from_inside,
					   siphdr->from_internal)) != NULL)
	    {
	      ssh_free(siphdr->call_id[0]);
	      ssh_url_construct_authority(id, NULL, nhost, NULL,
					  (unsigned char **)
					  (&siphdr->call_id[0]));
	      ssh_free(nhost);
	    }

	}
    }
  ssh_free(id); ssh_free(host);
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(sip_packet_change_via)
{
  AlgSipCurrentPacket cp = thread_context;
  SshAppgwSip sipalg = fsm_context;
  SshAppgwSipConnection session = cp->session;
  SshSipHdr siphdr = cp->siphdr;
  char *proto, *sent, *params;
  SshUInt16 port;
  char *nsent;

  SHUTDOWN(sipalg);

  SSH_FSM_SET_NEXT(sip_packet_change_request_uri);
  if (siphdr->change.via)
    {
      if (siphdr->num_via &&
	  alg_sip_parse_sip_via(siphdr->via[0], &proto, &sent, &port, &params))
	{
	  if ((nsent = alg_sip_map_address(sipalg, session, sent,
					   session->initiated_from_inside,
					   siphdr->from_internal)) != NULL)
	    {
	      ssh_free(siphdr->via[0]);
	      siphdr->via[0] = alg_sip_write_sip_via(proto, nsent, 0,
						     params);
	      ssh_free(nsent);
	    }
	  ssh_free(proto); ssh_free(sent); ssh_free(params);
	}
    }
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(sip_packet_change_request_uri)
{
  AlgSipCurrentPacket cp = thread_context;
  SshAppgwSip sipalg = fsm_context;
  SshAppgwSipConnection session = cp->session;
  SshSipHdr siphdr = cp->siphdr;
  char *dname, *user, *host, *params;
  char *nhost;

  SHUTDOWN(sipalg);

  SSH_FSM_SET_NEXT(sip_packet_change_contact);
  if (siphdr->change.request_uri)
    {
      if (siphdr->is_request)
	{
	  if (alg_sip_parse_sip_address(siphdr->u.request.uri,
					&dname, &user, &host, &params))
	    {
	      if ((nhost = alg_sip_map_address(sipalg, session, host,
					       session->initiated_from_inside,
					       siphdr->from_internal)) != NULL)
		{
		  ssh_free(siphdr->u.request.uri);
		  siphdr->u.request.uri =
		    alg_sip_write_sip_address(dname, user, nhost, params,
					      TRUE);
		  ssh_free(nhost);
		}
	      ssh_free(dname); ssh_free(user); ssh_free(host);
	      ssh_free(params);
	    }
	}
    }
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(sip_packet_change_contact)
{
  AlgSipCurrentPacket cp = thread_context;
  SshAppgwSip sipalg = fsm_context;
  SshAppgwSipConnection session = cp->session;
  SshSipHdr siphdr = cp->siphdr;
  char *dname, *user, *host, *params;
  char *nhost;

  SHUTDOWN(sipalg);

  SSH_FSM_SET_NEXT(sip_packet_done);
  if (siphdr->change.contact)
    {
      if (siphdr->num_contact &&
	  alg_sip_parse_sip_address(siphdr->contact[0],
				    &dname, &user, &host, &params))
	{
	  if ((nhost = alg_sip_map_address(sipalg, session,
					   host,
					   session->initiated_from_inside,
					   siphdr->from_internal)) != NULL)
	    {
	      ssh_free(siphdr->contact[0]);
	      siphdr->contact[0] =
		alg_sip_write_sip_address(dname, user, nhost, params, FALSE);
	      ssh_free(nhost);
	    }
	  ssh_free(dname); ssh_free(user); ssh_free(host); ssh_free(params);
	}
      else
	{
	  SSH_FSM_SET_NEXT(sip_packet_done);
	}
    }
  return SSH_FSM_CONTINUE;
}

static void
sip_packet_open_ports_cb(SshUInt16 port, SshUInt16 nports, void *context)
{
  AlgSipCurrentPacket cp = context;
  SshAppgwSipConnection session = cp->session;
  void *tmp;

  if (port)
    {
      if ((tmp =
	   ssh_realloc(session->transport_ports,
		       session->num_transport_ports *
		       sizeof(SshAppgwSipOpenPortStruct),
		       (1 + session->num_transport_ports) *
		       sizeof(SshAppgwSipOpenPortStruct)))
	  == NULL)
	{
	  session->port_open_failed = 0x1;
	  SSH_FSM_CONTINUE_AFTER_CALLBACK(&cp->thread);
	}

      session->transport_ports = tmp;
      session->transport_ports[session->num_transport_ports].port = port;
      session->transport_ports[session->num_transport_ports].nports = nports;

      session->num_transport_ports += 1;
    }
  else
    {
      session->port_open_failed = 0x1;
    }

  SSH_FSM_CONTINUE_AFTER_CALLBACK(&cp->thread);
}

SSH_FSM_STEP(sip_packet_change_sdp)
{
  SshAppgwSip sipalg = fsm_context;
  AlgSipCurrentPacket cp = thread_context;
  SshAppgwSipConnection session = cp->session;
  char *s0, *s1, *s2, *s3, *s4;
  char *addr, *naddr, *colon;
  SshUInt16 nports, dstport;
  SshSipHdr siphdr = cp->siphdr;
  SshSdpHdr sdphdr = siphdr->payload.sdp.header;
  int i;

  SHUTDOWN(sipalg);

  if (!siphdr->from_internal)
    {
      siphdr->payload.sdp.mapped = 0x1;
      SSH_FSM_SET_NEXT(sip_packet_done);
      return SSH_FSM_CONTINUE;
    }

  /* Change SDP m, o and c address information; prefer dns names. */
  for (i = 0; i < sdphdr->num_m; i++)
    {
      if (alg_sip_parse_sdp_m(sdphdr->m[i],
			      &s0, &dstport, &nports, &s3, &s4))
	{
	  ssh_free(sdphdr->m[i]);
	  sdphdr->m[i] = alg_sip_write_sdp_m(s0,
					     session->transport_ports[i].port,
					     nports,
					     s3, s4);
	  ssh_free(s0); ssh_free(s3); ssh_free(s4);
	}
    }

  if (alg_sip_parse_sdp_o(sdphdr->o[0], &s0, &s1, &s2, &s3, &s4, &addr))
    {
      naddr =
	alg_sip_map_address(sipalg,
			    session, addr,
			    session->initiated_from_inside,
			    siphdr->from_internal);
      if ((colon = strchr(naddr, ':')) != NULL) *colon = '\0';
      ssh_free(sdphdr->o[0]);
      sdphdr->o[0] = alg_sip_write_sdp_o(s0, s1, s2, s3, s4, naddr);
      ssh_free(naddr);
      ssh_free(addr);

      ssh_free(s0); ssh_free(s1); ssh_free(s2); ssh_free(s3); ssh_free(s4);
    }

  if (alg_sip_parse_sdp_c(sdphdr->c[0], &s0, &s1, &addr))
    {
      naddr =
	alg_sip_map_address(sipalg,
			    session, addr,
			    session->initiated_from_inside,
			    siphdr->from_internal);
      if ((colon = strchr(naddr, ':')) != NULL) *colon = '\0';
      ssh_free(sdphdr->c[0]);
      sdphdr->c[0] = alg_sip_write_sdp_c(s0, s1, naddr);
      ssh_free(naddr);
      ssh_free(addr);

      ssh_free(s0); ssh_free(s1);
    }

  siphdr->payload.sdp.mapped = 0x1;
  SSH_FSM_SET_NEXT(sip_packet_done);
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(sip_packet_open_ports)
{
  SshAppgwSip sipalg = fsm_context;
  AlgSipCurrentPacket cp = thread_context;
  SshSipHdr siphdr = cp->siphdr;
  SshSdpHdr sdphdr = siphdr->payload.sdp.header;
  SshAppgwSipConnection session = cp->session;
  SshUInt16 dstport, nports;
  char *mline, *media, *proto, *rest;

  SHUTDOWN(sipalg);

  if (session->port_open_failed)
    {
      SSH_FSM_SET_NEXT(sip_packet_done);
      return SSH_FSM_CONTINUE;
    }

  if (session->num_transport_ports == sdphdr->num_m)
    {
      SSH_FSM_SET_NEXT(sip_packet_done);
      return SSH_FSM_CONTINUE;
    }

  SSH_FSM_SET_NEXT(sip_packet_open_ports);

  /* Grab destination port and range size from the current m-line. */
  mline = sdphdr->m[session->num_transport_ports];
  if (alg_sip_parse_sdp_m(mline, &media, &dstport, &nports, &proto, &rest))
    {
      if (nports == 0 && !strncmp(proto, "RTP", 3))
	nports = 4;

      ssh_free(media); ssh_free(proto); ssh_free(rest);

      /* Loop to open ports for each media */
      SSH_FSM_ASYNC_CALL({
	alg_sip_open_transport(sipalg,
			       session->instance,
			       session->initiated_from_inside,
			       dstport, nports,
			       sip_packet_open_ports_cb,
			       cp);
      });
    }
  else
    {
      session->num_transport_ports++;
      return SSH_FSM_CONTINUE;
    }
}

SSH_FSM_STEP(sip_packet_done)
{
  SshAppgwSip sipalg = fsm_context;
  AlgSipCurrentPacket cp = thread_context;
  SshAppgwSipConnection session = cp->session;
  SshSipHdr p;

  if (!sipalg->shutdown)
    {
      if (cp->siphdr->payload_sdp &&
	  cp->siphdr->from_internal &&
	  !cp->siphdr->payload.sdp.mapped)
	{
	  if (session->num_transport_ports == 0)
	    {
	      SSH_FSM_SET_NEXT(sip_packet_open_ports);
	      return SSH_FSM_CONTINUE;
	    }
	  else
	    {
	      SSH_FSM_SET_NEXT(sip_packet_change_sdp);
	      return SSH_FSM_CONTINUE;
	    }
	}

      /* Current packet was processed, record it into session. */
      cp->siphdr->next = NULL;
      if ((p = session->c_siphdr) != NULL)
	{
	  while (p->next) p = p->next;
	  p->next = cp->siphdr;
	}
      else
	session->c_siphdr = cp->siphdr;

      /* gave the responsibility to session mechanism */
      cp->siphdr = NULL;
      SSH_FSM_CONDITION_SIGNAL(&cp->session->packet_received);
    }

  SSH_DEBUG(SSH_D_MIDOK,
	    ("Packet done, thread terminating (%p).%s",
	     &cp->thread, sipalg->shutdown ? " [shutdown]" : ""));

  return SSH_FSM_FINISH;
}


/* Start new SIP connection. This opens holes on the firewall for SIP
   traffic */
SSH_FSM_STEP(sip_session_start)
{
  SSH_DEBUG(SSH_D_HIGHOK, ("Session: Started"));
  SSH_FSM_SET_NEXT(sip_session_wait);
  return SSH_FSM_CONTINUE;
}

static void
sip_session_terminate_timeout(void *context)
{
  SshAppgwSipConnection session = context;

  session->terminated = 0x1;
  ssh_fsm_condition_signal(ssh_fsm_get_fsm(&session->thread),
			   &session->packet_received);
}

/* Wait for events on connection (received packets or timeouts) */
SSH_FSM_STEP(sip_session_wait)
{
  SshAppgwSipConnection session = thread_context;
  char *sip, *sdp = NULL;
  SshAppgwSip sipalg = fsm_context;

  if (sipalg->shutdown || session->port_open_failed)
    {
      SSH_FSM_SET_NEXT(sip_session_done);
      return SSH_FSM_CONTINUE;
    }

  /* Are we done after receiving terminate timeout */
  if (session->terminated)
    {
      SSH_FSM_SET_NEXT(sip_session_done);
      return SSH_FSM_CONTINUE;
    }

  if (session->c_siphdr == NULL)
    {
      SSH_DEBUG(SSH_D_HIGHOK, ("Session: Waiting for packets"));
      SSH_FSM_CONDITION_WAIT(&session->packet_received);
    }

  SSH_FSM_SET_NEXT(sip_session_wait);

  while (session->c_siphdr)
    {
      SshSipHdr siphdr;

      siphdr = session->c_siphdr;
      session->c_siphdr = siphdr->next;

      SSH_DEBUG(SSH_D_HIGHOK, ("Session: Received %s",
			       siphdr->is_request ? "request" : "response"));

      if (siphdr->is_request)
	{
	  if (!strcasecmp(siphdr->u.request.method, "bye") ||
	      !strcasecmp(siphdr->u.request.method, "cancel"))
	    {
	      if (!session->terminating)
		{
		  session->terminating = 0x1;
		  ssh_register_timeout(&session->timeout,
				       30L, 0L,
				       sip_session_terminate_timeout,
				       session);
		}
	    }
	}

      if (siphdr->payload_sdp)
	{
	  SshSdpHdr sdphdr = siphdr->payload.sdp.header;
	  if ((sdp = alg_sip_write_sdp_header(sdphdr)) == NULL)
	    {
	      SSH_DEBUG(SSH_D_FAIL, ("Session: Can't write SDP header"));
	      goto failed;
	    }
	  siphdr->content_length = strlen(sdp);
	}
      else
	{
	  if ((sdp = ssh_memdup(siphdr->payload.sip.content,
				siphdr->payload.sip.content_len))
	      == NULL)
	    goto failed;
	  
	  siphdr->content_length = siphdr->payload.sip.content_len;
	}

      if (sdp)
	SSH_DEBUG(SSH_D_LOWOK, ("SDP=%s", sdp));

      if ((sip = alg_sip_write_sip_header(siphdr)) != NULL)
	{
	  SshBufferStruct output;
	  SshUdpListener listener;

	  ssh_buffer_init(&output);
	  ssh_buffer_append_cstrs(&output, sip, NULL);
	  if (sdp)
	    ssh_buffer_append_cstrs(&output, "\n\n", sdp, NULL);

	  ssh_free(sip);
	  SSH_DEBUG(SSH_D_HIGHOK, ("Session: Sending SIP"));

	  switch (siphdr->proto)
	    {
	    case SSH_IPPROTO_UDP:









	      if (siphdr->from_initiator)
		listener = siphdr->instance->responder_listener;
	      else
		listener = siphdr->instance->initiator_listener;

	      ssh_udp_send(listener,
			   NULL, NULL,
			   ssh_buffer_ptr(&output), ssh_buffer_len(&output));
	      break;

	    case SSH_IPPROTO_TCP:
	    default:
	      break;
	    }
	  ssh_buffer_uninit(&output);

	  /* close appgw instance for this connection unless it is the
	     master instance. */
	  if (session->instance != siphdr->instance)
	    {
	      ssh_appgw_done(siphdr->instance);
	      siphdr->instance = NULL;
	    }
	}
    failed:
      alg_sip_free_header(siphdr);
    }

  if (sdp)
    ssh_free(sdp);

  session->c_siphdr = NULL;
  return SSH_FSM_CONTINUE;
}

static void sip_session_thread_destroy(SshFSM fsm, void *context)
{
  SshAppgwSipConnection session = context;
  SshAppgwSip sipalg = ssh_fsm_get_gdata_fsm(fsm);

  ssh_adt_delete(sipalg->sessions, &session->bag_header);

  if (ssh_adt_num_objects(sipalg->sessions) == 0 &&
      sipalg->shutdown)
    {
      sipalg->shutdown_pending = 0x0;
      alg_sip_destroy(sipalg);
    }
}

SSH_FSM_STEP(sip_session_done)
{
  SshAppgwSipConnection session = thread_context;
  SshAppgwSip sipalg = fsm_context;
  SshSipHdr siphdr;
  int i;

  for (i = 0; i < session->num_transport_ports; i++)
    {
      alg_sip_close_transport(sipalg,
			      session->instance,
			      session->transport_ports[i].port,
			      session->transport_ports[i].nports);
    }

  while ((siphdr = session->c_siphdr) != NULL)
    {
      session->c_siphdr = siphdr->next;
      alg_sip_free_header(siphdr);
    }

  ssh_free(session->transport_ports);
  ssh_cancel_timeout(&session->timeout);

  if (sipalg->shutdown)
    {
      if (session->instance)
	{
	  SshADTHandle handle;
	  for (handle = ssh_adt_enumerate_start(sipalg->sessions);
	       handle != SSH_ADT_INVALID;
	       handle = ssh_adt_enumerate_next(sipalg->sessions, handle))
	    {
	      SshAppgwSipConnection s = ssh_adt_get(sipalg->sessions, handle);
	      if (s != session && s->instance == session->instance)
		s->instance = NULL;
	    }
	  ssh_appgw_done(session->instance);
	  session->instance = NULL;
	}
    }

  SSH_DEBUG(SSH_D_HIGHOK, ("Session: Terminated %p", &session->thread));
  return SSH_FSM_FINISH;
}

void alg_sip_process_packet(SshAppgwSip sipalg,
			    SshAppgwContext instance,
			    Boolean from_initiator,
			    Boolean from_internal,
			    SshInetIPProtocolID proto,
			    const unsigned char *data, size_t data_len)
{
  SshSipHdr siphdr;
  SshSdpHdr sdphdr;
  char *packet;
  const char *errortext = "";
  AlgSipCurrentPacket cp;
  char *sipend, *end;
  SshADTHandle handle;
  SshAppgwSipConnection session;
  Boolean newsession;

  if (sipalg->shutdown)
    return;

  if ((packet = (char *)ssh_memdup(data, data_len)) == NULL)
    {
      errortext = "Out of memory when processing SIP packet";

    audit:
      ssh_appgw_audit_event(instance,
			    SSH_AUDIT_WARNING,
			    SSH_AUDIT_TXT, errortext,
			    SSH_AUDIT_ARGUMENT_END);
      return;
    }

  newsession = FALSE;
  session = NULL;

  if ((siphdr = alg_sip_parse_request(packet, &sipend)) != NULL)
    {
      /* Check if it a packet to already existing session (by
	 session-id), or a inbound packet to port natted session
	 initiated from inside */

      handle = alg_sip_session_get_handle(sipalg, siphdr);
      if (handle == SSH_ADT_INVALID && !from_initiator)
	{
	  if (from_internal)
	    handle =
	      alg_sip_session_get_handle_by_dst(sipalg,
						&instance->
						responder_orig_ip,
						instance->
						responder_orig_port);
	  else
	    handle =
	      alg_sip_session_get_handle_by_dst(sipalg,
						&instance->
						initiator_ip_after_nat,
						instance->
						initiator_port_after_nat);
	}

      /* If not check if we are supposed to set up session */
      if (handle == SSH_ADT_INVALID)
	{
	  if (!strcasecmp(siphdr->u.request.method, "invite") ||
	      !strcasecmp(siphdr->u.request.method, "message") ||
	      !strcasecmp(siphdr->u.request.method, "register"))
	    {
	      if ((session = alg_sip_session_create(sipalg, siphdr)) != NULL)
		{
		  char localaddr[64], appgwaddr[64];

		  /* New session and packet from internal address */
		  if (from_internal)
		    {
		      session->initiated_from_inside = 0x1;

		      ssh_snprintf(localaddr, sizeof(localaddr),
				   "%@:%d",
				   ssh_ipaddr_render,
				   &instance->initiator_ip,
				   instance->initiator_port);

		      ssh_snprintf(appgwaddr, sizeof(appgwaddr),
				   "%@:%d",
				   ssh_ipaddr_render,
				   &instance->initiator_ip_after_nat,
				   instance->initiator_port_after_nat);
		    }
		  else
		    {
		      session->initiated_from_inside = 0x0;

		      /* If we have a conduit, this may be a packet
			 matching one. */
		      if (sipalg->config)
			{
			  SshIpAddr internal_ip;





			  internal_ip =
			    ssh_appgw_sip_conduit_apply(sipalg->config,
							&instance->
							responder_orig_ip,
							FALSE);
			  ssh_snprintf(localaddr, sizeof(localaddr),
				       "%@:%d",
				       ssh_ipaddr_render, internal_ip,
				       5060);

			  ssh_snprintf(appgwaddr, sizeof(appgwaddr),
				       "%@:%d",
				       ssh_ipaddr_render,
				       &instance->responder_orig_ip,
				       instance->responder_orig_port);

			  ssh_free(internal_ip);
			}
		      else
			{
			  errortext = "Appgw configuration missing";
			  goto audit_and_free;
			}
		    }

		  SSH_DEBUG(SSH_D_MIDOK, ("ALG=%s L=%s",appgwaddr, localaddr));

		  /* Set up session */
		  session->instance  = instance;
		  session->localaddr = ssh_strdup(localaddr);
		  session->appgwaddr = ssh_strdup(appgwaddr);
		  session->c_siphdr  = NULL;

		  handle = ssh_adt_insert(sipalg->sessions, session);
		  newsession = TRUE;
		}
	      else
		{
		  alg_sip_session_destroy(session, NULL);

		  errortext = "Out of memory when creating new SIP session";
		  goto audit_and_free;
		}
	    }
	  else
	    {
	      errortext = "Invalid SIP session establishing message type";
	    audit_and_free:
	      ssh_appgw_audit_event(instance,
				    SSH_AUDIT_WARNING,
				    SSH_AUDIT_TXT, errortext,
				    SSH_AUDIT_ARGUMENT_END);
	      alg_sip_free_header(siphdr);
	      ssh_free(packet);
	      return;
	    }
	}

      SSH_ASSERT(handle != SSH_ADT_INVALID);

      session = ssh_adt_get(sipalg->sessions, handle);

      SSH_DEBUG(SSH_D_MIDOK,
		("REQ S-init=%s P-from=%s",
		 session->initiated_from_inside ? "IN" : "OUT",
		 from_internal ? "internal" : "external"));

      if (session->initiated_from_inside)
	{
	  if (!from_internal)
	    {
	      /* change from and call-id. */
	      siphdr->change.to = 0x1;
	      siphdr->change.request_uri = 0x1;
	      siphdr->change.callid = 0x1;
	    }
	  else
	    {
	      /* change from, call-id, via, and contact */
	      siphdr->change.from = 0x1;
	      siphdr->change.via = 0x1;
	      siphdr->change.contact = 0x1;
	      siphdr->change.callid = 0x1;
	    }
	}
      else
	{
	  /* Session intiated from outside */
	  if (!from_internal)
	    {
	      siphdr->change.to = 0x1;
	      siphdr->change.request_uri = 0x1;
	    }
	  else
	    {
	      siphdr->change.from = 0x1;
	      siphdr->change.via = 0x1;
	      siphdr->change.contact = 0x1;
	    }
	}
    }
  else
    {
      ssh_free(packet);
      if ((packet = (char *)ssh_memdup(data, data_len)) == NULL)
	{
	  errortext = "Out of memory when processing SIP packet";
	  goto audit;
	}
    }


  if (siphdr == NULL &&
      (siphdr = alg_sip_parse_response(packet, &sipend)) != NULL)
    {
      handle = alg_sip_session_get_handle(sipalg, siphdr);

      if (handle == SSH_ADT_INVALID && from_initiator)
	{
	  /* see IM responses case from request not from initiator */
	  handle =
	    alg_sip_session_get_handle_by_src(sipalg,
					      &instance->initiator_ip,
					      instance->initiator_port);
	}

      if (handle == SSH_ADT_INVALID)
	{
	  errortext = "SIP response without valid request.";
	  goto audit_and_free;
	}

      session = ssh_adt_get(sipalg->sessions, handle);

      SSH_DEBUG(SSH_D_MIDOK,
		("REP S-init=%s P-from=%s",
		 session->initiated_from_inside ? "IN" : "OUT",
		 from_internal ? "internal" : "external"));


      if (session->initiated_from_inside)
	{
	  if (!from_internal)
	    {
	      /* change from and call-id. */
	      siphdr->change.from = 0x1;
	      siphdr->change.callid = 0x1;
	    }
	  else
	    {
	      /* change from, call-id, via, request-uri, and
		 contact */
	      siphdr->change.to = 0x1;
	      siphdr->change.callid = 0x1;
	      siphdr->change.via = 0x1;
	      siphdr->change.contact = 0x1;
	    }
	}
      else
	{
	  if (!from_internal)
	    {
	      siphdr->change.from = 0x1;
	      siphdr->change.contact = 0x1;
	    }
	  else
	    {
	      siphdr->change.to = 0x1;
	      siphdr->change.via = 0x1;
	      siphdr->change.contact = 0x1;
	    }
	}
    }

  if (siphdr == NULL)
    {
      errortext = "Can't parse SIP request or response from packet received";
      ssh_free(packet);
      goto audit;
    }

  siphdr->from_internal = from_internal ? 0x1: 0x0;
  siphdr->from_initiator = from_initiator ? 0x1 : 0x0;
  siphdr->instance = instance;
  siphdr->proto = proto;

  sdphdr = NULL;
  if (sipend)
    {
      if (siphdr->num_content_type == 1 &&
	  strcmp(siphdr->content_type[0], "application/sdp") == 0)
	{
	  siphdr->payload_sdp = 0x1;
	  SSH_DEBUG(SSH_D_LOWOK, ("inbound SDP=%s", sipend));
	  if ((sdphdr = alg_sip_parse_sdp(sipend, &end)) == NULL)
	    {
	      errortext = "SDP payload within SIP not understood";
	      goto audit_and_free;
	    }
	  siphdr->payload.sdp.header = sdphdr;
	}
      else
	{
	  siphdr->payload_sip = 0x1;
	  siphdr->payload.sip.content_len = strlen(sipend);
	  if ((siphdr->payload.sip.content =
	       ssh_memdup(sipend,
			  siphdr->payload.sip.content_len)) == NULL)
	    siphdr->payload.sip.content_len = 0;
	}
    }

  if (newsession)
    {
      SSH_DEBUG(SSH_D_MIDOK,
		("init session: new thread %p", &session->thread));
      /* Start processing the session. */
      ssh_fsm_thread_init(&sipalg->fsm,
			  &session->thread,
			  sip_session_start,
			  NULL_FNPTR, sip_session_thread_destroy,
			  session);
    }

  if ((cp = ssh_calloc(1, sizeof(*cp))) == NULL)
    {
      errortext = "Can't allocate memory for packet processing.";
      goto audit_and_free;
    }

  cp->session = session;
  cp->siphdr = siphdr;

  SSH_DEBUG(SSH_D_MIDOK,
	    ("init packet: new thread %p", &cp->thread));
  ssh_fsm_thread_init(&sipalg->fsm,
		      &cp->thread,
		      sip_packet_start,
		      NULL_FNPTR, sip_packet_thread_destroy,
		      cp);

  ssh_free(packet);
}

/***************************************************************************
 * ALG framework functions
 */

static void
alg_sip_conn_cb(SshAppgwContext instance,
		SshAppgwAction action,
		const unsigned char *udp_data, size_t udp_data_len,
		void *context)
{
  SshAppgwSip sipalg = (SshAppgwSip) context;
  SshAppgwSipConfig config;

  switch (action)
    {
    case SSH_APPGW_REDIRECT:
      SSH_NOTREACHED;
      break;

    case SSH_APPGW_UPDATE_CONFIG:
      if ((config =
	   ssh_appgw_sip_unmarshal_config(instance->config_data,
					  instance->config_data_len))
	  != NULL)
	{
	  if (sipalg->config)
	    ssh_appgw_sip_destroy_config(sipalg->config);
	  sipalg->config = config;
	}
      else
	{
	  ssh_log_event(SSH_LOGFACILITY_DAEMON, SSH_LOG_CRITICAL,
			"service %s: internal error, could not "
			"unmarshal configuration!", instance->service_name);
	  break;
	}
      break;

    case SSH_APPGW_SHUTDOWN:
      sipalg->shutdown = 0x1;

      /* Signal all connections about termination. */
      if (ssh_adt_num_objects(sipalg->sessions) &&
	  !sipalg->shutdown_pending)
	{
	  SshADTHandle h;
	  SshAppgwSipConnection session;

	  for (h = ssh_adt_enumerate_start(sipalg->sessions);
	       h != SSH_ADT_INVALID;
	       h = ssh_adt_enumerate_next(sipalg->sessions, h))
	    {
	      session = ssh_adt_get(sipalg->sessions, h);
	      ssh_fsm_continue(&session->thread);
	    }

	  sipalg->shutdown_pending = 0x1;
	}

      /* We have no connections now, destroy directly */
      if (--sipalg->registered == 0)
	if (!sipalg->shutdown_pending)
	  alg_sip_destroy(sipalg);
      break;

    case SSH_APPGW_NEW_INSTANCE:
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("SIP connection %@.%d > %@.%d",
                 ssh_ipaddr_render, &instance->initiator_ip,
                 instance->initiator_port,
                 ssh_ipaddr_render, &instance->responder_orig_ip,
                 instance->responder_orig_port));
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Responder sees initiator as '%@.%d' and itself as '%@:%d'",
                 ssh_ipaddr_render, &instance->initiator_ip_after_nat,
                 instance->initiator_port_after_nat,
		 ssh_ipaddr_render, &instance->responder_ip_after_nat,
                 instance->responder_port_after_nat));
      break;

    case SSH_APPGW_UDP_PACKET_FROM_INITIATOR:
      alg_sip_process_packet(sipalg, instance,
			     TRUE,
			     alg_sip_packet_from_internal(sipalg,
							  TRUE, instance),
			     SSH_IPPROTO_UDP,
			     udp_data, udp_data_len);
      break;

    case SSH_APPGW_UDP_PACKET_FROM_RESPONDER:
      alg_sip_process_packet(sipalg, instance,
			     FALSE,
			     alg_sip_packet_from_internal(sipalg,
							  FALSE, instance),
			     SSH_IPPROTO_UDP,
			     udp_data, udp_data_len);
      break;

    case SSH_APPGW_FLOW_INVALID:
      break;
    }
}

static void
alg_sip_reg_cb(SshAppgwError error, void *context)
{
  SshAppgwSip sipalg = (SshAppgwSip) context;
  const char *why = "unknown appgw error";

  switch (error)
    {
    case SSH_APPGW_ERROR_OK: why = "ok"; break;
    case SSH_APPGW_ERROR_TOOMANY: why = "too many"; break;
    case SSH_APPGW_ERROR_NOTFOUND: why = "not found"; break;
    case SSH_APPGW_ERROR_VERSION: why = "invalid version"; break;
    case SSH_APPGW_ERROR_PROTOVERSION: why = "invalid protocol"; break;
    default: break;
    }

  if (error != SSH_APPGW_ERROR_OK)
    {
      ssh_log_event(SSH_LOGFACILITY_DAEMON, SSH_LOG_ERROR,
                    "%s: Can't start application gateway: "
                    "registration failed; reason %s.", SSH_APPGW_NAME, why);
      alg_sip_destroy(sipalg);
      return;
    }

  if (++sipalg->registered == sipalg->instances)
    ssh_log_event(SSH_LOGFACILITY_DAEMON, SSH_LOG_NOTICE,
		  "%s: Application gateway started.", SSH_APPGW_NAME);
}

void
ssh_appgw_sip_init(SshPm pm)
{
  SshAppgwParamsStruct params;
  SshAppgwSip sipalg;

  if ((sipalg = ssh_calloc(1, sizeof(*sipalg))) == NULL)
    {
      ssh_log_event(SSH_LOGFACILITY_DAEMON, SSH_LOG_ERROR,
                    "%s: Can't create application gateway: no space.",
                    SSH_APPGW_NAME);
      return;
    }
  sipalg->pm = pm;

  if ((sipalg->sessions =
       ssh_adt_create_generic(SSH_ADT_BAG,
			      SSH_ADT_HASH, alg_sip_session_hash,
			      SSH_ADT_COMPARE, alg_sip_session_cmp,
			      SSH_ADT_DESTROY, alg_sip_session_destroy,
			      SSH_ADT_HEADER,
			      SSH_ADT_OFFSET_OF(SshAppgwSipConnectionStruct,
						bag_header),
			      SSH_ADT_ARGS_END))
      == NULL)
    {
      ssh_log_event(SSH_LOGFACILITY_DAEMON, SSH_LOG_ERROR,
                    "%s: Can't create application gateway: no space.",
                    SSH_APPGW_NAME);
      alg_sip_destroy(sipalg);
      return;
    }




  sipalg->baseport = 38000;
  sipalg->portmap_size = 125;

  sipalg->portmap = NULL;
  sipalg->portmap_handles = NULL;
  if ((sipalg->portmap =
       ssh_calloc(1, sipalg->portmap_size * 8)) == NULL ||
      (sipalg->portmap_handles =
       ssh_calloc(1, sipalg->portmap_size * 8)) == NULL)
    {
      ssh_log_event(SSH_LOGFACILITY_DAEMON, SSH_LOG_ERROR,
                    "%s: Can't create application gateway: no space.",
                    SSH_APPGW_NAME);
      alg_sip_destroy(sipalg);
      return;
    }

  memset(&params, 0, sizeof(params));
  params.ident = SSH_APPGW_IDENT;
  params.printable_name = SSH_APPGW_NAME;
  params.version = SSH_APPGW_VERSION;
  params.flow_idle_timeout = 3600;

  sipalg->registered = 0;
  sipalg->instances = 2;
  sipalg->shutdown = 0x0;
  sipalg->shutdown_pending = 0x0;

  ssh_fsm_init(&sipalg->fsm, sipalg);

  /* Register application gateway for the protocols served. */
  params.ipproto = SSH_IPPROTO_UDP;
  params.flow_idle_timeout = 0;
  ssh_appgw_register_local(pm,
			   &params,
			   0,
			   alg_sip_conn_cb, sipalg,
			   alg_sip_reg_cb, sipalg);


  params.ipproto = SSH_IPPROTO_TCP;
  params.flow_idle_timeout = 0;
  ssh_appgw_register_local(pm,
			   &params,
			   0,
			   alg_sip_conn_cb, sipalg,
			   alg_sip_reg_cb, sipalg);
}

#endif /* SSHDIST_IPSEC_FIREWALL */
/* eof */
