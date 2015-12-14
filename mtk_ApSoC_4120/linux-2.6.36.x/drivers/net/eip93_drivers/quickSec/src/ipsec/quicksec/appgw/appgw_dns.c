/*
  File: appgw_dns.c

  Description:
        DNS application level gateway for NAT as in RFC2694.

        This ALG inspects packet formatting and if NAT is used, performs
        NAT related DNS mappings on Bi-NAT environments. Twice-NAT is
        not supported. Secure DNS is not supported.

        Private to external
        - Forward and reverse queries do not need mappings.

        External to private
        - Forward answers are changed to external NAT'd address.
        - Reverse query is modified to include internal address.
        - Reverse answer is modified to include external address again.

  Copyright:
        Copyright (c) 2002-2003, 2005 SFNT Finland Oy.
        All rights reserved
*/

#include "sshincludes.h"
#include "sshinet.h"
#include "sshtimeouts.h"
#include "sshadt.h"
#include "sshadt_bag.h"
#include "sshadt_list.h"
#include "appgw_api.h"
#include "appgw_dns.h"
#include "sshobstack.h"
#include "sshdns.h"
#include "sshdnspacket.h"

#ifdef SSHDIST_IPSEC_FIREWALL

#define SSH_DEBUG_MODULE "SshAppgwDNS"

/* Identification string. */
#define SSH_APPGW_IDENT          "alg-dns@ssh.com"
#define SSH_APPGW_NAME           "DNSALG"
#define SSH_APPGW_VERSION        2

/* Flow and operations ageing timer. */
#define SSH_APPGW_DNS_TIMER      10

/* DNS Application gateway shared.
   This is registered at the application gw framework and can be used
   to pass global data around. */
typedef struct
SshAppgwDNSRec *SshAppgwDNS, SshAppgwDNSStruct;

/* DNS Connection withing ALG.
   This is stored within instance->user_data.
   Multiple operations may be run over single connection, especially
   in the future, when we support DNS with TCP transport. */
typedef struct
SshAppgwDNSConnectionRec *SshAppgwDNSConnection, SshAppgwDNSConnectionStruct;

/* An DNSoperation within a connection. */
typedef struct
SshAppgwDNSOperationRec *SshAppgwDNSOperation, SshAppgwDNSOperationStruct;

struct SshAppgwDNSRec
{
  SshPm pm;

  SshUInt64 num_operations;
  SshUInt64 max_operations;
  SshADTContainer connections;
  unsigned int registered:1;

  SshAppgwDNSConfig config;

  SshTimeoutStruct timeout;
  SshUInt32 id;
};

struct SshAppgwDNSConnectionRec
{
  SshADTMapHeaderStruct adt_header;

  /* Type of connection, UDP, or if not, then TCP */
  unsigned int is_udp:1;

  /* Number of currently active operations over this connection */
  SshADTContainer operations;

  SshUInt32 id;
  SshAppgwContext instance; /* Back pointer to instance. */
  SshAppgwDNS dnsalg;       /* Pointer to configuration. */
};

/* An RPC operation, performed over connection. */
struct SshAppgwDNSOperationRec
{
  SshADTBagHeaderStruct adt_header;

  /* TTL, number of SSH_APPGW_DNS_TIMER second intervals we allow
     responses to this operation. */
  unsigned int ttl:16;

  /* We have done PTR mapping for query packet, and need to compensate
     on response. */
  unsigned int ptr_compensate_response:1;

  /* The connection to which this operation belongs to. */
  SshAppgwDNSConnection connection;

  /* The original query packet. */
  SshDNSPacket packet;
};


static void ssh_appgw_dns_done(SshAppgwDNSConnection conn);


/*****************************************************************************
 * Operation container management.
 */
static unsigned long appgw_dns_operation_hash(void *ptr, void *ctx)
{
  SshAppgwDNSOperation op = (SshAppgwDNSOperation) ptr;
  unsigned long request_hash = 0, i, len = 0;

  if (op->packet->question_count)
    {
      if (op->packet->question_array[0].qname)
	len = strlen(op->packet->question_array[0].qname);

      for (i = 0; i < len; i++)
	request_hash = ((request_hash << 19) ^ (request_hash >> 13)) +
	  ((unsigned char *)op->packet->question_array[0].qname)[i];
    }

  return op->packet->id ^ request_hash;
}

static int appgw_dns_operation_compare(void *ptr1, void *ptr2, void *ctx)
{
  SshAppgwDNSOperation op1 = (SshAppgwDNSOperation) ptr1;
  SshAppgwDNSOperation op2 = (SshAppgwDNSOperation) ptr2;

  if (op1->packet->id != op2->packet->id)
    return -1;

  return strcmp(op1->packet->question_array[0].qname,
                op2->packet->question_array[0].qname);
}

/* Destroy operation and possibly the connection it belongs to,
   depending if the connection is permanent by nature. */
static void appgw_dns_operation_destroy(void *ptr, void *ctx)
{
  SshAppgwDNSOperation op = (SshAppgwDNSOperation) ptr;

  op->connection->dnsalg->num_operations -= 1;

  SSH_DEBUG(SSH_D_MIDOK, ("Destroying operation (%lld left)",
                          op->connection->dnsalg->num_operations));

  /* If ssh_appgw_done() would delete the flow immediately, we should
     call it here. Now, instead we get invalid flow notifications from
     the framework, and delete it later, handling only packet cleanup
     here.

  if (op->connection->is_udp)
     ssh_appgw_dns_done(op->connection);
  */
  ssh_dns_packet_free(op->packet);
  ssh_free(op);
}


/*****************************************************************************
 * Connection container management.
 */
static unsigned long appgw_dns_connection_hash(void *ptr, void *ctx)
{
  SshAppgwDNSConnection conn = (SshAppgwDNSConnection) ptr;
  return conn->id;
}

static int appgw_dns_connection_compare(void *ptr1, void *ptr2, void *ctx)
{
  SshAppgwDNSConnection conn1 = (SshAppgwDNSConnection) ptr1;
  SshAppgwDNSConnection conn2 = (SshAppgwDNSConnection) ptr2;
  return conn1->id - conn2->id;
}

static void appgw_dns_connection_destroy(void *ptr, void *ctx)
{
  SshAppgwDNSConnection conn = (SshAppgwDNSConnection) ptr;

  ssh_appgw_done(conn->instance);
  ssh_adt_destroy(conn->operations);
  ssh_free(conn);
}

/*****************************************************************************
 * Operation timeout management.
 */

/* Timeout callback to remove DNS operations that have not completed
   within specified time. */
static void appgw_dns_operation_timeout(void *context)
{
  SshAppgwDNS dnsalg = (SshAppgwDNS) context;
  SshAppgwDNSOperation o;
  SshAppgwDNSConnection c;
  SshADTHandle ch, oh;

  for (ch = ssh_adt_enumerate_start(dnsalg->connections);
       ch != SSH_ADT_INVALID;
       ch = ssh_adt_enumerate_next(dnsalg->connections, ch))
    {
      c = ssh_adt_get(dnsalg->connections, ch);

      for (oh = ssh_adt_enumerate_start(c->operations);
           oh != SSH_ADT_INVALID;
           oh = ssh_adt_enumerate_next(c->operations, oh))
        {
          o = ssh_adt_get(c->operations, oh);
          if (o->ttl == 0)
            {
              /* Delete operation, this calls appgw_dns_operation_destroy. */
              ssh_adt_delete(c->operations, oh);
            }
          else
            {
              o->ttl -= 1;
            }
        }
    }

  (void)ssh_register_timeout(&dnsalg->timeout,
                             SSH_APPGW_DNS_TIMER, 0L,
                             appgw_dns_operation_timeout,
                             dnsalg);
}

/* Destroy connection. */
static void ssh_appgw_dns_done(SshAppgwDNSConnection conn)
{
  SshAppgwDNS dnsalg = conn->dnsalg;
  SshADTHandle handle;

  ssh_appgw_audit_event(conn->instance,
                        SSH_AUDIT_APPGW_SESSION_END,
                        SSH_AUDIT_ARGUMENT_END);

  /* Fast, due to concrete headers. */
  if ((handle = ssh_adt_get_handle_to(dnsalg->connections, conn))
      != SSH_ADT_INVALID)
    ssh_adt_delete(dnsalg->connections, handle);
}

/* Return a mallocated IP address pointer from reverse address query
   string in format of reversed bytes | ('.in-addr.arpa'|'ip6.arpa'),
   or NULL, if out of memory or address is not valid IPv4 or IPv6
   address. */
static SshIpAddr
ssh_appgw_dns_ptr_address(const char *name)
{
  char *p, res[128], buffer[128], *buf, *dot;
  SshIpAddr result;
  size_t len, i, j;

  len = strlen(name);
  if (len > sizeof(res))
    return NULL;

  memset(res, 0, sizeof(res));
  memset(buffer, 0, sizeof(buffer));
  strcat(buffer, name);

  i = (int)buffer[0];
  while (i < len)
    {
      j = buffer[i + 1];
      buffer[i + 1] = '.';
      i += (j + 1);
    }

  buf = &buffer[1];

  if ((p = strstr(buf, ".in-addr.arpa")) != NULL ||
      (p = strstr(buf, ".IN-ADDR.ARPA")) != NULL)
    {
      *p = 0;
      while ((dot = strrchr(buf, '.')) != NULL)
        {
          strncat(res, dot + 1, p - dot);
          p = dot;
          strcat(res, ".");
          *dot = '\000';
        }
      strncat(res, buf, p - buf);

      if ((result = ssh_malloc(sizeof(*result))) == NULL)
        return NULL;

      if (ssh_ipaddr_parse(result, ssh_ustr(res)))
        return result;
      else
        {
          ssh_free(result);
          return NULL;
        }
    }
  else if ((p = strstr(buf, ".ip6.arpa")) != NULL ||
           (p = strstr(buf, ".IP6.ARPA")) != NULL)
    {
      unsigned short words = 0, nibbles = 0;

      *p = 0;
      while ((dot = strrchr(buf, '.')) != NULL)
        {
          if (words == 8)
            return NULL;

          res[words * 5 + nibbles++] = *(dot + 1);
          *dot = 0;
          if (nibbles == 4)
            {
              res[words++ * 5 + 4] = ':';
              nibbles = 0;
            }
        }

      if (nibbles == 3 && words == 7)
        {
          res[words * 5 + 3] = buf[0];
          res[words * 5 + 4] = 0;
        }
      else
        res[0] = 0;

      if ((result = ssh_malloc(sizeof(*result))) == NULL)
        return NULL;

      if (ssh_ipaddr_parse(result, ssh_ustr(res)))
        return result;
      else
        {
          ssh_free(result);
          return NULL;
        }
    }
  else
    return NULL;
}

static unsigned char *
appgw_dns_make_dns_name(unsigned char *name)
{
  unsigned char *q, *p;
  size_t len;

  q = name;
  while ((p = ssh_ustrchr(q + 1, '.')) != NULL)
    {
      len = (p - q) - 1;
      if (len > 63)
	return NULL;
      *q = (char)len;
      q = p;
    }
  len = strlen((char *)q + 1);
  if (len > 63)
    return NULL;
  *q = len;

  return name;
}


/* Return a mallocated string containing reversed bytes of 'addr' |
   '.in-addr.arpa', as used on reverse query. Return NULL if run out
   of memory.  */
static char *
ssh_appgw_dns_address_ptr(SshObStackContext obstack, SshIpAddr addr)
{
  char buf[128], *p;
  int rv;

  if (SSH_IP_IS4(addr))
    {
      rv = ssh_snprintf(buf + 1 , sizeof(buf) - 1,
                        "%d.%d.%d.%d.in-addr.arpa",
                        SSH_IP4_BYTE4(addr), SSH_IP4_BYTE3(addr),
                        SSH_IP4_BYTE2(addr), SSH_IP4_BYTE1(addr));
    }
  else if (SSH_IP_IS6(addr))
    {
      int offset = 1, i;
      SshUInt16 b;

      for (rv = 0, i = 15; i != -1 && rv != -1; i--)
        {
          b = SSH_IP6_BYTEN(addr, i);
          rv = ssh_snprintf(buf + offset, sizeof(buf)- offset,
                            "%x.%x.",
                            b & 0x0f, b >> 4 & 0x0f);
          offset += 4;
        }
      if (rv != -1 && (sizeof(buf) - offset > 10))
        {
          strcat(buf, "ip6.arpa");
	  rv = offset + 8;
        }
    }
  else
    return NULL;

  if (rv == -1)
    {
      return NULL;
    }
  else
    {
      /* Terminate, rv == number of actual data bytes, 1 is leading
	 length */
      buf[rv + 2] = '\0';

      /* Convert buffer to DNS format */
      if (appgw_dns_make_dns_name(buf) == NULL)
	return  NULL;

      if ((p = ssh_obstack_alloc(obstack, rv + 2)) == NULL)
	return NULL;

      memcpy(p, buf, rv + 2);
      return p;
    }
}

/* Here data_len has been checked to be less than 2^16 */
static void
ssh_appgw_dns_call(SshAppgwDNS dnsalg,
                   SshAppgwDNSConnection conn,
                   const unsigned char *data, size_t data_len)
{
  SshDNSPacket p;
  SshAppgwDNSOperation op;
  unsigned char buf[SSH_DNS_MAX_PACKET_SIZE];
  size_t len;
  SshDNSQuestion question;
  int i;

  if ((p = ssh_dns_packet_decode(data, data_len)) == NULL)
    {
      ssh_appgw_audit_event(conn->instance,
			    SSH_AUDIT_CORRUPT_PACKET,
			    SSH_AUDIT_TXT,
			    "Broken DNS query received",
			    SSH_AUDIT_ARGUMENT_END);
      return;
    }


  /* It must be a question. */
  if (p->flags & SSH_DNS_FLAG_IS_RESPONSE)
    {
      ssh_appgw_audit_event(conn->instance,
			    SSH_AUDIT_PROTOCOL_PARSE_ERROR,
			    SSH_AUDIT_TXT,
			    "Initiator started DNS transaction with "
			    "a response packet",
			    SSH_AUDIT_ARGUMENT_END);
      ssh_dns_packet_free(p);
      return;
    }

  /* Record it */
  if (dnsalg->num_operations < dnsalg->max_operations)
    {
      if ((op = ssh_calloc(1, sizeof(*op))) == NULL)
	{
	  ssh_appgw_audit_event(conn->instance,
				SSH_AUDIT_WARNING,
				SSH_AUDIT_TXT,
				"Out of memory for operation",
				SSH_AUDIT_ARGUMENT_END);
	  ssh_dns_packet_free(p);
	  return;
	}

      dnsalg->num_operations += 1;

      op->connection = conn;
      op->packet = p;
      op->ttl = 2;
      op->ptr_compensate_response = 0;

#ifdef SSHDIST_IPSEC_NAT
      for (i = 0; i < p->question_count; i++)
	{
	  question = &p->question_array[i];

	  /* Perform external to private reverse query management. */
	  if (question->qclass == SSH_DNS_CLASS_INTERNET
	      && (question->qtype == SSH_DNS_RESOURCE_PTR
		  || question->qtype == SSH_DNS_QUERY_ANY))
	    {
	      SshIpAddr raddr, mapped;

	      raddr = ssh_appgw_dns_ptr_address(question->qname);
	      if (raddr != NULL)
		{
		  /* Map from external to internal address */
		  if ((mapped =
		       ssh_appgw_dns_static_nat_apply(dnsalg->config,
						      raddr, FALSE))
		      != NULL)
		    {
		      question->qname =
			ssh_appgw_dns_address_ptr(p->obstack, mapped);
		      op->ptr_compensate_response = 1;
		    }
		  ssh_free(raddr);
		}
	    }
	}
#endif /* SSHDIST_IPSEC_NAT */

      /* Record it AFTER we have changed the query. */
      SSH_DEBUG(SSH_D_MIDOK, ("Creating operation (%lld present)",
			      op->connection->dnsalg->num_operations));
      ssh_adt_insert(conn->operations, op);

      if ((len =
	   ssh_dns_packet_encode(p, buf, sizeof(buf)))
	  > 0)
	ssh_udp_send(conn->instance->responder_listener,
		     NULL, NULL, buf, len);
      /* Do not free the query packet, we have stored it. */
    }
  else
    {
      ssh_dns_packet_free(p);
      ssh_snprintf(buf, sizeof(buf), "Limit %llu of %llu reached",
		   dnsalg->num_operations,
		   dnsalg->max_operations);

      ssh_appgw_audit_event(conn->instance,
			    SSH_AUDIT_FLOOD,
			    SSH_AUDIT_TXT, buf,
			    SSH_AUDIT_ARGUMENT_END);
      return;
    }
}

/* Here data_len has been checked to be less than 2^16 */
static void
ssh_appgw_dns_reply(SshAppgwDNS dnsalg,
                    SshAppgwDNSConnection conn,
                    const unsigned char *data, size_t data_len)
{
  SshDNSPacket p;
  SshAppgwDNSOperation op = NULL;
  SshAppgwDNSOperationStruct ops;
  unsigned char buf[SSH_DNS_MAX_PACKET_SIZE];
  size_t len;
  SshADTHandle h;
  int i, j;
  SshDNSRecord answer;

  if ((p = ssh_dns_packet_decode(data, data_len)) == NULL)
    {
      ssh_appgw_audit_event(conn->instance,
			    SSH_AUDIT_CORRUPT_PACKET,
			    SSH_AUDIT_TXT,
			    "Broken DNS response received",
			    SSH_AUDIT_ARGUMENT_END);
      return;
    }

  /* It must be a question. */
  if (!(p->flags & SSH_DNS_FLAG_IS_RESPONSE))
    {
      ssh_dns_packet_free(p);
      ssh_appgw_audit_event(conn->instance,
			    SSH_AUDIT_PROTOCOL_PARSE_ERROR,
			    SSH_AUDIT_TXT,
			    "Responder send DNS query as response "
			    "to a query",
			    SSH_AUDIT_ARGUMENT_END);
      return;
    }

  if (p->response_code != SSH_DNS_OK)
    goto forward;

  /* We must have matching query. */
  ops.connection = conn;
  ops.packet = p;
  if ((h = ssh_adt_get_handle_to_equal(conn->operations, &ops))
      == SSH_ADT_INVALID)
    {
      ssh_dns_packet_free(p);

      ssh_appgw_audit_event(conn->instance,
			    SSH_AUDIT_PROTOCOL_PARSE_ERROR,
			    SSH_AUDIT_TXT,
			    "Received unexpected DNS answer, either not "
			    "queried or duplicate",
			    SSH_AUDIT_ARGUMENT_END);
      return;
    }

  op = ssh_adt_get(conn->operations, h);

#ifdef SSHDIST_IPSEC_NAT

  for (i = 0; i < p->answer_count; i++)
    {
      answer = &p->answer_array[i];

      /* Response for A and PTR queries */
      if ((p->flags & SSH_DNS_FLAG_IS_RESPONSE)
	  && answer->dns_class == SSH_DNS_CLASS_INTERNET)
	{
	  if (answer->type == SSH_DNS_RESOURCE_A ||
	      answer->type == SSH_DNS_RESOURCE_AAAA)
	    {
	      SshIpAddrStruct addr[1];
	      SshIpAddr mapped;

	      SSH_IP_DECODE(addr, answer->rdata, answer->rdlength);

	      SSH_DEBUG(SSH_D_MIDOK,
			("%s %s = %@",
			 (answer->type == SSH_DNS_RESOURCE_A)
			 ? "A" : "AAAA",
			 answer->name, ssh_ipaddr_render, addr));

	      /* MAP from internal to external address. */
	      if ((mapped =
		   ssh_appgw_dns_static_nat_apply(dnsalg->config,
						  addr, TRUE))
		  != NULL)
		{
		  if (SSH_IP_IS6(mapped))
		    answer->rdlength = 16;
		  else
		    answer->rdlength = 4;

		  if ((answer->rdata =
		       ssh_obstack_alloc(p->obstack, answer->rdlength))
		      == NULL)
		    {
		      ssh_dns_packet_free(p);
		      return;
		    }
		  SSH_IP_ENCODE(mapped, answer->rdata, len);
		  SSH_ASSERT(len == answer->rdlength);
		  answer->ttl = 1;
		}
	    }
	  if (answer->type == SSH_DNS_RESOURCE_PTR &&
	      op->ptr_compensate_response)
	    {
	      SshIpAddr raddr, paddr, mapped;

	      raddr = ssh_appgw_dns_ptr_address(answer->name);
	      if (raddr)
		{
		  /* Map from internal to external address. */
		  if ((mapped =
		       ssh_appgw_dns_static_nat_apply(dnsalg->config,
						      raddr, TRUE))
		      != NULL)
		    {
		      answer->name =
			ssh_appgw_dns_address_ptr(p->obstack, mapped);
		      answer->ttl = 1;

		      for (j = 0; j < p->question_count; j++)
			{
			  paddr =
			    ssh_appgw_dns_ptr_address(p->
						      question_array[j].qname);
			  if (SSH_IP_EQUAL(paddr, raddr))
			    p->question_array[j].qname =
			      ssh_appgw_dns_address_ptr(p->obstack, mapped);
			  ssh_free(paddr);
			}
		    }
		  ssh_free(raddr);
		}
	    }
	}
    }
#endif /* SSHDIST_IPSEC_NAT */

 forward:
  if ((len = ssh_dns_packet_encode(p, buf, sizeof(buf))) > 0)
    ssh_udp_send(conn->instance->initiator_listener,
		 NULL, NULL, buf, len);
  ssh_dns_packet_free(p);

  if (op)
    ssh_adt_delete_object(conn->operations, op);
}

void
ssh_appgw_dns_destroy(SshAppgwDNS dnsalg)
{
  ssh_cancel_timeout(&dnsalg->timeout);
  ssh_adt_destroy(dnsalg->connections);

  if (dnsalg->config)
    ssh_appgw_dns_destroy_config(dnsalg->config);

  if (dnsalg->registered)
    {
      SSH_DEBUG(SSH_D_HIGHSTART, ("Unregistering from firewall"));
      ssh_appgw_unregister_local(dnsalg->pm,
                                 SSH_APPGW_IDENT,
                                 SSH_APPGW_VERSION,
                                 SSH_IPPROTO_UDP);
    }
  ssh_free(dnsalg);
}

static void
ssh_appgw_dns_conn_cb(SshAppgwContext instance,
                      SshAppgwAction action,
                      const unsigned char *udp_data, size_t udp_len,
                      void *context)
{
  SshAppgwDNS dnsalg = (SshAppgwDNS) context;
  SshAppgwDNSConnection conn;
  SshAppgwDNSConfig config;

  if (action == SSH_APPGW_UDP_PACKET_FROM_INITIATOR ||
      action == SSH_APPGW_UDP_PACKET_FROM_RESPONDER)
    {
      if (udp_len > 65536)
        {
          ssh_appgw_audit_event(instance,
                                SSH_AUDIT_CORRUPT_PACKET,
                                SSH_AUDIT_TXT,
                                "Too long (over 65535 bytes) packet",
                                SSH_AUDIT_ARGUMENT_END);
          return;
        }
    }

  switch (action)
    {
    case SSH_APPGW_REDIRECT:
      SSH_NOTREACHED;
      break;

    case SSH_APPGW_UPDATE_CONFIG:
      if ((config =
           ssh_appgw_dns_unmarshal_config(instance->config_data,
                                          instance->config_data_len)) != NULL)
        {
          if (dnsalg->config)
            ssh_appgw_dns_destroy_config(dnsalg->config);
          dnsalg->config = config;
        }
      else
        ssh_log_event(SSH_LOGFACILITY_DAEMON, SSH_LOG_ERROR,
                      "%s: Received broken configuration.", SSH_APPGW_NAME);

      break;

    case SSH_APPGW_SHUTDOWN:
      ssh_log_event(SSH_LOGFACILITY_DAEMON, SSH_LOG_NOTICE,
                    "%s: Shutting down.", SSH_APPGW_NAME);

      /* Destroy the application gateway instance and we are done. */
      ssh_appgw_dns_destroy(dnsalg);
      break;

    case SSH_APPGW_NEW_INSTANCE:

      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Responder sees initiator as `%@.%d'",
                 ssh_ipaddr_render, &instance->initiator_ip_after_nat,
                 instance->initiator_port));
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Initiator sees responder as `%@.%d'",
                 ssh_ipaddr_render, &instance->responder_ip_after_nat,
                 instance->responder_port));

      if ((conn = ssh_calloc(1, sizeof(*conn))) == NULL)
        {
          ssh_appgw_audit_event(instance,
                                SSH_AUDIT_NOTICE,
                                SSH_AUDIT_TXT, "Out of memory for connection",
                                SSH_AUDIT_ARGUMENT_END);
          ssh_appgw_done(instance);
          return;
        }

      if ((conn->operations =
           ssh_adt_create_generic(
               SSH_ADT_MAP,
               SSH_ADT_HEADER,
               SSH_ADT_OFFSET_OF(SshAppgwDNSOperationStruct, adt_header),
               SSH_ADT_HASH,     appgw_dns_operation_hash,
               SSH_ADT_COMPARE,  appgw_dns_operation_compare,
               SSH_ADT_DESTROY,  appgw_dns_operation_destroy,
               SSH_ADT_ARGS_END))
          == NULL)
        {
          ssh_appgw_audit_event(instance,
                                SSH_AUDIT_NOTICE,
                                SSH_AUDIT_TXT, "Out of memory for connection",
                                SSH_AUDIT_ARGUMENT_END);
          ssh_appgw_done(instance);
          return;
        }

      conn->id = ++dnsalg->id;
      conn->instance = instance;
      conn->dnsalg = dnsalg;
      conn->is_udp = (instance->initiator_stream == NULL);

      instance->user_context = conn;


      ssh_adt_insert(dnsalg->connections, conn);

      ssh_appgw_audit_event(conn->instance,
                            SSH_AUDIT_APPGW_SESSION_START,
                            SSH_AUDIT_ARGUMENT_END);

      if (instance->initiator_stream)
        {
          /* No TCP yet */
          ssh_appgw_dns_done(conn);
        }
      break;

    case SSH_APPGW_UDP_PACKET_FROM_INITIATOR:
      ssh_appgw_dns_call(dnsalg, instance->user_context, udp_data, udp_len);
      break;

    case SSH_APPGW_UDP_PACKET_FROM_RESPONDER:
      ssh_appgw_dns_reply(dnsalg, instance->user_context, udp_data, udp_len);
      break;

    case SSH_APPGW_FLOW_INVALID:
      /* Framework destroyed flow, remove resources associated. */
      ssh_appgw_dns_done(instance->user_context);
      break;
    }
}

static void
ssh_appgw_dns_reg_cb(SshAppgwError error, void *context)
{
  SshAppgwDNS dnsalg = (SshAppgwDNS) context;
  char *why = "unknown reason";

  if (error != SSH_APPGW_ERROR_OK)
    {
      switch (error)
        {
        case SSH_APPGW_ERROR_OK: why = "ok"; break;
        case SSH_APPGW_ERROR_TOOMANY: why = "too many"; break;
        case SSH_APPGW_ERROR_NOTFOUND: why = "not found"; break;
        case SSH_APPGW_ERROR_VERSION: why = "invalid version"; break;
        case SSH_APPGW_ERROR_PROTOVERSION: why = "invalid protocol"; break;
        default: break;
        }

      ssh_log_event(SSH_LOGFACILITY_DAEMON, SSH_LOG_ERROR,
                    "%s: Can't start application gateway: "
                    "registration failed; reason %s.", SSH_APPGW_NAME, why);
      ssh_appgw_dns_destroy(dnsalg);
      return;
    }
  ssh_log_event(SSH_LOGFACILITY_DAEMON, SSH_LOG_NOTICE,
                "%s: Application gateway started.", SSH_APPGW_NAME);
  dnsalg->registered = 1;

  (void)ssh_register_timeout(&dnsalg->timeout,
                             SSH_APPGW_DNS_TIMER, 0L,
                             appgw_dns_operation_timeout,
                             dnsalg);
}

void
ssh_appgw_dns_init(SshPm pm)
{
  SshAppgwDNS dnsalg;
  SshAppgwParamsStruct params;

  if ((dnsalg = ssh_calloc(1, sizeof(*dnsalg))) == NULL)
    {
      ssh_log_event(SSH_LOGFACILITY_DAEMON, SSH_LOG_ERROR,
                    "%s: Can't create application gateway: no space.",
                    SSH_APPGW_NAME);
      return;
    }

  dnsalg->id = 1;
  dnsalg->pm = pm;
  dnsalg->max_operations = 256;

  if ((dnsalg->connections =
       ssh_adt_create_generic(SSH_ADT_MAP,
                              SSH_ADT_HEADER,
                              SSH_ADT_OFFSET_OF(SshAppgwDNSConnectionStruct,
                                                adt_header),
                              SSH_ADT_HASH,     appgw_dns_connection_hash,
                              SSH_ADT_COMPARE,  appgw_dns_connection_compare,
                              SSH_ADT_DESTROY,  appgw_dns_connection_destroy,
                              SSH_ADT_CONTEXT,  dnsalg,
                              SSH_ADT_ARGS_END))
      == NULL)
    {
      ssh_log_event(SSH_LOGFACILITY_DAEMON, SSH_LOG_ERROR,
                    "%s: Can't create application gateway: "
                    "no space for connection container.",
                    SSH_APPGW_NAME);
      ssh_free(dnsalg);
      return;
    }

  SSH_DEBUG(SSH_D_HIGHSTART, ("Registering DNS ALG to the firewall"));

  memset(&params, 0, sizeof(params));
  params.ident = SSH_APPGW_IDENT;
  params.printable_name = SSH_APPGW_NAME;
  params.version = SSH_APPGW_VERSION;
  params.ipproto = SSH_IPPROTO_UDP;
  params.flow_idle_timeout = 10;

  ssh_appgw_register_local(pm,
                           &params,
                           0,
                           ssh_appgw_dns_conn_cb, dnsalg,
                           ssh_appgw_dns_reg_cb, dnsalg);
}

#endif /* SSHDIST_IPSEC_FIREWALL */

/* eof */
