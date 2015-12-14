/*
 *
 * appgw_wins.c
 *
 * Copyright:
 *       Copyright (c) 2002, 2003 SFNT Finland Oy.
 *       All rights reserved.
 *
 * Application level gateway for NetBIOS Name Services and WINS.
 *
 * References:
 *
 *   RFC 1001  PROTOCOL STANDARD FOR A NetBIOS SERVICE ON A TCP/UDP TRANSPORT:
 *             CONCEPTS AND METHODS
 *   RFC 1002  PROTOCOL STANDARD FOR A NetBIOS SERVICE ON A TCP/UDP TRANSPORT:
 *             DETAILED SPECIFICATIONS
 *
 */

#include "sshincludes.h"
#include "sshinet.h"
#include "sshtimeouts.h"
#include "sshgetput.h"
#include "sshadt.h"
#include "sshadt_bag.h"
#include "appgw_api.h"
#include "appgw_wins_internal.h"


#ifdef SSHDIST_IPSEC_NAT
#ifdef SSHDIST_IPSEC_FIREWALL

/************************** Types and definitions ***************************/

#define SSH_DEBUG_MODULE "SshAppgwWINS"

/* Identification string. */
#define SSH_APPGW_IDENT           "alg-wins@ssh.com"
#define SSH_APPGW_NAME            "WINSALG"
#define SSH_APPGW_VERSION         1

/* Flow and operations ageing timer. */
#define SSH_APPGW_WINS_TIMER      10

/* Number of timer ticks a flow is kept alive if it does not receive
   any packets. When the flow receives packets, it will get this
   much lifetime. */
#define SSH_APPGW_WINS_KEEPALIVE  (8/*hours*/*60/*minutes*/*6/*ticks*/)

/* Number of timer ticks an operation is kept alive if we don't receive
   response from name server */
#define SSH_APPGW_OPERATION_TTL   2

/* A NetBIOS Name Service / WINS connection. */
struct SshAppgwWINSConnectionRec
{
  /* Link fields for list of active connections. */
  struct SshAppgwWINSConnectionRec *next;
  struct SshAppgwWINSConnectionRec *prev;

  /* An unique ID for this connection. */
  SshUInt32 unique_id;

  /* TTL, number of SSH_APPGW_WINS_TIMER second intervals this flow is
     kept alive.  */
  SshUInt16 ttl;

  /* Currently active operations. */
  SshUInt32 num_operations;

  /* Total number of operations. */
  SshUInt64 total_operations;

  /* The application gateway context. */
  SshAppgwContext instance;

  /* Application gateway instance context. */
  struct SshAppgwWINSCtxRec *wins_alg;
};

typedef struct SshAppgwWINSConnectionRec SshAppgwWINSConnectionStruct;
typedef struct SshAppgwWINSConnectionRec *SshAppgwWINSConnection;


/* Context data for NetBIOS Datagram Service application gateways. */
struct SshAppgwWINSCtxRec
{
  /* Policy manager. */
  SshPm pm;

  /* Active operations. */
  SshADTContainer operations;
  SshUInt64 num_operations;
  SshUInt64 max_operations;

  SshTimeoutStruct timeout;

  /* Flags. */
  unsigned int registered : 1;  /* Successfully registered with firewall. */

  /* Next unique ID for connections. */
  SshUInt32 next_unique_id;

  /* Active connections. */
  SshAppgwWINSConnection connections;
};

typedef struct SshAppgwWINSCtxRec SshAppgwWINSCtxStruct;
typedef struct SshAppgwWINSCtxRec *SshAppgwWINSCtx;


/* A WINS operation. */
struct SshAppgwWINSOperationRec
{
  SshADTBagHeaderStruct adt_header;

  /* TTL, number of SSH_APPGW_WINS_TIMER second intervals we allow
     responses to this operation. */
  SshUInt16 ttl;

  /* The connection to which this operation belongs to. */
  SshAppgwWINSConnection connection;

  /* Decoded packet */
  SshWINSPacket packet;

  /* Encoded packed */
  SshBufferStruct encoded_packet;
};

typedef struct SshAppgwWINSOperationRec SshAppgwWINSOperationStruct;
typedef struct SshAppgwWINSOperationRec *SshAppgwWINSOperation;


/************************** Static help functions ***************************/

static void ssh_appgw_wins_done(SshAppgwWINSConnection conn);

/************************ ADT bag for WINS operations ***********************/

static SshUInt32
ssh_appgw_wins_operation_hash(void *ptr, void *ctx)
{
  SshAppgwWINSOperation op = (SshAppgwWINSOperation) ptr;

  return op->connection->unique_id ^ op->packet->header.xid;
}


static int
ssh_appgw_wins_operation_compare(void *ptr1, void *ptr2, void *ctx)
{
  SshAppgwWINSOperation op1 = (SshAppgwWINSOperation) ptr1;
  SshAppgwWINSOperation op2 = (SshAppgwWINSOperation) ptr2;

  if (op1->connection->unique_id != op2->connection->unique_id)
    return -1;

  if (op1->packet->header.xid != op2->packet->header.xid)
    return -1;

  return 0;
}


static void
ssh_appgw_wins_operation_destroy(void *ptr, void *ctx)
{
  SshAppgwWINSOperation op = (SshAppgwWINSOperation) ptr;

  op->connection->wins_alg->num_operations -= 1;
  op->connection->num_operations -= 1;

  SSH_DEBUG(SSH_D_MIDOK, ("Destroying operation (%lld left)",
                          op->connection->wins_alg->num_operations));

  ssh_buffer_uninit(&(op->encoded_packet));
  ssh_wins_packet_free(op->packet);
  ssh_free(op);
}


static void
ssh_appgw_wins_send_to_responder(SshAppgwWINSConnection conn,
                                 SshBuffer buf)
{
  conn->ttl = SSH_APPGW_WINS_KEEPALIVE;

  SSH_DEBUG_HEXDUMP(SSH_D_DATADUMP, ("WINS datagram:"),
                    ssh_buffer_ptr(buf), ssh_buffer_len(buf));

  ssh_udp_send(conn->instance->responder_listener, NULL, NULL,
               ssh_buffer_ptr(buf), ssh_buffer_len(buf));
}


static void
ssh_appgw_wins_call(SshAppgwWINSCtx wins_alg,
                    SshAppgwWINSConnection conn,
                    const unsigned char *data,
                    size_t data_len)
{
  SshAppgwWINSOperationStruct ops;
  SshWINSPacketStruct packet;
  SshWINSPacket p = &packet;
  SshADTHandle h;

  SSH_DEBUG_HEXDUMP(SSH_D_DATADUMP,
                    ("Original WINS datagram:"), data, data_len);

  if (ssh_wins_header_decode(&(p->header), data,
                             (SshUInt16)data_len) == FALSE)
    goto broken_wins_call;

  /* Check whether this is a re-sending */
  ops.connection = conn;
  ops.packet = p;

  h = ssh_adt_get_handle_to_equal(wins_alg->operations, &ops);
  if (h != SSH_ADT_INVALID)
    {
      SshAppgwWINSOperation op = ssh_adt_get(wins_alg->operations, h);

      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Retransmit of xid 0x%04X", p->header.xid));

      ssh_appgw_wins_send_to_responder(conn, &op->encoded_packet);
      return;
    }

  /* This is a new request */
  p = ssh_wins_packet_allocate();
  if (p == NULL)
    goto wins_call_out_of_memory;

  /* Copy the already decoded WINS header and decode only the
     appended records */
  p->header = packet.header;
  ssh_wins_packet_decode(p, data, (SshUInt16)data_len, FALSE);

  /* Is it OK? */
  if (p->header.flags & SSH_WINS_FLAG_BROKEN)
    {
      ssh_wins_packet_free(p);
      goto broken_wins_call;
    }

  /* It must be a request. */
  if (p->header.flags & SSH_WINS_FLAG_IS_RESPONSE)
    {
      ssh_wins_packet_free(p);
      ssh_appgw_audit_event(conn->instance,
                            SSH_AUDIT_PROTOCOL_PARSE_ERROR,
                            SSH_AUDIT_TXT,
                            "Unexpected WINS received from initiator.",
                            SSH_AUDIT_ARGUMENT_END);
      return;
    }

  /* We don't forward any NetBIOS broadcast packets */
  if (p->header.flags & SSH_WINS_FLAG_BROADCAST)
    {
      ssh_wins_packet_free(p);
      SSH_DEBUG(SSH_D_MIDSTART, ("- Broadcast datagram -> dropped!"));
      return;
    }

  conn->total_operations += 1;

  if (wins_alg->num_operations < wins_alg->max_operations)
    {
      SshAppgwWINSOperation op;

      op = ssh_calloc(1, sizeof(*op));
      if (op == NULL)
        {
          ssh_wins_packet_free(p);
          goto wins_call_out_of_memory;
        }

      wins_alg->num_operations += 1;
      conn->num_operations += 1;

      op->connection = conn;
      op->packet = p;
      op->ttl = SSH_APPGW_OPERATION_TTL;








      /* Record it AFTER we have changed the query. */
      SSH_DEBUG(SSH_D_MIDOK, ("Creating operation (%lld present)",
                              wins_alg->num_operations));
      ssh_buffer_init(&(op->encoded_packet));
      if (ssh_wins_packet_encode(p, &(op->encoded_packet)))
        {
          ssh_appgw_wins_send_to_responder(conn, &(op->encoded_packet));
          ssh_adt_insert(wins_alg->operations, op);
        }
      else
        ssh_appgw_wins_operation_destroy(op, wins_alg);
      return;
    }
  else
    {
      ssh_wins_packet_free(p);
      ssh_appgw_audit_event(conn->instance,
                            SSH_AUDIT_WARNING,
                            SSH_AUDIT_TXT,
                            "Resource limit reached. WINS operation dropped.",
                            SSH_AUDIT_ARGUMENT_END);
      return;
    }

  /* error logging: */
broken_wins_call:

  ssh_appgw_audit_event(conn->instance,
                        SSH_AUDIT_PROTOCOL_PARSE_ERROR,
                        SSH_AUDIT_TXT,
                        "Broken WINS packet received from initiator.",
                        SSH_AUDIT_ARGUMENT_END);
  return;

wins_call_out_of_memory:

  ssh_appgw_audit_event(conn->instance,
                        SSH_AUDIT_WARNING,
                        SSH_AUDIT_TXT,
                        "Running low on memory. WINS operation dropped.",
                        SSH_AUDIT_ARGUMENT_END);
  return;
}


static void
ssh_appgw_wins_reply(SshAppgwWINSCtx wins_alg,
                     SshAppgwWINSConnection conn,
                     const unsigned char *data, size_t data_len)
{
  SshWINSPacket p;

  SSH_DEBUG_HEXDUMP(SSH_D_DATADUMP,
                    ("Original WINS datagram:"), data, data_len);

  p = ssh_wins_packet_allocate();
  if (p != NULL)
    {
      SshBufferStruct buf;
      SshAppgwWINSOperation op;
      SshAppgwWINSOperationStruct ops;
      SshADTHandle h;

      ssh_wins_packet_decode(p, data, (SshUInt16)data_len, TRUE);

      /* Is it OK? */
      if (p->header.flags & SSH_WINS_FLAG_BROKEN)
        {
          ssh_wins_packet_free(p);
          ssh_appgw_audit_event(conn->instance,
                                SSH_AUDIT_PROTOCOL_PARSE_ERROR,
                                SSH_AUDIT_TXT,
                                "Broken WINS packet received from responder.",
                                SSH_AUDIT_ARGUMENT_END);
          return;
        }

      /* It must be a response. */
      if (!(p->header.flags & SSH_WINS_FLAG_IS_RESPONSE))
        {
          ssh_wins_packet_free(p);
          ssh_appgw_audit_event(conn->instance,
                                SSH_AUDIT_PROTOCOL_PARSE_ERROR,
                                SSH_AUDIT_TXT,
                                "Unexpected WINS packet received from "
                                "responder.",
                                SSH_AUDIT_ARGUMENT_END);
          return;
        }

      /* We must have matching query. */
      ops.connection = conn;
      ops.packet = p;

      h = ssh_adt_get_handle_to_equal(wins_alg->operations, &ops);
      if (h == SSH_ADT_INVALID)
        {
          ssh_wins_packet_free(p);
          ssh_appgw_audit_event(conn->instance,
                                SSH_AUDIT_PROTOCOL_PARSE_ERROR,
                                SSH_AUDIT_TXT,
                                "Received an unexpected WINS answer.",
                                SSH_AUDIT_ARGUMENT_END);
          return;
        }

      op = ssh_adt_get(wins_alg->operations, h);








      ssh_buffer_init(&buf);
      if (ssh_wins_packet_encode(p, &buf))
        {
          SSH_DEBUG_HEXDUMP(SSH_D_DATADUMP, ("WINS datagram:"),
                            ssh_buffer_ptr(&buf), ssh_buffer_len(&buf));

          ssh_udp_send(conn->instance->initiator_listener, NULL, NULL,
                       ssh_buffer_ptr(&buf), ssh_buffer_len(&buf));
        }
      ssh_buffer_uninit(&buf);

      if (p->header.op_code == SSH_WINS_WACK)
        {
          SshUInt16 new_ttl;

          SSH_ASSERT(p->answer != NULL);

          /* Recalculate new timeout... */
          new_ttl = p->answer->ttl / SSH_APPGW_WINS_TIMER;

          if (new_ttl > SSH_APPGW_OPERATION_TTL)
            op->ttl = new_ttl;
        }
      else
        {
          ssh_adt_delete_object(wins_alg->operations, op);
        }

      /* We don't need the reply packet any more */
      ssh_wins_packet_free(p);
    }
  else
    {
      ssh_appgw_audit_event(conn->instance,
                            SSH_AUDIT_WARNING,
                            SSH_AUDIT_TXT,
                            "Running low on memory. WINS response dropped.",
                            SSH_AUDIT_ARGUMENT_END);
    }
}


static void ssh_appgw_wins_operation_timeout(void *context)
{
  SshAppgwWINSCtx wins_alg = (SshAppgwWINSCtx) context;
  SshADTHandle h, hnext;

  for (h = ssh_adt_enumerate_start(wins_alg->operations);
       h != SSH_ADT_INVALID;
       h = hnext)
    {
      SshAppgwWINSOperation op;

      op = ssh_adt_get(wins_alg->operations, h);

      hnext = ssh_adt_enumerate_next(wins_alg->operations, h);

      if (op->ttl > 0)
        op->ttl--;
      else
        ssh_adt_delete(wins_alg->operations, h);
    }

  ssh_register_timeout(&(wins_alg->timeout), SSH_APPGW_WINS_TIMER, 0L,
                       ssh_appgw_wins_operation_timeout, wins_alg);
}


static void ssh_appgw_wins_done(SshAppgwWINSConnection conn)
{
  SshAppgwWINSCtx wins_alg = (SshAppgwWINSCtx) conn->wins_alg;
  SshAppgwWINSConnection p, prev;
  SshADTHandle h, hnext;

  /* Delete pending operations */
  for (h = ssh_adt_enumerate_start(wins_alg->operations);
       h != SSH_ADT_INVALID;
       h = hnext)
    {
      SshAppgwWINSOperation op;

      op = ssh_adt_get(wins_alg->operations, h);

      hnext = ssh_adt_enumerate_next(wins_alg->operations, h);

      if (op->connection == conn)
        ssh_adt_delete(wins_alg->operations, h);
    }

  prev = p = wins_alg->connections;
  while (p)
    {
      if (p == conn)
        {
          SSH_DEBUG(SSH_D_MIDOK, ("Destroying connection %p", conn));
          if (p == wins_alg->connections)
            {
              wins_alg->connections = wins_alg->connections->next;
              if (wins_alg->connections)
                wins_alg->connections->prev = NULL;
            }
          else
            {
              prev->next = p->next;
              if (prev->next)
                prev->next->prev = prev;
            }
          break;
        }
      prev = p;
      p = p->next;
    }

  ssh_appgw_done(conn->instance);
  ssh_free(conn);
}


/************************ Initializing with firewall ************************/

static void
ssh_appgw_wins_destroy(SshAppgwWINSCtx wins_alg)
{
  ssh_cancel_timeouts(ssh_appgw_wins_operation_timeout, wins_alg);

  /* Free all connections. */
  while (wins_alg->connections)
    {
      SshAppgwWINSConnection conn = wins_alg->connections;

      wins_alg->connections = conn->next;
      ssh_appgw_wins_done(conn->instance->user_context);
    }

  ssh_adt_destroy(wins_alg->operations);

  if (wins_alg->registered)
    {
      SSH_DEBUG(SSH_D_HIGHSTART, ("Unregistering from firewall"));
      ssh_appgw_unregister_local(wins_alg->pm,
                                 SSH_APPGW_IDENT,
                                 SSH_APPGW_VERSION,
                                 SSH_IPPROTO_UDP);
    }

  ssh_free(wins_alg);
}


static void
ssh_appgw_wins_conn_cb(SshAppgwContext instance,
                       SshAppgwAction action,
                       const unsigned char *udp_data,
                       size_t udp_len,
                       void *context)
{
  SshAppgwWINSCtx wins_alg = (SshAppgwWINSCtx) context;
  SshAppgwWINSConnection conn;

  if (action == SSH_APPGW_UDP_PACKET_FROM_INITIATOR ||
      action == SSH_APPGW_UDP_PACKET_FROM_RESPONDER)
    {
      if (udp_len > 65536)
        {
          ssh_appgw_audit_event(instance,
                                SSH_AUDIT_PROTOCOL_PARSE_ERROR,
                                SSH_AUDIT_TXT,
                                (action == SSH_APPGW_UDP_PACKET_FROM_RESPONDER
                                 ? "Too long WINS packet received from "
                                   "responder"
                                 : "Too long WINS packet received from "
                                 "initiator"),
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
      SSH_DEBUG_HEXDUMP(SSH_D_NICETOKNOW,
                        ("New configuration data for service %u:",
                         (unsigned int) instance->service_id),
                        instance->config_data, instance->config_data_len);
      break;

    case SSH_APPGW_SHUTDOWN:
      ssh_log_event(SSH_LOGFACILITY_DAEMON, SSH_LOG_NOTICE,
                    "%s: Shutting down.", SSH_APPGW_NAME);

      /* Destroy the application gateway instance. */
      ssh_appgw_wins_destroy(wins_alg);

      /* All done. */
      break;

    case SSH_APPGW_NEW_INSTANCE:
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("New NBNS/WINS connection %@.%d > %@.%d",
                 ssh_ipaddr_render, &instance->initiator_ip,
                 instance->initiator_port,
                 ssh_ipaddr_render, &instance->responder_ip,
                 instance->responder_port));
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Responder sees initiator as `%@.%d'",
                 ssh_ipaddr_render, &instance->initiator_ip_after_nat,
                 instance->initiator_port));
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Initiator sees responder as `%@.%d'",
                 ssh_ipaddr_render, &instance->responder_ip_after_nat,
                 instance->responder_port));

      conn = ssh_calloc(1, sizeof(*conn));
      if (conn == NULL)
        {
          ssh_appgw_audit_event(conn->instance,
                                SSH_AUDIT_WARNING,
                                SSH_AUDIT_TXT,
                                "Can't serve connection; reason: no space.",
                                SSH_AUDIT_ARGUMENT_END);

          ssh_log_event(SSH_LOGFACILITY_DAEMON, SSH_LOG_INFORMATIONAL,
                        "%s: Can't serve connection; reason: no space.",
                        SSH_APPGW_NAME);
          ssh_appgw_done(instance);
          return;
        }

      /* Link it to the gateway's list of active connections. */
      conn->next = wins_alg->connections;
      if (wins_alg->connections)
        wins_alg->connections->prev = conn;
      wins_alg->connections = conn;

      conn->instance = instance;
      conn->wins_alg = wins_alg;
      instance->user_context = conn;

      conn->unique_id = wins_alg->next_unique_id++;

      conn->ttl = SSH_APPGW_WINS_KEEPALIVE;
      conn->num_operations = 0;
      conn->total_operations = 0;
      break;

    case SSH_APPGW_UDP_PACKET_FROM_INITIATOR:
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Packet from initiator"));
      ssh_appgw_wins_call(wins_alg, instance->user_context,
                          udp_data, udp_len);
      break;

    case SSH_APPGW_UDP_PACKET_FROM_RESPONDER:
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Packet from responder"));
      ssh_appgw_wins_reply(wins_alg, instance->user_context,
                           udp_data, udp_len);
      break;

    case SSH_APPGW_FLOW_INVALID:
      /* Framework destroyed flow, remove resources associated. */
      ssh_appgw_wins_done(instance->user_context);
      break;
    }
}


static void
ssh_appgw_wins_reg_cb(SshAppgwError error, void *context)
{
  SshAppgwWINSCtx wins_alg = (SshAppgwWINSCtx) context;

  if (error != SSH_APPGW_ERROR_OK)
    {
      char *why;

      switch (error)
        {
        case SSH_APPGW_ERROR_OK:
          why = "ok";
          break;

        case SSH_APPGW_ERROR_TOOMANY:
          why = "too many";
          break;

        case SSH_APPGW_ERROR_NOTFOUND:
          why = "not found";
          break;

        case SSH_APPGW_ERROR_VERSION:
          why = "invalid version";
          break;

        case SSH_APPGW_ERROR_PROTOVERSION:
          why = "invalid protocol version";
          break;

        default:
          why = "unknown reason";
          break;
        }

      ssh_log_event(SSH_LOGFACILITY_DAEMON, SSH_LOG_ERROR,
                    "%s: Can't start application gateway: "
                    "registration failed; reason %s.", SSH_APPGW_NAME, why);
      ssh_appgw_wins_destroy(wins_alg);
      return;
    }

  ssh_log_event(SSH_LOGFACILITY_DAEMON, SSH_LOG_NOTICE,
                "%s: Application gateway started.", SSH_APPGW_NAME);
  wins_alg->registered = 1;

  ssh_register_timeout(&(wins_alg->timeout), SSH_APPGW_WINS_TIMER, 0L,
                       ssh_appgw_wins_operation_timeout, wins_alg);
}


void
ssh_appgw_wins_init(SshPm pm)
{
  SshAppgwWINSCtx wins_alg;
  SshAppgwParamsStruct params;

  wins_alg = ssh_calloc(1, sizeof(*wins_alg));
  if (wins_alg == NULL)
    {
      ssh_log_event(SSH_LOGFACILITY_DAEMON, SSH_LOG_ERROR,
                    "%s: Can't create application gateway: no space.",
                    SSH_APPGW_NAME);
      return;
    }

  wins_alg->pm = pm;
  wins_alg->max_operations = 1000;
  wins_alg->next_unique_id = 1;

  wins_alg->operations =
    ssh_adt_create_generic(SSH_ADT_BAG,
                           SSH_ADT_HEADER,
                           SSH_ADT_OFFSET_OF(SshAppgwWINSOperationStruct,
                                             adt_header),
                           SSH_ADT_HASH,    ssh_appgw_wins_operation_hash,
                           SSH_ADT_COMPARE, ssh_appgw_wins_operation_compare,
                           SSH_ADT_DESTROY, ssh_appgw_wins_operation_destroy,
                           SSH_ADT_CONTEXT, wins_alg,
                           SSH_ADT_ARGS_END);

  if (wins_alg->operations == NULL)
    {
      ssh_log_event(SSH_LOGFACILITY_DAEMON, SSH_LOG_ERROR,
                    "%s: Can't create application gateway: "
                    "no space for operation container.",
                    SSH_APPGW_NAME);
      ssh_free(wins_alg);
      return;
    }

  SSH_DEBUG(SSH_D_HIGHSTART, ("Registering to firewall"));

  memset(&params,0,sizeof(params));
  params.ident = SSH_APPGW_IDENT;
  params.printable_name = "NetBIOS Name Service / WINS";
  params.version = SSH_APPGW_VERSION;
  params.ipproto = SSH_IPPROTO_UDP;
  params.flow_idle_timeout = 10;

  ssh_appgw_register_local(pm,
                           &params,
                           0,
                           ssh_appgw_wins_conn_cb, wins_alg,
                           ssh_appgw_wins_reg_cb, wins_alg);
}


#endif /* SSHDIST_IPSEC_FIREWALL */
#endif /* SSHDIST_IPSEC_NAT */
