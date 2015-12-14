/*
 *
 * appgw_pass_through_tcp.c
 *
 * Copyright:
 *       Copyright (c) 2002, 2003 SFNT Finland Oy.
 *       All rights reserved.
 *
 * A sample pass-through application gateway for TCP.
 *
 */

#include "sshincludes.h"
#include "sshtimeouts.h"
#include "appgw_api.h"
#include "appgw_pass_through_tcp.h"
#include "sshfsm.h"
#include "sshencode.h"
#include "sshinetencode.h"

#ifdef SSHDIST_IPSEC_NAT
#ifdef SSHDIST_IPSEC_FIREWALL

/************************** Types and definitions ***************************/

#define SSH_DEBUG_MODULE "SshAppgwPassThroughTcp"

/* Version. */
#define SSH_APPGW_PASS_THROUGH_TCP_VERSION      1

/* The name of the application gateway as shown in syslog events. */
#define SSH_APPGW_NAME                          "Pass-through TCP ALG"

/* Configuration data object. */
struct SshAppgwPassThroughTcpConfigRec
{
  struct SshAppgwPassThroughTcpConfigRec *next;

  /* Service ID of this configuration data. */
  SshUInt32 service_id;

  /* Redirection information. */
  SshIpAddrStruct redirect_ip;
  SshUInt16 redirect_port;
};

/* An I/O structure for unidirectional communication. */
struct SshAppgwPassThroughTcpIORec
{
  /* Flags. */
  unsigned int active : 1;      /* Thread active. */
  unsigned int terminate : 1;   /* Terminate when already read data
                                   has been flushed. */

  /* Source stream. */
  SshStream src;

  /* Destination stream. */
  SshStream dst;

  /* Buffer for data being copied. */
  unsigned char buf[1024];
  size_t data_in_buf;
  size_t bufpos;

  /* Pointer to the connection structure. */
  struct SshAppgwPassThroughTcpConnRec *conn;
};

typedef struct SshAppgwPassThroughTcpIORec SshAppgwPassThroughTcpIOStruct;
typedef struct SshAppgwPassThroughTcpIORec *SshAppgwPassThroughTcpIO;

/* A TCP connection through the gateway. */
struct SshAppgwPassThroughTcpConnRec
{
  /* Link fields for list of active connections. */
  struct SshAppgwPassThroughTcpConnRec *next;
  struct SshAppgwPassThroughTcpConnRec *prev;

  /* Flags. */
  unsigned int close_on_peer_eof : 1; /* Close when EOF is seen on one
                                         direction.  Otherwise, close
                                         when both ends have seen the
                                         EOF. */

  /* The application gateway context. */
  SshAppgwContext ctx;

  /* Thread handling the initiator->responder communication. */
  SshFSMThreadStruct thread_i;
  SshAppgwPassThroughTcpIOStruct io_i;

  /* Thread handling the responder->initiator communication. */
  SshFSMThreadStruct thread_r;
  SshAppgwPassThroughTcpIOStruct io_r;

  /* Configuration data for the connection. */
  SshAppgwPassThroughTcpConfig config;
};

typedef struct SshAppgwPassThroughTcpConnRec SshAppgwPassThroughTcpConnStruct;
typedef struct SshAppgwPassThroughTcpConnRec *SshAppgwPassThroughTcpConn;

/* Context data for TCP pass-through gateways. */
struct SshAppgwPassThroughTcpCtxRec
{
  /* Policy manager. */
  SshPm pm;

  /* FSM controlling the gateway. */
  SshFSMStruct fsm;

  /* Flags. */
  unsigned int registered : 1;  /* Successfully registered with firewall. */
  unsigned int shutdown : 1;    /* The system is shutting down. */

  /* Active TCP connections through this gateway. */
  SshAppgwPassThroughTcpConn connections;

  /* Known configuration data objects. */
  SshAppgwPassThroughTcpConfig config_data;
};

typedef struct SshAppgwPassThroughTcpCtxRec SshAppgwPassThroughTcpCtxStruct;
typedef struct SshAppgwPassThroughTcpCtxRec *SshAppgwPassThroughTcpCtx;

/******************* Prototypes for static help function ********************/

/* A stream notification callback. */
static void ssh_appgw_pass_through_tcp_stream_cb(
                                        SshStreamNotification notification,
                                        void *context);

/* A timeout function to terminate the TCP pass-through connection
   `context'. */
static void ssh_appgw_pass_through_tcp_connection_terminate(void *context);

/* Check if the system is shutting down and if so, unregister and
   destroy the application gateway instance. */
static void ssh_appgw_pass_through_tcp_check_shutdown(
                                                SshAppgwPassThroughTcpCtx ctx);

/* Destroy and optionally unregister TCP pass-through application
   gateway instance `ctx'. */
static void ssh_appgw_pass_through_tcp_destroy(SshAppgwPassThroughTcpCtx ctx);


/********************** Prototypes for state functions **********************/

SSH_FSM_STEP(ssh_appgw_pass_through_tcp_st_wait_input);
SSH_FSM_STEP(ssh_appgw_pass_through_tcp_st_write_data);
SSH_FSM_STEP(ssh_appgw_pass_through_tcp_st_terminate);


/***************************** State functions ******************************/

SSH_FSM_STEP(ssh_appgw_pass_through_tcp_st_wait_input)
{
  SshAppgwPassThroughTcpCtx tcp_ctx = (SshAppgwPassThroughTcpCtx) fsm_context;
  SshAppgwPassThroughTcpIO io = (SshAppgwPassThroughTcpIO) thread_context;
  int read;

  SSH_DEBUG(SSH_D_LOWOK,("entering wait_input state"));

  /* Check if the system is shutting down. */
  if (tcp_ctx->shutdown)
    {
      /** System shutting down. */
      SSH_DEBUG(SSH_D_LOWOK,("shutting down connection"));
      SSH_FSM_SET_NEXT(ssh_appgw_pass_through_tcp_st_terminate);
      return SSH_FSM_CONTINUE;
    }

  /* Read some data. */
  read = ssh_stream_read(io->src, io->buf, sizeof(io->buf));

  if (read < 0)
    {
      /* We would block.  Check if we should terminate. */
      if (io->terminate)
        {
          /** Connection closed. */
          SSH_DEBUG(SSH_D_LOWOK,("shutting down connection"));
          SSH_FSM_SET_NEXT(ssh_appgw_pass_through_tcp_st_terminate);
          return SSH_FSM_CONTINUE;
        }

      /* Wait for more input. */
      return SSH_FSM_SUSPENDED;
    }
  else if (read == 0)
    {
      /** EOF. */
      /* Signal that we won't write any more data. */
      SSH_DEBUG(SSH_D_LOWOK,("connection terminating"));
      ssh_stream_output_eof(io->dst);
      SSH_FSM_SET_NEXT(ssh_appgw_pass_through_tcp_st_terminate);
    }
  else
    {
      /** Data read. */
      SSH_DEBUG_HEXDUMP(SSH_D_LOWOK,
                        ("Read %d bytes:", read),
                        io->buf, read);
      io->data_in_buf = read;
      SSH_FSM_SET_NEXT(ssh_appgw_pass_through_tcp_st_write_data);
    }

  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_appgw_pass_through_tcp_st_write_data)
{
  SshAppgwPassThroughTcpCtx tcp_ctx = (SshAppgwPassThroughTcpCtx) fsm_context;
  SshAppgwPassThroughTcpIO io = (SshAppgwPassThroughTcpIO) thread_context;
  int wrote;

  SSH_DEBUG(SSH_D_LOWOK,("entering write_data state"));

  SSH_ASSERT(io->data_in_buf);
  SSH_ASSERT(io->bufpos < io->data_in_buf);

  /* First, check if the system is shutting down. */
  if (tcp_ctx->shutdown)
    {
      /** System shutting down. */
      SSH_DEBUG(SSH_D_LOWOK,("shutting down connection"));
      SSH_FSM_SET_NEXT(ssh_appgw_pass_through_tcp_st_terminate);
      return SSH_FSM_CONTINUE;
    }

  /* Write as much as possible. */
  while (io->bufpos < io->data_in_buf)
    {
      wrote = ssh_stream_write(io->dst, io->buf + io->bufpos,
                               io->data_in_buf - io->bufpos);
      if (wrote < 0)
        {
          /* We would block.  Wait until we can write more data. */
          return SSH_FSM_SUSPENDED;
        }
      else if (wrote == 0)
        {
          /** Write failed. */
          SSH_DEBUG(SSH_D_LOWOK,("write failed.. pipe closed"));
          SSH_FSM_SET_NEXT(ssh_appgw_pass_through_tcp_st_terminate);
          return SSH_FSM_CONTINUE;
        }
      else
        {
          io->bufpos += wrote;
        }
    }

  SSH_ASSERT(io->bufpos >= io->data_in_buf);
  io->bufpos = 0;
  io->data_in_buf = 0;

  /** Data written. */
  SSH_FSM_SET_NEXT(ssh_appgw_pass_through_tcp_st_wait_input);
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_appgw_pass_through_tcp_st_terminate)
{
  SshAppgwPassThroughTcpIO io = (SshAppgwPassThroughTcpIO) thread_context;
  SshAppgwPassThroughTcpConn conn = io->conn;

  SSH_DEBUG(SSH_D_LOWOK,("entering terminate state"));

  /* This thread is finished. */
  io->active = 0;

  /* Check if we were the last thread in the connection. */
  if (!conn->io_i.active && !conn->io_r.active)
    {
      /* Yes we were.  Let's register a timeout to destroy the
         connection object. */
      ssh_xregister_timeout(0, 0,
                           ssh_appgw_pass_through_tcp_connection_terminate,
                           conn);
    }
  else
    {
      /* No we are not.  Check the close strategy. */
      if (conn->close_on_peer_eof)
        {
          /* Close when EOF is seen on one direction.  Let's notify
             our peer. */
          conn->io_i.terminate = 1;
          conn->io_r.terminate = 1;

          /* Be lazy and just call the stream callback. */
          ssh_appgw_pass_through_tcp_stream_cb(SSH_STREAM_INPUT_AVAILABLE,
                                               conn);
        }
      else
        {
          /* Wait until both ends see EOF.  Nothing here. */
        }
    }

  /* Terminate this thread. */
  return SSH_FSM_FINISH;
}


/************************ Initializing with firewall ************************/

static void
ssh_appgw_pass_through_tcp_conn_cb(SshAppgwContext ctx,
                                   SshAppgwAction action,
                                   const unsigned char *udp_data,
                                   size_t udp_len,
                                   void *context)
{
  SshAppgwPassThroughTcpCtx tcp_ctx = (SshAppgwPassThroughTcpCtx) context;
  SshAppgwPassThroughTcpConn conn;
  SshAppgwPassThroughTcpConfig config;
  SshAppgwPassThroughTcpConfig c;

  switch (action)
    {
    case SSH_APPGW_REDIRECT:
      /* Lookup configuration data. */
      for (config = tcp_ctx->config_data; config; config = config->next)
        if (config->service_id == ctx->service_id)
          {
            SshIpAddrStruct ip = ctx->responder_ip;
            SshUInt16 port = ctx->responder_port;

            if (SSH_IP_DEFINED(&config->redirect_ip))
              ip = config->redirect_ip;
            if (config->redirect_port)
              port = config->redirect_port;

            ssh_appgw_redirect(ctx, &ip, port);
            return;
          }

      /* No redirection. */
      ssh_appgw_redirect(ctx, &ctx->responder_ip, ctx->responder_port);
      break;

    case SSH_APPGW_UPDATE_CONFIG:
      SSH_DEBUG_HEXDUMP(SSH_D_NICETOKNOW,
                        ("New configuration data for service %u:",
                         (unsigned int) ctx->service_id),
                        ctx->config_data, ctx->config_data_len);

      /* Unmarshal configuration data. */
      config
        = ssh_appgw_pass_through_tcp_config_unmarshal(ctx->config_data,
                                                      ctx->config_data_len);
      if (config == NULL)
        {
          ssh_appgw_audit_event(ctx, SSH_AUDIT_WARNING,
                                SSH_AUDIT_TXT,
                                "Could not decode configuration data",
                                SSH_AUDIT_ARGUMENT_END);
          ssh_log_event(SSH_LOGFACILITY_DAEMON, SSH_LOG_ERROR,
                        "%s: Could not decode configuration data "
                        "for service %u",
                        SSH_APPGW_NAME,
			(unsigned int) ctx->service_id);
          return;
        }

      /* Store service ID. */
      config->service_id = ctx->service_id;

      /* Do we already know this service ID? */
      for (c = tcp_ctx->config_data; c; c = c->next)
        if (c->service_id == config->service_id)
          {
            /* Steal new attributes from the new config object. */
            config->next = c->next;
            memcpy(c, config, sizeof(*config));

            /* Clear new fields so they won't get freed when the
               object is freed. */
            memset(config, 0, sizeof(*config));
            ssh_appgw_pass_through_tcp_config_destroy(config);
            return;
          }

      /* Configuration data for a new service object. */
      config->next = tcp_ctx->config_data;
      tcp_ctx->config_data = config;
      break;

    case SSH_APPGW_SHUTDOWN:
      tcp_ctx->shutdown = 1;

      if (tcp_ctx->connections)
        {
          /* We have active connections so let's notify them about the
              shutdown.  They will terminate after they receive the
              notification. */
          for (conn = tcp_ctx->connections; conn; conn = conn->next)
            {
              ssh_fsm_continue(&conn->thread_i);
              ssh_fsm_continue(&conn->thread_r);
            }
        }
      else
        {
          /* Shutdown immediately. */
          ssh_appgw_pass_through_tcp_destroy(tcp_ctx);
        }
      break;

    case SSH_APPGW_NEW_INSTANCE:
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("New TCP pass-through connection %@.%d > %@.%d",
                 ssh_ipaddr_render, &ctx->initiator_ip,
                 ctx->initiator_port,
                 ssh_ipaddr_render, &ctx->responder_ip,
                 ctx->responder_port));
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Responder sees initiator as `%@.%d'",
                 ssh_ipaddr_render, &ctx->initiator_ip_after_nat,
                 ctx->initiator_port));
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Initiator sees responder as `%@.%d'",
                 ssh_ipaddr_render, &ctx->responder_ip_after_nat,
                 ctx->responder_port));

      /* Lookup its configuration data. */
      for (config = tcp_ctx->config_data; config; config = config->next)
        if (config->service_id == ctx->service_id)
          break;

      if (config == NULL)
        {
          ssh_appgw_audit_event(ctx,
                                SSH_AUDIT_WARNING,
                                SSH_AUDIT_TXT,
                                "No configuration data specified for "
                                "this service.",
                                SSH_AUDIT_ARGUMENT_END);
          ssh_appgw_done(ctx);
          return;
        }

      /* Create a new connection. */
      conn = ssh_calloc(1, sizeof(*conn));
      if (conn == NULL)
        {
          SSH_DEBUG(SSH_D_ERROR,
                    ("Could not allocate TCP pass-through connection"));
          ssh_appgw_done(ctx);
          return;
        }

      /* Link connection to the gateway's list of active
         connections. */
      conn->next = tcp_ctx->connections;
      if (tcp_ctx->connections)
        tcp_ctx->connections->prev = conn;
      tcp_ctx->connections = conn;

      /* Store application level gateway framework's context. */
      conn->ctx = ctx;

      /* Store configuration data. */
      conn->config = config;

      /* Store application gateway context into SshAppgwContext's
         `user_context'. */
      ctx->user_context = tcp_ctx;

      /* Set stream callbacks. */
      ssh_stream_set_callback(conn->ctx->initiator_stream,
                              ssh_appgw_pass_through_tcp_stream_cb, conn);
      ssh_stream_set_callback(conn->ctx->responder_stream,
                              ssh_appgw_pass_through_tcp_stream_cb, conn);

      /* Setup I/O threads. */

      conn->io_i.active = 1;
      conn->io_i.src = conn->ctx->initiator_stream;
      conn->io_i.dst = conn->ctx->responder_stream;
      conn->io_i.conn = conn;

      ssh_fsm_thread_init(&tcp_ctx->fsm, &conn->thread_i,
                          ssh_appgw_pass_through_tcp_st_wait_input,
                          NULL_FNPTR, NULL_FNPTR,
                          &conn->io_i);

      conn->io_r.active = 1;
      conn->io_r.src = conn->ctx->responder_stream;
      conn->io_r.dst = conn->ctx->initiator_stream;
      conn->io_r.conn = conn;

      ssh_fsm_thread_init(&tcp_ctx->fsm, &conn->thread_r,
                          ssh_appgw_pass_through_tcp_st_wait_input,
                          NULL_FNPTR, NULL_FNPTR,
                          &conn->io_r);
      break;

    case SSH_APPGW_UDP_PACKET_FROM_INITIATOR:
    case SSH_APPGW_UDP_PACKET_FROM_RESPONDER:
      SSH_NOTREACHED;
      break;

    case SSH_APPGW_FLOW_INVALID:
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Flow invalid"));
      break;
    }
}

static void
ssh_appgw_pass_through_tcp_stream_cb(SshStreamNotification notification,
                                     void *context)
{
  SshAppgwPassThroughTcpConn conn = (SshAppgwPassThroughTcpConn) context;

  /* Simply continue all active threads. */
  if (conn->io_i.active)
    ssh_fsm_continue(&conn->thread_i);
  if (conn->io_r.active)
    ssh_fsm_continue(&conn->thread_r);
}

static void
ssh_appgw_pass_through_tcp_connection_terminate(void *context)
{
  SshAppgwPassThroughTcpConn conn = (SshAppgwPassThroughTcpConn) context;
  SshAppgwPassThroughTcpCtx tcp_ctx;

  /* Get application gateway context. */
  tcp_ctx = (SshAppgwPassThroughTcpCtx) conn->ctx->user_context;
  conn->ctx->user_context = NULL;

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("TCP pass-through connection %@.%d > %@.%d terminated",
             ssh_ipaddr_render, &conn->ctx->initiator_ip,
             conn->ctx->initiator_port,
             ssh_ipaddr_render, &conn->ctx->responder_ip,
             conn->ctx->responder_port));

  ssh_stream_set_callback(conn->ctx->initiator_stream, NULL_FNPTR, NULL);
  ssh_stream_set_callback(conn->ctx->responder_stream, NULL_FNPTR, NULL);

  ssh_appgw_done(conn->ctx);

  /* Remove us from the application gateway's list of connections. */

  if (conn->next)
    conn->next->prev = conn->prev;

  if (conn->prev)
    conn->prev->next = conn->next;
  else
    tcp_ctx->connections = conn->next;

  /* Free our connection structure. */
  ssh_free(conn);

  /* And check if the system is shutting down. */
  ssh_appgw_pass_through_tcp_check_shutdown(tcp_ctx);
}

static void
ssh_appgw_pass_through_tcp_check_shutdown(SshAppgwPassThroughTcpCtx ctx)
{
  if (ctx->shutdown && ctx->connections == NULL)
    /* The system is shutting down and this was the last connection.
       Let's shutdown this application gateway. */
    ssh_appgw_pass_through_tcp_destroy(ctx);
}

static void
ssh_appgw_pass_through_tcp_destroy_cb(void *context)
{
  SshAppgwPassThroughTcpCtx ctx = (SshAppgwPassThroughTcpCtx) context;

  ssh_fsm_uninit(&ctx->fsm);

  if (ctx->registered)
    {
      ssh_log_event(SSH_LOGFACILITY_DAEMON, SSH_LOG_NOTICE,
                    "%s: Shutting down.", SSH_APPGW_NAME);
      ssh_appgw_unregister_local(ctx->pm,
                                 SSH_APPGW_PASS_THROUGH_TCP_IDENT,
                                 SSH_APPGW_PASS_THROUGH_TCP_VERSION,
                                 SSH_IPPROTO_TCP);
    }

  /* Free all config data objects. */
  while (ctx->config_data)
    {
      SshAppgwPassThroughTcpConfig c = ctx->config_data;

      ctx->config_data = c->next;
      ssh_appgw_pass_through_tcp_config_destroy(c);
    }

  ssh_free(ctx);
}

static void
ssh_appgw_pass_through_tcp_destroy(SshAppgwPassThroughTcpCtx ctx)
{
  /* Register a zero-timeout to destroy the application gateway
     instance.  This is needed since this function is called also from
     thread destructors and the FSM library needs to access the FSM
     context that will be destroyed when the context is freed. */
  ssh_xregister_timeout(0, 0, ssh_appgw_pass_through_tcp_destroy_cb, ctx);
}

static void
ssh_appgw_pass_through_tcp_reg_cb(SshAppgwError error, void *context)
{
  SshAppgwPassThroughTcpCtx ctx = (SshAppgwPassThroughTcpCtx) context;

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
                    "%s: Could not start application gateway: "
                    "registration failed: %s",
                    SSH_APPGW_NAME, why);
      ssh_appgw_pass_through_tcp_destroy(ctx);
      return;
    }

  ssh_log_event(SSH_LOGFACILITY_DAEMON, SSH_LOG_NOTICE,
                "%s: Application gateway started.", SSH_APPGW_NAME);
  ctx->registered = 1;
}


void
ssh_appgw_pass_through_tcp_init(SshPm pm)
{
  SshAppgwPassThroughTcpCtx ctx;
  SshAppgwParamsStruct params;

  ctx = ssh_calloc(1, sizeof(*ctx));
  if (ctx == NULL)
    {
      ssh_log_event(SSH_LOGFACILITY_DAEMON, SSH_LOG_ERROR,
                    "%s: Could not create application gateway: out of memory.",
                    SSH_APPGW_NAME);
      return;
    }
  ctx->pm = pm;
  ssh_fsm_init(&ctx->fsm, ctx);

  SSH_DEBUG(SSH_D_HIGHSTART, ("Registering to firewall"));

  memset(&params,0,sizeof(params));
  params.ident = SSH_APPGW_PASS_THROUGH_TCP_IDENT;
  params.printable_name =  "Pass-through TCP";
  params.version = SSH_APPGW_PASS_THROUGH_TCP_VERSION;
  params.ipproto = SSH_IPPROTO_TCP;


  ssh_appgw_register_local(ctx->pm,
                           &params,
                           SSH_APPGW_F_REDIRECT,
                           ssh_appgw_pass_through_tcp_conn_cb, ctx,
                           ssh_appgw_pass_through_tcp_reg_cb, ctx);
}


/*********************** Handling configuration data ************************/

SshAppgwPassThroughTcpConfig
ssh_appgw_pass_through_tcp_config_create(void)
{
  SshAppgwPassThroughTcpConfig config;

  config = ssh_calloc(1, sizeof(*config));

  return config;
}


void
ssh_appgw_pass_through_tcp_config_destroy(SshAppgwPassThroughTcpConfig config)
{
  if (config == NULL)
    return;

  ssh_free(config);
}


Boolean
ssh_appgw_pass_through_tcp_config_redirect(SshAppgwPassThroughTcpConfig config,
                                           const unsigned char *address,
                                           const unsigned char *port)
{
  if (address)
    {
      if (!ssh_ipaddr_parse(&config->redirect_ip, address))
        return FALSE;
    }

  if (port)
    {
      config->redirect_port = ssh_uatoi(port);
      if (config->redirect_port == 0)
        return FALSE;
    }

  return TRUE;
}


unsigned char *
ssh_appgw_pass_through_tcp_config_marshal(SshAppgwPassThroughTcpConfig config,
                                          size_t *data_len_return)
{
  unsigned char ip_buf[SSH_MAX_IPADDR_ENCODED_LENGTH];
  size_t ip_len;
  unsigned char *data;

  /* Encode redirect address. */
  ip_len = ssh_encode_ipaddr_array(ip_buf, sizeof(ip_buf),
                                   &config->redirect_ip);

  /* Encode config data. */
  *data_len_return = ssh_encode_array_alloc(
                        &data,
                        SSH_FORMAT_UINT32_STR, ip_buf, ip_len,
                        SSH_FORMAT_UINT32, (SshUInt32) config->redirect_port,
                        SSH_FORMAT_END);
  if (*data_len_return == 0)
    return NULL;

  return data;
}


SshAppgwPassThroughTcpConfig
ssh_appgw_pass_through_tcp_config_unmarshal(const unsigned char *data,
                                            size_t data_len)
{
  SshAppgwPassThroughTcpConfig config;
  const unsigned char *redirect_ip;
  size_t redirect_ip_len;
  SshUInt32 redirect_port;

  /* Allocate a config object. */
  config = ssh_appgw_pass_through_tcp_config_create();
  if (config == NULL)
    goto error;

  if (data_len)
    {
      if (ssh_decode_array(data, data_len,
                           SSH_FORMAT_UINT32_STR_NOCOPY,
                           &redirect_ip, &redirect_ip_len,

                           SSH_FORMAT_UINT32, &redirect_port,
                           SSH_FORMAT_END) != data_len)
        goto error;

      /* Store configuration data. */

      ssh_decode_ipaddr_array(redirect_ip, redirect_ip_len,
                              &config->redirect_ip);
      config->redirect_port = redirect_port;
    }

  /* All done. */
  return config;


  /* Error handling. */

 error:

  ssh_appgw_pass_through_tcp_config_destroy(config);

  return NULL;
}

#endif /* SSHDIST_IPSEC_FIREWALL */
#endif /* SSHDIST_IPSEC_NAT */
