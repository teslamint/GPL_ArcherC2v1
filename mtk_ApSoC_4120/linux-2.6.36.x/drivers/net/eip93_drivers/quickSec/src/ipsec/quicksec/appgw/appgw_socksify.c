/*
 *
 * appgw_socksify.c
 *
 * Copyright:
 *       Copyright (c) 2002, 2003 SFNT Finland Oy.
 *       All rights reserved.
 *
 * Application gateway that wraps TCP connections into SOCKSv4
 * protocol and redirects them through a SOCKS server.
 *
 */

/* TODO:

   - Full support for SOCKS5
   - User-name & password
*/

#include "sshincludes.h"
#include "sshtimeouts.h"
#include "sshfsm.h"
#include "appgw_api.h"
#include "sshsocks.h"
#include "appgw_socksify.h"
#include "sshencode.h"
#include "sshinetencode.h"

#ifdef SSHDIST_IPSEC_NAT
#ifdef SSHDIST_IPSEC_FIREWALL

/************************** Types and definitions ***************************/

#define SSH_DEBUG_MODULE "SshAppgwSocksify"

/* Version. */
#define SSH_APPGW_SOCKSIFY_VERSION      1

/* The name of the application gateway as shown in syslog events. */
#define SSH_APPGW_NAME                  "SOCKSIFYALG"

/* Configuration data object. */
struct SshAppgwSocksifyConfigRec
{
  struct SshAppgwSocksifyConfigRec *next;

  /* Service ID of this configuration data. */
  SshUInt32 service_id;

  /* Information about SOCKS server. */

  SshIpAddrStruct server_ip;
  SshUInt16 server_port;
  SshUInt32 version;

  unsigned char *user_name;
  size_t user_name_len;

  unsigned char *password;
  size_t password_len;

  /* IP address and port to connet to. */
  SshIpAddrStruct connect_ip;
  SshUInt16 connect_port;
};

/* A context structure for the I/O threads. */
struct SshAppgwSocksifyIOCtxRec
{
  /* Flags. */
  unsigned int valid : 1;         /* Thread valid. */
  unsigned int blocked_input : 1; /* Blocked in input wait. */
  unsigned int failed : 1;        /* Failed. */

  unsigned char buffer[1024];
  size_t data_in_buf;
  size_t bufpos;

  size_t input_treshold;

  SshStream i_stream;
  SshStream o_stream;
  SshFSMThreadStruct thread;

  SshFSMThread master;
};

typedef struct SshAppgwSocksifyIOCtxRec SshAppgwSocksifyIOCtxStruct;
typedef struct SshAppgwSocksifyIOCtxRec *SshAppgwSocksifyIOCtx;

/* A connection to be SOCKSified. */
struct SshAppgwSocksifyConnRec
{
  /* Link fields for list of active connections. */
  struct SshAppgwSocksifyConnRec *next;
  struct SshAppgwSocksifyConnRec *prev;

  /* An FSM thread handling this connection. */
  SshFSMThreadStruct thread;

  /* An application gateway context. */
  SshAppgwContext ctx;

  /* I/O threads. */
  SshAppgwSocksifyIOCtxStruct client_to_server;
  SshAppgwSocksifyIOCtxStruct server_to_client;

  /* Configuration data for the connection. */
  SshAppgwSocksifyConfig config;
};

typedef struct SshAppgwSocksifyConnRec SshAppgwSocksifyConnStruct;
typedef struct SshAppgwSocksifyConnRec *SshAppgwSocksifyConn;

/* Context data for socksify application gateways. */
struct SshAppgwSocksifyCtxRec
{
  /* Policy manager. */
  SshPm pm;

  /* FSM controlling the gateway. */
  SshFSMStruct fsm;

  /* Flags. */
  unsigned int registered : 1;  /* Successfully registered with firewall. */
  unsigned int shutdown : 1;    /* The system is shutting down. */

  /* Active connections. */
  SshAppgwSocksifyConn connections;

  /* Known configuration data objects. */
  SshAppgwSocksifyConfig config_data;
};

typedef struct SshAppgwSocksifyCtxRec SshAppgwSocksifyCtxStruct;
typedef struct SshAppgwSocksifyCtxRec *SshAppgwSocksifyCtx;

/******************* Prototypes for static help functions *******************/

/* Destroy and optionally unregister socksify application gateway
   instance `ctx'. */
static void ssh_appgw_socksify_destroy(SshAppgwSocksifyCtx ctx);


/********************** Prototypes for state functions **********************/

SSH_FSM_STEP(ssh_appgw_socksify_st_io_read);
SSH_FSM_STEP(ssh_appgw_socksify_st_io_write);
SSH_FSM_STEP(ssh_appgw_socksify_st_io_error);
SSH_FSM_STEP(ssh_appgw_socksify_st_io_terminate);

SSH_FSM_STEP(ssh_appgw_socksify_st_main);


/***************************** State functions ******************************/

SSH_FSM_STEP(ssh_appgw_socksify_st_io_read)
{
  SshAppgwSocksifyIOCtx io = (SshAppgwSocksifyIOCtx) thread_context;
  int read;

  while (io->data_in_buf - io->bufpos < io->input_treshold)
    {
      io->blocked_input = 0;
      read = ssh_stream_read(io->i_stream,
                             io->buffer + io->data_in_buf,
                             sizeof(io->buffer) - io->data_in_buf);
      if (read < 0)
        {
          io->blocked_input = 1;
          return SSH_FSM_SUSPENDED;
        }
      else if (read == 0)
        {
          if (io->input_treshold > 1)
            /* Premature EOF. */
            SSH_FSM_SET_NEXT(ssh_appgw_socksify_st_io_error);
          else
            /* Normal EOF. */
            SSH_FSM_SET_NEXT(ssh_appgw_socksify_st_io_terminate);

          return SSH_FSM_CONTINUE;
        }
      else
        {
          io->data_in_buf += read;
        }
    }

  SSH_ASSERT(io->data_in_buf - io->bufpos >= io->input_treshold);

  if (io->input_treshold > 1)
    {
      unsigned char *cp;

      /* Reading SOCKS reply. */
      cp = io->buffer + io->bufpos;

      if (cp[0] != 0)
        {
          SSH_DEBUG(SSH_D_ERROR, ("Unsupported SOCKS version"));
          SSH_FSM_SET_NEXT(ssh_appgw_socksify_st_io_error);
          return SSH_FSM_CONTINUE;
        }

      if (cp[1] != SSH_SOCKS4_REPLY_GRANTED)
        {
          SSH_DEBUG(SSH_D_ERROR, ("SOCKS server reported error %d",
                                  (int) cp[1]));
          SSH_FSM_SET_NEXT(ssh_appgw_socksify_st_io_error);
          return SSH_FSM_CONTINUE;
        }

      /* We ignore binding info. */

      /* SOCKS reply consumed. */
      io->bufpos += io->input_treshold;

      if (io->bufpos >= io->data_in_buf)
        {
          io->bufpos = 0;
          io->data_in_buf = 0;
        }

      /* After this, we accept whatever comes from the stream. */
      io->input_treshold = 1;

      /* And restart this state. */
      return SSH_FSM_CONTINUE;
    }

  SSH_FSM_SET_NEXT(ssh_appgw_socksify_st_io_write);
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_appgw_socksify_st_io_write)
{
  SshAppgwSocksifyIOCtx io = (SshAppgwSocksifyIOCtx) thread_context;
  int wrote;

  while (io->bufpos < io->data_in_buf)
    {
      wrote = ssh_stream_write(io->o_stream, io->buffer + io->bufpos,
                               io->data_in_buf - io->bufpos);
      if (wrote < 0)
        {
          return SSH_FSM_SUSPENDED;
        }
      else if (wrote == 0)
        {
          SSH_FSM_SET_NEXT(ssh_appgw_socksify_st_io_error);
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

  SSH_FSM_SET_NEXT(ssh_appgw_socksify_st_io_read);
  return SSH_FSM_CONTINUE;
}


SSH_FSM_STEP(ssh_appgw_socksify_st_io_error)
{
  SshAppgwSocksifyIOCtx io = (SshAppgwSocksifyIOCtx) thread_context;

  io->failed = 1;
  SSH_FSM_SET_NEXT(ssh_appgw_socksify_st_io_terminate);

  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_appgw_socksify_st_io_terminate)
{
  SshAppgwSocksifyIOCtx io = (SshAppgwSocksifyIOCtx) thread_context;

  io->valid = 0;
  ssh_fsm_continue(io->master);

  return SSH_FSM_FINISH;
}


SSH_FSM_STEP(ssh_appgw_socksify_st_main)
{
  SshAppgwSocksifyCtx socks_ctx = (SshAppgwSocksifyCtx) fsm_context;
  SshAppgwSocksifyConn conn = (SshAppgwSocksifyConn) thread_context;

  if (!socks_ctx->shutdown)
    {
      if (conn->client_to_server.failed || conn->server_to_client.failed)
        {
          /* One thread failed. */
          SSH_DEBUG(SSH_D_NICETOKNOW, ("IO thread failed"));
        }
      else if (conn->client_to_server.valid && conn->server_to_client.valid)
        {
          /* Both threads active. */
          return SSH_FSM_SUSPENDED;
        }
      else if ((conn->client_to_server.valid
                && !conn->client_to_server.blocked_input)
               || (conn->server_to_client.valid
                   && !conn->server_to_client.blocked_input))
        {
          /* One thread active and it is not waiting for more input. */
          return SSH_FSM_SUSPENDED;
        }
    }

  /* Kill possible active threads. */
  if (conn->client_to_server.valid)
    {
      ssh_fsm_kill_thread(&conn->client_to_server.thread);
      conn->client_to_server.valid = 0;
    }
  if (conn->server_to_client.valid)
    {
      ssh_fsm_kill_thread(&conn->server_to_client.thread);
      conn->server_to_client.valid = 0;
    }

  /* All done. */

  SSH_ASSERT(!conn->client_to_server.valid);
  SSH_ASSERT(!conn->server_to_client.valid);

  return SSH_FSM_FINISH;
}


/************************ Initializing with firewall ************************/

static void
ssh_appgw_socksify_thread_destructor(SshFSM fsm, void *context)
{
  SshAppgwSocksifyCtx socks_ctx = ssh_fsm_get_gdata_fsm(fsm);
  SshAppgwSocksifyConn conn = (SshAppgwSocksifyConn) context;

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("Connection %@.%d > %@.%d terminated",
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
    socks_ctx->connections = conn->next;

  if (socks_ctx->shutdown && socks_ctx->connections == NULL)
    /* The system is shutting down and this was the last connection.
       Let's shutdown this application gateway. */
    ssh_appgw_socksify_destroy(socks_ctx);

  /* And free our connection structure. */
  ssh_free(conn);
}

static void
ssh_appgw_socksify_stream_cb(SshStreamNotification notification, void *context)
{
  SshAppgwSocksifyConn conn = (SshAppgwSocksifyConn) context;

  if (conn->client_to_server.valid)
    ssh_fsm_continue(&conn->client_to_server.thread);

  if (conn->server_to_client.valid)
    ssh_fsm_continue(&conn->server_to_client.thread);
}

static void
ssh_appgw_socksify_conn_cb(SshAppgwContext ctx,
                           SshAppgwAction action,
                           const unsigned char *udp_data,
                           size_t udp_len,
                           void *context)
{
  SshAppgwSocksifyCtx socks_ctx = (SshAppgwSocksifyCtx) context;
  SshAppgwSocksifyConn conn;
  unsigned char *cp;
  size_t len, ip_len;
  SshAppgwSocksifyConfig config;
  SshAppgwSocksifyConfig c;
  unsigned char ip_buf[32];
  unsigned char int_buf1[4];
  unsigned char int_buf2[4];

  switch (action)
    {
    case SSH_APPGW_REDIRECT:
      /* Lookup configuration data. */
      for (config = socks_ctx->config_data; config; config = config->next)
        if (config->service_id == ctx->service_id)
          {
            ssh_appgw_redirect(ctx, &config->server_ip, config->server_port);
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
      config = ssh_appgw_socksify_config_unmarshal(ctx->config_data,
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
      for (c = socks_ctx->config_data; c; c = c->next)
        if (c->service_id == config->service_id)
          {
            /* Free dynamically allocated fields from the old
               config. */
            ssh_free(c->user_name);
            ssh_free(c->password);

            /* Steal new attributes from the new config object. */
            config->next = c->next;
            memcpy(c, config, sizeof(*config));

            /* Clear new fields so they won't get freed when the
               object is freed. */
            memset(config, 0, sizeof(*config));
            ssh_appgw_socksify_config_destroy(config);
            return;
          }

      /* Configuration data for a new service object. */
      config->next = socks_ctx->config_data;
      socks_ctx->config_data = config;
      break;

    case SSH_APPGW_SHUTDOWN:
      socks_ctx->shutdown = 1;

      if (socks_ctx->connections)
        {
          /* Notify all connections about shutdown. */
          for (conn = socks_ctx->connections; conn; conn = conn->next)
            ssh_fsm_continue(&conn->thread);
        }
      else
        {
          /* Shutdown immediately. */
          ssh_appgw_socksify_destroy(socks_ctx);
        }
      break;

    case SSH_APPGW_NEW_INSTANCE:
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("New connection %@.%d > %@.%d",
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
      for (config = socks_ctx->config_data; config; config = config->next)
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

      conn = ssh_calloc(1, sizeof(*conn));
      if (conn == NULL)
        {
          ssh_appgw_audit_event(ctx,
                                SSH_AUDIT_WARNING,
                                SSH_AUDIT_TXT,
                                "Could not allocate context for connection",
                                SSH_AUDIT_ARGUMENT_END);
          ssh_appgw_done(ctx);
          return;
        }

      SSH_IP_ENCODE(&config->server_ip, ip_buf, ip_len);
      SSH_PUT_16BIT(int_buf1, config->server_port);
      SSH_PUT_32BIT(int_buf2, config->version);

      ssh_appgw_audit_event(ctx,
                            SSH_AUDIT_APPGW_SESSION_START,
                            SSH_AUDIT_SOCKS_VERSION, int_buf2, 4,
                            SSH_AUDIT_SOCKS_SERVER_IP, ip_buf, ip_len,
                            SSH_AUDIT_SOCKS_SERVER_PORT, int_buf1, 2,
                            SSH_AUDIT_USERNAME, config->user_name,
                            SSH_AUDIT_ARGUMENT_END);









      if (SSH_IP_DEFINED(&config->connect_ip) || config->connect_port)
        {
          SSH_IP_ENCODE(SSH_IP_DEFINED(&config->connect_ip)
                        ? &config->connect_ip
                        : &ctx->responder_orig_ip,
                        ip_buf, ip_len);

          SSH_PUT_16BIT(int_buf1, config->connect_port
                        ? config->connect_port
                        : ctx->responder_orig_port);

          ssh_appgw_audit_event(ctx,
                                SSH_AUDIT_NOTICE,
                                SSH_AUDIT_TXT,
                                "Redirecting connection",
                                SSH_AUDIT_TARGET_IP, ip_buf, ip_len,
                                SSH_AUDIT_TARGET_PORT, int_buf1, 2,
                                SSH_AUDIT_ARGUMENT_END);

        }

      /* Link it to the gateway's list of active connections. */
      conn->next = socks_ctx->connections;
      if (socks_ctx->connections)
        socks_ctx->connections->prev = conn;
      socks_ctx->connections = conn;

      conn->ctx = ctx;
      conn->config = config;

      conn->client_to_server.valid = 1;
      conn->client_to_server.i_stream = conn->ctx->initiator_stream;
      conn->client_to_server.o_stream = conn->ctx->responder_stream;
      conn->client_to_server.master = &conn->thread;

      conn->server_to_client.valid = 1;
      conn->server_to_client.i_stream = conn->ctx->responder_stream;
      conn->server_to_client.o_stream = conn->ctx->initiator_stream;
      conn->server_to_client.master = &conn->thread;

      /* Start an auxiliary thread for the server->client
         communication.  Its initial task is to process SOCKS server
         reply. */
      conn->server_to_client.input_treshold = 8;
      ssh_fsm_thread_init(&socks_ctx->fsm, &conn->server_to_client.thread,
                          ssh_appgw_socksify_st_io_read, NULL_FNPTR,
                          NULL_FNPTR, &conn->server_to_client);

      /* Start another auxiliary thread to handle the client->server
         communication.  Its initial task is to send a SOCKS connect
         request. */

      cp = conn->client_to_server.buffer;

      /* Version. */
      *cp++ = conn->config->version;

      /* Command. */
      *cp++ = SSH_SOCKS4_COMMAND_CODE_CONNECT;

      /* Port. */
      if (conn->config->connect_port)
        /* Use the port from the configuration data. */
        SSH_PUT_16BIT(cp, conn->config->connect_port);
      else
        SSH_PUT_16BIT(cp, conn->ctx->responder_orig_port);
      cp += 2;

      /* Address. */
      if (SSH_IP_DEFINED(&conn->config->connect_ip))
        SSH_IP_ENCODE(&conn->config->connect_ip, cp, len);
      else
        SSH_IP_ENCODE(&conn->ctx->responder_orig_ip, cp, len);
      cp += len;

      /* User name. */
      *cp++ = '\0';

      conn->client_to_server.data_in_buf = cp - conn->client_to_server.buffer;
      conn->client_to_server.input_treshold = 1;

      ssh_fsm_thread_init(&socks_ctx->fsm, &conn->client_to_server.thread,
                          ssh_appgw_socksify_st_io_write, NULL_FNPTR,
                          NULL_FNPTR, &conn->client_to_server);

      /* Set stream callbacks. */
      ssh_stream_set_callback(conn->ctx->initiator_stream,
                              ssh_appgw_socksify_stream_cb, conn);
      ssh_stream_set_callback(conn->ctx->responder_stream,
                              ssh_appgw_socksify_stream_cb, conn);

      /* And finally, start a main thread that waits for the auxiliary
         threads and handles the final cleanup. */
      ssh_fsm_thread_init(&socks_ctx->fsm, &conn->thread,
                          ssh_appgw_socksify_st_main, NULL_FNPTR,
                          ssh_appgw_socksify_thread_destructor, conn);
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
ssh_appgw_socksify_destroy_cb(void *context)
{
  SshAppgwSocksifyCtx ctx = (SshAppgwSocksifyCtx) context;

  ssh_fsm_uninit(&ctx->fsm);

  if (ctx->registered)
    {
      ssh_log_event(SSH_LOGFACILITY_DAEMON, SSH_LOG_NOTICE,
                    "%s: Shutting down.", SSH_APPGW_NAME);
      ssh_appgw_unregister_local(ctx->pm,
                                 SSH_APPGW_SOCKSIFY_IDENT,
                                 SSH_APPGW_SOCKSIFY_VERSION,
                                 SSH_IPPROTO_TCP);
    }

  /* Free all config data objects. */
  while (ctx->config_data)
    {
      SshAppgwSocksifyConfig c = ctx->config_data;

      ctx->config_data = c->next;
      ssh_appgw_socksify_config_destroy(c);
    }

  ssh_free(ctx);
}

static void
ssh_appgw_socksify_destroy(SshAppgwSocksifyCtx ctx)
{
  /* Register a zero-timeout to destroy the application gateway
     instance.  This is needed since this function is called also from
     thread destructors and the FSM library needs to access the FSM
     context that will be destroyed when the context is freed. */
  ssh_xregister_timeout(0, 0, ssh_appgw_socksify_destroy_cb, ctx);
}

static void
ssh_appgw_socksify_reg_cb(SshAppgwError error, void *context)
{
  SshAppgwSocksifyCtx ctx = (SshAppgwSocksifyCtx) context;

  if (error != SSH_APPGW_ERROR_OK)
    {
      char *why = "unknown reason";

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

	case SSH_APPGW_ERROR_FAILED:
	  why = "internal error";
	  break;
        }
      ssh_log_event(SSH_LOGFACILITY_DAEMON, SSH_LOG_ERROR,
                    "%s: Could not start application gateway: "
                    "registration failed: %s",
                    SSH_APPGW_NAME, why);
      ssh_appgw_socksify_destroy(ctx);
      return;
    }

  ssh_log_event(SSH_LOGFACILITY_DAEMON, SSH_LOG_NOTICE,
                "%s: Application gateway started.", SSH_APPGW_NAME);
  ctx->registered = 1;
}

void
ssh_appgw_socksify_init(SshPm pm)
{
  SshAppgwSocksifyCtx ctx;
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
  params.ident = SSH_APPGW_SOCKSIFY_IDENT;
  params.printable_name = "SOCKS Wrapper";
  params.version = SSH_APPGW_SOCKSIFY_VERSION;
  params.ipproto = SSH_IPPROTO_TCP;

  ssh_appgw_register_local(ctx->pm,
                           &params,
                           SSH_APPGW_F_REDIRECT,
                           ssh_appgw_socksify_conn_cb, ctx,
                           ssh_appgw_socksify_reg_cb, ctx);
}


/*********************** Handling configuration data ************************/

SshAppgwSocksifyConfig
ssh_appgw_socksify_config_create(void)
{
  SshAppgwSocksifyConfig config;

  config = ssh_calloc(1, sizeof(*config));

  return config;
}


void
ssh_appgw_socksify_config_destroy(SshAppgwSocksifyConfig config)
{
  if (config == NULL)
    return;

  ssh_free(config->user_name);
  ssh_free(config->password);
  ssh_free(config);
}


Boolean
ssh_appgw_socksify_config_server(SshAppgwSocksifyConfig config,
                                 const unsigned char *address,
                                 const unsigned char *port,
                                 const unsigned char *version,
                                 const unsigned char *user_name,
                                 size_t user_name_len,
                                 const unsigned char *password,
                                 size_t password_len)
{
  if (SSH_IP_DEFINED(&config->server_ip))
    /* Configuration already set. */
    return FALSE;

  if (!ssh_ipaddr_parse(&config->server_ip, address))
    return FALSE;

  config->server_port = ssh_uatoi(port);
  if (config->server_port == 0)
    return FALSE;

  config->version = ssh_uatoi(version);
  if (config->version != 4 && config->version != 5)
    return FALSE;

  if (user_name)
    {
      config->user_name = ssh_memdup(user_name, user_name_len);
      if (config->user_name == NULL)
        return FALSE;

      config->user_name_len = user_name_len;
    }

  if (password)
    {
      config->password = ssh_memdup(password, password_len);
      if (config->password == NULL)
        return FALSE;

      config->password_len = password_len;
    }

  return TRUE;
}


Boolean
ssh_appgw_socksify_config_destination(SshAppgwSocksifyConfig config,
                                      const unsigned char *address,
                                      const unsigned char *port)
{
  if (!ssh_ipaddr_parse(&config->connect_ip, address))
    return FALSE;

  if (port)
    {
      config->connect_port = ssh_uatoi(port);
      if (config->connect_port == 0)
        return FALSE;
    }

  return TRUE;
}


unsigned char *
ssh_appgw_socksify_config_marshal(SshAppgwSocksifyConfig config,
                                  size_t *data_len_return)
{
  unsigned char server_ip_buf[SSH_MAX_IPADDR_ENCODED_LENGTH];
  size_t server_ip_len;
  unsigned char connect_ip_buf[SSH_MAX_IPADDR_ENCODED_LENGTH];
  size_t connect_ip_len;
  unsigned char *data;

  /* Encode addresses. */
  server_ip_len = ssh_encode_ipaddr_array(server_ip_buf,
                                          sizeof(server_ip_buf),
                                          &config->server_ip);
  connect_ip_len = ssh_encode_ipaddr_array(connect_ip_buf,
                                           sizeof(connect_ip_buf),
                                           &config->connect_ip);

  /* Encode config data. */
  *data_len_return = ssh_encode_array_alloc(
                &data,
                SSH_FORMAT_UINT32, (SshUInt32) SSH_APPGW_SOCKSIFY_VERSION,
                SSH_FORMAT_UINT32_STR, server_ip_buf, server_ip_len,
                SSH_FORMAT_UINT32, (SshUInt32) config->server_port,
                SSH_FORMAT_UINT32, config->version,

                SSH_FORMAT_UINT32_STR,
                config->user_name, config->user_name_len,

                SSH_FORMAT_UINT32_STR,
                config->password, config->password_len,

                SSH_FORMAT_UINT32_STR, connect_ip_buf, connect_ip_len,
                SSH_FORMAT_UINT32, (SshUInt32) config->connect_port,

                SSH_FORMAT_END);

  if (*data_len_return == 0)
    /* Could not encode. */
    return NULL;

  return data;
}


SshAppgwSocksifyConfig
ssh_appgw_socksify_config_unmarshal(const unsigned char *data, size_t data_len)
{
  SshAppgwSocksifyConfig config = NULL;
  SshUInt32 format_version;
  const unsigned char *server_ip;
  size_t server_ip_len;
  SshUInt32 server_port;
  SshUInt32 version;
  const unsigned char *user_name;
  size_t user_name_len;
  const unsigned char *password;
  size_t password_len;
  const unsigned char *connect_ip;
  size_t connect_ip_len;
  SshUInt32 connect_port;

  /* We must receive a non-empty configuration data block. */
  if (data_len == 0)
    goto error;

  if (ssh_decode_array(data, data_len,
                       SSH_FORMAT_UINT32, &format_version,

                       SSH_FORMAT_UINT32_STR_NOCOPY,
                       &server_ip, &server_ip_len,

                       SSH_FORMAT_UINT32, &server_port,
                       SSH_FORMAT_UINT32, &version,

                       SSH_FORMAT_UINT32_STR_NOCOPY,
                       &user_name, &user_name_len,

                       SSH_FORMAT_UINT32_STR_NOCOPY, &password, &password_len,

                       SSH_FORMAT_UINT32_STR_NOCOPY,
                       &connect_ip, &connect_ip_len,

                       SSH_FORMAT_UINT32, &connect_port,
                       SSH_FORMAT_END) != data_len)
    goto error;

  /* Check version and mandatory arguments. */

  if (format_version != SSH_APPGW_SOCKSIFY_VERSION)
    goto error;

  if (server_ip_len == 0)
    goto error;

  /* Allocate a config object. */
  config = ssh_appgw_socksify_config_create();
  if (config == NULL)
    goto error;

  ssh_decode_ipaddr_array(server_ip, server_ip_len, &config->server_ip);

  if (server_port)
    config->server_port = server_port;
  else
    config->server_port = 1080;

  if (version)
    config->version = version;
  else
    config->version = 4;

  if (user_name_len)
    {
      config->user_name = ssh_memdup(user_name, user_name_len);
      if (config->user_name == NULL)
        goto error;
      config->user_name_len = user_name_len;
    }

  if (password_len)
    {
      config->password = ssh_memdup(password, password_len);
      if (config->password == NULL)
        goto error;
      config->password_len = password_len;
    }

  if (connect_ip_len)
    ssh_decode_ipaddr_array(connect_ip, connect_ip_len, &config->connect_ip);
  config->connect_port = connect_port;

  /* All done. */
  return config;


  /* Error handling. */

 error:
  if (config)
    ssh_appgw_socksify_config_destroy(config);

  return NULL;
}
#endif /* SSHDIST_IPSEC_FIREWALL */
#endif /* SSHDIST_IPSEC_NAT */
