/*
 *
 * appgw_http.c
 *
 * Copyright:
 *       Copyright (c) 2002, 2003 SFNT Finland Oy.
 *       All rights reserved.
 *
 * An application gateway for HTTP.
 *
 */

#include "sshincludes.h"
#include "sshtimeouts.h"
#include "appgw_api.h"
#include "sshfsm.h"
#include "sshregex.h"
#include "sshinet.h"
#include "sshurl.h"

#include "appgw_http.h"
#include "appgw_http_internal.h"

#define SSH_DEBUG_MODULE "SshAppgwHttp"

#ifdef SSHDIST_IPSEC_FIREWALL

/******************* Prototypes for static help function ********************/

/* Callback for idle timeout */
static void
ssh_appgw_http_inactive(void* ctx);

/* A stream notification callback. */
static void
ssh_appgw_http_stream_cb(SshStreamNotification notification,
                         void *context);

/* A timeout function to terminate the TCP pass-through connection
   `context'. */
static void
ssh_appgw_http_connection_terminate(void *context);

/* Destroy and optionally unregister TCP pass-through application
   gateway instance `ctx'. */
static void
ssh_appgw_http_destroy(SshAppgwHttpCtx ctx);

/* Free a connection object */
static void
ssh_appgw_http_connection_free(SshAppgwHttpConn con);

/********************** Prototypes for handling configuration *******/

static Boolean
ssh_appgw_http_del_config(SshAppgwHttpCtx http_ctx, int service_id);

static Boolean
ssh_appgw_http_add_config(SshAppgwHttpCtx http_ctx, SshAppgwHttpConfig,
                          const char*,int);

/********************** Prototypes for state functions **************/

SSH_FSM_STEP(ssh_appgw_http_st_wait_input);
SSH_FSM_STEP(ssh_appgw_http_st_write_data);
SSH_FSM_STEP(ssh_appgw_http_st_inject);
SSH_FSM_STEP(ssh_appgw_http_st_terminate);
SSH_FSM_STEP(ssh_appgw_http_st_inject);

/***************************** State functions ******************************/

SSH_FSM_STEP(ssh_appgw_http_st_wait_input)
{
  SshAppgwHttpCtx http_ctx = (SshAppgwHttpCtx) fsm_context;
  SshAppgwHttpIO io = (SshAppgwHttpIO) thread_context;
  SshAppgwHttpConn con = (SshAppgwHttpConn)io->conn;
  SshAppgwHttpState state = (SshAppgwHttpState)io->state;
  size_t buf_left;
  int read;

  SSH_DEBUG(SSH_D_MIDOK,
            ("entering state st_wait_input: (%s) reading_hdr %d nmsgs %d",
             (state == &con->state_i ? "i" : "r"),
             state->reading_hdr,
             state->nmsgs));

  /* Is there any data which must be injected at this point? */
  if (ssh_appgw_http_is_inject(io,con,state) == TRUE)
    {
      SSH_FSM_SET_NEXT(ssh_appgw_http_st_inject);
      return SSH_FSM_CONTINUE;
    }

  /* Initial pass over data already present in buffer */
  ssh_appgw_http_handle_state(io,con,state);

  if (http_ctx->shutdown || io->terminate || con->teardown)
    {
      /** System shutting down. */
      SSH_FSM_SET_NEXT(ssh_appgw_http_st_terminate);
      return SSH_FSM_CONTINUE;
    }

  if (state->flush_buf)
    {
      SSH_FSM_SET_NEXT(ssh_appgw_http_st_write_data);
      return SSH_FSM_CONTINUE;
    }

  /* Read more data into the buffer */
  buf_left = sizeof(io->buf) - io->data_in_buf;

  if (buf_left > 0)
    {
      read = ssh_stream_read(io->src, io->buf + io->data_in_buf, buf_left);

      SSH_DEBUG(SSH_D_MY,("read %d bytes (offset %d data %d)",
                          read, io->offset_in_buf, io->data_in_buf));

      /* Handle blocking and errors */
      if (read < 0)
        {
          /* We would block.  Check if we should terminate. */
          if (io->terminate || con->teardown)
            {
              /** Connection closed. */
              SSH_FSM_SET_NEXT(ssh_appgw_http_st_terminate);
              return SSH_FSM_CONTINUE;
            }
          return SSH_FSM_SUSPENDED;
        }
      else if (read == 0)
        {
          /** EOF. */
          /* Signal that we won't write any more data. */
          ssh_stream_output_eof(io->dst);
          SSH_FSM_SET_NEXT(ssh_appgw_http_st_terminate);
          return SSH_FSM_CONTINUE;
        }

      /* Pass body through */

      con->inactive = 0;
      io->data_in_buf += read;
    }

  /* Do another pass over the buffer, considering data that
     was just read */
  ssh_appgw_http_handle_state(io,con,state);

  /* Should we stay here ? */

  if (state->flush_buf == 0)
    {
      if (io->data_in_buf + io->offset_in_buf >= sizeof(io->buf))
        {
          SSH_DEBUG(SSH_D_NETGARB,("Out of buffer parsing HTTP stream"));
          con->teardown = 1;
          SSH_FSM_SET_NEXT(ssh_appgw_http_st_terminate);
          return SSH_FSM_CONTINUE;
        }

      SSH_FSM_SET_NEXT(ssh_appgw_http_st_wait_input);
      return SSH_FSM_CONTINUE;
    }

  /* .. or move on to flush data */

  SSH_FSM_SET_NEXT(ssh_appgw_http_st_write_data);
  return SSH_FSM_CONTINUE;
}

/* Inject a HTTP response into the stream from con->reply_r.actions.
   Free this response and return to ssh_appgw_http_st_wait() if
   the connection seems persistent. If the connection is non-persistent
   move to ssh_appgw_http_st_terminate() state. */
SSH_FSM_STEP(ssh_appgw_http_st_inject)
{
  SshAppgwHttpCtx http_ctx = (SshAppgwHttpCtx) fsm_context;
  SshAppgwHttpIO io = (SshAppgwHttpIO) thread_context;
  SshAppgwHttpConn con = (SshAppgwHttpConn)io->conn;
  SshAppgwHttpState state = (SshAppgwHttpState)io->state;
  SshAppgwHttpReplyAction act;
  int wrote;
  int is_close;

  SSH_DEBUG(SSH_D_MIDOK,("entering state st_inject (%s): msgs %d ",
                         (state == &con->state_i ? "i" : "r"),
                         state->nmsgs));

  /* Check if the system is shutting down. */
  if (http_ctx->shutdown || io->terminate || con->teardown)
    {
      /** System shutting down. */
      SSH_FSM_SET_NEXT(ssh_appgw_http_st_terminate);
      return SSH_FSM_CONTINUE;
    }

  act = con->reply_r.actions;
  SSH_ASSERT(act != NULL );

  /* Write as much as possible. */
  while (act->offset < act->data_in_buf)
    {
      wrote = ssh_stream_write(io->dst,
                               (unsigned char *)act->buf + act->offset,
                               act->data_in_buf - act->offset);

      if (wrote < 0)
        {
          /* We would block.  Wait until we can write more data. */
          return SSH_FSM_SUSPENDED;
        }
      else if (wrote == 0)
        {
          /** Write failed. */
          SSH_FSM_SET_NEXT(ssh_appgw_http_st_terminate);
          return SSH_FSM_CONTINUE;
        }
      else
        {
          act->offset += wrote;
        }
    }

  con->reply_r.actions = act->next;
  is_close = act->close_after_action;

  if (state->nmsgs++ >= 1 && act->http_version != SSH_APPGW_HTTP_HTTPV_09)
    is_close = 0;

  ssh_appgw_http_replyaction_free(act);

  if (is_close == 1)
    {
      SSH_DEBUG(SSH_D_MIDOK,("closing connection after inject"));
      ssh_stream_output_eof(io->dst);

      con->io_i.terminate = 1;
      con->io_r.terminate = 1;

      SSH_FSM_SET_NEXT(ssh_appgw_http_st_terminate);
      return SSH_FSM_CONTINUE;
    }

  SSH_FSM_SET_NEXT(ssh_appgw_http_st_wait_input);
  return SSH_FSM_CONTINUE;
}

/* Flush the buffer [io->buf,io->buf + io->offset_in_buf] and adjust
   the buffer by removing this amount. */
SSH_FSM_STEP(ssh_appgw_http_st_write_data)
{
  int wrote;
  SshAppgwHttpCtx http_ctx = (SshAppgwHttpCtx) fsm_context;
  SshAppgwHttpIO io = (SshAppgwHttpIO) thread_context;
  SshAppgwHttpConn con = (SshAppgwHttpConn)io->conn;
  SshAppgwHttpState state = (SshAppgwHttpState)io->state;

  SSH_DEBUG(SSH_D_MIDOK,("entering state st_write_data "));

  state->flush_buf = 0;

  /* First, check if the system is shutting down. */
  if (http_ctx->shutdown || io->terminate || con->teardown)
    {
      /** System shutting down. */
      SSH_FSM_SET_NEXT(ssh_appgw_http_st_terminate);
      return SSH_FSM_CONTINUE;
    }

  /* Write as much as possible. */
  while (io->bufpos < io->offset_in_buf)
    {
      SSH_ASSERT(io->bufpos <= io->offset_in_buf);
      SSH_ASSERT(io->offset_in_buf <= io->data_in_buf);

      wrote = ssh_stream_write(io->dst, io->buf + io->bufpos,
                               io->offset_in_buf - io->bufpos);
      SSH_TRACE_HEXDUMP(SSH_D_MY,
                        ("iobuf: %d bytes", io->offset_in_buf - io->bufpos),
                        io->buf + io->bufpos,
                        io->offset_in_buf - io->bufpos);
      if (wrote < 0)
        {
          /* We would block.  Wait until we can write more data. */
          return SSH_FSM_SUSPENDED;
        }
      else if (wrote == 0)
        {
          /** Write failed. */
          SSH_FSM_SET_NEXT(ssh_appgw_http_st_terminate);
          return SSH_FSM_CONTINUE;
        }
      else
        {
          io->bufpos += wrote;
        }
      SSH_ASSERT(io->bufpos <= io->offset_in_buf);
      SSH_ASSERT(io->offset_in_buf <= io->data_in_buf);
    }

  /* Make room for more stuff */

  if (io->bufpos > 0)
    {
      memmove(io->buf,
              io->buf + io->bufpos,
              io->data_in_buf - io->bufpos);

      io->offset_in_buf -= io->bufpos;
      io->data_in_buf -= io->bufpos;
      io->bufpos = 0;
    }

  SSH_ASSERT(io->bufpos <= io->data_in_buf);

  if (io->offset_in_buf == 0)
    {
      SSH_FSM_SET_NEXT(ssh_appgw_http_st_wait_input);
      return SSH_FSM_CONTINUE;
    }

  SSH_FSM_SET_NEXT(ssh_appgw_http_st_write_data);
  return SSH_FSM_CONTINUE;
}

/* Terminate state for the I/O threads. Wake up the
   peer thread and finish. */
SSH_FSM_STEP(ssh_appgw_http_st_terminate)
{
  SshAppgwHttpIO io = (SshAppgwHttpIO) thread_context;
  SshAppgwHttpConn conn = io->conn;
#ifdef DEBUG_LIGHT
  SshAppgwHttpIO io_r = &conn->io_r;
  SshAppgwHttpIO io_i = &conn->io_i;
#endif /* DEBUG_LIGHT */

  SSH_DEBUG(SSH_D_MIDOK,
            ("entering state st_terminate (%s): "
             "teardown %d terminate i: %d r: %d",
             (io == io_i ?  "i" : "r"),
             conn->teardown,io_r->terminate,io_i->terminate));

  /* This thread is finished. */
  io->active = 0;

  /* Check if we were the last thread in the connection. */
  if (!conn->io_i.active && !conn->io_r.active)
    {
      /* Yes we were.  Let's register a timeout to destroy the
         connection object. */
      ssh_xregister_timeout(0, 0,
                           ssh_appgw_http_connection_terminate,
                           conn);
    }
  else
    {
      if (conn->teardown == 1)
        {
          if (conn->io_r.active == 1)
            ssh_fsm_continue(&conn->thread_r);

          if (conn->io_i.active == 1)
            ssh_fsm_continue(&conn->thread_i);
        }
    }

  /* Terminate this thread. */
  return SSH_FSM_FINISH;
}



/* Callback for receiving new connections, configurations and
   shutdown orders from the policy manager. */
static void
ssh_appgw_http_conn_cb(SshAppgwContext ctx,
                       SshAppgwAction action,
                       const unsigned char *udp_data,
                       size_t udp_len,
                       void *context)
{
  SshAppgwHttpCtx http_ctx = (SshAppgwHttpCtx) context;
  SshAppgwHttpConn conn;
  SshAppgwHttpConfig config;
  const unsigned char *config_data;
  size_t config_data_len;
  int service_id;
  char *service_name;

  switch (action)
    {
    case SSH_APPGW_FLOW_INVALID:
      service_name = ctx->service_name;
      break;

    case SSH_APPGW_UPDATE_CONFIG:
      config_data = ctx->config_data;
      config_data_len = ctx->config_data_len;
      service_id = ctx->service_id;
      service_name = ctx->service_name;

      ssh_appgw_http_del_config(http_ctx,service_id);

      config = ssh_appgw_http_unmarshal_config(config_data, config_data_len);
      if (config != NULL)
        {
          if (ssh_appgw_http_add_config(http_ctx, config,
                                        service_name, service_id)
               == FALSE)
            {
              ssh_log_event(SSH_LOGFACILITY_DAEMON,
                            SSH_LOG_CRITICAL,
                            "service %s: insufficient memory available, "
                            "unable to apply new configuration",
                            (service_name!=NULL?service_name:"NULL"));
            }
        }
      else
        {
          ssh_log_event(SSH_LOGFACILITY_DAEMON,
                        SSH_LOG_CRITICAL,
                        "service %s: internal error, could not "
                        "unmarshal configuration!",
                        (service_name!=NULL?service_name:"NULL"));

          SSH_DEBUG(SSH_D_FAIL,("error unmarshaling configuration"));
        }
      break;

    case SSH_APPGW_REDIRECT:
      config = ssh_appgw_http_get_config(http_ctx, ctx->service_id);
      if (config != NULL
          && (SSH_IP_DEFINED(&config->tcp_dst) && config->tcp_port != 0))
        ssh_appgw_redirect(ctx, &config->tcp_dst, config->tcp_port);
      else
        ssh_appgw_redirect(ctx,
                           &ctx->responder_orig_ip,
                           ctx->responder_orig_port);
      break;

    case SSH_APPGW_SHUTDOWN:
      http_ctx->shutdown = 1;

      ssh_log_event(SSH_LOGFACILITY_DAEMON, SSH_LOG_NOTICE,
                    "%s: Shutting down.", SSH_APPGW_NAME);

      if (http_ctx->connections)
        {
          /* We have active connections so let's notify them about the
             shutdown.  They will terminate after they receive the
             notification. */
          for (conn = http_ctx->connections; conn; conn = conn->next)
            {
              ssh_fsm_continue(&conn->thread_i);
              ssh_fsm_continue(&conn->thread_r);
            }
        }
      else
        {
          /* Shutdown immediately. */
          ssh_appgw_http_destroy(http_ctx);
        }
      break;

    case SSH_APPGW_NEW_INSTANCE:
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("New TCP HTTP connection %@.%d > %@.%d",
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

      /* Create a new connection. */
      conn = ssh_calloc(1, sizeof(*conn));
      if (conn == NULL)
        {
          SSH_DEBUG(SSH_D_ERROR,
                    ("Could not allocate TCP HTTP connection"));
          ssh_appgw_done(ctx);
          return;
        }

      conn->http_ctx = http_ctx;

      /* Grab configuration */

      conn->service_id = ctx->service_id;

      config = ssh_appgw_http_get_config(http_ctx, conn->service_id);
      if (config == NULL)
        {
          ssh_appgw_audit_event(conn->ctx,
                                SSH_AUDIT_WARNING,
                                SSH_AUDIT_TXT,
                                "connection for unconfigured service",
                                SSH_AUDIT_ARGUMENT_END);
        }

      conn->inactive = 0;
      ssh_appgw_http_inactive(conn);

      /* Link connection to the gateway's list of active
         connections. */
      conn->next = http_ctx->connections;
      if (http_ctx->connections)
        http_ctx->connections->prev = conn;
      http_ctx->connections = conn;

      /* Store application level gateway framework's context. */
      conn->ctx = ctx;

      /* Store application gateway context into SshAppgwContext's
         `user_context'. */
      ctx->user_context = http_ctx;

      /* Initialize state  */
      ssh_appgw_hdr_reset_state(&conn->state_i);
      ssh_appgw_hdr_reset_state(&conn->state_r);
      ssh_appgw_msg_begin(conn,&conn->state_i);
      ssh_appgw_msg_begin(conn,&conn->state_r);
      conn->state_i.nmsgs = 0;
      conn->state_r.nmsgs = 0;
      conn->reply_r.actions = NULL;

      /* Set stream callbacks. */
      ssh_stream_set_callback(conn->ctx->initiator_stream,
                              ssh_appgw_http_stream_cb, conn);
      ssh_stream_set_callback(conn->ctx->responder_stream,
                              ssh_appgw_http_stream_cb, conn);

      /* Setup I/O threads. */

      conn->io_i.active = 1;
      conn->io_i.src = conn->ctx->initiator_stream;
      conn->io_i.dst = conn->ctx->responder_stream;
      conn->io_i.conn = conn;
      conn->io_i.state = &conn->state_i;

      ssh_fsm_thread_init(&http_ctx->fsm, &conn->thread_i,
                          ssh_appgw_http_st_wait_input,
                          NULL_FNPTR, NULL_FNPTR,
                          &conn->io_i);

      conn->io_r.active = 1;
      conn->io_r.src = conn->ctx->responder_stream;
      conn->io_r.dst = conn->ctx->initiator_stream;
      conn->io_r.conn = conn;
      conn->io_r.state = &conn->state_r;

      ssh_fsm_thread_init(&http_ctx->fsm, &conn->thread_r,
                          ssh_appgw_http_st_wait_input,
                          NULL_FNPTR, NULL_FNPTR,
                          &conn->io_r);

      conn->teardown = 0;

     break;

    case SSH_APPGW_UDP_PACKET_FROM_INITIATOR:
    case SSH_APPGW_UDP_PACKET_FROM_RESPONDER:
      SSH_NOTREACHED;
      break;
    }
}

/* Inactivity timeout callback for initiating the tearing down
   of inactive connections. */
static void
ssh_appgw_http_inactive(void *ctx)

{
  SshAppgwHttpConn con;
  SshAppgwHttpCtx http_ctx;

  con = (SshAppgwHttpConn)ctx;
  http_ctx = con->http_ctx;

  if (con->inactive == 1)
    {
      ssh_appgw_audit_event(con->ctx,
                            SSH_AUDIT_WARNING,
                            SSH_AUDIT_TXT,
                            "terminating idle connection",
                            SSH_AUDIT_ARGUMENT_END);

      SSH_DEBUG(SSH_D_MY,("tearing down inactive connection"));

      con->teardown = 1;

      if (con->io_r.active == 1)
        ssh_fsm_continue(&con->thread_r);

      if (con->io_i.active == 1)
        ssh_fsm_continue(&con->thread_i);
    }
  else
    {
      con->inactive = 1;
      ssh_xregister_timeout(SSH_APPGW_HTTP_INACTIVE_TIMEOUT,
                           0, ssh_appgw_http_inactive, con);
    }
}

/* Callback to wake threads for I/O */
static void
ssh_appgw_http_stream_cb(SshStreamNotification notification,
                         void *context)
{
  SshAppgwHttpConn conn = (SshAppgwHttpConn) context;

  /* Simply continue all active threads. */
  if (conn->io_i.active)
    ssh_fsm_continue(&conn->thread_i);
  if (conn->io_r.active)
    ssh_fsm_continue(&conn->thread_r);
}

/* Free the connection structure and all reply actions associated with it */
static void
ssh_appgw_http_connection_free(SshAppgwHttpConn con)
{
  SshAppgwHttpReplyAction act,a2;
  SshAppgwHttpRequestMethod met,m2;

  act = con->reply_r.actions;
  while (act != NULL)
    {
      a2 = act->next;
      ssh_appgw_http_replyaction_free(act);
      act = a2;
    }

  met = con->reply_r.methods;
  while (met != NULL)
    {
      m2 = met->next;
      ssh_free(met);
      met = m2;
    }

  ssh_free(con);
}

/* Terminate a connection, and if the connection is the
   last one and the system is shutting down then call
   ssh_appgw_http_destroy(). */
static void
ssh_appgw_http_connection_terminate(void *context)
{
  SshAppgwHttpConn conn = (SshAppgwHttpConn) context;
  SshAppgwHttpCtx http_ctx;

  /* Get application gateway context. */
  http_ctx = (SshAppgwHttpCtx) conn->ctx->user_context;
  conn->ctx->user_context = NULL;

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("service %s: "
             "TCP HTTP connection %@.%d > %@.%d terminated",
             ssh_appgw_get_service_name(conn),
             ssh_ipaddr_render, &conn->ctx->initiator_ip,
             conn->ctx->initiator_port,
             ssh_ipaddr_render, &conn->ctx->responder_ip,
             conn->ctx->responder_port));

  ssh_stream_set_callback(conn->ctx->initiator_stream, NULL_FNPTR, NULL);
  ssh_stream_set_callback(conn->ctx->responder_stream, NULL_FNPTR, NULL);

  ssh_appgw_done(conn->ctx);

  /* Destroy the inactivity timeout */
  ssh_cancel_timeouts(ssh_appgw_http_inactive,conn);

  /* Remove us from the application gateway's list of connections. */
  if (conn->next)
    conn->next->prev = conn->prev;

  if (conn->prev)
    conn->prev->next = conn->next;
  else
    http_ctx->connections = conn->next;

  /* Free our connection structure. */
  ssh_appgw_http_connection_free(conn);

  if (http_ctx->shutdown && http_ctx->connections == NULL)
    /* The system is shutting down and this was the last connection.
       Let's shutdown this application gateway. */
    ssh_appgw_http_destroy(http_ctx);
}

/* Destroy the appgw instance. This function unregisters the appgw
   from the PM. */
static void
ssh_appgw_http_destroy(SshAppgwHttpCtx ctx)
{
  SshAppgwHttpConfig config,c2;

  ssh_fsm_uninit(&ctx->fsm);

  config = ctx->configs;
  while (config != NULL)
    {
      c2 = config->next;
      ssh_appgw_http_destroy_config(config);
      config = c2;
    }

  if (ctx->registered)
    {
      SSH_DEBUG(SSH_D_HIGHSTART, ("Unregistering from firewall"));
      ssh_appgw_unregister_local(ctx->pm,
                                 SSH_APPGW_HTTP_IDENT,
                                 SSH_APPGW_HTTP_VERSION,
                                 SSH_IPPROTO_TCP);
    }

  ssh_free(ctx);
}

/* This function is called after an instance has tried
   registering itself to the PM. If the registration fails
   this callback destroys the associated context. */
static void
ssh_appgw_http_reg_cb(SshAppgwError error, void *context)
{
  SshAppgwHttpCtx ctx = (SshAppgwHttpCtx) context;

  if (error != SSH_APPGW_ERROR_OK)
    {
      char *why = NULL;

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
      SSH_DEBUG(SSH_D_FAIL, ("Registering failed: %s", why));

      ssh_log_event(SSH_LOGFACILITY_DAEMON,
                    SSH_LOG_CRITICAL,
                    "registering HTTP APPGW failed: %s",why);

      ssh_appgw_http_destroy(ctx);
      return;
    }

  ssh_log_event(SSH_LOGFACILITY_DAEMON,
                SSH_LOG_NOTICE,
                "%s: Application gateway started.",
                SSH_APPGW_NAME);

  SSH_DEBUG(SSH_D_HIGHOK, ("Registration ok"));
  ctx->registered = 1;
}

/* Fetch a service name for the connection "con". This
   function always returns a valid string. The caller
   must not manipulate the result. */
const char*
ssh_appgw_get_service_name(const SshAppgwHttpConn con)
{
  SshAppgwHttpConfig config;
  SshAppgwHttpCtx http_ctx;

  SSH_ASSERT(con != NULL);

  http_ctx = con->http_ctx;
  config = ssh_appgw_http_get_config(http_ctx,con->service_id);

  if (config == NULL)
    return "unconfigured";

  if (config->service_name == NULL)
    return "http";

  return config->service_name;
}

/* Add the configuration "config" to the context using the
   specified service_id and service_name. Returns FALSE
   if insufficient memory is unavailable. */
static Boolean
ssh_appgw_http_add_config(SshAppgwHttpCtx http_ctx,
                          SshAppgwHttpConfig config,
                          const char *service_name,
                          int service_id)
{
  char *dupname;

  dupname = NULL;

  if (service_name != NULL)
    dupname = ssh_strdup(service_name);
  else
    dupname = ssh_strdup("http");

  if (dupname == NULL)
    return FALSE;

  config->service_id = service_id;

  if (config->service_name == NULL)
    ssh_free(config->service_name);

  config->service_name = dupname;

  config->next = http_ctx->configs;
  http_ctx->configs = config;
  SSH_DEBUG(SSH_D_MY,
            ("adding configuration for service id %d",
             config->service_id));
  return TRUE;
}


/* Remove and destroy a configuration with specified service_id.
   ReturnsTRUE if this operation succeeds. */
static Boolean
ssh_appgw_http_del_config(SshAppgwHttpCtx http_ctx,
                          int service_id)
{
  SshAppgwHttpConfig c,c2;

  if (http_ctx->configs == NULL)
    return FALSE;

  c = http_ctx->configs;

  if (c->service_id == service_id)
    {
      http_ctx->configs = c->next;
      ssh_appgw_http_destroy_config(c);
      return TRUE;
    }

  while (c->next != NULL)
    {
      if (c->next->service_id == service_id)
        {
          c2 = c->next;
          c->next = c2->next;

          ssh_appgw_http_destroy_config(c);
          return TRUE;
        }
      c = c->next;
    }

  return FALSE;
}

/* Fetch the configuration with the specified service_id from the
   instance context. Returns NULL if this configuration can not be
   found. */
SshAppgwHttpConfig
ssh_appgw_http_get_config(const SshAppgwHttpCtx http_ctx,
                          int service_id)
{
  SshAppgwHttpConfig c;

  /* Look up based on service_id */

  for (c = http_ctx->configs;
       c != NULL && c->service_id != service_id;
       c = c->next);

  return c;
}

/* This function initializes the global context and registers the
   firewall to the PM. This will result in a call to
   ssh_appgw_http_reg_cb() which siganls the success/failure. */
void
ssh_appgw_http_init(SshPm pm)
{
  SshAppgwHttpCtx ctx;
  SshAppgwParamsStruct params;

  ctx = ssh_calloc(1, sizeof(*ctx));
  if (ctx == NULL)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Could not allocate context"));
      return;
    }
  ctx->pm = pm;

  ssh_fsm_init(&ctx->fsm, ctx);

  ctx->configs = NULL;

  SSH_DEBUG(SSH_D_HIGHSTART, ("Registering to firewall"));

  memset(&params,0,sizeof(params));
  params.ident = SSH_APPGW_HTTP_IDENT;
  params.printable_name = "HTTP TCP";
  params.version = SSH_APPGW_HTTP_VERSION;
  params.ipproto = SSH_IPPROTO_TCP;

  ssh_appgw_register_local(ctx->pm,
                           &params,
                           SSH_APPGW_F_REDIRECT,
                           ssh_appgw_http_conn_cb, ctx,
                           ssh_appgw_http_reg_cb, ctx);
}

#endif /* SSHDIST_IPSEC_FIREWALL */
