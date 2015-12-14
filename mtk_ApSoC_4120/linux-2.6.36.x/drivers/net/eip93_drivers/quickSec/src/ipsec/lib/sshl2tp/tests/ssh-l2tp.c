/*
 *
 * ssh-l2tp.c
 *
 * Author: Markku Rossi <mtr@ssh.fi>
 *
*  Copyright:
*          Copyright (c) 2002, 2003 SFNT Finland Oy.
*  Copyright:
*          Copyright (c) 2002, 2003 SFNT Finland Oy.
 *               All rights reserved.
 *
 * Test utility for L2TP LAC and LNS operations.
 *
 */

#include "sshincludes.h"
#include "ssheloop.h"
#include "sshglobals.h"
#include "sshtimeouts.h"
#include "sshgetopt.h"
#include "sshl2tp.h"
#include "sshinet.h"
#include "sshstream.h"
#include "sshppp.h"
#include "sshcrypt.h"
#include "sshnameserver.h"

/************************** Types and definitions ***************************/

#define SSH_DEBUG_MODULE "ssh-l2tp"

#define PPP_DEBUG_LEVEL SSH_D_LOWOK

/* Context structure for initiator sessions. */
struct InitiatorSessionCtxRec
{
  SshL2tp l2tp;
  SshL2tpServer l2tp_server;

  /* The mode of the initiator. */
  Boolean lac;

  /* How many sub-sessions to start. */
  SshUInt32 num_children;

  char *addr;
  char *port;

  SshL2tpSessionInfo session;
  SshOperationHandle handle;
  SshPPPHandle ppp;
};

typedef struct InitiatorSessionCtxRec InitiatorSessionCtxStruct;
typedef struct InitiatorSessionCtxRec *InitiatorSessionCtx;

/* Context structure for responder sessions. */
struct ResponderSessionCtxRec
{
  SshL2tpSessionInfo session;
  SshPPPHandle ppp;
};

typedef struct ResponderSessionCtxRec ResponderSessionCtxStruct;
typedef struct ResponderSessionCtxRec *ResponderSessionCtx;

static char *program;

SshInt32 session_timeout = -1;
SshUInt32 tunnel_timeout = 0;

SshUInt32 make_num_sessions = 1;
SshUInt32 make_num_tunnels = 1;

SshUInt32 num_tunnels = 0;
SshUInt32 num_sessions = 0;

char *key = NULL;
size_t key_len = 0;

SshUInt32 l2tp_shutdown_timeout = 0;
SshUInt32 l2tp_destroy_timeout = 0;

char *float_port = NULL;

char *address = NULL;
char *port = NULL;
Boolean no_ppp = FALSE;

int exit_value = 1;

Boolean float_initiator_port = FALSE;

SshL2tp l2tp;


/********************* Prototypes for static functions **********************/




static void usage(void);


/*************************** Responder functions ****************************/

static SshOperationHandle
tunnel_request_cb(SshL2tpTunnelInfo info,
                  SshL2tpTunnelRequestCompletionCB completion_cb,
                  void *completion_cb_context,
                  void *context)
{
#if 0
  SSH_DEBUG(SSH_D_ERROR, ("Accepting new tunnel from %s:%s",
                          info->remote_addr, info->remote_port));
#endif

  (*completion_cb)(TRUE, key, key_len,
                   float_port,
                   0, 0, NULL, 0,
                   completion_cb_context);

  return NULL;
}

static void
responder_tunnel_status_cb(SshL2tpTunnelInfo info,
                           SshL2tpTunnelStatus status,
                           void *callback_context)
{
  char *what;

  switch (status)
    {
    case SSH_L2TP_TUNNEL_OPEN_FAILED:
      what = "open failed";
      break;

    case SSH_L2TP_TUNNEL_OPENED:
      what = "opened";
      num_tunnels++;
      break;

    case SSH_L2TP_TUNNEL_TERMINATED:
      what = "terminated";
      num_tunnels--;
      break;
    }

  SSH_DEBUG(SSH_D_ERROR,
            ("Tunnel %s:%s %5d %s, #t=%u (result=%d, error=%d)",
             info->remote_addr, info->remote_port, info->local_id,
             what, num_tunnels,
             info->result_code,
             info->error_code));
}


static SshOperationHandle
session_request_cb(SshL2tpSessionInfo info,
                   SshL2tpSessionRequestCompletionCB completion_cb,
                   void *completion_cb_context,
                   void *context)
{
#if 0
  SSH_DEBUG(SSH_D_ERROR, ("Accepting new session for tunnel %s:%s",
                          info->tunnel->remote_addr,
                          info->tunnel->remote_port));
#endif

  (*completion_cb)(TRUE, 0, 0, NULL, 0, completion_cb_context);

  return NULL;
}


static void
resp_ppp_get_s_secret(SshPPPHandle ppp, SshPppAuthType auth_type,
                      void *user_context, void *ppp_context,
                      SshUInt8 *name, SshUInt32 namelen)
{
  SSH_DEBUG(PPP_DEBUG_LEVEL, ("Get server secret `%.*s'", namelen, name));
  ssh_ppp_return_secret(ppp, ppp_context, "ssh", 3);
}


static void
resp_ppp_signal_cb(void *context, SshPppSignal signal)
{
  ResponderSessionCtx ctx = (ResponderSessionCtx) context;

  switch (signal)
    {
    case SSH_PPP_SIGNAL_LCP_UP:
      {
        /* Address control field compression. */
        int i_acfc = ssh_ppp_get_lcp_input_acfc(ctx->ppp);
        int o_acfc = ssh_ppp_get_lcp_output_acfc(ctx->ppp);
        /* Protocol field compression. */
        int i_pfc = ssh_ppp_get_lcp_input_pfc(ctx->ppp);
        int o_pfc = ssh_ppp_get_lcp_output_pfc(ctx->ppp);

        SSH_DEBUG(PPP_DEBUG_LEVEL,
                  ("LCP up: i_acfc=%d, o_acfc=%d, i_pfc=%d, o_pfc=%d",
                   i_acfc, o_acfc, i_pfc, o_pfc));
      }
      break;

    case SSH_PPP_SIGNAL_LCP_DOWN:
      SSH_DEBUG(PPP_DEBUG_LEVEL, ("LCP down"));
      break;

    case SSH_PPP_SIGNAL_IPCP_UP:
      {
        SshIpAddrStruct peer_ip;
        SshIpAddrStruct own_ip;

        ssh_ppp_get_ipcp_peer_ip(ctx->ppp, &peer_ip);
        ssh_ppp_get_ipcp_own_ip(ctx->ppp, &own_ip);

        SSH_DEBUG(SSH_D_ERROR, ("IPCP up: peer_ip=%@, own_ip=%@",
                                ssh_ipaddr_render, &peer_ip,
                                ssh_ipaddr_render, &own_ip));
      }
      break;

    case SSH_PPP_SIGNAL_IPCP_DOWN:
      SSH_DEBUG(PPP_DEBUG_LEVEL, ("IPCP down"));
      break;

    case SSH_PPP_SIGNAL_IPCP_FAIL:
      SSH_DEBUG(SSH_D_ERROR, ("IPCP fail"));
      break;

    case SSH_PPP_SIGNAL_PPP_HALT:
      break;

    case SSH_PPP_SIGNAL_SERVER_AUTH_FAIL:
      SSH_DEBUG(SSH_D_ERROR, ("Server authentiation failed"));
      break;

    case SSH_PPP_SIGNAL_CLIENT_AUTH_FAIL:
      SSH_DEBUG(SSH_D_ERROR, ("Client authentiation failed"));
      break;

    case SSH_PPP_SIGNAL_SERVER_AUTH_OK:
      SSH_DEBUG(PPP_DEBUG_LEVEL, ("Server authentiation OK"));
      break;

    case SSH_PPP_SIGNAL_CLIENT_AUTH_OK:
      SSH_DEBUG(PPP_DEBUG_LEVEL, ("Client authentiation OK"));
      break;

    case SSH_PPP_SIGNAL_FATAL_ERROR:
      ssh_fatal("PPP fatal error");
      break;
    }
}


static void
resp_ppp_output_cb(SshPPPHandle ppp, void *ctx, SshUInt8 *buffer,
                   unsigned long offset, unsigned long len)
{
  ResponderSessionCtx context = (ResponderSessionCtx) ctx;

  ssh_l2tp_session_send(l2tp, context->session, buffer + offset, len);
  ssh_xfree(buffer);
}

static void
resp_l2tp_data_cb(SshL2tpSessionInfo session, const unsigned char *data,
                  size_t data_len)
{
  ResponderSessionCtx ctx = (ResponderSessionCtx) session->upper_level_data;
  unsigned char *buf;

  buf = ssh_xmemdup(data, data_len);
  if (buf == NULL)
    return;

  ssh_ppp_frame_input(ctx->ppp, buf, 0, data_len);
}

static void
responder_session_status_cb(SshL2tpSessionInfo info,
                            SshL2tpSessionStatus status,
                            void *callback_context)
{
  char *what;
  ResponderSessionCtx ctx;
  SshPppParamsStruct ppp_config;

  switch (status)
    {
    case SSH_L2TP_SESSION_OPEN_FAILED:
      what = "open failed";
      break;

    case SSH_L2TP_SESSION_OPENED:
      what = "opened";
      num_sessions++;

      /* Create responder session context. */
      ctx = ssh_xcalloc(1, sizeof(*ctx));

      SSH_ASSERT(info->upper_level_data == NULL);
      info->upper_level_data = ctx;

      info->data_cb = resp_l2tp_data_cb;

      ctx->session = info;

      if (no_ppp)
        break;

      memset(&ppp_config, 0, sizeof(ppp_config));

      /* Start PPP to the data stream. */

      ppp_config.ctx = ctx;

      ppp_config.eap_md5_server = 1;
      ppp_config.chap_server = 1;
      ppp_config.pap_server = 1;

      ppp_config.ipcp = 1;
      ppp_config.frame_mode = SSH_PPP_MODE_L2TP;

      ppp_config.name = "L2TP PPP Server";
      ppp_config.namelen = strlen(ppp_config.name);

      ssh_ipaddr_parse(&ppp_config.own_ipv4_addr,  "10.42.1.7");
      ssh_ipaddr_parse(&ppp_config.peer_ipv4_addr, "10.42.1.2");

      ppp_config.get_server_secret_cb    = resp_ppp_get_s_secret;
      ppp_config.signal_cb               = resp_ppp_signal_cb;
      ppp_config.output_frame_cb         = resp_ppp_output_cb;

      ctx->ppp = ssh_ppp_session_create(&ppp_config);
      ssh_ppp_boot(ctx->ppp);
      break;

    case SSH_L2TP_SESSION_TERMINATED:
      what = "terminated";
      num_sessions--;

      /* Shutdown PPP. */

      SSH_ASSERT(info->upper_level_data);
      ctx = info->upper_level_data;

      if (ctx->ppp)
        ssh_ppp_destroy(ctx->ppp);
      ssh_xfree(ctx);

      info->upper_level_data = NULL;
      break;

    case SSH_L2TP_SESSION_WAN_ERROR_NOTIFY:
      what = "received WEN";
      break;

    case SSH_L2TP_SESSION_SET_LINK_INFO:
      what = "received SLI";
      break;
    }

  SSH_DEBUG(SSH_D_ERROR,
            ("Session %5d of tunnel %s:%s %5d %s, #t=%u, #s=%u "
             "(result=%d, error=%d)",
             info->local_id,
             info->tunnel->remote_addr,
             info->tunnel->remote_port,
             info->tunnel->local_id,
             what,
             num_tunnels, num_sessions,
             info->result_code, info->error_code));

  SSH_DEBUG(SSH_D_ERROR, ("Remote: Session ID %d, Tunnel ID %d",
                          info->remote_id,
                          info->tunnel->remote_id));

#if 0
  if (info->result_code)
    SSH_DEBUG(SSH_D_ERROR,
              ("Reason: %s - %s (%d %d)",
               ssh_find_keyword_name(ssh_l2tp_session_result_codes,
                                     info->result_code),
               ssh_find_keyword_name(ssh_l2tp_error_codes,
                                     info->error_code),
               info->result_code, info->error_code));
#endif
}


/*************************** Initiator functions ****************************/

static void
abort_session(void *context)
{
  InitiatorSessionCtx ctx = (InitiatorSessionCtx) context;

  ssh_operation_abort(ctx->handle);
  ssh_xfree(ctx);
}


static void
destroy_session(void *context)
{
  InitiatorSessionCtx ctx = (InitiatorSessionCtx) context;

  ssh_l2tp_session_close(ctx->l2tp,
                         ctx->session->tunnel->local_id,
                         ctx->session->local_id,
                         0, 0, NULL, 0,
                         0, 0, NULL, 0);
}


static void
init_ppp_get_c_secret(SshPPPHandle ppp, SshPppAuthType auth_type,
                      void *user_context, void *ppp_context,
                      SshUInt8 *name, SshUInt32 namelen)
{
  SSH_DEBUG(PPP_DEBUG_LEVEL, ("Get CHAP client secret `%.*s'", namelen, name));
  ssh_ppp_return_secret(ppp, ppp_context, "ssh", 3);
}


static void
init_ppp_signal_cb(void *context, SshPppSignal signal)
{
  InitiatorSessionCtx ctx = (InitiatorSessionCtx) context;

  switch (signal)
    {
    case SSH_PPP_SIGNAL_LCP_UP:
      {
        /* Address control field compression. */
        int i_acfc = ssh_ppp_get_lcp_input_acfc(ctx->ppp);
        int o_acfc = ssh_ppp_get_lcp_output_acfc(ctx->ppp);
        /* Protocol field compression. */
        int i_pfc = ssh_ppp_get_lcp_input_pfc(ctx->ppp);
        int o_pfc = ssh_ppp_get_lcp_output_pfc(ctx->ppp);

        SSH_DEBUG(PPP_DEBUG_LEVEL,
                  ("LCP up: i_acfc=%d, o_acfc=%d, i_pfc=%d, o_pfc=%d",
                   i_acfc, o_acfc, i_pfc, o_pfc));
      }
      break;

    case SSH_PPP_SIGNAL_LCP_DOWN:
      SSH_DEBUG(PPP_DEBUG_LEVEL, ("LCP down"));
      break;

    case SSH_PPP_SIGNAL_IPCP_UP:
      {
        SshIpAddrStruct peer_ip;
        SshIpAddrStruct own_ip;

        ssh_ppp_get_ipcp_peer_ip(ctx->ppp, &peer_ip);
        ssh_ppp_get_ipcp_own_ip(ctx->ppp, &own_ip);

        SSH_DEBUG(SSH_D_ERROR, ("IPCP up: peer_ip=%@, own_ip=%@",
                                ssh_ipaddr_render, &peer_ip,
                                ssh_ipaddr_render, &own_ip));
      }
      break;

    case SSH_PPP_SIGNAL_IPCP_DOWN:
      SSH_DEBUG(PPP_DEBUG_LEVEL, ("IPCP down"));
      break;

    case SSH_PPP_SIGNAL_IPCP_FAIL:
      SSH_DEBUG(SSH_D_ERROR, ("IPCP fail"));
      break;

    case SSH_PPP_SIGNAL_PPP_HALT:
      break;

    case SSH_PPP_SIGNAL_SERVER_AUTH_FAIL:
      SSH_DEBUG(SSH_D_ERROR, ("Server authentiation failed"));
      break;

    case SSH_PPP_SIGNAL_CLIENT_AUTH_FAIL:
      SSH_DEBUG(SSH_D_ERROR, ("Client authentiation failed"));
      break;

    case SSH_PPP_SIGNAL_SERVER_AUTH_OK:
      SSH_DEBUG(PPP_DEBUG_LEVEL, ("Server authentiation OK"));
      break;

    case SSH_PPP_SIGNAL_CLIENT_AUTH_OK:
      SSH_DEBUG(PPP_DEBUG_LEVEL, ("Client authentiation OK"));
      break;

    case SSH_PPP_SIGNAL_FATAL_ERROR:
      ssh_fatal("PPP fatal error");
      break;
    }
}

static void
init_ppp_output_cb(SshPPPHandle ppp, void *ctx, SshUInt8 *buffer,
                   unsigned long offset, unsigned long len)
{
  InitiatorSessionCtx context = (InitiatorSessionCtx) ctx;

  ssh_l2tp_session_send(context->l2tp, context->session,
                        buffer + offset, len);
  ssh_xfree(buffer);
}

static void
init_l2tp_data_cb(SshL2tpSessionInfo session, const unsigned char *data,
                  size_t data_len)
{
  InitiatorSessionCtx ctx = (InitiatorSessionCtx) session->upper_level_data;
  unsigned char *buf;

  buf = ssh_xmemdup(data, data_len);
  if (buf == NULL)
    return;

  ssh_ppp_frame_input(ctx->ppp, buf, 0, data_len);
}


static void
initiator_session_status_cb(SshL2tpSessionInfo info,
                            SshL2tpSessionStatus status,
                            void *callback_context)
{
  InitiatorSessionCtx ctx = callback_context;
  char *what;
  SshPppParamsStruct ppp_config;
  int i;

  ssh_cancel_timeouts(abort_session, SSH_ALL_CONTEXTS);

  switch (status)
    {
    case SSH_L2TP_SESSION_OPEN_FAILED:
      what = "open failed";

      ssh_xfree(ctx->addr);
      ssh_xfree(ctx->port);
      ssh_xfree(ctx);
      break;

    case SSH_L2TP_SESSION_OPENED:
      what = "opened";
      num_sessions++;

      info->upper_level_data = ctx;
      info->data_cb = init_l2tp_data_cb;

      ctx->session = info;

      if (session_timeout > -1)
        ssh_xregister_timeout(session_timeout, 0, destroy_session, ctx);

      if (!no_ppp)
        {
          /* Start PPP to the data stream. */
          memset(&ppp_config, 0, sizeof(ppp_config));

          /* Start PPP to the data stream. */

          ppp_config.ctx = ctx;

#if 0
          ppp_config.eap_md5_client = 1;
          ppp_config.pap_client = 1;
#endif
          ppp_config.chap_client = 1;

          ppp_config.ipcp = 1;
          ppp_config.frame_mode = SSH_PPP_MODE_L2TP;

          ppp_config.name = "ssh";
          ppp_config.namelen = 3;

#if 0
          ssh_ipaddr_parse(&ppp_config.peer_ipv4_addr, "10.42.1.1");
#endif
          ssh_ipaddr_parse(&ppp_config.own_ipv4_addr,  "192.168.254.7");

          ppp_config.get_client_secret_cb       = init_ppp_get_c_secret;
          ppp_config.signal_cb                  = init_ppp_signal_cb;
          ppp_config.output_frame_cb            = init_ppp_output_cb;

          ctx->ppp = ssh_ppp_session_create(&ppp_config);
          if (ctx->ppp)
            ssh_ppp_boot(ctx->ppp);
        }

      /* And open sub-sessions. */
      for (i = 0; i < ctx->num_children; i++)
        {
          InitiatorSessionCtx nctx = ssh_xcalloc(1, sizeof(*ctx));

          nctx->l2tp = ctx->l2tp;
          nctx->l2tp_server = ctx->l2tp_server;
          /* No grandchildren. */

          if (ctx->lac)
            ssh_l2tp_lac_session_open(ctx->l2tp, ctx->l2tp_server,
                                      info->tunnel->local_id,
                                      ctx->addr, ctx->port,
                                      key, key_len, NULL,
                                      initiator_session_status_cb, nctx);
          else
            ssh_l2tp_lns_session_open(ctx->l2tp, ctx->l2tp_server,
                                      info->tunnel->local_id,
                                      ctx->addr, ctx->port,
                                      key, key_len, NULL,
                                      initiator_session_status_cb, nctx);
        }
      break;

    case SSH_L2TP_SESSION_TERMINATED:
      what = "terminated";
      num_sessions--;

      if (ctx->ppp)
        ssh_ppp_destroy(ctx->ppp);
      ssh_xfree(ctx->addr);
      ssh_xfree(ctx->port);
      ssh_xfree(ctx);
      break;

    case SSH_L2TP_SESSION_WAN_ERROR_NOTIFY:
      what = "received WEN";
      break;

    case SSH_L2TP_SESSION_SET_LINK_INFO:
      what = "received SLI";
      break;
    }

  if (info)
    SSH_DEBUG(SSH_D_ERROR,
              ("Session %5d of tunnel %s:%s %5d %s, #t=%u, #s=%u "
               "(result=%d, error=%d)",
               info->local_id,
               info->tunnel->remote_addr,
               info->tunnel->remote_port,
               info->tunnel->local_id,
               what,
               num_tunnels, num_sessions,
               info->result_code, info->error_code));

#if 0
  if (info->result_code)
    SSH_DEBUG(SSH_D_ERROR,
              ("Reason: %s - %s (%d %d)",
               ssh_find_keyword_name(ssh_l2tp_session_result_codes,
                                     info->result_code),
               ssh_find_keyword_name(ssh_l2tp_error_codes,
                                     info->error_code),
               info->result_code, info->error_code));
#endif
}


static void
l2tp_shutdown(void *context)
{
  ssh_l2tp_shutdown(l2tp, NULL, NULL);
}


static void
l2tp_destroy(void *context)
{
  ssh_l2tp_destroy(l2tp, NULL, NULL);
}


















static SshL2tpServer
get_server(void)
{
  static SshL2tpServer l2tp_global_server = NULL;
  SshL2tpServer server;
  static SshUInt32 initiator_port = 0;

  if (float_initiator_port)
    {
      char buf[16];

      if (initiator_port == 0)
        {
          if (port)
            initiator_port = atoi(port);
          else
            initiator_port = 1701;
        }
      ssh_snprintf(buf, sizeof(buf), "%d", initiator_port++);
      server = ssh_l2tp_server_start(l2tp, address, buf);
    }
  else
    {
      if (l2tp_global_server == NULL)
        l2tp_global_server = ssh_l2tp_server_start(l2tp, address, port);

      server = l2tp_global_server;
    }

  if (server == NULL)
    {
      fprintf(stderr, "%s: could not start L2TP server\n", program);
      exit(1);
    }

  return server;
}


int
main(int argc, char *argv[])
{
  int opt, i;
  SshL2tpParamsStruct params = {0};

  ssh_global_init();
  if (ssh_crypto_library_initialize() != SSH_CRYPTO_OK)
    {
      ssh_warning("Could not initialize the crypto library.");
      exit(1);
    }

  program = strrchr(argv[0], '/');
  if (program)
    program++;
  else
    program = argv[0];

  while ((opt = ssh_getopt(argc, argv, "0a:D:f:FhH:k:m:p:Ps:S:t:T:z:Z:", NULL))
         != EOF)
    {
      switch (opt)
        {
        case '0':
          exit_value = 0;
          break;

        case 'a':
          address = ssh_optarg;
          break;

        case 'D':
          ssh_debug_set_level_string(ssh_optarg);
          break;

        case 'f':
          float_port = ssh_optarg;
          break;

        case 'F':
          float_initiator_port = TRUE;
          break;

        case 'h':
          usage();
          exit(0);
          break;

        case 'H':
          params.hello_timer = atoi(ssh_optarg);
          break;

        case 'k':
          key = ssh_optarg;
          key_len = strlen(key);
          break;

        case 'm':
          params.max_tunnels = atoi(ssh_optarg);
          break;

        case 'p':
          port = ssh_optarg;
          break;

        case 'P':
          no_ppp = TRUE;
          break;

        case 's':
          make_num_sessions = atoi(ssh_optarg);
          break;

        case 'S':
          make_num_tunnels = atoi(ssh_optarg);
          break;

        case 't':
          session_timeout = atoi(ssh_optarg);
          break;

        case 'T':
          tunnel_timeout = atoi(ssh_optarg);
          break;

        case 'z':
          l2tp_shutdown_timeout = atoi(ssh_optarg);
          break;

        case 'Z':
          l2tp_destroy_timeout = atoi(ssh_optarg);
          break;
        }
    }

  ssh_event_loop_initialize();










  l2tp = ssh_l2tp_create(&params,
                         tunnel_request_cb,
                         responder_tunnel_status_cb,
                         session_request_cb,
                         responder_session_status_cb,
                         NULL,
                         NULL);
  if (l2tp == NULL)
    {
      fprintf(stderr, "%s: could not create L2TP module\n", program);
      exit(exit_value);
    }

  if (ssh_optind >= argc)
    /* Create a server object for the responder. */
    (void) get_server();

  for (i = ssh_optind; i < argc; i++)
    {
      char *arg = ssh_xstrdup(argv[i]);
      char *addr;
      char *port;
      SshUInt32 n;

      addr = strchr(arg, ':');
      if (addr == NULL)
        {
        malformed_argument:
          fprintf(stderr, "%s: malformed argument `%s'\n", program, arg);
          exit(1);
        }
      *addr = '\0';
      addr++;

      port = strchr(addr, ':');
      if (port)
        {
          *port = '\0';
          port++;
        }
      else
        {
          port = "1701";
        }

      if (strcmp(arg, "lns") == 0)
        {
          for (n = 0; n < make_num_tunnels; n++)
            {
              SshOperationHandle h;
              InitiatorSessionCtx ctx = ssh_xcalloc(1, sizeof(*ctx));

              ctx->l2tp = l2tp;
              ctx->l2tp_server = get_server();;
              ctx->lac = TRUE;
              ctx->num_children = make_num_sessions - 1;
              ctx->addr = ssh_xstrdup(addr);
              ctx->port = ssh_xstrdup(port);

              h = ssh_l2tp_lac_session_open(l2tp, ctx->l2tp_server,
                                            0, addr, port, key, key_len,
                                            NULL,
                                            initiator_session_status_cb, ctx);
              if (h && session_timeout > -1)
                {
                  ctx->handle = h;

                  ssh_xregister_timeout(session_timeout, 0,
                                       abort_session, ctx);
                }
            }
        }
      else if (strcmp(arg, "lac") == 0)
        {
          for (n = 0; n < make_num_tunnels; n++)
            {
              InitiatorSessionCtx ctx = ssh_xcalloc(1, sizeof(*ctx));

              ctx->l2tp = l2tp;
              ctx->lac = FALSE;
              ctx->num_children = make_num_sessions - 1;
              ctx->addr = ssh_xstrdup(addr);
              ctx->port = ssh_xstrdup(port);

              ssh_l2tp_lns_session_open(l2tp, get_server(),
                                        0, addr, port, NULL, 0, NULL,
                                        initiator_session_status_cb, ctx);
            }
        }
      else
        {
          goto malformed_argument;
        }

      ssh_xfree(arg);
    }

  if (l2tp_shutdown_timeout)
    ssh_xregister_timeout(l2tp_shutdown_timeout, 0,
                         l2tp_shutdown, NULL);

  if (l2tp_destroy_timeout)
    ssh_xregister_timeout(l2tp_destroy_timeout, 0,
                         l2tp_destroy, NULL);

  ssh_event_loop_run();
  ssh_name_server_uninit();
  ssh_event_loop_uninitialize();

  ssh_crypto_library_uninitialize();
  ssh_util_uninit();
  return 0;
}


/************************** Static help functions ***************************/

static void
usage(void)
{
  fprintf(stdout, "\
Usage: %s [OPTION]... [lac:ADDRESS[:PORT]]... [lns:ADDRESS[:PORT]]\n\
  -0                    exit with status 0 if L2TP library call fails\n\
  -a ADDRESS            local address to bind to\n\
  -D LEVEL              set debug level string to LEVEL\n\
  -f PORT               float receiver port to PORT\n\
  -F                    float initiator port.  The floating is started\n\
                        from the port local port (-p PORT) and increased\n\
                        by one for each tunnel (-S TUNNELS)\n\
  -h                    print this help and exit\n\
  -H TIME               send Hello messages after TIME seconds of\n\
                        inactivity\n\
  -k KEY                shared secret between LAC and LNS\n\
  -m MAX_TUNNELS        the maximum number of tunnels allowed\n\
  -p PORT               local UDP port\n\
  -P                    no PPP\n\
  -s SESSIONS           sessions per tunnel\n\
  -S TUNNELS            number of tunnels to create for each destination\n\
  -t TIMEOUT            destroy sessions after TIMEOUT seconds\n\
  -T TIMEOUT            destroy tunnels after TIMEOUT seconds\n\
  -z TIMEOUT            shutdown the L2TP server after TIMEOUT seconds\n\
  -Z TIMEOUT            destroy the L2TP server after TIMEOUT seconds\n\
",
          program);

  fprintf(stdout, "\nReport bugs to mtr@ssh.fi.\n");
}
