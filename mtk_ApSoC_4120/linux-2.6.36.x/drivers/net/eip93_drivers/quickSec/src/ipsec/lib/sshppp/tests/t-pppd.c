/*
  Author: Lauri Tarkkala <ltarkkal@ssh.fi>

  Copyright:
          Copyright (c) 2002, 2003 SFNT Finland Oy.
  All Rights Reserved.
*/

#define SSH_DEBUG_MODULE "SshPppPppd"

#include "sshincludes.h"

#include "ssheloop.h"
#include "sshfsm.h"
#include "sshstream.h"
#include "sshdevicestream.h"
#include "sshinet.h"
#include "sshgetopt.h"
#include "sshfdstream.h"
#include "sshtimeouts.h"
#include "sshbuffer.h"
#include "sshcrypt.h"
#include "sshglobals.h"
#include "sshnameserver.h"






#ifdef SSHDIST_RADIUS
#include "sshradius.h"
#endif /* SSHDIST_RADIUS */

#ifdef SSHDIST_EAP
#include "ssheap.h"
#endif /* SSHDIST_EAP */

#include "../sshppp.h"

#include <signal.h>

#ifdef HAVE_LINUX_PROC

#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif /* HAVE_SYS_TIME_H */

#ifdef HAVE_SYS_RESOURCE_H
#include <sys/resource.h>
#endif /* HAVE_SYS_RESOURCE_H */

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif /* HAVE_UNISTD_H */

#endif HAVE_LINUX_PROC

#define SSH_PPP_STRBUFSIZE 256






static char server_secret_buf[SSH_PPP_STRBUFSIZE];
static char client_secret_buf[SSH_PPP_STRBUFSIZE];
static char client_new_secret_buf[SSH_PPP_STRBUFSIZE];
static char system_name_buf[SSH_PPP_STRBUFSIZE];

static long server_token_fail_count = 0;
static long server_token_fail_max = 0;

static long client_token_fail_count = 0;
static long client_token_fail_max = 0;

static long server_secret_length = 0;
static long server_salt_length = 0;
static long client_new_secret_length = 0;
static long client_secret_length = 0;
static long client_salt_length = 0;
static unsigned long system_name_length = 0;

static char *program;


struct SshPPPTestPlaceHolder
{
  SshPPPHandle ppp;
  SshStream stream;
  SshUInt8* buf;
  unsigned long size;
  unsigned long len;
  struct SshPppParamsRec config;
  int reneg_counter;
  Boolean more_options;
  char *radius_url;
  char** argv;
  int argc;
#ifdef SSHDIST_RADIUS
  SshPppRadiusConfigurationStruct radius_config;
#ifdef SSHDIST_EAP
  SshEapRadiusConfigurationStruct eap_radius_config;
#endif /* SSHDIST_EAP */
#endif /* SSHDIST_RADIUS */
} placeholder;

static int link_up_secs = -1;

#ifdef HAVE_LINUX_PROC
static unsigned int vsize_before_session_create;
static unsigned int vsize_after_ppp_boot;
static unsigned int vsize_at_ipcp_up;
#endif

static void parse_args(SshPppParams);

static void
usage(int i)
{
  fprintf(stdout, "\
Usage: %s [OPTION] ...\n\
   -D LEVEL           set debug level string to LEVEL\n\
   -h                 print this help and exit\n\
   -H                 use HDLC framing instead of the <size><packet> format\n\
   -E                 negotiate PPPoE framing options\n\
   -N NUMBER          how many times to renegotiate the link\n\
   -m                 enable use of magic option in LCP\n\
   -Q                 do not specify IP in initial IPCP Configure Req\n\
   -p IP              IP is the IPv4 address to suggest to peer,\n\
                      if peer queries\n\
   -P IP              IP is the IPv4 address to require from peer\n\
                      (also set by -p <IP>)\n\
   -i IP              IP is the IPv4 address to request for this instance\n\
   -I IP              IP is the IPv4 address which the peer MUST propose \n\
                      to this instance\n\
   -n NAME            set system name to NAME\n\
   -l                 Dynamically allocate message buffers on demand\n\
   -u TIME            Do not halt the connection after IPCP has configured\n\
                      the link for TIME seconds\n\
                      If TIME is 0, the link is not halted at all\n\
   -s SECRET          set server-side secret to SECRET\n\
   -c SECRET          set client-side secret to SECRET\n\
   -w SECRET          set new client-side secret to SECRET\n\
   -f COUNT           client inputs NULL password after COUNT get_secret\n\
                      requests\n\
   -F COUNT           server inputs NULL password after COUNT get_secret\n\
                      requests\n\
   -S                 set server-side secret to NULL\n\
   -C                 set client-side secret to NULL\n\
   -1                 enable PAP authentication server\n\
   -2                 enable PAP authentication client\n\
   -3                 enable CHAP authentication server\n\
   -4                 enable CHAP authentication client\n\
   -5                 enable EAP-MD5 authentication server\n\
   -6                 enable EAP-MD5 authentication client\n"






"\
   -9                 enable MS-CHAP v1 authentication server\n\
   -0                 enable MS-CHAP v1 authentication client\n\
   -a                 enable MS-CHAP v2 authentication server\n\
   -A                 enable MS-CHAP v2 authentication client\n\
   -r URL             RADIUS server to use, in the form of a RADIUS URL\n\
   -X                 Options used after this option will take effect in\n\
                      first renegotiation\n\
",
          program);
  fprintf(stdout,"\nReport bugs to ltarkkal@ssh.fi\n");
  exit(i);
}

unsigned int
get_vsize(void)
{
#ifdef HAVE_LINUX_PROC
  char buf[1024];
  int pid;
  int len;
  int proc_stat_fd ;
  unsigned int vsize;
  unsigned rss;


  pid = getpid();
  ssh_snprintf(buf,1024,"/proc/%d/stat",pid);
  proc_stat_fd = open(buf,O_RDONLY,0);

  if (proc_stat_fd != -1)
    {
      len = read(proc_stat_fd,buf,1024);
      if (len > 0)
        {
          vsize = rss = 0;
          sscanf(buf,
                 "%*d %*s %*c %*d %*d %*d %*d %*d %*u %*u %*u"
                 "%*u %*u %*d %*d %*d %*d %*d %*d %*u %*u %*d %u %u %*u",
                 &vsize,&rss);
          close(proc_stat_fd);
          return vsize;
        }
      close(proc_stat_fd);
    }
#endif
  return 0;
}

static char*
auth_type_to_string(SshPppAuthType t)
{
  switch (t) {
  case SSH_PPP_AUTH_CHAP:
    return "CHAP";
#ifdef SSHDIST_EAP
  case SSH_PPP_AUTH_EAP:
    return "EAP";
  case SSH_PPP_AUTH_EAP_ID:
    return "EAP-ID";
#endif /* SSHDIST_EAP */
  case SSH_PPP_AUTH_PAP:
    return "PAP";
  case SSH_PPP_AUTH_MSCHAPv1:
    return "MS-CHAPv1";
  case SSH_PPP_AUTH_MSCHAPv2:
    return "MS-CHAPv2";
  case SSH_PPP_AUTH_MSCHAP_CHPWv2:
    return "MS-CHAP CPWv2";
  case SSH_PPP_AUTH_MSCHAP_CHPWv3:
    return "MS-CHAP CPWv3";
  default:
    SSH_NOTREACHED;
  }
  return "none";
}

#ifdef SSHDIST_EAP
static void
get_server_token(SshPPPHandle ppp,
                 SshPppAuthType auth_type,
                 SshUInt8 eap_type,
                 SshEapTokenType tok_type,
                 void *user_ctx,
                 void *ppp_ctx,
                 SshUInt8 *name,
                 SshUInt32 namelen)
{
  SshEapTokenStruct eap_token;






  if (server_token_fail_count >= server_token_fail_max)
    {
      server_token_fail_count = 0;
    }
  else
    {
      SSH_DEBUG(SSH_D_NICETOKNOW,("failing token request.."));
      server_token_fail_count++;
      return;
    }


  switch (tok_type)
    {
    case SSH_EAP_TOKEN_SHARED_SECRET:
      if (server_secret_length >= 0)
        ssh_eap_init_token_secret(&eap_token,
                                  server_secret_buf, server_secret_length);
      else
        ssh_eap_init_token_secret(&eap_token, NULL, 0);
      break;




















#if 0
    case SSH_EAP_TOKEN_USERNAME:
      if (system_name_length >= 0)
        ssh_eap_init_token_username(&eap_token,
                                    name, namelen);
      else
        ssh_eap_init_token_username(&eap_token, NULL, 0);
      break;
#endif
    case SSH_EAP_TOKEN_COUNTER32:
    case SSH_EAP_TOKEN_NONE:
    default:
      SSH_NOTREACHED;
    }

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("returning server token of type %d",tok_type));

  ssh_ppp_return_token(ppp, eap_type, ppp_ctx, &eap_token);





}

static void
get_client_token(SshPPPHandle ppp,
                 SshPppAuthType auth_type,
                 SshUInt8 eap_type,
                 SshEapTokenType tok_type,
                 void *user_ctx,
                 void *ppp_ctx,
                 SshUInt8 *name,
                 SshUInt32 namelen)
{
  SshEapTokenStruct eap_token;






  if (client_token_fail_count >= client_token_fail_max)
    {
      client_token_fail_count = 0;
    }
  else
    {
      SSH_DEBUG(SSH_D_NICETOKNOW,("failing token request.."));
      client_token_fail_count++;
      return;
    }

  switch (tok_type)
    {
    case SSH_EAP_TOKEN_SHARED_SECRET:
      if (client_secret_length >= 0)
        ssh_eap_init_token_secret(&eap_token,
                                  client_secret_buf,
                                  client_secret_length);
      else
        ssh_eap_init_token_secret(&eap_token, NULL, 0);

      break;




















#if 0
    case SSH_EAP_TOKEN_USERNAME:
      if (system_name_length >= 0)
        ssh_eap_init_token_username(&eap_token,
                                    system_name_buf, system_name_length);
      else
        ssh_eap_init_token_username(&eap_token, NULL, 0);
      break;
#endif
    case SSH_EAP_TOKEN_COUNTER32:
    case SSH_EAP_TOKEN_NONE:
    default:
      SSH_NOTREACHED;
    }

  ssh_ppp_return_token(ppp, eap_type, ppp_ctx, &eap_token);





}
#endif /* SSHDIST_EAP */

static void
get_server_secret(SshPPPHandle ppp,
                  SshPppAuthType auth_type,
                  void* user_ctx,
                  void* ppp_ctx,
                  SshUInt8* name,
                  SshUInt32 len)
{
  char buf[256];

  if (len == 0 || name == NULL) {
    name = "(null)";
  }

  if (len > 255)
    {
      len = 255;
    }

  memcpy(buf,name,len);
  buf[len] = '\0';

#ifdef SSHDIST_EAP
  if (auth_type == SSH_PPP_AUTH_EAP_ID)
    {
      ssh_ppp_return_secret(ppp, ppp_ctx, NULL, 0);
      return;
    }
#endif /* SSHDIST_EAP */

  SSH_DEBUG(SSH_D_HIGHOK,
            ("*** SERVER AUTH PROTOCOL: %s", auth_type_to_string(auth_type)));

  if (server_token_fail_max != 0)
    {
      if (server_token_fail_count >= server_token_fail_max)
        {
          server_token_fail_count = 0;
          ssh_ppp_return_secret(ppp, ppp_ctx, NULL, 0);
          return;
        }
      else
        {
          server_token_fail_count++;
        }
    }

  SSH_DEBUG(SSH_D_HIGHOK,
            ("returning server secret for name %s len %d",buf,len));

  if (server_secret_length >= 0)
    {
      ssh_ppp_return_secret(ppp, ppp_ctx,
                            (SshUInt8*)server_secret_buf,
                            server_secret_length);
    }
  else
    {
      ssh_ppp_return_secret(ppp, ppp_ctx, NULL, 0);
    }
}

static void
get_client_secret(SshPPPHandle ppp,
                  SshPppAuthType auth_type,
                  void* user_ctx,
                  void* ppp_ctx,
                  SshUInt8* name,
                  SshUInt32 len)
{
  char buf[1024];

  if (len == 0 || name == NULL) {
    name = "(null)";
  }

  if (len >= 1024)
    {
      len = 1023;
    }

  memcpy(buf,name,len);
  buf[len] = '\0';

  SSH_DEBUG(SSH_D_HIGHOK,("*** CLIENT AUTH PROTOCOL: %s",
                          auth_type_to_string(auth_type)));

  if (client_token_fail_max != 0)
    {
      if (client_token_fail_count >= client_token_fail_max)
        {
          client_token_fail_count = 0;
          ssh_ppp_return_secret(ppp, ppp_ctx, NULL, 0);
          return;
        }
      else
        {
          client_token_fail_count++;
        }
    }

  SSH_DEBUG(SSH_D_HIGHOK,
            ("returning client secret for name %s len %d",buf,len));

  if (auth_type != SSH_PPP_AUTH_MSCHAP_CHPWv2
       && auth_type != SSH_PPP_AUTH_MSCHAP_CHPWv3)
    {
      if (client_secret_length >= 0)
        {
          ssh_ppp_return_secret(ppp, ppp_ctx, (SshUInt8*)client_secret_buf,
                                client_secret_length);
        }
      else
        {
          ssh_ppp_return_secret(ppp, ppp_ctx, NULL, 0);
        }
    }
  else
    {
      if (client_new_secret_length >= 0)
        {
          ssh_ppp_return_secret(ppp, ppp_ctx,
                                (SshUInt8*)client_new_secret_buf,
                                client_new_secret_length);
          memcpy(client_secret_buf,client_new_secret_buf,
                 client_new_secret_length);
          client_secret_length = client_new_secret_length;
        }
      else
        {
          ssh_ppp_return_secret(ppp, ppp_ctx, NULL, 0);
        }
    }
}

static void chap_client_auth_ok(void* ctx)
{
  SSH_DEBUG(SSH_D_HIGHOK,("*** CLIENT AUTH OK"));
}

static void chap_client_auth_fail(void* ctx)
{
  SSH_DEBUG(SSH_D_FAIL,("*** CLIENT AUTH FAIL"));
}

static void chap_server_auth_ok(void* ctx)
{
  SSH_DEBUG(SSH_D_HIGHOK,("*** SERVER AUTH OK"));
}

static void chap_server_auth_fail(void* ctx)
{
  SSH_DEBUG(SSH_D_FAIL,("*** SERVER AUTH FAIL"));
}

static void
take_link_down(void* ctx)
{
  struct SshPPPTestPlaceHolder* ph;

  ph = (struct SshPPPTestPlaceHolder*)ctx;

  if (ph->reneg_counter > 0)
    {
      ph->reneg_counter--;

      SSH_DEBUG(SSH_D_HIGHOK,("****"));
      SSH_DEBUG(SSH_D_HIGHOK,("**** Forcing renegotiation of link"));
      SSH_DEBUG(SSH_D_HIGHOK,("****"));

      if (ph->more_options == TRUE)
        {
          parse_args(&ph->config);
        }
      ssh_ppp_renegotiate(ph->ppp,&ph->config);
    }
  else
    {
      ssh_ppp_halt(ph->ppp);
    }
}

static void ipcp_down(void* ctx)
{
  SSH_DEBUG(SSH_D_HIGHOK,("**** IPCP DOWN"));
}

static void ipcp_up(void* ctx)
{
  struct SshPPPTestPlaceHolder* ph;
  SshPPPHandle ppp;
  SshIpAddrStruct own_ip;
  SshIpAddrStruct peer_ip;

  ph = (struct SshPPPTestPlaceHolder*)ctx;
  ppp = ph->ppp;

  ssh_ppp_get_ipcp_peer_ip(ppp,&peer_ip);
  ssh_ppp_get_ipcp_own_ip(ppp,&own_ip);

#if 1







#endif

  SSH_DEBUG(SSH_D_HIGHOK,("**** IPCP: peer ip %@ own ip %@",
                          ssh_ipaddr_render, &peer_ip,
                          ssh_ipaddr_render, &own_ip));
  SSH_DEBUG(SSH_D_HIGHOK,("**** IPCP UP"));
#ifdef HAVE_LINUX_PROC
  vsize_at_ipcp_up = get_vsize();
#endif

  if (link_up_secs == -1)
    {
      take_link_down(ctx);
    }
  else if (link_up_secs > 0)
    {
      ssh_xregister_timeout(link_up_secs,0,&take_link_down,&placeholder);
    }
}

static void input_callback(void* ctx)
{
  struct SshPPPTestPlaceHolder* ph;
  int ret;
  SshUInt32 len;

  ph = (struct SshPPPTestPlaceHolder*)ctx;

  if (ph->stream == NULL)
    {
      return;
    }

  if (ph->buf == NULL)
    {
      ph->buf = ssh_xmalloc(1024);
      ph->size = 1024;
      ph->len = 0;
    }

  if (ph->len < 4)
    {
      ret = ssh_stream_read(ph->stream,
                            ph->buf + ph->len,
                            4 - ph->len);

      if (ret > 0)
        {
          ph->len += ret;
        }
    }

  if (ph->len >= 4)
    {
      len = SSH_GET_32BIT(ph->buf);
      ret = ssh_stream_read(ph->stream,
                            ph->buf + ph->len,
                            len - ph->len + 4);

      if (ret > 0)
        {
          ph->len += ret;
        }

    if (ph->len == (len+4))
      {
        SSH_DEBUG(5,("input_callback"));
        ssh_ppp_frame_input(ph->ppp, ph->buf, 4, len);
        ph->buf = NULL;
      }
    }
  ssh_xregister_timeout(0, 500000, input_callback, &placeholder);
}

static void ppp_halt(void* ctx)
{
  SshPPPHandle ppp;
  struct SshPPPTestPlaceHolder* ph;

  ph = (struct SshPPPTestPlaceHolder*)ctx;

  ppp = ph->ppp;

  ssh_ppp_destroy(ppp);
  if (ph->stream != NULL)
    {
      ssh_stream_destroy(ph->stream);
      ph->stream = NULL;
    }
#ifdef SSHDIST_RADIUS
  ssh_radius_client_server_info_destroy(ph->radius_config.servers);
  ssh_radius_client_destroy(ph->radius_config.client);
  ssh_radius_url_destroy_avpset(ph->radius_config.default_avps);
#endif /* SSHDIST_RADIUS */

  ph->ppp = NULL;
}

static void
ssh_ppp_pppd_output_cb(SshPPPHandle ppp,
                       void* ctx,
                       SshUInt8* buffer,
                       unsigned long offset,
                       unsigned long length)
{
  struct SshPPPTestPlaceHolder* ph;
  SshUInt8 buf[4];


  ph = (struct SshPPPTestPlaceHolder*)ctx;

  buf[0] = (length >> 24) & 0xFF;
  buf[1] = (length >> 16) & 0xFF;
  buf[2] = (length >>  8) & 0xFF;
  buf[3] = (length >>  0) & 0xFF;

  ssh_stream_write(ph->stream, buf,4);
  ssh_stream_write(ph->stream, buffer+offset,length);

  ssh_xfree(buffer);
}

static void
signal_router(void* ctx, SshPppSignal sig)
{
  struct SshPPPTestPlaceHolder* ph;

  ph = (struct SshPPPTestPlaceHolder*)ctx;

  switch (sig)
    {
    case SSH_PPP_SIGNAL_LCP_UP:
      SSH_DEBUG(SSH_D_HIGHOK,
                ("********* LCP input:  PFC %s ACFC %s ACCM 0x%08x MRU %5d",
                 (ssh_ppp_get_lcp_input_pfc(ph->ppp) ? " ON" : "OFF"),
                 (ssh_ppp_get_lcp_input_acfc(ph->ppp) ? " ON" : "OFF"),
                 ssh_ppp_get_lcp_input_accm(ph->ppp),
                 ssh_ppp_get_lcp_input_mru(ph->ppp)));

      SSH_DEBUG(SSH_D_HIGHOK,
                ("********* LCP output: PFC %s ACFC %s ACCM 0x%08x MRU %5d",
                 (ssh_ppp_get_lcp_output_pfc(ph->ppp) ? " ON" : "OFF"),
                 (ssh_ppp_get_lcp_output_acfc(ph->ppp) ? " ON" : "OFF"),
                 ssh_ppp_get_lcp_output_accm(ph->ppp),
                 ssh_ppp_get_lcp_output_mru(ph->ppp)));


      SSH_DEBUG(SSH_D_HIGHOK,("********* LCP UP"));
      break;

    case SSH_PPP_SIGNAL_LCP_DOWN:
      SSH_DEBUG(SSH_D_HIGHOK,("*********"));
      SSH_DEBUG(SSH_D_HIGHOK,("********* LCP DOWN *********"));
      SSH_DEBUG(SSH_D_HIGHOK,("*********"));
      break;

    case SSH_PPP_SIGNAL_IPCP_UP:
      ipcp_up(ctx);
      break;

    case SSH_PPP_SIGNAL_IPCP_DOWN:
      ipcp_down(ctx);
      break;

    case SSH_PPP_SIGNAL_IPCP_FAIL:
      break;

    case SSH_PPP_SIGNAL_PPP_HALT:
      SSH_DEBUG(SSH_D_FAIL,("**** PPP HALT!"));
      ppp_halt(ctx);
      break;
    case SSH_PPP_SIGNAL_SERVER_AUTH_FAIL:
      chap_server_auth_fail(ctx);
      break;
    case SSH_PPP_SIGNAL_SERVER_AUTH_OK:
      chap_server_auth_ok(ctx);
      break;
    case SSH_PPP_SIGNAL_CLIENT_AUTH_FAIL:
      chap_client_auth_fail(ctx);
      break;
    case SSH_PPP_SIGNAL_CLIENT_AUTH_OK:
      chap_client_auth_ok(ctx);
      break;
    case SSH_PPP_SIGNAL_FATAL_ERROR:
      SSH_DEBUG(SSH_D_FAIL,("**** FATAL ERROR"));
      ppp_halt(ctx);
      break;

    default:
      SSH_NOTREACHED;
    }
}

static void
sig_handler(int signum, void *ctx)
{
  struct SshPPPTestPlaceHolder* ph;

  SSH_DEBUG(SSH_D_HIGHOK, ("received signal %d", signum));

  ph = (struct SshPPPTestPlaceHolder*)ctx;

  switch (signum)
    {
    case SIGUSR1:
      if (ph->ppp != NULL)
        {
          ssh_ppp_renegotiate(ph->ppp,&ph->config);
        }
      break;
    case SIGPIPE:
      SSH_DEBUG(SSH_D_HIGHOK,("received SIGPIPE"));
      break;
    }
}

#ifdef SSHDIST_RADIUS
static Boolean
parse_radius(char *url)
{
  SshRadiusClientParamsStruct params;
  SshRadiusUrlStatus url_status;

  memset(&placeholder.radius_config, 0,
         sizeof(SshPppRadiusConfigurationStruct));

  memset(&placeholder.eap_radius_config, 0,
         sizeof(SshEapRadiusConfigurationStruct));

  memset(&params, 0, sizeof(params));

  if (url == NULL)
    return TRUE;

  url_status = ssh_radius_url_init_params(&params, url);

  if (url_status != SSH_RADIUS_URL_STATUS_SUCCESS)
    {
      SSH_DEBUG(SSH_D_FAIL,("error initializing radius client params"));
      goto fail;
    }

  placeholder.radius_config.client=ssh_radius_client_create(&params);
  ssh_radius_url_uninit_params(&params);

  if (placeholder.radius_config.client == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL,("error creating RADIUS client"));
      goto fail;
    }

  placeholder.radius_config.servers=ssh_radius_client_server_info_create();

  placeholder.radius_config.require_service_ppp = TRUE;
  placeholder.radius_config.use_framed_ip_address = TRUE;
  placeholder.radius_config.honor_radius_mtu = TRUE;

  if (placeholder.radius_config.servers == NULL)
    goto fail;

  url_status = ssh_radius_url_add_server(placeholder.radius_config.servers,
                                         url);

  if (url_status != SSH_RADIUS_URL_STATUS_SUCCESS)
    goto fail;

  url_status = ssh_radius_url_create_avpset(
                                 &placeholder.radius_config.default_avps,
                                 url);

  if (url_status != SSH_RADIUS_URL_STATUS_SUCCESS)
    goto fail;

  placeholder.radius_config.eap_radius_config = &placeholder.eap_radius_config;

  placeholder.eap_radius_config.radius_client =
    placeholder.radius_config.client;

  placeholder.eap_radius_config.radius_servers =
    placeholder.radius_config.servers;

  placeholder.eap_radius_config.default_avps =
    placeholder.radius_config.default_avps;

  return TRUE;

 fail:
  if (placeholder.radius_config.servers != NULL)
    ssh_radius_client_server_info_destroy(placeholder.radius_config.servers);

  if (placeholder.radius_config.client != NULL)
    ssh_radius_client_destroy(placeholder.radius_config.client);

  return FALSE;

}
#endif /* SSHDIST_RADIUS */

static void
parse_args(SshPppParams config)
{
  Boolean delim;
  int opt;
  SshPPPFrameOutputCB output_frame_cb;
#ifdef SSHDIST_RADIUS
  SshRadiusUrlStatus url_status;
  const char *str;
#endif /* SSHDIST_RADIUS */

  output_frame_cb = config->output_frame_cb;

  memset(config,0,sizeof(struct SshPppParamsRec));

  config->ipcp = 1;
  config->frame_mode = SSH_PPP_MODE_L2TP;
  config->no_magic_lcp = 1;
  config->query_without_ip = 0;

  config->ctx = &placeholder;
  config->signal_cb = signal_router;

  config->output_stream = NULL;
  config->input_stream = NULL;
  config->output_frame_cb = NULL_FNPTR;

  config->get_client_secret_cb = get_client_secret;
  config->get_server_secret_cb = get_server_secret;
  config->get_client_eap_token_cb = get_client_token;
  config->get_server_eap_token_cb = get_server_token;

  server_secret_length = -1;
  client_secret_length = -1;
  client_new_secret_length = -1;

  server_token_fail_count = 0;
  client_token_fail_count = 0;
  server_token_fail_max = 0;
  client_token_fail_max = 0;

  server_salt_length = -1;
  client_salt_length = -1;

  placeholder.more_options = FALSE;
  placeholder.radius_url = NULL;

  delim = FALSE;

  while ((opt = ssh_getopt(placeholder.argc,
                           placeholder.argv,
                           "r:D:s:c:w:n:i:p:I:P:u:f:F:Y:N:hHEmjl"
                           "1234567890aAQSCX",NULL)) != EOF) {
    switch(opt) {
    case 'D':
      ssh_debug_set_level_string(ssh_optarg);
      break;
    case 'u':
      link_up_secs = strtol(ssh_optarg,0,0);
      break;
    case 'h':
      usage(0);
      break;
    case 'H':
      config->frame_mode = SSH_PPP_MODE_HLDC;
      break;
    case 'E':
      config->pppoe_framing = TRUE;
      break;
    case 'm':
      config->no_magic_lcp = 0;
      break;
    case '1':
      config->pap_server = TRUE;
      break;
    case '2':
      config->pap_client = TRUE;
      break;
    case '3':
      config->chap_server = TRUE;
      break;
    case '4':
      config->chap_client = TRUE;
      break;
    case '5':
      config->eap_md5_server = TRUE;
      break;
    case '6':
      config->eap_md5_client = TRUE;
      break;








    case '9':
      config->mschapv1_server = TRUE;
      break;
    case '0':
      config->mschapv1_client = TRUE;
      break;
    case 'a':
      config->mschapv2_server = TRUE;
      break;
    case 'A':
      config->mschapv2_client = TRUE;
      break;










    case 'S':
      server_secret_length = -1;
      break;
    case 's':
      server_secret_length = strlen(ssh_optarg);
      if (server_secret_length > SSH_PPP_STRBUFSIZE)
        {
          usage(1);
        }
      memcpy(server_secret_buf,ssh_optarg,server_secret_length);
      break;
    case 'C':
      client_secret_length = -1;
      break;
    case 'c':
      client_secret_length = strlen(ssh_optarg);
      if (client_secret_length > SSH_PPP_STRBUFSIZE)
        {
          usage(1);
        }
      memcpy(client_secret_buf,ssh_optarg,client_secret_length);
      break;
    case 'w':
      client_new_secret_length = strlen(ssh_optarg);
      if (client_new_secret_length > SSH_PPP_STRBUFSIZE)
        {
          usage(1);
        }
      memcpy(client_new_secret_buf,ssh_optarg,client_new_secret_length);
      break;
    case 'F':
      server_token_fail_max = strtol(ssh_optarg,0,0);
      break;
    case 'f':
      client_token_fail_max = strtol(ssh_optarg,0,0);
      break;
    case 'n':
      system_name_length = strlen(ssh_optarg);
      if (system_name_length > SSH_PPP_STRBUFSIZE)
        {
          usage(1);
        }
      memcpy(system_name_buf,ssh_optarg,system_name_length);
      config->name = (SshUInt8*)system_name_buf;
      config->namelen = system_name_length;
      break;
    case 'I':
      ssh_ipaddr_parse(&config->own_ipv4_netaddr,ssh_optarg);
      ssh_ipaddr_parse(&config->own_ipv4_mask,"255.255.255.255");
      break;
    case 'i':
      ssh_ipaddr_parse(&config->own_ipv4_addr,ssh_optarg);
      break;
    case 'p':
      ssh_ipaddr_parse(&config->peer_ipv4_addr,ssh_optarg);
      ssh_ipaddr_parse(&config->peer_ipv4_netaddr,ssh_optarg);
      ssh_ipaddr_parse(&config->peer_ipv4_mask,"255.255.255.255");
      break;
    case 'P':
      ssh_ipaddr_parse(&config->peer_ipv4_netaddr,ssh_optarg);
      ssh_ipaddr_parse(&config->peer_ipv4_mask,"255.255.255.255");
      break;
    case 'Q':
      config->query_without_ip = TRUE;
      break;
    case 'l':
      output_frame_cb = ssh_ppp_pppd_output_cb;
      break;
    case 'N':
      placeholder.reneg_counter = strtol(ssh_optarg,0,0);
      break;
    case 'X':
      delim = TRUE;
      placeholder.more_options = TRUE;
      break;
#ifdef SSHDIST_RADIUS
    case 'r':
      placeholder.radius_url = ssh_optarg;
      url_status = ssh_radius_url_isok(ssh_optarg);
      if (url_status != SSH_RADIUS_URL_STATUS_SUCCESS)
        {
          str = ssh_find_keyword_name(ssh_radius_url_status_codes,
                                      url_status);
          fprintf(stderr,
                  "%s: error parsing RADIUS url: %s\n",
                  program,
                  (str!=NULL?str:"unknown error"));

          exit(1);
        }
      break;
#endif /* SSHDIST_RADIUS */
    default:
      usage(1);
    }
    if (delim == TRUE)
      {
        break;
      }
  }

  config->output_frame_cb = output_frame_cb;
  SSH_DEBUG(SSH_D_MIDOK,("outputframecb 0x%08x",output_frame_cb));

  if (config->output_frame_cb == NULL)
    {
      config->input_stream = placeholder.stream;
      config->output_stream = placeholder.stream;
    }
}

int
main(int argc, char* argv[])
{
  SshPPPHandle ppp;
  SshPppParams config;

  /* Std initialization */

  program = strrchr(argv[0], '/');
  if (program)
    program++;
  else
    program = argv[0];

  ssh_event_loop_initialize();
  ssh_crypto_library_initialize();

  /* Create configuration for PPP session */

  ssh_debug_set_level_string("SshPpp*=15,SshRadius*=10,SshEap*=10");

  link_up_secs = -1;
  placeholder.reneg_counter = 0;
  placeholder.argv = argv;
  placeholder.argc = argc;
  placeholder.stream = ssh_stream_fd_stdio();

  config = &placeholder.config;
  config->output_frame_cb = NULL;

  parse_args(config);

#ifdef SSHDIST_RADIUS
  if (parse_radius(placeholder.radius_url) == FALSE)
    {
      fprintf(stderr,"%s: error parsing RADIUS url\n",program);
      return 1;
    }
#endif /* SSHDIST_RADIUS */

  ssh_register_signal(SIGUSR1,sig_handler,&placeholder);
  ssh_register_signal(SIGPIPE,sig_handler,&placeholder);

#ifdef HAVE_LINUX_PROC
  vsize_before_session_create = get_vsize();
#endif

  ppp = ssh_ppp_session_create(config);

  if (ppp == NULL)
    {
      fprintf(stderr, "%s: error creating PPP object\n",program);
      ssh_event_loop_uninitialize();
      return 1;
    }

  placeholder.ppp = ppp;

#ifdef SSHDIST_RADIUS
  if (placeholder.radius_config.client != NULL)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW,("attaching RADIUS configuration"));
      ssh_ppp_configure_radius(ppp, &placeholder.radius_config);
    }
#endif /* SSHDIST_RADIUS */

  SSH_DEBUG(SSH_D_HIGHOK,("*** BOOTING PPP"));

  ssh_ppp_boot(ppp);
#ifdef HAVE_LINUX_PROC
  vsize_after_ppp_boot = get_vsize();
#endif

  /* 3... 2... 1... Let's Jam */

  if (config->output_frame_cb != NULL)
    {
      ssh_xregister_timeout(0,500000,input_callback,&placeholder);
    }

 ssh_event_loop_run();

  if (placeholder.ppp != NULL)
    {
      ssh_ppp_destroy(placeholder.ppp);
    }

  if (placeholder.buf != NULL)
    {
      ssh_xfree(placeholder.buf);
      placeholder.buf = NULL;
    }

  if (placeholder.stream != NULL)
    {
      ssh_stream_destroy(placeholder.stream);
      placeholder.stream = NULL;
    }

  ssh_cancel_timeouts(take_link_down,&placeholder);

  ssh_event_loop_run();

  ssh_unregister_signal(SIGUSR1);
  ssh_unregister_signal(SIGPIPE);

  ssh_crypto_library_uninitialize();
  ssh_name_server_uninit();
  ssh_event_loop_uninitialize();

#ifdef HAVE_LINUX_PROC
  fprintf(stderr,"VSIZE before session create%u\n",
          vsize_before_session_create);
  fprintf(stderr,"VSIZE after session create %u\n", vsize_after_ppp_boot);
  fprintf(stderr,"VSIZE at IPCP up %u\n", vsize_at_ipcp_up);

  fprintf(stderr,"PPP session create cost: %u\n",
          vsize_after_ppp_boot - vsize_before_session_create);
  fprintf(stderr,"IPCP up cost: %u\n",vsize_at_ipcp_up - vsize_after_ppp_boot);
#endif

  ssh_util_uninit();
  return 0;
}
