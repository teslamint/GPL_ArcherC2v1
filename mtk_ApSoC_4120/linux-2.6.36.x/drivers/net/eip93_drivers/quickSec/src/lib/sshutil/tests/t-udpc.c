/*
 *
 * Author: Tuomas A. Sirén <tuomas.siren@iki.fi>
 *
 *  Copyright:
 *          Copyright (c) 2002, 2003 SFNT Finland Oy.
 */

#define SSH_DEBUG_MODULE "t-udpc"

#include "sshincludes.h"
#include "sshgetopt.h"
#include "ssheloop.h"
#include "sshudp.h"
#include "sshbuffer.h"
#include "sshtimeouts.h"
#include "sshinet.h"
#include "sshnameserver.h"

typedef struct t_udpc_context
{
  char*                   plocal_port_or_service;
  char*                   pport_or_service;
  char*                   phost_name_or_address;
  Boolean                 udp;
  SshUdpListener  pudplistener;
  unsigned short  size;
  unsigned int    timeout;
  char*                   pdata;
}* t_udpc_context;

void t_udpc_timeout_callback(void *context);
void t_udpc_udp_callback(SshUdpListener listener, void *context);

int main(int argc, char* argv[])
{
  t_udpc_context  pcontext = 0;
  SshGetOptData   pgetoptdata = 0;
  int                             i;

  SSH_TRACE(SSH_D_MY, ("%s", "main"));

  pcontext = ssh_xmalloc(sizeof (*pcontext));
  memset(pcontext, 0, sizeof (*pcontext));

  pgetoptdata = ssh_xmalloc(sizeof (*pgetoptdata));
  memset(pgetoptdata, 0, sizeof (*pgetoptdata));

  ssh_getopt_init_data(pgetoptdata);

  while ((i = ssh_getopt(argc, argv,
                         "l:p:h:s:d:D:G:t:", pgetoptdata)) != -1)
    {
      switch (i)
        {
        case 'p':
          pcontext->pport_or_service =
            ssh_xstrdup(pgetoptdata->arg);
          break;
        case 'l':
          pcontext->plocal_port_or_service =
            ssh_xstrdup(pgetoptdata->arg);
          break;
        case 'h':
          pcontext->phost_name_or_address =
            ssh_xstrdup(pgetoptdata->arg);
          break;
        case 's':
          pcontext->size = atoi(pgetoptdata->arg);
          break;
        case 'd':
          pcontext->pdata = ssh_xstrdup(pgetoptdata->arg);
          break;
        case 'D':
          ssh_debug_set_module_level(SSH_DEBUG_MODULE,
                                     atoi(pgetoptdata->arg));
          break;
        case 'G':
          ssh_debug_set_global_level(atoi(pgetoptdata->arg));
          break;
        case 't':
          pcontext->timeout = atoi(pgetoptdata->arg);
          break;
        default:
          SSH_NOTREACHED;
          break;
        }
    }

  ssh_xfree(pgetoptdata);

  ssh_event_loop_initialize();

  if (pcontext->phost_name_or_address)
    {
      pcontext->pudplistener =
        ssh_udp_make_listener(SSH_IPADDR_ANY_IPV4,
                              pcontext->plocal_port_or_service,
                              pcontext->phost_name_or_address,
                              pcontext->pport_or_service,
                              NULL,
                              t_udpc_udp_callback,
                              pcontext);

      ssh_xregister_timeout(pcontext->timeout,
                            0,
                            t_udpc_timeout_callback,
                            pcontext);
    }
  else
    {
      pcontext->pudplistener =
        ssh_udp_make_listener(SSH_IPADDR_ANY_IPV4,
                              pcontext->pport_or_service,
                              NULL,
                              NULL,
                              NULL,
                              t_udpc_udp_callback,
                              pcontext);
    }

  ssh_event_loop_run();
  ssh_name_server_uninit();
  ssh_event_loop_uninitialize();

  ssh_xfree(pcontext);
  ssh_util_uninit();
  return 0;
}

void t_udpc_timeout_callback(void *context)
{
  t_udpc_context  pcontext = context;

  SSH_TRACE(SSH_D_MY, ("%s", "t_udpc_timeout_callback"));

  ssh_udp_send(pcontext->pudplistener,
               pcontext->phost_name_or_address,
               pcontext->pport_or_service,
               pcontext->pdata,
               strlen(pcontext->pdata));

  ssh_xregister_timeout(pcontext->timeout,
                        0,
                        t_udpc_timeout_callback,
                        pcontext);
}

void t_udpc_udp_callback(SshUdpListener  listener,
                         void* context)
{
  t_udpc_context  pcontext = context;
  SshUdpError             error;
  char                    remote_address[4096];
  char                    remote_port[4096];
  char                    buf[4096];
  size_t                  i;

  SSH_TRACE(SSH_D_MY, ("%s", "t_udpc_udp_callback"));

  error = ssh_udp_read(pcontext->pudplistener,
                       remote_address,
                       4096,
                       remote_port,
                       4096,
                       buf,
                       4096,
                       &i);

  switch (error)
    {
    case SSH_UDP_OK:
      buf[i] = 0;
      SSH_TRACE(SSH_D_MY, ("read: %s", buf));
      if (pcontext->phost_name_or_address)
        {
          buf[i] = 0;
          SSH_TRACE(SSH_D_MY, ("read: %s", buf));
        }
      else
        {
          ssh_udp_send(pcontext->pudplistener,
                       remote_address,
                       remote_port,
                       buf,
                       i);
        }
      break;
    case SSH_UDP_HOST_UNREACHABLE:
      SSH_TRACE(SSH_D_MY, ("SSH_UDP_HOST_UNREACHABLE"));
      break;
    case SSH_UDP_PORT_UNREACHABLE:
      SSH_TRACE(SSH_D_MY, ("SSH_UDP_PORT_UNREACHABLE"));
      break;
    case SSH_UDP_NO_DATA:
      SSH_TRACE(SSH_D_MY, ("SSH_UDP_NO_DATA"));
      break;
    default:
      SSH_NOTREACHED;
      break;
    }
}
