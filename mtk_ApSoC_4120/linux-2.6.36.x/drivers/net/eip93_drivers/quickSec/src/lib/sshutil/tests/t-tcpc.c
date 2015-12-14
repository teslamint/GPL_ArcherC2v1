/*
 *
 * Author: Tuomas A. Sirén <tuomas.siren@iki.fi>
 *
 *  Copyright:
 *          Copyright (c) 2002, 2003 SFNT Finland Oy.
 */

#define SSH_DEBUG_MODULE "t-tcpc"

#include "sshincludes.h"
#include "sshgetopt.h"
#include "ssheloop.h"
#include "sshtcp.h"
#include "sshbuffer.h"
#include "sshtimeouts.h"
#include "sshnameserver.h"

typedef struct t_tcpc_context
{
  char*                   pport_or_service;
  char*                   phost_name_or_address;
  SshTcpListener  ptcplistener;
  unsigned int    timeout;
  SshStream               pstream;
  SshBuffer               pbuffer;
  char*                   pdata;
}* t_tcpc_context;

void t_tcpc_tcp_callback(SshTcpError     error,
                         SshStream       stream,
                         void*           context);
void t_tcpc_stream_callback(SshStreamNotification notification,
                            void *context);
void t_tcpc_timeout_callback(void *context);

int main(int argc, char* argv[])
{
  t_tcpc_context  pcontext = 0;
  SshGetOptData   pgetoptdata = 0;
  int                             i;

  SSH_TRACE(SSH_D_MY, ("%s", "main"));

  pcontext = ssh_xmalloc(sizeof (*pcontext));
  memset(pcontext, 0, sizeof (*pcontext));

  pgetoptdata = ssh_xmalloc(sizeof (*pgetoptdata));
  memset(pgetoptdata, 0, sizeof (*pgetoptdata));

  ssh_getopt_init_data(pgetoptdata);
  pcontext->pport_or_service = "23242";

  while ((i = ssh_getopt(argc, argv, "p:h:d:D:G:t:", pgetoptdata)) != -1)
    {
      switch (i)
        {
        case 'p':
          pcontext->pport_or_service = ssh_xstrdup(pgetoptdata->arg);
          break;
        case 'h':
          pcontext->phost_name_or_address = ssh_xstrdup(pgetoptdata->arg);
          break;
        case 'd':
          pcontext->pdata = ssh_xstrdup(pgetoptdata->arg);
          break;
        case 'D':
          ssh_debug_set_module_level(SSH_DEBUG_MODULE, atoi(pgetoptdata->arg));
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

  pcontext->pbuffer = ssh_buffer_allocate();

  if (pcontext->phost_name_or_address)
    {
      ssh_tcp_connect(pcontext->phost_name_or_address,
                      pcontext->pport_or_service,
                      NULL,
                      t_tcpc_tcp_callback,
                      pcontext);
    }
  else
    {
      pcontext->ptcplistener =
        ssh_tcp_make_listener(SSH_IPADDR_ANY_IPV4,
                              pcontext->pport_or_service,
                              NULL,
                              t_tcpc_tcp_callback,
                              pcontext);
    }

  ssh_event_loop_run();
  ssh_name_server_uninit();
  ssh_event_loop_uninitialize();

  ssh_buffer_free(pcontext->pbuffer);
  ssh_xfree(pcontext);
  ssh_util_uninit();
  return 0;
}

void t_tcpc_tcp_callback(SshTcpError      error,
                         SshStream    stream,
                         void*                context)
{
  t_tcpc_context  pcontext = context;




  SSH_TRACE(SSH_D_MY, ("%s", "t_tcpc_tcp_callback"));

  switch (error)
    {
    case SSH_TCP_OK:
      pcontext->pstream = stream;
      ssh_stream_set_callback(pcontext->pstream,
                              t_tcpc_stream_callback,
                              pcontext);
      ssh_xregister_timeout(pcontext->timeout,
                            0,
                            t_tcpc_timeout_callback,
                            pcontext);
      break;
    case SSH_TCP_NEW_CONNECTION:
      ssh_tcp_destroy_listener(pcontext->ptcplistener);
      pcontext->ptcplistener = 0;
      pcontext->pstream = stream;
      ssh_stream_set_callback(pcontext->pstream,
                              t_tcpc_stream_callback,
                              pcontext);
      break;
    case SSH_TCP_NO_ADDRESS:
      SSH_NOTREACHED;
      break;
    case SSH_TCP_NO_NAME:
      SSH_NOTREACHED;
      break;
    case SSH_TCP_UNREACHABLE:
      SSH_NOTREACHED;
      break;
    case SSH_TCP_REFUSED:
      SSH_NOTREACHED;
      break;
    case SSH_TCP_TIMEOUT:
      SSH_NOTREACHED;
      break;
    case SSH_TCP_FAILURE:
      SSH_NOTREACHED;
      break;
    default:
      SSH_NOTREACHED;
      break;
    }
}

void t_tcpc_stream_callback(SshStreamNotification        notification,
                            void*                                 context)
{
  t_tcpc_context  pcontext = context;
  char                    buf[4096];
  int                             i;

  SSH_TRACE(SSH_D_MY, ("%s", "t_tcpc_stream_callback"));

  switch (notification)
    {
    case SSH_STREAM_INPUT_AVAILABLE:
      SSH_TRACE(SSH_D_MY, ("%s", "SSH_STREAM_INPUT_AVAILABLE"));
      while ((i = ssh_stream_read(pcontext->pstream,
                                  buf,
                                  4096)) > 0)
        {
          buf[i] = 0;
          SSH_TRACE(SSH_D_MY, ("read: %s", buf));

          if (pcontext->phost_name_or_address)
            {
              ssh_buffer_append(pcontext->pbuffer,
                                buf,
                                i);
              t_tcpc_stream_callback(SSH_STREAM_CAN_OUTPUT,
                                     pcontext);
            }
          else
            {
              SSH_TRACE(SSH_D_MY, ("output: %s", buf));
            }
        }
      break;
    case SSH_STREAM_CAN_OUTPUT:
      SSH_TRACE(SSH_D_MY, ("%s", "SSH_STREAM_CAN_OUTPUT"));
      if (ssh_buffer_len(pcontext->pbuffer) > 0)
        {
          i = ssh_stream_write(pcontext->pstream,
                               ssh_buffer_ptr(pcontext->pbuffer),
                               ssh_buffer_len(pcontext->pbuffer));

          if (i > 0)
            {
              ssh_buffer_consume(pcontext->pbuffer,
                                 i);
            }
        }
      break;
    case SSH_STREAM_DISCONNECTED:
      SSH_TRACE(SSH_D_MY, ("%s", "SSH_STREAM_DISCONNECTED"));
#if 0
      /* BUG BUG BUG */
      ssh_stream_destroy(pcontext->pstream);
#endif /* 0 */
      ssh_event_loop_abort();
      break;
    default:
      SSH_NOTREACHED;
      break;
    }
}

void t_tcpc_timeout_callback(void *context)
{
  t_tcpc_context  pcontext = context;

  SSH_TRACE(SSH_D_MY, ("%s", "t_tcpc_timeout_callback"));

  if (! pcontext || !pcontext->pdata)
    return;

  ssh_buffer_append(pcontext->pbuffer,
                    pcontext->pdata,
                    strlen(pcontext->pdata));

  t_tcpc_stream_callback(SSH_STREAM_CAN_OUTPUT,
                         pcontext);

  ssh_xregister_timeout(pcontext->timeout,
                        0,
                        t_tcpc_timeout_callback,
                        pcontext);
}
