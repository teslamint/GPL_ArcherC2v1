/*
 *
 * t-localstreamserver.c
 *
 * Author: Markku Rossi <mtr@ssh.fi>
 *
 *  Copyright:
 *          Copyright (c) 2002, 2003 SFNT Finland Oy.
 *               All rights reserved.
 *
 * What is this file for?
 *
 */

#define SSH_DEBUG_MODULE "TLocalStreamServer"

#include "sshincludes.h"
#include "sshdebug.h"
#include "ssheloop.h"
#include "sshbuffer.h"
#include "sshlocalstream.h"
#include "sshtimeouts.h"
#include "sshgetopt.h"

static void local_listener_callback(SshStream stream, void *context);
static void stream_callback(SshStreamNotification notification, void *context);

struct StreamRec
{
  SshStream stream;
  SshBufferStruct buffer;
  Boolean flow_control;
};

typedef struct StreamRec StreamStruct;
typedef struct StreamRec *Stream;

static char *program;

static Boolean echo = FALSE;

static void
usage(void)
{
  fprintf(stdout, "\
Usage: %s [OPTION]... PATH\n\
  -D LEVEL                set debug level string to LEVEL\n\
  -e                      echo data to standard output\n\
  -a access type (a/r/l)  Set the local stream access type.\n\
   a=all, r=current user + root, l = current user in this logon session only\n\
  -h                      print this help and exit\n\
",
          program);
}


int main(int argc, char *argv[])
{
  int opt;
  SshLocalListener listener;
  SshLocalStreamAccessType access_type;
  SshLocalStreamParamsStruct params;

  memset(&params, 0, sizeof(params));

  while ((opt = ssh_getopt(argc, argv, "a:D:eh", NULL)) != EOF)
    {
      switch (opt)
        {
        case 'a':
          access_type = SSH_LOCAL_STREAM_ACCESS_ROOT;
          if (ssh_optarg[0] == 'a')
            access_type = SSH_LOCAL_STREAM_ACCESS_ALL;
          else if (ssh_optarg[0] == 'r')
            access_type = SSH_LOCAL_STREAM_ACCESS_ROOT;
          else if (ssh_optarg[0] == 'l')
            access_type = SSH_LOCAL_STREAM_ACCESS_LOGON_SESSION;
          break;
        case 'D':
          ssh_debug_set_level_string(ssh_optarg);
          break;

        case 'e':
          echo = TRUE;
          break;

        case 'h':
          usage();
          exit(0);
          break;
        }
    }

  params.access = access_type;

  if (ssh_optind + 1 != argc)
    {
      usage();
      exit(1);
    }

  ssh_event_loop_initialize();

  listener = ssh_local_make_listener(argv[ssh_optind], &params,
                                     local_listener_callback,
                                     NULL);
  SSH_ASSERT(listener);

  ssh_event_loop_run();

  ssh_cancel_timeouts(SSH_ALL_CALLBACKS,
                      SSH_ALL_CONTEXTS);

  ssh_event_loop_uninitialize();
  ssh_util_uninit();
  return 0;
}

static void local_listener_callback(SshStream stream, void *context)
{
  Stream s = ssh_xcalloc(1, sizeof(*s));

  SSH_ASSERT(stream);

  s->stream = stream;
  ssh_buffer_init(&s->buffer);

  ssh_stream_set_callback(stream, stream_callback, s);
}

static void more_input_please(void *context)
{
  stream_callback(SSH_STREAM_INPUT_AVAILABLE, context);
}

static void stream_callback(SshStreamNotification notification, void *context)
{
  Stream stream = context;
  char buf[4096];
  int i;

  SSH_ASSERT(stream);

  switch (notification)
    {
    case SSH_STREAM_INPUT_AVAILABLE:
      while (ssh_buffer_len(&stream->buffer) < 4096)
        {
          memset(buf, 0, sizeof (buf));
          i = ssh_stream_read(stream->stream, buf, sizeof(buf));
          if (i == 0)
            {
              goto destroy;
            }
          else if (i > 0)
            {
              if (echo)
                fprintf(stderr, "%s", buf);
              ssh_buffer_append(&stream->buffer, buf, i);
            }
          else
            {
              /* Would block. */
              break;
            }
        }
      if (ssh_buffer_len(&stream->buffer) >= 4096)
        stream->flow_control = 1;

      if (ssh_buffer_len(&stream->buffer) > 0)
        stream_callback(SSH_STREAM_CAN_OUTPUT, stream);
      break;

    case SSH_STREAM_CAN_OUTPUT:
      while (ssh_buffer_len(&stream->buffer) > 0)
        {
          i = ssh_stream_write(stream->stream,
                               ssh_buffer_ptr(&stream->buffer),
                               ssh_buffer_len(&stream->buffer));
          if (i > 0)
            {
              ssh_buffer_consume(&stream->buffer, i);
            }
          else if (i == 0)
            {
              /* EOF */
            destroy:
              ssh_stream_destroy(stream->stream);
              ssh_buffer_uninit(&stream->buffer);
              ssh_xfree(stream);
              return;
            }
          else
            {
              /* Would block. */
              break;
            }
        }

      if (ssh_buffer_len(&stream->buffer) < 4096 && stream->flow_control)
        {
          stream->flow_control = FALSE;
          ssh_xregister_timeout(0, 0, more_input_please, stream);
        }
      break;

    case SSH_STREAM_DISCONNECTED:
      ssh_event_loop_abort();
    }
}
