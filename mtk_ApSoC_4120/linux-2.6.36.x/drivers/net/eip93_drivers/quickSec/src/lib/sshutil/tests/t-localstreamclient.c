/*
 *
 * t-localstreamclient.c
 *
 * Author: Markku Rossi <mtr@ssh.fi>
 *
 *  Copyright:
 *          Copyright (c) 2002, 2003 SFNT Finland Oy.
 *               All rights reserved.
 *
 * Local stream client test app.
 * Creates several localstreams to the same listener on the localhost, writes
 * and receives specified amount of data.
 *
 */

#define SSH_DEBUG_MODULE "TLocalStreamClient"

#include "sshincludes.h"
#include "sshdebug.h"
#include "ssheloop.h"
#include "sshbuffer.h"
#include "sshlocalstream.h"
#include "sshtimeouts.h"

static void local_connect_callback(SshStream stream, void *context);
static void stream_callback(SshStreamNotification notification, void *context);
static void timeout_callback(void *context);


struct MycontextRec
{
  SshBuffer buffer;
  long microseconds;

  size_t bytes;
  SshStream stream;
  int id;
};
typedef struct MycontextRec *Mycontext;

#define GET_OBJECT_FROM_CONTEXT(a)   Mycontext ctx = (Mycontext)a;

const char *usage =
"Usage:\n"
"t-localstreamclient name <ms> <bytes> <debug>\n"
"  name   name of the localstream\n"
"  ms     delays in milliseconds between sends\n"
"  bytes  bytes to receive from server until stop\n"
"  debug  debug string\n"
"\n";

int main(int argc, char *argv[])
{
  Mycontext ctx, ctx2, ctx3;

  if (argc < 2)
  {
    printf(usage);
    return 0;
  }

  ssh_event_loop_initialize();

  if (argc == 5)
    ssh_debug_set_level_string(argv[4]);

  ctx = ssh_xmalloc(sizeof(*ctx));
  ctx->id = 1;
  ctx->buffer = ssh_buffer_allocate();
  if (argc >= 3)
    ctx->microseconds = atol(argv[2])*1000;
  else
    ctx->microseconds = 500000;
  if (argc >= 4)
    ctx->bytes = atoi(argv[3]);
  else
    ctx->bytes = 1000;

  ssh_local_connect(argv[1],
                    local_connect_callback,
                    ctx);
#if 1
  /* 2nd connection */
  ctx2 = ssh_xmalloc(sizeof(*ctx2));
  ctx2->id = 2;
  ctx2->buffer = ssh_buffer_allocate();
  ctx2->microseconds = 300000;
  ctx2->bytes = 840;

  ssh_local_connect(argv[1],
                    local_connect_callback,
                    ctx2);
#endif

#if 1
  /* 3rd connection */
  ctx3 = ssh_xmalloc(sizeof(*ctx3));
  ctx3->id = 3;
  ctx3->buffer = ssh_buffer_allocate();
  ctx3->microseconds = 460000;
  ctx3->bytes = 680;

  ssh_local_connect(argv[1],
                    local_connect_callback,
                    ctx3);
#endif

  printf("running event loop now\n");
  ssh_event_loop_run();

  ssh_cancel_timeouts(SSH_ALL_CALLBACKS,
                      SSH_ALL_CONTEXTS);

  ssh_buffer_free(ctx->buffer);

  ssh_event_loop_uninitialize();

  ssh_util_uninit();
  return 0;
}

static void local_connect_callback(SshStream stream, void *context)
{
  GET_OBJECT_FROM_CONTEXT(context);

  if (stream == NULL)
  {
    printf("connect failed, id = %d\n", ctx->id);
    return;
  }

  ctx->stream = stream;

  printf("connect done, id = %d\n", ctx->id);

  ssh_stream_set_callback(stream,
                          stream_callback,
                          ctx);

  stream_callback(SSH_STREAM_INPUT_AVAILABLE, ctx);
  if (stream)
    stream_callback(SSH_STREAM_CAN_OUTPUT, ctx);
}

static void stream_callback(SshStreamNotification notification, void *context)
{
  char buf[4096];
  int i;
  GET_OBJECT_FROM_CONTEXT(context);

  SSH_ASSERT(ctx->stream);

  switch (notification)
    {
    case SSH_STREAM_INPUT_AVAILABLE:
      do
        {
          memset(buf, 0, sizeof (buf));
          i = ssh_stream_read(ctx->stream,
                              buf,
                              sizeof (buf) - 1);
          if (0 == i)
            {
              /* EOF */
              ssh_stream_destroy(ctx->stream);
              ssh_cancel_timeouts(timeout_callback, ctx);
              ctx->stream = NULL;
              return;
            }
          else if (i > 0)
            {
              printf("From server:%s", buf);
              if (i > ctx->bytes)
                {
                  ssh_stream_destroy(ctx->stream);
                  ssh_cancel_timeouts(timeout_callback, ctx);
                  return;
                }
              ctx->bytes -= i;
              printf("%d bytes left to read, id %d\n", ctx->bytes, ctx->id);
            }
        } while (i > 0);
      break;

    case SSH_STREAM_CAN_OUTPUT:
      while (ssh_buffer_len(ctx->buffer) > 0)
        {
          i = ssh_stream_write(ctx->stream,
                               ssh_buffer_ptr(ctx->buffer),
                               ssh_buffer_len(ctx->buffer));
          printf("wrote to server, id %d\n", ctx->id);
          if (i > 0)
            {
              ssh_buffer_consume(ctx->buffer, i);
            }
          else if (i == 0)
            {
              /* EOF */
              ssh_stream_destroy(ctx->stream);
              ssh_cancel_timeouts(timeout_callback, ctx);
              ctx->stream = NULL;
              return;
            }
          else
            {
              /* Would block. */
              return;
            }
        }

      SSH_ASSERT(ssh_buffer_len(ctx->buffer) == 0);

      /* Order new data. */
      ssh_xregister_timeout(0,
                           ctx->microseconds,
                           timeout_callback,
                           ctx);
      break;

    case SSH_STREAM_DISCONNECTED:
      ssh_event_loop_abort();
    }
}

static void timeout_callback(void *context)
{
  char* time_string = 0;
  char  b[500];
  GET_OBJECT_FROM_CONTEXT(context);


  SSH_ASSERT(ctx->stream);

  time_string = ssh_readable_time_string(ssh_time(),
                                         1);
  SSH_ASSERT(time_string);

  ssh_snprintf(b, 500, "client %d:", ctx->id);
  ssh_buffer_append(ctx->buffer,
                    b,
                    strlen(b));
  ssh_buffer_append(ctx->buffer,
                    time_string,
                    strlen(time_string));
  ssh_buffer_append(ctx->buffer,
                    "\n",
                    strlen("\n"));

  ssh_xfree(time_string);

  stream_callback(SSH_STREAM_CAN_OUTPUT,
                  ctx);

}
