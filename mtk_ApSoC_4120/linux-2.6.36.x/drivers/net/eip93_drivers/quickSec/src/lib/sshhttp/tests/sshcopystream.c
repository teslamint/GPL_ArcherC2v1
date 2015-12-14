/*
 *
 * sshcopystream.c
 *
 * Author: Markku Rossi <mtr@ssh.fi>
 *
 *  Copyright:
 *          Copyright (c) 2002 - 2004 SFNT Finland Oy.
 *               All rights reserved.
 *
 * What is this file for?
 *
 */

#include "sshincludes.h"
#include "sshstream.h"
#include "sshbuffer.h"
#include "sshcopystream.h"
#include "sshtimeouts.h"

/*
 * Types and definitions.
 */

#define SSH_DEBUG_MODULE "SshCopyStream"

struct SshCopyStreamCtxRec
{
  struct
  {
    SshStream stream;
    SshBufferStruct buffer;
    size_t bufsize;

    Boolean blocked;
    Boolean eof_seen;
  } from;

  struct
  {
    SshStream stream;
    SshBufferStruct buffer;

    Boolean blocked;
    Boolean eof_seen;
  } to;

  SshCopyStreamCopyCb copy;
  SshCopyStreamDestroyCb destroy;

  void *context;
};

typedef struct SshCopyStreamCtxRec SshCopyStreamCtx;


/*
 * Prototypes for static functions.
 */

static void ssh_copy_stream_callback(SshStreamNotification notification,
                                     void *context);

static void finish_copy(void *context);


/*
 * Global functions.
 */

void
ssh_copy_stream(SshStream to, SshStream from, SshCopyStreamCopyCb copy,
                SshCopyStreamDestroyCb destroy, void *context)
{
  SshCopyStreamCtx *ctx = ssh_xcalloc(1, sizeof(*ctx));

  ctx->from.stream = from;
  ssh_buffer_init(&ctx->from.buffer);
  ctx->from.bufsize = 4096;

  ctx->to.stream = to;
  ssh_buffer_init(&ctx->to.buffer);

  ctx->copy = copy;
  ctx->destroy = destroy;
  ctx->context = context;

  ssh_stream_set_callback(ctx->from.stream, ssh_copy_stream_callback, ctx);
  ssh_stream_set_callback(ctx->to.stream, ssh_copy_stream_callback, ctx);

  /* And bootstrap us. */
  ssh_copy_stream_callback(SSH_STREAM_INPUT_AVAILABLE, ctx);
}


/*
 * Static functions.
 */

static void
ssh_copy_stream_callback(SshStreamNotification notification, void *context)
{
  SshCopyStreamCtx *ctx = context;

 restart:

  switch (notification)
    {
    case SSH_STREAM_INPUT_AVAILABLE:
      /* Read as much as we can. */
      while (1)
        {
          size_t to_read;
          int got;
          unsigned char *cp;

          ctx->from.blocked = FALSE;
          to_read = ctx->from.bufsize - ssh_buffer_len(&ctx->from.buffer);

          if (to_read == 0)
            break;

          /* Read some data. */

          ssh_buffer_append_space(&ctx->from.buffer, &cp, to_read);
          got = ssh_stream_read(ctx->from.stream, cp, to_read);

          if (got < 0)
            {
              ctx->from.blocked = TRUE;
              ssh_buffer_consume_end(&ctx->from.buffer, to_read);
              return;
            }
          else if (got == 0)
            {
              /* EOF seen in the input. */
              ctx->from.eof_seen = TRUE;
              ssh_buffer_consume_end(&ctx->from.buffer, to_read);
              break;
            }
          else
            {
              /* Got something. */
              ssh_buffer_consume_end(&ctx->from.buffer, to_read - got);
            }
        }

      /* Read done. */

      /* Copy the data to the output buffer. */
      (*ctx->copy)(&ctx->to.buffer, &ctx->from.buffer,
                   ctx->from.eof_seen, ctx->context);

      /* Can we output anything? */
      if (!ctx->to.blocked)
        {
          notification = SSH_STREAM_CAN_OUTPUT;
          goto restart;
        }

      /* Must wait for a write notification. */
      break;

    case SSH_STREAM_CAN_OUTPUT:
      /* Write as much as we can. */
      while (ssh_buffer_len(&ctx->to.buffer) > 0)
        {
          int wrote;

          ctx->to.blocked = FALSE;
          wrote = ssh_stream_write(ctx->to.stream,
                                   ssh_buffer_ptr(&ctx->to.buffer),
                                   ssh_buffer_len(&ctx->to.buffer));

          if (wrote < 0)
            {
              ctx->to.blocked = TRUE;
              break;
            }
          else if (wrote == 0)
            {
              ctx->to.eof_seen = TRUE;
              break;
            }
          else
            {
              ssh_buffer_consume(&ctx->to.buffer, wrote);
            }
        }

      /* Are we done? */
      if (ctx->to.eof_seen
          || (ssh_buffer_len(&ctx->to.buffer) == 0
              && ctx->from.eof_seen))
        {
          /* We'r done */

          ssh_stream_destroy(ctx->from.stream);
          ssh_stream_destroy(ctx->to.stream);

          ssh_xregister_timeout(0, 0, finish_copy, ctx);
          return;
        }

      /* Can we read more? */
      if (!ctx->from.blocked)
        {
          notification = SSH_STREAM_INPUT_AVAILABLE;
          goto restart;
        }

      /* Must wait for a read notification. */
      break;

    case SSH_STREAM_DISCONNECTED:
      break;
    }
}


static void
finish_copy(void *context)
{
  SshCopyStreamCtx *ctx = context;

  (*ctx->destroy)(ctx->context);

  ssh_buffer_uninit(&ctx->from.buffer);
  ssh_buffer_uninit(&ctx->to.buffer);

  ssh_xfree(ctx);
}
