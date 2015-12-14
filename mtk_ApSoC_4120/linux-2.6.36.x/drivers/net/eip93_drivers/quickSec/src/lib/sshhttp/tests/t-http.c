/*
 *
 * t-http.c
 *
 * Author: Markku Rossi <mtr@ssh.fi>
 *
 *  Copyright:
 *          Copyright (c) 2002 - 2005 SFNT Finland Oy.
 *               All rights reserved.
 *
 * Regression tests for the HTTP library.
 *
 */

#include "sshincludes.h"
#include "sshtimeouts.h"
#include "sshhttp.h"
#include "ssheloop.h"
#include "sshnameserver.h"
#include "sshnameserver.h"

#define SSH_DEBUG_MODULE "SshHttpTests"

#define VERBOSE_TESTS 0

/* The HTTP server handle. */
static SshHttpServerContext server_ctx = NULL;

/* The HTTP client context. */
static SshHttpClientContext client_ctx = NULL;

/* An SshOpeationHandle for the currently active HTTP operation. */
static SshOperationHandle operation = NULL;

/* Run tests. */
static void run_next_test(void);

/*
 * Variables controlling the tests (some of them).
 */

static int abort_at_eof = 0;

Boolean content_length_check = FALSE;
SshUInt32 content_length = 0;

Boolean status_code_check = FALSE;
SshUInt32 status_code = 0;

/*
 * A function to abort an HTTP operation.
 */

/* An abort function to abort an ongoing HTTP client operation.  */
static void
abort_operation(void *context)
{
  if (operation)
    {
#if VERBOSE_TESTS
      printf("\n*** aborting operation %p\n", operation);
#endif /* VERBOSE_TESTS */

      ssh_operation_abort(operation);
      operation = NULL;

      run_next_test();
    }
}


/*
 * The server URI handlers.
 */

static Boolean
handler_static_data(SshHttpServerContext server_ctx,
                    SshHttpServerConnection conn, SshStream stream,
                    void *context)
{
  SshBuffer buffer = ssh_buffer_allocate();

  /* This is almost trivial. */

  ssh_http_server_set_values(conn,
                             SSH_HTTP_HDR_FIELD, "Content-Type", "text/plain",
                             SSH_HTTP_HDR_END);
  ssh_buffer_append_cstrs(buffer, context, NULL);
  ssh_http_server_send_buffer(conn, buffer);

  return TRUE;
}

static Boolean
handler_redirect(SshHttpServerContext server_ctx,
		 SshHttpServerConnection conn, SshStream stream,
		 void *context)
{
  ssh_http_server_relative_redirect(conn, (unsigned char *)context);
  ssh_stream_destroy(stream);
  return TRUE;
}

/*
 * An URI handler which maintains an explicit stream.
 */

static void server_stream_callback(SshStreamNotification notification,
                                   void *context);

struct ServerStreamWriteCtxRec
{
  Boolean waiting_for_timeout;

  SshUInt32 to_write;
  SshUInt32 intermediate_sleep;
  SshUInt32 intermediate_sleep_usec;

  SshStream stream;
  SshHttpServerConnection conn;
};

typedef struct ServerStreamWriteCtxRec ServerStreamWriteCtx;




static void
server_stream_write_more(void *context)
{
  ServerStreamWriteCtx *ctx = (ServerStreamWriteCtx *) context;
  ctx->waiting_for_timeout = FALSE;
  server_stream_callback(SSH_STREAM_CAN_OUTPUT, context);
}

static void
server_stream_callback(SshStreamNotification notification, void *context)
{
  ServerStreamWriteCtx *ctx = (ServerStreamWriteCtx *) context;
  int i;
  unsigned char *data = (unsigned char *) "f\n";

  switch (notification)
    {
    case SSH_STREAM_CAN_OUTPUT:
      if (ctx->waiting_for_timeout)
        return;

      while (ctx->to_write > 0)
        {
          i = ssh_stream_write(ctx->stream, data, 1);
          if (i == 0)
            {
              /* EOF */
              goto done;
            }
          else if (i < 0)
            {
              /* Would block. */
              return;
            }
          else
            {
              /* Wrote something. */
              ctx->to_write -= i;

              if (ctx->intermediate_sleep || ctx->intermediate_sleep_usec)
                {
                  ctx->waiting_for_timeout = TRUE;
                  ssh_http_server_flush(ctx->conn);
                  ssh_xregister_timeout(ctx->intermediate_sleep,
                                       ctx->intermediate_sleep_usec,
                                       server_stream_write_more, ctx);
                  return;
                }
            }
        }
      goto done;
      break;

    case SSH_STREAM_INPUT_AVAILABLE:
      /* Nothing here. */
      break;

    case SSH_STREAM_DISCONNECTED:
    done:
      ssh_cancel_timeouts(server_stream_write_more, ctx);
      ssh_stream_destroy(ctx->stream);
      ssh_xfree(ctx);
      break;
    }
}


static Boolean
handler_slow_data_source(SshHttpServerContext server_ctx,
                         SshHttpServerConnection conn, SshStream stream,
                         void *context)
{
  ServerStreamWriteCtx *ctx;

  ssh_http_server_set_values(conn,
                             SSH_HTTP_HDR_FIELD, "Content-Type", "text/plain",
                             SSH_HTTP_HDR_END);

  ctx = ssh_xcalloc(1, sizeof(*ctx));

  ctx->to_write = 100;
  ctx->intermediate_sleep = 0;
  ctx->intermediate_sleep_usec = 100000; /* 1/10 seconds. */
  ctx->stream = stream;
  ctx->conn = conn;

  ssh_stream_set_callback(stream, server_stream_callback, ctx);
  server_stream_callback(SSH_STREAM_CAN_OUTPUT, ctx);

  return TRUE;
}


static Boolean
handler_no_content(SshHttpServerContext server_ctx,
                   SshHttpServerConnection conn, SshStream stream,
                   void *context)
{
  ssh_http_server_error(conn, 204, /* No content */
                        SSH_HTTP_HDR_END);
  ssh_stream_destroy(stream);

  return TRUE;
}


static struct
{
  char *pattern;
  SshHttpServerUriHandler handler;
  void *context;
} uri_handlers[] =
{
  {"/static-data*",             handler_static_data, "Hello, world!"},
  {"/slow-data-source*",        handler_slow_data_source, NULL},
  {"/no-content",               handler_no_content, NULL},
  {"/redirect",                 handler_redirect, "/static-data"},
  {NULL, NULL_FNPTR, NULL},
};


/*
 * The test functions.
 */

static void
consume_stream_callback(SshStreamNotification notification, void *context)
{
  SshStream stream = (SshStream) context;
  int i;
  unsigned char buf[100];

  if (notification == SSH_STREAM_INPUT_AVAILABLE)
    {
      while (1)
        {
          i = ssh_stream_read(stream, buf, sizeof(buf));
          if (i == 0)
            {
              /* Check the content length if requested. */
              if (content_length_check)
                {
                  SshStreamStatsStruct stats;

                  ssh_stream_get_stats(stream, &stats);

                  if (stats.read_bytes != content_length)
                    {
                      printf("content length mismatch: expected %u, got %u\n",
                             (unsigned int) content_length,
                             (unsigned int) stats.read_bytes);
                      exit(1);
                    }
                }

              /* EOF */
              if (abort_at_eof)
                {
                  abort_operation(NULL);
                }
              else
                {
#if VERBOSE_TESTS
                  printf("\n");
#endif /* VERBOSE_TESTS */

                  ssh_stream_destroy(stream);

                  /* Continue tests. */
                  run_next_test();
                }
              return;
            }
          if (i < 0)
            {
              /* Would block. */
              return;
            }
          /* Read something. */
          {
            SshStreamStatsStruct stats;

            ssh_stream_get_stats(stream, &stats);
#if VERBOSE_TESTS
            printf("\r  received %ld bytes", stats.read_bytes);
            fflush(stdout);
#endif /* VERBOSE_TEST */


          }
        }
    }
  else if (notification == SSH_STREAM_DISCONNECTED)
    {
      printf("got SSH_STREAM_DISCONNECTED");
      exit(1);
    }
}


static void
read_result(SshHttpClientContext ctx, SshHttpResult result,
            SshTcpError ip_error, SshStream stream, void *callback_context)
{
  if (result != SSH_HTTP_RESULT_SUCCESS)
    {
      printf("operation failed: %s\n", ssh_http_error_code_to_string(result));
      exit(1);
    }

  if (status_code_check)
    {
      const unsigned char *reason_phrase;
      SshUInt32 code = ssh_http_get_status_code(ctx, &reason_phrase);

      if (code != status_code)
        {
          printf("invalid status code: expected %u, got %u\n",
                 (unsigned int) status_code,
                 (unsigned int) code);
          exit(1);
        }
    }

  ssh_stream_set_callback(stream, consume_stream_callback, stream);
  consume_stream_callback(SSH_STREAM_INPUT_AVAILABLE, stream);
}


static struct
{
  char *name;
  char *test_spec;
} tests[] =
{
  {"GET: static data via redirect",
   "url=http://127.0.0.1:9876/redirect"},
  {"GET: static data",
   "url=http://127.0.0.1:9876/static-data"},
  {"GET: static data with implicit context",
   "url=http://127.0.0.1:9876/static-data,implicit-context=1"},
  {"GET: slow data source",
   "url=http://127.0.0.1:9876/slow-data-source"},
  {"GET: slow data source with implicit context",
   "url=http://127.0.0.1:9876/slow-data-source,implicit-context=1"},
  {"timeout: GET: slow data source",
   "url=http://127.0.0.1:9876/slow-data-source,abort-timeout=5"},
  {"timeout: GET: slow data source with implicit context",
   "url=http://127.0.0.1:9876/slow-data-source,abort-timeout=5,\
implicit-context=1"},
  {"timeout at EOF: GET: slow data source",
   "url=http://127.0.0.1:9876/slow-data-source,abort-at-eof=1"},
  {"timeout at EOF: GET: slow data source with implicit context",
   "url=http://127.0.0.1:9876/slow-data-source,abort-at-eof=1,\
implicit-context=1"},
  {"GET: no content",
   "url=http://127.0.0.1:9876/no-content,content-length=0,status-code=204"},
  {"GET: no content with implicit context",
   "url=http://127.0.0.1:9876/no-content,content-length=0,status-code=204,\
implicit-context=1"},
  {NULL, NULL},
};

/* Our current position in the tests array. */
static SshUInt32 tests_position = 0;

/* A timeout to run the tests. */
static void
run_tests(void *context)
{
  if (client_ctx)
    {
      ssh_http_client_uninit(client_ctx);
      client_ctx = NULL;
    }

  if (tests[tests_position].name == NULL)
    {
      /* The end of tests reached.  Let's stop the server so the event
         loop terminates. */
      ssh_http_server_stop(server_ctx, NULL_FNPTR, NULL);
      ssh_name_server_uninit();
    }
  else
    {
      SshUInt32 i = tests_position++;
      char *url = NULL;
      SshUInt32 abort_timeout = 0;
      int implicit_context = 0;
      char *start, *mid, *end;

      /* Init global tests variables. */
      abort_at_eof = 0;

      content_length_check = FALSE;
      status_code_check = FALSE;

      printf("%s\n", tests[i].name);

      /* Parse arguments. */
      start = tests[i].test_spec;
      while (*start != '\0')
        {
          mid = NULL;

          for (end = start; *end && *end != ','; end++)
            if (*end == '=')
              mid = end;

          SSH_ASSERT(mid != NULL);

#define CMPVAR(what) (mid - start == strlen(what) \
                      && strncmp(start, what, mid - start) == 0)
#define VALUE (mid + 1)
#define VALUE_LEN (end - mid - 1)

          if (CMPVAR("url"))
            url = ssh_xmemdup(VALUE, VALUE_LEN);
          else if (CMPVAR("abort-timeout"))
            abort_timeout = (SshUInt32) strtol(VALUE, NULL, 10);
          else if (CMPVAR("implicit-context"))
            implicit_context = atoi(VALUE);
          else if (CMPVAR("abort-at-eof"))
            abort_at_eof = atoi(VALUE);
          else if (CMPVAR("content-length"))
            {
              content_length_check = TRUE;
              content_length = atoi(VALUE);
            }
          else if (CMPVAR("status-code"))
            {
              status_code_check = TRUE;
              status_code = atoi(VALUE);
            }
          else
            ssh_fatal("unknown variable %.*s", (int) (mid - start), start);

          start = end;
          if (*start == ',')
            start++;
        }

      if (!implicit_context)
        {
          client_ctx = ssh_http_client_init(NULL);
          if (!client_ctx)
            {
              printf("could not create HTTP client\n");
              exit(1);
            }
        }

      /* Start the operation. */
      operation = ssh_http_get(client_ctx, url, read_result, NULL,
                               SSH_HTTP_HDR_END);

      if (abort_timeout && operation)
        ssh_xregister_timeout(abort_timeout, 0, abort_operation, NULL);

      /* Cleanup. */
      ssh_xfree(url);
    }
}


static void
run_next_test(void)
{
  operation = NULL;
  ssh_xregister_timeout(0, 0, run_tests, NULL);
}


int
main(int argc, char *argv[])
{
  int i;
  SshHttpServerParams server_params;

#ifndef WIN32
  signal(SIGPIPE, SIG_IGN);
#endif /* not WIN32 */

#if 1
  ssh_debug_set_level_string("SshHttp*=9");
#endif

  /* Initialize the event loop. */
  ssh_event_loop_initialize();

  /* Create the HTTP server. */

  memset(&server_params, 0, sizeof(server_params));
  server_params.address = "127.0.0.1";
  server_params.port = "9876";

  server_ctx = ssh_http_server_start(&server_params);
  if (!server_ctx)
    {
      fprintf(stderr, "Could not create server.\n");
      exit(1);
    }

  /* Set the test URI handlers. */
  for (i = 0; uri_handlers[i].pattern; i++)
    ssh_http_server_set_handler(server_ctx, uri_handlers[i].pattern, 0,
                                uri_handlers[i].handler,
                                uri_handlers[i].context);

  /* Register a timeout to run the tests. */
  run_next_test();

  /* Run the event loop. */
  ssh_event_loop_run();

  /* Cleanup. */
  ssh_name_server_uninit();
  ssh_event_loop_uninitialize();

  ssh_util_uninit();
  /* All done. */
  return 0;
}
