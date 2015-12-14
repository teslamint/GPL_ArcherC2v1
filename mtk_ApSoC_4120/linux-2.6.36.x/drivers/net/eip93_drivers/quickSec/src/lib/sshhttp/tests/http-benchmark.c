/*
 *
 * http-benchmark.c
 *
 *  Copyright:
 *          Copyright (c) 2002 - 2004 SFNT Finland Oy.
 *               All rights reserved.
 *
 * Benchmark program for http. Input the contents of a file to memory
 * and post it to a remote server.
 *
 */

#include "sshincludes.h"
#include "sshtimeouts.h"
#include "sshhttp.h"
#include "ssheloop.h"
#include "sshoperation.h"
#include "sshinet.h"
#include "sshurl.h"
#include "sshgetopt.h"
#include "sshfileio.h"
#include "sshtimemeasure.h"

#define SSH_DEBUG_MODULE "SshHttpBenchmark"

typedef struct HttpTestCtxRec {
  SshHttpClientContext client_ctx;
  SshTimeMeasure timer;
  SshUInt32 iterations;
  unsigned char *url;
  unsigned char *buf;
  size_t buf_len;

} HttpTestCtxStruct, *HttpTestCtx;

static void usage(void)
{
  printf("Usage: http-benchmark [Options]\n"
         "Options : \n"
	 "\t-f FILE\n"
	 "\t-u URL\n"
         "\t-d DEBUG\n");
}

static void test_finish(void *ctx)
{
  HttpTestCtx http_ctx = ctx;

  ssh_http_client_uninit(http_ctx->client_ctx);
  ssh_xfree(http_ctx->buf);
  ssh_time_measure_free(http_ctx->timer);
  ssh_xfree(http_ctx);
  ssh_event_loop_uninitialize();
  ssh_util_uninit();
  exit(0);
}
void result_callback(SshHttpClientContext ctx,
		     SshHttpResult result,
		     SshTcpError ip_error,
		     SshStream stream,
		     void *callback_context)
{
  HttpTestCtx http_ctx = callback_context;
  SshUInt64 secs;
  SshUInt32 nanos;
  SshUInt32 s;

  SSH_DEBUG(SSH_D_HIGHOK, ("In the result callback with TCP error status "
			   "'%s' and HTTP result '%s'\n",
			   ssh_tcp_error_string(ip_error),
			   ssh_http_error_code_to_string(result)));
  




  http_ctx->iterations--;
  
  if (http_ctx->iterations == 0)
    {
      ssh_time_measure_get_value(http_ctx->timer,
				 &secs, &nanos);
      s = (SshUInt32)secs;

      printf("Test completed in %d's and %d'ns\n", (int)s, (int)nanos);
      
      if (stream)
	ssh_stream_destroy(stream);

      ssh_xregister_timeout(0, 0, test_finish, http_ctx);
      return;
    }
  else
    {
      if (stream)
	ssh_stream_destroy(stream);

      ssh_http_post(http_ctx->client_ctx, http_ctx->url, http_ctx->buf, 
		    http_ctx->buf_len, result_callback, http_ctx,
		    SSH_HTTP_HDR_END);
      
    }
}

int
main(int ac, char **av)
{
  HttpTestCtx http_ctx;
  SshHttpClientContext client_ctx;
  SshHttpClientParams client_params;
  SshUInt32 iterations = 1;
  unsigned char *buf;
  char *url = NULL;
  size_t buf_len, opt;
  char *file = NULL;

  while ((opt = ssh_getopt(ac, av, "u:d:p:f:n:h", NULL)) != EOF)
    {
      switch (opt)
        {
        case 'n':
	  iterations = atoi(ssh_optarg);
          break;
        case 'd':
          ssh_debug_set_level_string(ssh_optarg);
          break;
        case 'u':
          url = ssh_optarg;
          break;
        case 'f':
          file = ssh_optarg;
          break;
        default:
        case 'h':
          usage();
          exit(1);
	}
    }
  
  if (file == NULL || url == NULL)
    {
      usage();
      exit(1);
    }
  if (!ssh_read_file(file, &buf, &buf_len))
    {
      exit(1);
    }

  ssh_event_loop_initialize();

  memset(&client_params, 0, sizeof(client_params));
  if ((client_ctx = ssh_http_client_init(&client_params)) == NULL)
    {
      ssh_free(buf);
      exit(1);
    }

  http_ctx = ssh_xcalloc(1, sizeof(*http_ctx));
  http_ctx->timer = ssh_time_measure_allocate(); 
  http_ctx->buf = buf; 
  http_ctx->buf_len = buf_len; 
  http_ctx->client_ctx = client_ctx; 
  http_ctx->url = url; 
  http_ctx->iterations = iterations; 

  /* Start the timer. */
  ssh_time_measure_start(http_ctx->timer);

  SSH_DEBUG_HEXDUMP(99, ("Input buffer : %d bytes, prefix :", buf_len), 
		    buf, 256);

  ssh_http_post(client_ctx, url, buf, buf_len, result_callback, http_ctx,
		SSH_HTTP_HDR_END);

  ssh_event_loop_run();
  ssh_event_loop_uninitialize();
  return 0;
}
