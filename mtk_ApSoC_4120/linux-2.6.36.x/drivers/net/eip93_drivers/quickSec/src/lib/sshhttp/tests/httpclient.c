/*
 *
 * httpclient.c
 *
 * Author: Markku Rossi <mtr@ssh.fi>
 *
 *  Copyright:
 *          Copyright (c) 2002 - 2004 SFNT Finland Oy.
 *               All rights reserved.
 *
 * Test client for the SSH HTTP library.
 *
 */

#include "sshincludes.h"
#include "sshhttp.h"
#include "sshtimeouts.h"
#include "ssheloop.h"
#include "sshgetopt.h"
#include "sshfileio.h"
#include "sshnameserver.h"

#define SSH_DEBUG_MODULE "SshHttpClient"

#if 0
#define POST_DATA "doh=a%20deer&a=female%20deer&tom&dick&harry"
#else
#define POST_DATA "cb=0&qr=asdfsdafsafsafs&search.x=61&search.y=10"
#endif

/*
 * Global variables.
 */

/* Program name. */
char *program;

/* Output file name. */
char *output_name = NULL;

/*
 * Prototypes for static functions.
 */

static void usage(void);

static void connect_callback(SshHttpClientContext ctx, SshStream stream,
                             void *callback_context);

static void content_stream_callback(SshStreamNotification notification,
                                    void *context);

static void result_callback(SshHttpClientContext ctx, SshHttpResult result,
                            SshTcpError ip_error, SshStream stream,
                            void *callback_context);

static void stream_callback(SshStreamNotification notification,
                            void *context);

static void abort_timeout(void *context);


/*
 * Static variables.
 */

FILE *ofp = NULL;
size_t datalen = 0;
SshUInt32 timeout = 0;
Boolean timeout_aborted = FALSE;
static SshHttpClientContext ctx;
SshUInt32 num_requests = 0;
Boolean print_cookies = FALSE;

char *content_data_file = NULL;
size_t content_data_len;
FILE *ifp = NULL;
unsigned char ibuf[4096];
size_t data_in_ibuf;
size_t ibuf_pos;

/* Yes, this is definitely enought ;-) */
SshHttpCookie cookies[100];
unsigned int num_cookies = 0;

/* Just for testing. */
Boolean do_post = FALSE;

Boolean no_expect_100_continue = FALSE;

/*
 * Global functions.
 */

int
main(int argc, char *argv[])
{
  int c;
  const char *debug_string = "SshHttp*=5";
  SshHttpClientParams params;
  char *cp, *start;
  struct stat stat_st;
  Boolean more_items;
  Boolean urls_from_file = FALSE;
  memset(&params, 0, sizeof(params));
#if 0
  params.socks = "socks://muuri.ssh.fi:1080/127.0.0.0/8,192.168.0.0/16";
#endif
  params.num_redirections = 5;

  /* Remove the directory part from the program name. */
  program = strrchr(argv[0], '/');
  if (program == NULL)
    program = argv[0];
  else
    program++;

  /* Parse options. */
  while ((c = ssh_getopt(argc, argv, "0bcC:d:eho:p:P:t:f", NULL)) != EOF)
    {
      switch (c)
        {
        case '0':
          params.use_http_1_0 = TRUE;
          break;

        case 'b':
          do_post = TRUE;
          break;

        case 'c':
          print_cookies = TRUE;
          break;

        case 'f':
          urls_from_file = TRUE;
          break;
          
        case 'C':
          memset(&cookies[num_cookies], 0, sizeof(SshHttpCookie));
          more_items = TRUE;

          /* Name */

          start = ssh_optarg;
          cp = strchr(start, ':');
          if (cp == NULL)
            {
            malformed_cookie:
              fprintf(stderr, "%s malformed Cookie `%s'\n", program,
                      ssh_optarg);
              exit(1);
            }

          cookies[num_cookies].name = ssh_xmemdup(start, cp - start);
          start = ++cp;

          /* Value */

          cp = strchr(start, ':');
          if (cp == NULL)
            {
              cp = start + strlen(start);
              more_items = FALSE;
            }

          cookies[num_cookies].value = ssh_xmemdup(start, cp - start);

          /* Path */
          if (more_items)
            {
              start = ++cp;
              cp = strchr(start, ':');
              if (cp == NULL)
                {
                  cp = start + strlen(start);
                  more_items = FALSE;
                }

              cookies[num_cookies].path = ssh_xmemdup(start, cp - start);
            }

          /* Domain */
          if (more_items)
            {
              start = ++cp;
              cp = strchr(start, ':');
              if (cp == NULL)
                {
                  cp = start + strlen(start);
                  more_items = FALSE;
                }

              cookies[num_cookies].domain = ssh_xmemdup(start, cp - start);
            }

          /* Port */
          if (more_items)
            {
              start = ++cp;
              cp = strchr(start, ':');
              if (cp == NULL)
                {
                  cp = start + strlen(start);
                  more_items = FALSE;
                }

              cookies[num_cookies].port = ssh_xmemdup(start, strlen(start));
            }
          if (more_items)
            goto malformed_cookie;

          num_cookies++;
          break;

        case 'd':
          debug_string = ssh_optarg;
          break;

        case 'e':
          no_expect_100_continue = TRUE;
          break;

        case 'h':
          usage();
          exit(0);
          break;

        case 'o':
          output_name = ssh_optarg;
          break;

        case 'p':
          content_data_file = ssh_optarg;
          if (stat(content_data_file, &stat_st) < 0)
            {
              fprintf(stderr, "%s: couldn't stat file `%s': %s\n", program,
                      content_data_file, strerror(errno));
              exit(1);
            }
          content_data_len = stat_st.st_size;
          break;

        case 'P':
          params.http_proxy_url = ssh_optarg;
          break;

        case 't':
          timeout = atoi(ssh_optarg);
          break;

        case '?':
          fprintf(stderr, "Try `%s -h' for more information.\n", program);
          exit(1);
          break;
        }
    }

  if (ssh_optind >= argc)
    {
      fprintf(stderr, "%s: no URLs specified.\n\n", program);
      usage();
      exit(1);
    }

  if (output_name && ssh_optind + 1 < argc)
    {
      fprintf(stderr, "%s: only one URL can be specified with option `-o'\n",
              program);
      exit(1);
    }

  ssh_debug_set_level_string(debug_string);
  ssh_event_loop_initialize();

  ctx = ssh_http_client_init(&params);

  for (; ssh_optind < argc; ssh_optind++)
    {
      unsigned int i;

      num_requests++;

      /* Cookies. */
      for (i = 0; i < num_cookies; i++)
        {
          SshHttpCookie *cookie = &cookies[i];

          ssh_http_set_values(ctx,
                              SSH_HTTP_HDR_COOKIE, cookie->name, cookie->value,
                              SSH_HTTP_HDR_END);
          if (cookie->path)
            ssh_http_set_values(ctx,
                                SSH_HTTP_HDR_COOKIE_PATH, cookie->path,
                                SSH_HTTP_HDR_END);
          if (cookie->domain)
            ssh_http_set_values(ctx,
                                SSH_HTTP_HDR_COOKIE_DOMAIN, cookie->domain,
                                SSH_HTTP_HDR_END);
          if (cookie->port)
            ssh_http_set_values(ctx,
                                SSH_HTTP_HDR_COOKIE_PORT, cookie->port,
                                SSH_HTTP_HDR_END);
        }

      if (no_expect_100_continue)
        ssh_http_set_values(ctx,
                            SSH_HTTP_HDR_NO_EXPECT_100_CONTINUE,
                            SSH_HTTP_HDR_END);

      if (urls_from_file)
        {
          unsigned char *url_from_file = NULL;
          size_t url_from_file_len;

          if (FALSE == ssh_read_file(argv[ssh_optind],
                                     &url_from_file, &url_from_file_len))
            ssh_fatal("failed to read file %s", argv[ssh_optind]);
          url_from_file = ssh_xrealloc(url_from_file, url_from_file_len + 1);
          url_from_file[url_from_file_len] = '\0';
          ssh_http_get(ctx, (char *)url_from_file,
                       result_callback, url_from_file,
                       SSH_HTTP_HDR_END);
        }
      else if (content_data_file)
        {
#if 0
          ssh_http_put_stream(ctx, argv[ssh_optind],
                              connect_callback, content_data_file,
                              result_callback, argv[ssh_optind],
                              SSH_HTTP_HDR_CONTENT_LENGTH, content_data_len,
                              SSH_HTTP_HDR_END);
#else
          ssh_http_post_stream(ctx, argv[ssh_optind],
                               connect_callback, content_data_file,
                               result_callback, argv[ssh_optind],
#if 0
                               SSH_HTTP_HDR_CONTENT_LENGTH, content_data_len,
#else
                               SSH_HTTP_HDR_SERVER_IS_HTTP_1_1,
#endif
                               SSH_HTTP_HDR_END);
#endif
        }
      else if (do_post)
        ssh_http_post(ctx, argv[ssh_optind],
                      (unsigned char *)POST_DATA, strlen(POST_DATA),
                      result_callback, argv[ssh_optind],
                      SSH_HTTP_HDR_END);
      else
        ssh_http_get(ctx, argv[ssh_optind], result_callback, argv[ssh_optind],
                     SSH_HTTP_HDR_END);
    }

  if (timeout)
    ssh_xregister_timeout(timeout, 0, abort_timeout, ctx);

  ssh_event_loop_run();

  if (!timeout_aborted && ctx)
    ssh_http_client_uninit(ctx);

  ssh_name_server_uninit();
  ssh_event_loop_uninitialize();

  return 0;
}


/*
 * Static functions.
 */

static void
usage()
{
  fprintf(stderr, "Usage: %s [OPTION]... URL...\n\
  -0             use HTTP/1.0 protocol\n\
  -b             use POST method instead of GET\n\
  -c             print all response `Set-Cookie' cookies\n\
  -C NAME:VALUE[:PATH[:DOMAIN[:PORT]]]\n\
                 send a cookie to the server\n\
  -d DEBUG       set debug level according to debug string DEBUG\n\
  -e             do not try to use existing connection\n\
  -h             print this help and exit\n\
  -o NAME        save output to file NAME\n\
  -p NAME        perform a HTTP PUT request reading the content data from \n\
                 file NAME\n\
  -P PROXYURL    use HTTP proxy, specified by the URL PROXYURL\n\
  -t TIMEOUT     abort operations after TIMEOUT seconds\n\
",
          program);
}


static void
connect_callback(SshHttpClientContext ctx, SshStream stream,
                 void *callback_context)
{
  char *fname = (char *) callback_context;

  ifp = fopen(fname, "r");
  if (ifp == NULL)
    {
      fprintf(stderr, "%s: couldn't open content data file `%s': %s\n",
              program, fname, strerror(errno));
      ssh_stream_destroy(stream);
      return;
    }

  data_in_ibuf = fread(ibuf, 1, sizeof(ibuf), ifp);
  ibuf_pos = 0;

  ssh_stream_set_callback(stream, content_stream_callback, stream);
  content_stream_callback(SSH_STREAM_CAN_OUTPUT, stream);
}


static void
content_stream_callback(SshStreamNotification notification, void *context)
{
  SshStream stream = (SshStream) context;
  int i;
  if (notification != SSH_STREAM_CAN_OUTPUT)
    return;

  while (1)
    {
      /* Write everything from the buffer. */
      while (data_in_ibuf - ibuf_pos > 0)
        {
          i = ssh_stream_write(stream, ibuf + ibuf_pos,
                               data_in_ibuf - ibuf_pos);
          if (i == 0)
            {
              /* EOF received. */
              data_in_ibuf = ibuf_pos = 0;
              fprintf(stderr, "%s: write: EOF received\n", program);
              break;
            }
          if (i < 0)
            /* Would block. */
            return;

          ibuf_pos += i;
        }

      /* Wrote it all. */
      if (data_in_ibuf < sizeof(ibuf))
        {
          /* This was the last block. */
          fclose(ifp);
          ssh_stream_output_eof(stream);
          ssh_stream_destroy(stream);
          return;
        }

      /* Read more data to the buffer. */
      data_in_ibuf = fread(ibuf, 1, sizeof(ibuf), ifp);
      ibuf_pos = 0;
    }
}


static void
result_callback(SshHttpClientContext ctx, SshHttpResult result,
                SshTcpError ip_error, SshStream stream, void *callback_context)
{
  char *url = (char *) callback_context;

  if (result != SSH_HTTP_RESULT_SUCCESS)
    {
      if (result == SSH_HTTP_RESULT_HTTP_ERROR)
        {
          const char *desc;
          SshUInt32 code;

          code = ssh_http_get_status_code(ctx, &desc);
          printf("%s: HTTP error: %u %s\n", program, (unsigned int) code,
                 desc);
        }
      else
        fprintf(stderr, "%s: error: %s\n", program,
                ssh_http_error_code_to_string(result));
    }
  else
    {
      int i;
      char *name;
      const char *cp;

      if (output_name)
        name = output_name;
      else
        {
          name  = ssh_xstrdup(url);
          for (i = 0; name[i]; i++)
            if (name[i] == '/' || name[i] == ':')
              name[i] = '_';
        }

      printf("%s:\n  filename:\t%s\n", url, name);

      /* Extract some header fields. */
      cp = ssh_http_get_header_field(ctx, "content-type");
      if (cp)
        printf("  Content-Type:\t%s\n", cp);

      if (print_cookies)
        {
          const SshHttpSetCookie *cookies;
          unsigned int num_cookies;

          cookies = ssh_http_get_cookies(ctx, &num_cookies);
          if (cookies)
            {
              unsigned int i;

              printf("  Set-Cookies:\n");

              for (i = 0; i < num_cookies; i++)
                {
                  const SshHttpSetCookie *cookie = &cookies[i];

                  printf("    %s=\"%s\"", cookie->name, cookie->value);
                  if (cookie->comment)
                    printf("; Comment=\"%s\"", cookie->comment);
                  if (cookie->comment_url)
                    printf("; CommentURL=\"%s\"", cookie->comment_url);
                  if (cookie->discard)
                    printf("; Discard");
                  if (cookie->domain)
                    printf("; Domain=\"%s\"", cookie->domain);
                  if (cookie->max_age_given)
                    printf("; Max-Age=\"%lu\"",
                           (unsigned long) cookie->max_age);
                  if (cookie->expires)
                    printf("; Expires=\"%s\"", cookie->expires);
                  if (cookie->path)
                    printf("; Path=\"%s\"", cookie->path);
                  if (cookie->port)
                    printf("; Port=\"%s\"", cookie->port);
                  if (cookie->secure)
                    printf("; secure");

                  printf("\n");
                }
            }
        }

      printf("  [");
      fflush(stdout);

      ofp = fopen(name, "w");
      if (ofp == NULL)
        {
          fprintf(stderr, "%s: couldn't create output file `%s'\n",
                  program, name);
          ssh_stream_destroy(stream);
          return;
        }

      if (output_name == NULL)
        ssh_xfree(name);

      ssh_stream_set_callback(stream, stream_callback, stream);
      stream_callback(SSH_STREAM_INPUT_AVAILABLE, stream);
    }
}


static void
stream_callback(SshStreamNotification notification, void *context)
{
  SshStream stream = (SshStream) context;
  unsigned char buf[4096];
  int l;

  while (1)
    {
      l = ssh_stream_read(stream, buf, sizeof(buf));
      if (l == 0)
        {
          SshStreamStatsStruct stats;
          SshHttpInputStatus status;

          /* EOF */

          ssh_stream_get_stats(stream, &stats);
          printf("]=%ld bytes\n", stats.read_bytes);

          status = ssh_http_get_input_status(ctx);
          printf("status=%d\n", status);

          ssh_stream_destroy(stream);

          if (--num_requests == 0)
            ssh_cancel_timeouts(abort_timeout, ctx);
          return;
        }
      if (l < 0)
        {
          /* Would block. */
          return;
        }

      fwrite(buf, l, 1, ofp);
#if 0
      printf("%d+", l);
#else
      printf(".");
#endif
      fflush(stdout);
    }
}


static void
abort_timeout(void *context)
{
  SshHttpClientContext ctx = (SshHttpClientContext) context;

  fprintf(stderr, "%s: ***** abort timeout *****\n", program);

  timeout_aborted = TRUE;
  ssh_http_client_uninit(ctx);
  ctx = NULL;
}
