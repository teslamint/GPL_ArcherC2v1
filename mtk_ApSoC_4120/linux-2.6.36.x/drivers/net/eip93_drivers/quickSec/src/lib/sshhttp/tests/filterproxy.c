/*
 *
 * filterproxy.c
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
#include "sshhttp.h"
#include "ssheloop.h"
#include "sshgetopt.h"
#include "sshmatch.h"
#include "sshcopystream.h"

/*
 * TODO: the smart update is very much under construction.
 */
#define SMART_UPDATE 0

/*
 * Types and definitions.
 */

#define SSH_DEBUG_MODULE "SshHttpFilterProxy"

typedef enum
{
  FILTER_TEXT = 0,
  FILTER_ENTITY
} FilterState;

struct ProxyRequestRec
{
  SshHttpServerContext server;
  SshHttpServerConnection conn;
  SshStream server_stream;

  SshHttpClientContext client;
  SshStream client_stream;

  FilterState state;
};

typedef struct ProxyRequestRec ProxyRequest;



struct ProxyCensorRec
{
  struct ProxyCensorRec *next;
  char *pattern;
};

typedef struct ProxyCensorRec ProxyCensor;


/*
 * Global variables.
 */

/* Program name. */
char *program;

/* Proxy URL for the HTTP client. */
char *proxy_url = "http://www-cache.ssh.fi:8080/";

/* The censor data file. */
char *censor_file = "./censor.dat";

ProxyCensor *censor = NULL;


/*
 * Prototypes for static functions.
 */

static void usage(void);

static void read_censor_list();

/* The default HTTP proxy handler. */
static Boolean proxy_handler(SshHttpServerContext ctx,
                             SshHttpServerConnection conn,
                             SshStream stream, void *context);

/* The smart filter catch handler. */
static Boolean catch_handler(SshHttpServerContext ctx,
                             SshHttpServerConnection conn,
                             SshStream stream, void *context);

/* Authentication handler. */
static Boolean authentication_handler(SshHttpServerContext ctx,
                                      SshHttpServerConnection conn,
                                      SshStream stream, void *context);

/* HTTP client result callback. */
static void result_callback(SshHttpClientContext ctx, SshHttpResult result,
                            SshTcpError ip_error, SshStream stream,
                            void *callback_context);

static void copy_data(SshBuffer to, SshBuffer from, size_t size_hint,
                      void *context);

static void req_finish(void *context);

#if SMART_UPDATE
static void filter_html(SshBuffer to, SshBuffer from, size_t size_hint,
                        void *context);

static char *parse_img_src(char *data, size_t len);
#endif


/*
 * Global functions.
 */

int
main(int argc, char *argv[])
{
  int c;
  const char *debug_string = "SshHttpFilterProxy=5";
  SshHttpServerParams params;
  SshHttpServerContext ctx;

  memset(&params, 0, sizeof(params));
  params.port = "8080";

#ifndef WIN32
  signal(SIGPIPE, SIG_IGN);
#endif /* not WIN32 */

  /* Remove the directory part from the program name. */
  program = strrchr(argv[0], '/');
  if (program == NULL)
    program = argv[0];
  else
    program++;

  /* Parse options. */
  while ((c = ssh_getopt(argc, argv, "d:hp:P:", NULL)) != EOF)
    {
      switch (c)
        {
        case 'd':
          debug_string = ssh_optarg;
          break;

        case 'h':
          usage();
          exit(0);
          break;

        case 'p':
          params.port = ssh_optarg;
          break;

        case 'P':
          proxy_url = ssh_optarg;
          break;
        }
    }

  if (ssh_optind < argc)
    {
      fprintf(stderr, "%s: garbage after options.\n\n", program);
      usage();
      exit(1);
    }

  ssh_debug_set_level_string(debug_string);
  ssh_event_loop_initialize();

  read_censor_list();

  SSH_DEBUG(SSH_D_HIGHSTART, ("running on %s", params.port));

  ctx = ssh_http_server_start(&params);

  if (ctx)
    {
      /* Set the URI handlers. */
      ssh_http_server_set_handler(ctx, "http://*", 0, proxy_handler, NULL);
      ssh_http_server_set_handler(ctx, "/catch*", 0, catch_handler, NULL);
      ssh_http_server_set_handler(ctx, "*", 10, authentication_handler, NULL);

      ssh_event_loop_run();
    }
  else
    fprintf(stderr, "%s: couldn't create listener\n", program);

  ssh_event_loop_uninitialize();

  return 0;
}


/*
 * Static functions.
 */

static void
usage()
{
  fprintf(stderr, "Usage: %s [OPTION]...\n"
"  -d DEBUG       set debug level according to the debug string DEBUG\n"
"  -p PORT        listen to port PORT\n"
"  -P PROXY       use HTTP proxy PROXY\n"
          "", program);
}

static void
read_censor_list()
{
  FILE *fp;
  char buf[1024];

  fp = fopen(censor_file, "rb");
  if (fp == NULL)
    {
      SSH_DEBUG(SSH_D_ERROR, ("could not open censor file `%s'",
                              censor_file));
      return;
    }

  while (fgets(buf, sizeof(buf), fp) != NULL)
    {
      char *cp;
      ProxyCensor *c = ssh_xcalloc(1, sizeof(*c));

      cp = strchr(buf, '\n');
      if (cp)
        *cp = '\0';

      c->next = censor;
      censor = c;
      c->pattern = ssh_xstrdup(buf);
    }
  fclose(fp);
}


/* The URI handler. */
static Boolean
proxy_handler(SshHttpServerContext ctx,
              SshHttpServerConnection conn,
              SshStream stream, void *context)
{
  const char *method = ssh_http_server_get_method(conn);
  const char *uri = ssh_http_server_get_uri(conn);
  SshHttpClientParams params;
  ProxyRequest *req;
  SshBuffer error;
  ProxyCensor *c;

  SSH_DEBUG(SSH_D_HIGHSTART,
            ("method=%s, uri=%s", method, uri));

  for (c = censor; c; c = c->next)
    if (ssh_match_pattern(uri, c->pattern))
      {
        SSH_DEBUG(SSH_D_HIGHSTART,
                  ("censored by pattern `%s'", c->pattern));
        ssh_http_server_error(conn, 301,
                              SSH_HTTP_HDR_LOCATION,
                              "http://people.ssh.fi/mtr/censor.jpg",
                              SSH_HTTP_HDR_FIELD,
                              "Content-Type", "text/html",
                              SSH_HTTP_HDR_END);
        ssh_stream_destroy(stream);
        return TRUE;
      }

  memset(&params, 0, sizeof(params));
  params.http_proxy_url = proxy_url;
  params.num_redirections = 0;

  req = ssh_xcalloc(1, sizeof(*req));
  req->server = ctx;
  req->conn = conn;
  req->server_stream = stream;

  req->client = ssh_http_client_init(&params);

  if (strcmp(method, "GET") == 0)
    ssh_http_get(req->client, uri, result_callback, req,
                 SSH_HTTP_HDR_END);
  else if (strcmp(method, "HEAD") == 0)
    ssh_http_head(req->client, uri, result_callback, req,
                  SSH_HTTP_HDR_END);
  else if (strcmp(method, "POST") == 0
           || strcmp(method, "PUT") == 0)
    {
      SSH_DEBUG(SSH_D_ERROR, ("%s not implemented yet", method));
      ssh_xfree(req);

      error = ssh_buffer_allocate();
      ssh_buffer_append_cstrs(error, "<body><h1>Method `", method,
                              "' not implemented yet</h1>\n", NULL);
      ssh_http_server_send_buffer(conn, error);
    }
  else
    {
      SSH_DEBUG(SSH_D_ERROR, ("unknown method `%s'", method));
      ssh_xfree(req);

      error = ssh_buffer_allocate();
      ssh_buffer_append_cstrs(error, "<body><h1>Unknown method `",
                              method, "'</h1>\n", NULL);

      ssh_http_server_send_buffer(conn, error);
    }

  return TRUE;
}


static Boolean
catch_handler(SshHttpServerContext ctx, SshHttpServerConnection conn,
              SshStream stream, void *context)
{
  SshBuffer data = ssh_buffer_allocate();

  ssh_buffer_append_cstrs(data,
                          "<body><h1>ProxyFilter Update Wizard</h1>\n",
                          NULL);
  ssh_http_server_send_buffer(conn, data);

  return TRUE;
}


static Boolean
authentication_handler(SshHttpServerContext ctx,
                       SshHttpServerConnection conn,
                       SshStream stream, void *context)
{
  SshHttpAuthentication auth;
  char *name;
  char *password;

  auth = ssh_http_server_get_proxy_authentication(conn, &name, &password);

  switch (auth)
    {
    case SSH_HTTP_AUTHENTICATION_NONE:
      break;

    case SSH_HTTP_AUTHENTICATION_BASIC:
      fprintf(stderr, "%s: authentication: name=%s, password=%s\n",
              program, name, password);
      ssh_xfree(name);
      ssh_xfree(password);

      /* Allow access. */
      return FALSE;
      break;
    }

  /* Deny access. */
  ssh_http_server_error_proxy_authentication_required(conn, "WWW Proxy");
  ssh_stream_destroy(stream);
  return TRUE;
}


static void
result_callback(SshHttpClientContext ctx, SshHttpResult result,
                SshTcpError ip_error, SshStream stream, void *callback_context)
{
  ProxyRequest *req = callback_context;
  SshBuffer error;
  char buf[256];

  switch (result)
    {
    case SSH_HTTP_RESULT_SUCCESS:
      {
        const char *value = NULL;
        SshCopyStreamCopyCb copy_cb = copy_data;

        if ((value = ssh_http_get_header_field(ctx, "Content-Type")))
          ssh_http_server_set_values(req->conn,
                                     SSH_HTTP_HDR_FIELD,
                                     "Content-Type", value,
                                     SSH_HTTP_HDR_END);

        req->client_stream = stream;

#if SMART_UPDATE
        if (value && strncmp(value, "text/html", 9) == 0)
          copy_cb = filter_html;
#endif

        ssh_copy_stream(req->server_stream, req->client_stream,
                        copy_cb, req_finish, req);
      }
      break;

    case SSH_HTTP_RESULT_MALFORMED_URL:
      error = ssh_buffer_allocate();

      ssh_buffer_append_cstrs(error, "<body><h1>Malformed URL</h1>n", NULL);
      ssh_http_server_send_buffer(req->conn, error);

      ssh_xfree(req);
      break;

    case SSH_HTTP_RESULT_REDIRECT_LIMIT_EXCEEDED:
      {
        const char *location = ssh_http_get_header_field(ctx, "Location");
        const char *reason_phrase;

        SSH_DEBUG(SSH_D_HIGHSTART, ("Redirect: %s", location));
        ssh_http_server_error(req->conn,
                              ssh_http_get_status_code(ctx, &reason_phrase),
                              SSH_HTTP_HDR_LOCATION, location,
                              SSH_HTTP_HDR_END);

        ssh_stream_destroy(req->server_stream);
        ssh_xfree(req);

      }
      break;

    case SSH_HTTP_RESULT_HTTP_ERROR:
      {
        const char *reason_phrase;
        SshUInt32 error_code;

        error_code = ssh_http_get_status_code(ctx, &reason_phrase);
        error = ssh_buffer_allocate();

        ssh_snprintf(buf, sizeof(buf), "%ld", error_code);

        ssh_http_server_error(req->conn, error_code,
                              SSH_HTTP_HDR_END);

        ssh_buffer_append_cstrs(error,
                                "<body><h1>HTTP Error (", buf,
                                ")</h1>\n<pre>\n",
                                reason_phrase, "\n", NULL);
        ssh_http_server_send_buffer(req->conn, error);

        ssh_xfree(req);
      }
      break;

    default:
      error = ssh_buffer_allocate();

      ssh_snprintf(buf, sizeof(buf), "%d", result);

      ssh_buffer_append_cstrs(error,
                              "<body><h1>HTTP Library Error ", buf, "</h1>\n",
                              NULL);
      ssh_http_server_send_buffer(req->conn, error);
      ssh_xfree(req);
      break;
    }
}


static void
copy_data(SshBuffer to, SshBuffer from, Boolean eof_seen, void *context)
{
  ssh_buffer_append(to, ssh_buffer_ptr(from), ssh_buffer_len(from));
  ssh_buffer_clear(from);
}


static void
req_finish(void *context)
{
  ProxyRequest *req = context;

  /* The ssh_copy_stream() destroys the streams. */

  ssh_http_client_uninit(req->client);
  ssh_xfree(req);
}


#if SMART_UPDATE
static void
filter_html(SshBuffer to, SshBuffer from, Boolean eof_seen, void *context)
{
  ProxyRequest *req = context;
  unsigned char *cp;
  size_t len;
  size_t i;

 restart:

  cp = ssh_buffer_ptr(from);
  len = ssh_buffer_len(from);

  for (i = 0; i < len; i++)
    {
      switch (req->state)
        {
        case FILTER_TEXT:
          if (cp[i] == '<')
            {
              ssh_buffer_append(to, cp, i);
              ssh_buffer_consume(from, i);

              len = ssh_buffer_len(from);
              cp = ssh_buffer_ptr(from);

              /* Is the end of the tag seen? */
              for (i = 0; i < len; i++)
                if (cp[i] == '>')
                  {
                    i++;
                    break;
                  }

              if (i >= len && !eof_seen)
                /* No, need more data. */
                return;

              /* Yes, it is seen. */

              if (i > 4 && strncasecmp(cp, "<img", 4) == 0)
                {
                  char *url = parse_img_src(cp, i);
                  ssh_buffer_append_cstrs(to,
                                          "<a href=\"http://amme.ssh.fi:8080",
                                          "/catch?url=", url, "\">*</a>",
                                          NULL);
                }

              ssh_buffer_append(to, cp, i);
              ssh_buffer_consume(from, i);

              goto restart;
            }
          else if (cp[i] == '&')
            req->state = FILTER_ENTITY;
          break;

        case FILTER_ENTITY:
          if (cp[i] == ';')
            req->state = FILTER_TEXT;
          break;
        }
    }

  ssh_buffer_append(to, ssh_buffer_ptr(from), ssh_buffer_len(from));
  ssh_buffer_clear(from);
}


static char *
parse_img_src(char *data, size_t len)
{
  int i;

  for (i = 0; i < len - 7; i++)
    {
      if ((data[i] == 's' || data[i] == 'S')
          && (data[i + 1] == 'r' || data[i + 1] == 'R')
          && (data[i + 2] == 'c' || data[i + 2] == 'C')
          && data[i + 3] == '='
          && data[i + 4] == '"')
        {
          int start = i + 5;

          for (i += 6; i < len && data[i] != '"'; i++)
            ;

          return ssh_xmemdup(data + start, i - start);
        }
    }

  return "???";
}
#endif
