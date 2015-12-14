/*
 *
 * httpserver.c
 *
 * Author: Markku Rossi <mtr@ssh.fi>
 *
 *  Copyright:
 *          Copyright (c) 2002 - 2004 SFNT Finland Oy.
 *               All rights reserved.
 *
 * Test server for the SSH HTTP library.
 *
 */

#include "sshincludes.h"
#include "sshhttp.h"
#include "sshmatch.h"
#include "sshtimeouts.h"
#include "ssheloop.h"
#include "sshgetopt.h"
#include "sshnameserver.h"

#ifdef TLS
#include "sshtls.h"
#include "sshcrypt.h"
#include "cmi.h"
#include "x509.h"
#include "sshfileio.h"
#include "sshdirectory.h"
#endif

#define SSH_DEBUG_MODULE "SshHttpServer"

/*
 * Global variables.
 */

/* Program name. */
char *program;

/* Flush after each write to the output stream. */
Boolean flushed_writes = FALSE;

#ifdef TLS
SshTlsConfigurationStruct tls_configuration;
#endif

/*
 * Prototypes for static functions.
 */

static void usage(void);

/* The default authentication handler. */
static Boolean authentication_handler(SshHttpServerContext ctx,
                                      SshHttpServerConnection conn,
                                      SshStream stream, void *context);

/* The default file handler. */
static Boolean file_handler(SshHttpServerContext ctx,
                            SshHttpServerConnection conn,
                            SshStream stream, void *context);

/* Echo handler.  Echo everything POSTed or PUT in the request. */
static Boolean echo_handler(SshHttpServerContext ctx,
                            SshHttpServerConnection conn,
                            SshStream stream, void *context);

/* Garbage handler.  Generate infinitely garbage. */
static Boolean garbage_handler(SshHttpServerContext ctx,
                               SshHttpServerConnection conn,
                               SshStream stream, void *context);

/* Another Garbage handler.  Generate a buffer of garbage. */
static Boolean garbage_buffer_handler(SshHttpServerContext ctx,
                                      SshHttpServerConnection conn,
                                      SshStream stream, void *context);

/* Exit handler.  This will stop the server. */
static Boolean exit_handler(SshHttpServerContext ctx,
                            SshHttpServerConnection conn,
                            SshStream stream, void *context);

/* Error handler.  This will send an HTTP error to the client. */
static Boolean error_handler(SshHttpServerContext ctx,
                             SshHttpServerConnection conn,
                             SshStream stream, void *context);

#ifdef TLS
/* Read in certificates and private keys from the directory
   `directory'.  All root certificates are assumed trusted. */
static void read_certs_and_keys(SshCMContext cert_manager,
                                const char *directory);

/* Wrap TLS protocol around an incoming TCP/IP stream. */
static SshStream tls_wrapper(SshHttpServerConnection conn,
                             SshStream stream, void *context);
#endif


/* Stream wrapper that convert all data to upper-case. */
static SshStream upper_case_wrapper(SshHttpServerConnection conn,
                                    SshStream stream,
                                    void *context);

/*
 * Global functions.
 */

int
main(int argc, char *argv[])
{
  int c;
#ifdef TLS
  const char *debug_string="SshHttp*=9,SshTls*=5";
#else /* not TLS */
  const char *debug_string="SshHttp*=5";
#endif /* not TLS */
  SshHttpServerParams params;
  SshHttpServerContext ctx;

#ifdef TLS
  char *tls_cert_dir = NULL;
  Boolean tls_weak_ciphers = FALSE;
  Boolean tls_caching = TRUE;
  Boolean tls_client_auth = FALSE;

  if (!ssh_x509_library_initialize(NULL))
    ssh_fatal("Failed to initialize the certificate/crypto library.");

#endif /* TLS */

  memset(&params, 0, sizeof(params));
  params.port = "8080";

#if !defined(WIN32) && 1
  signal(SIGPIPE, SIG_IGN);
#endif /* not WIN32 */

  /* Remove the directory part from the program name. */
  program = strrchr(argv[0], '/');
  if (program == NULL)
    program = argv[0];
  else
    program++;

  /* Parse options. */
  while ((c = ssh_getopt(argc, argv, "d:fhp:u"
#ifdef TLS
                         "c:wan"
#endif
                         , NULL)) != EOF)
    {
      switch (c)
        {
        case 'd':
          debug_string = ssh_optarg;
          break;

        case 'f':
          flushed_writes = TRUE;
          break;

        case 'h':
          usage();
          exit(0);
          break;

        case 'p':
          params.port = ssh_optarg;
          break;


        case 'u':
          params.tcp_wrapper = upper_case_wrapper;
          params.tcp_wrapper_context = NULL;
          break;

        case '?':
          fprintf(stderr, "Try `%s -h' for more information.\n", program);
          exit(1);
          break;

#ifdef TLS
        case 'c':
          tls_cert_dir = ssh_optarg;
          break;

        case 'w':
          tls_weak_ciphers = TRUE;
          break;

        case 'a':
          tls_client_auth = TRUE;
          break;

        case 'n':
          tls_caching = FALSE;
          break;
#endif /* TLS */
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

#ifdef TLS
  {
    SshCMConfig conf = ssh_cm_config_allocate();
    ssh_tls_configuration_defaults(&tls_configuration);
    tls_configuration.cert_manager = ssh_cm_allocate(conf);

    if (tls_caching)
      {
        tls_configuration.session_cache
          = ssh_tls_create_session_cache(100, 600);
      }

    read_certs_and_keys(tls_configuration.cert_manager, tls_cert_dir);

    tls_configuration.temporary_key =
      ssh_tls_create_temporary_key(6000);

    tls_configuration.is_server = TRUE;

    if (tls_weak_ciphers)
      tls_configuration.flags |= SSH_TLS_WEAKCIPHERS;

    if (tls_client_auth)
      tls_configuration.flags |= SSH_TLS_CLIENTAUTH;

    tls_configuration.flags |= SSH_TLS_SSL2;

    tls_configuration.key_exchange_timeout = 500;

    params.tcp_wrapper = tls_wrapper;
    params.tcp_wrapper_context = NULL;
  }
#endif

  ctx = ssh_http_server_start(&params);

  if (ctx)
    {
      /* Set the URI handlers. */
      ssh_http_server_set_handler(ctx, "/garbage*", 0, garbage_handler,
                                  NULL);
      ssh_http_server_set_handler(ctx, "/buffer_garbage*", 0,
                                  garbage_buffer_handler, NULL);
      ssh_http_server_set_handler(ctx, "/exit", 0, exit_handler, NULL);
      ssh_http_server_set_handler(ctx, "/error", 0, error_handler, NULL);
      ssh_http_server_set_handler(ctx, "/echo*", 0, echo_handler, NULL);
      ssh_http_server_set_handler(ctx, "*", 0, file_handler, NULL);

      /* Protect `/documents*' URL space. */
      ssh_http_server_set_handler(ctx, "/documents*", 10,
                                  authentication_handler, NULL);

      ssh_event_loop_run();

      ssh_http_server_stop(ctx, NULL_FNPTR, NULL);
    }
  else
    fprintf(stderr, "%s: couldn't create listener\n", program);

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
  fprintf(stderr, "Usage: %s [OPTION]...\n"
"  -d DEBUG       set debug level according to debug string DEBUG\n"
"  -f             flush output after each write to the output stream\n"
"  -h             print this help and exit\n"
"  -p PORT        listent to port PORT\n"
#ifdef TLS
"TLS server specific options:\n"
"  -c DIR         read in certificates from the directory DIR\n"
"  -w             enable weak ciphers\n"
"  -a             require client authentication\n"
"  -n             disable session caching (default is to enable)\n"
#endif
          , program);
}


/*
 * The URI handlers.
 */

static Boolean
authentication_handler(SshHttpServerContext ctx,
                       SshHttpServerConnection conn,
                       SshStream stream, void *context)
{
  SshHttpAuthentication auth;
  char *name;
  char *password;

  auth = ssh_http_server_get_authentication(conn, &name, &password);

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
  ssh_http_server_error_unauthorized(conn, "FooDocuments");
  ssh_stream_destroy(stream);
  return TRUE;
}


/* File. */

/* File handler stream context. */
struct FileHandlerStreamContextRec
{
  FILE *fp;
  unsigned char buf[128];
  size_t data_in_buf;
  size_t bufpos;
  SshStream stream;
  SshHttpServerConnection conn;
};

typedef struct FileHandlerStreamContextRec FileHandlerStreamContext;


static void
file_handler_stream_callback(SshStreamNotification notification,
                             void *context)
{
  FileHandlerStreamContext *ctx = (FileHandlerStreamContext *) context;
  int i;

  /* Ignore the notification. */

  while (1)
    {
      /* Do we have any data in our buffer? */
      if (ctx->bufpos >= ctx->data_in_buf)
        {
          /* Read more. */
          i = fread(ctx->buf, 1, sizeof(ctx->buf), ctx->fp);
          if (i <= 0)
            {
              /* Assume EOF. */
            eof:
              fclose(ctx->fp);
              ssh_stream_destroy(ctx->stream);
              ssh_xfree(ctx);
              return;
            }

          ctx->data_in_buf = i;
          ctx->bufpos = 0;
        }

      i = ssh_stream_write(ctx->stream, ctx->buf + ctx->bufpos,
                           ctx->data_in_buf - ctx->bufpos);
      if (i == 0)
        {
          /* EOF. */
          goto eof;
        }
      else if (i < 0)
        /* Would block. */
        return;
      else
        {
          ctx->bufpos += i;
          if (flushed_writes)
            ssh_http_server_flush(ctx->conn);
        }
    }
}


static Boolean
file_handler(SshHttpServerContext server_ctx, SshHttpServerConnection conn,
             SshStream stream, void *context)
{
  FileHandlerStreamContext *ctx;
  FILE *fp;
  const char *uri;
  char *path;
  int i;
  char *prefix = "/ssh/www";
  struct stat stat_st;
  char cookie_visit_count[256];
  Boolean is_cooked = FALSE;
  const SshHttpCookie *cookies;
  unsigned int num_cookies;

  uri = ssh_http_server_get_uri(conn);

  fprintf(stderr, "%s: file_handler(): uri=%s\n", program, uri);

  if (strcmp(uri, "/empty") == 0)
    {
      ssh_stream_destroy(stream);
      return TRUE;
    }
  if (strcmp(uri, "/") == 0)
    {
      ssh_http_server_error(conn, 301,
                            SSH_HTTP_HDR_LOCATION_RELATIVE, "/i/",
                            SSH_HTTP_HDR_END);
      ssh_stream_destroy(stream);
      return TRUE;
    }

  i = strlen(uri);
  if (i > 0 && uri[i - 1] == '/')
    {
      path = ssh_xmalloc(strlen(prefix) + i + strlen("index.html") + 1);
      strcpy(path, prefix);
      strcpy(path + strlen(prefix), uri);
      strcpy(path + strlen(prefix) + i, "index.html");
    }
  else
    {
      path = ssh_xmalloc(strlen(prefix) + strlen(uri) + 1);
      strcpy(path, prefix);
      strcpy(path + strlen(prefix), uri);
    }

  fp = fopen(path, "r");
  if (fp == NULL)
    {
      fprintf(stderr, "%s: couldn't open file `%s': %s\n", program, path,
              strerror(errno));

      ssh_http_server_error_not_found(conn);
      ssh_stream_destroy(stream);
      ssh_xfree(path);
      return TRUE;
    }

  if (stat(path, &stat_st) >= 0)
    {
      ssh_http_server_set_values(conn,
                                 SSH_HTTP_HDR_CONTENT_LENGTH,
                                 (size_t) stat_st.st_size,
                                 SSH_HTTP_HDR_LAST_MODIFIED,
                                 (SshTime) stat_st.st_mtime,
                                 SSH_HTTP_HDR_END);
    }

  ssh_http_server_set_values(conn,
                             SSH_HTTP_HDR_FIELD, "X-Foobar", "bar",
                             SSH_HTTP_HDR_DATE, ssh_time(),
                             SSH_HTTP_HDR_END);

  /* Handle the `VisitCount' cookie. */
  if (ssh_match_pattern(uri, "*.html"))
    {
      strcpy(cookie_visit_count, "1");
      cookies = ssh_http_server_get_cookies(conn, &num_cookies);
      for (i = 0; (unsigned int) i < num_cookies; i++)
        {
          if (strcmp(cookies[i].name, "VisitCount") == 0)
            {
              is_cooked = TRUE;
              ssh_snprintf(cookie_visit_count, sizeof(cookie_visit_count),
                           "%u", atoi(cookies[i].value) + 1);
            }
        }

      ssh_http_server_set_values(conn,
#if 1
                                 SSH_HTTP_HDR_COOKIE, "VisitCount",
                                 cookie_visit_count,
                                 SSH_HTTP_HDR_COOKIE_PATH, "/",
#if 0
                                 SSH_HTTP_HDR_COOKIE_MAX_AGE,
                                 (SshTime) 60 * 60 * 24,
                                 SSH_HTTP_HDR_COOKIE_SEND_EXPIRES,
#endif
#endif
#if 1
                                 SSH_HTTP_HDR_COOKIE, "ServerMagic", "m!a!gic",
                                 SSH_HTTP_HDR_COOKIE_PATH, "/",
#if 0
                                 SSH_HTTP_HDR_COOKIE_MAX_AGE,
                                 (SshTime) 60 * 60,
                                 SSH_HTTP_HDR_COOKIE_SEND_EXPIRES,
#endif
#endif
                                 SSH_HTTP_HDR_END);
    }

  ssh_xfree(path);

  ctx = ssh_xcalloc(1, sizeof(*ctx));
  ctx->fp = fp;
  ctx->stream = stream;
  ctx->conn = conn;

  if (is_cooked)
    {
      ssh_snprintf((char *)ctx->buf, sizeof(ctx->buf),
                   "<h1>You have loaded these pages %s times</h1>\n",
                   cookie_visit_count);
      ctx->data_in_buf = strlen((char *)ctx->buf);
    }

  ssh_stream_set_callback(stream, file_handler_stream_callback, ctx);
  file_handler_stream_callback(SSH_STREAM_INPUT_AVAILABLE, ctx);

  return TRUE;
}


/* Echo. */

struct EchoHandlerStreamContextRec
{
  unsigned char buf[4096];
  size_t data_in_buf;
  size_t bufpos;
  SshStream stream;
};

typedef struct EchoHandlerStreamContextRec EchoHandlerStreamContext;


static void
echo_handler_stream_callback(SshStreamNotification notification,
                             void *context)
{
  EchoHandlerStreamContext *ctx = (EchoHandlerStreamContext *) context;
  int i;

  /* Couldn't care less about the notification. */

  while (1)
    {
      /* Do we have any data in our buffer? */
      if (ctx->bufpos >= ctx->data_in_buf)
        {
          /* Read more. */
          i = ssh_stream_read(ctx->stream, ctx->buf, sizeof(ctx->buf));
          if (i == 0)
            {
              /* Assume EOF. */
            eof:
              ssh_stream_destroy(ctx->stream);
              ssh_xfree(ctx);
              return;
            }
          if (i < 0)
            /* Would block. */
            return;

          ctx->data_in_buf = i;
          ctx->bufpos = 0;
        }

      i = ssh_stream_write(ctx->stream, ctx->buf + ctx->bufpos,
                           ctx->data_in_buf - ctx->bufpos);
      if (i == 0)
        {
          /* EOF. */
          goto eof;
        }
      else if (i < 0)
        /* Would block. */
        return;
      else
        ctx->bufpos += i;
    }
}


static Boolean
echo_handler(SshHttpServerContext ctx, SshHttpServerConnection conn,
             SshStream stream, void *context)
{
  EchoHandlerStreamContext *stream_ctx;

  fprintf(stderr, "%s: echo_handler()\n", program);

  stream_ctx = ssh_xcalloc(1, sizeof(*stream_ctx));
  stream_ctx->stream = stream;

  ssh_stream_set_callback(stream, echo_handler_stream_callback, stream_ctx);
  echo_handler_stream_callback(SSH_STREAM_INPUT_AVAILABLE, stream_ctx);

  return TRUE;
}


/* Garbage. */

struct GarbageHandlerStreamContextRec
{
  char buf[4096];
  size_t data_in_buf;
  size_t bufpos;
  int line;
  const char *uri;
  SshStream stream;
  SshHttpServerConnection conn;
};

typedef struct GarbageHandlerStreamContextRec GarbageHandlerStreamContext;

static void garbage_handler_stream_callback(SshStreamNotification notification,
                                            void *context);


static void
garbage_more_timeout(void *context)
{
  GarbageHandlerStreamContext *ctx = (GarbageHandlerStreamContext *) context;

  /* Format the next line of output. */
  ssh_snprintf(ctx->buf, sizeof(ctx->buf), "Garbage line %d: %s\n",
               ctx->line++, ctx->uri);
  ctx->data_in_buf = strlen(ctx->buf);
  ctx->bufpos = 0;

  garbage_handler_stream_callback(SSH_STREAM_CAN_OUTPUT, context);
}


static void
garbage_handler_stream_callback(SshStreamNotification notification,
                                void *context)
{
  GarbageHandlerStreamContext *ctx = (GarbageHandlerStreamContext *) context;
  int i = 0;

  /* Couldn't care less about the notification. */

  while (ctx->bufpos < ctx->data_in_buf)
    {
      i = ssh_stream_write(ctx->stream, (unsigned char *)
                           (ctx->buf + ctx->bufpos),
                           ctx->data_in_buf - ctx->bufpos);

      if (i == 0)
        {
          /* EOF. */
          ssh_cancel_timeouts(garbage_more_timeout, ctx);
          ssh_stream_destroy(ctx->stream);
          ssh_xfree(ctx);
          return;
        }
      else if (i < 0)
        /* Would block. */
        return;

      ctx->bufpos += i;
      ssh_http_server_flush(ctx->conn);
    }

  if (i > 0)
    ssh_xregister_timeout(1, 0, garbage_more_timeout, ctx);
}


static Boolean
garbage_handler(SshHttpServerContext ctx, SshHttpServerConnection conn,
                SshStream stream, void *context)
{
  GarbageHandlerStreamContext *stream_ctx;

  fprintf(stderr, "%s: garbage_handler()\n", program);

  stream_ctx = ssh_xcalloc(1, sizeof(*stream_ctx));
  stream_ctx->stream = stream;
  stream_ctx->conn = conn;
  stream_ctx->uri = ssh_http_server_get_uri(conn);

  ssh_http_server_set_values(conn,
                             SSH_HTTP_HDR_FIELD, "Content-Type", "text/plain",
                             SSH_HTTP_HDR_END);

  ssh_stream_set_callback(stream, garbage_handler_stream_callback, stream_ctx);
  garbage_more_timeout(stream_ctx);

  return TRUE;
}

static Boolean
garbage_buffer_handler(SshHttpServerContext ctx, SshHttpServerConnection conn,
                       SshStream stream, void *context)
{
  SshBuffer buffer;

  /* This is quite easy. */
  buffer = ssh_buffer_allocate();

  /* Generate the output. */
  ssh_http_server_set_values(conn,
                             SSH_HTTP_HDR_FIELD, "Content-Type", "text/html",
                             SSH_HTTP_HDR_END);

  ssh_buffer_append_cstrs(buffer,
                          "<html><body>",
                          "<h1>Hello, world!  ",
                          "This is a buffer full of garbage</h1>\n",
                          "Garbage, garbage, garbage<p>\n",
                          "</body></html>\n",
                          NULL);

  ssh_http_server_send_buffer(conn, buffer);

  return TRUE;
}


static Boolean
exit_handler(SshHttpServerContext ctx, SshHttpServerConnection conn,
             SshStream stream, void *context)
{
  ssh_http_server_stop(ctx, NULL_FNPTR, NULL);
  ssh_stream_destroy(stream);

  return TRUE;
}

static Boolean
error_handler(SshHttpServerContext ctx, SshHttpServerConnection conn,
              SshStream stream, void *context)
{
  SshBuffer buffer = ssh_buffer_allocate();

  ssh_buffer_append_cstrs(buffer,
                          "<h1>This is a bug report</h1>\n"
                          "<pre>Your client did not send content length\n",
                          NULL);

  ssh_http_server_error(conn, 411,
                        SSH_HTTP_HDR_END);
  ssh_http_server_send_buffer(conn, buffer);

  return TRUE;
}

/* TLS specific functions. */
#ifdef TLS
SshPrivateKey get_private_key(char *filename)
{
  unsigned char *buf;
  size_t len;
  SshPrivateKey key;
  char *keyname;

  if (!ssh_read_file(filename, &buf, &len))
    {
      SSH_DEBUG(7, ("Can't open the private key file `%s'.", filename));
      return NULL;
    }

  key = ssh_x509_decode_private_key(buf, len);

  if (key == NULL)
    {
      SSH_DEBUG(7, ("Couldn't import the private key."));
      return NULL;
    }

  keyname = ssh_private_key_name(key);

  fprintf(stderr, "Loaded private key `%s'.\n", keyname);

  ssh_xfree(keyname);

  tls_configuration.private_key = key;

  return key;
}

static void load_cert(SshCMContext cert_manager, char *name)
{
  unsigned char *buf;
  size_t len;

  SshCMCertificate cert = ssh_cm_cert_allocate(cert_manager);

  if (!ssh_read_file(name, &buf, &len))
    {
      SSH_DEBUG(7, ("Can't open cert file `%s'.", name));
      return;
    }

  SSH_DEBUG(7, ("Adding certificate from the cert file `%s'.", name));

  if (ssh_cm_cert_set_ber(cert, buf, len) != SSH_CM_STATUS_OK)
    {
      SSH_DEBUG(7, ("Couldn't add the certificate to the manager."));
      ssh_xfree(buf);
      return;
    }

  ssh_xfree(buf);
  ssh_cm_cert_non_crl_issuer(cert);

  {
    char *issuer, *subject;
    SshX509Certificate c;

    if (ssh_cm_cert_get_x509(cert, &c) == SSH_CM_STATUS_OK)
      {
        ssh_x509_cert_get_subject_name(c, &subject);
        ssh_x509_cert_get_issuer_name(c, &issuer);

        fprintf(stderr, "Certificate %s <= %s",
                subject, issuer);

        if (!strcmp(issuer,subject))
          {
            ssh_cm_cert_force_trusted(cert);
            fprintf(stderr, " [trusted root]");
          }

        fprintf(stderr, "\n");

        ssh_xfree(issuer);
        ssh_xfree(subject);
        ssh_x509_cert_free(c);
      }
  }

  if (ssh_cm_add(cert) != SSH_CM_STATUS_OK)
    {
      ssh_fatal("CM didn't accept the certificate.");
      return;
    }
}

static void read_certs_and_keys(SshCMContext cert_manager, const char *name)
{
  SshDirectoryHandle dir;
  const char *fname;
  int l;
  char buf[1000];

  if (name == NULL) name = ".";

  dir = ssh_directory_open(name);

  if (dir == NULL)
    ssh_fatal("Cannot open the certificates directory `%s'.",
              name);

  while (ssh_directory_read(dir))
    {
      fname = ssh_directory_file_name(dir);
      l = strlen(fname);
      ssh_snprintf(buf, 1000, "%s/%s", name, fname);
      if (((l > 4) && !strcmp(fname + l - 4, ".crt")) ||
          ((l > 3) && !strcmp(fname + l - 3, ".ca")))
        {
          load_cert(cert_manager, buf);
        }
      if ((l > 4) && !strcmp(fname + l - 4, ".prv"))
        {
          get_private_key(buf);
        }
    }

  ssh_directory_close(dir);
}

static SshStream tls_wrapper(SshHttpServerConnection conn,
                             SshStream stream, void *context)
{
  return ssh_tls_server_wrap(stream, &tls_configuration);
}
#endif



/*
 * Test for the stream wrapper.
 */

typedef enum
{
  UCW_IN_TEXT = 0,
  UCW_IN_TAG,
  UCW_IN_ENTITY
} UpperCaseWrapperState;

struct UpperCaseWrapperCtxRec
{
  /* The wrapper stream. */
  SshStream stream;

  /* Where are we? */
  UpperCaseWrapperState state;

  /* The user's callback for this stream. */
  SshStreamCallback callback;
  void *callback_context;
};

typedef struct UpperCaseWrapperCtxRec UpperCaseWrapperCtx;

static int
upper_case_wrapper_read(void *context, unsigned char *buf, size_t size)
{
  UpperCaseWrapperCtx *ctx = context;

  return ssh_stream_read(ctx->stream, buf, size);
}


static int
upper_case_wrapper_write(void *context, const unsigned char *buf, size_t size)
{
  UpperCaseWrapperCtx *ctx = context;
  size_t i;
  unsigned char *nbuf = ssh_xmemdup(buf, size);
  int wrote;

  for (i = 0; i < size; i++)
    {
      switch (ctx->state)
        {
        case UCW_IN_TEXT:
          if (nbuf[i] == '<')
            ctx->state = UCW_IN_TAG;
          else if (nbuf[i] == '&')
            ctx->state = UCW_IN_ENTITY;
          else
            {
              if (islower(nbuf[i]))
                nbuf[i] = toupper(nbuf[i]);
            }
          break;

        case UCW_IN_TAG:
          if (nbuf[i] == '>')
            ctx->state = UCW_IN_TEXT;
          break;

        case UCW_IN_ENTITY:
          if (nbuf[i] == ';')
            ctx->state = UCW_IN_TEXT;
          break;
        }
    }

  wrote = ssh_stream_write(ctx->stream, nbuf, size);

  ssh_xfree(nbuf);

  return wrote;
}


static void
upper_case_wrapper_output_eof(void *context)
{
  UpperCaseWrapperCtx *ctx = context;

  ssh_stream_output_eof(ctx->stream);
}


static void
upper_case_wrapper_set_callback(void *context, SshStreamCallback callback,
                                void *callback_context)
{
  UpperCaseWrapperCtx *ctx = context;

  ctx->callback = callback;
  ctx->callback_context = callback_context;
}

static void
upper_case_wrapper_destroy(void *context)
{
  UpperCaseWrapperCtx *ctx = context;

  ssh_stream_destroy(ctx->stream);
  ssh_xfree(ctx);
}


static SshStreamMethodsStruct upper_case_wrapper_methods_table =
{
  upper_case_wrapper_read,
  upper_case_wrapper_write,
  upper_case_wrapper_output_eof,
  upper_case_wrapper_set_callback,
  upper_case_wrapper_destroy,
};


static void
upper_case_wrapper_stream_cb(SshStreamNotification notification, void *context)
{
  UpperCaseWrapperCtx *ctx = context;

  if (ctx->callback)
    (*ctx->callback)(notification, ctx->callback_context);
}


static SshStream
upper_case_wrapper(SshHttpServerConnection conn,
                   SshStream stream, void *context)
{
  UpperCaseWrapperCtx *ctx = ssh_xcalloc(1, sizeof(*ctx));
  SshStream str;

  ctx->stream = stream;

  ssh_stream_set_callback(stream, upper_case_wrapper_stream_cb, ctx);

  str = ssh_stream_create(&upper_case_wrapper_methods_table, ctx);
  if (str == NULL)
    ssh_fatal("Insufficient memory to create HTTP read stream");
  return str;
}
