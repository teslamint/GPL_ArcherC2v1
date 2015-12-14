/*
 *
 * appgw_http_state.c
 *
 * Copyright:
 *       Copyright (c) 2002, 2003 SFNT Finland Oy.
 *       All rights reserved.
 *
 * State handling for HTTP Appgw.
 *
 */

#include "sshincludes.h"
#include "sshtimeouts.h"
#include "appgw_api.h"
#include "sshfsm.h"
#include "sshregex.h"
#include "sshinet.h"
#include "sshurl.h"

#include "appgw_http.h"
#include "appgw_http_internal.h"

#define SSH_DEBUG_MODULE "SshAppgwHttpState"

#ifdef SSHDIST_IPSEC_FIREWALL

/********************** Prototypes for utility functions *******************/

/* Return length of header-line contents (length of line excluding \r\n) */
static int
ssh_appgw_hdr_length(unsigned char *src, size_t src_len);

/* Return length of header-line contents (length of line including \r\n) */
static int
ssh_appgw_line_length(unsigned char *src, size_t src_len);

/* String to integer */
static int
ssh_appgw_hdr_strtoi(int *dst, unsigned char *src);

/* String to transfer encoding */
static int
ssh_appgw_hdr_str_to_transfer_encoding(SshAppgwHttpTransferEncoding *dst,
                                       unsigned char *src);

/* String to HTTP method */
static int
ssh_appgw_hdr_str_to_method(SshAppgwHttpMethod *dst, unsigned char *src);

/* Case-insensitive string comparison bounded by length */
static int
ssh_appgw_http_strncasecmp(const unsigned char *dst, const unsigned char *src,
                           size_t srclen);

/* Skip header-field name in buffer and return a pointer to content */
static unsigned char *
ssh_appgw_skip_hdr_field(unsigned char *src);

/* Get version string from HTTP request-line */
static unsigned char *
ssh_appgw_get_version_str(unsigned char *src);

/* Get a header line from buffer which begins with the prefix "hdr" */
static int
ssh_appgw_hdr_get_from_buf(const unsigned char *hdr, unsigned char *src,
                           size_t src_len, unsigned char **dst);

/* Check if header line begins with the prefix "hdr" */
static Boolean
ssh_appgw_hdr_cmp(const unsigned char *hdr, unsigned char *src,
                  size_t src_len);

static Boolean
ssh_appgw_parse_request_line(SshAppgwHttpIO io,
                             SshAppgwHttpConn con,
                             SshAppgwHttpState state,
                             unsigned char *req);

/* Parse a HTTP status-line */
static Boolean
ssh_appgw_parse_response_line(SshAppgwHttpIO io,
                              SshAppgwHttpConn con,
                              SshAppgwHttpState state,
                              unsigned char *response);


/**************** Utility functions ***********************************/

static int
ssh_appgw_http_strncasecmp(const unsigned char *dst, const unsigned char *src,
                           size_t srclen)
{
  while (srclen-- > 0)
    {
      if (*dst == '\0' || *src == '\0')
        {
          if (*dst == *src)
            return 0;

          return -1;
        }

      if (tolower(*src) != tolower(*dst))
        return -1;

      src++;
      dst++;
    }

  return 0;
}

static int
ssh_appgw_hdr_strtoi(int *dst, unsigned char *src)
{
  if (src == NULL)
    return -1;

  *dst = 0;
  while (*src != '\0' && *src == ' ')
    src++;

  if (*src == '\0')
    return 0;

  while (*src != '\0')
    {
      if (*src < '0' || *src > '9')
        return -1;

      *dst = *dst * 10 + (*src - '0');

      src++;
    }
  return 1;
}

static int
ssh_appgw_hdr_strtoi_hex(int *dst, unsigned char *src)
{
  if (src == NULL)
    return -1;

  *dst = 0;
  while (*src != '\0' && *src == ' ')
    src++;

  if (*src == '\0')
    return 0;

  while (*src != '\0')
    {
      if (*src >= '0' && *src <= '9')
        *dst = *dst * 16 + (*src - '0');
      else if (tolower(*src) >= 'a' && tolower(*src) <= 'f')
        *dst = *dst * 16 + (10 + tolower(*src) - 'a');
      else if (*src != ' ' && *src != '\t')
        return -1;

      src++;
    }
  return 1;
}


static int
ssh_appgw_hdr_str_to_transfer_encoding(SshAppgwHttpTransferEncoding *dst,
                                       unsigned char *src)
{
  *dst = 0;
  while (*src != '\0' && *src == ' ')
    src++;

  if (*src == '\0')
    return 0;

  if (ssh_appgw_hdr_cmp(ssh_custr("chunked"), src,
                        ssh_ustrlen(src)) == TRUE)
    {
      *dst = SSH_APPGW_HTTP_TE_CHUNKED;
      return 1;
    }

  return -1;
}

static int
ssh_appgw_hdr_str_to_method(SshAppgwHttpMethod *dst, unsigned char *src)
{
  if (*src == '\0')
    return 0;

  if (ssh_appgw_http_strncasecmp(src, ssh_custr("OPTIONS "),
                                 strlen("options ")) == 0)
    *dst = SSH_APPGW_HTTP_METHOD_OPTIONS;
  else if (ssh_appgw_http_strncasecmp(src, ssh_custr("GET "),
                                      strlen("get ")) == 0)
    *dst = SSH_APPGW_HTTP_METHOD_GET;
  else if (ssh_appgw_http_strncasecmp(src, ssh_custr("HEAD "),
                                      strlen("head ")) == 0)
    *dst = SSH_APPGW_HTTP_METHOD_HEAD;
  else if (ssh_appgw_http_strncasecmp(src, ssh_custr("POST "),
                                      strlen("post ")) == 0)
    *dst = SSH_APPGW_HTTP_METHOD_POST;
  else if (ssh_appgw_http_strncasecmp(src, ssh_custr("PUT "),
                                      strlen("put ")) == 0)
    *dst = SSH_APPGW_HTTP_METHOD_PUT;
  else if (ssh_appgw_http_strncasecmp(src, ssh_custr("DELETE "),
                                      strlen("delete ")) == 0)
    *dst = SSH_APPGW_HTTP_METHOD_DELETE;
  else if (ssh_appgw_http_strncasecmp(src, ssh_custr("TRACE "),
                                      strlen("trace ")) == 0)
    *dst = SSH_APPGW_HTTP_METHOD_TRACE;
  else if (ssh_appgw_http_strncasecmp(src, ssh_custr("CONNECT "),
                                      strlen("connect ")) ==0)
    *dst = SSH_APPGW_HTTP_METHOD_CONNECT;
  else
    {
      *dst = SSH_APPGW_HTTP_METHOD_NONE;
      return 0;
    }
  return 1;
}

static unsigned char *
ssh_appgw_get_version_str(unsigned char *url)
{
  unsigned char *version_str = NULL;

  /* Logic:
     1. Find first white space.
     2. Skip all consecutive white spaces.
     3. Find next white space following non-whitespace
     4. Skip all consecutive white spaces.
     5. Return remaining string. */

  while (*url != '\0' && *url != ' ')
    url++;

  if (*url != '\0')
    {
      while (*url != '\0' && *url == ' ')
        url++;

      if (*url != '\0')
        {
          while (*url != '\0' && *url != ' ')
            url++;

          if (*url != '\0')
            {
              while (*url != '\0' && *url == ' ')
                url++;

              if (*url != '\0')
                version_str = url;
            }
        }
    }
  return version_str;
}

static unsigned char *
ssh_appgw_skip_hdr_field(unsigned char *src)
{
  while (*src != '\0' && *src!= ':')
    src++;

  if (*src != '\0')
    {
      src++;
      while (*src != '\0' && *src == ' ')
        src++;
    }
  return src;
}

static int
ssh_appgw_line_length(unsigned char *src, size_t src_len)
{
  int i;

  if (src_len <= 0)
    return -1;

  for (i = 0; i < src_len && src[i] != '\n'; i++);

  if (i == src_len)
    return -1;

  if (src[i] != '\n')
    return -1;

  return i+1;

}

static int
ssh_appgw_hdr_length(unsigned char *src, size_t src_len)
{
  int i;

  i = ssh_appgw_line_length(src, src_len);

  if (i == -1)
    return -1;

  i=i-1;

  if (i > 0 && src[i-1] == '\r')
    return i-1;

  return i;
}

static void
ssh_appgw_dump_state(SshAppgwHttpState state)
{
  SSH_DEBUG(SSH_D_MY,("reading hdr %d",state->reading_hdr));
  SSH_DEBUG(SSH_D_MY,("reading body %d",state->reading_body));
  SSH_DEBUG(SSH_D_MY,("reading chunked hdr %d",
                          state->reading_chunk_hdr));
  SSH_DEBUG(SSH_D_MY,
            ("non_persistent %d",state->non_persistent_connection));

  SSH_DEBUG(SSH_D_MY,("internal http version %d",
                          state->http_version));
  SSH_DEBUG(SSH_D_MY,("transfer encoding %d",
                          state->transfer_encoding));
  SSH_DEBUG(SSH_D_MY,("body present %d",
                          state->message_body_present));
  SSH_DEBUG(SSH_D_MY,("nmsgs: %d",
                          state->nmsgs));

  if (state->body_length_valid)
    SSH_DEBUG(SSH_D_MY,("body length %d",state->body_length));
}

static unsigned char *
ssh_appgw_request_method_str_from_buf(SshAppgwHttpIO io,
                                      SshAppgwHttpState state)
{
  unsigned char *line;
  char *eptr;
  int res;

  res = ssh_appgw_hdr_get_from_buf(ssh_custr(""), io->buf, io->offset_in_buf,
                                   &line);

  if (res < 1 || line == NULL)
    return NULL;

  eptr = ssh_ustrchr(line, ' ');
  if (eptr != NULL)
    *eptr = '\0';

  return line;
}

static SshAppgwHttpRequestMethod
ssh_appgw_request_method_from_buf(SshAppgwHttpIO io,
                                  SshAppgwHttpState state)
{
  SshAppgwHttpRequestMethod m;
  unsigned char *line;
  int res;

  res = ssh_appgw_hdr_get_from_buf(ssh_custr(""), io->buf, io->offset_in_buf,
                                   &line);

  if (res < 1 || line == NULL)
    {
      return NULL;
    }

  m = ssh_malloc(sizeof(*m));
  if (m == NULL)
    {
      ssh_free(line);
      return NULL;
    }

  m->next = NULL;
  m->msg_number = state->nmsgs;

  res = ssh_appgw_hdr_str_to_method(&m->method, line);
  ssh_free(line);

  if (res != 1)
    {
      SSH_DEBUG(SSH_D_NETGARB,("unknown HTTP/1.1 method"));
      ssh_free(m);
      return NULL;
    }
  return m;
}

static unsigned char *
ssh_appgw_get_uri_from_buf(SshAppgwHttpIO io, SshAppgwHttpState state)
{
  unsigned char *url, *line;
  char *begin, *end;
  int len;

  url = NULL;

  len = ssh_appgw_hdr_get_from_buf(ssh_custr(""), io->buf, io->offset_in_buf,
                                   &line);

  if (len < 1 || line == NULL)
    return NULL;

  /* Find first whitespace */
  begin = ssh_ustrchr(line, ' ');

  if (begin == NULL)
    return NULL;

  /* Skip consecutive whitespaces */
  while (*begin == ' ' && *begin != '\0')
    begin++;

  if (*begin == '\0')
    return NULL;

  /* Find next white space or end of string or line */
  end = strchr(begin,' ');

  if (end == NULL)
    end = begin + strlen(begin);

  url = ssh_malloc(end-begin+1);
  if (url == NULL)
    {
      ssh_free(line);
      SSH_DEBUG(SSH_D_FAIL, ("out of memory error"));
      return NULL;
    }
  memcpy(url,begin,end-begin);
  url[end-begin] = '\0';

  ssh_free(line);
  return url;
}

static int
ssh_appgw_hdr_get_from_buf(const unsigned char *hdr, unsigned char *src,
                           size_t src_len, unsigned char **dst)
{
  int i;
  int len;

  i = ssh_appgw_line_length(src,src_len);

  *dst = NULL;

  if (i == -1)
    return 0;

  if (ssh_appgw_hdr_cmp(hdr,src,i) == TRUE)
    {
      len = ssh_appgw_hdr_length(src, i);

      *dst = ssh_malloc(len+1);

      if (*dst != NULL)
        {
          memcpy(*dst,src,len);
          (*dst)[len] = '\0';
        }
      return i;
    }
  return 0;
}

static Boolean
ssh_appgw_hdr_cmp(const unsigned char *hdr, unsigned char *src, size_t src_len)
{
  while (src_len-- > 0)
    {
      if (*hdr == '\0')
        return TRUE;

      /* Currently based on tolower(), which is unfortunately
         dependent on locale settings. Should this use a hard-coded
         table ? */

      if (tolower(*src) != tolower(*hdr))
        return FALSE;

      src++;
      hdr++;
    }

  if (*hdr == '\0')
    return TRUE;

  return FALSE;
}

/* Extract destination host for request */
static unsigned char *
ssh_appgw_http_get_dst_host(SshAppgwHttpIO io,
                            SshAppgwHttpConn con,
                            SshAppgwHttpState state)
{
  unsigned char *host, *tmp;
  int ip;

  host = NULL;

  /* Try to figure out host line in case we are not using HTTP/1.1 */
  if (state->http_version != SSH_APPGW_HTTP_HTTPV_11)
    {
      unsigned char *url;

      url = ssh_appgw_get_uri_from_buf(io,state);

      if (url != NULL)
        {
          SSH_DEBUG(SSH_D_MY,("parsing URL: %s",url));
          if (ssh_url_parse(url,NULL,&host,NULL,NULL,NULL,NULL) == FALSE)
            {
              host = NULL;
              SSH_DEBUG(SSH_D_NETGARB,
                        ("Could not extract host from URL"));
            }
          ssh_free(url);
        }
      else
        {
          SSH_DEBUG(SSH_D_NETGARB,
                    ("Could not extract Request-URI from Request-Line"));
          return NULL;
        }
    }
  else /* state->http_version == SSH_APPGW_HTTP_HTTPV_11 */
    {
      if (con->req_i.host_line_index >= 0)
        {
          int res;

          res = ssh_appgw_hdr_get_from_buf(ssh_custr("Host:"),
                                           io->buf +
                                           con->req_i.host_line_index,
                                           io->offset_in_buf -
                                           con->req_i.host_line_index,
                                           &host);

          if (res == 0)
            {
              SSH_DEBUG(SSH_D_FAIL,("Recorded Host line is not a "
                                    "host line!"));

              return NULL;
            }
          /* Out of memory */
          if (host == NULL)
            return NULL;

          tmp = ssh_appgw_skip_hdr_field(host);
          tmp = ssh_strdup(tmp);
          if (tmp == NULL)
            {
              ssh_free(host);
              return NULL;
            }
          ssh_free(host);
          host = tmp;
        }
    }

  if (host != NULL)
    {
      if (ssh_appgw_hdr_strtoi(&ip, host) == 1)
        {
          SshIpAddrStruct tmp;

          SSH_INT_TO_IP4(&tmp,ip);
          ssh_free(host);
          host = ssh_malloc(SSH_IP_ADDR_STRING_SIZE);

          if (host == NULL)
            return NULL;

          ssh_ipaddr_print(&tmp,host,64);
        }
    }
  else /* host == NULL */
    {
      SSH_DEBUG(SSH_D_NETGARB,
                ("Could not extract host line, using destination "
                 "IP address as host line"));

      /* Use IP Address */
      host = ssh_malloc(SSH_IP_ADDR_STRING_SIZE);
      if (host == NULL)
        return NULL;

      ssh_ipaddr_print(&con->ctx->responder_ip, host,64);
    }

  SSH_DEBUG(SSH_D_MY,("destination host: %s",host));

  return host;
}

/*********************** Functions for parsing HTTP stream **************/

/* Update buffer after having parsed a line in the header of length
   "res" bytes. */
static void
ssh_appgw_http_hdr_line(SshAppgwHttpIO io,
                        SshAppgwHttpConn con,
                        SshAppgwHttpState state,
                        int res)
{
  SSH_ASSERT(res >= 0);

  io->offset_in_buf += res;

  SSH_ASSERT(io->bufpos <= io->data_in_buf);
  SSH_ASSERT(io->offset_in_buf <= io->data_in_buf );
}

/* If a Host: header is present in a request, then store the offset
   of this header line in the buffer. */
static int
ssh_appgw_msg_handle_req_line(SshAppgwHttpConn con,
                              SshAppgwHttpIO io,
                              SshAppgwHttpState state)
{
  int res;
  unsigned char *src, *tmpbuf;
  size_t srclen;

  src = io->buf + io->offset_in_buf;
  srclen = io->data_in_buf - io->offset_in_buf;

  /* Check for Host:  header */

  res = ssh_appgw_hdr_get_from_buf(ssh_custr("Host:"), src, srclen, &tmpbuf);

  if (res > 0)
    {
      if (tmpbuf == NULL)
        return -1;

      con->req_i.host_line_index = io->offset_in_buf;

      ssh_free(tmpbuf);
      return res;
    }
  return 0;
}

static int
ssh_appgw_msg_handle_response_line(SshAppgwHttpConn con,
                                   SshAppgwHttpIO io,
                                   SshAppgwHttpState state)
{
  return 0;
}

/* Handle a header line that is not the initial (status or request-line). */
static int
ssh_appgw_msg_handle_line(SshAppgwHttpConn con,
                          SshAppgwHttpIO io,
                          SshAppgwHttpState state)
{
  int ok, res, body_len;
  unsigned char *src, *body, *tmpbuf;
  size_t srclen;

  src = io->buf + io->offset_in_buf;
  srclen = io->data_in_buf - io->offset_in_buf;

  /* Check for "Content-Length:" */

  res = ssh_appgw_hdr_get_from_buf(ssh_custr("Content-Length:"),
                                   src, srclen, &tmpbuf);

  if (res > 0)
    {
      if (tmpbuf == NULL)
        return -1;

      state->body_length = 0;
      body = ssh_appgw_skip_hdr_field(tmpbuf);
      ok = ssh_appgw_hdr_strtoi(&body_len, body);
      ssh_free(tmpbuf);

      if (ok == -1 || body_len < 0)
        {
          SSH_DEBUG(SSH_D_MY,
                    ("Could not parse Content-Length header"));
          return -1;
        }
      state->body_length = body_len;
      state->body_length_valid = 1;
      return res;
    }


  /* Check for Transfer-Encoding header */

  res = ssh_appgw_hdr_get_from_buf(ssh_custr("Transfer-Encoding:"),
                                   src, srclen, &tmpbuf);

  if (res > 0)
    {
      if (tmpbuf == NULL)
        return -1;

      body = ssh_appgw_skip_hdr_field(tmpbuf);
      ok=ssh_appgw_hdr_str_to_transfer_encoding(&state->transfer_encoding,
                                                body);
      ssh_free(tmpbuf);

      if (ok < 1)
        {
          SSH_DEBUG(SSH_D_MY,
                    ("Could not parse Transfer-Encoding header"));


          return -1;
        }
      return res;
    }

  /* Check request/reply specific headers */

  if (state == &con->state_i)
    return ssh_appgw_msg_handle_req_line(con,io,state);
  else if (state == &con->state_r)
    return ssh_appgw_msg_handle_response_line(con,io,state);
  else
    {
      SSH_NOTREACHED;
    }
  return -1;
}

/* Handle HTTP/1.x CONNECT method. */
static int
ssh_appgw_handle_connect_method(SshAppgwHttpConn con,
                                SshAppgwHttpState state)
{
  int code;

  if (state == &con->state_r)
    {
      if (con->reply_r.current_method == SSH_APPGW_HTTP_METHOD_CONNECT)
        {
          code = con->reply_r.return_code;

          if (code >= 200 && code <= 299)
            {
              /* A 2xx response was received to a CONNECT method. Enable
                 transparent tunneling. */

              SSH_DEBUG(SSH_D_MIDOK,("Enabling tunneling for CONNECT method"));

              con->state_r.reading_hdr = 0;
              con->state_r.reading_body = 1;
              con->state_r.body_length_valid = 0;
              con->state_r.transfer_encoding = SSH_APPGW_HTTP_TE_NONE;
              con->state_r.flush_buf = 1;

              con->state_i.reading_hdr = 0;
              con->state_i.reading_body = 1;
              con->state_i.body_length_valid = 0;
              con->state_i.transfer_encoding = SSH_APPGW_HTTP_TE_NONE;
              con->state_r.flush_buf = 1;
              return 1;
            }
        }
    }
  return 0;
}

/* Update state to reflect a "received complete HTTP header" event.
   This function examines the request for whether a message-body
   is present, whether a transparent tunnel should be opened
   and whether the connection may be persistent. */
static void
ssh_appgw_msg_end_sent(SshAppgwHttpConn con,
                       SshAppgwHttpState state)
{
  state->reading_hdr = 0;
  state->reading_body = 1;
  state->flush_buf = 1;
  state->body_read = 0;

  /* Determine if there exists a message body */

  if (state == &con->state_i)
    {
      state->nmsgs++;

      if ((state->body_length_valid == 1 && state->body_length > 0)
           || state->transfer_encoding == SSH_APPGW_HTTP_TE_CHUNKED)
        state->message_body_present = 1;
      else
        state->message_body_present = 0;

      if (state->http_version == SSH_APPGW_HTTP_HTTPV_09)
        {
          /* HTTP / 0.9 replies do not have headers, so prep the responder
             state to read the message body here */
          ssh_appgw_msg_begin(con,&con->state_r);
          con->state_r.http_version = SSH_APPGW_HTTP_HTTPV_09;
          con->state_r.reading_body = 1;
          con->state_r.reading_hdr = 0;
          con->state_r.body_read = 0;
          con->state_r.message_body_present = 1;
          con->state_r.non_persistent_connection = 1;

          if (con->io_r.active == 1)
            ssh_fsm_continue(&con->thread_r);
        }
    }
  else if (state == &con->state_r)
    {
      /* Handle continue header */
      if (con->reply_r.return_code != 100)
  	state->nmsgs++;

      state->message_body_present = 1;

      if (con->reply_r.current_method == SSH_APPGW_HTTP_METHOD_HEAD)
        state->message_body_present = 0;
      else if ((con->reply_r.return_code >= 100
                 && con->reply_r.return_code <= 199)
                || con->reply_r.return_code == 304
                || con->reply_r.return_code == 204)
        state->message_body_present = 0;

      if (state->http_version == SSH_APPGW_HTTP_HTTPV_09)
        state->message_body_present = 1;
    }
  else
    {
      SSH_NOTREACHED;
    }

  if (state->http_version == SSH_APPGW_HTTP_HTTPV_09)
    state->non_persistent_connection = 1;

  /* If there exists a probability that a further message could
     be forwarded to us, then we consider this connection persistent
     and deal with it.. due to the issues of "Keep-Alives" and what not. */

  if (state->message_body_present == 1
       && (state->body_length_valid == 0
           || state->transfer_encoding == SSH_APPGW_HTTP_TE_NONE))
    state->non_persistent_connection = 1;

  if (state->transfer_encoding == SSH_APPGW_HTTP_TE_CHUNKED)
    {
      state->reading_chunk_hdr = 1;
      state->reading_chunk_data_end = 0;
      state->reading_chunk_trailer = 0;
    }

  if (con->io_r.active == 1)
    ssh_fsm_continue(&con->thread_r);

  /* Handle CONNECT tunneling through proxies. Note that this
     can be disabled by e.g. putting a cut or block rule for a CONNECT
     request */

  if (ssh_appgw_handle_connect_method(con,state) == 0)
    {
      if (state->message_body_present == 0)
        ssh_appgw_msg_begin(con,state);
    }
  else
    {
      if (con->io_i.active == 1)
        ssh_fsm_continue(&con->thread_i);
    }
}

/* Parse a HTTP status-line from a HTTP response. Return TRUE if
   the operation succeeds, FALSE otherwise. Extract HTTP version
   and status code from the status-line.*/
static Boolean
ssh_appgw_parse_response_line(SshAppgwHttpIO io,
                              SshAppgwHttpConn con,
                              SshAppgwHttpState state,
                              unsigned char *response)
{
  int len,res;
  unsigned char *version_str;
  unsigned char codebuf[4];

  /* HTTP responses have version string at beginning of line */
  version_str = response;
  len = ssh_ustrlen(response);

  if (con->state_i.http_version == SSH_APPGW_HTTP_HTTPV_09)
    state->http_version = SSH_APPGW_HTTP_HTTPV_09;
  else
    {
      if (len < 9)
        {
          ssh_appgw_audit_event(con->ctx,
                                SSH_AUDIT_PROTOCOL_PARSE_ERROR,
                                SSH_AUDIT_TXT,
                                "No version field in status line",
                                SSH_AUDIT_ARGUMENT_END);

          return FALSE;
        }

      if (ssh_appgw_http_strncasecmp(version_str, ssh_custr("HTTP/1.1 "),
                                     9) == 0)
        state->http_version = SSH_APPGW_HTTP_HTTPV_11;
      else if (ssh_appgw_http_strncasecmp(version_str, ssh_custr("HTTP/1.0 "),
                                          9)== 0)
        state->http_version = SSH_APPGW_HTTP_HTTPV_10;
      else
        {
          ssh_appgw_audit_event(con->ctx,
                                SSH_AUDIT_PROTOCOL_PARSE_ERROR,
                                SSH_AUDIT_TXT,
                                "Unrecognized version field in status-line",
                                SSH_AUDIT_ARGUMENT_END);

          SSH_DEBUG(SSH_D_NETGARB,
                    ("Unknown HTTP version in status-line"));

          SSH_TRACE_HEXDUMP(SSH_D_MY, ("version_str:"),
                            (const unsigned char *)version_str, 20);
          return FALSE;
        }
      version_str += 9;
      len -= 9;

      if (len < 3)
        {
          ssh_appgw_audit_event(con->ctx,
                                SSH_AUDIT_PROTOCOL_PARSE_ERROR,
                                SSH_AUDIT_TXT,
                                "No reply-code in status-line",
                                SSH_AUDIT_ARGUMENT_END);

          SSH_DEBUG(SSH_D_NETGARB,("missing status code in status-line"));
          return FALSE;
        }

      if (len == 3)
	{
	  /* RFC2616 specifies the status line as:
	     "Status-Line = HTTP-Version SP Status-Code SP Reason-Phrase CRLF"

	     Some HTTP servers seem to omit the Reason-Phrase and the 
	     preceding SP from the response status-line. */
          SSH_DEBUG(SSH_D_NETGARB,("missing reason phrase in status-line"));
	}

      else if (version_str[3] != ' ')
        {
          ssh_appgw_audit_event(con->ctx,
                                SSH_AUDIT_PROTOCOL_PARSE_ERROR,
                                SSH_AUDIT_TXT,
                                "No reply-code field in status-line",
                                SSH_AUDIT_ARGUMENT_END);

          SSH_DEBUG(SSH_D_NETGARB,
                    ("lacking SP after status code in status-line"));
          return FALSE;
        }

      memcpy(codebuf,version_str,3);
      codebuf[3] = '\0';

      res = ssh_appgw_hdr_strtoi(&con->reply_r.return_code, codebuf);

      if (res != 1 || con->reply_r.return_code < 0
           || con->reply_r.return_code > 999)
        {
          SSH_DEBUG(SSH_D_NETGARB,
                    ("unable to parse status code in status-line"));
          return FALSE;
        }
      SSH_DEBUG(SSH_D_MY,("status code %d",con->reply_r.return_code));
    }
  return 1;
}

/* Parse a HTTP request-line from a HTTP request. Return TRUE if
   the operation succeeds, FALSE otherwise. Currently only
   extracts the version from the request-line. This is needed
   for further parsing of the request. */
static Boolean
ssh_appgw_parse_request_line(SshAppgwHttpIO io,
                             SshAppgwHttpConn con,
                             SshAppgwHttpState state,
                             unsigned char *req)
{
  unsigned char *version_str;

  SSH_DEBUG(SSH_D_MIDOK,
            ("parsing request line %s",req));

  version_str = ssh_appgw_get_version_str(req);

  state->http_version = SSH_APPGW_HTTP_HTTPV_UNKNOWN;

  if (version_str == NULL)
    {
      if (ssh_appgw_http_strncasecmp(req, ssh_custr("GET "), 4) == 0)
        state->http_version = SSH_APPGW_HTTP_HTTPV_09;
    }
  else
    {
      if (ssh_appgw_http_strncasecmp(version_str, ssh_custr("HTTP/1.0"),
                                     8) == 0)
        state->http_version = SSH_APPGW_HTTP_HTTPV_10;
      else if (ssh_appgw_http_strncasecmp(version_str, ssh_custr("HTTP/1.1"),
                                          8) == 0)
        state->http_version = SSH_APPGW_HTTP_HTTPV_11;
    }

  if (state->http_version == SSH_APPGW_HTTP_HTTPV_UNKNOWN)
    {
      ssh_appgw_audit_event(con->ctx,
                            SSH_AUDIT_PROTOCOL_PARSE_ERROR,
                            SSH_AUDIT_TXT,
                            "Unrecognized HTTP version",
                            SSH_AUDIT_ARGUMENT_END);

      SSH_DEBUG(SSH_D_NETGARB,("Unknown version in HTTP request-line: %s",
                               version_str));
      return FALSE;
    }
  SSH_DEBUG(SSH_D_MY,("internal http version %d",state->http_version));

  return TRUE;
}

/* Try to extract and parse the initial line of a HTTP request or status
   in io->buf. return 1 if this is successful, -1 if there is insufficient
   data in the buffer or insufficient resources available to perform
   the operation. */
static int
ssh_appgw_msg_handle_initial_line(SshAppgwHttpConn con,
                                  SshAppgwHttpIO io,
                                  SshAppgwHttpState state)
{
  int res;
  unsigned char *tmpbuf;

  res = ssh_appgw_hdr_get_from_buf(ssh_custr(""),
                                   io->buf + io->offset_in_buf,
                                   io->data_in_buf - io->offset_in_buf,
                                   &tmpbuf);

  /* A complete line in the buffer is expected */
  if (res <= 0)
    return -1;

  if (tmpbuf == NULL)
    return -1;

  if (state == &con->state_i)
    {
      /* Mark contents of buffer as OK */
      con->req_i.request_line_valid = 1;

      if (ssh_appgw_parse_request_line(io, con, state, tmpbuf) == FALSE)
        res = -1;
    }
  else
    {
      if (ssh_appgw_parse_response_line(io, con, state, tmpbuf) == FALSE)
        res = -1;
    }

  ssh_free(tmpbuf);

  return res;
}

/* Perform manipulations of state before evaluating header against ruleset */
static void
ssh_appgw_fix_msg(SshAppgwHttpIO io,
                  SshAppgwHttpConn con,
                  SshAppgwHttpState state)
{
  /* RFC 2616 4.4: If both a transfer-encoding and body length are present,
     then  the latter must be ignored. */

  if (state->body_length_valid == 1
       && state->transfer_encoding != SSH_APPGW_HTTP_TE_NONE)
    state->body_length_valid = 0;
}

/* If this stream is I->R then attempt to cache the request method.
   If this stream is R->I then attempt to fetch from the cache
   the method of the request. */
static Boolean
ssh_appgw_add_method(SshAppgwHttpConn con,
                     SshAppgwHttpIO io,
                     SshAppgwHttpState state)
{
  SshAppgwHttpRequestMethod m,l;

  if (state == &con->state_r)
    {
      while (con->reply_r.methods != NULL)
	{
	  if (con->reply_r.methods->msg_number == state->nmsgs)
	    break;
	  
	  m = con->reply_r.methods;
	  con->reply_r.methods = m->next;
	  ssh_free(m);
	}
      if (con->reply_r.methods == NULL)
	{
	  SSH_DEBUG(SSH_D_FAIL,
		    ("Could not find cached request method!"));
	  return FALSE;
	}
      m = con->reply_r.methods;

      SSH_DEBUG(SSH_D_MY, ("reply is to method %d request", m->method));

      con->reply_r.current_method = m->method;

      /* Handle continue header */
      if (con->reply_r.return_code != 100)
	{
	  con->reply_r.methods = m->next;
	  ssh_free(m);
	}
      return TRUE;
    }
  else if (state == &con->state_i)
    {
      if (con->req_i.request_line_valid == 0)
        {
          ssh_appgw_audit_event(con->ctx,
                                SSH_AUDIT_PROTOCOL_PARSE_ERROR,
                                SSH_AUDIT_TXT,
                                "No valid request line",
                                SSH_AUDIT_ARGUMENT_END);

          SSH_DEBUG(SSH_D_NETGARB,
                    ("unable to parse method because no request line"));
          return FALSE;
        }

      m = ssh_appgw_request_method_from_buf(io, state);
      if (m == NULL)
           return FALSE;

      l = con->reply_r.methods;

      if (l == NULL)
        con->reply_r.methods = m;
      else
        {
          while (l->next != NULL)
            l = l->next;

          l->next = m;
        }

      SSH_DEBUG(SSH_D_MY,
                ("caching method %d for reply %d",
                 m->method,m->msg_number));

      con->req_i.current_method = m->method;

      return TRUE;
    }
  else
    {
      SSH_NOTREACHED;
    }
  return FALSE;
}

/* Create a SshAppgwHttpReplyAction object based on SshAppgwHttpBlockAction
   for the HTTP header being considered. */
static Boolean
ssh_appgw_inject_reply(SshAppgwHttpIO io,
                       SshAppgwHttpConn con,
                       SshAppgwHttpState state,
                       SshAppgwHttpBlockAction block)
{
  SshAppgwHttpReplyAction act;
  SshAppgwHttpReplyAction next;
  int no_body, no_header;

  if ((act = ssh_malloc(sizeof(*act))) == NULL)
    {
      ssh_appgw_audit_event(con->ctx,
                            SSH_AUDIT_PROTOCOL_PARSE_ERROR,
                            SSH_AUDIT_TXT, "out of memory error",
                            SSH_AUDIT_ARGUMENT_END);

      ssh_log_event(SSH_LOGFACILITY_DAEMON,
                    SSH_LOG_ERROR,
                    "service %s: out of memory error",
                    ssh_appgw_get_service_name(con));

      SSH_DEBUG(SSH_D_FAIL,("out of memory error"));
      return FALSE;
    }

  act->msg_number = state->nmsgs;
  act->status = SSH_APPGW_HTTP_REQ_INJECT;

  no_body = 0;
  no_header = 0;

  act->bufsize = 1024 + ssh_ustrlen(block->content_type) +
                 block->data_len;
  act->buf = ssh_malloc(act->bufsize);
  act->data_in_buf = 0;
  act->offset = 0;
  act->close_after_action = 0;

  SSH_ASSERT(block != NULL);
  SSH_ASSERT(block->content_type != NULL);

  if (con->req_i.current_method == SSH_APPGW_HTTP_METHOD_CONNECT
       && block->code >= 200
       && block->code <= 299)
    {
      ssh_appgw_audit_event(con->ctx,
                            SSH_AUDIT_PROTOCOL_PARSE_ERROR,
                            SSH_AUDIT_TXT,
                            "a block rule with status code 2xx "
                            "triggered for a connect request. "
                            "The HTTP client and server "
                            "are now in an inconsistent state.",
                            SSH_AUDIT_ARGUMENT_END);
    }

  if (con->req_i.current_method == SSH_APPGW_HTTP_METHOD_HEAD)
    no_body = 1;

  if (block->code == 204 || block->code == 304
       || (block->code >= 100 && block->code <= 199))
    no_body = 1;

  if (state->http_version == SSH_APPGW_HTTP_HTTPV_09)
    {
      no_body = 0;
      no_header = 1;
    }

  if (act->buf == NULL)
    {
      ssh_appgw_audit_event(con->ctx,
                            SSH_AUDIT_PROTOCOL_PARSE_ERROR,
                            SSH_AUDIT_TXT, "out of memory error",
                            SSH_AUDIT_ARGUMENT_END);

      ssh_log_event(SSH_LOGFACILITY_DAEMON,
                    SSH_LOG_ERROR,
                    "service %s: out of memory error",
                    ssh_appgw_get_service_name(con));

      SSH_DEBUG(SSH_D_FAIL,("out of memory error"));
      ssh_free(act);
      return FALSE;
    }


  if (state->http_version == SSH_APPGW_HTTP_HTTPV_09
       || state->http_version == SSH_APPGW_HTTP_HTTPV_10)
    act->close_after_action = 1;

  if (state->http_version == SSH_APPGW_HTTP_HTTPV_11)
    act->close_after_action = state->non_persistent_connection;

  act->http_version = state->http_version;

  switch (state->http_version)
    {
    default:
    case SSH_APPGW_HTTP_HTTPV_NONE:
      break;
    case SSH_APPGW_HTTP_HTTPV_09:
    case SSH_APPGW_HTTP_HTTPV_10:
    case SSH_APPGW_HTTP_HTTPV_11:
      if (no_body == 0)
        {
          char *data;
          int data_len, i;
		  size_t buf_len;

          if (block->data != NULL)
            {
              data = (char *)block->data;
              data_len = block->data_len;
            }
          else
            {
              data = "\n";
              data_len = 1;
            }

          buf_len = act->bufsize;

          if (no_header == 0)
            {
              i =
                ssh_snprintf(act->buf,
                             buf_len,
                             "%s %d Not Found\r\n"
                             "Server: %s\r\n",
                             (state->http_version == SSH_APPGW_HTTP_HTTPV_11 ?
                              "HTTP/1.1" : "HTTP/1.0"),
                             block->code,
                             SSH_APPGW_HTTP_NAME);
              buf_len -= i;
              act->data_in_buf += i;

              if (block->content_type != NULL)
                {
                  i = ssh_snprintf(act->buf + act->data_in_buf,
                                   buf_len,
                                   "Content-Type: %s\r\n",
                                   block->content_type);
                  act->data_in_buf += i;
                  buf_len -= i;
                }

              if (block->header != NULL)
                {
                  i = (block->header_len >= buf_len
                       ?buf_len
                       :block->header_len);

                  memcpy(act->buf+act->data_in_buf, block->header, i);
                  act->data_in_buf += i;
                  buf_len -= i;
                }

              i = ssh_snprintf(act->buf + act->data_in_buf,
                               buf_len,
                               "Content-Length: %u\r\n\r\n",
                             data_len);
              act->data_in_buf += i;
              buf_len -= i;
            }
          else
            {
              act->data_in_buf = 0;
            }

          i = (data_len >= buf_len ? buf_len : data_len);

          memcpy(act->buf + act->data_in_buf, data, i);
          act->data_in_buf += i;
        }
      else
        {
          act->data_in_buf =
            ssh_snprintf(act->buf,
                         act->bufsize,
                         "%s %d Not Found\r\n"
                         "Server: %s\r\n"
                         "\r\n",
                         (state->http_version == SSH_APPGW_HTTP_HTTPV_11 ?
                          "HTTP/1.1" : "HTTP/1.0"),
                         block->code,
                         SSH_APPGW_HTTP_NAME);
        }

      break;
    case SSH_APPGW_HTTP_HTTPV_UNKNOWN:
      break;
    }
  SSH_DEBUG(SSH_D_HIGHOK,("injecting %d reply as msg %d",
                          SSH_APPGW_HTTP_ERROR_CODE,
                          act->msg_number));

  next = con->reply_r.actions;
  act->next = NULL;

  if (next == NULL)
    con->reply_r.actions = act;
  else
    {
      while (next->next != NULL)
        next = next->next;
      next->next = act;
    }

  if (con->io_r.active == 1)
    ssh_fsm_continue(&con->thread_r);

  return TRUE;
}

/*********************** Rule/Message matching functions ******************/

/* Check if a clause matches a HTTP header.  */
static int
ssh_appgw_match_clause(SshAppgwHttpIO io,
                       SshAppgwHttpConn con,
                       SshAppgwHttpState state,
                       SshAppgwHttpMatchClause clause)
{
  int idx,srclen;
  unsigned char *src, *host;

  if (clause->min_url_length > 0 && con->req_i.request_line_valid == 1)
    {
      unsigned char *url;

      url = ssh_appgw_get_uri_from_buf(io, state);

      if (url == NULL)
        return -1;

      if (ssh_ustrlen(url) < clause->min_url_length)
        {
          ssh_free(url);
          return 0;
        }
      ssh_free(url);
    }

  /* Check host header matches */

  if (clause->host != NULL)
    {
      host = ssh_appgw_http_get_dst_host(io, con, state);

      if (host == NULL)
        return -1;

      if (ssh_appgw_http_strncasecmp(host, clause->host,
                                     ssh_ustrlen(clause->host)) != 0)
        {
          ssh_free(host);
          return 0;
        }
      ssh_free(host);
    }

  if (clause->hdr_regex != NULL)
    {
      idx = 0;

      for (;;)
        {
          src = io->buf + idx;
          srclen = ssh_appgw_hdr_length(src, io->offset_in_buf - idx);

          if (srclen < 0)
            return 0;

          if (ssh_regex_match(clause->hdr_regex, src, srclen) == TRUE)
            break;

          if (ssh_regex_get_match_error(clause->hdr_regex)
              == SSH_REGEX_OUT_OF_MEMORY)
            {
              SSH_DEBUG(SSH_D_FAIL,("out of memory error"));
              return -1;
            }

          idx += ssh_appgw_line_length(src,io->offset_in_buf - idx);
        }
    }

  return 1;
}

/* Check configuration for how to handle this request */
static SshAppgwHttpRuleAction
ssh_appgw_check_msg(SshAppgwHttpIO io,
                    SshAppgwHttpConn con,
                    SshAppgwHttpState state,
                    SshAppgwHttpRule *act_rule)
{
  int i,is_match,res;
  SshAppgwHttpRule rule;
  SshAppgwHttpMatchClause clause;
  SshAppgwHttpConfig config;

  *act_rule = NULL;

  if (con->teardown)
    {
      SSH_DEBUG(SSH_D_MY,("connection signaled for closing, "
                          "aborting msg check"));
      return SSH_APPGW_HTTP_ACTION_CUT;
    }

  config = ssh_appgw_http_get_config(con->http_ctx,con->service_id);
  if (config == NULL)
    {
      ssh_appgw_audit_event(con->ctx,
                            SSH_AUDIT_PROTOCOL_PARSE_ERROR,
                            SSH_AUDIT_TXT, "no valid configuration available",
                            SSH_AUDIT_ARGUMENT_END);

      SSH_DEBUG(SSH_D_FAIL,("Could not find configuration for service id %d, "
                            "cutting connection",con->service_id));
      return SSH_APPGW_HTTP_ACTION_CUT;
    }

  SSH_DEBUG(SSH_D_MY,("examining request using service id %d",
                      con->service_id));

  if (state == &con->state_i)
    {
      /* Go through all rules untill a match is found */

      for (rule = config->rules; rule != NULL; rule = rule->next)
        {
          is_match = 1;

          for (i = 0; i < rule->nclauses; i++)
            {
              clause = rule->clauses[i];

              res = ssh_appgw_match_clause(io, con, state, clause);

              if (res == -1)
                  return SSH_APPGW_HTTP_ACTION_CUT;

              is_match &= res;

            }

          if (is_match)
            {
              *act_rule = rule;
              return rule->action;
            }
        }
      SSH_DEBUG(SSH_D_MY,("passing initiator msg"));
      return SSH_APPGW_HTTP_ACTION_PASS;
    }
  else
    {
      SSH_DEBUG(SSH_D_MY,("passing responder msg"));
      return SSH_APPGW_HTTP_ACTION_PASS;
    }
  /*NOTREACHED*/
}
static const unsigned char *
ssh_appgw_http_get_version_str(SshAppgwHttpState state)
{
  const unsigned char *http_version_str;

  if (state->http_version == SSH_APPGW_HTTP_HTTPV_11)
    http_version_str = ssh_custr("HTTP/1.1");
  else if (state->http_version == SSH_APPGW_HTTP_HTTPV_10)
    http_version_str = ssh_custr("HTTP/1.0");
  else if (state->http_version == SSH_APPGW_HTTP_HTTPV_09)
    http_version_str = ssh_custr("HTTP/0.9");
  else
    http_version_str = ssh_custr("HTTP/???");

  return http_version_str;
}

/* Parse a HTTP request header. The header is expected to be
   in [io->buf,io->offset_in_buf] and SshAppgwHttpState
   and SshAppgwHttpCon are assumed to have up-to-date
   status information regarding the header.
   After handling the request the state vars are set
   to either expect another request or a message body
   or close the connection. */
static void
ssh_appgw_http_handle_header(SshAppgwHttpIO io,
                             SshAppgwHttpConn con,
                             SshAppgwHttpState state)
{
  SshAppgwHttpRuleAction act;
  SshAppgwHttpRule rule;
  unsigned char *rule_name;
  const unsigned char *rule_action;
  unsigned char *url, *method, *host;
  const unsigned char *http_version_str;

  if (ssh_appgw_add_method(con, io, state) == FALSE)
    {
      con->teardown = 1;
      return;
    }

  ssh_appgw_fix_msg(io, con, state);

  act = ssh_appgw_check_msg(io, con, state, &rule);

  if (rule != NULL)
    {
      /* Make sure the log entry has been filed, before
         we run the functions below (they may cause
         other log entries to be filed...) */

      rule_name = rule->name;
      switch (act)
        {
        case SSH_APPGW_HTTP_ACTION_PASS:
          rule_action = ssh_custr("pass");
          break;
        case SSH_APPGW_HTTP_ACTION_BLOCK:
          rule_action = ssh_custr("block");
          break;
        case SSH_APPGW_HTTP_ACTION_CUT:
        default:
          rule_action = ssh_custr("cut");
          break;
        }

      url = ssh_appgw_get_uri_from_buf(io, state);
      method = ssh_appgw_request_method_str_from_buf(io, state);
      host = ssh_appgw_http_get_dst_host(io, con, state);
      http_version_str = ssh_appgw_http_get_version_str(state);

      ssh_appgw_audit_event(con->ctx,
                            SSH_AUDIT_HTTP_REQUEST,
                            SSH_AUDIT_HTTP_VERSION, http_version_str,
                            SSH_AUDIT_HTTP_METHOD, method,
                            SSH_AUDIT_DESTINATION_HOST, host,
                            SSH_AUDIT_REQUEST_URI, url,
                            SSH_AUDIT_RULE_NAME, rule_name,
                            SSH_AUDIT_RULE_ACTION, rule_action,
                            SSH_AUDIT_ARGUMENT_END);

      ssh_free(method);
      ssh_free(url);
      ssh_free(host);
    }

  switch (act)
    {
    case SSH_APPGW_HTTP_ACTION_PASS:
      SSH_DEBUG(SSH_D_HIGHOK,("msg ok"));
      ssh_appgw_msg_end_sent(con,state);
      ssh_appgw_dump_state(state);

      SSH_ASSERT(io->bufpos <= io->data_in_buf);

      return;

    case SSH_APPGW_HTTP_ACTION_BLOCK:
      if (ssh_appgw_inject_reply(io,con,state,
                                 rule->block) ==FALSE)
        {
          con->teardown = 1;
          return;
        }

      ssh_appgw_msg_end_sent(con,state);

      if (state->message_body_present)
        state->ignore_body = 1;

      memmove(io->buf,io->buf + io->offset_in_buf,
              io->data_in_buf - io->offset_in_buf);

      io->data_in_buf -= io->offset_in_buf;
      io->offset_in_buf = 0;

      con->req_i.host_line_index = -1;       /* Sanity */
      return;

    case SSH_APPGW_HTTP_ACTION_CUT:
    default:
      SSH_DEBUG(SSH_D_HIGHOK,
                ("msg failed check, cutting connection"));
      con->teardown = 1;
      return;
    }
}

/****************** Exported functions ************************************/

/* Reset HTTP state */
void
ssh_appgw_hdr_reset_state(SshAppgwHttpState state)
{
  state->initial_line_read = 0;
  state->body_length_valid = 0;
  state->reading_hdr = 0;
  state->reading_body = 0;
  state->message_body_present = 0;
  state->reading_chunk_hdr = 0;
  state->reading_chunk_trailer = 0;
  state->reading_chunk_data_end = 0;
  state->non_persistent_connection = 0;
  state->flush_buf = 0;
  state->ignore_body = 0;
  state->http_version = SSH_APPGW_HTTP_HTTPV_NONE;
  state->transfer_encoding = SSH_APPGW_HTTP_TE_NONE;
}

/* Modify state to expect the beginning of a HTTP header next. */
void
ssh_appgw_msg_begin(SshAppgwHttpConn con,
                    SshAppgwHttpState state)
{
  state->reading_body = 0;
  state->reading_hdr = 1;
  state->initial_line_read = 0;
  state->message_body_present = 0;
  state->reading_chunk_hdr = 0;
  state->reading_chunk_data_end = 0;
  state->reading_chunk_trailer = 0;
  state->http_version = SSH_APPGW_HTTP_HTTPV_NONE;
  state->transfer_encoding = SSH_APPGW_HTTP_TE_NONE;
  state->body_length_valid = 0;
  state->ignore_body = 0;

  if (state == &con->state_i)
    {
      con->req_i.current_method = SSH_APPGW_HTTP_METHOD_NONE;
      con->req_i.request_line_valid = 0;
      con->req_i.host_line_index = -1;
    }
  else if (state == &con->state_r)
    {
      ;
    }
  else
    {
      SSH_NOTREACHED;
    }
}

/* Free a replyaction object */
void
ssh_appgw_http_replyaction_free(SshAppgwHttpReplyAction act)
{
  ssh_free(act->buf);
  ssh_free(act);
}

/* Return TRUE if a HTTP response should be injected to the responder. */
Boolean
ssh_appgw_http_is_inject(SshAppgwHttpIO io,
                         SshAppgwHttpConn con,
                         SshAppgwHttpState state)
{
  if (state != &con->state_r)
    return FALSE;

  if (con->reply_r.actions == NULL)
    return FALSE;

  if (state->reading_hdr == 0
       && state->http_version != SSH_APPGW_HTTP_HTTPV_09)
    return FALSE;

  SSH_DEBUG(SSH_D_MY,("next inject is msg# %d current msg# %d",
                      con->reply_r.actions->msg_number,state->nmsgs));

  if (con->reply_r.actions->msg_number == state->nmsgs)
    return TRUE;

  return FALSE;
}

void
ssh_appgw_http_handle_body(SshAppgwHttpIO io,
                           SshAppgwHttpConn con,
                           SshAppgwHttpState state)
{
  unsigned char *src;
  size_t srclen,off;
  int res, i;
  unsigned char *tmpbuf;
  int body_left, body_len;

  SSH_ASSERT(state->reading_body == 1);

  src = io->buf + io->offset_in_buf;
  srclen = io->data_in_buf - io->offset_in_buf;
  body_left = state->body_length - state->body_read;

  switch (state->transfer_encoding)
    {
    case SSH_APPGW_HTTP_TE_CHUNKED:
      if (state->reading_chunk_hdr)
        {
          SSH_DEBUG(SSH_D_MY,("reading chunk hdr"));

          res = ssh_appgw_hdr_get_from_buf(ssh_custr(""), src, srclen,
                                           &tmpbuf);

          if (res <= 0)
            return;

          state->body_read = 0;

          /* Note: strtoi_hex() can handle tmpbuf == NULL */
          i = ssh_appgw_hdr_strtoi_hex(&body_len, tmpbuf);
          if (i < 1 || body_len < 0)
            {
              ssh_appgw_audit_event(con->ctx,
                                    SSH_AUDIT_PROTOCOL_PARSE_ERROR,
                                    SSH_AUDIT_TXT,
                                    "error reading chunk length",
                                    SSH_AUDIT_ARGUMENT_END);

              SSH_DEBUG(SSH_D_NETGARB,
                        ("error reading chunk length"));
              ssh_free(tmpbuf);
              con->teardown = 1;
              return;
            }

          state->body_length = body_len;
          SSH_DEBUG(SSH_D_MY,("chunk length %d",state->body_length));

          io->offset_in_buf += res;
          SSH_ASSERT(io->offset_in_buf <= io->data_in_buf);
          state->reading_chunk_hdr = 0;

          if (state->body_length == 0)
            state->reading_chunk_trailer = 1;

          ssh_free(tmpbuf);
          state->flush_buf = 1;
        }
      else if (state->reading_chunk_data_end)
        {
          if (srclen < 2)
            return;

          if (*src != '\r' || *(src+1) != '\n')
            {
              ssh_appgw_audit_event(con->ctx,
                                    SSH_AUDIT_PROTOCOL_PARSE_ERROR,
                                    SSH_AUDIT_TXT,
                                    "error reading transfer-encoding chunk",
                                    SSH_AUDIT_ARGUMENT_END);

              SSH_DEBUG(SSH_D_NETGARB,
                        ("CRLF following chunk is missing (%i,%i)",
                         *src,*(src+1)));
              con->teardown = 1;
              return;
            }
          state->reading_chunk_data_end = 0;
          state->reading_chunk_hdr = 1;
          io->offset_in_buf += 2;
          SSH_ASSERT(io->offset_in_buf <= io->data_in_buf);
          state->flush_buf = 1;
        }
      else if (state->reading_chunk_trailer)
        {
          int end;

          SSH_DEBUG(SSH_D_MY,("reading chunk trailer"));
          /* Skip lines untill an empty line is found */

          do
            {

              src = io->buf + io->offset_in_buf;
              srclen = io->data_in_buf - io->offset_in_buf;

              end = ssh_appgw_hdr_length(src,srclen);
              if (end == -1)
                return;
              res = ssh_appgw_line_length(src,srclen);
              io->offset_in_buf += res;
              SSH_ASSERT(io->offset_in_buf <= io->data_in_buf);
              state->flush_buf = 1;
            } while (end != 0);

          state->reading_chunk_trailer = 0;

          ssh_appgw_hdr_reset_state(state);
          ssh_appgw_msg_begin(con,state);
          state->flush_buf = 1;
        }
      else
        {
          SSH_DEBUG(SSH_D_MY,("reading chunk body"));

          if (body_left > io->data_in_buf - io->offset_in_buf)
            {
              res = io->data_in_buf - io->offset_in_buf;
            }
          else
            {
              state->reading_chunk_data_end = 1;
              res = body_left;
            }

          if (res > 0)
            state->flush_buf = 1;

          io->offset_in_buf += res;
          SSH_ASSERT(io->offset_in_buf <= io->data_in_buf);
          state->body_read += res;
        }
      break;

    default:
    case SSH_APPGW_HTTP_TE_NONE:
      SSH_DEBUG(SSH_D_MY,
                ("handling te/NONE offset %d data length %d "
                 "body read %d body length %d",
                 io->offset_in_buf,
                 io->data_in_buf,
                 state->body_read,
                 state->body_length));

      off = io->offset_in_buf;

      if (state->body_length_valid == 1)
        {
          io->offset_in_buf += body_left;

          if (io->offset_in_buf > io->data_in_buf)
            io->offset_in_buf = io->data_in_buf;

          state->body_read += (io->offset_in_buf - off);

          if (state->body_read >= state->body_length)
            {
              ssh_appgw_hdr_reset_state(state);
              ssh_appgw_msg_begin(con,state);
            }
        }
      else
        {
          io->offset_in_buf = io->data_in_buf;
        }

      if (off < io->offset_in_buf)
        state->flush_buf = 1;

      break;
    }
  SSH_ASSERT(io->offset_in_buf <= io->data_in_buf);
  return;

}


/* Main function for traversing the HTTP data stream and
   extracting the required information for parsing. A request header
   is extracted into the beginning of the io->buf, parsed and
   handled according to a configuration and then possibly forwarded.

   If the request is to be forwarded state->flush_buf signal is raised.
   If the connection should be torn down then the con->teardown signal
   is raised.

   After setting the flush_buf signal we expect the data
   [io->buf,io->buf+io->offset_in_buf] to disappear from the
   buffer before the next invocation. */
void
ssh_appgw_http_handle_state(SshAppgwHttpIO io,
                            SshAppgwHttpConn con,
                            SshAppgwHttpState state)
{
  int res,len;
  unsigned char *src;
  size_t srclen;
  unsigned int ignore_it;

  /* Pass body through */

  SSH_ASSERT(io->offset_in_buf <= io->data_in_buf);

  if (state->reading_body)
    {
      ignore_it = state->ignore_body;

      ssh_appgw_http_handle_body(io,con,state);

      SSH_ASSERT(io->offset_in_buf <= io->data_in_buf);

      /* Should we scrap the message body? */
      if (ignore_it == 1)
        {
          SSH_DEBUG(SSH_D_MY,("ignoring message body"));
          memmove(io->buf,io->buf + io->offset_in_buf,
                  io->data_in_buf - io->offset_in_buf);

          io->data_in_buf -= io->offset_in_buf;
          io->offset_in_buf = 0;
          state->flush_buf = 0;
        }
      return;
    }

  SSH_ASSERT(state->reading_hdr == 1 );

  if (state->initial_line_read == 0)
    {
      src = io->buf + io->offset_in_buf;
      srclen = io->data_in_buf - io->offset_in_buf;

      SSH_TRACE_HEXDUMP(SSH_D_MY,
                        ("handling: %d bytes:",srclen),
                        src,srclen);

      res = ssh_appgw_hdr_length(src, srclen);

      /* No newline available */
      if (res == -1)
        return;

      if (res == 0)
        {
          /* Empty line.. ignore it */
          len = ssh_appgw_line_length(src, srclen);
          SSH_ASSERT(len >= 0);
          io->offset_in_buf += len;
          SSH_ASSERT(io->offset_in_buf <= io->data_in_buf);
          state->flush_buf = 1;
          return;
        }

      res = ssh_appgw_msg_handle_initial_line(con,io,state);

      if (res < 0)
        {
          ssh_appgw_audit_event(con->ctx,
                                SSH_AUDIT_PROTOCOL_PARSE_ERROR,
                                SSH_AUDIT_TXT,
                                "error reading request/status line",
                                SSH_AUDIT_ARGUMENT_END);

          SSH_DEBUG(SSH_D_NETGARB,("error reading request/status line"));
          con->teardown = 1;
          return;
        }
      ssh_appgw_http_hdr_line(io,con,state,res);
      state->initial_line_read = 1;

      if (state->http_version == SSH_APPGW_HTTP_HTTPV_09)
        {
          /* We are already done */
          ssh_appgw_http_handle_header(io, con, state);
          state->flush_buf = 1;
          return;
        }
    }

  /* Parse the rest of the headers */

  while (io->data_in_buf > io->offset_in_buf)
    {
      SSH_ASSERT(io->bufpos <= io->data_in_buf);

      src = io->buf + io->offset_in_buf;
      srclen = io->data_in_buf - io->offset_in_buf;

      res = ssh_appgw_hdr_length(src, srclen);

      /* No newline available */
      if (res == -1)
        return;

      if (res == 0)
        {
          res = ssh_appgw_line_length(src, srclen);
          ssh_appgw_http_hdr_line(io, con, state, res);

          ssh_appgw_http_handle_header(io, con, state);

          state->flush_buf = 1;
          return;
        }

      res = ssh_appgw_msg_handle_line(con,io,state);

      if (res == -1)
        {
          con->teardown = 1;
          return;
        }

      if (res == 0)
        res = ssh_appgw_line_length(src, srclen);

      ssh_appgw_http_hdr_line(io, con, state, res);
    }
  return;
}


#endif /* SSHDIST_IPSEC_FIREWALL */
