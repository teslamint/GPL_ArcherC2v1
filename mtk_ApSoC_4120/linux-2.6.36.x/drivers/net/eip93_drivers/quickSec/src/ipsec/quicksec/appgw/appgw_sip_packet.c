/*
  File: appgw_sip_packet.c

  Copyright:
  	Copyright (c) 2003 SFNT Finland Oy.
	All rights reserved.

  Description:
        Decode and Encode SIP packets in extent needed at SIP ALG.
*/

#include "sshincludes.h"
#include "sshurl.h"
#include "appgw_api.h"

#ifdef SSHDIST_IPSEC_FIREWALL

#include "appgw_sip.h"

static char *token(const char **p)
{
  char *v, *space;

  while (**p != '\0' && isspace(((unsigned char)**p))) (*p)++;

  if ((space = strchr(*p, ' ')) != NULL)
    {
      v = ssh_memdup(*p, space - *p);
      *p += (space - *p) + 1;
    }
  else if (**p)
    v = ssh_strdup(*p);
  else
    v = NULL;

  return v;
}

void
alg_sip_free_header(SshSipHdr siphdr)
{
  int i;

  if (siphdr == NULL)
    return;

  for (i = 0; i < siphdr->num_via; i++) ssh_free(siphdr->via[i]);
  ssh_free(siphdr->via);
  for (i = 0; i < siphdr->num_to; i++) ssh_free(siphdr->to[i]);
  ssh_free(siphdr->to);
  for (i = 0; i < siphdr->num_from; i++) ssh_free(siphdr->from[i]);
  ssh_free(siphdr->from);
  for (i = 0; i < siphdr->num_call_id; i++) ssh_free(siphdr->call_id[i]);
  ssh_free(siphdr->call_id);
  for (i = 0; i < siphdr->num_contact; i++) ssh_free(siphdr->contact[i]);
  ssh_free(siphdr->contact);
  for (i = 0; i < siphdr->num_unhandled; i++) ssh_free(siphdr->unhandled[i]);
  ssh_free(siphdr->unhandled);
  for (i = 0; i < siphdr->num_content_type; i++)
    ssh_free(siphdr->content_type[i]);
  ssh_free(siphdr->content_type);

  if (siphdr->is_request)
    {
      ssh_free(siphdr->u.request.method);
      ssh_free(siphdr->u.request.uri);
      ssh_free(siphdr->u.request.version);
    }
  else
    {
      ssh_free(siphdr->u.response.version);
      ssh_free(siphdr->u.response.phrase);
    }

  if (siphdr->payload_sdp) alg_sip_free_sdp_header(siphdr->payload.sdp.header);
  else if (siphdr->payload_sip) ssh_free(siphdr->payload.sip.content);

  ssh_free(siphdr);
}

static void
alg_sip_write_header(SshBuffer o, SshSipHdr siphdr)
{
  int i;
  char clen[16];

  for (i = 0; i < siphdr->num_via; i++)
    ssh_buffer_append_cstrs(o, "Via: ", siphdr->via[i], "\n", NULL);
  for (i = 0; i < siphdr->num_to; i++)
    ssh_buffer_append_cstrs(o, "To: ", siphdr->to[i], "\n", NULL);
  for (i = 0; i < siphdr->num_from; i++)
    ssh_buffer_append_cstrs(o, "From: ", siphdr->from[i], "\n", NULL);
  for (i = 0; i < siphdr->num_call_id; i++)
    ssh_buffer_append_cstrs(o, "Call-ID: ", siphdr->call_id[i], "\n", NULL);
  for (i = 0; i < siphdr->num_contact; i++)
    ssh_buffer_append_cstrs(o, "Contact: ", siphdr->contact[i], "\n", NULL);

  for (i = 0; i < siphdr->num_unhandled; i++)
    ssh_buffer_append_cstrs(o, siphdr->unhandled[i], "\n", NULL);

  if (siphdr->num_content_type)
    {
      ssh_snprintf(clen, sizeof(clen), "%d", siphdr->content_length);
      ssh_buffer_append_cstrs(o,
                              "Content-Type: ", siphdr->content_type[0], "\n",
                              "Content-Length: ", clen,
                              NULL);
    }
}

char *
alg_sip_write_sip_header(SshSipHdr siphdr)
{
  SshBufferStruct o;
  char *p;

  ssh_buffer_init(&o);

  if (siphdr->is_request)
    {
      ssh_buffer_append_cstrs(&o,
                              siphdr->u.request.method, " ",
                              siphdr->u.request.uri, " ",
                              siphdr->u.request.version, "\n",
                              NULL);
    }
  else
    {
      char code[16];
      ssh_snprintf(code, sizeof(code), "%d", siphdr->u.response.value);
      ssh_buffer_append_cstrs(&o,
                              siphdr->u.response.version, " ",
                              code, " ",
                              siphdr->u.response.phrase, "\n",
                              NULL);
    }

  alg_sip_write_header(&o, siphdr);
  ssh_buffer_append(&o, "\0", 1);

  p = ssh_buffer_steal(&o, NULL);
  ssh_buffer_uninit(&o);
  return p;

}

static char *
alg_sip_parse_request_line(char *data, SshSipHdr siphdr)
{
  char *ws;

  siphdr->is_request = TRUE;

  if ((ws = strchr(data, ' ')) != NULL)
    *ws++ = '\0';
  siphdr->u.request.method = ssh_strdup(data);

  data = ws;
  if ((ws = strchr(data, ' ')) != NULL)
    *ws++ = '\0';
  siphdr->u.request.uri = ssh_strdup(data);

  data = ws;
  if ((ws = strchr(data, '\r')) != NULL)
    {
      *ws++ = '\0';
      if (*ws == '\n') *ws++ = '\0';
    }
  siphdr->u.request.version = ssh_strdup(data);

  if (strstr(siphdr->u.request.version, "SIP/") == NULL)
    return NULL;
  else
    return ws;
}

static char *
alg_sip_parse_response_line(char *data, SshSipHdr siphdr)
{
  char *ws = NULL;

  if (data == NULL)
    return NULL;

  siphdr->is_request = FALSE;
  if (data && (ws = strchr(data, ' ')) != NULL)
    *ws++ = '\0';
  siphdr->u.response.version = ssh_strdup(data);

  data = ws;
  if (data && (ws = strchr(data, ' ')) != NULL)
    *ws++ = '\0';
  siphdr->u.response.value = strtoul(data, NULL, 0);

  data = ws;
  if (data && (ws = strchr(data, '\r')) != NULL)
    {
      *ws++ = '\0';
      if (*ws == '\n') *ws++ = '\0';
    }

  siphdr->u.response.phrase = ssh_strdup(data);

  if (siphdr->u.response.version == NULL ||
      strstr(siphdr->u.response.version, "SIP/") == NULL)
    return NULL;
  else
    return ws;
}

static void
add_handled(char ***field, size_t *nfields, char *value, Boolean append)
{
  char *p, *n;
  size_t len;
  char **tmp;

  p = value;
  while (*p != '\0' && isspace(((unsigned char)*p)))
    p++;

  if (append)
    {
      len = strlen((*field)[*nfields - 1]) + strlen(value) + 2;
      n = ssh_calloc(len, sizeof(char));
      strcat(n, (*field)[*nfields - 1]);
      strcat(n, p);
      ssh_free((*field)[*nfields - 1]);
      (*field)[*nfields - 1] = n;
    }
  else
    {
      tmp = ssh_realloc(*field,
                        *nfields * sizeof(char **),
                        (*nfields + 1) * sizeof(char **));
      if (tmp)
        {
          tmp[*nfields] = ssh_strdup(p);
          *field = tmp;
          *nfields += 1;
        }
    }
}

static void
add_unhandled(SshSipHdr siphdr, char *tag, char *value, Boolean append)
{
  char *p, *n;
  size_t len;
  char **tmp;

  p = value;
  while (*p != '\0' && isspace(((unsigned char)*p)))
    p++;

  if (append)
    {
      len  = strlen(siphdr->unhandled[siphdr->num_unhandled - 1]);
      len += strlen(value) + 3;
      n = ssh_calloc(len, sizeof(char));
      strcat(n, siphdr->unhandled[siphdr->num_unhandled - 1]);
      strcat(n, p);
      ssh_free(siphdr->unhandled[siphdr->num_unhandled - 1]);
      siphdr->unhandled[siphdr->num_unhandled - 1] = n;
    }
  else
    {
      tmp = ssh_realloc(siphdr->unhandled,
                        siphdr->num_unhandled * sizeof(char **),
                        (siphdr->num_unhandled + 1) * sizeof(char *));
      if (tmp)
        {
          len  = strlen(tag) + strlen(value) + 3;
          n = ssh_malloc(len);
          ssh_snprintf(n, len, "%s: %s", tag, p);
          tmp[siphdr->num_unhandled++] = n;
          siphdr->unhandled = tmp;
        }
    }
}

static char *
parse_line(SshSipHdr siphdr, char *tag, char *data, Boolean continuation)
{
  char *p = data, *next;
  char *comma;
  Boolean append = FALSE;

  while (*p != '\0' && isspace(((unsigned char)*p)))
    p++;

  next = p;
  while (next)
    {
      comma = strchr(p, ',');
      if (comma)
        {
          *comma = '\0';
          next = comma + 1;
        }
      else
        {
          next = NULL;
        }

      if (continuation && p[0] == ';')
        append = TRUE;

      if (!strcasecmp(tag, "call-id") || !strcasecmp(tag, "i"))
        add_handled(&siphdr->call_id, &siphdr->num_call_id, p, append);

      else if (!strcasecmp(tag, "contact") || !strcasecmp(tag, "m"))
        add_handled(&siphdr->contact, &siphdr->num_contact, p, append);

      else if (!strcasecmp(tag, "from") || !strcasecmp(tag, "f"))
        add_handled(&siphdr->from, &siphdr->num_from, p, append);

      else if (!strcasecmp(tag, "to") || !strcasecmp(tag, "t"))
        add_handled(&siphdr->to, &siphdr->num_to, p, append);

      else if (!strcasecmp(tag, "via") || !strcasecmp(tag, "v"))
        add_handled(&siphdr->via, &siphdr->num_via, p, append);

      else if (!strcasecmp(tag, "content-type") || !strcasecmp(tag, "c"))
        add_handled(&siphdr->content_type,
                    &siphdr->num_content_type, p, append);

      else if (!strcasecmp(tag, "content-length") || !strcasecmp(tag, "l"))
        siphdr->content_length = strtoul(p, NULL, 0);

      else
        {
          add_unhandled(siphdr, tag, p, append);
        }

      p = next;
    }

  return p;
}

static char *
alg_sip_parse_header(char *data, SshSipHdr siphdr)
{
  char *p, *next;
  char *tag = NULL;
  char *colon;

  p = data;

  while (*p != '\0' && isspace(((unsigned char)*p)))
    p++;

  while (p && *p)
    {
      /* end of headers */
      if (*p == '\n') { p++; break; }
      if (*p == '\r' && *(p+1) == '\n') { p++; p++; break; }

      if ((next = strchr(p, '\r')) != NULL)
        {
          *next++ = '\0';
          while (isspace(((unsigned char)*next))) *next++ = '\0';
        }

      if (tag != NULL && isspace(((unsigned char)*p)))
        {
          /* continuation line */
          parse_line(siphdr, tag, p, TRUE);
        }
      else if ((colon = strchr(p, ':')) != NULL)
        {
          tag = p;
          *colon = '\0';
          p = colon + 1;
          parse_line(siphdr, tag, p, FALSE);
        }
      p = next;
    }
  return p;
}

SshSipHdr alg_sip_parse_request(char *data, char **endptr)
{
  SshSipHdr siphdr = NULL;
  char *p = data;

  /* skip whitespace */
  while (*p != '\0' && isspace(((unsigned char)*p))) p++;

  if (*p)
    {
      if ((siphdr = ssh_calloc(1, sizeof(*siphdr))) != NULL)
        {
          if ((p = alg_sip_parse_request_line(p, siphdr)) != NULL)
            *endptr = alg_sip_parse_header(p, siphdr);
          else
            {
              alg_sip_free_header(siphdr);
              siphdr = NULL;
            }
        }
    }

  return siphdr;
}

SshSipHdr alg_sip_parse_response(char *data, char **endptr)
{
  SshSipHdr siphdr = NULL;
  char *p = data;

  /* skip whitespace */
  while (*p != '\0' && isspace(((unsigned char)*p))) p++;

  if (*p)
    {
      if ((siphdr = ssh_calloc(1, sizeof(*siphdr))) != NULL)
        {
          if ((p = alg_sip_parse_response_line(p, siphdr)) != NULL)
            *endptr = alg_sip_parse_header(p, siphdr);
          else
            {
              alg_sip_free_header(siphdr);
              siphdr = NULL;
            }
        }

    }

  return siphdr;
}

/* Contact, To and From:

   name-addr / addr-spec [;to-params]
   name-addr = [display-name] '<' addr-spec '>'
   addr-spec = sips-uri | sip-uri | absolute-uri
*/

char *alg_sip_write_sip_address(char *displayname,
                                char *user, char *host,
                                char *params,
                                Boolean uri_p)
{
  SshBufferStruct b;
  char *p;

  ssh_buffer_init(&b);

  ssh_buffer_append_cstrs(&b,
                          displayname ?displayname :"",
                          displayname ?" " :"",
                          uri_p ?"" :"<",
                          "sip:", user ?user :"", user ?"@" :"", host,
                          uri_p ?"" :">",
                          params ?";" :"", params ?params : "",
                          NULL);

  ssh_buffer_append(&b, "\0", 1);
  p = ssh_buffer_steal(&b, NULL);
  ssh_buffer_uninit(&b);
  return p;
}

Boolean alg_sip_parse_sip_address(const char *addrline,
                                  char **displayname,
                                  char **user, char **host,
                                  char **params)
{
  char *semi, *la, *ra, *name, *scheme, *path;
  const char *p;

  *displayname = *user = *host = *params = NULL;
  p = addrline;

  name = NULL;
  semi = strchr(addrline, ';');
  if ((la = strchr(addrline, '<')) != NULL)
    {
      /* 2, 3 */
      if ((ra = strchr(la, '>')) == NULL)
        goto failed;
      name = ssh_memdup(la+1, (ra - la) - 1);
      if (la != addrline)
        *displayname = ssh_memdup(addrline, (la - addrline) - 1);
    }
  else
    {
      /* 1 */
      *displayname = NULL;
      if (semi == NULL)
        name = ssh_strdup(addrline);
      else
        name = ssh_memdup(addrline, (semi - addrline) - 1);
    }
  if (semi)
    *params = ssh_strdup(semi+1);

  path = NULL;
  if (ssh_url_parse_get(name,
                        (unsigned char **)((void *)&scheme), NULL,
                        (unsigned char **)((void *)&path), NULL, NULL, FALSE)
      != SSH_URL_OK
      || path == NULL || scheme == NULL || strcmp(scheme, "sip"))
    {
      ssh_free(path);
      goto failed;
    }
  ssh_free(scheme);
  ssh_free(name);

  if (ssh_url_parse_authority(path,
                              (unsigned char **)user,
                              NULL,
                              (unsigned char **)host,
                              NULL) != SSH_URL_OK)
    {
      ssh_free(path);
      goto failed;
    }
  ssh_free(path);
  return TRUE;

 failed:
  ssh_free(name);
  ssh_free(*displayname);
  ssh_free(*user);
  ssh_free(*host);
  ssh_free(*params);
  return FALSE;
}


/* sent-protocol lws sent-by [;via-params]
   via-params=(ttl,maddr,received,branch,extension)*/

char *alg_sip_write_sip_via(char *proto,
                            char *sent, SshUInt16 port,
                            char *params)
{
  SshBufferStruct b;
  char *p, portstr[6];

  ssh_buffer_init(&b);

  if (port)
    ssh_snprintf(portstr, sizeof(portstr), ":%d", port);
  ssh_buffer_append_cstrs(&b,
                          proto, " ", sent, " ",
                          port ? portstr : "",
                          params ? " ;" : "",
                          params ? params :"",
                          NULL);

  ssh_buffer_append(&b, "\0", 1);
  p = ssh_buffer_steal(&b, NULL);
  ssh_buffer_uninit(&b);

  return p;
}

Boolean alg_sip_parse_sip_via(const char *vialine,
                              char **proto,
                              char **sent, SshUInt16 *port,
                              char **params)
{
  const char *p = vialine, *paramsp, *colon;

  *proto = *sent = *params = NULL;

  if ((*proto = token(&p)) == NULL) goto failed;
  if ((*sent = token(&p)) == NULL) goto failed;

  *port = 0;
  if ((colon = strchr(*sent, ':')) != NULL)
    *port = (SshUInt16)strtoul((colon+1), NULL, 0);

  paramsp = strchr(vialine, ';');
  if (paramsp)
    *params = ssh_strdup(paramsp+1);
  return TRUE;

 failed:
  ssh_free(*proto); ssh_free(*sent);
  return FALSE;
}

#if 0
int main(int ac, char **av)
{
  unsigned char *input;
  size_t input_len;
  SshSipHdr siphdr;
  char *r;

  if (ssh_read_file(av[1], &input, &input_len))
    {
      if ((siphdr = alg_sip_parse_request(input)) != NULL)
        {
          if ((r = alg_sip_write_sip_header(siphdr)) != NULL)
            {
              printf("%s\n", r);
              ssh_free(r);
            }
          alg_sip_free_header(siphdr);
        }
      ssh_free(input);
    }
  ssh_util_uninit();
  return 0;
}
#endif

/*
 Session description protocol parsing for SIP application gateway.


 session = session-level + [media-level]*
 session-level = v= ... [media-level | end]*
 media-level = m= ... [media-level | end ]*

 session description =
   v=      zero
   o=      origin=username sessionid version nettype addrtype address
   s=      session name, utf-8
   [i=]    information, details, type of stream e.g.
   [u=]    URI, ptr to addtional information
   ([e=]*  Email
   [p=]*)+ Phone, should be international, w or w/o hyphens
   [c=]    connectiondata=nettype addrtype address (here or media)
   [b=]    bandwidth (CT|AS):value, or X-AA:value
   (t= [r=]*)+ t=start stop r=interval duration offsets
   [z=]    time zone adjustments
   [k=]    encryption key
   [a=]*   attributes

 nettype  = IN
 addrtype = IP4
 address  = IP or DNS (latter preferred), if multicast IP,
 in format address/ttl

 media description =
   m =   media data
   [i=] media title
   [c=]*        connection data; may be multiple; optinal if on session
   [b=] bandwidth
   [k=] encryption key
   [a=]*        attributes

 We only need to care about 'o=', 'c=', and 'm='
*/

static void
add_sdp_unhandled(SshSdpHdr sdphdr, char *tag, char *value)
{
  char *p, *n;
  size_t len;
  char **tmp;

  p = value;
  while (*p != '\0' && isspace(((unsigned char)*p)))
    p++;

  tmp = ssh_realloc(sdphdr->unhandled,
                    sdphdr->num_unhandled * sizeof(char **),
                    (sdphdr->num_unhandled + 1) * sizeof(char *));
  if (tmp)
    {
      len  = strlen(tag) + strlen(value) + 3;
      n = ssh_malloc(len);
      ssh_snprintf(n, len, "%s=%s", tag, p);
      tmp[sdphdr->num_unhandled++] = n;
      sdphdr->unhandled = tmp;
    }
}

void
alg_sip_free_sdp_header(SshSdpHdr sdphdr)
{
  int i;

  if (sdphdr == NULL)
    return;

  for (i = 0; i < sdphdr->num_v; i++) ssh_free(sdphdr->v[i]);
  ssh_free(sdphdr->v);
  for (i = 0; i < sdphdr->num_m; i++) ssh_free(sdphdr->m[i]);
  ssh_free(sdphdr->m);
  for (i = 0; i < sdphdr->num_o; i++) ssh_free(sdphdr->o[i]);
  ssh_free(sdphdr->o);
  for (i = 0; i < sdphdr->num_c; i++) ssh_free(sdphdr->c[i]);
  ssh_free(sdphdr->c);

  for (i = 0; i < sdphdr->num_unhandled; i++) ssh_free(sdphdr->unhandled[i]);
  ssh_free(sdphdr->unhandled);

  ssh_free(sdphdr);
}

char *
alg_sip_write_sdp_header(SshSdpHdr sdphdr)
{
  int i;
  SshBufferStruct o;
  char *p;

  ssh_buffer_init(&o);

  for (i = 0; i < sdphdr->num_v; i++)
    ssh_buffer_append_cstrs(&o, "v=", sdphdr->v[i], "\n", NULL);
  for (i = 0; i < sdphdr->num_o; i++)
    ssh_buffer_append_cstrs(&o, "o=", sdphdr->o[i], "\n", NULL);
  for (i = 0; i < sdphdr->num_c; i++)
    ssh_buffer_append_cstrs(&o, "c=", sdphdr->c[i], "\n", NULL);
  for (i = 0; i < sdphdr->num_m; i++)
    ssh_buffer_append_cstrs(&o, "m=", sdphdr->m[i], "\n", NULL);

  for (i = 0; i < sdphdr->num_unhandled; i++)
    ssh_buffer_append_cstrs(&o, sdphdr->unhandled[i], "\n", NULL);

  ssh_buffer_append(&o, "\0", 1);

  p = ssh_buffer_steal(&o, NULL);
  ssh_buffer_uninit(&o);
  return p;
}

SshSdpHdr alg_sip_parse_sdp(char *data, char **endptr)
{
  SshSdpHdr sdphdr;
  char *p = data, *next, *equal, *tag;

  if ((sdphdr = ssh_calloc(1, sizeof(*sdphdr))) == NULL)
    return NULL;

  /* skip whitespace */
  while (*p != '\0' && isspace(((unsigned char)*p))) p++;

  while (p && *p)
    {
      if ((next = strchr(p, '\n')) != NULL)
        *next++ = '\0';

      if ((equal = strchr(p, '=')) != NULL)
        {
          tag = p;
          *equal = '\0';
          p = equal + 1;

          if (!strcasecmp(tag, "v"))
            add_handled(&sdphdr->v, &sdphdr->num_v, p, FALSE);
          else if (!strcasecmp(tag, "m"))
            add_handled(&sdphdr->m, &sdphdr->num_m, p, FALSE);
          else if (!strcasecmp(tag, "o"))
            add_handled(&sdphdr->o, &sdphdr->num_o, p, FALSE);
          else if (!strcasecmp(tag, "c"))
            add_handled(&sdphdr->c, &sdphdr->num_c, p, FALSE);
          else
            add_sdp_unhandled(sdphdr, tag, p);
        }
      p = next;
    }
  *endptr = p;
  return sdphdr;
}

char *alg_sip_write_sdp_o(const char *user, const char *session,
                          const char *version, const char *nettype,
                          const char *addrtype, const char *address)
{
  SshBufferStruct b;
  char *p;

  ssh_buffer_init(&b);

  ssh_buffer_append_cstrs(&b,
                          user,
                          " ",  session,
                          " ",  version,
                          " ",  nettype,
                          " ",  addrtype,
                          " ",  address,
                          NULL);

  ssh_buffer_append(&b, "\0", 1);
  p = ssh_buffer_steal(&b, NULL);
  ssh_buffer_uninit(&b);

  return p;
}


Boolean
alg_sip_parse_sdp_o(const char *oline,
                    char **user,
                    char **session, char **version,
                    char **nettype, char **addrtype, char **address)
{
  const char *p;

  *user = *session = *version = *nettype = *addrtype = *address = NULL;

  p = oline;

  if ((*user = token(&p)) == NULL) goto failed;
  if ((*session = token(&p)) == NULL) goto failed;
  if ((*version = token(&p)) == NULL) goto failed;
  if ((*nettype = token(&p)) == NULL) goto failed;
  if ((*addrtype = token(&p)) == NULL) goto failed;
  if ((*address = token(&p)) == NULL) goto failed;

  return TRUE;

 failed:
  ssh_free(*user);
  ssh_free(*session); ssh_free(*version);
  ssh_free(*nettype); ssh_free(*addrtype);
  return FALSE;
}

char *
alg_sip_write_sdp_c(const char *nettype,
                    const char *addrtype,
                    const char *address)
{
  SshBufferStruct b;
  char *p;

  ssh_buffer_init(&b);

  ssh_buffer_append_cstrs(&b,
                          nettype,
                          " ",  addrtype,
                          " ",  address,
                          NULL);

  ssh_buffer_append(&b, "\0", 1);
  p = ssh_buffer_steal(&b, NULL);
  ssh_buffer_uninit(&b);

  return p;
}

Boolean
alg_sip_parse_sdp_c(const char *cline,
                    char **nettype, char **addrtype, char **address)
{
  const char *p;

  *nettype = *addrtype = *address = NULL;

  p = cline;

  if ((*nettype = token(&p)) == NULL) goto failed;
  if ((*addrtype = token(&p)) == NULL) goto failed;
  if ((*address = token(&p)) == NULL) goto failed;

  return TRUE;

 failed:
  ssh_free(*nettype); ssh_free(*addrtype);
  return FALSE;
}

char *
alg_sip_write_sdp_m(const char *media,
                    SshUInt16 port, SshUInt16 nports,
                    const char *proto,
                    const char *rest)
{
  SshBufferStruct b;
  char *p;
  char portstr[12];
  int off;

  ssh_buffer_init(&b);

  off = ssh_snprintf(portstr, sizeof(portstr), "%d", port);
  if (nports)
    ssh_snprintf(portstr + off, sizeof(portstr) - off, "/%d", nports);

  ssh_buffer_append_cstrs(&b,
                          media,
                          " ",  portstr,
                          " ",  proto,
                          " ",  rest,
                          NULL);

  ssh_buffer_append(&b, "\0", 1);
  p = ssh_buffer_steal(&b, NULL);
  ssh_buffer_uninit(&b);

  return p;
}

Boolean
alg_sip_parse_sdp_m(const char *mline,
                    char **media,
                    SshUInt16 *port, SshUInt16 *nports,
                    char **proto,
                    char **rest)
{
  const char *p;
  char *slash, *portstr;

  *media = *proto = *rest = NULL;
  *port = *nports = 0;

  p = mline;

  if ((*media = token(&p)) == NULL) goto failed;
  if ((portstr = token(&p)) == NULL)
    goto failed;
  else
    {
      if ((slash = strchr(portstr, '/')) != NULL)
        {
          *slash++ = '\0';
          *nports = (SshUInt16)strtoul(slash, NULL, 0);
        }
      *port = (SshUInt16)strtoul(portstr, NULL, 0);
      ssh_free(portstr);
    }

  if ((*proto = token(&p)) == NULL) goto failed;
  *rest = ssh_strdup(p);
  return TRUE;

 failed:
  ssh_free(media); ssh_free(proto);
  return FALSE;
}
#endif /* SSHDIST_IPSEC_FIREWALL */
/* eof */
