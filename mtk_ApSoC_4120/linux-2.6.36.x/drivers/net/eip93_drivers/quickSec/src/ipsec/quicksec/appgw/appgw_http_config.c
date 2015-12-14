/*
 *
 * appgw_http_config.c
 *
 * Copyright:
 *       Copyright (c) 2002, 2003 SFNT Finland Oy.
 *       All rights reserved.
 *
 * An application gateway for HTTP.
 *
 */

#include "sshincludes.h"
#include "sshtimeouts.h"
#include "appgw_api.h"
#include "sshfsm.h"
#include "sshregex.h"
#include "sshgetput.h"

#include "appgw_http.h"
#include "appgw_http_internal.h"

#ifdef SSHDIST_IPSEC_FIREWALL

#define SSH_DEBUG_MODULE "SshAppgwHttpConfig"

SshAppgwHttpConfig
ssh_appgw_http_create_config(void)
{
  SshAppgwHttpConfig c;

  /* Look up based on service_id */

  c = ssh_malloc(sizeof(*c));
  if (c == NULL)
    return NULL;

  c->rules = NULL;
  c->blocks = NULL;
  c->clauses = NULL;
  c->nclauses = 0;
  c->service_id = 0;
  c->service_name = NULL;
  c->regex_ctx = ssh_regex_create_context();

  if (c->regex_ctx == NULL)
    {
      SSH_DEBUG(SSH_D_ERROR,("Could not allocate regex context"));
      ssh_free(c);
      return NULL;
    }
  return c;
}

void
ssh_appgw_http_destroy_config(SshAppgwHttpConfig config)
{
  SshAppgwHttpRule rule,r2;
  SshAppgwHttpBlockAction block,b2;
  int idx;

  if (config == NULL)
    return;

  rule = config->rules;
  while (rule != NULL)
    {
      r2 = rule->next;

      ssh_free(rule->name);
      ssh_free(rule->clauses);
      ssh_free(rule);

      rule = r2;
    }

  block = config->blocks;
  while (block != NULL)
    {
      b2 = block->next;

      ssh_free(block->content_type);
      ssh_free(block->header);
      ssh_free(block->name);
      ssh_free(block->data);
      ssh_free(block);

      block = b2;
    }

  for (idx = 0; idx < config->nclauses; idx++)
    ssh_appgw_http_free_clause(config->clauses[idx]);

  ssh_regex_free_context(config->regex_ctx);
  ssh_free(config->service_name);
  ssh_free(config->clauses);
  ssh_free(config);
}

void
ssh_appgw_http_set_tcp_redirect(SshAppgwHttpConfig config,
                                const SshIpAddr tcp_dst,
                                SshUInt16 tcp_port)
{
  memset(&config->tcp_dst, 0, sizeof(config->tcp_dst));
  config->tcp_port =  0;

  if (tcp_dst)
    config->tcp_dst = *tcp_dst;
  config->tcp_port = tcp_port;
}

void
ssh_appgw_http_free_clause(SshAppgwHttpMatchClause clause)
{
  if (clause->hdr_regex != NULL)
    ssh_regex_free(clause->hdr_regex);

  ssh_free(clause->hdr_regex_str);
  ssh_free(clause->name);
  ssh_free(clause->host);
  ssh_free(clause);
}

SshAppgwHttpMatchClause
ssh_appgw_http_find_clause(SshAppgwHttpConfig config,
                           const unsigned char *clause_name)
{
  int idx;
  for (idx = 0; idx < config->nclauses; idx++)
    {
      SSH_ASSERT(config->clauses[idx] != NULL);
      if (ssh_ustrcmp(config->clauses[idx]->name, clause_name) == 0)
        return config->clauses[idx];

    }
  return NULL;
}

SshAppgwHttpConfigValue
ssh_appgw_http_add_clause(SshAppgwHttpConfig config,
                          const unsigned char *clause_name,
                          const unsigned char *hdr_regex,
                          const unsigned char *host,
                          int min_url_length)
{
  SshAppgwHttpMatchClause clause;
  SshAppgwHttpMatchClause *clauses;

  if (clause_name == NULL || config == NULL)
    return SSH_APPGW_HTTP_CONFIG_BAD_OP;

  SSH_DEBUG(SSH_D_MY,("adding clause named '%s'",clause_name));

  clause = ssh_appgw_http_find_clause(config, clause_name);

  if (clause != NULL)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("clause named %s already exists",clause_name));
      return SSH_APPGW_HTTP_CONFIG_CLAUSE_EXISTS;
    }

  if ((clause = ssh_malloc(sizeof(*clause))) == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL,("out of memory error"));
      return SSH_APPGW_HTTP_CONFIG_OUT_OF_MEMORY;
    }

  clause->name = NULL;
  clause->hdr_regex = NULL;
  clause->hdr_regex_str = NULL;
  clause->host = NULL;

  clause->name = ssh_strdup(clause_name);

  if (clause->name == NULL)
    {
      ssh_appgw_http_free_clause(clause);
      return SSH_APPGW_HTTP_CONFIG_OUT_OF_MEMORY;
    }

  if (hdr_regex != NULL)
    {



      clause->hdr_regex = ssh_regex_create(config->regex_ctx,
                                           ssh_csstr(hdr_regex),
                                           SSH_REGEX_SYNTAX_SSH);

      if (clause->hdr_regex == NULL)
        {
          ssh_appgw_http_free_clause(clause);
          return SSH_APPGW_HTTP_CONFIG_BAD_REGEX;
        }

      clause->hdr_regex_str = ssh_strdup(hdr_regex);

      if (clause->hdr_regex_str == NULL)
        {
          ssh_appgw_http_free_clause(clause);
          return SSH_APPGW_HTTP_CONFIG_OUT_OF_MEMORY;
        }
    }

  if (host != NULL)
    {
      clause->host = ssh_strdup(host);
      if (clause->host == NULL)
        {
          ssh_appgw_http_free_clause(clause);
          return SSH_APPGW_HTTP_CONFIG_OUT_OF_MEMORY;
        }
    }

  clause->min_url_length = min_url_length;

  clauses = ssh_realloc(config->clauses,
                        (config->nclauses)
                        *sizeof(SshAppgwHttpMatchClause),
                        (config->nclauses+1)
                        *sizeof(SshAppgwHttpMatchClause));
  if (clauses == NULL)
    {
      ssh_appgw_http_free_clause(clause);
      return SSH_APPGW_HTTP_CONFIG_OUT_OF_MEMORY;
    }

  clauses[config->nclauses] = clause;
  config->nclauses++;
  config->clauses = clauses;

  return SSH_APPGW_HTTP_CONFIG_OK;
}

static SshAppgwHttpConfigValue
ssh_appgw_http_add_block_internal(SshAppgwHttpConfig config,
                                  const unsigned char *block_name,
                                  int http_code,
                                  const unsigned char *content_type,
                                  const unsigned char *header,
                                  int header_len,
                                  const unsigned char *data,
                                  int data_len,
                                  SshAppgwHttpBlockAction *block_ret)
{
  SshAppgwHttpBlockAction block;

  if (block_name == NULL || config == NULL)
    return SSH_APPGW_HTTP_CONFIG_BAD_OP;

  SSH_DEBUG(SSH_D_MY,("adding block named '%s'",block_name));

  for (block = config->blocks; block != NULL; block=block->next)
    if (ssh_ustrcmp(block_name, block->name) == 0)
      {
        SSH_DEBUG(SSH_D_FAIL,
                  ("block action named '%s' already exists",block_name));
        return SSH_APPGW_HTTP_CONFIG_BLOCK_EXISTS;
      }

  block = ssh_calloc(1,sizeof(*block));

  if (block == NULL)
    return SSH_APPGW_HTTP_CONFIG_OUT_OF_MEMORY;

  block->name = NULL;
  block->content_type = NULL;
  block->data = NULL;
  block->data_len = 0;
  block->header = NULL;
  block->header_len = 0;

  block->name = ssh_strdup(block_name);
  if (content_type != NULL)
    block->content_type = ssh_strdup(content_type);

  block->code = (http_code < 100 || http_code > 999? 404: http_code );
  if (data != NULL)
    {
      block->data_len = data_len;
      if ((block->data = ssh_malloc(block->data_len)) != NULL)
        memcpy(block->data,data,block->data_len);
    }

  if (header != NULL)
    {
      block->header_len = header_len;
      if ((block->header = ssh_malloc(block->header_len)) != NULL)
        memcpy(block->header,header,block->header_len);
    }

  if ((data != NULL && block->data == NULL)
      || (header != NULL && block->header == NULL)
       || block->name == NULL
       || block->content_type == NULL)
    {
      ssh_free(block->data);
      ssh_free(block->header);
      ssh_free(block->content_type);
      ssh_free(block->name);
      ssh_free(block);
      return SSH_APPGW_HTTP_CONFIG_OUT_OF_MEMORY;
    }

  block->next = config->blocks;
  config->blocks = block;

  if (block_ret)
    *block_ret = block;

  return SSH_APPGW_HTTP_CONFIG_OK;
}

SshAppgwHttpConfigValue
ssh_appgw_http_add_block(SshAppgwHttpConfig config,
                         const unsigned char *block_name,
                         int http_code,
                         const unsigned char *content_type,
                         const unsigned char *data,
                         int data_len)

{
  if (content_type == NULL)
    content_type = ssh_custr("text/html");

  return ssh_appgw_http_add_block_internal(config, block_name,
                                           http_code, content_type,
                                           NULL, 0,
                                           data, data_len,
                                           NULL);
}

SshAppgwHttpConfigValue
ssh_appgw_http_add_block_custom_header(SshAppgwHttpConfig config,
                                       const unsigned char *block_name,
                                       int http_code,
                                       const unsigned char *content_type,
                                       const unsigned char *header,
                                       int header_len,
                                       const unsigned char *data,
                                       int data_len)
{
  SshAppgwHttpConfigValue ret;

  ret = ssh_appgw_http_add_block_internal(config, block_name,
                                          http_code, content_type,
                                          header, header_len,
                                          data, data_len,
                                          NULL);

  return ret;
}



SshAppgwHttpConfigValue
ssh_appgw_http_rule_set_action(SshAppgwHttpConfig config,
                               SshAppgwHttpRule r,
                               SshAppgwHttpRuleAction action,
                               const char *param)
{
  SshAppgwHttpBlockAction block;

  if (config == NULL || r == NULL)
    return SSH_APPGW_HTTP_CONFIG_BAD_OP;

  r->action = action;
  r->block = NULL;

  if (action == SSH_APPGW_HTTP_ACTION_BLOCK && param != NULL)
    {
      for (block = config->blocks; block != NULL; block=block->next)
        if (ssh_usstrcmp(block->name, param) == 0)
          break;

      if (block == NULL)
        {
          SSH_DEBUG(SSH_D_FAIL,("could not find block reply definition"));
          return SSH_APPGW_HTTP_CONFIG_COULD_NOT_FIND_BLOCK;
        }

      r->block = block;
    }
  return SSH_APPGW_HTTP_CONFIG_OK;;
}

SshAppgwHttpConfigValue
ssh_appgw_http_rule_add_clause(SshAppgwHttpConfig config,
                               SshAppgwHttpRule rule,
                               const unsigned char *clause_name)
{
  SshAppgwHttpMatchClause clause;
  SshAppgwHttpMatchClause *clauses;

  if (config == NULL || rule == NULL)
    return SSH_APPGW_HTTP_CONFIG_BAD_OP;

  clause = ssh_appgw_http_find_clause(config, clause_name);

  if (clause == NULL)
    return SSH_APPGW_HTTP_CONFIG_COULD_NOT_FIND_CLAUSE;

  clauses = ssh_realloc(rule->clauses,
                        rule->nclauses*sizeof(SshAppgwHttpMatchClause),
                        (rule->nclauses+1)*sizeof(SshAppgwHttpMatchClause));

  if (clauses == NULL)
    return SSH_APPGW_HTTP_CONFIG_OUT_OF_MEMORY;

  SSH_DEBUG(SSH_D_MY,("adding clause '%s' to rule '%s'",
                      rule->name,clause_name));

  rule->clauses = clauses;
  rule->clauses[rule->nclauses] = clause;
  rule->nclauses++;

  return SSH_APPGW_HTTP_CONFIG_OK;
}

SshAppgwHttpConfigValue
ssh_appgw_http_add_rule(SshAppgwHttpConfig config,
                        const unsigned char *rule_name,
                        int precedence,
                        SshAppgwHttpRuleAction action,
                        const unsigned char *block_name,
                        SshAppgwHttpRule *rule)
{
  SshAppgwHttpRule r;
  SshAppgwHttpBlockAction block;

  *rule = NULL;

  if (rule_name == NULL || config == NULL)
    return SSH_APPGW_HTTP_CONFIG_BAD_OP;

  for (r = config->rules; r != NULL; r = r->next)
    if (ssh_ustrcmp(rule_name, r->name) == 0)
      {
        SSH_DEBUG(SSH_D_FAIL,
                  ("rule named '%s' already exists",rule_name));
        return SSH_APPGW_HTTP_CONFIG_RULE_EXISTS;
      }

  block = NULL;

  if (block_name != NULL)
    {
      for (block = config->blocks; block != NULL; block = block->next)
        if (ssh_ustrcmp(block_name, block->name) == 0)
          break;

      if (block == NULL)
        {
          SSH_DEBUG(SSH_D_FAIL,("could not find block reply definition"));
          return SSH_APPGW_HTTP_CONFIG_COULD_NOT_FIND_BLOCK;
        }
    }

  /* Construct rule */

  r = ssh_malloc(sizeof(*r));
  if (r == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL,("out of memory error"));
      return SSH_APPGW_HTTP_CONFIG_OUT_OF_MEMORY;
    }

  if ((r->name = ssh_strdup(rule_name)) == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL,("out of memory error"));
      ssh_free(r);
      return SSH_APPGW_HTTP_CONFIG_OUT_OF_MEMORY;
    }

  r->action = action;
  r->block = block;
  r->nclauses = 0;
  r->clauses = NULL;
  r->precedence = precedence;

  /* Add rule according to precedence */

  if (config->rules == NULL || config->rules->precedence < r->precedence)
    {
      r->next = config->rules;
      config->rules = r;
    }
  else
    {
      SshAppgwHttpRule r2;

      r2 = config->rules;
      while (r2->next != NULL)
        {
          if (r2->next->precedence < r->precedence)
            break;
          r2 = r2->next;
        }

      if (r2->next == NULL)
        {
          r2->next = r;
          r->next = NULL;
        }
      else
        {
          r->next = r2->next->next;
          r2->next = r;
        }
    }

  SSH_DEBUG(SSH_D_MY,("HTTP appgw rule '%s' added",r->name));

  *rule = r;
  return SSH_APPGW_HTTP_CONFIG_OK;
}

static int
ssh_appgw_http_marshal_data(SshBuffer buf, const unsigned char *str,
                            size_t len)
{
  SshUInt32 i;

  if (str == NULL)
    {
      SSH_PUT_32BIT(&i,0);
      if (ssh_buffer_append(buf, (unsigned char *)&i, 4) == SSH_BUFFER_ERROR)
        return 0;
    }
  else
    {
      SSH_PUT_32BIT(&i,len);
      if (ssh_buffer_append(buf, (unsigned char*)&i, 4) == SSH_BUFFER_ERROR)
        return 0;

      if (ssh_buffer_append(buf, (unsigned char *)str,len) == SSH_BUFFER_ERROR)
        return 0;
    }
  return 1;
}

static int
ssh_appgw_http_marshal_string(SshBuffer buf, const unsigned char *str)
{
  if (str == NULL)
    return ssh_appgw_http_marshal_data(buf, NULL, 0);
  else
    return ssh_appgw_http_marshal_data(buf, str, ssh_ustrlen(str));
}


static int
ssh_appgw_http_marshal_int(SshBuffer buf, int i)
{
  SshUInt32 hi;

  SSH_PUT_32BIT(&hi,i);
  if (ssh_buffer_append(buf,(unsigned char*)&hi,4) == SSH_BUFFER_ERROR)
    return 0;
  return 1;
}

static int
ssh_appgw_http_unmarshal_int(SshBuffer buf, int *result)
{
  if (ssh_buffer_len(buf) < 4)
    {
      *result = 0;
      return 0;
    }

  *result = (int)(SSH_GET_32BIT(ssh_buffer_ptr(buf)));
  ssh_buffer_consume(buf,4);
  return 1;
}

static int
ssh_appgw_http_unmarshal_data(SshBuffer buf, unsigned char **ptr, int *len)
{
  *ptr = NULL;
  *len = 0;

  if (ssh_appgw_http_unmarshal_int(buf, len) == 0)
    return 0;

  if (*len == 0)
    return 1;

  if (ssh_buffer_len(buf) < *len)
    return 0;

  *ptr = ssh_malloc(*len);
  if (ptr == NULL)
    return 0;

  memcpy(*ptr,ssh_buffer_ptr(buf),*len);
  ssh_buffer_consume(buf,*len);
  return 1;
}

static int
ssh_appgw_http_unmarshal_string(SshBuffer buf, unsigned char **ptr)
{
  int len;

  *ptr = NULL;

  if (ssh_appgw_http_unmarshal_int(buf, &len) == 0)
    return 0;

  if (len == 0)
    return 1;

  if (ssh_buffer_len(buf) < len)
    return 0;

  *ptr = ssh_malloc(len+1);
  if (ptr == NULL)
    return 0;

  memcpy(*ptr,ssh_buffer_ptr(buf),len);
  (*ptr)[len] = '\0';
  ssh_buffer_consume(buf,len);
  return 1;

}

#define CFGVERSION "APPGW-HTTP-CONFIG-PKT-10"

unsigned char*
ssh_appgw_http_marshal_config(SshAppgwHttpConfig config,
                              size_t *res_len)
{
  SshBuffer buf;
  char *data;
  int i,nblocks,nrules,ok;
  unsigned char tbuf[SSH_IP_ADDR_STRING_SIZE];
  SshAppgwHttpBlockAction reply;
  SshAppgwHttpRule rule;

  nblocks = 0;
  for (reply = config->blocks; reply != NULL; reply=reply->next)
    nblocks++;

  nrules = 0;
  for (rule = config->rules; rule != NULL; rule=rule->next)
    nrules++;

  buf = ssh_buffer_allocate();
  if (buf == NULL)
    return NULL;

  ok = 1;
  ok &= ssh_appgw_http_marshal_string(buf, ssh_custr(CFGVERSION));

  /* Marshal TCP redirection */
  tbuf[0] = '\0';
  if (SSH_IP_DEFINED(&config->tcp_dst))
    ssh_ipaddr_print(&config->tcp_dst, tbuf, sizeof(tbuf));

  ok &= ssh_appgw_http_marshal_string(buf, tbuf);
  ok &= ssh_appgw_http_marshal_int(buf, config->tcp_port);

  ok &= ssh_appgw_http_marshal_int(buf,config->nclauses);
  for (i = 0; i < config->nclauses; i++)
    {
      ok &= ssh_appgw_http_marshal_string(buf,config->clauses[i]->name);
      ok &= ssh_appgw_http_marshal_string(buf,
                                          config->clauses[i]->hdr_regex_str);
      ok &= ssh_appgw_http_marshal_string(buf,config->clauses[i]->host);
      ok &= ssh_appgw_http_marshal_int(buf,config->clauses[i]->min_url_length);
    }

  ok &= ssh_appgw_http_marshal_int(buf,nblocks);

  for (reply = config->blocks; reply != NULL; reply=reply->next)
    {
      ok &= ssh_appgw_http_marshal_string(buf,reply->name);
      ok &= ssh_appgw_http_marshal_int(buf,reply->code);
      ok &= ssh_appgw_http_marshal_string(buf,reply->content_type);
      ok &= ssh_appgw_http_marshal_data(buf, reply->header,
                                        reply->header_len);
      ok &= ssh_appgw_http_marshal_data(buf, reply->data,
                                        reply->data_len);
    }


  ok &= ssh_appgw_http_marshal_int(buf,nrules);

  for (rule = config->rules; rule != NULL; rule=rule->next)
    {
      ok &= ssh_appgw_http_marshal_string(buf,rule->name);
      ok &= ssh_appgw_http_marshal_int(buf,rule->action);

      if (rule->block != NULL)
        ok &= ssh_appgw_http_marshal_string(buf,rule->block->name);
      else
        ok &= ssh_appgw_http_marshal_string(buf,NULL);

      ok &= ssh_appgw_http_marshal_int(buf,rule->precedence);
      ok &= ssh_appgw_http_marshal_int(buf,rule->nclauses);
      for (i = 0; i < rule->nclauses; i++)
        ok &= ssh_appgw_http_marshal_string(buf,rule->clauses[i]->name);
    }

  ok &= ssh_appgw_http_marshal_int(buf,0);

  data = ssh_malloc(ssh_buffer_len(buf));

  if (ok == 0 || data == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL,("out of memory error"));
      ssh_buffer_free(buf);
      return NULL;
    }
  memcpy(data,ssh_buffer_ptr(buf),ssh_buffer_len(buf));
  *res_len = ssh_buffer_len(buf);

  ssh_buffer_free(buf);
  SSH_DEBUG(SSH_D_MY,
            ("marshaled config blob (%d bytes)",*res_len));

  return (unsigned char *)data;
}

SshAppgwHttpConfig
ssh_appgw_http_unmarshal_config(const unsigned char *data,
                                size_t len)
{
  SshAppgwHttpConfig c;
  unsigned char *tmp;
  SshBufferStruct buf;
  int ok, i, i2, nobs, check, port;

  SSH_DEBUG(SSH_D_MY,
            ("unmarshaling configuration blob (%d bytes)",
             len));

  c = ssh_appgw_http_create_config();

  if (c == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL,("ouf of memory error"));
      return NULL;
    }

  if (len == 0 || data == NULL)
    return c;

  ssh_buffer_wrap(&buf, (unsigned char *) data, len);
  buf.end = len;

  ok = 1;
  ok &= ssh_appgw_http_unmarshal_string(&buf,&tmp);

  if (ok == 0 || ssh_usstrcmp(tmp, CFGVERSION) != 0)
    {
      ssh_free(tmp);
      ssh_appgw_http_destroy_config(c);
      return NULL;
    }
  ssh_free(tmp);

  tmp = NULL;
  ok &= ssh_appgw_http_unmarshal_string(&buf, &tmp);
  ok &= ssh_appgw_http_unmarshal_int(&buf, &port);
  ok &= ssh_appgw_http_unmarshal_int(&buf, &nobs);

  if (ok == 0)
    {
      ssh_free(tmp);
      ssh_appgw_http_destroy_config(c);
      return NULL;
    }

  memset(&c->tcp_dst, 0, sizeof(c->tcp_dst));
  if (tmp)
    ssh_ipaddr_parse(&c->tcp_dst, tmp);
  c->tcp_port = (SshUInt16)port;
  ssh_free(tmp);

  for (i = 0; i < nobs; i++)
    {
      unsigned char *name, *regex, *host;
      int min_url_length;

      ok &= ssh_appgw_http_unmarshal_string(&buf, &name);
      ok &= ssh_appgw_http_unmarshal_string(&buf, &regex);
      ok &= ssh_appgw_http_unmarshal_string(&buf, &host);
      ok &= ssh_appgw_http_unmarshal_int(&buf, &min_url_length);

      if (name == NULL)
        ok = 0;
      else if (ssh_appgw_http_add_clause(c, name, regex,host, min_url_length)
               != SSH_APPGW_HTTP_CONFIG_OK)
        ok = 0;

      ssh_free(name);
      ssh_free(regex);
      ssh_free(host);
    }

  ok &= ssh_appgw_http_unmarshal_int(&buf,&nobs);
  if (ok == 0)
    {
      ssh_appgw_http_destroy_config(c);
      return NULL;
    }

  for (i = 0; i < nobs; i++)
    {
      unsigned char *name, *content_type;
      int code,data_len,header_len;
      unsigned char *data,*header;

      ok &= ssh_appgw_http_unmarshal_string(&buf, &name);
      ok &= ssh_appgw_http_unmarshal_int(&buf, &code);
      ok &= ssh_appgw_http_unmarshal_string(&buf, &content_type);
      ok &= ssh_appgw_http_unmarshal_data(&buf, &header, &header_len);
      ok &= ssh_appgw_http_unmarshal_data(&buf, &data, &data_len);

      if (name == NULL)
        ok = 0;
      else if (ssh_appgw_http_add_block_internal(c, name, code, content_type,
                                                 header, header_len,
                                                 data, data_len, NULL)
               != SSH_APPGW_HTTP_CONFIG_OK)
        ok = 0;

      ssh_free(name);
      ssh_free(header);
      ssh_free(content_type);
      ssh_free(data);
    }

  ok &= ssh_appgw_http_unmarshal_int(&buf,&nobs);
  if (ok == 0)
    {
      ssh_appgw_http_destroy_config(c);
      return NULL;
    }

  for (i = 0; i < nobs; i++)
    {
      int nclauses, action, precedence;
      unsigned char *name, *block;
      SshAppgwHttpRule r;

      ok &= ssh_appgw_http_unmarshal_string(&buf, &name);
      ok &= ssh_appgw_http_unmarshal_int(&buf, &action);
      ok &= ssh_appgw_http_unmarshal_string(&buf, &block);
      ok &= ssh_appgw_http_unmarshal_int(&buf, &precedence);
      ok &= ssh_appgw_http_unmarshal_int(&buf, &nclauses);

      if (ok == 1)
        {
          if (ssh_appgw_http_add_rule(c,name,precedence,action,block,&r)
               != SSH_APPGW_HTTP_CONFIG_OK)
            {
              ok = 0;
            }
          else
            {
              unsigned char *clause_name;

              for (i2 = 0; i2 < nclauses; i2++)
                {
                  clause_name = NULL;
                  ok &= ssh_appgw_http_unmarshal_string(&buf, &clause_name);
                  if (ok == 1)
                    if (ssh_appgw_http_rule_add_clause(c,r,clause_name)
                         != SSH_APPGW_HTTP_CONFIG_OK)
                      ok = 0;
                  ssh_free(clause_name);
                }
            }
          ssh_free(name);
          ssh_free(block);
        }
    }
  ok &= ssh_appgw_http_unmarshal_int(&buf,&check);

  if (ok == 0 || check != 0)
    {
      SSH_DEBUG(SSH_D_MY,("check int value %d",check));
      ssh_appgw_http_destroy_config(c);
      return NULL;
    }

  return c;
}
#endif /* SSHDIST_IPSEC_FIREWALL */
