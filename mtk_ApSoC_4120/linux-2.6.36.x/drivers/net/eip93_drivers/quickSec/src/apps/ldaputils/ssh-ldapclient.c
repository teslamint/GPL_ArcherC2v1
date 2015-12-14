/*
 * Author: Tero Kivinen <kivinen@iki.fi>
 *  Copyright:
 *          Copyright (c) 2002, 2003 SFNT Finland Oy.
 * Program: LDAP search client
 */

#include "sshincludes.h"

#ifdef SSHDIST_APPS_LDAPUTILS

#include "sshldap.h"
#include "sshmp.h"
#include "sshdebug.h"
#include "sshtimeouts.h"
#include "sshfileio.h"
#include "ssheloop.h"
#include "sshgetopt.h"
#include "sshnameserver.h"






#define SSH_DEBUG_MODULE "SshLdapClient"

/* Program name */
char *program;
char *filename = NULL;
int item_cnt = 0;

void ldap_result(SshLdapClient client, SshLdapResult result,
                 const SshLdapResultInfo info,
                 void *callback_context);

void ldap_search(SshLdapClient client,
                 SshLdapObject object,
                 void *callback_context);

void ldap_disconnect(void *context);

void ldap_connected(SshLdapClient client,
                    SshTcpError status,
                    void *context);

typedef struct LdapSearchCtxRec {
  unsigned char **searchs;
  int cnt;
  int current;
  SshLdapClient client;
  struct LdapConnectCtxRec *connect_ctx; 
  char *base_dn;
  unsigned char **attrs;
  size_t *attr_lens;
  SshLdapSearchScope scope;
  SshLdapDerefAliases deref;
  int number_of_attributes;
  SshLdapSearchFilter f;
} *LdapSearchCtx;






typedef struct LdapConnectCtxRec {
  unsigned char *bind_name, *password;
  size_t bind_name_len, password_len;
  LdapSearchCtx search_ctx;
  unsigned char *ldap_server_name;
  SshLdapVersion ldap_protocol_version;






















} *LdapConnectCtx;

static void free_connect_ctx(LdapConnectCtx connect_ctx)
{



  ssh_xfree(connect_ctx);
  return;
}
























































































































































void ldap_connected(SshLdapClient client,
                    SshTcpError status,
                    void *context)
{
  LdapConnectCtx connect_ctx = context;
  switch (status)
    {
    case SSH_TCP_OK:
    case SSH_TCP_NEW_CONNECTION:














      /* Not really mandatory for LDAPv3 */
      ssh_ldap_client_bind(client,
                           connect_ctx->bind_name, connect_ctx->bind_name_len,
                           connect_ctx->password, connect_ctx->password_len,
                           ldap_result, connect_ctx->search_ctx);




        ssh_xfree(connect_ctx);
      break;
    default:
      ssh_warning("Connection to %s failed: %s",
                  connect_ctx->ldap_server_name,
                  ssh_tcp_error_string(status));
      free_connect_ctx(connect_ctx);
      break;
    }

  return;
}











void ldap_disconnect(void *context)
{
  SshLdapClient client = context;

  SSH_DEBUG(5, ("Calling disconnect"));
  ssh_ldap_client_disconnect(client);
  ssh_name_server_uninit();
}

void ldap_next(void *context)
{
  LdapSearchCtx search_ctx = context;

  if (search_ctx->current == search_ctx->cnt)
    {
      ldap_disconnect(search_ctx->client);
      return;
    }

  if (!ssh_ldap_string_to_filter(search_ctx->searchs[search_ctx->current],
                                 strlen((char *)search_ctx->
                                        searchs[search_ctx->current]),
                                 &search_ctx->f))
    ssh_fatal("ssh_ldap_string_to_filter failed, string = %s",
              search_ctx->searchs[search_ctx->current]);

  ssh_ldap_client_search(search_ctx->client, search_ctx->base_dn,
                         search_ctx->scope,
                         search_ctx->deref, 0, 0,
                         FALSE, search_ctx->f,
                         search_ctx->number_of_attributes,
                         search_ctx->attrs,
                         search_ctx->attr_lens,
                         ldap_search, context, ldap_result, context);
  search_ctx->current++;
}

void ldap_result(SshLdapClient ctx,
                 SshLdapResult result,
                 const SshLdapResultInfo info,
                 void *callback_context)
{
  unsigned char *str;
  LdapSearchCtx search_ctx = callback_context;

  str = NULL;
  if (search_ctx->f)
    {
      ssh_ldap_filter_to_string(search_ctx->f, &str, NULL);
      ssh_ldap_free_filter(search_ctx->f);
    }

  if (result == SSH_LDAP_RESULT_SUCCESS &&
      info->matched_dn == NULL && info->error_message == NULL)
    SSH_DEBUG(4, ("Result callback called, result = success%s%s",
                  (str != NULL ? " : " : ""),
                  (str != NULL ? (char *)str : "")));
  else
    SSH_DEBUG(4, ("Result callback called, "
                  "result = %s (%d), matched_dn = %s, error = %s%s%s",
                  ssh_ldap_error_code_to_string(result),
                  result,
                  (info->matched_dn ?
                   (char *)info->matched_dn : "not returned"),
                  (info->error_message ?
                   (char *)info->error_message : "not returned"),
                  (str != NULL ? " : " : ""),
                  (str != NULL ? (char *)str : "")));
  ssh_xfree(str);
  if (result != 0)
    {
      ssh_warning("Operation failed: %s, %s",
                  ssh_ldap_error_code_to_string(result),
                  info->error_message ? (char *)info->error_message :
                  "(no error message)");
      if (result != SSH_LDAP_RESULT_ABORTED)
        {
          ldap_disconnect(search_ctx->client);





        }
      return;
    }
  ldap_next(callback_context);
  return;
}

void ldap_search(SshLdapClient ctx,
                 SshLdapObject object,
                 void *callback_context)
{
  int i, j, k, l;
  unsigned char *str;
  LdapSearchCtx search_ctx = callback_context;

  ssh_ldap_filter_to_string(search_ctx->f, &str, NULL);

  SSH_DEBUG(4, ("Search %s", (char *)str));
  ssh_xfree(str);
  SSH_DEBUG(4, ("Item %s, attributes = %d",
                object->object_name, object->number_of_attributes));

  ++item_cnt;
  if (filename && strcmp(filename, "-"))
    {
      char buffer[255];

      ssh_snprintf(buffer, sizeof(buffer), filename, item_cnt,
                   "object_name", 0);
      ssh_write_gen_file(buffer,
                         SSH_PEM_GENERIC,
                         (unsigned char *) object->object_name,
                         object->object_name_len);
    }

  for (i = 0; i < object->number_of_attributes; i++)
    {
      SSH_DEBUG(5, ("Attribute[%d] = %s, values = %d", i,
                    object->attributes[i].attribute_type,
                    object->attributes[i].number_of_values));
      for (j = 0; j < object->attributes[i].number_of_values; j++)
        {
          if (filename)
            {
              char buffer[255];

              ssh_snprintf(buffer, sizeof(buffer), filename, item_cnt,
                           object->attributes[i].attribute_type, j);

              ssh_write_gen_file(buffer,
                                 SSH_PEM_GENERIC,
                                 (unsigned char *)
                                 object->attributes[i].values[j],
                                 object->attributes[i].value_lens[j]);
            }
          else
            {
              for (k = 0; k < object->attributes[i].value_lens[j]; k++)
                {
                  if (!isprint(object->attributes[i].values[j][k] & 0xff))
                    break;
                }
              if (k == object->attributes[i].value_lens[j])
                {
                  SSH_DEBUG(6, ("Value[%d] = %s", j,
                                object->attributes[i].values[j]));
                }
              else
                {
                  char buffer[80];

                  SSH_DEBUG(6, ("Value[%d][0..%d]", j,
                                object->attributes[i].value_lens[j]));
                  for (k = 0; k < object->attributes[i].value_lens[j]; k += 16)
                    {
                      ssh_snprintf(buffer, sizeof(buffer), "%08x: ", k);
                      for (l = 0; l < 16; l++)
                        {
                          if (k + l < object->attributes[i].value_lens[j])
                            ssh_snprintf(buffer + strlen(buffer),
                                         sizeof(buffer) - strlen(buffer),
                                         "%02x",
                                         object->attributes[i].
                                         values[j][k + l] & 0xff);
                          else
                            ssh_snprintf(buffer + strlen(buffer),
                                         sizeof(buffer) - strlen(buffer),
                                         "  ");
                          if ((l % 2) == 1)
                            ssh_snprintf(buffer + strlen(buffer),
                                         sizeof(buffer) - strlen(buffer),
                                         " ");
                        }
                      ssh_snprintf(buffer + strlen(buffer),
                                   sizeof(buffer) - strlen(buffer),
                               " ");
                      for (l = 0; l < 16; l++)
                        {
                          if (k + l < object->attributes[i].value_lens[j])
                            {
                              if (isprint(object->attributes[i].
                                          values[j][k + l] & 0xff))
                                ssh_snprintf(buffer + strlen(buffer),
                                             sizeof(buffer) - strlen(buffer),
                                             "%c", object->attributes[i].
                                             values[j][k + l]);
                              else
                                ssh_snprintf(buffer + strlen(buffer),
                                             sizeof(buffer) - strlen(buffer),
                                             ".");
                            }
                          else
                            {
                              ssh_snprintf(buffer + strlen(buffer),
                                           sizeof(buffer) - strlen(buffer),
                                           " ");
                            }
                        }
                      SSH_DEBUG(6, ("%s", buffer));
                    }
                }
            }
        }
    }
  if (filename && !strcmp(filename, "-"))
    {
      ssh_write_file(filename, (unsigned char *)"\n", 1);
    }

  ssh_ldap_free_object(object);
}


const SshKeywordStruct deref_keywords[] = {
  { "never", SSH_LDAP_DEREF_ALIASES_NEVER },
  { "searching", SSH_LDAP_DEREF_ALIASES_IN_SEARCHING },
  { "base", SSH_LDAP_DEREF_ALIASES_FINDING_BASE_OBJECT },
  { "always", SSH_LDAP_DEREF_ALIASES_ALWAYS },
  { NULL, 0 }
};

const SshKeywordStruct scope_keywords[] = {
  { "base", SSH_LDAP_SEARCH_SCOPE_BASE_OBJECT },
  { "single", SSH_LDAP_SEARCH_SCOPE_SINGLE_LEVEL },
  { "subtree", SSH_LDAP_SEARCH_SCOPE_WHOLE_SUBTREE },
  { NULL, 0 }
};

int main(int argc, char **argv)
{
  int c, errflg = 0;
  struct SshLdapClientParamsRec params;
  SshLdapClient client;
  SshLdapVersion ldap_protocol_version = SSH_LDAP_VERSION_3;














#define TLSOPTS ""


#ifdef DEBUG_LIGHT
  const char *debug_string = "SshLdap*=6";
  const char *option_string= "hbd:s:p:u:P:S:a:f:D:O:v:" TLSOPTS;
#else
  const char *option_string= "hbs:p:u:P:S:a:f:D:O:v:" TLSOPTS;
#endif /* DEBUG_LIGHT */
  unsigned char **attrs = NULL;
  char *attributes = NULL, *base_dn = NULL;
  size_t *attr_lens = NULL;
  int i, number_of_attributes = 0;
  LdapConnectCtx connect_ctx;
  struct LdapSearchCtxRec search_ctx;
  SshLdapSearchScope scope = SSH_LDAP_SEARCH_SCOPE_WHOLE_SUBTREE;
  SshLdapDerefAliases deref = SSH_LDAP_DEREF_ALIASES_NEVER;
  unsigned char *ldap_server_name;
  unsigned char *ldap_server_port, *bind_name, *password;

  ldap_server_name = ssh_ustr("ryijy.hel.internal");
  ldap_server_port = ssh_ustr("389");
  bind_name = ssh_ustr("");
  password = ssh_ustr("");

  ssh_math_library_initialize();




  memset(&params, 0, sizeof(params));
  params.socks = NULL;
  params.connection_attempts = 1;

  program = strrchr(argv[0], '/');
  if (program == NULL)
    program = argv[0];
  else
    program++;

  while ((c = ssh_getopt(argc, argv, option_string, NULL)) != EOF)
    {
      switch (c)
        {
        case 'f': filename = ssh_optarg; break;
#ifdef DEBUG_LIGHT
        case 'd': debug_string = ssh_optarg; break;
#endif /* DEBUG_LIGHT */
        case 's': ldap_server_name = (unsigned char *)ssh_optarg; break;
        case 'p': ldap_server_port = (unsigned char *)ssh_optarg; break;
        case 'u': bind_name = (unsigned char *)ssh_optarg; break;
        case 'P': password = (unsigned char *)ssh_optarg; break;
        case 'O': params.socks = (unsigned char *)ssh_optarg; break;
        case 'a': attributes = ssh_optarg; break;
        case 'D': deref = ssh_find_keyword_number(deref_keywords, ssh_optarg);
          if (deref == -1)
            {
              fprintf(stderr, "Invalid keyword for deref option: %s\n",
                      ssh_optarg);
              exit(1);
            }
          break;
        case 'S': scope = ssh_find_keyword_number(scope_keywords, ssh_optarg);
          if (scope == -1)
            {
              fprintf(stderr, "Invalid keyword for scope option: %s\n",
                      ssh_optarg);
              exit(1);
            }
          break;
        case 'v':
        if (!strncasecmp(ssh_optarg, "2", 1) ||
            !strncasecmp(ssh_optarg, "v2", 2) ||
            !strncasecmp(ssh_optarg, "ldapv2", 6))
          { ldap_protocol_version = SSH_LDAP_VERSION_2; break; }
        if (!strncasecmp(ssh_optarg, "3", 1) ||
            !strncasecmp(ssh_optarg, "v3", 2) ||
            !strncasecmp(ssh_optarg, "ldapv3", 6))
          { ldap_protocol_version = SSH_LDAP_VERSION_3; break; }
        errflg++; break;
          break;



































        case '?':
        default:
          errflg++; break;
        }
    }
  params.version = ldap_protocol_version;
  if (errflg || argc - ssh_optind < 2)
    {
      fprintf(stderr, "Usage: %s [-f [:x:]file_to_write_%%d_%%s_%%d]\n"
#ifdef DEBUG_LIGHT
              "  [-d debug_flags]\n"
#endif /* DEBUG_LIGHT */
              "  [-s server_name] [-p server_port]\n"





              "  [-v ldapv2|ldapv3] \n"
              "  [-u username] [-P password] [-O socks_url]\n"
              "  [-a attribute,attribute...]\n"
              "  [-D never | searching | base | always]\n"
              "  [-S base | single | subtree] base_dn search search ...\n",
              program);



      ssh_math_library_uninitialize();
      ssh_util_uninit();
      exit(1);
    }

  if (attributes)
    {
      char *p;

      number_of_attributes = 1;
      p = attributes;
      while ((p = strchr(p, ',')))
        {
          number_of_attributes++;
          p++;
        }

      attrs = ssh_xcalloc(number_of_attributes, sizeof(*attrs));
      attr_lens = ssh_xcalloc(number_of_attributes, sizeof(*attr_lens));

      p = attributes;
      i = 0;
      while ((p = strchr(attributes, ',')))
        {
          attrs[i] = ssh_xmemdup(attributes, p - attributes);
          attr_lens[i] = p - attributes;
          attributes = p + 1;
          i++;
        }
      attrs[i] = ssh_xstrdup(attributes);
      attr_lens[i] = strlen(attributes);
    }

  base_dn = argv[ssh_optind++];

#ifdef DEBUG_LIGHT
  ssh_debug_set_level_string(debug_string);
#endif /* DEBUG_LIGHT */
  ssh_event_loop_initialize();

  connect_ctx = ssh_xcalloc(sizeof(*connect_ctx), 1);
  connect_ctx->ldap_protocol_version = ldap_protocol_version;
  connect_ctx->bind_name = bind_name;
  connect_ctx->bind_name_len = ssh_ustrlen(bind_name);
  connect_ctx->password = password;
  connect_ctx->password_len = ssh_ustrlen(password);
  connect_ctx->search_ctx = &search_ctx;
  search_ctx.connect_ctx = connect_ctx; 





























































  client = ssh_ldap_client_create(&params);

  search_ctx.searchs = (unsigned char **)(argv + ssh_optind);
  search_ctx.cnt = argc - ssh_optind;
  search_ctx.current = 0;
  search_ctx.client = client;
  search_ctx.base_dn = base_dn;
  search_ctx.deref = deref;
  search_ctx.scope = scope;
  search_ctx.attrs = attrs;
  search_ctx.attr_lens = attr_lens;
  search_ctx.number_of_attributes = number_of_attributes;
  search_ctx.f = NULL;

  ssh_ldap_client_connect(client,
                          ldap_server_name, ldap_server_port,
                          ldap_connected, connect_ctx);
  ssh_event_loop_run();

  for (i = 0; i < number_of_attributes; i++) ssh_xfree(attrs[i]);
  ssh_xfree(attrs);
  ssh_xfree(attr_lens);

  ssh_ldap_client_destroy(client);



  ssh_math_library_uninitialize();
  ssh_name_server_uninit();
  ssh_event_loop_uninitialize();
  ssh_util_uninit();

  return 0;
}



























#else /* SSHDIST_APPS_LDAPUTILS */
int main(int argc, char **argv)
{
  ssh_fatal("%s: %s", argv[0], SSH_NOT_BUILT_DUE_TO_MISSING_DISTDEFS);
  return 0;
}
#endif /* SSHDIST_APPS_LDAPUTILS */
