/*
  File: t-ldapconv.c

  Authors:
        based on the code by Tero Kivinen <kivinen@iki.fi>

  Description:
        Interactive test program for LDAP convenience API.

  Copyright:
          Copyright (c) 2002, 2003 SFNT Finland Oy.
  Copyright:
          Copyright (c) 2002, 2003 SFNT Finland Oy.
        All rights reserved.
*/

#include "sshincludes.h"
#include "sshldap.h"
#include "sshdebug.h"
#include "sshtimeouts.h"
#include "sshfileio.h"
#include "ssheloop.h"
#include "sshgetopt.h"
#include "sshnameserver.h"

#define SSH_DEBUG_MODULE "t-ldapconv"

typedef struct LdapSearchRec {
  char *filename;
  int cnt;
} *LdapSearch;

int result_object_count = 0;

static void
ldap_result_cb(SshLdapClient client,
               SshLdapResult result,
               const SshLdapResultInfo info,
               void *callback_context)
{
  if (result == SSH_LDAP_RESULT_SUCCESS &&
      (info->matched_dn == NULL || !info->matched_dn[0]) &&
      (info->error_message == NULL || !info->error_message[0]))
    ssh_warning("result = success, number-of-objects=%d", result_object_count);
  else
    ssh_warning("result = %s(%d), matched = %s, error = %s",
                ssh_find_keyword_name(ssh_ldap_error_keywords, result),
                result,
                (info->matched_dn ? (char *)info->matched_dn : "not returned"),
                (info->error_message ? (char *)info->error_message :
                 "not returned"));
}

static void
ldap_object_cb(SshLdapClient client,
               SshLdapObject object,
               void *callback_context)
{
  int i, j, k, l;
  LdapSearch search = callback_context;
  char buffer[255];

  SSH_DEBUG(SSH_D_HIGHOK,
            ("object %s, # of attributes = %d",
             object->object_name, object->number_of_attributes));

  result_object_count += 1;

  if (search->filename && strcmp(search->filename, "-"))
    {
      ssh_snprintf(buffer, sizeof(buffer),
                   search->filename,
                   search->cnt, "obj", 0);
      ssh_write_gen_file(buffer,
                         SSH_PEM_GENERIC,
                         object->object_name, object->object_name_len);
    }

  for (i = 0; i < object->number_of_attributes; i++)
    {
      SSH_DEBUG(5,
                (" attribute[%d] = %s, values = %d", i,
                 object->attributes[i].attribute_type,
                 object->attributes[i].number_of_values));
      for (j = 0; j < object->attributes[i].number_of_values; j++)
        {
          if (search->filename)
            {
              ssh_snprintf(buffer, sizeof(buffer),
                           search->filename,
                           search->cnt,
                           object->attributes[i].attribute_type, j);
              ssh_write_gen_file(buffer,
                                 SSH_PEM_GENERIC,
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
                  SSH_DEBUG(6, ("Value[%d] = %s",
                                j, object->attributes[i].values[j]));
                }
              else
                {
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
                                         object->attributes[i].values[j][k + l]
                                         & 0xff);
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
                              if (isprint(object->
                                          attributes[i].
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
  search->cnt += 1;
  ssh_ldap_free_object(object);
}

const SshKeywordStruct deref_keywords[] = {
  { "never", SSH_LDAP_DEREF_ALIASES_NEVER },
  { "searching", SSH_LDAP_DEREF_ALIASES_IN_SEARCHING },
  { "base", SSH_LDAP_DEREF_ALIASES_FINDING_BASE_OBJECT },
  { "always", SSH_LDAP_DEREF_ALIASES_ALWAYS },
  { NULL, 0 }
};

#define D(x) ssh_warning((x))

void usage(int code)
{
  D("usage: t-ldapconv [options] ldap-url");
  D("where options are:");
  D("\t -h\t\t displays this help text.");
  D("\t -f string\t file to write resulting objects.");
  D("\t -d string\t sets debug strings for the application.");
  D("\t -S URL\t\t sets SOCKSv4 server to access the LDAP directory.");
  D("\t -V number\t sets LDAP protocol version. Either 2 or 3.");
  D("\t -D string\t alias dereferencing; never|search|base|always.");

  D("and LDAP-URL syntax is:");
  D("\t ldap://[<name>:<password>@]server[:port]/<object>");
  D("\t <object> = <base-dn>[?<attributes>[?<scope>?<filter>]]");

  D("for example:");
  D("\t ldap://CN=admin:a6m1n@server.ssh.com/DC=COM??sub?(objectclass=*)");

  if (code > -1)
    exit(code);
}
#undef D

int main(int ac, char **av)
{
  int deref = SSH_LDAP_DEREF_ALIASES_NEVER, c;
  char *debug = NULL, *prefix = "";
  SshLdapClientParamsStruct params;
  LdapSearch search;

  memset(&params, 0, sizeof(params));
  params.version = SSH_LDAP_VERSION_2;




  while ((c = ssh_getopt(ac, av, "f:hd:V:S:D:", NULL)) != EOF)
    {
      switch (c)
        {
        case 'h': usage(0); break;
        case 'd': debug = ssh_optarg; break;
        case 'V': params.version = atoi(ssh_optarg); break;
        case 'S': params.socks = ssh_optarg; break;
        case 'D':
          if ((deref = ssh_find_keyword_number(deref_keywords, ssh_optarg))
              == -1)
            usage(3);
          break;
        case 'f': prefix = ssh_optarg; break;
        case '?': usage(1); break;
        }
    }

  ac -= ssh_optind;
  av += ssh_optind;

  if (ac < 1)
    usage(2);

  ssh_event_loop_initialize();

  search = ssh_xcalloc(1, sizeof(*search));
  search->cnt = 0;
  search->filename = prefix;

  if (debug)
    ssh_debug_set_level_string(debug);

  ssh_ldap_search_url(&params,
                      av[0],
                      ldap_object_cb, search,
                      ldap_result_cb, search);

  ssh_event_loop_run();
  ssh_name_server_uninit();
  ssh_event_loop_uninitialize();
  ssh_free(search);

  ssh_util_uninit();
  return 0;
}
