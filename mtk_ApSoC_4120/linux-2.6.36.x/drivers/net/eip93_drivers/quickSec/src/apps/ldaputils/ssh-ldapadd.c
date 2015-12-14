/*
 *  Copyright:
 *          Copyright (c) 2002, 2003 SFNT Finland Oy.
 *  Program: LDAP modification client.
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

#define SSH_DEBUG_MODULE "SshLdapAdd"

typedef struct LdapAddOperationRec {
  Boolean doadd, dodelete;
  SshLdapObject object;
  unsigned char *baseobject;
  size_t baseobject_len;
  int retval;
} *LdapAddOperation;


static void
ldap_add_operation(SshLdapClient client,
                   SshLdapResult result,
                   const SshLdapResultInfo info,
                   void *callback_context);

/* Program name */
char *program;

void ldap_result(SshLdapClient client,
                 SshLdapResult result,
                 const SshLdapResultInfo info,
                 void *callback_context)
{
  LdapAddOperation operation = callback_context;

  operation->retval |= result;
  if (result == SSH_LDAP_RESULT_SUCCESS &&
      info->matched_dn == NULL && info->error_message == NULL)
    SSH_DEBUG(4, ("Result callback called, result = success"));
  else
    ssh_warning("Result callback called, "
                "result = %s (%d), matched = %s, error = %s",
                ssh_find_keyword_name(ssh_ldap_error_keywords, result),
                result,
                  (info->matched_dn ?
                   (char *)info->matched_dn : "not returned"),
                (info->error_message ?
                 (char *)info->error_message : "not returned"));

  ldap_add_operation(client, SSH_LDAP_RESULT_SUCCESS, info, operation);
}

static void
ldap_add_operation(SshLdapClient client,
                   SshLdapResult result,
                   const SshLdapResultInfo info,
                   void *callback_context)
{
  LdapAddOperation operation = callback_context;

  if (result == SSH_LDAP_RESULT_SUCCESS)
    {
      if (operation->dodelete)
        {
          operation->dodelete = FALSE;
          ssh_ldap_client_delete(client,
                                 operation->baseobject,
                                 operation->baseobject_len,
                                 ldap_result, operation);
          return;
        }

      if (operation->doadd)
        {
          operation->doadd = FALSE;
          ssh_ldap_client_add(client,
                              operation->object,
                              ldap_result, operation);
          return;
        }

      ssh_ldap_client_disconnect(client);
      ssh_name_server_uninit();
    }
  else
    {
      ssh_warning("Connect/Bind callback called, "
                  "result = %s (%d), matched = %s, error = %s",
                  ssh_find_keyword_name(ssh_ldap_error_keywords, result),
                  result,
                  (info->matched_dn ?
                   (char *)info->matched_dn : "not returned"),
                  (info->error_message ?
                   (char *)info->error_message : "not returned"));
      operation->retval |= result;
      ssh_ldap_client_disconnect(client);
      ssh_name_server_uninit();
      return;
    }
  if (operation->object)
    ssh_ldap_free_object(operation->object);
  operation->object = NULL;
  ssh_xfree(operation->baseobject);
  operation->baseobject = NULL;
}

int main(int argc, char **argv)
{
  int c, errflg = 0;
  struct SshLdapClientParamsRec params;
  SshLdapClient client;
#ifdef DEBUG_LIGHT
  const char *debug_string = "SshLdap*=6";
  const char *option_string = "rRb:d:s:p:u:P:S:";
#else
  const char *option_string = "rRb:s:p:u:P:S:";
#endif
  int i;
  char *base_dn;
  SshLdapObject o;
  Boolean do_remove, do_add;
  unsigned char *ldap_server_name = ssh_ustr("ldap");
  unsigned char *ldap_server_port = ssh_ustr("389");
  unsigned char *ldap_user_name = ssh_ustr(""), *ldap_user_pass = ssh_ustr("");
  int retval = 0;
  LdapAddOperation operation;

  memset(&params, 0, sizeof(params));
  params.socks = NULL;
  params.connection_attempts = 1;
  params.version = SSH_LDAP_VERSION_3;

  base_dn = "o=SSH Communications Security, c=FI";
  do_remove = FALSE;
  do_add = TRUE;

  program = strrchr(argv[0], '/');
  if (program == NULL)
    program = argv[0];
  else
    program++;

  while ((c = ssh_getopt(argc, argv, option_string, NULL)) != EOF)
    {
      switch (c)
        {
        case 'r': do_remove = TRUE; break;
        case 'R': do_remove = TRUE; do_add = FALSE; break;
        case 'b': base_dn = ssh_optarg; break;
#ifdef DEBUG_LIGHT
        case 'd': debug_string = ssh_optarg; break;
#endif /* DEBUG_LIGHT */
        case 's': ldap_server_name = (unsigned char*) ssh_optarg; break;
        case 'p': ldap_server_port = (unsigned char*) ssh_optarg; break;
        case 'u': ldap_user_name = (unsigned char*) ssh_optarg; break;
        case 'P': ldap_user_pass = (unsigned char*) ssh_optarg; break;
        case 'S': params.socks = (unsigned char*) ssh_optarg; break;
        case '?': errflg++; break;
        }
    }

  if (errflg)
    {
#ifdef DEBUG_LIGHT
      fprintf(stderr, "Usage: %s [-rR] [-b base_dn] [-d debug_flags] "\
              "[-s server_name] [-p server_port] [-u username] [-P password] "\
              "[-S socks_url] <attribute>=<value> ...\n",
              program);
      fprintf(stderr, "Usage: %s [-rR] [-b base_dn] [-d debug_flags] "\
              "[-s server_name] [-p server_port] [-u username] [-P password] "\
              "[-S socks_url] <attribute>=:[pbh]:<filename> ...\n",
              program);
#else
      fprintf(stderr, "Usage: %s [-rR] [-b base_dn] "\
              "[-s server_name] [-p server_port] [-u username] [-P password] "\
              "[-S socks_url] <attribute>=<value> ...\n",
              program);
      fprintf(stderr, "Usage: %s [-rR] [-b base_dn] "\
              "[-s server_name] [-p server_port] [-u username] [-P password] "\
              "[-S socks_url] <attribute>=:[pbh]:<filename> ...\n",
              program);
#endif /* DEBUG_LIGHT */
      exit(1);
    }

  ssh_math_library_initialize();
#ifdef DEBUG_LIGHT
  ssh_debug_set_level_string(debug_string);
#endif /* DEBUG_LIGHT */

  client = ssh_ldap_client_create(&params);

  operation = ssh_xcalloc(1, sizeof(*operation));

  if (do_remove)
    {
      operation->dodelete = TRUE;
      operation->baseobject = (unsigned char *)ssh_xstrdup(base_dn);
      operation->baseobject_len = strlen(base_dn);
    }

  if (do_add)
    {
      operation->doadd = TRUE;

      operation->object = o = ssh_xcalloc(1, sizeof(*o));
      o->object_name = ssh_xstrdup(base_dn);
      o->object_name_len = strlen(base_dn);
      o->number_of_attributes = 0;
      o->attributes = ssh_xcalloc(argc - ssh_optind, sizeof(*o->attributes));
      for (; ssh_optind < argc; ssh_optind++)
        {
          char *p, *attribute;
	  unsigned char *value;
          size_t value_len;

          p = strchr(argv[ssh_optind], '=');
          if (p == NULL)
            ssh_fatal("Invalid arguments, no = character found");

          attribute = ssh_xmemdup(argv[ssh_optind], p - argv[ssh_optind]);
          value = (unsigned char *)++p;
          if (*value == ':')
            {
              Boolean ret;

              ret = ssh_read_gen_file(p, &value, &value_len);
              if (!ret)
                ssh_fatal("Reading file %s failed", p);
            }
          else
            {
              value = (unsigned char *)ssh_xstrdup((char *)value);
              value_len = strlen((char *)value);
            }

          for (i = 0; i < o->number_of_attributes; i++)
            {
              if (memcmp(o->attributes[i].attribute_type,
                         attribute,
                         o->attributes[i].attribute_type_len) == 0)
                break;
            }

          if (i == o->number_of_attributes)
            {
              o->number_of_attributes++;
              o->attributes[i].attribute_type = (unsigned char *)attribute;
              o->attributes[i].attribute_type_len = strlen(attribute);
              o->attributes[i].number_of_values = 1;
              o->attributes[i].values =
                ssh_xcalloc(1, sizeof(*o->attributes[i].values));
              o->attributes[i].value_lens =
                ssh_xcalloc(1, sizeof(*o->attributes[i].value_lens));
            }
          else
            {
	      ssh_free(attribute);
              o->attributes[i].number_of_values++;
              o->attributes[i].values =
                ssh_xrealloc(o->attributes[i].values,
                             sizeof(*o->attributes[i].values) *
                             o->attributes[i].number_of_values);
              o->attributes[i].value_lens =
                ssh_xrealloc(o->attributes[i].value_lens,
                             sizeof(*o->attributes[i].value_lens) *
                             o->attributes[i].number_of_values);
            }
          o->attributes[i].values[o->attributes[i].number_of_values - 1] =
            value;
          o->attributes[i].value_lens[o->attributes[i].number_of_values - 1] =
            value_len;
        }
    }

  ssh_event_loop_initialize();

  ssh_ldap_client_connect_and_bind(client,
                                   ldap_server_name, ldap_server_port,
                                   NULL_FNPTR,
                                   ldap_user_name,
                                   ssh_ustrlen(ldap_user_name),
                                   ldap_user_pass,
                                   ssh_ustrlen(ldap_user_pass),
                                   ldap_add_operation, operation);

  ssh_event_loop_run();
  ssh_ldap_client_destroy(client);

  if (operation->baseobject)
    ssh_free(operation->baseobject);
  if (operation->object)
    {
      int j;

      if (operation->object->object_name)
	ssh_free(operation->object->object_name);
      for(i = 0; i < operation->object->number_of_attributes; i++)
	{
	  for(j = 0;
	      j < operation->object->attributes[i].number_of_values;
	      j++)
	    if (operation->object->attributes[i].values[j])
	      ssh_free(operation->object->attributes[i].values[j]);
	  if (operation->object->attributes[i].values)
	    ssh_free(operation->object->attributes[i].values);
	  if (operation->object->attributes[i].value_lens)
	    ssh_free(operation->object->attributes[i].value_lens);
	  if (operation->object->attributes[i].attribute_type)
	    ssh_free(operation->object->attributes[i].attribute_type);
	}
      if (operation->object->attributes)
	ssh_free(operation->object->attributes);
      if (operation->object)
	ssh_free(operation->object);
    }
  retval = operation->retval;
  ssh_xfree(operation);
  ssh_name_server_uninit();
  ssh_event_loop_uninitialize();
  ssh_math_library_uninitialize();
  ssh_util_uninit();
  return retval;
}
#else /* SSHDIST_APPS_LDAPUTILS */
int main(int argc, char **argv)
{
  ssh_fatal("%s: %s", argv[0], SSH_NOT_BUILT_DUE_TO_MISSING_DISTDEFS);
  return 0;
}
#endif /* SSHDIST_APPS_LDAPUTILS */
