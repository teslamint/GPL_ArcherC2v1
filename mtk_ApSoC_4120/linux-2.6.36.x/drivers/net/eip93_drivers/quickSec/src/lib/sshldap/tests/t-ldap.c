/*
 *
 * Author: Tero Kivinen <kivinen@iki.fi>
 *
*  Copyright:
*          Copyright (c) 2002, 2003 SFNT Finland Oy.
 */
/*
 *        Program: sshldap
 *
 *        Creation          : 19:02 Jul 31 1998 kivinen
 *        Last Modification : 16:24 Apr 27 2004 kivinen
 *        Version           : 1.355
 *        
 *
 *        Description       : Ldap test module. This test program assumes
 *                            that ether is a ldap server running in the
 *                            ryijy.hel.internal port 389 (can be changed by
 *                            command line options) and that server serves
 *                            objects that match "o=Example, c=FI".
 *                            For modifications the base dn "cn=root,
 *                            o=Example, c=FI" and password
 *                            "kukkuuRESET" are used unless specified otherwise
 *                            in the command line.
 */

#include "sshincludes.h"
#include "sshldap.h"
#include "sshtimeouts.h"
#include "ssheloop.h"
#include "sshgetopt.h"
#include "sshnameserver.h"

#define SSH_DEBUG_MODULE "SshLdapTest"

/* Program name */
char *program;
char *ldap_server_name = "ryijy.hel.internal", *ldap_server_port = "389";
char *bind_name, *password;
size_t bind_name_len, password_len;

static void do_search_test(void *context);
static void do_test(void *context);

static void
ldap_result_cb(SshLdapClient ctx,
               SshLdapResult result,
               const SshLdapResultInfo info,
               void *callback_context)
{
  unsigned char *str;
  SshLdapSearchFilter filter = (SshLdapSearchFilter) callback_context;

  str = NULL;
  if (filter)
    {
      ssh_ldap_filter_to_string(filter, &str, NULL);
      ssh_ldap_free_filter(filter);
    }

  if (result == SSH_LDAP_RESULT_SUCCESS &&
      info->matched_dn == NULL && info->error_message == NULL)
    SSH_DEBUG(4, ("Result callback called, result = success%s%s",
                  (str != NULL ? " : " : ""),
                  (str != NULL ? (char *)str : "")));
  else
    SSH_DEBUG(4, ("Result callback called, "
                  "result = %s (%d), matched = %s, error = %s%s%s",
          ssh_find_keyword_name(ssh_ldap_error_keywords, result),
          result,
          (info->matched_dn ? (char *)info->matched_dn : "not returned"),
          (info->error_message ? (char *)info->error_message : "not returned"),
          (str != NULL ? " : " : ""),
          (str != NULL ? (char *)str : "")));
  if (result != 0 && result != SSH_LDAP_RESULT_ABORTED)
    ssh_fatal("Operation failed");

  ssh_xfree(str);
  return;
}


static void
ldap_object_cb(SshLdapClient ctx,
               SshLdapObject object,
               void *callback_context)
{
  int i, j, k;
  unsigned char *str;
  SshLdapSearchFilter filter = callback_context;

  if (filter)
    {
      ssh_ldap_filter_to_string(filter, &str, NULL);
      SSH_DEBUG(4, ("Search %s", str));
      ssh_xfree(str);
    }

  SSH_DEBUG(4, ("Item %s, attributes = %d",
                object->object_name, object->number_of_attributes));
  for (i = 0; i < object->number_of_attributes; i++)
    {
      SSH_DEBUG(5, ("Attribute[%d] = %s, values = %d", i,
                    object->attributes[i].attribute_type,
                    object->attributes[i].number_of_values));
      for (j = 0; j < object->attributes[i].number_of_values; j++)
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
              SSH_DEBUG_HEXDUMP(6, ("Value[%d] = ", j),
                                (unsigned char *)
                                object->attributes[i].values[j],
                                object->attributes[i].value_lens[j]);
            }
        }
    }
  ssh_ldap_free_object(object);
}



char *ldap_search_text_strings[] = {
  /* From the rfc 1960 */
  "(cn=Babs Jensen)",
  "(!(cn=Tim Howes))",
  "(&(objectClass=Person)(|(sn=Jensen)(cn=Babs J*)))",
  "(o=univ*of*mich*)",

  /* Our test cases */

  /* And */
  "(&(abba=baab))",
  "(&(abba=baab)(cdde=dcce))",
  "(&(abba=baab)(cdde=dcce)(cdde=dcce)(cdde=dcce)(cdde=dcce)(cdde=dcce))",

  /* Or */
  "(|(abba=baab))",
  "(|(abba=baab)(cdde=dcce))",
  "(|(abba=baab)(cdde=dcce)(cdde=dcce)(cdde=dcce)(cdde=dcce)(cdde=dcce))",

  /* Not */
  "(!(abba=baab))",

  /* Equal */
  "(abba=baab)",
  "(abba=ba ab)",
  "(abba=ba ab \\(\\))",
  "(abba=\\(\\)ba ab \\(\\))",
  "(abba=x\\(\\)ba ab \\(\\)x)",
  "(abba=\\*x\\(\\)ba \\*ab \\(\\)x\\*)",
  "(abba=\\\\\\*x\\(\\)ba\\\\ \\*ab\\\\ \\(\\)x\\*\\\\)",

  /* Approx */
  "(abba~=baab)",
  "(abba~=ba ab)",
  "(abba~=ba ab \\(\\))",
  "(abba~=\\(\\)ba ab \\(\\))",
  "(abba~=x\\(\\)ba ab \\(\\)x)",
  "(abba~=\\*x\\(\\)ba \\*ab \\(\\)x\\*)",
  "(abba~=\\\\\\*x\\(\\)ba\\\\ \\*ab\\\\ \\(\\)x\\*\\\\)",

  /* Greater or equal */
  "(abba>=baab)",
  "(abba>=ba ab)",
  "(abba>=ba ab \\(\\))",
  "(abba>=\\(\\)ba ab \\(\\))",
  "(abba>=x\\(\\)ba ab \\(\\)x)",
  "(abba>=\\*x\\(\\)ba \\*ab \\(\\)x\\*)",
  "(abba>=\\\\\\*x\\(\\)ba\\\\ \\*ab\\\\ \\(\\)x\\*\\\\)",

  /* Less or equal */
  "(abba<=baab)",
  "(abba<=ba ab)",
  "(abba<=ba ab \\(\\))",
  "(abba<=\\(\\)ba ab \\(\\))",
  "(abba<=x\\(\\)ba ab \\(\\)x)",
  "(abba<=\\*x\\(\\)ba \\*ab \\(\\)x\\*)",
  "(abba<=\\\\\\*x\\(\\)ba\\\\ \\*ab\\\\ \\(\\)x\\*\\\\)",

  /* Present */
  "(abba=*)",

  /* Substring */
  "(abba=baab*)",
  "(abba=*baab)",
  "(abba=ba*ab)",
  "(abba=*ba*ab)",
  "(abba=ba*ab*)",
  "(abba=*ba*ab*)",
  "(abba=ba ab*)",
  "(abba=ba* ab \\(\\))",
  "(abba=*ba ab \\(\\))",
  "(abba=ba ab \\(\\)*)",
  "(abba=*ba ab \\(\\)*)",
  "(abba=*ba *ab \\(\\)*)",
  "(abba=*\\(\\)ba ab \\(\\))",
  "(abba=\\(\\)ba *ab \\(\\))",
  "(abba=\\(\\)ba ab \\(\\)*)",
  "(abba=*\\(\\)ba* ab \\(\\))",
  "(abba=*\\(\\)ba* ab* \\(\\))",
  "(abba=\\(\\)ba* ab* \\(\\)*)",
  "(abba=\\(\\)ba ab* \\(\\)*)",
  "(abba=*\\(\\)ba ab* \\(\\)*)",
  "(abba=*\\(\\)ba* ab* \\(\\)*)",
  "(abba=x\\(\\)ba* ab \\(\\)x)",
  "(abba=*\\*x\\(\\)ba \\*ab \\(\\)x\\*)",
  "(abba=\\*x\\(\\)ba* \\*ab \\(\\)x\\*)",
  "(abba=*\\*x\\(\\)ba* \\*ab \\(\\)x\\*)",
  "(abba=\\*x\\(\\)ba* \\*ab* \\(\\)x\\*)",
  "(abba=*\\*x\\(\\)ba* \\*ab* \\(\\)x\\*)",
  "(abba=\\*x\\(\\)ba \\*ab \\(\\)x\\**)",
  "(abba=\\*x\\(\\)ba* \\*ab \\(\\)x\\**)",
  "(abba=\\*x\\(\\)ba* \\*ab* \\(\\)x\\**)",
  "(abba=*\\*x\\(\\)ba \\*ab \\(\\)x\\**)",
  "(abba=*\\*x\\(\\)ba* \\*ab \\(\\)x\\**)",
  "(abba=*\\*x\\(\\)ba* \\*ab* \\(\\)x\\**)",
  "(abba=*\\\\\\*x\\(\\)ba\\\\ \\*ab\\\\ \\(\\)x\\*\\\\)",
  "(abba=\\\\\\*x\\(\\)ba*\\\\ \\*ab\\\\ \\(\\)x\\*\\\\)",
  "(abba=*\\\\\\*x\\(\\)ba*\\\\ \\*ab\\\\ \\(\\)x\\*\\\\)",
  "(abba=*\\\\\\*x\\(\\)ba*\\\\ \\*ab*\\\\ \\(\\)x\\*\\\\)",
  "(abba=\\\\\\*x\\(\\)ba\\\\ \\*ab\\\\ \\(\\)x\\*\\\\*)",
  "(abba=*\\\\\\*x\\(\\)ba\\\\ \\*ab\\\\ \\(\\)x\\*\\\\*)",
  "(abba=*\\\\\\*x\\(\\)ba*\\\\ \\*ab\\\\ \\(\\)x\\*\\\\*)",
  "(abba=*\\\\\\*x\\(\\)ba*\\\\ \\*ab*\\\\ \\(\\)x\\*\\\\*)",
  "(abba=\\\\\\*x\\(\\)ba*\\\\ \\*ab\\\\ \\(\\)x\\*\\\\*)",
  "(abba=\\\\\\*x\\(\\)ba*\\\\ \\*ab*\\\\ \\(\\)x\\*\\\\*)",
  "(abba=*x*b*b*b*b*b*b*b*b*b*b*b*b*b*b*b*b*b*b*)",
  "(abba=x*b*b*b*b*b*b*b*b*b*b*b*b*b*b*b*b*b*b*)",
  "(abba=*x*b*b*b*b*b*b*b*b*b*b*b*b*b*b*b*b*b*b)",
  "(abba=x*b*b*b*b*b*b*b*b*b*b*b*b*b*b*b*b*b*b)",
  NULL
};

char *successfull_searches[] = {
  "(objectclass=*)",
  "(sn=Kivinen)",
  "(sn<=Kivinen)",
  "(sn>=Kivinen)",
  "(sn~=kivinen)",
  "(sn=k*v*n*n)",
  "(|(sn=Kivinen)(sn=Ylonen))",
  "(&(sn=Kivinen)(mail=kivinen*))",
  "(!(objectclass=person))",
  NULL
};

typedef struct TestContextRec {
  SshLdapClient client;
  int test_number;
  char *test_name;
  int test_set;
  SshLdapResult can_fail_with_this;
  SshLdapSearchFilter f;
} *TestContext;

void do_test(void *context);

static void
ldap_disconnect(void *context)
{
  SshLdapClient ctx = context;

  SSH_DEBUG(5, ("Calling disconnect"));
  ssh_ldap_client_disconnect(ctx);
}

static void
ldap_result_test(SshLdapClient ctx,
                 SshLdapResult result,
                 const SshLdapResultInfo info,
                 void *callback_context)
{
  const char *str;
  TestContext test_context = callback_context;

  str = test_context->test_name;

  if (result == SSH_LDAP_RESULT_ABORTED)
    return;

  if (result == SSH_LDAP_RESULT_SUCCESS &&
      info->matched_dn == NULL && info->error_message == NULL)
    SSH_DEBUG(4, ("Result callback called, result = success, operation = %s",
                  str));
  else
    SSH_DEBUG(4, ("Result callback called, result = %s (%d), "
                  "matched = %s, "
                  "error = %s, "
                  "operation = %s",
        ssh_find_keyword_name(ssh_ldap_error_keywords, result), result,
        (info->matched_dn ? (char *)info->matched_dn : "not returned"),
        (info->error_message ? (char *)info->error_message : "not returned"),
        str));
  if (result != 0)
    {
      if (test_context->can_fail_with_this == result)
        SSH_DEBUG(4, ("Failed with expected error code, thats ok"));
      else
        ssh_fatal("Operation failed");
    }
  if (test_context->f)
    {
      ssh_ldap_free_filter(test_context->f);
      test_context->f = NULL;
    }

  if (test_context->test_set == 0)
    do_test(test_context);
  if (test_context->test_set == 1)
    do_search_test(test_context);
  return;
}

static void
do_test_start(SshLdapClient client,
              SshLdapResult result,
              const SshLdapResultInfo info,
              void *callback_context)
{
  if (result == SSH_LDAP_RESULT_SUCCESS)
    do_test(callback_context);
}

void do_test(void *context)
{
  TestContext test_context = context;
  SshLdapClient client = test_context->client;
  SshLdapObject object;
  SshLdapModifyOperation *operations;
  SshLdapAttribute attributes;
  SshLdapAttributeValueAssertion ava;
  SshLdapSearchFilter f;
  int i;

  switch (test_context->test_number++)
    {
    case 0:
      /* Delete Koe Erkki, in case it exists from the previous runs */
      test_context->test_name = "Delete Koe Erkki";
      test_context->can_fail_with_this = SSH_LDAP_RESULT_NO_SUCH_OBJECT;
      ssh_ldap_client_delete(client,
                             "cn=Koe Erkki, ou=Test, "
                             "o=Example, c=FI",
                             strlen("cn=Koe Erkki, ou=Test, "
                                    "o=Example, c=FI"),
                             ldap_result_test, test_context);
      break;

    case 1:
      /* Delete Koe ErkkiPetteri, in case it exists from the previous runs */
      test_context->test_name = "Delete Koe ErkkiPetteri";
      test_context->can_fail_with_this = SSH_LDAP_RESULT_NO_SUCH_OBJECT;
      ssh_ldap_client_delete(client,
                             "cn=Koe ErkkiPetteri, ou=Test, "
                             "o=Exampl, c=FI",
                             strlen("cn=Koe ErkkiPetteri, ou=Test, "
                                    "o=Example, c=FI"),
                             ldap_result_test, test_context);
      break;

    case 3:
      /* Add test organization */
      object = ssh_xcalloc(1, sizeof(*object));
      test_context->can_fail_with_this = SSH_LDAP_RESULT_ENTRY_ALREADY_EXISTS;
      object->object_name =
        ssh_xstrdup("ou=Test, o=Example, c=FI");
      object->object_name_len = strlen(object->object_name);
      object->number_of_attributes = 2;
      object->attributes = ssh_xcalloc(2, sizeof(*object->attributes));
      for (i = 0; i < 2; i++)
        {
          static const char *type[] = { "ou", "objectclass" };
          static const char *values[] = { "Test", "organizationalUnit" };

          object->attributes[i].attribute_type = ssh_xstrdup(type[i]);
          object->attributes[i].attribute_type_len =
            strlen(object->attributes[i].attribute_type);
          object->attributes[i].number_of_values = 1;
          object->attributes[i].values =
            ssh_xcalloc(1, sizeof(*object->attributes[i].values));
          object->attributes[i].value_lens =
            ssh_xcalloc(1, sizeof(*object->attributes[i].value_lens));
          object->attributes[i].values[0] = ssh_xstrdup(values[i]);
          object->attributes[i].value_lens[0] =
            strlen(object->attributes[i].values[0]);
        }
      test_context->test_name = "Add Test organization";
      ssh_ldap_client_add(client, object, ldap_result_test, test_context);
      ssh_ldap_free_object(object);
      break;

    case 4:
      /* Add Koe Erkki */
      object = ssh_xcalloc(1, sizeof(*object));
      test_context->can_fail_with_this = SSH_LDAP_RESULT_SUCCESS;
      object->object_name =
        ssh_xstrdup("cn=Koe Erkki, ou=Test, o=Example, "
                    "c=FI");
      object->object_name_len = strlen(object->object_name);
      object->number_of_attributes = 4;
      object->attributes = ssh_xcalloc(4, sizeof(*object->attributes));
      for (i = 0; i < 4; i++)
        {
          static const char *type[] = {   "cn",        "sn",    "mail",
                                          "objectclass" };
          static const char *values[] = { "Koe Erkki", "Erkki", "erkki@ssh.fi",
                                          "person" };

          object->attributes[i].attribute_type = ssh_xstrdup(type[i]);
          object->attributes[i].attribute_type_len =
            strlen(object->attributes[i].attribute_type);
          object->attributes[i].number_of_values = 1;
          object->attributes[i].values =
            ssh_xcalloc(1, sizeof(*object->attributes[i].values));
          object->attributes[i].value_lens =
            ssh_xcalloc(1, sizeof(*object->attributes[i].value_lens));
          object->attributes[i].values[0] = ssh_xstrdup(values[i]);
          object->attributes[i].value_lens[0] =
            strlen(object->attributes[i].values[0]);
        }
      test_context->test_name = "Add Koe Erkki";
      ssh_ldap_client_add(client, object, ldap_result_test, test_context);
      ssh_ldap_free_object(object);
      break;

    case 5:
      /* Modify it (change name) */
      test_context->can_fail_with_this = SSH_LDAP_RESULT_SUCCESS;
      operations = ssh_xcalloc(3, sizeof(*operations));
      attributes = ssh_xcalloc(3, sizeof(*attributes));

      operations[0] = SSH_LDAP_MODIFY_ADD;
      attributes[0].attribute_type = "sn";
      attributes[0].attribute_type_len = strlen(attributes[0].attribute_type);
      attributes[0].number_of_values = 1;
      attributes[0].values = ssh_xcalloc(1, sizeof(*attributes[0].values));
      attributes[0].value_lens =
        ssh_xcalloc(1, sizeof(*attributes[0].value_lens));
      attributes[0].values[0] = "ErkkiPetteri";
      attributes[0].value_lens[0] = strlen(attributes[0].values[0]);

      operations[1] = SSH_LDAP_MODIFY_DELETE;
      attributes[1].attribute_type = "mail";
      attributes[1].attribute_type_len = strlen(attributes[1].attribute_type);
      attributes[1].number_of_values = 0;
      attributes[1].values = NULL;
      attributes[1].value_lens = NULL;

      operations[2] = SSH_LDAP_MODIFY_ADD;
      attributes[2].attribute_type = "cn";
      attributes[2].attribute_type_len = strlen(attributes[2].attribute_type);
      attributes[2].number_of_values = 1;
      attributes[2].values = ssh_xcalloc(1, sizeof(*attributes[2].values));
      attributes[2].value_lens =
        ssh_xcalloc(1, sizeof(*attributes[2].value_lens));
      attributes[2].values[0] = "Koe ErkkiPetteri";
      attributes[2].value_lens[0] = strlen(attributes[2].values[0]);

      test_context->test_name = "Modify cn from Koe Erkki to Koe ErkkiPetteri";
      ssh_ldap_client_modify(client,
        "cn=Koe Erkki, ou=Test, o=Example, c=FI",
         strlen("cn=Koe Erkki, ou=Test, o=Example, c=FI"),
         3, operations, attributes, ldap_result_test, test_context);

      ssh_xfree(attributes[0].values);
      ssh_xfree(attributes[0].value_lens);
      ssh_xfree(attributes[2].values);
      ssh_xfree(attributes[2].value_lens);
      ssh_xfree(attributes);
      ssh_xfree(operations);
      break;

    case 6:
      /* Modify RDN test, move it to correct place */
      test_context->can_fail_with_this = SSH_LDAP_RESULT_SUCCESS;
      test_context->test_name =
        "Modify RDN from Koe Erkki to Koe ErkkiPetteri";
      ssh_ldap_client_modify_rdn(client,
        "cn=Koe Erkki, ou=Test, o=Example, c=FI",
        strlen("cn=Koe Erkki, ou=Test, o=Example, c=FI"),
        "cn=Koe ErkkiPetteri",
        strlen("cn=Koe ErkkiPetteri"),
        TRUE, ldap_result_test, test_context);
      break;

    case 7:
      /* Compare sn (should contain two values, both Erkki, and ErkkiPetteri */
      test_context->can_fail_with_this = SSH_LDAP_RESULT_COMPARE_TRUE;
      ava = ssh_xcalloc(1, sizeof(*ava));
      ava->attribute_type = "sn";
      ava->attribute_type_len = strlen(ava->attribute_type);
      ava->attribute_value = "ErkkiPetteri";
      ava->attribute_value_len = strlen(ava->attribute_value);
      test_context->test_name = "Compare sn to ErkkiPetteri";
      ssh_ldap_client_compare(client,
        "cn=Koe ErkkiPetteri, ou=Test, o=Example, c=FI",
        strlen("cn=Koe ErkkiPetteri, ou=Test, o=Example, "
               "c=FI"),
        ava, ldap_result_test, test_context);
      ssh_xfree(ava);
      break;

    case 8:
      /* Search all stuff in test organization */
      test_context->can_fail_with_this = SSH_LDAP_RESULT_SUCCESS;
      if (!ssh_ldap_string_to_filter("(objectclass=*)",
                                     strlen("(objectclass=*)"),
                                     &f))
        ssh_fatal("ssh_ldap_string_to_filter failed, string=(objectclass=*)");

      test_context->f = f;
      test_context->test_name = "First search with filter (objectclass=*)";
      ssh_ldap_client_search(client,
                             "ou=Test, o=Example, c=FI",
                             SSH_LDAP_SEARCH_SCOPE_WHOLE_SUBTREE,
                             SSH_LDAP_DEREF_ALIASES_NEVER, 0, 0,
                             FALSE, f,
                             0, NULL, NULL,
                             ldap_object_cb, f, ldap_result_test,
                             test_context);
      break;

    case 9:
      /* Delete Koe ErkkiPetteri */
      test_context->can_fail_with_this = SSH_LDAP_RESULT_SUCCESS;
      test_context->test_name = "Delete Koe ErkkiPetteri";
      ssh_ldap_client_delete(client,
                             "cn=Koe ErkkiPetteri, ou=Test, "
                             "o=Example, c=FI",
                             strlen("cn=Koe ErkkiPetteri, ou=Test, "
                                    "o=Example, c=FI"),
                             ldap_result_test, test_context);
      break;

    case 10:
      /* Redo the search */
      test_context->can_fail_with_this = SSH_LDAP_RESULT_SUCCESS;
      /* Search all stuff in test organization */
      if (!ssh_ldap_string_to_filter("(objectclass=*)",
                                     strlen("(objectclass=*)"),
                                     &f))
        ssh_fatal("ssh_ldap_string_to_filter failed, string=(objectclass=*)");

      test_context->f = f;
      test_context->test_name = "Second search with filter (objectclass=*)";
      ssh_ldap_client_search(client,
                             "ou=Test, o=Example, c=FI",
                             SSH_LDAP_SEARCH_SCOPE_WHOLE_SUBTREE,
                             SSH_LDAP_DEREF_ALIASES_NEVER, 0, 0,
                             FALSE, f,
                             0, NULL, NULL,
                             ldap_object_cb, f, ldap_result_test,
                             test_context);
      break;

    case 11:
      ldap_disconnect(client);
      break;

    default:
      do_test(test_context);
    }
}

static void do_search_test(void *context)
{
  TestContext test_context = context;
  SshLdapClient client = test_context->client;
  SshLdapSearchFilter f;
  unsigned char *attrs[2];
  size_t attr_lens[2];
  int i;

  switch (test_context->test_number++)
    {
    case 0:
      for (i = 0; successfull_searches[i] != NULL; i++)
        {
          test_context->f = NULL;
          test_context->can_fail_with_this = SSH_LDAP_RESULT_SUCCESS;
          test_context->test_name = "Search from should-succeed.";
          if (!ssh_ldap_string_to_filter(successfull_searches[i],
                                         strlen(successfull_searches[i]),
                                         &f))
            ssh_fatal("ssh_ldap_string_to_filter failed, string = %s",
                      successfull_searches[i]);

          if (successfull_searches[i+1] == NULL)
            ssh_ldap_client_search(client,
                                   "o=Example, c=FI",
                                   SSH_LDAP_SEARCH_SCOPE_WHOLE_SUBTREE,
                                   SSH_LDAP_DEREF_ALIASES_NEVER, 0, 0,
                                   FALSE, f,
                                   0, NULL, NULL,
                                   ldap_object_cb, NULL,
                                   ldap_result_test, test_context);
          else
            ssh_ldap_client_search(client,
                                   "o=Example, c=FI",
                                   SSH_LDAP_SEARCH_SCOPE_WHOLE_SUBTREE,
                                   SSH_LDAP_DEREF_ALIASES_NEVER, 0, 0,
                                   FALSE, f,
                                   0, NULL, NULL,
                                   ldap_object_cb, NULL, ldap_result_cb, NULL);
          ssh_ldap_free_filter(f);
        }
      break;

    case 1:
      if (!ssh_ldap_string_to_filter("(mail=*)", 8, &f))
        ssh_fatal("ssh_ldap_string_to_filter failed, string = (mail=*)");

      test_context->f = f;
      test_context->can_fail_with_this = SSH_LDAP_RESULT_SUCCESS;
      test_context->test_name = "Search 'mail' attribute from (mail=*) filter";
      attrs[0] = "mail";
      attr_lens[0] = strlen(attrs[0]);
      ssh_ldap_client_search(client, "o=Example, c=FI",
                             SSH_LDAP_SEARCH_SCOPE_WHOLE_SUBTREE,
                             SSH_LDAP_DEREF_ALIASES_NEVER, 0, 0,
                             FALSE, f,
                             1, attrs, attr_lens,
                             ldap_object_cb, f, ldap_result_test,
                             test_context);

      break;

    case 2:
      if (!ssh_ldap_string_to_filter("(mail=*)", 8, &f))
        ssh_fatal("ssh_ldap_string_to_filter failed, string = (mail=*)");

      test_context->f = f;
      test_context->can_fail_with_this = SSH_LDAP_RESULT_SUCCESS;
      test_context->test_name = "Search 'cn' attribute from (mail=*) filter";
      attrs[0] = "mail";
      attr_lens[0] = strlen(attrs[0]);
      attrs[1] = "cn";
      attr_lens[1] = strlen(attrs[1]);
      ssh_ldap_client_search(client, "o=Example, c=FI",
                             SSH_LDAP_SEARCH_SCOPE_WHOLE_SUBTREE,
                             SSH_LDAP_DEREF_ALIASES_NEVER, 0, 0,
                             FALSE, f,
                             2, attrs, attr_lens,
                             ldap_object_cb, f, ldap_result_test,
                             test_context);
      break;

    case 3:
      ldap_disconnect(client);
      break;
    }
}

static void
do_search_test_start(SshLdapClient client,
                     SshLdapResult result,
                     const SshLdapResultInfo info,
                     void *callback_context)
{
  if (result == SSH_LDAP_RESULT_SUCCESS)
    do_search_test(callback_context);
}

int main(int argc, char **argv)
{
  int c, errflg = 0;
  struct SshLdapClientParamsRec params;
  SshLdapClient client;
  const char *debug_string = "SshLdap*=6";
  SshLdapSearchFilter f;
  int i;
  TestContext test_context;

  memset(&params, 0, sizeof(params));
  params.socks = NULL;
  params.connection_attempts = 1;
  params.version = SSH_LDAP_VERSION_2;
  params.maxoperations = 128;
  params.request_timelimit = 120;
  params.response_sizelimit = 1024000;

  program = strrchr(argv[0], '/');
  if (program == NULL)
    program = argv[0];
  else
    program++;

  while ((c = ssh_getopt(argc, argv, "d:s:p:u:P:S:", NULL)) != EOF)
    {
      switch (c)
        {
        case 'd': debug_string = ssh_optarg; break;
        case 's': ldap_server_name = ssh_optarg; break;
        case 'p': ldap_server_port = ssh_optarg; break;
        case 'u':
          bind_name = ssh_optarg;
          bind_name_len = strlen(ssh_optarg);
          break;
        case 'P':
          password = ssh_optarg;
          password_len = strlen(ssh_optarg);
          break;
        case 'S': params.socks = ssh_optarg; break;
        case '?': errflg++; break;
        }
    }
  if (errflg || argc - ssh_optind != 0)
    {
      fprintf(stderr,
              "Usage: %s "
              "[-d debug_flags] "
              "[-s server_name] [-p server_port] [-S socks_url] "
              "[-u username] [-P password]\n",
              program);
      exit(1);
    }

  /* More complex test */
  if (bind_name == NULL)
    {
      bind_name = "cn=root, o=Example, c=FI";
      bind_name_len = strlen(bind_name);
    }

  if (password == NULL)
    {
      password = "kukkuuRESET";
      password_len = strlen(password);
    }

  ssh_debug_set_level_string(debug_string);
  ssh_event_loop_initialize();

  for (i = 0; ldap_search_text_strings[i] != NULL; i++)
    {
      unsigned char *string;
      size_t len;

      if (!ssh_ldap_string_to_filter(ldap_search_text_strings[i],
                                     strlen(ldap_search_text_strings[i]),
                                     &f))
        ssh_fatal("ssh_ldap_string_to_filter failed, string = %s",
                  ldap_search_text_strings[i]);
      if (!ssh_ldap_filter_to_string(f, &string, &len))
        ssh_fatal("ssh_ldap_filter_to_string failed, string = %s",
                  ldap_search_text_strings[i]);
      if (len != strlen(ldap_search_text_strings[i]) ||
          strcmp(ldap_search_text_strings[i], string) != 0)
        ssh_fatal("ssh_ldap_filter_to_string "
                  "string doesn't match the original string, "
                  "original = %s, returned = %s",
                  ldap_search_text_strings[i], string);
      ssh_ldap_free_filter(f);
      ssh_xfree(string);
    }

  client = ssh_ldap_client_create(&params);

  test_context = ssh_xcalloc(1, sizeof(*test_context));
  test_context->client = client;

  test_context->test_set = 0;
  test_context->test_number = 0;
  test_context->test_name = "Initialization";
  ssh_ldap_client_connect_and_bind(client,
                                   ldap_server_name, ldap_server_port,
                                   NULL_FNPTR,
                                   bind_name, strlen(bind_name),
                                   password, strlen(password),
                                   do_test_start, test_context);
  ssh_event_loop_run();
  test_context->test_set = 1;
  test_context->test_number = 0;
  test_context->test_name = "Initialization";
  ssh_ldap_client_connect_and_bind(client,
                                   ldap_server_name, ldap_server_port,
                                   NULL_FNPTR,
                                   bind_name, strlen(bind_name),
                                   password, strlen(password),
                                   do_search_test_start, test_context);
  ssh_event_loop_run();

  ssh_xfree(test_context);

  ssh_ldap_client_destroy(client);

  ssh_name_server_uninit();
  ssh_event_loop_uninitialize();

  ssh_util_uninit();
  return 0;
}
