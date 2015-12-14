/*
  File: t-ldapfilter.c

  Copyright:
        Copyright 2004 SFNT Finland Oy.
	All rights reserved.

  Description:

*/

#include "sshincludes.h"
#include "sshregression.h"
#include "sshldap.h"
#include "ldap-internal.h"
#include "sshasn1.h"

typedef struct TLdapFilterRec {
  char *input;
  Boolean decode_ok;
  Boolean encode_ok;
} *TLdapFilter, TLdapFilterStruct;

static struct TLdapFilterRec strtofilter[] = {
  { "(a=\\\\b)", TRUE, TRUE },
  { "(cn=Babs Jensen)", TRUE, TRUE },
  { "(!(cn=Tim Howes))", TRUE, TRUE },
  { "(&(objectClass=Person)(|(sn=Jensen)(cn=Babs J*)))", TRUE, TRUE },
  { "(o=univ*of*mich*ig*n)", TRUE, TRUE },
  { "(|(a=2)(a~=2)(a>=2)(a<=2)(a=*b))", TRUE, TRUE },
  { "(a=*)", TRUE, TRUE },
  { "", TRUE, TRUE },
  { "(!", FALSE, FALSE },
  { "a=b", TRUE, FALSE }
};

static Boolean test_strtofilter(void)
{
  int i;
  SshLdapSearchFilter filter;
  unsigned char *str;
  size_t str_len;
  SshAsn1Context asn1;
  SshAsn1Node node;
  Boolean rv;

  for (i = 0; i < sizeof(strtofilter)/sizeof(strtofilter[0]); i++)
    {
      rv = ssh_ldap_string_to_filter(strtofilter[i].input,
				     strlen(strtofilter[i].input),
				     &filter);

      if (!strtofilter[i].decode_ok)
	continue;

      if (!rv)
	return FALSE;

      if ((asn1 = ssh_asn1_init()) != NULL)
	{
	  node = ssh_ldap_create_filter(asn1, filter);
	  ssh_asn1_free(asn1);
	}

      if (!strtofilter[i].encode_ok)
	{
	  ssh_ldap_free_filter(filter);
	  continue;
	}

      if (!ssh_ldap_filter_to_string(filter, &str, &str_len))
	{
	  ssh_ldap_free_filter(filter);
	  return FALSE;
	}

      ssh_ldap_free_filter(filter);

      if (strcmp(str, strtofilter[i].input))
	{
	  ssh_free(str);
	  return FALSE;
	}
      ssh_free(str);
    }
  return TRUE;

}

int main(int ac, char **av)
{
  ssh_regression_init(&ac, &av,
		      "LDAP filter to string and back again conversions.",
		      "ipsec-support@safenet-inc.com");

  ssh_regression_section("Filter/String conversions");

  SSH_REGRESSION_TEST("String to Filter", test_strtofilter, ());

  ssh_regression_finish();
  return 0;
}
