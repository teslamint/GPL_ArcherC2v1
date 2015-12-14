/*
 *  t-fb-util.c
 *
 *  Copyright:
 *          Copyright (c) 2005 SFNT Finland Oy.
 *
 *
 * Test program for converison routines between IKE1 and IKEv2 payloads.
 */

#include "sshincludes.h"
#include "sshregression.h"
#ifdef SSHDIST_RADIUS
#include "sshradius.h"
#endif /* SSHDIST_RADIUS */
#ifdef SSHDIST_EAP
#include "ssheap.h"
#endif /* SSHDIST_EAP */

#ifdef SSHDIST_IKEV1

#include "sshikev2-initiator.h"
#include "sshikev2-exchange.h"
#include "sshikev2-util.h"
#include "sshikev2-fallback.h"
#include "ikev2-fb.h"

#include "dummy-if.h"

SshIkev2PayloadTS tsi_local, tsi_remote;

#define SSH_DEBUG_MODULE "t-fb-util"

struct {
  Boolean must_succeed;
  char *v1str;
  char *v1res;
} id_2_ts[] =
  {
    { TRUE,
      "ipv4(192.168.1.1)",
      "ipv4_range(any:0,[0..7]=192.168.1.1-192.168.1.1)" },
    { TRUE,
      "ipv4(any,192.168.1.1)",
      "ipv4_range(any:0,[0..7]=192.168.1.1-192.168.1.1)" },
    { TRUE,
      "ipv4(tcp:17,192.168.1.1)",
      "ipv4_range(tcp:17,[0..7]=192.168.1.1-192.168.1.1)" },
    { TRUE,
      "ipv4_subnet(192.168.1.0/24)",
      "ipv4_range(any:0,[0..7]=192.168.1.0-192.168.1.255)" },
    { TRUE,
      "ipv4_subnet(any:100,192.168.1.0/24)",
      "ipv4_range(any:100,[0..7]=192.168.1.0-192.168.1.255)" },
    { TRUE,
      "ipv4_subnet(udp:53,192.168.1.0/24)",
      "ipv4_range(udp:53,[0..7]=192.168.1.0-192.168.1.255)" },
    { TRUE,
      "ipv4_range(192.168.1.0-192.168.1.255)",
      "ipv4_range(any:0,[0..7]=192.168.1.0-192.168.1.255)" },
    { TRUE,
      "ipv4_range(any:0,192.168.1.0-192.168.1.255)",
      "ipv4_range(any:0,[0..7]=192.168.1.0-192.168.1.255)" },
    { TRUE,
      "ipv4_range(hopopt:0,192.168.1.0-192.168.1.255)",
      "ipv4_range(any:0,[0..7]=192.168.1.0-192.168.1.255)" },
    { TRUE,
      "ipv6(::1)",
      "ipv6_range(any:0,[0..31]=::1-::1)" },
    { TRUE,
      "ipv6(fe80::211:43ff:fe43:9279)",
      "ipv6_range(any:0,[0..31]="
      "fe80::211:43ff:fe43:9279-fe80::211:43ff:fe43:9279)" },
    { TRUE,
      "ipv6(icmp:2048,fe80::211:43ff:fe43:9279)",
      "ipv6_range(icmp:2048,[0..31]="
      "fe80::211:43ff:fe43:9279-fe80::211:43ff:fe43:9279)" },
    { TRUE,
      "ipv6_subnet(fe80::211:43ff:fe43:9270/125)",
      "ipv6_range(any:0,[0..31]="
      "fe80::211:43ff:fe43:9270-fe80::211:43ff:fe43:9277)" },
    { TRUE,
      "ipv6_range(any,::1-::6)",
      "ipv6_range(any:0,[0..31]=::1-::6)" },


    { FALSE, "fqdn(klinkkeri)", NULL },
    { FALSE, "usr@fqdn(klinkkeri)", NULL },
    { FALSE, "key_id(ffffff)", NULL },
#ifdef SSHDIST_IKE_CERT_AUTH
    { FALSE, "der_asn1_dn(C=FI,O=SFNT,CN=Sika Pantteri)", NULL },
#endif /* SSHDIST_IKE_CERT_AUTH */
  };

static Boolean test_id_to_ts(SshSADHandle sad)
{
  int i;
  SshIkev2PayloadTS ts;
  SshIkePayloadID id;
  char buffer[128];

  for (i = 0; i < sizeof(id_2_ts)/sizeof(id_2_ts[0]); i++)
    {
      if ((id = ssh_ike_string_to_id(id_2_ts[i].v1str)) == NULL)
	{
	  ssh_warning("test material incorrect: %s", id_2_ts[i].v1str);
	  return FALSE;
	}

      ts = ikev2_fb_tsv1_to_tsv2(sad, id);

      ssh_ike_id_free(id);
      if (ts == NULL)
	{
	  if (id_2_ts[i].must_succeed)
	    {
	      ssh_warning("v1ts->v2ts failed for: %s", id_2_ts[i].v1str);
	      ssh_ikev2_ts_free(sad, ts);
	      return FALSE;
	    }
	  else
	    {
	      continue;
	    }
	}

      id = ikev2_fb_tsv2_to_tsv1(ts);

      if (id == NULL)
	{
	  ssh_warning("v2ts->v1ts failed for: %s / %@",
		      id_2_ts[i].v1str,
		      ssh_ikev2_payload_ts_render, ts);
	  ssh_ikev2_ts_free(sad, ts);
	  return FALSE;
	}

      ssh_ikev2_ts_free(sad, ts);

      if (strcmp(ssh_ike_id_to_string(buffer, sizeof(buffer), id),
		 id_2_ts[i].v1res))
	{
	  ssh_warning("{%s, \n \"%s\", \n \"%@\" },",
		      id_2_ts[i].must_succeed ? "TRUE" : "FALSE",
		      id_2_ts[i].v1str,
		      ssh_ike_id_render, id);

	  ssh_warning("v2ts->v1ts failed for: %s", id_2_ts[i].v1str);
	}

      ssh_ike_id_free(id);
    }

  return TRUE;
}

int main (int ac, char **av)
{
  SshSADHandle sad;

  ssh_regression_init(&ac, &av,
		      "IKEv2 fallback to IKEv1 - utility regression test",
		      "ipsec-support@safenet-inc.com");


  sad = ssh_xcalloc(1, sizeof(sad));

  ssh_ikev2_ts_freelist_create(sad);

  ssh_regression_section("Traffic Selectors");
  SSH_REGRESSION_TEST("Ikev2 TS to Ikev1 ID", test_id_to_ts, (sad));
  ssh_regression_section("Identities");

  ssh_ikev2_ts_freelist_destroy(sad);
  ssh_xfree(sad);

  ssh_regression_finish();

  SSH_NOTREACHED;
  return 0;
}

#endif /* SSHDIST_IKEV1 */
