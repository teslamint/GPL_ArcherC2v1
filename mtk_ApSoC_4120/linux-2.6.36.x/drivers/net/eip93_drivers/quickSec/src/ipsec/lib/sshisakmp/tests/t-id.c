
#include "sshincludes.h"
#include "isakmp.h"
#include "x509.h"
#include "sshdebug.h"
#include "sshdsprintf.h"

int opt_verbose = 0;

short test1(SshIkeIpsecIdentificationType in_type,
           SshIkeIpsecIPProtocolID in_proto,
           SshUInt16 in_port,
           const char *in_name1, const char *in_name2)
{
  SshIkePayloadID id, tmp;
  char printname[256], name1[128], name2[128];
  size_t nl1, nl2;
  SshIkeIpsecIPProtocolID proto;
  SshIkeIpsecIdentificationType type;
  SshUInt16 port;
  short ssh_result = TRUE;
  short ssh_success;

  id = ssh_xmalloc(sizeof(*id));
  if (!ssh_ike_id_encode(id, in_type, in_proto, in_port, 0, in_name1,
                         in_name2))
    {
      ssh_free(id);
      return FALSE;
    }
  ssh_ike_id_to_string(printname, sizeof(printname), id);

  /* tmp and id should compare same */
  tmp = ssh_ike_string_to_id(printname);
  ssh_ike_id_to_string(printname, sizeof(printname), tmp);
  if (opt_verbose)
    printf("%s\n", printname);

  if (!ssh_ike_id_compare(tmp, id))
    {
      printf("ERROR %s, id's should have compared same\n",
              printname);
      return FALSE;
    }

  ssh_ike_id_free(tmp);

  nl1 = sizeof(name1);
  nl2 = sizeof(name2);

  ssh_success = ssh_ike_id_decode(id, &type, &proto, &port, NULL,
                                 name1, &nl1, name2, &nl2);


  if (opt_verbose)
    printf("Name1 decode for '%s' => '%s'.\n", in_name1, name1);

  if (ssh_success == TRUE)
    {
      if (opt_verbose)
        printf("decode returned true. ");

      if (type !=  in_type)
        {
          printf("ERROR type decode failed for %d (result is %d)\n",
                 in_type, type);
          ssh_result = FALSE;
        }

      if (proto != in_proto)
        {
          printf("ERROR proto decode failed for %d (result is %d).\n",
                 in_proto, proto);
          ssh_result = FALSE;
        }

      if (port !=  in_port)
        {
          printf("ERROR port decode failed for %d (result is %d).\n",
                 in_port, port);
          ssh_result = FALSE;
        }

      if (strcmp(name1, in_name1))
        {
          printf("ERROR name1 decode failed for '%s' (result is '%s').\n",
                 in_name1, name1);
          ssh_result = FALSE;
        }
    }
  else
    {
      printf("ERROR Decode returned an error.\n");
      ssh_result = FALSE;
    }

  switch (in_type)
    {
    case IPSEC_ID_IPV4_ADDR_SUBNET:
    case IPSEC_ID_IPV6_ADDR_SUBNET:
    case IPSEC_ID_IPV4_ADDR_RANGE:
    case IPSEC_ID_IPV6_ADDR_RANGE:
      if (strcmp(name2, in_name2))
        {
          printf("ERROR name2 decode failed for '%s' (result is '%s').\n",
                 in_name2, name2);
          ssh_result = FALSE;
        }
      break;
    default:
      break;
    }
  ssh_ike_id_free(id);

  return ssh_result;
}

int do_compare(SshIkePayloadID id, char *pn, Boolean how, char *str)
{
  int failed;
  SshIkePayloadID reverse = ssh_ike_string_to_id(pn);

  failed = 0;
  if (id != NULL && ssh_ike_id_compare(reverse, id) != how)
    {
      failed++;
      printf("ERROR %s ", str);
    }
  else
    {
      if (opt_verbose)
        printf("OK %s ", str);
    }
  ssh_ike_id_free(reverse);
  return failed;
}

#define COMPARE(_id, _pn, _how, _s) failed += do_compare(_id, _pn, _how, _s)

int do_test(char *idstring, Boolean how)
{
  char printname[5000], *p = NULL;
  int failed = 0;
  SshIkePayloadID idx = ssh_ike_string_to_id(idstring);
  if (idx)
    {
      p = ssh_ike_id_to_string(printname, sizeof(printname), idx);
      COMPARE(idx, p, how, "id_to_string");
    }
  else
    {
      if (how)
        failed++;
    }
  if (idx)
    {
      char *ds;
      ssh_dsprintf(&ds, "%@", ssh_ike_id_render, idx);
      COMPARE(idx, ds, how, "id_render");
      ssh_free(ds);
    }
  if (failed || opt_verbose)
    printf("%-.100s (%d bytes) [%s]\n",
           idstring ? idstring : "(null)",
           idstring ? strlen(idstring) : 0,
           idx ? "correct" : "incorrect");
  ssh_ike_id_free(idx);
  return failed;
}

#define TEST(_idstring, _how) failed += do_test(_idstring, _how)

#define TEST2(_idstring, _namesize) \
  do { \
    char *_printname; \
    SshIkePayloadID _idx = ssh_ike_string_to_id(_idstring); \
    _printname = ssh_xmalloc(_namesize); \
    ssh_ike_id_to_string(_printname, _namesize, _idx); \
    ssh_ike_id_free(_idx); \
    if (strlen(_printname) > _namesize) \
       printf("ERROR %s -> %s: [incorrect] len %d\n", \
               _idstring, _printname, _namesize); \
    if (strlen(_idstring) > _namesize && strlen(_printname) != _namesize - 1) \
       printf("ERROR %s -> %s: [incorrect] len %d vs %d too short\n", \
               _idstring, _printname, strlen(_printname), _namesize); \
    if (strncmp(_idstring, _printname, _namesize - 1) != 0) \
       printf("ERROR %s '%-.*s' -> %s: [incorrect] " \
	      "compare len %d does not match\n", \
               _idstring, _namesize - 1, _idstring, _printname, _namesize); \
    ssh_xfree(_printname);\
  } while (0)

Boolean test2(void)
{
  int failed = FALSE;
  int i;

  for (i = 1; i < 128; i++)
    {
      TEST2("ipv4(tcp:12345,[0..3]=192.168.210.128)", i);
      TEST2("ipv4_range(tcp:12345,[0..7]=192.168.210.128-192.168.211.233)", i);
      TEST2("ipv4_subnet(tcp:12345,[0..7]=192.168.210.0/25)", i);
      TEST2("ipv6(tcp:12345,[0..15]=3ffe:501:ffff::33)", i);
      TEST2("ipv6_range(tcp:12345,[0..31]=3ffe:501:ffff::33"
            "-3ffe:501:ffff::ff)", i);
      TEST2("ipv6_subnet(tcp:12345,[0..31]=3ffe:501:ffff::33/64)", i);
      TEST2("fqdn(tcp:12345,[0..39]=veryveryveryveryveryvery.longish.host.fi)",
	    i);
      TEST2("usr@fqdn(tcp:12345,[0..39]="
	    "tmo@veryveryveryveryvery.longish.host.fi)",
	    i);
    }
  TEST("ipv4()", FALSE);
  TEST("ipv4(udp:500,)", FALSE);
  TEST("ipv4(,192.168.2.1)", TRUE);
  TEST("ipv4(udp,192.168.2.255)", TRUE);
  TEST("ipv4(192.168.2.1)", TRUE);
  TEST("ipv4(tcp:1234,192.168.2.1)", TRUE);
  TEST("ipv4(tcp:1234-5678,192.168.2.1)", TRUE);

  TEST("ipv4_subnet()", FALSE);
  TEST("ipv4_subnet(192.168.2.1)", FALSE);
  TEST("ipv4_subnet(192.168.2.0/)", TRUE);
  TEST("ipv4_subnet(192.168.2.0/24)", TRUE);
  TEST("ipv4_subnet(192.168.2.1-192.168.2.2)", FALSE);

  TEST("ipv4_range()", FALSE);
  TEST("ipv4_range(192.168.2.1)", FALSE);
  TEST("ipv4_range(192.168.2.1-)", FALSE); /* means till 0.0.0.0 */
  TEST("ipv4_range(192.168.2.1-192.168.3.1)", TRUE);
  TEST("ipv4_range(192.168.2.1/22)", FALSE);

  TEST("ipv6()", FALSE);
  TEST("ipv6(udp:500,)", FALSE);
  TEST("ipv6(,3ffe:501:ffff::33)", TRUE);
  TEST("ipv6(udp,3ffe:501:ffff::33)", TRUE);
  TEST("ipv6(3ffe:501:ffff::33)", TRUE);
  TEST("ipv6(tcp:1234,3ffe:501:ffff::33)", TRUE);

  TEST("ipv6_subnet()", FALSE);
  TEST("ipv6_subnet(3ffe:501:ffff::33)", FALSE);
  TEST("ipv6_subnet(3ffe:501:ffff::33/)", TRUE);
  TEST("ipv6_subnet(3ffe:501:ffff::33/64)", TRUE);
  TEST("ipv6_subnet(3ffe:501:ffff::33-3ffe:501:ffff::34)", FALSE);

  TEST("ipv6_range()", FALSE);
  TEST("ipv6_range(3ffe:501:ffff::33)", FALSE);
  TEST("ipv6_range(3ffe:501:ffff::33-)", FALSE); /* means till ::0 */
  TEST("ipv6_range(3ffe:501:ffff::33-3ffe:501:ffff::34)", TRUE);
  TEST("ipv6_range(3ffe:501:ffff::33/22)", FALSE);

  TEST("fqdn(ssh.fi)", TRUE);
  TEST("fqdn(tcp:25,ssh.fi)", TRUE);
  TEST("fqdn(icmp,ssh.fi)", TRUE);
  TEST("usr@fqdn(tmo@ssh.fi)", TRUE);
  TEST("usr@fqdn(:500,tmo@ssh.fi)", TRUE);
  TEST("key_id(ff ff ff ff ff ff)", TRUE);
#ifdef SSHDIST_IKE_CERT_AUTH
  TEST("der_asn1_dn(,CN=Foo,O=SSH Communications Security, C=FI)", TRUE);
  TEST("der_asn1_dn(any:0,[0..67]=CN=Foo, O=SSH, C=FI)", TRUE);
  TEST("der_asn1_dn(any:0,[0..67]=O=SSH Communications Security, C=FI)", TRUE);
  /* Actually this is correct, but the data will expand into BMP
     string instead of octet string and the comparison will fail. */
  TEST(" der_asn1_dn(,C=FI, sn=MONONEN + givenname=TERO TAPANI "
       "+ x500uniqueidentifier=#1309303030303031313331 ) ", TRUE);
#endif /* SSHDIST_IKE_CERT_AUTH */

  /* Test that we can add whitespace before and after any token. */
  TEST("  ipv4   (   ,   192.168.2.1  )   ", TRUE);
  TEST("    ipv4   (   udp  ,   192.168.2.255  )  ", TRUE);
  TEST("   ipv4  (   192.168.2.1  )  ", TRUE);
  TEST("  ipv4  (  tcp    : 1234    ,    192.168.2.1   )  ", TRUE);
  TEST("  ipv4  (   tcp   :    1234    -    5678    ,  192.168.2.1 ) ", TRUE);

  TEST("  ipv4_subnet (  192.168.2.0  /  ) ", TRUE);
  TEST(" ipv4_subnet ( 192.168.2.0 / 24 ) ", TRUE);
  TEST(" ipv4_subnet ( 192.168.2.1 - 192.168.2.2 ) ", FALSE);

  TEST(" ipv4_range ( 192.168.2.1 - 192.168.3.1 ) ", TRUE);

  TEST("  ipv6  (  ,   3ffe:501:ffff::33  )  ", TRUE);
  TEST("  ipv6 ( udp , 3ffe:501:ffff::33  ) ", TRUE);
  TEST("    ipv6 (  3ffe:501:ffff::33 ) ", TRUE);
  TEST("\tipv6\t(\ttcp\t:\t1234\t,\t3ffe:501:ffff::33\t)\t", TRUE);

  TEST(" \t ipv6_subnet \t ( \t 3ffe:501:ffff::33 \t / \t ) \t ", TRUE);
  TEST("  ipv6_subnet(  3ffe:501:ffff::33 / 64 ) ", TRUE);

  TEST("   ipv6_range(3ffe:501:ffff::33   -  3ffe:501:ffff::34 ) ", TRUE);

  TEST("  fqdn  (   ssh.fi  )  ", TRUE);
  TEST("   fqdn  (  tcp  :  25  ,  ssh.fi  )  ", TRUE);
  TEST("   fqdn  (   icmp  ,   ssh.fi  ) ", TRUE);
  TEST("   usr@fqdn  (   tmo@ssh.fi   )  ", TRUE);
  TEST("   usr@fqdn   (   :   500   ,   tmo@ssh.fi   )   ", TRUE);
  TEST("   key_id(    ff ff ff ff ff ff   )", TRUE);
#ifdef SSHDIST_IKE_CERT_AUTH
  TEST("  der_asn1_dn  (  ,  CN=Foo,O=SSH Communications Security, C=FI  )  ",
       TRUE);
  TEST("  der_asn1_dn ( any : 0 ,   [0..67]  =  CN=Foo, O=SSH, C=FI  )  ",
       TRUE);
  TEST("  der_asn1_dn ( any : 0 , [0..67] = O=SSH Communications Security, "
       "C=FI ) ", TRUE);

  /* Actually this is correct, but the data will expand into BMP
     string instead of octet string and the comparison will fail. */
  TEST(" der_asn1_dn( , C=FI, sn=MONONEN + givenname=TERO TAPANI "
       "+ x500uniqueidentifier=#1309303030303031313331 ) ", TRUE);
#endif /* SSHDIST_IKE_CERT_AUTH */

  /* Test lists. */
#ifdef SSHDIST_IKE_ID_LIST
  TEST("list(ipv4(192.168.2.1),ipv4(192.168.2.5))", TRUE);
  TEST("list(ipv4(192.168.2.1),ipv4(192.168.2.5))", TRUE);
  TEST("list("
       "ipv4(192.168.2.1),"
       "ipv4(192.168.2.3),"
       "ipv4(192.168.2.5),"
       "ipv4(192.168.2.7),"
       "ipv4(192.168.2.9),"
       "ipv4(192.168.2.11),"
       "ipv4(192.168.2.13),"
       "ipv4(192.168.2.15),"
       "ipv4(192.168.2.17),"
       "ipv4(192.168.2.19),"
       "ipv4(192.168.2.21),"
       "ipv4(192.168.2.23),"
       "ipv4(192.168.2.25),"
       "ipv4(192.168.2.27),"
       "ipv4(192.168.2.29),"
       "ipv4(192.168.2.31),"
       "ipv4(192.168.2.33),"
       "ipv4(192.168.2.35),"
       "ipv4(192.168.2.37),"
       "ipv4(192.168.2.39),"
       "ipv4(192.168.2.41),"
       "ipv4(192.168.2.43),"
       "ipv4(192.168.2.45),"
       "ipv4(192.168.2.47),"
       "ipv4(192.168.2.49),"
       "ipv4(192.168.2.51),"
       "ipv4(192.168.2.53),"
       "ipv4(192.168.2.55),"
       "ipv4(192.168.2.57),"
       "ipv4(192.168.2.59),"
       "ipv4(192.168.2.61),"
       "ipv4(192.168.2.63),"
       "ipv4(192.168.2.65),"
       "ipv4(192.168.2.67),"
       "ipv4(192.168.2.69),"
       "ipv4(192.168.2.71),"
       "ipv4(192.168.2.73),"
       "ipv4(192.168.2.75),"
       "ipv4(192.168.2.77),"
       "ipv4(192.168.2.79),"
       "ipv4(192.168.2.81),"
       "ipv4(192.168.2.83),"
       "ipv4(192.168.2.85),"
       "ipv4(192.168.2.87),"
       "ipv4(192.168.2.89),"
       "ipv4(192.168.2.91),"
       "ipv4(192.168.2.93),"
       "ipv4(192.168.2.95),"
       "ipv4(192.168.2.97),"
       "ipv4(192.168.2.99),"
       "ipv4(192.168.2.101),"
       "ipv4(192.168.2.103),"
       "ipv4(192.168.2.105),"
       "ipv4(192.168.2.107),"
       "ipv4(192.168.2.109),"
       "ipv4(192.168.2.111),"
       "ipv4(192.168.2.113),"
       "ipv4(192.168.2.115),"
       "ipv4(192.168.2.117),"
       "ipv4(192.168.2.119),"
       "ipv4(192.168.2.121),"
       "ipv4(192.168.2.123),"
       "ipv4(192.168.2.125),"
       "ipv4(192.168.2.127),"
       "ipv4(192.168.2.129),"
       "ipv4(192.168.2.131),"
       "ipv4(192.168.2.133),"
       "ipv4(192.168.2.135),"
       "ipv4(192.168.2.137),"
       "ipv4(192.168.2.139),"
       "ipv4(192.168.2.141),"
       "ipv4(192.168.2.143),"
       "ipv4(192.168.2.145),"
       "ipv4(192.168.2.147),"
       "ipv4(192.168.2.149),"
       "ipv4(192.168.2.151),"
       "ipv4(192.168.2.153),"
       "ipv4(192.168.2.155),"
       "ipv4(192.168.2.157),"
       "ipv4(192.168.2.159),"
       "ipv4(192.168.2.161),"
       "ipv4(192.168.2.163),"
       "ipv4(192.168.2.165),"
       "ipv4(192.168.2.167),"
       "ipv4(192.168.2.169),"
       "ipv4(192.168.2.171),"
       "ipv4(192.168.2.173),"
       "ipv4(192.168.2.175),"
       "ipv4(192.168.2.177),"
       "ipv4(192.168.2.179),"
       "ipv4(192.168.2.181),"
       "ipv4(192.168.2.183),"
       "ipv4(192.168.2.185),"
       "ipv4(192.168.2.187),"
       "ipv4(192.168.2.189),"
       "ipv4(192.168.2.191),"
       "ipv4(192.168.2.193),"
       "ipv4(192.168.2.195),"
       "ipv4(192.168.2.197),"
       "ipv4(192.168.2.199),"
       "ipv4(192.168.2.201),"
       "ipv4(192.168.2.203),"
       "ipv4(192.168.2.205),"
       "ipv4(192.168.2.207),"
       "ipv4(192.168.2.209),"
       "ipv4(192.168.2.211),"
       "ipv4(192.168.2.213),"
       "ipv4(192.168.2.215),"
       "ipv4(192.168.2.217),"
       "ipv4(192.168.2.219),"
       "ipv4(192.168.2.221),"
       "ipv4(192.168.2.223),"
       "ipv4(192.168.2.225),"
       "ipv4(192.168.2.227),"
       "ipv4(192.168.2.229),"
       "ipv4(192.168.2.231),"
       "ipv4(192.168.2.233),"
       "ipv4(192.168.2.235),"
       "ipv4(192.168.2.237),"
       "ipv4(192.168.2.239),"
       "ipv4(192.168.2.241),"
       "ipv4(192.168.2.243),"
       "ipv4(192.168.2.245),"
       "ipv4(192.168.2.247),"
       "ipv4(192.168.2.249),"
       "ipv4(192.168.2.251),"
       "ipv4(192.168.2.253),"
       "ipv4(192.168.2.255)"
       ")", TRUE);
  TEST("list(any:0-0,[0..0]=ipv4(tcp:1-2,[0..4]=192.168.2.1),"
       "ipv4(udp:2-3,[0..4]=192.168.2.5))", TRUE);
  TEST("list(ipv4(tcp:1234-5678,192.168.2.1), "
       "ipv4_subnet(192.168.2.0/24), ipv4_range(192.168.2.1-192.168.3.1), "
       "ipv6(tcp:1234,3ffe:501:ffff::33), ipv6_subnet(3ffe:501:ffff::33/64), "
       "ipv6_range(3ffe:501:ffff::33-3ffe:501:ffff::34), fqdn(tcp:25,ssh.fi), "
       "usr@fqdn(:500,tmo@ssh.fi), key_id(ff ff ff ff ff ff))", TRUE);
#ifdef SSHDIST_IKE_CERT_AUTH
  TEST("list(der_asn1_dn(,CN=Foo,O=SSH Communications Security, C=FI), "
       "der_asn1_dn(any:0,[0..67]=CN=Foo, O=SSH, C=FI), "
       "der_asn1_dn(any:0,[0..67]=O=SSH Communications Security, C=FI), "
       "der_asn1_dn(,C=FI, Sn=MONONEN + Givenname=TERO TAPANI "
       "+ x500UniqueIdentifier=#1309303030303031313331))", TRUE);
#endif /* SSHDIST_IKE_CERT_AUTH */
#endif /* SSHDIST_IKE_ID_LIST */

  TEST("something()", FALSE);
  TEST("no id", FALSE);
  TEST("", FALSE);
  TEST(NULL, FALSE);
  TEST("unknown(udp:500,foobar)", FALSE);

  /* syntax cases */
  TEST("ipv4(udp,1,192.168.2.1)", FALSE);
  TEST("ipv4(udp,1:192.168.2.1)", FALSE);
  TEST("ipv4_subnet(udp,1,192.168.2.1/24)", FALSE);
  TEST("ipv4_subnet(,1,192.168.2.1/24)", FALSE);
  TEST("ipv4_subnet(,1:192.168.2.1/24)", FALSE);
  TEST("ipv4_range(udp,1,192.168.2.1-192.162.1.2)", FALSE);

  TEST("ipv4(123.456.789.0)", FALSE);
  TEST("ipv4(255.255.255.255)", TRUE);
  TEST("ipv4(0.0.0.0)", TRUE);
  TEST("ipv4(0.1.2)", TRUE);
  TEST("ipv4(0.1.)", TRUE);
  TEST("ipv4(0.1)", TRUE);
  TEST("ipv4(0.)", TRUE);
  TEST("ipv4(0)", FALSE);
  TEST("ipv4(-1.-1.-1.-1)", FALSE);
  TEST("ipv4(123456.789012.345678.123456789)", FALSE);
  TEST("ipv4(255.255.255.256)", FALSE);
  TEST("fqdn(f)", TRUE);
  {
    char buffer[1024];
    memset(buffer, 'f', sizeof(buffer) - 1);
    buffer[0] = 'f';
    buffer[1] = 'q';
    buffer[2] = 'd';
    buffer[3] = 'n';
    buffer[4] = '(';
    for (i = 1020; i > 6; i--)
      {
        buffer[i] = ')';
        buffer[i + 1] = '\0';
        TEST(buffer, TRUE);
      }
  }

  return failed == 0;
}

SshIkeIpsecIdentificationType ssh_tested_ids[] =
{
  IPSEC_ID_IPV4_ADDR,
  IPSEC_ID_FQDN,
  IPSEC_ID_USER_FQDN,
  IPSEC_ID_IPV4_ADDR_SUBNET,
  IPSEC_ID_IPV6_ADDR,
  IPSEC_ID_IPV6_ADDR_SUBNET,
  IPSEC_ID_IPV4_ADDR_RANGE,
  IPSEC_ID_IPV6_ADDR_RANGE,
  IPSEC_ID_DER_ASN1_DN,
  IPSEC_ID_DER_ASN1_GN,
  IPSEC_ID_KEY_ID,
  0
};

typedef enum { SSH_VALID, SSH_NOT_VALID } Validity;

typedef struct SshTestStringsRec
{
  SshIkeIpsecIdentificationType type;
  const char *tested_string;
  Validity validity;
} SshTestStrings;

SshTestStrings ssh_tested_ip_addresses[] =
{
  { IPSEC_ID_IPV4_ADDR, "192.168.2.1", SSH_VALID },
  { IPSEC_ID_IPV4_ADDR, "123.123.123.123", SSH_VALID },
  { IPSEC_ID_IPV4_ADDR, "127.0.0.1", SSH_VALID },
  { IPSEC_ID_IPV4_ADDR, "321.321.321.321", SSH_NOT_VALID },
  { IPSEC_ID_IPV4_ADDR, "255.255.255.0", SSH_VALID },
  { IPSEC_ID_IPV4_ADDR, "255.255.255.255", SSH_VALID },
  { IPSEC_ID_IPV4_ADDR, "0.0.0.0", SSH_VALID },
  { IPSEC_ID_IPV4_ADDR, "", SSH_NOT_VALID },

  { IPSEC_ID_IPV6_ADDR, "3ffe:501:ffff::33", SSH_VALID },
  { IPSEC_ID_IPV6_ADDR, "3ffe:501:ffff:0:200:e8ff:fe6f:c2e0", SSH_VALID },
  { IPSEC_ID_IPV6_ADDR, "::1", SSH_VALID },
  { IPSEC_ID_IPV6_ADDR, "ffffff:0:0:0:0:0:0:1", SSH_NOT_VALID },
  { IPSEC_ID_IPV6_ADDR, "ffff:ffff:ffff:ffff::1", SSH_VALID },
  { IPSEC_ID_IPV6_ADDR, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", SSH_VALID },
  { IPSEC_ID_IPV6_ADDR, "::", SSH_VALID },
  { IPSEC_ID_IPV6_ADDR, "", SSH_NOT_VALID },

  { 0, NULL, SSH_NOT_VALID },
};

const char* ssh_tested_ip_names[] =
{
  "ssh.fi",
  "some.nonexistant.domain.with.a.very.very.very.long.name.com",
  "clinet.fi",
  "netbsd.org",
  ""
};

const char* ssh_tested_hex_strings[] =
{
  "ff ee dd cc bb aa 99 88 77 66 55 44 33 22 11 00 ",
  "0f 0e 0d 0c 0b 0a 99 88 77 66 55 44 33 22 11 00 ",
  "ab cd ef gh ij kl mn op qr st uv wx yz", /* Heh heh */
  ""
};

const int SSH_TEST_OK = 0;
const int SSH_TEST_FAILED = 1;

int
main(int argc, char **argv)
{
  int i,j;
  short ssh_result = SSH_TEST_OK;
  Boolean ssh_expected_success;
  short ssh_success;

  if (argc > 1 && strcmp(argv[1], "-v") == 0)
    opt_verbose = 1;

  ssh_x509_library_initialize(NULL);

  for (i = 0; ssh_tested_ip_addresses[i].tested_string; i++)
    {
      for (j = 0; ssh_tested_ip_addresses[j].tested_string; j++)
        {
          if (opt_verbose)
            printf("Testing ip addresses %s and %s... ",
                   ssh_tested_ip_addresses[i].tested_string,
                   ssh_tested_ip_addresses[j].tested_string);

          ssh_expected_success =
            ssh_tested_ip_addresses[i].validity == SSH_VALID;









          ssh_success =
            test1(ssh_tested_ip_addresses[i].type, SSH_IPPROTO_TCP, 500,
                  ssh_tested_ip_addresses[i].tested_string,
                  ssh_tested_ip_addresses[j].tested_string) == TRUE;

          if (ssh_expected_success == FALSE)
            if (opt_verbose)
              printf("This test case should fail...");

          if (ssh_success == FALSE)
            {
              if (opt_verbose)
                printf("Case failed. ");
            }
          else
            {
              if (opt_verbose)
                printf("Case succeeded. ");
            }


          if (ssh_expected_success != ssh_success)
            {
              ssh_result = SSH_TEST_FAILED;
              printf("ERROR TEST FAILED\n");
            }
          else
            {
              if (opt_verbose)
                printf("Ok.\n");
            }
        }
    }

  if (!test2())
    ssh_result = SSH_TEST_FAILED;

  if (ssh_result == SSH_TEST_FAILED)
    printf("ERROR Test FAILED.\n");
  else
    printf("Test Ok.\n");

  ssh_x509_library_uninitialize();
  ssh_util_uninit();
  return ssh_result == SSH_TEST_FAILED;
}
