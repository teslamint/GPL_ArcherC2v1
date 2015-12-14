/*
 * Author: Tero Kivinen <kivinen@iki.fi>
 *
 * Copyright (c) 2004-2005 SFNT Finland Oy.
 */
/*
 *        Program: sshdns
 *        $Source: /home/user/socsw/cvs/cvsrepos/tclinux_phoenix/modules/eip93_drivers/quickSec/src/lib/sshutil/tests/Attic/t-renderer.c,v $
 *        $Author: bruce.chang $
 *
 *        Creation          : 15:25 May  6 2004 kivienn
 *        Last Modification : 12:20 Oct 21 2005 kivinen
 *        Last check in     : $Date: 2012/09/28 $
 *        Revision number   : $Revision: #1 $
 *        State             : $State: Exp $
 *        Version           : 1.342
 *        
 *
 *        Description       : Test snprintf renderes
 *
 *        $Log: t-renderer.c,v $
 *        Revision 1.1.2.1  2011/01/31 03:34:49  treychen_hc
 *        add eip93 drivers
 * *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        $EndLog$
 */

#include "sshincludes.h"
#include "sshoperation.h"
#include "sshadt.h"
#include "sshadt_bag.h"
#include "sshadt_list.h"
#include "sshobstack.h"
#include "sshinet.h"
#ifdef SSHDIST_UTIL_DNS_RESOLVER
#include "sshdns.h"
#endif /* SSHDIST_UTIL_DNS_RESOLVER */
#include "sshfsm.h"
#include "sshgetopt.h"
#include "ssheloop.h"
#include "sshglobals.h"
#include "sshrand.h"
#include "sshmiscstring.h"

#define SSH_DEBUG_MODULE "Main"

/* Program name */
char *program;

#define TEST_RENDERER_3(renderer, result, format, a1, a2, a3)   \
  { 								\
    int len, ret, i; 						\
    char *p; 							\
 								\
    len = strlen(result); 					\
 								\
    p = ssh_xmalloc(len + 10); 					\
   								\
    SSH_DEBUG(SSH_D_HIGHOK, 					\
	      ("Starting test renderer = %s, result " 		\
	       "should be %s", (renderer), (result))); 		\
			    					\
    for(i = len + 10; i > 0; i--) 				\
      { 							\
	SSH_DEBUG(SSH_D_MIDOK, 					\
		  ("Starting truncation to %d " 		\
		   "test renderer = %s, " 			\
		   "result should be %.*s", 			\
		   i, (renderer), i, 				\
		   (result))); 					\
        memset(p, 'Q', len + 10);				\
        p[len + 9] = 0;                                         \
	ret = ssh_snprintf(p, i, (format), (a1), (a2), (a3)); 	\
	if (i - 1 < len) 					\
	  { 							\
	    if (ret != i - 1) 					\
	      ssh_fatal("Renderer %s failed, should " 		\
			"return string of " 			\
			"length %d, returned %d", 		\
			(renderer), i - 1, ret); 		\
	    if (memcmp(p, (result), i - 1) != 0)		\
	      { 						\
		ssh_warning("Renderer returned\n[%s]", p); 	\
		ssh_warning("Renderer should have " 		\
			    "returned\n[%.*s]", i - 1, 		\
			    (result)); 				\
		ssh_fatal("Renderer %s failed len = %d", 	\
			  (renderer), i); 			\
	      } 						\
	  } 							\
	else 							\
	  { 							\
	    if (strcmp(p, (result)) != 0) 			\
	      { 						\
		ssh_warning("Renderer returned\n[%s]", p); 	\
		ssh_warning("Renderer should have " 		\
			    "returned\n[%s]", (result)); 	\
		ssh_fatal("Renderer %s failed", (renderer)); 	\
	      } 						\
	    if (i < len + 8 &&                                  \
		(p[i] != 'Q' ||                                 \
		 memcmp(p + i, p + i + 1,                       \
		        len + 10  - i - 2) != 0))               \
	      { 						\
		ssh_warning("Renderer overwrote data %d", i);   \
		SSH_DEBUG_HEXDUMP(0, ("data="), p, len + 10);   \
		ssh_fatal("Renderer %s failed", (renderer)); 	\
	      } 						\
	  } 							\
      } 							\
    ssh_free(p); 						\
  }

#define TEST_RENDERER(renderer, result, format, a1, a2)   \
  TEST_RENDERER_3(renderer, result, format, a1, a2, 0)

#define TEST_RENDERER_1(renderer, result, format, a1)   \
  TEST_RENDERER_3(renderer, result, format, a1, 0, 0)

#if 0
void try_renderer(char *renderer, char *result, const char *format,
		  void *func_ptr, void *param)
{
  int len, ret, i;
  char *p;

  len = strlen(result);

  p = ssh_xmalloc(len + 10);

  SSH_DEBUG(SSH_D_HIGHOK, ("Starting test renderer = %s, result should be %s",
			   renderer, result));

  for(i = len + 10; i > 0; i--)
    {
      SSH_DEBUG(SSH_D_MIDOK, ("Starting truncation to %d test renderer = %s, "
			      "result should be %.*s", i, renderer, i,
			      result));
      ret = ssh_vsnprintf(p, i, format, ap);
      if (i - 1 < len)
	{
	  if (ret != i - 1)
	    ssh_fatal("Renderer %s failed, should return string of length %d, "
		      "returned %d", renderer, i - 1, ret);
	  if (memcmp(p, result, i - 1) != 0)
	    {
	      ssh_warning("Renderer returned\n%s", p);
	      ssh_warning("Renderer should have returned\n%.*s", i - 1,
			  result);
	      ssh_fatal("Renderer %s failed len = %d", renderer, i);
	    }
	}
      else
	{
	  if (strcmp(p, result) != 0)
	    {
	      ssh_warning("Renderer returned\n%s", p);
	      ssh_warning("Renderer should have returned\n%s", result);
	      ssh_fatal("Renderer %s failed", renderer);
	    }
	}
    }
  ssh_free(p);
}
#endif

void test_renderers(void)
{
  SshIpAddrStruct address[1];
#ifdef SSHDIST_UTIL_DNS_RESOLVER
  SshDNSPacket packet;
#endif /* SSHDIST_UTIL_DNS_RESOLVER */
  SshUInt64 u64;
  SshUInt32 u32;
  SshTime t;
  SshUInt32 array[20];

  TEST_RENDERER("safe_text", "Testing", "%@", ssh_safe_text_render,
		"Testing");
  TEST_RENDERER("safe_text", "Testing With Control\\x0aChars", "%@",
		ssh_safe_text_render,
		"Testing With Control\nChars");
  TEST_RENDERER("safe_text", "Testing\\x02\\x03\\x04Random\\xe4Chars", "%@",
		ssh_safe_text_render,
		"Testing\002\003\004Random\344Chars");

  /* Bitmask renderrer */
  /* Basic tests */
  u32 = 0x02;
  TEST_RENDERER("ssh_uint32_bm_render", "SSH_PACKET_FROMADAPTER",
		"%(SSH_PACKET_FROMPROTOCOL,SSH_PACKET_FROMADAPTER,"
		"SSH_PACKET_IP4HDRCKSUMOK,SSH_PACKET_FORWARDED,"
		"SSH_PACKET_HWCKSUM,SSH_PACKET_MEDIABCAST)@",
		ssh_uint32_bm_render, &u32);
  u32 = 0x05;
  TEST_RENDERER("ssh_uint32_bm_render",
		"SSH_PACKET_FROMPROTOCOL,SSH_PACKET_IP4HDRCKSUMOK",
		"%(SSH_PACKET_FROMPROTOCOL,SSH_PACKET_FROMADAPTER,"
		"SSH_PACKET_IP4HDRCKSUMOK,SSH_PACKET_FORWARDED,"
		"SSH_PACKET_HWCKSUM,SSH_PACKET_MEDIABCAST)@",
		ssh_uint32_bm_render, &u32);
  u32 = 0xffffffff;
  TEST_RENDERER("ssh_uint32_bm_render",
		"SSH_PACKET_FROMPROTOCOL,SSH_PACKET_FROMADAPTER,"
		"SSH_PACKET_IP4HDRCKSUMOK,SSH_PACKET_FORWARDED,"
		"SSH_PACKET_HWCKSUM,SSH_PACKET_MEDIABCAST",
		"%(SSH_PACKET_FROMPROTOCOL,SSH_PACKET_FROMADAPTER,"
		"SSH_PACKET_IP4HDRCKSUMOK,SSH_PACKET_FORWARDED,"
		"SSH_PACKET_HWCKSUM,SSH_PACKET_MEDIABCAST)@",
		ssh_uint32_bm_render, &u32);
  /* Renderer should return only symbolic names for masks that are given
     in namestring */
  u32 = 0x02;
  TEST_RENDERER("ssh_uint32_bm_render", "",
		"%(SSH_PACKET_IP4HDRCKSUMOK=0x4,SSH_PACKET_FORWARDED,"
		"SSH_PACKET_HWCKSUM,SSH_PACKET_MEDIABCAST)@",
		ssh_uint32_bm_render, &u32);
  u32 = 0x40;
  TEST_RENDERER("ssh_uint32_bm_render", "",
		"%(SSH_PACKET_FROMPROTOCOL,SSH_PACKET_FROMADAPTER,"
		"SSH_PACKET_IP4HDRCKSUMOK,SSH_PACKET_FORWARDED,"
		"SSH_PACKET_HWCKSUM,SSH_PACKET_MEDIABCAST)@",
		ssh_uint32_bm_render, &u32);
  /* Automatic mask generation */
  u32 = 0x24;
  TEST_RENDERER("ssh_uint32_bm_render",
		"SSH_PACKET_IP4HDRCKSUMOK,SSH_PACKET_MEDIABCAST",
		"%(SSH_PACKET_IP4HDRCKSUMOK=0x4,SSH_PACKET_HWCKSUM=0x10,"
		"SSH_PACKET_MEDIABCAST)@",
		ssh_uint32_bm_render, &u32);
  /* Invalid format parameters */
  u32 = 0x24;
    TEST_RENDERER("ssh_uint32_bm_render",
                  "",
                  "%(SSH_PACKET_IP4HDRCKSUMOK=0x4,SSH_PACKET_HWCKSUM=0x10,"
                  "SSH_PACKET_MEDIABCAST@",
                  ssh_uint32_bm_render, &u32);

  SSH_IP_DECODE(address, "\x12\x34\x56\x78", 4);
  TEST_RENDERER("ipaddr", "18.52.86.120", "%(foo,bar=4,hip=0x10,hiiohoi)@",
		ssh_ipaddr_render, address);

  t = 1083845764;
  TEST_RENDERER("dns_time", "20040506121604", "%@", ssh_time_render, &t);
  TEST_RENDERER("dns_time32buf", "20040506121604", "%@", ssh_time32buf_render,
		"\x40\x9a\x2c\x84");

  TEST_RENDERER("ipaddr", "<null>", "%@", ssh_ipaddr_render, NULL);
  SSH_IP_UNDEFINE(address);
  TEST_RENDERER("ipaddr", "<none>", "%@", ssh_ipaddr_render, address);
  SSH_IP_DECODE(address, "\x12\x34\x56\x78", 4);
  TEST_RENDERER("ipaddr", "18.52.86.120", "%@", ssh_ipaddr_render, address);
  TEST_RENDERER("ipaddr4_uint32", "18.52.86.120", "%@",
		ssh_ipaddr4_uint32_render, (SshUInt32) 0x12345678);
  SSH_IP4_MASK_DECODE(address, "\x12\x34\x56\x78", 28);
  TEST_RENDERER("ipaddr", "18.52.86.120/28", "%@", ssh_ipaddr_render, address);
  SSH_IP4_MASK_DECODE(address, "\x12\x34\x56\x78", 9);
  TEST_RENDERER("ipaddr", "18.52.86.120/9", "%@", ssh_ipaddr_render, address);
  SSH_IP4_MASK_DECODE(address, "\x12\x34\x56\x78", 32);
  TEST_RENDERER("ipaddr", "18.52.86.120", "%@", ssh_ipaddr_render, address);
  SSH_IP4_MASK_DECODE(address, "\x12\x34\x56\x78", 0);
  TEST_RENDERER("ipaddr", "18.52.86.120/0", "%@", ssh_ipaddr_render, address);
  SSH_IP_DECODE(address, "\xff\xff\xff\xff", 4);
  TEST_RENDERER("ipaddr", "255.255.255.255", "%@", ssh_ipaddr_render, address);
  SSH_IP_DECODE(address, "\0\0\0\0", 4);
  TEST_RENDERER("ipaddr", "0.0.0.0", "%@", ssh_ipaddr_render, address);
#ifdef WITH_IPV6
  SSH_IP_DECODE(address, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", 16);
  TEST_RENDERER("ipaddr", "::", "%@", ssh_ipaddr_render, address);
  SSH_IP_DECODE(address, "\xff\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", 16);
  TEST_RENDERER("ipaddr", "ff00::", "%@", ssh_ipaddr_render, address);
  SSH_IP_DECODE(address, "\xff\0\0\0\0\0\0\0\0\0\0\0\0\0\0\1", 16);
  TEST_RENDERER("ipaddr", "ff00::1", "%@", ssh_ipaddr_render, address);
  SSH_IP_DECODE(address,
		"\x12\x23\x34\x45\x56\x67\x78\x89"
		"\x9a\xab\xbc\xcd\xde\xef\xf0\x0f",
		16);
  TEST_RENDERER("ipaddr", "1223:3445:5667:7889:9aab:bccd:deef:f00f",
		"%@", ssh_ipaddr_render, address);

  SSH_IP6_MASK_DECODE(address,
		      "\x12\x23\x34\x45\x56\x67\x78\x89"
		      "\x9a\xab\xbc\xcd\xde\xef\xf0\x0f",
		      16);
  TEST_RENDERER("ipaddr", "1223:3445:5667:7889:9aab:bccd:deef:f00f/16",
		"%@", ssh_ipaddr_render, address);

  SSH_IP6_MASK_DECODE(address,
		      "\x12\x23\x34\x45\x56\x67\x78\x89"
		      "\x9a\xab\xbc\xcd\xde\xef\xf0\x0f",
		      128);
  TEST_RENDERER("ipaddr", "1223:3445:5667:7889:9aab:bccd:deef:f00f",
		"%@", ssh_ipaddr_render, address);

  SSH_IP6_MASK_DECODE(address,
		      "\x12\x23\x34\x45\x56\x67\x78\x89"
		      "\x9a\xab\xbc\xcd\xde\xef\xf0\x0f",
		      100);
  TEST_RENDERER("ipaddr", "1223:3445:5667:7889:9aab:bccd:deef:f00f/100",
		"%@", ssh_ipaddr_render, address);

  SSH_IP6_MASK_DECODE(address,
		      "\x12\x23\x34\x45\x56\x67\x78\x89"
		      "\x9a\xab\xbc\xcd\xde\xef\xf0\x0f",
		      8);
  TEST_RENDERER("ipaddr", "1223:3445:5667:7889:9aab:bccd:deef:f00f/8",
		"%@", ssh_ipaddr_render, address);

  SSH_IP6_MASK_DECODE(address,
		      "\x12\x23\x34\x45\x56\x67\x78\x89"
		      "\x9a\xab\xbc\xcd\xde\xef\xf0\x0f",
		      0);
  TEST_RENDERER("ipaddr", "1223:3445:5667:7889:9aab:bccd:deef:f00f/0",
		"%@", ssh_ipaddr_render, address);
#endif /* WITH_IPV6 */

  SSH_IP_DECODE(address, "\xff\xff\xff\xf0", 4);
  TEST_RENDERER("ipmask", "255.255.255.240", "%@", ssh_ipmask_render, address);
  SSH_IP_DECODE(address, "\xff\xff\xff\xfe", 4);
  TEST_RENDERER("ipmask", "255.255.255.254", "%@", ssh_ipmask_render, address);
  SSH_IP_DECODE(address, "\xff\xff\xff\x80", 4);
  TEST_RENDERER("ipmask", "255.255.255.128", "%@", ssh_ipmask_render, address);
  SSH_IP_DECODE(address, "\xff\xff\xff\xff", 4);
  TEST_RENDERER("ipmask", "255.255.255.255", "%@", ssh_ipmask_render, address);
  SSH_IP_DECODE(address, "\xff\xff\x00\x00", 4);
  TEST_RENDERER("ipmask", "255.255.0.0", "%@", ssh_ipmask_render, address);
  SSH_IP_DECODE(address, "\xff\x00\x00\x00", 4);
  TEST_RENDERER("ipmask", "255.0.0.0", "%@", ssh_ipmask_render, address);
  SSH_IP_DECODE(address, "\x00\x00\x00\x00", 4);
  TEST_RENDERER("ipmask", "0.0.0.0", "%@", ssh_ipmask_render, address);

#ifdef WITH_IPV6
  SSH_IP_DECODE(address,
		"\xff\x00\x00\x00\x00\x00\x00\x00"
		"\x00\x00\x00\x00\x00\x00\x00\x00", 16);
  TEST_RENDERER("ipmask", "8", "%@", ssh_ipmask_render, address);

  SSH_IP_DECODE(address,
		"\xff\xff\x00\x00\x00\x00\x00\x00"
		"\x00\x00\x00\x00\x00\x00\x00\x00", 16);
  TEST_RENDERER("ipmask", "16", "%@", ssh_ipmask_render, address);

  SSH_IP_DECODE(address,
		"\xff\xff\xff\xff\xff\xff\xff\xff"
		"\x00\x00\x00\x00\x00\x00\x00\x00", 16);
  TEST_RENDERER("ipmask", "64", "%@", ssh_ipmask_render, address);

  SSH_IP_DECODE(address,
		"\xff\xff\xff\xff\xff\xff\xff\xff"
		"\x80\x00\x00\x00\x00\x00\x00\x00", 16);
  TEST_RENDERER("ipmask", "65", "%@", ssh_ipmask_render, address);

  SSH_IP_DECODE(address,
		"\xff\xff\xff\xff\xff\xff\xff\xfe"
		"\x00\x00\x00\x00\x00\x00\x00\x00", 16);
  TEST_RENDERER("ipmask", "63", "%@", ssh_ipmask_render, address);

  SSH_IP_DECODE(address,
		"\xff\xff\xff\xff\xff\xff\xff\xff"
		"\xff\xff\xff\xff\xff\xff\xff\xff", 16);
  TEST_RENDERER("ipmask", "128", "%@", ssh_ipmask_render, address);

  SSH_IP_DECODE(address,
		"\xff\xff\xff\xff\xff\xff\xff\xff"
		"\xff\xff\xff\xff\xff\xff\xff\xfe", 16);
  TEST_RENDERER("ipmask", "127", "%@", ssh_ipmask_render, address);

  TEST_RENDERER("ipaddr6_byte16", "::", "%@", ssh_ipaddr6_byte16_render,
		"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0");
  TEST_RENDERER("ipaddr6_byte16", "ff00::", "%@", ssh_ipaddr6_byte16_render,
		"\xff\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0");
  TEST_RENDERER("ipaddr6_byte16", "ff00::1", "%@", ssh_ipaddr6_byte16_render,
		"\xff\0\0\0\0\0\0\0\0\0\0\0\0\0\0\1");
  TEST_RENDERER("ipaddr6_byte16", "1223:3445:5667:7889:9aab:bccd:deef:f00f",
		"%@", ssh_ipaddr6_byte16_render,
		"\x12\x23\x34\x45\x56\x67\x78\x89"
		"\x9a\xab\xbc\xcd\xde\xef\xf0\x0f");
#endif /* WITH_IPV6 */

  TEST_RENDERER("ipproto", "tcp", "%@", ssh_ipproto_render, (SshUInt32) 6);
  TEST_RENDERER("ipproto", "udp", "%@", ssh_ipproto_render, (SshUInt32) 17);
  TEST_RENDERER("ipproto", "bbn", "%@", ssh_ipproto_render, (SshUInt32) 10);
  TEST_RENDERER("ipproto", "ipv6", "%@", ssh_ipproto_render, (SshUInt32) 41);
  TEST_RENDERER("ipproto", "esp", "%@", ssh_ipproto_render, (SshUInt32) 50);
  TEST_RENDERER("ipproto", "ah", "%@", ssh_ipproto_render, (SshUInt32) 51);
  TEST_RENDERER("ipproto", "(unknown 250)", "%@", ssh_ipproto_render,
		(SshUInt32) 250);

  TEST_RENDERER("etheraddr", "00:11:22:33:44:55", "%@", ssh_etheraddr_render,
		"\x00\x11\x22\x33\x44\x55");
  TEST_RENDERER("etheraddr", "00:00:00:00:00:00", "%@", ssh_etheraddr_render,
		"\x00\x00\x00\x00\x00\x00");
  TEST_RENDERER("etheraddr", "ff:ff:ff:ff:ff:ff", "%@", ssh_etheraddr_render,
		"\xff\xff\xff\xff\xff\xff");

  u64 = 1;
  TEST_RENDERER("format_number64", "1", "%.1000@",
		ssh_format_number64_render, &u64);
  u64 = 12;
  TEST_RENDERER("format_number64", "12", "%.1000@",
		ssh_format_number64_render, &u64);
  u64 = 123;
  TEST_RENDERER("format_number64", "123", "%.1000@",
		ssh_format_number64_render, &u64);
  u64 = 1234;
  TEST_RENDERER("format_number64", "1.2k", "%.1000@",
		ssh_format_number64_render, &u64);
  u64 = 12345;
  TEST_RENDERER("format_number64", "12k", "%.1000@",
		ssh_format_number64_render, &u64);
  u64 = 123456;
  TEST_RENDERER("format_number64", "123k", "%.1000@",
		ssh_format_number64_render, &u64);
  u64 = 1234567;
  TEST_RENDERER("format_number64", "1.2M", "%.1000@",
		ssh_format_number64_render, &u64);
  u64 = 12345678;
  TEST_RENDERER("format_number64", "12M", "%.1000@",
		ssh_format_number64_render, &u64);
  u64 = 123456789;
  TEST_RENDERER("format_number64", "123M", "%.1000@",
		ssh_format_number64_render, &u64);
  u64 = 1234567890;
  TEST_RENDERER("format_number64", "1.2G", "%.1000@",
		ssh_format_number64_render, &u64);
  u64 = SSH_C64(12345678901);
  TEST_RENDERER("format_number64", "12G", "%.1000@",
		ssh_format_number64_render, &u64);
  u64 = SSH_C64(123456789012);
  TEST_RENDERER("format_number64", "123G", "%.1000@",
		ssh_format_number64_render, &u64);
  u64 = SSH_C64(1234567890123);
  TEST_RENDERER("format_number64", "1.2T", "%.1000@",
		ssh_format_number64_render, &u64);
  u64 = SSH_C64(12345678901234);
  TEST_RENDERER("format_number64", "12T", "%.1000@",
		ssh_format_number64_render, &u64);
  u64 = SSH_C64(123456789012345);
  TEST_RENDERER("format_number64", "123T", "%.1000@",
		ssh_format_number64_render, &u64);
  u64 = SSH_C64(1234567890123456);
  TEST_RENDERER("format_number64", "1.2P", "%.1000@",
		ssh_format_number64_render, &u64);
  u64 = SSH_C64(12345678901234567);
  TEST_RENDERER("format_number64", "12P", "%.1000@",
		ssh_format_number64_render, &u64);
  u64 = SSH_C64(123456789012345678);
  TEST_RENDERER("format_number64", "123P", "%.1000@",
		ssh_format_number64_render, &u64);
  u64 = SSH_C64(1234567890123456789);
  TEST_RENDERER("format_number64", "1.2E", "%.1000@",
		ssh_format_number64_render, &u64);
  u64 = SSH_C64(12345678901234567890);
  TEST_RENDERER("format_number64", "12E", "%.1000@",
		ssh_format_number64_render, &u64);

  u64 = 1;
  TEST_RENDERER("format_number64", "1", "%@",
		ssh_format_number64_render, &u64);
  u64 = 12;
  TEST_RENDERER("format_number64", "12", "%@",
		ssh_format_number64_render, &u64);
  u64 = 123;
  TEST_RENDERER("format_number64", "123", "%@",
		ssh_format_number64_render, &u64);
  u64 = 1234;
  TEST_RENDERER("format_number64", "1.2k", "%@",
		ssh_format_number64_render, &u64);
  u64 = 12345;
  TEST_RENDERER("format_number64", "12k", "%@",
		ssh_format_number64_render, &u64);
  u64 = 123456;
  TEST_RENDERER("format_number64", "121k", "%@",
		ssh_format_number64_render, &u64);
  u64 = 1234567;
  TEST_RENDERER("format_number64", "1.2M", "%@",
		ssh_format_number64_render, &u64);
  u64 = 12345678;
  TEST_RENDERER("format_number64", "12M", "%@",
		ssh_format_number64_render, &u64);
  u64 = 123456789;
  TEST_RENDERER("format_number64", "118M", "%@",
		ssh_format_number64_render, &u64);
  u64 = 1234567890;
  TEST_RENDERER("format_number64", "1.1G", "%@",
		ssh_format_number64_render, &u64);
  u64 = SSH_C64(12345678901);
  TEST_RENDERER("format_number64", "11G", "%@",
		ssh_format_number64_render, &u64);
  u64 = SSH_C64(123456789012);
  TEST_RENDERER("format_number64", "115G", "%@",
		ssh_format_number64_render, &u64);
  u64 = SSH_C64(1234)*SSH_C64(1073741824);
  TEST_RENDERER("format_number64", "1.2T", "%@",
		ssh_format_number64_render, &u64);
  u64 = SSH_C64(12345)*SSH_C64(1073741824);
  TEST_RENDERER("format_number64", "12T", "%@",
		ssh_format_number64_render, &u64);
  u64 = SSH_C64(123)*SSH_C64(1099511627776);
  TEST_RENDERER("format_number64", "123T", "%@",
		ssh_format_number64_render, &u64);
  u64 = SSH_C64(1234)*SSH_C64(1099511627776);
  TEST_RENDERER("format_number64", "1.2P", "%@",
		ssh_format_number64_render, &u64);
  u64 = SSH_C64(12345)*SSH_C64(1024)*SSH_C64(1073741824);
  TEST_RENDERER("format_number64", "12P", "%@",
		ssh_format_number64_render, &u64);
  u64 = SSH_C64(123)*SSH_C64(1048576)*SSH_C64(1073741824);
  TEST_RENDERER("format_number64", "123P", "%@",
		ssh_format_number64_render, &u64);
  u64 = SSH_C64(1234)*SSH_C64(1048576)*SSH_C64(1073741824);
  TEST_RENDERER("format_number64", "1.2E", "%@",
		ssh_format_number64_render, &u64);
  u64 = SSH_C64(12345)*SSH_C64(1048576)*SSH_C64(1073741824);
  TEST_RENDERER("format_number64", "12E", "%@",
		ssh_format_number64_render, &u64);

  u32 = 1;
  TEST_RENDERER("format_number32", "1", "%.1000@",
		ssh_format_number32_render, &u32);
  u32 = 12;
  TEST_RENDERER("format_number32", "12", "%.1000@",
		ssh_format_number32_render, &u32);
  u32 = 123;
  TEST_RENDERER("format_number32", "123", "%.1000@",
		ssh_format_number32_render, &u32);
  u32 = 1234;
  TEST_RENDERER("format_number32", "1.2k", "%.1000@",
		ssh_format_number32_render, &u32);
  u32 = 12345;
  TEST_RENDERER("format_number32", "12k", "%.1000@",
		ssh_format_number32_render, &u32);
  u32 = 123456;
  TEST_RENDERER("format_number32", "123k", "%.1000@",
		ssh_format_number32_render, &u32);
  u32 = 1234567;
  TEST_RENDERER("format_number32", "1.2M", "%.1000@",
		ssh_format_number32_render, &u32);
  u32 = 12345678;
  TEST_RENDERER("format_number32", "12M", "%.1000@",
		ssh_format_number32_render, &u32);
  u32 = 123456789;
  TEST_RENDERER("format_number32", "123M", "%.1000@",
		ssh_format_number32_render, &u32);
  u32 = 1234567890;
  TEST_RENDERER("format_number32", "1.2G", "%.1000@",
		ssh_format_number32_render, &u32);

  u32 = 1;
  TEST_RENDERER("format_number32", "1", "%@",
		ssh_format_number32_render, &u32);
  u32 = 12;
  TEST_RENDERER("format_number32", "12", "%@",
		ssh_format_number32_render, &u32);
  u32 = 123;
  TEST_RENDERER("format_number32", "123", "%@",
		ssh_format_number32_render, &u32);
  u32 = 1234;
  TEST_RENDERER("format_number32", "1.2k", "%@",
		ssh_format_number32_render, &u32);
  u32 = 12345;
  TEST_RENDERER("format_number32", "12k", "%@",
		ssh_format_number32_render, &u32);
  u32 = 123456;
  TEST_RENDERER("format_number32", "121k", "%@",
		ssh_format_number32_render, &u32);
  u32 = 1234567;
  TEST_RENDERER("format_number32", "1.2M", "%@",
		ssh_format_number32_render, &u32);
  u32 = 12345678;
  TEST_RENDERER("format_number32", "12M", "%@",
		ssh_format_number32_render, &u32);
  u32 = 123456789;
  TEST_RENDERER("format_number32", "118M", "%@",
		ssh_format_number32_render, &u32);
  u32 = 1234567890;
  TEST_RENDERER("format_number32", "1.1G", "%@",
		ssh_format_number32_render, &u32);

  TEST_RENDERER_1("%d", "1234567", "%ld", (unsigned long) 1234567);
  TEST_RENDERER_1("%x", "1234567", "%lx", (unsigned long) 0x1234567);

  array[0] = 10;
  array[1] = 2;
  array[2] = 30;
  array[3] = 5;
  TEST_RENDERER("format_uint32_array", "10 2 30 5",
		  "%.4@", ssh_uint32_array_render, array);
  TEST_RENDERER_3("format_uint32_array",
		  "0000000a 00000002 0000001e 00000005",
		  "%.*@", -4, ssh_uint32_array_render, array);
  array[0] = -1;
  TEST_RENDERER_3("format_uint32_array",
		  "ffffffff 00000002 0000001e 00000005",
		  "%.*@", -4, ssh_uint32_array_render, array);

  TEST_RENDERER("hex", "666f6f", "%@", ssh_hex_render, "foo");
  TEST_RENDERER("hex", "666f6f66 6f6f", "%@", ssh_hex_render, "foofoo");
  TEST_RENDERER_3("hex", "666f6f66 6f", "%.*@", 5, ssh_hex_render, "foofoo");
  TEST_RENDERER_3("hex", "01020304 05", "%.*@", 5, ssh_hex_render,
		  "\1\2\3\4\5");
  TEST_RENDERER_3("hex", "00010203 04050607 08090a0b", "%.*@",
		  12, ssh_hex_render, "\0\1\2\3\4\5\6\7\10\11\12\13");
  TEST_RENDERER_3("hex", "666f6f00 04050607 08090a0b", "%.*@",
		  12, ssh_hex_render, "foo\0\4\5\6\7\10\11\12\13");
  TEST_RENDERER_3("hex", "666f6f00 04050607 0809feff", "%.*@",
		  12, ssh_hex_render, "foo\0\4\5\6\7\10\11\376\377");

  TEST_RENDERER("safe_text", "foo", "%@", ssh_safe_text_render, "foo");
  TEST_RENDERER("safe_text", "foofoo", "%@", ssh_safe_text_render, "foofoo");
  TEST_RENDERER_3("safe_text", "foofo", "%.*@", 5,
		  ssh_safe_text_render, "foofoo");
  TEST_RENDERER_3("safe_text", "\\x01\\x02\\x03\\x04\\x05", "%.*@", 5,
		  ssh_safe_text_render,
		  "\1\2\3\4\5");
  TEST_RENDERER_3("safe_text",
		  "\\x00\\x01\\x02\\x03\\x04\\x05"
		  "\\x06\\x07\\x08\\x09\\x0a\\x0b",
		  "%.*@",
		  12, ssh_safe_text_render, "\0\1\2\3\4\5\6\7\10\11\12\13");
  TEST_RENDERER_3("safe_text",
		  "foo\\x00\\x04\\x05\\x06\\x07\\x08\\x09\\x0a\\x0b",
		  "%.*@",
		  12, ssh_safe_text_render, "foo\0\4\5\6\7\10\11\12\13");
  TEST_RENDERER_3("safe_text",
		  "foo\\x00\\x04\\x05\\x06\\x07\\x08\\x09\\xfe\\xff",
		  "%.*@",
		  12, ssh_safe_text_render, "foo\0\4\5\6\7\10\11\376\377");

#if 0
  test_renderer("format_time");
  test_renderer("format_time32");
  test_renderer("format_time32buf");
  test_renderer("hex");
#endif

#ifdef SSHDIST_UTIL_DNS_RESOLVER
  TEST_RENDERER("dns_name", "uudestaan.iki.fi.", "%@",
		ssh_dns_name_render, "\11uudestaan\3iki\2fi");
  TEST_RENDERER("dns_name", "kivinen.iki.fi.", "%@",
		ssh_dns_name_render, "\7kivinen\3iki\2fi");
  TEST_RENDERER("dns_name", "todella-pitka-nimi-joka-lahestyy-63-merkin-"
		"rajaa-ja-62-merkkia.testing.com.",
		"%@",
		ssh_dns_name_render,
		">todella-pitka-nimi-joka-lahestyy-63-merkin-rajaa-"
		"ja-62-merkkia\7testing\3com");
  TEST_RENDERER("dns_name", "Pari erikois merkkia.",
		"%@", ssh_dns_name_render,
		"\24Pari erikois merkkia");
  TEST_RENDERER("dns_name", "Pari\\x09erikois\\x0amerkkia.",
		"%@", ssh_dns_name_render,
		"\24Pari\terikois\nmerkkia");
  TEST_RENDERER("dns_name", "<safety belt a>", "%@",
		ssh_dns_name_render, "a");
  TEST_RENDERER("dns_name", "<safety belt z>", "%@",
		ssh_dns_name_render, "z");
  TEST_RENDERER("dns_name", "uudestaan.<error xiki>", "%@",
		ssh_dns_name_render, "\11uudestaanxiki\2fi");
  TEST_RENDERER("dns_name", "uudestaan.<overflow>", "%.10@",
		ssh_dns_name_render, "\11uudestaan\3iki\2fi");
  TEST_RENDERER_3("dns_name", "uudestaan.<overflow>", "%.*@", 10,
		  ssh_dns_name_render, "\11uudestaan\3iki\2fi");

#ifdef WITH_IPV6
  packet = ssh_dns_packet_allocate(1, 2, 4, 8);
  packet->id = 0x1234;
  packet->flags = 0x8000;
  packet->op_code = 1;
  packet->response_code = 0;
  packet->question_array[0].qname = "\11uudestaan\3iki\2fi";
  packet->question_array[0].qtype = SSH_DNS_RESOURCE_A;
  packet->question_array[0].qclass = SSH_DNS_CLASS_INTERNET;

  packet->answer_array[0].name = "\7kivinen\3com";
  packet->answer_array[0].type = SSH_DNS_RESOURCE_A;
  packet->answer_array[0].dns_class = SSH_DNS_CLASS_INTERNET;
  packet->answer_array[0].ttl = 3600;
  packet->answer_array[0].rdlength = 4;
  packet->answer_array[0].rdata = "\x12\x34\x56\x78";


  packet->answer_array[1].name = "";
  packet->answer_array[1].type = SSH_DNS_RESOURCE_AAAA;
  packet->answer_array[1].dns_class = SSH_DNS_CLASS_INTERNET;
  packet->answer_array[1].ttl = 3601;
  packet->answer_array[1].rdlength = 16;
  packet->answer_array[1].rdata =
    "\x12\x34\x56\x78\x12\x34\x56\x78\x00\x00\x00\x00\x00\x00\x00\x00";

  packet->authority_array[0].name = "\3com";
  packet->authority_array[0].type = SSH_DNS_RESOURCE_NS;
  packet->authority_array[0].dns_class = SSH_DNS_CLASS_INTERNET;
  packet->authority_array[0].ttl = 3600*24;
  packet->authority_array[0].rdlength = 17;
  packet->authority_array[0].rdata = "\1a\11nsservers\3com";

  packet->authority_array[1].name = "";
  packet->authority_array[1].type = SSH_DNS_RESOURCE_MD;
  packet->authority_array[1].dns_class = SSH_DNS_CLASS_INTERNET;
  packet->authority_array[1].ttl = 60;
  packet->authority_array[1].rdlength = 16;
  packet->authority_array[1].rdata = "\7kivinen\3iki\2fi";

  packet->authority_array[2].name = "";
  packet->authority_array[2].type = SSH_DNS_RESOURCE_MF;
  packet->authority_array[2].dns_class = SSH_DNS_CLASS_INTERNET;
  packet->authority_array[2].ttl = 1;
  packet->authority_array[2].rdlength = 8;
  packet->authority_array[2].rdata = "\3iki\2fi";

  packet->authority_array[3].name = "\3www\7kivinen\3iki\2fi";
  packet->authority_array[3].type = SSH_DNS_RESOURCE_CNAME;
  packet->authority_array[3].dns_class = SSH_DNS_CLASS_INTERNET;
  packet->authority_array[3].ttl = 864000;
  packet->authority_array[3].rdlength = 17;
  packet->authority_array[3].rdata = "\10fireball\3acr\2fi";

  packet->additional_array[0].name = "";
  packet->additional_array[0].type = SSH_DNS_RESOURCE_SOA;
  packet->additional_array[0].dns_class = SSH_DNS_CLASS_INTERNET;
  packet->additional_array[0].ttl = 3600*24*7;
  packet->additional_array[0].rdlength = 64;
  packet->additional_array[0].rdata = "\1a\14ROOT-SERVERS\3net\0" /* domain */
    "\5nstld\14verisign-grs\3com\0"	/* mail */
    "\x77\x73\x62\xA8"			/* serial */
    "\x00\x00\x07\x08"			/* refresh */
    "\x00\x00\x03\x84"			/* retry */
    "\x00\x09\x3a\x80"			/* expire */
    "\x00\x01\x51\x80";			/* minimum */

  packet->additional_array[1].name = "";
  packet->additional_array[1].type = SSH_DNS_RESOURCE_MB;
  packet->additional_array[1].dns_class = SSH_DNS_CLASS_INTERNET;
  packet->additional_array[1].ttl = 60;
  packet->additional_array[1].rdlength = 16;
  packet->additional_array[1].rdata = "\7kivinen\3iki\2fi";

  packet->additional_array[2].name = "";
  packet->additional_array[2].type = SSH_DNS_RESOURCE_AFSDB;
  packet->additional_array[2].dns_class = SSH_DNS_CLASS_INTERNET;
  packet->additional_array[2].ttl = 1;
  packet->additional_array[2].rdlength = 2 + 8;
  packet->additional_array[2].rdata = "\x00\x00\3iki\2fi";

  packet->additional_array[3].name = "\3www\7kivinen\3iki\2fi";
  packet->additional_array[3].type = SSH_DNS_RESOURCE_MX;
  packet->additional_array[3].dns_class = SSH_DNS_CLASS_INTERNET;
  packet->additional_array[3].ttl = 864000;
  packet->additional_array[3].rdlength = 2 + 17;
  packet->additional_array[3].rdata = "\x00\x0a\10fireball\3acr\2fi";

  packet->additional_array[4].name = "\3com";
  packet->additional_array[4].type = SSH_DNS_RESOURCE_NULL;
  packet->additional_array[4].dns_class = SSH_DNS_CLASS_INTERNET;
  packet->additional_array[4].ttl = 3600*24;
  packet->additional_array[4].rdlength = 5;
  packet->additional_array[4].rdata = "\x12\x34\x00\x55\x66";

  packet->additional_array[5].name = "";
  packet->additional_array[5].type = SSH_DNS_RESOURCE_WKS;
  packet->additional_array[5].dns_class = SSH_DNS_CLASS_INTERNET;
  packet->additional_array[5].ttl = 60;
  packet->additional_array[5].rdlength = 9;
  packet->additional_array[5].rdata = "\x12\x34\x56\x78\x06\x11\x22\x44\x88";

  packet->additional_array[6].name = "\7in-addr\4arpa";
  packet->additional_array[6].type = SSH_DNS_RESOURCE_RP;
  packet->additional_array[6].dns_class = SSH_DNS_CLASS_INTERNET;
  packet->additional_array[6].ttl = 1;
  packet->additional_array[6].rdlength = 8 + 17;
  packet->additional_array[6].rdata = "\3iki\2fi\0\10fireball\3acr\2fi";

  packet->additional_array[7].name = "\3www\7kivinen\3iki\2fi";
  packet->additional_array[7].type = SSH_DNS_RESOURCE_HINFO;
  packet->additional_array[7].dns_class = SSH_DNS_CLASS_INTERNET;
  packet->additional_array[7].ttl = 864000;
  packet->additional_array[7].rdlength = 12;
  packet->additional_array[7].rdata = "\4i386\6NetBSD";

  TEST_RENDERER("dns_packet",
		"Id = 0x1234, flags = 0x8000, op_code = 1, "
		"response_code = No error (0), questions = 1; "
		"name = uudestaan.iki.fi., type = Host address (A) (1), "
		"class = 1, answers = 2; "
		"name = kivinen.com., type = Host address (A) (1), "
		"class = 1, ttl = 01:00:00, rdlength = 4, "
		"rdata = 18.52.86.120, name = ., "
		"type = IP6 Address (AAAA) (28), class = 1, ttl = 01:00:01, "
		"rdlength = 16, rdata = 1234:5678:1234:5678::, authoritys = 4; "
		"name = com., type = Authoritative server (NS) (2), "
		"class = 1, ttl = 1+00:00, rdlength = 17, "
		"rdata = a.nsservers.com., name = ., "
		"type = Mail destination (MD) (3), class = 1, ttl = 00:01:00, "
		"rdlength = 16, rdata = kivinen.iki.fi., name = ., "
		"type = Mail forwarder (MF) (4), class = 1, ttl = 00:00:01, "
		"rdlength = 8, rdata = iki.fi., name = www.kivinen.iki.fi., "
		"type = Canonical name (CNAME) (5), class = 1, "
		"ttl = 10+00:00, rdlength = 17, rdata = fireball.acr.fi., "
		"additionals = 8; "
		"name = ., type = Start of authority zone (SOA) (6), "
		"class = 1, ttl = 7+00:00, rdlength = 64, "
		"rdata = mname = a.ROOT-SERVERS.net., "
		"rname = nstld.verisign-grs.com., serial = 2004050600, "
		"refresh = 00:30:00, retry = 00:15:00, expire = 7+00:00, "
		"minimum = 1+00:00, name = ., "
		"type = Mailbox domain name (MB) (7), class = 1, "
		"ttl = 00:01:00, rdlength = 16, rdata = kivinen.iki.fi., "
		"name = ., type = AFS cell database (AFSDB) (18), class = 1, "
		"ttl = 00:00:01, rdlength = 10, rdata = subtype = 0, iki.fi., "
		"name = www.kivinen.iki.fi., "
		"type = Mail routing information (MX) (15), class = 1, "
		"ttl = 10+00:00, rdlength = 19, rdata = preference = 10, "
		"fireball.acr.fi., name = com., "
		"type = Null resource record (NULL) (10), class = 1, "
		"ttl = 1+00:00, rdlength = 5, rdata = \\x124\\x00Uf, name = ., "
		"type = Well known service (WKS) (11), class = 1, "
		"ttl = 00:01:00, rdlength = 9, rdata = 18.52.86.120, "
		"proto = tcp: 3 7 10 14 17 21 24 28, name = in-addr.arpa., "
		"type = Responsible person (RP) (17), class = 1, "
		"ttl = 00:00:01, rdlength = 25, rdata = iki.fi., "
		"fireball.acr.fi., name = www.kivinen.iki.fi., "
		"type = Host information (HINFO) (13), class = 1, "
		"ttl = 10+00:00, rdlength = 12, rdata = cpu = i386, "
		"os = NetBSD, <end>",
		"%@", ssh_dns_packet_render,
		packet);

  packet->additional_count = 0;
  TEST_RENDERER("dns_packet2",
		"\tId = 0x1234, flags = 0x8000, op_code = 1, "
		"response_code = No error (0)\n"
		"\tquestions = 1\n"
		  "\t\tname = uudestaan.iki.fi.\n"
		  "\t\ttype = Host address (A) (1)\n"
		  "\t\tclass = 1\n"
		"\tanswers = 2\n"
		  "\t\tname = kivinen.com.\n"
		  "\t\ttype = Host address (A) (1)\n"
		  "\t\tclass = 1\n"
		  "\t\tttl = 01:00:00\n"
		  "\t\trdlength = 4\n"
		  "\t\trdata = \n"
		    "\t\t\t18.52.86.120\n"
		  "\t\tname = .\n"
		  "\t\ttype = IP6 Address (AAAA) (28)\n"
		  "\t\tclass = 1\n"
		  "\t\tttl = 01:00:01\n"
		  "\t\trdlength = 16\n"
		  "\t\trdata = \n"
		    "\t\t\t1234:5678:1234:5678::\n"
		"\tauthoritys = 4\n"
		  "\t\tname = com.\n"
		  "\t\ttype = Authoritative server (NS) (2)\n"
		  "\t\tclass = 1\n"
		  "\t\tttl = 1+00:00\n"
		  "\t\trdlength = 17\n"
		  "\t\trdata = \n"
		    "\t\t\ta.nsservers.com.\n"
		  "\t\tname = .\n"
		  "\t\ttype = Mail destination (MD) (3)\n"
		  "\t\tclass = 1\n"
		  "\t\tttl = 00:01:00\n"
		  "\t\trdlength = 16\n"
		  "\t\trdata = \n"
		    "\t\t\tkivinen.iki.fi.\n"
		  "\t\tname = .\n"
		  "\t\ttype = Mail forwarder (MF) (4)\n"
		  "\t\tclass = 1\n"
		  "\t\tttl = 00:00:01\n"
		  "\t\trdlength = 8\n"
		  "\t\trdata = \n"
		    "\t\t\tiki.fi.\n"
		  "\t\tname = www.kivinen.iki.fi.\n"
		  "\t\ttype = Canonical name (CNAME) (5)\n"
		  "\t\tclass = 1\n"
  		  "\t\tttl = 10+00:00\n"
		  "\t\trdlength = 17\n"
		  "\t\trdata = \n"
		    "\t\t\tfireball.acr.fi.\n"
		"\tadditionals = 0\n"
		"\t<end>",
		"%.1@", ssh_dns_packet_render,
		packet);

  packet->question_count = 0;
  packet->answer_count = 0;
  packet->authority_count = 0;
  packet->additional_count = 8;
  TEST_RENDERER("dns_packet2",
		"\tId = 0x1234, flags = 0x8000, op_code = 1, "
		"response_code = No error (0)\n"
		"\tquestions = 0\n"
		"\tanswers = 0\n"
		"\tauthoritys = 0\n"
		"\tadditionals = 8\n"
		  "\t\tname = .\n"
		  "\t\ttype = Start of authority zone (SOA) (6)\n"
		  "\t\tclass = 1\n"
		  "\t\tttl = 7+00:00\n"
		  "\t\trdlength = 64\n"
		  "\t\trdata = \n"
		    "\t\t\tmname = a.ROOT-SERVERS.net.\n"
		    "\t\t\trname = nstld.verisign-grs.com.\n"
		    "\t\t\tserial = 2004050600\n"
		    "\t\t\trefresh = 00:30:00\n"
		    "\t\t\tretry = 00:15:00\n"
		    "\t\t\texpire = 7+00:00\n"
		    "\t\t\tminimum = 1+00:00\n"
		  "\t\tname = .\n"
		  "\t\ttype = Mailbox domain name (MB) (7)\n"
		  "\t\tclass = 1\n"
		  "\t\tttl = 00:01:00\n"
		  "\t\trdlength = 16\n"
		  "\t\trdata = \n"
		    "\t\t\tkivinen.iki.fi.\n"
		  "\t\tname = .\n"
		  "\t\ttype = AFS cell database (AFSDB) (18)\n"
		  "\t\tclass = 1\n"
		  "\t\tttl = 00:00:01\n"
		  "\t\trdlength = 10\n"
		  "\t\trdata = \n"
		    "\t\t\tsubtype = 0\n"
		    "\t\t\tiki.fi.\n"
		  "\t\tname = www.kivinen.iki.fi.\n"
		  "\t\ttype = Mail routing information (MX) (15)\n"
		  "\t\tclass = 1\n"
		  "\t\tttl = 10+00:00\n"
		  "\t\trdlength = 19\n"
		  "\t\trdata = \n"
		    "\t\t\tpreference = 10\n"
		    "\t\t\tfireball.acr.fi.\n"
		  "\t\tname = com.\n"
		  "\t\ttype = Null resource record (NULL) (10)\n"
		  "\t\tclass = 1\n"
		  "\t\tttl = 1+00:00\n"
		  "\t\trdlength = 5\n"
		  "\t\trdata = \n"
		    "\t\t\t\\x124\\x00Uf\n"
		  "\t\tname = .\n"
		  "\t\ttype = Well known service (WKS) (11)\n"
		  "\t\tclass = 1\n"
		  "\t\tttl = 00:01:00\n"
		  "\t\trdlength = 9\n"
		  "\t\trdata = \n"
		    "\t\t\t18.52.86.120\n"
		    "\t\t\tproto = tcp: 3 7 10 14 17 21 24 28\n"
		  "\t\tname = in-addr.arpa.\n"
		  "\t\ttype = Responsible person (RP) (17)\n"
		  "\t\tclass = 1\n"
		  "\t\tttl = 00:00:01\n"
		  "\t\trdlength = 25\n"
		  "\t\trdata = \n"
		    "\t\t\tiki.fi.\n"
		    "\t\t\tfireball.acr.fi.\n"
		  "\t\tname = www.kivinen.iki.fi.\n"
		  "\t\ttype = Host information (HINFO) (13)\n"
		  "\t\tclass = 1\n"
		  "\t\tttl = 10+00:00\n"
		  "\t\trdlength = 12\n"
		  "\t\trdata = \n"
		    "\t\t\tcpu = i386\n"
		    "\t\t\tos = NetBSD\n"
		  "\t<end>",
		"%.1@", ssh_dns_packet_render,
		packet);

  ssh_dns_packet_free(packet);
#endif /* WITH_IPV6 */



#endif /* SSHDIST_UTIL_DNS_RESOLVER */
}

int main(int argc, char **argv)
{
  const char *debug_string = "Main=3";
  int c, errflg = 0;

  program = strrchr(argv[0], '/');
  if (program == NULL)
    program = argv[0];
  else
    program++;

  while ((c = ssh_getopt(argc, argv, "d:", NULL)) != EOF)
    {
      switch (c)
        {
        case 'd': debug_string = ssh_optarg; break;
	default:
        case '?': errflg++; break;
        }
    }
  if (errflg || argc - ssh_optind != 0)
    {
      fprintf(stderr,
	      "Usage: %s [-d debug_flags]\n",
	      program);
      exit(1);
    }

  ssh_debug_set_level_string(debug_string);

  ssh_event_loop_initialize();

  test_renderers();

  ssh_event_loop_uninitialize();
  ssh_debug_uninit();
  ssh_global_uninit();









  return 0;
}
