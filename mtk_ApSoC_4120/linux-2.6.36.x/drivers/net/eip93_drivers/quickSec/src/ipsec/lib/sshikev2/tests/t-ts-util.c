/*
 *
 * Author: Tero Kivinen <kivinen@iki.fi>
 *
 *  Copyright:
 *          Copyright (c) 2004, 2005 SFNT Finland Oy.
 */
/*
 *        Program: sshikev2
 *        $Author: bruce.chang $
 *
 *        Creation          : 16:12 Aug 11 2004 kivinen
 *        Last Modification : 15:01 Apr 23 2009 kivinen
 *        Last check in     : $Date: 2012/09/28 $
 *        Revision number   : $Revision: #1 $
 *        State             : $State: Exp $
 *        Version           : 1.167
 *        
 *
 *        Description       : IKEv2 traffic selector test program
 *
 *
 *        $Log: t-ts-util.c,v $
 *        Revision 1.1.2.1  2011/01/31 03:29:33  treychen_hc
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
 *        $EndLog$
 */

#include "sshincludes.h"
#include "sshikev2-initiator.h"
#include "sshikev2-util.h"
#include "sshdebug.h"
#include "dummy-if.h"

SshSADHandle sad_handle;

Boolean do_test(const char *str, Boolean valid)
{
  SshIkev2PayloadTS ts1, ts2;
  char *str2, *str3, *str4;
  int ret1, ret2;
  size_t len;
  int i;

  ts1 = NULL;
  ts2 = NULL;
  str2 = NULL;
  str3 = NULL;
  str4 = NULL;

  ts1 = ssh_ikev2_ts_allocate(sad_handle);

  ret1 = ssh_ikev2_string_to_ts(str, ts1);
  if (ret1 == -1)
    {
      if (valid)
	{
	  ssh_warning("String %s failed even when should have succeed", str);
	  goto error;
	}
      goto out;
    }
  else
    {
      if (!valid)
	{
	  ssh_warning("String %s succeeded even when should have failed", str);
	  goto error;
	}
    }

  ssh_ikev2_ts_to_string(&str2, ts1);

  ts2 = ssh_ikev2_ts_allocate(sad_handle);

  ret2 = ssh_ikev2_string_to_ts(str2, ts2);

  if (ret2 == -1)
    {
      ssh_warning("String %s reencode of %s failed", str,str2);
      goto error;
    }

  if (ret1 != ret2)
    {
      ssh_warning("String %s reencode have different number of items "
		  "than original, %d vs %d", str, ret1, ret2);
      goto error;
    }

  if (ts1->number_of_items_used != ts2->number_of_items_used)
    {
      ssh_warning("String %s reencode have different number of used items "
		  "than original, %d vs %d", str,
		  (int) ts1->number_of_items_used,
		  (int) ts2->number_of_items_used);
      goto error;
    }

  for(i = 0; i < ts1->number_of_items_used; i++)
    {
      if (ts1->items[i].proto != ts2->items[i].proto ||
	  ts1->items[i].start_port != ts2->items[i].start_port ||
	  ts1->items[i].end_port != ts2->items[i].end_port ||
	  SSH_IP_CMP(ts1->items[i].start_address,
		     ts2->items[i].start_address) != 0 ||
	  SSH_IP_CMP(ts1->items[i].end_address,
		     ts2->items[i].end_address) != 0)
	{
	  ssh_warning("String %s reencode have different values for item %d",
		      str, i);
	  goto error;
	}
    }

  ssh_ikev2_ts_to_string(&str3, ts2);

  if (strcmp(str2, str3) != 0)
    {
      ssh_warning("String %s reencode2 have different value "
		  "%s vs %s", str, str2, str3);
      goto error;
    }

  len = strlen(str3);
  str4 = ssh_xmalloc(len + 10);
  for(i = 1; i < len + 10; i++)
    {
      memset(str4, 0, len + 10);
      ret1 = ssh_snprintf(str4, i, "%@", ssh_ikev2_ts_render, ts2);
      if (i - 1 < len)
	{
	  if (ret1 != i - 1)
	    {
	      ssh_warning("Partial string render of %s return wrong length, "
			  "returned %d, should have returned %d",
			  str, ret1, i - 1);
	      goto error;
	    }
	  if (memcmp(str4, str3, i - 1) != 0)
	    {
	      ssh_warning("Partial string render of %s mismatch with len %d, "
			  "value = %s", str3, i, str4);
	      goto error;
	    }
	}
      else
	{
	  if (strcmp(str4, str3) != 0)
	    {
	      ssh_warning("Partial string render of %s mismatch with len %d, "
			  "value = %s", str3, i, str4);
	      goto error;
	    }
	}
    }

 out:
  ssh_free(str4);
  ssh_free(str3);
  ssh_free(str2);
  if (ts2)
    ssh_ikev2_ts_free(sad_handle, ts2);
  if (ts1)
    ssh_ikev2_ts_free(sad_handle, ts1);
  return TRUE;
 error:
  ssh_free(str4);
  ssh_free(str3);
  ssh_free(str2);
  if (ts2)
    ssh_ikev2_ts_free(sad_handle, ts2);
  if (ts1)
    ssh_ikev2_ts_free(sad_handle, ts1);
  return FALSE;
}

Boolean do_subtest(const char *str1, const char *str2, Boolean matching)
{
  SshIkev2PayloadTS ts1, ts2;
  int ret;

  ts1 = NULL;
  ts2 = NULL;

  ts1 = ssh_ikev2_ts_allocate(sad_handle);
  ts2 = ssh_ikev2_ts_allocate(sad_handle);

  ret = ssh_ikev2_string_to_ts(str1, ts1);
  if (ret == -1)
    {
      ssh_warning("String %s failed even when should have succeed", str1);
      goto error;
    }
  ret = ssh_ikev2_string_to_ts(str2, ts2);
  if (ret == -1)
    {
      ssh_warning("String %s failed even when should have succeed", str2);
      goto error;
    }
  ret = ssh_ikev2_ts_match(ts1, ts2);

  ssh_ikev2_ts_free(sad_handle, ts2);
  ssh_ikev2_ts_free(sad_handle, ts1);

  if (ret != matching)
    {
      ssh_warning("Strings %s <> %s return %s, should have returned %s",
		  str1, str2,
		  ret ? "TRUE" : "FALSE",
		  matching ? "TRUE" : "FALSE");
      return FALSE;
    }
  return TRUE;
 error:
  if (ts2)
    ssh_ikev2_ts_free(sad_handle, ts2);
  if (ts1)
    ssh_ikev2_ts_free(sad_handle, ts1);
  return FALSE;
}

Boolean do_narrowtest(const char *str1, const char *str2,
		      const char *intersection, Boolean success,
		      const char *uni, const char *exclude1,
		      const char *exclude2)
{
  SshIkev2PayloadTS ts1, ts2, int_ts1, int_ts2;
  SshIkev2PayloadTS uni_ts1, uni_ts2, excl_ts1, excl_ts2, excl_ts3, excl_ts4;
  SshIkev2Error error;
  int ret;

  ts1 = NULL;
  ts2 = NULL;
  int_ts1 = NULL;
  int_ts2 = NULL;
  uni_ts1 = NULL;
  uni_ts2 = NULL;
  excl_ts1 = NULL;
  excl_ts2 = NULL;
  excl_ts3 = NULL;
  excl_ts4 = NULL;

  ts1 = ssh_ikev2_ts_allocate(sad_handle);
  ts2 = ssh_ikev2_ts_allocate(sad_handle);
  int_ts1 = ssh_ikev2_ts_allocate(sad_handle);
  uni_ts1 = ssh_ikev2_ts_allocate(sad_handle);
  uni_ts2 = ssh_ikev2_ts_allocate(sad_handle);
  excl_ts1 = ssh_ikev2_ts_allocate(sad_handle);
  excl_ts2 = ssh_ikev2_ts_allocate(sad_handle);

  ret = ssh_ikev2_string_to_ts(str1, ts1);
  if (ret == -1)
    {
      ssh_warning("String %s failed even when should have succeed", str1);
      goto error;
    }
  ret = ssh_ikev2_string_to_ts(str2, ts2);
  if (ret == -1)
    {
      ssh_warning("String %s failed even when should have succeed", str2);
      goto error;
    }
  ret = ssh_ikev2_string_to_ts(intersection, int_ts1);
  if (ret == -1)
    {
      ssh_warning("String %s failed even when should have succeed",
		  intersection);
      goto error;
    }
  ret = ssh_ikev2_string_to_ts(uni, uni_ts1);
  if (ret == -1)
    {
      ssh_warning("String %s failed even when should have succeed",
		  uni);
      goto error;
    }
  ret = ssh_ikev2_string_to_ts(exclude1, excl_ts1);
  if (ret == -1)
    {
      ssh_warning("String %s failed even when should have succeed",
		  exclude1);
      goto error;
    }
  ret = ssh_ikev2_string_to_ts(exclude2, excl_ts2);
  if (ret == -1)
    {
      ssh_warning("String %s failed even when should have succeed",
		  exclude2);
      goto error;
    }

  error = ssh_ikev2_ts_union(sad_handle, uni_ts2, ts1);
  if (error != SSH_IKEV2_ERROR_OK)
    {
      ssh_warning("ts_union returned error %s",
		  ssh_ikev2_error_to_string(error));
      goto error;
    }
  error = ssh_ikev2_ts_union(sad_handle, uni_ts2, ts2);
  if (error != SSH_IKEV2_ERROR_OK)
    {
      ssh_warning("ts_union returned error %s",
		  ssh_ikev2_error_to_string(error));
      goto error;
    }
  if (!ssh_ikev2_ts_match(uni_ts1, uni_ts2) ||
      !ssh_ikev2_ts_match(uni_ts2, uni_ts1))
    {
      ssh_warning("Strings %s <> %s union return \n%@, "
		  "should have returned \n%@",
		  str1, str2,
		  ssh_ikev2_ts_render, uni_ts2,
		  ssh_ikev2_ts_render, uni_ts1);
      goto error;
    }

  excl_ts3 = ssh_ikev2_ts_dup(sad_handle, ts1);
  error = ssh_ikev2_ts_exclude(sad_handle, excl_ts3, ts2);
  if (error != SSH_IKEV2_ERROR_OK)
    {
      if (error != SSH_IKEV2_ERROR_INVALID_ARGUMENT ||
	  *exclude1 != ' ')
	{
	  ssh_warning("ts_exclude returned error %s",
		      ssh_ikev2_error_to_string(error));
	  goto error;
	}
    }
  if (!ssh_ikev2_ts_match(excl_ts1, excl_ts3) ||
      !ssh_ikev2_ts_match(excl_ts3, excl_ts1))
    {
      ssh_warning("Strings %s <> %s exclude return \n%@, "
		  "should have returned \n%@",
		  str1, str2,
		  ssh_ikev2_ts_render, excl_ts3,
		  ssh_ikev2_ts_render, excl_ts1);
      goto error;
    }

  excl_ts4 = ssh_ikev2_ts_dup(sad_handle, ts2);
  error = ssh_ikev2_ts_exclude(sad_handle, excl_ts4, ts1);
  if (error != SSH_IKEV2_ERROR_OK)
    {
      if (error != SSH_IKEV2_ERROR_INVALID_ARGUMENT ||
	  *exclude2 != ' ')
	{
	  ssh_warning("ts_exclude returned error %s",
		      ssh_ikev2_error_to_string(error));
	  goto error;
	}
    }
  if (!ssh_ikev2_ts_match(excl_ts2, excl_ts4) ||
      !ssh_ikev2_ts_match(excl_ts4, excl_ts2))
    {
      ssh_warning("Strings %s <> %s exclude return \n%@, "
		  "should have returned \n%@",
		  str2, str1,
		  ssh_ikev2_ts_render, excl_ts4,
		  ssh_ikev2_ts_render, excl_ts2);
      goto error;
    }

  ret = ssh_ikev2_ts_narrow(sad_handle, FALSE, &int_ts2, ts1, ts2);

  if (ret == TRUE && success == FALSE)
    {
      ssh_warning("Narrowing strings %s <> %s return traffic selector %@ "
                  "instead of fail",
		  str1, str2,
		  ssh_ikev2_ts_render, int_ts2);
      goto error;
    }
  else if (ret == FALSE && success == TRUE)
    {
      ssh_warning("Narrowing strings %s <> %s return error, "
                  "should have returned %@",
		  str1, str2,
		  ssh_ikev2_ts_render, int_ts1);
      goto error;
    }
  else if (ret &&
	   (!ssh_ikev2_ts_match(int_ts1, int_ts2) ||
	    !ssh_ikev2_ts_match(int_ts2, int_ts1)))
    {
      ssh_warning("Strings %s <> %s return \n%@, should have returned \n%@",
		  str1, str2,
		  ssh_ikev2_ts_render, int_ts2,
		  ssh_ikev2_ts_render, int_ts1);
      goto error;
    }

  ssh_ikev2_ts_free(sad_handle, excl_ts4);
  ssh_ikev2_ts_free(sad_handle, excl_ts3);
  ssh_ikev2_ts_free(sad_handle, excl_ts2);
  ssh_ikev2_ts_free(sad_handle, excl_ts1);
  ssh_ikev2_ts_free(sad_handle, uni_ts2);
  ssh_ikev2_ts_free(sad_handle, uni_ts1);
  if (int_ts2)
    ssh_ikev2_ts_free(sad_handle, int_ts2);
  ssh_ikev2_ts_free(sad_handle, int_ts1);
  ssh_ikev2_ts_free(sad_handle, ts2);
  ssh_ikev2_ts_free(sad_handle, ts1);
  return TRUE;

 error:
  if (excl_ts4)
    ssh_ikev2_ts_free(sad_handle, excl_ts4);
  if (excl_ts3)
    ssh_ikev2_ts_free(sad_handle, excl_ts3);
  if (excl_ts2)
    ssh_ikev2_ts_free(sad_handle, excl_ts2);
  if (excl_ts1)
    ssh_ikev2_ts_free(sad_handle, excl_ts1);
  if (uni_ts2)
    ssh_ikev2_ts_free(sad_handle, uni_ts2);
  if (uni_ts1)
    ssh_ikev2_ts_free(sad_handle, uni_ts1);
  if (int_ts2)
    ssh_ikev2_ts_free(sad_handle, int_ts2);
  if (int_ts1)
    ssh_ikev2_ts_free(sad_handle, int_ts1);
  if (ts2)
    ssh_ikev2_ts_free(sad_handle, ts2);
  if (ts1)
    ssh_ikev2_ts_free(sad_handle, ts1);
  return FALSE;
}

#define TEST(_str,_success) if (!do_test(_str, _success)) failed++; else
#define SUBTEST(_str1,_str2,_success) \
  if (!do_subtest(_str1,_str2,_success)) failed++; else
#define SET(_str1,_str2,_int,_success, _union,_excl1,_excl2) \
  if (!do_narrowtest((_str1),(_str2),(_int),(_success),(_union),\
		     (_excl1),(_excl2))) \
    failed++; else

Boolean test(void)
{
  int failed = FALSE;

#if 0
  for (i = 16; i < 128; i++)
    {
      TEST2("ipv4(tcp:12345,[0..8]=192.168.210.128)", i);
      TEST2("ipv4_range(tcp:12345,[0..8]=192.168.210.128-192.168.211.233)", i);
      TEST2("ipv4_subnet(tcp:12345,192.168.210.0/25)", i);
      TEST2("ipv6(tcp:12345,[0..32]=3ffe:501:ffff::33)", i);
      TEST2("ipv6_range(tcp:12345,[0..32]=3ffe:501:ffff::33"
            "-3ffe:501:ffff::ff)", i);
      TEST2("ipv6_subnet(tcp:12345,3ffe:501:ffff::33/64)", i);
      TEST2("fqdn(tcp:12345,veryveryveryveryveryvery.longish.host.fi)", i);
      TEST2("usr@fqdn(tcp:12345,tmo@veryveryveryveryvery.longish.host.fi)", i);
    }
#endif
  TEST("ipv4()", FALSE);
  TEST("ipv4(udp:500,)", FALSE);
  TEST("ipv4(,192.168.2.1)", TRUE);
  TEST("ipv4(udp,192.168.2.255)", TRUE);
  TEST("ipv4(udp:0,192.168.2.255)", TRUE);
  TEST("ipv4(192.168.2.1)", TRUE);
  TEST("ipv4(tcp:1234,192.168.2.1)", TRUE);
  TEST("ipv4(tcp:1234-5678,192.168.2.1)", TRUE);

  TEST("ipv4(192.168.2.0/)", FALSE);
  TEST("ipv4(192.168.2.0/24)", TRUE);
  TEST("ipv4(192.168.2.0/-24)", FALSE);
  TEST("ipv4(192.168.2.1-192.168.2.2)", TRUE);

  TEST("ipv4(192.168.2.1-)", FALSE); /* means till 0.0.0.0 */
  TEST("ipv4(192.168.2.1-192.168.3.1)", TRUE);
  TEST("ipv4(192.168.2.1/22)", TRUE);

#ifdef WITH_IPV6
  TEST("ipv6()", FALSE);
  TEST("ipv6(udp:500,)", FALSE);
  TEST("ipv6(,3ffe:501:ffff::33)", TRUE);
  TEST("ipv6(udp,3ffe:501:ffff::33)", TRUE);
  TEST("ipv6(3ffe:501:ffff::33)", TRUE);
  TEST("ipv6(tcp:1234,3ffe:501:ffff::33)", TRUE);

  TEST("ipv6(3ffe:501:ffff::33)", TRUE);
  TEST("ipv6(3ffe:501:ffff::33/)", FALSE);
  TEST("ipv6(3ffe:501:ffff::33/64)", TRUE);
  TEST("ipv6(3ffe:501:ffff::33/-64)", FALSE);
  TEST("ipv6(3ffe:501:ffff::33-3ffe:501:ffff::34)", TRUE);

  TEST("ipv6(3ffe:501:ffff::33)", TRUE);
  TEST("ipv6(3ffe:501:ffff::33-)", FALSE); /* means till ::0 */
  TEST("ipv6(3ffe:501:ffff::33-3ffe:501:ffff::34)", TRUE);
  TEST("ipv6(3ffe:501:ffff::33/22)", TRUE);
  TEST("ipv6(3ffe:501:ffff::33-3ffe:501:ffff::34),"
       "ipv4(192.168.2.1-192.168.3.1)", TRUE);
  TEST("ipv6(udp:500-500,3ffe:501:ffff::33-3ffe:501:ffff::33),"
       "ipv6(3ffe:501:ffff::33-3ffe:501:ffff::34),"
       "ipv6(3ffe:501:ff00::00-3ffe:501:ff01::ffff),"
       "ipv4(192.168.2.1-192.168.3.1)", TRUE);
  TEST("ipv6(udp:500-500,3ffe:501:ffff::33-3ffe:501:ffff::33),"
       "ipv6(3ffe:501:ffff::33-3ffe:501:ffff::34),"
       "ipv6(3ffe:501:ff00::00-3ffe:501:ff01::ffff),"
       "ipv4(192.168.2.1-192.168.3.1),"
       "ipv6(tcp:500-500,3ffe:501:ffff::33-3ffe:501:ffff::33),"
       "ipv6(3fff:501:ffff::33-3fff:501:ffff::34),"
       "ipv6(3ffe:502:ff00::00-3ffe:502:ff01::ffff),"
       "ipv4(192.169.2.1-192.169.3.1)", TRUE);
#else /* WITH_IPV6 */
  TEST("ipv6(,3ffe:501:ffff::33)", FALSE);
  TEST("ipv6(udp,3ffe:501:ffff::33)", FALSE);
  TEST("ipv6(3ffe:501:ffff::33)", FALSE);
  TEST("ipv6(tcp:1234,3ffe:501:ffff::33)", FALSE);
  TEST("ipv6(3ffe:501:ffff::33)", FALSE);
  TEST("ipv6(3ffe:501:ffff::33/)", FALSE);
  TEST("ipv6(3ffe:501:ffff::33/64)", FALSE);
  TEST("ipv6(3ffe:501:ffff::33/-64)", FALSE);
  TEST("ipv6(3ffe:501:ffff::33-3ffe:501:ffff::34)", FALSE);
  TEST("ipv6(3ffe:501:ffff::33)", FALSE);
  TEST("ipv6(3ffe:501:ffff::33-)", FALSE); /* means till ::0 */
  TEST("ipv6(3ffe:501:ffff::33-3ffe:501:ffff::34)", FALSE);
  TEST("ipv6(3ffe:501:ffff::33/22)", FALSE);
  TEST("ipv6(3ffe:501:ffff::33-3ffe:501:ffff::34),"
       "ipv4(192.168.2.1-192.168.3.1)", FALSE);
  TEST("ipv6(udp:500-500,3ffe:501:ffff::33-3ffe:501:ffff::33),"
       "ipv6(3ffe:501:ffff::33-3ffe:501:ffff::34),"
       "ipv6(3ffe:501:ff00::00-3ffe:501:ff01::ffff),"
       "ipv4(192.168.2.1-192.168.3.1)", FALSE);
  TEST("ipv6(udp:500-500,3ffe:501:ffff::33-3ffe:501:ffff::33),"
       "ipv6(3ffe:501:ffff::33-3ffe:501:ffff::34),"
       "ipv6(3ffe:501:ff00::00-3ffe:501:ff01::ffff),"
       "ipv4(192.168.2.1-192.168.3.1),"
       "ipv6(tcp:500-500,3ffe:501:ffff::33-3ffe:501:ffff::33),"
       "ipv6(3fff:501:ffff::33-3fff:501:ffff::34),"
       "ipv6(3ffe:502:ff00::00-3ffe:502:ff01::ffff),"
       "ipv4(192.169.2.1-192.169.3.1)", FALSE);
#endif /* WITH_IPV6 */
  TEST("ipv4(opaque,1.2.3.4-2.3.4.5)",TRUE);

  /* Test that we can add whitespace before and after any token. */
  TEST("  ipv4   (   ,   192.168.2.1  )   ", TRUE);
  TEST("    ipv4   (   udp  ,   192.168.2.255  )  ", TRUE);
  TEST("   ipv4  (   192.168.2.1  )  ", TRUE);
  TEST("  ipv4  (  tcp    : 1234    ,    192.168.2.1   )  ", TRUE);
  TEST("  ipv4  (   tcp   :    1234    -    5678    ,  192.168.2.1 ) ", TRUE);

  TEST("  ipv4 (  192.168.2.0  /  ) ", FALSE);
  TEST(" ipv4 ( 192.168.2.0 / 24 ) ", TRUE);
  TEST(" ipv4 ( 192.168.2.1 - 192.168.2.2 ) ", TRUE);

  TEST(" ipv4 ( 192.168.2.1 - 192.168.3.1 ) ", TRUE);
#ifdef WITH_IPV6
  TEST("  ipv6  (  ,   3ffe:501:ffff::33  )  ", TRUE);
  TEST("  ipv6 ( udp , 3ffe:501:ffff::33  ) ", TRUE);
  TEST("    ipv6 (  3ffe:501:ffff::33 ) ", TRUE);
  TEST("\tipv6\t(\ttcp\t:\t1234\t,\t3ffe:501:ffff::33\t)\t", TRUE);

  TEST(" \t ipv6 \t ( \t 3ffe:501:ffff::33 \t / \t ) \t ", FALSE);
  TEST("  ipv6(  3ffe:501:ffff::33 / 64 ) ", TRUE);

  TEST("   ipv6(3ffe:501:ffff::33   -  3ffe:501:ffff::34 ) ", TRUE);
#else /* WITH_IPV6 */
  TEST("  ipv6  (  ,   3ffe:501:ffff::33  )  ", FALSE);
  TEST("  ipv6 ( udp , 3ffe:501:ffff::33  ) ", FALSE);
  TEST("    ipv6 (  3ffe:501:ffff::33 ) ", FALSE);
  TEST("\tipv6\t(\ttcp\t:\t1234\t,\t3ffe:501:ffff::33\t)\t", FALSE);
  TEST(" \t ipv6 \t ( \t 3ffe:501:ffff::33 \t / \t ) \t ", FALSE);
  TEST("  ipv6(  3ffe:501:ffff::33 / 64 ) ", FALSE);
  TEST("   ipv6(3ffe:501:ffff::33   -  3ffe:501:ffff::34 ) ", FALSE);
#endif /* WITH_IPV6 */
  TEST("something()", FALSE);
  TEST("no id", FALSE);
  TEST("", TRUE);
  TEST("unknown(udp:500,foobar)", FALSE);

  /* syntax cases */
  TEST("ipv4(udp,1,192.168.2.1)", FALSE);
  TEST("ipv4(udp,1:192.168.2.1)", FALSE);
  TEST("ipv4(udp,1,192.168.2.1/24)", FALSE);
  TEST("ipv4(,1,192.168.2.1/24)", FALSE);
  TEST("ipv4(,1:192.168.2.1/24)", FALSE);
  TEST("ipv4(udp,1,192.168.2.1-192.162.1.2)", FALSE);

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

  SUBTEST("ipv4(10.0.0.0-10.0.255.255)",
	  "ipv4(opaque,10.0.255.0-10.0.255.255)",
	  FALSE);
  SUBTEST("ipv4(1.2.3.4-2.3.4.5)",
	  "ipv4(1.2.3.4-2.3.4.5)",
	  TRUE);
  SUBTEST("ipv4(1.2.3.4-2.3.4.5)",
	  "ipv4(1.2.3.4-2.3.4.4)",
	  TRUE);
  SUBTEST("ipv4(1.2.3.4-2.3.4.5)",
	  "ipv4(1.2.3.5-2.3.4.5)",
	  TRUE);
  SUBTEST("ipv4(1.2.3.4-2.3.4.5)",
	  "ipv4(1.2.3.4)",
	  TRUE);
  SUBTEST("ipv4(1.2.3.4-2.3.4.5)",
	  "ipv4(2.3.4.5)",
	  TRUE);
  SUBTEST("ipv4(1.2.3.4-2.3.4.5)",
	  "ipv4(2.3.4.6)",
	  FALSE);
  SUBTEST("ipv4(1.2.3.4-2.3.4.5)",
	  "ipv4(1.2.3.3)",
	  FALSE);
  SUBTEST("ipv4(10.0.0.0-10.0.255.255)",
	  "ipv4(1.2.3.3)",
	  FALSE);
  SUBTEST("ipv4(10.0.0.0-10.0.255.255)",
	  "ipv4(udp,10.0.0.0-10.0.255.255)",
	  TRUE);
  SUBTEST("ipv4(10.0.0.0-10.0.255.255)",
	  "ipv4(tcp:any,10.0.2.0-10.0.2.255)",
	  TRUE);
  SUBTEST("ipv4(10.0.0.0-10.0.255.255)",
	  "ipv4(tcp:22-22,10.0.2.0-10.0.2.255)",
	  TRUE);
  SUBTEST("ipv4(10.0.0.0-10.0.255.255)",
	  "ipv4(tcp:22-65535,10.0.255.0-10.0.255.255)",
	  TRUE);
  SUBTEST("ipv4(tcp:any,10.0.0.0-10.0.255.255)",
	  "ipv4(tcp:22-65535,10.0.255.0-10.0.255.255)",
	  TRUE);
  SUBTEST("ipv4(tcp:22-2222,10.0.0.0-10.0.255.255)",
	  "ipv4(tcp:22-2222,10.0.255.0-10.0.255.255)",
	  TRUE);
  SUBTEST("ipv4(tcp:22-2222,10.0.0.0-10.0.255.255)",
	  "ipv4(udp:22-2222,10.0.255.0-10.0.255.255)",
	  FALSE);
  SUBTEST("ipv4(udp:22-2222,10.0.0.0-10.0.255.255)",
	  "ipv4(udp:21-2222,10.0.255.0-10.0.255.255)",
	  FALSE);
  SUBTEST("ipv4(udp:22-2222,10.0.0.0-10.0.255.255)",
	  "ipv4(udp:22-2223,10.0.255.0-10.0.255.255)",
	  FALSE);
  SUBTEST("ipv4(10.0.0.0-10.0.255.255)",
	  "ipv4(opaque,10.0.255.0-10.0.255.255)",
	  FALSE);
  SUBTEST("ipv4(opaque,10.0.0.0-10.0.255.255)",
	  "ipv4(opaque,10.0.255.0-10.0.255.255)",
	  TRUE);

#ifdef WITH_IPV6
  SUBTEST("ipv6(3ffe::1.2.3.4-3ffe::2.3.4.5)",
	  "ipv6(3ffe::1.2.3.4-3ffe::2.3.4.5)",
	  TRUE);
  SUBTEST("ipv6(3ffe::1.2.3.4-3ffe::2.3.4.5)",
	  "ipv6(3ffe::1.2.3.4-3ffe::2.3.4.4)",
	  TRUE);
  SUBTEST("ipv6(3ffe::1.2.3.4-3ffe::2.3.4.5)",
	  "ipv6(3ffe::1.2.3.5-3ffe::2.3.4.5)",
	  TRUE);
  SUBTEST("ipv6(3ffe::1.2.3.4-3ffe::2.3.4.5)",
	  "ipv6(3ffe::1.2.3.4)",
	  TRUE);
  SUBTEST("ipv6(3ffe::1.2.3.4-3ffe::2.3.4.5)",
	  "ipv6(3ffe::2.3.4.5)",
	  TRUE);
  SUBTEST("ipv6(3ffe::1.2.3.4-3ffe::2.3.4.5)",
	  "ipv6(3ffe::2.3.4.6)",
	  FALSE);
  SUBTEST("ipv6(3ffe::1.2.3.4-3ffe::2.3.4.5)",
	  "ipv6(3ffe::1.2.3.3)",
	  FALSE);
  SUBTEST("ipv6(3ffe::10.0.0.0-3ffe::10.0.255.255)",
	  "ipv6(3ffe::1.2.3.3)",
	  FALSE);
  SUBTEST("ipv6(3ffe::10.0.0.0-3ffe::10.0.255.255)",
	  "ipv6(udp,3ffe::10.0.0.0-3ffe::10.0.255.255)",
	  TRUE);
  SUBTEST("ipv6(3ffe::10.0.0.0-3ffe::10.0.255.255)",
	  "ipv6(tcp:any,3ffe::10.0.2.0-3ffe::10.0.2.255)",
	  TRUE);
  SUBTEST("ipv6(3ffe::10.0.0.0-3ffe::10.0.255.255)",
	  "ipv6(tcp:22-22,3ffe::10.0.2.0-3ffe::10.0.2.255)",
	  TRUE);
  SUBTEST("ipv6(3ffe::10.0.0.0-3ffe::10.0.255.255)",
	  "ipv6(tcp:22-65535,3ffe::10.0.255.0-3ffe::10.0.255.255)",
	  TRUE);
  SUBTEST("ipv6(tcp:any,3ffe::10.0.0.0-3ffe::10.0.255.255)",
	  "ipv6(tcp:22-65535,3ffe::10.0.255.0-3ffe::10.0.255.255)",
	  TRUE);
  SUBTEST("ipv6(tcp:22-2222,3ffe::10.0.0.0-3ffe::10.0.255.255)",
	  "ipv6(tcp:22-2222,3ffe::10.0.255.0-3ffe::10.0.255.255)",
	  TRUE);
  SUBTEST("ipv6(tcp:22-2222,3ffe::10.0.0.0-3ffe::10.0.255.255)",
	  "ipv6(udp:22-2222,3ffe::10.0.255.0-3ffe::10.0.255.255)",
	  FALSE);
  SUBTEST("ipv6(udp:22-2222,3ffe::10.0.0.0-3ffe::10.0.255.255)",
	  "ipv6(udp:21-2222,3ffe::10.0.255.0-3ffe::10.0.255.255)",
	  FALSE);
  SUBTEST("ipv6(udp:22-2222,3ffe::10.0.0.0-3ffe::10.0.255.255)",
	  "ipv6(udp:22-2223,3ffe::10.0.255.0-3ffe::10.0.255.255)",
	  FALSE);
  SUBTEST("ipv6(3ffe::10.0.0.0-3ffe::10.0.255.255)",
	  "ipv6(opaque,3ffe::10.0.255.0-3ffe::10.0.255.255)",
	  FALSE);
  SUBTEST("ipv6(opaque,3ffe::10.0.0.0-3ffe::10.0.255.255)",
	  "ipv6(opaque,3ffe::10.0.255.0-3ffe::10.0.255.255)",
	  TRUE);
  SUBTEST("ipv6(udp:500-500,3ffe:501:ffff::33-3ffe:501:ffff::33),"
	  "ipv6(3ffe:501:ffff::33-3ffe:501:ffff::34),"
	  "ipv6(3ffe:501:ff00::00-3ffe:501:ff01::ffff),"
	  "ipv4(192.168.2.1-192.168.3.1)",
	  "ipv6(udp:500-500,3ffe:501:ffff::33-3ffe:501:ffff::33),"
	  "ipv6(3ffe:501:ffff::33-3ffe:501:ffff::34),"
	  "ipv6(3ffe:501:ff00::00-3ffe:501:ff01::ffff),"
	  "ipv4(192.168.2.1-192.168.3.1)",
	  TRUE);
  SUBTEST("ipv6(udp:500-500,3ffe:501:ffff::33-3ffe:501:ffff::33),"
	  "ipv6(3ffe:501:ffff::33-3ffe:501:ffff::34),"
	  "ipv6(3ffe:501:ff00::00-3ffe:501:ff01::ffff),"
	  "ipv4(192.168.2.1-192.168.3.1)",
	  "ipv6(udp:500-500,3ffe:501:ffff::33-3ffe:501:ffff::33),"
	  "ipv6(3ffe:501:ffff::33-3ffe:501:ffff::34),"
	  "ipv6(3ffe:501:ff00::00-3ffe:501:ff01::ffff),"
	  "ipv4(192.168.2.1-192.168.2.22)",
	  TRUE);
  SUBTEST("ipv6(udp:500-500,3ffe:501:ffff::33-3ffe:501:ffff::33),"
	  "ipv6(3ffe:501:ffff::33-3ffe:501:ffff::34),"
	  "ipv6(3ffe:501:ff00::00-3ffe:501:ff01::ffff),"
	  "ipv4(192.168.2.1-192.168.3.1)",
	  "ipv6(udp:500-500,3ffe:501:ffff::33-3ffe:501:ffff::33),"
	  "ipv6(3ffe:501:ffff::33-3ffe:501:ffff::34),"
	  "ipv6(3ffe:501:ff00::00-3ffe:501:ff01::ffff)",
	  TRUE);
  SUBTEST("ipv6(udp:500-500,3ffe:501:ffff::33-3ffe:501:ffff::33),"
	  "ipv6(3ffe:501:ffff::33-3ffe:501:ffff::34),"
	  "ipv6(3ffe:501:ff00::00-3ffe:501:ff01::ffff),"
	  "ipv4(192.168.2.1-192.168.3.1)",
	  "ipv6(udp:500-500,3ffe:501:ffff::33-3ffe:501:ffff::33),"
	  "ipv6(3ffe:501:ffff::33-3ffe:501:ffff::34),"
	  "ipv6(3ffe:501:ff00::00-3ffe:501:ff01::100)",
	  TRUE);
  SUBTEST("ipv6(udp:500-500,3ffe:501:ffff::33-3ffe:501:ffff::33),"
	  "ipv6(3ffe:501:ffff::33-3ffe:501:ffff::34),"
	  "ipv6(3ffe:501:ff00::00-3ffe:501:ff01::ffff),"
	  "ipv4(192.168.2.1-192.168.3.1)",
	  "ipv6(udp:500-500,3ffe:501:ffff::33-3ffe:501:ffff::33),"
	  "ipv6(udp,3ffe:501:ffff::33-3ffe:501:ffff::34),"
	  "ipv6(3ffe:501:ff00::00-3ffe:501:ff01::100)",
	  TRUE);
  SUBTEST("ipv6(udp:500-500,3ffe:501:ffff::33-3ffe:501:ffff::33),"
	  "ipv6(3ffe:501:ffff::33-3ffe:501:ffff::34),"
	  "ipv6(3ffe:501:ff00::00-3ffe:501:ff01::ffff),"
	  "ipv4(192.168.2.1-192.168.3.1)",
	  "ipv6(udp,3ffe:501:ffff::33-3ffe:501:ffff::34),"
	  "ipv6(3ffe:501:ff00::00-3ffe:501:ff01::100)",
	  TRUE);
  SUBTEST("ipv6(udp:500-500,3ffe:501:ffff::33-3ffe:501:ffff::33),"
	  "ipv6(3ffe:501:ffff::33-3ffe:501:ffff::34),"
	  "ipv6(3ffe:501:ff00::00-3ffe:501:ff01::ffff),"
	  "ipv4(192.168.2.1-192.168.3.1)",
	  "ipv6(udp,3ffe:501:ffff::33-3ffe:501:ffff::34)",
	  TRUE);
  SUBTEST("ipv6(udp:500-500,3ffe:501:ffff::33-3ffe:501:ffff::33),"
	  "ipv6(3ffe:501:ffff::33-3ffe:501:ffff::34),"
	  "ipv6(3ffe:501:ff00::00-3ffe:501:ff01::ffff),"
	  "ipv4(192.168.2.1-192.168.3.1)",
	  "ipv6(udp:500,3ffe:501:ffff::33-3ffe:501:ffff::34)",
	  TRUE);
  SUBTEST("ipv6(udp:500-500,3ffe:501:ffff::33-3ffe:501:ffff::33),"
	  "ipv6(3ffe:501:ffff::33-3ffe:501:ffff::34),"
	  "ipv6(3ffe:501:ff00::00-3ffe:501:ff01::ffff),"
	  "ipv4(192.168.2.1-192.168.3.1)",
	  "ipv6(udp:500,3ffe:501:ffff::33)",
	  TRUE);
  SUBTEST("ipv6(udp:500-500,3ffe:501:ffff::33-3ffe:501:ffff::33),"
	  "ipv6(3ffe:501:ffff::33-3ffe:501:ffff::34),"
	  "ipv6(3ffe:501:ff00::00-3ffe:501:ff01::ffff),"
	  "ipv4(192.168.2.1-192.168.3.1)",
	  "ipv6(udp:500,3ffe:501:ffff::32)",
	  FALSE);
#endif /* WITH_IPV6 */

  /*
    SET(traffic_selector1,
        traffic_selector2,
        narrowed_selectors,
        narrowing_success,
        selector_union,
        exclude_2_from_1,
        exclude_1_from_2);
   */

  SET("ipv4(10.0.0.0/24)",
      "ipv4(10.0.0.0-10.0.0.255)",
      "ipv4(10.0.0.0-10.0.0.255)",
      TRUE,
      "ipv4(10.0.0.0/24)",
      "",
      "");

  SET(
      "ipv4(192.168.2.50-192.168.2.150),ipv4(192.168.2.170-192.168.2.200)",
      "ipv4(192.168.2.100-192.168.2.200)",
      "ipv4(192.168.2.100-192.168.2.150),ipv4(192.168.2.170-192.168.2.200)",
      TRUE,
      "ipv4(192.168.2.50-192.168.2.200)",
      "ipv4(192.168.2.50-192.168.2.99)",
      "ipv4(192.168.2.151-192.168.2.169)"
      );


  SET("ipv4(10.0.0.5),ipv4(10.0.0.0-10.0.0.255)",
      "ipv4(10.0.0.3-10.0.0.200)",
      "ipv4(10.0.0.3-10.0.0.200)",
      TRUE,
      "ipv4(10.0.0.0-10.0.0.255)",
      "ipv4(10.0.0.0-10.0.0.2),ipv4(10.0.0.201-10.0.0.255)",
      "");
  SET("ipv4(10.0.0.5),ipv4(10.0.0.0-10.0.0.100)",
      "ipv4(10.0.0.3-10.0.0.200)",
      "ipv4(10.0.0.3-10.0.0.100)",
      TRUE,
      "ipv4(10.0.0.0-10.0.0.200)",
      "ipv4(10.0.0.0-10.0.0.2)",
      "ipv4(10.0.0.101-10.0.0.200)");
  SET("ipv4(tcp:22,10.0.0.5),ipv4(tcp,10.0.0.0-10.0.0.100)",
      "ipv4(10.0.0.3-10.0.0.50),ipv4(10.0.0.70-10.0.0.255)",
      "ipv4(tcp,10.0.0.3-10.0.0.50),ipv4(tcp,10.0.0.70-10.0.0.100)",
      TRUE,
      "ipv4(tcp,10.0.0.0-10.0.0.100),ipv4(10.0.0.3-10.0.0.50),"
      "ipv4(10.0.0.70-10.0.0.255)",
      "ipv4(tcp,10.0.0.0-10.0.0.2),ipv4(tcp,10.0.0.51-10.0.0.69)",
      " ipv4(10.0.0.101-10.0.0.255)");
  SET("ipv4(tcp:22,10.0.0.90),ipv4(tcp,10.0.0.0-10.0.0.100)",
      "ipv4(10.0.0.3-10.0.0.50),ipv4(10.0.0.70-10.0.0.255)",
      "ipv4(tcp,10.0.0.70-10.0.0.100),ipv4(tcp,10.0.0.3-10.0.0.50)",
      TRUE,
      "ipv4(tcp,10.0.0.0-10.0.0.100),ipv4(10.0.0.3-10.0.0.50),"
      "ipv4(10.0.0.70-10.0.0.255)",
      "ipv4(tcp,10.0.0.0-10.0.0.2),ipv4(tcp,10.0.0.51-10.0.0.69)",
      " ipv4(10.0.0.101-10.0.0.255)");
  SET("ipv4(tcp:22,10.0.0.90),ipv4(10.0.0.0-10.0.0.100)",
      "ipv4(10.0.0.3-10.0.0.50),ipv4(10.0.0.70-10.0.0.255)",
      "ipv4(10.0.0.70-10.0.0.100),ipv4(10.0.0.3-10.0.0.50)",
      TRUE,
      "ipv4(10.0.0.0-10.0.0.255)",
      "ipv4(10.0.0.0-10.0.0.2),ipv4(10.0.0.51-10.0.0.69)",
      " ipv4(10.0.0.101-10.0.0.255)");

  SET("ipv4(192.168.0.1)",
      "ipv4(192.168.0.1)",
      "ipv4(192.168.0.1)",
      TRUE,
      "ipv4(192.168.0.1)",
      "",
      "");

  SET("ipv4(192.168.0.11),ipv4(192.168.0.1)",
      "ipv4(192.168.0.1)",
      "ipv4(192.168.0.1)",
      TRUE,
      "ipv4(192.168.0.11),ipv4(192.168.0.1)",
      "ipv4(192.168.0.11)",
      "");

  SET("ipv4(192.168.0.11)",
      "ipv4(192.168.0.1)",
      "",
      FALSE,
      "ipv4(192.168.0.11),ipv4(192.168.0.1)",
      "ipv4(192.168.0.11)",
      "ipv4(192.168.0.1)");

  SET("ipv4(192.168.0.1),ipv4(192.168.0.3),ipv4(192.168.0.5)",
      "ipv4(192.168.0.1)",
      "ipv4(192.168.0.1)",
      TRUE,
      "ipv4(192.168.0.1),ipv4(192.168.0.3),ipv4(192.168.0.5)",
      "ipv4(192.168.0.3),ipv4(192.168.0.5)",
      "");

  SET("ipv4(192.168.0.1),ipv4(192.168.0.3),ipv4(192.168.0.5)",
      "ipv4(192.168.0.5)",
      "ipv4(192.168.0.5)",
      TRUE,
      "ipv4(192.168.0.1),ipv4(192.168.0.3),ipv4(192.168.0.5)",
      "ipv4(192.168.0.1),ipv4(192.168.0.3)",
      "");


#ifdef WITH_IPV6
  SET("ipv4(192.168.0.1),ipv6(2001::)",
      "ipv4(192.168.0.1)",
      "ipv4(192.168.0.1)",
      TRUE,
      "ipv4(192.168.0.1),ipv6(2001::)",
      "ipv6(2001::)",
      "");

  SET("ipv6(2001::),ipv4(192.168.0.1)",
      "ipv4(192.168.0.1)",
      "ipv4(192.168.0.1)",
      TRUE,
      "ipv4(192.168.0.1),ipv6(2001::)",
      "ipv6(2001::)",
      "");
  
  SET("ipv6(::-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff),"
      "ipv4(0.0.0.0-255.255.255.255)",
      "ipv4(192.168.0.1)",
      "ipv4(192.168.0.1)",
      TRUE,
      "ipv6(::-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff),"
      "ipv4(0.0.0.0-255.255.255.255)",
      "ipv6(::-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff),"
      "ipv4(192.168.0.2-255.255.255.255),ipv4(0.0.0.0-192.168.0.0)",
      "");

#endif /* WITH_IPV6 */

#if 0
  SET("ipv4(tcp:22,10.0.0.90),ipv4(tcp:0-1023,10.0.0.0-10.0.0.100)",
      "ipv4(10.0.0.3-10.0.0.50),ipv4(10.0.0.70-10.0.0.255)",
      "ipv4(tcp:0-1023,10.0.0.70-10.0.0.100)"
      ",ipv4(tcp:0-1023,10.0.0.3-10.0.0.50)",
      TRUE,
      "ipv4(tcp:0-1023,10.0.0.0-10.0.0.100),ipv4(10.0.0.3-10.0.0.50),"
      "ipv4(10.0.0.70-10.0.0.255)",
      "ipv4(tcp:0-1023,10.0.0.0-10.0.0.2),"
      "ipv4(tcp:0-1023,10.0.0.51-10.0.0.69)",
      " ipv4(10.0.0.101-10.0.0.255)");
  SET("ipv4(tcp:22,10.0.0.90),ipv4(tcp:0-1023,10.0.0.0-10.0.0.100)",
      "ipv4(tcp:22,10.0.0.3-10.0.0.50),ipv4(tcp:2-99,10.0.0.70-10.0.0.255)",
      "ipv4(tcp:2-99,10.0.0.70-10.0.0.100),ipv4(tcp:22,10.0.0.3-10.0.0.50)",
      TRUE);
  SET("ipv4(tcp:22,10.0.0.9),ipv4(tcp:0-1023,10.0.0.0-10.0.0.100)",
      "ipv4(tcp:22,10.0.0.3-10.0.0.50),ipv4(tcp:2-99,10.0.0.70-10.0.0.255)",
      "ipv4(tcp:22,10.0.0.3-10.0.0.50),ipv4(tcp:2-99,10.0.0.70-10.0.0.100)",
      TRUE);
  SET("ipv6(tcp:22,2000::10.0.0.9)"
      ",ipv6(tcp:0-1023,2000::10.0.0.0-2000::10.0.0.100)",
      "ipv6(tcp:22,2000::10.0.0.3-2000::10.0.0.50)"
      ",ipv6(tcp:2-99,2000::10.0.0.70-2000::10.0.0.255)",
      "ipv6(tcp:22,2000::10.0.0.3-2000::10.0.0.50)"
      ",ipv6(tcp:2-99,2000::10.0.0.70-2000::10.0.0.100)",
      TRUE);
  SET("ipv4(10.0.0.20-10.0.0.30)",
      "ipv4(10.0.0.22-10.0.0.28)",
      "ipv4(10.0.0.22-10.0.0.28)",
      TRUE);

  SET("ipv4(0.0.0.0-255.255.255.255)",
      "ipv4(10.0.0.0-10.0.0.255),ipv4(192.168.2.1)",
      "ipv4(10.0.0.0-10.0.0.255),ipv4(192.168.2.1)",
      TRUE);
  SET("ipv4(tcp,0.0.0.0-255.255.255.255)",
      "ipv4(10.0.0.0-10.0.0.255),ipv4(192.168.2.1)",
      "ipv4(tcp,10.0.0.0-10.0.0.255),ipv4(tcp,192.168.2.1)",
      TRUE);
  SET("ipv4(tcp,0.0.0.0-255.255.255.255)",
      "ipv4(10.0.0.0-10.0.0.255),ipv4(udp,192.168.2.1)",
      "ipv4(tcp,10.0.0.0-10.0.0.255)",
      TRUE);
  SET("ipv4(tcp:22-1111,0.0.0.0-255.255.255.255)",
      "ipv4(tcp:1024-65535,10.0.0.0-10.0.0.255),"
      "ipv4(tcp:0-555,192.168.2.1)",
      "ipv4(tcp:1024-1111,10.0.0.0-10.0.0.255),"
      "ipv4(tcp:22-555,192.168.2.1)",
      TRUE);

#endif
  return failed == 0;
}

int
main(int argc, char **argv)
{
  sad_handle = ssh_xcalloc(1, sizeof(sad_handle));

  if (!ssh_ikev2_ts_freelist_create(sad_handle))
    ssh_fatal("ts_freelist_create failed");

  if (!test())
    {
      printf("ERROR Test FAILED.\n");
      exit(1);
    }

  printf("Test Ok.\n");

  ssh_ikev2_ts_freelist_destroy(sad_handle);
  ssh_free(sad_handle);










  return 0;
}
