/*
  File: t-icmp-util.c

  Description:
        Tests for ICMP utils

  Copyright:
        Copyright (c) 2005 SFNT Finland Oy.
        All rights reserved
*/

#include "sshincludes.h"
#include "sshinet.h"
#include "sshicmp-util.h"

static int verbose;

int run_test(char *test_id, const char *string, const char *result)
{
  char *result_string = 
    ssh_icmputil_string_to_tsstring(string);
  int ret = 0;

  if (result_string == NULL && result == NULL)
    ret = 1;
  else if ((result_string != NULL && result != NULL) &&
	   strcmp(result_string, result) == 0)
    ret = 1;
  else
    ret = 0;

  if (ret && verbose > 2)
    printf("Test <%s> OK:\n'%s' -> '%s'\n", 
	   test_id, string, result_string);    
  else if (ret && verbose > 1)
    printf("Test <%s> OK\n", test_id);
  else if (!ret && verbose > 0)
    printf("Test <%s> FAILED:\n'%s' -> '%s'\n", 
	   test_id, string, result_string);

  if (result_string)
    ssh_free(result_string);

  return ret;
}

#define RUN_TEST(R,C,F) do {(R) += (F); (C)++; } while (0);
 
int main(int argc, char **argv)
{
  int count = 0;
  int ok_count = 0;

  if (argc > 1 && strcmp("-d", argv[1]) == 0)
    verbose = 1;
  else if (argc > 1 && strcmp("-dd", argv[1]) == 0)
    verbose = 2;
  else if (argc > 1 && strcmp("-ddd", argv[1]) == 0)
    verbose = 3;
  
  /* SSH_IPPROTO_ICMP */

  RUN_TEST(ok_count, count, 
	   run_test("1", 
		    ssh_custr("ipv4(icmp:type(3),10.0.0.0/24)"),
		    ssh_custr("ipv4(icmp:0x0300-0x030d,10.0.0.0/24)")));

  RUN_TEST(ok_count, count, 
	   run_test("2", 
		    ssh_custr("ipv4(icmp:type(3,0),10.0.0.0/24)"),
		    ssh_custr("ipv4(icmp:0x0300,10.0.0.0/24)")));

  RUN_TEST(ok_count, count, 
	   run_test("3", 
		    ssh_custr("ipv4(icmp:type(3,6-13),10.0.0.0/24)"),
		    ssh_custr("ipv4(icmp:0x0306-0x030d,10.0.0.0/24)")));

  RUN_TEST(ok_count, count, 
	   run_test("4", 
		    ssh_custr("ipv4(icmp:type(echo),10.0.0.0/24)"),
		    ssh_custr("ipv4(icmp:0x0800,10.0.0.0/24)")));

  RUN_TEST(ok_count, count, 
	   run_test("5", 
		    ssh_custr("ipv4(icmp:type(time-exceeded),10.0.0.0/24)"),
		    ssh_custr("ipv4(icmp:0x0b00-0x0b01,10.0.0.0/24)")));

  RUN_TEST(ok_count, count, 
	   run_test("6", 
		    ssh_custr("ipv4(icmp:type(time-exceeded,0),10.0.0.0/24)"),
		   ssh_custr("ipv4(icmp:0x0b00,10.0.0.0/24)")));

  RUN_TEST(ok_count, count, 
	   run_test("7", 
		 ssh_custr("ipv4(icmp:type(time-exceeded,0-1),10.0.0.0/24)"),
		 ssh_custr("ipv4(icmp:0x0b00-0x0b01,10.0.0.0/24)")));

  RUN_TEST(ok_count, count, 
	   run_test("8", 
		    ssh_custr(
         "ipv4(icmp:type(redirect,net-redirect-host-redirect),10.0.0.0/24)"),
		    ssh_custr("ipv4(icmp:0x0500-0x0501,10.0.0.0/24)")));

  RUN_TEST(ok_count, count, 
	   run_test("9",
		    ssh_custr(
	 "ipv4(icmp:type(redirect,net-redirect -host-redirect),10.0.0.0/24)"),
		    ssh_custr("ipv4(icmp:0x0500-0x0501,10.0.0.0/24)")));

  RUN_TEST(ok_count, count, 
	   run_test("10",
		    ssh_custr(
	 "ipv4(icmp:type(redirect,net-redirect- host-redirect),10.0.0.0/24)"),
		    ssh_custr("ipv4(icmp:0x0500-0x0501,10.0.0.0/24)")));

  RUN_TEST(ok_count, count, 
	   run_test("11",
		    ssh_custr(
     " ipv4 (icmp :type(redirect, net-redirect - host-redirect),10.0.0.0/24)"),
		    ssh_custr(" ipv4 (icmp :0x0500-0x0501,10.0.0.0/24)")));

  RUN_TEST(ok_count, count, 
	   run_test("12", 
		    ssh_custr("ipv4(icmp:type(neighbor-solicit),10.0.0.0/24)"),
		    NULL));

  RUN_TEST(ok_count, count, 
	   run_test("13", 
		    ssh_custr("ipv4(icmp:type(too-big,0),10.0.0.0/24)"),
		    NULL));
		    
  RUN_TEST(ok_count, count, 
	   run_test("14", 
	   ssh_custr("ipv4(icmp:type(dst-unreachable,no-route),10.0.0.0/24)"),
		    NULL));

  RUN_TEST(ok_count, count, 
	   run_test("15",
		    ssh_custr("ipv4(icmp:type(echo,0-255),10.0.0.0)"),
		    ssh_custr("ipv4(icmp:0x0800,10.0.0.0)")));

  RUN_TEST(ok_count, count, 
	   run_test("16",
	   ssh_custr("ipv4(icmp:type(dst-unreachable,0-255),10.0.0.0)"),
	   ssh_custr("ipv4(icmp:0x0300-0x030d,10.0.0.0)")));

  /* SSH_IPPROTO_IPV6ICMP */

  RUN_TEST(ok_count, count, 
	   run_test("17", 
		    ssh_custr("ipv6(ipv6icmp:type(1),::1/128)"),
		    ssh_custr("ipv6(ipv6icmp:0x0100-0x0104,::1/128)")));

  RUN_TEST(ok_count, count, 
	   run_test("18", 
		    ssh_custr("ipv6(ipv6icmp:type(1,0),ff02::0/64)"),
		    ssh_custr("ipv6(ipv6icmp:0x0100,ff02::0/64)")));

  RUN_TEST(ok_count, count, 
	   run_test("19", 
		    ssh_custr("ipv6(ipv6icmp:type(1,4),3ffe::123:ffff/64)"),
		    ssh_custr("ipv6(ipv6icmp:0x0104,3ffe::123:ffff/64)")));
  
  RUN_TEST(ok_count, count, 
	   run_test("20", 
		    ssh_custr("ipv6(ipv6icmp:type(too-big),::1/128)"),
		    ssh_custr("ipv6(ipv6icmp:0x0200,::1/128)")));

  RUN_TEST(ok_count, count, 
	   run_test("21", 
		    ssh_custr("ipv6(ipv6icmp:type(echo),ff02::0/64)"),
		    ssh_custr("ipv6(ipv6icmp:0x8000,ff02::0/64)")));

  RUN_TEST(ok_count, count, 
	   run_test("22", 
		ssh_custr("ipv6(ipv6icmp:type(redirect),3ffe::123:ffff/64)"),
		ssh_custr("ipv6(ipv6icmp:0x8900,3ffe::123:ffff/64)")));

  RUN_TEST(ok_count, count, 
	   run_test("23", 
		    ssh_custr("ipv6(ipv6icmp:type(time-exceeded),::1/128)"),
		    ssh_custr("ipv6(ipv6icmp:0x0300-0x0301,::1/128)")));
		    
  RUN_TEST(ok_count, count, 
	   run_test("24", 
		  ssh_custr("ipv6(ipv6icmp:type(time-exceeded,0),ff02::0/64)"),
		    ssh_custr("ipv6(ipv6icmp:0x0300,ff02::0/64)")));

  RUN_TEST(ok_count, count, 
	   run_test("25", 
	   ssh_custr("ipv6(ipv6icmp:type(time-exceeded,1),3ffe::123:ffff/64)"),
		    ssh_custr("ipv6(ipv6icmp:0x0301,3ffe::123:ffff/64)")));

  RUN_TEST(ok_count, count, 
	   run_test("26", 
		  ssh_custr("ipv6(ipv6icmp:type(parameter-problem),::1/128)"),
		    ssh_custr("ipv6(ipv6icmp:0x0400-0x0402,::1/128)")));

  RUN_TEST(ok_count, count, 
	   run_test("27", 
 ssh_custr("ipv6(ipv6icmp:type(parameter-problem,invalid-header),ff02::0/64)"),
		    ssh_custr("ipv6(ipv6icmp:0x0400,ff02::0/64)")));

  RUN_TEST(ok_count, count, 
	   run_test("28", 
		 ssh_custr("ipv6(ipv6icmp:type(parameter-problem,unknown-nh-"
			   "unknown-option),3ffe::123:ffff/64)"),
		 ssh_custr("ipv6(ipv6icmp:0x0401-0x0402,3ffe::123:ffff/64)")));

  RUN_TEST(ok_count, count, 
	   run_test("29", 
	   ssh_custr("ipv6(ipv6icmp:type(redirect,net-redirect),::1/128)"),
		    NULL));

  RUN_TEST(ok_count, count, 
	   run_test("30",
 ssh_custr("ipv6(ipv6icmp:type(redirect,net-redirect-host-redirect),::1/128)"),
		    NULL));

  RUN_TEST(ok_count, count, 
	   run_test("31",
ssh_custr("ipv6(ipv6icmp:type(dst-unreachable,no-route-net-unknown),::1/128)"),
		    NULL));

  /* Misc test that attempt to parse unparsable selectors */

  RUN_TEST(ok_count, count, 
	   run_test("32",
		    ssh_custr("ipv4(icmp:type(echo_foo),10.0.0.0)"),
		    NULL));

  RUN_TEST(ok_count, count, 
	   run_test("33",
		    ssh_custr("ipv4(icmpfoo:type(echo_foo),10.0.0.0)"),
		    NULL));

  RUN_TEST(ok_count, count, 
	   run_test("34",
		    ssh_custr("ipv4(icmp:type(JAPAA!!!),10.0.0.0)"),
		    NULL));

  RUN_TEST(ok_count, count, 
	   run_test("35",
		    ssh_custr("ipv4(icm:type(JAPAA!!!),10.0.0.0)"),
		    NULL));

  /* Misc test that attempt to parse unparsable selectors */

  RUN_TEST(ok_count, count, 
	   run_test("36",
		    ssh_custr("ipv4(icmp:type(echo\n),10.0.0.0)"),
		    ssh_custr("ipv4(icmp:0x0800,10.0.0.0)")));

  RUN_TEST(ok_count, count, 
	   run_test("37",
		    ssh_custr("ipv4(icmpfoo:type(echo ),10.0.0.0)"),
		    NULL));

  RUN_TEST(ok_count, count, 
	   run_test("38",
		    ssh_custr("ipv4(icmp:type(dst-unreachable,"
			      "net-unknown-net-unreachable),10.0.0.0)"),
		    NULL));

  if (ok_count != count)
    printf("FAILED: %d out of %d tests failed.\n", (count - ok_count), count);
  else
    printf("OK: all %d tests succeeded\n", ok_count);

  return 0;
}
