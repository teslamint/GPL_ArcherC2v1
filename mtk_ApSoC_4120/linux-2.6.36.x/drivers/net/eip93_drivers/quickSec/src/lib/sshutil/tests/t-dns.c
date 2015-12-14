/*
  File: t-dns.c

  Description:
        Test DNS routines. This is an interactive program,
        and should not be run from the automatic tests.

  Copyright:
          Copyright (c) 2002, 2003, 2005 SFNT Finland Oy.
        All rights reserved
*/

#include "sshincludes.h"
#include "sshoperation.h"
#include "sshtcp.h"
#include "sshfsm.h"
#include "sshgetopt.h"
#include "sshnameserver.h"
#include "ssheloop.h"
#include "sshglobals.h"
#include "sshobstack.h"
#include "sshadt.h"
#include "sshadt_bag.h"
#include "sshadt_list.h"
#include "sshdns.h"
#include "sshtimemeasure.h"

#define SSH_DEBUG_MODULE "Main"

#define MAX_IP_ADDRS 16
#define TEST_CNT 100000

/* Program name */
char *program;

/* Options. */
int allow_non_authorative_option = 0;
int forward_option = 0;
int ignore_option = 0;
int name_server_ip_cnt = 0;
SshIpAddrStruct name_server_ip[MAX_IP_ADDRS];

#ifdef SSHDIST_UTIL_DNS_RESOLVER

/* Number of errors */
int errors = 0;

/* Number of successfull requests. */
int success = 0;



/* Global context. */
typedef struct SshDNSTestRec {
  SshFSMThread thread;
  int current;
  SshTimeMeasureStruct timer;
} *SshDNSTest, SshDNSTestStruct;

typedef enum {
  LOOKUP_FORWARD = 0,
  LOOKUP_REVERSE = 1,
  LOOKUP_FORWARD_FAIL = 2,
  LOOKUP_REVERSE_FAIL = 3
} SshDNSTestCaseType;

#define T_DNS_MAX_VALUES 5

typedef struct SshDNSTestCaseRec {
  SshDNSTestCaseType lookup_type;
  unsigned char *name;
  unsigned char *value[T_DNS_MAX_VALUES]; /* Null terminated list of
					     possible values. */
} *SshDNSTestCase, SshDNSTestCaseStruct;

SshDNSTestCaseStruct test_cases[] =
{
#if 0
  /* This does not work, as the www.imdb.com name servers are not following the
     dns specificiation. When asking CNAME of www.imdb.com from the authorative
     name servers they do not give authorative answer to it, and the authority
     section they give is not for the www.imdb.com it is for the names where
     the cname of the www.imdb.com points to. So this test will not work unless
     -a flag is given to the test program. */
  { LOOKUP_FORWARD, "www.imdb.com", { "207.171.166.140" } },
#endif
  { LOOKUP_FORWARD, "192.0.34.162", { "192.0.34.162" } },

#ifdef WITH_IPV6
  { LOOKUP_FORWARD, "2001:4f8:4:7:2e0:81ff:fe52:9ab6",
    { "2001:4f8:4:7:2e0:81ff:fe52:9ab6" } },
  { LOOKUP_FORWARD, "[2001:4f8:4:7:2e0:81ff:fe52:9ab6]",
    { "2001:4f8:4:7:2e0:81ff:fe52:9ab6" } },
  { LOOKUP_FORWARD, "::",
    { "::" } },
  { LOOKUP_FORWARD, "[::1]",
    { "::1" } },
#endif /* WITH_IPV6 */

  { LOOKUP_FORWARD, "admin.iki.fi", { "212.16.98.50" } },
  /* These other searches should come from cache, this will test the case where
     there is CNAME in the cache. */
  { LOOKUP_FORWARD, "admin.iki.fi", { "212.16.98.50" } },
  { LOOKUP_FORWARD, "admin.iki.fi", { "212.16.98.50" } },

  { LOOKUP_FORWARD, "www.portalify.fi", { "83.145.199.58" } },
  { LOOKUP_FORWARD, "www.portalify.com", { "83.145.199.58" } },
  { LOOKUP_FORWARD, "www.safenet-inc.com", { "192.43.161.95" } },
  { LOOKUP_FORWARD, "www.iki.fi", { "212.16.100.1,212.16.100.2",
			  "212.16.100.2,212.16.100.1" } },

#ifdef WITH_IPV6
  /* IPV6 disabled on www.kivinen.iki.fi says kivinen on 2006-06-09
  { LOOKUP_FORWARD, "www.kivinen.iki.fi",
    { "83.145.195.1,2001:670:83:f00::1",
      "2001:670:83:f00::1,83.145.195.1" } },
  */
  { LOOKUP_FORWARD, "www.netbsd.org",
    { "204.152.190.12,2001:4f8:3:7:2e0:81ff:fe52:9a6b",
      "2001:4f8:3:7:2e0:81ff:fe52:9a6b,204.152.190.12" } },
  { LOOKUP_FORWARD, "www.NetBSD.ORG.",
    { "204.152.190.12,2001:4f8:3:7:2e0:81ff:fe52:9a6b",
      "2001:4f8:3:7:2e0:81ff:fe52:9a6b,204.152.190.12" } },
#endif /* WITH_IPV6 */

#ifdef WITH_IPV6
  { LOOKUP_FORWARD, "localhost", { "127.0.0.1,::1", "::1,127.0.0.1" } },
  { LOOKUP_FORWARD, "localhost.", { "127.0.0.1,::1", "::1,127.0.0.1" } },
  { LOOKUP_FORWARD, "lOcaLhoSt", { "127.0.0.1,::1", "::1,127.0.0.1" } },
#else /* WITH_IPV6 */
  { LOOKUP_FORWARD, "localhost", { "127.0.0.1" } },
  { LOOKUP_FORWARD, "localhost.", { "127.0.0.1" } },
  { LOOKUP_FORWARD, "lOcaLhoSt", { "127.0.0.1" } },
#endif /* WITH_IPV6 */

#if 0
  /* Temporarely disabled as their reverses seem to be pointing 
     to wrong place. //Kivinen 2008-03-18. */
  { LOOKUP_REVERSE, "208.77.188.102", { "www.iana.org" } },
#endif
  { LOOKUP_REVERSE, "212.16.100.1", { "uudestaan.iki.fi" } },
  { LOOKUP_REVERSE, "212.16.100.2", { "jokotaas.iki.fi" } },
  { LOOKUP_REVERSE, "212.226.138.153",
    { "ip212-226-138-153.adsl.kpnqwest.fi" } },

#ifdef WITH_IPV6
  { LOOKUP_REVERSE, "2001:4f8:3:7:2e0:81ff:fe52:9ab6",
    { "mail.netbsd.org", "www.netbsd.org" } },
#endif /* WITH_IPV6 */
#if 0
  /* Temporarely disabled, as netbsd.org's servers were moved and their
     reverses does not seem to be fixed yet. //kivinen 2006-04-27 */
  { LOOKUP_REVERSE, "204.152.190.12", { "www.netbsd.org" } },
#endif

  { LOOKUP_REVERSE, "127.0.0.1" , { "localhost" } },
  { LOOKUP_REVERSE, "127.1" , { "localhost" } },
#ifdef WITH_IPV6
  { LOOKUP_REVERSE, "::1" , { "localhost" } },
#endif /* WITH_IPV6 */

  { LOOKUP_FORWARD_FAIL, "not-found-host.kivinen.iki.fi", { NULL } },
#ifdef WITH_IPV6
  { LOOKUP_REVERSE_FAIL, "2001:670:83:f00::1", { NULL } },
#endif /* WITH_IPV6 */

  /* This is the host used in the speed test, so it should be here in the end
     so when the speed test starts the name is already in the cache. */
  { LOOKUP_FORWARD, "www-v4.kivinen.iki.fi", { "83.145.195.1" } },
};

int test_cases_count = sizeof(test_cases) / sizeof(test_cases[0]);

SSH_FSM_STEP(t_dns_start);
SSH_FSM_STEP(t_dns_query);
SSH_FSM_STEP(t_dns_end);
SSH_FSM_STEP(t_dns_speed_start);
SSH_FSM_STEP(t_dns_speed_loop);
SSH_FSM_STEP(t_dns_speed_end);
SSH_FSM_STEP(t_dns_free);

#ifdef DEBUG_LIGHT
SshFSMStateDebugStruct t_dns_fsm_names[] =
{
  SSH_FSM_STATE("test_start", "Initialize", t_dns_start)
  SSH_FSM_STATE("test_query", "Do the query", t_dns_query)
  SSH_FSM_STATE("test_end", "Finish the test", t_dns_end)
  SSH_FSM_STATE("test_free", "Free", t_dns_free)
};
int t_dns_fsm_names_count = SSH_FSM_NUM_STATES(t_dns_fsm_names);
#endif /* DEBUG_LIGHT */

/* Start operation. */
SSH_FSM_STEP(t_dns_start)
{
  SshDNSTest test = fsm_context;
  SshNameServerConfigStruct config[1];
  int i;

  test->current = 0;
  memset(config, 0, sizeof(*config));
  config->timeout = 120000000;
  config->use_system = FALSE;
  config->allow_non_authorative_data = allow_non_authorative_option;
  config->forward_dns_queries = forward_option;
  config->ignore_default_safety_belt = ignore_option;
  ssh_name_server_init(config);
  ssh_name_server_init(config);

  for(i = 0; i < name_server_ip_cnt; i++)
    {
      ssh_dns_resolver_safety_belt_add(ssh_name_server_resolver(),
				       1,
				       &(name_server_ip[i]));
    }

  SSH_FSM_SET_NEXT(t_dns_query);
  return SSH_FSM_CONTINUE;
}

void t_dns_query_cb(SshTcpError error,
		    const unsigned char *result,
		    void *context)
{
  SshDNSTest test = context;
  int i;

  if ((test_cases[test->current].lookup_type == LOOKUP_FORWARD ||
       test_cases[test->current].lookup_type == LOOKUP_REVERSE))
    {
      if (error != SSH_TCP_OK)
	{
	  if (error == SSH_TCP_TIMEOUT)
	    ssh_warning("t_dns_query_cb called with error %s (%d) for name %s",
			ssh_tcp_error_string(error), error,
			test_cases[test->current].name);
	  else
	    ssh_fatal("t_dns_query_cb called with error %s (%d) for name %s",
		      ssh_tcp_error_string(error), error,
		      test_cases[test->current].name);
	  errors++;
	  goto next;
	}
      if (result == NULL)
	ssh_fatal("Result is NULL");
      for(i = 0; i < T_DNS_MAX_VALUES; i++)
	{
	  if (test_cases[test->current].value[i] == NULL)
	    ssh_fatal("Result %s does not match the value "
		      "for test %d (%s)",
		      result, test->current,
		      test_cases[test->current].name);
	  if (strcasecmp(result, test_cases[test->current].value[i]) == 0)
	    {
	      /* Ok. */
	      break;
	    }
	}
      if (i == T_DNS_MAX_VALUES)
	ssh_fatal("Result %s does not match the value for test %d (%s)",
		  result, test->current, test_cases[test->current].name);
      SSH_DEBUG(SSH_D_HIGHOK, ("Correct answer %s for %s from dns",
			       result, test_cases[test->current].name));
    }
  else
    {
      if (error == SSH_TCP_OK)
	ssh_fatal("t_dns_query_cb succeeded when it should have "
		  "failed for name %s",
		  test_cases[test->current].name);
      SSH_DEBUG(SSH_D_HIGHOK, ("Correct failure for %s from dns",
			       test_cases[test->current].name));
    }
  success++;

 next:
  test->current++;
  if (test->current >= test_cases_count)
    {
      ssh_fsm_set_next(test->thread, t_dns_end);
    }
  SSH_FSM_CONTINUE_AFTER_CALLBACK(test->thread);
}

/* Do the query. */
SSH_FSM_STEP(t_dns_query)
{
  SshDNSTest test = fsm_context;

  SSH_FSM_ASYNC_CALL(
    if (test_cases[test->current].lookup_type == LOOKUP_FORWARD ||
	test_cases[test->current].lookup_type == LOOKUP_FORWARD_FAIL)
      {
	ssh_tcp_get_host_addrs_by_name(test_cases[test->current].
				       name,
				       t_dns_query_cb, test);
      }
    else
     {
       ssh_tcp_get_host_by_addr(test_cases[test->current].
				name,
				t_dns_query_cb, test);
     }
    );
}

void t_dns_continue(void *context)
{
  SshDNSTest test = context;
  SSH_FSM_CONTINUE_AFTER_CALLBACK(test->thread);
}

SSH_FSM_STEP(t_dns_end)
{
  SSH_FSM_SET_NEXT(t_dns_speed_start);
  if (errors > 0 && success == 0)
    ssh_fatal("All tests failed");
  SSH_FSM_ASYNC_CALL(ssh_xregister_timeout(1, 0, t_dns_continue, fsm_context));
}

SSH_FSM_STEP(t_dns_speed_start)
{
  SshDNSTest test = fsm_context;

  SSH_FSM_SET_NEXT(t_dns_speed_loop);
  test->current = TEST_CNT;
  ssh_time_measure_reset(&test->timer);
  ssh_time_measure_start(&test->timer);
  return SSH_FSM_CONTINUE;
}

void t_dns_speed_cb(SshTcpError error,
		    const unsigned char *result,
		    void *context)
{
  SshDNSTest test = context;

  if (error != SSH_TCP_OK)
    {
      ssh_fatal("t_dns_speed_cb called with error %s (%d) for name %s",
		ssh_tcp_error_string(error), error,
		test_cases[test->current].name);
    }
  if (result == NULL)
    ssh_fatal("Result is NULL");

  test->current--;
  if (test->current == 0)
    {
      ssh_fsm_set_next(test->thread, t_dns_speed_end);
    }
  SSH_FSM_CONTINUE_AFTER_CALLBACK(test->thread);
}

SSH_FSM_STEP(t_dns_speed_loop)
{
  SshDNSTest test = fsm_context;
  SSH_FSM_ASYNC_CALL(
		     ssh_tcp_get_host_addrs_by_name("www-v4.kivinen.iki.fi",
						    t_dns_speed_cb, test);
		     );
}

SSH_FSM_STEP(t_dns_speed_end)
{
  SshDNSTest test = fsm_context;
  SshTimeT speed;

  SSH_FSM_SET_NEXT(t_dns_free);
  ssh_time_measure_stop(&test->timer);
  speed = ssh_time_measure_get(&test->timer, SSH_TIME_GRANULARITY_SECOND);
  speed = 1 / speed * TEST_CNT;
  printf("Speed test = %ld operations / s from cache\n", (long) speed);
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(t_dns_free)
{
  ssh_name_server_uninit();
  return SSH_FSM_FINISH;
}

#endif /* SSHDIST_UTIL_DNS_RESOLVER */

int main(int argc, char **argv)
{
  const char *debug_string = "Main=9,SshDns*=3,SshFSM*=3";
#ifdef SSHDIST_UTIL_DNS_RESOLVER
  SshFSMThreadStruct thread[1];
  SshDNSTestStruct test[1];
  SshFSMStruct fsm[1];
#endif /* SSHDIST_UTIL_DNS_RESOLVER */
  int c, errflg = 0;

  program = strrchr(argv[0], '/');
  if (program == NULL)
    program = argv[0];
  else
    program++;

  while ((c = ssh_getopt(argc, argv, "d:afin:", NULL)) != EOF)
    {
      switch (c)
        {
        case 'd': debug_string = ssh_optarg; break;
	case 'a': allow_non_authorative_option++; break;
	case 'f': forward_option++; break;
	case 'i': ignore_option++; break;
	case 'n':
	  if (name_server_ip_cnt >= MAX_IP_ADDRS)
	    errflg++;
	  else
	    {
	      if (ssh_ipaddr_parse(&(name_server_ip[name_server_ip_cnt]),
				   ssh_optarg))
		{
		  name_server_ip_cnt++;
		}
	      else
		{
		  fprintf(stderr, "Invalid IP-number %s\n", ssh_optarg);
		  exit(1);
		}
	    }
	  break;
        case '?': errflg++; break;
        }
    }
  if (errflg || argc - ssh_optind != 0)
    {
      fprintf(stderr,
	      "Usage: %s [-afi] [-d debug_flags] "
	      "[-n name_server_ip [-n name_server2_ip ...]]\n",
	      program);
      exit(1);
    }

  ssh_debug_set_level_string(debug_string);

  ssh_event_loop_initialize();

#ifdef SSHDIST_UTIL_DNS_RESOLVER
  ssh_event_loop_lock();
  memset(test, 0, sizeof(*test));
  ssh_fsm_init(fsm, test);
#ifdef DEBUG_LIGHT
  ssh_fsm_register_debug_names(fsm,
			       t_dns_fsm_names,
			       t_dns_fsm_names_count);
#endif /* DEBUG_LIGHT */
  ssh_fsm_thread_init(fsm, thread, t_dns_start, NULL, NULL, NULL);
#ifdef DEBUG_LIGHT
  ssh_fsm_set_thread_name(thread, "TestThread");
#endif /* DEBUG_LIGHT */
  test->thread = thread;
#endif /* SSHDIST_UTIL_DNS_RESOLVER */

  ssh_event_loop_unlock();
  ssh_event_loop_run();

  /* Exiting... */
  ssh_event_loop_lock();
  /* Nothing to cleanup here. */
  ssh_event_loop_unlock();
  ssh_event_loop_uninitialize();
  ssh_util_uninit();
  return 0;
}
