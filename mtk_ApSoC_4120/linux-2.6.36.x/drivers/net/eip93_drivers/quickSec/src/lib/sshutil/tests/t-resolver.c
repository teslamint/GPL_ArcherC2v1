/*
 * Author: Tero Kivinen <kivinen@iki.fi>
 *
 * Copyright (c) 2004, 2005 SFNT Finland Oy.
 */
/*
 *        Program: sshdns
 *        $Source: /home/user/socsw/cvs/cvsrepos/tclinux_phoenix/modules/eip93_drivers/quickSec/src/lib/sshutil/tests/Attic/t-resolver.c,v $
 *        $Author: bruce.chang $
 *
 *        Creation          : 15:57 Apr 16 2004 kivinen
 *        Last Modification : 15:37 Oct 29 2008 kivinen
 *        Last check in     : $Date: 2012/09/28 $
 *        Revision number   : $Revision: #1 $
 *        State             : $State: Exp $
 *        Version           : 1.348
 *        
 *
 *        Description       : Test DNS Resolver functions.
 *
 *        $Log: t-resolver.c,v $
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
#include "sshdns.h"
#include "sshfsm.h"
#include "sshgetopt.h"
#include "ssheloop.h"
#include "sshglobals.h"
#include "sshdsprintf.h"
#include "sshmiscstring.h"

#define SSH_DEBUG_MODULE "Main"

/* Program name */
char *program;

#ifdef SSHDIST_UTIL_DNS_RESOLVER

#define ENABLE_LOOP_TEST 0

/* Global context. */
typedef struct SshDNSTestRec {
  SshDNSResolver resolver;
  SshFSMThread thread;
  int current;
  SshUInt32 resolver_flags;
} *SshDNSTest, SshDNSTestStruct;

typedef struct SshDNSTestCaseRec {
  unsigned char *name;
  SshDNSRRType type;
  unsigned char *value;
  size_t value_len;
} *SshDNSTestCase, SshDNSTestCaseStruct;

SshDNSTestCaseStruct test_cases[] =
{
  { "\11uudestaan\3iki\2fi", SSH_DNS_RESOURCE_NS, NULL, 0 },
  { "\3iki\2fi", SSH_DNS_RESOURCE_NS, NULL, 0 },
  { "\7kivinen\3iki\2fi", SSH_DNS_RESOURCE_A, "\x53\x91\xc3\x01", 4 },
  { "\6www-v6\7kivinen\3iki\2fi", SSH_DNS_RESOURCE_AAAA,
    "\x20\x01\x1b\xc8\x10\x0d\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02", 16 },
  { "\3txt\7kivinen\3iki\2fi", SSH_DNS_RESOURCE_TXT, NULL, 0 },
  { "\3www\7kivinen\3iki\2fi", SSH_DNS_RESOURCE_A, "\x53\x91\xc3\x01", 4 },
  { "\10fireball\3acr\2fi", SSH_DNS_RESOURCE_A, "\x53\x91\xc3\x01", 4 },
  { "\10fireball\3acr\2fi", SSH_DNS_RESOURCE_MX,
    "\x00\x01\10fireball\3acr\2fi", 19 },
  { "\5haste\3acr\2fi", SSH_DNS_RESOURCE_A, "\x53\x91\xc3\x07", 4 },
  { "\3iki\2fi", SSH_DNS_RESOURCE_SOA, NULL, 0 },
  { "\11uudestaan\3iki\2fi", SSH_DNS_RESOURCE_A, "\xD4\x10\x64\x01", 4 },
  { "\11uudestaan\3iki\2fi", SSH_DNS_RESOURCE_WKS, NULL, 0 },
  { "\11uudestaan\3iki\2fi", SSH_DNS_RESOURCE_HINFO, "\10NonAlpha\6NetBSD",
    16 },
  { "\11uudestaan\3iki\2fi", SSH_DNS_RESOURCE_MX, NULL, 0 },
  { "\3www\2cs\2bu\3edu", SSH_DNS_RESOURCE_A, "\x80\xc5\x0a\x03", 4 },
  { "\3www\2cs\2bu\3edu", SSH_DNS_RESOURCE_CNAME, "\6cs-web\2bu\3edu", 15 },
  { "\3www\6google\3com", SSH_DNS_RESOURCE_A, NULL, 0 },
  { "\10porttest\10dns-oarc\3net", SSH_DNS_RESOURCE_TXT, "*GREAT", 6 },
  { "\10txidtest\10dns-oarc\3net", SSH_DNS_RESOURCE_TXT, "*GREAT", 6 },
};


int test_cases_count = sizeof(test_cases) / sizeof(test_cases[0]);

SSH_FSM_STEP(t_resolver_start);
SSH_FSM_STEP(t_resolver_query);
SSH_FSM_STEP(t_resolver_loop_start);
SSH_FSM_STEP(t_resolver_loop);
SSH_FSM_STEP(t_resolver_end);
SSH_FSM_STEP(t_resolver_free);

#ifdef DEBUG_LIGHT
SshFSMStateDebugStruct t_resolver_fsm_names[] =
{
  SSH_FSM_STATE("test_start", "Initialize resolver",
		t_resolver_start)
  SSH_FSM_STATE("test_query", "Do the query",
		t_resolver_query)
  SSH_FSM_STATE("test_loop_start", "Start loop tests",
		t_resolver_loop_start)
  SSH_FSM_STATE("test_loop", "Do some looping tests",
		t_resolver_loop)
  SSH_FSM_STATE("test_end", "Finish the test",
		t_resolver_end)
  SSH_FSM_STATE("test_free", "Free the resolver",
		t_resolver_free)
};
int t_resolver_fsm_names_count =
  SSH_FSM_NUM_STATES(t_resolver_fsm_names);
#endif /* DEBUG_LIGHT */

/* Start operation. */
SSH_FSM_STEP(t_resolver_start)
{
  SshDNSTest test = fsm_context;
  SshDNSNameServer name_server;
  SshIpAddrStruct array_of_ip_addresses[2];

  test->current = 0;
  test->resolver = ssh_dns_resolver_allocate();
  if (test->resolver == NULL)
    ssh_fatal("Could not allocate resolver.");

  if (!ssh_dns_resolver_configure(test->resolver, NULL))
    ssh_fatal("Could not configure resolver.");

  /* Configure safety belt. */
  ssh_dns_resolver_safety_belt_clear(test->resolver);

  if (!ssh_ipaddr_parse(&(array_of_ip_addresses[0]), "172.30.4.19"))
    ssh_fatal("ssh_ipaddr_parse 172.30.4.19 failed");

  if (!ssh_ipaddr_parse(&(array_of_ip_addresses[1]), "172.30.4.20"))
    ssh_fatal("ssh_ipaddr_parse 172.30.4.20 failed");

  name_server = ssh_dns_resolver_safety_belt_add(test->resolver,
						 2, array_of_ip_addresses);
  if (name_server == NULL)
    ssh_fatal("ssh_dns_resolver_safety_belt_add safenet failed");

  if (!ssh_ipaddr_parse(&(array_of_ip_addresses[0]), "212.16.100.1"))
    ssh_fatal("ssh_ipaddr_parse 212.16.100.1 failed");

  if (!ssh_ipaddr_parse(&(array_of_ip_addresses[1]), "212.16.100.2"))
    ssh_fatal("ssh_ipaddr_parse 212.16.100.2 failed");

  name_server = ssh_dns_resolver_safety_belt_add(test->resolver,
						 2, array_of_ip_addresses);
  if (name_server == NULL)
    ssh_fatal("ssh_dns_resolver_safety_belt_add iki failed");

  /* Reconfigure safety belt. */
  ssh_dns_resolver_safety_belt_clear(test->resolver);

  if (!ssh_ipaddr_parse(&(array_of_ip_addresses[0]), "172.30.4.19"))
    ssh_fatal("ssh_ipaddr_parse 172.30.4.19 failed");

  if (!ssh_ipaddr_parse(&(array_of_ip_addresses[1]), "172.30.4.20"))
    ssh_fatal("ssh_ipaddr_parse 172.30.4.20 failed");

  name_server = ssh_dns_resolver_safety_belt_add(test->resolver,
						 2, array_of_ip_addresses);
  if (name_server == NULL)
    ssh_fatal("ssh_dns_resolver_safety_belt_add safenet failed second time");

  if (!ssh_ipaddr_parse(&(array_of_ip_addresses[0]), "212.16.100.1"))
    ssh_fatal("ssh_ipaddr_parse 212.16.100.1 failed");

  if (!ssh_ipaddr_parse(&(array_of_ip_addresses[1]), "212.16.100.2"))
    ssh_fatal("ssh_ipaddr_parse 212.16.100.2 failed");

  name_server = ssh_dns_resolver_safety_belt_add(test->resolver,
						 2, array_of_ip_addresses);
  if (name_server == NULL)
    ssh_fatal("ssh_dns_resolver_safety_belt_add iki failed second time");

  SSH_FSM_SET_NEXT(t_resolver_query);
  return SSH_FSM_CONTINUE;
}

void t_resolver_result(SshDNSResponseCode error,
		       SshDNSRRset rrset,
		       void *context)
{
  SshDNSTest test = context;
  unsigned char *p;

  if (error != SSH_DNS_OK)
    {
      if (error == SSH_DNS_TIMEOUT ||
	  error == SSH_DNS_UNREACHABLE)
	{
	  ssh_warning("Query to %@ for %s (%d) failed with error code %s (%d)"
		      " temporary failure, ignored",
		      ssh_dns_name_render, test_cases[test->current].name,
		      ssh_dns_rrtype_string(test_cases[test->current].type),
		      test_cases[test->current].type,
		      ssh_dns_response_code_string(error), error);
	}
      else
	{
	  ssh_fatal("Query to %@ for %s (%d) failed with error code %s (%d)",
		    ssh_dns_name_render, test_cases[test->current].name,
		    ssh_dns_rrtype_string(test_cases[test->current].type),
		    test_cases[test->current].type,
		    ssh_dns_response_code_string(error), error);
	}
      goto next;
    }
  if (rrset == NULL)
    ssh_fatal("Query to %@ for %s (%d) return null rrset",
	      ssh_dns_name_render, test_cases[test->current].name,
	      ssh_dns_rrtype_string(test_cases[test->current].type),
	      test_cases[test->current].type);

  ssh_dsprintf(&p, "RRset:\n%.1@", ssh_dns_rrset_render, rrset);
  SSH_DEBUG(SSH_D_MIDSTART, ("%s", p));
  ssh_free(p);

  if (test_cases[test->current].value_len != 0)
    {
      if (rrset->number_of_rrs == 0)
	{
	  printf("Didn't return anything, should return:\n");
	  ssh_debug_hexdump(0, test_cases[test->current].value,
			    test_cases[test->current].value_len);
	  ssh_fatal("Query to %@ for %s (%d) returned wrong value",
		    ssh_dns_name_render, test_cases[test->current].name,
		    ssh_dns_rrtype_string(test_cases[test->current].type),
		    test_cases[test->current].type);
	}
      if (test_cases[test->current].value[0] == '*' &&
	  test_cases[test->current].value_len > 2)
	{
	  size_t len;
	  p = rrset->array_of_rdata[0];
	  while (1)
	    {
	      p = memchr(p,
			 test_cases[test->current].value[1],
			 rrset->array_of_rdlengths[0] -
			 (p - rrset->array_of_rdata[0]));
	      if (p == NULL)
		{
		  /* Could not find string */
		  printf("Data returned:\n");
		  ssh_debug_hexdump(0, rrset->array_of_rdata[0],
				    rrset->array_of_rdlengths[0]);
		  printf("Should return string containing:\n");
		  ssh_debug_hexdump(0, test_cases[test->current].value,
				    test_cases[test->current].value_len);
		  ssh_fatal("Query to %@ for %s (%d) returned wrong value",
			    ssh_dns_name_render, test_cases[test->current].name,
			    ssh_dns_rrtype_string(test_cases[test->current].type),
			    test_cases[test->current].type);
		}
	      len = rrset->array_of_rdlengths[0] -
		(p - rrset->array_of_rdata[0]);
	      if (len > test_cases[test->current].value_len - 1)
		len = test_cases[test->current].value_len - 1;
	      if (memcmp(p,
			 test_cases[test->current].value + 1,
			 len) == 0)
		{
		  /* Found */
		  break;
		}
	      p++;
	    }
	}
      else if (test_cases[test->current].value_len !=
	       rrset->array_of_rdlengths[0] ||
	       memcmp(test_cases[test->current].value,
		      rrset->array_of_rdata[0],
		      test_cases[test->current].value_len) != 0)
	{
	  printf("Data returned:\n");
	  ssh_debug_hexdump(0, rrset->array_of_rdata[0],
			    rrset->array_of_rdlengths[0]);
	  printf("Should return:\n");
	  ssh_debug_hexdump(0, test_cases[test->current].value,
			    test_cases[test->current].value_len);
	  ssh_fatal("Query to %@ for %s (%d) returned wrong value",
		    ssh_dns_name_render, test_cases[test->current].name,
		    ssh_dns_rrtype_string(test_cases[test->current].type),
		    test_cases[test->current].type);
	}
    }
 next:
  test->current++;
  if (test->current >= test_cases_count)
    ssh_fsm_set_next(test->thread, t_resolver_loop_start);
  SSH_FSM_CONTINUE_AFTER_CALLBACK(test->thread);
}

SSH_FSM_STEP(t_resolver_query)
{
  SshDNSTest test = fsm_context;

  SSH_FSM_ASYNC_CALL(
		     ssh_dns_resolver_find(test->resolver,
					   test_cases[test->current].name,
					   test_cases[test->current].type,
					   1000000 * 120,
					   /* 1 seconds * 120. */
					   test->resolver_flags,
					   t_resolver_result, test);
		     );
}

void t_resolver_loop_result(SshDNSResponseCode error,
			    SshDNSRRset rrset,
			    void *context)
{
  SshDNSTest test = context;
  unsigned char *p;

  if (error != SSH_DNS_OK)
    {
      if (error == SSH_DNS_TIMEOUT ||
	  error == SSH_DNS_UNREACHABLE ||
	  error == SSH_DNS_MEMORY_ERROR)
	{
	  ssh_warning("Query to %05d.iki.fi failed with error code %s (%d)"
		      " temporary failure, ignored",
		      test->current,
		      ssh_dns_response_code_string(error), error);
	}
      else
	{
	  ssh_fatal("Query to %05d.iki.fi failed with error code %s (%d)",
		    test->current,
		    ssh_dns_response_code_string(error), error);
	}
      goto next;
    }
  if (rrset == NULL)
    ssh_fatal("Query to %05d.iki.fi return null rrset",
	      test->current);

  ssh_dsprintf(&p, "RRset:\n%.1@", ssh_dns_rrset_render, rrset);
  SSH_DEBUG(SSH_D_MIDSTART, ("%s", p));
  ssh_free(p);
 next:
  SSH_FSM_CONTINUE_AFTER_CALLBACK(test->thread);
}

SSH_FSM_STEP(t_resolver_loop_start)
{
  SshDNSTest test = fsm_context;
  SshDNSRRsetCacheConfigStruct config[1];
  SshDNSRRsetCache cache;

  test->current = 0;
  SSH_FSM_SET_NEXT(t_resolver_loop);
  cache = ssh_dns_resolver_rrset_cache(test->resolver);

  config->max_memory = 65536;
  config->keep_rrsets = 100;
  config->max_rrsets = 200;
  config->minimum_lifetime = 1;
  config->maximum_ttl = 5;

  if (!ssh_dns_rrset_cache_configure(cache, config))
    ssh_fatal("RRset cache configure failed");
  return SSH_FSM_CONTINUE;
}

void t_resolver_loop_sleep(void *context)
{
  SshDNSTest test = context;
  SSH_FSM_CONTINUE_AFTER_CALLBACK(test->thread);
}

SSH_FSM_STEP(t_resolver_loop)
{
  SshDNSTest test = fsm_context;
  unsigned char buffer[100];

#if !ENABLE_LOOP_TEST
  SSH_FSM_SET_NEXT(t_resolver_end);
  return SSH_FSM_CONTINUE;
#endif /* ENABLE_LOOP_TEST */
  test->current++;
  if (test->current > 1000)
    {
      SSH_FSM_SET_NEXT(t_resolver_end);
      return SSH_FSM_CONTINUE;
    }
  if (test->current % 100 == 0)
    {
      SSH_DEBUG(SSH_D_MIDSTART, ("Sleeping for 2 seconds"));
      SSH_FSM_ASYNC_CALL(ssh_xregister_timeout(2, 0,
					       t_resolver_loop_sleep,
					       test));
    }

  ssh_snprintf(buffer, sizeof(buffer), "\5%05d\3iki\2fi", test->current);

  SSH_FSM_ASYNC_CALL(
		     ssh_dns_resolver_find(test->resolver,
					   buffer,
					   SSH_DNS_RESOURCE_TXT,
					   1000000 * 10,
					   /* 1 seconds * 10. */
					   test->resolver_flags,
					   t_resolver_loop_result, test);
		     );
}

void t_resolver_end_cb(void *context)
{
  SshDNSTest test = context;
  SSH_FSM_CONTINUE_AFTER_CALLBACK(test->thread);
}

SSH_FSM_STEP(t_resolver_end)
{
  SshDNSTest test = fsm_context;

  SSH_FSM_SET_NEXT(t_resolver_free);
  SSH_FSM_ASYNC_CALL(ssh_xregister_timeout(0, 0,
					   t_resolver_end_cb,
					   test));
}

SSH_FSM_STEP(t_resolver_free)
{
  SshDNSTest test = fsm_context;

  ssh_dns_resolver_free(test->resolver);
  test->resolver = NULL;
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
  int use_tcp = 0;

  ssh_dns_debug_pretty_print = 1;

  program = strrchr(argv[0], '/');
  if (program == NULL)
    program = argv[0];
  else
    program++;

  while ((c = ssh_getopt(argc, argv, "td:", NULL)) != EOF)
    {
      switch (c)
        {
        case 'd': debug_string = ssh_optarg; break;
	case 't': use_tcp++; break;
        case '?': errflg++; break;
        }
    }
  if (errflg || argc - ssh_optind != 0)
    {
      fprintf(stderr, "Usage: %s [-d debug_flags] [-t]\n", program);
      exit(1);
    }

  ssh_debug_set_level_string(debug_string);

  ssh_event_loop_initialize();

#ifdef SSHDIST_UTIL_DNS_RESOLVER
  ssh_event_loop_lock();
  memset(test, 0, sizeof(*test));
  if (use_tcp)
    test->resolver_flags |= SSH_DNS_RESOLVER_USE_TCP;
  ssh_fsm_init(fsm, test);
#ifdef DEBUG_LIGHT
  ssh_fsm_register_debug_names(fsm,
			       t_resolver_fsm_names,
			       t_resolver_fsm_names_count);
#endif /* DEBUG_LIGHT */
  ssh_fsm_thread_init(fsm, thread, t_resolver_start, NULL, NULL, NULL);
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
