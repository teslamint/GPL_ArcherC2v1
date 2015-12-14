/**
  File: ikev2-perftool.c

  @copyright
  	Copyright (c) 2002-2005 SFNT Finland Oy -
   	all rights reserved.

  Client tool for measuring IKEv2 SA establishment rate.

*/

#include "sshincludes.h"
#include "sshfsm.h"
#include "ssheloop.h"
#include "sshtimemeasure.h"
#include "sshrand.h"
#ifdef SSHDIST_UTIL_TCP
#include "sshnameserver.h"
#endif /* SSHDIST_UTIL_TCP */
#include "sshgetopt.h"
#include "sshglobals.h"
#include "sshcrypt.h"
#ifdef SSHDIST_IKE_CERT_AUTH
#include "x509.h"
#endif /* SSHDIST_IKE_CERT_AUTH */
#ifdef SSHDIST_RADIUS
#include "sshradius.h"
#endif /* SSHDIST_RADIUS */
#ifdef SSHDIST_IKE_EAP_AUTH
#ifdef SSHDIST_EAP
#include "ssheap.h"
#endif /* SSHDIST_EAP */
#endif /* SSHDIST_IKE_EAP_AUTH */

#include "sshikev2-initiator.h"
#include "sshikev2-exchange.h"
#include "sshikev2-util.h"
#include "dummy-if.h"

#define SSH_DEBUG_MODULE "Ikev2Perf"

Boolean g_ike_nomatch = FALSE;
Boolean g_ipsec_nomatch = FALSE;
Boolean opt_client = TRUE;

/* pad-dummy.c */
int d_pad_allocate(const unsigned char *cert_config);
void d_pad_destroy(void);

#ifdef SSH_IKEV2_MULTIPLE_AUTH
Boolean use_multiple_auth = FALSE;
#endif /* SSH_IKEV2_MULTIPLE_AUTH */

SshSADHandle sad_handle;
SshIkev2 ikev2;
extern SshSADInterfaceStruct dummy_if;
unsigned int num_servers = 1;
SshIkev2Server server[1];

SshIkev2PayloadTS tsi_local = NULL;
SshIkev2PayloadTS tsi_remote = NULL;
Boolean use_certs = FALSE;
#ifdef SSHDIST_IKE_EAP_AUTH
#ifdef SSHDIST_EAP
Boolean use_eap = FALSE;
#ifdef SSHDIST_RADIUS
SshEapRadiusConfiguration radius_config = NULL;
#endif /* SSHDIST_RADIUS */
#endif /* SSHDIST_EAP */
#endif /* SSHDIST_IKE_EAP_AUTH */

#ifdef SSHDIST_IKE_MOBIKE
Boolean mobike_supported = FALSE;
#endif /* SSHDIST_IKE_MOBIKE */


typedef enum {
  IKE_PERF_SEARCHING_FAST,
  IKE_PERF_SEARCHING_MEDIUM,
  IKE_PERF_SEARCHING_SLOW,
  IKE_PERF_SEARCHING_SLOW_1,
  IKE_PERF_SEARCHING_SLOW_2,
  IKE_PERF_SEARCHING_SLOW_3,
  IKE_PERF_SEARCHING_SLOW_4,
  IKE_PERF_SEARCHING_VERY_SLOW
} SshIkePerfState;

const char *ike_perf_state_names[] = {
  "fast", "medium", "slow", "slow 1", "slow 2", "slow 3", "slow 4", 
  "very slow"
};

typedef struct TestCtxRec {
  SshFSMStruct fsm[1];
  SshFSMThreadStruct thread[1];

#ifdef SSHDIST_EXTERNALKEY
  SshExternalKey externalkey;
  char *short_name;
#endif /*  SSHDIST_EXTERNALKEY */

#ifdef SSHDIST_IKEV1
  /* Use IKEv1 */
  Boolean ikev1;
#endif /* SSHDIST_IKEV1 */

  /* IKE server */
  SshIkev2Server server;

  /* Total number of IKE SA's */
  int num_sas;
  /* Index of IKE SA currently being processed */
  int sa_index;

  /* Array of IKE SA handles, has 'num_sas' elements */
  SshIkev2Sa *sas;
  /* Array of local traffic selectors, has 'num_sas' elements */
  SshIkev2PayloadTS *local_ts;

  /* Use ports for local traffic selectors */
  Boolean use_port_ts;
  /* Range of local ports (for traffic selectors) */
  int local_start_port;
  int local_end_port;
  /* IP protocol (for traffic selectors) */
  int ipproto;

  /* Local IKE server */
  SshIpAddrStruct local_ike_ip;
  SshUInt16 local_ike_port;

  /* Remote IKE peer */
  SshIpAddrStruct remote_ike_ip;
  SshUInt16 remote_ike_port;

  /* Time measurement */
  SshTimeMeasureStruct timer[1];
  unsigned int start_time;

  /* Interval between SA initiators */
  int sleep_microsecs;

  /* State when dynamically adjusting for optimal performance */
  SshIkePerfState state;
  int prev_sleep_microsecs;
  int last_ok_sleep;
  int num_test_failures;

  /* Repeat test until no packet transmissions occur */
  Boolean repeat_test;
  Boolean do_repeat;
  Boolean delete_ike_sas;
  /* The timeout in microseconds to wait before starting the next repeat */
  int repeat_test_timeout;

  /* Time elapsed for current and prev test runs */
  unsigned int current_time;
  unsigned int prev_time;
  /* Best recorded time */
  unsigned int min_time;

  /* SA setup statistics */
  int num_started;
  int num_done;
  int num_ok;
  int num_failed;

} TestCtxStruct,  *TestCtx;

TestCtx test_ctx;


/* Modifies the timeout paramter for the next test iteration. Returns 
   TRUE if the test should be terminated (the state has reached 
   IKE_PERF_SEARCHING_VERY_SLOW and the last test time was not an 
   improvement over the previous test). Returns FALSE if another test 
   iteration should take packe*/
Boolean ike_perf_tune_params(TestCtx test_ctx, Boolean improving)
{
  int prev_timeout = test_ctx->prev_sleep_microsecs;
  int timeout = test_ctx->sleep_microsecs;

  SSH_DEBUG(3, ("Current/Previous sleep times %d %d improving %d, state %s",
		test_ctx->sleep_microsecs, test_ctx->prev_sleep_microsecs,
		improving, ike_perf_state_names[test_ctx->state]));
  

  /* If any negotiations has failed just double the timeout parameter. */
  if (test_ctx->num_failed)
    {
      test_ctx->prev_sleep_microsecs = timeout;

      /* If a previous run has completed without any failed negotiations
	 then revert to the sleep time used there. Otherwise just double 
	 the sleep interval if all previous runs have had at least one
	 negotiation failing. */
      if (test_ctx->last_ok_sleep)
	{
	  test_ctx->sleep_microsecs = test_ctx->last_ok_sleep;

	  if (test_ctx->state != IKE_PERF_SEARCHING_VERY_SLOW)
	    test_ctx->state++;
	}
      else
	{
	  if (++test_ctx->num_test_failures == 10)
	    {
	      fprintf(stdout, "Aborting test due to repeated failed "
		      "negotiations\n");
	      exit(1);
	    }
	  test_ctx->sleep_microsecs = 2 * timeout;
	  test_ctx->state = IKE_PERF_SEARCHING_MEDIUM;
	}
      return FALSE;
    }
  test_ctx->last_ok_sleep = timeout;

  /* Revert to the previous test sleep timeout and jump to next slowest 
     decreasing search state. */
  if (!improving)
    {
      test_ctx->sleep_microsecs = prev_timeout;
      if (test_ctx->state == IKE_PERF_SEARCHING_VERY_SLOW)
	return TRUE;
      test_ctx->state++;
      return FALSE;
    }

  /* Record the previous timeout */
  test_ctx->prev_sleep_microsecs = timeout;

  switch (test_ctx->state)
    {
    case IKE_PERF_SEARCHING_FAST:
      timeout /= 2;
      break;
    case IKE_PERF_SEARCHING_MEDIUM:
      timeout = timeout * 3 / 4;
      if (timeout == prev_timeout)
	timeout--;
      break;
    case IKE_PERF_SEARCHING_SLOW:
      timeout = timeout * 9 / 10;
      if (timeout == prev_timeout)
	timeout--;
      break;

    case IKE_PERF_SEARCHING_SLOW_1:
      timeout = timeout * 39 / 40;
      if (timeout == prev_timeout)
	timeout--;
      break;

    case IKE_PERF_SEARCHING_SLOW_2:
      timeout = timeout * 69 / 70;
      if (timeout == prev_timeout)
	timeout--;
      break;

    case IKE_PERF_SEARCHING_SLOW_3:
      timeout = timeout * 99 / 100;
      if (timeout == prev_timeout)
	timeout--;
      break;

    case IKE_PERF_SEARCHING_SLOW_4:
      timeout = timeout * 199 / 200;
      if (timeout == prev_timeout)
	timeout--;
      break;

    case IKE_PERF_SEARCHING_VERY_SLOW:
      if (timeout != 0)
	timeout--;
      break;
    }

  /* Update to the new timeout */
  test_ctx->sleep_microsecs = timeout;
  return FALSE;
}


void ikev2_sa_allocated(SshIkev2Error error,
			SshIkev2Sa ike_sa,
			void *context)
{
  TestCtx test_ctx = context;

  SSH_DEBUG(SSH_D_HIGHSTART, ("IKEv2 sa allocate done, error=%d", error));

  if (error != SSH_IKEV2_ERROR_OK || ike_sa == NULL)
    ssh_fatal("IKEv2 sa allocate failed");

  /* Store the IKE SA handle. The actual IKE SA is managed in the
     dummy SAD module. */
  test_ctx->sas[test_ctx->sa_index] = ike_sa;
  test_ctx->sa_index++;

  SSH_FSM_CONTINUE_AFTER_CALLBACK(test_ctx->thread);
}


static void clear_ike_sa(TestCtx test_ctx, SshIkev2Sa ike_sa)
{
  int i;

  for (i = 0; i < test_ctx->num_sas; i++)
    if (test_ctx->sas[i] == ike_sa)
      {
	test_ctx->sas[i] = NULL;
	return;
      }
}

void delete_callback(SshSADHandle sad_handle,
		     SshIkev2Sa ike_sa,
		     SshIkev2ExchangeData ed,
		     SshIkev2Error error)
{
  clear_ike_sa(test_ctx, ike_sa);
}

void delete_ike_sa(void *context)
{
  SshIkev2Sa sa = (SshIkev2Sa) context;

  SSH_ASSERT(sa->flags & SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_IKEV1);

  ssh_ikev2_ike_sa_delete(sa, SSH_IKEV2_IKE_DELETE_FLAGS_NO_NOTIFICATION,
			  delete_callback);
}

void ikev2_ipsec_sa_created(SshSADHandle sad_handle,
			    SshIkev2Sa sa,
			    SshIkev2ExchangeData ed,
			    SshIkev2Error error)
{
  test_ctx->num_done++;

  SSH_DEBUG(SSH_D_HIGHSTART, ("IPsec SA create done error=%d "
			      "%d/%d done/total", error,
			      test_ctx->num_done, test_ctx->num_sas));
  if (error != SSH_IKEV2_ERROR_OK)
    {
      test_ctx->num_failed++;

      /* Mark the IKE as SA freed so as not to delete it later */
      clear_ike_sa(test_ctx, sa);
    }
  else
    {
      test_ctx->num_ok++;

#ifdef SSHDIST_IKEV1
      /* Delete the SA for IKEv1 since keeping large number of IKEv1 SA's 
	 in the isakmp library consumes more CPU than we'd like. */
      if (sa->flags & SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_IKEV1)
	ssh_xregister_timeout(1, 0, delete_ike_sa, sa);
#endif /* SSHDIST_IKEV1 */
    }

  /* Continue the thread when all operations are completed */
  if (test_ctx->num_done == test_ctx->num_sas)
    {
      SSH_DEBUG(SSH_D_HIGHOK, ("All negotiations completed, continuing "
			       "FSM thread"));
      ssh_fsm_continue(test_ctx->thread);
    }
}

void next_negotiation_callback(void *context)
{
  TestCtx test_ctx = context;

  SSH_DEBUG(SSH_D_MY, ("In timeout call, starting next negotiation"));
  SSH_FSM_CONTINUE_AFTER_CALLBACK(test_ctx->thread);
}

void repeat_test_callback(void *context)
{
  TestCtx test_ctx = context;
  SSH_FSM_CONTINUE_AFTER_CALLBACK(test_ctx->thread);
}

void ike_sa_delete_cb(SshSADHandle sad_handle,
		      SshIkev2Sa ike_sa,
		      SshIkev2ExchangeData ed,
		      SshIkev2Error error)
{
  test_ctx->sa_index++;
  SSH_FSM_CONTINUE_AFTER_CALLBACK(test_ctx->thread);
}



void ikev2_server_stopped(SshIkev2Error error, void *context)
{
  TestCtx test_ctx = (TestCtx) context;

  SSH_DEBUG(SSH_D_HIGHSTART,
	    ("IKEv2 server shut down done, error = %d", error));
  if (error != SSH_IKEV2_ERROR_OK)
    ssh_fatal("IKEv2 server stop failed");
  SSH_FSM_CONTINUE_AFTER_CALLBACK(test_ctx->thread);
}

#ifdef SSHDIST_EXTERNALKEY
void ek_free_cb(void *context)
{
  TestCtx test_ctx = (TestCtx) context;

  SSH_DEBUG(SSH_D_HIGHSTART, ("Externalkey freed"));
  SSH_FSM_CONTINUE_AFTER_CALLBACK(test_ctx->thread);
}
#endif /*  SSHDIST_EXTERNALKEY */

SSH_FSM_STEP(ikev2_sa_init);
SSH_FSM_STEP(ikev2_sa_allocate);
SSH_FSM_STEP(ikev2_sa_ipsec_prepare);
SSH_FSM_STEP(ikev2_sa_do_ipsec);
SSH_FSM_STEP(ikev2_wait_done);
SSH_FSM_STEP(ikev2_measure_test_time);
SSH_FSM_STEP(ikev2_repeat_test);
SSH_FSM_STEP(ikev2_stop);
SSH_FSM_STEP(ikev2_uninit);
SSH_FSM_STEP(ikev2_free_ek);
SSH_FSM_STEP(ikev2_stop_name_server);
SSH_FSM_STEP(ikev2_finish);


SSH_FSM_STEP(ikev2_sa_init)
{
  TestCtx test_ctx = (TestCtx) thread_context;

  /* Reserve memory for IKE SA pointers and local traffic selectors */
  test_ctx->sas = ssh_xcalloc(test_ctx->num_sas, sizeof(SshIkev2Sa));
  test_ctx->local_ts = ssh_xcalloc(test_ctx->num_sas,
				   sizeof(SshIkev2PayloadTS));

  test_ctx->sa_index = 0;

  SSH_FSM_SET_NEXT(ikev2_sa_allocate);
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ikev2_sa_allocate)
{
  TestCtx test_ctx = (TestCtx) thread_context;
  SshIkev2PayloadTS ts;
  SshIpAddrStruct local_address;
  SshUInt16 local_start_port, local_end_port;
  SshUInt32 flags = 0;
  SshUInt8 ipproto;

  if (test_ctx->sa_index == test_ctx->num_sas)
    {
      SSH_FSM_SET_NEXT(ikev2_sa_ipsec_prepare);
      return SSH_FSM_CONTINUE;
    }

  ts = ssh_ikev2_ts_allocate(sad_handle);
  if (ts == NULL)
    ssh_fatal("Cannot allocate traffic selector");

  if (test_ctx->use_port_ts)
    {
      local_start_port = test_ctx->local_start_port + test_ctx->sa_index;
      SSH_ASSERT(local_start_port <= test_ctx->local_end_port);
      local_end_port = local_start_port;
      local_address = *test_ctx->server->ip_address;
      ipproto = test_ctx->ipproto;
    }
  else
    {
      /* Generate a random IP address */
      SshUInt32 num;
      num = ssh_rand();

      SSH_INT_TO_IP4(&local_address, num);
      local_start_port = 0;
      local_end_port = 0xffff;
      ipproto = 0;
    }

  if (ssh_ikev2_ts_item_add(ts,
			    ipproto,
			    &local_address, &local_address,
			    local_start_port, local_end_port)
      != SSH_IKEV2_ERROR_OK)
    ssh_fatal("Cannot add traffic selector");

  test_ctx->local_ts[test_ctx->sa_index] = ts;

  SSH_DEBUG(SSH_D_HIGHSTART, ("Allocate IKE SA on server %p",
			      test_ctx->server));
#ifdef SSHDIST_IKEV1
  if (test_ctx->ikev1)
  flags = SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_IKEV1;
#endif /* SSHDIST_IKEV1 */

  SSH_FSM_ASYNC_CALL(ssh_ikev2_ike_sa_allocate(test_ctx->server,
					       &test_ctx->remote_ike_ip, flags,
					       ikev2_sa_allocated, test_ctx));
  SSH_NOTREACHED;
}

SSH_FSM_STEP(ikev2_sa_ipsec_prepare)
{
  TestCtx test_ctx = (TestCtx) thread_context;

  SSH_FSM_SET_NEXT(ikev2_sa_do_ipsec);

  ssh_time_measure_reset(test_ctx->timer);
  ssh_time_measure_start(test_ctx->timer);
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ikev2_sa_do_ipsec)
{
  TestCtx test_ctx = (TestCtx) thread_context;
  SshIkev2ExchangeData ed;
  int index = test_ctx->num_started;

  ed = ssh_ikev2_ipsec_create_sa(test_ctx->sas[index], 0);
  if (ed == NULL)
    ssh_fatal("Error allocating exchange data");

#ifdef SSHDIST_IKEV1
  if (test_ctx->ikev1)
    ed->ike_ed->exchange_type = SSH_IKE_XCHG_TYPE_IP; 
#endif /* SSHDIST_IKEV1 */
  
  SSH_DEBUG(SSH_D_HIGHSTART, ("Create IPsec SA (number %d)", index + 1));

  ssh_ikev2_ipsec_send(ed, NULL, test_ctx->local_ts[index],
		       tsi_remote,
		       ikev2_ipsec_sa_created);
  
  /* One more IKE negotiation started */
  if (++test_ctx->num_started == test_ctx->num_sas)
    {
      SSH_DEBUG(SSH_D_HIGHOK, ("All negotations started, suspending "
			       "until completion"));
      SSH_FSM_SET_NEXT(ikev2_wait_done);
      return SSH_FSM_CONTINUE;
    }
  else
    {
      SSH_FSM_ASYNC_CALL(ssh_xregister_timeout(0, test_ctx->sleep_microsecs,
					       next_negotiation_callback,
					       test_ctx));
      SSH_NOTREACHED;
    }
}

SSH_FSM_STEP(ikev2_wait_done)
{
  TestCtx test_ctx = (TestCtx) thread_context;

  /* Wait until all negotiations are completed */
  if (test_ctx->num_done != test_ctx->num_sas)
    return SSH_FSM_SUSPENDED;

  SSH_FSM_SET_NEXT(ikev2_measure_test_time);
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ikev2_measure_test_time)
{
  TestCtx test_ctx = (TestCtx) thread_context;
  SshIkev2GlobalStatistics stats;
  unsigned int current_time, sleep_time;
  
  /* All negotations are done, now get the time elapsed. */
  ssh_time_measure_stop(test_ctx->timer);
  
  current_time = (unsigned int)
    ssh_time_measure_get(test_ctx->timer,
			 SSH_TIME_GRANULARITY_MILLISECOND);

  if ((test_ctx->min_time == 0 || current_time < test_ctx->min_time) &&
      test_ctx->num_failed == 0)
    test_ctx->min_time = current_time;
  
  /* Print out some statistics from the IKE server */
  stats = test_ctx->server->statistics;

  if (stats->total_retransmits || stats->total_init_no_response)
    {
      SSH_DEBUG(1, ("Failure information"));
      SSH_DEBUG(1, ("Number of retransmitted packets : %d",
	      (int)stats->total_retransmits));
      SSH_DEBUG(1, ("Number of negotations for which no response "
		    "was received : %d", (int)stats->total_init_no_response));
    }      

  /* Update the current and previous test times  */  
  if (test_ctx->current_time)
    test_ctx->prev_time = test_ctx->current_time;
  test_ctx->current_time = current_time;

  SSH_DEBUG(2, ("Current test results:"));
  SSH_DEBUG(2, ("%d IKE negotiations completed in %d milliseconds",
		test_ctx->num_done, current_time));
  
  if (test_ctx->num_failed)
    SSH_DEBUG(1, ("%d IKE negotiations have failed, results inconclusive",
		  test_ctx->num_failed));

  /* Update the timeout parameter if repeating the test */
  if (test_ctx->repeat_test)
    {
      Boolean improving = TRUE;
      
      if (test_ctx->prev_time && 
	  (test_ctx->current_time > test_ctx->prev_time))
	improving = FALSE;
      
      SSH_DEBUG(3, ("Current/Previous test elapsed time %d %d",
		    test_ctx->current_time, test_ctx->prev_time));

      /* Save the last sleep timeout as ike_perf_tune_params modifies it */
      sleep_time = test_ctx->sleep_microsecs;
      
      if (!ike_perf_tune_params(test_ctx, improving))
	{
	  test_ctx->do_repeat = TRUE;
	  fprintf(stdout, "%d/%d negotiations done/failed in %d "
		  "milliseconds: timeout %d repeating ...\n",
		  test_ctx->num_done,
		  test_ctx->num_failed,
		  test_ctx->current_time,
		  sleep_time);
	  fflush(stdout);  
	}
    }
  
  test_ctx->sa_index = 0;
  
  SSH_FSM_SET_NEXT(ikev2_stop);
  return SSH_FSM_CONTINUE;
}


SSH_FSM_STEP(ikev2_stop)
{
  TestCtx test_ctx = (TestCtx) thread_context;
  int idx;

  ssh_cancel_timeouts(delete_ike_sa, SSH_ALL_CONTEXTS);

  if (test_ctx->delete_ike_sas)
    { 
      /* Send delete notifications for the established IKE SA's */
    again:
      if (test_ctx->sa_index < test_ctx->num_sas)
	{
	  idx = test_ctx->sa_index;
	  
	  if (test_ctx->sas[idx] && 
	      test_ctx->sas[idx]->flags & SSH_IKEV2_IKE_SA_FLAGS_IKE_SA_DONE)
	    {
	      SSH_DEBUG(10, ("Deleting SA %d", idx));
	      SSH_FSM_ASYNC_CALL(ssh_ikev2_ike_sa_delete(test_ctx->sas[idx],
							 0, ike_sa_delete_cb));
	      SSH_NOTREACHED;
	    }      
	  else
	    {
	      test_ctx->sa_index++;
	      goto again;
	    }
	}
    }
  else
    {
      for (idx = 0; idx < test_ctx->num_sas; idx++)
	test_ctx->sas[idx] = NULL;
    }

  for (idx = 0; idx < test_ctx->num_sas; idx++)
    ssh_ikev2_ts_free(sad_handle, test_ctx->local_ts[idx]);

  if (test_ctx->do_repeat)
    {
      SSH_FSM_SET_NEXT(ikev2_repeat_test);
    }
  else
    {
      ssh_ikev2_ts_free(sad_handle, tsi_remote); 
      SSH_FSM_SET_NEXT(ikev2_uninit);
    }

  SSH_DEBUG(SSH_D_LOWOK, ("Shutting down IKE server"));

  SSH_FSM_ASYNC_CALL(ssh_ikev2_server_stop(test_ctx->server, 0,
					   ikev2_server_stopped,
					   test_ctx));
  SSH_NOTREACHED;
}


SSH_FSM_STEP(ikev2_repeat_test)
{
  TestCtx test_ctx = (TestCtx) thread_context;

  ssh_xfree(test_ctx->sas);
  ssh_xfree(test_ctx->local_ts);

  /* Restart the IKE server. */
  test_ctx->server = ssh_ikev2_server_start(ikev2, 
					    &test_ctx->local_ike_ip,
					    test_ctx->local_ike_port, 4500,
					    test_ctx->remote_ike_port, 4500,
					    &dummy_if, sad_handle);
  if (test_ctx->server  == NULL)
    {
      ssh_warning("ikev2 server start failed");
      exit(1);
    } 

  /* Reset variables */
  test_ctx->do_repeat = FALSE;
  test_ctx->num_started = 0;
  test_ctx->num_done = 0;
  test_ctx->num_ok = 0;
  test_ctx->num_failed = 0;
  ssh_time_measure_init(test_ctx->timer);
  
  SSH_FSM_SET_NEXT(ikev2_sa_init);

  SSH_DEBUG(SSH_D_LOWOK, ("Scheduling %d second timeout to restart test",
			  test_ctx->repeat_test_timeout));

  SSH_FSM_ASYNC_CALL(ssh_xregister_timeout(test_ctx->repeat_test_timeout, 0,
					   repeat_test_callback,
					   test_ctx));
  SSH_NOTREACHED;
}

SSH_FSM_STEP(ikev2_uninit)
{
  /* Display test results */
  fprintf(stdout, "Best achieved test results:\n");

  if (test_ctx->min_time)
    {
      fprintf(stdout, "\t%d IKE negotiations completed in %d milliseconds\n",
	      test_ctx->num_done, test_ctx->min_time);
    }
  else
    {  
      fprintf(stdout, "\n Test results inconclusive\n");
      if (test_ctx->num_failed)
	fprintf(stdout, "\n%d IKE negotiations have failed\n",
		test_ctx->num_failed);
    }  

  SSH_DEBUG(SSH_D_HIGHSTART, ("Destroying IKEv2"));

  d_sad_destroy(sad_handle);
  d_pad_destroy();

  SSH_FSM_SET_NEXT(ikev2_free_ek);
  
  ssh_ikev2_destroy(ikev2);
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ikev2_free_ek)
{
  TestCtx test_ctx = (TestCtx) thread_context;

#ifdef SSHDIST_EXTERNALKEY
  SSH_DEBUG(SSH_D_HIGHSTART, ("Destroying External Key"));

  SSH_FSM_SET_NEXT(ikev2_stop_name_server);

  if (test_ctx->short_name)
    ssh_free(test_ctx->short_name);

  if (test_ctx->externalkey)
    SSH_FSM_ASYNC_CALL(ssh_ek_free(test_ctx->externalkey,
				   ek_free_cb,
				   test_ctx));
  else
    return SSH_FSM_CONTINUE;
#else /*  SSHDIST_EXTERNALKEY */
  SSH_FSM_SET_NEXT(ikev2_stop_name_server);
  return SSH_FSM_CONTINUE;
#endif /*  SSHDIST_EXTERNALKEY */
}

SSH_FSM_STEP(ikev2_stop_name_server)
{
  SSH_DEBUG(SSH_D_HIGHSTART, ("Shutting down name server"));

  SSH_FSM_SET_NEXT(ikev2_finish);
#ifdef SSHDIST_UTIL_TCP
  ssh_name_server_uninit();
#endif /* SSHDIST_UTIL_TCP */
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ikev2_finish)
{
  SSH_DEBUG(SSH_D_HIGHSTART, ("Finish"));

#ifdef HAVE_THREADS
  ssh_threaded_timeouts_uninit();
#endif /* HAVE_THREADS */

  return SSH_FSM_FINISH;
}

/* ------------------------------------------------------------------------- */


void usage(char *program, Boolean help)
{
  fprintf(stderr, "Usage: %s [OPTION]... DESTINATION\n"
	  "\t-n : [number] Number of IKE SA's to generate\n"
	  "\t-t : [number] Timeout (microseconds) between IKE negotations\n"
	  "\t-R : [number] IKE retry limit\n"
	  "\t-T : [number] IKE base retry timer in milliseconds\n"
	  "\t-i : [address] Local IP address\n"
	  "\t-p : [port] Local IKE port\n"
	  "\t-P : [port] Remote IKE port\n"
	  "\t-o : [string] Local traffic selectors IP protocol\n"
	  "\t-z : Use ports for local traffic selectors\n"
	  "\t-S : [traffic selector] Remote traffic selector\n"
	  "\t-r : [number] Repeat test until no packet retransmits,\n"
	  "\t     wait [number] seconds between tests\n"  
	  "\t-D : Delete established IKE SA's when starting a new test with\n"
	  "\t     the -r option\n"  
	  "\t-x : Use certificates for authentication\n"
#ifdef SSHDIST_IKEV1
	  "\t-v : Use IKE version 1 (note that ESN is proposed for\n"
	  "\t     IKEv1 when using the default policy)\n"
#endif /* SSHDIST_IKEV1 */
#ifdef SSHDIST_IKE_EAP_AUTH
#ifdef SSHDIST_EAP
	  "\t-E : Use EAP for authentication\n"
#endif /* SSHDIST_EAP */
#endif /* SSHDIST_IKE_EAP_AUTH */
#ifdef SSHDIST_EXTERNALKEY
	  "\t-y : [string] Externalkey type\n"
	  "\t-Y : [string] Externalkey init info\n"
#endif /* SSHDIST_EXTERNALKEY */
	  "\t-f : [policy file] Policy file\n"
	  "\t-g : [policy file] PAD policy file\n"
	  "\t-d : [string] Debug string\n"
	  "\t-h : Print usage information\n\n",
	  program);
  
  if (help)
    fprintf(stderr, 
	    "Description:\n"
	    "\t ikev2-perftool is a utility for measuring the IKE SA setup\n"
	    "\t performance rate of an IKE peer. The program establishes  \n"
	    "\t the required number of IKE SA's with the specified remote \n"
	    "\t peer and returns the elapsed time.\n\n"
	    "\t To determine the maximum rate a IKE peer can establish IKE\n"
	    "\t connections, the -t parameter will need to be tuned. If the \n"
	    "\t -r option is specified, the program will try to find the \n"
	    "\t optimal value for the timeout interval parameter specified\n" 
	    "\t by -t by repeating the test with different timeout values\n"
	    "\t until a optimal value is found.\n\n"
	    
	    "\t The traffic selectors that the program uses for Create Child\n"
	    "\t SA's are specified by the -o, -z and -S options. The remote \n"
	    "\t traffic selector is specified by the -S option, the default \n"
	    "\t value is ipv4(0.0.0.0.0/0), this traffic selector is the \n"
	    "\t same for each SA established. \n\n"
	    
	    "\t Local traffic selectors differ for each SA established, the \n"
	    "\t default is to generate a random IPv4 address X, and use the \n"
	    "\t local traffic selector ipv4(X). The alternative (with -z \n"
	    "\t specified) is to use a single port range with the local IP \n"
	    "\t address as the traffic selector, the IP protocol may also be\n"
	    "\t specified using the -o option.\n\n"
	    
	    "\t The program reads its PAD configuration from the file \n"
	    "\t specified by -g, the default file is certificates.config.\n"
	    "\t The PAD file format is the same as in the t-ikev2 program.\n\n"
	    
	    "\t The policy on the remote IKE peer needs to be configured \n"
	    "\t to match the policy settings of this test program.\n");
  
}

int main(int argc, char **argv)
{
  struct SshIkev2ParamsRec params;
  SshUInt32 retry_timer_msec, retry_limit;
  const char *tsi_remote_string = NULL;
  const char *debug_string = NULL;
  const char *policy = NULL;
  const char *cert_config = "certificates.config";
  char *program;
  char *local_ip = "0.0.0.0";
  char *ipproto  = NULL;
  char *ek_accelerator_type = NULL;
  char *ek_accelerator_init_info = NULL;
  char *remote_ip = NULL;
  int c, errflg = 0;

  retry_timer_msec = retry_limit = 0;

  test_ctx = ssh_xcalloc(1, sizeof(*test_ctx));
  test_ctx->sleep_microsecs = 50000;
  test_ctx->num_sas = 100;
  test_ctx->local_ike_port = 500;
  test_ctx->remote_ike_port = 500;

  memset(&params, 0, sizeof(params));

   program = strrchr(argv[0], '/');
  if (program == NULL)
    program = argv[0];
  else
    program++;

  while ((c = ssh_getopt(argc, argv, "n:t:d:i:p:R:T:P:o:ES:f:y:Y:g:r:vhxzD", 
			 NULL))
         != EOF)
    {
      switch (c)
	{
        case 'n': test_ctx->num_sas = atoi(ssh_optarg); break;
        case 't': test_ctx->sleep_microsecs = atoi(ssh_optarg); break;
        case 'd': debug_string = ssh_optarg; break;
	case 'i': local_ip = ssh_optarg; break;
	case 'p': test_ctx->local_ike_port = atoi(ssh_optarg); break;
 	case 'P': test_ctx->remote_ike_port = atoi(ssh_optarg); break;
	case 'o': ipproto = ssh_optarg; break;
#ifdef SSHDIST_IKE_EAP_AUTH
#ifdef SSHDIST_EAP
	case 'E': use_eap = TRUE; break;
#endif /* SSHDIST_EAP */
#endif /* SSHDIST_IKE_EAP_AUTH */
	case 'S': tsi_remote_string = ssh_optarg; break;
	case 'f': policy = ssh_optarg; break;
        case 'y': ek_accelerator_type = ssh_optarg; break;
        case 'Y': ek_accelerator_init_info = ssh_optarg; break;
	case 'g': cert_config = ssh_optarg; break;
	case 'x': use_certs = TRUE; break;
#ifdef SSHDIST_IKEV1
	case 'v': test_ctx->ikev1 = TRUE; break;
#endif /* SSHDIST_IKEV1 */
	case 'z': test_ctx->use_port_ts = TRUE; break;
	case 'r': 
	  test_ctx->repeat_test = TRUE; 
	  test_ctx->repeat_test_timeout = atoi(ssh_optarg);
	  break; 
	case 'D': test_ctx->delete_ike_sas = TRUE; break;
        case 'R': retry_limit = atoi(ssh_optarg); break;
        case 'T': retry_timer_msec = atoi(ssh_optarg); break;
	case 'h': usage(program, TRUE); exit(0);
        }
    }

  /* Destination address. */
  if (ssh_optind >= argc)
    {
      fprintf(stderr, "%s: No destination IP address specified\n",
              program);
      usage(program, FALSE);
      exit(1);
    }
  remote_ip = argv[ssh_optind++];

  if (errflg || argc - ssh_optind != 0)
    {
      usage(program, FALSE);
      exit(1);
    }

  ssh_event_loop_initialize();

#ifdef HAVE_THREADS
  ssh_threaded_timeouts_init();
#endif /* HAVE_THREADS */

#ifdef DEBUG_LIGHT
  if (debug_string)
    ssh_debug_set_level_string(debug_string);
#endif /* DEBUG_LIGHT */

#ifdef SSHDIST_IKE_CERT_AUTH
  if (!ssh_x509_library_initialize(NULL))
    ssh_fatal("Cannot initialize certificate and crypto library");
#else /* SSHDIST_IKE_CERT_AUTH */
  if (ssh_crypto_library_initialize() != SSH_CRYPTO_OK)
    ssh_fatal("Cannot initialize the crypto library");
#endif /* SSHDIST_IKE_CERT_AUTH */

#ifdef SSHDIST_CRYPT_ECP
  ssh_pk_provider_register(&ssh_pk_ec_modp);
#endif /* SSHDIST_CRYPT_ECP */




  /* Init externalkey if an accelerator has been specified. */
#ifdef SSHDIST_EXTERNALKEY
  if (ek_accelerator_type)
    {
      SshEkStatus status;

      test_ctx->externalkey = ssh_ek_allocate();
      if (test_ctx->externalkey == NULL)
	ssh_fatal("Cannot allocate external key");

      /* Add accelerator provider. */
      status = ssh_ek_add_provider(test_ctx->externalkey,
                                   ek_accelerator_type,
                                   ek_accelerator_init_info,
                                   NULL,
                                   SSH_EK_PROVIDER_FLAG_KEY_ACCELERATOR,
                                   &test_ctx->short_name);
      if (status != SSH_EK_OK)
	ssh_fatal("Cannot add external key provider %s (%s)",
		  ek_accelerator_type,
		  ek_accelerator_init_info);

      params.external_key = test_ctx->externalkey;
      params.accelerator_short_name = test_ctx->short_name;
    }
  else
    {
      test_ctx->externalkey = NULL;
      test_ctx->short_name = NULL;
    }
#endif /* SSHDIST_EXTERNALKEY */

  params.retry_limit = retry_limit;
  params.retry_timer_msec = retry_timer_msec;

  /* Parse IP addresses */
  if (!ssh_ipaddr_parse(&test_ctx->local_ike_ip, local_ip))
    ssh_fatal("Invalid IP address specified  %s", local_ip);

  if (!ssh_ipaddr_parse(&test_ctx->remote_ike_ip, remote_ip))
    ssh_fatal("Cannot parse the remote IP address %s", remote_ip);

  sad_handle = d_sad_allocate(policy);

  d_pad_allocate(cert_config);

  /* Convert traffic selector */
  if (tsi_remote_string == NULL)
    tsi_remote_string = "ipv4(0.0.0.0/0)";
  tsi_remote = ssh_ikev2_ts_allocate(sad_handle);
  if (tsi_remote == NULL)
    ssh_fatal("TS allocation failed");
  if (ssh_ikev2_string_to_ts(tsi_remote_string, tsi_remote) == -1)
    ssh_fatal("Remote TS parsing failed");


#ifdef SSHDIST_IKEV1
  if (test_ctx->ikev1)
    {
      memset(&params.v1_params, 0, sizeof(params.v1_params));
      params.v1_fallback = TRUE;
      params.v1_params->max_isakmp_sa_count = test_ctx->num_sas + 100;
      params.v1_params->spi_size = 0;
      params.v1_params->zero_spi = TRUE;
      params.v1_params->base_retry_limit = params.retry_limit;
    }
#endif /* SSHDIST_IKEV1 */

   /* Create IKE context */
  ikev2 = ssh_ikev2_create(&params);
  if (ikev2 == NULL)
    ssh_fatal("Ikev2 create failed");

  if (test_ctx->use_port_ts)
    {
      test_ctx->local_start_port = ssh_rand() % 0xffff;
      test_ctx->local_end_port =
	test_ctx->local_start_port + test_ctx->num_sas;
      if (test_ctx->local_end_port > 0xffff)
	test_ctx->local_end_port = test_ctx->local_end_port - 0xffff;
    }

  if (ipproto == NULL)
    test_ctx->ipproto = SSH_IPPROTO_ANY;
  else
    test_ctx->ipproto = ssh_find_keyword_number(ssh_ip_protocol_id_keywords,
						ipproto);
  if (test_ctx->ipproto == -1)
    {
      usage(program, FALSE);
      ssh_warning("Invalid IP proto specified");
      exit(1);
    }

  /* Start the IKE server. */
  test_ctx->server = ssh_ikev2_server_start(ikev2, 
					    &test_ctx->local_ike_ip,
					    test_ctx->local_ike_port, 4500,
					    test_ctx->remote_ike_port, 4500,
					    &dummy_if, sad_handle);
  if (test_ctx->server == NULL)
    {
      ssh_warning("ikev2 server start failed");
      exit(1);
    } 
  ssh_time_measure_init(test_ctx->timer);

  ssh_fsm_init(test_ctx->fsm, NULL);
  ssh_fsm_thread_init(test_ctx->fsm, test_ctx->thread, ikev2_sa_init, NULL,
		      NULL_FNPTR, test_ctx);

  ssh_event_loop_run();

  ssh_fsm_uninit(test_ctx->fsm);
#ifdef SSHDIST_UTIL_TCP
  ssh_name_server_uninit();
#endif /* SSHDIST_UTIL_TCP */

  ssh_xfree(test_ctx->sas);
  ssh_xfree(test_ctx->local_ts);
  ssh_xfree(test_ctx);

#ifdef SSHDIST_IKE_CERT_AUTH
  ssh_x509_library_uninitialize();
#else /* SSHDIST_IKE_CERT_AUTH */
  ssh_crypto_library_uninitialize();
#endif /* SSHDIST_IKE_CERT_AUTH */

  ssh_event_loop_uninitialize();

#ifdef DEBUG_LIGHT
  ssh_debug_uninit();
#endif /* DEBUG_LIGHT */
  ssh_global_uninit();












  return 0;
}
