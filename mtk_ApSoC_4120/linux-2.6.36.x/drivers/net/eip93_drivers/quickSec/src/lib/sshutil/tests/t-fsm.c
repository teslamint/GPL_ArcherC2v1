/*
 *
 * t-fsm.c
 *
 * Author: Markku Rossi <mtr@ssh.fi>
 *
 * Copyright:
 * 	Copyright (c) 2002, 2003, 2005 SFNT Finland Oy.
 *      All rights reserved.
 *
 * Regression test for FSM.
 *
 */

#include "sshincludes.h"
#include "ssheloop.h"
#include "sshtimeouts.h"
#include "sshfsm.h"
#include "sshtime.h"

#define SSH_DEBUG_MODULE "t-fsm2"

/********************** Prototypes for state functions **********************/

SSH_FSM_STEP(loop);
SSH_FSM_STEP(main_start);
SSH_FSM_STEP(main_loop_done);

SSH_FSM_STEP(waiter);
SSH_FSM_STEP(waiter_done);
SSH_FSM_STEP(main_wait_many);
SSH_FSM_STEP(main_wait_many_wait);

SSH_FSM_STEP(wait_cond);
SSH_FSM_STEP(main_condition_test);
SSH_FSM_STEP(main_condition_test_signal);
SSH_FSM_STEP(main_condition_test_signal_done);
SSH_FSM_STEP(main_condition_test_broadcast_done);
SSH_FSM_STEP(main_condition_test_destroy_done);

SSH_FSM_STEP(kenny);
SSH_FSM_STEP(main_kill_thread);
SSH_FSM_STEP(main_kill_thread_do_kill);

SSH_FSM_STEP(main_async_call);
SSH_FSM_STEP(main_async_call_done);
SSH_FSM_STEP(main_async_sync_call_done);

SSH_FSM_STEP(wait_msg);
SSH_FSM_STEP(wait_msg_done);
SSH_FSM_STEP(main_msg);
SSH_FSM_STEP(main_msg_send);
SSH_FSM_STEP(main_msg_wait_done);

SSH_FSM_STEP(slow_loop);
SSH_FSM_STEP(main_suspend_start);
SSH_FSM_STEP(main_all_done);

/* Testing FSM debugging.  You do not have to create the state array
   unless you want to get FSM level debugging from the state machine.
   To demonstrate this, we initalize just three states although our
   test case contains many more. */
static SshFSMStateDebugStruct state_array[] =
{
  SSH_FSM_STATE("loop", "Loop counter", loop)
  SSH_FSM_STATE("main-start", "Main start", main_start)
  SSH_FSM_STATE("main-loop-done", "Main loop done", main_loop_done)

  SSH_FSM_STATE("waiter", "Waiter", waiter)
  SSH_FSM_STATE("waiter_done", "Waiter done", waiter_done)
  SSH_FSM_STATE("main_wait_many", "Main wait many", main_wait_many)
  SSH_FSM_STATE("main_wait_many_wait", "Main wait many wait",
		main_wait_many_wait)

  SSH_FSM_STATE("wait_cond", "Wait cond", wait_cond)
  SSH_FSM_STATE("main_condition_test", "Main condition test",
		main_condition_test)
  SSH_FSM_STATE("main_condition_test_signal", "Main condition test signal",
		main_condition_test_signal)
  SSH_FSM_STATE("main_condition_test_signal_done",
		"Main condition test signal done",
		main_condition_test_signal_done)
  SSH_FSM_STATE("main_condition_test_broadcast_done",
		"Main condition test broadcast done",
		main_condition_test_broadcast_done)
  SSH_FSM_STATE("main_condition_test_destroy_done",
		"Main condition test destroy done",
		main_condition_test_destroy_done)

  SSH_FSM_STATE("kenny", "Kenny", kenny)
  SSH_FSM_STATE("main_kill_thread", "Main kill thread", main_kill_thread)
  SSH_FSM_STATE("main_kill_thread_do_kill", "Main kill thread do kill",
		main_kill_thread_do_kill)

  SSH_FSM_STATE("main_async_call", "Main async call", main_async_call)
  SSH_FSM_STATE("main_async_call_done", "Main async call done",
		main_async_call_done)
  SSH_FSM_STATE("main_async_sync_call_done",
		"Main async sync call done", main_async_sync_call_done)

  SSH_FSM_STATE("wait_msg", "Wait msg", wait_msg)
  SSH_FSM_STATE("wait_msg_done", "Wait msg done", wait_msg_done)
  SSH_FSM_STATE("main_msg", "Main msg", main_msg)
  SSH_FSM_STATE("main_msg_send", "Main msg send", main_msg_send)
  SSH_FSM_STATE("main_msg_wait_done", "Main msg wait done", main_msg_wait_done)
};

static int num_states = SSH_FSM_NUM_STATES(state_array);


/******************************** Test cases ********************************/

int errors = 0;

int done;
int rounds;

SshFSMThreadStruct thread1;

#define NUM_THREADS 100

int num_threads = 0;
SshFSMThread threads[NUM_THREADS];

SshFSMConditionStruct cond;


/******************** Waiting for a thread to terminate *********************/

SSH_FSM_STEP(loop)
{
#ifdef DEBUG_LIGHT
  char *name = (char *) thread_context;
#endif /* DEBUG_LIGHT */

  SSH_DEBUG(SSH_D_LOWOK, ("%s: rounds=%d", name, rounds));

  if (--rounds <= 0)
    return SSH_FSM_FINISH;

  return SSH_FSM_YIELD;
}

SSH_FSM_STEP(main_start)
{
  rounds = 100;
  ssh_fsm_thread_init(fsm, &thread1, loop, NULL_FNPTR, NULL_FNPTR, "loop");
  ssh_fsm_set_thread_name(&thread1, "Loop");

  SSH_FSM_SET_NEXT(main_loop_done);
  SSH_FSM_WAIT_THREAD(&thread1);
}

SSH_FSM_STEP(main_loop_done)
{
  if (rounds != 0)
    errors++;

  SSH_DEBUG(SSH_D_NICETOKNOW, ("Thread wait works"));

  SSH_FSM_SET_NEXT(main_wait_many);

  return SSH_FSM_CONTINUE;
}

/**** Waiting for multiple threads which wait for a thread to terminate. ****/

SSH_FSM_STEP(waiter)
{
#ifdef DEBUG_LIGHT
  int idx = (int) thread_context;
#endif /* DEBUG_LIGHT */

  SSH_DEBUG(SSH_D_LOWSTART, ("Waiter %d starting", idx));

  SSH_FSM_SET_NEXT(waiter_done);
  SSH_FSM_WAIT_THREAD(&thread1);
}

SSH_FSM_STEP(waiter_done)
{
  int idx = (int) thread_context;

  SSH_DEBUG(SSH_D_LOWOK, ("Waiter %d done", idx));

  threads[idx] = NULL;
  num_threads--;
  SSH_FSM_CONDITION_SIGNAL(&cond);
  return SSH_FSM_FINISH;
}

SSH_FSM_STEP(main_wait_many)
{
  /* Create the loop thread. */
  rounds = 100;
  ssh_fsm_thread_init(fsm, &thread1, loop, NULL_FNPTR, NULL_FNPTR, "loop");
  ssh_fsm_set_thread_name(&thread1, "Loop");

  /* Create some waiters. */
  for (num_threads = 0; num_threads < NUM_THREADS; num_threads++)
    {
      threads[num_threads] = ssh_fsm_thread_create(fsm, waiter, NULL_FNPTR,
                                                   NULL_FNPTR,
                                                   (void *) num_threads);
      ssh_fsm_set_thread_name(threads[num_threads], "waiter");
      SSH_ASSERT(threads[num_threads]);
    }

  /* And wait that the waiters are done. */
  SSH_FSM_SET_NEXT(main_wait_many_wait);
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(main_wait_many_wait)
{
  int i;

  if (num_threads > 0)
    SSH_FSM_CONDITION_WAIT(&cond);

  SSH_DEBUG(SSH_D_NICETOKNOW, ("Waiters done."));

  for (i = 0; i < NUM_THREADS; i++)
    if (threads[i] != NULL)
      {
        SSH_DEBUG(SSH_D_ERROR, ("Waiter %d not exited correctly", i));
        errors++;
      }

  SSH_FSM_SET_NEXT(main_condition_test);
  return SSH_FSM_CONTINUE;
}


/*************************** Condition variables ****************************/

SSH_FSM_STEP(wait_cond)
{
  int idx = (int) thread_context;

  SSH_DEBUG(SSH_D_NICETOKNOW, ("Waiter %d", idx));
  rounds++;

  if (!done)
    SSH_FSM_CONDITION_WAIT(&cond);

  SSH_DEBUG(SSH_D_NICETOKNOW, ("Waiter %d done", idx));
  threads[idx] = NULL;
  return SSH_FSM_FINISH;
}

SSH_FSM_STEP(main_condition_test)
{
  done = 0;
  rounds = 0;

  /* Create waiters for condition. */
  SSH_DEBUG(SSH_D_NICETOKNOW, ("Starting waiters"));
  for (num_threads = 0; num_threads < NUM_THREADS; num_threads++)
    {
      threads[num_threads] = ssh_fsm_thread_create(fsm, wait_cond,
                                                   NULL_FNPTR, NULL_FNPTR,
                                                   (void *) num_threads);
      ssh_fsm_set_thread_name(threads[num_threads], "waiting condition");
      SSH_ASSERT(threads[num_threads]);
    }

  SSH_FSM_SET_NEXT(main_condition_test_signal);
  return SSH_FSM_YIELD;
}

SSH_FSM_STEP(main_condition_test_signal)
{
  if (rounds != NUM_THREADS)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Condition waiters have not started yet"));
      errors++;
    }
  rounds = 0;

  /* Wake up one. */

  SSH_DEBUG(SSH_D_NICETOKNOW, ("Signalling condition"));
  SSH_FSM_CONDITION_SIGNAL(&cond);

  SSH_FSM_SET_NEXT(main_condition_test_signal_done);

  return SSH_FSM_YIELD;
}

SSH_FSM_STEP(main_condition_test_signal_done)
{
  if (rounds != 1)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Signal woke up more that one thread"));
      errors++;
    }
  rounds = 0;

  /* Wake them all. */

  SSH_DEBUG(SSH_D_NICETOKNOW, ("Broadcasting condition"));
  SSH_FSM_CONDITION_BROADCAST(&cond);

  SSH_FSM_SET_NEXT(main_condition_test_broadcast_done);

  return SSH_FSM_YIELD;
}

SSH_FSM_STEP(main_condition_test_broadcast_done)
{
  if (rounds != NUM_THREADS)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Broadcast did not wake all threads"));
      errors++;
    }
  rounds = 0;
  done = 1;

  /* Destroy them all. */

  SSH_DEBUG(SSH_D_NICETOKNOW, ("Destroying waiters"));
  SSH_FSM_CONDITION_BROADCAST(&cond);

  SSH_FSM_SET_NEXT(main_condition_test_destroy_done);

  return SSH_FSM_YIELD;
}

SSH_FSM_STEP(main_condition_test_destroy_done)
{
  int i;

  if (rounds != NUM_THREADS)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Broadcast did not wake all threads"));
      errors++;
    }

  for (i = 0; i < NUM_THREADS; i++)
    if (threads[i] != NULL)
      {
        SSH_DEBUG(SSH_D_ERROR, ("Waiter %d not exited correctly", i));
        errors++;
      }

  SSH_FSM_SET_NEXT(main_kill_thread);
  return SSH_FSM_CONTINUE;
}


/****************************** Killing thread ******************************/

SSH_FSM_STEP(kenny)
{
#ifdef DEBUG_LIGHT
  char *name = (char *) thread_context;
#endif /* DEBUG_LIGHT */

  SSH_ASSERT(!SSH_FSM_IS_THREAD_DONE(&thread1));
  SSH_ASSERT(SSH_FSM_IS_THREAD_RUNNING(&thread1));
  SSH_ASSERT(SSH_FSM_THREAD_EXISTS(&thread1));
  SSH_DEBUG(SSH_D_NICETOKNOW, ("%s: suspending", name));
  return SSH_FSM_SUSPENDED;
}

static void
kenny_destructor(SshFSM fsm, void *context)
{
#ifdef DEBUG_LIGHT
  char *name = (char *) context;
#endif /* DEBUG_LIGHT */

  SSH_ASSERT(SSH_FSM_IS_THREAD_DONE(&thread1));
  SSH_ASSERT(!SSH_FSM_IS_THREAD_RUNNING(&thread1));
  SSH_ASSERT(!SSH_FSM_THREAD_EXISTS(&thread1));

  SSH_DEBUG(SSH_D_NICETOKNOW, ("Oh my God, they killed %s!", name));
  rounds++;
}

SSH_FSM_STEP(main_kill_thread)
{
  rounds = 0;

  SSH_ASSERT(!SSH_FSM_THREAD_EXISTS(&thread1));
  ssh_fsm_thread_init(fsm, &thread1, kenny, NULL_FNPTR,
                      kenny_destructor, "Kenny");
  SSH_ASSERT(!SSH_FSM_IS_THREAD_DONE(&thread1));
  SSH_ASSERT(SSH_FSM_THREAD_EXISTS(&thread1));

  ssh_fsm_set_thread_name(&thread1, "Kenny");

  SSH_FSM_SET_NEXT(main_kill_thread_do_kill);
  return SSH_FSM_YIELD;
}

SSH_FSM_STEP(main_kill_thread_do_kill)
{
  ssh_fsm_kill_thread(&thread1);

  if (rounds != 1)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Killing thread did not call destructor"));
      errors++;
    }

  SSH_FSM_SET_NEXT(main_async_call);
  return SSH_FSM_YIELD;
}


/**************************** Asynchronous calls ****************************/

static void
timeout_cb(void *context)
{
  SshFSMThread thread = context;

  SSH_DEBUG(SSH_D_NICETOKNOW, ("In timeout callback."));

  done = 1;
  SSH_FSM_CONTINUE_AFTER_CALLBACK(thread);
}

SSH_FSM_STEP(main_async_call)
{
  done = 0;
  SSH_FSM_SET_NEXT(main_async_call_done);
  SSH_FSM_ASYNC_CALL(ssh_xregister_timeout(0, 500000, timeout_cb, thread));
}

SSH_FSM_STEP(main_async_call_done)
{
  if (!done)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Asynchronous call did not set done"));
      errors++;
    }

  done = 0;
  SSH_FSM_SET_NEXT(main_async_sync_call_done);
  SSH_FSM_ASYNC_CALL(timeout_cb(thread));
}

SSH_FSM_STEP(main_async_sync_call_done)
{
  if (!done)
    {
      SSH_DEBUG(SSH_D_ERROR,
                ("Synchronous asynchronous call did not set done"));
      errors++;
    }

  SSH_FSM_SET_NEXT(main_msg);
  return SSH_FSM_CONTINUE;
}


/********************************* Messages *********************************/

SSH_FSM_STEP(wait_msg)
{
#ifdef DEBUG_LIGHT
  int idx = (int) thread_context;
#endif /* DEBUG_LIGHT */

  SSH_DEBUG(SSH_D_NICETOKNOW, ("Waiter %d started", idx));
  rounds++;

  return SSH_FSM_SUSPENDED;
}

SSH_FSM_STEP(wait_msg_done)
{
  int idx = (int) thread_context;

  SSH_DEBUG(SSH_D_NICETOKNOW, ("Waiter %d dying", idx));

  threads[idx] = NULL;
  num_threads--;
  rounds++;

  SSH_FSM_CONDITION_SIGNAL(&cond);
  return SSH_FSM_FINISH;
}

static void
message_handler(SshFSMThread thread, SshUInt32 message)
{
#ifdef DEBUG_LIGHT
  int idx = (int) ssh_fsm_get_tdata(thread);
#endif /* DEBUG_LIGHT */

  SSH_DEBUG(SSH_D_NICETOKNOW, ("Waiter %d: got message %d",
                               idx, (int) message));

  SSH_FSM_SET_NEXT(wait_msg_done);
  ssh_fsm_continue(thread);
}

SSH_FSM_STEP(main_msg)
{
  rounds = 0;

  /* Create waiters */
  SSH_DEBUG(SSH_D_NICETOKNOW, ("Creating message waiters"));
  for (num_threads = 0; num_threads < NUM_THREADS; num_threads++)
    {
      threads[num_threads] = ssh_fsm_thread_create(fsm, wait_msg,
                                                   message_handler, NULL_FNPTR,
                                                   (void *) num_threads);
      ssh_fsm_set_thread_name(threads[num_threads], "waiting message");
      SSH_ASSERT(threads[num_threads]);
    }

  SSH_FSM_SET_NEXT(main_msg_send);
  return SSH_FSM_YIELD;
}

SSH_FSM_STEP(main_msg_send)
{
  int i;

  if (rounds != NUM_THREADS)
    {
      SSH_DEBUG(SSH_D_ERROR, ("All waiters have not started"));
      errors++;
    }
  rounds = 0;

  SSH_DEBUG(SSH_D_NICETOKNOW, ("Sending messages"));
  for (i = 0; i < num_threads; i++)
    SSH_FSM_THROW(threads[i], 42);

  SSH_FSM_SET_NEXT(main_msg_wait_done);
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(main_msg_wait_done)
{
  if (num_threads)
    SSH_FSM_CONDITION_WAIT(&cond);

  if (rounds != NUM_THREADS)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Not all threds died"));
      errors++;
    }
#ifdef SSH_FSM_DEBUG
  ssh_fsm_print_trace(thread);
#endif /* SSH_FSM_DEBUG */

  SSH_FSM_SET_NEXT(main_suspend_start);
  return SSH_FSM_CONTINUE;
}

/*************************** Suspend / Resumed *****************************/

static void
slow_timeout_cb(void *context)
{
  SshFSMThread thread = context;

  SSH_DEBUG(SSH_D_NICETOKNOW, ("In slow timeout callback."));
  SSH_FSM_CONTINUE_AFTER_CALLBACK(thread);
}

SSH_FSM_STEP(slow_loop)
{
#ifdef DEBUG_LIGHT
  char *name = (char *) thread_context;
#endif /* DEBUG_LIGHT */

  SSH_DEBUG(SSH_D_LOWOK, ("%s: rounds=%d", name, rounds));

  if (--rounds <= 0)
    return SSH_FSM_FINISH;
  
  SSH_FSM_ASYNC_CALL(ssh_xregister_timeout(0, 500000, slow_timeout_cb,
					   thread));
}

static void
resume_fsm(void *context)
{
  SSH_DEBUG(SSH_D_NICETOKNOW, ("Resuming FSM."));
  ssh_fsm_resume(context);
  done = 1;
}

static void
suspend_fsm(void *context)
{
  SSH_DEBUG(SSH_D_NICETOKNOW, ("Suspending FSM."));
  ssh_fsm_suspend(context);
  ssh_xregister_timeout(5, 0, resume_fsm, context);
}

SshTime start_time;

SSH_FSM_STEP(main_suspend_start)
{
  rounds = 20;
  done = 0;
  start_time = ssh_time();
  ssh_fsm_thread_init(fsm, &thread1, slow_loop, NULL_FNPTR, NULL_FNPTR,
		      "loop");
  ssh_fsm_set_thread_name(&thread1, "Loop");

  ssh_xregister_timeout(2, 0, suspend_fsm, fsm);
  SSH_FSM_SET_NEXT(main_all_done);
  SSH_FSM_WAIT_THREAD(&thread1);
}

SSH_FSM_STEP(main_all_done)
{
  if ((ssh_time() - start_time) < 13)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Suspend & resume didn't work as loop "
			      "didn't take over "
			      "13 seconds, took = %d seconds",
			      (int) (ssh_time() - start_time)));
      errors++;
    }
  
  if (!done)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Suspend / resume was not done"));
      errors++;
    }
  return SSH_FSM_FINISH;
}

/*********************************** Main ***********************************/

int
main(int argc, char *argv[])
{
  SshFSMStruct fsmstruct;
  SshFSMThread thread;
  SshFSM fsm = &fsmstruct;

  if (argc == 2)
    ssh_debug_set_level_string(argv[1]);

  ssh_event_loop_initialize();

  ssh_fsm_init(fsm, NULL);

  ssh_fsm_register_debug_names(fsm, state_array, num_states);

  /* Create a condition variable. */
  ssh_fsm_condition_init(fsm, &cond);

  thread = ssh_fsm_thread_create(fsm, main_start, NULL_FNPTR,
				 NULL_FNPTR, "main");
  ssh_fsm_set_thread_name(thread, "main");

  ssh_event_loop_run();

  ssh_fsm_uninit(fsm);

  ssh_event_loop_uninitialize();
  ssh_util_uninit();
  return errors;
}
