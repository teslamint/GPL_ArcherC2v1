/*

  t-operation.c

Author: Vesa Suontama <vsuontam@ssh.fi>

  Copyright:
          Copyright (c) 2002, 2003 SFNT Finland Oy.
                   All rights reserved


  Created Thu Sep 28 11:44:28 2000.

  Very simple test program for SshOperationHandles.

*/

#include "sshincludes.h"
#include "ssheloop.h"
#include "sshtimeouts.h"
#include "sshoperation.h"

#define NUM_TICKS 5
#define TICK_TIME 0, 100000
#define TRIPLE_TICK_TIME 0, (300000+110000)
typedef void (*SshTestOperationEndCB)(void *context);

typedef struct TOperationRec
{
  SshUInt32 num;
  void *context;
  SshTestOperationEndCB callback;
  SshOperationHandle handle;
  char *prompt;
} *TOperation;


static void ssh_test_operation_tick(void *context)
{
  TOperation operation = context;

  fprintf(stderr, "%s: Test Tick %ld:\n",
          operation->prompt,
          operation->num++);

  if (operation->num == NUM_TICKS + 1)
    {
      (*operation->callback)(operation->context);
      ssh_operation_unregister(operation->handle);

      ssh_xfree(operation->prompt);
      ssh_xfree(operation);
    }
  else
    {
      ssh_xregister_timeout(TICK_TIME, ssh_test_operation_tick, operation);
    }
}

static void abort_callback(void *context)
{
  TOperation operation = context;

  ssh_cancel_timeouts(ssh_test_operation_tick, operation);
  ssh_xfree(operation->prompt);
  ssh_xfree(operation);
}

static SshOperationHandle
ssh_start_counting(const char *prompt,
                   SshTestOperationEndCB end_cb,
                   void *context)
{
  TOperation t;

  t = ssh_xcalloc(1, sizeof(*t));
  t->callback = end_cb;
  t->context = context;
  t->prompt = ssh_xstrdup(prompt);
  t->handle = ssh_operation_register(abort_callback, t);
  ssh_xregister_timeout(TICK_TIME, ssh_test_operation_tick, t);
  return t->handle;
}

static void attached_destructor(Boolean aborted, void *context)
{
  char *message = context;
  if (aborted)
    fprintf(stderr, "Aborted ");

  fprintf(stderr, "Destructor: %s.\n", message);
}


static void ssh_end_test(void *context)
{
  char *message = context;

  fprintf(stderr, "%s.\n", message);
}

static void ssh_test_operation_abort(void *context)
{
  SshOperationHandle handle = context;
  ssh_operation_abort(handle);
}


/* Tests. */
static void start_test_to_end(void *context)
{
  ssh_start_counting("1. Normal Test. This should end at 5",
                     ssh_end_test,
                     "Operation_ended_normally");

}


static void start_test_and_abort(void *context)
{
  SshOperationHandle handle;

  handle = ssh_start_counting("2. Normal Test. This should be aborted "
                              "at 3",
                              ssh_end_test,
                              "This must not be seen!");
  ssh_xregister_timeout(TRIPLE_TICK_TIME, ssh_test_operation_abort, handle);
}

static void start_test_and_attach(void *context)
{
  SshOperationHandle handle;

  handle = ssh_start_counting("3. Normal Test. This should count "
                              "as the first test, and call destructor",
                              ssh_end_test,
                              "This is the end of the test 3.");
  ssh_operation_attach_destructor(handle, attached_destructor,
                                  "Destructor_called");
}


static void start_test_and_attach_and_abort(void *context)
{
  SshOperationHandle handle;
  handle = ssh_start_counting("Attach Test. This should count "
                              "to 3 and call destructor at abort",
                              ssh_end_test,
                              "This must not be seen!");

  ssh_xregister_timeout(TRIPLE_TICK_TIME, ssh_test_operation_abort, handle);
  ssh_operation_attach_destructor(handle, attached_destructor,
                                  "Destructor_called");
}

static void start_test_and_2attach_and_abort(void *context)
{
  SshOperationHandle handle;
  handle = ssh_start_counting("Attach Test. This should count "
                              "to 3 and call destructor at abort",
                              ssh_end_test,
                              "This must not be seen!");

  ssh_xregister_timeout(TRIPLE_TICK_TIME, ssh_test_operation_abort, handle);

  ssh_operation_attach_destructor(handle, attached_destructor,
                                  "This destructor be called last");

  ssh_operation_attach_destructor(handle, attached_destructor,
                                  "This destructor be called first");
}



int main(int argc, char **argv)
{
  ssh_event_loop_initialize();
  ssh_xregister_timeout(0, 0, start_test_to_end, NULL);
  ssh_xregister_timeout(NUM_TICKS + 2, 0, start_test_and_abort, NULL);
  ssh_xregister_timeout(NUM_TICKS * 2 + 2, 0, start_test_and_attach, NULL);
  ssh_xregister_timeout(NUM_TICKS * 3 + 2, 0, start_test_and_attach_and_abort,
                        NULL);
  ssh_xregister_timeout(NUM_TICKS * 3 + 2, 0, start_test_and_2attach_and_abort,
                        NULL);
  ssh_event_loop_run();
  ssh_event_loop_uninitialize();
  ssh_util_uninit();
  return 0;
}
