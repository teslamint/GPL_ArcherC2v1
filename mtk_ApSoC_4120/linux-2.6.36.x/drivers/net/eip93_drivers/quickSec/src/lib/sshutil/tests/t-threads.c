/*
 *
 * Author: Tero Kivinen <kivinen@iki.fi>
 *                               Jukka Aittokallio <jai@ssh.fi>
 *
 *  Copyright:
 *          Copyright (c) 2002, 2003 SFNT Finland Oy.
 */
/*
 *        Program: Util Lib
 *
 *        Creation          : 15:01 Feb 23 2000 kivinen
 *        Last Modification : 22:11 Jun 14 2000 kivinen
 *        Version           : 1.210
 *        
 *
 *        Description       : Multithread timeouts support test program
 *
 */

#include "sshincludes.h"

#ifdef _XOPEN_SOURCE_EXTENDED
#undef _XOPEN_SOURCE_EXTENDED
#define SAVED_XOPEN_SOURCE_EXTENDED
#endif /* _XOPEN_SOURCE_EXTENDED */

#ifdef _XOPEN_SOURCE
#undef _XOPEN_SOURCE
#define SAVED_XOPEN_SOURCE
#endif /* _XOPEN_SOURCE */

#ifdef HAVE_PTHREADS
#ifndef WIN32
#include <pthread.h>
/* We must include strings.h here because otherwise we get conflict later */
#include <strings.h>
/* The pthread.h also defines try to something, and when we later include
   sshincludes.h we get warning about redefined symbol. */
#undef try
#endif /* WIN32 */
#endif /* HAVE_PTHREADS */

#ifdef SAVED_XOPEN_SOURCE_EXTENDED
#undef _XOPEN_SOURCE_EXTENDED
#define _XOPEN_SOURCE_EXTENDED 1
#undef SAVED_XOPEN_SOURCE_EXTENDED
#endif /* SAVED_XOPEN_SOURCE_EXTENDED */

#ifdef SAVED_XOPEN_SOURCE
#undef _XOPEN_SOURCE
#define _XOPEN_SOURCE 1
#undef SAVED_XOPEN_SOURCE
#endif /* SAVED_XOPEN_SOURCE */

#include "sshincludes.h"
#include "ssheloop.h"
#include "sshtimeouts.h"
#include "sshmutex.h"
#include "sshgetopt.h"

typedef void *(*SshForkedFunc)(void *context);
typedef struct SshThreadRec *SshThread;
SshMutex debug_mutex;

#ifdef WIN32

#define D(x) \
  (ssh_mutex_lock(debug_mutex), \
   printf x, \
   ssh_mutex_unlock(debug_mutex), 0)

struct SshThreadRec {
  HANDLE handle;
  DWORD thread_id;
  SshForkedFunc func;
  void *func_context;
};

DWORD WINAPI thread_func(LPVOID context)
{
  SshThread thread = (SshThread)context;
  thread->func(thread->func_context);
  return 0;
}

SshThread fork_thread(SshForkedFunc func, void *context)
{
  SshThread t;
  DWORD thread_id;
  HANDLE handle;

  t = (SshThread)ssh_xmalloc(sizeof(*t));
  t->func = func;
  t->func_context = context;
  if (!(handle = CreateThread(NULL, 0, thread_func, t, 0, &thread_id)))
    {
      ssh_xfree(t);
      return NULL;
    }
  t->thread_id = thread_id;
  t->handle = handle;
  return t;
}

void wait_thread(SshThread thread)
{
  WaitForSingleObject(thread->handle, INFINITE);
  CloseHandle(thread->handle);
  ssh_xfree(thread);
}

#endif

#ifdef HAVE_PTHREADS

#define DEBUG_HEAVY
#ifdef DEBUG_HEAVY
#define D(x) \
  (ssh_mutex_lock(debug_mutex), \
   printf x, \
   ssh_mutex_unlock(debug_mutex), 0)
#else /* DEBUG_HEAVY */
#define D(x)
#endif /* DEBUG_HEAVY */

struct SshThreadRec {
  pthread_t thread;
};

SshThread fork_thread(SshForkedFunc func, void *context)
{
  SshThread thread;

  thread = ssh_xcalloc(1, sizeof(*thread));
  if (pthread_create(&thread->thread, NULL, func, context) != 0)
    ssh_fatal("pthread_create failed : %s", strerror(errno));
  return thread;
}

void wait_thread(SshThread thread)
{
  if (pthread_join(thread->thread, NULL) != 0)
    ssh_fatal("pthread_join failed : %s", strerror(errno));
  ssh_xfree(thread);
}

#endif /* HAVE_PTHREADS */

#ifdef HAVE_THREADS

SshMutex mutex1_start, mutex2_start;
SshMutex mutex1, mutex2, mutex3;
int operations1 = 10;
int operations2 = 10;
SshThread thread1, thread2;
int threads;

void call_wait_thread(void *context)
{
  SshThread thread = context;
  D(("Call_wait_thread called, number of threads now out %d, thread = %p\n",
     threads, thread));
  D(("Waiting for thread\n"));
  wait_thread(thread);
  threads--;
  D(("Waited for thread, decrementing threads counter, new value = %d\n",
     threads));
}

void *func1(void *context)
{
  D(("In thread 1, starting\n"));
  D(("In thread 1, Locking mutex 3\n"));
  ssh_mutex_lock(mutex3);
  D(("In thread 1, Locking mutex 1\n"));
  ssh_mutex_lock(mutex1);
  ssh_mutex_lock(mutex1_start);
  ssh_mutex_unlock(mutex1_start);
  while (operations1 >= 0)
    {
      D(("In thread 1, Decrementing operations counter, value = %d\n",
         operations1));

      if (operations1 != operations2)
        ssh_fatal("Thread 1 and thread 2 are out of sync");

      operations1--;

      D(("In thread 1, Unlocking mutex 3\n"));
      ssh_mutex_unlock(mutex3);
      /* L1 */
      D(("In thread 1, Locking mutex 2\n"));
      ssh_mutex_lock(mutex2);

      D(("In thread 1, Unlocking mutex 1\n"));
      ssh_mutex_unlock(mutex1);
      /* L2 */
      D(("In thread 1, Locking mutex 3\n"));
      ssh_mutex_lock(mutex3);

      D(("In thread 1, Unlocking mutex 2\n"));
      ssh_mutex_unlock(mutex2);
      /* L3 */
      D(("In thread 1, Locking mutex 1\n"));
      ssh_mutex_lock(mutex1);
    }
  D(("In thread 1, Unlocking mutex 1\n"));
  ssh_mutex_unlock(mutex1);
  D(("In thread 1, Unlocking mutex 3\n"));
  ssh_mutex_unlock(mutex3);

  D(("In thread 1, All done, inserting timeout, thread = %p\n", thread1));
  ssh_xregister_threaded_timeout(0, 0, call_wait_thread, thread1);
  D(("In thread 1, Exiting\n"));
  return NULL;
}

void *func2(void *context)
{
  D(("In thread 2, starting\n"));
  D(("In thread 2, Locking mutex 2\n"));
  ssh_mutex_lock(mutex2);
  ssh_mutex_lock(mutex2_start);
  ssh_mutex_unlock(mutex2_start);

  D(("In thread 2, Locking mutex 3\n"));
  ssh_mutex_lock(mutex3);
  while (operations2 >= 0)
    {
      D(("In thread 2, Decrementing operations counter, value = %d\n",
         operations2));

      if (operations1 + 1 != operations2)
        ssh_fatal("Thread 1 and thread 2 are out of sync");

      operations2--;

      D(("In thread 2, Unlocking mutex 2\n"));
      ssh_mutex_unlock(mutex2);
      /* L3 */
      D(("In thread 2, Locking mutex 1\n"));
      ssh_mutex_lock(mutex1);

      D(("In thread 2, Unlocking mutex 3\n"));
      ssh_mutex_unlock(mutex3);
      /* L1 */
      D(("In thread 2, Locking mutex 2\n"));
      ssh_mutex_lock(mutex2);

      D(("In thread 2, Unlocking mutex 1\n"));
      ssh_mutex_unlock(mutex1);
      /* L2 */
      D(("In thread 2, Locking mutex 3\n"));
      ssh_mutex_lock(mutex3);
    }
  D(("In thread 2, Unlocking mutex 2\n"));
  ssh_mutex_unlock(mutex2);
  D(("In thread 2, Unlocking mutex 3\n"));
  ssh_mutex_unlock(mutex3);
  D(("In thread 2, All done, inserting timeout, thread = %p\n", thread2));
  ssh_xregister_threaded_timeout(0, 0, call_wait_thread, thread2);
  D(("In thread 2, Exiting\n"));
  return 0;
}

void check_for_threads(void *context)
{
  D(("Checking for threads, number of threads = %d\n", threads));
  if (threads == 0)
    {
      D(("No more threads, uninitilizing threaded timeouts\n"));
      ssh_threaded_timeouts_uninit();
      return;
    }
  D(("Still some threads running, reinserting timeout\n"));
  ssh_xregister_timeout(0, 100000, check_for_threads, NULL);
  return;
}

void start_program(void *context)
{
  D(("Unlocking start mutex 1 and 2\n"));
  ssh_mutex_unlock(mutex1_start);
  ssh_mutex_unlock(mutex2_start);
}

char *program;

void usage(void)
{
  fprintf(stderr, "Usage: %s [-d debug_level_string]\n", program);
  exit(0);
}


void main(int argc, char **argv)
{
  const char *debug_level = "Sgw*=5";
  SshMutex mutex;
  int option;

  program = strrchr(argv[0], '/');
  if (program == NULL)
    program = argv[0];
  else
    program++;

  while ((option = ssh_getopt(argc, argv, "d:f:", NULL)) != -1)
    {
      switch (option)
        {
        case 'd': debug_level = ssh_optarg; break;
        case '?':
          usage();
          break;
        }
    }
  if (argc - ssh_optind > 1)
    usage();

  ssh_event_loop_initialize();
  ssh_debug_set_level_string(debug_level);

  debug_mutex = ssh_mutex_create("Debug", 0);
  if (!debug_mutex)
    ssh_fatal("Cannot create mutex");

  D(("Calling timeout init\n"));
  ssh_threaded_timeouts_init();

  D(("Creating test mutex 1\n"));
  mutex = ssh_mutex_create("Test 1", 0);
  if (!mutex)
    ssh_fatal("Cannot create mutex");

  D(("Locking test mutex 1\n"));
  ssh_mutex_lock(mutex);
  D(("Unlocking test mutex 1\n"));
  ssh_mutex_unlock(mutex);
  D(("Getting name test mutex 1\n"));
  if (strcmp(ssh_mutex_get_name(mutex), "Test 1") != 0)
    ssh_fatal("get name failed");
  D(("Destroying test mutex 1\n"));
  ssh_mutex_destroy(mutex);

  D(("Creating lock 1 and 2\n"));
  mutex1 = ssh_mutex_create("Lock 1", 0);
  mutex1_start = ssh_mutex_create("Start lock 1", 0);
  mutex2 = ssh_mutex_create("Lock 2", 0);
  mutex2_start = ssh_mutex_create("Start lock 2", 0);
  mutex3 = ssh_mutex_create("Lock 3", 0);

  if (!mutex1 || !mutex1_start || !mutex2 || !mutex2_start || !mutex3)
    ssh_fatal("Cannot create mutex");

  D(("Locking start lock 1 and 2\n"));
  ssh_mutex_lock(mutex1_start);
  ssh_mutex_lock(mutex2_start);
  D(("Forking thread 1\n"));
  thread1 = fork_thread(func1, NULL);
  D(("Forking thread 2\n"));
  thread2 = fork_thread(func2, NULL);
  threads = 2;

  D(("Registering timeouts\n"));
  ssh_xregister_timeout(0, 600000, check_for_threads, NULL);
  ssh_xregister_timeout(0, 500000, start_program, NULL);
  D(("Staring event loop\n"));
  ssh_event_loop_run();
  D(("Event loop run returned\n"));

  D(("Destroying mutex 1, 2, and 3\n"));
  ssh_mutex_destroy(mutex1);
  ssh_mutex_destroy(mutex1_start);
  ssh_mutex_destroy(mutex2);
  ssh_mutex_destroy(mutex2_start);
  ssh_mutex_destroy(mutex3);
  D(("Destroying debug_mutex\n"));
  ssh_mutex_destroy(debug_mutex);

  ssh_event_loop_uninitialize();
  ssh_util_uninit();
  exit(0);
}

#else  /* HAVE_THREADS */
int main(int argc, char **argv)
{
  printf("No thread support included, testing ignored\n");
  return 0;
}
#endif /* HAVE_THREADS */
