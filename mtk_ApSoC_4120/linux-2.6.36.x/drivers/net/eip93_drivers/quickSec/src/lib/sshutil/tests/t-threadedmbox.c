/*
 * t-threadedmbox.c
 *
 *  Copyright:
 *          Copyright (c) 2002 - 2009 SFNT Finland Oy.
 *
 *
 *  Test utility for the threadedmbox. 
 */

#include "sshincludes.h"
#include "ssheloop.h"
#include "sshtimeouts.h"
#include "sshgetopt.h"
#include "sshregression.h"
#include "sshthreadedmbox.h"

#define SSH_DEBUG_MODULE "SshThreadedMboxTest"

#define TOTAL_MESSAGES 100

static SshUInt32 max_threads = 2;
static SshThreadedMbox mbox;
static SshUInt32 cbs_received = 0;

static void uninit_and_exit(void *context)
{
  ssh_event_loop_uninitialize();
  ssh_util_uninit();
  exit(0);
}

static void end_tests(void *context)
{
  printf("MBox test completed successfully\n");
  ssh_threaded_mbox_destroy(mbox);
#ifdef WINDOWS
  /* We will cause a small memory leak in thread library if we
     don't let event loop still handle the thread completion event. */
  ssh_register_timeout(NULL, 1, 0, uninit_and_exit, NULL);
#else
  uninit_and_exit(NULL);
#endif /* WINDOWS */
}


static void eloop_cb(void *context)
{
  cbs_received++;

  SSH_DEBUG(SSH_D_LOWOK, ("Now received %d callbacks ", cbs_received));
  
  if (cbs_received == TOTAL_MESSAGES)
    {
      ssh_register_timeout(NULL, 0, 0, end_tests, NULL);
    }
}

static void thread_cb(void *context)
{
 Boolean status; 
  SSH_DEBUG(SSH_D_LOWOK, ("In the thread callback"));
  
  status = ssh_threaded_mbox_send_to_eloop(mbox, eloop_cb, NULL);
  if (!status)
    exit(1);
}


void run_tests(void *context)
{
  Boolean status; 
  SshUInt32 i;

  for (i = 0; i < TOTAL_MESSAGES; i++)
    {
      status = ssh_threaded_mbox_send_to_thread(mbox, thread_cb, NULL);
      if (!status)
       ssh_fatal("Cannot send a message to the thread side");
    }

  SSH_DEBUG(SSH_D_LOWOK, ("Sent all %d messages to the threads", 
			  TOTAL_MESSAGES));
  return;
}

void usage()
{
  printf("Usage: t-threadedmbox -n THREADS -d DEBUG_LEVEL\n"
         "-n maximum number of threads to use "
         "-d debuglevel\n");
}


int main(int ac, char *av[])
{
  int opt;

  while ((opt = ssh_getopt(ac, av, "n:d:", NULL)) != EOF)
    {
      switch (opt)
        {
         case 'n':
          max_threads = atoi(ssh_optarg);
          break;
         case 'd':
          ssh_debug_set_level_string(ssh_optarg);
          break;
         default:
        case 'h':
          usage();
          exit(1);
        }
    }
  ac -= ssh_optind;
  av += ssh_optind;

  ssh_event_loop_initialize();

  mbox = ssh_threaded_mbox_create(max_threads);
  SSH_ASSERT(mbox != NULL);

  ssh_register_timeout(NULL, 0, 0, run_tests, mbox);
  ssh_event_loop_run();

  ssh_threaded_mbox_destroy(mbox);
  ssh_event_loop_uninitialize();

  exit(0);
}
