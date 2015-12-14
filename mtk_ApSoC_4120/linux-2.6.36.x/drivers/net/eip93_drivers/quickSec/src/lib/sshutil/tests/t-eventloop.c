/*

  t-eventloop.c


  Copyright:
          Copyright (c) 2002 - 2009 SFNT Finland Oy.
          All rights reserved


*/

#include "sshincludes.h"
#include "ssheloop.h"
#include "sshtimeouts.h"
#include "sshgetopt.h"

/* Forward declarations */
#ifdef WIN32
void perf_main(int number);
#endif /* WIN32 */

void another_callback(void *ctx)
{
  fprintf(stderr, "Another callback\n");
  ssh_event_loop_abort();
}

void signal_callback(int sig_num, void *context)
{
  fprintf(stderr, "The signal %d invoked\n", sig_num);
#ifndef WIN32
  ssh_register_signal(SIGUSR1, signal_callback, NULL);
#endif /* WIN32 */
}

void program_entry(void *context)
{
  int argc = (int)(size_t)context;
  fprintf(stderr, "The number of arguments given to the program is %d\n",
          argc);
#ifndef WIN32
  ssh_register_signal(SIGUSR1, signal_callback, NULL);
  ssh_register_signal(SIGINT, signal_callback, NULL);
#endif /* WIN32 */
  ssh_xregister_timeout(2, 00000, another_callback, NULL);
}


#ifdef WIN32
/* Windows multiple waiting threads -test */
HANDLE events[200];

void event_signaled(void *context)
{
  int i = (int)(size_t)context;
  fprintf(stderr, "event signaled %d\n", i);

  if (i == 4)
    ssh_event_loop_unregister_handle(events[32]);
  if (i == 68)
    ssh_event_loop_unregister_handle(events[117]);
}

void multiple_threads_stop(void *context)
{
  int i = 0;

  fprintf(stderr, "multiple_threads_stop\n");
  for (; i < 200; i++)
    {
      ssh_event_loop_unregister_handle(events[i]);
    }
}

void multiple_threads(void *context)
{
  int i = 0;

  fprintf(stderr, "multiple threads test starts\n");
  fprintf(stderr, "In this test, you should get *only three* callbacks.\n");

  for (; i<200; i++) 
  {
    events[i] = CreateEvent(NULL, FALSE, FALSE, NULL);
    ssh_event_loop_register_handle(events[i], 
                                   FALSE,
                                   event_signaled, 
                                   (void *)(size_t)i);
  }

  /* Take events from far apart and signal them */
  SetEvent(events[4]);
  SetEvent(events[68]);
  /* Short delay to ensure that events 4 and 68 will be processed before
     32, 117 and 189 (so events 32 and 117 will be correctly unregistered
     and their callback functions will never be called) */
  Sleep(50); 
  SetEvent(events[32]);
  SetEvent(events[117]);
  SetEvent(events[189]);

  ssh_xregister_timeout(1, 0, multiple_threads_stop, NULL);
}
/* Windows multiple waiting threads -test */
#endif /* WIN32 */

/* Usage of the test program */
void usage(char *program)
{
  fprintf(stderr, "Usage: %s [-D LEVEL][-P][-N][-h]\n", program);
  fprintf(stderr, "\n -D\tSet debug level string to LEVEL");
  fprintf(stderr, "\n -P\tEnable flag to get the perf number of eventloop");
  fprintf(stderr, "\n\tBy default it is off");
  fprintf(stderr, "\n -N\tNumber of timeouts and events to be registered");
  fprintf(stderr, "\n\tSet atleast 1000 and above. Default value is 10000");
  fprintf(stderr, "\n -h\tUsage or help\n");
}

int main(int argc, char **argv)
{
  int c, opt_perf_number;
  char *program = NULL;
  Boolean opt_perf_flag, usage_flag;

  /* Set to default value FALSE */
  opt_perf_flag = usage_flag = FALSE;

  /* Get the program name */
  program = strrchr(argv[0], '\\');
  if (program == NULL)
    program = argv[0];
  else
    program++;

  /* Parse the appropriate options and set the optional flags */
  while ((c = ssh_getopt(argc, argv, "D:h:N:P", NULL)) != EOF)
    {
      switch (c)
        {
        case 'D':
          ssh_debug_set_level_string(ssh_optarg);
          break;

        case 'P': 
          opt_perf_flag = TRUE; 
          break;

        case 'N': 
          opt_perf_number = atoi(ssh_optarg); 
          break;

        case 'h': 
        case '?': 
        default:
          usage_flag = TRUE; 
          break;
        }
    }

  if (usage_flag)
    {
      usage_flag = FALSE;
      /* Usage of the test program */
      usage(program);
      exit(1);
    }

  /* Initialize the event loop */
  ssh_event_loop_initialize();

  /* if this flag is set then perform performance test for eventloop. 
     Otherwise, do the usual test */
  if (opt_perf_flag)
    {
#ifdef WIN32
       if (opt_perf_number)
         perf_main(opt_perf_number);
#endif /* WIN32 */
    }
  else
    {
      ssh_xregister_timeout(2, 0, program_entry, (void *)(size_t)argc);
#ifdef WIN32
      ssh_xregister_timeout(1, 0, multiple_threads, (void *)(size_t)argc);
#endif /* WIN32 */
   }
  /* Run the event loop */
  ssh_event_loop_run();

  /* Uninitialize the eventloop */
  ssh_event_loop_uninitialize();

  ssh_util_uninit();
  return 0;
}
