/*
  eventloop_perf.c

  Copyright:
          Copyright (c) 2008 SFNT.
                   All rights reserved
*/
#ifdef WIN32

#include "sshincludes.h"
#include "ssheloop.h"
#include "sshtimeouts.h"
#include "sshadt.h"
#include "sshadt_list.h"

/* Define globals here */

typedef struct SshQueryPerfCounterRec {
  
 /* Get the start time using QueryPerformanceCounter() or GetTickCount() */
  void (*perf_start)(SshInt64 *start);
  
  /* Get the end time using QueryPerformanceCounter() or GetTickCount() */
  void (*perf_stop)(SshInt64 *stop);
  
  /* Get the duration of time for niterations */
  double (*perf_duration)(SshInt64 start, SshInt64 stop, int niterations);

  /* QueryPerformanceFrequency()function retrieves the frequency of the 
     high-resolution performance counter, if one exists. */
  LARGE_INTEGER frequency;

  /* If one exists "frequency", then set TRUE otherwise, set FALSE (In 
     which case we shall be using the GetTickCount()) */
  BOOL frequency_exist;

  /* This shall be used in calculation of the perf_duration */
  float multiplier;

} *SshQueryPerfCounter;

static SshQueryPerfCounter qpc = NULL;

/* These variables will be used to get the start and end time
   for execution */
static SshInt64 start, stop;

/* Variable to count home many times tmo_callback executed */
static long tmo_counter = 0;

/* Variable to know how many times to execute the callback */
long ntimes = 0;

/* List of handles to events */
HANDLE hevents[100];

/* Repeat the event test for "repeat_ntimes_event_test" times */
long repeat_ntimes_event_test = 0;

/* List of the events to be signaled */
static SshADTContainer hevent_list = NULL;

#if 0
/* list of timeouts registered */
static SshADTContainer timeout_list = NULL;
#endif /* 0 */

/* Global handle to the next timeout in the timeout_list */
SshADTHandle t_handle = NULL;

/* Used in conjuction with t_handle */
BOOL t_flag = FALSE;

/* Forward declarations */
static void timeout_callback(void *ctx);
static void register_timeout_test(void *ctx);
static void event_callback(void *context);
static void signal_event_test(void *ctx);
static void register_event_test(void *ctx);

void perf_main(int number);
void perf_main_init(int number);
void perf_main_uninit(void *ctx);

/* Macros here */
#define PERF_OUTPUT_EVENT_RESULT()                                     \
  do                                                                   \
  {                                                                    \
     fprintf(stderr, "\tTime to execute %d events: %lf ms\n", ntimes,  \
                  qpc->perf_duration(start_time, end_time, 0));        \
     fprintf(stderr, "\tAverage time to execute 1 events: %lf ms\n",   \
                  qpc->perf_duration(start_time, end_time, ntimes));   \
  } while(0)

#define PERF_OUTPUT_TIMEOUT_RESULT()                                        \
  do                                                                         \
  {                                                                          \
      fprintf(stderr, "\tTime to execute %d timeouts: %lf ms\n", tmo_counter,\
              qpc->perf_duration(start, stop, 0));                           \
      fprintf(stderr, "\tAverage time to execute 1 timeout : %lf ms\n",      \
              qpc->perf_duration(start, stop, tmo_counter));                 \
      fprintf(stderr,"\n");                                                  \
  } while(0)

void counter_start(SshInt64 *start)
{
  LARGE_INTEGER li;
  
  if (qpc->frequency_exist)
    {
      QueryPerformanceCounter(&li);
      *start = li.QuadPart;
    }
  else
    {
      *start = GetTickCount();
    }
  return;
}

void counter_stop(SshInt64 *stop)
{
  LARGE_INTEGER li;

  if (qpc->frequency_exist)
    {
      QueryPerformanceCounter(&li);
      *stop = li.QuadPart;
    }
  else
    {
      *stop = GetTickCount();
    }
  return;
}

/* If the value of the variable niterations == 0, then function returns 
   the (stop - start) time. i.e. Total time to execute the all the events.
   If the niterations is Non-Zero value, then the functions returns the 
   average time for "niterations" iterations. 
   i.e ((stop - start) / niterations) */
double counter_duration(SshInt64 start, SshInt64 stop, int niterations)
{
  if (qpc->frequency_exist)
    {
      if (!niterations)
        return (double)((((double)(stop - start) * (double)qpc->multiplier) /
               (double)qpc->frequency.QuadPart) / 1000000);
      else
        return (double)(((((double)(stop - start)  * (double)qpc->multiplier)/
               (double)qpc->frequency.QuadPart) / niterations) / 1000000);
    }
  else
    {
      if (!niterations)
        return (double)(stop - start);
      else
        return (double)((stop - start) / niterations);
    }
}

/* Timeout callback */
static void timeout_callback(void *ctx)
{
  tmo_counter++;

  /* Note the starting time for first timeout_callback */
  if (tmo_counter == 1)
    {
      /* Get the start time using the performance counter */
      qpc->perf_start(&start);

#ifdef DEBUG_LIGHT
      fprintf(stderr, "\tSetting the start time for timeouts: %I64d\n", start);
#endif
    }

  /* All of the timeout_callback are done. Note the end time */
  if (ntimes == tmo_counter)
    {
      /* Get the end time using the performance counter */
      qpc->perf_stop(&stop);

#ifdef DEBUG_LIGHT
      fprintf(stderr, "\tSetting the end time for timeouts: %I64d\n", stop);
#endif
      /* Output the performance details of timeout */
      PERF_OUTPUT_TIMEOUT_RESULT();

      /* Signal the event test to perform */
      ssh_register_timeout(NULL, 1, 0, signal_event_test, (void*)TRUE);

      start = stop = 0;
      return;
    }
  else
    {
      return;
    }
}

static void register_timeout_test(void *ctx)
{
  int i, count;
  count = (int)ctx;

  fprintf(stderr, "\n\tStarting performance test for Event Loop\n");
  fprintf(stderr, "\n");

  for (i = 1; i <= count; i++)
    {
      SshTimeout t = NULL;
      /* Let the default time to fire the callback be 5 seconds */
      t = ssh_register_timeout(NULL, 5, 00000, timeout_callback, (void*)i);
#if 0
      if (t)
        ssh_adt_insert_to(timeout_list, SSH_ADT_END, t);
#endif /* 0 */
    }
}

/* Cancel the timeout t */
static void cancel_timeout(SshTimeout t)
{
  if (t)
    ssh_cancel_timeout(t);
  return;
}

static void register_cancel_timeout_test(void *ctx)
{
#if 0
  SshTimeout t = NULL;
  
  if (!t_flag && timeout_list)
    t_handle = ssh_adt_enumerate_start(timeout_list);

  if (t_handle != SSH_ADT_INVALID)
    {
      t = ssh_adt_get(timeout_list, t_handle);
      t_handle = ssh_adt_enumerate_next(timeout_list, t_handle);
      if (t)
        ssh_register_timeout(NULL, 0, 0, cancel_timeout, t);
    }
#endif /* 0 */
}

/* Some globals for event callback */
SshInt64 start_time, end_time;
int repeat_counter = 0;
BOOL e_flag = FALSE;
long e_count = 0;
int e_over = 0;

static void event_callback(void *context)
{
  if (e_count == 0 && !e_flag)
    {
      /* Get the start time using performance counter */
      qpc->perf_start(&start_time); 

#ifdef DEBUG_LIGHT
      fprintf(stderr, "\tSetting the start_time for events: %I64d\n", 
              start_time);
#endif
      e_flag = TRUE;
    }
  e_count++;

  if (100 == e_count)
    {
      repeat_counter++;
      e_count = 0;
      if (repeat_counter > repeat_ntimes_event_test)
        {
          /* Get the end time using performance counter */
          qpc->perf_stop(&end_time);

          /* Output the performance details */
#ifdef DEBUG_LIGHT
          fprintf(stderr, "\tSetting the end_time for events: %I64d\n",
                  end_time);
#endif
          PERF_OUTPUT_EVENT_RESULT();

          /* Signal to unregister all the events registered. 
             signal_event_test() will unregistered the events */
          ssh_register_timeout(NULL, 0, 0, signal_event_test, (void*) FALSE);
          return;
        }
      else
        {
          if (repeat_counter == repeat_ntimes_event_test)
            {
              /* Get the end time using performance counter */
              qpc->perf_stop(&end_time);

#ifdef DEBUG_LIGHT
              fprintf(stderr, "\tSetting the end_time for events: %I64d\n",
                      end_time);
#endif
              PERF_OUTPUT_EVENT_RESULT();

              /* Signal to unregister all the events registered. 
                 signal_event_test() will unregistered the events */
              ssh_register_timeout(NULL, 0, 00000, signal_event_test, 
                                  (void*) FALSE);
              return;
            }
          else
            {
              e_count = 0;
              e_over++;
              /* Restart the event test */
              ssh_register_timeout(NULL, 0, 00000, signal_event_test, 
                                   (void*) TRUE);
              return;
            }
        }
    }

  if ((ntimes-1) == e_count)
    {
      /* Get the end time using performance counter */
      qpc->perf_stop(&end_time);

      /* Output the performance details */
#ifdef DEBUG_LIGHT
      fprintf(stderr, "\tSetting the end_time for events: %I64d\n", end_time);
#endif
      PERF_OUTPUT_EVENT_RESULT();

      /* Unregister the events registered */
      ssh_register_timeout(NULL, 0, 00000, signal_event_test, (void*) FALSE);
      return;
    }
}

/* This function provides dual functionality. First,
   if the "flag" value is TRUE in which case we raise
   all the events. Secondly, if the flag value is FALSE
   then we unregister all the events registered in the
   hevent_list */
static void signal_event_test(void *ctx)
{
  BOOL flag = (BOOL) ctx;

  /* if flag is true then raise the events */
  if (flag)
    {
      int i = 0;
      for (; i < sizeof(hevents) / sizeof(HANDLE); i++)
        {
          if (hevents[i])
            SetEvent(hevents[i]);
        }
    }
  else /* Otherwise unregister all the events */
    {
      int j = 0;
      for (; j < sizeof(hevents) / sizeof(HANDLE); j++)
        {
          if (hevents[j])
            {
              ssh_event_loop_unregister_handle(hevents[j]);
            }
        }
      /* Uninit the perf related data */
      ssh_register_timeout(NULL, 0, 0, perf_main_uninit, NULL);
    }
  return;
}

/* Register the events in the event loop 
   using ssh_event_loop_register_handle() */
static void register_event_test(void *ctx)
{
  int i, j;
  j = (int) ctx;
  
  for (i = 0; i < j; i++)
    {
      /* Create events for j times. "j" value is predefined as 100 */
      hevents[i] = CreateEvent(NULL, FALSE, FALSE, NULL);

      /* Register events and callback for the events */
      if (hevents[i])
        {
          ssh_event_loop_register_handle(hevents[i], FALSE,
                                         event_callback, (void*)i);
          ssh_adt_insert_to(hevent_list, SSH_ADT_END, hevents[i]);
        }
    }
}

void perf_main_init(int number)
{
  if (!number)
    ntimes = 10000;
  else
    ntimes = number;
  
  /* Do event test for (ntimes/100) */
  repeat_ntimes_event_test = ntimes / 100;

  hevent_list = ssh_adt_create_generic(SSH_ADT_LIST, SSH_ADT_ARGS_END);
  
  /* Create the timeout list. This shall be used in cancel registered 
     timeout */
#if 0
  timeout_list = ssh_adt_create_generic(SSH_ADT_LIST, SSH_ADT_ARGS_END);
#endif /* 0 */

  /* Allocate a global qpc for performance counter. Free the same at 
     perf_main_uninit()*/
  qpc = ssh_calloc(1, sizeof(struct SshQueryPerfCounterRec));

  if (!qpc)
    ssh_fatal("Unable to allocate resources for performance counter...");
  else
    {
      qpc->perf_start = counter_start;
      qpc->perf_stop = counter_stop;
      qpc->perf_duration = counter_duration;
      if (QueryPerformanceFrequency(&qpc->frequency))
        qpc->frequency_exist = TRUE;
      else
        qpc->frequency_exist = FALSE;
      
      qpc->multiplier = 1.0e9;
    }

  return;
}

void perf_main_uninit(void *ctx)
{
  SshADTHandle handle = NULL;
  int i = 0;
  HANDLE e;

  if (hevent_list)
   {
     handle = ssh_adt_enumerate_start(hevent_list);
     while (handle != SSH_ADT_INVALID)
       {
         e = ssh_adt_get(hevent_list, handle);
         handle = ssh_adt_enumerate_next(hevent_list, handle);
         if (e)
           CloseHandle(e);
       }
     ssh_adt_destroy(hevent_list);
   }

  if (qpc)
    ssh_free(qpc);
}

void perf_main(int number)
{
  /* We have array of 100 events. */
  int nevent = 100;

  /* Do the performance test related init */
  perf_main_init(number);

  /* Register the timeout test */
  register_timeout_test((void *)ntimes);

  /* Register the event test */
  ssh_register_timeout(NULL, 0, 0, register_event_test,(void *)nevent);

#if 0
  ssh_register_timeout(NUL, 2, 0, register_cancel_timeout_test, 
                        (void*)timeout_list);
#endif
}

#endif
