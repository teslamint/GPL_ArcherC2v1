#include "sshincludes.h"
#include "ssheloop.h"
#include "sshtimeouts.h"
#include "sshtimemeasure.h"
#include "sshrand.h"

#define SSH_DEBUG_MODULE "t-timeout"

typedef struct TimoRec
{
  SshTimeoutStruct tentry;
  int id;
} *Timo, TimoStruct;

static TimoStruct timeouts[100000];

static int g_last_triggered_id = -1;
static int g_check_order = 0;

static void timeout_cb(void *context)
{
  Timo timo = context;

  SSH_VERIFY(timo->id != -1);

  if (g_check_order)
    SSH_VERIFY(timo->id > g_last_triggered_id);
  timo->id = -1;
}

static void to_cancel(size_t n, int order)
{
  int i;

  if (order == 0)
    {
      for (i = 0; i < n; i++)
        {
          ssh_cancel_timeout(&timeouts[i].tentry);
        }
    }
  if (order == 1)
    {
      for (i = n; i > 0; i--)
        {
          ssh_cancel_timeout(&timeouts[i-1].tentry);
        }
    }
  if (order == 2)
    {
      ssh_cancel_timeouts(timeout_cb, SSH_ALL_CONTEXTS);
    }

  if (order == 3)
    {
      for (i = 0; i < n; i++)
        {
          ssh_cancel_timeouts(timeout_cb, &timeouts[i]);
        }
    }

  if (order == 4)
    {
      for (i = 0; i < n; i++)
        {
          ssh_cancel_timeouts(SSH_ALL_CALLBACKS, &timeouts[i]);
        }
    }
}

static void to_register(size_t n, int order)
{
  int i;

  if (order == 0)
    {
      for (i = 0; i < n; i++)
        {
          timeouts[i].id = i;
          ssh_register_timeout(&timeouts[i].tentry,
                               0L, 0L,
                               timeout_cb, &timeouts[i]);
        }
    }
  if (order == 1)
    {
      for (i = 0; i < n; i++)
        {
          timeouts[i].id = i;
          ssh_register_timeout(&timeouts[i].tentry,
                               (i / 10L), (i % 10L),
                               timeout_cb, &timeouts[i]);
        }
    }

  if (order == 2)
    {
      for (i = n; i > 0; i--)
        {
          timeouts[i].id = i;
          ssh_register_timeout(&timeouts[i-1].tentry,
                               (i / 10L), (i % 10L),
                               timeout_cb, &timeouts[i-1]);
        }
    }

  if (order == 3)
    {
      for (i = 0; i < n; i++)
        {
          timeouts[i].id = i;
          ssh_register_timeout(&timeouts[i].tentry,
                               ssh_rand() % 10L, ssh_rand() % 1000000L,
                               timeout_cb, &timeouts[i]);
        }
    }

  if (order == 4)
    {
      for (i = 0; i < n; i++)
        {
          timeouts[i].id = i;
          ssh_register_timeout(&timeouts[i].tentry,
                               ssh_rand() % 10L, ssh_rand() % 1000000L,
                               timeout_cb, &timeouts[i % 8]);
        }
    }
}

#define MILLISTAMP(t, x) \
 (printf("%s (%lu microseconds).\n", \
 t, ((unsigned long)ssh_time_measure_stamp(x, \
    SSH_TIME_GRANULARITY_MICROSECOND))))

int main(int ac, char **av)
{
  SshTimeMeasure tm;
  int n, i;

  printf("Sizeof SshTimeoutStruct = %d\n", sizeof(SshTimeoutStruct));
  if (ac == 1)
    n = 10000;
  else
    n = atoi(av[1]);

  printf("n = %d.\n", n);

  ssh_event_loop_initialize();

  tm = ssh_time_measure_allocate();

  /* Register n zero timeouts. */
  ssh_time_measure_reset(tm);  ssh_time_measure_start(tm);
  to_register(n, 0);
  ssh_time_measure_stop(tm);
  MILLISTAMP("register zero timeouts", tm);

  /* Cancel these in registration order */
  ssh_time_measure_reset(tm);  ssh_time_measure_start(tm);
  to_cancel(n, 0);
  ssh_time_measure_stop(tm);
  MILLISTAMP("cancel at registration order", tm);

  /* Register n zero timeouts. */
  ssh_time_measure_reset(tm);  ssh_time_measure_start(tm);
  to_register(n, 0);
  ssh_time_measure_stop(tm);
  MILLISTAMP("register zero timeouts", tm);

  /* Cancel these in registration order */
  ssh_time_measure_reset(tm);  ssh_time_measure_start(tm);
  to_cancel(n, 1);
  ssh_time_measure_stop(tm);
  MILLISTAMP("cancel at reverse registration order", tm);

  /* Register n timeouts in acending order of firing time. */
  ssh_time_measure_reset(tm);  ssh_time_measure_start(tm);
  to_register(n, 1);
  ssh_time_measure_stop(tm);
  MILLISTAMP("register accending firing time", tm);

  /* Cancel these timeouts, from first to last. */
  ssh_time_measure_reset(tm);  ssh_time_measure_start(tm);
  to_cancel(n, 0);
  ssh_time_measure_stop(tm);
  MILLISTAMP("cancel at registration order", tm);

  /* Register n timeouts in descending order of firing time */
  ssh_time_measure_reset(tm);  ssh_time_measure_start(tm);
  to_register(n, 2);
  ssh_time_measure_stop(tm);
  MILLISTAMP("register decending firing time", tm);

  ssh_time_measure_reset(tm);  ssh_time_measure_start(tm);
  to_cancel(n, 1);
  ssh_time_measure_stop(tm);
  MILLISTAMP("cancel reverse registration order", tm);

  /* Random order */
  ssh_time_measure_reset(tm);  ssh_time_measure_start(tm);
  to_register(n, 3);
  ssh_time_measure_stop(tm);
  MILLISTAMP("register random order", tm);

  ssh_time_measure_reset(tm);  ssh_time_measure_start(tm);
  to_cancel(n, 1);
  ssh_time_measure_stop(tm);
  MILLISTAMP("cancel reverse registration order", tm);

  /* Random order, old API cancel by function */
  ssh_time_measure_reset(tm);  ssh_time_measure_start(tm);
  to_register(n, 3);
  ssh_time_measure_stop(tm);
  MILLISTAMP("register random order", tm);

  ssh_time_measure_reset(tm);  ssh_time_measure_start(tm);
  to_cancel(n, 2);
  ssh_time_measure_stop(tm);
  MILLISTAMP("cancel all by callback function and wildcard context", tm);

  /* Random order, old API cancel by context */
  ssh_time_measure_reset(tm);  ssh_time_measure_start(tm);
  to_register(n, 3);
  ssh_time_measure_stop(tm);
  MILLISTAMP("register random order", tm);

  ssh_time_measure_reset(tm);  ssh_time_measure_start(tm);
  to_cancel(n, 3);
  ssh_time_measure_stop(tm);
  MILLISTAMP("cancel all by callback function and given context", tm);

  /* Random order, old API cancel by context and wildcard callback */
  ssh_time_measure_reset(tm);  ssh_time_measure_start(tm);
  to_register(n, 3);
  ssh_time_measure_stop(tm);
  MILLISTAMP("register random order", tm);

  ssh_time_measure_reset(tm);  ssh_time_measure_start(tm);
  to_cancel(n, 4);
  ssh_time_measure_stop(tm);
  MILLISTAMP("cancel all by wildcard function and given context", tm);


  ssh_time_measure_reset(tm);  ssh_time_measure_start(tm);
  to_register(n, 4);
  ssh_time_measure_stop(tm);
  MILLISTAMP("register random order, shared context", tm);

  ssh_time_measure_reset(tm);  ssh_time_measure_start(tm);
  to_cancel(n, 4);
  ssh_time_measure_stop(tm);
  MILLISTAMP("cancel all by wildcard function and given context", tm);

  ssh_time_measure_reset(tm);  ssh_time_measure_start(tm);
  to_register(n, 4);
  ssh_time_measure_stop(tm);
  MILLISTAMP("register random order, shared context", tm);

  ssh_time_measure_reset(tm);  ssh_time_measure_start(tm);
  to_cancel(n, 2);
  ssh_time_measure_stop(tm);
  MILLISTAMP("cancel all by wildcard function and wildcard", tm);

  ssh_time_measure_free(tm);

  /* Now register timeouts and receive them from the callback */
  to_register(n, 3);
  ssh_event_loop_run();

  for (i = 0; i < n; i++)
    if (timeouts[i].id != -1)
      ssh_fatal("timeout %d did not trigger!", timeouts[i].id);

  g_last_triggered_id = -1;
  g_check_order = 1;

  to_register(n, 0);
  ssh_event_loop_run();
  for (i = 0; i < n; i++)
    if (timeouts[i].id != -1)
      ssh_fatal("timeout %d did not trigger!", timeouts[i].id);

  ssh_event_loop_uninitialize();
  ssh_util_uninit();
  return 0;
}
