/*
  File: linux_timeout.c

  Copyright:
        Copyright (c) 2002-2008 SFNT Finland Oy.
	All rights reserved

  Implementation of the kernel timeout API, ssh_kernel_timeout_*
  functions. These functions are common to all Linux 2.x versions.

*/

#include "linux_internal.h"

/*
  Some random notes about the new timeout system:

  - reference counting + dual-linked list is used to stop need for any
  list traversal (except when doing timeout-cancel).

  Typically reference count of a timeout that is normally on track is 2.

  The reference count is incremented when:
   - timeout is added to kernel, and
   - timeout is added to global timeout list

  The reference count is decremented when:
   - timeout first starts [and it checks for reaching zero;
     if so, it's been already removed from global timeout list]

  Another cheaper way would be to do this by simple is_dead flag or
  equivalent, but I do not think it's equally elegant (especially if
  there is some case where we may want to provide extra references to
  some external user of module or somesuch in future). NOTE: There's
  assertion about timeout's reference being last reference, which
  needs to be changed if applications are given handles to
  timeout-using objects.

  Cheapest way would involve simply freeing struct in two places (end
  of timeout cb, and successful canceling of timeout). I do not
  consider that approach to be good for future expandability, though,
  and this reference scheme makes underlying implementation
  considerably easier to keep track of.

  Besides, the IPsec typically does few timeouts/second at most, so
  this is not speed-critical code but it has been major bug nest when
  it's been too complicated.

  lock priority:
   1. run-lock
   2. queue-lock

   thus, queue->run is invalid [run must be grabbed first to prevent
   livelocks]
*/

#define SSH_DEBUG_MODULE "SshInterceptorTimeout"

extern SshInterceptor ssh_interceptor_context;

/* Timeout structure */
typedef struct SshKernelTimeoutRec *SshKernelTimeout;
typedef struct SshKernelTimeoutRec  SshKernelTimeoutStruct;

struct SshKernelTimeoutRec
{
 /* reference counter for the timeout structure.  when it reaches zero
    (=nobody has handle on timeout), the structure may be freed. When
    timeout in the freelist, this stores the lenght of the list. */
  SshUInt32 refcnt;

  /* When timeout is fired, its is on doubly linked list. When timeout
     is not fired, it is on freelist linked by 'next' field. */
  SshKernelTimeout prev, next;

  /* Application callback and its context */
  SshKernelTimeoutCallback callback;
  void *context;

  /* Underlying platform timeout */
  struct timer_list timer;
};

#define SSH_REMOVE_FROM_LIST(head, ctx)                                     \
do {                                                                        \
  if ((ctx)->prev == NULL)                                                  \
    (head) = (ctx)->next;                                                   \
  else                                                                      \
    (ctx)->prev->next = (ctx)->next;                                        \
  if ((ctx)->next != NULL)                                                  \
    (ctx)->next->prev = (ctx)->prev;                                        \
} while(0)

/* List of timeouts that are in the queue. The list is protected
   by queue-lock */
static SshKernelTimeout ssh_timeout_list = NULL;

/* Ditto, except the read during cancel phase does not matter. */
static SshKernelTimeout ssh_timeout_running = NULL;

/* Timeout freelist */
static SshKernelTimeout ssh_timeout_freelist = NULL;

/* Maximum number of entries on timeout freelist. For the quicksec we
   know we have only around 10 timers running at a time, thus we
   should never run out of these shortly after startup */
#define SSH_KERNEL_TIMO_FL_LENGHT 50


#define SSH_KERNEL_TIMO_FL_PUT(fl, timo)		\
do {							\
  if ((fl) == NULL ||					\
      (fl)->refcnt < SSH_KERNEL_TIMO_FL_LENGHT)	        \
    {							\
      (timo)->next = (fl);				\
      (timo)->refcnt = (fl) ? (fl)->refcnt + 1 : 1;	\
      (fl) = (timo);					\
    }							\
  else							\
    ssh_free((timo));					\
} while (0)

#define SSH_KERNEL_TIMO_FL_GET(fl, timo)		\
do {							\
  if ((fl) == NULL)					\
    {							\
      (timo) = ssh_calloc(1, sizeof(*(timo)));		\
    }							\
  else							\
    {							\
      (timo) = (fl);					\
      (fl) = (fl)->next;				\
      (timo)->next = NULL;				\
      (timo)->refcnt = 0;				\
      memset((timo), 0, sizeof(*(timo)));		\
    }							\
} while (0)


/* Initialize the freelist with the defined (SSH_KERNEL_TIMO_FL_LENGHT)
   amount of entries cached on it. */
void
ssh_kernel_timeout_freelist_init(void)
{
  int i;
  SshKernelTimeout to;
  SshKernelTimeout empty_freelist = NULL;

  for (i = 0; i < SSH_KERNEL_TIMO_FL_LENGHT; i++)
    {
      SSH_KERNEL_TIMO_FL_GET(empty_freelist, to);
      if (to)
	SSH_KERNEL_TIMO_FL_PUT(ssh_timeout_freelist, to);
    }
}

/* Free any cached timeouts on the freelist. */
void
ssh_kernel_timeout_freelist_uninit(void)
{
  while (ssh_timeout_freelist != NULL)
    {
      SshKernelTimeout timo;

      SSH_KERNEL_TIMO_FL_GET(ssh_timeout_freelist, timo);

      if (timo != NULL)
	ssh_free(timo);
    }
}

/* Timeout freeing function.  If reference count is zero after it has
   been decremented, the timeout is moved into freelist freed and any
   access to it is invalid.

   NOTE: _Some_ lock must be held when this is called; typically the
   queue-lock. */

static Boolean
ssh_kernel_timeout_maybe_free(SshKernelTimeout timeout)
{
  /* Do we still have references left? */
  if ((--timeout->refcnt))
    return FALSE;

  SSH_KERNEL_TIMO_FL_PUT(ssh_timeout_freelist, timeout);

  /* Remove the num_timeout statistics reference */
  ssh_interceptor_context->num_timeouts--;
  return TRUE;
}


/* Timeout callback function. This is called when a timeout expires. */
static void
ssh_kernel_timeout_cb(unsigned long data)
{
  SshKernelTimeout to;
#ifdef DEBUG_LIGHT
  Boolean result;
#endif /* DEBUG_LIGHT */





  to = (SshKernelTimeout) data;

  /* Take run lock */
  SSH_TIMEOUT_RUN_LOCK(ssh_interceptor_context);

  /* Take queue lock */
  SSH_TIMEOUT_QUEUE_LOCK(ssh_interceptor_context);

  /* Check if reference count has reached zero [= we do no longer
     exist in the global timeout list ]. */
  if (ssh_kernel_timeout_maybe_free(to))
    {
      goto unlock_and_exit;
    }

  SSH_ASSERT(ssh_timeout_running == NULL);
  ssh_timeout_running = to;

  ssh_interceptor_context->num_timeout_callbacks++;

  /* We don't need queue lock when running callback */
  SSH_TIMEOUT_QUEUE_UNLOCK(ssh_interceptor_context);

  SSH_ASSERT(in_softirq());
  SSH_ASSERT(in_irq() == 0);

  /* We got the timeout lock, execute the callback now. */
  if (ssh_timeout_running)
    (*to->callback) (to->context);

  SSH_TIMEOUT_QUEUE_LOCK(ssh_interceptor_context);

  ssh_interceptor_context->num_timeout_callbacks--;

  /* Remove ourselves from the timeout list - it isn't removed
     because we have held run lock for this whole time
     (cancel executes only when matching run is done). */

  /* Remove from doubly linked list */
  SSH_REMOVE_FROM_LIST(ssh_timeout_list, to);

  /* Removed from list -> remove _probably_ last reference [or
     semantics have changed] */

#ifdef DEBUG_LIGHT
  result =
#endif /* DEBUG_LIGHT */
    ssh_kernel_timeout_maybe_free(to);
  SSH_ASSERT(result == TRUE);


  SSH_ASSERT(ssh_timeout_running != NULL);
  ssh_timeout_running = NULL;

  SSH_LINUX_STATISTICS(ssh_interceptor_context,
  { ssh_interceptor_context->stats.num_timeout_run++; });

 unlock_and_exit:
  SSH_TIMEOUT_QUEUE_UNLOCK(ssh_interceptor_context);
  SSH_TIMEOUT_RUN_UNLOCK(ssh_interceptor_context);



}

/* Registers a timeout function that is to be called once when the
   specified time has elapsed.  Our specs say that it is an fatal
   error to call zero timeout even though Linux's timeouts accepts
   zero timeouts.  This has been implemented as the specs notes,
   however it can change in the future - as it causes no problems.

   The arguments are as follows:
     seconds        number of full seconds after which the timeout is delivered
     useconds       number of microseconds to add to full seconds
                    (this may be larger than 1000000, meaning several seconds)
     callback       the callback function to call
     context        context argument to pass to callback function. */

void
ssh_kernel_timeout_register(SshUInt32 seconds,
                            SshUInt32 useconds,
                            SshKernelTimeoutCallback callback, void *context)
{
  SshKernelTimeout to;

  /* Accept not zero timeouts */
  if (seconds + useconds == 0)
    ssh_warning("ssh_kernel_timeout_register: zero-length timeout");

  /* Hardware accel/shutdown/etc code may call us from misc contexts.
     Disable soft interrupts before using spin locks. */
  local_bh_disable();
  SSH_TIMEOUT_QUEUE_LOCK(ssh_interceptor_context);
  SSH_ASSERT(ssh_interceptor_context->is_timeout_shutdown == FALSE);

  /* First time here, fill the timout freelist */
  if (ssh_timeout_freelist == NULL
      && ssh_interceptor_context->num_timeouts == 0)
    {
      ssh_kernel_timeout_freelist_init();
    }
  SSH_KERNEL_TIMO_FL_GET(ssh_timeout_freelist, to);
  if (!to)
    ssh_fatal("could not allocate timeout");

  to->refcnt = 2;

  to->callback = callback;
  to->context = context;

  to->next = ssh_timeout_list;
  if (ssh_timeout_list)
    ssh_timeout_list->prev = to;
  ssh_timeout_list = to;

  /* it's added to the global timeout list, and to kernel timer. */
  init_timer(&to->timer);
  to->timer.expires = jiffies + (seconds * HZ) + ((useconds * HZ) / 1000000);

  /* Expiring at EXACTLY same moment is problematic because it may
     lead to the timer simply hogging all the CPU and not letting
     anything else run. Thus, we make sure it'll let something else
     run as well. */
  if (to->timer.expires == jiffies)
    to->timer.expires++;
  to->timer.function = ssh_kernel_timeout_cb;
  to->timer.data = (unsigned long) to;

  add_timer(&to->timer);

  ssh_interceptor_context->num_timeouts++;

  SSH_TIMEOUT_QUEUE_UNLOCK(ssh_interceptor_context);
  local_bh_enable();
}

/* Cancels any timeouts with a matching callback function and context.
   `callback' may be SSH_KERNEL_ALL_CALLBACKS, which matches any
   function, and `context' may be SSH_KERNEL_ALL_CONTEXTS, which
   matches any context.  It is guaranteed that the timeout will not be
   delivered once it has been cancelled, even if it had elapsed (but
   not yet delivered) before cancelling it. */

/* On 2.4 we could do all this a lot easier with del_timer_sync which
   is atomic on SMP towards other timeouts. However, it would require
   ugly ifdefs or moving the entire timeout routines to version
   specific directories. This works fine on all versions and is SMP
   safe. -Pekka */

/* 2.2 is history, so we move to using del_timer_sync(). */

void
ssh_kernel_timeout_cancel(SshKernelTimeoutCallback callback, void *context)
{
  SshKernelTimeout to, next_to;

  local_bh_disable();
  /* After this there cannot be new entries added to the lists */
  SSH_TIMEOUT_QUEUE_LOCK(ssh_interceptor_context);

  /* Check if the timeout thread is executing the timeout we should cancel */
  if (ssh_timeout_running != NULL &&
      (ssh_timeout_running->callback == callback ||
       callback == SSH_KERNEL_ALL_CALLBACKS) &&
      (ssh_timeout_running->context == context ||
       context == SSH_KERNEL_ALL_CONTEXTS))
    {
      /* Yes, we are currently executing the thread we are canceling, wait for
         the timeout to finish */
      /* We must free the queue lock, before we can try to get the run lock,
         because otherwise the timeout thread might block waiting for the
         queue lock when registering / deleting new timeouts inside the
         timeout function it is currently executing, thus never finishing ->
         deadlock. */
      SSH_TIMEOUT_QUEUE_UNLOCK(ssh_interceptor_context);

      /* Get the run lock. This means that there cannot be any timeouts
         running after this. */





      SSH_TIMEOUT_RUN_LOCK(ssh_interceptor_context);

      /* _Now_ there cannot be any timeouts running anymore.. */
      SSH_ASSERT(ssh_timeout_running == NULL);

      /* First we need to get the queue lock back */
      SSH_TIMEOUT_QUEUE_LOCK(ssh_interceptor_context);

      /* Now we can go in with normal checks, after we release the run lock. */
      /* It is safe to release run lock, because we have the queue lock, thus
         only timeout that can be executed is not related to those ones
         we are going to cancel */
      SSH_TIMEOUT_RUN_UNLOCK(ssh_interceptor_context);
    }

  for (to = ssh_timeout_list; to; to = next_to)
    {
      next_to = to->next;

      if ((to->callback == callback || callback == SSH_KERNEL_ALL_CALLBACKS)
          && (to->context == context || context == SSH_KERNEL_ALL_CONTEXTS))
        {
	  SSH_LINUX_STATISTICS(ssh_interceptor_context,
	  { ssh_interceptor_context->stats.num_timeout_cancelled++; });
	  
          /* Timeout is in queue, remove it. */
          if (del_timer_sync(&to->timer))
            {
              /* We managed to remove it before it got executed so we
                 may remove the kernel-related reference. */
              ssh_kernel_timeout_maybe_free(to);
            }

          /* Remove from doubly linked list */
          SSH_REMOVE_FROM_LIST(ssh_timeout_list, to);

          /* Remove list-related reference. */
          ssh_kernel_timeout_maybe_free(to);
        }
    }

  /* Release the queue lock */
  SSH_TIMEOUT_QUEUE_UNLOCK(ssh_interceptor_context);
  local_bh_enable();
}
