/*

  timeout.c

  Copyright:
          Copyright (c) 2002 - 2008 SFNT Finland Oy.
  All rights reserved.

  This file contains implementation of functions for timed callback
  functions. The description for these functions can be found at
  kernel_timeouts.h.

  The timed callbacks are managed by using a TimeoutManager object
  that maintains a list of all registered timed callbacks.

  The OS kernel timer object (NDIS_TIMER) is used to implement 
  timed callback features. One periodic timer is created to run in a
  pre-defined interval. This timer calculates the elapsed time and then
  schedules WorkItems that runs the timed callbacks functions in a
  system worker thread context.
*/

/*-------------------------------------------------------------------------
  INCLUDE FILES
  -------------------------------------------------------------------------*/
#include "sshincludes.h"
#include "kernel_timeouts.h"
#include "interceptor_i.h"
#include "engine_alloc.h"

/*-------------------------------------------------------------------------
  DEFINITIONS
  -------------------------------------------------------------------------*/

/* Debug info */
#define SSH_DEBUG_MODULE "SshInterceptorTimeout"

/* Number of pre-allocated timeout structures */
#define SSH_PRE_ALLOCATED_TIMEOUTS      20

/* Type definitions */

/*------------------------------------------------------------------------
  SSH Timeout

  Type definition for timeout attributes.
  ------------------------------------------------------------------------*/
typedef struct SshTimeoutRec
{
  /* For book-keeping timeouts in a double-linked list. Do not move this, 
     because some code assumes (for performance reasons) that this is the
     first item in SshTimeoutStruct. */
  LIST_ENTRY link;

  /* Expiry time in ticks */
  SshInt64 expires;

  /* Pointer into our timeout manager object */
  SshTimeoutManager timeout_mgr;

  /* Timed callback function that is executed when timer is expired */
  SshKernelTimeoutCallback callback;

  /* Parameter for timed callback function */
  void *context;

  /* This flag is set if this is a pre-allocated timeout. */
  SshUInt8 pre_allocated : 1;

} SshTimeoutStruct, *SshTimeout;


/*------------------------------------------------------------------------
  SSH Timer

  Type definition for system timer object.
  ------------------------------------------------------------------------*/
typedef struct SshTimerRec
{
#ifdef _WIN32_WCE
  NDIS_TIMER timer;
#else
  /* Kernel timer and associated DPC object */
  KTIMER timer;
  KDPC timer_dpc;
  /* Length of single (timer interrupt) tick in microseconds */
  ULONG tick_length;
#endif /* _WIN32_WCE */
} SshTimerStruct, *SshTimer;


/*------------------------------------------------------------------------
  SSH Timeout Manager
  
  Type definition for object that manages all timeout operations 
  (register, cancel).
  ------------------------------------------------------------------------*/
typedef struct SshTimeoutManagerRec
{
  /* System timer */
  SshTimerStruct timer;

  /* Timeout currently in timer callback */
  SshTimeout active_timeout;

  /* The processor running the active timeout */
  SshInt16 active_timeout_cpu;

  /* Number of cancel operations pending */
  SshUInt32 pending_cancels : 31;
  /* This flag is set if system timer must be resceduled when the last 
     pending cancel operation completes */
  SshUInt32 must_reschedule : 1;

  /* Double-linked list for timeouts and it's lock */
  LIST_ENTRY timeout_list;
  NDIS_SPIN_LOCK timeout_list_lock;

  /* Free-list of pre-allocated timeout structures and lock for ensuring the
     data integrity */
  LIST_ENTRY free_timeouts;
  NDIS_SPIN_LOCK free_list_lock;

  /* Pre-allocated timeouts */
  SshTimeoutStruct pre_allocated_timeouts[SSH_PRE_ALLOCATED_TIMEOUTS];

} SshTimeoutManagerStruct;


#ifdef _WIN32_WCE

/* We need to use standard NDIS timer on Windows CE */
typedef PNDIS_TIMER_FUNCTION SshSystemTimerCallback;

__inline void
ssh_get_tick_count_us(SshTimeoutManager timeout_mgr,
                      SshInt64 *tick_count)
{
  *tick_count = (SshInt64)GetTickCount() * 1000;
}

__inline void
ssh_timer_init(SshTimer timer,
               SshSystemTimerCallback cb,
               void *context)
{
  NdisInitializeTimer(&(timer)->timer, cb, context);
}


#define ssh_timer_uninit(timer)  /* Nothing to do */

__inline void
ssh_timer_start(SshTimer timer,
                SshInt64 microseconds)
{
  NdisSetTimer(&(timer)->timer, (UINT)(microseconds / 1000));
}

__inline void
ssh_timer_stop(SshTimer timer)
{                                                    
  BOOLEAN cancelled; 
                              
  NdisCancelTimer(&(timer)->timer, &cancelled);    
}

#else

/* We can use higher resolution timer on Windows 2K/XP/2K3 */
typedef PKDEFERRED_ROUTINE SshSystemTimerCallback;

__inline void
ssh_get_tick_count_us(SshTimeoutManager timeout_mgr,
                      SshInt64 *tick_count)
{
  LARGE_INTEGER ticks;

  KeQueryTickCount(&ticks);

  *tick_count = ticks.QuadPart * timeout_mgr->timer.tick_length;
}

__inline void
ssh_timer_init(SshTimer timer,
               SshSystemTimerCallback cb,
               void *context)
{
  timer->tick_length = KeQueryTimeIncrement();
  timer->tick_length /= 10;

  KeInitializeTimer(&timer->timer);               
  KeInitializeDpc(&timer->timer_dpc,              
                  cb, context);                     
} 

#define ssh_timer_uninit(timer)  /* Nothing to do */

__inline void
ssh_timer_start(SshTimer timer,
                SshInt64 microseconds)
{
  LARGE_INTEGER expires;

  expires.QuadPart = microseconds;
  expires.QuadPart *= -10;

  KeSetTimer(&timer->timer, expires, &timer->timer_dpc);
}

__inline void
ssh_timer_stop(SshTimer timer)   
{
  KeCancelTimer(&timer->timer);
}

/* For increased WHQL compatibility (prevent one warning), we should not
   use the outdated macro-version of KeQueryTickCount() */
#if defined(KeQueryTickCount) && !defined(_WIN64)
#undef KeQueryTickCount

NTKERNELAPI VOID KeQueryTickCount(PLARGE_INTEGER tick_count);

#endif /* KeQueryTickCount */

#endif /* _WIN32_WCE */


/*--------------------------------------------------------------------------
  EXTERNALS
  --------------------------------------------------------------------------*/

/*--------------------------------------------------------------------------
  GLOBALS
  --------------------------------------------------------------------------*/

/*--------------------------------------------------------------------------
  LOCAL VARIABLES
  --------------------------------------------------------------------------*/

/*--------------------------------------------------------------------------
  LOCAL FUNCTION PROTOTYPES
  --------------------------------------------------------------------------*/
#ifdef _WIN32_WCE

static void
ssh_kernel_timeout_execute(void *sys_arg1,
                           SshTimeoutManager timeout_mgr,
                           void *sys_arg2,
                           void *sys_arg3);

#else

KDEFERRED_ROUTINE ssh_kernel_timeout_execute;

#endif /* _WIN32_WCE */

/*-------------------------------------------------------------------------
  IN-LINE FUNCTIONS
  -------------------------------------------------------------------------*/

__inline SshTimeout
ssh_kernel_timeout_alloc(SshTimeoutManager timeout_mgr)
{
  SshTimeout timeout = NULL;
  PLIST_ENTRY entry;
  
  entry = NdisInterlockedRemoveHeadList(&timeout_mgr->free_timeouts,
                                        &timeout_mgr->free_list_lock);
  if (entry != NULL)
    timeout = CONTAINING_RECORD(entry, SshTimeoutStruct, link);

  if (timeout == NULL)
    {
      timeout = ssh_calloc(1, sizeof(*timeout));
      if (timeout == NULL)
        ssh_fatal("Out of memory!");

      timeout->pre_allocated = 0;
    }

  return (timeout);
}


__inline void
ssh_kernel_timeout_free(SshTimeoutManager timeout_mgr,
                        SshTimeout timeout)
{
  if (timeout->pre_allocated)
    NdisInterlockedInsertTailList(&timeout_mgr->free_timeouts,
                                  &timeout->link,
                                  &timeout_mgr->free_list_lock);
  else
    ssh_free(timeout);
}


__inline void
ssh_kernel_timeout_reschedule_timer(SshTimeoutManager timeout_mgr,
                                    SSH_IRQL irql)
{
  if (IsListEmpty(&timeout_mgr->timeout_list))
    {
      ssh_timer_stop(&timeout_mgr->timer);
    }
  else
    {
      SshInt64 now;
      SshInt64 expires;
      SshTimeout timeout = CONTAINING_RECORD(timeout_mgr->timeout_list.Flink,
                                             SshTimeoutStruct, link);

      ssh_get_tick_count_us(timeout_mgr, &now);

      expires = timeout->expires - now;

      if (expires < 0)
        expires = 0;

      if ((irql < SSH_DISPATCH_LEVEL) && (expires < 1000))
        {
          /* If the calling thread was running at IRQL less than 
             DISPATCH_LEVEL before it acquired the spin lock (meaning that
             it can be pre-empted), we should refuse to schedule "too short"
             (repetitive) timeout, otherwise we could cause an infinite loop.

             This is what could happen:

             1) After the calling thread releases the spin lock currently
                held, thus causing the IRQL to drop below DISPATCH_LEVEL...

             2) If the very short timeout was not already executed (by
                another CPU on SMP platform...

             3) With a very high probability, DPC routine of the system 
                timer is executed on the context of the thread which 
                originally scheduled the timeout (because this thread is
                the one executing when the dispatcher interrupt is 
                handled)...

             4) If the timeout callback simply checks whether the original
                caller thread has completed some task... and when not, it 
                re-schedules another very short timeout which will fire 
                almost immediately...

             5) The result is that the original thread will never get chance 
                to continue execution... */

          expires = 1000;  /* one millisecond */
        }

      ssh_timer_start(&timeout_mgr->timer, expires);
    }
}


/*--------------------------------------------------------------------------
  EXPORTED FUNCTIONS
  --------------------------------------------------------------------------*/

/*-------------------------------------------------------------------------
  ssh_kernel_timeout_register()

  Registers a timed callback function. Timeouts are kept in a
  double-linked list so that they can be cancelled before their
  timer is expired.
  
  Arguments:
  secs - expiration time in seconds
  usecs - expiration time in microseconds
  callback - callback function to execute when timeout expires
  context - context passed to callback function
  
  Returns:
  
  Notes:
   If the registered timeout is currently under cancellation it
   is immediately cancelled by not registering it.
  -------------------------------------------------------------------------*/
VOID
ssh_kernel_timeout_register(SshUInt32 secs,
                            SshUInt32 usecs,
                            SshKernelTimeoutCallback callback,
                            void *context)
{
  SshTimeoutManager timeout_mgr;
  SshTimeout timeout;
  PLIST_ENTRY pred, succ;
  SSH_IRQL irql = SSH_GET_IRQL();

  
  SSH_ASSERT(the_interceptor != NULL);
  SSH_ASSERT(the_interceptor->timeout_mgr != NULL);

  timeout_mgr = the_interceptor->timeout_mgr;

  SSH_DEBUG(SSH_D_LOWSTART, ("ssh_kernel_timeout_register()"));

  timeout = ssh_kernel_timeout_alloc(timeout_mgr);
  /* Compute relative expiration time, units are microsecond intervals */
  ssh_get_tick_count_us(timeout_mgr, &timeout->expires);
  timeout->expires += 1000000 * secs + usecs;
  timeout->callback = callback;
  timeout->context = context;

  NdisAcquireSpinLock(&timeout_mgr->timeout_list_lock);

  for (succ = timeout_mgr->timeout_list.Flink;
       succ != &timeout_mgr->timeout_list; succ = succ->Flink)
    {
      SshTimeout to = CONTAINING_RECORD(succ, SshTimeoutStruct, link);

      if (to->expires > timeout->expires)
        break;
    }
  
  /* Insert new timeout to the sorted, doubly-linked queue */
  pred = succ->Blink;
  timeout->link.Blink = pred;
  timeout->link.Flink = succ;
  pred->Flink = &timeout->link;
  succ->Blink = &timeout->link;

  /* If new timeout was inserted into the beginning of the queue AND 
     timer callback is not currently running, reschedule the timer. 
     If timer callback is running, the timer is rescheduled after the 
     callback returns (in that case this timeout could also get 
     immediately canceled). */
  if ((pred == &timeout_mgr->timeout_list) && 
      (timeout_mgr->active_timeout == NULL))
    {
      /* The system timer is rescheduled either now or when all pending 
         cancel operations have been completed. */
      if (timeout_mgr->pending_cancels == 0)
        ssh_kernel_timeout_reschedule_timer(timeout_mgr, irql);
      else
        timeout_mgr->must_reschedule = 1;
    }
  
  NdisReleaseSpinLock(&timeout_mgr->timeout_list_lock);
}


/*--------------------------------------------------------------------------
  ssh_kernel_timeout_cancel()

  Cancels a previously registered timeout or all timed callbacks
  if their's timed callback execution has not yet started.

  Arguments:
  callback - timed callback function to cancel or all callbacks
  context - callback function context or all contexts
  
  Returns:
  
  Notes:
  Global cancellation of timeouts is still required before the application
  using timeouts is terminated.
  -------------------------------------------------------------------------*/
VOID
ssh_kernel_timeout_cancel(SshKernelTimeoutCallback callback,
                          void *context)
{
  SshTimeoutManager timeout_mgr;
  LIST_ENTRY canceled_timeouts;
  PLIST_ENTRY first;
  SshTimeout timeout;
  SSH_IRQL irql = SSH_GET_IRQL();

  SSH_ASSERT(the_interceptor != NULL);
  SSH_ASSERT(the_interceptor->timeout_mgr != NULL);

  timeout_mgr = the_interceptor->timeout_mgr;

  SSH_DEBUG(SSH_D_LOWSTART, ("ssh_kernel_timeout_cancel()"));

  NdisInitializeListHead(&canceled_timeouts);

  NdisAcquireSpinLock(&timeout_mgr->timeout_list_lock);

  timeout_mgr->pending_cancels++;

 retry:

    /* If we have active timeout, check that are we canceling 
     it. If we aren't, we can continue disabling other timeouts.
     Actually there still remains one rare condition, we could 
     prepare ourselves. If we are canceling all timeouts, we should
     make a delayed waiting for active timeout gets away and then 
     we can remove the timeouts. */
  if (timeout_mgr->active_timeout && 
      (timeout_mgr->active_timeout->context == context ||
       context == SSH_KERNEL_ALL_CONTEXTS) &&
      timeout_mgr->active_timeout->callback == callback &&
      timeout_mgr->active_timeout_cpu == ssh_kernel_get_cpu())
    {
      /* If we are canceling the timeout we are already executing, 
         we cannot cancel it, since it executing and is anyway disabled
         after the callback execution ends. Just release spinlock and
	 return to the caller. */

      NdisReleaseSpinLock(&timeout_mgr->timeout_list_lock);
      ssh_fatal("Canceling timeout callback (%p %p) on the same CPU where the" 
                " callback is executing at the moment.", context, callback);
      return;
    }
  else if (timeout_mgr->active_timeout && 
           (timeout_mgr->active_timeout->context == context ||
            context == SSH_KERNEL_ALL_CONTEXTS) &&
           timeout_mgr->active_timeout->callback == callback &&
           timeout_mgr->active_timeout_cpu != ssh_kernel_get_cpu())
    {
      /* We are cancelling the same callback which is on execution on 
         other CPU. Wait for it to finish and cancel it only after 
         that. */
      NdisReleaseSpinLock(&timeout_mgr->timeout_list_lock);
      
      if (irql < SSH_DISPATCH_LEVEL)
        {
          NdisMSleep(50);
        }
      else
        {
          SSH_ASSERT(ssh_kernel_num_cpus() > 1);
          NdisStallExecution(20);
        }
      
      NdisAcquireSpinLock(&timeout_mgr->timeout_list_lock);
      goto retry;
    }
  else if (timeout_mgr->active_timeout &&
           context == SSH_KERNEL_ALL_CONTEXTS &&
           callback == SSH_KERNEL_ALL_CALLBACKS) 
           
    {
      /* Case when we are disabling all callbacks on all contexts (i.e.
         disabling the interceptor) or we are disabling all certain callbacks
         in all contexts. We must wait until active timeout finishes. */
      NdisReleaseSpinLock(&timeout_mgr->timeout_list_lock);
      
      if (irql < SSH_DISPATCH_LEVEL)
        {
          NdisMSleep(50);
        }
      else
        {
          SSH_ASSERT(ssh_kernel_num_cpus() > 1);
          NdisStallExecution(20);
        }
      
      NdisAcquireSpinLock(&timeout_mgr->timeout_list_lock);
      goto retry;
    }
  else
    {
      PLIST_ENTRY current;

      /* No timer callbacks running, perform the cancel processing */
      first = timeout_mgr->timeout_list.Flink;
      
      current = first;
      while (current != &timeout_mgr->timeout_list)
        {
          PLIST_ENTRY next = current->Flink;

          timeout = CONTAINING_RECORD(current, SshTimeoutStruct, link);

          if ((timeout->callback == callback) ||
              (callback == SSH_KERNEL_ALL_CALLBACKS))
            {
              if ((timeout->context == context) ||
                  (context == SSH_KERNEL_ALL_CONTEXTS))
                {
                  /* Move this timeout into the list of canceled timeouts.
                     The timeout will be freed after we release the spin
                     lock. */
                  RemoveEntryList(current);
                  InsertTailList(&canceled_timeouts, &timeout->link);
                }
            }

          current = next;
        }

      timeout_mgr->pending_cancels--;

      if (timeout_mgr->pending_cancels == 0 &&
          !timeout_mgr->active_timeout)
        {
          /* If first timeout was canceled, reschedule the timer */
          if ((timeout_mgr->timeout_list.Flink != first) ||
              (timeout_mgr->must_reschedule == 1))
            {
              ssh_kernel_timeout_reschedule_timer(timeout_mgr, irql);

              timeout_mgr->must_reschedule = 0;
            }
        }
    }

  NdisReleaseSpinLock(&timeout_mgr->timeout_list_lock);

  while (!IsListEmpty(&canceled_timeouts))
    {
      first = RemoveHeadList(&canceled_timeouts);

      timeout = CONTAINING_RECORD(first, SshTimeoutStruct, link);

      ssh_kernel_timeout_free(timeout_mgr, timeout);
    }
}


Boolean
ssh_kernel_timeouts_init(SshInterceptor interceptor)
{
  SshTimeoutManager timeout_mgr;
  unsigned int i;

  SSH_ASSERT(interceptor != NULL);
  SSH_ASSERT(SSH_GET_IRQL() == SSH_PASSIVE_LEVEL);

  /* Create timeout_manager if it does not exist. */
  timeout_mgr = ssh_calloc(1, sizeof(*timeout_mgr));
  if (timeout_mgr == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Could not create timeout manager!"));
      return FALSE;
    }

  NdisInitializeListHead(&timeout_mgr->timeout_list);
  NdisAllocateSpinLock(&timeout_mgr->timeout_list_lock);

  NdisInitializeListHead(&timeout_mgr->free_timeouts);
  NdisAllocateSpinLock(&timeout_mgr->free_list_lock);

  for (i = 0; i < SSH_PRE_ALLOCATED_TIMEOUTS; i++)
    {
      SshTimeout timeout = &timeout_mgr->pre_allocated_timeouts[i];

      timeout->pre_allocated = 1;
      InsertTailList(&timeout_mgr->free_timeouts, &timeout->link);
    }

  interceptor->timeout_mgr = timeout_mgr;

  ssh_timer_init(&timeout_mgr->timer, 
                 ssh_kernel_timeout_execute, 
                 timeout_mgr);

  return TRUE;
}


VOID
ssh_kernel_timeouts_uninit(SshInterceptor interceptor)
{
  SSH_ASSERT(interceptor != NULL);
  SSH_ASSERT(interceptor->timeout_mgr != NULL);

  ssh_timer_stop(&(interceptor->timeout_mgr->timer));
  ssh_timer_uninit(&(interceptor->timeout_mgr->timer));

  /* Destroy the TimeoutManager */
  ssh_free(interceptor->timeout_mgr);
  interceptor->timeout_mgr = NULL;
}


VOID
ssh_kernel_timeouts_suspend(SshInterceptor interceptor)
{
  SSH_ASSERT(interceptor != NULL);
  SSH_ASSERT(interceptor->timeout_mgr != NULL);

  ssh_timer_stop(&(interceptor->timeout_mgr->timer));
}


VOID
ssh_kernel_timeouts_resume(SshInterceptor interceptor,
                           SshUInt32 suspend_time_sec,
                           SshUInt32 suspend_time_usec)
{
  SshTimeoutManager timeout_mgr;
  PLIST_ENTRY entry;
  __int64 interval;
  SSH_IRQL irql = SSH_GET_IRQL();

  SSH_ASSERT(interceptor != NULL);
  SSH_ASSERT(interceptor->timeout_mgr != NULL);

  timeout_mgr = interceptor->timeout_mgr;

  /* Compute relative expiration time, units are microsecond intervals */
  interval = 1000000 * suspend_time_sec + suspend_time_usec;

  /* Adjust the tick counts for scheduled timeouts */
  NdisAcquireSpinLock(&timeout_mgr->timeout_list_lock);

  for (entry = timeout_mgr->timeout_list.Flink;
       entry != &(timeout_mgr->timeout_list);
       entry = entry->Flink)
    {
      SshTimeout timeout = CONTAINING_RECORD(entry, SshTimeoutStruct, link);

      if (interval > timeout->expires)
        timeout->expires = 0;
      else
        timeout->expires -= interval;
    }

  NdisReleaseSpinLock(&timeout_mgr->timeout_list_lock);

  ssh_kernel_timeout_reschedule_timer(timeout_mgr, irql);
}


/*-------------------------------------------------------------------------
  LOCAL FUNCTIONS
  -------------------------------------------------------------------------*/

/* This function is called as a DPC routine when timer expires */
static void
ssh_kernel_timeout_execute(
#ifdef _WIN32_WCE
                           void *sys_arg1,
#else
                           KDPC *dpc,
#endif /* _WIN32_WCE */
                           SshTimeoutManager timeout_mgr,
                           void *sys_agr2,
                           void *sys_arg3)
{
  SshTimeout timeout = NULL;

  SSH_DEBUG(SSH_D_LOWSTART, ("ssh_kernel_timeout_execute()"));

#pragma warning(disable : 6011)
  /* */
  NdisAcquireSpinLock(&timeout_mgr->timeout_list_lock);
  if (!IsListEmpty(&timeout_mgr->timeout_list))
    {
      PLIST_ENTRY entry;

      entry = RemoveHeadList(&timeout_mgr->timeout_list);
      timeout = CONTAINING_RECORD(entry, SshTimeoutStruct, link);
      timeout_mgr->active_timeout = timeout;
      timeout_mgr->active_timeout_cpu = (SshUInt16)ssh_kernel_get_cpu();
    }
  NdisReleaseSpinLock(&timeout_mgr->timeout_list_lock);

  if (timeout != NULL)
    {
      SSH_DEBUG(SSH_D_LOWSTART, ("Executing timer callback"));

      timeout->callback(timeout->context);

      SSH_DEBUG(SSH_D_LOWSTART, ("Timer callback done"));

      NdisAcquireSpinLock(&timeout_mgr->timeout_list_lock);

      timeout_mgr->active_timeout = NULL;

      /* Do not restart the system timer now if one or more cancel operations
         are currently pending. (In this case the timer is rescheduled when
         the last cancel operation completes.) This "trick" keeps timeout
         cancellation simple... */
      if (timeout_mgr->pending_cancels == 0)
        ssh_kernel_timeout_reschedule_timer(timeout_mgr,
                                            SSH_DISPATCH_LEVEL);
      else
        timeout_mgr->must_reschedule = 1;

      NdisReleaseSpinLock(&timeout_mgr->timeout_list_lock);

      ssh_kernel_timeout_free(timeout_mgr, timeout);
    }
  else
    {
      /* All timeouts were canceled after the timer expired, but before this
         function acquired the timeout_list_lock. Unlikely, but possible. */
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Timeout queue is empty!"));
    }
#pragma warning(default : 6011)
} 

