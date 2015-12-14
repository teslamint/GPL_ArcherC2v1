/*
  icept_kernel_stubs_vxworks.c

  Copyright:
 	Copyright (c) 2002, 2003 SFNT Finland Oy.
        All rights reserved

  Kernel-mode implementations of various functions for BSD-like
  operating systems.
*/

#define SSH_ALLOW_CPLUSPLUS_KEYWORDS

#include "sshincludes.h"
#include "kernel_timeouts.h"
#include "kernel_mutex.h"
#include "icept_internal.h"
#include "kernel_alloc.h"
#include <stdlib.h>
#include <time.h>
#include <netLib.h>
#include <tickLib.h>
#include "cacheLib.h"
#include "icept_vxworks.h"
#include "sshsimplehashtable.h"
#include "sshdlqueue.h"


#define SSH_DEBUG_MODULE "IceptKernelStubsVxWorks"

/* From VxWorks BSP */
extern int sysClkRateGet();

/*
  Undefine SSH macros which are supposed to protect against
  unwanted use of system malloc / free.
*/
#ifdef malloc
#undef malloc
#endif
#ifdef free
#undef free
#endif

/**********************************************************************
 * ssh_kernel_alloc functions
 **********************************************************************/

#define SSH_MALLOC_OVERHEAD  (sizeof(SshUInt32))
#define SSH_VX_KERNEL_ALLOC_DMA 0x00000001

void *
ssh_kernel_alloc(size_t size, SshUInt32 flag)
{
  unsigned char *v;

  if (flag & SSH_KERNEL_ALLOC_DMA)
    {
      v = cacheDmaMalloc(size + SSH_MALLOC_OVERHEAD);
      ((SshUInt32 *) v)[0] = SSH_VX_KERNEL_ALLOC_DMA;
    }
  else
    {
      v = malloc(size + SSH_MALLOC_OVERHEAD);
      ((SshUInt32 *) v)[0] = 0;
    }

  return (v + SSH_MALLOC_OVERHEAD);
}


void
ssh_kernel_free(void *ptr)
{
  SshUInt32 v = ((SshUInt32 *)ptr)[-1];

  SSH_ASSERT(v == SSH_VX_KERNEL_ALLOC_DMA || v == 0);

  if (v == SSH_VX_KERNEL_ALLOC_DMA)
    cacheDmaFree((unsigned char *) ptr - SSH_MALLOC_OVERHEAD);
  else
    free((unsigned char *) ptr - SSH_MALLOC_OVERHEAD);
}

extern int ssh_net_id; /* To check if this is already tNetTask. */
/* Mechanism for moving execution to tNetTask. */

/* Move execution to netJob. returns 0 if successful. */
int ssh_netjob_synchronous_invoke(FUNCPTR function, void *context)
{
  STATUS stat;
  SEMAPHORE *s;

  s = semBCreate(SEM_Q_PRIORITY, SEM_FULL);
  if (!s) return 2;
  
  semTake(s, WAIT_FOREVER);
  stat = netJobAdd(function, (int)context, (int)s, 0, 0, 0);

  if (stat == OK) 
    {
      semTake(s, WAIT_FOREVER);
      semDelete(s);
      return 0;
    }

  semGive(s);
  semDelete(s);
  return 1;
}

#if VXWORKS_NETVER < 55122
void ssh_interceptor_get_time(SshTime *seconds, SshUInt32 *useconds)
{
  struct timespec ts;

  clock_gettime(CLOCK_REALTIME, &ts);

  if (seconds)
    *seconds = (SshTime)ts.tv_sec;
  if (useconds)
    *useconds = (SshUInt32)ts.tv_nsec / 1000;
}
#else /* VXWORKS_NETVER < 55122 */
void ssh_interceptor_get_time(SshTime *seconds, SshUInt32 *useconds)
{
  struct timeval tv;

  microtime(&tv);

  if (seconds)
    *seconds = (SshTime)tv.tv_sec;
  if (useconds)
    *useconds = (SshUInt32)tv.tv_usec;
}
#endif /* VXWORKS_NETVER < 55122 */

/**********************************************************************
 * Timeout functions
 **********************************************************************/

/* Timeout lists */
#define SSH_KTIMEOUT_SLOTS  32
#define SSH_KTIMEOUT_MASK   (SSH_KTIMEOUT_SLOTS - 1)

typedef struct SshKernelTimeoutRec
{
  /* This link must be the first member in the structure. */
  SshDlNodeStruct link;
  SshKernelTimeoutCallback cb;
  void *context;
  timer_t timer;
#ifdef DEBUG_LIGHT
  SshUInt32 tag;
  SshUInt32 magic;
#endif /* DEBUG_LIGHT */
} *SshKernelTimeout;

union
{
  SshSimpleHashStruct hash;
  void *size[SSH_SIMPLE_HASH_SIZE_POINTERS(SSH_KTIMEOUT_SLOTS)];
} ssh_timeouts;
SshDlQueueStruct ssh_timeouts_free_queue;
SshUInt32 ssh_timeouts_cnt;

SshUInt32 ssh_vx_kernel_timeout_hash(void *timeout_rec)
{
  SshUInt32 hash;
  struct SshKernelTimeoutRec *r = timeout_rec;
  hash = ((int) r->cb ) ^ ((int) r->context);

  return hash ^ (hash >> 16);
}

void ssh_kernel_timeout_cb(timer_t tid, int kto);

SshKernelTimeout ssh_vx_alloc_kernel_timeout(void)
{
  SshKernelTimeout t = ssh_malloc(sizeof(struct SshKernelTimeoutRec));
  if (!t) return NULL;
  if (timer_create(CLOCK_REALTIME, NULL, &t->timer) != OK)
    goto fail_t;
  if (timer_connect(t->timer, &ssh_kernel_timeout_cb, (int)t) != OK)
    goto fail_c;

#ifdef DEBUG_LIGHT
  t->tag = ssh_timeouts_cnt++;
  t->magic = 0xf4eeda7a;
#endif /* DEBUG_LIGHT */
  return t;

 fail_c:
  timer_delete(t->timer);
 fail_t:
  ssh_free(t);
  return NULL;
}

void ssh_vx_delete_kernel_timeout(SshKernelTimeout t)
{
#ifdef DEBUG_LIGHT
  SSH_ASSERT(t->magic == 0xf4eeda7a);
  t->magic = 0xdead7173;
#endif /* DEBUG_LIGHT */
  timer_delete(t->timer);
  ssh_free(t);
}

/* The system no longer needs these. */
void ssh_kernel_timeout_init(void)
{
  SSH_SIMPLE_HASH_INIT(&(ssh_timeouts.hash), SSH_KTIMEOUT_SLOTS, 
		       sizeof(ssh_timeouts));
  SSH_DLQUEUE_INIT(&ssh_timeouts_free_queue, 100); 
  /* 100 should be typically enough to keep rate of memory allocations low. */
}

/* Free ssh_timeouts_free_queue contents. */
void ssh_kernel_timeout_uninit(void) { 
  SshDlNode node;

  while ((node = SSH_DLQUEUE_DETACH(&ssh_timeouts_free_queue)) != NULL)
{
      ssh_vx_delete_kernel_timeout((SshKernelTimeout)node);
    }
}

/* This function is called on timeouts instead of calling the real timeout
   callback directly.  This will remove the timeout from the kernel
   list of timeouts and call the real callback. */
void ssh_kernel_timeout_wrap(int tid, int kto, int do_callback, 
			     int hash_, int stub)
{
  SshKernelTimeout t = (SshKernelTimeout)kto;
  SshDlNode free_me;
  SshKernelTimeoutCallback cb;
  void *context;
  SshUInt32 hash = hash_;

  /* printf("Timer triggered: t=%p[h=%x] task=%p\n", t, 
	 ssh_vx_kernel_timeout_hash(t), (void*)taskIdSelf());
  */

  if (!SSH_SIMPLE_HASH_NODE_EXISTS(&(ssh_timeouts.hash), &(t->link),
				   hash))
      {
      /* This timer was cancelled between invocation of ssh_kernel_timeout_cb
	 and this function => do nothing. */
      return;
    }

  SSH_SIMPLE_HASH_NODE_DETACH(&(ssh_timeouts.hash), &(t->link), hash);

#ifdef DEBUG_LIGHT
  SSH_ASSERT(t->magic == 0xbeef1234);
  t->magic = 0xf4eeda7a;
#endif /* DEBUG_LIGHT */
  cb = t->cb;
  context = t->context;

  free_me = SSH_DLQUEUE_INSERT(&(ssh_timeouts_free_queue), &(t->link));
  if (free_me)
    {
      ssh_vx_delete_kernel_timeout((SshKernelTimeout)free_me);
    }
  else




  if (do_callback) (*cb)(context);
}

void ssh_kernel_timeout_cb(timer_t tid, int kto)
{
  SshUInt32 hash_;
  SSH_ASSERT(taskIdSelf() == ssh_net_id);

  /* Calculate hash here, the timeout structure might have been freed
     prior netjob is actually executed. */
  hash_ = ssh_vx_kernel_timeout_hash((void *)kto);

  if (netJobAdd((FUNCPTR)ssh_kernel_timeout_wrap,
                (int)tid,(int)kto,TRUE,(int)hash_, 0) != OK)
    {
      ssh_kernel_timeout_wrap((int)tid, (int)kto, FALSE, (int)hash_, 0);
      /* timer is lost, tNetTask is out of resources to fit in more
         to the queue, issue a warning to the user, check your VxWorks
         configuration */
      ssh_warning("timeout lost");
    }
}


/* Registers a timeout function that is to be called once when the specified
   time has elapsed.  The callback function may get called concurrently with
   other functions.

   The timeout will be delivered approximately after the specified time.  The
   exact time may differ somewhat from the specified time.

   The arguments are as follows:
     seconds        number of full seconds after which the timeout is delivered
     microseconds   number of microseconds to add to full seconds
                    (this may be larger than 1000000, meaning several seconds)
     callback       the callback function to call
     context        context argument to pass to callback function.
   The timeout cannot be zero. */

void ssh_engine_natt_keepalive_timeout(void);

SSH_COND_SWITCH_HELPER_P4(ssh_kernel_timeout_register, 
			  SshUInt32, seconds, 
			  SshUInt32, microseconds,
			  SshKernelTimeoutCallback, callback,
			  void *, context);

void ssh_kernel_timeout_register(SshUInt32 seconds, SshUInt32 microseconds,
                                 SshKernelTimeoutCallback callback,
                                 void *context)
{
  SshDlNode dl;
  SshKernelTimeout t;
  struct itimerspec value;

  SSH_COND_SWITCH_TO_NETTASK_P4(ssh_kernel_timeout_register,
				SshUInt32, seconds, 
				SshUInt32, microseconds,
				SshKernelTimeoutCallback, callback,
				void *, context);

  SSH_ASSERT(taskIdSelf() == ssh_net_id);

  dl = SSH_DLQUEUE_DETACH(&(ssh_timeouts_free_queue));
  if (dl) 
    {
      t = (SshKernelTimeout)dl;
    }
  else
    {
      /* Loop until kernel timeout is gotten. 
	 Notice: in low memory situation we might be here forever.
         We're trusting that one of other threads executing frees 
	 up some memory. */
      for(t = ssh_vx_alloc_kernel_timeout(); 
	  t == NULL; 
	  t = ssh_vx_alloc_kernel_timeout())
	{
	  /* If t is NULL, wait a bit, maybe more memory becomes available. */
	  taskDelay(1);




	}
    }

#ifdef DEBUG_LIGHT
  SSH_ASSERT(t->magic == 0xf4eeda7a);
  t->magic = 0xbeef1234;
#endif /* DEBUG_LIGHT */
  t->cb = callback;
  t->context = context;

  SSH_SIMPLE_HASH_NODE_INSERT(&(ssh_timeouts.hash), &(t->link),
			      ssh_vx_kernel_timeout_hash(t));

  if (microseconds >= 1000000)
    {
    seconds += microseconds/1000000;
    microseconds = microseconds%1000000;
  }

  /* 0 timeout will cancel it */
  if (seconds == 0 && microseconds == 0)
    microseconds = 1;

  value.it_interval.tv_sec = value.it_interval.tv_nsec =0;
  value.it_value.tv_sec = seconds;
  value.it_value.tv_nsec = microseconds * 1000;

  if (timer_settime(t->timer, 0, &value, NULL) != OK)
    {
      /* Could not set timeout */
      ssh_fatal("timeout");
    }
}

#ifdef DEBUG_LIGHT
void ssh_kernel_timeout_offsets(void)
{
  printf("Ptr to timeout hash: %p, size: %d buckets: %d/%d\n", 
	 &(ssh_timeouts.hash), sizeof(ssh_timeouts),
	 ssh_timeouts.hash.cur_elems, ssh_timeouts.hash.max_elem + 1);
  printf("Ptr to timeout freelist: %p size: %d len: %d\n", 
	 &(ssh_timeouts_free_queue), sizeof(ssh_timeouts_free_queue),
	 100 - (int)ssh_timeouts_free_queue.capacity_left);
}
#endif /* DEBUG_LIGHT */

void ssh_kernel_timeout_cancel_internal(SshKernelTimeout t)
{
  SshDlNode free_me;

  SSH_ASSERT(taskIdSelf() == ssh_net_id);

  SSH_SIMPLE_HASH_NODE_DETACH(&(ssh_timeouts.hash), &(t->link),
			      ssh_vx_kernel_timeout_hash(t));

  timer_cancel(t->timer);

#ifdef DEBUG_LIGHT
  SSH_ASSERT(t->magic == 0xbeef1234);
  t->magic = 0xf4eeda7a;
#endif /* DEBUG_LIGHT */

  free_me = SSH_DLQUEUE_INSERT(&(ssh_timeouts_free_queue), &(t->link));
  if (free_me)
    {
      ssh_vx_delete_kernel_timeout((SshKernelTimeout)free_me);
    }
}

/* Cancels any timeouts with a matching callback function and context.
   `callback' may be SSH_KERNEL_ALL_CALLBACKS, which matches any function, and
   `context' may be SSH_KERNEL_ALL_CONTEXTS, which matches any context.
   It is guaranteed that the timeout will not be delivered once it has
   been cancelled, even if it had elapsed (but not yet delivered) before
   cancelling it. */

SSH_COND_SWITCH_HELPER_P2(ssh_kernel_timeout_cancel,
			  SshKernelTimeoutCallback, callback,
			  void *, context);

void ssh_kernel_timeout_cancel(SshKernelTimeoutCallback callback,
                               void *context)
{
  SshKernelTimeout t;
  SshSimpleHashEnumerator e;
  SshDlNode n;

  SSH_COND_SWITCH_TO_NETTASK_P2(ssh_kernel_timeout_cancel,
				SshKernelTimeoutCallback, callback,
				void *, context);

  SSH_ASSERT(taskIdSelf() == ssh_net_id);

  if (callback == SSH_KERNEL_ALL_CALLBACKS ||
      context == SSH_KERNEL_ALL_CONTEXTS)
    {
      /* Do global hashtable walk. */
      
      n = SSH_SIMPLE_HASH_ENUMERATOR_START(&(ssh_timeouts.hash), e);
      while (n)
        {
	  t = (SshKernelTimeout) n;

	  if ((callback == SSH_KERNEL_ALL_CALLBACKS || t->cb == callback) &&
	      (context == SSH_KERNEL_ALL_CONTEXTS || t->context == context))
            {
	      ssh_kernel_timeout_cancel_internal(t);
	    }

	  n = SSH_SIMPLE_HASH_ENUMERATOR_NEXT(&(ssh_timeouts.hash), e);
	}
            }
          else
    {
      /* Cancel on timer => only search specific hashtable branch. */
      struct SshKernelTimeoutRec kts_proto;
      kts_proto.cb = callback;
      kts_proto.context = context;

      n = SSH_SIMPLE_HASH_ENUMERATOR_START_HASHVALUE(
	&(ssh_timeouts.hash), e, ssh_vx_kernel_timeout_hash(&kts_proto));
      while (n)
	{
	  t = (SshKernelTimeout) n;

	  if (t->cb == callback && t->context == context)
	    {
	      ssh_kernel_timeout_cancel_internal(t);
        }

	  n = SSH_SIMPLE_HASH_ENUMERATOR_NEXT(&(ssh_timeouts.hash), e);
	}
    }

  if (callback == SSH_KERNEL_ALL_CALLBACKS ||
      context == SSH_KERNEL_ALL_CONTEXTS)
    {
      /* Also clean timeouts freelist. 
         Do this every time on global clean, to make sure all
         resources allocated by the virtual stack disappear even when
         there still remain other virtual stacks. */
      ssh_kernel_timeout_uninit();
    }
}

void *ssh_kernel_thread_id(void)
{
  return (void *)taskIdSelf();
}

unsigned int ssh_kernel_num_cpus(void)
{
  return 1;
}

unsigned int ssh_kernel_get_cpu(void)
{
  return 0;
}

/**********************************************************************
 * Miscellaneous stubs to get things to compile
 **********************************************************************/













































































