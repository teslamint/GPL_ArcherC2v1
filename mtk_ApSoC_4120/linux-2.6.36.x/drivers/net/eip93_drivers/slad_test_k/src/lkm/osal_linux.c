/*c*
* File:        osal_linux.c
*
* Security Look Aside  Driver Module for AuthenTec crypto hardware.
* Target-dependent functions and definitions for Linux.
*
*


     Copyright 2007-2010 AuthenTec B.V.

*
*
* Edit History:
*
* Initial revision
*    Created.
*/


/********************************************************
* Header files.
*********************************************************/

#include "slad_osal.h"
//#include "hwpal.h"


#define EXPORT_SYMTAB

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/ioport.h>
#include <linux/slab.h>
#include <linux/cache.h>
#include <linux/fs.h>
#include <linux/interrupt.h>
#include <linux/delay.h>
#include <linux/sched.h>
#include <linux/wait.h>
#include <asm/io.h>

#include <linux/version.h>

#if ( LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,27) )
#include  <linux/semaphore.h>
#define kill_proc(...)
#else
#include <asm/semaphore.h>
#endif

#if ( LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,29) )
#include  <linux/swab.h>
#define OSAL_LINUX_SWAB(a)      __arch_swab32(a)
#else
#define OSAL_LINUX_SWAB(a)      __arch__swab32(a)
#endif

#include <linux/unistd.h>
#include <linux/interrupt.h>
#include <linux/pci.h>
#include <linux/types.h>
#include <asm/uaccess.h>
//#include <asm/ibm44x.h>




void
osal_resource_lock (SLAD_PLATFORM_PARAMS * platform_params_p,
                    SLAD_RESOURCE rsc)
{
#ifdef SLAD_CONFIG_USE_SEMAPHORES
  tasklet_disable (&platform_params_p->bh_tasklet);
  down (rsc);
#else
  spin_lock_bh (rsc);
#endif
}

void
osal_resource_unlock (SLAD_PLATFORM_PARAMS * platform_params_p,
                      SLAD_RESOURCE rsc)
{
#ifdef SLAD_CONFIG_USE_SEMAPHORES
  up (rsc);
  tasklet_enable (&platform_params_p->bh_tasklet);
#else
  spin_unlock_bh (rsc);
#endif
}

void
osal_yield_kernel (void)
{
}



UINT32
osal_swap_endian (UINT32 data)
{
  unsigned short a = 0x0102;
  unsigned char *p;
  p = (unsigned char *) &a;

  if (*p == 0x01)               // Big Endian System
    return OSAL_LINUX_SWAB (data);
  else
    return data;
}

void
osal_watch_dog_init (WATCH_DOG_T * watch_dog, watch_dog_callback function,
                     unsigned long data)
{
  init_timer (watch_dog);
  watch_dog->expires = jiffies;
  watch_dog->function = function;
  watch_dog->data = data;
}

void
osal_watch_dog_uninit (WATCH_DOG_T * watch_dog)
{
  del_timer_sync (watch_dog);
}

void
osal_watch_dog_nap (WATCH_DOG_T * watch_dog)
{
  del_timer_sync (watch_dog);
}

void
osal_watch_dog_reset (WATCH_DOG_T * watch_dog, unsigned long delay)
{
  mod_timer (watch_dog, jiffies + delay);
}

int
osal_watch_dog_pending (WATCH_DOG_T * watch_dog)
{
  return timer_pending (watch_dog);
}

/***************************************************************************
* Send signals / callbacks.
*
*
* dst
*    Pointer to SLAD_SIGNAL structure.
*
*
* return value
*    void
****************************************************************************/
void
osal_notify (int device_num, OSAL_NOTIFY * notify)
{
  /* If a callback function has been defined, call it. */
  if (notify->callback)
    {
      (notify->callback) (device_num);
    }

  /* If a signal has been defined, send the signal. */
  if (notify->signal_number)
    {
      kill_proc (notify->process_id, notify->signal_number, 1);

    }
}








/****************************************************************
* Delay for the specified number of microseconds.
*
*
* d
*    Delay (in microseconds).
*
*
* return value
*    void
*****************************************************************/
void
osal_delay (int d)
{
  udelay (d);
}


/****************************************************************
* Copy data in from application buffer.
*
*
* userland
*    TRUE if application buffer is in user space.
*
* dst
*    Pointer to kernel buffer.
*
* src
*    Pointer to application buffer.
*
* len
*    Length of data to copy (in bytes).
*
*
* return value
*    void
*****************************************************************/
void
osal_copy_from_app (int userland, void *dst, void *src, int len)
{
  if (userland)
    {

      if (copy_from_user (dst, src, len))
        {
          memcpy (dst, src, len);
          //printk ("Could not copy from user mode memory\n");
        }
    }
  else
    {

      memcpy (dst, src, len);
    }
}


/*****************************************************************
* Copy data out to application buffer.
*
*
* userland
*    TRUE if application buffer is in user space.
*
* dst
*    Pointer to application buffer.
*
* src
*    Pointer to kernel buffer.
*
* len
*    Length of data to copy (in bytes).
*
*
* return value
*    void
******************************************************************/
void
osal_copy_to_app (int userland, void *dst, void *src, int len)
{
  if (userland)
    {

      if (copy_to_user (dst, src, len))
        {
          memcpy (dst, src, len);
          //printk ("Could not copy to user mode memory\n");
        }

    }
  else
    {

      memcpy (dst, src, len);
    }
}


/******************************************************************
* Mem compare function which can handle userland memory.
*
*
* userland
*    TRUE if appl_buf is in user space.
*
* appl_buf
*    Pointer to application data buffer to compare.
*
* kernel_buf
*    Pointer to kernel data buffer to compare.
*
* len
*    Length of data to compare (in bytes).
*
*
* return value
*    Same as standard memcmp() routine.
*******************************************************************/
int
slad_memcmp_user (int userland, void *appl_buf, void *kernel_buf, int len)
{
  BYTE *tbuf = NULL;
  int r = 0;

  /* If appl_buf is in user-space, copy it into a temporary allocated buffer. */
  if (userland)
    {
      tbuf = osal_malloc (len);
      if (tbuf != NULL)
        {
        if (copy_from_user (tbuf, appl_buf, len) == 0)
          {
      appl_buf = tbuf;
    }
        else
          {
            //Could not copy from user mode memory
            appl_buf = NULL;
          }
        }
      else
        {
          appl_buf = NULL;
        }
    }

  /* If no problems above, do the standard memcmp. */
  if ((appl_buf != NULL) && (kernel_buf != NULL))
    {
      r = memcmp (appl_buf, kernel_buf, len);
    }

  /* Free the temp buffer, if it was allocated. */
  if (tbuf != NULL)
    {
      osal_free (tbuf, len);
    }

  return r;
}


/*******************************************************************
* Allocate continuous locked memory block, which is capable of
later being converted
* to a physical address if required. The allocated memory is
also zeroed by this routine.
*
*
* n
*    Size of memory block, in bytes.
*
*
* return value
*    Pointer to allocated memory block.
*******************************************************************
*********************************/

void *
osal_malloc (int n)
{
  void *p;
  p = kmalloc (n, (in_interrupt ()? GFP_ATOMIC : GFP_KERNEL) | GFP_DMA);

  if (p)
    {
      /* Init the allocated memory. */
      memset (p, 0, n);
    }

  return p;

}

void *
osal_malloc_cache_aligned (int n)
{
  void *p_actual, *p_aligned = NULL;
  int len_actual;

  len_actual = n;

  if (len_actual % L1_CACHE_BYTES)
    len_actual =
      (len_actual / L1_CACHE_BYTES) * L1_CACHE_BYTES + L1_CACHE_BYTES;

  len_actual += L1_CACHE_BYTES + sizeof (p_actual);

  p_actual =
    kmalloc (len_actual,
             (in_interrupt ()? GFP_ATOMIC : GFP_KERNEL) | GFP_DMA);

  if (p_actual)
    {
      memset (p_actual, 0, len_actual);

      p_aligned =
        (UINT32 *) L1_CACHE_ALIGN ((UINT32) p_actual + sizeof (p_actual));
      *((UINT32 *) ((UINT32) p_aligned - sizeof (p_actual))) =
        (UINT32) p_actual;


    }

  return p_aligned;

}


/*********************************************************************
* Free a memory block previously allocated by slad_alloc().
*
*
* p
*    Pointer to memory block.
*
* n
*    Size of memory block, in bytes.    (Ignored with this platform.)
*
*
* return value
*    void.
**********************************************************************/
void
osal_free (void *p, int n)
{
  if (p)
    kfree (p);
}

void
osal_free_cache_aligned (void *p, int n)
{
  void *p_actual;

  if (p)
    {
      p_actual = (UINT32 *) * ((UINT32 *)
        ((UINT32) p - sizeof (p_actual)));
      //osal_printf("\nfree: p_actual: %p  \n", p_actual );

      kfree (p_actual);

    }
}



/*************************************************************
* Lock or Allocate a DMA buffer
*
*
* userland
*    TRUE if user buffer (buf) is in user space.
*
* device
*    Pointer to SLAD_DEVICE structure for specified device.
*
* dma
*    Pointer to SLAD_DMA_OBJ structure to be filled in.
*
* buf
*    Buffer to attempt to lock. If this buffer can not be locked
*    in place, a bounce buffer will be allocated instead.
*    If NULL, no lock will be attempted, and a DMA buffer
*    will simply be allocated.
*
* len
*    Size of DMA buffer to lock or allocate, in bytes.
*
* copy_flag
*    If TRUE and a bounce buffer is allocated, the contents of buf
*    will be copied to the bounce buffer after it is allocated.
*    If FALSE and a bounce buffer is allocated, the buffer will be zeroed.
*
*
* return value
*    Virtual address of the DMA buffer, or NULL if failure.
*******************************************************************/

#if 0
void *
osal_dma_lock (int userland, SLAD_DMA_OBJ * dma, void *buf,
               int len, int copy_flag)
{
  /* Prevent double-locking. */
  if (dma->locked)
    {

      osal_debug_printf ("osal_dma_lock(); previously locked!\n");
      osal_dma_unlock (dma, 0);
    }

  dma->userland = userland;
  dma->user_addr = buf;
  dma->allocated = FALSE;
  dma->get_pages_order = 0;


  dma->pdevice = NULL;


  /* Has user supplied a buffer? */
  if (buf)
    {

#ifdef SLAD_OSAL_DO_NOT_ALLOC_BOUNCE_BUFFERS_FOR_KERNEL_MODE_BUFFERS
      /* For this case, believe that KERNEL-MODE buffer is already DMA-SAFE,
         but user must ensure that it is indeed DMA-SAFE */

      /* Bounce Buffer is anyway to be allocated for user-mode */
      if (userland)
#else
      /* Is this buffer unsuitable for DMA? */
      if (userland || (buf != (void *) L1_CACHE_ALIGN ((int) buf)))
#endif

        {
          dma->alloc_len = len + (L1_CACHE_BYTES - 1);
          dma->alloc_addr = osal_malloc (dma->alloc_len);
          if (dma->alloc_addr)
            {
              dma->virt_addr =
                (void *) L1_CACHE_ALIGN ((int) dma->alloc_addr);
              dma->allocated = TRUE;
              /* If copy flag is set,
              copy contents of user buffer to the bounce buffer. */
              if (copy_flag)
                {
                  osal_copy_from_app (userland, dma->virt_addr, buf, len);

                }
            }

        }
      else
        {
          /* Ok to use buffer as is. */
          dma->virt_addr = buf;

        }


    }
  else
    {
      /* Allocate a cache-aligned buffer. */
      //dma->alloc_len = pad + len + (L1_CACHE_BYTES - 1);
      dma->alloc_len = len + (L1_CACHE_BYTES - 1);
      dma->alloc_addr = osal_malloc (dma->alloc_len);
      if (dma->alloc_addr)
        {
          dma->virt_addr = (void *) L1_CACHE_ALIGN ((int) dma->alloc_addr);
          dma->allocated = TRUE;
        }
      else
        {
          dma->virt_addr = 0;
          dma->allocated = FALSE;
        }
    }

  /* Do we have a good DMA buffer? */
  if (dma->virt_addr)
    {

      dma->locked = TRUE;
      dma->len = len;

      /* Get the bus address of the DMA buffer. */

#define is_kernel_addr(...) 1
      if (is_kernel_addr ((unsigned long) dma->virt_addr))
        {
          dma->bus_addr = virt_to_phys (dma->virt_addr);
        }
      else
        {
          printk ("SLAD osal_dma_lock(): NON KERNEL ADDR!\n");
        }
      dma_sync_single_for_device (NULL, virt_to_bus (dma->virt_addr),
                                  dma->len, DMA_TO_DEVICE);
      //dma_map_single (NULL, dma->virt_addr, dma->len, DMA_BIDIRECTIONAL);

    }
  return dma->virt_addr;
}


/*******************************************************************
* Free a DMA buffer.
*
*
* dma
*    Pointer to SLAD_DMA_OBJ structure.
*
* copy_len
*    If a bounce buffer was allocated, this is the amount of data (in bytes)
*    to copy back from the bounce buffer to the user's buffer.
*
*
* return value
*    void
********************************************************************/


void
osal_dma_unlock (SLAD_DMA_OBJ * dma, int copy_len)
{


  if (dma->locked)
    {

      if (dma->len)
        {
          /* it make more sense to invalidate only as many as
           * D-cache lines as required no more and
           * no less. So, invalidate cache lines
           * by copy_len
           */
          if (copy_len /* && ((dma->flags & 0x1) == 0) */ )
            osal_dma_inv (*dma, dma->virt_addr, copy_len);

        }
      if (dma->allocated)
        {

          if (dma->user_addr && copy_len)
            {

              osal_copy_to_app (dma->userland, dma->user_addr, dma->virt_addr,
                                copy_len);
            }

          /* if (dma->alloc_addr != NULL) */
          //{
          osal_free (dma->alloc_addr, dma->alloc_len);
          dma->alloc_addr = NULL;
          dma->virt_addr = NULL;
          //}


          dma->allocated = FALSE;
        }


      dma->locked = FALSE;
      dma->bus_addr = (UINT32) NULL;
      dma->len = 0;
    }
}


/**********************************************************************
* Move a DMA buffer.
* This is a special purpose function to "move" the opaque contents of a
* DMA object from one location to another without freeing/locking it.
* After the move, the source DMA object will be flagged as "unlocked".
*
*
* dst
*    Pointer to destination SLAD_DMA_OBJ structure.
*
* src
*    Pointer to source SLAD_DMA_OBJ structure.
*
*
* return value
*    void
************************************************************************/
void
slad_dma_obj_move (SLAD_DMA_OBJ * dst, SLAD_DMA_OBJ * src)
{
  /* Prevent creating a locked orphan. */
  if (dst->locked)
    {
      osal_debug_printf ("slad_dma_obj_move(); dst previously locked!\n");
      osal_dma_unlock (dst, 0);
    }

  /* Copy the contents of the DMA object. */
  memcpy (dst, src, sizeof (SLAD_DMA_OBJ));

  /* The source DMA object is now duplicated in dst,
  and will be unlocked by the dst. */
  src->locked = FALSE;
}

#endif


/********************************************************************
* Create a resource.
*
*
* device
*    Pointer to SLAD_DEVICE structure for specified device.
*
*
* return value
*    Pointer to SLAD_RESOURCE object, or NULL if failed to create resource.
************************************************************************/
SLAD_RESOURCE
osal_resource_create (void)
{
  SLAD_RESOURCE rsc = NULL;

#ifdef SLAD_CONFIG_USE_SEMAPHORES
  rsc = (SLAD_RESOURCE) osal_malloc (sizeof (struct semaphore));
#else
  rsc = (SLAD_RESOURCE) osal_malloc (sizeof (spinlock_t));
#endif

  if (rsc != NULL)
    {
#ifdef SLAD_CONFIG_USE_SEMAPHORES
      init_MUTEX (rsc);
#else
      spin_lock_init (rsc);
#endif
    }

  return rsc;
}


/***********************************************************************
* Delete a resource.
*
*
* device
*    Pointer to SLAD_DEVICE structure for specified device.
*
* rsc
*    Pointer to SLAD_RESOURCE to be deleted.
*
*
* return value
*    void
***********************************************************************/
void
osal_resource_delete (SLAD_RESOURCE rsc)
{
  if (rsc != NULL)
    {
#ifdef SLAD_CONFIG_USE_SEMAPHORES
      osal_free (rsc, sizeof (struct semaphore));
#else
      osal_free (rsc, sizeof (spinlock_t));
#endif
    }
}

void *
osal_malloc_coherent (void **buf_addr, void **bus_addr, int len)
{
  void *p;
  dma_addr_t dma_addr;
  p = dma_alloc_coherent (NULL, len, &dma_addr, GFP_KERNEL | GFP_DMA);
  if (NULL == p)
    {
      printk ("\n osal_malloc_coherent failed \n");
      *buf_addr = NULL;
      return NULL;
    }
  else
    {
      *bus_addr = (void *) dma_addr;
      *buf_addr = p;
      return p;
    }
}

void
osal_free_coherent (void *v, dma_addr_t dma_addr, int len)
{
  dma_free_coherent (NULL, len, v, dma_addr);
}

void
osal_enable_engine (void)
{
  // hwpal_enable_engine ();
}

UINT32
osal_get_time (void)
{
  struct timeval t;
  do_gettimeofday (&t);
  return ((UINT32) t.tv_sec);
}

void
hwpal_enable_engine (void)
{

}


DECLARE_WAIT_QUEUE_HEAD(osal_flag_sync);

/****************************************************************************
 * Wait until flag f gets set.
 *
 * This function may only be called in a 'process context', as it sleeps.
 * It waits until the flag f is set (by a function that also calls osal_wakeup)
 * It is safe against race conditions, it does not block if f is already set.
 * It has a timeout specified in milliseconds. Implemented timeout granularity
 * is in 'jiffies'.
 *
 * Usage example:
 * f=0;
 * ... Perform actions that eventually cause the flag to be set.
 * osal_wait_flag(&f, 1000);
 * ... Test whether the flag is set, otherwise there the
 *     operation has timed out.
 *
 * f
 *    pointer to the flag to check for.
 *
 * timeout_msec
 *    timeout in milliseconds.
 */

void osal_wait_flag(int *f, unsigned int timeout_msec)
{
    wait_event_timeout(osal_flag_sync, *f, timeout_msec * HZ / 1000);
}

/****************************************************************************
 * Wake up the process that is waiting with osal_wait_flag().
 * This function can be called from interrupt context and process context.
 * This function does not itself set the flag.
 *
 * Usage example:
 * f = 1;
 * osal_wakeup();
 */

void osal_wakeup(void)
{
    wake_up( &osal_flag_sync);
}
