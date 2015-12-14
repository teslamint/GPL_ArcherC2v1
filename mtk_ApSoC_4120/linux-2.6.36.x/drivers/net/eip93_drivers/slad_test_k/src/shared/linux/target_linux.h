/*h*
* File:  target_linux.h
*
* Security Look-aside Driver Module for SafeNet crypto hardware.
* Target-dependent functions and definitions for Linux.
*
*

     Copyright 2007-2008 SafeNet Inc

*
* Edit History:
*
*Initial revision
*    Created.
*/
#ifndef __TARGET_LINUX__
#define __TARGET_LINUX__

#include "c_sladtestapp.h"
#ifdef MODULE

#include <linux/kernel.h>
#include <linux/pci.h>
#include <linux/interrupt.h>
#include <asm/uaccess.h>


#ifndef KERNEL_VERSION
#define KERNEL_VERSION(a,b,c)        (((a) << 16) + ((b) << 8) + (c))
#endif

#if !defined (SLAD_CONFIG_DONT_ALLOW_WORKQUEUES)
#define SLAD_USE_WORKQUEUES    1
#include <linux/workqueue.h>
#elif !defined (SLAD_CONFIG_DONT_ALLOW_TASKLETS)
#define SLAD_USE_TASKLETS    1
#else
#error Old bottom halves not allowed in 2.6 kernel. Use workqueues or tasklets.
#endif


#define SLAD_EXPORT_SYMBOL(symbol) EXPORT_SYMBOL(symbol)

typedef wait_queue_head_t WAIT_QUEUE_HEAD_T;
typedef struct timer_list WATCH_DOG_T;
typedef void (*watch_dog_callback) (unsigned long data);




typedef struct
{
  struct device pdev;
  volatile UINT32 int_status;
  spinlock_t int_lock;
#if defined (SLAD_USE_WORKQUEUES)
  struct work_struct wq_work;   /* still newer workqueue method */
#elif defined (SLAD_USE_TASKLETS)
  struct tasklet_struct bh_tasklet;     /* newer tasklet method */
#else
  struct tq_struct tqs;         /* old bottom half method */
#endif
}
SLAD_PLATFORM_PARAMS;

#ifdef SLAD_CONFIG_USE_SEMAPHORES
typedef struct semaphore *SLAD_RESOURCE;
#else
typedef spinlock_t *SLAD_RESOURCE;
#endif

int poll_plb_devices (void);

#endif /* MODULE */

#ifndef SLAD_TEST_DEFS_ONLY_FROM_SLAD_API_INTERFACE_FOLDER
// V-Driver filler defs
typedef void *SLAD_RESOURCE;



typedef struct
{

  int filler;
  volatile UINT32 int_status;
}
SLAD_PLATFORM_PARAMS;
#define SLAD_EXPORT_SYMBOL(...)

#endif // SLAD_TEST_DEFS_ONLY_FROM_SLAD_API_INTERFACE_FOLDER



int poll_plb_devices (void);

// end V-driver filler defs
#ifndef SLAD_TEST_DEFS_ONLY_FROM_SLAD_API_INTERFACE_FOLDER
typedef unsigned int slad_bus_addr;
#endif

#ifndef SLAD_TEST_DEFS_ONLY_FROM_SLAD_API_INTERFACE_FOLDER
struct _SLAD_DMA_OBJ
{

  struct device *pdevice;
  int userland;
  int locked;
  int allocated;
  void *user_addr;
  void *alloc_addr;
  int alloc_len;
  void *virt_addr;
  UINT32 bus_addr;
  int len;
  UINT32 get_pages_order;       
  /* 0 if locked by kmalloc() else order arg if locked by __get_dma_pages() */
  UINT32 dma_data_type;
  int flags;
};
typedef struct _SLAD_DMA_OBJ SLAD_DMA_OBJ;
//typedef struct _SLAD_DMA_OBJ slad_sa_handle;
typedef struct _SLAD_SA_HANDLE
{
  int magic;
  int gather_flag;
  int scatter_flag;
  SLAD_DMA_OBJ sa_dma_obj;
  SLAD_DMA_OBJ srec_dma_obj;

#if 0
  int is_sa_safe_for_pe_caching;
#endif

} slad_sa_handle;
typedef slad_sa_handle *sa_handle;

typedef struct _SLAD_DMA_OBJ slad_buff_handle;
typedef slad_buff_handle *buff_handle;

#endif // SLAD_TEST_DEFS_ONLY_FROM_SLAD_API_INTERFACE_FOLDER

#endif /* __TARGET_LINUX__ */
