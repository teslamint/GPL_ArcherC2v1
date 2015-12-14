/*h*
* File:   slad_osal_kernel.h
*
* Security Look-aside Driver Module for SafeNet crypto hardware.
* Target-dependent functions and definitions for osal.
*
*

     Copyright 2007-2008 SafeNet Inc


*
* Edit History:
*
*Initial revision
* Created.
*/

#ifndef __SLAD_TARGET_H__
#define __SLAD_TARGET_H__


#include "os_config.h"


#ifdef SLAD_ALLOW_BIG_ALLOC
#ifndef SLAD_MAX_KMALLOC
/* max no bytes to alloc using kmalloc 
--- use dma_get_pages() if request is greater */
#define SLAD_MAX_KMALLOC (64*1024)
#endif
#endif


/*************************************************************
* Definitions and macros.
**************************************************************/

struct device_map
{
  struct device_map *next;
  UINT32 device_type;
  UINT32 deviceId;
  UINT32 deviceinfo;
  UINT32 base_addr_hw_rd;
  BYTE *base_addr_rd;
  UINT32 base_addr_hw_wr;
  BYTE *base_addr_wr;
  int int_line;
};

struct device_map_head
{
  struct device_map *list;
};

#ifdef SLAD_INSTRUMENT_PE_IRQ
extern unsigned long slad_pe_irq_cnt;
extern unsigned long slad_pe_irq_type;
#endif
extern struct device_map_head device_map_vec;
void add_device_to_list (struct device_map *d);




#define DATA_TYPE_SA 1
#define DMA_DATA_TYPE_NO_CACHE 2


#include "osal_common_defs.h"

/*
typedef struct
{
  UINT32 process_id;
  UINT32 signal_number;
  void (*callback) (int device_num);
}
OSAL_NOTIFY;

*/


typedef struct _interrupt_block
{
  void *dev_handle;
  int int_line;
  SLAD_PLATFORM_PARAMS platform_params; 
  /* platform-dependent parameters for this device */
  int (*callback) (struct _interrupt_block * intblk);
  void (*slad_isr_common_bottom) (void *dev_handle, UINT32 int_status);
} INTBLK;

typedef struct _osal_init_operations
{
  void (*slad_commad_parser) (void *buff);

} osal_init_operations;

extern osal_init_operations slad_init_op;

#define SLAD_LINUX_KERNEL_MODULE 1
#ifdef SLAD_LINUX_KERNEL_MODULE
#define osal_main(arg) osal_init_driver(arg)
#else
#define osal_main(arg) main(arg)

int osal_init_driver (void);
#endif


#define  osal_memory_barrier_write() wmb();
#define  osal_memory_barrier() mb();

int osal_init_driver (void);
void osal_resource_lock (SLAD_PLATFORM_PARAMS * platform_params_p,
                         SLAD_RESOURCE rsc);
void osal_resource_unlock (SLAD_PLATFORM_PARAMS * platform_params_p,
                           SLAD_RESOURCE rsc);

void osal_yield_kernel (void);




#define osal_ioremap_nocache( paddr, size  )  ioremap_nocache( paddr, size )
#define osal_iounmap(vaddr )  iounmap( vaddr )

/* Not required for this platform. */
#define slad_check_module_init()

// Log Module
#ifdef SLAD_TEST_APP_ENABLE_INFO_LOGS
#define LOG_SEVERITY_MAX LOG_SEVERITY_INFO
#else
#define LOG_SEVERITY_MAX LOG_SEVERITY_WARNING
#endif

#include "log.h"

//void osal_printf (char *s, ...);
#ifdef SLAD_DEBUG_DRIVER_MESSAGES
#define osal_debug_printf osal_printf
#else
#define osal_debug_printf(...)
#endif
/* We do not have the luxery of "C" library in kernel, but some of the
   frequently used functions are implemented in most of the kernels.
   But it still depend on the host kernel.
*/
//void osal_memset (void *buff, int val, size_t size);
#define osal_memset(buff,val,len) memset(buff,val,len)
// void osal_bzero(void * buf,size_t len);
#define osal_bzero(buff,len) memset(buff,0,len)
// void osal_swap_endian( void *dstbuf, void *srcbuf, size_t no_of_words);
UINT32 osal_swap_endian (UINT32 data);

void osal_notify (int device_num, OSAL_NOTIFY * notify);
//void osal_write32 (UINT32 data, void * addr);
//UINT32 osal_read32 (void * addr);
#define osal_write32(data, addr)  iowrite32(data,addr)
#define osal_read32(addr)  ioread32(addr)
#define osal_put_user(datum, ptr) put_user(datum,ptr)
#define osal_get_user(datum,ptr) get_user(datum,ptr)
#define osal_target_sleep(n)


int osal_interrupt_install (INTBLK * intblk);
void osal_interrupt_remove (INTBLK * intblk);
int osal_schedule_bottom_half (INTBLK * intblk);

int slad_register_device (void);

void osal_delay (int d);

void osal_copy_from_app (int userland, void *dst, void *src, int len);
void osal_copy_to_app (int userland, void *dst, void *src, int len);

int slad_memcmp_user (int userland, void *appl_buf, void *kernel_buf,
                      int len);
void *osal_malloc (int n);

void *osal_malloc_cache_aligned (int n);

void osal_free_cache_aligned (void *p, int n);



void osal_free (void *p, int n);
SLAD_RESOURCE osal_resource_create (void);
void osal_resource_delete (SLAD_RESOURCE rsc);



void *osal_malloc_coherent (void **buf_addr, void **bus_addr, int len);
void osal_free_coherent (void *v, dma_addr_t dma_addr, int len);


/////
#define slad_osal_get_pid() 0
#undef SLAD_OSAL_IS_IN_USER_MODE
#define slad_osal_user_signal() 0

#define slad_osal_watchdog()
#define slad_osal_install_notifier(fn)

UINT32 osal_get_time (void);




#endif /* __SLAD_TARGET_H__ */
