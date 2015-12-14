/*
 * linux_pcihw.c
 *
 * Author: Markus Stenberg <mstenber@ssh.com>
 *
 *  Copyright:
 *          Copyright (c) 2002, 2003 SFNT Finland Oy.
 *       All rights reserved
 *
 * Created:       Tue Feb 20 09:20:18 2001 mstenber
 * Last modified: Fri Apr  5 09:27:44 2002 mstenber
 * 
 *
 */

#include <linux/slab.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/errno.h>
#include <linux/pci.h>
#include <linux/init.h>
#include <linux/delay.h>
#include <linux/interrupt.h>
#include <asm/irq.h>
#include <linux/ioport.h>
#include <asm/io.h>
#include <asm/bitops.h>

#define SSH_DEBUG_MODULE "SshIpsecInterceptorLinuxPciHw"

#define SSH_ALLOW_CPLUSPLUS_KEYWORDS
#define SSH_ALLOW_MS_VISUAL_C_KEYWORDS

#ifndef STANDALONE_TEST

#include "sshincludes.h"
#include "kernel_mutex.h"
#include "linux_internal.h"
#include "linux_mutex_internal.h"
#include "linux_versions.h"

#else








#endif /* STANDALONE_TEST */

#include "sshpcihw.h"

/********************************************** simple-freelist-abstraction  */

#define SSH_USE_SIMPLE_FREELIST





#ifndef __GNUC__
#undef SSH_USE_SIMPLE_FREELIST
#endif /* !__GNUC__ */

#ifndef ADDSTAT
#define ADDSTAT(prefix)
#endif /* !ADDSTAT */


#ifdef SSH_USE_SIMPLE_FREELIST


/* #if 0 */

/* This is simple-freelist abstraction which uses void pointers to keep
   track of data fields. Many of the speed-critical functions could be
   also written as macros, but for now inlined functions are sufficient.

   This is GCC-only code. If porting to other platform, the whole
   thing should be rewritten as macros, which is not fun.

   Therefore the code is only enabled when using GCC.

   This should find a better home, as well.. header file is not
   neccessarily 'the place' for it.
*/

/* Allocate new simple-freelist. */
static inline Boolean
ssh_sf_allocate(void **head, SshPciHwMutex *mutex)
{
  *head = NULL;
  *mutex = ssh_pcihw_mutex_alloc();
  return *mutex != NULL;
}

static inline void
ssh_sf_free(void *head, SshPciHwMutex mutex)
{
  void *next;
  while (head)
    {
      next = *((void **)head);
      ssh_free(head);
      head = next;
    }
  ssh_pcihw_mutex_free(mutex);
}

static inline void *
ssh_sf_pop(void **head, SshPciHwMutex mutex, int size, Boolean locked)
{
  void *r;







  if (!locked) ssh_pcihw_mutex_lock(mutex);
  r = *head;
  if (r)
    {
      *head = *((void **)r);
      ADDSTAT(fastmalloc);
      if (!locked) ssh_pcihw_mutex_unlock(mutex);
    }
  else
    {
      if (!locked) ssh_pcihw_mutex_unlock(mutex);
      r = ssh_malloc(size);
    }

  return r;
}

static inline void
ssh_sf_push(void **head, SshPciHwMutex mutex, void *v, Boolean locked)
{
  SSH_ASSERT(v != NULL);

  if (!locked) ssh_pcihw_mutex_lock(mutex);
  *((void **)v) = *head;
  *head = v;
  if (!locked) ssh_pcihw_mutex_unlock(mutex);
}

#define SSH_SF_DEF(prefix) \
static void *prefix##_head; \
static SshPciHwMutex prefix##_mutex;

#define SSH_SF_INIT(prefix) ssh_sf_allocate(&prefix##_head, &prefix##_mutex)

#define SSH_SF_UNINIT(prefix) ssh_sf_free(prefix##_head, prefix##_mutex)

#define SSH_SF_ALLOC(prefix,size,locked) \
 ssh_sf_pop(&prefix##_head, prefix##_mutex, size, locked)

#define SSH_SF_FREE(prefix, value,locked) \
 ssh_sf_push(&prefix##_head, prefix##_mutex, value, locked)

#else /* !SSH_USE_SIMPLE_FREELIST */

#define SSH_SF_INIT(prefix) TRUE
#define SSH_SF_UNINIT(prefix)
#define SSH_SF_ALLOC(prefix, size, locked) ssh_malloc(size)
#define SSH_SF_FREE(prefix, value, locked) ssh_free(value)
#define SSH_SF_DEF(prefix)

#endif /* SSH_USE_SIMPLE_FREELIST */

/* Implementation of Linux version of PciHw API.

   This is mainly a proof of concept code to verify
   that it is indeed possible to do this with
   reasonable effort. */

#define NUM_MEMORY_BLOCKS 4


struct SshPciHwDeviceRec {
  SshPciHwContext context;

  struct pci_dev *pdev;

  const unsigned char *reserved_by; /* NULL by default. */

  /* irq is 0 if it hasn't been set callback yet. */
  SshUInt8 irq;
  SshPciHwInterruptCallback irq_cb;
  void *irq_cb_context;

  void *mapped_memory[NUM_MEMORY_BLOCKS];
  SshUInt8 num_mapped_memory;

  SshUInt32 reserved_memory[NUM_MEMORY_BLOCKS][2]; /* addr, len pairs. */
  SshUInt8 num_reserved_memory;



  SshPciHwDevice next; /* next in the pcihwcontext. */
};

struct SshPciHwContextRec {
  SshPciHwDevice first_device;
};

Boolean ssh_pcihw_device_reserve(SshPciHwDevice dev,
                                 const unsigned char *drivername)
{
  if (dev->reserved_by) return FALSE;
  dev->reserved_by = drivername;
  return TRUE;
}

void ssh_pcihw_device_release(SshPciHwDevice dev)
{
  int i;

  if (!dev->reserved_by) return;

  /* NOTE: this should be called with some form of lock held to
     prevent interrupts from happening during release (BAD). */

  /* Release the IRQ. */
  if (dev->irq)
    {
      free_irq(dev->irq, (void *)dev);
      dev->irq = 0;
    }

  /* Free the mapped memory. */
  for (i = 0 ; i < dev->num_mapped_memory ; i++)
    iounmap(dev->mapped_memory[i]);
  dev->num_mapped_memory = 0;

  /* Free the memory regions. */
  for (i = 0 ; i < dev->num_reserved_memory ; i++)
    release_mem_region(dev->reserved_memory[i][0],
                       dev->reserved_memory[i][1]);
  dev->num_reserved_memory = 0;

  SSH_ASSERT(dev->reserved_by != NULL);
  dev->reserved_by = NULL;

}

void ssh_pcihw_device_set_busmaster(SshPciHwDevice dev)
{
  pci_set_master(dev->pdev);
}

/* Individual PCI devices' content is platform dependant. However,
   following accessor functions are available. */
void ssh_pcihw_device_get_id(SshPciHwDevice dev,
                             SshUInt16 *vendor_id,
                             SshUInt16 *device_id,
                             SshUInt8 *rev_id)
{
  *vendor_id = dev->pdev->vendor;
  *device_id = dev->pdev->device;
  pci_read_config_byte(dev->pdev, PCI_REVISION_ID, rev_id);
}

void ssh_pcihw_device_get_irq(SshPciHwDevice dev,
                              SshUInt8 *irq)
{
  *irq = dev->pdev->irq;
}

void ssh_pcihw_device_get_resource(SshPciHwDevice dev,
                                   SshUInt32 idx,
                                   SshUInt32 *resource_start,
                                   SshUInt32 *resource_len)
{
  *resource_start = pci_resource_start(dev->pdev, idx);
  *resource_len = pci_resource_len(dev->pdev, idx);
}

Boolean
request_mem_region_compatible(SshUInt32 mem_start,
                              SshUInt32 mem_len,
                              const unsigned char *reserved_by)
{
  return request_mem_region(mem_start, mem_len, reserved_by) != NULL;
}

/* Resource allocation. */
Boolean
ssh_pcihw_device_assign_phys_mem(SshPciHwDevice dev,
                                 SshUInt32 mem_start,
                                 SshUInt32 mem_len)
{
  int i = dev->num_reserved_memory;

  SSH_ASSERT(dev->reserved_by != NULL);
  if (i >= NUM_MEMORY_BLOCKS)
    {
      SSH_DEBUG(SSH_D_ERROR, ("out of memory blocks."));
      return FALSE;
    }
  if (!request_mem_region_compatible(mem_start,
                          mem_len,
                          dev->reserved_by))
    {
      SSH_DEBUG(SSH_D_ERROR, ("region not available: %x[%x]",
                              mem_start, mem_len));
      return FALSE;
    }
  dev->reserved_memory[i][0] = mem_start;
  dev->reserved_memory[i][1] = mem_len;
  dev->num_reserved_memory++;
  return TRUE;
}

void *
ssh_pcihw_device_map_phys(SshPciHwDevice dev,
                          SshUInt32 address,
                          SshUInt32 len)
{
  int i = dev->num_mapped_memory;
  void *p;
  
  SSH_ASSERT(dev->reserved_by != NULL);
  if (i >= NUM_MEMORY_BLOCKS)
    {
      SSH_DEBUG(SSH_D_ERROR, ("out of memory blocks."));
      return NULL;
    }
  p = ioremap_nocache(address, len);
  if (!p)
    {
      /* If ioremap_nocache() fails, it is propably because
         get_vm_area() has hit the VMALLOC_END boundary, or cannot
         find a block big enough in the highest 1GB of the 32bit
         address space, i.e.  the kernel address space. You must
         increase the size of the VMALLOC_RESERVE from 128 to 192 in
         include/asm-i386/page.h.

         If you have more than 960KB of physical memory, your Linux
         2.4 kernel configuration is most likely incorrect. You should
         have the Linux kernel "High Memory Support"
         enabled. (CONFIG_HIGHMEM). See menuconfig help in "Processor
         type and features"--->"High Memory Support" for more details.
         Also check /proc/meminfo if the system successfully detected
         the high memory. */
      SSH_DEBUG(SSH_D_ERROR, ("Unable to ioremap_nocache address "
                              "%p [size=%d%s]. You must add VMALLOC_RESERVE.",
                              address, 
                              (len > 1024*1024) ? len/1024/1024 : len/1024,
                              (len > 1024*1024) ? "M" : "K"));
      return NULL;
    }
  dev->mapped_memory[i] = p;
  dev->num_mapped_memory++;
  return p;
}

typedef struct {
  struct tasklet_struct task;
  SshPciHwSoftCallback callback;
  void *callback_ctx;
  SshUInt32 extra;
} *SshPciHwDeviceSoftContext;

SSH_SF_DEF(softcontext_freelist);

static void interrupt_wrapper_bh(unsigned long arg)
{
  void *ctx = (void *) arg;
  SshPciHwDeviceSoftContext context = (SshPciHwDeviceSoftContext) ctx;

  local_bh_disable();

  /* printk(" .. wrapper-bh ..\n"); */
  context->callback(context->callback_ctx, context->extra);
  SSH_SF_FREE(softcontext_freelist, context, FALSE);

#ifndef STANDALONE_TEST
  ssh_linux_module_dec_use_count();
#endif /* STANDALONE_TEST */

  local_bh_enable();
}

Boolean ssh_pcihw_schedule(SshPciHwSoftCallback callback,
                           void *callback_ctx, SshUInt32 extra)

{
  SshPciHwDeviceSoftContext ctx;

  ctx = SSH_SF_ALLOC(softcontext_freelist, sizeof(*ctx), FALSE);
  SSH_VERIFY(ctx != NULL);
  ctx->callback = callback;
  ctx->callback_ctx = callback_ctx;
  ctx->extra = extra;

  /* let's _hope_ the code doesn't do rampant queueing, because
   we do not guard against it (yet - hifn seems like sensible chip). */
#ifndef STANDALONE_TEST
  ssh_linux_module_inc_use_count();
#endif /* STANDALONE_TEST */

  memset(&ctx->task, 0, sizeof(ctx->task));

  ctx->task.func = interrupt_wrapper_bh;
  ctx->task.data = (unsigned long) ctx;

  tasklet_schedule(&ctx->task);

  /* printk(" .. schedule-bh ..\n"); */
  return TRUE;
}

#ifndef LINUX_HAS_IRQRETURN_T_ENUM
#ifndef IRQ_HANDLED
typedef void irqreturn_t;
#define IRQ_NONE
#define IRQ_HANDLED
#endif /* IRQ_HANDLED */
#endif /* !LINUX_HAS_IRQRETURN_T_ENUM */

#ifdef LINUX_HAS_IRQ_RETURN_T
static irqreturn_t interrupt_wrapper(int irq,
				     void *ctx)
#else /* LINUX_HAS_IRQ_RETURN_T */
static irqreturn_t interrupt_wrapper(int irq,
				     void *ctx,
				     struct pt_regs *regs)
#endif /* LINUX_HAS_IRQ_RETURN_T */
{
  SshPciHwDevice dev = (SshPciHwDevice)ctx;
  if (!(irq > 0 && irq < NR_IRQS)) return IRQ_NONE;
  if (irq != dev->irq)
    {
      SSH_DEBUG(SSH_D_ERROR, ("invalid interrupt received."));
      return IRQ_NONE;
    }
  /* printk(" .. wrapped interrupt ..\n"); */
  dev->irq_cb(irq, dev->irq_cb_context);

  return IRQ_HANDLED;
}

Boolean
ssh_pcihw_device_assign_irq(SshPciHwDevice dev,
                            SshUInt8 irq,
                            SshPciHwInterruptCallback cb,
                            void *cb_context)
{
  Boolean success;

  SSH_VERIFY(dev->irq == 0);
  SSH_ASSERT(dev->reserved_by != NULL);

  dev->irq = irq;
  dev->irq_cb = cb;
  dev->irq_cb_context = cb_context;

#ifndef IRQF_SHARED
#ifdef SA_SHIRQ
#define IRQF_SHARED SA_SHIRQ
#endif /* SA_SHIRQ */
#endif /* IRQF_SHARED */

  success = !request_irq(irq,
                         interrupt_wrapper,
                         IRQF_SHARED,
                         dev->reserved_by,
                         (void *)dev);

  if (!success)
    dev->irq = 0; /* mark the device free. */
  return success;
}

/* Accessors for the PCI config block. */

SshUInt16
ssh_pcihw_device_config_get_word(SshPciHwDevice dev,
                                 SshUInt16 ofs)
{
  SshUInt16 word=0;

  pci_read_config_word(dev->pdev, ofs, &word);
  return word;
}

void
ssh_pcihw_device_config_set_word(SshPciHwDevice dev,
                                 SshUInt16 ofs,
                                 SshUInt16 word)
{
  pci_write_config_word(dev->pdev, ofs, word);
}

SshUInt8
ssh_pcihw_device_config_get_byte(SshPciHwDevice dev,
                                 SshUInt16 ofs)
{
  SshUInt8 byte=0;

  pci_read_config_byte(dev->pdev, ofs, &byte);
  return byte;
}

void
ssh_pcihw_device_config_set_byte(SshPciHwDevice dev,
                                 SshUInt16 ofs,
                                 SshUInt8 byte)
{
  pci_write_config_byte(dev->pdev, ofs, byte);
}

/************************************************************** PciHwContext */

/* Global PCI hardware context initialization/uninitialization. This
   can be used for storing the intermediate SshPciHwDevice structures,
   or other bookkeeping depending on the operation system involved. */
SshPciHwContext ssh_pcihw_init(void)
{
  SshPciHwContext ctx;
  SshPciHwDevice dev;

  struct pci_dev *pdev = NULL;

  if (!SSH_SF_INIT(softcontext_freelist))
    return NULL;
  ctx = ssh_calloc(1, sizeof(*ctx));
  if (!ctx) return NULL;
  /* main structure has been created. now, we iterate through all
     pci devices in system and create respective SshPciHwDevice
     structures. */
  while ((pdev = pci_get_subsys(PCI_ANY_ID,
                                 PCI_ANY_ID,
                                 PCI_ANY_ID,
                                 PCI_ANY_ID,
                                 pdev)))
    {
      /* Create device and push it to the device list. */
      dev = ssh_calloc(1, sizeof(*dev));
      if (!dev)
        {
          ssh_pcihw_uninit(ctx);
          return NULL;
        }

      dev->context = ctx;
      dev->pdev = pdev;

      /* Add to device list. */
      dev->next = ctx->first_device;
      ctx->first_device = dev;

      /* printk("created - %p-%p\n", dev, pdev); */

    }
#if 1
  /* Check that iteration is not broken. */
  ssh_pcihw_enumerate(ctx, SSH_PCIHW_CLASS_ANY, NULL_FNPTR, NULL);
#endif
  return ctx;
}

void ssh_pcihw_uninit(SshPciHwContext ctx)
{
  SshPciHwDevice dev, next;

  if (!ctx) return;
  while ((dev=ctx->first_device))
    {
      next = dev->next;
      ssh_pcihw_device_release(dev);
      ssh_free(dev);
      ctx->first_device = next;
    }
  ssh_free(ctx);
  SSH_SF_UNINIT(softcontext_freelist);
}

/* PCI device enumeration code.

   It will call the provided callback once for each found device, and
   it will stop when it either runs out of devices or the callback
   returns FALSE.
*/
void
ssh_pcihw_enumerate(SshPciHwContext ctx,
                    SshPciHwClass class,
                    SshPciHwEnumerateFunction callback,
                    void *callback_context)
{
  SshPciHwDevice dev;

  SSH_ASSERT(ctx != NULL);
  for (dev = ctx->first_device ; dev ; dev = dev->next)
    {
      SSH_ASSERT(dev->pdev != NULL);

      /* printk("test-iter-%p-%p-%x(%x)\n", dev, dev->pdev,
         class, dev->pdev->class); */

      if (class != SSH_PCIHW_CLASS_ANY &&
          (class << 8) != dev->pdev->class)
        continue;
      if (dev->reserved_by)
        continue;
      if (!callback)
        continue;
      if (!callback(dev, callback_context))
        return; /* no further callbacks desired. */
    }
}


/*********************************************************** General utility */

SshUInt32 ssh_pcihw_virt_to_phys(void *pointer)
{
  return virt_to_phys(pointer);
}

void *ssh_pcihw_phys_to_virt(SshUInt32 address)
{
  return phys_to_virt(address);
}

SshUInt32 ssh_pcihw_get_long(void *pointer)
{
  SshUInt32 v = readl(pointer);

#ifdef STANDALONE_TEST
#if 0

  if (v)
    printk(" %p == %x\n", pointer, v);
#endif /* 0 */
#endif /* STANDALONE_TEST */
  return v;
}

void ssh_pcihw_set_long(void *pointer, SshUInt32 value)
{
#ifdef STANDALONE_TEST
#if 0
  if (ssh_pcihw_get_long(pointer) != value)
    printk(" %p = %x\n", pointer, value);
#endif /* 0 */
#endif /* STANDALONE_TEST */
  writel(value, pointer);
}

void ssh_pcihw_udelay(SshUInt32 delay)
{
  udelay(delay);
}

#ifndef STANDALONE_TEST

/********************************************************************* Mutex */

SshPciHwMutex ssh_pcihw_mutex_alloc(void)
{
  SshKernelMutex mutex = ssh_kernel_mutex_alloc();
  return (SshPciHwMutex) mutex;
}

void ssh_pcihw_mutex_free(SshPciHwMutex mutex)
{
  ssh_kernel_mutex_free((SshKernelMutex) mutex);
}

void ssh_pcihw_mutex_lock(SshPciHwMutex ctx)
{
  SshKernelMutex mutex = (SshKernelMutex) ctx;

  spin_lock_irqsave(&mutex->lock, mutex->flags);

#ifdef DEBUG_LIGHT
  SSH_ASSERT(!mutex->taken);
  mutex->taken = TRUE;
  mutex->jiffies = jiffies;
#endif
}

void ssh_pcihw_mutex_unlock(SshPciHwMutex ctx)
{
  SshKernelMutex mutex = (SshKernelMutex) ctx;

#ifdef DEBUG_LIGHT
  SSH_ASSERT(mutex->taken);
  mutex->taken = FALSE;
#endif /* DEBUG_LIGHT */
  
  spin_unlock_irqrestore(&mutex->lock, mutex->flags);
}

#endif /* STANDALONE_TEST */
