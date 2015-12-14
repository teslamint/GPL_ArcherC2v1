/*

  safenet1x41.c

  Copyright:
 	Copyright (c) 2002 - 2007 SFNT Finland Oy.
        All rights reserved.

        Integration to UDM driver for SafeXcel Chips.
*/

#ifdef KERNEL
#ifdef __linux__
#include "linux_internal.h"
#include <linux/kernel.h>
#ifdef SSH_SAFENET_AMCC_SUPPORT
#include <linux/dma-mapping.h>
#endif /* SSH_SAFENET_AMCC_SUPPORT */
#endif /* __linux__ */
#endif /* KERNEL */

#include "sshincludes.h"
#include "safenet1x41_params.h"

#include "interceptor.h"
#include "engine_hwaccel.h"
#include "kernel_alloc.h"
#include "kernel_mutex.h"
#include "kernel_encode.h"
#include "sshpcihw.h"

#ifndef KERNEL
#include "ssheloop.h"
#include "sshtimeouts.h"
#endif /* KERNEL */

#include "ip_cksum.h"
#include "sshcrypt.h"
#include "sshhash.h"
#include "sshhash_i.h"
#include "sha.h"
#include "md5.h"


#ifdef VXWORKS
#include "cacheLib.h"
#include "netLib.h"
#include "icept_internal.h"
#include "intLib.h"
#define printk printf
#endif /* VXWORKS */

#include "udm.h"
#include "cgx.h"
#include "initblk.h"

#define SSH_DEBUG_MODULE "SshSafenet1x41"

/* Important : None of the defines below should be touched. */

/* Size of the PDR descriptor ring */
#define SSH_SAFENET_NR_PDR_ENTRIES (SSH_SAFENET_MAX_QUEUED_OPERATIONS + 10)

/* Size of the CGX descriptor ring (unused) */
#define SSH_SAFENET_NR_CDR_ENTRIES 0

/* AH header length (including ICV) */
#define SSH_SAFENET_AH_HDRLEN 24

/* The amount of EMI memory on a 1841 board, 16 MB */
#define SSH_SAFENET_EMI_MEMORY (16 * 1024 * 1024)

/* The amount of EMI memory each SA requires */
#define SSH_SAFENET_SA_EMI_MEMORY (sizeof(UDM_SA))

/* The total number of SA's available in EMI memory. */
#define SSH_SAFENET_SA_EMI_SAS \
        (SSH_SAFENET_EMI_MEMORY / SSH_SAFENET_SA_EMI_MEMORY)

/* The size of the static array with each bit indicating whether the
   SA in EMI memory is currently in use. */
#define SSH_SAFENET_EMI_BYTES (SSH_SAFENET_SA_EMI_SAS / 8)

#ifndef KERNEL
#undef SSH_SAFENET_PACKET_IS_DMA
#define ssh_kernel_alloc(a,b) ssh_malloc(a)
#define ssh_kernel_free ssh_free
#define printk printf

#ifndef VXWORKS
#define ssh_kernel_timeout_register(a,b,c,d) ssh_register_timeout(NULL,a,b,c,d)
#define ssh_kernel_timeout_cancel(a,b) ssh_cancel_timeouts(a,b)
#endif /* VXWORKS */

#endif /* KERNEL */

#undef KERN_NOTICE
#define KERN_NOTICE ".. "

#ifdef SSH_SAFENET_AMCC_SUPPORT
#ifdef __linux__
/* If SSH_SAFENET_NOT_COHERENT_CACHE is defined we don't need
 *    SSH_SAFENET_SA_CACHE_ALIGN */
#if defined(SSH_SAFENET_NOT_COHERENT_CACHE)
#undef SSH_SAFENET_SA_CACHE_ALIGN
static inline void * safenet_alloc_coherent(size_t size, int flag)
{
  dma_addr_t dma_handle = 0;
  static int cnt = 0;
  return dma_alloc_coherent(NULL, size, &dma_handle, GFP_KERNEL);
}
static inline void safenet_free_coherent(void *vaddr, size_t size)
{
  dma_free_coherent(NULL,size, vaddr,0);
}

#define ssh_kernel_alloc_sa(a,b) safenet_alloc_coherent(a,b)
#define ssh_kernel_free_sa(a,b) safenet_free_coherent(a,b)

#else /*SSH_SAFENET_NOT_COHERENT_CACHE*/

#define ssh_kernel_alloc_sa(a,b) ssh_kernel_alloc(a,b)
#define ssh_kernel_free_sa(a,b) ssh_kernel_free
#endif /*SSH_SAFENET_NOT_COHERENT_CACHE*/

#else /* __linux__ */

#define ssh_kernel_alloc_sa(a,b) ssh_kernel_alloc(a,b)
#define ssh_kernel_free_sa(a,b) ssh_kernel_free

#endif /* __linux__ */
#endif /* SSH_SAFENET_AMCC_SUPPORT */













































typedef struct SshSafenetDeviceRec *SshSafenetDevice;
typedef struct SshSafenetDeviceRec SshSafenetDeviceStruct;
typedef struct SshSafenetOperationRec *SshSafenetOperation;

/* The data structure holding the device parameters */
struct SshSafenetDeviceRec {

  struct SshSafenetDeviceRec *next;

  SshKernelMutex lock;

  int device_number;

  UDM_DEVICEINFO device_info;
  UDM_NOTIFY cdr_notify;
  UDM_NOTIFY pdr_notify;

  /* The number of active sessions (HWAccel context instances)
     in this device */
  int session_count;

  /* TRUE if SA's can reside in EMI memory */
  Boolean use_emi_sa;

  /* TRUE if this device sets the 'copy_pad' field in SA's it creates. */
  Boolean copy_pad;

#ifdef SSH_SAFENET_USE_EMI_MEMORY
  /* The next SA index in EMI memory from which to search for an available SA
     in EMI memory. */
  SshUInt32 emi_word_index;

  /* A bitfield array of available SA's in EMI memory. A one indicates the
     SA is in use, zero indicates it is available. */
  unsigned char emi_sas[SSH_SAFENET_EMI_BYTES];

  /* A modified bit for EMI SA's. A one indicates the SA is in use
     or is recently deleted, zero indicates it is free. */
  unsigned char emi_sas_mod[SSH_SAFENET_EMI_BYTES];
#endif /* SSH_SAFENET_USE_EMI_MEMORY */

  SshUInt16 packet_id;
  Boolean polling;
  Boolean is_eip94c;

#ifdef VXWORKS
  /* Flag that soft irq has been scheduled for the device */
  Boolean soft_irq_pending;
#endif

#ifdef SSH_SAFENET_PROFILING
  /* how many packets have been submitted to the packet processing
     queue */
  unsigned int packets_queued;

  /* how many packets have been scheduled for completion */
  unsigned int packets_processed, packets_processed_old;

  /* amount of bytes processed since last displayed profile */
  unsigned int bytes;

  /* the rate of packets processed per second */
  unsigned int packet_rate;

  /* how many packets have been dropped */
  unsigned int packets_dropped;

  /* how many interrupts have been received for this device. */
  unsigned int interrupts_received;

  /* the number of packets notified by an per packet interrupt to be
     ready by the crypto module */
  unsigned int packets_notified;
  unsigned int packets_schedule_failed;

  /* how many session have been created, destroyed and failed */
  unsigned int sessions_created;
  unsigned int sessions_destroyed;
  unsigned int sessions_failed;
#endif /* SSH_SAFENET_PROFILING */
};

struct SshSafenetOperationRec {

  SshSafenetDevice device;
  SshHWAccel accel;

  /* Original packet */
  SshInterceptorPacket pp;

  UDM_PKT pkt;

  int bypass_offset;

  /* length of input packet */
  size_t len;
  /* header length of input packet */
  size_t hdrlen;
  /* offset of where to update the IPv6 next header field */
  size_t ipsec_offset_prevnh;

  unsigned char *packet;

  SshUInt8 ah_esp; /* 1 if doing a combined AH ESP operation */
  SshUInt8 esp;    /* 1 if doing an ESP operation */
  SshUInt8 ah;     /* 1 if doing an AH operation */

  /* notify callback for completion of the operation. */
  SshHWAccelCompletion completion;
  void *completion_context;

  void *original_src;
};

#define ROUNDUP4(val)  (((val) + 3) & 0xfffffffc)
#define ROUNDUP8(val)  (((val) + 7) & 0xfffffff8)
#define ROUNDUP16(val) (((val) + 15)& 0xfffffff0)

typedef struct HwAccelTransformRec {
  /* This is NULL if the SA does not reside in EMI memory. */
  VPTR emi_sa;
  /* The SA index in EMI memory, unused if the SA is in host memory. */
  SshUInt32 emi_sa_index;

  /* The host memory SA and State Record, these are not used if the
     SA resides in EMI memory. */
  UDM_SA *sa;
  UDM_STATE_RECORD *srec;
#ifdef SSH_SAFENET_AMCC_SUPPORT
  size_t sa_len;
#endif /* SSH_SAFENET_AMCC_SUPPORT */
} *HwAccelTransform, HwAccelTransformStruct;

struct SshHWAccelRec {

#define HWACCEL_FLAGS_ESP           0x0001
#define HWACCEL_FLAGS_AH            0x0002
#define HWACCEL_FLAGS_TUNNEL        0x0004
#define HWACCEL_FLAGS_IPV6          0x0008
#define HWACCEL_FLAGS_OUTBOUND      0x0010
#define HWACCEL_FLAGS_AES           0x0020
#define HWACCEL_FLAGS_NATT          0x0040
#define HWACCEL_FLAGS_ANTIREPLAY    0x0080
#define HWACCEL_FLAGS_DF_SET        0x0100
#define HWACCEL_FLAGS_DF_CLEAR      0x0200












  /* Flags needs to be first member of this structure since it is shared
     with SshTlsHWAccelRec */
  SshUInt16 flags;

  SshSafenetDevice device;
  SshInterceptor interceptor;

  HwAccelTransformStruct esp;
  HwAccelTransformStruct ah;

  SshKernelRWMutexStruct lock;

  unsigned char hdr[SSH_IPH6_HDRLEN];

   /* The amount of bytes (excluding ESP padding) added to the packet
     length by the outbound IPSec transform. For an inbound transform the
     packet will be reduced by this length. */
  SshUInt16 added_len;

  SshUInt16 iv_len;
};

/* global list for all Safenet devices on the PCI-bus */
#define SSH_UDM_MAX_DEVICES 2
static SshSafenetDeviceStruct devices[SSH_UDM_MAX_DEVICES];
static SshSafenetDevice safenet_devices = NULL;

#ifdef SSH_SAFENET_AMCC_SUPPORT
#ifdef SSH_SAFENET_PE_SA_CACHING
static UDM_SA* prev_sa = NULL;
#endif /* SSH_SAFENET_PE_SA_CACHING */
#endif /* SSH_SAFENET_AMCC_SUPPORT */

















/* Forward declarations */
const char *ssh_safenet_get_printable_status(int driver_status);
void ssh_safenet_setup_init_block(SshSafenetDevice device,
                                  Boolean pci_swap,
                                  INIT_BLOCK *iblk);
static void safenet_copy_key_material(unsigned char *dst,
                                      const unsigned char *src,
                                      int len);
static Boolean safenet_is_pci_swapping(SshSafenetDevice device);


static void safenet_operation_complete(SshSafenetOperation op);
static void ssh_hwaccel_perform_operation(SshSafenetOperation op);
static Boolean safenet_hwaccel_init(void);

#ifdef SAFENET_DEBUG
static void print_safenet_device_info(SshSafenetDevice device);
#endif /* SAFENET_DEBUG */

#ifdef SAFENET_DEBUG_HEAVY
static void print_safenet_pkt(UDM_PKT *pkt);
static void print_safenet_sa(UDM_SA *sa);
static void print_safenet_srec(UDM_STATE_RECORD *srec);
#endif /* SAFENET_DEBUG_HEAVY */

static SshSafenetOperation op_freelist = NULL;
static SshKernelMutex op_freelist_mutex;

static SshHWAccel accel_freelist = NULL;
static SshKernelMutex accel_freelist_mutex;

void safenet_freelist_free(void *list)
{
  void *next;

  SSH_DEBUG(SSH_D_HIGHOK, ("Entered"));

  while (list)
    {
      next = *((void **)list);
      ssh_free(list);
      list = next;
    }
}

void *safenet_freelist_alloc(int number_of, int size)
{
  void *list = NULL;
  void *item;
  int i;

  SSH_DEBUG(SSH_D_HIGHOK, ("Entered"));

  for (i = 0; i < number_of; i++)
    {
      item = ssh_calloc(1, size);
      if (!item)
        {
          safenet_freelist_free(list);
          return NULL;
        }
      *((void **)item) = list;
      list = item;
    }
  return list;
}

#define SAFENET_FREELIST_GET_NO_LOCK(item, list)        \
do                                                      \
  {                                                     \
    (item) = (void *)(list);                            \
    if (list)                                           \
      (list) = *((void **)(item));                      \
  }                                                     \
while (0)

#define SAFENET_FREELIST_GET(item, list, mutex)         \
do                                                      \
  {                                                     \
    ssh_kernel_mutex_lock(mutex);                       \
    SAFENET_FREELIST_GET_NO_LOCK(item, list);           \
    ssh_kernel_mutex_unlock(mutex);                     \
  }                                                     \
while (0)

#define SAFENET_FREELIST_PUT_NO_LOCK(item, list)        \
do                                                      \
  {                                                     \
    *((void **)(item)) = (list);                        \
    (list) = (void *)(item);                            \
  }                                                     \
while (0)

#define SAFENET_FREELIST_PUT(item, list, mutex)         \
do                                                      \
  {                                                     \
    ssh_kernel_mutex_lock(mutex);                       \
    SAFENET_FREELIST_PUT_NO_LOCK(item, list);           \
    ssh_kernel_mutex_unlock(mutex);                     \
  }                                                     \
while (0)

void safenet_operation_freelist_free()
{
  safenet_freelist_free(op_freelist);
  if (op_freelist_mutex)
    ssh_kernel_mutex_free(op_freelist_mutex);
}

Boolean safenet_operation_freelist_alloc()
{
  op_freelist_mutex = ssh_kernel_mutex_alloc();
  if (op_freelist_mutex == NULL)
    return FALSE;
  op_freelist = (struct SshSafenetOperationRec *)safenet_freelist_alloc(
    SSH_SAFENET_MAX_QUEUED_OPERATIONS, sizeof(struct SshSafenetOperationRec));
  if (op_freelist == NULL)
    {
      ssh_kernel_mutex_free(op_freelist_mutex);
      return FALSE;
    }
  else
    return TRUE;
}

#define SAFENET_OPERATION_FREELIST_GET(op) \
  SAFENET_FREELIST_GET(op, op_freelist, op_freelist_mutex)

#define SAFENET_OPERATION_FREELIST_PUT(op) \
  SAFENET_FREELIST_PUT(op, op_freelist, op_freelist_mutex)

void safenet_hwaccel_freelist_free(void)
{
  safenet_freelist_free(accel_freelist);
  if (accel_freelist_mutex)
    ssh_kernel_mutex_free(accel_freelist_mutex);
}

Boolean safenet_hwaccel_freelist_alloc(void)
{
  accel_freelist_mutex = ssh_kernel_mutex_alloc();
  if (accel_freelist_mutex == NULL)
    return FALSE;

  accel_freelist = (struct SshHWAccelRec *)safenet_freelist_alloc(
    SSH_ENGINE_MAX_TRANSFORM_CONTEXTS, sizeof(struct SshHWAccelRec));
  if (accel_freelist == NULL)
    {
      ssh_kernel_mutex_free(accel_freelist_mutex);
      return FALSE;
    }
  else
    return TRUE;
}

#define SAFENET_HWACCEL_FREELIST_GET(accel) \
  SAFENET_FREELIST_GET(accel, accel_freelist, accel_freelist_mutex)

#define SAFENET_HWACCEL_FREELIST_PUT(accel) \
  SAFENET_FREELIST_PUT(accel, accel_freelist, accel_freelist_mutex)

/************************************************************************/

#ifdef SSH_SAFENET_MIN_BYTE_SWAP
static void ssh_swap_endian_w (void * buf, size_t num_of_words)
{
   int i = 0;

   for (i = 0; i < num_of_words; i++)
   {
      st_le32( (UINT32 *)buf + i, *((UINT32 *)buf + i));
   }
}
#endif /* SSH_SAFENET_MIN_BYTE_SWAP */


/* A macro to dump a packet. */
#define SSH_DUMP_PACKET(level, str, pp)                                       \
do                                                                            \
  {                                                                           \
    size_t packet_len, len;                                                   \
    const unsigned char *seg;                                                 \
                                                                              \
    packet_len = ssh_interceptor_packet_len(pp);                              \
    SSH_DEBUG((level), ("%s (len=%ld, protocol=%d, flags=0x%lx)",             \
                        (str), (long)packet_len, pp->protocol,pp->flags));    \
    ssh_interceptor_packet_reset_iteration(pp, 0, packet_len);                \
    while (ssh_interceptor_packet_next_iteration_read(pp, &seg, &len))        \
      SSH_DEBUG_HEXDUMP((level), ("seg len %lx:", (long)len), seg,            \
                        len);                                                 \
    if (seg != NULL)                                                          \
      ssh_fatal("SSH_DUMP_PACKET freed the packet");                          \
  }                                                                           \
while (0)



/* Update the IP header and upper layer checksums after NAT-T and ESP
   transport mode decapsulation is performed. This frees 'pp' on error. */
Boolean ssh_hwaccel_natt_update_header(SshHWAccel accel,
				       SshInterceptorPacket pp, size_t hdrlen)
{
  unsigned char *ucp;
  SshUInt16 cksum;
 
  SSH_ASSERT((accel->flags & HWACCEL_FLAGS_TUNNEL) == 0);
 
  /* Update the IP header. */
  ucp = ssh_interceptor_packet_pullup(pp, hdrlen);
  if (!ucp)
    return FALSE;
 
  if (!(accel->flags & HWACCEL_FLAGS_IPV6))
    {
      SSH_IPH4_SET_CHECKSUM(ucp, 0);
      cksum = ssh_ip_cksum(ucp, hdrlen);
      SSH_IPH4_SET_CHECKSUM(ucp, cksum);
    }
 
  /* Update upper layer checksums. */
  if (!ssh_ip_cksum_packet_compute(pp, 0, hdrlen))
    {
      SSH_DEBUG(SSH_D_FAIL, ("Cannot compute checksum, dropping packet"));
      return FALSE;
    }
  pp->flags &= ~SSH_PACKET_HWCKSUM;
  return TRUE;
}

/* This function computes the offset of where to insert or remove the ESP/AH
   header and the offset of the previous (extension) header whose next
   header field should be updated after IPsec en(de)capsulation. */
Boolean
ssh_safenet_compute_ip6_hdrlen(SshInterceptorPacket pp,
			       size_t *hdrlen,
			       size_t *ipsec_offset_prevnh)
{
  size_t packet_len, offset = 0;
  size_t prev_nh_ofs;
  unsigned char buf[40];
  SshInetIPProtocolID next;

  packet_len = ssh_interceptor_packet_len(pp);

  if (SSH_IPH6_HDRLEN > packet_len)
    return FALSE;

  ssh_interceptor_packet_copyout(pp, 0, buf, 40);

  if (SSH_IPH6_VERSION(buf) != 6)
    return FALSE;
  if (SSH_IPH6_LEN(buf) + SSH_IPH6_HDRLEN != packet_len)
    return FALSE;

  prev_nh_ofs = SSH_IPH6_OFS_NH;
  offset = SSH_IPH6_HDRLEN;
  next = SSH_IPH6_NH(buf);

  /* Iterate through possible IPv6 extension headers. */
  if (next == 0)
    {
      /* Hop-by-hop extension header.  Must be first,
	 immediately after the initial IPv6 header. */
      if (offset + SSH_IP6_EXT_HOP_BY_HOP_HDRLEN > packet_len)
	return FALSE;

      ssh_interceptor_packet_copyout(pp, offset, buf, 2);

      prev_nh_ofs = offset + SSH_IP6_EXT_COMMON_OFS_NH;
      offset += SSH_IP6_EXT_COMMON_LENB(buf);
      next = SSH_IP6_EXT_COMMON_NH(buf);
    }

 next_extension_header:
 switch (next)
   {
   case 0: /* A hop-by-hop-header in the wrong place. */
     return FALSE;

   case SSH_IPPROTO_IPV6ROUTE:   /* Routing extension header. */
     if (offset + SSH_IP6_EXT_ROUTING_HDRLEN > packet_len)
       return FALSE;

     ssh_interceptor_packet_copyout(pp, offset, buf,
				    SSH_IP6_EXT_ROUTING_HDRLEN);

     prev_nh_ofs = offset + SSH_IP6_EXT_COMMON_OFS_NH;
     next = SSH_IP6_EXT_ROUTING_NH(buf);

     offset += 8 + 8 * SSH_IP6_EXT_ROUTING_LEN(buf);
     goto next_extension_header;
     break;

  case SSH_IPPROTO_IPV6OPTS: /* Destination options header. */

    if (offset + SSH_IP6_EXT_DSTOPTS_HDRLEN > packet_len)
      return FALSE;
    ssh_interceptor_packet_copyout(pp, offset, buf, 2);

    prev_nh_ofs = offset + SSH_IP6_EXT_COMMON_OFS_NH;
    offset += SSH_IP6_EXT_DSTOPTS_LENB(buf);
    next = SSH_IP6_EXT_DSTOPTS_NH(buf);
    goto next_extension_header;
    break;

  case SSH_IPPROTO_IPV6FRAG: /* Fragment header. */
    if (offset + SSH_IP6_EXT_FRAGMENT_HDRLEN > packet_len)
      return FALSE;

    ssh_interceptor_packet_copyout(pp, offset, buf,
				   SSH_IP6_EXT_FRAGMENT_HDRLEN);

    prev_nh_ofs = offset + SSH_IP6_EXT_FRAGMENT_OFS_NH;
    offset += SSH_IP6_EXT_FRAGMENT_HDRLEN;
    next = SSH_IP6_EXT_FRAGMENT_NH(buf);
    goto next_extension_header;
    break;

   case SSH_IPPROTO_AH:
   case SSH_IPPROTO_ESP:
   case SSH_IPPROTO_TCP:
   case SSH_IPPROTO_UDP:
   case SSH_IPPROTO_SCTP:
   case SSH_IPPROTO_IPV6ICMP:
   default:
     break;
   }

 *ipsec_offset_prevnh = prev_nh_ofs;
 *hdrlen = offset;
 return TRUE;
}


#ifdef SSH_SAFENET_PROFILING
/* Display the interval debug information */
void ssh_safenet_profile_timeout(void *ctx)
{
  SshSafenetDevice dev = ctx;

  if (!dev)
    {
      printk(KERN_NOTICE "no device\n");
      return;
    }

  /* Calculate the current packet rate packets/sec */
  if (SSH_SAFENET_PROFILING_RATE_SEC)
    dev->packet_rate =
      (dev->packets_processed - dev->packets_processed_old) /
      SSH_SAFENET_PROFILING_RATE_SEC;

  if (dev->packets_processed - dev->packets_processed_old > 0)
    {
      printk("Profiling from device number %d\n", dev->device_number);

      printk("PROFILE: %d pkt/s, %d Mbits/s, q=%d,n=%d,p=%d,d=%d,i=%d\n",
             dev->packet_rate,
             (8 * dev->bytes) / SSH_SAFENET_PROFILING_RATE_SEC / 1000 / 1000,
             dev->packets_queued,
             dev->packets_notified,
             dev->packets_processed,
	     dev->packets_dropped,
	     dev->interrupts_received);

      printk("PROFILE: sessions c=%d,d=%d,f=%d\n",
             dev->sessions_created,
             dev->sessions_destroyed,
	     dev->sessions_failed);
    }








  /* prepare for a new timeout */
  dev->bytes = 0;
  dev->packets_processed_old = dev->packets_processed;

  dev->packets_queued = dev->packets_notified =
    dev->packets_processed = dev->packets_processed_old =
    dev->packets_dropped = dev->interrupts_received = 0;

  ssh_kernel_timeout_register(SSH_SAFENET_PROFILING_RATE_SEC, 0,
			      ssh_safenet_profile_timeout, (void *)dev);
}
#endif /* SSH_SAFENET_PROFILING */


/* Use this to get completed operations */
void ssh_safenet_pdr_bh_cb(void *context, SshUInt32 extra)
{
  SshSafenetOperation op = NULL;
  UDM_PKT pkt[SSH_SAFENET_PDR_GET_COUNT];
  UINT32 count;
  int status, i;
  int device_num = extra;
#ifdef SSH_SAFENET_PROFILING
  Boolean first_packet = TRUE;
#endif /* SSH_SAFENET_PROFILING */

  SSH_ASSERT(extra < SSH_UDM_MAX_DEVICES);

  SSH_DEBUG(SSH_D_NICETOKNOW, ("In the safenet pdr callback from device %d",
                               device_num));

#ifdef VXWORKS
  {
    /* Reset soft irq pending flag */
    int old_lock = intLock();
    devices[device_num].soft_irq_pending = FALSE;
    intUnlock(old_lock);
  }
#endif

  while (1)
    {
      count = SSH_SAFENET_PDR_GET_COUNT;
      status = udm_pkt_get(device_num, pkt, &count);

      /* Check status is ok */
      if (status != UDM_SUCCESS)
        goto fail;

      for (i = 0; i < count; i++)
        {
          /* Get op from the user handle part of the returned packet */
          op = pkt[i].user_handle;

#ifdef SSH_SAFENET_PROFILING
          if (first_packet && context)
            {
              op->device->interrupts_received++;
              first_packet = FALSE;
            }
          op->device->packets_notified++;
#endif /* SSH_SAFENET_PROFILING */















          /* Copy the updated UDM_PKT packet structure to op */
          memcpy(&op->pkt, &pkt[i], sizeof(UDM_PKT));

          op->pkt.dst = op->pkt.src = op->original_src;

          /* Call the completion operation */
          safenet_operation_complete(op);
        }

      SSH_DEBUG(SSH_D_LOWOK, ("Got %d packets from udm_pkt_get", count));

      /* Break here since we are in the softirq context, and we don't
	 want to execute for excessively long periods. */
      if (devices[device_num].device_info.device_type != UDM_DEVICETYPE_1841 ||
	  count < SSH_SAFENET_PDR_GET_COUNT)
	break;
    }

  return;

 fail:
  SSH_DEBUG(SSH_D_FAIL, ("Cannot retrieve packets from the pdr ring"));
  return;
}


/* The UDM notify callback. */
void ssh_safenet_pdr_cb(int device_num)
{
#ifdef VXWORKS
  /* Limit number of jobs added to tNetTask work queue. It may overflow. */
  int old_lock = intLock();
  Boolean pending = devices[device_num].soft_irq_pending;
  devices[device_num].soft_irq_pending = TRUE;
  intUnlock(old_lock);
  if (pending)
    return;

  if (!ssh_pcihw_schedule(ssh_safenet_pdr_bh_cb, (void *) 1,
			  (SshUInt32)device_num))
    {





    }

#else /* VXWORKS */
  ssh_safenet_pdr_bh_cb((void *)1, (SshUInt32)device_num);
#endif /* VXWORKS */
}



/*********************************************************************/

static void safenet_operation_complete(SshSafenetOperation op)
{
  SshInterceptorPacket pp = NULL;
  SshHWAccel accel;
  UDM_PKT_BITS *pktb;
  unsigned char *ucp;
  size_t return_len, hdrlen, len;
  size_t ofs = 0;
  SshUInt8 tunnel;
  SshUInt16 cks;
  unsigned char proto;
  SshHWAccelResultCode rc = SSH_HWACCEL_FAILURE;

  return_len = len = 0;
  accel = op->accel;

  hdrlen = op->hdrlen;

  /* Are we doing tunnel mode IPSec? We use transform mode AH when doing
     a combined ESP-AH transform even in tunnel mode. */
  if (op->ah_esp)
    tunnel = (op->esp && (accel->flags & HWACCEL_FLAGS_TUNNEL)) ? 1 : 0;
  else
    tunnel = (accel->flags & HWACCEL_FLAGS_TUNNEL) ? 1 : 0;

  pktb = (UDM_PKT_BITS *) &op->pkt;

  if (pktb->status)
    {
      if (pktb->status & 0x01)
	{
	  rc = SSH_HWACCEL_ICV_FAILURE;
	  SSH_DEBUG(SSH_D_FAIL, ("Authentication failure"));
	}
      if (pktb->status & 0x02)
	{
	  rc = SSH_HWACCEL_PAD_FAILURE;
	  SSH_DEBUG(SSH_D_FAIL, ("Crypto padding failure"));
	}
      if (pktb->status & 0x08)
	{
	  rc = SSH_HWACCEL_FAILURE;
	  SSH_DEBUG(SSH_D_FAIL, ("Extended error"));
	}

      if ((pktb->status & 0x04) && (accel->flags & HWACCEL_FLAGS_ANTIREPLAY))
	{
	  rc = SSH_HWACCEL_SEQ_FAILURE;
	  SSH_DEBUG(SSH_D_FAIL, ("Sequence number failure"));
	}

      /* The UDM always does antireplay checking. Ignore that error if
	 the SA indicates that antireplay should not be performed and
	 that is the only error. */
      if ((pktb->status == 4)
	  && !(accel->flags & HWACCEL_FLAGS_ANTIREPLAY))
	;
      else
	goto fail;
    }

#ifdef SAFENET_DEBUG_HEAVY
  SSH_DEBUG(10, ("After combined transform"));
  print_safenet_pkt(&op->pkt);
  print_safenet_sa((UDM_SA *)op->pkt.sa);
  print_safenet_srec((UDM_STATE_RECORD *)op->pkt.srec);
#endif /* SAFENET_DEBUG_HEAVY */

  SSH_DEBUG(SSH_D_NICETOKNOW,
	    ("return len=%d, pad control=%d, next header=%d",
	     pktb->len, pktb->pad_control, pktb->next_header));

#ifdef SSH_SAFENET_PROFILING
  op->device->packets_processed++;
  op->device->bytes += op->len;
#endif /* SSH_SAFENET_PROFILING */

  SSH_DEBUG(SSH_D_MY, ("copy_pad value is %d", op->device->copy_pad));

  if (op->device->copy_pad)
    {
      SSH_DEBUG(SSH_D_LOWOK,
		("Stripping padding from packet len=%d, pad_len=%d",
		 pktb->len, pktb->pad_control));

      if (pktb->len < pktb->pad_control)
	goto fail;
      pktb->len -= pktb->pad_control;
    }

  pktb->len += op->bypass_offset;

  if (op->esp)
    {
      if (accel->flags & HWACCEL_FLAGS_OUTBOUND)
	return_len = pktb->len + hdrlen;
      else if (tunnel)
	{
	  SSH_ASSERT(pktb->len > hdrlen);
	  return_len = pktb->len - hdrlen;
	}
      else
	return_len = pktb->len;
    }
  else /* ah */
    {
      if (accel->flags & HWACCEL_FLAGS_OUTBOUND)
	return_len = pktb->len;
      else if (tunnel)
	{
	  SSH_ASSERT(pktb->len > SSH_SAFENET_AH_HDRLEN + hdrlen);
	  return_len = pktb->len  - SSH_SAFENET_AH_HDRLEN - hdrlen;
	}
      else
	{
	  SSH_ASSERT(pktb->len > SSH_SAFENET_AH_HDRLEN);
	  return_len = pktb->len  - SSH_SAFENET_AH_HDRLEN;
	}
    }

  /* Default to out-of-memory */
  rc = SSH_HWACCEL_CONGESTED;

#ifndef SSH_SAFENET_PACKET_IS_DMA

  /* Create a new packet, which is large enough to accommodate the
     returned packet data */
  pp = ssh_interceptor_packet_alloc_and_copy_ext_data
    (op->accel->interceptor, op->pp, return_len);

   if (pp == NULL)
    goto fail;

  if (op->esp)
    {
      if (tunnel && !(accel->flags & HWACCEL_FLAGS_OUTBOUND))
	ofs = hdrlen;

       /* Copy stuff from temporary buffer to the real packet. */
      if (!ssh_interceptor_packet_copyin(pp, 0, op->packet + ofs, return_len))
	goto error;
    }
  else /* ah */
    {
      if (!tunnel && !(accel->flags & HWACCEL_FLAGS_OUTBOUND))
	{
	  /* Copy the transport mode header to the real packet. */
	  if (!ssh_interceptor_packet_copyin(pp, 0, op->packet, hdrlen))
	    goto error;

	  /* Copy the payload to the real packet. */
	  if (!ssh_interceptor_packet_copyin(pp, hdrlen,
					     op->packet + hdrlen +
					     SSH_SAFENET_AH_HDRLEN,
					     return_len - hdrlen))
	    goto error;
	}
      else
	{
	  if ((accel->flags & HWACCEL_FLAGS_OUTBOUND) == 0)
	    ofs =  SSH_SAFENET_AH_HDRLEN + hdrlen;

	  /* Copy the data to the real packet. */
	  if (!ssh_interceptor_packet_copyin(pp, 0, op->packet + ofs,
					     return_len))
	    goto error;
	}
    }

  ucp = ssh_interceptor_packet_pullup(pp, hdrlen);
  if (!ucp)
    goto error;

  /* free the contiguous packet buffer */
  if (op->packet)
    ssh_kernel_free(op->packet);
  op->packet = NULL;

  /* free the original packet structure */
  ssh_interceptor_packet_free(op->pp);
  op->pp = NULL;

#else /* SSH_SAFENET_PACKET_IS_DMA */
  {
    SshInterceptorInternalPacket ipp;

    pp = op->pp;
    op->pp = NULL;
    ipp = (SshInterceptorInternalPacket)pp;

    /* Discard the outer tunnel header for inbound transforms */
    if (tunnel && !(accel->flags & HWACCEL_FLAGS_OUTBOUND))
      {
	if (!ssh_interceptor_packet_delete(pp, 0, hdrlen))
	  goto error;
      }

    /* Discard the AH header for inbound transforms */
    if (!op->esp && !(accel->flags & HWACCEL_FLAGS_OUTBOUND))
      {
	ofs = tunnel ? 0 : hdrlen;

	if (!ssh_interceptor_packet_delete(pp, ofs, SSH_SAFENET_AH_HDRLEN))
	  goto error;
      }

    len = ssh_interceptor_packet_len(pp);
    if (return_len > len)
      {
	ipp->skb->len += (return_len - len);
	ipp->skb->tail += (return_len - len);
	SSH_ASSERT(ipp->skb->tail <= ipp->skb->end);
      }
    else
      {
	if (!ssh_interceptor_packet_delete(pp, return_len, len - return_len))
	  goto error;
      }

    SSH_ASSERT(ipp->skb->len == return_len);
    ucp = ipp->skb->data;
  }
#endif /* SSH_SAFENET_PACKET_IS_DMA */

  if (accel->flags & HWACCEL_FLAGS_OUTBOUND)
    {
      if (!tunnel)
	{
	  proto = op->esp ? SSH_IPPROTO_ESP : SSH_IPPROTO_AH;

	  /* Update the next header field of the (extension) header before
	     that of the ESP/AH header. */
	  if (accel->flags & HWACCEL_FLAGS_IPV6)
	    {
	      if (!ssh_interceptor_packet_copyin(pp, op->ipsec_offset_prevnh,
						 &proto, 1))
		goto error;

#ifndef SSH_SAFENET_PACKET_IS_DMA
	      /* The previous call may have invalidated 'ucp' */
	      ucp = ssh_interceptor_packet_pullup(pp, hdrlen);
	      if (!ucp)
		goto error;
#endif /* SSH_SAFENET_PACKET_IS_DMA */
	    }
	  else
	    {
	      SSH_IPH4_SET_PROTO(ucp, proto);
	    }
	}

      /* Update the outer header */
      if (accel->flags & HWACCEL_FLAGS_IPV6)
	{
	  SSH_ASSERT(return_len >= SSH_IPH6_HDRLEN);
	  SSH_IPH6_SET_LEN(ucp, return_len - SSH_IPH6_HDRLEN);
	}
      else
	{
	  SSH_IPH4_SET_LEN(ucp, return_len);
	  SSH_IPH4_SET_CHECKSUM(ucp, 0);
	  cks = ssh_ip_cksum(ucp, hdrlen);
	  SSH_IPH4_SET_CHECKSUM(ucp, cks);
	}
    }
  else
    {
      if (tunnel)
	{
	  /* Nothing required here. */
	}
      else
	{
	  if (accel->flags & HWACCEL_FLAGS_IPV6)
	    {
	      /* Update the next header field of the (extension) header which
		 was before that of the ESP/AH header. */
	      proto = pktb->next_header;
	      if (!ssh_interceptor_packet_copyin(pp, op->ipsec_offset_prevnh,
						 &proto, 1))
		goto error;

#ifndef SSH_SAFENET_PACKET_IS_DMA
	      /* The previous call may have invalidated 'ucp' */
	      ucp = ssh_interceptor_packet_pullup(pp, hdrlen);
	      if (!ucp)
		goto error;
#endif /* SSH_SAFENET_PACKET_IS_DMA */

	      if (op->esp)
		{
		  SSH_ASSERT(pktb->len >= SSH_IPH6_HDRLEN);
		  SSH_IPH6_SET_LEN(ucp, pktb->len - SSH_IPH6_HDRLEN);
		}
	      else
		{
		  SSH_ASSERT(return_len >= SSH_IPH6_HDRLEN);
		  SSH_IPH6_SET_LEN(ucp, return_len - SSH_IPH6_HDRLEN);
		}
	    }
	  else /* ipv4 */
	    {
	      SSH_IPH4_SET_PROTO(ucp, pktb->next_header);

	      if (op->esp)
		SSH_IPH4_SET_LEN(ucp, pktb->len);
	      else
		SSH_IPH4_SET_LEN(ucp, return_len);

	      SSH_IPH4_SET_CHECKSUM(ucp, 0);
	      cks = ssh_ip_cksum(ucp, hdrlen);
	      SSH_IPH4_SET_CHECKSUM(ucp, cks);
	    }
	}
    }

  /* If doing a combined ESP/AH operation, start the AH operation now. */
  if ((accel->flags & HWACCEL_FLAGS_ESP) && (accel->flags & HWACCEL_FLAGS_AH))
    {
      if ((accel->flags & HWACCEL_FLAGS_OUTBOUND) && op->esp)
	{
	  op->esp = 0;
	  op->ah = 1;
	  op->pp = pp;

	  SSH_DEBUG(SSH_D_LOWOK, ("Calling perform op again"));
	  ssh_hwaccel_perform_operation(op);
	  return;
	}
      else if (!(accel->flags & HWACCEL_FLAGS_OUTBOUND) && op->ah)
	{
	  op->esp = 1;
	  op->ah = 0;
	  op->pp = pp;

	  SSH_DEBUG(SSH_D_LOWOK, ("Calling perform op again"));
	  ssh_hwaccel_perform_operation(op);
	  return;
	}
    }
  
  /* For transport mode, update the IP header and upper layer checksums. */
  if ((accel->flags & HWACCEL_FLAGS_NATT) &&
      !(accel->flags & HWACCEL_FLAGS_OUTBOUND) && 
      !(accel->flags & HWACCEL_FLAGS_TUNNEL))
    {
      if (!ssh_hwaccel_natt_update_header(accel, pp, hdrlen))
	goto error;
    }
  




  rc = SSH_HWACCEL_OK;
  (*op->completion)(pp, rc, op->completion_context);

  SAFENET_OPERATION_FREELIST_PUT(op);
  return;

 fail:
  if (pp)
    ssh_interceptor_packet_free(pp);

 error:
#ifdef SSH_SAFENET_PROFILING
  op->device->packets_dropped++;
#endif /* SSH_SAFENET_PROFILING */

#ifndef SSH_SAFENET_PACKET_IS_DMA
  /* free the contiguous packet buffer */
  if (op->packet)
    ssh_kernel_free(op->packet);
#endif /* SSH_SAFENET_PACKET_IS_DMA */

  (*op->completion)(op->pp, rc, op->completion_context);

  SAFENET_OPERATION_FREELIST_PUT(op);
  return;
}

void ssh_hwaccel_perform_combined(SshHWAccel accel,
                                  SshInterceptorPacket pp,
                                  SshHWAccelCompletion completion,
                                  void *completion_context)
{
  SshSafenetDevice device = accel->device;
  SshSafenetOperation op;

#ifdef SSH_SAFENET_PROFILING
  device->packets_queued++;
#endif /* SSH_SAFENET_PROFILING */





  SAFENET_OPERATION_FREELIST_GET(op);
  if (!op)
    goto fail;

  memset(op, 0, sizeof(*op));

  op->completion = completion;
  op->completion_context = completion_context;
  op->device = device;
  op->accel = accel;
  op->pp = pp;

  if ((accel->flags & HWACCEL_FLAGS_ESP) && (accel->flags & HWACCEL_FLAGS_AH))
    {
      op->ah_esp = 1;

      if (accel->flags & HWACCEL_FLAGS_OUTBOUND)
	op->esp = 1;
      else
	op->ah = 1;
    }
  else if (accel->flags & HWACCEL_FLAGS_ESP)
    op->esp = 1;
  else
    op->ah = 1;

  ssh_hwaccel_perform_operation(op);
  return;

 fail:

  ssh_interceptor_packet_free(pp);

#ifdef SSH_SAFENET_PROFILING
  device->packets_dropped++;
#endif /* SSH_SAFENET_PROFILING */

  if (op != NULL)
    SAFENET_OPERATION_FREELIST_PUT(op);

  (*completion)(NULL, SSH_HWACCEL_CONGESTED, completion_context);
}



static void ssh_hwaccel_perform_operation(SshSafenetOperation op)
{
  SshHWAccel accel = op->accel;
  SshInterceptorPacket pp = op->pp;
  SshSafenetDevice device = op->device;
  unsigned char proto = 0, *ucp, *packet = NULL;
  int status = UDM_SUCCESS;
  size_t packet_len, dstlen;
  Boolean ipv6_packet = FALSE;
  Boolean df_bit_set = FALSE;
  UDM_PKT_BITS *pktb;
  UINT32 count;
  SshUInt8 tunnel, tos = 0;
  SshUInt32 flow_label = 0;
  SshUInt8 next_header = 0;

  packet_len = ssh_interceptor_packet_len(pp);

  /* Are we doing tunnel mode IPSec? We use transform mode AH when doing
     a combined ESP-AH transform even in tunnel mode. */
  if (op->ah_esp)
    tunnel = (op->esp && (accel->flags & HWACCEL_FLAGS_TUNNEL)) ? 1 : 0;
  else
    tunnel = (accel->flags & HWACCEL_FLAGS_TUNNEL) ? 1 : 0;

  /* Check if the packet is IPv6 or IPv4 */
  ucp = ssh_interceptor_packet_pullup(pp, SSH_IPH4_HDRLEN);
  if (ucp == NULL)
    goto error;

  if (SSH_IPH4_VERSION(ucp) != 4 && SSH_IPH6_VERSION(ucp) != 6)
    goto fail;

  ipv6_packet = (SSH_IPH6_VERSION(ucp) == 6);

  if (!ipv6_packet && (SSH_IPH4_FRAGOFF(ucp) & SSH_IPH4_FRAGOFF_DF))
    df_bit_set = TRUE;
  
    /* Get the packet's header length (for tunnel mode we are only interested
     in the outer tunnel header). */
  if (tunnel)
    {
      if (accel->flags & HWACCEL_FLAGS_IPV6)
	{
	  op->hdrlen = SSH_IPH6_HDRLEN;
	  op->ipsec_offset_prevnh = SSH_IPH6_OFS_NH;
	}
      else
	{
	  op->hdrlen = SSH_IPH4_HDRLEN;
	}
    }
  else /* transport mode */
    {
      if (ipv6_packet)
	{
	  if (!ssh_safenet_compute_ip6_hdrlen(pp,
					      &op->hdrlen,
					      &op->ipsec_offset_prevnh))
	    goto fail;
	}
      else
	{
	  op->hdrlen = 4 * SSH_IPH4_HLEN(ucp);
	  if (op->hdrlen > 60)
	    goto fail;
	}
    }

  SSH_DEBUG(SSH_D_LOWOK, ("Input packet length %d, tunnel %d, hdrlen %d",
			  packet_len, tunnel, op->hdrlen));

  if (!tunnel)
    {
      if (accel->flags & HWACCEL_FLAGS_IPV6)
	ssh_interceptor_packet_copyout(pp, op->ipsec_offset_prevnh,
				       &proto, 1);
      else
	ssh_interceptor_packet_copyout(pp, SSH_IPH4_OFS_PROTO,
				       &proto, 1);
    }

  next_header =
    tunnel ? (ipv6_packet ? SSH_IPPROTO_IPV6 : SSH_IPPROTO_IPIP) : proto;
  
  SSH_DEBUG(SSH_D_MY, ("next header=%d, tunnel=%d IPv6=%d", 
		       next_header, tunnel, ipv6_packet));

  /* If doing outbound tunnel mode, then insert the outer header here */
  if ((accel->flags & HWACCEL_FLAGS_OUTBOUND) && tunnel)
    {
      /* Fetch the TOS and flow label for IPv6 packets and copy them
	 to the outer header. */
      if (ipv6_packet)
	{
	  SSH_ASSERT(packet_len > SSH_IPH6_HDRLEN);
	  ucp = ssh_interceptor_packet_pullup(pp, SSH_IPH6_HDRLEN);
	  if (ucp == NULL)
	    goto error;
	  tos = SSH_IPH6_CLASS(ucp);
	  flow_label = SSH_IPH6_FLOW(ucp);
	}

      ucp = ssh_interceptor_packet_insert(pp, 0, op->hdrlen);
      if (ucp == NULL)
	goto error;

      SSH_ASSERT(op->hdrlen <= sizeof(accel->hdr));
      memcpy(ucp, accel->hdr, op->hdrlen);

      /* AH tunnel mode requires special handling. The next header field 
	 from the packet (IPIP or IPV6) should be placed in the outer tunnel
	 header. The packet engine replaces this field by the AH next header
	 type and moves the next_header field to the corect position of the
	 AH packet. */
      if (op->ah) 
	{
	  SSH_ASSERT((accel->flags & HWACCEL_FLAGS_OUTBOUND) != 0);
	  SSH_ASSERT(tunnel != 0);

	  if (accel->flags & HWACCEL_FLAGS_IPV6)
	    SSH_IPH6_SET_NH(ucp, next_header);
	  else
	    SSH_IPH4_SET_PROTO(ucp, next_header);
	}

      if (!(accel->flags & HWACCEL_FLAGS_IPV6))
	{
	  /* Set the identification field */
	  device->packet_id++;
	  SSH_IPH4_SET_ID(ucp, device->packet_id);

	  /* Set/Clear the DF bit for IPv4/IPv4 tunnelled packets */
	  if (!ipv6_packet)
	    {
	      if ((accel->flags & HWACCEL_FLAGS_DF_SET) ||
		  (!(accel->flags & HWACCEL_FLAGS_DF_CLEAR) && df_bit_set))
		SSH_IPH4_SET_FRAGOFF(ucp, SSH_IPH4_FRAGOFF_DF); 
	    }
	}
      else
	{
	  SSH_IPH6_SET_CLASS(ucp, tos);
	  SSH_IPH6_SET_FLOW(ucp, flow_label);
	}
    }

  /* Recompute the packet length with the added tunnel header. */
  packet_len = ssh_interceptor_packet_len(pp);

  /* Compute the maximum possible packet return length */
  dstlen = packet_len +
    ((accel->flags & HWACCEL_FLAGS_OUTBOUND) ? accel->added_len : 0);

#ifdef SSH_SAFENET_PACKET_IS_DMA
  {
    SshInterceptorInternalPacket ipp;

    ipp = (SshInterceptorInternalPacket)pp;
    SSH_ASSERT(packet_len == ipp->skb->len);

    /* Ensure that there is tail room for the added headers when
       doing outbound transforms */
    if (accel->flags & HWACCEL_FLAGS_OUTBOUND)
      {
	SSH_ASSERT(dstlen - packet_len >= 0);
	if (skb_tailroom(ipp->skb) < dstlen - packet_len)
	  {
	    ucp = ssh_interceptor_packet_insert(pp, packet_len,
						dstlen - packet_len);
	    if (ucp == NULL)
	      goto error;
	  }
      }
    packet = ipp->skb->data;
   }
#else /* SSH_SAFENET_PACKET_IS_DMA */

  /* Get a contiguous packet buffer */
  if ((packet = ssh_kernel_alloc(dstlen, SSH_KERNEL_ALLOC_DMA)) == NULL)
    goto fail;

  /* Copy the data from the interceptor packet to the dma-enabled
     source buffer */
  ssh_interceptor_packet_copyout(pp, 0, packet, packet_len);

  op->packet = packet;
#endif /* SSH_SAFENET_PACKET_IS_DMA */

  if (op->esp)
    {
      if (accel->flags & HWACCEL_FLAGS_OUTBOUND)
	op->pkt.src = packet + op->hdrlen;
      else
	op->pkt.src = packet;
    }
  else /* ah */
    {
      op->pkt.src = packet;
    }

  /* Do the transform inplace */
  op->pkt.dst = op->pkt.src;

  /* Determine the packet offsets */
  if (op->esp)
    {
      if (accel->flags & HWACCEL_FLAGS_OUTBOUND)
	{
	  op->bypass_offset = 0;
	  op->len = packet_len - op->hdrlen;
	}
      else
	{
	  op->bypass_offset = op->hdrlen;
	  op->len = packet_len;
	}
    }
  else
    {
      op->bypass_offset = 0;
      op->len = packet_len;
    }

  pktb = (UDM_PKT_BITS *) &op->pkt;

  if (accel->flags & HWACCEL_FLAGS_OUTBOUND)
    pktb->next_header = next_header;

  pktb->hash_final = 1;

  pktb->len = op->len - op->bypass_offset;
  pktb->bypass_offset   = 0;

  op->original_src = op->pkt.src;

  /* Do the transform inplace */
  op->pkt.dst = op->pkt.src = op->pkt.src + op->bypass_offset;

  pktb->user_handle = op;
  pktb->pad_control = (accel->flags & HWACCEL_FLAGS_AES) ? 0x8 : 0;

  if (op->esp)
    {
      if (accel->esp.emi_sa)
	{
	  pktb->sa_busid = UDM_BUSID_EMI;
	  pktb->sa = accel->esp.emi_sa;
	}
      else
	{
	  pktb->sa_busid = UDM_BUSID_HOST;
	  pktb->srec = accel->esp.srec;
	  pktb->sa   = accel->esp.sa;
	}
    }
  else
    {
      if (accel->ah.emi_sa)
	{
	  pktb->sa_busid = UDM_BUSID_EMI;
	  pktb->sa = accel->ah.emi_sa;
	}
      else
	{
	  pktb->sa_busid = UDM_BUSID_HOST;
	  pktb->srec = accel->ah.srec;
	  pktb->sa   = accel->ah.sa;
	}
    }
#ifdef SSH_SAFENET_AMCC_SUPPORT 
#ifdef SSH_SAFENET_PE_SA_CACHING
  if ((prev_sa == (UDM_SA*)op->pkt.sa) && (NULL != (UDM_SA *)op->pkt.sa))
    {
	  pktb->chain_sa_cache = 1;
    }
  else
    {
      pktb->chain_sa_cache = 0;
    }
  prev_sa = (UDM_SA*)op->pkt.sa;
#endif /* SSH_SAFENET_PE_SA_CACHING */
#endif /* SSH_SAFENET_AMCC_SUPPORT */
		   
#ifdef SAFENET_DEBUG_HEAVY
  SSH_DEBUG(10, ("Before combined transform"));
  print_safenet_pkt(&op->pkt);
  print_safenet_sa((UDM_SA *)op->pkt.sa);
  print_safenet_srec((UDM_STATE_RECORD *)op->pkt.srec);
#endif /* SAFENET_DEBUG_HEAVY */

  count = 1;
  status = udm_pkt_put(device->device_number, &op->pkt, &count);

  if (status != UDM_SUCCESS || count != 1)
    {
      SSH_DEBUG(SSH_D_FAIL, ("udm pkt put failed, status %d", status));
      goto fail;
    }

  if (device->polling)
    ssh_safenet_pdr_bh_cb( (void *)1, device->device_number);

  return;

 fail:
  ssh_interceptor_packet_free(pp);

 error:

#ifdef SSH_SAFENET_PROFILING
  device->packets_dropped++;
#endif /* SSH_SAFENET_PROFILING */

#ifndef SSH_SAFENET_PACKET_IS_DMA
  if (packet)
    ssh_kernel_free(packet);
#endif /* SSH_SAFENET_PACKET_IS_DMA */

  (*op->completion)(NULL, SSH_HWACCEL_CONGESTED, op->completion_context);
}


/******************** SA bookkeeping *******************************/


/* The device to use is chosen from that which has the least number of
   SshHWAccel contexts associated with it. */
static SshSafenetDevice safenet_find_least_used_device(void)
{
  SshSafenetDevice device, best_device = NULL;
  int best_device_load = 0, load;

  for (device = safenet_devices; device; device = device->next)
    {
      load = device->session_count;

      if (!best_device || best_device_load > load)
        {
          best_device = device;
          best_device_load = load;
        }
    }

  return best_device;
}

/* The Safenet device requires as input the HMAC inner and outer precomputes
   when creating SA's and not the usual HMAC key. This computes the HMAC
   precomputes from the HMAC key. */
static Boolean
ssh_safenet_compute_hmac_precomputes(Boolean sha_hash,
                                     const unsigned char *key,
                                     size_t keylen,
                                     unsigned char inner[20],
                                     unsigned char outer[20])
{
  unsigned char ipad[64];
  unsigned char opad[64];
  SshUInt32 buf[5];
  int i;

  buf[0] = 0x67452301L;
  buf[1] = 0xefcdab89L;
  buf[2] = 0x98badcfeL;
  buf[3] = 0x10325476L;
  buf[4] = 0xc3d2e1f0L;

  for (i = 0; i < 64; i++)
    {
      ipad[i] = 0x36;
      opad[i] = 0x5c;
    }

  if (keylen > 64)
    return FALSE;

  for (i = 0; i < keylen; i++)
    {
      ipad[i] ^= key[i];
      opad[i] ^= key[i];
    }

  if (sha_hash)
    ssh_sha_transform(buf, ipad);
  else
    ssh_md5_transform(buf, ipad);

  SSH_PUT_32BIT_LSB_FIRST(inner, buf[0]);
  SSH_PUT_32BIT_LSB_FIRST(inner + 4, buf[1]);
  SSH_PUT_32BIT_LSB_FIRST(inner + 8, buf[2]);
  SSH_PUT_32BIT_LSB_FIRST(inner + 12, buf[3]);
  SSH_PUT_32BIT_LSB_FIRST(inner + 16, buf[4]);

  buf[0] = 0x67452301L;
  buf[1] = 0xefcdab89L;
  buf[2] = 0x98badcfeL;
  buf[3] = 0x10325476L;
  buf[4] = 0xc3d2e1f0L;

  if (sha_hash)
    ssh_sha_transform(buf, opad);
  else
    ssh_md5_transform(buf, opad);

  SSH_PUT_32BIT_LSB_FIRST(outer, buf[0]);
  SSH_PUT_32BIT_LSB_FIRST(outer + 4, buf[1]);
  SSH_PUT_32BIT_LSB_FIRST(outer + 8, buf[2]);
  SSH_PUT_32BIT_LSB_FIRST(outer + 12, buf[3]);
  SSH_PUT_32BIT_LSB_FIRST(outer + 16, buf[4]);

  SSH_DEBUG_HEXDUMP(SSH_D_LOWOK, ("Key"), key, keylen);
  SSH_DEBUG_HEXDUMP(SSH_D_LOWOK, ("Inner digest"), inner, 20);
  SSH_DEBUG_HEXDUMP(SSH_D_LOWOK, ("Outer digest"), outer, 20);
  return TRUE;
}

static void safenet_copy_key_material(unsigned char *dst,
                                      const unsigned char *src,
                                      int len)
{
#ifdef CGX_BIG_ENDIAN
  int i;

  /* Swap byte order of each 4 bytes. */
  for (i = 0; i < len; i += 4)
    {
      dst[i + 0] = src[i + 3];
      dst[i + 1] = src[i + 2];
      dst[i + 2] = src[i + 1];
      dst[i + 3] = src[i + 0];
    }
#else
  /* No endian issues, just a regular copy. */
  memcpy(dst, src, len);
#endif
}


static Boolean build_safenet_ah_sa(SshHWAccel accel,
				   UDM_SA *sa,
				   UDM_STATE_RECORD *srec,
				   SshUInt32 spi,
				   SshUInt32 seq,
				   int hash_alg,
				   const unsigned char *inner,
				   const unsigned char *outer)

{
  size_t digest_len = 0;
  int device_type = accel->device->device_info.device_type;

  if (hash_alg == SA_HASH_SHA1)
    digest_len = 20;
  else if (hash_alg == SA_HASH_MD5)
    digest_len = 16;
  else
    return FALSE;

  /* Set the state record */

  safenet_copy_key_material((BYTE *)srec->rev1.inner, inner, digest_len);
  srec->rev1.hash_count = 0;

  /* Set the SA */

  safenet_copy_key_material(sa->rev1.inner, inner, digest_len);
  safenet_copy_key_material(sa->rev1.outer, outer, digest_len);

  if (accel->flags & HWACCEL_FLAGS_OUTBOUND)
    sa->rev1.opcode = SA_OPCODE_AH_OUTBOUND;
  else
    sa->rev1.opcode = SA_OPCODE_AH_INBOUND;

  sa->rev1.crypto_pad = SA_PAD_IPSEC;
  sa->rev1.hash_algo = hash_alg;
  sa->rev1.crypto_algo = SA_CRYPTO_NULL;
  sa->rev1.comp_algo = SA_COMP_NULL;
  sa->rev1.input_busid = UDM_BUSID_HOST;
  sa->rev1.output_busid = UDM_BUSID_HOST;
  sa->rev1.hash_loading = SA_HASH_SA;

  /* This must be set for the 1841 devices */
  sa->rev1.use_red_keys = (device_type == UDM_DEVICETYPE_1841) ? 1 : 0;
  sa->rev1.save_hash = (device_type == UDM_DEVICETYPE_1841) ? 0 : 1;

  sa->rev1.spi = (UINT32)spi;
  sa->rev1.seq = (UINT32)seq;

  sa->rev1.copy_header = 1;
  sa->rev1.copy_payload = 1;
  sa->rev1.copy_pad = accel->device->copy_pad ? 1 : 0;

  sa->rev1.ipv6 = (accel->flags & HWACCEL_FLAGS_IPV6) ? 1 : 0;
  sa->rev1.header_proc = 1;

  /* Set to 0 to enable mutable bit handling */
  sa->rev1.mutable_bits = 0;
  sa->rev1.srec_busid = UDM_BUSID_HOST;
  sa->rev1.hmac = 0;
  /* SA revision */
  sa->rev1.rev = 1;

  if (device_type != UDM_DEVICETYPE_1841)
    sa->rev1.srec = (UINT32)srec;

#ifdef SSH_SAFENET_MIN_BYTE_SWAP
  ssh_swap_endian_w((UINT32 *)&(sa->rev1) + 3, (sizeof (UDM_SA_REV1) / 4) - 3);
  ssh_swap_endian_w(&(sa->rev1.srec), 3);
  ssh_swap_endian_w(srec, sizeof(UDM_STATE_RECORD) / 4);
#endif /* SSH_SAFENET_MIN_BYTE_SWAP */

#ifdef SAFENET_DEBUG_HEAVY
  print_safenet_sa(sa);
  print_safenet_srec(srec);
#endif /* SAFENET_DEBUG_HEAVY */
  return TRUE;
}


static Boolean
build_safenet_esp_sa(SshHWAccel accel,
		     UDM_SA *sa,
		     UDM_STATE_RECORD *srec,
		     SshUInt32 spi,
		     SshUInt32 seq,
		     int ciph_alg,
		     int hash_alg,
		     const unsigned char *ciph_key,
		     size_t ciph_key_len,
		     const unsigned char *inner,
		     const unsigned char *outer)
{
  size_t digest_len = 0;
  UINT32 aes_key_len = 0;
  int device_type = accel->device->device_info.device_type;

  memset(sa, 0, sizeof(*sa));
  memset(srec, 0, sizeof(*srec));

  /* Check the cipher key size */
  if (ciph_alg == SA_CRYPTO_DES && ciph_key_len != 8)
    return FALSE;

  if (ciph_alg == SA_CRYPTO_TDES && ciph_key_len != 24)
    return FALSE;

  if (ciph_alg == SA_CRYPTO_AES)
    {
      if (ciph_key_len == 16)
        aes_key_len = 2;
      else if (ciph_key_len == 24)
        aes_key_len = 3;
      else if (ciph_key_len == 32)
        aes_key_len = 4;
      else
        return FALSE;
    }

  if (hash_alg == SA_HASH_SHA1)
    digest_len = 20;

  if (hash_alg == SA_HASH_MD5)
    digest_len = 16;

  /******* Set the state record **********/

  if (hash_alg != SA_HASH_NULL)
    safenet_copy_key_material((BYTE *)srec->rev1.inner, inner, digest_len);

  srec->rev1.hash_count = 0;


  /********** Set the SA *****************/

  if (ciph_alg != SA_CRYPTO_NULL)

    safenet_copy_key_material((BYTE *)sa->rev1.key1, ciph_key, ciph_key_len);

  if (hash_alg != SA_HASH_NULL)
    {
      /* Copy the hash digests. */
      safenet_copy_key_material(sa->rev1.inner, inner, digest_len);
      safenet_copy_key_material(sa->rev1.outer, outer, digest_len);
    }

  sa->rev1.opcode = (accel->flags & HWACCEL_FLAGS_OUTBOUND)
    ? SA_OPCODE_ESP_OUTBOUND : SA_OPCODE_ESP_INBOUND;
  sa->rev1.iv_loading = (accel->flags & HWACCEL_FLAGS_OUTBOUND) ?
    SA_IV_REUSE : SA_IV_INPUT;
  sa->rev1.crypto_pad = SA_PAD_IPSEC;
  sa->rev1.crypto_algo = ciph_alg;
  sa->rev1.hash_algo = hash_alg;
  sa->rev1.comp_algo = SA_COMP_NULL;
  sa->rev1.header_proc = 1;
  sa->rev1.input_busid = UDM_BUSID_HOST;
  sa->rev1.output_busid = UDM_BUSID_HOST;

  /* This must be set for the 1841 devices */
  if (device_type == UDM_DEVICETYPE_1841)
    sa->rev1.use_red_keys = 1;
  else
    sa->rev1.use_red_keys = 0;

  sa->rev1.spi = (UINT32)spi;
  sa->rev1.seq = (UINT32)seq;

  sa->rev1.ipv6 = (accel->flags & HWACCEL_FLAGS_IPV6) ? 1 : 0;
  sa->rev1.hash_loading = SA_HASH_SA;
  sa->rev1.save_iv = 0      ;
  sa->rev1.save_hash = 0;
  sa->rev1.copy_header = 0;
  sa->rev1.copy_pad = accel->device->copy_pad ? 1 : 0;

  /* Set to 1 disables mutable bit handling */
  sa->rev1.mutable_bits = 1;
  sa->rev1.srec_busid = UDM_BUSID_HOST;

  /* We always use CBC mode of encryption */
  sa->rev1.crypto_mode = SA_CRYPTO_MODE_CBC;
  sa->rev1.crypto_feedback = SA_CRYPTO_FEEDBACK_8;

  sa->rev1.hmac = 1;

  /* SA revision */
  sa->rev1.rev = 1;

  if (ciph_alg == SA_CRYPTO_AES)
    sa->rev1.arc4_aes_key_len = aes_key_len;

  if (device_type != UDM_DEVICETYPE_1841)
    sa->rev1.srec = (UINT32)srec;

#ifdef SSH_SAFENET_MIN_BYTE_SWAP
  ssh_swap_endian_w((UINT32 *)&(sa->rev1) + 3, (sizeof (UDM_SA_REV1) / 4) - 3);
  ssh_swap_endian_w(&(sa->rev1.srec), 3);
  ssh_swap_endian_w(srec, sizeof(UDM_STATE_RECORD) / 4);
#endif /* SSH_SAFENET_MIN_BYTE_SWAP */

#ifdef SAFENET_DEBUG_HEAVY
  print_safenet_sa(sa);
  print_safenet_srec(srec);
#endif /* SAFENET_DEBUG_HEAVY */
  return TRUE;
}


#ifdef SSH_SAFENET_USE_EMI_MEMORY
static Boolean write_emi_sa(SshSafenetDevice device,
			    HwAccelTransform transform,
			    UDM_SA *sa, int sa_size)
{
  UINT32 emi_addr, temp;

  SshUInt32 emi_index = 0;
  size_t iterations = 0;
  Boolean emi_available = FALSE;

  SSH_DEBUG(SSH_D_LOWOK, ("The current SA word index is %d",
			  device->emi_word_index));

  SSH_DEBUG_HEXDUMP(90, ("EMI SA index table prefix before allocation"),
		    device->emi_sas, 16);

  ssh_kernel_mutex_lock(device->lock);

  /* Search for an available EMI SA.
     Uses a method similar to the NRU algorithm to allocate slots from
     the bit array device->emi_sas. The emi_sas_mod array is used to store
     a modified bit, which indicates whether an SA was recently deleted
     from the slot. Needed because of the SafeXcel 184x caching.
  */
  iterations = 0;
  while (iterations < 10)
    {

      if (device->emi_word_index >= SSH_SAFENET_EMI_BYTES)
	device->emi_word_index = 0;

      /* All slots are reserved from this index. */
      if (device->emi_sas[device->emi_word_index] == 0xff)
	{
  	  /* If SA bit is set, the modified bit should also be set. */
	  SSH_ASSERT(device->emi_sas_mod[device->emi_word_index] == 0xff);

#ifdef SAFENET_DEBUG_EMI
	  SSH_DEBUG(90, ("Omitting reserved indices %d-%d",
			 8*device->emi_word_index,
			 8*device->emi_word_index+7));
#endif /* SAFENET_DEBUG_EMI */

	  device->emi_word_index++;
	  iterations++;
	  continue;
	}
      /* There are some slots available, but none are free yet. */
      else if (device->emi_sas_mod[device->emi_word_index] == 0xff)
	{
#ifdef SAFENET_DEBUG_EMI
	  unsigned char mask = device->emi_sas[device->emi_word_index];
	  SSH_DEBUG(90,
		    ("Visiting indices %d-%d, mask %d%d%d%d %d%d%d%d (%x)",
		     8*device->emi_word_index,
		     8*device->emi_word_index+7,
		     ((mask&1)!=0),((mask&2)!=0),((mask&4)!=0),((mask&8)!=0),
		     ((mask&16)!=0),((mask&32)!=0),((mask&64)!=0),
		     ((mask&128)!=0),
		     mask));
#endif /* SAFENET_DEBUG_EMI */

	  /* Set the modified bits to 0 on available slots. */
	  device->emi_sas_mod[device->emi_word_index] &=
	    device->emi_sas[device->emi_word_index];

	  device->emi_word_index++;
	  iterations++;
	  continue;
	}
      else
	{
	  unsigned char word, word_mod, offset, offset_mask;

	  word = device->emi_sas[device->emi_word_index];
	  word_mod = device->emi_sas_mod[device->emi_word_index];

	  offset = 0;
	  while (1)
	    {
	      /* Slot must be available and not modified recently. */
	      if ((word & 0x1) == 0)
		{
		  if ((word_mod & 0x1) == 0)
		    break;
		}
	      else
		{
		  /* All reserved slots should have a modified bit of one. */
		  SSH_ASSERT((word_mod & 0x1) == 1);
		}

	      word >>= 1;
	      word_mod >>= 1;
	      offset++;
	    }

	  SSH_ASSERT(offset <= 7);

	  emi_index = (8 * device->emi_word_index) + offset;

	  /* Mark all available slots as 'not modified' from this EMI index. */
	  device->emi_sas_mod[device->emi_word_index] &=
	    device->emi_sas[device->emi_word_index];

#ifdef SAFENET_DEBUG_EMI
	  {
	    unsigned char mask;
	    mask = device->emi_sas[device->emi_word_index];
	    SSH_DEBUG(90,
		      ("Visiting indices %d-%d, mask %d%d%d%d %d%d%d%d (%x)",
		       8*device->emi_word_index,
		       8*device->emi_word_index+7,
		       ((mask&1)!=0),((mask&2)!=0),((mask&4)!=0),((mask&8)!=0),
		       ((mask&16)!=0),((mask&32)!=0),((mask&64)!=0),
		       ((mask&128)!=0),
		       mask));
	  }
#endif /* SAFENET_DEBUG_EMI */

      	  /* Mark the position in device->emi_word_index as one
	     to indicate that this SA is in use. */
	  offset_mask = (unsigned char) (1 << offset);
	  device->emi_sas[device->emi_word_index] |= offset_mask;

	  /* Also mark the position as modified. */
	  device->emi_sas_mod[device->emi_word_index] |= offset_mask;

	  emi_available = TRUE;

	  transform->emi_sa_index = emi_index;
	  break;
	}
    }

  /* Do not search slots from the same word index in consecutive calls. */
  device->emi_word_index++;

  ssh_kernel_mutex_unlock(device->lock);

  SSH_DEBUG(SSH_D_LOWOK, ("The updated SA word index is %d, the "
			  "actual EMI index is %d",
			  device->emi_word_index, emi_index));

  if (emi_available)
    {
      /* Calculate the EMI address where SA will be stored. */
      emi_addr = emi_index * SSH_SAFENET_SA_EMI_MEMORY;

      /* Setup target page register, bits 12-13 denote ram
	 type = SDRAM. */
      temp = (emi_addr >> 16) + 0x00001000;
      udm_bus_write (device->device_number, &temp, 0x0198, 4);

      transform->emi_sa = (VPTR)(emi_addr + 0x10000000);
      /* Write SA to EMI (EMI page starts at target offset 0x10000). */
      udm_bus_write (device->device_number, (void *)sa,
		     (emi_addr & 0xffff) + 0x10000, sa_size);
    }
  SSH_DEBUG_HEXDUMP(90, ("EMI SA index table prefix after allocation"),
		    device->emi_sas, 16);

  return emi_available;
}
#endif /* SSH_SAFENET_USE_EMI_MEMORY */

SshHWAccel
ssh_hwaccel_alloc_combined(SshInterceptor interceptor,
                           SshUInt32 flags,
                           SshUInt32 *flags_return,
                           SshUInt32 ah_spi,
                           const char *ah_macname,
                           const unsigned char *ah_authkey,
                           size_t ah_authkeylen,
                           SshUInt32 esp_spi,
                           const char *esp_macname,
                           const char *esp_ciphname,
                           const unsigned char *esp_authkey,
                           size_t esp_authkeylen,
                           const unsigned char *esp_ciphkey,
                           size_t esp_ciphkeylen,
                           const unsigned char *esp_iv,
                           size_t esp_ivlen,
                           SshUInt32 ipcomp_cpi,
                           const char *ipcomp_compname,
			   SshIpAddr ipip_src, SshIpAddr ipip_dst,
			   SshUInt32 seq_num_low, SshUInt32 seq_num_high,
			   SshUInt16 natt_remote_port,
			   const unsigned char *natt_oa_l,
			   const unsigned char *natt_oa_r)

{
  SshSafenetDevice device = NULL;
  SshHWAccel accel = NULL;
  unsigned char inner[20]; /* inner precompute for HMAC */
  unsigned char outer[20]; /* outer precompute for HMAC */
  int proto = 0, ciph_alg = SA_CRYPTO_NULL;
  int hash_alg = SA_HASH_NULL;
  char *mac_name = NULL;
  unsigned char *mac_key = NULL;
  size_t mac_key_len = 0;
  UDM_STATE_RECORD srec;
  UDM_SA sa;

  *flags_return = flags;
  if (flags & SSH_HWACCEL_COMBINED_FLAG_ESP)
    SSH_DEBUG(SSH_D_NICETOKNOW,
	      ("alloc_combined ESP %s/%s/%s[%x] (%d/%d) spi=%x, %x=%s.",
	       esp_ciphname ? esp_ciphname : "none",
	       esp_macname ? esp_macname : "none",
	       ipcomp_compname ? ipcomp_compname : "none",
	       ipcomp_cpi,
	       esp_authkeylen, esp_ciphkeylen, esp_spi, flags,
             (flags & SSH_HWACCEL_COMBINED_FLAG_ENCAPSULATE) ?
	       "encrypt" : "decrypt"));

  if (flags & SSH_HWACCEL_COMBINED_FLAG_AH)
    SSH_DEBUG(SSH_D_NICETOKNOW,
	      ("alloc_combined AH %s (%d) spi=%x, %x=%s.",
	       ah_macname ? ah_macname : "none",
	       ah_authkeylen, ah_spi, flags,
	       (flags & SSH_HWACCEL_COMBINED_FLAG_ENCAPSULATE) ?
	       "outbound" : "inbound"));


  device = safenet_find_least_used_device();

  if (!device)
    {
      SSH_DEBUG(SSH_D_FAIL, ("No device available"));
      return NULL;
    }

  if (flags & SSH_HWACCEL_COMBINED_FLAG_ENCAPSULATE)
    {
      if (seq_num_low)
	seq_num_low--;
    }

  if (seq_num_high)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Extended sequence numbers are not supported"));
      return NULL;
    }

  SAFENET_HWACCEL_FREELIST_GET(accel);
  if (!accel)
    return NULL;

  memset(accel, 0, sizeof(*accel));

  if (flags & SSH_HWACCEL_COMBINED_FLAG_NATT)
    {
      *flags_return &= ~SSH_HWACCEL_COMBINED_FLAG_NATT;
      accel->flags |= HWACCEL_FLAGS_NATT;
    }

  if (flags & SSH_HWACCEL_COMBINED_FLAG_ENCAPSULATE)
    accel->flags |= HWACCEL_FLAGS_OUTBOUND;

  if (flags & SSH_HWACCEL_COMBINED_FLAG_ESP)
    {
      accel->flags |=  HWACCEL_FLAGS_ESP;
      mac_name = (char *)esp_macname;
      mac_key = (unsigned char *)esp_authkey;
      mac_key_len = esp_authkeylen;
      proto = SSH_IPPROTO_ESP;

      /* ESP header */
      accel->added_len += 8;
    }

  if (flags & SSH_HWACCEL_COMBINED_FLAG_AH)
    {
      accel->flags |=  HWACCEL_FLAGS_AH;
      mac_name = (char *)ah_macname;
      mac_key = (unsigned char *)ah_authkey;
      mac_key_len = ah_authkeylen;

      /* AH tunnel mode requires special handling. The next header field 
	 from the packet (IPIP or IPV6) should be placed in the outer tunnel
	 header. The packet engine replaces this field by the AH next header
	 type and moves the next_header field to the corect position of the
	 AH packet. */
      if (flags & SSH_HWACCEL_COMBINED_FLAG_REQUIRE_IPV6)
	proto = SSH_IPPROTO_IPV6;
      else
	proto = SSH_IPPROTO_IPIP;
      
      /* AH header (excluding the ICV) */
      accel->added_len += 12;
    }

  if (((flags & SSH_HWACCEL_COMBINED_FLAG_ESP) == 0) &&
      ((flags & SSH_HWACCEL_COMBINED_FLAG_AH) == 0))
      goto fail;

  /* IPComp not supported */
  if (flags & SSH_HWACCEL_COMBINED_FLAG_IPCOMP)
    {
      SSH_DEBUG(SSH_D_FAIL, ("IPCOMP not supported"));
      goto fail;
    }

  if (flags & SSH_HWACCEL_COMBINED_FLAG_ANTIREPLAY)
    accel->flags |= HWACCEL_FLAGS_ANTIREPLAY;
  if (flags & SSH_HWACCEL_COMBINED_FLAG_DF_SET)
    accel->flags |= HWACCEL_FLAGS_DF_SET;
  if (flags & SSH_HWACCEL_COMBINED_FLAG_DF_CLEAR)
    accel->flags |= HWACCEL_FLAGS_DF_CLEAR;

  /* 64 bit sequence numbers not supported */
  if (flags & SSH_HWACCEL_COMBINED_FLAG_LONGSEQ)
    {
      SSH_DEBUG(SSH_D_FAIL, ("64 bit sequence numbers not supported"));
      goto fail;
    }

  if (flags & SSH_HWACCEL_COMBINED_FLAG_REQUIRE_IPV6)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("IPv6 SA"));
      accel->flags |= HWACCEL_FLAGS_IPV6;
    }

  /* Get the ESP cipher algorithm */
  if (esp_ciphname && strcmp(esp_ciphname, "none"))
    {
      if (!strcmp(esp_ciphname, "aes-cbc"))
        {
	  accel->added_len += 16; /* iv */
	  accel->added_len += 16 + 1; /* worst case ESP trailer + padding */
          accel->iv_len = 16;
	  accel->flags |= HWACCEL_FLAGS_AES;
          ciph_alg = SA_CRYPTO_AES;
        }
      else if (!strcmp(esp_ciphname, "3des-cbc"))
        {
	  accel->added_len += 8; /* iv */
	  accel->added_len += 8 + 1; /* worst case ESP trailer + padding */
          accel->iv_len = 8;
          ciph_alg = SA_CRYPTO_TDES;
        }
      else if (!strcmp(esp_ciphname, "des-cbc"))
        {
	  accel->added_len += 8; /* iv */
	  accel->added_len += 8 + 1; /* worst case ESP trailer + padding */
          accel->iv_len = 8;
          ciph_alg = SA_CRYPTO_DES;
        }
      else
        {
          SSH_DEBUG(SSH_D_FAIL, ("Unsupported Cipher algorithm %s",
                                 esp_ciphname));
	  goto fail;
        }
    }
  else
    {
      accel->iv_len = 0;
      accel->added_len += 8 + 1; /* worst case ESP trailer + padding */
      ciph_alg = SA_CRYPTO_NULL;
    }

  /* Get the mac algorithm */
  if (mac_name && strcmp(mac_name, "none"))
    {
      if (!strcmp(mac_name, "hmac-sha1-96"))
        {
          hash_alg = SA_HASH_SHA1;
        }
      else if (!strcmp(mac_name, "hmac-md5-96"))
        {
          hash_alg = SA_HASH_MD5;
        }
      else
        {
          SSH_DEBUG(SSH_D_FAIL, ("Unsupported MAC algorithm %s", mac_name));
	  goto fail;
	}

      accel->added_len += 12; /* ICV */
    }
  else
    {
      hash_alg = SA_HASH_NULL;
    }

  /* Verify we don't have both null cipher and null mac */
  if (hash_alg == SA_HASH_NULL && ciph_alg == SA_CRYPTO_NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Cannot have both null cipher and null mac"));
      goto fail;
    }

  accel->device = device;
  accel->interceptor = interceptor;

  /* Construct outer IP header if required */
  if (flags & SSH_HWACCEL_COMBINED_FLAG_IPIP)
    {
      accel->flags |= HWACCEL_FLAGS_TUNNEL;

      if (accel->flags & HWACCEL_FLAGS_OUTBOUND)
        {
          if ((accel->flags & HWACCEL_FLAGS_IPV6) == 0)
            {
              SSH_IPH4_SET_VERSION(accel->hdr, 4);
              SSH_IPH4_SET_HLEN(accel->hdr, 5);
	      SSH_IPH4_SET_TTL(accel->hdr, 240);
	      SSH_IPH4_SET_PROTO(accel->hdr, proto);
	      SSH_IPH4_SET_SRC(ipip_src, accel->hdr);
	      SSH_IPH4_SET_DST(ipip_dst, accel->hdr);

              SSH_DEBUG_HEXDUMP(SSH_D_LOWOK, ("ipv4 header"),
				accel->hdr, 20);
            }
          else
            {
              SSH_IPH6_SET_VERSION(accel->hdr, 6);
              SSH_IPH6_SET_NH(accel->hdr, proto);
              SSH_IPH6_SET_HL(accel->hdr, 64);
              SSH_IPH6_SET_SRC(ipip_src, accel->hdr);
              SSH_IPH6_SET_DST(ipip_dst, accel->hdr);

              SSH_DEBUG_HEXDUMP(SSH_D_LOWOK, ("ipv6 header"),
				accel->hdr, sizeof(accel->hdr));

            }
        }
    }
  else /* transport mode */
    {
      memset(accel->hdr, 0, sizeof(accel->hdr));
    }

  memset(inner, 0, 20);
  memset(outer, 0, 20);

  /* Compute the inner and outer hmac precomputes */
  if (hash_alg != SA_HASH_NULL)
    if (!ssh_safenet_compute_hmac_precomputes(hash_alg == SA_HASH_SHA1,
					      mac_key,
					      mac_key_len,
					      inner, outer))
      goto fail;

  SSH_DEBUG_HEXDUMP(10, ("Inner HMAC digest"), inner, sizeof(inner));
  SSH_DEBUG_HEXDUMP(10, ("Outer HMAC digest"), outer, sizeof(outer));

  if (flags & SSH_HWACCEL_COMBINED_FLAG_AH)
    {
      memset(&srec, 0, sizeof(srec));
      memset(&sa, 0, sizeof(sa));

      if (!build_safenet_ah_sa(accel, &sa, &srec, ah_spi, seq_num_low,
			       hash_alg, inner, outer))
        goto fail;

#ifdef SSH_SAFENET_USE_EMI_MEMORY
      if (device->use_emi_sa)
	{
	  if (!write_emi_sa(accel->device, &accel->ah, &sa, sizeof(UDM_SA)))
	    goto fail;
	}
      else
#endif /* SSH_SAFENET_USE_EMI_MEMORY */
	{
      size_t sa_size = sizeof(*accel->ah.sa) + sizeof(*accel->ah.srec);
	  UDM_SA *psa;

#ifdef SSH_SAFENET_SA_CACHE_ALIGN
	  sa_size += (sizeof(*UDM_SA*) + (2 * L1_CACHE_LINE_SIZE));
#endif /* SSH_SAFENET_SA_CACHE_ALIGN */

#ifdef SSH_SAFENET_AMCC_SUPPORT 
      psa = ssh_kernel_alloc_sa(sa_size, SSH_KERNEL_ALLOC_DMA);
      accel->ah.sa_len = sa_size;
#else
      psa = ssh_kernel_alloc(sa_size, SSH_KERNEL_ALLOC_DMA);
#endif /* SSH_SAFENET_AMCC_SUPPORT */
	  if (psa == NULL)
	    goto fail;

#ifdef SSH_SAFENET_SA_CACHE_ALIGN
	  {
	    UDM_SA *tmp;

	    /* orig-sa-address, |alignment boundary|, sa-address, srec */
	    accel->ah.sa = (UDM_SA *) L1_CACHE_ALIGN(psa);
	    if ((unsigned int)(accel->ah.sa - psa) < sizeof(UDM_SA *))
	      {
		/* If there is not enough space to store the
		   non-cache-aligned A buffer address, shift SA buffer
		   by one cache line to make space in front of it */
		accel->ah.sa = (UDM_SA *)
		  ((unsigned char *)accel->ah.sa + L1_CACHE_LINE_SIZE);
	      }
	    /* Store the original potentially non aligned address in
	       front of aligned sa record */
	    tmp = (UDM_SA *)
	      ((unsigned char *)accel->ah.sa - sizeof(UDM_SA *));
	    *tmp = psa;
	  }
#else /* SSH_SAFENET_SA_CACHE_ALIGN */
	  accel->ah.sa = psa;
#endif /* SSH_SAFENET_SA_CACHE_ALIGN */

	  /* Put state record contiguous with the SA, this is required
	     for the 184x devices. */
	  accel->ah.srec = (UDM_STATE_RECORD *)((unsigned char *)accel->ah.sa +
						sizeof(*accel->ah.sa));

	  memcpy(accel->ah.sa, &sa, sizeof(sa));
	  memcpy(accel->ah.srec, &srec, sizeof(srec));
	}
   }

  if (flags & SSH_HWACCEL_COMBINED_FLAG_ESP)
    {
      if (flags & SSH_HWACCEL_COMBINED_FLAG_AH)
	hash_alg = SA_HASH_NULL;

      memset(&srec, 0, sizeof(srec));
      memset(&sa, 0, sizeof(sa));

      if (!build_safenet_esp_sa(accel, &sa, &srec, esp_spi, seq_num_low,
				ciph_alg,  hash_alg,
				esp_ciphkey, esp_ciphkeylen,
				inner, outer))
        goto fail;

      /* For 184x, attempt to write the SA directly into EMI memory. */
#ifdef SSH_SAFENET_USE_EMI_MEMORY
      if (device->use_emi_sa)
	{
	  if (!write_emi_sa(accel->device, &accel->esp, &sa, sizeof(UDM_SA)))
	    goto fail;
	}
      else
#endif /* SSH_SAFENET_USE_EMI_MEMORY */
	{
      size_t sa_size = sizeof(*accel->ah.sa) + sizeof(*accel->ah.srec);
	  UDM_SA *psa;

#ifdef SSH_SAFENET_SA_CACHE_ALIGN
	  sa_size += (sizeof(*UDM_SA*) + (2 * L1_CACHE_LINE_SIZE));
#endif /* SSH_SAFENET_SA_CACHE_ALIGN */

#ifdef SSH_SAFENET_AMCC_SUPPORT
      psa = ssh_kernel_alloc_sa(sa_size, SSH_KERNEL_ALLOC_DMA);
      accel->esp.sa_len = sa_size;
#else
      psa = ssh_kernel_alloc(sa_size, SSH_KERNEL_ALLOC_DMA);
#endif /* SSH_SAFENET_AMCC_SUPPORT */

	  if (psa == NULL)
	    goto fail;

#ifdef SSH_SAFENET_SA_CACHE_ALIGN
	  {
	    UDM_SA *tmp;

	    /* orig-sa-address, |alighment boundary|, sa-address, srec */
	    accel->esp.sa = (UDM_SA *) L1_CACHE_ALIGN(psa);
	    if ((unsigned int)(accel->esp.sa - psa) < sizeof(UDM_SA *))
	      {
		/* If there is not enough space to store the
		   non-cache-aligned A buffer address, shift SA buffer
		   by one cache line to make space in front of it */
		accel->esp.sa = (UDM_SA *)
		  ((unsigned char *)accel->esp.sa + L1_CACHE_LINE_SIZE);
	      }
	    /* Store the original potentially non aligned address in
	       front of aligned sa record */
	    tmp = (UDM_SA *)
	      ((unsigned char *)accel->esp.sa - sizeof(UDM_SA *));
	    *tmp = psa;
	  }
#else /* SSH_SAFENET_SA_CACHE_ALIGN */
	  accel->esp.sa = psa;
#endif /* SSH_SAFENET_SA_CACHE_ALIGN */

	  /* Put state record contiguous with the SA, this is required
	     for the 1841 devices. */
	  accel->esp.srec =
	    (UDM_STATE_RECORD *)((unsigned char *)accel->esp.sa +
				 sizeof(*accel->esp.sa));

	  memcpy(accel->esp.sa, &sa, sizeof(sa));
	  memcpy(accel->esp.srec, &srec, sizeof(srec));
	}
    }

   /* increase the session counter, needed for load-balancing */
  ssh_kernel_mutex_lock(device->lock);
  device->session_count++;
  ssh_kernel_mutex_unlock(device->lock);

  SSH_DEBUG(SSH_D_MIDOK, ("Alloc combined succeeded"));

#ifdef SSH_SAFENET_PROFILING
  if (device)
    device->sessions_created++;
#endif /* SSH_SAFENET_PROFILING */

  SSH_DEBUG(SSH_D_LOWOK, ("added_len is %d and iv_len is %d",
			  accel->added_len, accel->iv_len));

  /* Clean memory */
  memset(&srec, 0, sizeof(srec));
  memset(&sa, 0, sizeof(sa));

  return accel;
 fail:

#ifdef SSH_SAFENET_PROFILING
  device->sessions_failed++;
#endif /* SSH_SAFENET_PROFILING */

  SSH_DEBUG(SSH_D_FAIL, ("Alloc combined failed"));

  if (accel)
    {
      if (accel->esp.sa)
	{
#ifdef SSH_SAFENET_SA_CACHE_ALIGN
	  accel->esp.sa = *(UDM_SA *)
	    ((unsigned char *)accel->esp.sa - sizeof(UDM_SA *));
#endif
#ifdef SSH_SAFENET_AMCC_SUPPORT 
      ssh_kernel_free_sa(accel->esp.sa, accel->esp.sa_len);
#else
      ssh_kernel_free(accel->esp.sa);
#endif /* SSH_SAFENET_AMCC_SUPPORT */
	}
      if (accel->ah.sa)
	{
#ifdef SSH_SAFENET_SA_CACHE_ALIGN
	  accel->ah.sa = *(UDM_SA *)
	    ((unsigned char *)accel->esp.sa - sizeof(UDM_SA *));
#endif
#ifdef SSH_SAFENET_AMCC_SUPPORT
      ssh_kernel_free_sa(accel->ah.sa, accel->ah.sa_len);
#else
      ssh_kernel_free(accel->ah.sa);
#endif /* SSH_SAFENET_AMCC_SUPPORT */
	}

      SAFENET_HWACCEL_FREELIST_PUT(accel);
    }

  /* Clean memory */
  memset(&srec, 0, sizeof(srec));
  memset(&sa, 0, sizeof(sa));

  return NULL;
}


SshHWAccelResultCode
ssh_hwaccel_update_combined(SshHWAccel accel, 
                            SshIpAddr ipip_src, 
                            SshIpAddr ipip_dst, 
			    SshUInt16 natt_remote_port)
{
  return SSH_HWACCEL_UNSUPPORTED;

  if (!(accel->flags & SSH_HWACCEL_COMBINED_FLAG_IPIP))
    return SSH_HWACCEL_UNSUPPORTED;
  
  if (accel->flags & HWACCEL_FLAGS_OUTBOUND)
    {
     if ((accel->flags & HWACCEL_FLAGS_IPV6) == 0)
	{
	  SSH_IPH4_SET_SRC(ipip_src, accel->hdr);
	  SSH_IPH4_SET_DST(ipip_dst, accel->hdr);
	  
	  SSH_DEBUG_HEXDUMP(SSH_D_LOWOK, ("updated ipv4 header"),
			    accel->hdr, 20);
	}
      else
	{
	  SSH_IPH6_SET_SRC(ipip_src, accel->hdr);
	  SSH_IPH6_SET_DST(ipip_dst, accel->hdr);
	  
	  SSH_DEBUG_HEXDUMP(SSH_D_LOWOK, ("updated ipv6 header"),
			    accel->hdr, sizeof(accel->hdr));
	  
	}
    }

  return SSH_HWACCEL_OK;
}



/* Frees the hardware acceleration context.  The engine guarantees
   that no operations will be in progress using the context when this
   is called. */
void ssh_hwaccel_free_combined(SshHWAccel accel)
{
  SshSafenetDevice device = accel->device;
#ifdef SSH_SAFENET_USE_EMI_MEMORY
  unsigned char mask;
#endif /* SSH_SAFENET_USE_EMI_MEMORY */

#ifdef SSH_SAFENET_PROFILING
  device->sessions_destroyed++;
#endif /* SSH_SAFENET_PROFILING */

  SSH_DEBUG(SSH_D_MIDOK, ("Freeing SshHWAccel instance"));

  ssh_kernel_mutex_lock(device->lock);
  device->session_count--;

#ifdef SSH_SAFENET_USE_EMI_MEMORY
  SSH_DEBUG_HEXDUMP(90, ("EMI SA index table prefix before freeing"),
		    device->emi_sas, 16);

  /* Mark the EMI SA's as freed if they were in use. */
  if (accel->ah.emi_sa != NULL)
    {
      SSH_ASSERT(accel->ah.emi_sa_index < SSH_SAFENET_EMI_BYTES * 8);

      mask = (unsigned char) ~(1 << (accel->ah.emi_sa_index & 7));
      device->emi_sas[accel->ah.emi_sa_index / 8] &= mask;

      SSH_DEBUG(SSH_D_NICETOKNOW, ("Freeing AH from index %d",
				   accel->ah.emi_sa_index));
    }

  /* Mark the EMI SA's as freed if they were in use. */
  if (accel->esp.emi_sa != NULL)
    {
      SSH_ASSERT(accel->esp.emi_sa_index < SSH_SAFENET_EMI_BYTES * 8);

      mask = (unsigned char) ~(1 << (accel->esp.emi_sa_index & 7));
      device->emi_sas[accel->esp.emi_sa_index / 8] &= mask;

      SSH_DEBUG(SSH_D_NICETOKNOW, ("Freeing ESP from index %d",
				   accel->esp.emi_sa_index));
    }
  SSH_DEBUG_HEXDUMP(90, ("EMI SA index table prefix after freeing"),
		    (unsigned char *)device->emi_sas, 16);
#endif /* SSH_SAFENET_USE_EMI_MEMORY */

  ssh_kernel_mutex_unlock(device->lock);

  if (accel->ah.sa)
#ifdef SSH_SAFENET_AMCC_SUPPORT 
    ssh_kernel_free_sa(accel->ah.sa, accel->ah.sa_len);
#else
    ssh_kernel_free(accel->ah.sa);
#endif /* SSH_SAFENET_AMCC_SUPPORT */
  if (accel->esp.sa)
#ifdef SSH_SAFENET_AMCC_SUPPORT
    ssh_kernel_free_sa(accel->esp.sa, accel->esp.sa_len);
#else
    ssh_kernel_free(accel->esp.sa);
#endif /* SSH_SAFENET_AMCC_SUPPORT */

  SAFENET_HWACCEL_FREELIST_PUT(accel);
}

/*********** Initialization functions *******************************/

#ifdef USERMODE_ENGINE
static void safenet_got_signal(int sig, void *context)
{
  SshSafenetDevice device = context;

  ssh_safenet_pdr_cb(device->device_number);
  return;

}
#endif /* USERMODE_ENGINE */

Boolean ssh_safenet_device_init(SshSafenetDevice device)
{
  INIT_BLOCK initblock;
  Boolean pci_swap;
  int status;

  device->lock = ssh_kernel_mutex_alloc();

  /* Copy the pad for the 1141 device types to avoid a lockup problem
     that occurs if there is no output data from certain operations. */
  device->copy_pad =
    (device->device_info.device_type == UDM_DEVICETYPE_1141 ||
     device->device_info.device_type == UDM_DEVICETYPE_1141V11) ? 1 : 0;

  SSH_DEBUG(SSH_D_LOWOK, ("copy_pad is %d, device type is %d",
			  device->copy_pad, device->device_info.device_type));

#ifdef USERMODE_ENGINE
  ssh_register_signal(SIGUSR2, safenet_got_signal, device);

  device->pdr_notify.process_id = getpid();
  device->pdr_notify.signal_number = SIGUSR2;
#else /* USERMODE_ENGINE */
  /* Setting the notify callback to NULL would disable interrupts for
     the device. */
  if (device->polling)
    device->pdr_notify.callback = NULL_FNPTR;
  else
    device->pdr_notify.callback = ssh_safenet_pdr_cb;
#endif /* USERMODE_ENGINE */

  /* Uninitialize the deivce before testing for PCI swapping */
  udm_device_uninit(device->device_number);
  pci_swap = safenet_is_pci_swapping(device);

  /* Setup the initialization block */
  ssh_safenet_setup_init_block(device, pci_swap, &initblock);

  /* Initialize */
  status = udm_device_init(device->device_number, &initblock);

#ifdef SAFENET_DEBUG
  if (status != UDM_DRVSTAT_SUCCESS)
    {
      printk(KERN_NOTICE "Cannot determine the udm driver version %s\n",
             ssh_safenet_get_printable_status(status));
    }
#endif /* SAFENET_DEBUG */


#ifdef SSH_SAFENET_PROFILING
  if (status == UDM_DRVSTAT_SUCCESS && SSH_SAFENET_PROFILING_RATE_SEC)
    ssh_kernel_timeout_register(SSH_SAFENET_PROFILING_RATE_SEC, 0,
                                ssh_safenet_profile_timeout, (void *)device);
#endif /* SSH_SAFENET_PROFILING */

  return (status == UDM_DRVSTAT_SUCCESS);
}




void ssh_safenet_device_uninit(SshSafenetDevice device)
{
#ifdef SSH_SAFENET_PROFILING
  ssh_kernel_timeout_cancel(ssh_safenet_profile_timeout, (void *)device);
#endif /* SSH_SAFENET_PROFILING */

  udm_device_uninit(device->device_number);

  ssh_kernel_mutex_free(device->lock);
  memset(&device, 0, sizeof(device));
}


static Boolean safenet_hwaccel_init()
{
  SshSafenetDevice device;
  UDM_DEVICEINFO device_info;
  Boolean found = FALSE;
  UINT32 vers;
  int i, status;

  SSH_DEBUG(SSH_D_HIGHOK, ("Hardware acceleration initialization entered"));

  /* Get driver version. */
  status = udm_driver_version(&vers);

  if (status != UDM_DRVSTAT_SUCCESS)
    {
#ifdef SAFENET_DEBUG
      printk(KERN_NOTICE "Cannot determine the udm driver version %s\n",
             ssh_safenet_get_printable_status(status));
#endif /* SAFENET_DEBUG */

      goto fail;
    }

#ifdef SAFENET_DEBUG
  printk(KERN_NOTICE  "UDM version %x.%02x\n",
         (vers >> 24) & 0xff, (vers >> 16) &0xff);
#endif /* SAFENET_DEBUG */

  /* Get device info and store the number of devices */
  for (i = 0 ; i < SSH_UDM_MAX_DEVICES; i++)
    {
      status = udm_device_info(i, &device_info);

      if (status != UDM_DRVSTAT_SUCCESS)
        continue;

      /* We support the following device types at present */
      if (device_info.device_type != UDM_DEVICETYPE_1141V11 &&
          device_info.device_type != UDM_DEVICETYPE_1141 &&
	  device_info.device_type != UDM_DEVICETYPE_1841 &&
	  device_info.device_type != UDM_DEVICETYPE_EIP92B &&
#ifdef SSH_SAFENET_AMCC_SUPPORT
	  device_info.device_type != UDM_DEVICETYPE_EIP94 && 
#else
	  device_info.device_type != UDM_DEVICETYPE_EIP94C &&
#endif /* SSH_SAFENET_AMCC_SUPPORT */	  
	  device_info.device_type != UDM_DEVICETYPE_EIP94C_B)
        continue;

      found = TRUE;

      device = &devices[i];

#ifdef SSH_SAFENET_AMCC_SUPPORT	  
      if (device_info.device_type == UDM_DEVICETYPE_EIP94 ||
#else
      if (device_info.device_type == UDM_DEVICETYPE_EIP94C ||
#endif /* SSH_SAFENET_AMCC_SUPPORT */		
	  device_info.device_type == UDM_DEVICETYPE_EIP94C_B)
	device->is_eip94c = TRUE;

#ifdef SSH_SAFENET_USE_EMI_MEMORY
      if (device_info.device_type == UDM_DEVICETYPE_1841)
	device->use_emi_sa = TRUE;
#endif /* SSH_SAFENET_USE_EMI_MEMORY */

      device->polling = FALSE;
#ifdef SSH_SAFENET_POLLING
      device->polling = TRUE;
#endif /* SSH_SAFENET_POLLING */

      device->device_number = i;
      memcpy(&device->device_info, &device_info, sizeof(device_info));

      if (!ssh_safenet_device_init(device))
        {
#ifdef SAFENET_DEBUG
	  printk("Device init failed\n");
#endif /* SAFENET_DEBUG */
          goto fail;
        }

#ifdef SAFENET_DEBUG
      print_safenet_device_info(device);
#endif /* SAFENET_DEBUG */

      /* Insert the device to the global list */
      device->next = safenet_devices;
      safenet_devices = device;
    }

#ifdef SAFENET_DEBUG
  printk(KERN_NOTICE "The UDM_SA size is %d bytes and the UDM_STATE_RECORD "
	 "size is %d bytes", sizeof(UDM_SA), sizeof(UDM_STATE_RECORD));
#endif /* SAFENET_DEBUG */

  if (found)
    {
      if (!safenet_operation_freelist_alloc())
	goto fail;

      if (!safenet_hwaccel_freelist_alloc())
	goto fail;












      return TRUE;
    }
 fail:

  printk("Hardware acceleration initialization failed, using software "
	 "crypto\n");

  ssh_hwaccel_uninit();
  return FALSE;
}


void safenet_hwaccel_uninit()
{
  SshSafenetDevice device, next_device;

  device = safenet_devices;

  while (device)
    {
      next_device = device->next;
      ssh_safenet_device_uninit(device);
      device = next_device;
    }

#ifdef SAFENET_DEBUG
  printk(KERN_NOTICE "hwaccel uninit done\n");
#endif /* SAFENET_DEBUG */

  safenet_devices = NULL;

  safenet_operation_freelist_free();
  safenet_hwaccel_freelist_free();











}

Boolean ssh_hwaccel_init()
{
  return safenet_hwaccel_init();
}

void ssh_hwaccel_uninit()
{
  safenet_hwaccel_uninit();
  return;
}



/*********************** UDM specific code *********************/


/* Determine if data is being swapped across the PCI bus */
static Boolean safenet_is_pci_swapping(SshSafenetDevice device)
{
  int swap = FALSE;

  if (device->is_eip94c)
    return FALSE;

#ifdef CGX_BIG_ENDIAN
  int device_num = device->device_number;
  UINT32 d = 0;

  /* Set device's endian config register to disable all endian adjustment. */
  d = 0xe4e4e4e4;
  udm_bus_write(device_num, &d, 0xe0, sizeof(UINT32));

  /* Read the vendor/device id register. */
  udm_bus_read(device_num, &d, 0x84, sizeof(UINT32));

  /* If we did not get what we expected, assume swapping is
     ocurring over the PCI bus. */
  if (d != ((device->device_info.vendor_id << 16) |
            device->device_info.device_id))
    {
      swap = TRUE;
    }

#ifdef SAFENET_DEBUG
  printk(KERN_NOTICE "is pci swapping; d=0x%08x, swap=%d\n", d, swap);
#endif /* SAFENET_DEBUG */

#else /* CGX_BIG_ENDIAN */

#ifdef SAFENET_DEBUG
  printk(KERN_NOTICE " no pci swapping \n");
#endif /* SAFENET_DEBUG */
#endif /* CGX_BIG_ENDIAN */
  return swap;
}

void ssh_safenet_setup_init_block(SshSafenetDevice device,
                                  Boolean pci_swap,
                                  INIT_BLOCK *iblk)
{
  UINT16 pdr_poll_delay, pdr_delay_after;
  UINT32 pdr_int_count;

  memset((void *)iblk, 0, sizeof (INIT_BLOCK));

  if (device->device_info.device_type == UDM_DEVICETYPE_1841)
    {
      pdr_poll_delay = 0x1FF;
      pdr_delay_after = 0x1FF;
      pdr_int_count = 3;










    }
  else
    {
#ifdef SSH_SAFENET_AMCC_SUPPORT 
      /* EIP94 AMCC values */
      pdr_poll_delay = 0x8;
      pdr_delay_after = 0x8;
      pdr_int_count = 16;
#else /* SSH_SAFENET_AMCC_SUPPORT */
      pdr_poll_delay = 0x1;
      pdr_delay_after = 0x1;
      pdr_int_count = 1;
#endif /* SSH_SAFENET_AMCC_SUPPORT */
    }

  iblk->cdr_busid = UDM_BUSID_HOST;
  iblk->cdr_addr  = 0;
  iblk->cdr_entries = SSH_SAFENET_NR_CDR_ENTRIES;
  iblk->cdr_int_count = 1;
  iblk->cdr_int_type = 0x0100;
  iblk->cdr_poll_delay = 8;
  iblk->cdr_delay_after = 1;

  iblk->hpcdr_busid = UDM_BUSID_DISABLED;
  iblk->hpcdr_addr = 0;
  iblk->hpcdr_entries = 0;
  iblk->hpcdr_int_count	= 0;
  iblk->hpcdr_int_type = 0x0000;

  iblk->pdr_addr = 0;
  iblk->pdrr_addr = 0;
  iblk->pdr_entries = SSH_SAFENET_NR_PDR_ENTRIES;
  iblk->pdr_int_count = pdr_int_count;
  iblk->pdr_poll_delay = pdr_poll_delay;
  iblk->pdr_delay_after = pdr_delay_after;

  /* SAs are in host memory, created and managed by host. */
  iblk->sa_config = 0;
  iblk->sa_busid = UDM_BUSID_HOST;
  iblk->sa_addr = 0;
  iblk->sa_entries = 0;

  if (!device->is_eip94c)
    {
      iblk->dma_config = 0x03f0;
      iblk->pe_dma_config |= PE_DMA_CFG_RDR_BUSID_HOST;
    }
  else
    {
      iblk->dma_config = 0x00180006;
      iblk->pe_dma_config =   PE_DMA_CFG_PE_MODE
	| PE_DMA_CFG_PDR_BUSID_HOST
	| PE_DMA_CFG_GATH_BUSID_HOST
	| PE_DMA_CFG_SCAT_BUSID_HOST
	| PE_DMA_CFG_ENABLE_FAILSAFE;
    }

  /* Not using scatter/gather. */
  iblk->part_src_addr = 0;
  iblk->part_dst_addr = 0;
  iblk->part_config = 0;
  iblk->part_src_entries = 0;
  iblk->part_dst_entries = 0;

  iblk->int_config = 0;

#ifdef SSH_SAFENET_TARGET_REQUIRES_SWAP
  iblk->target_endian_mode	= 0xe41b;
#else /* SSH_SAFENET_TARGET_REQUIRES_SWAP */
  iblk->target_endian_mode	= pci_swap ? 0xe41b : 0xe4e4;
#endif /* SSH_SAFENET_TARGET_REQUIRES_SWAP */

#ifdef CGX_BIG_ENDIAN
  iblk->pe_endian_mode = 0xe41b;
#else
  iblk->pe_endian_mode = 0xe4e4;
#endif

  if (!device->is_eip94c)
    {
      iblk->pe_dma_config = PE_DMA_CFG_PE_MODE
	| PE_DMA_CFG_PDR_BUSID_HOST
	| PE_DMA_CFG_GATH_BUSID_HOST
	| PE_DMA_CFG_SCAT_BUSID_HOST
	| PE_DMA_CFG_ENABLE_FAILSAFE;
    }

  if (pci_swap)
    {
      iblk->pe_dma_config
	|= PE_DMA_CFG_ENDIAN_SWAP_DESC
	| PE_DMA_CFG_ENDIAN_SWAP_SA
	| PE_DMA_CFG_ENDIAN_SWAP_PART;
    }
  else
    {
      iblk->pe_dma_config |= PE_DMA_CFG_ENDIAN_SWAP_PKT;
    }

#if 0
  iblk->pdr_offset = (int) (sizeof(UDM_PD_REV1) / sizeof(UINT32));
#endif
  iblk->pdr_offset = 8;
  iblk->pe_dma_input_threshold = 0x0008;
  iblk->pe_dma_output_threshold = 0x0008;

  if (device->device_info.device_type == UDM_DEVICETYPE_1841)
    {
      iblk->bus_id_config = 0x00000001;
      iblk->pe_dma_config |= PE_DMA_CFG_RDR_BUSID_HOST;
    }
  else
    {
      iblk->pe_dma_config |= PE_DMA_CFG_ENABLE_FAILSAFE;
    }

  iblk->crashlog_busid = UDM_BUSID_HOST;
  iblk->crashlog_addr	= 0;
  iblk->chipinfo_busid = UDM_BUSID_HOST;
  iblk->chipinfo_addr  = 0;  /* let driver allocate */
  iblk->statusblock_busid = UDM_BUSID_HOST;
  iblk->statusblock_addr = 0;	 /* let driver allocate */
  iblk->intsrc_mailbox_busid = UDM_BUSID_HOST;
  iblk->intsrc_mailbox_addr = 0;
  iblk->kcs_busid = UDM_BUSID_DISABLED;
  iblk->kcs_addr = 0;
  iblk->token_busid = UDM_BUSID_DISABLED;
  iblk->token_addr = 0;
  iblk->software_timer_busid = UDM_BUSID_DISABLED;
  iblk->software_timer_addr = 0;

  iblk->online_int_type = 0x8100;
  iblk->fatalerror_int_type = 0x8100;
  iblk->resetack_int_type = 0x8100;



  iblk->kcr_start_page = 0;
  iblk->kcr_extended_cnt = 0;
  iblk->pf_active_low_int = 0;
  iblk->reserved = 0;
  iblk->max_cgx_pci_burst = 32;
  iblk->target_read_count = 1;

  iblk->dsp_mask_control = 0;
  iblk->dsp_int_config = 1;

  iblk->ext_map = 0x00000000;

  if (device->device_info.device_type == UDM_DEVICETYPE_1841)
    iblk->misc_options = UDM_MISC_OPTIONS_FORCE_PD_READ;

  if (device->use_emi_sa)
    {
      iblk->dram_config	   = 0x00000032;
      iblk->ext_memcfg	   = 0x00000020;
      iblk->refresh_timer  = 0x0000830b;
      iblk->ext_mem_wait   = 0x00000033;
    }
  else
    {
      iblk->dram_config    = 0x00000022;
      iblk->ext_memcfg     = 0x00000000;
      iblk->refresh_timer  = 0x00000490;
      iblk->ext_mem_wait   = 0x00000011;
    }

  iblk->dsp_pmdmiom_wait = 0x00000000;


  iblk->cdr_notify = &device->cdr_notify;
  iblk->pdr_notify = &device->pdr_notify;

  iblk->exp0_notify = NULL;
  iblk->exp2_notify = NULL;
  iblk->pkcp_notify = NULL;
  iblk->ppi_backdoor = NULL;

  iblk->user_boot_control = 0;
  iblk->user_boot_interrupt_to_force	= 0;
  iblk->user_boot_signblock_busid = UDM_BUSID_DISABLED;
  iblk->user_boot_signblock_addr = 0;

  iblk->udm_firmware = NULL;
}



/************** Debugging help funtions *************************/

const char *ssh_safenet_get_printable_status(int driver_status)
{
  switch (driver_status)
    {
    case UDM_DRVSTAT_SUCCESS:
      return "The operation was successful";
    case UDM_DRVSTAT_COMMAND_INVALID:
      return "The command was invalid";
    case UDM_DRVSTAT_DEVICE_INVALID :
      return "Invalid device number specified";
    case UDM_DRVSTAT_DEVICE_NOT_FOUND :
      return "Device not found";
    case UDM_DRVSTAT_DEVICE_NOT_INIT :
      return "Device not initialized";
    case UDM_DRVSTAT_CDR_FULL :
      return "CDR queue full";
    case UDM_DRVSTAT_PDR_FULL :
      return "PDR command queue full";
    case UDM_DRVSTAT_MALLOC_ERR :
      return "No memory available";
    case UDM_DRVSTAT_UPLOAD_ERR :
      return "Device upload error";
    case UDM_DRVSTAT_INIT_FAIL :
      return "Device initialization failed";
    case UDM_DRVSTAT_CDR_EMPTY :
      return "CDR queue empty";
    case UDM_DRVSTAT_PDR_EMPTY :
      return "PDR queue  empty";
    case UDM_DRVSTAT_GDR_FULL :
      return "GDR queue full";
    case UDM_DRVSTAT_IOCTL_ERR :
      return "IOCTL error";
    case UDM_DRVSTAT_USERMODE_API_ERR :
      return "Usermode API error";
    case UDM_DRVSTAT_BAD_PARAM_CDR_BUSID :
      return "Bad CDR Busid parameter";
    case UDM_DRVSTAT_BAD_PARAM_CDR_ENTRIES :
      return "Bad CDR entry parameter";
    case UDM_DRVSTAT_BAD_PARAM_CDR_POLL_DELAY :
      return "Bad CDR poll delay specified";
    case UDM_DRVSTAT_BAD_PARAM_CDR_DELAY_AFTER :
      return "Bad CDR delay after parameter";
    case UDM_DRVSTAT_BAD_PARAM_CDR_INT_COUNT :
      return "Bad CDR count int parameter";
    case UDM_DRVSTAT_BAD_PARAM_PDR_BUSID :
      return "Bad PDR busid";
    case UDM_DRVSTAT_BAD_PARAM_PDR_ENTRIES :
      return "Bad number of PDR entries";
    case UDM_DRVSTAT_BAD_PARAM_PDR_POLL_DELAY :
      return "Bad PDR poll delay";
    case UDM_DRVSTAT_BAD_PARAM_PDR_DELAY_AFTER :
      return "Bad PDR delay after parameter";
    case UDM_DRVSTAT_BAD_PARAM_PDR_INT_COUNT :
      return "Bad PDR int count parameter";
    case UDM_DRVSTAT_BAD_PARAM_PDR_OFFSET :
      return "Bad PDR offset";
    case UDM_DRVSTAT_BAD_PARAM_SA_BUSID :
      return "Bad SA busid";
    case UDM_DRVSTAT_BAD_PARAM_SA_ENTRIES :
      return "Bad number of SA entries";
    case UDM_DRVSTAT_BAD_PARAM_SA_CONFIG :
      return "Bad SA configuration parameter";
    case UDM_DRVSTAT_BAD_PARAM_PAR_SRC_BUSID :
      return "Bad PAR source busid";
    case UDM_DRVSTAT_BAD_PARAM_PAR_SRC_SIZE :
      return "Bad PAR source size";
    case UDM_DRVSTAT_BAD_PARAM_PAR_DST_BUSID :
      return "Bad PAR desitination busid";
    case UDM_DRVSTAT_BAD_PARAM_PAR_DST_SIZE :
      return "Bad PAR destination size";
    case UDM_DRVSTAT_BAD_PARAM_PAR_CONFIG :
      return "Bad configuration parameter";
    case UDM_DRVSTAT_INTERNAL_ERR :
      return "Internal error";
    default:
      return "Unknown Status";
    }
}

#ifdef SAFENET_DEBUG
static void print_safenet_device_info(SshSafenetDevice device)
{
  UDM_DEVICEINFO info = device->device_info;

  printk(KERN_NOTICE " Printing Device Info for device %d....\n",
         device->device_number);

  printk(KERN_NOTICE " Device number:    %d\n", info.device_num);
  printk(KERN_NOTICE " Device type:      %x\n", info.device_type);
  printk(KERN_NOTICE " Base address:     %x\n", info.base_addr);
  printk(KERN_NOTICE " Address length:   %x\n", info.addr_len);
  printk(KERN_NOTICE " Vendor id:        %x\n", info.vendor_id);
  printk(KERN_NOTICE " Device id:        %x\n", info.device_id);

  if (info.features & DEVICEINFO_FEATURES_PE)
    printk(KERN_NOTICE "Packet engine is present\n");

  if (info.features & DEVICEINFO_FEATURES_HE)
    printk(KERN_NOTICE "Hash /Encrypt engine is present\n");

  if (info.features & DEVICEINFO_FEATURES_RNG)
    printk(KERN_NOTICE "RNG is present\n");

  if (info.features & DEVICEINFO_FEATURES_PKCP)
    printk(KERN_NOTICE "Public key coprocessor is present\n");

  if (info.features & DEVICEINFO_FEATURES_KMR)
    printk(KERN_NOTICE "Key management ring is present\n");

  if (info.features & DEVICEINFO_FEATURES_KCR)
    printk(KERN_NOTICE "KCR is present\n");

  if (info.features & DEVICEINFO_FEATURES_PKCP_PKE)
    printk(KERN_NOTICE "Public key accelerator present\n");

  if (info.features & DEVICEINFO_FEATURES_PKCP_PKECRT)
    printk(KERN_NOTICE "CRT algorithm is present\n");

  if (info.crypto_algs & DEVICEINFO_CRYPTO_ALGS_TDES)
    printk(KERN_NOTICE "TDES crypto algorithm is supported\n");

  if (info.crypto_algs & DEVICEINFO_CRYPTO_ALGS_DES)
    printk(KERN_NOTICE "DES crypto algorithm is supported\n");

  if (info.crypto_algs & DEVICEINFO_CRYPTO_ALGS_AES)
    printk(KERN_NOTICE "AES crypto algorithm is supported\n");

  if (info.crypto_algs & DEVICEINFO_CRYPTO_ALGS_ARCFOUR)
    printk(KERN_NOTICE "ARCFOUR crypto algorithm is supported\n");

  if (info.crypto_algs & DEVICEINFO_CRYPTO_ALGS_RC5)
    printk(KERN_NOTICE "RC5 crypto algorithm is supported\n");

  if (info.hash_algs & DEVICEINFO_HASH_ALGS_SHA1)
    printk(KERN_NOTICE "SHA1 hash algorithm is supported\n");

  if (info.hash_algs & DEVICEINFO_HASH_ALGS_MD5)
    printk(KERN_NOTICE "MD5 hash algorithm is supported\n");

  if (info.hash_algs & DEVICEINFO_HASH_ALGS_MD2)
    printk(KERN_NOTICE "MD2 hash algorithm is supported\n");

  if (info.hash_algs & DEVICEINFO_HASH_ALGS_RIPEMD128)
    printk(KERN_NOTICE "Ripemd128 hash algorithm is supported\n");

  if (info.hash_algs & DEVICEINFO_HASH_ALGS_RIPEMD160)
    printk(KERN_NOTICE "Ripemd160 hash algorithm is supported\n");

  if (info.comp_algs & DEVICEINFO_COMP_ALGS_DEFLATE)
    printk(KERN_NOTICE "Deflate compression algorithm is supported\n");

  if (info.pkt_ops & DEVICEINFO_PKT_OPS_ESP)
    printk(KERN_NOTICE "ESP transform is supported\n");

  if (info.pkt_ops & DEVICEINFO_PKT_OPS_AH)
    printk(KERN_NOTICE "AH transform is supported\n");

  if (info.pkt_ops & DEVICEINFO_PKT_OPS_IPCOMP)
    printk(KERN_NOTICE "IPComp transform is supported\n");

  return;
}
#endif /* SAFENET_DEBUG */


#ifdef SAFENET_DEBUG_HEAVY

static const char *opcode_text(UINT32 idx)
{
  switch (idx)
    {
    case SA_OPCODE_ENCRYPT: return "ENCRYPT";
    case SA_OPCODE_ENCRYPT_HASH: return "ENCRYPT-HASH";
    case SA_OPCODE_HASH: return "HASH";
    case SA_OPCODE_DECRYPT: return "DECRYPT";
    case SA_OPCODE_HASH_DECRYPT: return "HASH-DECRYPT";
    case SA_OPCODE_ESP_OUTBOUND: return "ESP-OUTBOUND";
    case SA_OPCODE_AH_OUTBOUND: return "AH-OUTBOUND";
    case SA_OPCODE_ESP_INBOUND: return "ESP-INBOUND";
    case SA_OPCODE_AH_INBOUND: return "AH-INBOUND";
    default:
      return "reserved";
    }
};

static const char *crypto_algo_text(UINT32 idx)
{
  switch (idx)
    {
    case SA_CRYPTO_DES:  return "DES";
    case SA_CRYPTO_TDES: return "3DES";
    case SA_CRYPTO_ARC4: return "ARC4";
    case SA_CRYPTO_AES:  return "AES";
    case SA_CRYPTO_NULL: return "NULL";
    default:
      return "reserved";
    }
};

static const char *hash_algo_text(UINT32 idx)
{
  switch (idx)
    {
    case SA_HASH_SHA1: return "SHA1";
    case SA_HASH_MD5:  return "MD5";
    case SA_HASH_NULL:  return "NULL";
    default:
      return "reserved";
    }
};

static const char *crypto_mode_text(UINT32 idx)
{
  switch (idx)
    {
    case SA_CRYPTO_MODE_ECB: return "ECB";
    case SA_CRYPTO_MODE_CBC: return "CBC";
    case SA_CRYPTO_MODE_OFB: return "OFB";
    case SA_CRYPTO_MODE_CFB: return "CFB";
    default:
      return "reserved";
    }
};

static const char *crypto_feedback_text(UINT32 idx)
{
  switch (idx)
    {
    case SA_CRYPTO_FEEDBACK_64: return "64-bit";
    case SA_CRYPTO_FEEDBACK_8:  return "8-bit";
    case SA_CRYPTO_FEEDBACK_1:  return "1-bit";
    default:
      return "reserved";
    }
};

static const char *crypto_pad_text(UINT32 idx)
{
  switch (idx)
    {
    case SA_PAD_IPSEC:    return "IPSEC";
    case SA_PAD_PKCS7:    return "PKCS#7";
    case SA_PAD_CONSTANT: return "CONSTANT";
    case SA_PAD_ZERO:     return "ZERO";
    default:
      return "reserved";
    }
};

static const char *iv_loading_text(UINT32 idx)
{
  switch (idx)
    {
    case SA_IV_REUSE: return "REUSE";
    case SA_IV_INPUT: return "INPUT";
    case SA_IV_STATE: return "STATE";
    default:
      return "reserved";
    }
};

static const char *hash_loading_text(UINT32 idx)
{
  switch (idx)
    {
    case SA_HASH_SA:      return "SA";
    case SA_HASH_STATE:   return "STATE";
    case SA_HASH_NO_LOAD: return "NO LOAD";
    default:
      return "reserved";
    }
};

static void print_safenet_pkt(UDM_PKT *pkt)
{
  UDM_PKT_BITS *pktb = (UDM_PKT_BITS *)pkt;

  SSH_DEBUG(10, ("print_safenet_pkt; pkt = 0x%p", pkt));
  SSH_DEBUG(10, ("src = 0x%p", pkt->src));
  SSH_DEBUG(10, ("dst = 0x%p", pkt->dst));
  SSH_DEBUG(10, ("sa = 0x%p", pkt->sa));
  SSH_DEBUG(10, ("srec = 0x%p", pkt->srec));
  SSH_DEBUG(10, ("user_handle = 0x%p", pkt->user_handle));
  SSH_DEBUG(10, ("ready/done 1 = %d/%d", pktb->ready1, pktb->done1));
  SSH_DEBUG(10, ("pad_control = %x", pktb->pad_control));
  SSH_DEBUG(10, ("load_sa_digests = %d", pktb->load_sa_digests));
  SSH_DEBUG(10, ("hash_final = %d", pktb->hash_final));
  SSH_DEBUG(10, ("status = 0x%02x", pktb->status));
  SSH_DEBUG(10, ("len = %d", pktb->len));
  SSH_DEBUG(10, ("ready/done 2 = %d/%d", pktb->ready2, pktb->done2));
  SSH_DEBUG(10, ("bypass_offset = %d", pktb->bypass_offset));
  SSH_DEBUG(10, ("\n"));
}

static void print_safenet_sa(UDM_SA *sa)
{
  SSH_DEBUG(10, ("print_safenet_sa; sa=0x%08x", (int)sa));
  SSH_DEBUG(10, ("opcode = 0x%02x(%s)",
		 sa->rev1.opcode, opcode_text(sa->rev1.opcode)));
  SSH_DEBUG(10, ("crypto_pad = 0x%02x(%s)",
                 sa->rev1.crypto_pad, crypto_pad_text(sa->rev1.crypto_pad)));
  SSH_DEBUG(10, ("crypto_algo = 0x%02x(%s)",
                 sa->rev1.crypto_algo,
                 crypto_algo_text(sa->rev1.crypto_algo)));
  SSH_DEBUG(10, ("hash_algo = 0x%02x(%s)",
                 sa->rev1.hash_algo, hash_algo_text(sa->rev1.hash_algo)));
  SSH_DEBUG(10, ("header_proc = %d", sa->rev1.header_proc));
  SSH_DEBUG(10, ("iv_loading = 0x%02x(%s)",
                 sa->rev1.iv_loading, iv_loading_text(sa->rev1.iv_loading)));
  SSH_DEBUG(10, ("hash_loading = 0x%02x(%s)",
                 sa->rev1.hash_loading,
                 hash_loading_text(sa->rev1.hash_loading)));
  SSH_DEBUG(10, ("save_iv/hash = %d/%d",
                 sa->rev1.save_iv, sa->rev1.save_hash));
  SSH_DEBUG(10, ("copy_header/payload/pad = %d/%d/%d",
                 sa->rev1.copy_header, sa->rev1.copy_payload,
                 sa->rev1.copy_pad));
  SSH_DEBUG(10, ("mutable_bits = %d", sa->rev1.mutable_bits));
  SSH_DEBUG(10, ("crypto_mode = 0x%02x(%s)",
                 sa->rev1.crypto_mode,
                 crypto_mode_text(sa->rev1.crypto_mode)));
  SSH_DEBUG(10, ("crypto_feedback = 0x%02x(%s)",
                 sa->rev1.crypto_feedback,
                 crypto_feedback_text(sa->rev1.crypto_feedback)));
  SSH_DEBUG(10, ("hmac = %d", sa->rev1.hmac));
  SSH_DEBUG(10, ("aes_decrypt_key = %d", sa->rev1.aes_decrypt_key));
  SSH_DEBUG(10, ("aes_key_len = %d", sa->rev1.arc4_aes_key_len));
  SSH_DEBUG(10, ("rev = %d", sa->rev1.rev));
  SSH_DEBUG(10, ("offset = %d", sa->rev1.offset));
  SSH_DEBUG(10, ("spi = 0x%08x", sa->rev1.spi));
  SSH_DEBUG(10, ("seq = 0x%08x", sa->rev1.seq));
  SSH_DEBUG(10, ("srec = 0x%08x", (int)sa->rev1.srec));
  SSH_DEBUG_HEXDUMP(10, ("key1 = "), sa->rev1.key1, sizeof (sa->rev1.key1));
  SSH_DEBUG_HEXDUMP(10, ("key2 = "), sa->rev1.key2, sizeof (sa->rev1.key2));
  SSH_DEBUG_HEXDUMP(10, ("key3 = "), sa->rev1.key3, sizeof (sa->rev1.key3));
  SSH_DEBUG_HEXDUMP(10, ("key4 = "), sa->rev1.key4, sizeof (sa->rev1.key4));
  SSH_DEBUG_HEXDUMP(10, ("inner = "), sa->rev1.inner, sizeof (sa->rev1.inner));
  SSH_DEBUG_HEXDUMP(10, ("outer = "), sa->rev1.outer, sizeof (sa->rev1.outer));
  SSH_DEBUG(10, ("\n"));
}

static void print_safenet_srec(UDM_STATE_RECORD *srec)
{
  SSH_DEBUG(10, ("print_safenet_srec(); srec=0x%08x", (int)srec));
  SSH_DEBUG(10, ("hash_count = %d", srec->rev1.hash_count));

  SSH_DEBUG_HEXDUMP(10, ("srec IV"),
                    (unsigned char *)srec->rev1.iv,
                    sizeof(srec->rev1.iv));

  SSH_DEBUG_HEXDUMP(10, ("srec inner digest"),
                    (unsigned char *)srec->rev1.inner,
                    sizeof(srec->rev1.inner));
  SSH_DEBUG(10, ("\n"));
}
#endif /* SAFENET_DEBUG_HEAVY */


/****************** Unsupported Operations *******************/



SshHWAccel ssh_hwaccel_alloc_ipcomp(SshInterceptor interceptor,
                                    Boolean compress,
                                    const char *compression_name)

{
  return NULL;
}


void ssh_hwaccel_perform_ipcomp(SshHWAccel accel,
                                SshInterceptorPacket pp,
                                size_t offset,
                                size_t len,
                                SshHWAccelCompletion completion,
                                void *completion_context)
{
  SSH_NOTREACHED;
}


void ssh_hwaccel_perform_modp(const SshHWAccelBigInt b,
                              const SshHWAccelBigInt e,
                              const SshHWAccelBigInt m,
                              SshHWAccelModPCompletion callback,
                              void *callback_context)
{
  (*callback)(NULL, callback_context);
}


void ssh_hwaccel_get_random_bytes(size_t bytes_requested,
                                  SshHWAccelRandomBytesCompletion callback,
                                  void *callback_context)
{
  (*callback)(NULL, 0, callback_context);
}


void ssh_hwaccel_free(SshHWAccel accel)
{
  return;
}

SshHWAccel ssh_hwaccel_alloc_ipsec(SshInterceptor interceptor,
				   Boolean  encrypt,
				   const char * cipher_name,
				   const unsigned char * cipher_key,
				   size_t cipher_key_len,
				   const unsigned char * cipher_nonce,
				   size_t cipher_nonce_len,
				   Boolean ah_style_mac,
				   const char * mac_name,
				   const unsigned char * mac_key,
				   size_t mac_key_len)
{
  return NULL;
}

void ssh_hwaccel_perform_ipsec(SshHWAccel accel,
                               SshInterceptorPacket pp,
                               size_t encrypt_iv_offset,
                               size_t encrypt_len_incl_iv,
                               size_t mac_start_offset,
                               size_t mac_len,
                               size_t icv_offset,
                               SshHWAccelCompletion completion,
                               void *completion_context)
{
  SSH_NOTREACHED;
}









































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































