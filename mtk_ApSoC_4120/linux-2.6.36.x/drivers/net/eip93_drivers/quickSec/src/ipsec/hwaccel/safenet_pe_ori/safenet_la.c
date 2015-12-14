/*
  safenet_la.c

  Copyright:
  Copyright (c) 2007 - 2009 SFNT Finland Oy.
  All rights reserved.

  Implementation of Quicksec HWACCEL interface for some SafeNet 
  Look-Aside Chips.
*/

#include "sshincludes.h"
#include "sshtimeouts.h"
#include "safenet_la_params.h"
#include "safenet_pe.h"

#ifdef KERNEL
#ifdef __linux__
#include "linux_internal.h"

#include <linux/time.h>
#include <linux/timer.h>
#include <linux/bitops.h>
#include <linux/interrupt.h>

#include <linux/sched.h>
#include <linux/delay.h>
#include <linux/kernel.h>

#endif /* __linux__ */
#endif /* KERNEL */
	
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

#undef SSH_DEBUG_MODULE
#define SSH_DEBUG_MODULE "SshSafenet174x"

#ifdef VXWORKS
#error "VxWorks is not supported by this version."
#endif /* VXWORKS */

#ifdef USERMODE_ENGINE
#error "Usermode engine not supported by this version."
#endif /* USERMODE_ENGINE */


#define SSH_SAFENET_AH_HDRLEN 24

#ifndef KERNEL
#undef SSH_SAFENET_PACKET_IS_DMA
#define ssh_kernel_alloc(a,b) ssh_malloc(a)
#define ssh_kernel_free ssh_free
#define printk printf

#define ssh_kernel_timeout_register(a,b,c,d) ssh_register_timeout(NULL,a,b,c,d)
#define ssh_kernel_timeout_cancel(a,b) ssh_cancel_timeouts(a,b)
#endif /* KERNEL */

#undef SAFENET_PE_LA_PACKETBUFFER_DMACHECK

typedef struct SshSafenetDeviceRec
{
  SshUInt32 device_number;
  Boolean timer_running;

  /* Do we use polling mode or interrupt mode. */
  Boolean polling;

  SshKernelMutex operation_lock;
  SshUInt32 operation_count;
  SshUInt32 session_count;

  /* Fromhw side (i.e. packet from the HW locks etc..) */
  SshKernelMutex fromhw_lock;
  Boolean processing_fromhw;
  Boolean redo_fromhw_processing;

  /* Per device fromhw packets. */
  PE_PKT_DESCRIPTOR fromhw_pkt[2 * SSH_SAFENET_PDR_GET_COUNT];

  /* Tohw side (i.e. packet to the HW locks etc..) */
  SshKernelMutex tohw_lock;
  SshUInt32 tohw_pktdesc_count;
  SshUInt32 pending_pktdesc_count;
  Boolean processing_tohw;
  Boolean redo_tohw_processing;
  PE_PKT_DESCRIPTOR tohw_descriptors[2 * SSH_SAFENET_MAX_QUEUED_OPERATIONS];
  PE_PKT_DESCRIPTOR pending_descriptors[2 * SSH_SAFENET_MAX_QUEUED_OPERATIONS];
} SshSafenetDeviceStruct, *SshSafenetDevice;

typedef struct SshSafenetDevicesRec
{
  SshUInt16 packet_id;
  
  SshUInt16  num_devices;
  SshSafenetDeviceStruct safenet_device[PE_MAX_DEVICES];
} SshSafenetDevicesStruct, *SshSafenetDevices;

typedef struct SshSafenetOperationRec 
{
  SshSafenetDevice device;

  SshHWAccel accel;

  /* Original packet */
  SshInterceptorPacket pp;
  PE_PKT_DESCRIPTOR pkt;
  
  /* header length of fromhw packet */
  size_t hdrlen;
  
  /* offset of where to update the IPv6 next header field */
  size_t ipsec_offset_prevnh;
  unsigned char *packet;
  
  SshUInt8 ah_esp; /* 1 if doing a combined AH ESP operation */
  SshUInt8 esp;    /* 1 if doing an ESP operation */
  SshUInt8 ah;     /* 1 if doing an AH operation */
  
  /* notify callback and relevant data for completion of 
     the operation. */
  SshHWAccelCompletion completion;
  void *completion_context;
  void *original_src;
} SshSafenetOperationStruct, *SshSafenetOperation;

typedef struct HwAccelTransformRec 
{
  void *sa;
  size_t sa_len;
} *HwAccelTransform, HwAccelTransformStruct;

struct SshHWAccelRec 
{
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
  unsigned char hdr[SSH_IPH6_HDRLEN];
  
  /* The amount of bytes (excluding ESP padding) added to the packet
     length by the outbound IPSec transform. For an inbound transform the
     packet will be reduced by this length. */
  SshUInt16 added_len;
};

/* Global list for all Safenet devices on the PCI-bus */
static SshSafenetDevicesStruct safenet_devices;

/* Forward declarations */
void safenet_operation_complete(SshSafenetOperation op);
void ssh_hwaccel_perform_operation(SshSafenetOperation op,
				   SshSafenetDevice device);
static Boolean safenet_hwaccel_init(void);

#ifdef SSH_SAFENET_PKTGET_TIMER
void safenet_pktget_timer_cb(void *context);
#endif /* SSH_SAFENET_PKTGET_TIMER */

static SshSafenetOperation op_freelist = NULL;
static SshKernelMutex op_freelist_mutex = NULL;

static SshHWAccel accel_freelist = NULL;
static SshKernelMutex accel_freelist_mutex = NULL;

static __inline SshSafenetDevice
ssh_safenet_device_get(SshUInt32 device_number)
{
  register int i;
  SshSafenetDevice device;

  for (i = 0; safenet_devices.num_devices; i++)
    {
      device = &safenet_devices.safenet_device[i];

      if (device->device_number == device_number)
        return device;
    }

  return NULL;
}

static __inline void 
safenet_freelist_free(void *list)
{
  void *next;

  SSH_DEBUG(SSH_D_HIGHOK, ("Freeing %p", list));

  while (list)
    {
      next = *((void **)list);
      ssh_free(list);
      list = next;
    }
}

static __inline void *
safenet_freelist_alloc(int count, int size)
{
  void *list = NULL;
  void *item;
  int i;

  SSH_DEBUG(SSH_D_HIGHOK, ("Allocating count %d of size %d",
                           count, size));

  for (i = 0; i < count; i++)
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
  do                                                    \
    {                                                   \
      (item) = (void *)(list);                          \
      if (list)                                         \
        (list) = *((void **)(item));                    \
    }                                                   \
  while (0)

#define SAFENET_FREELIST_GET(item, list, mutex)         \
  do                                                    \
    {                                                   \
      ssh_kernel_mutex_lock(mutex);                     \
      SAFENET_FREELIST_GET_NO_LOCK(item, list);         \
      ssh_kernel_mutex_unlock(mutex);                   \
    }                                                   \
  while (0)

#define SAFENET_FREELIST_PUT_NO_LOCK(item, list)        \
  do                                                    \
    {                                                   \
      *((void **)(item)) = (list);                      \
      (list) = (void *)(item);                          \
    }                                                   \
  while (0)

#define SAFENET_FREELIST_PUT(item, list, mutex)         \
  do                                                    \
    {                                                   \
      ssh_kernel_mutex_lock(mutex);                     \
      SAFENET_FREELIST_PUT_NO_LOCK(item, list);         \
      ssh_kernel_mutex_unlock(mutex);                   \
    }                                                   \
  while (0)

static void safenet_operation_freelist_free(void)
{
  if (op_freelist)
    safenet_freelist_free(op_freelist);
  op_freelist = NULL;

  if (op_freelist_mutex)
    ssh_kernel_mutex_free(op_freelist_mutex);
  op_freelist_mutex = NULL;
}

static Boolean safenet_operation_freelist_alloc(void)
{
  op_freelist_mutex = ssh_kernel_mutex_alloc();
  if (op_freelist_mutex == NULL)
    return FALSE;
  
  op_freelist = (struct SshSafenetOperationRec *)safenet_freelist_alloc(
                                   2 * SSH_SAFENET_MAX_QUEUED_OPERATIONS, 
                                   sizeof(struct SshSafenetOperationRec));
  
  if (op_freelist == NULL)
    {
      ssh_kernel_mutex_free(op_freelist_mutex);
      return FALSE;
    }

  return TRUE;
}

#define SAFENET_OPERATION_FREELIST_GET(op)                      \
  SAFENET_FREELIST_GET(op, op_freelist, op_freelist_mutex)

#define SAFENET_OPERATION_FREELIST_PUT(op)                      \
  SAFENET_FREELIST_PUT(op, op_freelist, op_freelist_mutex)

static __inline void
safenet_hwaccel_freelist_free(void)
{
  SSH_DEBUG(SSH_D_NICETOKNOW, ("Freeing HWaccel freelist."));

  if (accel_freelist)
    safenet_freelist_free(accel_freelist);
  accel_freelist = NULL;

  if (accel_freelist_mutex)
    ssh_kernel_mutex_free(accel_freelist_mutex);
  accel_freelist_mutex = NULL;
}

static __inline Boolean 
safenet_hwaccel_freelist_alloc(void)
{
  SSH_DEBUG(SSH_D_NICETOKNOW, ("Allocating HWaccel freelist"));
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

  return TRUE;
}

#define SAFENET_HWACCEL_FREELIST_GET(accel)                              \
  SAFENET_FREELIST_GET(accel, accel_freelist, accel_freelist_mutex)

#define SAFENET_HWACCEL_FREELIST_PUT(accel)                              \
  SAFENET_FREELIST_PUT(accel, accel_freelist, accel_freelist_mutex)

/************************************************************************/

/* A macro to dump a packet. */
#define SSH_DUMP_PACKET(level, str, pp)                                  \
  do                                                                     \
    {                                                                    \
      size_t packet_len, len;                                            \
      const unsigned char *seg;                                          \
                                                                         \
      packet_len = ssh_interceptor_packet_len(pp);                       \
      SSH_DEBUG((level), ("%s (len=%ld, protocol=%d, flags=0x%lx)",      \
                     (str), (long)packet_len, pp->protocol,pp->flags));  \
                                                                         \
      ssh_interceptor_packet_reset_iteration(pp, 0, packet_len);         \
      while (ssh_interceptor_packet_next_iteration_read(pp, &seg, &len)) \
        SSH_DEBUG_HEXDUMP((level), ("seg len %lx:", (long)len), seg,     \
                          len);                                          \
                                                                         \
      if (seg != NULL)                                                   \
        ssh_fatal("SSH_DUMP_PACKET freed the packet");                   \
    }                                                                    \
  while (0)


/* Update the IP header and upper layer checksums after NAT-T and ESP
   transport mode decapsulation is performed. This frees 'pp' on error. */
Boolean 
ssh_hwaccel_natt_update_header(SshHWAccel accel, 
                               SshInterceptorPacket pp,
                               size_t hdrlen)
{
  unsigned char *ucp;
  SshUInt16 cksum;
 
  SSH_ASSERT((accel->flags & HWACCEL_FLAGS_TUNNEL) == 0);
 
  SSH_DEBUG(SSH_D_NICETOKNOW, ("Updating natt header."));

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

  /* Prevent packet checksum calculation in HW. */
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

  SSH_DEBUG(SSH_D_NICETOKNOW, ("Computing IPv6 hdrlen."));

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
      {
        if (offset + SSH_IP6_EXT_ROUTING_HDRLEN > packet_len)
          return FALSE;
       
        ssh_interceptor_packet_copyout(pp, offset, buf,
                                       SSH_IP6_EXT_ROUTING_HDRLEN);
       
        prev_nh_ofs = offset + SSH_IP6_EXT_COMMON_OFS_NH;
        next = SSH_IP6_EXT_ROUTING_NH(buf);
       
        offset += 8 + 8 * SSH_IP6_EXT_ROUTING_LEN(buf);
        goto next_extension_header;
      }

    case SSH_IPPROTO_IPV6OPTS: /* Destination options header. */
      {
        if (offset + SSH_IP6_EXT_DSTOPTS_HDRLEN > packet_len)
          return FALSE;

        ssh_interceptor_packet_copyout(pp, offset, buf, 2);
        prev_nh_ofs = offset + SSH_IP6_EXT_COMMON_OFS_NH;
        offset += SSH_IP6_EXT_DSTOPTS_LENB(buf);
        next = SSH_IP6_EXT_DSTOPTS_NH(buf);

        goto next_extension_header;
      }

    case SSH_IPPROTO_IPV6FRAG: /* Fragment header. */
      {
        if (offset + SSH_IP6_EXT_FRAGMENT_HDRLEN > packet_len)
          return FALSE;
      
        ssh_interceptor_packet_copyout(pp, offset, buf,
                                       SSH_IP6_EXT_FRAGMENT_HDRLEN);
      
        prev_nh_ofs = offset + SSH_IP6_EXT_FRAGMENT_OFS_NH;
        offset += SSH_IP6_EXT_FRAGMENT_HDRLEN;
        next = SSH_IP6_EXT_FRAGMENT_NH(buf);
        goto next_extension_header;
      }

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

/* Use this to get completed operations */
void 
ssh_safenet_pdr_bh_cb(SshSafenetDevice device, void *context)
{
  SshUInt32 count = 0, i = 0; 
  SshSafenetOperation  op = NULL;

  ssh_kernel_mutex_lock(device->fromhw_lock);
  if (device->processing_fromhw)
    {
      device->redo_fromhw_processing = 1;
      ssh_kernel_mutex_unlock(device->fromhw_lock);
      return;
    }

  device->processing_fromhw = 1;
  ssh_kernel_mutex_unlock(device->fromhw_lock);

 redo:
  op = NULL;

  if (safenet_pe_pktget(device->device_number, 
                        device->fromhw_pkt, 
                        (uint32_t *)&count))
    {
      for(i = 0; i < count; i++)
        {    
          op = (SshSafenetOperation)device->fromhw_pkt[i].user_handle;

          memcpy(&op->pkt, &device->fromhw_pkt[i], sizeof(PE_PKT_DESCRIPTOR));

          safenet_operation_complete(op);
        }

      ssh_kernel_mutex_lock(device->operation_lock);
      device->operation_count -= count;
      ssh_kernel_mutex_unlock(device->operation_lock);
    }
  else
    {
      SSH_DEBUG(SSH_D_FAIL, ("Cannot retrieve packets from the pdr ring")); 
    }
  
  /* Recursion check. Do we need to poll again the packets (i.e. 
     has someone else called this function during we've been running). */
  ssh_kernel_mutex_lock(device->fromhw_lock);
  if (device->redo_fromhw_processing == 1)
    {
      device->redo_fromhw_processing = 0;
      ssh_kernel_mutex_unlock(device->fromhw_lock);
      goto redo;
    }
  
  device->processing_fromhw = 0;
  ssh_kernel_mutex_unlock(device->fromhw_lock);
}

/* The PE notify callback. */
void ssh_safenet_pdr_cb(int device_num)
{
  SshSafenetDevice device = ssh_safenet_device_get(device_num);
  
  SSH_ASSERT(device->polling == 0);
  SSH_DEBUG(SSH_D_NICETOKNOW, ("Packets indicated by interrupt."));

  SSH_ASSERT(device != NULL);
    
  ssh_safenet_pdr_bh_cb(device, NULL);
}


/*********************************************************************/
void safenet_operation_complete(SshSafenetOperation op)
{
  SshInterceptorPacket pp = NULL;
  SshHWAccel accel = NULL;
  PE_PKT_DESCRIPTOR *pkt = NULL;
  unsigned char *ucp = NULL;
  size_t return_len, len, head_strip_len;
  size_t head_strip_ofs = 0;
  SshUInt8 tunnel;
  SshUInt16 cks;
  unsigned char proto;
  SshHWAccelResultCode rc = SSH_HWACCEL_FAILURE;
  
  return_len = len = 0;
  accel = op->accel;

  pkt = &op->pkt;

  if (op->ah_esp)
    tunnel = (op->esp && (accel->flags & HWACCEL_FLAGS_TUNNEL)) ? 1 : 0;
  else
    tunnel = (accel->flags & HWACCEL_FLAGS_TUNNEL) ? 1 : 0;
  
  if (pkt->status != PE_PKT_STATUS_OK)
    {
      if (pkt->status & PE_PKT_STATUS_ICV_FAILURE)
	{
	  rc = SSH_HWACCEL_ICV_FAILURE;
	  SSH_DEBUG(SSH_D_FAIL, ("Authentication failure"));
          goto fail;
        }
      
      if (pkt->status & PE_PKT_STATUS_PAD_FAILURE)
	{
	  rc = SSH_HWACCEL_PAD_FAILURE;
	  SSH_DEBUG(SSH_D_FAIL, ("Crypto padding failure"));
          goto fail;
	}
      
      if (pkt->status & PE_PKT_STATUS_FAILURE)
	{
	  rc = SSH_HWACCEL_FAILURE;
	  SSH_DEBUG(SSH_D_FAIL, ("Extended error"));
          goto fail;
	}
      
      if ((pkt->status & PE_PKT_STATUS_SEQ_FAILURE) &&
          (accel->flags & HWACCEL_FLAGS_ANTIREPLAY))
	{
	  rc = SSH_HWACCEL_SEQ_FAILURE;
	  SSH_DEBUG(SSH_D_FAIL, ("Sequence number failure"));
          goto fail;
	}
      
      if (pkt->status & PE_PKT_STATUS_UNSUPPORTED)
	{
	  rc = SSH_HWACCEL_UNSUPPORTED;
	  SSH_DEBUG(SSH_D_FAIL, ("Unsupported operation"));
          goto fail;
	}
      
      /* The driver always does antireplay checking. Ignore that error if
	 the SA indicates that antireplay should not be performed and
	 that is the only error. */
      if ((pkt->status != PE_PKT_STATUS_SEQ_FAILURE)
	  || (accel->flags & HWACCEL_FLAGS_ANTIREPLAY))
	goto fail;





    }
  
  if (op->esp)
    {
      /* Outbound traffic, tunnel or transport. I.e. IP header  + ESP data. */
      if (accel->flags & HWACCEL_FLAGS_OUTBOUND)
        {
          head_strip_len = 0;
          return_len = pkt->dst_len + op->hdrlen;
        }

      /* Inbound tunnel mode. Decrypted packet length from ESP. */
      else if (tunnel)
        {
          head_strip_len = op->hdrlen;
          return_len = pkt->dst_len;
        }
      
      /* Inbound transport mode. Decrypted data, we need to 
         add header length, since that was not passed to HW. */
      else
        {
          head_strip_len = 0;
          return_len = pkt->dst_len + op->hdrlen;
        }
      head_strip_ofs = 0;
    }
  else /* AH */
    {
      /* Outbound tunnel or transport mode. */
      if (accel->flags & HWACCEL_FLAGS_OUTBOUND)
        {
          SSH_ASSERT(pkt->dst == op->original_src);

	  head_strip_ofs = 0;
          head_strip_len = 0;
          return_len = pkt->dst_len;
        }
	
      /* Inbound modes. */
      else
      {
        /* First we calculate the AH header length correctly */
        /* Initial value in bytes: */
        unsigned int ah_header_len = 0;
        /* now we get at least 6 words of AH header */
        unsigned char * ah_header_p = ssh_interceptor_packet_pullup(
                                          op->pp, 
                                          op->hdrlen + SSH_SAFENET_AH_HDRLEN)
	                                  + op->hdrlen;
 
	    /* now we calculate the length of the AH header
	       the standard value is 4 (which in fact means 4 + 2,
	       see RFC2402 for details) but this value can be different
	       for advanced protocols, such as GCM-AES, in this case the
	       AH length can be 7 or other value */
	    ah_header_len = (ah_header_p[SSH_AHH_OFS_LEN] + 2) * 4;
        SSH_DEBUG(SSH_D_LOWOK, ("AH Header Length is %d bytes.",
				ah_header_len));

      /* Inbound tunnel mode. */
        if (tunnel)
        {
	  head_strip_ofs = 0;
          head_strip_len = op->hdrlen + ah_header_len;/*SSH_SAFENET_AH_HDRLEN*/
          SSH_ASSERT(head_strip_len >= 0);

          return_len = pkt->dst_len  - head_strip_len;
        }
      /* Inbound transport mode. */
      else
	{
	  head_strip_ofs = op->hdrlen;
          head_strip_len = ah_header_len;/*SSH_SAFENET_AH_HDRLEN;*/
          SSH_ASSERT(head_strip_len >= 0);
	  
          return_len = pkt->dst_len  - ah_header_len;/*SSH_SAFENET_AH_HDRLEN;*/
        }
	}
    }
  
  /* Default to out-of-memory */
  rc = SSH_HWACCEL_CONGESTED;
  
#ifdef SSH_SAFENET_PACKET_IS_DMA

  pp = op->pp;
  op->pp = NULL;
  
  /* Discard the outer tunnel header for inbound transforms. */
  if (head_strip_len)
    {
      if (!ssh_interceptor_packet_delete(pp, head_strip_ofs, head_strip_len))
        goto error;
    }

  len = ssh_interceptor_packet_len(pp);
  if (return_len > len)
    {
      ssh_fatal("HW expanded the packet outside given limits.");
    }
  else
    {
      /* Strip off trailing garbage. */
      if (return_len < len)
        if (!ssh_interceptor_packet_delete(pp, return_len, len - return_len))
          goto error;
    }
  
  ucp = ssh_interceptor_packet_pullup(pp, return_len < SSH_IPH6_HDRLEN ?
				      return_len : SSH_IPH6_HDRLEN);
  if (ucp == NULL)
    goto error;

#else /* SSH_SAFENET_PACKET_IS_DMA */
#error "This code is not supported with !SSH_SAFENET_PACKET_IS_DMA"
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
	  cks = ssh_ip_cksum(ucp, op->hdrlen);
	  SSH_IPH4_SET_CHECKSUM(ucp, cks);
	}
    }
  else /* Inbound */
    {
      if (tunnel == 0)
	{
	  if (accel->flags & HWACCEL_FLAGS_IPV6)
	    {
	      /* Update the next header field of the (extension) header which
		 was before that of the ESP/AH header. */
	      proto = pkt->next_header;
	      if (!ssh_interceptor_packet_copyin(pp, op->ipsec_offset_prevnh,
						 &proto, 1))
		goto error;
              
#ifndef SSH_SAFENET_PACKET_IS_DMA
	      /* The previous call may have invalidated 'ucp' */
	      ucp = ssh_interceptor_packet_pullup(pp, op->hdrlen);
	      if (!ucp)
		goto error;
#endif /* SSH_SAFENET_PACKET_IS_DMA */
              
	      if (op->esp)
		{
		  SSH_IPH6_SET_LEN(ucp, pkt->dst_len);
		}
	      else
		{
		  SSH_ASSERT(return_len >= op->hdrlen);
		  SSH_IPH6_SET_LEN(ucp, return_len - op->hdrlen);
		}
	    }
	  else /* ipv4 */
	    {
	      SSH_IPH4_SET_PROTO(ucp, pkt->next_header);
              
	      SSH_IPH4_SET_LEN(ucp, return_len);

	      SSH_IPH4_SET_CHECKSUM(ucp, 0);
	      cks = ssh_ip_cksum(ucp, op->hdrlen);
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

	  ssh_hwaccel_perform_operation(op, op->device);
	  return;
	}
      else if (!(accel->flags & HWACCEL_FLAGS_OUTBOUND) && op->ah)
	{
	  op->esp = 1;
	  op->ah = 0;
	  op->pp = pp;
	  SSH_DEBUG(SSH_D_LOWOK, ("Calling perform op again"));

	  ssh_hwaccel_perform_operation(op, op->device);
	  return;
	}
    }
  
  /* For transport mode, update the IP header and upper layer checksums. */
  if ((accel->flags & HWACCEL_FLAGS_NATT) &&
      !(accel->flags & HWACCEL_FLAGS_OUTBOUND) && 
      !(accel->flags & HWACCEL_FLAGS_TUNNEL))
    {
      if (!ssh_hwaccel_natt_update_header(accel, pp, op->hdrlen))
	goto error;
    }
  
  rc = SSH_HWACCEL_OK;
  (*op->completion)(pp, rc, op->completion_context);

  SAFENET_OPERATION_FREELIST_PUT(op);
  return;
  
 fail:
  
  SSH_DEBUG(SSH_D_FAIL, ("safenet_operation_complete: FAILED.\n"));
  if (pp)
    ssh_interceptor_packet_free(pp);
  
 error:
  
  SSH_DEBUG(SSH_D_FAIL, ("safenet_operation_complete: ERROR.\n"));
  /* free the contiguous packet buffer */
  if (op->packet)
    ssh_kernel_free(op->packet);
  
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

  SAFENET_OPERATION_FREELIST_GET(op);
  if (!op)
    goto fail;


  SSH_ASSERT(accel != NULL);
  SSH_ASSERT(pp != NULL);
  SSH_ASSERT(completion != NULL);

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
    {
      SSH_ASSERT(accel->esp.sa != NULL);
      op->esp = 1;
    }
  else
    {
      SSH_ASSERT(accel->ah.sa != NULL);
      op->ah = 1;
    }

  ssh_hwaccel_perform_operation(op, op->device);
  
  return;

 fail:
 
  ssh_interceptor_packet_free(pp);

  if (op != NULL)
    SAFENET_OPERATION_FREELIST_PUT(op);

  (*completion)(NULL, SSH_HWACCEL_CONGESTED, completion_context);
}

void 
ssh_hwaccel_perform_operation(SshSafenetOperation op, 
                              SshSafenetDevice device)
{
  SshHWAccel accel = NULL;
  SshInterceptorPacket pp = NULL;
  unsigned char proto = 0, *ucp, *packet = NULL;
  size_t packet_len, dstlen;
  Boolean ipv6_packet = FALSE;
  Boolean df_bit_set = FALSE;
  SshUInt8 tunnel, tos = 0, sent_packets = 0;
  SshUInt32 flow_label = 0;
  SshUInt32 total_written_this_round = 0;
  SshUInt32 currently_in_hw = 0;
  PE_PKT_DESCRIPTOR *pkt = NULL;
  SshUInt16 free_space = 0;
#ifdef  SSH_SAFENET_PACKET_IS_DMA 
  SshInterceptorInternalPacket ipp;
#endif /* SSH_SAFENET_PACKET_IS_DMA */

  SSH_ASSERT(device != NULL);

  if (op == NULL)
    goto send_now;

  accel = op->accel;
  pp = op->pp;
  op->pp = NULL;

  pkt = &op->pkt;

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
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Packet pullup failed."));
      goto error;
    }

  if (SSH_IPH4_VERSION(ucp) != 4 && SSH_IPH6_VERSION(ucp) != 6)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Incorrect IP version."));
      goto fail;
    }

  if ((SSH_IPH6_VERSION(ucp) == 6))
    ipv6_packet = 1;

  if (!ipv6_packet && (SSH_IPH4_FRAGOFF(ucp) & SSH_IPH4_FRAGOFF_DF))
    df_bit_set = TRUE;
  
  /* Get the packet's header length (for tunnel mode we are only interested
     in the outer tunnel header). */
  if (tunnel && (accel->flags & HWACCEL_FLAGS_OUTBOUND))
  {
      /* Tunnel mode. */
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
  else
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

  SSH_DEBUG(SSH_D_LOWOK, ("Fromhw packet length %d, tunnel %s, hdrlen %d",
			  packet_len, tunnel ? "Yes" : "No", op->hdrlen));

  if (!tunnel)
    {
      /* In transport mode we need to know the next proto. */
      if (accel->flags & HWACCEL_FLAGS_IPV6)
	ssh_interceptor_packet_copyout(pp, op->ipsec_offset_prevnh,
				       &proto, 1);
      else
	ssh_interceptor_packet_copyout(pp, SSH_IPH4_OFS_PROTO,
				       &proto, 1);
    }

  /* When outbound tunnel mode, insert the outer header. */
  if ((accel->flags & HWACCEL_FLAGS_OUTBOUND) && tunnel)
    {
      /* Fetch the TOS and flow label for IPv6 packets and copy them
	 to the outer header. */
      if (ipv6_packet)
	{
	  SSH_ASSERT(packet_len > SSH_IPH6_HDRLEN);
	  ucp = ssh_interceptor_packet_pullup(pp, SSH_IPH6_HDRLEN);
	  if (ucp == NULL)
            {
              SSH_DEBUG(SSH_D_NICETOKNOW, ("Packet pullup failed."));
              goto error;
            }

	  tos = SSH_IPH6_CLASS(ucp);
	  flow_label = SSH_IPH6_FLOW(ucp);
	}

      ucp = ssh_interceptor_packet_insert(pp, 0, op->hdrlen);
      if (ucp == NULL)
	goto error;

      SSH_ASSERT(op->hdrlen <= sizeof(accel->hdr));
      memcpy(ucp, accel->hdr, op->hdrlen);

      if (accel->flags & HWACCEL_FLAGS_IPV6)
	{
	  SSH_IPH6_SET_CLASS(ucp, tos);
	  SSH_IPH6_SET_FLOW(ucp, flow_label);
	}
      else
	{
	  /* Set the identification field */
	  SSH_IPH4_SET_ID(ucp, safenet_devices.packet_id++);
          
	  /* Set/Clear the DF bit for IPv4/IPv4 tunnelled packets */
	  if (!ipv6_packet)
	    {
	      if ((accel->flags & HWACCEL_FLAGS_DF_SET) ||
		  (!(accel->flags & HWACCEL_FLAGS_DF_CLEAR) && df_bit_set))
		SSH_IPH4_SET_FRAGOFF(ucp, SSH_IPH4_FRAGOFF_DF); 
	    }
	}
    }

  /* Update the packet length with the added tunnel header. */
  packet_len = ssh_interceptor_packet_len(pp);

  /* Compute the maximum possible packet return length */
  dstlen = packet_len +
    ((accel->flags & HWACCEL_FLAGS_OUTBOUND) ? accel->added_len : 0); 

#ifdef SSH_SAFENET_PACKET_IS_DMA 
  /* Ensure that there is tail room for the added headers when
     doing outbound transforms */
  if (accel->flags & HWACCEL_FLAGS_OUTBOUND)
    {
      SSH_ASSERT(dstlen - packet_len >= 0);
      if (dstlen - packet_len)
        {
          /* Insert extra bytes to the tail, needed by the potential 
             expansion of the packet. */
          ucp = ssh_interceptor_packet_insert(pp, packet_len,
                                              dstlen - packet_len);
          if (ucp == NULL)
            goto error;
        }
    }

  ipp = (SshInterceptorInternalPacket)pp;
  if (skb_linearize_cow(ipp->skb) != 0)
    goto fail;

  /* We need only the start of the packet, so pulling up only
     1 byte... */
  packet = ssh_interceptor_packet_pullup(pp, 1);
  if (packet == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failed to pullup packet."));
      goto error;
    }

#else /* SSH_SAFENET_PACKET_IS_DMA */

  /* Get a contiguous packet buffer */
  packet = ssh_kernel_alloc(dstlen, SSH_KERNEL_ALLOC_DMA);
  if (packet == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failed to allocate memory for packet."));
      goto fail;
    }

  /* Copy the data from the interceptor packet to the dma-enabled
     source buffer */
  ssh_interceptor_packet_copyout(pp, 0, packet, packet_len);
  op->packet = packet;

#endif /* SSH_SAFENET_PACKET_IS_DMA */

  /* Original src now always points to the start of the buffer. */
  op->original_src = packet;

  /* Determine the packet offsets */
  if (op->esp)
    {
      pkt->sa_data = accel->esp.sa;
      
      /* pkt->src is the same for inbound & outbound. */
      pkt->src = op->original_src + op->hdrlen;
      pkt->src_len = packet_len - op->hdrlen;
      pkt->dst_len = dstlen - op->hdrlen;
    }
  else
    {
      pkt->sa_data = accel->ah.sa;

      pkt->src = op->original_src;
      pkt->src_len = packet_len;
      pkt->dst_len = dstlen;
    }
  SSH_ASSERT(accel != NULL);
  SSH_ASSERT(pkt->sa_data != NULL);
  
  /* Write back to the place we started from... */
  pkt->dst = pkt->src;

  /* Prepare the common packet desciptor and send it to the 
     packet engine interface */
  if (accel->flags & HWACCEL_FLAGS_OUTBOUND)
    pkt->next_header = tunnel ? (ipv6_packet ? 
                                 SSH_IPPROTO_IPV6 : SSH_IPPROTO_IPIP) : proto;

  pkt->user_handle = op;
  pkt->flags = accel->flags;

  op->pp = pp;

  SSH_ASSERT(op->pp != NULL);
  SSH_ASSERT(pkt->user_handle != NULL);

 send_now:
  ssh_kernel_mutex_lock(device->tohw_lock);
  if (device->processing_tohw)
    {
      if (op && ((device->pending_pktdesc_count + 1) > 
                 (2 * SSH_SAFENET_MAX_QUEUED_OPERATIONS)))
        {
          ssh_kernel_mutex_unlock(device->tohw_lock);

          /* Since we may not touch the tohw_pktdescs here (even though
             it might have free space), we must drop the packet. */          
          SSH_DEBUG(SSH_D_FAIL, ("Could not process packet, silently "
                                 "dropping packet."));
          
          goto fail;
        }

      if (op)
	device->pending_descriptors[device->pending_pktdesc_count++] = *pkt;
      
      device->redo_tohw_processing = 1;

      ssh_kernel_mutex_unlock(device->tohw_lock);
      return;
    }

  device->processing_tohw = 1;

 redo_now:
  /* Do we have pending descriptors? Move these first to the real 
     sending list. */
  if (device->pending_pktdesc_count)
    {
      /* If we have OP to be done, we must insert it to the pending list 
         first to preserve the order of the packets. */
      if (op)
        {
          device->pending_descriptors[device->pending_pktdesc_count++] = *pkt;
          
          /* From here on, the pending list owns the packet. */
          op = NULL;
        }

      free_space = (2 * SSH_SAFENET_MAX_QUEUED_OPERATIONS) - 
        device->tohw_pktdesc_count;

      /* Do we have more space in the tohw list than pending list contains */
      if (free_space >= device->pending_pktdesc_count)
        {
          /* Yes we do. */
          memcpy(&device->tohw_descriptors[device->tohw_pktdesc_count], 
                 device->pending_descriptors, 
                 sizeof(PE_PKT_DESCRIPTOR) * device->pending_pktdesc_count);

          device->tohw_pktdesc_count += device->pending_pktdesc_count;
          device->pending_pktdesc_count = 0;
        }
      else 
        {
          /* No we dont, copy only what we can. */
          memcpy(&device->tohw_descriptors[device->tohw_pktdesc_count], 
                 device->pending_descriptors, 
                 sizeof(PE_PKT_DESCRIPTOR) * free_space);

          /* Update also the pending list, since we copied from the start 
             of the packet list... */
          memcpy(device->pending_descriptors, 
                 &device->pending_descriptors[free_space], 
                 sizeof(PE_PKT_DESCRIPTOR) * 
                 (device->pending_pktdesc_count - free_space));

          device->tohw_pktdesc_count += free_space;
          SSH_ASSERT(device->tohw_pktdesc_count == 
                     (2 * SSH_SAFENET_MAX_QUEUED_OPERATIONS));

          device->pending_pktdesc_count = 
            device->pending_pktdesc_count - free_space;
        }
    }
  ssh_kernel_mutex_unlock(device->tohw_lock);

  if (op)
    device->tohw_descriptors[device->tohw_pktdesc_count++] = *pkt;
    
  SSH_ASSERT((device->tohw_pktdesc_count <= 
              (2 * SSH_SAFENET_MAX_QUEUED_OPERATIONS)));

  sent_packets = 0;

  if (((device->tohw_pktdesc_count >= SSH_SAFENET_PDR_BURST_COUNT) ||
       (op == NULL)) && device->tohw_pktdesc_count)
    sent_packets = safenet_pe_pktput(device->device_number, 
                                     device->tohw_descriptors, 
                                     device->tohw_pktdesc_count);
  
  ssh_kernel_mutex_lock(device->tohw_lock);
  if (sent_packets)
    {
      ssh_kernel_mutex_lock(device->operation_lock);
      
      device->operation_count += sent_packets;
      currently_in_hw = device->operation_count;
      total_written_this_round += sent_packets;
      
      ssh_kernel_mutex_unlock(device->operation_lock);
      
      device->tohw_pktdesc_count -= sent_packets;
    }

  if (device->redo_tohw_processing)
    {
      device->redo_tohw_processing = 0;
      sent_packets = 0;
      
      /* We must invalidate op, since we cannot
         regenerate the packet. */
      op = NULL;
      goto redo_now;
    }
  device->processing_tohw = 0;
  ssh_kernel_mutex_unlock(device->tohw_lock);
  
  if (total_written_this_round >= SSH_SAFENET_PDR_BURST_COUNT &&
      currently_in_hw >= SSH_SAFENET_PDR_BURST_COUNT &&
      device->polling && op)
    ssh_safenet_pdr_bh_cb(device, NULL);

  return;

 fail:
  if (pp)
    ssh_interceptor_packet_free(pp);
  
 error:
  if (packet)
    ssh_kernel_free(packet);

  (*op->completion)(NULL, SSH_HWACCEL_CONGESTED, op->completion_context);

  SAFENET_OPERATION_FREELIST_PUT(op);
}
 
 
#ifdef SSH_SAFENET_PKTGET_TIMER
void safenet_pktget_timer_cb(void *context)
{
  SshSafenetDevice device = (SshSafenetDevice)context;
  int send_pkt_count = 0;
  int may_call_tohw = 1;

  ssh_kernel_mutex_lock(device->tohw_lock);
  if (device->processing_tohw)
    {
      /* Cause a small recursion for the fromhw :-) */
      device->redo_tohw_processing = 1;
      may_call_tohw = 0;
    }

  /* tohw_pktdesc_count may be in 'stale' state here, so as it
     is not protected by any locks for reading & writing here,
     so it may be in unknown state here. Anyway it does not matter,
     since all it causes is just an extra call to the hwaccel
     perform operation. */
  send_pkt_count = device->tohw_pktdesc_count + 
    device->pending_pktdesc_count;
  ssh_kernel_mutex_unlock(device->tohw_lock);
  
  if (send_pkt_count && may_call_tohw)
    ssh_hwaccel_perform_operation(NULL, device);
   
  ssh_safenet_pdr_bh_cb(device, NULL);

  ssh_kernel_timeout_register(0, SSH_SAFENET_PKTGET_TIMER_PERIOD,
                              safenet_pktget_timer_cb, (void *)device);
}
#endif /* SSH_SAFENET_PKTGET_TIMER */

/* The device to use is chosen from that which has the least number of
   SshHWAccel contexts associated with it. The data in device structure
   might be in stale state, since we do not utilize any locks for these. 
   It does not matter, since we are using this only as a hint which device
   is least loaded. */
SshSafenetDevice 
safenet_find_least_used_device(void)
{
  SshSafenetDevice device, best_device = NULL;
  int best_device_load = 0, load, i;

  for (i = 0; i < safenet_devices.num_devices; i++)
    {
      device = &safenet_devices.safenet_device[i];
      load = device->session_count;

      if (!best_device || best_device_load > load)
        {
          best_device = device;
          best_device_load = load;
        }
    }

  return best_device;
}

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
  int proto = 0, ciph_alg = PE_CIPHER_ALG_NULL;
  int hash_alg = PE_HASH_ALG_NULL;
  char *mac_name = NULL;
  unsigned char *mac_key = NULL;
  size_t mac_key_len = 0;
  PE_SA_PARAMS sa_params;

  memset(&sa_params, 0x0, sizeof(PE_SA_PARAMS));
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
    accel->flags |= HWACCEL_FLAGS_NATT;
    
  if (flags & SSH_HWACCEL_COMBINED_FLAG_ENCAPSULATE)
    accel->flags |= HWACCEL_FLAGS_OUTBOUND;

  if (((flags & SSH_HWACCEL_COMBINED_FLAG_ESP)) &&
      ((flags & SSH_HWACCEL_COMBINED_FLAG_AH)))
    goto fail;

  if (((flags & SSH_HWACCEL_COMBINED_FLAG_ESP) == 0) &&
      ((flags & SSH_HWACCEL_COMBINED_FLAG_AH) == 0))
    goto fail;

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
      proto = SSH_IPPROTO_AH;

      /* AH header (excluding the ICV) */
      accel->added_len += 12;
    }

  /* IPComp not supported */
  if (flags & SSH_HWACCEL_COMBINED_FLAG_IPCOMP)
    {
      SSH_DEBUG(SSH_D_FAIL, ("IPCOMP not supported"));
      goto fail;
    }

  if (flags & SSH_HWACCEL_COMBINED_FLAG_ANTIREPLAY)
    accel->flags |= HWACCEL_FLAGS_ANTIREPLAY;










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
	  accel->flags |= HWACCEL_FLAGS_AES;
          ciph_alg = PE_CIPHER_ALG_AES;
        }
      else if (!strcmp(esp_ciphname, "aes-gcm"))
        {
        accel->added_len += 8; /* iv */
        accel->added_len += 16 + 1; /* worst case ESP trailer + padding */
        accel->added_len += 16; /* ICV */
        accel->flags |= HWACCEL_FLAGS_AES;
        ciph_alg = PE_CIPHER_ALG_AES;
        hash_alg = PE_HASH_ALG_GHASH;
        }
      else if (!strcmp(esp_ciphname, "aes-gcm-64"))
        {
        accel->added_len += 8; /* iv */
        accel->added_len += 16 + 1; /* worst case ESP trailer + padding */
        accel->added_len += 16; /* ICV */	  
        accel->flags |= HWACCEL_FLAGS_AES;
        ciph_alg = PE_CIPHER_ALG_AES;
        hash_alg = PE_HASH_ALG_GHASH_64;
        }
      else if (!strcmp(esp_ciphname, "null-auth-aes-gmac"))
        {
        accel->added_len += 8; /* iv */
        accel->added_len += 16 + 1; /* worst case ESP trailer + padding */
        accel->added_len += 16; /* ICV */	  
        accel->flags |= HWACCEL_FLAGS_AES;
        ciph_alg = PE_CIPHER_ALG_AES;
        hash_alg = PE_HASH_ALG_GMAC;
        }
      else if (!strcmp(esp_ciphname, "3des-cbc"))
        {
        accel->added_len += 8; /* iv */
        accel->added_len += 8 + 1; /* worst case ESP trailer + padding */
        ciph_alg = PE_CIPHER_ALG_TDES;
        }
      else if (!strcmp(esp_ciphname, "des-cbc"))
        {
        accel->added_len += 8; /* iv */
        accel->added_len += 8 + 1; /* worst case ESP trailer + padding */
        ciph_alg = PE_CIPHER_ALG_DES;
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
      accel->added_len += 8 + 1; /* worst case ESP trailer + padding */
      ciph_alg = PE_CIPHER_ALG_NULL;
    }

  /* Get the mac algorithm */
  if (hash_alg == PE_HASH_ALG_NULL)
  {
  if (mac_name && strcmp(mac_name, "none"))
    {
      if (!strcmp(mac_name, "hmac-sha1-96"))
        {
          hash_alg = PE_HASH_ALG_SHA1;
          accel->added_len += 12; /* ICV */
        }
      else if (!strcmp(mac_name, "hmac-md5-96"))
        {
          hash_alg = PE_HASH_ALG_MD5;
          accel->added_len += 12; /* ICV */
        }
      else if (!strcmp(mac_name, "hmac-sha256-128"))
        {
          hash_alg = PE_HASH_ALG_SHA256;
          accel->added_len += 16; /* ICV */
        }
      else if (!strcmp(mac_name, "hmac-sha512-256"))
        {
          hash_alg = PE_HASH_ALG_SHA512;
          accel->added_len += 32; /* ICV */
        }
      else if (!strcmp(mac_name, "hmac-sha384-192"))
        {
          hash_alg = PE_HASH_ALG_SHA384;
          accel->added_len += 24; /* ICV */
        }
      else
        {
          SSH_DEBUG(SSH_D_FAIL, ("Unsupported MAC algorithm %s", mac_name));
	  goto fail;
	    }
    }
  else
    {
      hash_alg = PE_HASH_ALG_NULL;
    }
  }
  
  
  /* Verify we don't have both null cipher and null mac */
  if (hash_alg == PE_HASH_ALG_NULL && ciph_alg == PE_CIPHER_ALG_NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Cannot have both null cipher and null mac"));
      goto fail;
    }

  SSH_ASSERT(interceptor != NULL);

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

  /* Build SA in a packet engine platform specific memory area */
  if (flags & SSH_HWACCEL_COMBINED_FLAG_AH)
  {
      sa_params.spi = ah_spi;
      sa_params.seq = seq_num_low;
      sa_params.hash_alg = hash_alg;
      sa_params.mac_key = mac_key;
      sa_params.mac_key_len = mac_key_len;

      if (!safenet_pe_build_sa(device->device_number, PE_SA_TYPE_AH, 
                               accel->flags, sa_params, &accel->ah.sa))
	{
	  goto fail;
	}
  }

  if (flags & SSH_HWACCEL_COMBINED_FLAG_ESP)
  {
      if (flags & SSH_HWACCEL_COMBINED_FLAG_AH)
	hash_alg = PE_HASH_ALG_NULL;

      sa_params.spi = esp_spi;
      sa_params.seq = seq_num_low;
      sa_params.hash_alg = hash_alg;
      sa_params.mac_key = mac_key;
      sa_params.mac_key_len = mac_key_len;
      sa_params.ciph_alg = ciph_alg;
      sa_params.ciph_key = (unsigned char *)esp_ciphkey;
      sa_params.ciph_key_len = esp_ciphkeylen;
      sa_params.esp_iv = (unsigned char *)esp_iv;
      sa_params.esp_ivlen = esp_ivlen;

      if (!safenet_pe_build_sa(device->device_number, PE_SA_TYPE_ESP, 
                               accel->flags, sa_params, &accel->esp.sa))
	  {
	      goto fail;
	  }
  }

  /* increase the session counter, needed for load-balancing */
  ssh_kernel_mutex_lock(device->operation_lock);
  device->session_count++;
  ssh_kernel_mutex_unlock(device->operation_lock);

  SSH_DEBUG(SSH_D_MIDOK, ("Alloc combined succeeded"));
  SSH_DEBUG(SSH_D_LOWOK, ("added_len is %d", accel->added_len));
  return accel;
  
 fail:

  SSH_DEBUG(SSH_D_FAIL, ("Alloc combined failed"));
  if (accel)
  {
      if (accel->esp.sa)
	{
          safenet_pe_destroy_sa(accel->esp.sa);
	}

      if (accel->ah.sa)
	{
          safenet_pe_destroy_sa(accel->ah.sa);
	}

      SAFENET_HWACCEL_FREELIST_PUT(accel);
  }
  return NULL;
}


SshHWAccelResultCode
ssh_hwaccel_update_combined(SshHWAccel accel, 
                            SshIpAddr ipip_src, 
                            SshIpAddr ipip_dst, 
			    SshUInt16 natt_remote_port)
{
  return SSH_HWACCEL_UNSUPPORTED;

#if 0
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
#endif /* 0 */
}

static void ssh_hwaccel_free_accel(SshHWAccel accel)
{
  if (accel->ah.sa)
    safenet_pe_destroy_sa(accel->ah.sa);
    
  if (accel->esp.sa)
    safenet_pe_destroy_sa(accel->esp.sa);
    
  SAFENET_HWACCEL_FREELIST_PUT(accel);
}

/* Frees the hardware acceleration context.  The engine guarantees
   that no operations will be in progress using the context when this
   is called. */
void ssh_hwaccel_free_combined(SshHWAccel accel)
{
  SshSafenetDevice device = accel->device;
  
  SSH_DEBUG(SSH_D_MIDOK, ("Freeing SshHWAccel instance"));

  ssh_kernel_mutex_lock(device->operation_lock);
  device->session_count--;
  ssh_kernel_mutex_unlock(device->operation_lock);

  ssh_hwaccel_free_accel(accel);
}

/*********** Initialization functions *******************************/

static void ssh_safenet_device_uninit(SshSafenetDevice device)
{
#ifdef SSH_SAFENET_PKTGET_TIMER
  if (device->timer_running)
    ssh_kernel_timeout_cancel(safenet_pktget_timer_cb, (void *)device);
#endif

  safenet_pe_uninit(device->device_number);
  
  ssh_kernel_mutex_free(device->operation_lock);
  ssh_kernel_mutex_free(device->tohw_lock);
  ssh_kernel_mutex_free(device->fromhw_lock);
  memset(&device, 0, sizeof(device));
  
  SSH_DEBUG(SSH_D_HIGHOK, ("ssh_safenet_device_uninit: done"));
}


static Boolean 
safenet_hwaccel_init()
{
  SshSafenetDevice device;
  SshUInt32 device_count = PE_MAX_DEVICES;
  int i, j = 0;
  PE_DEVICE_INIT pe_device_init[PE_MAX_DEVICES];
  
  SSH_DEBUG(SSH_D_HIGHOK, ("Hardware acceleration initialization started."));
  
  memset(pe_device_init, 0, PE_MAX_DEVICES * sizeof(PE_DEVICE_INIT));
  
  /* Prepare device callbacks */
  for (i = 0 ; i < device_count; i++)
    {
      pe_device_init[i].device_callback.process_id = 0;
      pe_device_init[i].device_callback.signal_number = 0;

      /* Setting the notify callback to NULL would disable interrupts for
         the device. */
      pe_device_init[i].device_callback.callback = NULL_FNPTR;     

#ifndef SSH_SAFENET_POLLING
      pe_device_init[i].device_callback.callback = ssh_safenet_pdr_cb;
#endif /* SSH_SAFENET_POLLING */
    }
  
  /* Initialize all devices using PE call */
  if (!safenet_pe_init(pe_device_init, (uint32_t*)&device_count))
    goto fail;
  
  memset(&safenet_devices, 0x0, sizeof(SshSafenetDevicesStruct));
  safenet_devices.num_devices = device_count;

  /* Prepare device based synchronization locks and the timers 
     for all found devices.  */
  for (i = 0 ; i < PE_MAX_DEVICES; i++)
    {
      if (pe_device_init[i].found)
        {
          device = &safenet_devices.safenet_device[j++];
          memset(device, 0x0, sizeof(SshSafenetDeviceStruct));
          
          device->device_number = pe_device_init[i].device_number;
          device->operation_lock = ssh_kernel_mutex_alloc();
          device->tohw_lock = ssh_kernel_mutex_alloc();
          device->fromhw_lock = ssh_kernel_mutex_alloc();

          if (device->operation_lock == NULL || 
              device->tohw_lock == NULL ||
              device->fromhw_lock == NULL)
              goto fail;

#ifdef SSH_SAFENET_PKTGET_TIMER
          /* register the timer */
          ssh_kernel_timeout_register(0, 
                                      SSH_SAFENET_PKTGET_TIMER_PERIOD,
                                      safenet_pktget_timer_cb, (void *)device);
          device->timer_running = TRUE;
          #ifdef SAFENET_DEBUG
          ssh_debug("PKTGET timer started with period of %d ms\n",
		    SSH_SAFENET_PKTGET_TIMER_PERIOD);
          #endif
#endif
          #ifdef SAFENET_DEBUG
          ssh_debug("SSH_SAFENET_PDR_BURST_COUNT is %d packet(s)\n",
		    SSH_SAFENET_PDR_BURST_COUNT);
          #endif

#ifdef SSH_SAFENET_POLLING
          device->polling = TRUE;
#else /* SSH_SAFENET_POLLING */
          device->polling = FALSE;
#endif /* SSH_SAFENET_POLLING */

        }
    }
  
  if (!safenet_operation_freelist_alloc())
    goto fail;
  
  if (!safenet_hwaccel_freelist_alloc())
    goto fail;
  
  SSH_DEBUG(SSH_D_HIGHOK, ("safenet_hwaccel_init: done"));
  
  return TRUE;

 fail:

  SSH_DEBUG(SSH_D_FAIL, ("Hardware acceleration initialization failed, "
                         "using software crypto."));
  
  ssh_hwaccel_uninit();
  return FALSE;
}


static void safenet_hwaccel_uninit(void)
{
  SshSafenetDevice device;
  int i;

  for (i = 0; i < safenet_devices.num_devices;)
    {
      device = &safenet_devices.safenet_device[i];
  
      ssh_kernel_mutex_lock(device->operation_lock);
      if (device->operation_count > 0)
        {
          ssh_kernel_mutex_unlock(device->operation_lock);

          udelay(100);
          continue;
        }

      ssh_kernel_mutex_unlock(device->operation_lock);
      ssh_safenet_device_uninit(device);

      i++;
    }

  safenet_operation_freelist_free();
  safenet_hwaccel_freelist_free();

  SSH_DEBUG(SSH_D_HIGHOK, ("safenet_hwaccel_uninit: done"));
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
