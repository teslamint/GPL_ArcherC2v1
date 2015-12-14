/*

  linux_internal.h

  Copyright:
 	Copyright (c) 2002-2008 SFNT Finland Oy.
	All rights reserved.

  Common internal declarations for linux interceptor.

*/

#ifndef LINUX_INTERNAL_H
#define LINUX_INTERNAL_H

#ifndef SSH_IS_MAIN_MODULE
#define __NO_VERSION__
#endif /* !SSH_IS_MAIN_MODULE */

#define SSH_ALLOW_CPLUSPLUS_KEYWORDS
#define SSH_ALLOW_MS_VISUAL_C_KEYWORDS

#include "sshincludes.h"

/* Parameters used to tune the interceptor. */
#include "linux_versions.h"
#include "linux_params.h"

#include <linux/types.h>
#include <linux/init.h>
#include <linux/skbuff.h>
#include <linux/string.h>
#include <linux/delay.h>
#include <linux/poll.h>
#include <linux/proc_fs.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <net/pkt_sched.h>

#include <linux/interrupt.h>
#include <linux/inetdevice.h>

#include <net/ip.h>
#include <net/inet_common.h>

#ifdef SSH_LINUX_INTERCEPTOR_IPV6
#include <net/ipv6.h>
#include <net/addrconf.h>
#endif /* SSH_LINUX_INTERCEPTOR_IPV6 */

#ifndef SSH_IPSEC_IP_ONLY_INTERCEPTOR
#include <linux/if_arp.h>
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */

#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>
#include <linux/netfilter_bridge.h>
#include <linux/netfilter_arp.h>

#include <linux/module.h>
#include <linux/moduleparam.h>

#include <linux/cpumask.h>

#ifdef LINUX_NEED_IF_ADDR_H
#include <linux/if_addr.h>
#endif /* LINUX_NEED_IF_ADDR_H */

#ifdef SSHDIST_QUICKSEC
#ifdef SSH_BUILD_IPSEC
#include "ipsec_params.h"
#endif /* SSH_BUILD_IPSEC */
#endif /* SSHDIST_QUICKSEC */

#include "engine.h"
#include "kernel_includes.h"
#include "kernel_mutex.h"
#include "kernel_timeouts.h"
#include "interceptor.h"
#include "sshinet.h"
#include "sshdebug.h"
#include "sshadt.h"

#include "linux_packet_internal.h"
#include "linux_mutex_internal.h"

#include <linux/threads.h>

#ifdef SSHDIST_QUICKSEC
#ifdef SSH_BUILD_IPSEC
#include "linux_nf_internal.h"
#endif /* SSH_BUILD_IPSEC */
#endif /* SSHDIST_QUICKSEC */







/****************************** Sanity checks ********************************/

#ifndef MODULE
#error "Quicksec can only be compiled as a MODULE"
#endif /* MODULE */

#ifndef CONFIG_NETFILTER
#error "Kernel is not compiled with CONFIG_NETFILTER"
#endif /* CONFIG_NETFILTER */

/* Check that SSH_LINUX_FWMARK_EXTENSION_SELECTOR is in range. */
#ifdef SSH_LINUX_FWMARK_EXTENSION_SELECTOR
#if (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0)
#if (SSH_LINUX_FWMARK_EXTENSION_SELECTOR >= \
     SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS)
#error "Invalid value specified for SSH_LINUX_FWMARK_EXTENSION_SELECTOR"
#endif
#endif /* (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0) */
#endif /* SSH_LINUX_FWMARK_EXTENSION_SELECTOR */


/****************************** Internal defines *****************************/

#define SSH_LINUX_INTERCEPTOR_NR_CPUS NR_CPUS

/********************** Kernel version specific wrapper macros ***************/

#ifdef LINUX_HAS_DEV_GET_FLAGS
#define SSH_LINUX_DEV_GET_FLAGS(dev) dev_get_flags(dev)
#else /* LINUX_HAS_DEV_GET_FLAGS */
#define SSH_LINUX_DEV_GET_FLAGS(dev) ((dev)->flags)
#endif /* LINUX_HAS_DEV_GET_FLAGS */

#ifdef LINUX_NF_HOOK_SKB_IS_POINTER
typedef struct sk_buff SshHookSkb;
#define SSH_HOOK_SKB_PTR(_skb) _skb
#else  /* LINUX_NF_HOOK_SKB_IS_POINTER */
typedef struct sk_buff *SshHookSkb;
#define SSH_HOOK_SKB_PTR(_skb) *_skb
#endif /* LINUX_NF_HOOK_SKB_IS_POINTER */

#ifdef LINUX_HAS_SKB_MARK
#define SSH_SKB_MARK(__skb) ((__skb)->mark)
#else /* LINUX_HAS_SKB_MARK */
#define SSH_SKB_MARK(__skb) ((__skb)->nfmark)
#endif /* LINUX_HAS_SKB_MARK */

#ifdef LINUX_HAS_DST_MTU
#define SSH_LINUX_DST_MTU(__dst) (dst_mtu((__dst)))
#else /* LINUX_HAS_DST_MTU */
#define SSH_LINUX_DST_MTU(__dst) (dst_pmtu((__dst)))
#endif /* LINUX_HAS_DST_MTU */

/* Before 2.6.22 kernels, the net devices were accessed
   using directly global variables. 
   2.6.22 -> 2.6.23 introduced new functions accessing
   the net device list. 
   2.6.24 -> these new functions started taking new
   arguments. */
#ifndef LINUX_HAS_NETDEVICE_ACCESSORS 
/* For 2.4.x -> 2.6.21 kernels */
#define SSH_FIRST_NET_DEVICE()     dev_base
#define SSH_NEXT_NET_DEVICE(_dev)  _dev->next

#else /* LINUX_HAS_NETDEVICE_ACCESSORS */
#ifndef LINUX_NET_DEVICE_HAS_ARGUMENT
/* For 2.6.22 -> 2.6.23 kernels */
#define SSH_FIRST_NET_DEVICE()     first_net_device()
#define SSH_NEXT_NET_DEVICE(_dev)  next_net_device(_dev) 

#else /* LINUX_NET_DEVICE_HAS_ARGUMENT */
/* For 2.6.24 -> kernels */
#define SSH_FIRST_NET_DEVICE()     first_net_device(&init_net)
#define SSH_NEXT_NET_DEVICE(_dev)  next_net_device(_dev)

#endif /* LINUX_NET_DEVICE_HAS_ARGUMENT */
#endif /* LINUX_HAS_NETDEVICE_ACCESSORS */

#ifdef LINUX_NET_DEVICE_HAS_ARGUMENT
#define SSH_DEV_GET_BY_INDEX(_i) dev_get_by_index(&init_net, (_i))
#else /* LINUX_NET_DEVICE_HAS_ARGUMENT */
#define SSH_DEV_GET_BY_INDEX(_i) dev_get_by_index((_i))
#endif /* LINUX_NET_DEVICE_HAS_ARGUMENT */

#ifdef LINUX_HAS_SKB_DATA_ACCESSORS
/* On new kernel versions the skb->end, skb->tail, skb->network_header, 
   skb->mac_header, and skb->transport_header are either pointers to
   skb->data (on 32bit platforms) or offsets from skb->data 
   (on 64bit platforms). */

#define SSH_SKB_GET_END(__skb) (skb_end_pointer((__skb)))

#define SSH_SKB_GET_TAIL(__skb) (skb_tail_pointer((__skb)))
#define SSH_SKB_SET_TAIL(__skb, __ptr) \
   (skb_set_tail_pointer((__skb), (__ptr) - (__skb)->data))
#define SSH_SKB_RESET_TAIL(__skb) (skb_reset_tail_pointer((__skb)))

#define SSH_SKB_GET_NETHDR(__skb) (skb_network_header((__skb)))
#define SSH_SKB_SET_NETHDR(__skb, __ptr) \
   (skb_set_network_header((__skb), (__ptr) - (__skb)->data))
#define SSH_SKB_RESET_NETHDR(__skb) (skb_reset_network_header((__skb)))

#define SSH_SKB_GET_MACHDR(__skb) (skb_mac_header((__skb)))
#define SSH_SKB_SET_MACHDR(__skb, __ptr) \
   (skb_set_mac_header((__skb), (__ptr) - (__skb)->data))
#define SSH_SKB_RESET_MACHDR(__skb) (skb_reset_mac_header((__skb)))

#define SSH_SKB_GET_TRHDR(__skb) (skb_transport_header((__skb)))
#define SSH_SKB_SET_TRHDR(__skb, __ptr) \
   (skb_set_transport_header((__skb), (__ptr) - (__skb)->data))
#define SSH_SKB_RESET_TRHDR(__skb) (skb_reset_transport_header((__skb)))

#else  /* LINUX_HAS_SKB_DATA_ACCESSORS */

#define SSH_SKB_GET_END(__skb) ((__skb)->end)

#define SSH_SKB_GET_TAIL(__skb) ((__skb)->tail)
#define SSH_SKB_SET_TAIL(__skb, __ptr) ((__skb)->tail = (__ptr))
#define SSH_SKB_RESET_TAIL(__skb) ((__skb)->tail = NULL)

#define SSH_SKB_GET_NETHDR(__skb) ((__skb)->nh.raw)
#define SSH_SKB_SET_NETHDR(__skb, __ptr) ((__skb)->nh.raw = (__ptr))
#define SSH_SKB_RESET_NETHDR(__skb) ((__skb)->nh.raw = NULL)

#define SSH_SKB_GET_MACHDR(__skb) ((__skb)->mac.raw)
#define SSH_SKB_SET_MACHDR(__skb, __ptr) ((__skb)->mac.raw = (__ptr))
#define SSH_SKB_RESET_MACHDR(__skb) ((__skb)->mac.raw = NULL)

#define SSH_SKB_GET_TRHDR(__skb) ((__skb)->h.raw)
#define SSH_SKB_SET_TRHDR(__skb, __ptr) ((__skb)->h.raw = (__ptr))
#define SSH_SKB_RESET_TRHDR(__skb) ((__skb)->h.raw = NULL)

#endif /* LINUX_HAS_SKB_DATA_ACCESSORS */

#ifdef LINUX_HAS_SKB_CSUM_OFFSET
/* On linux-2.6.20 and later skb->csum is split into 
   a union of csum and csum_offset. */
#define SSH_SKB_CSUM_OFFSET(__skb) ((__skb)->csum_offset)
#define SSH_SKB_CSUM(__skb) ((__skb)->csum)
#else /* LINUX_HAS_SKB_CSUM_OFFSET */
#define SSH_SKB_CSUM_OFFSET(__skb) ((__skb)->csum)
#define SSH_SKB_CSUM(__skb) ((__skb)->csum)
#endif /* LINUX_HAS_SKB_CSUM_OFFSET */

#ifdef LINUX_NF_INET_HOOKNUMS

#define SSH_NF_IP_PRE_ROUTING NF_INET_PRE_ROUTING
#define SSH_NF_IP_LOCAL_IN NF_INET_LOCAL_IN
#define SSH_NF_IP_FORWARD NF_INET_FORWARD
#define SSH_NF_IP_LOCAL_OUT NF_INET_LOCAL_OUT
#define SSH_NF_IP_POST_ROUTING NF_INET_POST_ROUTING
#define SSH_NF_IP_PRI_FIRST INT_MIN

#define SSH_NF_IP6_PRE_ROUTING NF_INET_PRE_ROUTING
#define SSH_NF_IP6_LOCAL_IN NF_INET_LOCAL_IN
#define SSH_NF_IP6_FORWARD NF_INET_FORWARD
#define SSH_NF_IP6_LOCAL_OUT NF_INET_LOCAL_OUT
#define SSH_NF_IP6_POST_ROUTING NF_INET_POST_ROUTING
#define SSH_NF_IP6_PRI_FIRST INT_MIN

#else /* LINUX_UNIFIED_NETFILTER_IP_HOOKNUMS */

#define SSH_NF_IP_PRE_ROUTING NF_IP_PRE_ROUTING
#define SSH_NF_IP_LOCAL_IN NF_IP_LOCAL_IN
#define SSH_NF_IP_FORWARD NF_IP_FORWARD
#define SSH_NF_IP_LOCAL_OUT NF_IP_LOCAL_OUT
#define SSH_NF_IP_POST_ROUTING NF_IP_POST_ROUTING
#define SSH_NF_IP_PRI_FIRST NF_IP_PRI_FIRST

#define SSH_NF_IP6_PRE_ROUTING NF_IP6_PRE_ROUTING
#define SSH_NF_IP6_LOCAL_IN NF_IP6_LOCAL_IN
#define SSH_NF_IP6_FORWARD NF_IP6_FORWARD
#define SSH_NF_IP6_LOCAL_OUT NF_IP6_LOCAL_OUT
#define SSH_NF_IP6_POST_ROUTING NF_IP6_POST_ROUTING
#define SSH_NF_IP6_PRI_FIRST NF_IP6_PRI_FIRST

#endif /* LINUX_NF_INET_HOOKNUMS */

#ifdef LINUX_HAS_NFPROTO_ARP
#define SSH_NFPROTO_ARP NFPROTO_ARP
#else /* LINUX_HAS_NFPROTO_ARP */
#define SSH_NFPROTO_ARP NF_ARP
#endif /* LINUX_HAS_NFPROTO_ARP */


/*
  Since 2.6.31 there is now skb->dst pointer and
  functions skb_dst() and skb_dst_set() should be used.

  The code is modified to use the functions. For older
  version corresponding macros are defined.
 */
#ifndef LINUX_HAS_SKB_DST_FUNCTIONS
#define skb_dst(__skb) ((__skb)->dst)
#define skb_dst_set(__skb, __dst) ((void)((__skb)->dst = (__dst)))
#endif

/****************************** Statistics helper macros *********************/

#ifdef DEBUG_LIGHT

#define SSH_LINUX_STATISTICS(interceptor, block)         \
do                                                       \
  {                                                      \
    if ((interceptor))                                   \
      {                                                  \
        spin_lock_bh(&(interceptor)->statistics_lock);   \
        block;                                           \
        spin_unlock_bh(&(interceptor)->statistics_lock); \
      }                                                  \
  }                                                      \
while (0)

#else /* DEBUG_LIGHT */

#define SSH_LINUX_STATISTICS(interceptor, block)

#endif /* DEBUG_LIGHT */

/****************************** Interface handling ***************************/

/* Sanity check that the interface index 'ifnum' fits into 
   the SshInterceptorIfnum data type. 'ifnum' may be equal to 
   SSH_INTERCEPTOR_INVALID_IFNUM. */
#define SSH_LINUX_ASSERT_IFNUM(ifnum) \
SSH_ASSERT(((SshUInt32) (ifnum)) < ((SshUInt32) SSH_INTERCEPTOR_MAX_IFNUM) \
|| ((SshUInt32) (ifnum)) == ((SshUInt32) SSH_INTERCEPTOR_INVALID_IFNUM))

/* Sanity check that the interface index 'ifnum' is a valid 
   SshInterceptorIfnum. */
#define SSH_LINUX_ASSERT_VALID_IFNUM(ifnum) \
SSH_ASSERT(((SshUInt32) (ifnum)) < ((SshUInt32) SSH_INTERCEPTOR_MAX_IFNUM) \
&& ((SshUInt32) (ifnum)) != ((SshUInt32) SSH_INTERCEPTOR_INVALID_IFNUM))


/****************************** Proc entries *********************************/

#define SSH_PROC_ENGINE "engine"
#define SSH_PROC_STATISTICS "statistics"
#define SSH_PROC_DEBUG "debug"
#define SSH_PROC_VERSION "version"

/* Ipm receive buffer size. This must be big enough to fit a maximum sized
   IP packet + internal packet data + ipm message header. There is only
   one receive buffer. */
#define SSH_LINUX_IPM_RECV_BUFFER_SIZE 66000

/* Ipm channel message structure. These structures are used for queueing 
   messages from kernel to userspace. The maximum number of allocated messages
   is limited by SSH_LINUX_MAX_IPM_MESSAGES (in linux_params.h). */
typedef struct SshInterceptorIpmMsgRec 
SshInterceptorIpmMsgStruct, *SshInterceptorIpmMsg;

struct SshInterceptorIpmMsgRec 
{
  /* Send queue is doubly linked, freelist uses only `next'. */
  SshInterceptorIpmMsg next;
  SshInterceptorIpmMsg prev;

  Boolean reliable;

  /* Offset for partially sent message */
  size_t offset;
  
  /* Message length and data. */
  size_t len;
  unsigned char *buf;
};

/* Ipm structure */
typedef struct SshInterceptorIpmRec
{
  /* RW lock for protecting the send message queue and the message freelist. */
  rwlock_t lock;

  /* Is ipm channel open */
  atomic_t open;
  
  /* Message freelist and number of allocated messages. */
  SshInterceptorIpmMsg msg_freelist;
  SshUInt32 msg_allocated;

  /* Output message queue */
  SshInterceptorIpmMsg send_queue;
  SshInterceptorIpmMsg send_queue_tail;

} SshInterceptorIpmStruct, *SshInterceptorIpm;


/* Structure for ipm channel /proc entry. */
typedef struct SshInterceptorIpmProcEntryRec
{
  /* /proc filesystem inode */
  struct proc_dir_entry *entry;

  /* RW lock for protecting the proc entry */
  rwlock_t lock;

  /* Is an userspace application using this entry */
  Boolean open;

  /* Is another read ongoing? When this is TRUE 
     then `send_msg' is owned by the reader. */
  Boolean read_active;
  
  /* Is another write ongoing? When this is TRUE
     then `recv_buf' is owned by the writer. */
  Boolean write_active;

  /* Wait queue for blocking mode reads and writes. */
  wait_queue_head_t wait_queue;

  /* Output message under processing. */
  SshInterceptorIpmMsg send_msg;

  /* Input message length */
  size_t recv_len;

  /* Offset in the receive buffer. */
  size_t recv_offset;
  
  /* Input message buffer */
  size_t recv_buf_size;
  unsigned char *recv_buf;
  
} SshInterceptorIpmProcEntryStruct, *SshInterceptorIpmProcEntry;


/* Structure for other /proc entries. */
typedef struct SshInterceptorProcEntryRec
{
  /* /proc filesystem entry */
  struct proc_dir_entry *entry;

  /* RW lock for protecting the proc entry */
  rwlock_t lock;

  /* Is an userspace application using this entry */
  Boolean open;
  
  /* Is another read or write ongoing? When this is TRUE 
     then `buf' is owned by the reader/writer. */
  Boolean active;

  /* Number of bytes returned to the userpace application */
  size_t buf_len;

  /* Preallocated buffer for read and write operations. */
  char buf[1024];

} SshInterceptorProcEntryStruct, *SshInterceptorProcEntry;


/****************************** Interceptor Object ***************************/

struct SshInterceptorRec {

#ifdef SSH_LINUX_INTERCEPTOR_NETFILTER_HOOKS
  SshNfInterceptorStruct nf[1];
#endif /* SSH_LINUX_INTERCEPTOR_NETFILTER_HOOKS */







  /* Engine context */
  SshEngine engine;
  Boolean engine_open;

  /* Callback for packet. */
  SshInterceptorPacketCB packet_callback;

  /* Context for packet callback. */
  void *packet_callback_context;

#if (SSH_LINUX_INTERCEPTOR_NR_CPUS > 1)
  SshInterceptorPacketCB active_packet_callback[SSH_LINUX_INTERCEPTOR_NR_CPUS];
#endif /* SSH_LINUX_INTERCEPTOR_NR_CPUS > 1 */

  /* Name of related engine-instance */
  char *name;

  /* Ipm channel */
  SshInterceptorIpmStruct ipm;

  /* /proc filesystem entries */
  struct proc_dir_entry *proc_dir;

  SshInterceptorIpmProcEntryStruct ipm_proc_entry;
  
  SshInterceptorProcEntryStruct version_proc_entry;
#ifdef DEBUG_LIGHT
  SshInterceptorProcEntryStruct debug_proc_entry;
  SshInterceptorProcEntryStruct stats_proc_entry;
#endif /* DEBUG_LIGHT */

  /* Debug level */
  unsigned char debug_level_string[128];

  /* Main mutex for interceptor use */
  SshKernelMutex interceptor_lock;

  /* Mutex for timeouts only */
  SshKernelMutex timeout_lock;

  /* Mutex for memory map manipulation */
  SshKernelMutex memory_lock;

  /* Mutex for packet handling */
  SshKernelMutex packet_lock;

  /* Protected by SSH_TIMEOUT_QUEUE_LOCK() and SSH_TIMEOUT_QUEUE_UNLOCK()
     macros */
  int num_timeout_callbacks;
  int num_timeouts;

#ifdef DEBUG_LIGHT
  /* Statistics spin lock */
  spinlock_t statistics_lock;

  struct {
    /* Statistics */
    SshUInt64 num_packets_out;
    SshUInt64 num_packets_in;
    SshUInt64 num_bytes_out;
    SshUInt64 num_bytes_in;
    SshUInt64 num_passthrough;
    SshUInt64 num_fastpath_packets_in;
    SshUInt64 num_fastpath_packets_out;
    SshUInt64 num_fastpath_bytes_in;
    SshUInt64 num_fastpath_bytes_out;
    SshUInt64 num_errors;
    SshUInt64 num_packets_sent;
    SshUInt64 num_bytes_sent;
    SshUInt64 allocated_memory;
    SshUInt64 allocated_memory_max;
    SshUInt64 num_allocations;
    SshUInt64 num_allocations_large;
    SshUInt64 num_allocations_total;
    SshUInt64 num_allocated_packets;
    SshUInt64 num_allocated_packets_total;
    SshUInt64 num_copied_packets;
    SshUInt64 num_failed_allocs;
    SshUInt64 num_light_locks;
    SshUInt64 num_light_interceptor_locks;
    SshUInt64 num_heavy_locks;
    SshUInt64 num_timeout_run;
    SshUInt64 num_timeout_cancelled;
    SshUInt64 ipm_send_queue_len;
    SshUInt64 ipm_send_queue_bytes;
  } stats;
#endif /* DEBUG_LIGHT */



























  /* Are timeouts disabled? */
  Boolean is_timeout_shutdown;








};

typedef struct SshInterceptorRec SshInterceptorStruct;

/****************************** Function prototypes **************************/

/* Call packet_callback */
#if (SSH_LINUX_INTERCEPTOR_NR_CPUS > 1)

/* On SMP systems, the used packet_callback function pointer
   is written to the CPU's slot in the 'active_packet_callback'
   table before making the call, and cleared after return from 
   the callback. During interceptor_uninit the packet_callback 
   is set to a dummy callback, and table is checked to ensure 
   that no kernel threads are using the real packet_callback. */
#define SSH_LINUX_INTERCEPTOR_PACKET_CALLBACK(interceptor, pkt)              \
do                                                                           \
  {                                                                          \
    SshUInt32 cpu_id = smp_processor_id();                                   \
    (interceptor)->active_packet_callback[cpu_id] =                          \
      (interceptor)->packet_callback;                                        \
    ((interceptor)->active_packet_callback[cpu_id])                          \
      ((SshInterceptorPacket) (pkt), (interceptor)->packet_callback_context);\
    (interceptor)->active_packet_callback[cpu_id] = NULL_FNPTR;              \
  }                                                                          \
while (0);

#else /* SSH_LINUX_INTERCEPTOR_NR_CPUS <= 1 */

/* On UP systems, just call the callback. */
#define SSH_LINUX_INTERCEPTOR_PACKET_CALLBACK(interceptor, pkt)              \
do                                                                           \
  {                                                                          \
    ((interceptor)->packet_callback)                                         \
      ((SshInterceptorPacket) (pkt), (interceptor)->packet_callback_context);\
  }                                                                          \
while (0);

#endif /* SSH_LINUX_INTERCEPTOR_NR_CPUS > 1 */

/* Proc entries */
Boolean ssh_interceptor_proc_init(SshInterceptor interceptor);
void ssh_interceptor_proc_uninit(SshInterceptor interceptor);

/* Ipm channel */

/* init / uninit */
Boolean ssh_interceptor_ipm_init(SshInterceptor interceptor);
void ssh_interceptor_ipm_uninit(SshInterceptor interceptor);

/* open / close. These functions handle ipm message queue flushing. */
void interceptor_ipm_open(SshInterceptor interceptor);
void interceptor_ipm_close(SshInterceptor interceptor);

/* open / close notifiers. These functions notify engine. */
void ssh_interceptor_notify_ipm_open(SshInterceptor interceptor);
void ssh_interceptor_notify_ipm_close(SshInterceptor interceptor);

Boolean ssh_interceptor_send_to_ipm(unsigned char *data, size_t len,
				    Boolean reliable, void *machine_context);
ssize_t ssh_interceptor_receive_from_ipm(unsigned char *data, size_t len);

void interceptor_ipm_message_free(SshInterceptor interceptor,
                                  SshInterceptorIpmMsg msg);

/* Debug */
void ssh_kernel_fatal_callback(const char *buf, void *context);
void ssh_kernel_warning_callback(const char *buf, void *context);
void ssh_kernel_debug_callback(const char *buf, void *context);

size_t ssh_interceptor_get_debug_level(SshInterceptor interceptor,
				       char *debug_string,
				       size_t debug_string_len);
void ssh_interceptor_set_debug_level(SshInterceptor interceptor,
				     char *debug_string);
void ssh_interceptor_restore_debug_level(SshInterceptor interceptor);
Boolean ssh_interceptor_debug_init(SshInterceptor interceptor);
void ssh_interceptor_debug_uninit(SshInterceptor interceptor);

/* Packet access and manipulation. */

/* Header-only allocation.
   This function will assert that the interface numbers will
   fit into the data type SshInterceptorIfnum. */
SshInterceptorInternalPacket
ssh_interceptor_packet_alloc_header(SshInterceptor interceptor,
                                    SshUInt32 flags,
                                    SshInterceptorProtocol protocol,
                                    SshUInt32 ifnum_in,
                                    SshUInt32 ifnum_out,
                                    struct sk_buff *skb,
                                    Boolean force_copy_skbuff,
                                    Boolean free_original_on_copy,
				    Boolean packet_from_system);



/* Allocates new packet skb with copied data from original
   + the extra free space reserved for extensions. */
struct sk_buff *
ssh_interceptor_packet_skb_dup(SshInterceptor interceptor,
			       struct sk_buff *skb,
                               size_t addbytes_active_ofs,
                               size_t addbytes_active);

/* Packet duplication */
SshInterceptorPacket
ssh_interceptor_packet_dup(SshInterceptor interceptor,
                          SshInterceptorPacket pp);

/* Align the interceptor packet at the data offset 'offset' to a word
   boundary. On failure, 'pp' is freed and returns FALSE. */
Boolean
ssh_interceptor_packet_align(SshInterceptorPacket packet, size_t offset);

/* Verify that `skbp' has enough headroom to be sent out through `skbp->dev'.
   On failure this frees `skbp' and returns NULL. */
struct sk_buff *
ssh_interceptor_packet_verify_headroom(struct sk_buff *skbp, 
				       size_t media_header_len);

/* Packet freelist init / uninit. */
Boolean ssh_interceptor_packet_freelist_init(SshInterceptor interceptor);
void ssh_interceptor_packet_freelist_uninit(SshInterceptor interceptor);
int ssh_interceptor_packet_freelist_stats(SshInterceptor interceptor,
					  char *buf, int maxsize);

int ssh_linux_module_inc_use_count(void);
void ssh_linux_module_dec_use_count(void);

/* Timeouts. */

/* Locking macros to protect the timeout callback counters 
   in linux_main.c and linux_timeout.c */
#define SSH_TIMEOUT_QUEUE_LOCK(interceptor)                                 \
  ssh_kernel_mutex_lock((interceptor)->interceptor_lock)

#define SSH_TIMEOUT_QUEUE_UNLOCK(interceptor)                               \
  ssh_kernel_mutex_unlock((interceptor)->interceptor_lock)

#define SSH_TIMEOUT_RUN_LOCK(interceptor)                                   \
  ssh_kernel_mutex_lock((interceptor)->timeout_lock)

#define SSH_TIMEOUT_RUN_UNLOCK(interceptor)                                 \
  ssh_kernel_mutex_unlock((interceptor)->timeout_lock)

/* Free any cached timeouts on the freelist. */
void ssh_kernel_timeout_freelist_uninit(void);

/* Initialize the freelist with the defined (SSH_KERNEL_TIMO_FL_LENGHT)
   amount of entries cached on it. */
void ssh_kernel_timeout_freelist_init(void);




































#endif /* LINUX_INTERNAL_H */
