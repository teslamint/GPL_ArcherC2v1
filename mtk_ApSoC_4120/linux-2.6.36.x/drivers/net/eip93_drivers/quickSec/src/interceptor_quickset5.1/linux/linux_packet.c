/*

  linux_packet.c

  Copyright:
          Copyright (c) 2002-2008 SFNT Finland Oy.
	  All rights reserved

  Packet manipulation functions, all ssh_interceptor_packet* functions.

*/

#include "linux_internal.h"
#include "linux_packet_internal.h"

#define SSH_DEBUG_MODULE "SshInterceptorPacket"

/* Packet context freelist head pointer array. There is a freelist entry for
   each CPU and one freelist entry (with index SSH_LINUX_INTERCEPTOR_NR_CPUS)
   shared among all CPU's. When getting a packet, the current CPU freelist is
   searched, if that is empty the shared freelist is searched (which requires
   taking a lock). When returning a packet, if the CPU is the same as when
   the packet was allocated, the packet is returned to the CPU freelist, if
   not it is returned to the shared freelist (which again requires taking
   a lock). */
struct SshInterceptorInternalPacketRec
*ssh_packet_freelist_head[SSH_LINUX_INTERCEPTOR_NR_CPUS + 1] = {NULL};

#ifdef DEBUG_LIGHT

static int freelist_got[SSH_LINUX_INTERCEPTOR_NR_CPUS + 1];
static int freelist_alloc;
static int freelist_reused;

int ssh_interceptor_packet_freelist_stats(SshInterceptor interceptor,
					  char *buf, int maxsize)
{
  int len;

  ssh_kernel_mutex_lock(interceptor->packet_lock);
  len = ssh_snprintf(buf, maxsize,
                     "Freelist list - "
                     "reused:%d allocated:%d\n",
                     freelist_reused,
                     freelist_alloc);

  ssh_kernel_mutex_unlock(interceptor->packet_lock);
  return len;
}

#endif /* DEBUG_LIGHT */







































static inline SshInterceptorInternalPacket
ssh_freelist_packet_get(SshInterceptor interceptor,
			Boolean may_borrow)
{





  SshInterceptorInternalPacket p;
  unsigned int cpu;

  icept_preempt_disable();

  cpu = smp_processor_id();

  p = ssh_packet_freelist_head[cpu];
  if (p)
    {
      p->cpu = cpu;

      ssh_packet_freelist_head[p->cpu] =
	(SshInterceptorInternalPacket) p->packet.next;

#ifdef DEBUG_LIGHT
      ssh_kernel_mutex_lock(interceptor->packet_lock);
      freelist_reused++;
      ssh_kernel_mutex_unlock(interceptor->packet_lock);
#endif /* DEBUG_LIGHT */
    }
  else
    {
      /* Try getting a packet from the shared freelist */
      ssh_kernel_mutex_lock(interceptor->packet_lock);

      p = ssh_packet_freelist_head[SSH_LINUX_INTERCEPTOR_NR_CPUS];
      if (p)
	{
	  p->cpu = cpu;

	  ssh_packet_freelist_head[SSH_LINUX_INTERCEPTOR_NR_CPUS] =
	    (SshInterceptorInternalPacket) p->packet.next;

#ifdef DEBUG_LIGHT
	  freelist_reused++;
#endif /* DEBUG_LIGHT */
	  ssh_kernel_mutex_unlock(interceptor->packet_lock);
	  goto done;
	}
      ssh_kernel_mutex_unlock(interceptor->packet_lock);









      p = ssh_malloc(sizeof(*p));


      if (!p)
	goto done;

      p->cpu = cpu;
#ifdef DEBUG_LIGHT
      ssh_kernel_mutex_lock(interceptor->packet_lock);



      freelist_alloc++;
      ssh_kernel_mutex_unlock(interceptor->packet_lock);
#endif /* DEBUG_LIGHT */
    }

 done:

#ifdef DEBUG_LIGHT
  if (p)
    freelist_got[p->cpu]++;










#endif /* DEBUG_LIGHT */

  icept_preempt_enable();

  return p;
}

static inline void
ssh_freelist_packet_put(SshInterceptor interceptor,
                        SshInterceptorInternalPacket p)
{
  unsigned int cpu;

  icept_preempt_disable();

  cpu = p->cpu;

  SSH_ASSERT(cpu < SSH_LINUX_INTERCEPTOR_NR_CPUS);

#ifdef DEBUG_LIGHT
  memset(p, 'F', sizeof(*p));
#endif /* DEBUG_LIGHT */

  if (likely(cpu == smp_processor_id()))
    {
      p->packet.next =
	(SshInterceptorPacket) ssh_packet_freelist_head[cpu];
      ssh_packet_freelist_head[cpu] = p;
    }
  else
    {
      cpu = SSH_LINUX_INTERCEPTOR_NR_CPUS;
      
      /* The executing CPU is not the same as when the packet was
	 allocated. Put the packet back to the shared freelist */
      ssh_kernel_mutex_lock(interceptor->packet_lock);
      
      p->packet.next =
	(SshInterceptorPacket) ssh_packet_freelist_head[cpu];
      ssh_packet_freelist_head[cpu] = p;
      
      ssh_kernel_mutex_unlock(interceptor->packet_lock);
    }

  icept_preempt_enable();
}


Boolean
ssh_interceptor_packet_freelist_init(SshInterceptor interceptor)
{
  unsigned int i;

  for (i = 0; i < SSH_LINUX_INTERCEPTOR_NR_CPUS + 1; i++)
    ssh_packet_freelist_head[i] = NULL;

#ifdef DEBUG_LIGHT
  freelist_alloc = 0;
  freelist_reused = 0;
#endif /* DEBUG_LIGHT */
  return TRUE;
}

void
ssh_interceptor_packet_freelist_uninit(SshInterceptor interceptor)
{
  SshInterceptorInternalPacket p;
  unsigned int i;

  ssh_kernel_mutex_lock(interceptor->packet_lock);

  for (i = 0; i < SSH_LINUX_INTERCEPTOR_NR_CPUS + 1; i++)
    {
#ifdef DEBUG_HEAVY
      printk("CPU %i, packets got=%d\n", i, freelist_got[i]);
#endif /* DEBUG_HEAVY */

      /* Traverse freelist and free allocated all packets. */
      p = ssh_packet_freelist_head[i];
      while (p != NULL)
	{
	  ssh_packet_freelist_head[i] =
	    (SshInterceptorInternalPacket) p->packet.next;



















	  ssh_free(p);

	  p = ssh_packet_freelist_head[i];
#ifdef DEBUG_LIGHT
	  freelist_alloc--;
#endif /* DEBUG_LIGHT */
	}
    }

#ifdef DEBUG_LIGHT
  if (freelist_alloc != 0)
    {
      printk("<3> WARNING: %d SshInterceptorPackets are missing "
	     "from the freelist!\n", freelist_alloc);
















































    }
#endif /* DEBUG_LIGHT */

  ssh_kernel_mutex_unlock(interceptor->packet_lock);
}

/******************************************* General packet allocation stuff */

/* Allocates new packet skb with copied data from original
   + the extra free space reserved for extensions. */
struct sk_buff *
ssh_interceptor_packet_skb_dup(SshInterceptor interceptor,
			       struct sk_buff *skb,
                               size_t addbytes_active_ofs,
                               size_t addbytes_active)
{
  struct sk_buff *new_skb;
  ssize_t offset;
  size_t addbytes_spare_start = SSH_INTERCEPTOR_PACKET_HEAD_ROOM;
  size_t addbytes_spare_end = SSH_INTERCEPTOR_PACKET_TAIL_ROOM;
  unsigned char *ptr;

  SSH_DEBUG(SSH_D_LOWOK,
	    ("skb dup: len %d extra %d offset %d headroom %d tailroom %d",
	     skb->len, addbytes_active, addbytes_active_ofs,
	     addbytes_spare_start, addbytes_spare_end));

  /* Create new skb */
  new_skb = alloc_skb(skb->len + addbytes_active +
                      addbytes_spare_start +
                      addbytes_spare_end,
                      SSH_LINUX_ALLOC_SKB_GFP_MASK);
  if (!new_skb)
    {
      SSH_LINUX_STATISTICS(interceptor,
      { interceptor->stats.num_failed_allocs++; });
      return NULL;
    }

  /* Set the fields */
  new_skb->len = skb->len + addbytes_active;
  new_skb->data = new_skb->head + addbytes_spare_start;
  SSH_SKB_SET_TAIL(new_skb, new_skb->data + new_skb->len);
  new_skb->protocol = skb->protocol;
  new_skb->dev = skb->dev;

  new_skb->pkt_type = skb->pkt_type;
#ifdef LINUX_HAS_SKB_STAMP
  new_skb->stamp = skb->stamp;
#endif /* LINUX_HAS_SKB_STAMP */
  new_skb->destructor = NULL_FNPTR;

  /* Set transport header offset. TX Checksum offloading relies this to be
     set in the case that the checksum has to be calculated in software
     in dev_queue_xmit(). */
  ptr = SSH_SKB_GET_TRHDR(skb);
  if (ptr != NULL)
    {
      offset = ptr - skb->data;
      if (offset > addbytes_active_ofs)
	offset += addbytes_active;
      SSH_SKB_SET_TRHDR(new_skb, new_skb->data + offset);
    }

  /* Set mac header offset. This is set for convinience. Note that if
     mac header has already been removed from the sk_buff then the mac
     header data is not copied to the duplicate. */
  ptr = SSH_SKB_GET_MACHDR(skb);
  if (ptr != NULL)
    {
      offset = ptr - skb->data;
      if (offset > addbytes_active_ofs)
	offset += addbytes_active;
      SSH_SKB_SET_MACHDR(new_skb, new_skb->data + offset);
    }

  /* Set network header offset. This one is maintained out of convenience
     (so we need not do setting by hand unless we definitely want to, 
     i.e. sending packet out). */
  ptr = SSH_SKB_GET_NETHDR(skb);
  if (ptr != NULL)
    {
      offset = ptr - skb->data;
      if (offset > addbytes_active_ofs)
	offset += addbytes_active;
      SSH_SKB_SET_NETHDR(new_skb, new_skb->data + offset);
    }

  /* not used by old interceptor. */
  new_skb->sk = NULL; /* kernel does this.. copying might make more sense? */

  /* not needed according to kernel (alloc_skb does this) */
  atomic_set(&new_skb->users, 1);

  /* Set csum fields. */
  new_skb->ip_summed = skb->ip_summed;
  if (
#ifdef LINUX_HAS_NEW_CHECKSUM_FLAGS
      new_skb->ip_summed == CHECKSUM_COMPLETE
#else /* LINUX_HAS_NEW_CHECKSUM_FLAGS */
      new_skb->ip_summed == CHECKSUM_HW
#endif /* LINUX_HAS_NEW_CHECKSUM_FLAGS */
      )
    {
      SSH_SKB_CSUM(new_skb) = SSH_SKB_CSUM(skb);
    }
#ifdef LINUX_HAS_NEW_CHECKSUM_FLAGS
  else if (new_skb->ip_summed == CHECKSUM_PARTIAL)
    {
      SSH_SKB_CSUM_OFFSET(new_skb) = SSH_SKB_CSUM_OFFSET(skb);
#ifdef LINUX_HAS_SKB_CSUM_START
      /* Set csum_start. */
      offset = (skb->head + skb->csum_start) - skb->data;
      if (offset > addbytes_active_ofs)
	offset += addbytes_active;
      new_skb->csum_start = (new_skb->data + offset) - new_skb->head;
#endif /* LINUX_HAS_SKB_CSUM_START */
    }
#endif /* LINUX_HAS_NEW_CHECKSUM_FLAGS */
  else
    {
      SSH_SKB_CSUM(new_skb) = 0;
    }

  new_skb->priority = skb->priority;
  skb_dst_set(new_skb, dst_clone(skb_dst(skb)));
  memcpy(new_skb->cb, skb->cb, sizeof(skb->cb));

#ifdef LINUX_HAS_SKB_SECURITY
  new_skb->security = skb->security;
#endif /* LINUX_HAS_SKB_SECURITY */

#ifdef CONFIG_NETFILTER
  SSH_SKB_MARK(new_skb) = SSH_SKB_MARK(skb);
#ifdef LINUX_HAS_SKB_NFCACHE
  new_skb->nfcache = NFC_UNKNOWN;
#endif /* LINUX_HAS_SKB_NFCACHE */
#ifdef CONFIG_NETFILTER_DEBUG
#ifdef LINUX_HAS_SKB_NFDEBUG
  new_skb->nf_debug = skb->nf_debug;
#endif /* LINUX_HAS_SKB_NFDEBUG */
#endif /* CONFIG_NETFILTER_DEBUG */
#endif /* CONFIG_NETFILTER */

  SSH_LINUX_STATISTICS(interceptor,
  { interceptor->stats.num_copied_packets++; });
  
  /* Copy data from
     active_ofs+ => active_ofs+addbytes+ */
  if ((skb->len - addbytes_active_ofs) > 0)
    {
      memcpy(new_skb->data + addbytes_active_ofs + addbytes_active,
             skb->data + addbytes_active_ofs,
             skb->len - addbytes_active_ofs);
    }

  /* Copy the 0+ => 0+ where value < ofs (header part that is
     left alone). */
  if (addbytes_active_ofs > 0)
    {
      SSH_ASSERT(addbytes_active_ofs <= skb->len);
      memcpy(new_skb->data,
             skb->data,
             addbytes_active_ofs);
    }

  return new_skb;
}



/* Allocates a packet header wrapping the given skbuff.
   Packet headers can be allocated only using this function.

   Note that the actual packet->skb is NULL after packet has been
   returned.

   This function returns NULL if the packet header cannot be
   allocated. */

SshInterceptorInternalPacket
ssh_interceptor_packet_alloc_header(SshInterceptor interceptor,
                                    SshUInt32 flags,
                                    SshInterceptorProtocol protocol,
                                    SshUInt32 ifnum_in,
                                    SshUInt32 ifnum_out,
				    struct sk_buff *skb,
                                    Boolean force_copy_skbuff,
                                    Boolean free_original_on_copy,
				    Boolean packet_from_system)
{
  SshInterceptorInternalPacket p;

  /* Linearize the packet in case it isn't already. */
#ifdef LINUX_SKB_LINEARIZE_NEEDS_FLAGS
  if (skb && skb_is_nonlinear(skb) && skb_linearize(skb, GFP_ATOMIC) != 0)
    return NULL;
#else /* LINUX_SKB_LINEARIZE_NEEDS_FLAGS */
  if (skb && skb_is_nonlinear(skb) && skb_linearize(skb) != 0)
    return NULL;
#endif /* LINUX_SKB_LINEARIZE_NEEDS_FLAGS */
  
  /* Allocate a wrapper structure */
  p = ssh_freelist_packet_get(interceptor, !packet_from_system);
  if (p == NULL)
    {
      SSH_LINUX_STATISTICS(interceptor,
      { interceptor->stats.num_failed_allocs++; });
      return NULL;
    }

  /* Initialize all the fields */
  p->packet.flags = flags;

  /* Assert that the interface number fits into SshInterceptorIfnum.
     Note that both interface numbers may be equal to
     SSH_INTERCEPTOR_INVALID_IFNUM. */
  SSH_LINUX_ASSERT_IFNUM(ifnum_in);
  SSH_LINUX_ASSERT_IFNUM(ifnum_out);

  p->packet.ifnum_in = ifnum_in;
  p->packet.ifnum_out = ifnum_out;
  p->original_ifnum = ifnum_in;

#ifdef SSH_IPSEC_IP_ONLY_INTERCEPTOR
  p->packet.route_selector = 0;
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */

  p->packet.pmtu = 0;
  p->packet.protocol = protocol;
#if (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0)
  memset(p->packet.extension, 0, sizeof(p->packet.extension));
#ifdef SSH_LINUX_FWMARK_EXTENSION_SELECTOR
  /* Copy the linux fwmark to the extension slot indexed by
     SSH_LINUX_FWMARK_EXTENSION_SELECTOR. */
  if (skb)
    p->packet.extension[SSH_LINUX_FWMARK_EXTENSION_SELECTOR] = 
      SSH_SKB_MARK(skb);
#endif /* SSH_LINUX_FWMARK_EXTENSION_SELECTOR */
#endif /* (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0) */
  p->interceptor = interceptor;
  p->skb = skb;

  SSH_LINUX_STATISTICS(interceptor,
  {
    interceptor->stats.num_allocated_packets++;
    interceptor->stats.num_allocated_packets_total++;
  });

  if (skb)
    {
      /* we have skb */
      if (force_copy_skbuff || skb_cloned(skb))
        {
          /* The skb was already cloned, so make a new copy to be modified by
           * the engine processing. */
          p->skb = ssh_interceptor_packet_skb_dup(interceptor, skb, 0, 0);
          if (p->skb == NULL)
            {
	      SSH_LINUX_STATISTICS(interceptor, 
	      { interceptor->stats.num_allocated_packets--; });
	      ssh_freelist_packet_put(interceptor, p);
              return NULL;
            }

          if (free_original_on_copy)
            {
              /* Free the original buffer as we will not return it anymore */
              dev_kfree_skb_any(skb);
            }
        }
      else
        {
          /* No one else has cloned the original skb, so use it
             without copying */
          p->skb = skb;
        }

      /* If the packet is of media-broadcast persuasion, add it to the
         flags. */
      if (p->skb->pkt_type == PACKET_BROADCAST)
        p->packet.flags |= SSH_PACKET_MEDIABCAST;
      if (p->skb->pkt_type == PACKET_MULTICAST)
        p->packet.flags |= SSH_PACKET_MEDIABCAST;
      
#ifdef LINUX_HAS_NEW_CHECKSUM_FLAGS
      if (p->skb->ip_summed == CHECKSUM_COMPLETE 
	  || p->skb->ip_summed == CHECKSUM_PARTIAL)
	p->packet.flags |= SSH_PACKET_HWCKSUM;
#else /* LINUX_HAS_NEW_CHECKSUM_FLAGS */
      if (p->skb->ip_summed == CHECKSUM_HW)
	p->packet.flags |= SSH_PACKET_HWCKSUM;
#endif /* LINUX_HAS_NEW_CHECKSUM_FLAGS */

      SSH_DEBUG(SSH_D_LOWOK,
		("alloc header: skb len %d headroom %d tailroom %d",
		 p->skb->len, skb_headroom(p->skb), skb_tailroom(p->skb)));
    }

  return p;
}

/* Linux-interceptor-specific feature for duplicating existing packet
   in it's entirety. */
SshInterceptorPacket
ssh_interceptor_packet_dup(SshInterceptor interceptor,
                           SshInterceptorPacket pp)
{
  SshInterceptorInternalPacket new_packet;
  SshInterceptorInternalPacket ipp = (SshInterceptorInternalPacket)pp;

  /* Create similar header. */
  if ((new_packet =
       ssh_interceptor_packet_alloc_header(interceptor,
					   pp->flags,
					   pp->protocol,
					   pp->ifnum_in,
					   pp->ifnum_out,
					   ipp->skb,
					   TRUE,
					   FALSE,
					   FALSE)) != NULL)
    {
      new_packet->original_ifnum = ipp->original_ifnum;
    }
  return (SshInterceptorPacket)new_packet;
}


/* Allocates a packet of at least the given size.  Packets can only be
   allocated using this function (either internally by the interceptor or
   by other code by calling this function).  This returns NULL if no more
   packets can be allocated. */

SshInterceptorPacket
ssh_interceptor_packet_alloc(SshInterceptor interceptor,
                             SshUInt32 flags,
                             SshInterceptorProtocol protocol,
                             SshInterceptorIfnum ifnum_in,
                             SshInterceptorIfnum ifnum_out,
			     size_t total_len)
{
  SshInterceptorInternalPacket packet;
  size_t len;
  struct sk_buff *skb;

  packet = (SshInterceptorInternalPacket)
    ssh_interceptor_packet_alloc_header(interceptor,
                                        flags,
                                        protocol,
					ifnum_in,
					ifnum_out,
					NULL,
					FALSE,
                                        FALSE,
					FALSE);
  if (!packet)
    return NULL;                /* header allocation failed */

  /* Allocate actual kernel packet. Note that some overhead is calculated
     so that media headers etc. fit without additional allocations or
     copying. */
  len = total_len + SSH_INTERCEPTOR_PACKET_HEAD_ROOM +
    SSH_INTERCEPTOR_PACKET_TAIL_ROOM;
  skb = alloc_skb(len, SSH_LINUX_ALLOC_SKB_GFP_MASK);
  if (skb == NULL)
    {
      SSH_LINUX_STATISTICS(interceptor, 
      { interceptor->stats.num_failed_allocs++; });
      ssh_freelist_packet_put(interceptor, packet);
      return NULL;
    }
  packet->skb = skb;

  /* Set data area inside the packet */
  skb->len = total_len;
  skb->data = skb->head + SSH_INTERCEPTOR_PACKET_HEAD_ROOM;
  SSH_SKB_SET_TAIL(skb, skb->data + total_len);

  /* Ensure the IP header offset is 16 byte aligned for ethernet frames. */
  if (protocol == SSH_PROTOCOL_ETHERNET)
    {
      /* Assert that SSH_INTERCEPTOR_PACKET_TAIL_ROOM is large enough */
      SSH_ASSERT(SSH_SKB_GET_END(skb) - SSH_SKB_GET_TAIL(skb) >= 2);
      skb->data += 2;
      /* This works on both pointers and offsets. */
      skb->tail += 2;
    }

#ifdef LINUX_HAS_NEW_CHECKSUM_FLAGS
  if (flags & SSH_PACKET_HWCKSUM)
    {
      if (flags & SSH_PACKET_FROMADAPTER)
	skb->ip_summed = CHECKSUM_COMPLETE;
      else if (flags & SSH_PACKET_FROMPROTOCOL)
	skb->ip_summed = CHECKSUM_PARTIAL;
    }
#else /* LINUX_HAS_NEW_CHECKSUM_FLAGS */
  if (flags & SSH_PACKET_HWCKSUM)
    skb->ip_summed = CHECKSUM_HW;
#endif /* LINUX_HAS_NEW_CHECKSUM_FLAGS */

  /* If support for other than IPv6, IPv4 and ARP
     inside the engine on Linux are to be supported, their
     protocol types must be added here. */
  switch(protocol)
    {
#ifdef SSH_LINUX_INTERCEPTOR_IPV6
    case SSH_PROTOCOL_IP6:
      skb->protocol = __constant_htons(ETH_P_IPV6);
      break;
#endif /* SSH_LINUX_INTERCEPTOR_IPV6 */

    case SSH_PROTOCOL_ARP:
      skb->protocol = __constant_htons(ETH_P_ARP);
      break;

    case SSH_PROTOCOL_IP4:
    default:
      skb->protocol = __constant_htons(ETH_P_IP);
      break;
    }

  SSH_DEBUG(SSH_D_LOWOK,
	    ("alloc packet: skb len %d headroom %d tailroom %d",
	     packet->skb->len, skb_headroom(packet->skb),
	     skb_tailroom(packet->skb)));

  return (SshInterceptorPacket) packet;
}

/* Frees the given packet. All packets allocated by
   ssh_interceptor_packet_alloc must eventually be freed using this
   function by either calling this explicitly or by passing the packet
   to the interceptor send function. */

void
ssh_interceptor_packet_free(SshInterceptorPacket pp)
{
  SshInterceptorInternalPacket packet = (SshInterceptorInternalPacket) pp;

  /* Free the packet buffer first */
  if (packet->skb)
    {
      dev_kfree_skb_any(packet->skb);
      packet->skb = NULL;
    }

  SSH_LINUX_STATISTICS(packet->interceptor, 
  { packet->interceptor->stats.num_allocated_packets--; });

  /* Free the wrapper */
  ssh_freelist_packet_put(packet->interceptor, packet);
}


#ifdef INTERCEPTOR_HAS_PACKET_CACHE
SshInterceptorPacket
ssh_interceptor_packet_cache(SshInterceptor interceptor,
			     SshInterceptorPacket pp)
{
  SshInterceptorInternalPacket src = (SshInterceptorInternalPacket) pp;
  SshInterceptorInternalPacket dst;

  /* Allocate a wrapper structure */
  dst = ssh_freelist_packet_get(interceptor, TRUE);
  if (dst == NULL)
    {
      SSH_LINUX_STATISTICS(interceptor, 
      { interceptor->stats.num_failed_allocs++; });
      return NULL;
    }

  dst->interceptor = src->interceptor;
  dst->packet = src->packet;
  dst->packet.next = NULL;

  dst->original_ifnum = src->original_ifnum;

  SSH_LINUX_STATISTICS(interceptor, 
  {
    interceptor->stats.num_allocated_packets++;
    interceptor->stats.num_allocated_packets_total++;
  });

  if (src->skb)
    dst->skb = skb_get(src->skb);

  return (SshInterceptorPacket) dst;
}
#endif /* INTERCEPTOR_HAS_PACKET_CACHE */

#if defined(KERNEL_INTERCEPTOR_USE_FUNCTIONS) || !defined(KERNEL)
/* Returns the length of the data packet. */
size_t
ssh_interceptor_packet_len(SshInterceptorPacket pp)
{
  SshInterceptorInternalPacket packet = (SshInterceptorInternalPacket) pp;
  return packet->skb->len;
}

/* Returns a pointer to the first byte of the packet that can be
   modified. */
unsigned char *
ssh_interceptor_packet_pullup(SshInterceptorPacket pp, size_t bytes)
{
  SshInterceptorInternalPacket packet = (SshInterceptorInternalPacket) pp;

  return packet->skb->data;
}

/* Returns a pointer to the first byte of the packet that should
   not be modified. */
const unsigned char *
ssh_interceptor_packet_pullup_read(SshInterceptorPacket pp, size_t bytes)
{
  SshInterceptorInternalPacket packet = (SshInterceptorInternalPacket) pp;

  return packet->skb->data;
}
#endif /* defined(KERNEL_INTERCEPTOR_USE_FUNCTIONS) || !defined(KERNEL) */

/* Inserts space for the given number of bytes in the packet. This
   doesn't copy any actual data into the packet. Implementation note: most
   of the time, the insertion will take place near the start of the packet,
   and only twenty or so bytes are typically inserted. */

unsigned char *
ssh_interceptor_packet_insert(SshInterceptorPacket pp,
                              size_t offset, size_t bytes)
{
  SshInterceptorInternalPacket packet = (SshInterceptorInternalPacket) pp;
  struct sk_buff *new_skb, *skb;

  skb = packet->skb;

  if (offset == 0)
    {
      /* If there is enough unused space at the start of the packet,
         just use it. */
      if (skb->data - skb->head >=
          bytes + SSH_INTERCEPTOR_PACKET_HARD_HEAD_ROOM)
        {
          skb->data -= bytes;
          skb->len += bytes;

	  SSH_DEBUG(SSH_D_LOWOK,
		    ("prepended to packet %p %d bytes, "
		     "headroom %d tailroom %d",
		     pp, bytes, skb_headroom(skb), skb_tailroom(skb)));

          return skb->data;
        }
    }

  /* If there is enough space at the start of the packet and insertation
     offset is closer to head, move the head to make enough room */
  if ((skb->data - skb->head >= bytes + SSH_INTERCEPTOR_PACKET_HARD_HEAD_ROOM)
      && offset < skb->len - offset)
    {
      memmove(skb->data - bytes, skb->data, offset);
      skb->data -= bytes;
      skb->len += bytes;

      SSH_DEBUG(SSH_D_LOWOK,
		("inserted to packet %p head %d bytes at offset %d, "
		 "moved %d bytes, headroom %d tailroom %d",
		 pp, bytes, offset, 
		 offset, skb_headroom(skb), skb_tailroom(skb)));

      return skb->data + offset;
    }

  /* Next best situation is when there is enough space at the
     end of the packet. Just copy the tail of the packet. */
  if (SSH_SKB_GET_END(skb) - SSH_SKB_GET_TAIL(skb) > bytes)
    {
      if (skb->len - offset > 0)
        memmove(skb->data + offset + bytes, skb->data + offset,
                skb->len - offset);

      skb->len += bytes;
      /* This works for both pointers and offsets. */
      skb->tail += bytes;

      SSH_DEBUG(SSH_D_LOWOK,
		("inserted to packet %p tail %d bytes at offset %d, "
		 "moved %d bytes, headroom %d tailroom %d",
		 pp, bytes, offset, 
		 ((skb->len - bytes - offset) > 0 ?
		  (skb->len - bytes - offset) : 0),
		 skb_headroom(skb), skb_tailroom(skb)));

      return skb->data + offset;
    }

  /* The most unfortunate case. We must allocate a new buffer,
     copy everything to it and then free the old one.
     Create new skb with 'bytes' added to 'offset' in the packet. */
  new_skb =
    ssh_interceptor_packet_skb_dup(packet->interceptor, skb, offset, bytes);

  if (!new_skb)
    {
      ssh_interceptor_packet_free(pp);
      return NULL;
    }

  /* Free the old packet */
  packet->skb = new_skb;
  dev_kfree_skb_any(skb);

  /* The packet changed! */
  return new_skb->data + offset;
}

/* Deletes the specified number of bytes from the buffer. */

Boolean
ssh_interceptor_packet_delete(SshInterceptorPacket pp, size_t offset,
                              size_t bytes)
{
  SshInterceptorInternalPacket packet = (SshInterceptorInternalPacket) pp;
  struct sk_buff *skb;

  skb = packet->skb;

  if (offset == 0)
    {
      /* Remove from head. */
      skb->data += bytes;
      skb->len -= bytes;

      SSH_DEBUG(SSH_D_LOWOK,
		("deleted from packet % p head %d bytes, "
		 "headroom %d tailroom %d",
		 pp, bytes, skb_headroom(skb), skb_tailroom(skb)));
      
      return TRUE;
    }

  if (offset + bytes >= skb->len)
    {
      /* Remove from tail. */
      skb->tail -= bytes;
      skb->len -= bytes;

      SSH_DEBUG(SSH_D_LOWOK,
		("deleted from packet %p tail %d bytes, "
		 "headroom %d tailroom %d",
		 pp, bytes, skb_headroom(skb), skb_tailroom(skb)));

      return TRUE;
    }

  /* Remove from somewhere in between. */
  memmove(skb->data + bytes, skb->data, offset);
  skb->data += bytes;
  skb->len -= bytes;
  
  SSH_DEBUG(SSH_D_LOWOK,
	    ("deleted from packet %p %d bytes at offset %d, "
	     "headroom %d tailroom %d",
	     pp, bytes, offset, skb_headroom(skb), skb_tailroom(skb)));

  return TRUE;
}

/* Copies data into the packet.  Space for the new data must already have
   been allocated.  It is a fatal error to attempt to copy beyond the
   allocated packet.  Multiple threads may call this function concurrently,
   but not for the same packet.  This does not change the length of the
   packet. */

Boolean
ssh_interceptor_packet_copyin(SshInterceptorPacket pp, size_t offset,
                              const unsigned char *buf, size_t len)
{
  SshInterceptorInternalPacket packet = (SshInterceptorInternalPacket) pp;

  memmove(packet->skb->data + offset, buf, len);

  return TRUE;
}

/* Copies data out from the packet.  Space for the new data must
   already have been allocated.  It is a fatal error to attempt to
   copy beyond the allocated packet. Multiple threads may call this
   function concurrently, but not for the same packet. */

void
ssh_interceptor_packet_copyout(SshInterceptorPacket pp, size_t offset,
                               unsigned char *buf, size_t len)
{
  SshInterceptorInternalPacket packet = (SshInterceptorInternalPacket) pp;

  memmove(buf, packet->skb->data + offset, len);
}

/* These functions iterate over contiguous segments of the packet,
   starting from offset `offset', continuing for a total of
   `total_bytes' bytes.  It is guaranteed that `*len_return' will
   not be set to a value that would exceed `len' minus sum of previous
   lengths.  Also, previous pointers are guaranteed to stay valid if
   no other ssh_interceptor_packet_* functions are used during
   iteration for the same packet.  At each iteration, these functions
   return a pointer to the first byte of the contiguous segment inside
   the `*data_ret', and set `*len_return' to the number of bytes available at
   that address.

   The ssh_interceptor_packet_reset_iteration function will just reset the
   internal pointers to new offset and number of bytes without changing
   anything else. After that you need to call the
   ssh_interceptor_packet_next_iteration function to get the first block.

   The loop ends when the iteration function returns FALSE, and then after the
   loop you need to check the value of the `*data_ret'. If it is NULL then the
   whole packet was processed and the operation was ended because there was no
   more data available. If it is not NULL then the there was an error and the
   underlaying packet buffer has already been freed and all the pointers
   pointing to that memory area (returned by previous calls to this function)
   are invalidated.

   These functions are used as follows:

     ssh_interceptor_packet_reset_iteration(pp, offset, total_bytes);
     while (ssh_interceptor_packet_next_iteration(pp, &ptr, &len))
       {
         code that uses ptr and len;
       }
     if (ptr != NULL)
       {
         code that will clean up the state and return. Note that the pp has
         already been freed at this point.
         return ENOBUF;
       }

   Only one operation can be in progress on a single packet concurrently,
   but multiple iterations may be executed simultaneously for different
   packet buffers.  Thus, the implementation must keep any state in the
   packet object, not in global variables.

   Multiple threads may call these functions concurrently,
   but not for the same packet.

   There is two different versions of next_iteration function, one to get data
   that you can modify (ssh_interceptor_packet_next_iteration) and one to get
   read only version of the data (ssh_interceptor_packet_next_iteration_read).
   The read only version should be used in all cases where the packet is not
   modifed, so interceptor can optimize extra copying of the packets away.
   */
void
ssh_interceptor_packet_reset_iteration(SshInterceptorPacket pp,
                                       size_t offset, size_t total_bytes)
{
  SshInterceptorInternalPacket packet = (SshInterceptorInternalPacket) pp;

  packet->iteration_offset = offset;
  packet->iteration_bytes = total_bytes;

  return;
}

static Boolean
ssh_interceptor_packet_next_iteration_internal
(SshInterceptorInternalPacket packet,
 unsigned char **data_ret,
 size_t * len_return)
{
  size_t len;

  SSH_ASSERT(packet != NULL);
  SSH_ASSERT(packet->skb != NULL);

  if (packet->iteration_bytes <= 0)
    {
      /* We have already iterated all data. */
      (*data_ret) = NULL;
      return FALSE;
    }

  len = packet->skb->len - packet->iteration_offset;
  if (len <= 0)
    {
      packet->iteration_bytes = 0;
      (*data_ret) = NULL;
      return FALSE;
    }

  if (len > packet->iteration_bytes)
    len = packet->iteration_bytes;

  (*data_ret) = packet->skb->data + packet->iteration_offset;
  (*len_return) = len;
  packet->iteration_offset += len;
  packet->iteration_bytes -= len;

  return TRUE;
}

Boolean
ssh_interceptor_packet_next_iteration(SshInterceptorPacket pp,
                                      unsigned char **data_ret,
                                      size_t * len_return)
{
  SshInterceptorInternalPacket packet = (SshInterceptorInternalPacket) pp;

  return ssh_interceptor_packet_next_iteration_internal(packet,
                                                        data_ret,
                                                        len_return);
}

Boolean
ssh_interceptor_packet_next_iteration_read(SshInterceptorPacket pp,
                                           const unsigned char **data_ret,
                                           size_t * len_return)
{
  SshInterceptorInternalPacket packet = (SshInterceptorInternalPacket) pp;
  unsigned char *tmp;
  Boolean result;

  SSH_ASSERT(data_ret != NULL);

  result = ssh_interceptor_packet_next_iteration_internal(packet,
                                                          &tmp,
                                                          len_return);
  *data_ret = tmp;
  return result;
}

Boolean ssh_interceptor_packet_export_internal_data(SshInterceptorPacket pp,
                                                    unsigned char **data_ret,
                                                    size_t *len_return)
{
  unsigned char *data;
  SshInterceptorInternalPacket ipp = (SshInterceptorInternalPacket)pp;

  data = ssh_calloc(2, sizeof(SshUInt32));

  if (data == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Unable to export internal packet data"));
      *data_ret = NULL;
      *len_return = 0;
      return FALSE;
    }

  SSH_PUT_32BIT(data, ipp->original_ifnum);
  if (ipp->skb)
    SSH_PUT_8BIT(data + 4, ipp->skb->pkt_type);

  *data_ret = data;
  *len_return = 2 * sizeof(SshUInt32);

  return TRUE;
}

Boolean ssh_interceptor_packet_import_internal_data(SshInterceptorPacket pp,
                                                    const unsigned char *data,
                                                    size_t len)
{
  SshInterceptorInternalPacket ipp = (SshInterceptorInternalPacket)pp;
  SshUInt32 orig_ifnum;

  if (len == 0)
    {
      /* No data to import, i.e. packet created by engine. */
      ipp->original_ifnum = SSH_INTERCEPTOR_INVALID_IFNUM;
      if (ipp->skb)
	ipp->skb->pkt_type = PACKET_HOST;
      return TRUE;
    }
  else if (data == NULL || len < (2 * sizeof(SshUInt32)))
    {
      /* Attempt to import corrupted data. */
      SSH_DEBUG(SSH_D_FAIL, ("Unable to import internal packet data"));
      return FALSE;
    }

  orig_ifnum = SSH_GET_32BIT(data);
  ipp->original_ifnum = orig_ifnum;
  
  if (ipp->skb)
    ipp->skb->pkt_type = SSH_GET_8BIT(data + 4);
  
  return TRUE;
}

#ifdef INTERCEPTOR_HAS_PACKET_DETACH
void
ssh_interceptor_packet_detach(SshInterceptorPacket packet)
{
#ifdef KERNEL
#ifdef SSH_LINUX_PACKET_DETACH
  SshInterceptorInternalPacket pp = (SshInterceptorInternalPacket) packet;

  /* If the packet has an associated SKB and that SKB is associated
     with a socket, orphan the skb from it's owner. */
  if (pp->skb != NULL)
    skb_orphan(pp->skb);
#endif /* SSH_LINUX_SUPPORT_DETACH */
#endif /* KERNEL */

}
#endif /* INTERCEPTOR_HAS_PACKET_DETACH */


Boolean
ssh_interceptor_packet_align(SshInterceptorPacket pp, size_t offset)
{
  SshInterceptorInternalPacket packet = (SshInterceptorInternalPacket) pp;
  struct sk_buff *skb, *new_skb;
  unsigned long addr;
  size_t word_size, bytes;

  word_size = sizeof(int *);
  SSH_ASSERT(word_size < SSH_INTERCEPTOR_PACKET_TAIL_ROOM);

  skb = packet->skb;

  addr = (unsigned long) (skb->data + offset);

  bytes = (size_t)((((addr + word_size - 1) / word_size) * word_size) - addr);
  if (bytes == 0)
    return TRUE;

  if (SSH_SKB_GET_END(skb) - SSH_SKB_GET_TAIL(skb) >= bytes)
    {
      memmove(skb->data + bytes, skb->data, skb->len);
      skb->data += bytes;
      /* This works for both pointers and offsets. */
      skb->tail += bytes;
      
      SSH_DEBUG(SSH_D_LOWOK,
		("Aligning skb->data %p at offset %d to word "
		 "boundary (word_size %d), headroom %d tailroom %d",
		 skb->data, offset, word_size,
		 skb_headroom(skb), skb_tailroom(skb)));

      return TRUE;
    }
  else if (skb->data - skb->head >= word_size - bytes)
    {
      bytes = word_size - bytes;
      memmove(skb->data - bytes, skb->data, skb->len);
      skb->data -= bytes;
      skb->tail -= bytes;
      return TRUE;
    }
  else
    {
      /* Allocate a new packet which has enough head/tail room to allow
	 alignment. */
      new_skb = ssh_interceptor_packet_skb_dup(packet->interceptor, skb, 0, 0);

      if (!new_skb)
	{
	  ssh_interceptor_packet_free(pp);
	  return FALSE;
	}
      SSH_ASSERT(SSH_SKB_GET_END(new_skb) - SSH_SKB_GET_TAIL(new_skb) 
		 >= word_size);

      /* Free the old packet */
      packet->skb = new_skb;
      dev_kfree_skb_any(skb);
      return ssh_interceptor_packet_align(pp, offset);
    }
}

struct sk_buff *
ssh_interceptor_packet_verify_headroom(struct sk_buff *skbp, 
				       size_t media_header_len)
{
  SshUInt32 required_headroom;
  struct sk_buff *skbp2;
  
  SSH_ASSERT(skbp != NULL);
  SSH_ASSERT(skbp->dev != NULL);
  
  required_headroom = LL_RESERVED_SPACE(skbp->dev);
#if (SSH_INTERCEPTOR_PACKET_HARD_HEAD_ROOM > 0)
  if (required_headroom < SSH_INTERCEPTOR_PACKET_HARD_HEAD_ROOM)
    required_headroom = SSH_INTERCEPTOR_PACKET_HARD_HEAD_ROOM;
#endif /* (SSH_INTERCEPTOR_PACKET_HARD_HEAD_ROOM > 0) */

  if (unlikely(required_headroom > media_header_len &&
	       skb_headroom(skbp) < (required_headroom - media_header_len)))
    {
      SSH_DEBUG(SSH_D_NICETOKNOW,
		("skb does not have enough headroom for device %d, "
		 "reallocating skb headroom",
		 skbp->dev->ifindex));
      skbp2 = skb_realloc_headroom(skbp, 
				   (required_headroom - media_header_len));
      dev_kfree_skb_any(skbp);
      
      return skbp2;
    }

  return skbp;
}
