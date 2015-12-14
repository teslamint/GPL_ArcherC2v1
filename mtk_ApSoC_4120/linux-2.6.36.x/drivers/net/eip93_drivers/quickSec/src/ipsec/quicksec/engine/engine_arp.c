/*
 *
 * engine_arp.c
 *
 * Copyright:
 *       Copyright (c) 2002, 2003, 2004, 2005, 2006 SFNT Finland Oy.
 *       All rights reserved.
 *
 * Implements ARP, and generally the common code for using ethernet
 * (rfc894, rfc1112) and IEEE 802 (rfc1042, rfc1469) encapsulation for
 * media headers.  Services provided by this file are used by both the
 * ethernet and IEEE 802 code.
 *
 * This source also implements rfc2461 "Neighbor Discovery for IP
 * Version 6 (IPv6)". Most of the ARP cache shared code with both
 * IPv4/IPv6, except at
 * ssh_engine_arp_send_(solicitation|request). Notice that
 * SSH_ENGINE_MEDIA_ETHER_NO_ARP_RESPONSES is relevant only to IPv4 processing.
 *
 * Note: this implementation of the ARP protocol assumes that the
 * following data be entered to the arp cache as permanent entries on
 * startup (this is done in ssh_engine_arp_update_interface): - IP
 * addresses of all interfaces of this type, and their ethernet
 * addresses - directed broadcast addreses of the networks connected
 * to each interface, and a broadcast ethernet address for each of
 * them
 *
 * This data is entered in the cache by
 * ssh_engine_arp_update_interface.
 */







#include "sshincludes.h"
#include "engine_internal.h"
#ifdef SSH_ENGINE_MEDIA_ETHER_NO_ARP_RESPONSES
#include "sshinetencode.h"
#include "engine_pm_api_marshal.h"
#endif /* SSH_ENGINE_MEDIA_ETHER_NO_ARP_RESPONSES */

#define SSH_DEBUG_MODULE "SshEngineArp"

#ifdef SSH_IPSEC_IP_ONLY_INTERCEPTOR
/* The interceptor operates at IP level only.  ARP code not needed. */

/* Keep the compiler happy that don't like empty source files (Compaq
   Tru64). */
int ssh_engine_arp_dummy;

#else /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */
/* The interceptor may provide or require packets with media headers.
   Include this code. */

static const unsigned char ssh_engine_arp_ethernet_broadcast_addr[] =
  { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };




static const unsigned char ssh_engine_arp_token_ring_multicast_addr[6] =
  { 0x03, 0x00, 0x00, 0x20, 0x00, 0x00 }; 

static const unsigned char ssh_engine_arp_hdr_ipv4_reply[] =
  { 0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x02 };

static const unsigned char ssh_engine_arp_hdr_ipv4_request[] =
  { 0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01 };

#ifdef SSH_IPSEC_PREALLOCATE_TABLES
/* Array of arp cache entries. */
SshEngineArpCacheEntryStruct
  ssh_engine_arp_entry_table[SSH_ENGINE_ARP_CACHE_SIZE];
/* Freelist for arp cache entries.  This list is protected by
   engine->interface_lock. */
SshEngineArpCacheEntry ssh_engine_arp_entry_freelist;
#endif /* SSH_IPSEC_PREALLOCATE_TABLES */

void ssh_engine_arp_cache_timeout(void *context);

#ifdef DEBUG_LIGHT
/* Render an ethernet media address to a buffer.  This is used as
   a render function to the %@ syntax. */
int ssh_engine_arp_render_eth_mac(unsigned char *buf, int buf_size,
                                  int precision, void *datum)
{
  int len;
  unsigned char *hw_addr = datum;

  ssh_snprintf(buf, buf_size, "%02x:%02x:%02x:%02x:%02x:%02x",
                hw_addr[0], hw_addr[1], hw_addr[2],
                hw_addr[3], hw_addr[4], hw_addr[5]);

  len = ssh_ustrlen(buf);

  if (precision >= 0 && len > precision)
    len = precision;

  return len;
}
#endif

/* Some prototype declarations... */
void ssh_engine_arp_complete(SshEngine engine,
                             SshEnginePacketContext pc, SshIpAddr ip,
                             const unsigned char *hw);


/* Moves the given entry to the beginning of the arp cache lru.  This
   should be called whenever the cache entry is used to map something.
   This can also be used to initially insert the entry on the list,
   provided that its lru_prev and lru_next fields are first
   initialized to NULL.  The engine->interface_lock must be held
   when this is called. */
void ssh_engine_arp_lru_bump(SshEngine engine,
                             SshEngineArpCacheEntry entry,
                             Boolean new_entry)
{
  SshEngineArpCache cache = &engine->arp_cache;

  ssh_kernel_mutex_assert_is_locked(engine->interface_lock);

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("entry %p status %d cache head %p tail %p "
             "entry next %p prev %p",
             entry,
             entry->status,
             cache->lru_head, cache->lru_tail,
             entry->lru_next, entry->lru_prev));

  /* Permanent entries are not on the LRU.  Do nothing if
     permanent. */
  if (entry->status == SSH_ENGINE_ARP_PERMANENT)
    return;

  /* Require that new entries are not on the list */
  SSH_ASSERT(new_entry == FALSE || cache->lru_head != entry);
  SSH_ASSERT(new_entry == FALSE || cache->lru_tail != entry);

  /* If already at head of list, do nothing.  This may actually be a
     fairly frequent case as most traffic is probably to a single
     server on the local network or to the external gateway. */
  if (cache->lru_head == entry)
    return;

  /* Remove the entry from the list if it is not new. */
  if (!new_entry)
    {
      /* Assert that we're on the list */
      SSH_ASSERT(entry->lru_next != NULL || entry == cache->lru_tail);
      SSH_ASSERT(entry->lru_prev != NULL || entry == cache->lru_head);

      /* Remove the entry from the lru list (if it is on the list). */
      /* If not last, update prev pointer from next node; if last,
         update tail pointer of the list. */
      if (entry->lru_next)
        entry->lru_next->lru_prev = entry->lru_prev;
      else
        cache->lru_tail = entry->lru_prev;

      /* We know it is not the first (was checked above).
         And since we are not a new entry, we must be on the list. */
      SSH_ASSERT(entry->lru_prev != NULL);
      entry->lru_prev->lru_next = entry->lru_next;
    }
  else
    {
      /* Assert that entry is actually in pristine condition.. */
      SSH_ASSERT(entry->lru_next == NULL);
      SSH_ASSERT(entry->lru_prev == NULL);
    }

  /* Insert the entry at the head of the list. */
  if (cache->lru_head)
    cache->lru_head->lru_prev = entry;
  entry->lru_prev = NULL;
  entry->lru_next = cache->lru_head;
  cache->lru_head = entry;
  if (cache->lru_tail == NULL)
    cache->lru_tail = entry;

  /* Mark entry for removal from list */
  entry->flags |= SSH_ENGINE_ARP_ON_LRU_LIST;
}

/* Calls the completion function for any packets that are on the
   cache->packets_waiting_completion list.  This will take
   engine->interface_lock momentarily to access the list. */

void ssh_engine_arp_call_pending_completions(SshEngine engine)
{
  SshEngineArpCache cache = &engine->arp_cache;
  SshEnginePacketContext pc;

  /* Keep looping until there are no more packets waiting for their
     completion function to be called. */
  for (;;)
    {
      /* Protect access to the list using engine->interface_lock. */
      ssh_kernel_mutex_lock(engine->interface_lock);
      /* Get the first packet from the list (and remove it from the list). */
      pc = cache->packets_waiting_completion;
      if (pc)
	{
	  cache->packets_waiting_completion = pc->next;
	  pc->next = NULL;
	}
      /* Release the lock. */
      ssh_kernel_mutex_unlock(engine->interface_lock);

      /* If there are no more packets, stop. */
      if (!pc)
        break;

      /* Call the completion function for the packet to signal failure to
         higher-level code. */
      ssh_engine_arp_complete(engine, pc, NULL, NULL);
    }
}


/* Removes the given entry from the arp cache (hash and lru), and
   frees it.  The engine lock must be held when this is called. */
void ssh_engine_arp_free_entry(SshEngine engine,
                               SshEngineArpCacheEntry entry)
{
  SshEngineArpCache cache = &engine->arp_cache;
  SshEngineArpCacheEntry *entryp;
  SshUInt32 hash;
  SshEnginePacketContext pc;

  ssh_kernel_mutex_assert_is_locked(engine->interface_lock);

  SSH_DEBUG(SSH_D_LOWSTART,
            ("Deleting entry %p from the ARP cache.", entry));

  /* Remove the entry from the lru list. */
  if (entry->flags & SSH_ENGINE_ARP_ON_LRU_LIST)
    {
      /* If not last, update prev pointer from next node; if last,
         update tail pointer of the list. */
      if (entry->lru_next)
        entry->lru_next->lru_prev = entry->lru_prev;
      else
        cache->lru_tail = entry->lru_prev;

      /* If not first, update next pointer of prev node; if first, update
         the head pointer of the list. */
      if (entry->lru_prev)
        entry->lru_prev->lru_next = entry->lru_next;
      else
        cache->lru_head = entry->lru_next;

      entry->flags &= ~ SSH_ENGINE_ARP_ON_LRU_LIST;
    }

  /* Decrement the count of entries in the arp cache. */
  cache->num_entries--;

  /* Remove the entry from the hash lists. */
  hash = SSH_IP_HASH(&entry->ip_addr);
  hash %= SSH_ENGINE_ARP_HASH_SIZE;

  /* Find the pointer to the entry in the hash table. */
  for (entryp = &cache->hash[hash]; *entryp; entryp = &(*entryp)->next)
    if (*entryp == entry)
      break;
  /* The entry should always be in the hash table. */
  SSH_ASSERT(*entryp == entry);

  /* Remove the entry from the hash table. */
  *entryp = entry->next;

  /* If the packet (entry?) is on the retry list, remove it. */
  if (entry->on_retry_list)
    {
      for (entryp = &cache->retry_list; *entryp;
           entryp = &(*entryp)->retry_list_next)
        if (*entryp == entry)
          break;
      SSH_ASSERT(*entryp == entry);
      *entryp = entry->retry_list_next;
    }

  /* Free all queued packets. */
  if (entry->queued_packet != NULL)
    {
      pc = entry->queued_packet;
      /* Put the packet on the list of packets waiting for their completion
         function to be called to indicate failure.  We cannot call the
         completion function directly from here, because we are holding
         the lock and the completion function expects to be called
         without the lock held.  The ssh_engine_arp_call_pending_completions
         function should be called after the lock is released after a
         call here. */
      pc->next = cache->packets_waiting_completion;
      cache->packets_waiting_completion = pc;
    }

#ifdef SSH_IPSEC_PREALLOCATE_TABLES
  entry->status = 0x7a; /* magic */
  entry->next = ssh_engine_arp_entry_freelist;
  ssh_engine_arp_entry_freelist = entry;

#else /* SSH_IPSEC_PREALLOCATE_TABLES */
  /* Free the entry data structure itself. */
  memset(entry, 'F', sizeof(*entry));
  ssh_free(entry);
#endif /* SSH_IPSEC_PREALLOCATE_TABLES */

}

/* Allocates a new arp cache entry.  This also checks if the arp cache is
   full, and if so, removes the least recently accessed entry from the cache
   (and returns it for reuse).  Anyway, this returns an arp cache entry
   that should be added to the appropriate hash table slot.  This will
   not automatically add the entry to the lru list; ssh_engine_arp_lru_bump
   should be called for the entry to do that.  The engine lock must be
   held when this is called.

   This function may return NULL if no memory could be allocated. */

static SshEngineArpCacheEntry
ssh_engine_arp_cache_new_entry(SshEngine engine)
{
  SshEngineArpCache cache = &engine->arp_cache;
  SshEngineArpCacheEntry entry;
#ifdef DEBUG_LIGHT
  Boolean deleted = FALSE;
#endif /* DEBUG_LIGHT */

  ssh_kernel_mutex_assert_is_locked(engine->interface_lock);





  /* Check if the cache is already full. */
  while (cache->num_entries >= SSH_ENGINE_ARP_CACHE_SIZE)
    {
      /* Reuse the least recently used entry from the cache. */
      entry = cache->lru_tail;
      if (!entry)
        {
          SSH_DEBUG(SSH_D_ERROR,
                    ("Could not vacate an ARP entry due to all space"
                     " consumed by `permanent' entries. Increase"
                     " SSH_ENGINE_ARP_CACHE_SIZE"));

#ifdef SSH_IPSEC_STATISTICS
          engine->stats.out_of_arp_cache_entries++;
#endif /* SSH_IPSEC_STATISTICS */
          return NULL;
        }
      /* It should be impossible to have permanent entries in the
         lru list, permanent entries are not put there */
      SSH_ASSERT(entry->status != SSH_ENGINE_ARP_PERMANENT);
      /* We are the last entry, therefore the lru_next must be NULL */
      SSH_ASSERT(entry->lru_next == NULL);

      /* Free the arp cache entry.  We do it this way instead of reusing
         to reduce the probability of dangling timeouts and other
         implementation bugs. */
      ssh_engine_arp_free_entry(engine, entry);
#ifdef DEBUG_LIGHT
      deleted = TRUE;
#endif /* DEBUG_LIGHT */
    }

#ifdef SSH_IPSEC_PREALLOCATE_TABLES
  /* Get an available entry from the freelist. */
  if (!ssh_engine_arp_entry_freelist)
    {
#ifdef SSH_IPSEC_STATISTICS
      engine->stats.out_of_arp_cache_entries++;
#endif /* SSH_IPSEC_STATISTICS */
      return NULL;
    }

  entry = ssh_engine_arp_entry_freelist;
  SSH_ASSERT(entry->status == 0x7a); /* magic */
  ssh_engine_arp_entry_freelist = entry->next;
  memset(entry, 0, sizeof(*entry));
  entry->status = SSH_ENGINE_ARP_FAILED;

#else /* SSH_IPSEC_PREALLOCATE_TABLES */
  /* Allocate a new arp cache entry. */
  if (!(entry = ssh_calloc(1, sizeof(*entry))))
    {
#ifdef SSH_IPSEC_STATISTICS
      engine->stats.out_of_arp_cache_entries++;
#endif /* SSH_IPSEC_STATISTICS */
      return NULL;
    }

  /* Force similar behaviour between preallocate tables
     and non-preallocate tables. */
  entry->status = SSH_ENGINE_ARP_FAILED;
#endif /* SSH_IPSEC_PREALLOCATE_TABLES */

  /* Increment the number of arp cache entries. */
  cache->num_entries++;
  SSH_DEBUG(SSH_D_LOWSTART, ("Creating new ARP cache entry %s",
                             deleted ? "(deleted old to make space)": ""));

  return entry;
}

/* This function is called when a reply is received to an arp request.
   This will update the packet as appropriate, and if all arp lookups
   for the packet are complete, this will send the packet.  This will
   save the hardware address in the packet.  This function can be
   called concurrently (but not for the same packet).  If `ip' and `hw'
   are NULL, then the ARP lookup is considered to have failed.  The engine
   lock must not be held by the caller when this is called. */

void ssh_engine_arp_complete(SshEngine engine,
                             SshEnginePacketContext pc, SshIpAddr ip,
                             const unsigned char *hw)
{
  SshUInt16 ethertype;
  unsigned char ownhw[6];
  SshInterceptorInterface *iface;

  if (ip != NULL)
    SSH_DEBUG(SSH_D_HIGHOK,
              ("pc=%p: arp complete for %@ as %@, flags 0x%lx",
               pc, ssh_ipaddr_render, ip,
               ssh_engine_arp_render_eth_mac, hw,
               pc->pp ? (long)pc->pp->flags : (long)0));
  else
    SSH_DEBUG(SSH_D_HIGHOK, ("pc=%p: arp lookup failed", pc));

  /* Check if the lookup failed. */
  if (hw == NULL || ip == NULL)
    {
      /* Indicate failure. */
      (*pc->arp_callback)(pc, NULL, NULL, 0);
      return;
    }

  /* Determine ethertype. */
  if (SSH_IP_IS6(ip))
    ethertype = SSH_ETHERTYPE_IPv6;
  else
    ethertype = SSH_ETHERTYPE_IP;

  /* Obtain our own hardware address for the relevant network interface.
     We also sanity check the interface number to make sure it is within
     the allowed range and that it is still valid (it is possible that the
     interface could have gone down while we were not holding the lock). */
  ssh_kernel_mutex_lock(engine->interface_lock);
  /* Sanity check ifnum. */
  iface = ssh_ip_get_interface_by_ifnum(&engine->ifs, pc->arp_ifnum);
  if (iface == NULL
      || iface->to_adapter.media == SSH_INTERCEPTOR_MEDIA_NONEXISTENT)
    {
      /* Invalid ifnum or nonexistent interface. */
      ssh_kernel_mutex_unlock(engine->interface_lock);
      SSH_DEBUG(SSH_D_FAIL, ("Invalid ifnum %d or nonexistent interface",
                             (int)pc->arp_ifnum));
      (*pc->arp_callback)(pc, NULL, NULL, 0);
      return;
    }
  memcpy(ownhw, iface->media_addr, sizeof(ownhw));
  ssh_kernel_mutex_unlock(engine->interface_lock);

  /* Pass the result to the callback. */
  (*pc->arp_callback)(pc, ownhw, hw, ethertype);
}

/* Add an entry to the ARP cache, but only if there was an request
   entry present. req_required variable tells if request has to be
   present or not. */
void ssh_engine_arp_add_address(SshEngine engine,
                                SshIpAddr ip_addr,
				SshEngineIfnum ifnum,
                                const unsigned char *hw)
{
  SshUInt32 hash;
  SshEngineArpCache cache = &engine->arp_cache;
  SshEngineArpCacheEntry entry, *entryp;
  SshEnginePacketContext queued_pc;
  SshTime now;
  Boolean from_incomplete = FALSE;

  ssh_interceptor_get_time(&now, NULL);

  /* Compute the hash value. */
  hash = SSH_IP_HASH(ip_addr);
  hash %= SSH_ENGINE_ARP_HASH_SIZE;

  /* Take the engine lock to access protected data structures. */
  ssh_kernel_mutex_lock(engine->flow_control_table_lock);
  ssh_kernel_mutex_lock(engine->interface_lock);

  /* Find the entry from the hash table slot. */
  for (entry = cache->hash[hash]; entry; entry = entry->next)
    if (SSH_IP_EQUAL(&entry->ip_addr, ip_addr) && entry->ifnum == ifnum)
      break;

  /* Ignore the arp reply if there is no corresponding entry in our
     arp cache. */
  if (entry == NULL)
    {
      ssh_kernel_mutex_unlock(engine->interface_lock);
      ssh_kernel_mutex_unlock(engine->flow_control_table_lock);

      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("No cache entry found for arp replyaddr %@ buck %u",
                 ssh_ipaddr_render, ip_addr, (unsigned int) hash));
      return;
    }

  /* Process the packet, depending on the status of the entry. */
  switch (entry->status)
    {
    case SSH_ENGINE_ARP_INCOMPLETE:
    case SSH_ENGINE_ARP_FAILED:
      SSH_DEBUG(SSH_D_MIDOK, ("arp input for incomplete/failed entry"));

      /* We didn't previously have a hardware address for this entry.
         Set the time-to-live field to a higher value to keep the
         entry in the cache for reasonably long. */
      entry->expires = now + SSH_ENGINE_ARP_COMPLETE_LIFETIME;

      /* Mark that we now have complete information for the entry. */
      entry->status = SSH_ENGINE_ARP_COMPLETE;

      /* Remove the packet from the retry list. */
      if (entry->on_retry_list)
        {
          for (entryp = &cache->retry_list; *entryp;
               entryp = &(*entryp)->retry_list_next)
            if (*entryp == entry)
              break;
          SSH_ASSERT(*entryp == entry);
          *entryp = entry->retry_list_next;
          entry->on_retry_list = FALSE;
          entry->retry_list_next = NULL;
        }

      from_incomplete = TRUE;
      /* Fall to next case. */

    case SSH_ENGINE_ARP_COMPLETE:
      SSH_DEBUG(SSH_D_MIDOK, ("arp input for already complete entry"));

      /* In each of these cases, we can accept the arp reply and update
         both the hardware address and the status.  Note that we do not
         update the time-to-live of the entry, to make it harder for
         someone to flush important entries from the arp cache by
         arp flooding.  The time-to-live will get updated if the entry
         is used for sending a packet a second time. If we are actually
         already complete ARP entry, the MAC address might be chaning 
         later on. Compare and update if needed. */
      if (!from_incomplete && memcmp(entry->ethernet_addr, hw, 6)) 
        {
          ssh_engine_update_nh_node_mac(engine, ip_addr, ifnum, hw);
        }
      
      memcpy(entry->ethernet_addr, hw, 6);

      /* Bump the ARP entry to the beginning of the list. */
      ssh_engine_arp_lru_bump(engine, entry, FALSE);

      /* Continue processing of the queued packet (if any). */
      queued_pc = entry->queued_packet;
      entry->queued_packet = NULL;
 
      ssh_kernel_mutex_unlock(engine->interface_lock);
      ssh_kernel_mutex_unlock(engine->flow_control_table_lock);

      if (queued_pc != NULL)
        ssh_engine_arp_complete(engine, queued_pc, ip_addr, hw);

      return;

    case SSH_ENGINE_ARP_PERMANENT:
      ssh_kernel_mutex_unlock(engine->interface_lock);
      ssh_kernel_mutex_unlock(engine->flow_control_table_lock);

      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Received arp reply for a permanent arp entry"));

      return;

    default:
      ssh_kernel_mutex_unlock(engine->interface_lock);
      ssh_kernel_mutex_unlock(engine->flow_control_table_lock);
      
      ssh_fatal("ssh_engine_arp_add_address: bad entry status %d",
                entry->status);
    }

  ssh_fatal("ssh_engine_arp_add_address: Should not have gotten here!");
}

/* Lookup the IP address `ip_addr' from the ARP cache.  The function
   store the IP's hardware address in `hw' and returns TRUE if the IP
   address is know and we have a complete entry for it.  If the IP
   address is unknown, the function returns FALSE. */
Boolean ssh_engine_arp_lookup_address(SshEngine engine,
				      SshIpAddr ip_addr,
				      SshEngineIfnum ifnum,
                                      unsigned char *hw,
                                      SshUInt8 *flags_return)
{
  SshUInt32 hash;
  SshEngineArpCache cache = &engine->arp_cache;
  SshEngineArpCacheEntry entry;

  /* Compute the hash. */
  hash = SSH_IP_HASH(ip_addr);
  hash %= SSH_ENGINE_ARP_HASH_SIZE;

  /* The ARP cache is protected by the flow table lock. */
  ssh_kernel_mutex_lock(engine->interface_lock);

  /* Find the entry from the hash table slot. */
  for (entry = cache->hash[hash]; entry; entry = entry->next)
    if (SSH_IP_EQUAL(&entry->ip_addr, ip_addr)
	&& (entry->ifnum == ifnum || (entry->flags & SSH_ENGINE_ARP_F_GLOBAL)))
      break;

  /* Did we find an entry? */
  if (entry == NULL)
    {
      ssh_kernel_mutex_unlock(engine->interface_lock);
      return FALSE;
    }

  /* Process the packet depending on the status of the entry. */
  switch (entry->status)
    {
    case SSH_ENGINE_ARP_COMPLETE:
      /* Bump the ARP entry to the beginning of the list. */
      ssh_engine_arp_lru_bump(engine, entry, FALSE);
      /* FALLTHROUGH */

    case SSH_ENGINE_ARP_PERMANENT:
      SSH_DEBUG(SSH_D_MIDOK, ("arp lookup for %s entry",
                              entry->status == SSH_ENGINE_ARP_COMPLETE
                              ? "complete" : "permanent"));

      /* Fetch the entry's hardware address. */
      memcpy(hw, entry->ethernet_addr, 6);

      /* Store flags. */
      *flags_return = entry->flags;

      ssh_kernel_mutex_unlock(engine->interface_lock);

      /* Found it. */
      return TRUE;
      break;

    default:
      ssh_kernel_mutex_unlock(engine->interface_lock);
      SSH_DEBUG(SSH_D_UNCOMMON, ("arp lookup for some other entry"));
      return FALSE;
      break;
    }
  /* NOTREACHED */
}

/* Looks up the hardware address for the given network interface.  The engine
   lock must be held when this is called. */

Boolean
ssh_engine_arp_get_hwaddr(SshEngine engine, SshUInt32 ifnum,
                          unsigned char *hw)
{
  SshInterceptorInterface *ifp;

  ssh_kernel_mutex_assert_is_locked(engine->interface_lock);

  /* Get a pointer to the interface data structure. */
  ifp  = ssh_ip_get_interface_by_ifnum(&engine->ifs, ifnum);

  /* Make sure it exists. */
  if (ifp == NULL
      || ifp->to_adapter.media == SSH_INTERCEPTOR_MEDIA_NONEXISTENT)
    {
      SSH_DEBUG(SSH_D_ERROR, ("failed to get local media address"));
      memset(hw, 0, 6);
      return FALSE;
    }

  /* Copy the interface's media address. */
  memcpy(hw, ifp->media_addr, 6);
  return TRUE;
}

/* Sends an arp reply with the given addresses. */

void ssh_engine_arp_send_reply(SshEngine engine,
                               Boolean outgoing,
                               SshEngineIfnum ifnum_out,
                               SshIpAddr target_ip,
                               const unsigned char *target_hw,
                               SshIpAddr sender_ip,
                               const unsigned char *sender_hw,
                               const unsigned char *source_hw)
{
  SshInterceptorPacket pp;
  unsigned char *ucp;

  SSH_ASSERT(SSH_IP_IS4(target_ip) && SSH_IP_IS4(sender_ip));

  /* Allocate a new packet for the specified interface. */
  pp = ssh_interceptor_packet_alloc(engine->interceptor,
                                    (outgoing
                                     ? SSH_PACKET_FROMPROTOCOL
                                     : SSH_PACKET_FROMADAPTER),
                                    SSH_PROTOCOL_ETHERNET,
				    SSH_INTERCEPTOR_INVALID_IFNUM,
				    ifnum_out,
				    28);
  if (pp == NULL)
    return;

  SSH_DEBUG(SSH_D_MIDOK, ("Sending ARP to interface %d",
			  (int) pp->ifnum_out));

  /* Get a pointer to the packet data. */
  ucp = ssh_interceptor_packet_pullup(pp, 28);
  if (ucp == NULL)
    return;

  /* Build the ARP reply. */
  memcpy(ucp, ssh_engine_arp_hdr_ipv4_reply, 8);

  /* Store sender information. */
  memcpy(ucp + 8, sender_hw, 6);
  SSH_IP4_ENCODE(sender_ip, ucp + 8 + 6);

  /* Store target information. */
  memcpy(ucp + 8 + 6 + 4, target_hw, 6);
  SSH_IP4_ENCODE(target_ip, ucp + 8 + 6 + 4 + 6);

  /* Encapsulate the packet in an ethernet header.  We send the packet
     as an ethernet unicast to the target hardware address. */
  ssh_engine_encapsulate_and_send(engine, pp, source_hw, target_hw,
                                  SSH_ETHERTYPE_ARP);
}

/* Processes the incoming gratuitous ARP request from another
   machine. */
void ssh_engine_gratuitous_arp(SshEngine engine, 
                               SshIpAddr sender_ip,
                               SshEngineIfnum ifnum,
                               const unsigned char *sender_hw)
{
  SshUInt32 hash;
  SshEngineArpCache cache = &engine->arp_cache;
  SshEngineArpCacheEntry entry;
  
    /* Compute the hash value. */
  hash = SSH_IP_HASH(sender_ip);
  hash %= SSH_ENGINE_ARP_HASH_SIZE;

  /* Take the engine lock to access protected data structures. */
  ssh_kernel_mutex_lock(engine->interface_lock);

  /* Find the entry from the hash table slot. */
  for (entry = cache->hash[hash]; entry; entry = entry->next)
    if (SSH_IP_EQUAL(&entry->ip_addr, sender_ip) && entry->ifnum == ifnum)
      break;

  if (entry == NULL)
    {
      ssh_kernel_mutex_unlock(engine->interface_lock);
      SSH_DEBUG(SSH_D_NICETOKNOW, ("No cache entry found for gratuitous "
				   "addr %@", ssh_ipaddr_render, sender_ip));
      return;
    }

  switch (entry->status)
    {
    case SSH_ENGINE_ARP_INCOMPLETE:
    case SSH_ENGINE_ARP_FAILED:
      SSH_DEBUG(SSH_D_NICETOKNOW, 
		("Gratuitous ARP request for incomplete/failed entry"));
      ssh_kernel_mutex_unlock(engine->interface_lock);
      return;

    case SSH_ENGINE_ARP_COMPLETE:
      SSH_DEBUG(SSH_D_NICETOKNOW, 
		("Updating ARP and next hop table cache according to "
		 "gratuitous ARP request, "
		 "HW addr changed for %@ from %@ to %@", 
		 ssh_ipaddr_render, sender_ip, 
		 ssh_engine_arp_render_eth_mac, entry->ethernet_addr, 
		 ssh_engine_arp_render_eth_mac, sender_hw));
      
      memcpy(entry->ethernet_addr, sender_hw, 6); 
      ssh_kernel_mutex_unlock(engine->interface_lock);
      
      ssh_kernel_mutex_lock(engine->flow_control_table_lock);
      ssh_engine_update_nh_node_mac(engine, sender_ip, ifnum, sender_hw);
      ssh_kernel_mutex_unlock(engine->flow_control_table_lock);
      return;

    case SSH_ENGINE_ARP_PERMANENT:
      SSH_DEBUG(SSH_D_NICETOKNOW, 
		("Gratuitous ARP request for permanent entry. Doing "
		 "nothing."));
      ssh_kernel_mutex_unlock(engine->interface_lock);
      return;
    }

  ssh_fatal("ssh_engine_arp_add_address: bad entry status %d",
	    entry->status);
  ssh_kernel_mutex_unlock(engine->interface_lock);
  ssh_fatal("ssh_engine_gratuitous_arp: Should not have gotten here!");
}

/* Processes an incoming arp packet.  This function will update the
   arp table as appropriate, and will cause the SshEngineArpComplete
   callback to be called for any pending requests completed by this
   packet.  The packet in `pp' should not contain media header, but
   the media header should be saved in pd->mediahdr.  Normally, this
   will not free `pp' and returns TRUE, because the packet will
   normally also be passed to the host TCP/IP stack.  If an error
   causes the packet to be freed, this returns FALSE.

   This function can be called concurrently.  This will momentarily lock
   the engine lock to modify the cache data structures. */

Boolean ssh_engine_arp_input(SshEngine engine, SshInterceptorPacket pp)
{
  SshIpAddrStruct ip_addr;
  const unsigned char *hw, *ucp;

  SSH_DEBUG(SSH_D_HIGHSTART, ("ARP input."));

  /* Make sure arp header and standard fields are all there. */
  if (ssh_interceptor_packet_len(pp) < 28)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Got arp packet that is too short"));
      return TRUE;
    }

  /* Get a pointer to the data. */
  ucp = ssh_interceptor_packet_pullup_read(pp, 28);
  if (ucp == NULL)
    {
      return FALSE;
    }

  /* Check if it is an IPv4 arp reply with 48 bit hw address. */
  if (memcmp(ucp, ssh_engine_arp_hdr_ipv4_reply, 8) == 0)
    {
      /* Got an IPv4 ARP reply.  Extract the ip and hardware addresses. */
      SSH_IP4_DECODE(&ip_addr, ucp + 8 + 6);
      hw = ucp + 8;

      /* Check if it is an ethernet broadcast or multicast address.
         We do not want to accept arp replies that specify an ethernet
         broadcast or multicast address. */
      if (SSH_ETHER_IS_MULTICAST(hw))
        {
          SSH_DEBUG(SSH_D_ERROR, ("Got multicast address in arp reply"));
          return TRUE;
        }

      ssh_engine_arp_add_address(engine, &ip_addr, pp->ifnum_in, hw);
      return TRUE;
    }

  /* Check if it is an IPv4 arp request with 48 bit hw address. */
  if (memcmp(ucp, ssh_engine_arp_hdr_ipv4_request, 8) == 0)
    {
      SshIpAddrStruct sender_ip;
      unsigned char sender_hw[6];
      SshIpAddrStruct target_ip;
      unsigned char target_hw[6];
      SshUInt8 flags;

      /* Got an IPv4 ARP request. Extract information from the packet. */
      memcpy(sender_hw, ucp + 8, 6);
      SSH_IP4_DECODE(&sender_ip, ucp + 8 + 6);
      SSH_IP4_DECODE(&target_ip, ucp + 8 + 16);
      SSH_DEBUG(SSH_D_NICETOKNOW, 
		("arp request from %d (%x); who-has %@ tell %@",
		 (int) pp->ifnum_in, pp->flags,
		 ssh_ipaddr_render, &target_ip,
		 ssh_ipaddr_render, &sender_ip));
      if (SSH_IP_IS_NULLADDR(&sender_ip))
        {
          SSH_DEBUG(SSH_D_NICETOKNOW, ("Request is an ARP Probe."
                                       " No action needed."));
          return TRUE;
        }
      /* Lookup the IP address from the ARP cache. */
      if (ssh_engine_arp_lookup_address(engine, &target_ip, pp->ifnum_in,
					target_hw, &flags))
        {
          SSH_DEBUG(SSH_D_NICETOKNOW, 
		    ("%s; %@ is-at %@: flags=0x%x",
		     SSH_IP_EQUAL(&sender_ip, &target_ip) ? 
		     "gratuitous arp request" 
		     : "arp request", 
		     ssh_ipaddr_render, &target_ip,
		     ssh_engine_arp_render_eth_mac,
		     target_hw,
		     (unsigned int) flags));
          /* Reply to arp requests from local stack except gratuitous arp
             requests, which are sent out. Or if we do proxy arp for the IP.
          */
          if (((pp->flags & SSH_PACKET_FROMPROTOCOL) &&
               (!SSH_IP_EQUAL(&sender_ip, &target_ip)))
              || (flags & SSH_ENGINE_ARP_F_PROXY))
            {
              unsigned char source_hw[6];
              Boolean ret;

              /* If we are doing proxy ARP, reply with our interface's
                 address. */
              if (flags & SSH_ENGINE_ARP_F_PROXY)
		{
		  /* Fetch our interface's hardware address. */
		  ssh_kernel_mutex_lock(engine->interface_lock);
		  ret = ssh_engine_arp_get_hwaddr(engine, pp->ifnum_in, 
						  source_hw);
		  ssh_kernel_mutex_unlock(engine->interface_lock);
		  memcpy(target_hw, source_hw, 6);
		}
	      else 
		{
		  ret = TRUE;
		  memcpy(source_hw, target_hw, 6);
		}

              /* Reply for this ARP request. */
              if (ret == TRUE)
                ssh_engine_arp_send_reply(engine,
                                          ((pp->flags & SSH_PACKET_FROMADAPTER)
                                           ? TRUE : FALSE),
                                          pp->ifnum_in,
                                          &sender_ip, sender_hw,
                                          &target_ip, target_hw,
                                          source_hw);

              /* Done with the packet. */
              ssh_interceptor_packet_free(pp);
              return FALSE;
            } 
          else if ((pp->flags & SSH_PACKET_FROMADAPTER) &&
                    (SSH_IP_EQUAL(&sender_ip, &target_ip)))
            {
              /* Gratuitous ARP case.  */
              ssh_engine_gratuitous_arp(engine, &sender_ip, pp->ifnum_in, 
					sender_hw);              
              return TRUE;
            }
          else if ((pp->flags & SSH_PACKET_FROMADAPTER) &&
                   memcmp(sender_hw, target_hw, 6))
            {
	      ssh_engine_arp_add_address(engine,
					 &sender_ip,
					 pp->ifnum_in,
					 sender_hw);
	      return TRUE;
            }
        }
    }

  /* We did not recognize the arp packet or do not want to process it. */
  SSH_DEBUG(SSH_D_UNCOMMON,
            ("Packet was some other ARP packet, no action taken"));
  return TRUE;
}

#if defined(WITH_IPV6)
/* Send an IPv6 Neighbor Solicitation ICMP (the IPv6 equivalent of ARP). */
void ssh_engine_arp_send_solicitation(SshEngine engine,
                                      SshIpAddr targetaddr,
                                      SshEngineIfnum ifnum_out,
                                      SshIpAddr ownaddr,
                                      unsigned char *ownhw)
{
  SshInterceptorPacket pp;
  unsigned char *ucp, *icmp, addr[16];
  unsigned char media_addr[6];
  SshUInt16 checksum;
  SshIpAddrStruct dstaddr;

  SSH_ASSERT(SSH_IP_IS6(targetaddr));
  SSH_DEBUG(SSH_D_MIDSTART,
            ("solicitation for %@ requested (we are %@)",
             ssh_ipaddr_render, targetaddr,
             ssh_engine_arp_render_eth_mac, ownhw));

  /* Allocate a packet for the neighbor solicitation.  32 = icmp type
     (1) + icmp code (1) + checksum (2) + reserved(4) + target addr
     (16) + options (8). */
  pp = ssh_interceptor_packet_alloc(engine->interceptor,
				    SSH_PACKET_FROMPROTOCOL,
                                    SSH_PROTOCOL_ETHERNET,
				    SSH_INTERCEPTOR_INVALID_IFNUM,
				    ifnum_out,
                                    SSH_IPH6_HDRLEN + 32);
  if (!pp)
    {
      SSH_DEBUG(SSH_D_ERROR,
                ("Could not allocate packet for solicitation message."));
      return;
    }

  if (!(ucp = ssh_interceptor_packet_pullup(pp, SSH_IPH6_HDRLEN + 32)))
    {
      SSH_DEBUG(SSH_D_ERROR,
                ("Failed pullup of solicitation message"));
      return;
    }

  /* Use solicited-node multicast address for target address. */
  memset(addr, 0, 16);
  addr[0] = 0xff;
  addr[1] = 0x02;
  addr[11] = 0x01;
  addr[12] = 0xff;
  addr[13] = SSH_IP6_BYTE14(targetaddr);
  addr[14] = SSH_IP6_BYTE15(targetaddr);
  addr[15] = SSH_IP6_BYTE16(targetaddr);
  SSH_IP6_DECODE(&dstaddr, addr);

  /* The ethernet multicast group for the above constructed IP address */
  media_addr[0] = 0x33;
  media_addr[1] = 0x33;
  media_addr[2] = addr[12];
  media_addr[3] = addr[13];
  media_addr[4] = addr[14];
  media_addr[5] = addr[15];

  /* Construct the IPv6 pseudo-header. */
  memset(ucp, 0, SSH_IP6_PSEUDOH_HDRLEN);
  SSH_IP6_PSEUDOH_SET_SRC(ownaddr, ucp);
  SSH_IP6_PSEUDOH_SET_DST(&dstaddr, ucp);
  SSH_IP6_PSEUDOH_SET_LEN(ucp, 32);
  SSH_IP6_PSEUDOH_SET_NH(ucp, SSH_IPPROTO_IPV6ICMP);

  /* ICMP header */
  icmp = ucp + SSH_IPH6_HDRLEN;
  SSH_ICMP6H_SET_TYPE(icmp, SSH_ICMP6_TYPE_NEIGHBOR_SOLICITATION);
  SSH_ICMP6H_SET_CODE(icmp, 0);
  SSH_ICMP6H_SET_CHECKSUM(icmp, 0);

  /* Neighbor solicitation */
  SSH_PUT_32BIT(icmp + 4, 0);   /* reserved, must be set to 0 */
  SSH_IP6_ENCODE(targetaddr, icmp + 8); /* target address */




  SSH_PUT_8BIT(icmp + 24, SSH_ICMP6_NEIGHDISC_OPT_SOURCE_LINK_ADDRESS);
  SSH_PUT_8BIT(icmp + 25, 1); /* 8 bytes */
  memcpy(icmp + 26, ownhw, 6); /* Ethernet address */

  /* Calculate checksum */
  checksum = ssh_ip_cksum_packet(pp, 0, SSH_IPH6_HDRLEN + 32);
  SSH_ICMP6H_SET_CHECKSUM(icmp, checksum);

  /* Now construct the real IPv6 headers */
  SSH_IPH6_SET_VERSION(ucp, 6);
  SSH_IPH6_SET_CLASS(ucp, 0);
  SSH_IPH6_SET_FLOW(ucp, 0);
  SSH_IPH6_SET_LEN(ucp, 32);
  SSH_IPH6_SET_NH(ucp, SSH_IPPROTO_IPV6ICMP);
  SSH_IPH6_SET_HL(ucp, 255);
  SSH_IPH6_SET_SRC(ownaddr, ucp);
  SSH_IPH6_SET_DST(&dstaddr, ucp);

  SSH_DEBUG(SSH_D_MIDSTART,
            ("Solicitation message, ether from %@ to %@",
             ssh_engine_arp_render_eth_mac, ownhw,
             ssh_engine_arp_render_eth_mac, media_addr));
  SSH_DUMP_PACKET(SSH_D_LOWSTART, "solicitation packet", pp);

  /* Encapsulate the packet in an ethernet header.  We send the packet as
     an ethernet broadcast. */
  ssh_engine_encapsulate_and_send(engine, pp, ownhw, media_addr,
                                  SSH_ETHERTYPE_IPv6);
}

/* Send an IPv6 Neighbor Advertisement ICMP
   (the IPv6 equivalent of ARP reply). */

void ssh_engine_arp_send_advertisement(SshEngine engine,
				       Boolean outgoing,
				       SshEngineIfnum ifnum_out,
				       SshIpAddr dst_ip,
				       unsigned char *dst_hw,
				       SshIpAddr target_ip,
				       unsigned char *target_hw,
				       SshIpAddr own_ip,
				       unsigned char *own_hw,
				       Boolean router,
				       Boolean solicited,
				       Boolean override)
{
  SshInterceptorPacket pp;
  unsigned char *ucp, *icmp;
  SshUInt16 checksum;
  SshUInt8 flags = 0;

  SSH_ASSERT(SSH_IP_IS6(target_ip));
  SSH_DEBUG(SSH_D_MIDSTART,
            ("advertisement for %@ hw %@ to %@ hw %@",
             ssh_ipaddr_render, target_ip,
             ssh_engine_arp_render_eth_mac, target_hw,
             ssh_ipaddr_render, dst_ip,
             ssh_engine_arp_render_eth_mac, dst_hw));

  /* Allocate a packet for the neighbor advertisement. 32 = icmp type
     (1) + icmp code (1) + checksum (2) + reserved(4) + target addr
     (16) + options (8). */
  pp = ssh_interceptor_packet_alloc(engine->interceptor,
				    (outgoing ?
				     SSH_PACKET_FROMPROTOCOL :
				     SSH_PACKET_FROMADAPTER),
                                    SSH_PROTOCOL_ETHERNET,
				    SSH_INTERCEPTOR_INVALID_IFNUM,
				    ifnum_out,
                                    SSH_IPH6_HDRLEN + 32);
  if (!pp)
    {
      SSH_DEBUG(SSH_D_ERROR,
                ("Could not allocate packet for solicitation message."));
      return;
    }

  if (!(ucp = ssh_interceptor_packet_pullup(pp, SSH_IPH6_HDRLEN + 32)))
    {
      SSH_DEBUG(SSH_D_ERROR,
                ("Failed pullup of solicitation message"));
      return;
    }

  /* Construct the IPv6 pseudo-header. */
  memset(ucp, 0, SSH_IP6_PSEUDOH_HDRLEN);
  SSH_IP6_PSEUDOH_SET_SRC(own_ip, ucp);
  SSH_IP6_PSEUDOH_SET_DST(dst_ip, ucp);
  SSH_IP6_PSEUDOH_SET_LEN(ucp, 32);
  SSH_IP6_PSEUDOH_SET_NH(ucp, SSH_IPPROTO_IPV6ICMP);

  /* ICMP header */
  icmp = ucp + SSH_IPH6_HDRLEN;
  SSH_ICMP6H_SET_TYPE(icmp, SSH_ICMP6_TYPE_NEIGHBOR_ADVERTISEMENT);
  SSH_ICMP6H_SET_CODE(icmp, 0);
  SSH_ICMP6H_SET_CHECKSUM(icmp, 0);

  /* Neighbor advertisement */
  if (router)
    flags |= 0x80;
  if (solicited)
    flags |= 0x40;
  if (override)
    flags |= 0x20;
  SSH_PUT_32BIT(icmp + 4, 0);   /* reserved, must be set to 0 */
  SSH_PUT_8BIT(icmp + 4, flags);
  SSH_IP6_ENCODE(target_ip, icmp + 8); /* target address */




  SSH_PUT_8BIT(icmp + 24, SSH_ICMP6_NEIGHDISC_OPT_TARGET_LINK_ADDRESS);
  SSH_PUT_8BIT(icmp + 25, 1); /* 8 bytes */
  memcpy(icmp + 26, target_hw, 6); /* Ethernet address */

  /* Calculate checksum */
  checksum = ssh_ip_cksum_packet(pp, 0, SSH_IPH6_HDRLEN + 32);
  SSH_ICMP6H_SET_CHECKSUM(icmp, checksum);

  /* Now construct the real IPv6 headers */
  SSH_IPH6_SET_VERSION(ucp, 6);
  SSH_IPH6_SET_CLASS(ucp, 0);
  SSH_IPH6_SET_FLOW(ucp, 0);
  SSH_IPH6_SET_LEN(ucp, 32);
  SSH_IPH6_SET_NH(ucp, SSH_IPPROTO_IPV6ICMP);
  SSH_IPH6_SET_HL(ucp, 255);
  SSH_IPH6_SET_SRC(own_ip, ucp);
  SSH_IPH6_SET_DST(dst_ip, ucp);

  SSH_DEBUG(SSH_D_MIDSTART,
            ("Advertisement message, ether from %@ to %@",
             ssh_engine_arp_render_eth_mac, own_hw,
             ssh_engine_arp_render_eth_mac, dst_hw));
  SSH_DUMP_PACKET(SSH_D_LOWSTART, "advertisement packet", pp);

  /* Encapsulate the packet in an ethernet header.  We send the packet to
     destination hw address. */
  ssh_engine_encapsulate_and_send(engine, pp, own_hw, dst_hw,
                                  SSH_ETHERTYPE_IPv6);
}


/* Processes an incoming IPv6 neighbor advertisement packet.  This
   function will update the arp table as appropriate, and will cause
   the SshEngineArpComplete callback to be called for any pending
   requests completed by this packet.  The packet in `pp' should not
   contain media header, but the media header should be saved in
   pd->mediahdr.  Normally, this will not free `pp' and returns TRUE,
   because the packet will normally also be passed to the host TCP/IP
   stack.  If an error causes the packet to be freed, this returns
   FALSE.

   This function can be called concurrently.  This will momentarily lock
   the engine lock to modify the cache data structures. */

Boolean ssh_engine_arp_neighbor_advertisement(SshEngine engine,
                                              SshInterceptorPacket pp)
{
  const unsigned char *ucp;
  size_t offset, len, optlen;
  SshUInt8 ipproto, hop_limit;
  unsigned char opthdr[4], hw[SSH_ETHERH_ADDRLEN];
  SshIpAddrStruct targetaddr;
  Boolean link_address_found = FALSE;
  SshEnginePacketData pd;

  SSH_DEBUG(SSH_D_HIGHSTART,
            ("Neighbor advertisement input (proto=%d flags=0x%x)",
             pp->protocol, (unsigned int) pp->flags));

  /* Do sanity checks that the packet is of proper type, comes from
     the network, and that it is long enough to contain the IPv6
     Neighbor advertisement ICMP header, which is at least 24 bytes
     long. */
  len = ssh_interceptor_packet_len(pp);
  if (pp->protocol != SSH_PROTOCOL_IP6 ||
      len < SSH_IPH6_HDRLEN + 24)
    {
      SSH_DEBUG(13, ("Neighbor advertisement not IPv6 or too short"));
      return TRUE;
    }

  /* Look at the IP header. */
  if (!(ucp = ssh_interceptor_packet_pullup_read(pp, SSH_IPH6_HDRLEN + 24)))
    {
      SSH_DEBUG(SSH_D_ERROR, ("Packet dropped because pullup failed"));
      return FALSE;
    }
  ipproto = SSH_IPH6_NH(ucp);
  hop_limit = SSH_IPH6_HL(ucp);

  /* Move to the beginning of the ICMPv6 header.  We have 24 bytes of valid
     data from there. */
  ucp += SSH_IPH6_HDRLEN;

  /* Check that this ICMP is a neighbor advertisement. */
  if (ucp[0] != SSH_ICMP6_TYPE_NEIGHBOR_ADVERTISEMENT ||
      ucp[1] != 0)
    {
      SSH_DEBUG(SSH_D_MIDRESULT, ("Not handled because ICMPv6 type (%d, %d) "
                                  "not Neighbor Advertisement",
                                  ucp[0], ucp[1]));
      return TRUE;
    }




  SSH_IP6_DECODE(&targetaddr, ucp + 8);
  if (SSH_IP_IS_MULTICAST(&targetaddr) || hop_limit != 255)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Neighbor advertisement fails checks"));
      return TRUE;
    }

  /* There are two possibilities regarding the media address. Either
     there is ICMPv6 Source/Target link-layer Address option (which is
     preferred), or if that is not present then we should have cached
     media address (in packet data). If neither requirement can be
     satisfied, then we will not process the packet further. */
  for (offset = SSH_IPH6_HDRLEN + 24; offset + 2 < len; offset += optlen)
    {
      /* Read option header from the packet. */
      ssh_interceptor_packet_copyout(pp, offset, opthdr, 2);

      /* Get and sanity check option length. */
      optlen = opthdr[1] * 8;
      if (optlen == 0 || offset + optlen > len)
        {
          SSH_DEBUG(SSH_D_ERROR, ("Neighbor advertisement with bad optlen"));
          return TRUE;
        }

      /* We are only interested in target addresses */
      if (opthdr[0] == SSH_ICMP6_NEIGHDISC_OPT_TARGET_LINK_ADDRESS)
        {
          /* Sanity check that the link-level address is not too long. */
          if (optlen - 2 > SSH_ETHERH_ADDRLEN)
            {
              SSH_DEBUG(SSH_D_ERROR,
                        ("Received neighbor advertisement with media "
                         "data (%d) longer than ether addr len",
                         optlen - 2));
              return TRUE;
            }
          SSH_DEBUG(SSH_D_MIDSTART, ("Neighbor link address found"));

          ssh_interceptor_packet_copyout(pp, offset + 2, hw, optlen - 2);
          link_address_found = TRUE;
          break;
        }
    }

  pd = SSH_INTERCEPTOR_PACKET_DATA(pp, SshEnginePacketData);
  if (!link_address_found && pd->mediatype == SSH_INTERCEPTOR_MEDIA_ETHERNET)
    {
      SSH_DEBUG(SSH_D_MIDSTART,
                ("Neigh adv with cached media address"));

      memcpy(hw, pd->mediahdr + SSH_ETHERH_OFS_SRC, sizeof(hw));
      link_address_found = TRUE;
    }

  /* If no link media address found, nor cached, do not continue. */
  if (!link_address_found)
    {
      SSH_DEBUG(SSH_D_MIDOK,
                ("No link level address or cached media address found "
                 "for ICMPv6 neighbor advertisement message, "
                 "passing unhandled."));
      return TRUE;
    }

  /* Sanity check that the media address is not a multicast/broadcast
     address. */
  if (SSH_ETHER_IS_MULTICAST(hw))
    {
      SSH_DEBUG(SSH_D_ERROR,
                ("Got multicast address (%@) in neighbor "
                 "advertisement, dropped.",
                 ssh_engine_arp_render_eth_mac, hw));
      return TRUE;
    }

  SSH_DEBUG(SSH_D_MIDOK,
            ("neigh adv for address %@ hw %@",
             ssh_ipaddr_render, &targetaddr,
             ssh_engine_arp_render_eth_mac, hw));

  /* Add the received address to the cache.  This will cause the callback to
     be called, if there is any, and update the cache if there is an entry for
     it. */
  ssh_engine_arp_add_address(engine, &targetaddr, pp->ifnum_in, hw);
  return TRUE;
}
/* Processes an IPv6 neighbor solicitation packet. This
   function will update the arp table as appropriate, and reply to
   the solicitation if it is an neighbor discovery. The packet
   in `pp' should not contain media header, but the media header
   should be saved in pd->mediahdr.  Normally, this will not free
   `pp' and returns TRUE, because the packet will normally also be
   passed to the host TCP/IP stack.  If an error causes the packet
   to be freed, this returns FALSE.

   This function can be called concurrently.  This will momentarily lock
   the engine lock to modify the cache data structures. */

Boolean ssh_engine_arp_neighbor_solicitation(SshEngine engine,
					     SshInterceptorPacket pp)
{
  const unsigned char *ucp;
  size_t offset, len, optlen;
  SshUInt8 ipproto, hop_limit;
  unsigned char opthdr[4], src_hw[SSH_ETHERH_ADDRLEN];
  unsigned char target_hw[SSH_ETHERH_ADDRLEN];
  SshIpAddrStruct target_ip, src_ip, dst_ip;
  Boolean src_address_option = FALSE, src_address_cached = FALSE;
  SshEnginePacketData pd;
  SshUInt8 flags = 0;

  SSH_DEBUG(SSH_D_HIGHSTART,
            ("Neighbor solicitation input (proto=%d flags=0x%x)",
             pp->protocol, (unsigned int) pp->flags));

  /* Do sanity checks that the packet is of proper type and that it
     is long enough to contain the IPv6 Neighbor solicitation ICMP
     header, which is at least 24 bytes long. */
  len = ssh_interceptor_packet_len(pp);
  if (pp->protocol != SSH_PROTOCOL_IP6 ||
      len < SSH_IPH6_HDRLEN + 24)
    {
      SSH_DEBUG(13, ("Neighbor solicitation not IPv6 or too short"));
      return TRUE;
    }

  /* Look at the IP header. */
  if (!(ucp = ssh_interceptor_packet_pullup_read(pp, SSH_IPH6_HDRLEN + 24)))
    {
      SSH_DEBUG(SSH_D_ERROR, ("Packet dropped because pullup failed"));
      return FALSE;
    }
  SSH_IPH6_SRC(&src_ip, ucp);
  SSH_IPH6_DST(&dst_ip, ucp);
  ipproto = SSH_IPH6_NH(ucp);
  hop_limit = SSH_IPH6_HL(ucp);

  /* Move to the beginning of the ICMPv6 header.  We have 24 bytes of valid
     data from there. */
  ucp += SSH_IPH6_HDRLEN;

  /* Check that this ICMP is a neighbor advertisement. */
  if (ucp[0] != SSH_ICMP6_TYPE_NEIGHBOR_SOLICITATION ||
      ucp[1] != 0)
    {
      SSH_DEBUG(SSH_D_MIDRESULT, ("Not handled because ICMPv6 type (%d, %d) "
                                  "not Neighbor Solicitation",
                                  ucp[0], ucp[1]));
      return TRUE;
    }




  SSH_IP6_DECODE(&target_ip, ucp + 8);
  if (SSH_IP_IS_MULTICAST(&target_ip) || hop_limit != 255)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Neighbor solicitation fails checks"));
      return TRUE;
    }

  /* There are two possibilities regarding the media address. Either
     there is ICMPv6 Source link-layer Address option (which is
     preferred), or if that is not present then we should have cached
     media address (in packet data). If neither requirement can be
     satisfied, then we will not process the packet further. */
  for (offset = SSH_IPH6_HDRLEN + 24; offset + 2 < len; offset += optlen)
    {
      /* Read option header from the packet. */
      ssh_interceptor_packet_copyout(pp, offset, opthdr, 2);

      /* Get and sanity check option length. */
      optlen = opthdr[1] * 8;
      if (optlen == 0 || offset + optlen > len)
	{
	  SSH_DEBUG(SSH_D_ERROR,
		    ("Neighbor solicitation with bad optlen"));
	  return TRUE;
	}

      /* We are only interested in source addresses */
      if (opthdr[0] == SSH_ICMP6_NEIGHDISC_OPT_SOURCE_LINK_ADDRESS)
	{
	  /* Sanity check that the link-level address is not too long. */
	  if (optlen - 2 > SSH_ETHERH_ADDRLEN)
	    {
	      SSH_DEBUG(SSH_D_ERROR,
			("Received neighbor solicitation with media "
			 "data (%d) longer than ether addr len",
			 optlen - 2));
	      return TRUE;
	    }
	  SSH_DEBUG(SSH_D_MIDSTART, ("Neighbor link address found"));

	  ssh_interceptor_packet_copyout(pp, offset + 2, src_hw, optlen - 2);
	  src_address_option = TRUE;
	  break;
	}
    }

  pd = SSH_INTERCEPTOR_PACKET_DATA(pp, SshEnginePacketData);
  if (!src_address_option &&
      pd->mediatype == SSH_INTERCEPTOR_MEDIA_ETHERNET)
    {
      SSH_DEBUG(SSH_D_MIDSTART,
		("Neigh sol with cached media address"));

      memcpy(src_hw, pd->mediahdr + SSH_ETHERH_OFS_SRC, sizeof(src_hw));
      src_address_cached = TRUE;
    }

  /* If no link media address found, nor cached, do not continue. */
  if (!src_address_option && !src_address_cached)
    {
      SSH_DEBUG(SSH_D_MIDOK,
		("No link level address or cached media address found "
		 "for ICMPv6 neighbor solicitation message, "
		 "passing unhandled."));
      return TRUE;
    }

  /* Sanity check that the media address is not a multicast/broadcast
     address. */
  if (SSH_ETHER_IS_MULTICAST(src_hw))
    {
      SSH_DEBUG(SSH_D_ERROR,
		("Got multicast address (%@) in neighbor "
		 "solicitation, dropped.",
		 ssh_engine_arp_render_eth_mac, src_hw));
      return TRUE;
    }

  SSH_DEBUG(SSH_D_MIDOK,
	    ("neigh sol for address %@ from address %@ hw %@",
	     ssh_ipaddr_render, &target_ip,
	     ssh_ipaddr_render, &src_ip,
	     ssh_engine_arp_render_eth_mac, src_hw));

  /* Add source address to neighbor cache if solicitation came from network.
     Note: ssh_engine_arp_add() does not call the completition callbacks
     for pending ARP entries. A full neigh sol - neigh adv pair is needed
     for a compeleted ARP resolution. */

  /* RFC2461:
     If the Source Address is not the unspecified
     address and, on link layers that have addresses, the solicitation
     includes a Source Link-Layer Address option, then the recipient
     SHOULD create or update the Neighbor Cache entry for the IP Source
     Address of the solicitation.  If an entry does not already exist, the
     node SHOULD create a new one and set its reachability state to STALE
     as specified in Section 7.3.3.  If an entry already exists, and the
     cached link-layer address differs from the one in the received Source
     Link-Layer option, the cached address should be replaced by the
     received address and the entry's reachability state MUST be set to
     STALE.*/

  if ((pp->flags & SSH_PACKET_FROMADAPTER) &&
      !SSH_IP_IS_NULLADDR(&src_ip) &&
      src_address_option)
    {

      /* Take the engine lock to access protected data structures. */
      ssh_kernel_mutex_lock(engine->interface_lock);

      ssh_engine_arp_add(engine, &src_ip, pp->ifnum_in, src_hw,
			 FALSE, FALSE, FALSE);

      /* Release the engine lock. */
      ssh_kernel_mutex_unlock(engine->interface_lock);
    }

  /* Let duplicate address detection neighbor solicitations from local
     stack go through. DAD packets have solicited node multicast IPv6 dst,
     undefined IPv6 src, and local ICMPv6 neighbor solicitation target.

     Implementation note: The interceptor might have not yet sent the
     interface information to engine. In such case ssh_engine_ip_is_local()
     returns FALSE. But so does ssh_engine_arp_lookup_address(), as the 
     local addresses are added to ARP cache when receiving interface 
     information. The result is that the solicitation will go through 
     unmodified. */

  if ((pp->flags & SSH_PACKET_FROMPROTOCOL) &&
      SSH_IP_IS_NULLADDR(&src_ip) &&
      SSH_IP_IS_MULTICAST(&dst_ip) &&
      ssh_engine_ip_is_local(engine, &target_ip))
    {
      SSH_DEBUG(SSH_D_MIDOK, 
		("Neighbor solicitation for address %@ is DAD",
		 ssh_ipaddr_render, &target_ip));
      return TRUE;
    }

  /* Lookup the IP address from the ARP cache. */
  if (ssh_engine_arp_lookup_address(engine, &target_ip, pp->ifnum_in,
				    target_hw, &flags))
    {
      /* Reply to neigh sols from local stack to multicast addresses
	 or from network with a target address we are proxy arping. */
      if (((pp->flags & SSH_PACKET_FROMPROTOCOL) &&
	   SSH_IP6_IS_MULTICAST(&dst_ip))
	  || (flags & SSH_ENGINE_ARP_F_PROXY))
	{
	  SshIpAddrStruct own_ip;
	  unsigned char own_hw[SSH_ETHERH_ADDRLEN];
	  Boolean ret;
	  Boolean solicited = TRUE;
	  Boolean override = TRUE;
	  Boolean outgoing = TRUE;

	  SSH_DEBUG(SSH_D_NICETOKNOW,
		    ("Sending neigh adv for address %@ hw %@: flags=0x%x",
		     ssh_ipaddr_render, &target_ip,
		     ssh_engine_arp_render_eth_mac, target_hw,
		     (unsigned int) flags));

	  ssh_kernel_mutex_lock(engine->interface_lock);

	  /* Fetch our interface's IP address */
          /* Try looking first with the destination address (src_ip here). 
             So prefer addresses with same scope. */
	  ret = ssh_engine_get_ipaddr(engine, pp->ifnum_in,
				      SSH_PROTOCOL_IP6, &src_ip, &own_ip);
          if (ret == FALSE)
            ret = ssh_engine_get_ipaddr(engine, pp->ifnum_in, 
                                         SSH_PROTOCOL_IP6, NULL, &own_ip);
	  /* Fetch our interface's hw address */
	  ret &= ssh_engine_arp_get_hwaddr(engine, pp->ifnum_in, own_hw);

	  ssh_kernel_mutex_unlock(engine->interface_lock);

	  /* If we are doing proxy ARP, reply with our interface's
	     address. */
	  if (flags & SSH_ENGINE_ARP_F_PROXY)
	    {
	      memcpy(target_hw, own_hw, 6);
	      override = FALSE;
	    }

	  /* RFC2461:
	     If the source of the solicitation is the unspecified address,
	     the node MUST set the Solicited flag to zero and multicast the
	     advertisement to the all-nodes address.Otherwise, the node MUST
	     set the Solicited flag to one and unicast the advertisement to
	     the Source Address of the solicitation. */
	  solicited = TRUE;
	  if (SSH_IP_IS_NULLADDR(&src_ip))
	    {
	      unsigned char addr[16];
	      memset(addr, 0, 16);
	      addr[0] = 0xff;
	      addr[1] = 0x02;
	      addr[15] = 0x01;
	      SSH_IP6_DECODE(&src_ip, addr);
	      src_hw[0] = 0x33;
	      src_hw[1] = 0x33;
	      src_hw[2] = addr[12];
	      src_hw[3] = addr[13];
	      src_hw[4] = addr[14];
	      src_hw[5] = addr[15];
	      solicited = FALSE;
	    }

	  if (pp->flags & SSH_PACKET_FROMPROTOCOL)
	    outgoing = FALSE;

	  /* Reply for this neighbour advertisement. */
	  if (ret == TRUE)
	    ssh_engine_arp_send_advertisement(engine,
					      outgoing,
					      pp->ifnum_in,
					      &src_ip, src_hw,
					      &target_ip, target_hw,
					      &own_ip, own_hw,
					      FALSE, /* router flag */
					      solicited,
					      override);

	  /* Done with the packet. */
	  ssh_interceptor_packet_free(pp);
	  /* Drop the solicitation */
	  return FALSE;
	}
    }

  /* Let the solicitation continue to network / protocol. */
  return TRUE;
}

#endif  /* defined(WITH_IPV6) */

#if defined(SSH_IPSEC_UNIFIED_ADDRESS_SPACE) && \
    defined(SSH_ENGINE_MEDIA_ETHER_NO_ARP_RESPONSES)

typedef struct SshEngineArpContextRec {
  SshEngine engine;
  SshIpAddrStruct target;
} *SshEngineArpContext, SshEngineArpContextStruct;

static void ssh_engine_arp_now(void *context)
{
  SshEngineArpContext c = (SshEngineArpContext)context;
  if (!ssh_engine_upcall_timeout(c->engine))
    {
      ssh_free(c);
      return;
    }
  ssh_pmp_receive_ether_arprequest(c->engine->pm, &c->target);
  ssh_free(c);
}
#endif /* SSH_IPSEC_UNIFIED_ADDRESS_SPACE */

/* Sends an arp request for the IP address in the arp cache entry.
   The function must not be called with engine lock held, as it will
   send packet to the interceptor (that may indicate packet to engine
   while engine_send is still executing. */

void ssh_engine_arp_send_request(SshEngine engine,
                                 SshIpAddr targetaddr,
                                 SshEngineIfnum ifnum_out,
                                 SshIpAddr ownaddr,
                                 unsigned char *ownhw)
{
  SSH_ASSERT(SSH_IP_IS4(targetaddr));
  SSH_DEBUG(SSH_D_MIDSTART, ("arp send request for %@",
                             ssh_ipaddr_render, targetaddr));

#ifdef SSH_ENGINE_MEDIA_ETHER_NO_ARP_RESPONSES
  {
    /* There is no point in sending ARP requests, because the engine
       will never receive ARP replies.  Instead, we send a request to
       the policy manager to send out a bogus packet to the desired
       destination; we will then snoop the ARP ethernet address from
       that packet. */
#ifdef SSH_IPSEC_UNIFIED_ADDRESS_SPACE
    {
      SshEngineArpContext c;

      if ((c = ssh_malloc(sizeof(*c))) == NULL)
        return;

      c->engine = engine;
      c->target = *targetaddr;

      ssh_kernel_mutex_lock(engine->flow_control_table_lock);
      ssh_engine_record_upcall(engine);
      ssh_kernel_mutex_unlock(engine->flow_control_table_lock);

      if (ssh_register_timeout(NULL, 0L, 0L,
                               ssh_engine_arp_now, (void *)c)
          == NULL)
	{
	  /* Timeout registration failed,
	     decrement pending upcall counter */
	  ssh_engine_upcall_timeout(engine);
	  ssh_free(c);
	}
    }
#else /* SSH_IPSEC_UNIFIED_ADDRESS_SPACE */
    {
      unsigned char target[SSH_MAX_IPADDR_ENCODED_LENGTH];
      size_t target_len;

      if ((target_len =
           ssh_encode_ipaddr_array(target, sizeof(target), targetaddr))
          == 0)
        return;

      ssh_engine_send(engine, TRUE, FALSE,
                      SSH_ENCODE_UINT32((SshUInt32)0), /* reserved */
                      SSH_ENCODE_CHAR((unsigned int) SSH_EPA_ETHER_ARPREQUEST),
                      SSH_ENCODE_UINT32_STR(target, target_len),
                      SSH_FORMAT_END);
    }
#endif /* SSH_IPSEC_UNIFIED_ADDRESS_SPACE */
  }

#else /* SSH_ENGINE_MEDIA_ETHER_NO_ARP_RESPONSES */

  {
    unsigned char *ucp;
    SshInterceptorPacket pp;

    /* Allocate a new packet for the specified interface.  We reserve
       28 bytes for the packet (the size of an IPv4 ethernet arp
       request). */
    pp = ssh_interceptor_packet_alloc(engine->interceptor,
                                      SSH_PACKET_FROMPROTOCOL,
                                      SSH_PROTOCOL_ETHERNET,
				      SSH_INTERCEPTOR_INVALID_IFNUM,
				      ifnum_out, 28);
    if (!pp)
      return;

    /* Get a pointer to the packet data. */
    ucp = ssh_interceptor_packet_pullup(pp, 28);
    if (ucp == NULL)
      return; /* pp was just allocated; no need to do anything special here */

    /* Build the arp request.  First copy the header. */
    memcpy(ucp, ssh_engine_arp_hdr_ipv4_request, 8);

    /* Store our own IP address. */
    if (SSH_IP_IS4(ownaddr))
      SSH_IP4_ENCODE(ownaddr, ucp + 14);
    else
      memset(ucp + 14, 0, 4);
    memcpy(ucp + 8, ownhw, 6);

    /* Set the target hardware address  to zero. */
    memset(ucp + 18, 0, 6);

    /* Set the target address being queried. */
    SSH_IP4_ENCODE(targetaddr, ucp + 24);

    /* Encapsulate the packet in an ethernet header.  We send the packet as
       an ethernet broadcast. */
    ssh_engine_encapsulate_and_send(engine, pp, ownhw,
                                    ssh_engine_arp_ethernet_broadcast_addr,
                                    SSH_ETHERTYPE_ARP);
  }
#endif /* SSH_ENGINE_MEDIA_ETHER_NO_ARP_RESPONSES */
}

/* This function is called from a timeout if we don't get an answer
   for an arp request fast enough.  This will resend the request and
   reset the timer, until the maximum number of retries has been
   performed.  If there is still no reply, the entry is marked failed
   (but the packet queue is not yet freed, in case the reply is just
   delayed; the list will anyway will be freed when the arp cache
   entry times out).  This function is called from a timeout, possibly
   concurrently with other functions. */

void ssh_engine_arp_request_timeout(void *context)
{
  SshEngine engine = (SshEngine)context;
  SshEngineArpCache cache = &engine->arp_cache;
  SshEngineArpCacheEntry entry, *entryp;
#define MAX_RESENDS     5
  struct {
    SshIpAddrStruct addr;
    SshEngineIfnum ifnum;
  } resends[MAX_RESENDS], *r;
  SshEnginePacketContext to_be_freed[MAX_RESENDS];
  SshIpAddrStruct ownaddr;
  unsigned char ownhw[6];
  SshUInt32 num_resend, num_to_free, i;
  Boolean resend_full;

 restart:
  resend_full = FALSE;
  num_resend = 0;
  num_to_free = 0;

  SSH_DEBUG(SSH_D_LOWSTART, ("ARP; request timeout"));

  /* Take the engine lock. */
  ssh_kernel_mutex_lock(engine->interface_lock);

  /* Mark that no retry timeout is scheduled. */
  cache->retry_timeout_scheduled = FALSE;

  /* Process all entries on the retry list. */
  for (entryp = &cache->retry_list; *entryp; )
    {
      entry = *entryp;

      /* If the retry count has been exhausted, set the status of the
         entry to failed and return.  However, we do not immediately
         free the queued packets in case an arp reply arrives late.
         The packets will eventually be freed when the arp cache entry
         expires anyway.  Since the time-to-live of failed entries is
         never increased, this should happen reasonably soon. */
      if (entry->arp_retry_count >= SSH_ENGINE_MAX_ARP_RETRIES)
        {
          SSH_ASSERT(entry->status == SSH_ENGINE_ARP_INCOMPLETE);

          SSH_DEBUG(SSH_D_MIDOK,
                    ("ArpReq failed after retries for q'd packet %p.",
                     entry->queued_packet));

          /* Free the queued packet. */
          if (entry->queued_packet != NULL)
            {
              if (num_to_free >= MAX_RESENDS)
                { /* If too many, abort now (we restart when these
                     have been sent). */
                  resend_full = TRUE;
                  break;
                }
              to_be_freed[num_to_free++] = entry->queued_packet;
              entry->queued_packet = NULL;
            }

          /* Mark the entry as failed and return. */
          entry->status = SSH_ENGINE_ARP_FAILED;

          /* Remove the entry from the retry list.  This also moves us to
             the next entry on the list. */
          *entryp = entry->retry_list_next;
          entry->on_retry_list = FALSE;
          entry->retry_list_next = NULL;
          continue;
        }

      /* Decrement the remaining retry count. */
      entry->arp_retry_count++;

      SSH_DEBUG(SSH_D_MIDOK, ("Retry #%d for packet %p.",
                              (int)entry->arp_retry_count,
                              entry->queued_packet));

      /* Queue the ARP request to be sent when lock is no longer held
         (due to us not being allowed to interceptor-send with upper
         level lock held. */
      if (num_resend >= MAX_RESENDS)
        { /* If too many, abort now (we restart when these have been sent). */
          resend_full = TRUE;
          break;
        }
      resends[num_resend].ifnum = entry->queued_packet->arp_ifnum;
      resends[num_resend].addr = entry->ip_addr;
      num_resend++;

      /* Move to next entry. */
      entryp = &entry->retry_list_next;
    }

  /* If there are still entries on the retry list, schedule a retry
     timeout (unless one is already scheduled, which could happen if
     we restart below). */
  if (cache->retry_list != NULL && !cache->retry_timeout_scheduled)
    {
      SSH_DEBUG(SSH_D_MIDOK, ("Scheduling a retry timeout."));
      cache->retry_timeout_scheduled = TRUE;
      ssh_kernel_mutex_unlock(engine->interface_lock);
      ssh_kernel_timeout_register((long)0, (long)SSH_ENGINE_ARP_RESEND_TIMEOUT,
                                  ssh_engine_arp_request_timeout,
                                  (void *)engine);
    }
  else
    ssh_kernel_mutex_unlock(engine->interface_lock);

  /* Call arp_complete for all packets to be freed (i.e., ARP lookups that
     have failed). */
  for (i = 0; i < num_to_free; i++)
    ssh_engine_arp_complete(engine, to_be_freed[i], NULL, NULL);

  /* Then send any pending requests (resends). */
  for (i = 0; i < num_resend; i++)
    {
      Boolean ret;

      r = &resends[i];

      /* Get our own addresses for the interface. */
      ssh_kernel_mutex_lock(engine->interface_lock);
      ret = ssh_engine_arp_get_hwaddr(engine, r->ifnum, ownhw);
      if (ret == TRUE)
        {
          if (ssh_engine_get_ipaddr(engine, (SshEngineIfnum) r->ifnum,
                                    SSH_IP_IS6(&r->addr) ?
                                    SSH_PROTOCOL_IP6 : SSH_PROTOCOL_IP4,
                                    &r->addr, &ownaddr) != TRUE)
            ret = ssh_engine_get_ipaddr(engine, (SshEngineIfnum) r->ifnum,
                                        SSH_IP_IS6(&r->addr) ?
                                        SSH_PROTOCOL_IP6 : SSH_PROTOCOL_IP4,
                                        NULL, &ownaddr);
        }

      if (ret == FALSE)
        {
          SSH_DEBUG(SSH_D_FAIL, ("Could not find local ip-address %@"
                                 " or hwaddr",
                                 ssh_ipaddr_render, &ownaddr));
          ssh_kernel_mutex_unlock(engine->interface_lock);
        }
      else
        {
          ssh_kernel_mutex_unlock(engine->interface_lock);
          /* Send the ARP request or neighbor solicitation. */
#if defined(WITH_IPV6)
          if (SSH_IP_IS6(&r->addr))
            ssh_engine_arp_send_solicitation(engine, &r->addr, r->ifnum,
                                             &ownaddr, ownhw);
          else
#endif /* WITH_IPV6 */
            ssh_engine_arp_send_request(engine, &r->addr, r->ifnum,
                                        &ownaddr, ownhw);
        }
    }

  /* Repeat if the resend list became full (until we no longer have more
     resends remaining). */
  if (resend_full)
    goto restart;
}

/* Looks up the physical ethernet addresses for the next hop gateway
   nh.  This calls the supplied callback (either immediately or at a later
   time) when done (with both source and destination physical addresses).
   This assumes that the pc and nh arguments will remain valid until the
   callback has been called.

   There are several possible methods that this function uses for obtaining
   the physical address:
     1. local broadcast address (255.255.255.255) is hardwired
     2. multicast addresses are hardwired to multicast ethernet addresses
        (rfc1112 or rfc1469)
     3. loopback address (127.x.x.x) is hardwired to fail
     4. otherwise, a lookup is performed.  The media address in arp cache,
        if found, is returned.  It is expected that the local
        addresses for each interface, and the per-network broadcast addresses
        are stored in the arp cache as permanent entries.
     5. The arp protocol is used to find out the hardware address.  An entry
        is added in the arp cache. */

void ssh_engine_arp_lookup(SshEnginePacketContext pc,
                           SshIpAddr next_hop,
                           SshEngineIfnum ifnum,
                           SshEngineArpComplete callback)
{
  SshEngine engine = pc->engine;
  SshEngineArpCache cache = &engine->arp_cache;
  SshUInt32 hash;
  SshEngineArpCacheEntry entry;
  unsigned char media_addr[6], ownhw[6];
  SshIpAddrStruct ownaddr;
  SshUInt16 ethertype;
  SshEnginePacketContext old_pc = NULL;
  SshTime now;

  ssh_interceptor_get_time(&now, NULL);

  SSH_DEBUG(SSH_D_MIDSTART,
            ("ARP lookup for pc %p IP dst %@ ifnum %d",
             pc, ssh_ipaddr_render, next_hop, (int) ifnum));

  /* Save the callback function and ifnum for re-tries. */
  pc->arp_callback = callback;
  pc->arp_ifnum = ifnum;


  /* We first check the arp cache, as normal addresses are most
     frequent.  We only check for special addresses if the entry is
     not found in the cache; it is guaranteed that special addresses
     never end up in the arp cache. */

#ifdef SSH_IPSEC_SMALL
  /* And very first, we cleanup the cache from expired addresses. */
  ssh_engine_arp_cache_timeout(engine);
#endif /* SSH_IPSEC_SMALL */

  /* Compute a hash value from the ip address. */
  hash = SSH_IP_HASH(next_hop);
  hash %= SSH_ENGINE_ARP_HASH_SIZE;

  /* Take the engine lock. */
  ssh_kernel_mutex_lock(engine->interface_lock);

  /* Obtain our own hardware address for the interface on which we will send
     the ARP request.  We want to do this before anything that can jump
     to "success". */
  if (ssh_engine_arp_get_hwaddr(engine, ifnum, ownhw) == FALSE)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Failed to find hwaddr of interface %d",
		 (int) ifnum));
      /* fail: label releases the interface_lock */
      goto fail;
    }

  /* Check if the slot contains the address we are looking for. */
  for (entry = cache->hash[hash]; entry; entry = entry->next)
    if (SSH_IP_EQUAL(&entry->ip_addr, next_hop)
	&& (entry->ifnum == ifnum
	    || (entry->flags & SSH_ENGINE_ARP_F_GLOBAL)))
      break;

  if (entry != NULL)
    {
      /* We have now found an arp cache entry for the desired IP address. */
      switch (entry->status)
        {
        case SSH_ENGINE_ARP_INCOMPLETE:

          SSH_DEBUG(6, (" ...request is for an incomplete entry."));

          /* Queue the packet in the entry. */

          /* Only one saved packet is kept per entry.  We keep the
             last packet; there is a reason for this, namely that the
             code in ssh_engine_arp_lookup assumes that the packet is
             not freed when returning SSH_ENGINE_ARP_IN_PROGRESS.  We
             must also watch out for the same packet already being
             queued. */
          if (entry->queued_packet != pc)
            old_pc = entry->queued_packet;

          SSH_ASSERT(pc != NULL && old_pc != pc);

          /* If we had an old queued packet, call arp_complete for it now 
	     unless the old_pc was the packet context for an IPsec flow
	     in which case we fail the current operation. */
          if (old_pc != NULL)
	    {
	      if (old_pc->flags & SSH_ENGINE_FLOW_D_IPSECINCOMING)
		{
		  SSH_DEBUG(SSH_D_FAIL, ("ARP lookup currently in progress "
					 "for IPsec flow related event, "
					 "aborting this operation"));
		  goto fail;
		}
	      else
		{
		  SSH_DEBUG(SSH_D_FAIL, ("Failing ARP lookup for pc=%p", 
					 old_pc));

		  /* Save the packet so that its processing will continue 
		     when the lookup is complete. */
                  SSH_ASSERT(pc->pp != NULL);
                  ssh_interceptor_packet_detach(pc->pp);
		  entry->queued_packet = pc;

		  ssh_kernel_mutex_unlock(engine->interface_lock);

		  ssh_engine_arp_complete(engine, old_pc, NULL, NULL);
		}
	    }
          /* Return immediately.  The callback will be called when the ARP
             request completes. */
          return;

        case SSH_ENGINE_ARP_FAILED:
          SSH_DEBUG(SSH_D_MIDOK,
                    (" ...request is for recently failed address."));
          /* An arp request for the address has recently failed.  Just
             indicate failure. */
          goto fail;

        case SSH_ENGINE_ARP_COMPLETE:
          SSH_DEBUG(SSH_D_MIDOK,
                    ("...request is for a completely mapped address %@",
                     ssh_engine_arp_render_eth_mac, entry->ethernet_addr));

	  if ((pc->flags & SSH_ENGINE_PC_REROUTE_FLOW))
	    {
	      SSH_DEBUG(SSH_D_MIDOK,
			("...request is for a completely mapped address %@ "
			 "but application requested fresh information.",
			 ssh_engine_arp_render_eth_mac, entry->ethernet_addr));

	      ssh_engine_arp_delete(engine, next_hop, ifnum);
	      goto refresh;
	    }
	  else
	    {
	      SSH_DEBUG(SSH_D_MIDOK,
			("...request is for a completely mapped address %@",
			 ssh_engine_arp_render_eth_mac, entry->ethernet_addr));

	      /* Move the entry to the beginning of the lru list. */
	      ssh_engine_arp_lru_bump(engine, entry, FALSE);

	      /* There is valid arp information for the address.  Copy the
		 hardware address, and return success.  Note that we must
		 copy the address to a local buffer to avoid race
		 conditions where the entry would be freed before
		 arp_complete does its job. */
	      memcpy(media_addr, entry->ethernet_addr, 6);
	      goto success;
	    }

        case SSH_ENGINE_ARP_PERMANENT:
          SSH_DEBUG(SSH_D_MIDOK,
                    ("...request for a permanently mapped address %@",
                     ssh_engine_arp_render_eth_mac, entry->ethernet_addr));

          memcpy(media_addr, entry->ethernet_addr, 6);
          goto success;

        default:
          /* engine lock still held. */
          ssh_fatal("ssh_engine_arp_map: bad status %d", entry->status);
        }
      SSH_NOTREACHED;
      goto fail;
    }

 refresh:
  /* Local broadcast address 255.255.255.255 */
  if (SSH_IP_IS_BROADCAST(next_hop) ||
      (SSH_IP_IS4(next_hop) && 
       ssh_ip_get_interface_by_broadcast(&engine->ifs, next_hop)))
    {
      memcpy(media_addr, ssh_engine_arp_ethernet_broadcast_addr, 6);
      goto success;
    }

  /* IP multicast addresses */
  if (SSH_IP_IS_MULTICAST(next_hop))
    {
      if (cache->token_ring_multicast)
        {
          /* Use token ring multicast addresses. */
          memcpy(media_addr, ssh_engine_arp_token_ring_multicast_addr, 6);
        }
      else if (SSH_IP_IS6(next_hop))
        {
          /* Normal rfc2464 multicast. */
          media_addr[0] = 0x33;
          media_addr[1] = 0x33;
          media_addr[2] = SSH_IP6_BYTE13(next_hop);
          media_addr[3] = SSH_IP6_BYTE14(next_hop);
          media_addr[4] = SSH_IP6_BYTE15(next_hop);
          media_addr[5] = SSH_IP6_BYTE16(next_hop);
        }
      else
        {
          /* Normal rfc1112 multicast. */
          media_addr[0] = 0x01;
          media_addr[1] = 0x00;
          media_addr[2] = 0x5e;
          media_addr[3] = SSH_IP4_BYTE2(next_hop) & 0x7f;
          media_addr[4] = SSH_IP4_BYTE3(next_hop);
          media_addr[5] = SSH_IP4_BYTE4(next_hop);
        }
      goto success;
    }

  /* Loopback addresses. */
  if (SSH_IP_IS_LOOPBACK(next_hop))
    goto fail;

  /* If no luck so far, allocate new entry and initiate first ARP request */
  SSH_DEBUG(SSH_D_MIDOK, ("cached entries or special cases not found."));

  /* Obtain our own IP address. */
  if ((ssh_engine_get_ipaddr(engine, ifnum,
                             SSH_IP_IS6(next_hop)
                             ? SSH_PROTOCOL_IP6 : SSH_PROTOCOL_IP4,
                             next_hop, &ownaddr) == FALSE) && 
      (ssh_engine_get_ipaddr(engine, ifnum,
                             SSH_IP_IS6(next_hop)
                             ? SSH_PROTOCOL_IP6 : SSH_PROTOCOL_IP4,
                             NULL, &ownaddr) == FALSE))
    {
      SSH_DEBUG(SSH_D_FAIL, ("Could not find local ip-address %@"
                             " (next-hop gw %@) of correct type",
                             ssh_ipaddr_render, &ownaddr,
                             ssh_ipaddr_render, next_hop));
      goto fail;
    }

  /* There was no entry for this address and it is not one of the
     special addresses (local broadcasts and local addresses are
     always stored in the arp cache).  Allocate one (or reuse the old
     one).  Note that this may flush an old entry out of the cache if
     there are too many.  Note that the engine lock is still being
     held. */
  if ((entry = ssh_engine_arp_cache_new_entry(engine)) == NULL)
    {
      SSH_DEBUG(SSH_D_ERROR,
		("Could not add ARP entry; memory allocation failure"));
      goto fail;
    }

  /* Initialize the arp cache entry. */
  memcpy(&entry->ip_addr, next_hop, sizeof(entry->ip_addr));
  entry->ifnum = ifnum;
  entry->status = SSH_ENGINE_ARP_INCOMPLETE;
  entry->arp_retry_count = 1;
  entry->expires = now + SSH_ENGINE_ARP_INCOMPLETE_LIFETIME;
  entry->flags = 0;
  memset(entry->ethernet_addr, 0, sizeof(entry->ethernet_addr));

  SSH_ASSERT(pc->pp != NULL);
  ssh_interceptor_packet_detach(pc->pp);
  entry->queued_packet = pc;
  entry->lru_next = NULL;
  entry->lru_prev = NULL;
  entry->on_retry_list = FALSE;
  entry->retry_list_next = NULL;

  /* Add the entry into the list in the hash table. */
  entry->next = cache->hash[hash];
  cache->hash[hash] = entry;

  SSH_DEBUG(SSH_D_MIDOK, ("ARP: add %@ (ifnum %d) bucket %d while mapping",
                          ssh_ipaddr_render, &entry->ip_addr, (int) ifnum,
			  (unsigned int) hash));

  /* Add the entry to the arp cache lru list. */
  ssh_engine_arp_lru_bump(engine, entry, TRUE);

  /* Send an arp request for the entry. */

  /* Put the entry on the retry list so that retries will get processed.
     Also schedule a retry timeout if one hasn't been scheduled yet. */
  entry->retry_list_next = cache->retry_list;
  cache->retry_list = entry;
  entry->on_retry_list = TRUE;

  SSH_DEBUG(SSH_D_MIDOK, (" ...SSH_ENGINE_ARP_IN_PROGRESS now."));

  /* Return an indication that the arp request is in progress, and the
     packet will be processed when the request is complete. */
  if (!cache->retry_timeout_scheduled)
    {
      cache->retry_timeout_scheduled = TRUE;

      /* Release engine lock before sending packets or registering a
         timeout. */
      ssh_kernel_mutex_unlock(engine->interface_lock);

      /* Send the request. */
#if defined(WITH_IPV6)
      if (SSH_IP_IS6(next_hop))
        ssh_engine_arp_send_solicitation(engine, next_hop, ifnum,
                                         &ownaddr, ownhw);
      else
#endif /* WITH_IPV6 */
        ssh_engine_arp_send_request(engine, next_hop, ifnum, &ownaddr, ownhw);
      /* Schedule a timeout. */
      ssh_kernel_timeout_register((long)0,
                                  (long)SSH_ENGINE_ARP_RESEND_TIMEOUT,
                                  ssh_engine_arp_request_timeout,
                                  (void *)engine);
    }
  else
    {
      ssh_kernel_mutex_unlock(engine->interface_lock);

#if defined(WITH_IPV6)
      if (SSH_IP_IS6(next_hop))
        ssh_engine_arp_send_solicitation(engine, next_hop, ifnum,
                                         &ownaddr, ownhw);
      else
#endif /* WITH_IPV6 */
        ssh_engine_arp_send_request(engine, next_hop, ifnum, &ownaddr, ownhw);
    }

  /* Call the completion function for any packets waiting for it. */
  ssh_engine_arp_call_pending_completions(engine);

  return;

 fail:
  /* The ARP lookup failed immediately. */
  ssh_kernel_mutex_unlock(engine->interface_lock);

  /* Call the completion function for any packets waiting for it. */
  ssh_engine_arp_call_pending_completions(engine);

  (*callback)(pc, NULL, NULL, 0);
  return;

 success:
  /* The ARP lookup succeeded immediately. */
  ssh_kernel_mutex_unlock(engine->interface_lock);

  /* Call the completion function for any packets waiting for it. */
  ssh_engine_arp_call_pending_completions(engine);

  if (SSH_IP_IS6(next_hop))
    ethertype = SSH_ETHERTYPE_IPv6;
  else
    ethertype = SSH_ETHERTYPE_IP;
  (*callback)(pc, ownhw, media_addr, ethertype);
  return;
}

/* This function is called from a timeout every
   SSH_ENGINE_ARP_LIFETIME_CHECK_INTERVAL seconds.  This goes through
   all arp cache entries, and purges any entries whose lifetime has
   expired.  This may be called concurrently with other functions;
   this will momentarily take the engine lock to protect data
   structures. */

void ssh_engine_arp_cache_timeout(void *context)
{
  SshEngine engine = (SshEngine)context;
  SshEngineArpCache cache = &engine->arp_cache;
  SshUInt32 i;
  SshEngineArpCacheEntry *entryp, entry;
  unsigned long num_arp = 0, num_reclaimed = 0;
  SshTime now;

  SSH_DEBUG(SSH_D_LOWSTART, ("ARP; cache timeout"));

  ssh_interceptor_get_time(&now, NULL);

  /* Take the engine lock to protect data structures. */
  ssh_kernel_mutex_lock(engine->interface_lock);
  SSH_DEBUG(SSH_D_MIDSTART, ("timing out arp entries (%d elements in table)",
                             (int) cache->num_entries));

  /* Loop over the entire hash table. */
  for (i = 0; i < SSH_ENGINE_ARP_HASH_SIZE; i++)
    {
      /* Loop over all entries in the hash table slot. */
      for (entryp = &cache->hash[i]; *entryp != NULL;)
        {
          num_arp++;
          entry = *entryp;

          /* Permanent entries never expire. */
          if (entry->status != SSH_ENGINE_ARP_PERMANENT)
            {
              /* The entry has expired if its lifetime is less than
                 the check interval. */
	      if (entry->expires < now)
                {
                  /* Free the entry now.  This will remove it from the
                     hash table, lru list, cancels arp resend
                     timeouts, and frees any queued packets.  This
                     also sets *entryp to point to the next packet. */
                  SSH_DEBUG(SSH_D_LOWOK,
                            ("  ...arp entry for %@ timed out, status %d",
                             ssh_ipaddr_render, &entry->ip_addr,
                             (int)entry->status));
                  ssh_engine_arp_free_entry(engine, entry);
                  num_reclaimed++;
                  continue; /* we've effectively already moved to next entry */
                }
            }
          /* Move to the next entry. */
          entryp = &(*entryp)->next;
        }
    }
  ssh_kernel_mutex_unlock(engine->interface_lock);

  /* Call the completion function for any packets waiting for it. */
  ssh_engine_arp_call_pending_completions(engine);

  SSH_DEBUG(SSH_D_MIDOK,
            ("entries left %ld, reclaimed %ld", num_arp, num_reclaimed));

#ifndef SSH_IPSEC_SMALL
  /* Schedule the timeout to occur again after the lifetime check
     interval. */
  ssh_kernel_timeout_register((long)SSH_ENGINE_ARP_LIFETIME_CHECK_INTERVAL, 0L,
                              ssh_engine_arp_cache_timeout, (void *)engine);
#endif /* SSH_IPSEC_SMALL */
}

/* Initializes the data structures needed for arp lookups and the arp
   cache.  This is not called concurrently for the same engine and
   media context. */

void ssh_engine_arp_init(SshEngine engine, SshUInt32 flags)
{
  /* Initialize the arp cache field to zero. */
  memset(&engine->arp_cache, 0, sizeof(engine->arp_cache));




  engine->arp_cache.token_ring_multicast =
    (flags & SSH_ENGINE_ARP_RFC1469_MCAST) != 0;

#ifdef SSH_IPSEC_PREALLOCATE_TABLES
  { /* Initialize arp entry freelist. */
    SshUInt32 i;
    ssh_engine_arp_entry_freelist = NULL;
    for (i = 0; i < SSH_ENGINE_ARP_CACHE_SIZE; i++)
      {
        ssh_engine_arp_entry_table[i].status = 0x7a; /* free magic */
        ssh_engine_arp_entry_table[i].next = ssh_engine_arp_entry_freelist;
        ssh_engine_arp_entry_freelist = &ssh_engine_arp_entry_table[i];
      }
  }
#endif /* SSH_IPSEC_PREALLOCATE_TABLES */

#ifndef SSH_IPSEC_SMALL
  /* Call the arp cache timeout once to start scheduling the timeouts. */
  ssh_engine_arp_cache_timeout((void *)engine);
#endif /* SSH_IPSEC_SMALL */
}

/* Clears the ARP cache.  All entries are dropped from the cache, and
   all pending ARP requests are gracefully completed (by calling their
   callbacks with failure indication). This will momentarily take
   engine->interface_lock to modify the cache data structures. */

void ssh_engine_arp_clear(SshEngine engine)
{
  SshUInt32 i;

  /* Loop over the arp cache hash table. */
  ssh_kernel_mutex_lock(engine->interface_lock);
  for (i = 0; i < SSH_ENGINE_ARP_HASH_SIZE; i++)
    {
      /* Free all entries in the hash slot.  Freeing the entry will
         also remove it from the hash table. */
      while (engine->arp_cache.hash[i])
        ssh_engine_arp_free_entry(engine, engine->arp_cache.hash[i]);
    }
  ssh_kernel_mutex_unlock(engine->interface_lock);

  /* Call the completion function for any packets waiting for it. */
  ssh_engine_arp_call_pending_completions(engine);
}

/* Uninitializes (frees) the data structures allocated for the arp
   cache.  This is not called concurrently for the same engine and
   media context. */

void ssh_engine_arp_uninit(SshEngine engine)
{
  /* Clear the ARP cache and abort any pending ARP requests. */
  ssh_engine_arp_clear(engine);

  /* Cancel the arp cache timeout. */
  /* Note this call will also cancel the timeout for
     process_asynch_packets().
     If SEND_IS_SYNC then packets generated during
     ssh_engine_arp_clear() will never be sent out. */
  ssh_kernel_timeout_cancel(SSH_KERNEL_ALL_CALLBACKS, (void *)engine);
}

/* Removes any mapping for the given ip address, even if permanent.
   This function is called with the engine lock held. This must not
   release it even momentarily. */

void ssh_engine_arp_delete(SshEngine engine,
			   SshIpAddr ip_addr, SshEngineIfnum ifnum)
{
  SshEngineArpCache cache = &engine->arp_cache;
  SshUInt32 hash;
  SshEngineArpCacheEntry entry;

  SSH_DEBUG(SSH_D_HIGHSTART,
            ("arp delete %@", ssh_ipaddr_render, ip_addr));

  ssh_kernel_mutex_assert_is_locked(engine->interface_lock);

  /* Compute a hash value from the ip address. */
  hash = SSH_IP_HASH(ip_addr);
  hash %= SSH_ENGINE_ARP_HASH_SIZE;

  /* Check if the slot contains the address we are looking for. */
  for (entry = cache->hash[hash]; entry; entry = entry->next)
    if (SSH_IP_EQUAL(&entry->ip_addr, ip_addr) && entry->ifnum == ifnum)
      break;

  /* If an entry matching the address was found, remove it now. */
  if (entry)
    ssh_engine_arp_free_entry(engine, entry);
  /* We should really call ssh_engine_arp_call_pending_completions here,
     but cannot since the API for this function specifies that this is
     called with the lock held.  However, not doing it here should not
     be a problem in real life; the completions will be called next time
     an entry is freed. */
}

/* Adds a permanent mapping for the given address in the arp cache
   as a permanent entry.  This function is called with the engine lock
   held; this must not release it even momentarily. */

Boolean ssh_engine_arp_add(SshEngine engine,
			   SshIpAddr ip_addr, SshEngineIfnum ifnum,
                           const unsigned char *hw_addr, Boolean permanent,
                           Boolean proxy_arp,
			   Boolean is_global)
{
  SshEngineArpCache cache = &engine->arp_cache;
  SshUInt32 hash;
  SshEngineArpCacheEntry entry;
  SshTime now;

  ssh_interceptor_get_time(&now, NULL);

  SSH_DEBUG(SSH_D_HIGHSTART,
            ("add %sip %@ media %@",
             permanent ? "permanent " : "",
             ssh_ipaddr_render, ip_addr,
             ssh_engine_arp_render_eth_mac, hw_addr));

  ssh_kernel_mutex_assert_is_locked(engine->interface_lock);

  /* Remove any old entry for the same IP that might be in the cache.
     This could potentially happen with dynamic IP addresses. */
  ssh_engine_arp_delete(engine, ip_addr, ifnum);

  /* Compute a hash value from the ip address. */
  hash = SSH_IP_HASH(ip_addr);
  hash %= SSH_ENGINE_ARP_HASH_SIZE;

#ifdef DEBUG_LIGHT
  /* The entry should not be in the cache since we just deleted it. */
  for (entry = cache->hash[hash]; entry; entry = entry->next)
    if (SSH_IP_EQUAL(&entry->ip_addr, ip_addr) && entry->ifnum == ifnum)
      break;
  SSH_ASSERT(entry == NULL);
#endif /* DEBUG_LIGHT */

  /* There was no entry for this address in the arp cache.  Allocate one.
     Note that this may flush an old entry out of the cache if there are
     too many.  Note that this call may put something on
     cache->packets_waiting_completion, and
     ssh_engine_arp_call_pending_completions should be called after the lock
     is released.  We don't specify that in our external interface, but
     that should not cause problems in real life. */
  entry = ssh_engine_arp_cache_new_entry(engine);
  if (entry == NULL)
    {
      SSH_DEBUG(SSH_D_ERROR,
                ("Could not add ARP entry due to memory allocation failure"));
      return FALSE;
    }

  /* Initialize the arp cache entry. */
  memcpy(&entry->ip_addr, ip_addr, sizeof(entry->ip_addr));
  entry->ifnum = ifnum;
  entry->status =
    permanent ? SSH_ENGINE_ARP_PERMANENT : SSH_ENGINE_ARP_COMPLETE;
  entry->arp_retry_count = 0;
  entry->expires = now + SSH_ENGINE_ARP_COMPLETE_LIFETIME;

  entry->flags = 0;
  if (proxy_arp)
    entry->flags |= SSH_ENGINE_ARP_F_PROXY;
  if (is_global)
    entry->flags |= SSH_ENGINE_ARP_F_GLOBAL;

  memcpy(entry->ethernet_addr, hw_addr, sizeof(entry->ethernet_addr));
  entry->queued_packet = NULL;
  entry->lru_next = NULL;
  entry->lru_prev = NULL;
  entry->on_retry_list = 0;
  entry->retry_list_next = NULL;

  /* Add the entry into the list in the hash table. */
  entry->next = cache->hash[hash];
  cache->hash[hash] = entry;

  SSH_DEBUG(SSH_D_HIGHSTART, ("arp added %@ media %@ bucket %d entry %p",
                              ssh_ipaddr_render, ip_addr,
                              ssh_engine_arp_render_eth_mac,
                              entry->ethernet_addr,
			      (unsigned int) hash,
                              entry));

  /* Note: the entry is NOT put on the arp cache lru list, if it is a
     permanent entry.  Permanent entries are however counted in
     num_entries.  (This makes the code more robust; on systems with a
     high number of IP aliases (e.g. web servers), there could be more
     local IP addresses than is the nominal size of the ARP cache.) */





  /* Add the entry to the arp cache lru list if not permanent. */
  if (!permanent)
    ssh_engine_arp_lru_bump(engine, entry, TRUE);

  return TRUE;
}

/* Processes the interface structure, and adds (`add' is TRUE) or
   removes (`add' is FALSE) all the appropriate network addresses in
   the arp cache.  This function is called with the engine lock held;
   this must not release the lock even momentarily. */

void ssh_engine_arp_process_interface(SshEngine engine,
                                      SshInterceptorInterface *ifp,
                                      Boolean add)
{
  SshEngineArpCache cache = &engine->arp_cache;
  SshEngineArpCacheEntry entry, next;
  SshUInt32 i;

  ssh_kernel_mutex_assert_is_locked(engine->interface_lock);

  /* If the adapter does not have an ethernet-like media type in either
     direction, then do nothing. */
  if (ifp->to_adapter.media != SSH_INTERCEPTOR_MEDIA_ETHERNET &&
      ifp->to_adapter.media != SSH_INTERCEPTOR_MEDIA_FDDI &&
      ifp->to_adapter.media != SSH_INTERCEPTOR_MEDIA_TOKENRING &&
      ifp->to_protocol.media != SSH_INTERCEPTOR_MEDIA_ETHERNET &&
      ifp->to_protocol.media != SSH_INTERCEPTOR_MEDIA_FDDI &&
      ifp->to_protocol.media != SSH_INTERCEPTOR_MEDIA_TOKENRING)
    return;

  /* Process all ip addresses for the interface.  Add or remove each address
     mapping. */
  if (add)
    {
      for (i = 0; i < ifp->num_addrs; i++)
	{
	  if (ifp->addrs[i].protocol != SSH_PROTOCOL_IP4 &&
	      ifp->addrs[i].protocol != SSH_PROTOCOL_IP6)
	    continue;
	  
	  /* Add this mapping in the arp cache as a permanent entry. */
	  (void) ssh_engine_arp_add(engine, &ifp->addrs[i].addr.ip.ip,
				    ifp->ifnum,
				    ifp->media_addr, TRUE, FALSE, FALSE);
	  
	  if (ifp->addrs[i].protocol == SSH_PROTOCOL_IP4)
	    (void) ssh_engine_arp_add(engine, &ifp->addrs[i].addr.ip.broadcast,
				      ifp->ifnum,
				      ssh_engine_arp_ethernet_broadcast_addr,
				      TRUE, FALSE, FALSE);
	}
    }
  else 
    {
      /* We are removing a interface. We flush all the entries related to
	 the specific interface. */
      SSH_DEBUG(SSH_D_HIGHSTART,
		("Deleting all arp entries for ifnum %d", ifp->ifnum));
      
      for (i = 0; i < SSH_ENGINE_ARP_HASH_SIZE; i++)
	{
	  /* Check if the slot contains the address we are looking for. */
	  entry = cache->hash[i];
	  while (entry)
	    {
	      next = entry->next;

	      /* Do we have a match on the interface number? */
	      if (entry->ifnum == ifp->ifnum)
		{
		  SSH_DEBUG(SSH_D_HIGHOK, ("Deleting arp entry %p for "
					   "interface %d", entry, ifp->ifnum));
		  ssh_engine_arp_free_entry(engine, entry);
		}

	      entry = next;
	    }
	}
    }
}

/* A function of this type is called to inform the media-specific code
   about network interfaces of that type that are available.  For
   ethernet and ieee 802 networks, this registers the interface
   addresses in the arp cache as permanent entries.  Entries for the
   old interface structure will first be removed from the cache to
   handle updates correctly.  Either interface can be NULL.  This
   function is called with the engine lock held; this must not release
   it even momentarily. */

void ssh_engine_arp_update_interface(SshEngine engine,
                                     SshEngineIfnum ifnum,
                                     SshInterceptorInterface *oldif,
                                     SshInterceptorInterface *newif)
{
  ssh_kernel_mutex_assert_is_locked(engine->interface_lock);

  /* Remove any addresses related to the old interface from the cache. */
  if (oldif != NULL)
    ssh_engine_arp_process_interface(engine, oldif, FALSE);

  /* Add any addresses related to the new interface to the cache. */
  if (newif != NULL)
    ssh_engine_arp_process_interface(engine, newif, TRUE);
}


#ifdef SSH_ENGINE_MEDIA_ETHER_NO_ARP_RESPONSES

/* Six zeroes (null ethernet address). */
const unsigned char ssh_engine_ethernet_null_addr[6] = {
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

/* Updates existing arp cache entry same way ssh_engine_arp_input would. */

void ssh_engine_arp_add_kludge(SshEngine engine,
			       SshIpAddr ip_addr,
			       SshEngineIfnum ifnum,
                               const unsigned char *hw_addr)
{
  SshEngineArpCache cache = &engine->arp_cache;
  SshUInt32 hash;
  SshEngineArpCacheEntry entry, *entryp;
  SshEnginePacketContext queued_pc;
  SshTime now;

  ssh_interceptor_get_time(&now, NULL);
  SSH_DEBUG(SSH_D_MIDSTART,
            ("arp update ip %@ mac %@",
             ssh_ipaddr_render, ip_addr,
             ssh_engine_arp_render_eth_mac, hw_addr));

  /* Ignore null ethernet addresses (all zeroes). */
  if (memcmp(hw_addr, ssh_engine_ethernet_null_addr, 6) == 0)
    {
      SSH_DEBUG(SSH_D_LOWOK, ("rejecting null ethernet address"));
      return;
    }

  /* Don't accept multicast or broadcast addresses. */
  if (SSH_ETHER_IS_MULTICAST(hw_addr))
    {
      SSH_DEBUG(SSH_D_ERROR, ("rejecting multicast address"));
      return;
    }

  /* Compute a hash value from the ip address. */
  hash = SSH_IP_HASH(ip_addr);
  hash %= SSH_ENGINE_ARP_HASH_SIZE;

  ssh_kernel_mutex_lock(engine->interface_lock);

  /* Search the cache for the correct entry. */
  for (entry = cache->hash[hash]; entry; entry = entry->next)
    if (SSH_IP_EQUAL(&entry->ip_addr, ip_addr) && entry->ifnum == ifnum)
      {
        if (entry->status == SSH_ENGINE_ARP_COMPLETE ||
            entry->status == SSH_ENGINE_ARP_PERMANENT)
          break;

        /* Mark that we now have complete information for the entry. */
        entry->status = SSH_ENGINE_ARP_COMPLETE;
        entry->expires = now + SSH_ENGINE_ARP_COMPLETE_LIFETIME;

        /* Remove the packet from the retry list. */
        if (entry->on_retry_list)
          {
            for (entryp = &cache->retry_list; *entryp;
                 entryp = &(*entryp)->retry_list_next)
              if (*entryp == entry)
                break;
            SSH_ASSERT(*entryp == entry);
            *entryp = entry->retry_list_next;
            entry->on_retry_list = FALSE;
            entry->retry_list_next = NULL;
          }

        /* Update entrys address and move it to head of lru list. */
        memcpy(entry->ethernet_addr, hw_addr, 6);
        ssh_engine_arp_lru_bump(engine, entry, FALSE);

        /* Continue processing of the queued packet (if any). */
        queued_pc = entry->queued_packet;
        entry->queued_packet = NULL;
        ssh_kernel_mutex_unlock(engine->interface_lock);

        if (queued_pc != NULL)
          ssh_engine_arp_complete(engine, queued_pc, ip_addr, hw_addr);

        return;
      }

  /* Entry was not found. Release engine lock and return. */
  ssh_kernel_mutex_unlock(engine->interface_lock);
  return;
}

#endif /* SSH_ENGINE_MEDIA_ETHER_NO_ARP_RESPONSES */

#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */
