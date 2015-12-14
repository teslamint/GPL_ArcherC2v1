/** ARP (Address Resolution Protocol) functionality. 

<keywords ARP (Address Resolution Protocol), Address Resolution Protocol (ARP)>

File: engine_arp.h

@copyright
Copyright (c) 2002 - 2006 SFNT Finland Oy, all rights reserved. 

Definitions for ARP (Address Resolution Protocol).  This code is 
common to interfaces using ethernet (RFC 894) and IEEE 802 (RFC 1042 
and RFC 1469) encapsulation for media headers.  Services provided by 
this file are used by both the ethernet and IEEE 802 (FDDI, Token 
Ring) code.

Note: This file should not be included directly.  Instead, the 
engine_internal.h header file should be included, which will include 
this file.

*/

#ifndef ENGINE_ARP_H
#define ENGINE_ARP_H

#ifndef SSH_IPSEC_IP_ONLY_INTERCEPTOR

/* ************ ARP functions for use by media-specific code ***********/

/* Flag masks for ssh_engine_arp_init. */

#define SSH_ENGINE_ARP_RFC1469_MCAST 0x01 /** RFC 1469 mcast (Token Ring). */

/** Size of the ARP cache hash table.  This value should be a small
    prime of approximately the same order of magnitude as the maximum
    expected number of entries in the ARP cache.  It does not matter if
    the number of ARP cache entries goes above this, but performance
    will suffer (slightly) if this value is exceeded by substantially
    more than a factor of five. */
#define SSH_ENGINE_ARP_HASH_SIZE 101

/** The number of times to retry sending an ARP request before giving up. */
#define SSH_ENGINE_MAX_ARP_RETRIES 5

/** Time after which we resend the ARP request if we haven't received a
    reply, expressed in microseconds. */
#define SSH_ENGINE_ARP_RESEND_TIMEOUT  1000000 

/** The time (in seconds) that an incomplete or failed cache entry 
    will stay in the cache before being reclaimed. */
#define SSH_ENGINE_ARP_INCOMPLETE_LIFETIME 30 

/** The time (in seconds) after which a complete ARP cache entry will 
    be reclaimed from the cache.  Note that the lifetime is fixed; the 
    entry will be reclaimed after this time even if it is 
    continuously being used. This is to ensure that we will 
    eventually notice if a router has gone down, even if there is 
    outgoing traffic to it all the time. */
#define SSH_ENGINE_ARP_COMPLETE_LIFETIME 600  

/** ARP cache timeouts are checked every this many seconds. */
#define SSH_ENGINE_ARP_LIFETIME_CHECK_INTERVAL 10 

typedef enum
{
  SSH_ENGINE_ARP_INCOMPLETE,    /** ARP in progress. */
  SSH_ENGINE_ARP_FAILED,        /** No reply to ARP request. */
  SSH_ENGINE_ARP_COMPLETE,      /** Valid cache entry. */
  SSH_ENGINE_ARP_PERMANENT      /** Permanent valid cache entry. */
} SshEngineArpCacheEntryStatus;

/*  Flags for ARP cache entry. */
#define SSH_ENGINE_ARP_F_PROXY  0x01    /** Do proxy ARP for the IP address. */
#define SSH_ENGINE_ARP_ON_LRU_LIST 0x02 /** Entry is on LRU list. */
#define SSH_ENGINE_ARP_F_GLOBAL 0x04    /** Global entry. */

/** Data structure for an ARP cache entry.  All fields of this data structure
    are protected by the Engine lock, unless otherwise mentioned. */
typedef struct SshEngineArpCacheEntryRec
{
  /** The IP address of the ARP cache entry. */
  SshIpAddrStruct ip_addr;

  /** Scope of IP address in ARP lookups. */
  SshEngineIfnum ifnum;

  /** Status (SshEngineArpCacheEntryStatus) of the ARP cache entry. 
      If the entry is on the freelist, this is set to the magic value 
      0x7a. */
  SshUInt8 status; 

  /** A Boolean flag indicating that this packet is on the retry list. */
  SshUInt8 on_retry_list; 

  /** The number of times we have tried to send an ARP request 
      for this entry. */
  SshUInt8 arp_retry_count;

  /** Flags for the entry. */
  SshUInt8 flags;

  /** The ethernet address corresponding to the IP address.  This is
      only valid if `status' is SSH_ENGINE_ARP_COMPLETE or
      SSH_ENGINE_ARP_PERMANENT. */
  unsigned char ethernet_addr[6];

  /** Expire time for this ARP entry; the entry will be removed if not
      refreshed before this. */
  SshTime expires;

  /** The packet context for the packet that caused the ARP lookup.
      Only the first such packet is saved; any remaining packets sent
      while the lookup is in progress will be freed. */
  SshEnginePacketContext queued_packet;

  /** Pointer to the next entry in the slot of the ARP cache hash table.
      If the entry is on the freelist, this points to the next entry on the
      freelist. */
  struct SshEngineArpCacheEntryRec *next;

  /** Pointer to the next entry on the list of entries for which ARP
      retries are still being sent. */
  struct SshEngineArpCacheEntryRec *retry_list_next;

  /** Pointers to next and previous entries in the LRU list of ARP
      cache entries. */
  struct SshEngineArpCacheEntryRec *lru_next;
  struct SshEngineArpCacheEntryRec *lru_prev;
} *SshEngineArpCacheEntry, SshEngineArpCacheEntryStruct;

/** Data structure for the ARP cache.  Warning: the IPsec Engine makes
    an implicit assumption that all timeouts registered by the ARP code
    have a context argument pointing to the media context (i.e., this
    ARP cache structure for ethernet and ieee802).  The assumption is
    in ssh_engine_stop. */
typedef struct SshEngineArpCacheRec
{
  /** The hash table containing the ARP cache entries.  Each slot
      contains a list of entries, linked by their `next' field.  Access
      to this field and data structures pointed to by it must be
      protected by the engine->flow_table_lock. */
  SshEngineArpCacheEntry hash[SSH_ENGINE_ARP_HASH_SIZE];

  /** The total number of entries in the arp cache. This value is used in
      protecting against denial-of-service attacks that try to fill the
      ARP cache.  Access to this field must be protected using the
      engine->flow_table_lock. */
  SshUInt32 num_entries;

  /** Doubly linked list of ARP cache entries.  This is used to remove
      old entries from the list if the ARP cache becomes too full
      (e.g., as a result of a denial-of-service attack).  Access to
      this list must be protected using the engine->flow_table_lock. */
  SshEngineArpCacheEntry lru_head;
  SshEngineArpCacheEntry lru_tail;

  /** List of entries for which retries are being sent.  Access to this
      field must be protected using the engine->flow_table_lock. */
  SshEngineArpCacheEntry retry_list;

  /** Flag indicating that a retry timeout has been scheduled.  Access
      to this field must be protected using the engine->flow_table_lock. */
  Boolean retry_timeout_scheduled;

  /** Use token ring (RFC 1469) multicast Ethernet addresses when this
      is TRUE.  This field is initialized when the ARP cache is
      created, and is not changed after that. */
  Boolean token_ring_multicast;

  /** List of packets waiting for their completion function to be called to
      indicate failure.  This list is used in ssh_engine_arp_free_entry
      (which is called with engine->flow_table_lock held) to move calling
      ssh_engine_arp_complete to a location where the lock is no longer
      held. */
  SshEnginePacketContext packets_waiting_completion;
} SshEngineArpCacheStruct, *SshEngineArpCache;

typedef enum {
  /** The address was successfully mapped. */
  SSH_ENGINE_ARP_OK,

  /** Mapping could not be completed; an ARP lookup for the address is
      in progress.  The packet was queued and will be sent or freed
      later. */
  SSH_ENGINE_ARP_IN_PROGRESS,

  /** An ARP request for the address has recently timed out. */
  SSH_ENGINE_ARP_FAILURE
} SshEngineArpLookupError;

/** Initializes the data structures needed for ARP lookups and the ARP
    cache.  Possible flag bit masks were defined above.  This function
    will not be called concurrently for the same Engine. */
void ssh_engine_arp_init(SshEngine engine, SshUInt32 flags);

/** Uninitializes (frees) the data structures allocated for the ARP
    cache.  This will free any queued packets.  This function will not
    be called concurrently for the same Engine, and no other threads
    will be executing in IPsec Engine code when this is called, except
    possibly for timeouts. */
void ssh_engine_arp_uninit(SshEngine engine);

/** Clears the ARP cache.  All entries are dropped from the cache, and
    all pending ARP requests are gracefully completed (by calling their
    callbacks with failure indication).  This will momentarily take
    engine->flow_table_lock to modify the cache data structures. */
void ssh_engine_arp_clear(SshEngine engine);

/** Processes an incoming ARP packet.  This function will update the
    ARP table as appropriate, and will cause the SshEngineArpComplete
    callback to be called for any pending requests completed by this
    packet.  The packet in `pp' should not contain media header, but
    the media header should be saved in pc->mediahdr.  
    
    This function can be called concurrently.  This will momentarily lock
    engine->flow_table_lock to modify the cache data structures. 
    
    @return
    Normally, this will not free `pp' and returns TRUE, because the 
    packet will normally also be passed to the host TCP/IP stack.  If 
    an error causes the packet to be freed, this returns FALSE.
    
    */
Boolean ssh_engine_arp_input(SshEngine engine, SshInterceptorPacket pp);

#if defined(WITH_IPV6)
/** Processes an incoming IPv6 neighbor advertisement packet.  This
    function will update the ARP table as appropriate, and will cause
    the SshEngineArpComplete callback to be called for any pending
    requests completed by this packet.  The packet in `pp' should not
    contain media header, but the media header should be saved in
    pc->mediahdr.  
    
    This function can be called concurrently.  This will momentarily lock
    engine->flow_table_lock to modify the cache data structures. 
    
    @return
    Normally, this will not free `pp' and returns TRUE,
    because the packet will normally also be passed to the host TCP/IP
    stack.  If an error causes the packet to be freed, this returns
    FALSE.

    */
Boolean ssh_engine_arp_neighbor_advertisement(SshEngine engine,
                                              SshInterceptorPacket pp);

/** Processes an IPv6 neighbor solicitation packet. This
    function will update the ARP table as appropriate, and reply to
    the solicitation if it is an neighbor discovery. The packet
    in `pp' should not contain media header, but the media header
    should be saved in pd->mediahdr.  
    
    This function can be called concurrently.  This will momentarily 
    lock the engine lock to modify the cache data structures. 
    
    @return
    Normally, this will not free `pp' and returns TRUE, because the 
    packet will normally also be passed to the host TCP/IP stack.  If 
    an error causes the packet to be freed, this returns FALSE.

    */
Boolean ssh_engine_arp_neighbor_solicitation(SshEngine engine,
					     SshInterceptorPacket pp);
#endif /** WITH_IPV6 */

/** A function of this type will perform the encapsulation into a media
    header and sending the packet out after a successful ARP lookup.
    This will eventually free `pc' (and pc->pp).  The `src' and `dst'
    values will only be valid for the duration of this call, and must
    be copied if they are needed later.  
    
    This function may be called with engine->flow_table_lock held, and 
    this must not release it even momentarily.  This may not perform 
    any actions which could require taking the lock again.  This also 
    implies that this function cannot cancel any timeouts.  If the ARP 
    lookup fails, then this will be called with `src' and `dst' NULL. 
    `pc' and pc->pp will still be valid if that happens.  It is 
    guaranteed that this will be called once for every call to 
    ssh_engine_arp_lookup. */

typedef void (*SshEngineArpComplete)(SshEnginePacketContext pc,
                                     const unsigned char *src,
                                     const unsigned char *dst,
                                     SshUInt16 ethertype);

/** Looks up the physical Ethernet addresses for the IP packet in `pp'.
    The addresses may come from a number of sources: cached addresses from
    de-encapsulating the packet, addresses in the ARP cache, or addresses
    obtained using an ARP lookup that is obtained by this call.

    This looks for the address `next_hop' attached to interface `ifnum'.
    All ARP requests (or IPv6 neighbor solicitations) will be sent to the
    interface `ifnum'.

    This will call the `callback' function when done (see the declaration of
    the prototype above for how errors are handled).  It is guaranteed that
    the function will be called exactly once for each request.  The callback
    may get called during this function or at a later time.

    This function may be called concurrently; this will momentarily take
    engine->flow_table_lock to protect data structures. */
void ssh_engine_arp_lookup(SshEnginePacketContext pc,
                           SshIpAddr next_hop,
                           SshEngineIfnum ifnum,
                           SshEngineArpComplete callback);

/** Adds a mapping for the given address and ifnum in the ARP cache as 
    a permanent entry.  This function is called with
    engine->flow_table_lock held; this may not release it even
    momentarily.  
    
    If `permanent' is TRUE, the entry will be permanent
    (never expired from the cache).  If `proxy_arp' is TRUE, then
    engine will do proxy ARP for the IP with the hardware address
    `hw_addr'.  
    
    @return
    The function returns TRUE if the ARP cache entry was
    added and FALSE on error. If 'is_global' is TRUE, then
    the 'ip_addr':'hw_addr' mapping will be effective for
    all interfaces, and not just 'ifnum'. */
Boolean ssh_engine_arp_add(SshEngine engine,
                           SshIpAddr ip_addr,
			   SshEngineIfnum ifnum,
                           const unsigned char *hw_addr,
                           Boolean permanent,
                           Boolean proxy_arp,
			   Boolean is_global);

/** Removes any mapping for the given IP address and ifnum, even if permanent.
    This function is called with engine->flow_table_lock held; this may
    not release it even momentarily. The 'ip_address'/'ifnum' must match
    those used in ssh_engine_arp_add(), even if is_global was TRUE. */
void ssh_engine_arp_delete(SshEngine engine,
                           SshIpAddr ip_addr, SshEngineIfnum ifnum);

/** A function of this type is called to inform the media-specific code
    about network interfaces of that type that are available.  For
    Ethernet and ieee 802 networks, this registers the interface
    addresses in the ARP cache as permanent entries.  Entries for the
    old interface structure will first be removed from the cache to
    handle updates correctly.  This function is called with
    engine->flow_table_lock held; this must not release it even momentarily. */
void ssh_engine_arp_update_interface(SshEngine engine,
                                     SshEngineIfnum ifnum,
                                     SshInterceptorInterface *oldif,
                                     SshInterceptorInterface *newif);

#ifdef SSH_ENGINE_MEDIA_ETHER_NO_ARP_RESPONSES
/** Updates an existing ARP cache entry the same way as 
ssh_engine_arp_input would. */
void ssh_engine_arp_add_kludge(SshEngine engine,
			       SshIpAddr ip_addr,
			       SshEngineIfnum ifnum,
			       const unsigned char *hw_addr);
#endif /* SSH_ENGINE_MEDIA_ETHER_NO_ARP_RESPONSES */

#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */

#endif /* ENGINE_ARP_H */
