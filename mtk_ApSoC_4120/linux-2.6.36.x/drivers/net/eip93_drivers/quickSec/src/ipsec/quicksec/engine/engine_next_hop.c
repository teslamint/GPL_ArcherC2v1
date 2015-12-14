/*
 *
 * engine_next_hop.c
 *
 * Copyright:
 *       Copyright (c) 2002-2005 SFNT Finland Oy.
 *       All rights reserved.
 *
 * Next hop manipulation functions for the engine.
 *
 */

#include "sshincludes.h"
#include "engine_internal.h"

#define SSH_DEBUG_MODULE "SshEngineNextHop"

#ifndef SSH_IPSEC_IP_ONLY_INTERCEPTOR

/* Mask of next-hop flags that is used for comparing flags in next-hop lookup. 
 */
#define ENGINE_NH_NODE_FLAG_MASK                                          \
  (SSH_ENGINE_NH_LOCAL | SSH_ENGINE_NH_INBOUND | SSH_ENGINE_NH_OUTBOUND | \
   SSH_ENGINE_NH_TRANSFORM_APPLIED)

/* Lookup a next-hop node for the next-hop gateway `next_hop_gw' with
   flags `nh_node_flags'. If there is no matching next-hop node, the 
   function will allocate a new one with the attributes `ifnum', 
   `mediatype', and `mtu'.  The function returns the next-hop node and
   its index in `index_return' or NULL and SSH_IPSEC_INVALID_INDEX in
   `index_return' if the allocation or lookup operation fails.  If the 
   operation is successful, the function adds a reference to the returned 
   next-hop node.  The function must be called holding `flow_table_lock'. */
SshEngineNextHopControl 
ssh_engine_lookup_nh_node(SshEngine engine,
			  SshIpAddr src_ip,
			  SshIpAddr next_hop_gw,
			  SshUInt32 nh_node_flags,
			  SshEngineIfnum ifnum,
			  SshInterceptorMedia mediatype,
			  size_t mtu,
			  SshUInt32 *index_return)
{
  SshUInt32 i, hashvalue;
  SshEngineNextHopData d_nh = NULL;
  SshEngineNextHopControl c_nh = NULL;

  SSH_INTERCEPTOR_STACK_MARK();

  ssh_kernel_mutex_assert_is_locked(engine->flow_control_table_lock);

  *index_return = SSH_IPSEC_INVALID_INDEX;

  /* Check if we have an existing entry for this node in the next hop table. */
  hashvalue = SSH_IP_HASH(next_hop_gw);
  hashvalue %= engine->next_hop_hash_size;
  i = engine->next_hop_hash[hashvalue];
  while (i != SSH_IPSEC_INVALID_INDEX)
    {
      c_nh = SSH_ENGINE_GET_NH(engine, i);
      d_nh = FASTPATH_GET_NH(engine->fastpath, i);
      SSH_ASSERT(c_nh != NULL);
      SSH_ASSERT(d_nh != NULL);
      SSH_ASSERT(d_nh->flags != 0);

      if (SSH_IP_EQUAL(&d_nh->dst, next_hop_gw)
          && (src_ip == NULL || SSH_IP_EQUAL(&d_nh->src, src_ip))
          && (d_nh->flags & ENGINE_NH_NODE_FLAG_MASK) == nh_node_flags
          && ifnum == d_nh->ifnum)
        {
          /* Found an entry */
          SSH_DEBUG(SSH_D_LOWOK, ("found next hop node %d", (int) i));
          if (d_nh->flags & SSH_ENGINE_NH_EMBRYONIC)
            {








              SSH_DEBUG(SSH_D_FAIL, ("nh %d already being initialized",
                                     (int)i));
	      FASTPATH_RELEASE_NH(engine->fastpath, i);
              return NULL;
            }
	  FASTPATH_RELEASE_NH(engine->fastpath, i);
          break;
        }
      FASTPATH_RELEASE_NH(engine->fastpath, i);
      i = c_nh->next;
    }

  if (i == SSH_IPSEC_INVALID_INDEX)
    { 
      /* Allocate a new node from the freelist. */
      i = engine->next_hop_hash_freelist;
      if (i == SSH_IPSEC_INVALID_INDEX)
        {
#ifdef SSH_IPSEC_STATISTICS
	  engine->stats.out_of_nexthops++;
#endif /* SSH_IPSEC_STATISTICS */

          SSH_DEBUG(SSH_D_ERROR, ("out of next hop gateway nodes"));
          return NULL;
        }
      SSH_DEBUG(SSH_D_LOWOK, ("creating next hop node %d", (int) i));

      c_nh = SSH_ENGINE_GET_NH(engine, i);
      SSH_ASSERT(c_nh != NULL);
      SSH_ASSERT(c_nh->refcnt == 0);
      engine->next_hop_hash_freelist = c_nh->next;

      d_nh = FASTPATH_INIT_NH(engine->fastpath, i);
      d_nh->flags = SSH_ENGINE_NH_EMBRYONIC;
      d_nh->flags |= nh_node_flags;
      d_nh->dst = *next_hop_gw;

      if (src_ip != NULL)
        d_nh->src = *src_ip;
      else
        SSH_IP_UNDEFINE(&d_nh->src);

      c_nh->next = engine->next_hop_hash[hashvalue];
      engine->next_hop_hash[hashvalue] = i;
      c_nh->refcnt = 0;
      d_nh->ifnum = ifnum;
      d_nh->mediatype = mediatype;
      d_nh->mtu = mtu;
#ifdef SSH_IPSEC_STATISTICS
      engine->stats.active_nexthops++;
      engine->stats.total_nexthops++;
#endif /* SSH_IPSEC_STATISTICS */

      FASTPATH_COMMIT_NH(engine->fastpath, i, d_nh);
    }
  /* Return node's index. */
  *index_return = i;

  /* Add a reference. */
  c_nh->refcnt++;

  return c_nh;
}

/* Update next-hop nodes MAC for the destination IP.  If there is no 
   matching next-hop node, nothing is done. The function must be called 
   holding `flow_table_lock'. */
void ssh_engine_update_nh_node_mac(SshEngine engine,
                                   SshIpAddr next_hop_gw,
                                   const SshEngineIfnum ifnum,
                                   const unsigned char *target_hw)
{
  SshUInt32 i, hashvalue;
  SshEngineNextHopData d_nh = NULL;
  SshEngineNextHopControl c_nh = NULL;
  
  SSH_INTERCEPTOR_STACK_MARK();

  ssh_kernel_mutex_assert_is_locked(engine->flow_control_table_lock);

  /* Check if we have an existing entry for this node in the next hop table. */
  hashvalue = SSH_IP_HASH(next_hop_gw);
  hashvalue %= engine->next_hop_hash_size;
  i = engine->next_hop_hash[hashvalue];

  while (i != SSH_IPSEC_INVALID_INDEX)
    {
      c_nh = SSH_ENGINE_GET_NH(engine, i);
      d_nh = FASTPATH_GET_NH(engine->fastpath, i);
      SSH_ASSERT(d_nh->flags != 0);

      if (SSH_IP_EQUAL(&d_nh->dst, next_hop_gw)
          && ifnum == d_nh->ifnum)
        {
          /* Found an entry */
          SSH_DEBUG(SSH_D_LOWOK, ("updating next hop node %d", (int) i));
          
          ssh_engine_modify_media_header(d_nh->mediatype, NULL, target_hw,
                                         0, d_nh->mediahdr);

        }
      FASTPATH_RELEASE_NH(engine->fastpath, i);
      i = c_nh->next;
    }
}

/* Decrements the reference count of the given next hop node, and frees it
   if the reference count becomes zero.  This must be called with
   engine->flow_control_table_lock held. */

void ssh_engine_decrement_next_hop_refcnt(SshEngine engine,
                                          SshUInt32 next_hop_index)
{
  SshEngineNextHopControl c_nh = NULL;
  SshUInt32 hashvalue, *nhp;

  SSH_INTERCEPTOR_STACK_MARK();

  SSH_DEBUG(SSH_D_LOWOK, ("decrementing next hop node %d refcnt",
                          (int)next_hop_index));

  ssh_kernel_mutex_assert_is_locked(engine->flow_control_table_lock);

  /* Decrement the reference count of the node. */
  SSH_ASSERT(next_hop_index < engine->next_hop_hash_size);
  c_nh = SSH_ENGINE_GET_NH(engine, next_hop_index);

  c_nh->refcnt--;

  /* If the reference count reaches zero, free the node. */
  if (c_nh->refcnt == 0)
    {
      SshEngineNextHopData d_nh;

      SSH_DEBUG(SSH_D_LOWOK, ("freeing next hop node %d",
                              (int)next_hop_index));

      d_nh = FASTPATH_GET_NH(engine->fastpath, next_hop_index);

      /* Compute its hash value. */
      hashvalue = SSH_IP_HASH(&d_nh->dst);
      hashvalue %= engine->next_hop_hash_size;

      FASTPATH_UNINIT_NH(engine->fastpath, next_hop_index, d_nh);

      /* Remove it from the hash list. */
      nhp = &engine->next_hop_hash[hashvalue];
      SSH_ASSERT(*nhp != SSH_IPSEC_INVALID_INDEX);
      for (;;)
        {
	  SshEngineNextHopControl next;
	  
          if (*nhp == next_hop_index)
            break;
	  
          SSH_ASSERT(*nhp != SSH_IPSEC_INVALID_INDEX);
	  next = SSH_ENGINE_GET_NH(engine, *nhp);
	  nhp = &next->next;
        }
      *nhp = c_nh->next;

      c_nh->next = engine->next_hop_hash_freelist;
      engine->next_hop_hash_freelist = next_hop_index;
#ifdef SSH_IPSEC_STATISTICS
      engine->stats.active_nexthops--;
#endif /* SSH_IPSEC_STATISTICS */
    }
}

#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */
