/*
 * util_peer.c
 *
 * Copyright:
 *      Copyright (c) 2002 - 2009 SFNT Finland Oy.
 *      All rights reserved.
 *
 * Peer information database.
 *
 */


#include "sshincludes.h"
#include "quicksecpm_internal.h"

#define SSH_DEBUG_MODULE "SshPmPeer"

/************************* Definitions **************************************/

#define SSH_PM_PEER_HANDLE_HASH(peer_handle) \
((peer_handle) % SSH_PM_PEER_HANDLE_HASH_TABLE_SIZE)

#define SSH_PM_PEER_IKE_SA_HASH(ike_sa_handle) \
((ike_sa_handle) % SSH_PM_PEER_IKE_SA_HASH_TABLE_SIZE)

#define SSH_PM_PEER_LOCAL_ADDR_HASH(local_ip) \
(SSH_IP_HASH((local_ip)) % SSH_PM_PEER_ADDR_HASH_TABLE_SIZE)

/************************* Peer hashtable handling **************************/

static void
pm_peer_handle_hash_insert(SshPm pm, SshPmPeer peer)
{
  SshUInt32 hash;

  SSH_ASSERT(peer != NULL);
  SSH_ASSERT(peer->peer_handle != SSH_IPSEC_INVALID_INDEX);

  hash = SSH_PM_PEER_HANDLE_HASH(peer->peer_handle);

  peer->next_peer_handle = pm->peer_handle_hash[hash];
  if (peer->next_peer_handle)
    peer->next_peer_handle->prev_peer_handle = peer;
  pm->peer_handle_hash[hash] = peer;
}

static void
pm_peer_handle_hash_remove(SshPm pm, SshPmPeer peer)
{
  SshUInt32 hash;

  SSH_ASSERT(peer != NULL);
  SSH_ASSERT(peer->peer_handle != SSH_IPSEC_INVALID_INDEX);
  
  if (peer->next_peer_handle)
    peer->next_peer_handle->prev_peer_handle = peer->prev_peer_handle;
  if (peer->prev_peer_handle)
    peer->prev_peer_handle->next_peer_handle = peer->next_peer_handle;
  else
    {
      hash = SSH_PM_PEER_HANDLE_HASH(peer->peer_handle);
      SSH_ASSERT(pm->peer_handle_hash[hash] == peer);
      pm->peer_handle_hash[hash] = peer->next_peer_handle;
    }

  peer->next_peer_handle = NULL;
  peer->prev_peer_handle = NULL;
}

static void
pm_peer_sa_hash_insert(SshPm pm, SshPmPeer peer)
{
  SshUInt32 hash;

  SSH_ASSERT(peer != NULL);

  hash = SSH_PM_PEER_IKE_SA_HASH(peer->ike_sa_handle);

  peer->next_sa_handle = pm->peer_sa_hash[hash];
  if (peer->next_sa_handle)
    peer->next_sa_handle->prev_sa_handle = peer;
  pm->peer_sa_hash[hash] = peer;
}

static void
pm_peer_sa_hash_remove(SshPm pm, SshPmPeer peer)
{
  SshUInt32 hash;

  SSH_ASSERT(peer != NULL);
  
  if (peer->next_sa_handle)
    peer->next_sa_handle->prev_sa_handle = peer->prev_sa_handle;
  if (peer->prev_sa_handle)
    peer->prev_sa_handle->next_sa_handle = peer->next_sa_handle;
  else
    {
      hash = SSH_PM_PEER_IKE_SA_HASH(peer->ike_sa_handle);
      SSH_ASSERT(pm->peer_sa_hash[hash] == peer);
      pm->peer_sa_hash[hash] = peer->next_sa_handle;
    }

  peer->next_sa_handle = NULL;
  peer->prev_sa_handle = NULL;
}

static void
pm_peer_addr_hash_insert(SshPm pm, SshPmPeer peer)
{
  SshUInt32 hash;

  SSH_ASSERT(peer != NULL);

  hash = SSH_PM_PEER_LOCAL_ADDR_HASH(peer->local_ip);

  peer->next_addr = pm->peer_addr_hash[hash];
  if (peer->next_addr)
    peer->next_addr->prev_addr = peer;
  pm->peer_addr_hash[hash] = peer;
}

static void
pm_peer_addr_hash_remove(SshPm pm, SshPmPeer peer)
{
  SshUInt32 hash;

  SSH_ASSERT(peer != NULL);
  
  if (peer->next_addr)
    peer->next_addr->prev_addr = peer->prev_addr;
  if (peer->prev_addr)
    peer->prev_addr->next_addr = peer->next_addr;
  else
    {
      hash = SSH_PM_PEER_LOCAL_ADDR_HASH(peer->local_ip);
      SSH_ASSERT(pm->peer_addr_hash[hash] == peer);
      pm->peer_addr_hash[hash] = peer->next_addr;
    }

  peer->next_addr = NULL;
  peer->prev_addr = NULL;
}

/************************* Peer reference counting ***************************/

static void
pm_peer_take_ref(SshPmPeer peer)
{
  SSH_ASSERT(peer != NULL);
  peer->refcnt++;
  SSH_DEBUG(SSH_D_LOWOK, ("Taking reference to peer 0x%lx, refcnt %d",
			  (unsigned long) peer->peer_handle, peer->refcnt));
}

/**************************** Peer lookup ***********************************/

SshPmPeer
ssh_pm_peer_by_handle(SshPm pm, SshUInt32 peer_handle)
{
  SshPmPeer peer;
  SshUInt32 hash;

  if (peer_handle == SSH_IPSEC_INVALID_INDEX)
    return NULL;

  hash = SSH_PM_PEER_HANDLE_HASH(peer_handle);
  
  for (peer = pm->peer_handle_hash[hash]; 
       peer != NULL; 
       peer = peer->next_peer_handle)
    {
      if (peer->peer_handle == peer_handle)
	return peer;
    }

  return NULL;
}

/** Iterating through peers that use IKE SA `ike_sa_handle'. */

SshPmPeer
ssh_pm_peer_by_ike_sa_handle(SshPm pm, SshUInt32 ike_sa_handle)
{
  SshPmPeer peer;
  SshUInt32 hash;

  hash = SSH_PM_PEER_IKE_SA_HASH(ike_sa_handle);

  for (peer = pm->peer_sa_hash[hash]; 
       peer != NULL; 
       peer = peer->next_sa_handle)
    {
      if (peer->ike_sa_handle == ike_sa_handle)
	return peer;
    }
  
  return NULL;
}

SshPmPeer
ssh_pm_peer_next_by_ike_sa_handle(SshPm pm, SshPmPeer peer)
{
  SshPmPeer next_peer;

  if (peer == NULL)
    return NULL;

  for (next_peer = peer->next_sa_handle; 
       next_peer != NULL;
       next_peer = next_peer->next_sa_handle)
    {
      if (next_peer->ike_sa_handle == peer->ike_sa_handle)
	return next_peer;
    }

  return NULL;
}

SshPmPeer
ssh_pm_peer_by_p1(SshPm pm, SshPmP1 p1)
{
  SSH_ASSERT(p1 != NULL);
  return ssh_pm_peer_by_ike_sa_handle(pm, SSH_PM_IKE_SA_INDEX(p1));
}

SshUInt32
ssh_pm_peer_handle_by_p1(SshPm pm, SshPmP1 p1)
{
  SshPmPeer peer;

  SSH_ASSERT(p1 != NULL);

  peer = ssh_pm_peer_by_p1(pm, p1);
  if (peer)
    return peer->peer_handle;
  
  return SSH_IPSEC_INVALID_INDEX;
}

SshPmP1
ssh_pm_p1_by_peer_handle(SshPm pm, SshUInt32 peer_handle)
{
  SshPmPeer peer;
  
  if (peer_handle == SSH_IPSEC_INVALID_INDEX)
    return NULL;
  
  peer = ssh_pm_peer_by_handle(pm, peer_handle);
  if (peer == NULL)
    return NULL;
  
  return ssh_pm_p1_from_ike_handle(pm, peer->ike_sa_handle, TRUE);
}

SshUInt32
ssh_pm_peer_handle_lookup(SshPm pm,
			  SshIpAddr remote_ip, SshUInt16 remote_port,
			  SshIpAddr local_ip, SshUInt16 local_port,
			  SshIkev2PayloadID remote_id,
			  SshIkev2PayloadID local_id,			  
			  Boolean use_ikev1,
			  Boolean manual_key)
{
  SshPmPeer peer;

  /* Addresses are mandatory, ports and identities are optional. */
  SSH_ASSERT(remote_ip != NULL);
  SSH_ASSERT(local_ip != NULL);

  for (peer = pm->peer_addr_hash[SSH_PM_PEER_LOCAL_ADDR_HASH(local_ip)];
       peer != NULL;
       peer = peer->next_addr)
    {
      /* Match remote address. */
      if (SSH_IP_EQUAL(peer->remote_ip, remote_ip) == FALSE
	  || (remote_port != 0 && peer->remote_port != remote_port))
	continue;
      
      /* Match local address. */
      if (SSH_IP_EQUAL(peer->local_ip, local_ip) == FALSE
	  || (local_port != 0 && peer->local_port != local_port))
	continue;
      
      /* Match identities. */
      if (remote_id != NULL 
	  && ssh_pm_ikev2_id_compare(remote_id, peer->remote_id) == FALSE)
	continue;

      if (local_id != NULL 
	  && ssh_pm_ikev2_id_compare(local_id, peer->local_id) == FALSE)
	continue;

      /* Match rest. */      
      if (peer->manual_key != manual_key
	  || peer->use_ikev1 != use_ikev1)
	continue;

      /* We have a match. */
      return peer->peer_handle;
    }

  return SSH_IPSEC_INVALID_INDEX;
}


SshUInt32
ssh_pm_peer_handle_by_address(SshPm pm,
			      SshIpAddr remote_ip, SshUInt16 remote_port,
			      SshIpAddr local_ip, SshUInt16 local_port,
			      Boolean use_ikev1,
			      Boolean manual_key)
{
  return ssh_pm_peer_handle_lookup(pm, remote_ip, remote_port,
				   local_ip, local_port, NULL, NULL,
				   use_ikev1, manual_key);
}

/** Iterating through peers that use `local_ip'. */

SshPmPeer
ssh_pm_peer_by_local_address(SshPm pm, SshIpAddr local_ip)
{
  SshPmPeer peer;

  for (peer = pm->peer_addr_hash[SSH_PM_PEER_LOCAL_ADDR_HASH(local_ip)];
       peer != NULL;
       peer = peer->next_addr)
    {
      if (SSH_IP_EQUAL(peer->local_ip, local_ip))
	return peer;
    }

  return NULL;
}

SshPmPeer
ssh_pm_peer_next_by_local_address(SshPm pm, SshPmPeer peer)
{
  SshPmPeer next_peer;

  if (peer == NULL)
    return NULL;

  for (next_peer = peer->next_addr; 
       next_peer != NULL;
       next_peer = next_peer->next_addr)
    {
      if (SSH_IP_EQUAL(next_peer->local_ip, peer->local_ip))
	return next_peer;
    }

  return NULL;
}

SshUInt32
ssh_pm_peer_num_child_sas_by_p1(SshPm pm, SshPmP1 p1)
{
  SshUInt32 num_child_sas = 0;
  SshPmPeer peer = NULL;
  
  /* Count all the peer having the given P1. */
  for (peer = ssh_pm_peer_by_p1(pm, p1); 
       peer != NULL;
       peer = ssh_pm_peer_next_by_ike_sa_handle(pm, peer))
    {
      num_child_sas += peer->num_child_sas;
    }
  
  return num_child_sas;
}

/********************* Peer creation / destruction **************************/

SshUInt32
ssh_pm_peer_create_internal(SshPm pm, 
			    SshIpAddr remote_ip, SshUInt16 remote_port,
			    SshIpAddr local_ip, SshUInt16 local_port,
			    SshIkev2PayloadID local_id,
			    SshIkev2PayloadID remote_id,
			    SshUInt32 ike_sa_handle,
			    Boolean use_ikev1,
			    Boolean manual_key)
{
  SshUInt32 peer_handle, i;
  SshPmPeer peer;

  SSH_ASSERT(remote_ip != NULL);
  SSH_ASSERT(SSH_IP_DEFINED(remote_ip));
  SSH_ASSERT(manual_key || remote_port != 0);
  
  for (i = 0; i < SSH_PM_MAX_PEER_HANDLES; i++)
    {
      /* Select the next free peer_handle. */
      peer_handle = pm->next_peer_handle++;
      if (pm->next_peer_handle > SSH_PM_MAX_PEER_HANDLES)
	pm->next_peer_handle = 0;

      if (ssh_pm_peer_by_handle(pm, peer_handle))
	continue;
      
      /* Free peer_handle found, allocate a SshPmPeer. */
      peer = ssh_pm_peer_alloc(pm);
      if (!peer)
	return SSH_IPSEC_INVALID_INDEX;

      peer->peer_handle = peer_handle;
      *peer->remote_ip = *remote_ip;
      peer->remote_port = remote_port;
      *peer->local_ip = *local_ip;
      peer->local_port = local_port;

      peer->ike_sa_handle = ike_sa_handle;
      if (local_id)
	peer->local_id = ssh_pm_ikev2_payload_id_dup(local_id);
      if (remote_id)
	peer->remote_id = ssh_pm_ikev2_payload_id_dup(remote_id);
      peer->use_ikev1 = use_ikev1;
      
      if (manual_key)
	peer->manual_key = TRUE;

      /* Take one reference for p1. */
      peer->refcnt = 1;

      peer->num_child_sas = 0;

      SSH_DEBUG(SSH_D_MIDOK, 
		("Allocating peer 0x%lx remote %@;%d local %@;%d "
		 "remote ID %@ local ID %@ ike_sa_handle 0x%lx%s",
		 (unsigned long) peer->peer_handle,
		 ssh_ipaddr_render, remote_ip, (int) remote_port,
		 ssh_ipaddr_render, local_ip, (int) local_port,
		 ssh_pm_ike_id_render, peer->remote_id,
		 ssh_pm_ike_id_render, peer->local_id,
		 (unsigned long) peer->ike_sa_handle,
		 (peer->manual_key ? " [manual]" : "")));

      /* Insert into peer_handle_hash. */
      pm_peer_handle_hash_insert(pm, peer);

      /* Insert into peer_sa_hash. */
      pm_peer_sa_hash_insert(pm, peer);

      /* Insert into peer_addr_hash. */
      pm_peer_addr_hash_insert(pm, peer);

      return peer->peer_handle;
    }

  /* No free peer_handles available. */
  return SSH_IPSEC_INVALID_INDEX;
}

SshUInt32
ssh_pm_peer_create(SshPm pm, 
		   SshIpAddr remote_ip, SshUInt16 remote_port,
		   SshIpAddr local_ip, SshUInt16 local_port,
		   SshPmP1 p1, Boolean manual_key)
{
  Boolean use_ikev1 = FALSE;

  if (p1 != NULL)
    {
#ifdef SSHDIST_IKEV1
      if (p1->ike_sa->flags & SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_IKEV1)
	use_ikev1 = TRUE;
#endif /* SSHDIST_IKEV1 */
      return ssh_pm_peer_create_internal(pm, remote_ip, remote_port, 
					 local_ip, local_port, 
					 p1->local_id, p1->remote_id,
					 SSH_PM_IKE_SA_INDEX(p1),
					 use_ikev1,
					 manual_key);
    }
  else
    {
      return ssh_pm_peer_create_internal(pm, remote_ip, remote_port,
					 local_ip, local_port,
					 NULL, NULL, SSH_IPSEC_INVALID_INDEX,
					 FALSE,
					 manual_key);
    }
}

static void 
pm_peer_destroy(SshPm pm, SshPmPeer peer)
{
  SSH_ASSERT(peer != NULL);
  SSH_ASSERT(peer->refcnt > 0);

  peer->refcnt--;
  if (peer->refcnt > 0)
    {
      SSH_DEBUG(SSH_D_LOWOK, 
		("Freeing reference to peer 0x%lx, %d references left.",
		 (unsigned long) peer->peer_handle,
		 (int) peer->refcnt));
      return;
    }

  SSH_DEBUG(SSH_D_MIDOK, 
	    ("Destroying peer 0x%lx remote %@;%d local %@;%d "
	     "ike_sa_handle 0x%lx",
	     (unsigned long) peer->peer_handle,
	     ssh_ipaddr_render, peer->remote_ip, (int) peer->remote_port, 
	     ssh_ipaddr_render, peer->local_ip, (int) peer->local_port, 
	     (unsigned long) peer->ike_sa_handle));
  
  /* Remove from peer_handle_hash. */  
  pm_peer_handle_hash_remove(pm, peer);
  
  /* Remove from peer_sa_hash. */  
  pm_peer_sa_hash_remove(pm, peer);

  /* Remove from peer_addr_hash. */
  pm_peer_addr_hash_remove(pm, peer);

  /* Put peer back to freelist. */
  ssh_pm_peer_free(pm, peer);
}

void
ssh_pm_peer_handle_take_ref(SshPm pm, SshUInt32 peer_handle)
{
  SshPmPeer peer;
  
  SSH_ASSERT(peer_handle != SSH_IPSEC_INVALID_INDEX);
  
  peer = ssh_pm_peer_by_handle(pm, peer_handle);
  SSH_ASSERT(peer != NULL);
  pm_peer_take_ref(peer);
}

void
ssh_pm_peer_handle_destroy(SshPm pm, SshUInt32 peer_handle)
{
  SSH_ASSERT(peer_handle != SSH_IPSEC_INVALID_INDEX);
  pm_peer_destroy(pm, ssh_pm_peer_by_handle(pm, peer_handle));
}

/************************** Peer updating ***********************************/

static Boolean pm_peer_update_address(SshPm pm, 
				      SshPmPeer peer,
				      SshIpAddr new_remote_ip, 
				      SshUInt16 new_remote_port,
				      SshIpAddr new_local_ip, 
				      SshUInt16 new_local_port)
{
  SSH_ASSERT(peer != NULL);
  SSH_ASSERT(new_remote_ip != NULL);
  SSH_ASSERT(new_remote_port != 0);
  
  if (!SSH_IP_EQUAL(peer->remote_ip, new_remote_ip)
      || peer->remote_port != new_remote_port
      || !SSH_IP_EQUAL(peer->local_ip, new_local_ip)
      || peer->local_port != new_local_port)
    {
      SSH_DEBUG(SSH_D_MIDOK, 
		("Updating peer 0x%lx address remote %@;%d local %@;%d "
		 "to remote %@;%d local %@;%d",
		 (unsigned long) peer->peer_handle,
		 ssh_ipaddr_render, peer->remote_ip, (int) peer->remote_port,
		 ssh_ipaddr_render, peer->local_ip, (int) peer->local_port,
		 ssh_ipaddr_render, new_remote_ip, (int) new_remote_port,
		 ssh_ipaddr_render, new_local_ip, (int) new_local_port));
      
      /* Remove from peer_addr_hash. */
      pm_peer_addr_hash_remove(pm, peer);
      
      /* Update addresses and ports. */
      *peer->remote_ip = *new_remote_ip;
      peer->remote_port = new_remote_port;
      *peer->local_ip = *new_local_ip;
      peer->local_port = new_local_port;
      
      /* Insert into peer_addr_hash. */
      pm_peer_addr_hash_insert(pm, peer);
    }

  return TRUE;  
}

Boolean
ssh_pm_peer_p1_update_address(SshPm pm, 
			      SshPmP1 p1, 
			      SshIpAddr new_remote_ip, 
			      SshUInt16 new_remote_port,
			      SshIpAddr new_local_ip, 
			      SshUInt16 new_local_port)
{
  SshPmPeer peer;

  SSH_ASSERT(p1 != NULL);
  
  peer = ssh_pm_peer_by_p1(pm, p1);

  /* It is ok not to have any peers for p1. This means just that there are
     no IPsec SAs with this peer. */
  if (peer == NULL)
    return TRUE;

  return pm_peer_update_address(pm, peer, new_remote_ip, new_remote_port,
				new_local_ip, new_local_port);
}

Boolean
ssh_pm_peer_update_p1(SshPm pm, SshPmPeer peer, SshPmP1 new_p1)
{
  SshUInt32 new_ike_sa_handle = SSH_IPSEC_INVALID_INDEX;
  SshUInt32 old_ike_sa_handle = SSH_IPSEC_INVALID_INDEX;

  if (peer == NULL)
    return FALSE;

  if (new_p1 != NULL)
    {
      /* Fill in local and remote identities if they are not set. This may
	 happen when importing IPsec SAs without a valid IKEv1 SA. */
      if (peer->local_id == NULL)
	peer->local_id = ssh_pm_ikev2_payload_id_dup(new_p1->local_id);
      if (peer->remote_id == NULL)
	peer->remote_id = ssh_pm_ikev2_payload_id_dup(new_p1->remote_id);
      
      new_ike_sa_handle =  SSH_PM_IKE_SA_INDEX(new_p1);
    }

  old_ike_sa_handle = peer->ike_sa_handle;

  if (old_ike_sa_handle == new_ike_sa_handle)
    return TRUE;

  SSH_DEBUG(SSH_D_MIDOK, 
	    ("Updating peer 0x%lx ike_sa_handle from 0x%lx to 0x%lx",
	     (unsigned long) peer->peer_handle, 
	     (unsigned long) peer->ike_sa_handle,
	     (unsigned long) new_ike_sa_handle));

  /* Update ike_sa_handle and peer_sa_hash. */
  pm_peer_sa_hash_remove(pm, peer);
  peer->ike_sa_handle = new_ike_sa_handle;
  pm_peer_sa_hash_insert(pm, peer);
  
  /* Take one reference for the new IKE SA. */
  if (new_ike_sa_handle != SSH_IPSEC_INVALID_INDEX)
    pm_peer_take_ref(peer);
  
  /* Release the old IKE SA's reference. */
  if (old_ike_sa_handle != SSH_IPSEC_INVALID_INDEX)
    pm_peer_destroy(pm, peer);
  
  if (new_p1)
    pm_peer_update_address(pm, peer,
			   new_p1->ike_sa->remote_ip, 
			   new_p1->ike_sa->remote_port,
			   new_p1->ike_sa->server->ip_address,
			   SSH_PM_IKE_SA_LOCAL_PORT(new_p1->ike_sa));
  
  return TRUE;
}

/**************************** Module cleanup ********************************/

void
ssh_pm_peers_uninit(SshPm pm)
{
  SshUInt32 hash;
  SshPmPeer peer;

  for (hash = 0; hash < SSH_PM_PEER_IKE_SA_HASH_TABLE_SIZE; hash++)
    {
      do
	{
	  peer = pm->peer_handle_hash[hash];
	  if (peer)
	    pm_peer_destroy(pm, peer);
	}
      while (peer != NULL);
      SSH_ASSERT(pm->peer_handle_hash[hash] == NULL);
    }
}
