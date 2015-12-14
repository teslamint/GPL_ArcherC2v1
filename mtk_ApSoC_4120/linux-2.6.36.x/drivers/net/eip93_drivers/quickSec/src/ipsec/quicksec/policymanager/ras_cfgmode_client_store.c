/*
 * ras_cfgmode_client_store.c
 *
 * Copyright:
 *       Copyright (c) 2002 - 2009 SFNT Finland Oy.
 *       All rights reserved.
 *
 * Storage for active IKE configuration mode clients.
 *
 */

#include "sshincludes.h"
#include "quicksecpm_internal.h"

#define SSH_DEBUG_MODULE "SshPmCfgmodeClientStore"

#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_SERVER
#ifdef SSHDIST_ISAKMP_CFG_MODE

/*************************** Pre-allocated tables ***************************/

#ifdef SSH_IPSEC_PREALLOCATE_TABLES
static SshPmActiveCfgModeClientStruct
ssh_pm_active_cfgmode_clients[SSH_PM_MAX_CONFIG_MODE_CLIENTS];
#endif /* SSH_IPSEC_PREALLOCATE_TABLES */

#define SSH_PM_CFGMODE_CLIENT_HASH(peer_handle) \
  ((peer_handle) % SSH_PM_CFGMODE_CLIENT_HASH_TABLE_SIZE)

/************ Public function to manipulate CFGMODE client store ************/

Boolean
ssh_pm_cfgmode_client_store_init(SshPm pm)
{
  int i;

#ifdef SSH_IPSEC_PREALLOCATE_TABLES
  for (i = 0; i < SSH_PM_MAX_CONFIG_MODE_CLIENTS; i++)
    {
      ssh_pm_active_cfgmode_clients[i].peer_handle = SSH_IPSEC_INVALID_INDEX;
      ssh_pm_active_cfgmode_clients[i].next = pm->cfgmode_clients_freelist;
      pm->cfgmode_clients_freelist = &ssh_pm_active_cfgmode_clients[i];
    }
#else /* not SSH_IPSEC_PREALLOCATE_TABLES */
  for (i = 0; i < SSH_PM_MAX_CONFIG_MODE_CLIENTS; i++)
    {
      SshPmActiveCfgModeClient client = ssh_malloc(sizeof(*client));
      
      if (client == NULL)
        {
          SSH_DEBUG(SSH_D_ERROR, ("Could not allocate client structures"));
          ssh_pm_cfgmode_client_store_uninit(pm);
          return FALSE;
        }
      client->peer_handle = SSH_IPSEC_INVALID_INDEX;
      client->next = pm->cfgmode_clients_freelist;
      pm->cfgmode_clients_freelist = client;
    }
#endif /* not SSH_IPSEC_PREALLOCATE_TABLES */

  return TRUE;
}


void
ssh_pm_cfgmode_client_store_uninit(SshPm pm)
{
  int i;
  SshPmActiveCfgModeClient client;

  /* Free hash table. */
  for (i = 0; i < SSH_PM_CFGMODE_CLIENT_HASH_TABLE_SIZE; i++)
    {
      while (pm->cfgmode_clients_hash[i])
	{
	  client = pm->cfgmode_clients_hash[i];
	  
	  pm->cfgmode_clients_hash[i] = client->next;
	  
	  /* Release IP address. */
	  if (client->ip4)
	    {
	      (*client->free_cb)(pm, client->ip4, client->ip4_address_context,
				 client->free_cb_context);
	      ssh_free(client->ip4);
	    }
	  if (client->ip6)
	    {
	      (*client->free_cb)(pm, client->ip6, client->ip6_address_context,
				 client->free_cb_context);
	      ssh_free(client->ip6);
	    }

#ifndef SSH_IPSEC_PREALLOCATE_TABLES
	  ssh_free(client);
#endif /* not SSH_IPSEC_PREALLOCATE_TABLES */
	}
    }

#ifndef SSH_IPSEC_PREALLOCATE_TABLES
  /* Free freelist. */
  while (pm->cfgmode_clients_freelist)
    {
      client = pm->cfgmode_clients_freelist;
      pm->cfgmode_clients_freelist = client->next;
      
      ssh_free(client);
    }
#endif /* SSH_IPSEC_PREALLOCATE_TABLES */
}

SshPmActiveCfgModeClient
ssh_pm_cfgmode_client_store_alloc(SshPm pm, SshPmP1 p1)
{
  SshPmActiveCfgModeClient client, c;
  SshUInt32 hash, peer_handle;

  /* Check if there are free cfgmode_clients left. */ 
  if (pm->cfgmode_clients_freelist == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Out of cgmode_clients"));
      return NULL;
    }

  /* Lookup IKE peer entry. */
  peer_handle = ssh_pm_peer_handle_by_p1(pm, p1);
  if (peer_handle == SSH_IPSEC_INVALID_INDEX)
    {
      peer_handle = ssh_pm_peer_create(pm, p1->ike_sa->remote_ip,
				       p1->ike_sa->remote_port,
				       p1->ike_sa->server->ip_address,
				       SSH_PM_IKE_SA_LOCAL_PORT(p1->ike_sa),
				       p1, FALSE);
      if (peer_handle == SSH_IPSEC_INVALID_INDEX)
	{
	  SSH_DEBUG(SSH_D_FAIL, ("Could not create IKE peer for p1 %p", p1));
	  return NULL;
	}
    }
  SSH_ASSERT(peer_handle != SSH_IPSEC_INVALID_INDEX);

  /* Allocate client. */
  client = pm->cfgmode_clients_freelist;
  pm->cfgmode_clients_freelist = client->next;

  /* Initialize the client */
  memset(client, 0, sizeof(*client));  
  client->peer_handle = peer_handle;
  client->refcount = 1;
  client->status_cb = NULL_FNPTR;

  /* Link it to the hash table. */
  hash = SSH_PM_CFGMODE_CLIENT_HASH(client->peer_handle);
  for (c = pm->cfgmode_clients_hash[hash]; c; c = c->next)
    if (c == client)
      break;
  if (c == NULL)
    {
      client->next = pm->cfgmode_clients_hash[hash];
      pm->cfgmode_clients_hash[hash] = client;
    }

  return client;
}

SshPmActiveCfgModeClient
ssh_pm_cfgmode_client_store_lookup(SshPm pm, SshUInt32 peer_handle)
{
  SshUInt32 hash;
  SshPmActiveCfgModeClient c;
  
  SSH_ASSERT(peer_handle != SSH_IPSEC_INVALID_INDEX);
  hash = SSH_PM_CFGMODE_CLIENT_HASH(peer_handle);
  for (c = pm->cfgmode_clients_hash[hash]; c; c = c->next)
    if (c->peer_handle == peer_handle)
      return c;
  return NULL;
}


static void
pm_cfgmode_client_store_free(SshPm pm, SshPmActiveCfgModeClient client)
{
  client->next = pm->cfgmode_clients_freelist;

  if (client->ip4)
    {
      if (client->flags & SSH_PM_CFGMODE_CLIENT_IPV4_PROXY_ARP) 
	ssh_pme_arp_remove(pm->engine, client->ip4, 0);

      ssh_free(client->ip4);
      client->ip4 = NULL;
    }
  if (client->ip6)
    {
      if (client->flags & SSH_PM_CFGMODE_CLIENT_IPV6_PROXY_ARP) 
	ssh_pme_arp_remove(pm->engine, client->ip6, 0);

      ssh_free(client->ip6);
      client->ip6 = NULL;
    }
  client->peer_handle = SSH_IPSEC_INVALID_INDEX;
  pm->cfgmode_clients_freelist = client;
}

static void
pm_cfgmode_client_store_arp_cb(SshPm pm, Boolean success, void *context)
{
  SshPmActiveCfgModeClient client = (SshPmActiveCfgModeClient) context;
  SshPmStatusCB status_cb;

  SSH_ASSERT(client != NULL);

  SSH_DEBUG(SSH_D_LOWOK, ("ARP entry add %s",
			  (success ? "succeeded" : "failed")));

  if (!success)
    {
      if (client->flags & SSH_PM_CFGMODE_CLIENT_IPV4_REGISTERING)
	{
	  ssh_free(client->ip4);
	  client->ip4 = NULL;
	  client->ip4_address_context = NULL;
	}
      
      else
	{
	  SSH_ASSERT(client->flags & SSH_PM_CFGMODE_CLIENT_IPV6_REGISTERING);
	  ssh_free(client->ip6);
	  client->ip6 = NULL;
	  client->ip6_address_context = NULL;
	}
    }

  /* Unregister abort callback, unless operation was aborted. */
  if ((client->flags & SSH_PM_CFGMODE_CLIENT_ABORTED) == 0)
    ssh_operation_unregister(&client->operation);

  /* Clear status flags. */
  client->flags &= ~(SSH_PM_CFGMODE_CLIENT_IPV4_REGISTERING
		     | SSH_PM_CFGMODE_CLIENT_IPV6_REGISTERING
		     | SSH_PM_CFGMODE_CLIENT_ADDING_ARP
		     | SSH_PM_CFGMODE_CLIENT_ABORTED);

  status_cb = client->status_cb;
  client->status_cb = NULL_FNPTR;
  
  if (status_cb) 
    (*status_cb)(pm, success, client->status_cb_context);

  /* Release the reference to cfgmode client. */
  ssh_pm_cfgmode_client_store_unreference(pm, client);
}

void
pm_cfgmode_client_store_arp_abort(void *context)
{
  SshPmActiveCfgModeClient client = (SshPmActiveCfgModeClient) context;

  SSH_DEBUG(SSH_D_LOWOK, ("Aborting cfgmode client address registration"));
  
  SSH_ASSERT(client != NULL);
  SSH_ASSERT(client->flags & SSH_PM_CFGMODE_CLIENT_ADDING_ARP);

  /* Clear status callback. Let the engine operation complete, 
     because it cannot be aborted. */
  client->status_cb = NULL_FNPTR;
  client->flags |= SSH_PM_CFGMODE_CLIENT_ABORTED;
}

SshOperationHandle
ssh_pm_cfgmode_client_store_register(SshPm pm,
				     SshPmTunnel tunnel,
                                     SshPmActiveCfgModeClient client,
                                     SshIpAddr address,
				     void *address_context,
                                     SshPmRemoteAccessAttrsFreeCB free_cb,
                                     void *free_cb_context,
				     SshPmStatusCB status_cb,
				     void *status_cb_context)
{
  SSH_DEBUG(SSH_D_LOWOK,
	    ("Registering address `%@'", ssh_ipaddr_render, address));

  SSH_ASSERT(client->status_cb == NULL_FNPTR);

  if (client->flags & SSH_PM_CFGMODE_CLIENT_ADDING_ARP)
    goto error;

  if (!SSH_IP_DEFINED(address))
    goto error;
  
  if (SSH_IP_IS4(address))
    {
      SSH_ASSERT(client->ip4 == NULL);
      client->ip4 = ssh_memdup(address, sizeof(*address));
      if (client->ip4 == NULL)
	goto error;
      client->ip4_address_context = address_context;
    }
  else
    {
      SSH_ASSERT(client->ip6 == NULL);
      client->ip6 = ssh_memdup(address, sizeof(*address));
      if (client->ip6 == NULL)
	goto error;
      client->ip6_address_context = address_context;
    }

  client->free_cb = free_cb;
  client->free_cb_context = free_cb_context;
  
  /* Check if we should add a proxy ARP entry for the remote access client. */
  if (tunnel->flags & SSH_PM_TR_PROXY_ARP)
    {
      unsigned char media_addr[SSH_ETHERH_ADDRLEN];
      SshUInt32 flags;
      
      /* Create a fake ethernet address. */
      memset(media_addr, 0, sizeof(media_addr));
      if (SSH_IP_IS4(address))
	{
	  media_addr[1] = 2;
	  SSH_IP4_ENCODE(address, media_addr + 2);

	  client->flags |= SSH_PM_CFGMODE_CLIENT_IPV4_PROXY_ARP;
	}
      else
	{
	  SshUInt32 value;
	  
	  value = SSH_IP6_WORD0_TO_INT(address);
	  value ^= SSH_IP6_WORD1_TO_INT(address);
	  value ^= SSH_IP6_WORD2_TO_INT(address);
	  value ^= SSH_IP6_WORD3_TO_INT(address);
	  
	  media_addr[1] = 2;
	  SSH_PUT_32BIT(media_addr + 2, value);

	  client->flags |= SSH_PM_CFGMODE_CLIENT_IPV6_PROXY_ARP;
	}
      
      /* Flags for ARP entry. */
      flags = SSH_PME_ARP_PERMANENT | SSH_PME_ARP_GLOBAL | SSH_PME_ARP_PROXY;

      /* Store status_cb. */
      client->status_cb = status_cb;
      client->status_cb_context = status_cb_context;
      if (SSH_IP_IS4(address))
	client->flags |= SSH_PM_CFGMODE_CLIENT_IPV4_REGISTERING;
      else
	client->flags |= SSH_PM_CFGMODE_CLIENT_IPV6_REGISTERING;

      /* Register an abort callback for the engine operation. */
      ssh_operation_register_no_alloc(&client->operation,
				      pm_cfgmode_client_store_arp_abort,
				      client);

      /* Take a reference to the client and mark ARP ongoing. */
      ssh_pm_cfgmode_client_store_take_reference(pm, client);
      client->flags |= SSH_PM_CFGMODE_CLIENT_ADDING_ARP;

      /* Add ARP entry. */
      SSH_DEBUG(SSH_D_LOWSTART, ("Adding ARP entry"));
      ssh_pme_arp_add(pm->engine, address, 0,
		      media_addr, sizeof(media_addr),
		      flags, pm_cfgmode_client_store_arp_cb, client);

      return &client->operation;
    }

  if (status_cb) 
    (*status_cb)(pm, TRUE, status_cb_context);
  
  return NULL;

 error:
  if (status_cb) 
    (*status_cb)(pm, FALSE, status_cb_context);

  return NULL;
}

void
ssh_pm_cfgmode_client_store_unreference(SshPm pm,
					SshPmActiveCfgModeClient client)
{
  SshUInt32 hash;
  SshPmActiveCfgModeClient *clientp;

  /* Lookup the client. */
  SSH_ASSERT(client->peer_handle != SSH_IPSEC_INVALID_INDEX);
  hash = SSH_PM_CFGMODE_CLIENT_HASH(client->peer_handle);
  for (clientp = &pm->cfgmode_clients_hash[hash];
       *clientp;
       clientp = &(*clientp)->next)
    {
      if (*clientp == client)
	{
	  if (--client->refcount > 0)
	    /* This was not the last reference. */
	    return;

	  SSH_DEBUG(SSH_D_LOWOK, ("Releasing addresses `%@' and `%@'",
				  ssh_ipaddr_render, client->ip4,
				  ssh_ipaddr_render, client->ip6));

	  /* Remove it from the hash table. */
	  *clientp = client->next;

	  /* Release the IP address. */
	  if (client->free_cb)
	    {
	      if (client->ip4)
		(*client->free_cb)(pm, client->ip4,
				   client->ip4_address_context,
				   client->free_cb_context);
	      if (client->ip6)
		(*client->free_cb)(pm, client->ip6,
				   client->ip6_address_context,
				   client->free_cb_context);
	    }

	  /* And recycle the registry structure. */
	  pm_cfgmode_client_store_free(pm, client);
	  return;
	}
    }
}

void
ssh_pm_cfgmode_client_store_take_reference(SshPm pm,
					   SshPmActiveCfgModeClient client)
{
  client->refcount++;
}
#endif /* SSHDIST_ISAKMP_CFG_MODE */
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_SERVER */
