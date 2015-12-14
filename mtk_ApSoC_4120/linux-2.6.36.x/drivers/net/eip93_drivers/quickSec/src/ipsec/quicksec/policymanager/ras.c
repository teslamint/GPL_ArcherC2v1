/*
 * ras.c
 *
 * Copyright:
 *       Copyright (c) 2002 - 2009 SFNT Finland Oy.
 *       All rights reserved.
 *
 * High-level remote access server functionality.  This file
 * implements the attribute allocation functions of the high-level
 * remote access server.  This uses the low-level functions and
 * callbacks, defined in the `ras_addrpool.h' API.
 *
 */

#include "sshincludes.h"
#include "quicksecpm_internal.h"

#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_SERVER

#define SSH_DEBUG_MODULE "SshPmRemoteAccessServer"


/*************************** Types and Definitions **************************/

/** Internal address pool flag values. */
#define SSH_PM_RAS_ADDRPOOL_FLAG_REMOVED  0x0001


/*************************** Utility Functions *******************************/

/** Return address pool by id. This returns also the removed address pools. */
static SshPmAddressPool
pm_ras_get_address_pool_by_id(SshPm pm,
			      SshPmAddrPoolId id)
{
  SshPmAddressPool ap;

  for (ap = pm->addrpool; ap != NULL; ap = ap->next)
    {
      if (ap->address_pool_id == id)
	return ap;
    }

  return NULL;
}

/** Return address pool by name. This does not return removed address pools. */
static SshPmAddressPool
pm_ras_get_address_pool_by_name(SshPm pm,
				const unsigned char *name)
{
  SshPmAddressPool ap;

  for (ap = pm->addrpool; ap != NULL; ap = ap->next)
    {
      /* Skip removed address pools. */
      if (ap->flags & SSH_PM_RAS_ADDRPOOL_FLAG_REMOVED)
	continue;

      if (strcmp(ap->address_pool_name, name) == 0)
	return ap;
    }
  
  return NULL;
}

/** Map address pool name to id. This does not consider removed address
    pools. */
Boolean
ssh_pm_address_pool_get_id(SshPm pm, 
			   const unsigned char *name, 
                           SshPmAddrPoolId *id)
{
  SshPmAddressPool ap;

  SSH_ASSERT(id != NULL);
  ap = pm_ras_get_address_pool_by_name(pm, name);
  if (ap != NULL)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW,
		("Found address pool '%s' (id %d)",
		 ap->address_pool_name, ap->address_pool_id));
      *id = ap->address_pool_id;
      return TRUE;
    }

  return FALSE;
}

/** Return default address pool id. This does not consider removed address
    pools. */
Boolean
ssh_pm_address_pool_get_default_id(SshPm pm, 
				   SshPmAddrPoolId *id)
{
  SshPmAddressPool ap;

  SSH_ASSERT(id != NULL);
  ap = pm_ras_get_address_pool_by_name(pm, ADDRPOOL_DEFAULT_NAME);
  if (ap != NULL)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW,
		("Found address pool '%s' (id %d)",
		 ap->address_pool_name, ap->address_pool_id));
      *id = ap->address_pool_id;
      return TRUE;
    }
  
  return FALSE;
}

/** Remove an address pool from pm and destroy it. */
static void
pm_ras_delete_addrpool(SshPm pm,
		       SshPmAddressPool ap)
{
  SshPmAddressPool ap_prev;
  
  /* Remove address pool from pm list. */
  if (ap == pm->addrpool)
    {
      pm->addrpool = ap->next;
    }
  else
    {
      for (ap_prev = pm->addrpool;
	   ap_prev != NULL && ap_prev->next != NULL;
	   ap_prev = ap_prev->next)
	{
	  if (ap_prev->next == ap)
	    {
	      ap_prev->next = ap->next;
	      break;
	    }
	}
    }

  /* Destroy address pool. */
  ssh_pm_address_pool_destroy(ap);
  pm->num_address_pools--;
}

/** Mark an address pool removed. If the address pool has no active address
    leases then remove address pool from pm and destroy it. Otherwise the
    address pool is left in pm, but no new address are allocated from it. */
static void
pm_ras_remove_addrpool(SshPm pm,
		       SshPmAddressPool ap)
{
  
  /* Delete immediately all address pools that have no address leases. */
  if (ssh_pm_address_pool_num_allocated_addresses(ap) == 0)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW,
		("Deleting address pool, name '%s' (id %d)",
		 ap->address_pool_name, ap->address_pool_id));
      
      /* Remove from pm list and destroy addrpool. */	  
      pm_ras_delete_addrpool(pm, ap);
    }
  else
    {
      SSH_DEBUG(SSH_D_NICETOKNOW,
		("Marking address pool removed, name '%s' (id %d)",
		 ap->address_pool_name, ap->address_pool_id));
      
      /* Mark address pool removed. */
      ap->flags |= SSH_PM_RAS_ADDRPOOL_FLAG_REMOVED;
    }  
}


/***************** Default Allocate callback for RAS *************************/

/* Context structure for remote access attribute allocation state machine. */
typedef struct SshPmRasAllocCtxRec
{
  /* Thread and operation handle for the alloc operation. */
  SshFSMThreadStruct thread;
  SshOperationHandleStruct operation;

  /* Operation handle of the address pool alloc operation. */
  SshOperationHandle sub_operation;

  /* Input parameters. */
  SshIkev2ExchangeData ike_exchange_data;
  SshPmRemoteAccessAttrs requested_attributes;

  /* Result callback and context. */
  SshPmRemoteAccessAttrsAllocResultCB result_cb;
  void *result_cb_context;

  /* The tunnel or NULL if allocating from global pool. */
  SshPmTunnel tunnel;

  /* The index of the address pool. */
  SshUInt32 ap_id_index;

  /* The address pool id of the current address pool. */
  SshPmAddrPoolId id;

} *SshPmRasAllocCtx;

static void
pm_ras_addrpool_alloc_thread_destructor(SshFSM fsm, void *context)
{
  SshPm pm = ssh_fsm_get_gdata_fsm(fsm);
  SshPmRasAllocCtx ctx = (SshPmRasAllocCtx) context;

  /* Release our reference to the tunnel. */
  SSH_ASSERT(ctx->tunnel != NULL);
  SSH_PM_TUNNEL_DESTROY(pm, ctx->tunnel);
  
  /* Cleanup context. */
  if (ctx->ike_exchange_data != NULL)
    ssh_ikev2_exchange_data_free(ctx->ike_exchange_data);
  
  ssh_pm_free_remote_access_attrs(ctx->requested_attributes);
  ssh_free(ctx);
}

void
pm_ras_addrpool_alloc_abort(void *context)
{
  SshPmRasAllocCtx ctx = (SshPmRasAllocCtx) context;

  /* Abort sub operation. */
  if (ctx->sub_operation != NULL)
    ssh_operation_abort(ctx->sub_operation);

  /* Continue thread to terminal state. */
  ssh_fsm_set_next(&ctx->thread, pm_ras_addrpool_alloc_done);
  if (ssh_fsm_get_callback_flag(&ctx->thread))
    SSH_FSM_CONTINUE_AFTER_CALLBACK(&ctx->thread);
  else
    ssh_fsm_continue(&ctx->thread);
}

void
pm_ras_addrpool_alloc_result_cb(SshPmRemoteAccessAttrs attributes,
				void *context)
{
  SshPmRasAllocCtx ctx = (SshPmRasAllocCtx) context;

  /* Mark sub operation completed. */
  ctx->sub_operation = NULL;
  
  if (attributes)
    {
      /* Encode address pool id to address_context. */
      attributes->address_context = SSH_PM_UINT32_TO_PTR(ctx->id);
      SSH_DEBUG(SSH_D_HIGHOK, 
		("Allocated remote access attributes from pool id %d",
		 ctx->id));
      
      /* Pass attributes to caller. */
      (*ctx->result_cb)(attributes, ctx->result_cb_context);

      /* Finish thread. */
      ssh_operation_unregister(&ctx->operation);
      ssh_fsm_set_next(&ctx->thread, pm_ras_addrpool_alloc_done);
    }
  else
    {
      SSH_DEBUG(SSH_D_HIGHOK, 
		("Remote access attribute allocation failed from pool id %d",
		 ctx->id));

      /* Try next address pool. */
      ctx->ap_id_index++;
    }
  
  SSH_FSM_CONTINUE_AFTER_CALLBACK(&ctx->thread);
}

SSH_FSM_STEP(pm_ras_addrpool_alloc)
{
  SshPm pm = (SshPm) fsm_context;
  SshPmRasAllocCtx ctx = (SshPmRasAllocCtx) thread_context;
  SshPmAddressPool ap;
  
  SSH_FSM_SET_NEXT(pm_ras_addrpool_alloc);

  /* Try allocating from a tunnel's address pools. */
  while (ctx->ap_id_index < ctx->tunnel->num_address_pool_ids)
    {
      /* Find an Address Pool that this tunnel is configured to use. */
      ap = pm_ras_get_address_pool_by_id(pm,
					 ctx->tunnel->
					 address_pool_ids[ctx->ap_id_index]);
      if (ap != NULL 
	  && (ap->flags & SSH_PM_RAS_ADDRPOOL_FLAG_REMOVED) == 0)
	{
	  /* Attempt to allocate an address from the Address Pool. */
	  SSH_DEBUG(SSH_D_LOWOK,
		    ("Tunnel '%s': Allocating attributes from "
		     "address pool '%s' (id %d)",
		     ctx->tunnel->tunnel_name,
		     ap->address_pool_name, ap->address_pool_id));
	  
	  /* Store the address pool id to alloc context. */
	  ctx->id = ap->address_pool_id;
	  
	  SSH_FSM_ASYNC_CALL({
	    ctx->sub_operation =
	      ssh_pm_address_pool_alloc_address(ap,
					       ctx->ike_exchange_data,
					       ctx->requested_attributes,
					       pm_ras_addrpool_alloc_result_cb,
					       ctx);
	  });
	}
      
      /* No valid address pool found, try next address pool. */
      ctx->ap_id_index++;
    }
  
  /* No address pools found. Indicate allocation failure. */
  SSH_DEBUG(SSH_D_FAIL, ("Remote access attribute allocation failed"));
  (*ctx->result_cb)(NULL, ctx->result_cb_context);
  ssh_operation_unregister(&ctx->operation);

  return SSH_FSM_FINISH;
}

SSH_FSM_STEP(pm_ras_addrpool_alloc_done)
{
  /* The thread is finished. */
  return SSH_FSM_FINISH;
}

/** Remote access attribute allocation callback. */
SshOperationHandle
ssh_pm_ras_alloc_address(SshPm pm,
			 SshIkev2ExchangeData ike_exchange_data,
			 SshPmRemoteAccessAttrs requested_attributes,
			 SshPmRemoteAccessAttrsAllocResultCB result_cb,
			 void *result_cb_context,
			 void *context)
{
  SshPmTunnel tunnel;
  SshPmRasAllocCtx ctx = NULL;
  SshUInt32 tunnel_id;

  tunnel_id = SSH_PM_PTR_TO_UINT32(context);
  tunnel = ssh_pm_tunnel_get_by_id(pm, tunnel_id);
  if (tunnel == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("No tunnel found for tunnel id %d", tunnel_id));
      goto error;
    }

  /* Allocate context for the remote access attribute alloc thread. */
  ctx = ssh_calloc(1, sizeof(*ctx));
  if (ctx == NULL)
    goto error;

  ctx->ike_exchange_data = ike_exchange_data;
  if (ctx->ike_exchange_data != NULL)
    ssh_ikev2_exchange_data_take_ref(ctx->ike_exchange_data);

  ctx->requested_attributes = 
    ssh_pm_dup_remote_access_attrs(requested_attributes);
  
  ctx->result_cb = result_cb;
  ctx->result_cb_context = result_cb_context;
  SSH_ASSERT(tunnel != NULL);

  ctx->tunnel = tunnel;
  SSH_PM_TUNNEL_TAKE_REF(ctx->tunnel);

  /* Initialize operation handle for aborting the alloc thread. */
  ssh_operation_register_no_alloc(&ctx->operation,
				  pm_ras_addrpool_alloc_abort, ctx);
  
  /* Start thread. The thread attempts to allocate remote access attributes
     from the address pools configured to a tunnel or from the global address
     pool. The thread finishes on first successful allocation. Otherwise the
     thread moves to the next address pool until all configured address pools
     are tried. */
  ssh_fsm_thread_init(&pm->fsm, &ctx->thread, pm_ras_addrpool_alloc, 
		      NULL_FNPTR, pm_ras_addrpool_alloc_thread_destructor,
		      ctx);
  ssh_fsm_set_thread_name(&ctx->thread, "IKE RAS Address Pool");

  return &ctx->operation;

 error:
  if (ctx != NULL)
    ssh_free(ctx);

  /* Call result callback to indicate allocation failure. */
  (*result_cb)(NULL, result_cb_context);
  
  return NULL;
}


/********************** Default free callback for RAS ***********************/

/** Remote access address free callback. */
void
ssh_pm_ras_free_address(SshPm pm, 
			const SshIpAddr address,
			void *address_context,
			void *context)
{
  SshPmAddressPool ap;
  SshPmAddressPoolId id;

  /* The address pool id is encoded in address_context pointer. */
  id = SSH_PM_PTR_TO_UINT32(address_context);
  
  /* Lookup the address pool. */
  ap = pm_ras_get_address_pool_by_id(pm, id);
  if (ap != NULL && ssh_pm_address_pool_free_address(ap, address))
    {
      SSH_DEBUG(SSH_D_HIGHOK, 
		("Returned address '%@' to pool '%s' (id %d)", 
		 ssh_ipaddr_render, address,
		 ap->address_pool_name, ap->address_pool_id));
    }
  else
    {
      SSH_DEBUG(SSH_D_FAIL,
		("Could not return address '%@' to address pool id %d",
		 ssh_ipaddr_render, address,
		 id));
    }

  /* Check if address pool deletion is pending and delete address pool
     if this was the last missing address from the pool. */
  if (ap != NULL 
      && (ap->flags & SSH_PM_RAS_ADDRPOOL_FLAG_REMOVED)
      && ssh_pm_address_pool_num_allocated_addresses(ap) == 0)
    {
      SSH_DEBUG(SSH_D_LOWOK, ("Deleting removed address pool '%s'(id %d)",
			      ap->address_pool_name, ap->address_pool_id));
      pm_ras_delete_addrpool(pm, ap);
    }

  return;
}


/*************** Adding and Removing Address Pools to/from PM ***************/

/** Remove an Address Pool from policy manager. */
void 
ssh_pm_ras_remove_addrpool(SshPm pm,
			   const unsigned char *name)
{
  SshPmAddressPool ap, ap_next;
  
  /* Iterate through pools and remove pools that have a matching name. */
  for (ap = pm->addrpool; ap != NULL; ap = ap_next) 
    {
      ap_next = ap->next;
      
      /* Skip non-matching address pools. */
      if (name != NULL && strcmp(name, ap->address_pool_name) != 0)
	continue;
      
      pm_ras_remove_addrpool(pm, ap);
    }
  
  return;
}

/** Create and configure an address pool. */
Boolean
ssh_pm_ras_add_addrpool(SshPm pm, 
			SshPmRemoteAccessParams ras)
{
  SshPmAddressPool ap = NULL;
  SshPmAddressPool api = NULL;
  
  if (ras->name && (strlen(ras->name) == 0 
		    || strcmp(ras->name, ADDRPOOL_DEFAULT_NAME) == 0))
    
    {
      SSH_DEBUG(SSH_D_ERROR, ("Invalid address pool name"));
      return FALSE;
    }

  /* addresses input is mandatory */
  if ((!ras->addresses || strlen(ras->addresses) == 0)





      )
    {
      SSH_DEBUG(SSH_D_ERROR, ("Error, addresses cannot be empty"));
      return FALSE;
    }
  
  /* Create an address pool with passed params */
  ap = ssh_pm_address_pool_create();
  if (ap == NULL)
    {
      SSH_DEBUG(SSH_D_ERROR, 
		("Could not create remote access address pool instance"));
      return FALSE;
    }
  
  ap->pm = pm;
  ap->flags = 0;

  /* Name input should be there. If NULL, then assign default name for the
     address pool and returned the assigned in the RAS params. */
  if (!ras->name)
    {
      ap->address_pool_name = ssh_strdup(ADDRPOOL_DEFAULT_NAME);
      ras->name = ssh_strdup(ADDRPOOL_DEFAULT_NAME);
      if (ras->name == NULL)
	goto error;
    }
  else
    ap->address_pool_name = ssh_strdup(ras->name);
  
  if (ap->address_pool_name == NULL)
    goto error;
  
  ap->address_pool_id = pm->addrpool_id_next;

  /* Set attributes */
  if (!ssh_pm_address_pool_set_attributes(ap, ras->own_ip_addr, ras->dns,
					  ras->wins, ras->dhcp)) 
    goto error;
  
  /* add subnets */
  if (ras->subnets)
    {
      const unsigned char *value;
      unsigned char *subnet_str;
      
      if ((subnet_str = ssh_strdup(ras->subnets)) == NULL)
	goto error;
      
      value = strtok(subnet_str, ";");
      while (value != NULL)
        {
          SSH_DEBUG(SSH_D_HIGHOK, ("Adding subnet %s to address pool %s", 
                                   value, ap->address_pool_name));
	  if (ssh_pm_address_pool_add_subnet(ap, value) == FALSE)
	    {
	      ssh_free(subnet_str);
	      goto error;
	    }
          value = strtok(NULL, ";");
        }
      
      ssh_free(subnet_str);
    }
  
  /* add address ranges */
  if (ras->addresses)
    {
      char *value1, *address, *netmask, *addr_str;
      
      if ((addr_str = ssh_strdup(ras->addresses)) == NULL)
	goto error;
      
      value1 = strtok(addr_str, ";");
      
      while (value1)
	{
	  address = value1;
	  
	  /* goto netmask part */
	  for (netmask = value1; (*netmask) && (*netmask != '/'); netmask++);
	  
	  if (!*netmask)
	    {
	      ssh_free(addr_str);
	      goto error;
	    }
	  
	  /* add null at end of address */
	  *(netmask) = '\0';
	  
	  netmask = value1 + strlen(address) + 1;
	  
	  if (strlen(address) == 0 || strlen(netmask) == 0)
	    {
	      ssh_free(addr_str);
	      goto error;
	    }
	  
	  if (ssh_pm_address_pool_add_range(ap, address, netmask) == FALSE)
	    {
	      ssh_free(addr_str);
	      goto error;
	    }
	  
	  value1 = strtok(NULL, ";");
	}     
      
      ssh_free(addr_str);
    }










  
  /* Create afresh if there are no existing pool */ 
  if (!pm->addrpool)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("creating afresh"));
      pm->addrpool = ap;
    }

  /* if this is not first address pool, then check for duplicate */ 
  else
    {
      SshPmAddressPool prev_ap = pm->addrpool;
      
      /* check if address pool with same name exists or not */
      for(api = pm->addrpool; api != NULL; prev_ap = api, api = api->next)
	{
	  /* Ignore removed address pools. */
	  if (api->flags & SSH_PM_RAS_ADDRPOOL_FLAG_REMOVED)
	    continue;

	  if (strcmp(api->address_pool_name, ap->address_pool_name) == 0)
	    {
	      /* compare two address pools */
	      if (ssh_pm_address_pool_compare(api, ap))
                {
		  /* No change in addresspool, leave it as it is */
		  SSH_DEBUG(SSH_D_NICETOKNOW, 
			    ("Found matching unchanged addresspool, "
			     "name %s (id %d)",
			     api->address_pool_name, api->address_pool_id));
		  
		  ssh_pm_address_pool_destroy(ap);
		  return TRUE;
                }
              else
		{
                  SSH_DEBUG(SSH_D_NICETOKNOW, 
			    ("Found matching changed address pool, "
			     "name %s (id %d)",
			     api->address_pool_name, api->address_pool_id));
		  
		  /* Insert new address pool before the old one. */
		  if (api == pm->addrpool)
		    {
		      pm->addrpool = ap;
		      ap->next = api;
		    }
		  else
		    {
		      prev_ap->next = ap;
		      ap->next = api;
		    }
		  
		  /* Remove old addrpool. */
                  SSH_DEBUG(SSH_D_NICETOKNOW, 
			    ("Removing old address pool, "
			     "name %s (id %d)",
			     api->address_pool_name, api->address_pool_id));
		  pm_ras_remove_addrpool(pm, api);
		  goto out;
		}
	    }
	}
      SSH_ASSERT(api == NULL && prev_ap != NULL);
      
      /* No matching addrpool found, create new one at the end of list*/
      prev_ap->next = ap;
    }
  
  /* Increment address pool count */
  pm->num_address_pools++;
  
 out:
  if (ap->address_pool_id == pm->addrpool_id_next)
    pm->addrpool_id_next++;
  
  SSH_DEBUG(SSH_D_HIGHOK, ("Created addrpool, name %s, (id %d)", 
			   ap->address_pool_name, 
			   ap->address_pool_id));
  
  return TRUE;
  
 error:
  if (ap) 
    ssh_pm_address_pool_destroy(ap);
  
  /* Free the address pool name that this function has allocated
     because no name was given in params. */
  if (ras->name != NULL && strcmp(ras->name, ADDRPOOL_DEFAULT_NAME) == 0)
    {
      ssh_free(ras->name);
      ras->name = NULL;
    }

  return FALSE;
}

#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_SERVER */
