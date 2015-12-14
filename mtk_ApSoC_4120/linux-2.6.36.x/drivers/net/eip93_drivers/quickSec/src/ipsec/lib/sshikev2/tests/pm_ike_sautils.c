/*
 *
 * Author: Tero Kivinen <kivinen@iki.fi>
 *
 *  Copyright:
 *          Copyright (c) 2004,2005 SFNT Finland Oy.
 */
/*
 *        Program: sshikev2
 *        $Author: bruce.chang $
 *
 *        Creation          : 09:40 Jan 24 2005 kivinen
 *        Last Modification : 10:02 Jan 24 2005 kivinen
 *        Last check in     : $Date: 2012/09/28 $
 *        Revision number   : $Revision: #1 $
 *        State             : $State: Exp $
 *        Version           : 1.3
 *        
 *
 *        Description       : IKEv2 SA utility functions
 *
 *
 *        $Log: pm_ike_sautils.c,v $
 *        Revision 1.1.2.1  2011/01/31 03:29:29  treychen_hc
 *        add eip93 drivers
 * *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        $EndLog$
 */

#include "sshincludes.h"
#include "sshikev2-initiator.h"
#include "sshikev2-util.h"
#include "pm_ike_sad.h"

#define SSH_DEBUG_MODULE "SshPmIkev2SaUtil"

/* XXX Add prealloc */
/* XXX Add limit of number of SA records. */

/***********************************************************************/
/* 			Internal functions. 			       */
/***********************************************************************/

/* Allocate new SA payload. */
SshIkev2PayloadSA
ssh_ikev2_sa_allocate_new(SshSADHandle sad_handle)
{
  SshIkev2PayloadSA sa;

  /* XXX Increment count, and verify limits. */
  sa = ssh_calloc(1, sizeof(*sa));
  if (sa == NULL)
    return sa;
  /* Preallocate some transforms. */
  /* XXX Make this configurable later. */
  sa->number_of_transforms_allocated = SSH_IKEV2_SA_TRANSFORMS_PREALLOC;
  sa->transforms = ssh_calloc(sa->number_of_transforms_allocated,
			     sizeof(*(sa->transforms)));
  if (sa->transforms == NULL)
    sa->number_of_transforms_allocated = 0;

  return sa;
}

/* Free SA payload, it must not be in the free list
   anymore. */
void
ssh_ikev2_sa_destroy(SshSADHandle sad_handle, SshIkev2PayloadSA sa)
{
  /* XXX decrement limit count. */
  ssh_free(sa->transforms);
  sa->transforms = NULL;
  ssh_free(sa);
}

/* Init free list of SA payloads. Return TRUE if
   successfull. */
Boolean
ssh_ikev2_sa_freelist_create(SshSADHandle sad_handle)
{
  sad_handle->sa_free_list =
    ssh_adt_create_generic(SSH_ADT_LIST,
			   SSH_ADT_HEADER,
			   SSH_ADT_OFFSET_OF(SshIkev2PayloadSAStruct,
					     free_list_header),
			   SSH_ADT_ARGS_END);
  if (sad_handle->sa_free_list == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Out of memory, allocating server_list"));
      return FALSE;
    }
  /* XXX Do prealloc here. */
  return TRUE;
}

/* Destroy free list of SA payloads.  */
void
ssh_ikev2_sa_freelist_destroy(SshSADHandle sad_handle)
{
  if (sad_handle->sa_free_list)
    {
      SshIkev2PayloadSA sa;
      SshADTHandle h;

      while ((h = ssh_adt_enumerate_start(sad_handle->sa_free_list)) !=
	     SSH_ADT_INVALID)
	{
	  sa = ssh_adt_get(sad_handle->sa_free_list, h);
	  SSH_ASSERT(sa != NULL);
	  ssh_adt_detach_object(sad_handle->sa_free_list, sa);
	  ssh_ikev2_sa_destroy(sad_handle, sa);
	}
      SSH_ASSERT(ssh_adt_num_objects(sad_handle->sa_free_list) == 0);
      ssh_adt_destroy(sad_handle->sa_free_list);
    }
  sad_handle->sa_free_list = NULL;
}

/***********************************************************************/
/* 			External functions. 			       */
/***********************************************************************/

/* Allocate SA payload. The initial SA is empty. This will
   take it from the free list in SAD, or return NULL if no
   entries available. */
SshIkev2PayloadSA
ssh_ikev2_sa_allocate(SshSADHandle sad_handle)
{
  SshIkev2PayloadSA sa;

  sa = NULL;
  if (ssh_adt_num_objects(sad_handle->sa_free_list) > 0)
    sa = ssh_adt_detach_from(sad_handle->sa_free_list, SSH_ADT_BEGINNING);
  if (sa == NULL)
    sa = ssh_ikev2_sa_allocate_new(sad_handle);
  if (sa == NULL)
    return NULL;
  sa->ref_cnt = 1;
  sa->number_of_transforms_used = 0;
  memset(sa->protocol_id, 0, sizeof(sa->protocol_id));
  memset(sa->number_of_transforms, 0, sizeof(sa->number_of_transforms));
  memset(sa->proposals, 0, sizeof(sa->proposals));
  return sa;
}

/* Free SA payload. This will return it back to the free
   list if this was last reference */
void
ssh_ikev2_sa_free(SshSADHandle sad_handle,
		  SshIkev2PayloadSA sa)
{
  SSH_ASSERT(sa->ref_cnt != 0);

  /* Decrement reference count, and check whether we still have references. */
  sa->ref_cnt--;
  if (sa->ref_cnt != 0)
    {
      /* Yes. */
      return;
    }
  /* No references, free or move it to free list. */

  /* Verify if we need to free it immediately, i.e. if free
     list have too many items, then we simply free it,
     instead of putting it to the free list. */
  /* XXX Verify if we need to free it now */
  /* Put it back to free list. */
  ssh_adt_insert(sad_handle->sa_free_list, sa);
}
