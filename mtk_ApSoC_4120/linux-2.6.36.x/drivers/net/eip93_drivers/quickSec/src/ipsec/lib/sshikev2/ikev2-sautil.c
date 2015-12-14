/*
 *
 * Author: Tero Kivinen <kivinen@iki.fi>
 *
 *  Copyright:
 *          Copyright (c) 2004, 2005 SFNT Finland Oy.
 */
/*
 *        Program: sshikev2
 *        $Author: bruce.chang $
 *
 *        Creation          : 15:30 Aug 18 2004 kivinen
 *        Last Modification : 16:05 May 14 2009 kivinen
 *        Last check in     : $Date: 2012/09/28 $
 *        Revision number   : $Revision: #1 $
 *        State             : $State: Exp $
 *        Version           : 1.150
 *        
 *
 *        Description       : IKEv2 SA utility functions
 *
 *
 *        $Log: ikev2-sautil.c,v $
 *        Revision 1.1.2.1  2011/01/31 03:29:20  treychen_hc
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
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
 *        
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
#include "sshdebug.h"

#define SSH_DEBUG_MODULE "SshIkev2SaUtil"

/* Duplicate SA payload. This will take new entry from the
   free list and copy data from the current SA data in to
   it. This will return NULL if no free SA payloads
   available. */
SshIkev2PayloadSA
ssh_ikev2_sa_dup(SshSADHandle sad_handle,
		 SshIkev2PayloadSA sa)
{
  SshIkev2PayloadSA sa_copy;
  int i;

  sa_copy = ssh_ikev2_sa_allocate(sad_handle);
  if (sa_copy == NULL)
    return NULL;

  sa_copy->proposal_number = sa->proposal_number;
  memcpy(sa_copy->protocol_id, sa->protocol_id, sizeof(sa->protocol_id));
  memcpy(sa_copy->number_of_transforms, sa->number_of_transforms,
	 sizeof(sa->number_of_transforms));

  /* Copy items. */
  if (sa->number_of_transforms_used > sa_copy->number_of_transforms_allocated)
    {
      sa_copy->transforms =
	ssh_realloc(sa_copy->transforms,
		    sa_copy->number_of_transforms_allocated *
		    sizeof(*(sa_copy->transforms)),
		    sa->number_of_transforms_used *
		    sizeof(*(sa_copy->transforms)));
      if (sa_copy->transforms == NULL)
	{
	  sa_copy->number_of_transforms_allocated = 0;
	  return NULL;
	}
      sa_copy->number_of_transforms_allocated = sa->number_of_transforms_used;
    }
  memcpy(sa_copy->transforms, sa->transforms,
	 sa->number_of_transforms_used * sizeof(*(sa->transforms)));
  sa_copy->number_of_transforms_used = sa->number_of_transforms_used;


  for(i = 0; i < SSH_IKEV2_SA_MAX_PROPOSALS; i++)
    {
      if (sa->proposals[i] != NULL)
	{
	  sa_copy->proposals[i] =
	    &(sa_copy->transforms[(sa->proposals[i] - sa->transforms)]);
	}
    }
  return sa_copy;
}

/* Take extra reference to the SA payload. */
void
ssh_ikev2_sa_take_ref(SshSADHandle sad_handle,
		      SshIkev2PayloadSA sa)
{
  sa->ref_cnt++;
}

/* Add transform to the SA payload. This will add new entry
   to the end of the list. */
SshIkev2Error
ssh_ikev2_sa_add(SshIkev2PayloadSA sa,
		 SshUInt8 proposal_index,
		 SshIkev2TransformType type,
		 SshIkev2TransformID id,
		 SshUInt32 transform_attribute)
{
  SshIkev2PayloadTransform transform;

  if (sa->number_of_transforms_used >= sa->number_of_transforms_allocated)
    {
      transform = sa->transforms;
      /* XXX Check memory limits here */
      if (!ssh_recalloc(&(sa->transforms),
			&(sa->number_of_transforms_allocated),
			sa->number_of_transforms_allocated +
			SSH_IKEV2_SA_TRANSFORMS_ADD,
			sizeof(*(sa->transforms))))
	{
	  return SSH_IKEV2_ERROR_OUT_OF_MEMORY;
	}
      if (transform != sa->transforms)
	{
	  int i;
	  for(i = 0; i < SSH_IKEV2_SA_MAX_PROPOSALS; i++)
	    {
	      if (sa->proposals[i] != NULL)
		{
		  sa->proposals[i] =
		    &(sa->transforms[(sa->proposals[i] - transform)]);
		}
	    }
	}
    }
  transform = &(sa->transforms[sa->number_of_transforms_used]);
  transform->type = type;
  transform->id = id;
  transform->transform_attribute = transform_attribute;
  sa->number_of_transforms[proposal_index]++;
  if (sa->proposals[proposal_index] == NULL)
    sa->proposals[proposal_index] = transform;
  sa->number_of_transforms_used++;
  return SSH_IKEV2_ERROR_OK;
}

/* This routine checks if an ESP NULL-NULL proposal is included in the 
   proposals 'input_sa', return TRUE if an ESP NULL-NULL proposal is 
   present and FALSE otherwise. */
Boolean ikev2_proposal_is_esp_null_null(SshIkev2PayloadSA input_sa)
{
  SshIkev2PayloadTransform first_tr, tr;
  int proposal = 0, i;

  for (proposal = 0; proposal < SSH_IKEV2_SA_MAX_PROPOSALS; proposal++)
    {
      Boolean have_encr = FALSE, have_integ = FALSE;

      if (input_sa->protocol_id[proposal] == 0)
	break;
      
      if (input_sa->protocol_id[proposal] != SSH_IKEV2_PROTOCOL_ID_ESP)
	continue;
      
      first_tr = input_sa->proposals[proposal];
      
      for (i = 0; i < input_sa->number_of_transforms[proposal]; i++)
	{
	  tr = first_tr + i;

	  /* Check that type is valid. */
	  if (tr->type >= SSH_IKEV2_TRANSFORM_TYPE_MAX)
	    break;

	  /* Do we have an integrity algorithm? */
          if (tr->type == SSH_IKEV2_TRANSFORM_TYPE_INTEG && 
	      tr->id != SSH_IKEV2_TRANSFORM_AUTH_NONE)
            have_integ = TRUE;
	  
	  /* Do we have an encryption algorithm? */
	  if (tr->type == SSH_IKEV2_TRANSFORM_TYPE_ENCR &&
	      tr->id != SSH_IKEV2_TRANSFORM_ENCR_NULL)
            have_encr = TRUE;
	}
      if (!have_encr && !have_integ)
	return TRUE;
    }
  
  return FALSE;
}


/*--------------------------------------------------------------------*/
/* The following SA matching function has two alterinative
   implementations for your convenience. The first one flattens all
   policy algorithms into single ala-carte menu, and the latter keeps
   each proposal as a separate suite. Ala-carte is the default.       */
/*--------------------------------------------------------------------*/


#if 1
/* Take first algorithm for each transforms from input_sa, so that
   they are allowed by the policy_sa. Fill in the proposal_index and
   array suitable to be returned to the policy function. Return TRUE
   if successful, and FALSE if no proposal can be returned. */
Boolean
ssh_ikev2_sa_select(SshIkev2PayloadSA input_sa,
		    SshIkev2PayloadSA policy_sa,
		    int *proposal_index,
		    SshIkev2PayloadTransform
		    selected_transforms[SSH_IKEV2_TRANSFORM_TYPE_MAX],
		    SshIkev2SaSelectionError *failure_mask)
{









  Boolean seen_transform[SSH_IKEV2_TRANSFORM_TYPE_MAX];
  Boolean mandated[SSH_IKEV2_TRANSFORM_TYPE_MAX];
  SshIkev2PayloadTransform first_tr, tr, tr_integ_null;
  SshIkev2SaSelectionError failure = SSH_IKEV2_SA_SELECTION_ERROR_OK;
  int proposal, i, j;

  /* Check for ESP NULL-NULL proposals */
  if (ikev2_proposal_is_esp_null_null(input_sa))
    {
      if (failure_mask)
	*failure_mask |= SSH_IKEV2_SA_SELECTION_ERROR_ESP_NULL_NULL;
      return FALSE;
    }

  SSH_DEBUG(SSH_D_MIDSTART, ("input_sa: %.1@", 
			     ssh_ikev2_payload_sa_render, input_sa));
  SSH_DEBUG(SSH_D_MIDSTART, ("policy_sa: %.1@", 
			     ssh_ikev2_payload_sa_render, policy_sa));







  memset(mandated, 0, sizeof(mandated));
  for(j = 0; j < policy_sa->number_of_transforms_used; j++)
    {
      if (policy_sa->transforms[j].type >= SSH_IKEV2_TRANSFORM_TYPE_MAX)
	continue;
      mandated[policy_sa->transforms[j].type] =
	policy_sa->transforms[j].id != 0;
    }















































































































































































  /* Go through all proposals, and pick first proposal that is allowed
     by out policy. For each transform type, the first seen acceptable
     transform is used. */
  for (proposal = 0; proposal < SSH_IKEV2_SA_MAX_PROPOSALS; proposal++)
    {
      if (input_sa->protocol_id[proposal] == 0)
        {
	  break;
	}

      first_tr = input_sa->proposals[proposal];
      memset(selected_transforms, 0, sizeof(*selected_transforms) *
	     SSH_IKEV2_TRANSFORM_TYPE_MAX);
      memset(seen_transform, 0, sizeof(seen_transform));
      tr_integ_null = NULL;

      /* Go through all transforms in the proposal. */
      for (i = 0; i < input_sa->number_of_transforms[proposal]; i++)
	{
	  tr = first_tr + i;
	  /* Check that type is valid, if not skip this proposal. */
	  if (tr->type >= SSH_IKEV2_TRANSFORM_TYPE_MAX)
	    break;

	  /* Mark it as seen. */
	  seen_transform[tr->type] = TRUE;
  
          /* Notice if this was null integ transform for combined algorithm 
             handling. */
          if (tr->type == SSH_IKEV2_TRANSFORM_TYPE_INTEG && 
	      tr->id == SSH_IKEV2_TRANSFORM_AUTH_NONE)
            tr_integ_null = tr;

	  /* Check if we already have transform for this algorithm. */
	  if (selected_transforms[tr->type] != NULL)
	    continue;
	  /* Try to find matching transform from the policy. */
	  for(j = 0; j < policy_sa->number_of_transforms_used; j++)
	    {
	      if (tr->type == policy_sa->transforms[j].type &&
		  tr->id == policy_sa->transforms[j].id &&
		  tr->transform_attribute ==
		  policy_sa->transforms[j].transform_attribute)
		{
		  /* Found suitable algorithm, select it. */
		  selected_transforms[tr->type] = tr;
		  break;
		}
	      else 
		{
		  /* Check if failure was due to attribute mismatch only */
		  if (tr->type == policy_sa->transforms[j].type &&
		      tr->id == policy_sa->transforms[j].id)
		    failure |= SSH_IKEV2_SA_SELECTION_ERROR_ATTR_MISMATCH;
		}
	    }
	}
      /* If we selected some combined algorithm as cipher, ensure
         we do not get any integrity algorithm with it. Additionally,
         we'll accept it as integrity algorithm as it contains one as
         built-in. */
      if (selected_transforms[SSH_IKEV2_TRANSFORM_TYPE_ENCR])
	{
	  switch(selected_transforms[SSH_IKEV2_TRANSFORM_TYPE_ENCR]->id)
	    {
	    case SSH_IKEV2_TRANSFORM_ENCR_AES_GCM_8:
	    case SSH_IKEV2_TRANSFORM_ENCR_AES_GCM_12:
	    case SSH_IKEV2_TRANSFORM_ENCR_AES_GCM_16:
	    case SSH_IKEV2_TRANSFORM_ENCR_NULL_AUTH_AES_GMAC:
	      if (selected_transforms[SSH_IKEV2_TRANSFORM_TYPE_INTEG] &&
		  selected_transforms[SSH_IKEV2_TRANSFORM_TYPE_INTEG]->id !=
		  SSH_IKEV2_TRANSFORM_AUTH_NONE)
		{
		  /* Try to fix this by setting integ to NULL if 
		     policy had that choice available. */
		  if (tr_integ_null)
		    selected_transforms[SSH_IKEV2_TRANSFORM_TYPE_INTEG] =
		      tr_integ_null;
		  else
		    {
		      i = 0; /* No choice without integrity algorithm. */
		    }
		}
	      /* With combined algorithm integrity is not mandated. */
	      if (mandated[SSH_IKEV2_TRANSFORM_TYPE_INTEG])
		mandated[SSH_IKEV2_TRANSFORM_TYPE_INTEG] = FALSE;
	      break;
	    default: /* Nothing to be done */
	      break;
	    }
	}
 
      /* If we didn't find any error, check if we found
	 transforms for each algorithm.  */
      if (i == input_sa->number_of_transforms[proposal])
	{
	  /* Check if we did find algorithm for each
	     transform in the input sa. */
	  for(i = 0; i < SSH_IKEV2_TRANSFORM_TYPE_MAX; i++)
	    {
	      if ((seen_transform[i] || mandated[i]) &&
		  selected_transforms[i] == NULL)
		break;
	    }
	  if (i == SSH_IKEV2_TRANSFORM_TYPE_MAX)
	    {
	      /* Yes, this is suitable proposal, return this. */
	      *proposal_index = proposal;
#if DEBUG_LIGHT
	      {
		int k;
		SSH_DEBUG(SSH_D_MIDOK,("Proposal %d chosen with "
				       "fallback algorithm", proposal));
		for(k = 0; k < SSH_IKEV2_TRANSFORM_TYPE_MAX; k++)
		  {
		    if (selected_transforms[k]) 
		      { 
			SSH_DEBUG(SSH_D_LOWOK, 
				  ("  %s", 
				   ssh_ikev2_transform_to_string(
				     selected_transforms[k]->type, 
				     selected_transforms[k]->id)));
		      }
		  }
	      }
#endif /* DEBUG_LIGHT */
	      return TRUE;
	    }
	}

      /* Ok, either there were some unsupported transform
	 types in the proposal, or we didn't find
	 acceptable transform for each algorithm, so try
	 next proposals. */

      /* Record the failure mask for the current proposal. */
      for(i = 0; i < SSH_IKEV2_TRANSFORM_TYPE_MAX; i++)
	{
	  if ((seen_transform[i] || mandated[i]) &&
	      selected_transforms[i] == NULL)
	    {
	      switch (i)
		{
		case SSH_IKEV2_TRANSFORM_TYPE_ENCR:
		  failure |= SSH_IKEV2_SA_SELECTION_ERROR_ENCR_MISMATCH;
		  break;
		case SSH_IKEV2_TRANSFORM_TYPE_PRF:
		  failure |= SSH_IKEV2_SA_SELECTION_ERROR_PRF_MISMATCH;
		  break;
		case SSH_IKEV2_TRANSFORM_TYPE_INTEG:
		  failure |= SSH_IKEV2_SA_SELECTION_ERROR_INTEG_MISMATCH;
		  break;	
		case SSH_IKEV2_TRANSFORM_TYPE_D_H:
		  failure |= SSH_IKEV2_SA_SELECTION_ERROR_D_H_MISMATCH;
		  break;
		case SSH_IKEV2_TRANSFORM_TYPE_ESN:
		  failure |= SSH_IKEV2_SA_SELECTION_ERROR_ESN_MISMATCH;
		  break;
		}
	    } 
	}
    }

  if (failure_mask)
    *failure_mask |= failure;

  SSH_DEBUG(SSH_D_MIDRESULT, ("Proposal not chosen: failure = 0x%x",
			      (unsigned int) failure));

  /* We didn't find usable proposal, return error. */
  return FALSE;
}
#else /* 0 */
/* The the first input proposal that matches the policy proposal. */
Boolean
ssh_ikev2_sa_select(SshIkev2PayloadSA input_sa,
		    SshIkev2PayloadSA policy_sa,
		    int *proposal_index,
		    SshIkev2PayloadTransform
		    selected_transforms[SSH_IKEV2_TRANSFORM_TYPE_MAX],
		    SshIkev2SaSelectionError *failure_mask)
{
  Boolean seen_transform[SSH_IKEV2_TRANSFORM_TYPE_MAX];
  Boolean mandated[SSH_IKEV2_TRANSFORM_TYPE_MAX];
  SshIkev2PayloadTransform first_tr, tr, first_ptr, ptr, tr_integ_null;
  SshIkev2SaSelectionError failure = SSH_IKEV2_SA_SELECTION_ERROR_OK;
  int iprop, pprop, i, j;

  if (ikev2_proposal_is_esp_null_null(input_sa))
    {
      if (failure_mask)
	*failure_mask |= SSH_IKEV2_SA_SELECTION_ERROR_ESP_NULL_NULL;
      return FALSE;
    }

  memset(mandated, 0, sizeof(mandated));
  for(j = 0; j < policy_sa->number_of_transforms_used; j++)
    {
      if (policy_sa->transforms[j].type >= SSH_IKEV2_TRANSFORM_TYPE_MAX)
	continue;
      mandated[policy_sa->transforms[j].type] =
	policy_sa->transforms[j].id != 0;
    }

  /* Go through all input proposals. */
  for (iprop = 0;
       iprop < SSH_IKEV2_SA_MAX_PROPOSALS;
       iprop++)
    {
      if (input_sa->protocol_id[iprop] == 0)
        {
	  break;
	}
      
      first_tr = input_sa->proposals[iprop];

      for (pprop = 0;
	   pprop < SSH_IKEV2_SA_MAX_PROPOSALS;
	   pprop++)
	{
	  if (policy_sa->protocol_id[pprop] == 0)
	    break;

	  first_ptr = policy_sa->proposals[pprop];
          tr_integ_null = NULL;

	  memset(selected_transforms, 0, sizeof(*selected_transforms) *
		 SSH_IKEV2_TRANSFORM_TYPE_MAX);
	  memset(seen_transform, 0, sizeof(seen_transform));

	  /* Go through all transforms in the input proposal. */
	  for (i = 0; i < input_sa->number_of_transforms[iprop]; i++)
	    {
	      tr = first_tr + i;
	      /* Check that type is valid, if not skip this proposal. */
	      if (tr->type >= SSH_IKEV2_TRANSFORM_TYPE_MAX)
		break;

	      /* Mark it as seen. */
	      seen_transform[tr->type] = TRUE;

             /* Notice if this was null integ transform for combined algorithm 
                handling. */
             if (tr->type == SSH_IKEV2_TRANSFORM_TYPE_INTEG && 
		 tr->id == SSH_IKEV2_TRANSFORM_AUTH_NONE)
               tr_integ_null = tr;

	      /* Check if we already have transform for this algorithm. */
	      if (selected_transforms[tr->type] != NULL)
		continue;


	      /* Try to find matching transform from the policy. */
	      for (j = 0;
		   j < policy_sa->number_of_transforms[pprop];
		   j++)
		{
		  ptr = first_ptr + j;

		  if (tr->type == ptr->type
		      && tr->id == ptr->id
		      && tr->transform_attribute == ptr->transform_attribute)
		    {
		      /* Found suitable algorithm, select it. */
		      selected_transforms[tr->type] = tr;
		      break;
		    }
		}
	    }
	}

      /* If we selected some combined algorithm as cipher, ensure
         we do not get any integrity algorithm with it. Additionally,
         we'll accept it as integrity algorithm as it contains one as
         built-in. */
      switch(selected_transforms[SSH_IKEV2_TRANSFORM_TYPE_ENCR]?
	     (int)selected_transforms[SSH_IKEV2_TRANSFORM_TYPE_ENCR]->id : 0)
	{
	case SSH_IKEV2_TRANSFORM_ENCR_AES_GCM_8:
	case SSH_IKEV2_TRANSFORM_ENCR_AES_GCM_12:
	case SSH_IKEV2_TRANSFORM_ENCR_AES_GCM_16:
	case SSH_IKEV2_TRANSFORM_ENCR_NULL_AUTH_AES_GMAC:       
	  if (selected_transforms[SSH_IKEV2_TRANSFORM_TYPE_INTEG] &&
	      selected_transforms[SSH_IKEV2_TRANSFORM_TYPE_INTEG]->id !=
              SSH_IKEV2_TRANSFORM_AUTH_NONE)
	    {
              /* Try to fix this by setting integ to NULL if 
                 policy had that choice available. */
              if (tr_integ_null)
                selected_transforms[SSH_IKEV2_TRANSFORM_TYPE_INTEG] =
                       tr_integ_null;
              else
                {
                  i = 0; /* No choice without integrity algorithm. */
                }
            }
          /* With combined algorithm integrity is not mandated. */
          if (mandated[SSH_IKEV2_TRANSFORM_TYPE_INTEG])
            mandated[SSH_IKEV2_TRANSFORM_TYPE_INTEG] = FALSE;
	}          

      /* If we didn't find any error, check if we found
	 transforms for each algorithm.  */
      if (i == input_sa->number_of_transforms[iprop])
	{
	  /* Check if we did find algorithm for each
	     transform in the input sa. */
	  for(i = 0; i < SSH_IKEV2_TRANSFORM_TYPE_MAX; i++)
	    {
	      if ((seen_transform[i] || mandated[i]) &&
		  selected_transforms[i] == NULL)
		break;
	    }
	  if (i == SSH_IKEV2_TRANSFORM_TYPE_MAX)
	    {
	      /* Yes, this is suitable proposal, return this. */
	      *proposal_index = iprop;
	      return TRUE;
	    }
	}
      /* Ok, either there were some unsupported transform
	 types in the proposal, or we didn't find
	 acceptable transform for each algorithm, so try
	 next proposals. */
    }

  if (failure_mask)
    *failure_mask |= failure;

  /* We didn't find usable proposal, return error. */
  return FALSE;
}
#endif /* 0 */

