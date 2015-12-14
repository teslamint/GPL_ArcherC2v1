/*
  File: sad-dummy.c

  Copyright:
        Copyright 2004 SFNT Finland Oy.
	All rights reserved.

  Description:
  	Dummy SAD module
*/

#include "sshincludes.h"
#include "sshencode.h"

#include "sshadt.h"
#include "sshadt_map.h"

#include "sshikev2-initiator.h"
#include "sshikev2-exchange.h"
#include "sshikev2-sad.h"
#include "sshikev2-util.h"
#include "sshikev2-fallback.h"

#include "sad-dummy.h"
#include "pad-dummy.h"

#define SSH_DEBUG_MODULE "TestIkev2SAD"

/* IKE SA */
SshOperationHandle
d_sad_ike_sa_allocate(SshSADHandle sad_handle,
		      Boolean initiator,
		      SshIkev2SadIkeSaAllocateCB reply_callback,
		      void *reply_callback_context)
{
  SshIkev2Error status = SSH_IKEV2_ERROR_OK;
  SshIkev2Sa sa;
  unsigned char *spi;
  int i;

  SSH_DEBUG(SSH_D_HIGHSTART, ("Enter"));

  if ((sa = ssh_calloc(1, sizeof(*sa))) == NULL)
    {
      status = SSH_IKEV2_ERROR_OUT_OF_MEMORY;
      goto done;
    }
  else
    {
      SSH_IP_UNDEFINE(sa->remote_ip);
      sa->ref_cnt = 0;
      if (initiator)
	{
	  spi = sa->ike_spi_i;
	  sa->flags |= SSH_IKEV2_IKE_SA_FLAGS_INITIATOR;
	}
      else
	{
	  spi = sa->ike_spi_r;
	}
    }

 again:
  /* Assign SPI, and store SA */
  for (i = 0; i < sizeof(sa->ike_spi_i); i++)
    spi[i] = ssh_random_get_byte();

  if (ssh_adt_get_handle_to_equal(sad_handle->ike_sa_by_spi, sa)
      != SSH_ADT_INVALID)
    goto again;

  SSH_DEBUG(SSH_D_HIGHSTART, ("Returning SA %p", sa));

  ssh_adt_insert(sad_handle->ike_sa_by_spi, sa);

 done:
  (*reply_callback)(status,
		    sa,
		    reply_callback_context);

  return NULL;

}

void d_sad_ike_sa_delete_abort(void *context)
{
  SshIkev2Sa sa = context;

  ssh_free(sa->waiting_for_delete);
  sa->waiting_for_delete = NULL;
}

void d_sad_ike_sa_delete_old(void *context)
{
  SshIkev2Sa old_sa = context;
  SSH_DEBUG(SSH_D_HIGHSTART, ("Deleteing old IKE SA %p", old_sa));
  ssh_ikev2_ike_sa_delete(old_sa, 0, NULL);
}

SshOperationHandle
d_sad_ike_sa_delete(SshSADHandle sad_handle,
		    SshIkev2Sa sa,
		    SshIkev2SadDeleteCB reply_callback,
		    void *reply_callback_context)
{
  SshIkev2Error status = SSH_IKEV2_ERROR_OK;
  SshADTHandle handle;

  SSH_DEBUG(SSH_D_HIGHSTART, ("Enter SA %p", sa));

  SSH_ASSERT(sa->waiting_for_delete == NULL);
  SSH_ASSERT(sa->ref_cnt >= 1);
  sa->ref_cnt--;

  if (sa->ref_cnt > 0)
    {
      SSH_DEBUG(SSH_D_HIGHSTART, ("SA have %d references, waiting",
				  (int) sa->ref_cnt));
      sa->waiting_for_delete = ssh_calloc(1, sizeof(*sa->waiting_for_delete));
      if (sa->waiting_for_delete == NULL)
	{
	  if (reply_callback)
	    {
	      (*reply_callback)(SSH_IKEV2_ERROR_OUT_OF_MEMORY,
				reply_callback_context);
	    }
	  return NULL;
	}
      sa->waiting_for_delete->delete_callback = reply_callback;
      sa->waiting_for_delete->delete_callback_context = reply_callback_context;
      ssh_operation_register_no_alloc(sa->waiting_for_delete->operation_handle,
				      d_sad_ike_sa_delete_abort, sa);
      return sa->waiting_for_delete->operation_handle;
    }

  if ((handle = ssh_adt_get_handle_to_equal(sad_handle->ike_sa_by_spi, sa))
      != SSH_ADT_INVALID)
    ssh_adt_detach(sad_handle->ike_sa_by_spi, handle);

  ssh_cancel_timeouts(d_sad_ike_sa_delete_old, sa);
  ssh_ikev2_ike_sa_uninit(sa);
  ssh_free(sa);

  if (reply_callback)
    (*reply_callback)(status,
		      reply_callback_context);


  return NULL;
}

SshOperationHandle
d_sad_ike_sa_rekey(SshSADHandle sad_handle,
		   Boolean delete_old,
		   SshIkev2Sa old_sa,
		   SshIkev2Sa new_sa,
		   SshIkev2SadRekeyedCB reply_callback,
		   void *reply_callback_context)
{
  SshIkev2Error status = SSH_IKEV2_ERROR_OK;

  SSH_DEBUG(SSH_D_HIGHSTART, ("Enter old SA %p new SA %p, delete old = %s",
			      old_sa, new_sa,
			      delete_old ? "TRUE" : "FALSE"));
  if (delete_old)
    {
      ssh_xregister_timeout(3, 0, d_sad_ike_sa_delete_old, old_sa);
    }

  (*reply_callback)(status,
		    reply_callback_context);

  return NULL;
}


#ifdef SSHDIST_IKEV1
extern SshIkev2 ikev2;
#endif /* SSHDIST_IKEV1 */ 

SshOperationHandle
d_sad_ike_sa_get(SshSADHandle sad_handle,
		 const SshUInt32 ike_version,
		 const unsigned char *ike_sa_spi_i,
		 const unsigned char *ike_sa_spi_r,
		 SshIkev2SadIkeSaGetCB reply_callback,
		 void *reply_callback_context)
{
  SshIkev2Error status = SSH_IKEV2_ERROR_OK;
  SshIkev2SaStruct probe;
  SshIkev2Sa sa = NULL;
  SshADTHandle handle;

  SSH_DEBUG(SSH_D_HIGHSTART, ("Enter"));

  if (ike_version >= 2)
    {
      memset(&probe, 0, sizeof(probe));
      
      if (ike_sa_spi_i)
	memcpy(probe.ike_spi_i, ike_sa_spi_i, sizeof(probe.ike_spi_i));
      else
	memcpy(probe.ike_spi_i, ike_sa_spi_r, sizeof(probe.ike_spi_i));
      probe.flags |= SSH_IKEV2_IKE_SA_FLAGS_INITIATOR;
      
      handle = ssh_adt_get_handle_to_equal(sad_handle->ike_sa_by_spi, &probe);
      if (handle == SSH_ADT_INVALID)
	{
	  if (ike_sa_spi_i)
	    memcpy(probe.ike_spi_r, ike_sa_spi_i, sizeof(probe.ike_spi_r));
	  else
	    memcpy(probe.ike_spi_r, ike_sa_spi_r, sizeof(probe.ike_spi_r));
	  probe.flags &= ~SSH_IKEV2_IKE_SA_FLAGS_INITIATOR;
	  
	  handle = ssh_adt_get_handle_to_equal(sad_handle->ike_sa_by_spi, 
					       &probe);
	}
      
      if (handle)
	{
	  sa = ssh_adt_get(sad_handle->ike_sa_by_spi, handle);
	  sa->ref_cnt++;
	}
    }
#ifdef SSHDIST_IKEV1
  else if (ike_version == 1)
    {
      /* Return non-NULL SA for IKEv1 fallbacked SA's. They are all
	 managed inside IKEv1 library, and we know nothing about them
	 (except that the ikev2-recv.c does not use those for version 1
	 packet reception. */
      if (ssh_ikev2_fb_get_sa(ikev2, ike_sa_spi_i,
			      ike_sa_spi_r))
	sa = (SshIkev2Sa) SSH_IKEV2_FB_IKEV1_SA;
      
      SSH_DEBUG(SSH_D_HIGHSTART, ("Returning SA %p", sa));
      (*reply_callback)(status, sa, reply_callback_context);
      return NULL;
    }
#endif /* SSHDIST_IKEV1 */
  else
    status = SSH_IKEV2_ERROR_INVALID_MAJOR_VERSION;

  SSH_DEBUG(SSH_D_HIGHSTART, ("Returning SA %p", sa));

  (*reply_callback)(status,
		    sa,
		    reply_callback_context);

  return NULL;
}

/* Allocate exchange context. The IKE library calls this
   when it needs a exchange context to be allocated. This
   should allocate one obstack and store the obstack pointer
   to the SshIkev2ExchangeData obstack field. The IKEv2
   library will then initialize rest of the exchange data.
   This returns NULL if alloc fails. */
SshIkev2ExchangeData
d_sad_exchange_data_alloc(SshSADHandle sad_handle,
			  SshIkev2Sa sa)
{
  SshIkev2ExchangeData ed;
  SshObStackContext obstack;

  SSH_DEBUG(SSH_D_HIGHSTART, ("Enter SA %p", sa));

#ifdef SSHDIST_IKEV1
  /* Remove IKEv1 SA's from the IKE SA by SPI mapping as IKEv1 SA's are
     not managed there. The SA was added in the ssh_pm_ike_sa_allocate policy
     call which does not know if the SA to be allocated is IKEv1 or IKEv2. */
  if (sa->flags & SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_IKEV1)
    {
      SshADTHandle h;
      if ((h = ssh_adt_get_handle_to_equal(sad_handle->ike_sa_by_spi, sa))
	  != SSH_ADT_INVALID)
	ssh_adt_detach(sad_handle->ike_sa_by_spi, h);
    }
#endif /* SSHDIST_IKEV1 */

  /* XXX Add parameters here. */
  obstack = ssh_obstack_create(NULL);
  if (obstack == NULL)
    return NULL;

  ed = ssh_obstack_alloc(obstack, sizeof(*ed));
  if (ed == NULL)
    {
      ssh_obstack_destroy(obstack);
      return NULL;
    }
  memset(ed, 0, sizeof(*ed));

  ed->obstack = obstack;
  SSH_DEBUG(SSH_D_LOWOK, ("Exchange data allocated ED %p", ed));
  return ed;
}

#ifdef SSHDIST_IKE_EAP_AUTH
#ifdef SSHDIST_EAP
extern Boolean use_eap;
#endif /* SSHDIST_EAP */
#endif /* SSHDIST_IKE_EAP_AUTH */

/* Free exchange context. The IKE library calls this when it
   needs to free the exchange context. It has already
   uninitialized the exchange data from its own parts before
   calling this function. */
void d_sad_exchange_data_free(SshSADHandle sad_handle,
			      SshIkev2ExchangeData exchange_data)
{
  SSH_DEBUG(SSH_D_HIGHSTART, ("Enter SA %p, ED %p", exchange_data->ike_sa,
			      exchange_data));

#ifdef SSHDIST_IKE_EAP_AUTH
#ifdef SSHDIST_EAP
  if (use_eap && exchange_data->application_context != NULL)
    {
      d_pad_eap_destroy(sad_handle, exchange_data);
    }
#endif /* SSHDIST_EAP */
#endif /* SSHDIST_IKE_EAP_AUTH */
  
  ssh_obstack_destroy(exchange_data->obstack);
}


/* Take reference to the IKE SA. */
void
d_sad_ike_sa_take_ref(SshSADHandle sad_handle,
		      SshIkev2Sa ike_sa)
{
  SSH_DEBUG(SSH_D_MY2, ("Taking reference to IKE SA %p (to %d)",
			ike_sa,
			(int) ike_sa->ref_cnt + 1));
  ike_sa->ref_cnt++;
}

/* Free one reference to the IKE SA. If this was last
   reference then the IKE SA is returned to the policy
   manager using SshIkev2SadIkeSaPut call. */
void
d_sad_ike_sa_free_ref(SshSADHandle sad_handle,
		      SshIkev2Sa ike_sa)
{
  SSH_ASSERT(ike_sa->ref_cnt != 0);

  /* Decrement reference count, and check whether we still
     have references. */
  SSH_DEBUG(SSH_D_MY2, ("Freeing reference to IKE SA %p (to %d)",
			ike_sa,
			(int) ike_sa->ref_cnt - 1));
  ike_sa->ref_cnt--;
  if (ike_sa->ref_cnt == 0)
    {
      SSH_DEBUG(SSH_D_HIGHSTART, ("No more references SA %p", ike_sa));

      if (ike_sa->waiting_for_delete != NULL)
	{
	  SshIkev2SaDelete del;

	  /* Waiting for free, add one reference, and call delete. */
	  del = ike_sa->waiting_for_delete;
	  ike_sa->waiting_for_delete = NULL;
	  ike_sa->ref_cnt++;
	  d_sad_ike_sa_delete(sad_handle, ike_sa, del->delete_callback,
			      del->delete_callback_context);
	  ssh_operation_unregister(del->operation_handle);
	  ssh_free(del);
	}
    }
}

void
d_sad_ike_enumerate(SshSADHandle sad_handle,
		    SshIkev2SadIkeSaEnumerateCB enumerate_callback,
		    void *context)
{
  SshIkev2Sa sa = NULL;
  SshADTHandle handle;

  SSH_DEBUG(SSH_D_HIGHSTART, ("Enter"));

  handle = ssh_adt_enumerate_start(sad_handle->ike_sa_by_spi);

  while (handle != SSH_ADT_INVALID)
    {
      sa = ssh_adt_get(sad_handle->ike_sa_by_spi, handle);
      SSH_DEBUG(SSH_D_HIGHSTART, ("Enumerating SA %p", sa));
      (*enumerate_callback)(SSH_IKEV2_ERROR_OK,
			    sa,
			    context);
      handle = ssh_adt_enumerate_next(sad_handle->ike_sa_by_spi, handle);
    }
  (*enumerate_callback)(SSH_IKEV2_ERROR_OK,
			NULL,
			context);
}

void
d_sad_ike_sa_done(SshSADHandle sad_handle,
		  SshIkev2ExchangeData ed,
		  SshIkev2Error error_code)
{
  SSH_DEBUG(SSH_D_HIGHSTART, ("Enter SA %p ED %p", ed->ike_sa, ed));
  return;
}

/* IPsec */

SshOperationHandle
d_sad_ipsec_spi_allocate(SshSADHandle sad_handle,
			 SshIkev2ExchangeData ed,
			 SshIkev2SadIPsecSpiAllocateCB reply_callback,
			 void *reply_callback_context)
{
  SshIkev2Error status = SSH_IKEV2_ERROR_OK;
  SshUInt32 spi;

  SSH_DEBUG(SSH_D_HIGHSTART, ("Enter SA %p ED %p", ed->ike_sa, ed));

  /* Allocate inbound SPI (XXX:) and insert into SAD */

  spi = sad_handle->ipsec_spi_counter++;

  SSH_DEBUG(SSH_D_HIGHSTART, ("Returning SA %p ED %p SPI = %08lx",
			      ed->ike_sa, ed, (unsigned long) spi));
  if (reply_callback)
    (*reply_callback)(status,
		      spi,
		      reply_callback_context);

  return NULL;
}

void
d_sad_ipsec_spi_delete(SshSADHandle sad_handle,
		       SshUInt32 spi)
{
  SSH_DEBUG(SSH_D_HIGHSTART, ("Enter SPI %08lx", (unsigned long) spi));
}

SshOperationHandle
d_sad_ipsec_spi_delete_received(SshSADHandle sad_handle,
				SshIkev2ExchangeData ed,
				SshIkev2ProtocolIdentifiers protocol,
				int number_of_spis,
				SshUInt32 *spi_array,
				SshIkev2SadDeleteReceivedCB
				reply_callback,
				void *reply_context)
{
  SshIkev2Error status = SSH_IKEV2_ERROR_OK;

  SSH_DEBUG(SSH_D_HIGHSTART, ("Enter %d SPIs", number_of_spis));

  if (reply_callback)
    (*reply_callback)(status, protocol, 0, NULL,
		      reply_context);

  return NULL;
}

SshOperationHandle
d_sad_ipsec_sa_install(SshSADHandle sad_handle,
		       SshIkev2ExchangeData ed,
		       SshIkev2SadIPsecSaInstallCB reply_callback,
		       void *reply_callback_context)
{
  SshIkev2Error status = SSH_IKEV2_ERROR_OK;
  unsigned char keymat[64];

  SSH_DEBUG(SSH_D_HIGHSTART, ("Enter SA %p ED %p", ed->ike_sa, ed));

  SSH_DEBUG(SSH_D_HIGHOK,
	    ("Installing SA [iSPI=%08lx, oSPI=%08lx] "
	     "between %@ <-> %@",
	     (unsigned long) ed->ipsec_ed->spi_inbound,
	     (unsigned long) ed->ipsec_ed->spi_outbound,
	     ssh_ikev2_ts_render, ed->ipsec_ed->ts_local,
	     ssh_ikev2_ts_render, ed->ipsec_ed->ts_remote));

  if (ssh_ikev2_fill_keymat(ed, keymat, sizeof(keymat)) ==
      SSH_IKEV2_ERROR_OK)
    {
      SSH_DEBUG_HEXDUMP(SSH_D_LOWOK, ("KEYMAT"),
			keymat, sizeof(keymat));
    }

  /* Nothing here */
  (*reply_callback)(status,
		    reply_callback_context);

  return NULL;
}

void
d_sad_ipsec_sa_update(SshSADHandle sad_handle,
		      SshIkev2ExchangeData ed,
		      SshIpAddr ip_address,
		      SshUInt16 port)
{
  SSH_DEBUG(SSH_D_HIGHSTART, ("Enter IKE SA %p ED %p", ed->ike_sa, ed));

  /* Nothing here */
  return;
}

void
d_sad_ipsec_sa_done(SshSADHandle sad_handle,
		    SshIkev2ExchangeData ed,
		    SshIkev2Error error_code)
{
  SSH_DEBUG(SSH_D_HIGHSTART, ("Enter SA %p ED %p", ed->ike_sa, ed));

  /* Nothing here */
  return;
}
