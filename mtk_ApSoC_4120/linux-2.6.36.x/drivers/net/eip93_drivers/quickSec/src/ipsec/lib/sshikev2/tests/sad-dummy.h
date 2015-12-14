/*
  File: sad-dummy.h

  Copyright:
        Copyright 2004 SFNT Finland Oy.
	All rights reserved.

  Description:
  	Dummy SAD module
*/

#include "sshincludes.h"
#include "sshikev2-initiator.h"
#include "sshikev2-sad.h"
#include "pm_ike_sad.h"

SshOperationHandle
d_sad_ike_sa_allocate(SshSADHandle sad_handle,
		      Boolean initiator,
		      SshIkev2SadIkeSaAllocateCB reply_callback,
		      void *reply_context);

SshOperationHandle
d_sad_ike_sa_delete(SshSADHandle sad_handle,
		    SshIkev2Sa sa,
		    SshIkev2SadDeleteCB reply_callback,
		    void *reply_context);

SshOperationHandle
d_sad_ike_sa_rekey(SshSADHandle sad_handle,
		   Boolean delete_old,
		   SshIkev2Sa old_sa,
		   SshIkev2Sa new_sa,
		   SshIkev2SadRekeyedCB reply_callback,
		   void *reply_context);

SshOperationHandle
d_sad_ike_sa_get(SshSADHandle sad_handle,
		 const SshUInt32 ike_version,
		 const unsigned char *ike_sa_spi_i,
		 const unsigned char *ike_sa_spi_r,
		 SshIkev2SadIkeSaGetCB reply_callback,
		 void *reply_context);

SshIkev2ExchangeData
d_sad_exchange_data_alloc(SshSADHandle sad_handle,
			  SshIkev2Sa sa);

void
d_sad_exchange_data_free(SshSADHandle sad_handle,
			 SshIkev2ExchangeData exchange_data);

void
d_sad_ike_sa_take_ref(SshSADHandle sad_handle,
		      SshIkev2Sa ike_sa);

void
d_sad_ike_sa_free_ref(SshSADHandle sad_handle,
		      SshIkev2Sa ike_sa);

void
d_sad_ike_sa_done(SshSADHandle sad_handle,
		  SshIkev2ExchangeData ed,
		  SshIkev2Error error_code);

SshOperationHandle
d_sad_ipsec_spi_allocate(SshSADHandle sad_handle,
			 SshIkev2ExchangeData ed,
			 SshIkev2SadIPsecSpiAllocateCB reply_cb,
			 void *reply_context);

void
d_sad_ipsec_spi_delete(SshSADHandle sad_handle,
		       SshUInt32 spi);

SshOperationHandle
d_sad_ipsec_spi_delete_received(SshSADHandle sad_handle,
				SshIkev2ExchangeData ed,
				SshIkev2ProtocolIdentifiers protocol,
				int number_of_spis, 
				SshUInt32 *spi_array,
				SshIkev2SadDeleteReceivedCB
				reply_callback,
				void *reply_context);

SshOperationHandle
d_sad_ipsec_sa_rekey(SshSADHandle sad_handle,
		     SshIkev2ExchangeData ed,
		     SshUInt32 old_spi, 
		     SshIkev2SadRekeyedCB reply_callback,
		     void *reply_context);

void
d_sad_ike_enumerate(SshSADHandle sad_handle,
		    SshIkev2SadIkeSaEnumerateCB enumerate_callback,
		    void *context);

SshOperationHandle
d_sad_ipsec_sa_install(SshSADHandle sad_handle,
		       SshIkev2ExchangeData ed,
		       SshIkev2SadIPsecSaInstallCB reply_callback,
		       void *reply_context);

void
d_sad_ipsec_sa_update(SshSADHandle sad_handle,
		      SshIkev2ExchangeData ed,
		      SshIpAddr ip_address,
		      SshUInt16 port);

void
d_sad_ipsec_sa_done(SshSADHandle sad_handle,
		    SshIkev2ExchangeData ed,
		    SshIkev2Error error_code);

