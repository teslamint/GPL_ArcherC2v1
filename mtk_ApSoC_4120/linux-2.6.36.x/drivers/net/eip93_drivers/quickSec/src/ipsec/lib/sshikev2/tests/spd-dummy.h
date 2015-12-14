/*
  File: spd-dummy.c

  Copyright:
        Copyright 2004 SFNT Finland Oy.
	All rights reserved.

  Description:
  	Dummy SPD module
*/

SshOperationHandle
d_spd_fill_ike_sa(SshSADHandle sad_handle,
		  SshIkev2ExchangeData ed,
		  SshIkev2SpdFillSACB reply_callback,
		  void *reply_callback_context);

SshOperationHandle
d_spd_select_ike_sa(SshSADHandle sad_handle,
		    SshIkev2ExchangeData ed,
		    SshIkev2PayloadSA sa_in,
		    SshIkev2SpdSelectSACB reply_callback,
		    void *reply_callback_context);

SshOperationHandle
d_spd_notify_request(SshSADHandle sad_handle,
		     SshIkev2ExchangeData ed,
		     SshIkev2SpdNotifyCB reply_callback,
		     void *reply_callback_context);

void
d_spd_notify_received(SshSADHandle sad_handle,
		      Boolean authenticated,
		      SshIkev2ExchangeData ed,
		      SshIkev2ProtocolIdentifiers protocol_id,
		      unsigned char *spi,
		      size_t spi_size,
		      SshIkev2NotifyMessageType notify_message_type,
		      unsigned char *notification_data,
		      size_t notification_data_size);

SshOperationHandle
d_spd_fill_ipsec_sa(SshSADHandle sad_handle,
		    SshIkev2ExchangeData ed,
		    SshIkev2SpdFillSACB reply_callback,
		    void *reply_callback_context);

SshOperationHandle
d_spd_select_ipsec_sa(SshSADHandle sad_handle,
		      SshIkev2ExchangeData ed,
		      SshIkev2PayloadSA sa_in,
		      SshIkev2SpdSelectSACB reply_callback,
		      void *reply_callback_context);

SshOperationHandle
d_spd_narrow_ipsec_selector(SshSADHandle sad_handle,
			    SshIkev2ExchangeData ed,
			    SshIkev2PayloadTS tsi_in_local,
			    SshIkev2PayloadTS tsr_in_remote,
			    SshIkev2SpdNarrowCB reply_callback,
			    void *reply_callback_context);

void
d_spd_responder_exchange_done(SshSADHandle sad_handle,
			      SshIkev2Error error,
			      SshIkev2ExchangeData ed);
