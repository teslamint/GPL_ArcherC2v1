/*
  File: pad-dummy.c

  Copyright:
        Copyright 2004 SFNT Finland Oy.
	All rights reserved.

  Description:
  	Dummy PAD module
*/

SshOperationHandle
d_pad_new_connection(SshSADHandle sad_handle,
		     SshIkev2Server server,
		     SshUInt8 major, SshUInt8 minor,
		     SshIpAddr remote_address,
		     SshUInt16 port,
		     SshIkev2PadNewConnectionCB reply_callback,
		     void *reply_callback_context);

SshOperationHandle
d_pad_id(SshSADHandle sad_handle,
	 SshIkev2ExchangeData ed,
	 Boolean local,
#ifdef SSH_IKEV2_MULTIPLE_AUTH
         SshUInt32 authentication_round,
#endif /* SSH_IKEV2_MULTIPLE_AUTH */
	 SshIkev2PadIDCB reply_callback,
	 void *reply_callback_context);

#ifdef SSHDIST_IKE_CERT_AUTH
SshOperationHandle
d_pad_get_cas(SshSADHandle sad_handle,
	      SshIkev2ExchangeData ed,
	      SshIkev2PadGetCAsCB reply_callback,
	      void *reply_callback_context);

SshOperationHandle
d_pad_get_certificates(SshSADHandle sad_handle,
		       SshIkev2ExchangeData ed,
		       SshIkev2PadGetCertificatesCB reply_cb,
		       void *reply_callback_context);

void
d_pad_new_certificate_request(SshSADHandle sad_handle,
			      SshIkev2ExchangeData ed,
			      SshIkev2CertEncoding ca_encoding,
			      const unsigned char *certificate_authority,
			      size_t certificate_authority_len);

SshOperationHandle
d_pad_public_key(SshSADHandle sad_handle,
		 SshIkev2ExchangeData ed,
		 SshIkev2PadPublicKeyCB reply_callback,
		 void *reply_callback_context);

void
d_pad_new_certificate(SshSADHandle sad_handle,
		      SshIkev2ExchangeData ed,
		      SshIkev2CertEncoding cert_encoding,
		      const unsigned char *cert_data,
		      size_t cert_data_len);
#endif /* SSHDIST_IKE_CERT_AUTH */

SshOperationHandle
d_pad_shared_key(SshSADHandle sad_handle,
		 SshIkev2ExchangeData ed,
		 Boolean local,
		 SshIkev2PadSharedKeyCB reply_callback,
		 void *reply_callback_context);

#ifdef SSHDIST_IKE_EAP_AUTH
void
d_pad_eap_received(SshSADHandle sad_handle,
		   SshIkev2ExchangeData ed,
		   const unsigned char *eap,
		   size_t eap_length);

SshOperationHandle
d_pad_eap_request(SshSADHandle sad_handle,
		  SshIkev2ExchangeData ed,
		  SshIkev2PadEapRequestCB reply_callback,
		  void *reply_callback_context);

SshOperationHandle
d_pad_eap_key(SshSADHandle sad_handle,
	      SshIkev2ExchangeData ed,
	      SshIkev2PadSharedKeyCB reply_callback,
	      void *reply_callback_context);
void
d_pad_eap_destroy(SshSADHandle sad_handle,
		  SshIkev2ExchangeData ed);
#endif /* SSHDIST_IKE_EAP_AUTH */

void
d_pad_conf_received(SshSADHandle sad_handle,
		    SshIkev2ExchangeData ed,
		    SshIkev2PayloadConf conf_payload_in);

SshOperationHandle
d_pad_conf_request(SshSADHandle sad_handle,
		   SshIkev2ExchangeData ed,
		   SshIkev2PadConfCB reply_callback,
		   void *reply_callback_context);

void
d_pad_vendor_id_received(SshSADHandle sad_handle,
			 SshIkev2ExchangeData ed,
			 const unsigned char *vendor_id,
			 size_t vendor_id_len);

SshOperationHandle
d_pad_vendor_id_request(SshSADHandle sad_handle,
			SshIkev2ExchangeData ed,
			SshIkev2PadAddVendorIDCB reply_callback,
			void *reply_callback_context);


#ifdef SSHDIST_IKE_MOBIKE
SshOperationHandle
d_pad_get_address_pair(SshSADHandle sad_handle,
		       SshIkev2ExchangeData ed,
		       SshUInt32 address_index, 
		       SshIkev2PadGetAddressPairCB reply_callback,
		       void *reply_callback_context);

SshOperationHandle
d_pad_get_additional_address_list(SshSADHandle sad_handle,
			     SshIkev2ExchangeData ed,
			     SshIkev2PadGetAdditionalAddressListCB
			     reply_callback,
			     void *reply_callback_context);

#endif /* SSHDIST_IKE_MOBIKE */
