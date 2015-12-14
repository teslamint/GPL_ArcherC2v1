/*
 *
 * Author: Tero Kivinen <kivinen@iki.fi>
 *
 *  Copyright:
 *          Copyright (c) 2004 SFNT Finland Oy.
 */
/*
 *        Program: sshikev2
 *        $Author: bruce.chang $
 *
 *        Creation          : 17:21 Oct  7 2004 kivinen
 *        Last Modification : 17:35 Oct 25 2006 kivinen
 *        Last check in     : $Date: 2012/09/28 $
 *        Revision number   : $Revision: #1 $
 *        State             : $State: Exp $
 *        Version           : 1.169
 *        
 *
 *        Description       : IKEv2 Packet Encode routine
 *
 *
 *        $Log: ikev2-packet-encode.c,v $
 *        Revision 1.1.2.1  2011/01/31 03:29:15  treychen_hc
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
 *        $EndLog$
 */

#include "sshincludes.h"
#include "sshikev2-initiator.h"
#include "sshikev2-exchange.h"
#include "ikev2-internal.h"
#include "sshencode.h"

#define SSH_DEBUG_MODULE "SshIkev2PacketEncode"

/* This function encodes the header and the packet data
   (from `buffer') to the encoded_packet field inside
   `packet'. */
SshIkev2Error
ikev2_encode_header(SshIkev2Packet packet, SshBuffer buffer)
{
  size_t len;

  len = ssh_buffer_len(buffer);
  packet->encoded_packet_len = len + 28 + (packet->use_natt ? 4 : 0);
  packet->encoded_packet = ssh_malloc(packet->encoded_packet_len);
  if (packet->encoded_packet == NULL)
    return SSH_IKEV2_ERROR_OUT_OF_MEMORY;

  len = ssh_encode_array(packet->encoded_packet,
			 packet->encoded_packet_len,
			 SSH_ENCODE_DATA(ssh_ustr("\0\0\0\0"),
			 (size_t) (packet->use_natt ? 4 : 0)),
			 SSH_ENCODE_DATA(packet->ike_spi_i, (size_t) 8),
			 SSH_ENCODE_DATA(packet->ike_spi_r, (size_t) 8),
			 SSH_ENCODE_CHAR(
			 (unsigned int) packet->first_payload),
			 SSH_ENCODE_CHAR(
			 (unsigned int) ((packet->major_version << 4) |
					 packet->minor_version)),
			 SSH_ENCODE_CHAR((unsigned int) packet->exchange_type),
			 SSH_ENCODE_CHAR((unsigned int) packet->flags),
			 SSH_ENCODE_UINT32(packet->message_id),
			 SSH_ENCODE_UINT32(packet->encoded_packet_len -
			 (packet->use_natt ? 4 : 0)),
			 SSH_ENCODE_DATA(ssh_buffer_ptr(buffer), len),
			 SSH_FORMAT_END);
  if (len != packet->encoded_packet_len)
    return SSH_IKEV2_ERROR_OUT_OF_MEMORY;
  return SSH_IKEV2_ERROR_OK;
}

/* Encrypt the packet and calculate MAC of it. This will
   also encode the packet to the packet->encoded_packet. */
SshIkev2Error ikev2_encrypt_packet(SshIkev2Packet packet,
				   SshBuffer buffer)
{
  unsigned char temp_buffer[SSH_MAX_HASH_DIGEST_LENGTH];
  unsigned char iv_buffer[SSH_CIPHER_MAX_IV_SIZE], *p;
  size_t temp_len, mac_len, len, pad_len, iv_len;
  SshIkev2Sa ike_sa = packet->ike_sa;
  SshCryptoStatus status;
  SshCipher cipher;
  SshMac mac;
  int i;

  /* Lets check that the max IV size is smaller than the max HASH digest
     length, so we can use the digest buffer as a placeholder. */
  SSH_ASSERT(SSH_CIPHER_MAX_IV_SIZE < SSH_MAX_HASH_DIGEST_LENGTH);

  /* Get the MAC len. */
  mac_len = ssh_mac_length(ssh_csstr(ike_sa->mac_algorithm));

  /* Lenght of the packet. */
  len = ssh_buffer_len(buffer);

  /* Add the pad length field. */
  len++;

  /* Get the block size. */
  temp_len = ssh_cipher_get_block_length(ssh_csstr(ike_sa->encrypt_algorithm));

  /* Calculate the padding length. */
  pad_len = temp_len - (len % temp_len);
  if (pad_len == temp_len)
    pad_len = 0;

  /* Get IV length. */
  iv_len = ssh_cipher_get_iv_length(ssh_csstr(ike_sa->encrypt_algorithm));

  /* The final length of the encrypted payload contents will be
     IV len + data len + padding len + mac len. */
  len = 4 + iv_len + len + pad_len + mac_len;

  /* Allocate the final packet. */
  packet->encoded_packet_len = 28 + len + (packet->use_natt ? 4 : 0);
  packet->encoded_packet = ssh_malloc(packet->encoded_packet_len);
  if (packet->encoded_packet == NULL)
    return SSH_IKEV2_ERROR_OUT_OF_MEMORY;

  memset(temp_buffer, 0, sizeof(temp_buffer));

  temp_len =
    ssh_encode_array(packet->encoded_packet,
		     packet->encoded_packet_len,
		     SSH_ENCODE_DATA(ssh_ustr("\0\0\0\0"),
		     (size_t) (packet->use_natt ? 4 : 0)),
		     SSH_ENCODE_DATA(packet->ike_spi_i, (size_t) 8),
		     SSH_ENCODE_DATA(packet->ike_spi_r, (size_t) 8),
		     SSH_ENCODE_CHAR(
		     (unsigned int) SSH_IKEV2_PAYLOAD_TYPE_ENCRYPTED),
		     SSH_ENCODE_CHAR(
		     (unsigned int) ((packet->major_version << 4) |
				     packet->minor_version)),
		     SSH_ENCODE_CHAR((unsigned int) packet->exchange_type),
		     SSH_ENCODE_CHAR((unsigned int) packet->flags),
		     SSH_ENCODE_UINT32(packet->message_id),
		     SSH_ENCODE_UINT32(packet->encoded_packet_len -
		     (packet->use_natt ? 4 : 0)),
		     /* Generic payload header. */
		     SSH_ENCODE_CHAR((unsigned int) packet->first_payload),
		     SSH_ENCODE_CHAR((unsigned int) 0),
		     SSH_ENCODE_UINT16((SshUInt16) len),
		     /* IV. */
		     SSH_ENCODE_DATA(temp_buffer, iv_len),
		     /* Data. */
		     SSH_ENCODE_DATA(
		     ssh_buffer_ptr(buffer), ssh_buffer_len(buffer)),
		     /* Padding. */
		     SSH_ENCODE_DATA(temp_buffer, pad_len),
		     /* Padding length. */
		     SSH_ENCODE_CHAR((unsigned int) pad_len),
		     /* Mac. */
		     SSH_ENCODE_DATA(temp_buffer, mac_len),
		     SSH_FORMAT_END);
  if (temp_len != packet->encoded_packet_len)
    return SSH_IKEV2_ERROR_OUT_OF_MEMORY;

  p = packet->encoded_packet + (packet->use_natt ? 4 : 0);

  /* Generate iv. */
  for(i = 0; i < iv_len; i++)
    {
      p[28 + 4 + i]  = iv_buffer[i] = ssh_random_get_byte();
    }

#ifdef SSH_IKEV2_CRYPTO_KEY_DEBUG
  SSH_DEBUG_HEXDUMP(SSH_D_DATADUMP, ("Using cipher %s with key: ",
				     ike_sa->encrypt_algorithm),
		    (ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_INITIATOR) ?
		    ike_sa->sk_ei : ike_sa->sk_er, ike_sa->sk_e_len);
#endif /* SSH_IKEV2_CRYPTO_KEY_DEBUG */

  /* Allocate cipher */
  status =
    ssh_cipher_allocate(ssh_csstr(ike_sa->encrypt_algorithm),
			(ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_INITIATOR) ?
			ike_sa->sk_ei : ike_sa->sk_er, ike_sa->sk_e_len,
			TRUE, &cipher);
  if (status != SSH_CRYPTO_OK)
    return SSH_IKEV2_ERROR_OUT_OF_MEMORY;

#ifdef SSH_IKEV2_CRYPTO_KEY_DEBUG
  SSH_DEBUG_HEXDUMP(SSH_D_DATADUMP, ("IV"), iv_buffer, iv_len);
  SSH_DEBUG_HEXDUMP(SSH_D_DATADUMP, ("Encrypting"),
		    p + 28 + 4 + iv_len,
		    ssh_buffer_len(buffer) + pad_len + 1);
#endif /* SSH_IKEV2_CRYPTO_KEY_DEBUG */

  status =
    ssh_cipher_transform_with_iv(cipher,
				 p + 28 + 4 + iv_len,
				 p + 28 + 4 + iv_len,
				 ssh_buffer_len(buffer) + pad_len + 1,
				 iv_buffer);
  ssh_cipher_free(cipher);

  /* Check the result of encryption. */
  if (status != SSH_CRYPTO_OK)
      return SSH_IKEV2_ERROR_OUT_OF_MEMORY;

  /* Calculate the mac. */
#ifdef SSH_IKEV2_CRYPTO_KEY_DEBUG
  SSH_DEBUG_HEXDUMP(SSH_D_DATADUMP, ("Using MAC %s with key: ",
				     ike_sa->mac_algorithm),
		    (ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_INITIATOR) ?
		    ike_sa->sk_ai : ike_sa->sk_ar, ike_sa->sk_a_len);
#endif /* SSH_IKEV2_CRYPTO_KEY_DEBUG */
  
  /* Allocate mac. */
  status =
    ssh_mac_allocate(ssh_csstr(ike_sa->mac_algorithm),
		     (ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_INITIATOR) ?
		     ike_sa->sk_ai : ike_sa->sk_ar, ike_sa->sk_a_len, &mac);
  if (status != SSH_CRYPTO_OK)
    return SSH_IKEV2_ERROR_OUT_OF_MEMORY;

#ifdef SSH_IKEV2_CRYPTO_KEY_DEBUG
  SSH_DEBUG_HEXDUMP(SSH_D_DATADUMP, ("MACing"),
		    p, packet->encoded_packet_len - mac_len -
		    (packet->use_natt ? 4 : 0));
#endif /* SSH_IKEV2_CRYPTO_KEY_DEBUG */

  /* Calculate the mac. Mac includes everything from the
     start of the header. */
  ssh_mac_reset(mac);
  ssh_mac_update(mac, p, packet->encoded_packet_len - mac_len -
		 (packet->use_natt ? 4 : 0));
  status = ssh_mac_final(mac, temp_buffer);
  ssh_mac_free(mac);

#ifdef SSH_IKEV2_CRYPTO_KEY_DEBUG
  SSH_DEBUG_HEXDUMP(SSH_D_DATADUMP, ("Output of MAC"),
		    temp_buffer, mac_len);
#endif /* SSH_IKEV2_CRYPTO_KEY_DEBUG */

  /* Check the result of mac calculation. */
  if (status != SSH_CRYPTO_OK)
      return SSH_IKEV2_ERROR_OUT_OF_MEMORY;

  /* Copy the mac to the place. */
  memcpy(packet->encoded_packet + packet->encoded_packet_len - mac_len,
	 temp_buffer, mac_len);

  return SSH_IKEV2_ERROR_OK;
}
