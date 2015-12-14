/*
 *
 * Author: Tero Kivinen <kivinen@iki.fi>
 *
 *  Copyright:
 *          Copyright (c) 2005 SFNT Finland Oy.
 */
/*
 *        Program: sshikev2
 *        $Author: bruce.chang $
 *
 *        Creation          : 15:03 Mar 22 2005 kivinen
 *        Last Modification : 15:49 May 29 2006 kivinen
 *        Last check in     : $Date: 2012/09/28 $
 *        Revision number   : $Revision: #1 $
 *        State             : $State: Exp $
 *        Version           : 1.42
 *        
 *
 *        Description       : IKEv2 linearize functions
 *
 *
 *        $Log: ikev2-linearize.c,v $
 *        Revision 1.1.2.1  2011/01/31 03:29:14  treychen_hc
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
 *        $EndLog$
 */

#include "sshincludes.h"
#include "sshikev2-initiator.h"
#include "sshikev2-util.h"
#include "sshikev2-exchange.h"
#include "ikev2-internal.h"
#include "sshencode.h"
#include "sshinetencode.h"

#ifdef SSHDIST_IKEV1
#include "isakmp_linearize.h"
#include "sshbuffer.h"
#endif /* SSHDIST_IKEV1 */

#define SSH_DEBUG_MODULE "SshIkev2Linearize"

#define SSH_IKEV2_LINEARIZE_MAGIC 	0x41552335
#define SSH_IKEV2_LINEARIZE_VERSION	2

/* requires sa->server as set */
SshIkev2Error
ssh_ikev2_decode_sa(SshIkev2Sa sa, unsigned char *buf, size_t len)
{
  SshIkev2Error status;
  size_t offset, sklen, total_len;
  SshUInt32 magic, linearize_version;
  SshUInt32 encr_alg, prf_alg, mac_alg;
  SshUInt16 normal_local_port, nat_t_local_port;
  SshIpAddrStruct local_address[1];
  SshUInt32 ike_version;
  unsigned char *mobike_param;
  size_t mobike_param_len;
  SshUInt32 sk_a_len;
  SshUInt32 sk_p_len;
  SshUInt32 sk_e_len;
  SshUInt32 sk_d_len;

  offset = ssh_decode_array(buf, len,
			    SSH_DECODE_UINT32(&magic),
			    SSH_DECODE_UINT32(&linearize_version),
			    SSH_DECODE_UINT32(&ike_version),
			    SSH_FORMAT_END);

  if (offset != 12
      || magic != SSH_IKEV2_LINEARIZE_MAGIC
      || linearize_version != SSH_IKEV2_LINEARIZE_VERSION)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Invalid IKE SA export header format"));
      status = SSH_IKEV2_ERROR_INVALID_SYNTAX;
      goto error;
    }
  total_len = offset;

  offset = ssh_decode_array(buf + total_len, len - total_len,
			    SSH_DECODE_SPECIAL_NOALLOC(
			    ssh_decode_ipaddr_array, local_address),
			    SSH_DECODE_UINT16(&normal_local_port),
			    SSH_DECODE_UINT16(&nat_t_local_port),
			    SSH_DECODE_SPECIAL_NOALLOC(
			    ssh_decode_ipaddr_array, sa->remote_ip),
			    SSH_DECODE_UINT16(&sa->remote_port),
			    SSH_DECODE_UINT32(&sa->flags),
			    SSH_DECODE_DATA(sa->ike_spi_i, (size_t) 8),
			    SSH_DECODE_DATA(sa->ike_spi_r, (size_t) 8),
			    SSH_DECODE_UINT32(&encr_alg),
			    SSH_DECODE_UINT32(&prf_alg),
			    SSH_DECODE_UINT32(&mac_alg),
			    SSH_DECODE_UINT16(&sa->dh_group),
			    SSH_FORMAT_END);
  if (offset == 0)
    {
      SSH_DEBUG(SSH_D_FAIL, ("IKE SA decode failed"));
      status = SSH_IKEV2_ERROR_INVALID_SYNTAX;
      goto error;
    }
  total_len += offset;

  if ((sa->mac_algorithm = (unsigned char *)
       ssh_find_keyword_name(ssh_ikev2_mac_algorithms, mac_alg)) == NULL ||
      (sa->prf_algorithm = (unsigned char *)
       ssh_find_keyword_name(ssh_ikev2_prf_algorithms, prf_alg)) == NULL ||
      (sa->encrypt_algorithm = (unsigned char *)
       ssh_find_keyword_name(ssh_ikev2_encr_algorithms, encr_alg)) == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Invalid IKE SA algorithms"));
      status = SSH_IKEV2_ERROR_INVALID_SYNTAX;
      goto error;
    }

#ifdef SSHDIST_IKEV1
  if (ike_version == 1)
    {
      SshBufferStruct  buffer;
      SshIkePMPhaseI pm_info;
      int length;

      ssh_buffer_init(&buffer);
      ssh_buffer_wrap(&buffer, buf + total_len, len - total_len);
      buffer.end = len - total_len;

      sa->v1_sa = ssh_ike_sa_import(&buffer, (SshIkeServerContext)sa->server);
      if (sa->v1_sa == NULL)
	{
	  SSH_DEBUG(SSH_D_FAIL, ("IKEv1 SA decode failed"));  
	  status = SSH_IKEV2_ERROR_INVALID_SYNTAX;
	  goto error;
	}

      SSH_DEBUG(SSH_D_LOWOK, ("Taking reference to IKE SA %p to ref count %d",
			      sa, sa->ref_cnt + 1));
      sa->ref_cnt++;
      
      pm_info = ssh_ike_get_pm_phase_i_info_by_negotiation(sa->v1_sa);
      if (pm_info == NULL)
	{
	  SSH_DEBUG(SSH_D_ERROR, ("Could not get PM info from IKE SA"));
	  status = SSH_IKEV2_ERROR_SA_UNUSABLE;
	  goto error;
	}
      pm_info->policy_manager_data = sa;

      sa->flags |= SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_IKEV1;

      length = ssh_buffer_len(&buffer);
      ssh_buffer_uninit(&buffer);

      return SSH_IKEV2_ERROR_OK;
    }
#endif /* SSHDIST_IKEV1 */

  if (ike_version != 2)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Invalid IKE version %d", ike_version));
      return SSH_IKEV2_ERROR_INVALID_MAJOR_VERSION;
    }

  offset = ssh_decode_array(buf + total_len, len - total_len,
			    SSH_DECODE_UINT32_STR_NOCOPY(&mobike_param,
							 &mobike_param_len),
			    SSH_FORMAT_END);
  if (offset == 0)
    {
      SSH_DEBUG(SSH_D_FAIL, ("IKE SA decode failed"));
      status = SSH_IKEV2_ERROR_INVALID_SYNTAX;
      goto error;
    }
  total_len += offset;

#ifdef SSHDIST_IKE_MOBIKE
  /* Decode MOBIKE specific information. */
  status = ikev2_mobike_decode(sa, mobike_param, mobike_param_len);
  if (status != SSH_IKEV2_ERROR_OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("IKE SA MOBIKE parameter decode failed"));
      goto error;
    }
#endif /* SSHDIST_IKE_MOBIKE */

  /* Initialize and configure window. */
  status = ikev2_udp_window_init(sa);
  if (status != SSH_IKEV2_ERROR_OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("IKE SA window init failed"));
      goto error;
    }

  offset = ssh_decode_array(buf + total_len, len - total_len,
			    SSH_DECODE_UINT32_STR(&sa->sk_d, &sklen),
			    SSH_DECODE_UINT32(&sk_d_len),
			    SSH_DECODE_UINT32(&sk_a_len),
			    SSH_DECODE_UINT32(&sk_e_len),
			    SSH_DECODE_UINT32(&sk_p_len),
			    SSH_DECODE_SPECIAL_NOALLOC(
			    ikev2_udp_window_decode, sa->window_r_to_i),
			    SSH_DECODE_SPECIAL_NOALLOC(
			    ikev2_udp_window_decode, sa->window_i_to_r),
			    SSH_FORMAT_END);
  if (offset == 0)
    {
      SSH_DEBUG(SSH_D_FAIL, ("IKE SA decode failed"));
      status = SSH_IKEV2_ERROR_INVALID_SYNTAX;
      goto error;
    }
  total_len += offset;

  sa->sk_d_len = (size_t) sk_d_len;
  sa->sk_a_len = (size_t) sk_a_len;
  sa->sk_e_len = (size_t) sk_e_len;
  sa->sk_p_len = (size_t) sk_p_len;

  /* Verify that decoding consumed all data. */
  if (total_len != len)
    {
      SSH_DEBUG(SSH_D_FAIL,
		("IKE SA import buffer has %d bytes trailing garbage",
		 len - total_len));
      status = SSH_IKEV2_ERROR_INVALID_SYNTAX;
      goto error;
    }

  SSH_ASSERT(sklen ==  (sa->sk_d_len
			+ sa->sk_a_len * 2
			+ sa->sk_e_len * 2
			+ sa->sk_p_len * 2));

  sa->sk_ai = sa->sk_d  + sa->sk_d_len;
  sa->sk_ar = sa->sk_ai + sa->sk_a_len;
  sa->sk_ei = sa->sk_ar + sa->sk_a_len;
  sa->sk_er = sa->sk_ei + sa->sk_e_len;
  sa->sk_pi = sa->sk_er + sa->sk_e_len;
  sa->sk_pr = sa->sk_pi + sa->sk_p_len;

  /* As the last thing, we'll restart the packets at this SA. For this
     we'll need the ikev2 context, which we can get from the server,
     that needs to be given by the caller as sa->server->ikev2 */

  ikev2_udp_window_packets_restart(sa);

  return SSH_IKEV2_ERROR_OK;

 error:
  ssh_ikev2_ike_sa_uninit(sa);
  SSH_ASSERT(status != SSH_IKEV2_ERROR_OK);
  return status;
}

SshIkev2Error
ssh_ikev2_encode_sa(SshIkev2Sa sa, unsigned char **buf_ret, size_t *len_ret)
{
  SshIkev2Error status = SSH_IKEV2_ERROR_OK;
  size_t offset;
  SshUInt32 ike_version = 2;
  unsigned char *mobike_param = NULL;
  size_t mobike_param_len = 0;
  SshBufferStruct buffer;

  /* Skip IKE SAs which are not normal. */
  if ((sa->flags & SSH_IKEV2_IKE_SA_FLAGS_IKE_SA_DONE) == 0
      || sa->waiting_for_delete != NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Invalid IKE SA state"));
      return SSH_IKEV2_ERROR_SA_UNUSABLE;
    }

#ifdef SSHDIST_IKEV1
  if (sa->flags & SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_IKEV1 && sa->v1_sa == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Invalid IKEv1 SA state"));
      return SSH_IKEV2_ERROR_SA_UNUSABLE;
    }
#endif /* SSHDIST_IKEV1 */

  ssh_buffer_init(&buffer);

#ifdef SSHDIST_IKEV1
  if (sa->flags & SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_IKEV1)
    ike_version = 1;
#endif /* SSHDIST_IKEV1 */

  /* First encode the data common to IKEv1 and IKEv2 SA's */
  offset =
    ssh_encode_buffer(&buffer,
		      SSH_ENCODE_UINT32(
		      (SshUInt32) SSH_IKEV2_LINEARIZE_MAGIC),
		      SSH_ENCODE_UINT32(
		      (SshUInt32) SSH_IKEV2_LINEARIZE_VERSION),
		      SSH_ENCODE_UINT32(ike_version),
		      SSH_ENCODE_SPECIAL(
		      ssh_encode_ipaddr_encoder, sa->server->ip_address),
		      SSH_ENCODE_UINT16(
		      (SshUInt16) sa->server->normal_local_port),
		      SSH_ENCODE_UINT16(
		      (SshUInt16) sa->server->nat_t_local_port),
		      SSH_ENCODE_SPECIAL(
		      ssh_encode_ipaddr_encoder, sa->remote_ip),
		      SSH_ENCODE_UINT16((SshUInt16) sa->remote_port),
		      SSH_ENCODE_UINT32((SshUInt32) sa->flags),
		      SSH_ENCODE_DATA(sa->ike_spi_i, (size_t) 8),
		      SSH_ENCODE_DATA(sa->ike_spi_r, (size_t) 8),
		      SSH_ENCODE_UINT32((SshUInt32)
		      ssh_find_keyword_number(ssh_ikev2_encr_algorithms,
		                            ssh_csstr(sa->encrypt_algorithm))),
		      SSH_ENCODE_UINT32((SshUInt32)
		      ssh_find_keyword_number(ssh_ikev2_prf_algorithms,
			   	              ssh_csstr(sa->prf_algorithm))),
		      SSH_ENCODE_UINT32((SshUInt32)
		      ssh_find_keyword_number(ssh_ikev2_mac_algorithms,
					      ssh_csstr(sa->mac_algorithm))),
		      SSH_ENCODE_UINT16((SshUInt16) sa->dh_group),
		      SSH_FORMAT_END);
  if (offset == 0)
    {
      SSH_DEBUG(SSH_D_FAIL, ("IKE SA encode failed"));
      status = SSH_IKEV2_ERROR_OUT_OF_MEMORY;
      goto error;
    }

#ifdef SSHDIST_IKEV1
  if (sa->flags & SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_IKEV1)
    {
      offset = ssh_ike_sa_export(&buffer, sa->v1_sa);
      if (offset == 0)
	{
	  SSH_DEBUG(SSH_D_FAIL, ("IKEv1 SA encode failed"));
	  status = SSH_IKEV2_ERROR_OUT_OF_MEMORY;
	  goto error;
	}

      goto out;
    }
#endif /* SSHDIST_IKEV1 */

#ifdef SSHDIST_IKE_MOBIKE
  /* Encode MOBIKE specific information. */
  status = ikev2_mobike_encode(sa, &mobike_param, &mobike_param_len);
  if (status != SSH_IKEV2_ERROR_OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("IKE SA MOBIKE param encode failed"));
      goto error;
    }
#endif /* SSHDIST_IKE_MOBIKE */
  
  offset = 
    ssh_encode_buffer(&buffer,
		      SSH_ENCODE_UINT32_STR(mobike_param, mobike_param_len),
		      SSH_ENCODE_UINT32_STR(sa->sk_d,
					    (size_t) (sa->sk_d_len +
						      sa->sk_a_len * 2 +
						      sa->sk_e_len * 2 +
						      sa->sk_p_len * 2)),
		      SSH_ENCODE_UINT32((SshUInt32) sa->sk_d_len),
		      SSH_ENCODE_UINT32((SshUInt32) sa->sk_a_len),
		      SSH_ENCODE_UINT32((SshUInt32) sa->sk_e_len),
		      SSH_ENCODE_UINT32((SshUInt32) sa->sk_p_len),
		      /* initial_ed is skipped. */
		      /* rekey is skipped. */
		      SSH_ENCODE_SPECIAL(ikev2_udp_window_encode,
					 sa->window_r_to_i),
		      SSH_ENCODE_SPECIAL(ikev2_udp_window_encode,
					 sa->window_i_to_r),
		      /* ref_cnt, sa_header, waiting_for_delete are
			 skipped. */
		      SSH_FORMAT_END);
  if (offset == 0)
    {
      SSH_DEBUG(SSH_D_FAIL, ("IKE SA encode failed"));
      status = SSH_IKEV2_ERROR_OUT_OF_MEMORY;
      goto error;
    }

#ifdef SSHDIST_IKEV1
 out:
#endif /* SSHDIST_IKEV1 */
  SSH_ASSERT(status == SSH_IKEV2_ERROR_OK);
  ssh_free(mobike_param);
  *buf_ret = ssh_buffer_steal(&buffer, len_ret);
  ssh_buffer_uninit(&buffer);

  return SSH_IKEV2_ERROR_OK;

 error:
  SSH_ASSERT(status != SSH_IKEV2_ERROR_OK);
  ssh_free(mobike_param);
  ssh_buffer_uninit(&buffer);
  *buf_ret = 0;
  *len_ret = 0;

  return status;
}
