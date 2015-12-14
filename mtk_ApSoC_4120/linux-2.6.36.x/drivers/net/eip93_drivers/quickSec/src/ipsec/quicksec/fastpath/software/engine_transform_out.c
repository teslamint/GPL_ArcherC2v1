/*
 * engine_transform_out.c
 *
 * Copyright:
 *       Copyright (c) 2002-2006 SFNT Finland Oy.
 *       All rights reserved.
 *
 * Code to implement IPSEC and other transforms for outgoing packets.
 *
 *
 */

#include "sshincludes.h"
#include "engine_internal.h"
#ifdef SSHDIST_L2TP
#include "sshl2tp.h"
#include "sshl2tp_parse.h"
#endif /* SSHDIST_L2TP */

#include "fastpath_swi.h"

#define SSH_DEBUG_MODULE "SshEngineFastpathTransformOut"

#ifdef SSHDIST_IPSEC_TRANSFORM

/* The various transforms (headers) are always in the following order:
     IP [NATT] [AH] [ESP] [IPCOMP] [UDP+L2TP] [IPIP]
   Each individual header has fixed size:
     [IP 20 bytes, 40 for IPv6]
     NATT 16 bytes
     AH 12+MAClen bytes
     ESP 8 bytes + trailer 2+MAClen to 255+2+MAClen bytes
     IPCOMP 4 bytes - variable compression gain
     UDP+L2TP 37-44 bytes depending on options
*/

#ifdef SSHDIST_IPSEC_HWACCEL
#ifdef SSHDIST_IPSEC_NAT_TRAVERSAL
Boolean
fastpath_transform_add_natt_header(SshEnginePacketContext pc,
				   SshEngineTransformRun trr,
				   SshFastpathTransformContext tc)
{
  unsigned char *ucp, prefix[8];
  SshInterceptorPacket pp = pc->pp;
  SshUInt16 orig_id, cks, old_len, prefix_ofs;
  SshUInt8 proto;

  /* Only ESP is supported by the latest drafts and RFC. */
  if ((pc->transform & SSH_PM_IPSEC_AH))
    return TRUE;

  memset(prefix, 0, sizeof(prefix));

  /* Pull up the header by IP version and sanity check on it. */
  if (pp->protocol == SSH_PROTOCOL_IP4)
    {
      ucp = ssh_interceptor_packet_pullup(pp, SSH_IPH4_HDRLEN);
    }
#if defined (WITH_IPV6)
  else
    if (pp->protocol == SSH_PROTOCOL_IP6)
      {
	ucp = ssh_interceptor_packet_pullup(pp, SSH_IPH6_HDRLEN);
      }
#endif /* (WITH_IPV6) */
    else
      {
	SSH_DEBUG(SSH_D_LOWOK, ("Trying to add NAT-T to non IP packet"));
	return TRUE;
      }

  /* Sanity check for ucp */
  if (!ucp)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Pullup of IP header failed failed"));
    error:
      pc->pp = NULL;
      return FALSE;
    }
  else
    {
      if (pp->protocol == SSH_PROTOCOL_IP4)
	orig_id = SSH_IPH4_ID(ucp);
#if defined (WITH_IPV6)
      else
	orig_id = 0;
#endif /* (WITH_IPV6) */
    }

  if (tc->prefix_at_0)
    {
      prefix_ofs = 0;
    }
  else
    {
#if defined (WITH_IPV6)
      if (pc->pp->protocol == SSH_PROTOCOL_IP6)
	prefix_ofs = pc->ipsec_offset;
      else
#endif /* WITH_IPV6 */
	prefix_ofs = pc->hdrlen;
    }

  SSH_PUT_16BIT(prefix, trr->local_port);
  SSH_PUT_16BIT(prefix + 2, trr->remote_port);
  SSH_PUT_16BIT(prefix + 4, pc->packet_len - tc->natt_ofs - prefix_ofs);

  /* Update the new packet_len after insertion
     of NAT-T header operation,size of the NATT
     header is 8 bytes */
  old_len = (SshUInt16) pc->packet_len;
  pc->packet_len += 8;

  /* Update the next protocol (ip_nh) field and
     checksum in the IP header.In the case of IPv4
     there is checksum field otherwise there is no
     such field for the IPv6 */

#if defined (WITH_IPV6)
  if (SSH_IP_IS6(&trr->gw_addr))
    {
      /* Update IPv6 header. */
      SSH_IPH6_SET_LEN(ucp,
		       pc->packet_len - SSH_IPH6_HDRLEN);
      SSH_IPH6_SET_NH(ucp, tc->ip_nh);
    }
  else
#endif /* WITH_IPV6 */
    {
      cks = SSH_IPH4_CHECKSUM(ucp);

      proto = SSH_IPH4_PROTO(ucp);
      SSH_IPH4_SET_PROTO(ucp, tc->ip_nh);
      cks = ssh_ip_cksum_update_byte(cks,
				     SSH_IPH4_OFS_PROTO,
				     proto, tc->ip_nh);
      SSH_IPH4_SET_LEN(ucp, pc->packet_len);
      cks = ssh_ip_cksum_update_short(cks,
				      SSH_IPH4_OFS_LEN,
				      old_len, (SshUInt16) pc->packet_len);
      SSH_IPH4_SET_CHECKSUM(ucp, cks);
    }


  /* Insert the prefix into the actual packet. */
  ucp = ssh_interceptor_packet_insert(pc->pp,
				      pp->protocol == SSH_PROTOCOL_IP4 ?
				      SSH_IPH4_HDRLEN : SSH_IPH6_HDRLEN, 8);

  if (!ucp)
    {
      SSH_DEBUG(SSH_D_FAIL, ("insert failed"));
      goto error;
    }
  memcpy(ucp, prefix, 8);
  return TRUE;
}
#endif /* SSHDIST_IPSEC_NAT_TRAVERSAL */
#endif /* SSHDIST_IPSEC_HWACCEL */

Boolean
fastpath_transform_process_df(SshEnginePacketContext pc,
			      SshEngineTransformRun trr)
{
  SshUInt16 cks, fragoff;
  unsigned char *ucpw;

  ucpw = ssh_interceptor_packet_pullup(pc->pp, pc->hdrlen);
  if (!ucpw)
    {
      pc->pp = NULL;
      SSH_DEBUG(SSH_D_FAIL, ("pullup failed"));
      return FALSE;
    }

  /* Get the fragoff from pullup packet */
  fragoff = SSH_IPH4_FRAGOFF(ucpw);

  /* Do relevant changes for the df_bit_flag */
  if (((fragoff & SSH_IPH4_FRAGOFF_DF)
       && trr->df_bit_processing == SSH_ENGINE_DF_CLEAR)
      || (!(fragoff & SSH_IPH4_FRAGOFF_DF)
	  && trr->df_bit_processing == SSH_ENGINE_DF_SET))
    {
      SshUInt16 newfragoff;

      /* Get the old checksum value */
      cks = SSH_IPH4_CHECKSUM(ucpw);
      if (trr->df_bit_processing == SSH_ENGINE_DF_CLEAR)
	newfragoff =  fragoff & ~SSH_IPH4_FRAGOFF_DF;
      else
	newfragoff =  fragoff | SSH_IPH4_FRAGOFF_DF;

      SSH_IPH4_SET_FRAGOFF(ucpw, newfragoff);
      cks = ssh_ip_cksum_update_short(cks, SSH_IPH4_OFS_FRAGOFF,
				      fragoff, newfragoff);
      /* Set the new updated cks into ucpw */
      SSH_IPH4_SET_CHECKSUM(ucpw, cks);
    }
  return TRUE;
}


/* Performs the last part of the outgoing IP transform implementation.
   This is called after encryption or hardware accelerated processing.
   This function computes MAC if it has not yet been computed, and
   releases the transform context. */

void ssh_fastpath_transform_out_finish(SshInterceptorPacket pp,
#ifdef SSHDIST_IPSEC_HWACCEL
				     SshHWAccelResultCode result,
#endif /* SSHDIST_IPSEC_HWACCEL */
				     void *context)
{
  SshEnginePacketContext pc = (SshEnginePacketContext)context;
  SshFastpathTransformContext tc;
  SshEngineTransformRun trr;
  SshCryptoStatus status;
  void (*mac_update_func)(void *context, const unsigned char *buf, size_t len);

  SSH_INTERCEPTOR_STACK_MARK();

  tc = pc->u.flow.tc;
  trr = pc->u.flow.trr;

  SSH_DEBUG(SSH_D_LOWOK, ("transform complete, pp=0x%p", pp));
  if (pp)
    SSH_DUMP_PACKET(SSH_D_MY + 10, "resulting packet:", pp);

  pc->pp = pp;

#ifdef SSHDIST_IPSEC_HWACCEL
  if (pp == NULL || result != SSH_HWACCEL_OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Hardware acceleration dropped packet"));
      SSH_ENGINE_MARK_STAT(pc, SSH_ENGINE_STAT_HWACCELDROP);
      goto error;
    }
#endif /* SSHDIST_IPSEC_HWACCEL */

  /* We must have a packet here. Otherwise a fatal error. */
  SSH_ASSERT(pp != NULL);

  /* Update packet length. */
  pc->packet_len = ssh_interceptor_packet_len(pp);

  /* Update information after tunneling. */
  if (tc->prefix_at_0)
    {
      /* Reassign src and dst ip numbers to that of the tunnel. */
      pc->dst = trr->gw_addr;
      pc->src = trr->local_addr;
      /* Clear packet context flags.  Otherwise they might, e.g.,
         prevent fragmenting the packet if it were too big. */
      pc->pp->flags &= SSH_ENGINE_P_RESET_MASK;

#if defined (WITH_IPV6)
      if (SSH_IP_IS6(&trr->gw_addr))
        {
	  pp->protocol = SSH_PROTOCOL_IP6;
	  pc->hdrlen = SSH_IPH6_HDRLEN;
          /* Store also `pc->ipsec_offset' and
             `pc->ipsec_offset_prevnh' in case we're going to do
             nested tunnels some day. */
          pc->ipsec_offset = SSH_IPH6_HDRLEN;
          pc->ipsec_offset_prevnh = SSH_IPH6_OFS_NH;

        }
      else
#endif /* WITH_IPV6 */
	{
	  pp->protocol = SSH_PROTOCOL_IP4;
	  pc->hdrlen = SSH_IPH4_HDRLEN;
	}
    }

#ifdef SSHDIST_IPSEC_HWACCEL
#ifdef SSHDIST_IPSEC_NAT_TRAVERSAL
  if (tc->transform_accel &&
      pc->transform & SSH_PM_IPSEC_NATT &&
      tc->accel_unsupported_mask & SSH_HWACCEL_COMBINED_FLAG_NATT)
    {
      /* It can't do the requested nat-t, we do it now. */
      if (!fastpath_transform_add_natt_header(pc, trr, tc))
	goto error;
    }
#endif /* SSHDIST_IPSEC_NAT_TRAVERSAL */
#endif /* SSHDIST_IPSEC_HWACCEL */

  if (pc->pp->protocol == SSH_PROTOCOL_IP4
      && trr->df_bit_processing != SSH_ENGINE_DF_KEEP)
    {
      if (!fastpath_transform_process_df(pc, trr))
	goto error;
    }

  /* Update the flow's destination interface number since the
     transform can tunnel the packet using a different interface. Set
     the interface number here (normally derived from the IKE P1
     interface number) only for tunnel mode (IPIP) transforms, since
     for SCTP multihomed connections (and other) the packet has been
     routed by a call the ssh_engine_route() and the pc->u.flow.ifnum
     contains the correct value for this particular SCTP association
     path, and the `local_ifnum' could be wrong */
  if (pc->transform & SSH_PM_IPSEC_TUNNEL)
    pc->u.flow.ifnum = trr->local_ifnum;

  /* Get ICV from combined cipher if combined cipher is being used */
  if (pc->u.flow.mac_done == 0x00 && (!tc->mac_accel && !tc->mac) &&
      tc->cipher && tc->cipher->is_auth_cipher && 
      (pc->transform & SSH_PM_IPSEC_ESP))
    {
      unsigned char icv[SSH_MAX_HASH_DIGEST_LENGTH];
      SshUInt8 icv_iv_len;
      memset(icv, 0x33, sizeof(icv));
      if (pc->transform & SSH_PM_IPSEC_AH)
        {
          icv_iv_len = tc->cipher_iv_len;
        }
      else
        icv_iv_len = 0;
      
      SSH_ASSERT(tc->icv_len == tc->cipher->digest_length + icv_iv_len);
      SSH_ASSERT(tc->icv_len <= SSH_MAX_HASH_DIGEST_LENGTH);

      /* Produce ICV */
      status = (*tc->cipher->final)(tc->cipher_context, icv);
      if (status != SSH_CRYPTO_OK)
        {
          SSH_DEBUG(SSH_D_FAIL, 
		    ("Calculating ICV failed: %d", status));
          goto error;
        }

      /* Copy ICV into the packet. */
      if (!ssh_interceptor_packet_copyin(pp, pc->u.flow.mac_icv_ofs + 
					 icv_iv_len, icv, tc->icv_len))
        {
          SSH_DEBUG(SSH_D_ERROR, ("copyin failed, dropping packet"));
          goto error;
        }
      pc->u.flow.mac_done = 0x01;
    }

  /* Check if we still need to perform MAC computation (in software). */
  if (pc->u.flow.mac_done == 0x00 && 
      ((tc->mac_accel || tc->mac) ||
       (tc->cipher && (pc->transform & SSH_PM_CRYPT_NULL_AUTH_AES_GMAC))))
    {
      unsigned char icv[SSH_MAX_HASH_DIGEST_LENGTH];
#ifdef SSHDIST_IPSEC_HWACCEL
      if (tc->mac_accel)
	{
	  /* Use hardware acceleration to perform the MAC . */
	  pc->u.flow.mac_done = 0x01;
	  ssh_hwaccel_perform_ipsec(tc->mac_accel, pc->pp, 0, 0,
				    pc->u.flow.mac_ofs,
				    pc->u.flow.mac_len,
				    pc->u.flow.mac_icv_ofs,
				    ssh_fastpath_transform_out_finish,
				    (void *)pc);
	  return;
	}
#endif /* SSHDIST_IPSEC_HWACCEL */
      /* Else perform the MAC in software. */

      /* Start computing the MAC. */
      if (tc->mac)
        if (tc->mac->hmac)
          {
	    (*tc->mac->hash->start)(tc->mac_context);
            mac_update_func = tc->mac->hash->update;
          }
        else
          {
	    (*tc->mac->cipher->start)(tc->mac_context);
            mac_update_func = tc->mac->cipher->update;
          }
      else
	{
	  (*tc->cipher->reset)(tc->cipher_context);
	  mac_update_func = tc->cipher->update;
	}

#ifdef SSH_IPSEC_AH
      /* Add IP header for AH (with adjustments). */
      if (pc->transform & SSH_PM_IPSEC_AH)
        {
#if defined (WITH_IPV6)
          if (pp->protocol == SSH_PROTOCOL_IP6)
            {
              ssh_fastpath_mac_add_ah_header6(pc, mac_update_func,
					      tc->mac_context?tc->mac_context: 
					      tc->cipher_context, 
					      -tc->natt_len,
					      SSH_IPPROTO_AH);
              if (pc->pp == NULL)
                goto error;
            }
          else
#endif /* WITH_IPV6 */
            ssh_fastpath_mac_add_ah_header4(pp, pc->hdrlen, mac_update_func,
					    tc->mac_context?tc->mac_context : 
					    tc->cipher_context, -tc->natt_len,
					    SSH_IPPROTO_AH);
        }
#endif /* SSH_IPSEC_AH */

      /* Add the range from the packet that is to be included in MAC. */
      if (!ssh_fastpath_mac_add_range(pc->pp, pc->u.flow.mac_ofs,
				      pc->u.flow.mac_len,
				      mac_update_func,
				      tc->mac_context?tc->mac_context : 
				      tc->cipher_context))
        {
          SSH_DEBUG(SSH_D_FAIL, ("Adding MAC range failed"));
	  goto error;
        }
      /* Get the resulting ICV. */
      if (tc->mac)
        if (tc->mac->hmac)
	  status = (*tc->mac->hash->final)(tc->mac_context, icv);
        else
	  status = (*tc->mac->cipher->final)(tc->mac_context, icv);
      else 
        {
	  unsigned char iv[16];
	  /* IV for counter mode algorithm, use IPSec seq# as iv. */
          SSH_ASSERT(tc->cipher_iv_len == 8);
	  SSH_PUT_32BIT(icv, trr->mycount_low);
	  SSH_PUT_32BIT(icv + 4, trr->mycount_high);
	  SSH_PUT_32BIT(iv, tc->cipher_nonce);
	  SSH_PUT_32BIT(iv + 4, trr->mycount_low);
	  SSH_PUT_32BIT(iv + 8, trr->mycount_high);
	  SSH_PUT_32BIT(iv + 12, 1);
          status = (*tc->cipher->transform)(tc->cipher_context, iv,
                                            iv, 0,  iv);
          if (status == SSH_CRYPTO_OK)
            status = (*tc->cipher->final)(tc->cipher_context, icv + 8);
        }

      if (status != SSH_CRYPTO_OK)
        {
          SSH_DEBUG(SSH_D_FAIL, ("MAC operation failed: %d", status));
	  ssh_interceptor_packet_free(pc->pp);
          goto error;
        }

      /* Copy ICV into the packet. */
      if (!ssh_interceptor_packet_copyin(pc->pp, pc->u.flow.mac_icv_ofs, icv,
                                         tc->icv_len))
        {
          SSH_DEBUG(SSH_D_ERROR, ("copyin failed, dropping packet"));
          goto error;
        }
    }

  /* If using 64 bit sequence numbers, remove the most significant
     32 bits of the sequence number that was previously inserted to
     the packet. */
  if ((pc->transform & (SSH_PM_IPSEC_ESP | SSH_PM_IPSEC_AH)) &&
      (pc->transform & SSH_PM_IPSEC_LONGSEQ))
    {
      size_t longseq_ofs = 0;

      if (pc->transform & SSH_PM_IPSEC_AH)
        longseq_ofs = pc->packet_len - 4;
      else if (pc->transform & SSH_PM_IPSEC_ESP)
        longseq_ofs = pc->packet_len - tc->icv_len - 4;
      else
        SSH_NOTREACHED;

      if (!ssh_interceptor_packet_delete(pp, longseq_ofs, 4))
        goto error;

      pc->packet_len -= 4;
    }































  /* Indicate successful completion of the transform. */
  ssh_fastpath_release_transform_context(pc->engine->fastpath, tc);
  (*pc->u.flow.tr_callback)(pc, SSH_ENGINE_RET_OK, pc->u.flow.tr_context);
  return;

 error: /* pc->pp is now invalid */
  pc->pp = NULL;
  trr->statflags |= SSH_ENGINE_STAT_T_DROP;
  SSH_ENGINE_MARK_STAT(pc, SSH_ENGINE_STAT_ERRORDROP);
  ssh_fastpath_release_transform_context(pc->engine->fastpath, tc);
  (*pc->u.flow.tr_callback)(pc, SSH_ENGINE_RET_ERROR, pc->u.flow.tr_context);
}

/* Send ICMP fragneeded/toobig. Returns TRUE if this was done. In that
   case the caller shall indicate failure for the packet. The argument 
   'has_df' is ignored for IPv6. */
static Boolean
fastpath_transform_process_pmtu(SshFastpath fastpath,
				SshEnginePacketContext pc,
				SshFastpathTransformContext tc,
				SshUInt32 transform,
				Boolean has_df)
{
  SshUInt16 min_mtu_value, mtu_value;

  /* Calculate minimum allowed MTU based on the family */
#if defined (WITH_IPV6)
  if (pc->pp->protocol == SSH_PROTOCOL_IP6)
    min_mtu_value = (SshUInt16)SSH_ENGINE_MIN_FIRST_FRAGMENT_V6;
  else
#endif /* WITH_IPV6 */
    min_mtu_value = (SshUInt16)SSH_ENGINE_MIN_DF_LENGTH;

  /* Calculate MTU value to send. This is the one at flow (which,
     again is either the one from interface towards next hop, or the
     one received from route with ICMP to this transform) compensated
     with our own discount. */
  mtu_value = pc->u.flow.mtu - pc->u.flow.tr.packet_enlargement;

  /* Check if to send ICMP. We do this for the first really offending
     packet if the MTU is above protocol defined minimum value (stacks
     tend to drop ICMP's with too small MTU proposals) */
  SSH_DEBUG(SSH_D_NICETOKNOW,
	    ("MTU response: mtu=%d/%d, proto=%d/%d, has_df=%d",
	     mtu_value, min_mtu_value, 
	     pc->pp->protocol == SSH_PROTOCOL_IP4, 
	     SSH_IP_IS4((&pc->dst)),
	     has_df));
  
  if (mtu_value >= min_mtu_value)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("MTU comp ok."));
      if (pc->pp->protocol == SSH_PROTOCOL_IP4 || 
	  SSH_IP_IS4((&pc->dst)))
	{
	  if (has_df)
	    {
	      SSH_DEBUG(SSH_D_NICETOKNOW, ("ICMP error sending"));
	      SSH_DEBUG(SSH_D_NICETOKNOW,
			("Sending ICMP too big for IPv4; dst=%@, MTU=%d",
			 ssh_ipaddr_render, &pc->dst,
			 mtu_value));

	      ssh_engine_send_icmp_error(fastpath->engine, pc, 
					 SSH_ICMP_TYPE_UNREACH,
					 SSH_ICMP_CODE_UNREACH_NEEDFRAG,
					 mtu_value);

	      SSH_ENGINE_MARK_STAT(pc, SSH_ENGINE_STAT_FRAGDROP);
	      return TRUE;
	    }
	}
#if defined (WITH_IPV6)
      else if (pc->pp->protocol == SSH_PROTOCOL_IP6)
	{
	  if ((pc->pp->flags & SSH_PACKET_FROMADAPTER)
	      || (!(pc->pp->flags & SSH_PACKET_FROMADAPTER)
		  && ((transform & SSH_PM_IPSEC_TUNNEL)
		      || (!(transform & SSH_PM_IPSEC_TUNNEL)
			  && !(pc->pp->flags & SSH_ENGINE_P_WASFRAG)))))
	    {
	      SSH_DEBUG(SSH_D_MIDOK,
			("Sending ICMP too big for IPv6; dst=%@, MTU=%d",
			 ssh_ipaddr_render, &pc->dst,
			 mtu_value));

	      ssh_engine_send_icmp_error(fastpath->engine, pc, 
					 SSH_ICMP6_TYPE_TOOBIG,
					 0, mtu_value);

	      SSH_ENGINE_MARK_STAT(pc, SSH_ENGINE_STAT_FRAGDROP);
	      return TRUE;
	    }
	}
#endif /* WITH_IPV6 */
    }
  return FALSE;
}

/* Check if the resulting packet will exceed the path MTU.  Returns FALSE 
   in the case where the transform processing should not continue, the 
   packet should then be dropped. Otherwise returns TRUE. */
static Boolean 
fastpath_transform_check_pmtu(SshFastpath fastpath,
			      SshFastpathTransformContext tc,
			      SshEnginePacketContext pc,
			      SshUInt32 prefix_len,
			      SshUInt32 prefix_ofs,
			      Boolean has_df)
{
  SshUInt32 pad_len, new_mtu, new_len;
  SshEngineTransformData d_trd;

  /* Determine number of padding bytes for trailer. */
  pad_len = 0;
  if (tc->trailer_len > 0)
    {
      pad_len = (pc->packet_len + prefix_len -
                 prefix_ofs - tc->esp_ofs - tc->esp_len + 2) %
        tc->pad_boundary;
      if (pad_len == 0)
        pad_len = 0;
      else
        pad_len = tc->pad_boundary - pad_len;
    }
  
  /* Calculate resulting packet length. */
  new_len = pc->packet_len + prefix_len + tc->trailer_len + pad_len;

  /* Set the number of bytes that are added to the packet after
     all transforms are performed. */
#ifdef SSH_IPSEC_TCPENCAP
  new_len += tc->tcp_encaps_len;
#endif /* SSH_IPSEC_TCPENCAP */

#ifdef SSHDIST_IPSEC_HWACCEL
  /* A kludge for hardware accelerators which do not compute the 
     padding length correctly for null ciphers. Force the the PMTU 
     size to be 4 bytes smaller than it should be. */
  if (tc->transform_accel && (tc->transform & SSH_PM_CRYPT_NULL))
    new_len += 4;
#endif /* SSHDIST_IPSEC_HWACCEL */

  /* Check for overflow on packet size calculation. */
  if (new_len > 65535)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Resulting packet would be too big: new_len=%u", new_len));
      SSH_ENGINE_MARK_STAT(pc, SSH_ENGINE_STAT_FRAGDROP);
      return FALSE;
    }

  /* Path MTU processing. If the packet got longer than mtu recorded
     into flow (next hop, or one received from the net) we possibly
     send ICMP fragneeded/toobig */
  if (new_len > pc->u.flow.mtu)
    {
      SSH_DEBUG(SSH_D_HIGHOK, 
		("Resulting packet size %d exceeds flow MTU %d",
		 (unsigned int) new_len,
		 (unsigned int) pc->u.flow.mtu));

      /* This is a restarted outbound packet, update the pmtu value
	 of the previous transform. */
      if (pc->flags & SSH_ENGINE_PC_RESTARTED_OUT
	  && pc->prev_transform_index != SSH_IPSEC_INVALID_INDEX)
	{
	  ssh_kernel_mutex_lock(fastpath->engine->flow_control_table_lock);
	  d_trd = FASTPATH_GET_TRD(fastpath, pc->prev_transform_index);
	  SSH_ASSERT(d_trd->transform != 0);

	  new_mtu = pc->u.flow.mtu - (new_len - pc->u.flow.mtu);

	  if (d_trd->pmtu_received == 0 || new_mtu < d_trd->pmtu_received)
	    {
	      SSH_DEBUG(SSH_D_HIGHOK,
			("Updating PMTU of trd_index 0x%lx from %u to %u",
			 (unsigned long) pc->prev_transform_index,
			 (unsigned int) d_trd->pmtu_received,
			 (unsigned int) new_mtu));
	      d_trd->pmtu_received = (SshUInt16) new_mtu;



	      FASTPATH_COMMIT_TRD(fastpath, pc->prev_transform_index, d_trd);
	    }
	  else
	    {
	      SSH_DEBUG(SSH_D_NICETOKNOW, 
			("PMTU for trd 0x%lx is already lower than %d (%d)",
			 (unsigned long) pc->prev_transform_index,
			 (unsigned int) new_mtu, 
			 (unsigned int) d_trd->pmtu_received));
	      FASTPATH_RELEASE_TRD(fastpath, pc->prev_transform_index);
	    }
	  
	  ssh_kernel_mutex_unlock(fastpath->engine->flow_control_table_lock);

	  if (has_df)
	    return FALSE;
	}
      
      SSH_DEBUG(SSH_D_NICETOKNOW,
		("Modified pmtu processing: df=%d.\n", has_df));
      if (fastpath_transform_process_pmtu(fastpath, pc, tc,
					  pc->transform,
					  has_df))

	return FALSE;
    }
  return TRUE;
}

#ifdef SSHDIST_L2TP
static void 
fastpath_transform_construct_l2tp_header(SshEnginePacketContext pc,
				       SshFastpathTransformContext tc,
				       unsigned char *ucpw,
				       size_t ucpw_len,
				       size_t *return_hdr_len)

{
  SshEngineTransformRun trr = pc->u.flow.trr;
  SshUInt16 orig_len = (SshUInt16)ssh_interceptor_packet_len(pc->pp);
  unsigned char *orig_ucpw = ucpw;

  SSH_ASSERT(orig_len == ssh_interceptor_packet_len(pc->pp));

  /* Check here that we won't overflow the 'ucpw' buffer */
  SSH_ASSERT(ucpw_len >= SSH_UDP_HEADER_LEN + 8 + 4 + 2 + 1 + 1);
  
  /* Construct L2TP UDP+PPP headers. */
  if (pc->transform & SSH_PM_IPSEC_L2TP)
    {
      /* Construct UDP header. */
      SSH_UDPH_SET_SRCPORT(ucpw, trr->l2tp_local_port);
      SSH_UDPH_SET_DSTPORT(ucpw, trr->l2tp_remote_port);
      SSH_UDPH_SET_LEN(ucpw, orig_len + tc->prefix_len - tc->l2tp_ofs);
      /* SSH_UDPH_SET_CHECKSUM(ucpw, 0); (implicit by memset earlier) */

      /* Construct L2TP header. */ 





      ucpw += SSH_UDP_HEADER_LEN;
      SSH_L2TPH_SET_BITS(ucpw, SSH_L2TPH_F_LENGTH);
      SSH_L2TPH_SET_VERSION(ucpw, SSH_L2TP_DATA_MESSAGE_HEADER_VERSION);
      SSH_PUT_16BIT(ucpw + 2, orig_len + tc->prefix_len - tc->l2tp_ofs -
                    SSH_UDP_HEADER_LEN);
      SSH_PUT_16BIT(ucpw + 4, trr->l2tp_remote_tunnel_id);
      SSH_PUT_16BIT(ucpw + 6, trr->l2tp_remote_session_id);
      ucpw += 8;

      if (trr->l2tp_flags & SSH_ENGINE_L2TP_SEQ)
        {
          /* Set sequence numbers. */
          SSH_PUT_16BIT(ucpw, trr->l2tp_seq_ns);
          SSH_PUT_16BIT(ucpw + 2, trr->l2tp_seq_nr);
          ucpw += 4;
        }

      /* Construct PPP header. */
      if ((trr->l2tp_flags & SSH_ENGINE_L2TP_PPP_ACFC) == 0)
        {
          SSH_PUT_16BIT(ucpw, 0xff03);
          ucpw += 2;
        }
      if ((trr->l2tp_flags & SSH_ENGINE_L2TP_PPP_PFC) == 0)
        {
          /* SSH_PUT_8BIT(ucpw, 0); (already zeroed by memset above) */
          ucpw++;
        }
#if defined (WITH_IPV6)
      if (pc->pp->protocol == SSH_PROTOCOL_IP6)
        SSH_PUT_8BIT(ucpw, SSH_PPP_PROTO_IPV6);
      else
#endif /* WITH_IPV6 */
        SSH_PUT_8BIT(ucpw, SSH_PPP_PROTO_IP);
    }

  if (return_hdr_len)
    *return_hdr_len = (size_t)(ucpw - orig_ucpw) + 1;
}
#endif /* SSHDIST_L2TP */


/* Implements outgoing IPSEC transforms for outgoing IP packets.  This
   function implements AH, ESP, IPCOMP, L2TP, NAT Traversal, and
   IP-in-IP (for tunnel mode) transforms. This calls the callback when 
   done (either during the call to this function or at some later time). 
   This function may use hardware acceleration to perform its work. 
   When this is called, the packet has already gone through basic sanity 
   checks, and we know that it has at least hdrlen+8 bytes of data. */

void ssh_fastpath_transform_out(SshFastpath fastpath,
				SshEnginePacketContext pc,
				SshEngineTransformRun trr,
				SshFastpathTransformCB callback, 
				void *context)
{
  SshUInt32 new_len, pad_len, i, prefix_ofs, len;
  SshUInt16 prefix_len, enc_ofs = 0, mac_ofs = 0, enc_len, mac_len;
  SshFastpathTransformContext tc;
  unsigned char *ucpw;
  unsigned char prefix[SSH_ENGINE_MAX_TRANSFORM_PREFIX];
  SshUInt16 cks, fragoff;
  SshUInt8 tos, ttl;
  SshUInt16 orig_len, old_len;
#ifdef SSHDIST_IPSEC_NAT_TRAVERSAL
  SshUInt16 orig_id;
#endif /* SSHDIST_IPSEC_NAT_TRAVERSAL */
  unsigned char orig_ip_nh = pc->ipproto;
#ifdef SSHDIST_IPSEC_NAT
  Boolean forward;
#endif /* SSHDIST_IPSEC_NAT */
#if defined (WITH_IPV6)
  SshUInt32 flow_label = 0;
#endif /* WITH_IPV6 */
  Boolean has_df = FALSE, ipcomp_done;
  SshUInt8 esp_nh;
#ifdef SSH_IPSEC_AH
  SshUInt8 ah_nh;
#endif /* SSH_IPSEC_AH */
#ifdef SSHDIST_IPSEC_IPCOMP
#ifdef SSH_IPSEC_IPCOMP_IN_SOFTWARE
  SshFastpathTransformIpcompState ipcomp_state;
  SshFastpathTransformIpcompStatus ipcomp_status;
#endif /* SSH_IPSEC_IPCOMP_IN_SOFTWARE */
#endif /* SSHDIST_IPSEC_IPCOMP */

  SSH_INTERCEPTOR_STACK_MARK();

  SSH_DEBUG(SSH_D_NICETOKNOW, ("Outbound transform processing entered"));

  ipcomp_done = FALSE;

  /* Save callback function for later use. */
  pc->u.flow.tr_callback = callback;
  pc->u.flow.tr_context = context;

  orig_len = (SshUInt16) pc->packet_len;

  /* Obtain a transform context for the transform.  This may come from
     a cache or might be constructed here. */
  tc = ssh_fastpath_get_transform_context(fastpath, trr, pc, TRUE,
                                        pc->pp->protocol == SSH_PROTOCOL_IP6,
                                        SSH_IP_IS6(&trr->gw_addr));
  if (tc == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Allocating transform context failed"));
      /* Failed to allocate action context. */
    fail:
      SSH_ENGINE_MARK_STAT(pc, SSH_ENGINE_STAT_TRANSFORMDROP);
      if (tc != NULL)
        ssh_fastpath_release_transform_context(fastpath, tc);
      trr->statflags |= SSH_ENGINE_STAT_T_DROP;
      (*pc->u.flow.tr_callback)(pc, SSH_ENGINE_RET_FAIL,
				pc->u.flow.tr_context);
      return;
    }

#ifdef SSH_IPSEC_AH
  ah_nh = tc->ah_nh;
#endif /* SSH_IPSEC_AH */
  esp_nh = tc->esp_nh;
  prefix_len = tc->prefix_len;

  /* Save the transform run-time data pointer. */
  pc->u.flow.trr = trr;
  pc->u.flow.tc = tc;

#ifndef SSH_IPSEC_IP_ONLY_INTERCEPTOR
  SSH_ASSERT(pc->protocol_offset == 0);
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */

  /* Read some needed fields from the old (inner) header.  Note that
     we pull it up in write mode, so that we can modify it below if
     appropriate. */
#if defined (WITH_IPV6)
  if (pc->pp->protocol == SSH_PROTOCOL_IP6)
    /* In IPv6 we're interested only in the hop limit and traffic
       class, which reside in the first two words. */
    ucpw = ssh_interceptor_packet_pullup(pc->pp, 8);
  else
#endif /* WITH_IPV6 */
    ucpw = ssh_interceptor_packet_pullup(pc->pp, pc->hdrlen);
  if (!ucpw)
    {
      SSH_DEBUG(SSH_D_FAIL, ("pullup failed"));
    error:
      ssh_fastpath_release_transform_context(fastpath, tc);
      pc->pp = NULL;
      trr->statflags |= SSH_ENGINE_STAT_T_DROP;
      SSH_ENGINE_MARK_STAT(pc, SSH_ENGINE_STAT_ERRORDROP);
      (*callback)(pc, SSH_ENGINE_RET_ERROR, context);
      return;
    }
#if defined (WITH_IPV6)
  if (pc->pp->protocol == SSH_PROTOCOL_IP6)
    { /* IPv6 case, use the variable `tos' for the traffic class. */
      SSH_ASSERT(pc->packet_len == SSH_IPH6_LEN(ucpw) + SSH_IPH6_HDRLEN);
      tos = SSH_IPH6_CLASS(ucpw);
      flow_label = SSH_IPH6_FLOW(ucpw);
      if (pc->pp->flags & SSH_ENGINE_P_ISFRAG)
        fragoff = pc->fragment_offset;
      else
        fragoff = 0;
#ifdef SSHDIST_IPSEC_NAT_TRAVERSAL
      orig_id = 0;
#endif /* SSHDIST_IPSEC_NAT_TRAVERSAL */
    }
  else
#endif /* WITH_IPV6 */
    {
      SSH_ASSERT(pc->packet_len == SSH_IPH4_LEN(ucpw));
      tos = SSH_IPH4_TOS(ucpw);
      fragoff = SSH_IPH4_FRAGOFF(ucpw);
      SSH_ASSERT(pc->ipproto == SSH_IPH4_PROTO(ucpw));
#ifdef SSHDIST_IPSEC_NAT_TRAVERSAL
      orig_id = SSH_IPH4_ID(ucpw);
#endif /* SSHDIST_IPSEC_NAT_TRAVERSAL */
    }

  /* Determine the offset at which to insert headers. */
  if (tc->prefix_at_0)
    prefix_ofs = 0;
  else
    {
#if defined (WITH_IPV6)
      if (pc->pp->protocol == SSH_PROTOCOL_IP6)
        prefix_ofs = pc->ipsec_offset;
      else
#endif /* WITH_IPV6 */
        prefix_ofs = pc->hdrlen;
    }

  if ((pc->pp->protocol == SSH_PROTOCOL_IP4) && 
      (fragoff & SSH_IPH4_FRAGOFF_DF))
    has_df = TRUE;
  
  /* Check if the resulting packet will exceed the path MTU. Do this now
     for transform level hardware acceleration. Postpone this check for
     other cases until after software IPComp is performed. */
  if (tc->transform_accel)
    {
      if (!fastpath_transform_check_pmtu(fastpath, tc, pc, prefix_len, 
					 prefix_ofs, has_df))
	goto fail;
    }
  
  /* If this packet does not have IPv4 header checksum computed, i.e. the
     checksum should be computed by NIC, clear the flag and compute the
     IPv4 header checksum before encryption. */
  if (pc->pp->flags & SSH_PACKET_IP4HHWCKSUM)
    {
      unsigned char *ucp   = NULL;
      SshUInt16      cksum = 0;

      SSH_DEBUG(SSH_D_LOWOK, ("Computing IPv4 checksum"));

      ucp = ssh_interceptor_packet_pullup(pc->pp, pc->hdrlen);
      if (ucp == NULL)
        goto fail;
      
      SSH_IPH4_SET_CHECKSUM(ucp, 0);
      cksum = ssh_ip_cksum(ucp, pc->hdrlen);
      SSH_IPH4_SET_CHECKSUM(ucp, cksum);

      pc->pp->flags &= ~SSH_PACKET_IP4HHWCKSUM;
    }

  /* If this packet does not have the TCP/UDP checksum computed, i.e. the
     checksum should be computed by the NIC device, then we need to clear
     this flag and compute the upper layer checksum before encryption. */
  if (pc->pp->flags & SSH_PACKET_HWCKSUM)
    {
      SSH_DEBUG(SSH_D_LOWOK, ("Computing TCP/UDP checksum"));

      if (!ssh_ip_cksum_packet_compute(pc->pp, 0, pc->hdrlen))
	{
	  SSH_DEBUG(SSH_D_FAIL, ("Cannot compute checksum, dropping packet"));
	  goto error;
	}
      pc->pp->flags &= ~SSH_PACKET_HWCKSUM;
    }

#ifdef SSHDIST_IPSEC_NAT
  forward = (pc->flags & SSH_ENGINE_PC_FORWARD) != 0;
  if (ssh_fastpath_transform_nat(fastpath, pc, forward) == FALSE)
    {
      SSH_DEBUG(SSH_D_FAIL, ("NAT in outbound transform failed!"));
      goto fail;
    }

  /* ssh_engine_transform_nat() may invalidate the ucpw pointer
     for pullup, so we need to refetch it. */
#if defined (WITH_IPV6)
  if (pc->pp->protocol == SSH_PROTOCOL_IP6)
    /* In IPv6 we're interested only in the hop limit and traffic
       class, which reside in the first two words. */
    ucpw = ssh_interceptor_packet_pullup(pc->pp, 8);
  else
#endif /* WITH_IPV6 */
    ucpw = ssh_interceptor_packet_pullup(pc->pp, pc->hdrlen);

  if (ucpw == NULL)
    goto error;
#endif /* SSHDIST_IPSEC_NAT */

#ifdef SSH_IPSEC_STATISTICS
  /* Update statistics. */
  if (pc->transform & SSH_PM_IPSEC_ESP)
    {
      SSH_ENGINE_MARK_STAT(pc, SSH_ENGINE_STAT_ESP_OUT);
    }
  if (pc->transform & SSH_PM_IPSEC_AH)
    {
      SSH_ENGINE_MARK_STAT(pc, SSH_ENGINE_STAT_AH_OUT);
    }
#endif /* SSH_IPSEC_STATISTICS */

#ifdef SSHDIST_IPSEC_HWACCEL
  /* If we have transform-level acceleration context, use it now. */
  if (tc->transform_accel)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Performing hardware combined transform"));
      pc->u.flow.mac_done = 0x01; /* Indicate all is done. */

      ssh_hwaccel_perform_combined(tc->transform_accel,
                                   pc->pp,
                                   ssh_fastpath_transform_out_finish,
                                   (void *) pc);
      return;
    }

  /* Otherwise, prepare for for software transformation... */
#endif /* SSHDIST_IPSEC_HWACCEL */

  /* Update the TTL in the IP header if doing tunnel mode. */
  if (tc->prefix_at_0)
    { 
#if defined (WITH_IPV6)
      if (pc->pp->protocol == SSH_PROTOCOL_IP6)
        {
          if (pc->flags & SSH_ENGINE_PC_DECREMENT_TTL)
            {
              ttl = SSH_IPH6_HL(ucpw);
              ttl--;
              if (ttl == 0)
                {
                  SSH_DEBUG(SSH_D_NETGARB, ("Hop limit reached zero"));
                  SSH_ENGINE_MARK_STAT(pc, SSH_ENGINE_STAT_CORRUPTDROP);
                  goto fail;
                }
              SSH_IPH6_SET_HL(ucpw, ttl);
            }
        }
      else
#endif /* WITH_IPV6 */
        if (pc->flags & SSH_ENGINE_PC_DECREMENT_TTL)
          {
            ttl = SSH_IPH4_TTL(ucpw);
            ttl--;
            if (ttl == 0)
              {
                SSH_DEBUG(SSH_D_NETGARB, ("TTL reached zero"));
                SSH_ENGINE_MARK_STAT(pc, SSH_ENGINE_STAT_CORRUPTDROP);
                goto fail;
              }
            SSH_IPH4_SET_TTL(ucpw, ttl);
            cks = SSH_IPH4_CHECKSUM(ucpw);
            cks = ssh_ip_cksum_update_byte(cks, SSH_IPH4_OFS_TTL,
                                           ttl + 1, ttl);
            SSH_IPH4_SET_CHECKSUM(ucpw, cks);
          }
    }

#ifdef SSHDIST_IPSEC_IPCOMP
#ifdef SSH_IPSEC_IPCOMP_IN_SOFTWARE
  /* Try to perform IPComp transformation. */
  if (pc->transform & SSH_PM_IPSEC_IPCOMP)
    {
      ipcomp_state = ssh_fastpath_ipcomp_state(pc, tc);

      if (ipcomp_state == SSH_FASTPATH_TRANSFORM_NO_COMPRESS)
        {
          SSH_DEBUG(SSH_D_LOWOK, ("Compression cannot be performed, "
				  "omitting IPComp processing"));

	  /* No IPComp header will be inserted, update the prefix length 
	   of the packet and the ESP/AH next headers. */
	  prefix_len -= 4;
#ifdef SSH_IPSEC_AH
          if (ah_nh == SSH_IPPROTO_IPPCP)
            ah_nh = tc->ipcomp_nh;
#endif /* SSH_IPSEC_AH */
          if (esp_nh == SSH_IPPROTO_IPPCP)
            esp_nh = tc->ipcomp_nh;
#ifdef SSH_IPSEC_STATISTICS
          SSH_ENGINE_MARK_STAT(pc, SSH_ENGINE_STAT_NOIPCOMP_OUT);
#endif /* SSH_IPSEC_STATISTICS */
        }
      else if (ipcomp_state == SSH_FASTPATH_TRANSFORM_DO_COMPRESS)
        {
	  unsigned char *extra = NULL;
	  size_t extra_len = 0;

#ifdef SSHDIST_L2TP
	  /* Construct L2TP UDP+PPP headers. */
	  if (pc->transform & SSH_PM_IPSEC_L2TP)
	    {
	      /* Zero the inserted data so that all reserved bytes 
		 get zeroed. */
	      SSH_ASSERT(prefix_len < SSH_ENGINE_MAX_TRANSFORM_PREFIX);
	      memset(prefix, 0, prefix_len);
	      
	      fastpath_transform_construct_l2tp_header(pc, tc, 
						     prefix, sizeof(prefix), 
						     &extra_len);
	      extra = prefix;
	    }
#endif /* SSHDIST_L2TP */

	  /* And do the IPcomp operation */
          ipcomp_status = ssh_fastpath_transform_ipcomp_outbound(pc, tc, 
								 prefix_ofs, 
								 extra, 
								 extra_len);
	  switch (ipcomp_status)
	    {
	    case SSH_FASTPATH_IPCOMP_DROP:
            case SSH_FASTPATH_IPCOMP_NO_MEMORY:
	      SSH_DEBUG(SSH_D_FAIL, ("IPcomp operation failed"));
              goto error;
	      break;
            case SSH_FASTPATH_IPCOMP_SUCCESS:
	      SSH_DEBUG(SSH_D_MY, ("IPComp operation result success"));
	      /* Update the prefix length by reducing the length of the 
		 L2TP+UDP+PPP headers as these are now compressed. */
	      prefix_len -= (SshUInt16)extra_len;
	      ipcomp_done = TRUE;
	      break;
	    case SSH_FASTPATH_IPCOMP_PASSBY:
	      SSH_DEBUG(SSH_D_MY, ("IPComp operation result passby"));
	      /* No IPComp header was be inserted, update the prefix length 
		 of the packet and the ESP/AH next headers. */
	      prefix_len -= 4;
#ifdef SSH_IPSEC_AH
	      if (ah_nh == SSH_IPPROTO_IPPCP)
		ah_nh = tc->ipcomp_nh;
#endif /* SSH_IPSEC_AH */
	      if (esp_nh == SSH_IPPROTO_IPPCP)
		esp_nh = tc->ipcomp_nh;
	      break;	
	    }
	}
      else
	SSH_NOTREACHED;
    }
#endif /* SSH_IPSEC_IPCOMP_IN_SOFTWARE */
#endif /* SSHDIST_IPSEC_IPCOMP */

  /* Zero the inserted data so that all reserved bytes get zeroed. */
  SSH_ASSERT(prefix_len < SSH_ENGINE_MAX_TRANSFORM_PREFIX);
  memset(prefix, 0, prefix_len);

  /* Compression is done. Now we can compute the length of the final 
     packet, padding length etc. */
  old_len = (SshUInt16) pc->packet_len;
  SSH_ASSERT(old_len == ssh_interceptor_packet_len(pc->pp));

  /* Determine number of padding bytes for trailer. */
  pad_len = 0;
  if (tc->trailer_len > 0)
    {
      pad_len = (pc->packet_len + prefix_len -
                 prefix_ofs - tc->esp_ofs - tc->esp_len + 2) %
        tc->pad_boundary;
      if (pad_len == 0)
        pad_len = 0;
      else
        pad_len = tc->pad_boundary - pad_len;
    }
  
  /* Calculate resulting packet length and save the input packet
     length. */
  new_len = pc->packet_len + prefix_len + tc->trailer_len + pad_len;
  
  /* Check if the resulting packet will exceed the path MTU */
  if (!fastpath_transform_check_pmtu(fastpath, tc, pc, prefix_len, 
				     prefix_ofs, has_df))
    goto fail;
  
  if (!tc->prefix_at_0)
    {
      /* We are processing the packet in transport mode; modify the
         ipproto field of the IP header and update packet length in
         its header. */
#if defined (WITH_IPV6)
      if (pc->pp->protocol == SSH_PROTOCOL_IP6)
        {
	  ucpw = ssh_interceptor_packet_pullup(pc->pp, 8);
	  if (ucpw == NULL)
	    goto error;

          SSH_IPH6_SET_LEN(ucpw, new_len - SSH_IPH6_HDRLEN);
          ssh_interceptor_packet_copyout(pc->pp, pc->ipsec_offset_prevnh,
                                         &orig_ip_nh, 1);
          if (!ssh_interceptor_packet_copyin(pc->pp, pc->ipsec_offset_prevnh,
                                             &tc->ip_nh, 1))
            goto error;
        }
      else
#endif /* WITH_IPV6 */
        {
	  ucpw = ssh_interceptor_packet_pullup(pc->pp, pc->hdrlen);
	  if (ucpw == NULL)
	    goto error;

          SSH_IPH4_SET_PROTO(ucpw, tc->ip_nh);
          SSH_IPH4_SET_LEN(ucpw, new_len);
          cks = SSH_IPH4_CHECKSUM(ucpw);
          cks = ssh_ip_cksum_update_byte(cks, SSH_IPH4_OFS_PROTO,
                                         pc->ipproto, tc->ip_nh);
          cks = ssh_ip_cksum_update_short(cks, SSH_IPH4_OFS_LEN, orig_len,
                                          (SshUInt16)new_len);
          SSH_IPH4_SET_CHECKSUM(ucpw, cks);
        }
    }

  /* Check and audit for sequence number overflow. */
  if ((pc->transform & SSH_PM_IPSEC_ANTIREPLAY)
      && (((pc->transform & SSH_PM_IPSEC_LONGSEQ)
	   && SSH_UINT64_OVERFLOW(trr->mycount_low, trr->mycount_high))
	  || (!(pc->transform & SSH_PM_IPSEC_LONGSEQ)
	      && trr->mycount_low == 0xffffffff)))
    {
      SSH_DEBUG(SSH_D_FAIL,
		("Sequence number overflow detected, dropping packet."));
#ifdef SSH_IPSEC_AH
      if (pc->transform & SSH_PM_IPSEC_AH)
	{
	  pc->audit.corruption = SSH_PACKET_CORRUPTION_AH_SEQ_NUMBER_OVERFLOW;
	  pc->audit.spi = trr->myspis[SSH_PME_SPI_AH_IN];
	}
      else
#endif /* SSH_IPSEC_AH */
	{
	  pc->audit.corruption = SSH_PACKET_CORRUPTION_ESP_SEQ_NUMBER_OVERFLOW;
	  pc->audit.spi = trr->myspis[SSH_PME_SPI_ESP_IN];
	}
      pc->audit.ip_option = 0;
      pc->audit.seq = 0xffffffff;

      goto fail;
    }

  /* Fill in the ESP header.  We also compute the offsets for
     encryption and MAC computation here. */
  if (pc->transform & SSH_PM_IPSEC_ESP)
    {
      ucpw = prefix + tc->esp_ofs;
      SSH_PUT_32BIT(ucpw, trr->myspis[SSH_PME_SPI_ESP_IN]);

      /* If using 64 bit sequence numbers, only the least significant
         32 bits are sent to the peer. */
      i = trr->mycount_low;
      SSH_PUT_32BIT(ucpw + 4, i);
      enc_ofs = prefix_ofs + tc->esp_ofs + 8;
      ucpw += 8;

      if (tc->cipher && !tc->counter_mode)
        {
          /* Store raw IV for software implementations (this will be
             overwritten by real IV in hw implementations and
             encrypted in SW implementations.  This may be visible to
             the recipient, and thus should not contain any really
             sensitive data.  It is desirable to avoid situations
             where a large number of IVs differing only in one or two
             bit positions would be used, especially if such IVs were
             predictable to the attacker. (All modern ciphers are
             relatively resistant to differential cryptanalysis
             though, so this is not critical.) */
          SSH_ASSERT(tc->cipher_iv_len >= 8);
          i = SSH_GET_32BIT(pc->flow_id + 4);
          i += trr->mycount_low + (SshUInt32)fastpath->engine->run_time +
            (SshUInt32)(size_t)pc;
          SSH_PUT_32BIT(ucpw, i);
          i += (3 * trr->myreplaymask[SSH_ENGINE_REPLAY_WINDOW_WORDS - 1])
            ^ (SshUInt32)(size_t)ucpw;
          SSH_PUT_32BIT(ucpw + 4, i);
        }
      else if (tc->cipher && tc->counter_mode)
        {
          /* IV for counter mode algorithm, use IPSec seq# as counter */
          SSH_ASSERT(tc->cipher_iv_len == 8);
	  SSH_PUT_32BIT(ucpw, trr->mycount_low);
	  SSH_PUT_32BIT(ucpw + 4, trr->mycount_high);
        }
      enc_len = old_len + prefix_len - enc_ofs + pad_len + 2;
      mac_ofs = prefix_ofs + tc->esp_ofs;
      mac_len = new_len - mac_ofs - tc->icv_len;
    }
  else
    {
      enc_len = 0;
      mac_len = 0;
    }
  pc->u.flow.mac_icv_ofs = 0;
#ifdef SSH_IPSEC_AH
  /* Fill in AH header and adjust MAC ofs/len as needed. */
  if (pc->transform & SSH_PM_IPSEC_AH)
    {
      /* Fill in AH header. */
      ucpw = prefix + tc->ah_ofs;
      ucpw[0] = ah_nh ? ah_nh : pc->ipproto;
      ucpw[1] = (tc->icv_len + 12 + tc->ah_hdr_pad_len) / 4 - 2;
      SSH_PUT_32BIT(ucpw + 4, tc->ah_spi);
      pc->u.flow.mac_icv_ofs = prefix_ofs + tc->ah_ofs + 12;

      /* Zeroify the padding bytes */
      if (tc->ah_hdr_pad_len > 0)
        {
          for (i = 0; i < tc->ah_hdr_pad_len; i++)
            ucpw[12 + tc->icv_len + i] = 0;
        }

      /* If using 64 bit sequence numbers, only the least significant
	 32 bits are sent to the peer. */
      i = trr->mycount_low;
      SSH_PUT_32BIT(ucpw + 8, i);
      /* Recompute what to include in MAC. */
      mac_ofs = prefix_ofs + tc->ah_ofs;
      mac_len = new_len - mac_ofs;
      /* IP header is automatically added to the MAC, and the IP
         length in the IP header is automatically adjusted by the
         difference between the end of the IP header and the given
         offset, and IPPROTO in the IP header is automatically taken
         as SSH_IPPROTO_AH regardless of what it is (it could be UDP
         if NAT-T is used). */
    }
#endif /* SSH_IPSEC_AH */

  /* Update packet length in packet context. */
  pc->packet_len = new_len;

#ifdef SSHDIST_IPSEC_NAT_TRAVERSAL
  /* This code does not use the fastpath_transform_add_natt_header on
     purpose.  Doing the minimal work here is faster. */

  /* Construct NAT Traversal header. */
  if (pc->transform & SSH_PM_IPSEC_NATT)
    {
      /* Only ESP is supported by the latest drafts and RFC. */
      SSH_ASSERT((pc->transform & SSH_PM_IPSEC_AH) == 0);

      /* Fill in NAT Traversal header. */
      ucpw = prefix + tc->natt_ofs;
      SSH_PUT_16BIT(ucpw, trr->local_port);
      SSH_PUT_16BIT(ucpw + 2, trr->remote_port);
      SSH_PUT_16BIT(ucpw + 4, pc->packet_len - tc->natt_ofs - prefix_ofs);
    }
#endif /* SSHDIST_IPSEC_NAT_TRAVERSAL */

#ifdef SSHDIST_IPSEC_IPCOMP
#ifdef SSH_IPSEC_IPCOMP_IN_SOFTWARE
  /* Add an IPComp header if compression succeeded. */
  if ((pc->transform & SSH_PM_IPSEC_IPCOMP) && ipcomp_done)
    {
      ucpw = prefix + tc->ipcomp_ofs;
      ucpw[0] = tc->ipcomp_nh ? tc->ipcomp_nh : pc->ipproto;
      ucpw[1] = 0;
      SSH_PUT_16BIT(ucpw + 2, tc->ipcomp_cpi);
    }
#endif /* SSH_IPSEC_IPCOMP_IN_SOFTWARE */
#endif /* SSHDIST_IPSEC_IPCOMP */

#ifdef SSHDIST_L2TP
  /* Construct L2TP UDP+PPP headers. However if IPcomp compression 
     succeeded the L2TP headers are already compressed and should not be 
     added. */
  if ((pc->transform & SSH_PM_IPSEC_L2TP) && !ipcomp_done)
    {
      SshUInt8 l2tp_ofs = tc->l2tp_ofs;

      if (pc->transform & SSH_PM_IPSEC_IPCOMP)
	{
	  /* The offset of the L2TP header is 4 less than the the value 
	     in tc->l2tp_ofs if we get here (IPcomp compression did not 
	     succeed and there is no IPComp header) */
	  l2tp_ofs -= 4;
	}
      
      fastpath_transform_construct_l2tp_header(pc, tc, prefix + l2tp_ofs, 
					     sizeof(prefix) - l2tp_ofs, 
					     NULL);
    }
#endif /* SSHDIST_L2TP */

  /* Fill in new IP header for tunneling. */
  if (tc->prefix_at_0)
    {
      /* Construct a new IP header.  It is always at the beginning of
         the prefix. */
#if defined (WITH_IPV6)
      if (SSH_IP_IS6(&trr->gw_addr))
        {
          /* Construct a new IPv6 header. */
          SSH_IPH6_SET_VERSION(prefix, 6);
          if (pc->pp->protocol == SSH_PROTOCOL_IP4)
            /* We should map the IPv4 Type of Service to IPv6 Traffic
               Class but since no such mapping exists, we follow RFC
               2473 and use pre-defined value 0. */
            tos = 0;







          SSH_IPH6_SET_CLASS(prefix, tos);
          SSH_IPH6_SET_FLOW(prefix, flow_label);
          SSH_IPH6_SET_LEN(prefix, new_len - SSH_IPH6_HDRLEN);
          SSH_IPH6_SET_NH(prefix, tc->ip_nh);
          SSH_IPH6_SET_HL(prefix, 240);
          SSH_IPH6_SET_SRC(&trr->local_addr, prefix);
          SSH_IPH6_SET_DST(&trr->gw_addr, prefix);

          /* Initialize IPv6-specific fields in the packet context in
             case we should have to, e.g. fragment this packet. */
          pc->fragh_offset = pc->ipsec_offset = SSH_IPH6_HDRLEN;
          pc->fragh_offset_prevnh = pc->ipsec_offset_prevnh = SSH_IPH6_OFS_NH;
        }
      else
#endif /* WITH_IPV6 */
        {
          /* Construct the new IPv4 header. */
          SSH_IPH4_SET_VERSION(prefix, 4);
          SSH_IPH4_SET_HLEN(prefix, SSH_IPH4_HDRLEN / 4);
#if defined (WITH_IPV6)
          if (pc->pp->protocol == SSH_PROTOCOL_IP6)
            /* We should map the IPv6 Traffic Class to TOS but since
               no such mapping exists, we follow RFC 2473 and use
               pre-defined value 0. */
            tos = 0;
#endif /* WITH_IPV6 */
          SSH_IPH4_SET_TOS(prefix, tos);
          SSH_IPH4_SET_ID(prefix, trr->myipid);

          /* Copy DF and RF bits from the original header.*/
          fragoff &= (SSH_IPH4_FRAGOFF_DF | SSH_IPH4_FRAGOFF_RF);
          SSH_IPH4_SET_FRAGOFF(prefix, fragoff);

          SSH_IPH4_SET_TTL(prefix, 240); /* Outer header TTL. */
          SSH_IPH4_SET_SRC(&trr->local_addr, prefix);
          SSH_IPH4_SET_DST(&trr->gw_addr, prefix);
          SSH_IPH4_SET_PROTO(prefix, tc->ip_nh);
          SSH_IPH4_SET_LEN(prefix, pc->packet_len); /* Set new packet length */
          /* SSH_IPH4_SET_CHECKSUM(prefix, 0);
             (done implicitly by memset earlier) */
          cks = ssh_ip_cksum(prefix, SSH_IPH4_HDRLEN);
          SSH_IPH4_SET_CHECKSUM(prefix, cks);
        }
    }

  /* Insert the prefix into the packet. */
  for (i = 0; i < prefix_len; i += len)
    {
      len = 80;
      if (i + len > prefix_len)
        len = prefix_len - i;
      ucpw = ssh_interceptor_packet_insert(pc->pp, prefix_ofs + i, len);
      if (!ucpw)
        {
          SSH_DEBUG(SSH_D_FAIL, ("insert failed"));
          goto error;
        }
      memcpy(ucpw, prefix + i, len);
    }

  /* Insert ESP trailer (padding and MAC). */
  if (tc->trailer_len > 0)
    {
      i = old_len + prefix_len;
      SSH_ASSERT(i == ssh_interceptor_packet_len(pc->pp));
      ucpw = ssh_interceptor_packet_insert(pc->pp, i,
                                           tc->trailer_len + pad_len);
      if (!ucpw)
        {
          SSH_DEBUG(SSH_D_FAIL, ("insert failed"));
          goto error;
        }

      /* Initialize self-describing. */
      for (i = 0; i < pad_len; i++)
        ucpw[i] = i + 1;
      ucpw[i++] = (SshUInt8) pad_len;
      ucpw[i++] = esp_nh ? esp_nh : orig_ip_nh;
    }

  SSH_ASSERT(pc->packet_len == ssh_interceptor_packet_len(pc->pp));

  /* Determine mac_icv_ofs if not already done. */
  if (pc->u.flow.mac_icv_ofs == 0)
    pc->u.flow.mac_icv_ofs = pc->packet_len - tc->icv_len;

  /* If using 64 bit sequence numbers, insert the most significant
     32 bits of the sequence number to the packet. For ESP insert the data
     at the end of the payload just before the ICV, for AH insert at the
     end of the payload. The higher order bits of the sequence number
     are included in the ICV computation but do not get encrypted. Also
     they are not sent on the wire (the data gets removed in
     ssh_fastpath_transform_out_finish) */
  if ((pc->transform & (SSH_PM_IPSEC_ESP | SSH_PM_IPSEC_AH)) &&
      pc->transform & SSH_PM_IPSEC_LONGSEQ)
    {
      size_t longseq_ofs = 0;

      if (pc->transform & SSH_PM_IPSEC_AH)
        longseq_ofs = pc->packet_len;
      else if (pc->transform & SSH_PM_IPSEC_ESP)
        longseq_ofs = pc->u.flow.mac_icv_ofs;
      else
        SSH_NOTREACHED;

      ucpw = ssh_interceptor_packet_insert(pc->pp, longseq_ofs, 4);
      if (!ucpw)
        goto error;

      i = trr->mycount_high;
      SSH_PUT_32BIT(ucpw, i);
      mac_len += 4;
      pc->packet_len += 4;

      if (!(pc->transform & SSH_PM_IPSEC_AH))
        pc->u.flow.mac_icv_ofs += 4;
    }

  SSH_DUMP_PACKET(SSH_D_MY + 10, "to be encrypted: ", pc->pp);

#ifdef SSHDIST_IPSEC_HWACCEL
  /* Perform encryption and authentication computations. */
  if (tc->encmac_accel)
    {
      /* Use hardware acceleration to perform the rest. */
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Performing hardware IPsec transform"));
      pc->u.flow.mac_done = 0x01;
      ssh_hwaccel_perform_ipsec(tc->encmac_accel, pc->pp, enc_ofs, enc_len,
                                mac_ofs, mac_len, pc->u.flow.mac_icv_ofs,
                                ssh_fastpath_transform_out_finish, (void *)pc);
      return;
    }
#endif /* SSHDIST_IPSEC_HWACCEL */

  /* Save enough data to perform after encryption in callback. */
  pc->u.flow.mac_ofs = mac_ofs;
  pc->u.flow.mac_len = mac_len;
  pc->u.flow.mac_done = 0x00;

#ifdef SSHDIST_IPSEC_HWACCEL
  if (tc->enc_accel)
    {
      /* Use hardware acceleration to perform encryption, and then
         perform MAC computation in software. */
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Performing hardware IPsec transform"));
      ssh_hwaccel_perform_ipsec(tc->enc_accel, pc->pp, enc_ofs, enc_len,
                                0, 0, 0,
                                ssh_fastpath_transform_out_finish, (void *)pc);
      return;
    }
#endif /* SSHDIST_IPSEC_HWACCEL */

  SSH_DEBUG(SSH_D_NICETOKNOW, ("Performing software IPsec transform"));

  /* Perform encryption in software. */
  if (tc->cipher && (pc->transform & SSH_PM_IPSEC_ESP))
    {
      /* For auth_cipher, we'll have to handle aad
         before actual esp transform. */
      if (tc->cipher->is_auth_cipher)
        {
	  Boolean iv_in_aad = !!(pc->transform & SSH_PM_CRYPT_NULL_AUTH_AES_GMAC);
          SSH_ASSERT(tc->counter_mode);
          /* Pass in the AAD. Notice, enc_ofs-enc_ofs+enc_len
             MUST not be passed as AAD as it will be handled
             in combined transform. */

	  if (!ssh_ipsec_esp_process_aad(pc->pp,
					 tc->cipher,
					 tc->cipher_context,
					 mac_ofs,
					 enc_ofs - mac_ofs +
					 iv_in_aad * 8,
					 !!(pc->transform & SSH_PM_IPSEC_LONGSEQ), 
					 trr->mycount_high))
	    {
	      SSH_DEBUG(SSH_D_FAIL, ("process_aad failed"));
	      goto error;          
	    }
        }

      /* Encrypt the packet.  We also encrypt the iv. */
      if (!ssh_ipsec_esp_transform_chain(pc->pp,
                                         tc->cipher,
                                         tc->cipher_context,
                                         tc->counter_mode,
                                         tc->cipher_nonce,
                                         tc->cipher_block_len,
                                         tc->cipher_iv_len,
                                         enc_ofs,
                                         enc_len))
        {
          SSH_DEBUG(SSH_D_FAIL, ("transform_chain failed"));
          goto error;
        }
    }

  ssh_fastpath_transform_out_finish(pc->pp,
#ifdef SSHDIST_IPSEC_HWACCEL
				  SSH_HWACCEL_OK,
#endif /* SSHDIST_IPSEC_HWACCEL */
				  (void *)pc);
}
#endif /* SSHDIST_IPSEC_TRANSFORM */
