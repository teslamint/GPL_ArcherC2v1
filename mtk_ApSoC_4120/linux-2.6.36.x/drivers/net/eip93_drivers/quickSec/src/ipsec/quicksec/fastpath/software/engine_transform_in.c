/*
 * engine_transform_in.c
 *
 * Copyright:
 *       Copyright (c) 2002-2006 SFNT Finland Oy.
 *       All rights reserved.
 *
 * Code to implement IPSEC and other transforms for incoming packets.
 *
 *
 * Note : When decapsulating the headers in a packet, the offsets of each 
 * header must be computed from parsing the packet and not using the 
 * offsets in the SshFastpathTransformContext data type. For example, the 
 * IPComp header may or may not be present in a packet whose transform has 
 * IPComp enabled. Similarly in MOBIKE scanarios we must be able to 
 * decapsulate packets regardless of whether they have a NAT-T header or 
 * not. Hence you must not use any of the fields such as tc->esp_ofs, 
 * tc->l2tp_ofs etc. for finding the offset of a encapsulation header.  
 *
 */

#include "sshincludes.h"
#include "engine_internal.h"
#ifdef SSHDIST_L2TP
#include "sshl2tp.h"
#include "sshl2tp_parse.h"
#endif /* SSHDIST_L2TP */

#include "fastpath_swi.h"
#define SSH_DEBUG_MODULE "SshEngineFastpathTransformIn"

#ifdef SSHDIST_IPSEC_TRANSFORM

/* Structure describing a 64 bit integer. We cannot use 'SshUInt64'
   type since it is not guarenteed to be 64 bits on all platforms. */
typedef struct SshUInt64Rec
{
  SshUInt32 high;
  SshUInt32 low;
} SshUInt64Struct;

#define SSH_UINT64_GE(a, b)  \
((a.high > b.high) || (a.high == b.high && a.low > b.low))
#define SSH_UINT64_GEQ(a, b)  \
((a.high > b.high) || (a.high == b.high && a.low >= b.low))
#define SSH_UINT64_LE(a, b)  \
((a.high < b.high) || (a.high == b.high && a.low < b.low))
#define SSH_UINT64_LEQ(a, b) \
((a.high < b.high) || (a.high == b.high && a.low <= b.low))

#define SSH_UINT64_ADD(c, a, b)                                      \
  do { SshUInt32 __temp; __temp = a.low + b.low;                     \
  c.high = (__temp < a.low) ? a.high + b.high + 1 : a.high + b.high; \
  c.low = __temp; } while(0)

#define SSH_UINT64_ADD32(c, a, b)                                    \
  do { SshUInt32 __temp; __temp = a.low + b;                         \
  c.high = (__temp < a.low) ? a.high + 1 : a.high;                   \
  c.low = __temp; } while(0)

/* This assumes 'a' is larger (as a 64 bit integer) than 'b' */
#define SSH_UINT64_SUB(c, a, b)                                      \
  do { SshUInt32 __temp; __temp = a.low - b.low;                     \
  c.high = (b.low <= a.low) ? a.high - b.high : a.high - b.high - 1; \
  c.low = __temp; } while(0)
 
  
static Boolean
fastpath_transform_in_perform_antireplay(SshEnginePacketContext pc,
					 SshUInt32 sequence_number)
{
  SshFastpathTransformContext tc = pc->u.flow.tc;
  SshFastpath fastpath = pc->engine->fastpath;
  SshEngineTransformData trd;
  SshEngineTransformRun trr;
  SshUInt32 *replay_window;
  SshUInt32 transform;
  Boolean rekeyold;
  SshUInt64Struct seq, replay_offset, max, diff, temp;
  unsigned int bit_ofs;

  trr = pc->u.flow.trr;
  transform = pc->transform;
  seq.high = 0;
  seq.low = sequence_number;

  /* Update replay prevention information. */
  if (transform & (SSH_PM_IPSEC_ESP | SSH_PM_IPSEC_AH))
    {
      FP_LOCK_WRITE(fastpath);

      trd = FP_GET_TRD(fastpath, pc->transform_index);
      if (trd == NULL)
        {
          /* Transform generation mismatch. */
	  FP_RELEASE_TRD(fastpath, pc->transform_index);
          goto fail;
        }

      if (transform & SSH_PM_IPSEC_ANTIREPLAY)
        {
          /* Determine whether we are using old info or new info.
             This code also checks that the transform is still the
             same transform (SPIs have not changed). */
          if (transform & SSH_PM_IPSEC_AH)
            {
              if (trd->spis[SSH_PME_SPI_AH_IN] == tc->ah_spi)
                rekeyold = FALSE;
              else
                if (trd->old_spis[SSH_PME_SPI_AH_IN] == tc->ah_spi)
                  rekeyold = TRUE;
                else
                  {
                  badtrd:
                    SSH_DEBUG(SSH_D_FAIL, ("spi mismatch in trd replay"));
                    goto fail;
                  }
            }
          else
            {
              if (trd->spis[SSH_PME_SPI_ESP_IN] == tc->esp_spi)
                rekeyold = FALSE;
              else
                if (trd->old_spis[SSH_PME_SPI_ESP_IN] == tc->esp_spi)
                  rekeyold = TRUE;
                else
                  goto badtrd;
            }

          /* Read up-to-date anti-replay information from trd. */
          if (rekeyold)
            {
              replay_offset.high = trd->old_replay_offset_high;
              replay_offset.low = trd->old_replay_offset_low;
              replay_window = trd->old_replay_mask;
            }
          else
            {
              replay_offset.high = trd->replay_offset_high;
              replay_offset.low = trd->replay_offset_low;
              replay_window = trd->replay_mask;
            }

          if (transform & SSH_PM_IPSEC_LONGSEQ)
            {
              /* Determine seq_high from seq_low and the present position
                 of the antireplay window. */
              seq.high = (seq.low >= replay_offset.low) ? replay_offset.high :
                replay_offset.high + 1;
            }
          else
            {
              seq.high = 0;
            }

          /* Recheck that seq is not to the left of the window */
          if (SSH_UINT64_LE(seq, replay_offset))
            {
              SSH_DEBUG(SSH_D_FAIL, ("Replay prevention recheck fail"));
              trr->statflags |= SSH_ENGINE_STAT_T_REPLAY;
              SSH_ENGINE_MARK_STAT(pc, SSH_ENGINE_STAT_REPLAYDROP);
#ifdef SSH_IPSEC_AH
              if (transform & SSH_PM_IPSEC_AH)
		{
		  pc->audit.corruption
		    = SSH_PACKET_CORRUPTION_AH_SEQ_NUMBER_FAILURE;
		  pc->audit.spi = trr->myspis[SSH_PME_SPI_AH_IN];
		}
              else
#endif /* SSH_IPSEC_AH */
		{
		  pc->audit.corruption =
		    SSH_PACKET_CORRUPTION_ESP_SEQ_NUMBER_FAILURE;
		  pc->audit.spi = trr->myspis[SSH_PME_SPI_ESP_IN];
		}
	      pc->tunnel_id = trr->restart_tunnel_id;
	      pc->audit.ip_option = 0;
              goto fail;
            }

          SSH_UINT64_ADD32(max, replay_offset,
                           32 * SSH_ENGINE_REPLAY_WINDOW_WORDS);

          /* Recheck that seq does not lie in the replay window bit field */
          if (SSH_UINT64_LE(seq, max) || SSH_UINT64_GE(replay_offset, max))
            {
              SSH_UINT64_SUB(diff, seq, replay_offset);
              SSH_ASSERT(diff.high == 0);
              bit_ofs = diff.low;

              SSH_ASSERT(bit_ofs < 32 * SSH_ENGINE_REPLAY_WINDOW_WORDS);

              if (replay_window[bit_ofs / 32] &
                  ((SshUInt32) 1 << (bit_ofs & 31)))
                {
                  SSH_DEBUG(SSH_D_FAIL,("Replay prevention recheck fail"));
                  trr->statflags |= SSH_ENGINE_STAT_T_REPLAY;
                  SSH_ENGINE_MARK_STAT(pc, SSH_ENGINE_STAT_REPLAYDROP);
#ifdef SSH_IPSEC_AH
                  if (transform & SSH_PM_IPSEC_AH)
		    {
		      pc->audit.spi = trr->myspis[SSH_PME_SPI_AH_IN];
		      pc->audit.corruption =
			SSH_PACKET_CORRUPTION_AH_SEQ_NUMBER_FAILURE;
		    }
                  else
#endif /* SSH_IPSEC_AH */
		    {
		      pc->audit.spi = trr->myspis[SSH_PME_SPI_ESP_IN];
		      pc->audit.corruption =
			SSH_PACKET_CORRUPTION_ESP_SEQ_NUMBER_FAILURE;
		    }
		  pc->tunnel_id = trr->restart_tunnel_id;
		  pc->audit.ip_option = 0;
                  goto fail;
                }
            }

          /* Check whether we need to shift the replay window. Note that
             we must check that replay_offset does not wrap around when
             we add to it. */
          if (SSH_UINT64_GEQ(seq, max) && SSH_UINT64_LE(replay_offset, max))
            {
              SshUInt32 *words, diff_words = 0;
              unsigned int words_to_keep, i;

              SSH_DEBUG_HEXDUMP(SSH_D_NICETOKNOW, ("Old replay window"),
                                (unsigned char *)replay_window,
                                4 * SSH_ENGINE_REPLAY_WINDOW_WORDS);

              /* We need to shift the window.  We always shift in
                 multiples of 32 bits to improve performance. The goal
                 is to bring the bit position holding the new packet
                 into the last word of the array. This also improves
                 performance by causing this code to be executed for
                 every 32th packet only. */
              SSH_UINT64_SUB(diff, seq, max);
              SSH_UINT64_ADD32(diff, diff, 1);

              if (diff.high)
                {
                  words_to_keep = 0;
                }
              else
                {
                  /* Compute the number of words the window is to move. */
                  diff_words = (diff.low + 31) / 32;
                  /* Compute the number of words to keep in the window. */
                  if (diff_words > SSH_ENGINE_REPLAY_WINDOW_WORDS)
                    words_to_keep = 0;
                  else
                   words_to_keep = SSH_ENGINE_REPLAY_WINDOW_WORDS - diff_words;
                }

              /* Now update the window. */
              words = replay_window;
              for (i = 0; i < words_to_keep; i++)
                words[i] = words[i + diff_words];
              for (i = words_to_keep; i < SSH_ENGINE_REPLAY_WINDOW_WORDS; i++)
                words[i] = 0;

              diff.low = diff_words * 32;
              SSH_UINT64_ADD(replay_offset, replay_offset, diff);

              SSH_UINT64_ADD32(temp, replay_offset,
                               32 * SSH_ENGINE_REPLAY_WINDOW_WORDS - 32);
              SSH_ASSERT(SSH_UINT64_LEQ(temp, seq));

              SSH_UINT64_ADD32(temp, replay_offset,
                               32 * SSH_ENGINE_REPLAY_WINDOW_WORDS);
              SSH_ASSERT(SSH_UINT64_GE(temp, seq));

              SSH_DEBUG_HEXDUMP(SSH_D_NICETOKNOW,
                                ("Updated replay window"),
                                (unsigned char *)replay_window,
                                4 * SSH_ENGINE_REPLAY_WINDOW_WORDS);
            }

          /* Set the appropriate bit in the replay window to indicate
             that the corresponding packet has been received. */
          SSH_UINT64_SUB(diff, seq, replay_offset);
          SSH_ASSERT(diff.high == 0);
          bit_ofs = diff.low;

          SSH_ASSERT(bit_ofs < 32 * SSH_ENGINE_REPLAY_WINDOW_WORDS);

          replay_window[bit_ofs / 32] |= ((SshUInt32) 1 << (bit_ofs & 31));

          /* Update anti-replay information in trd. */
          if (rekeyold)
            {
              trd->old_replay_offset_high = replay_offset.high;
              trd->old_replay_offset_low = replay_offset.low;
            }
          else
            {
              trd->replay_offset_high = replay_offset.high;
              trd->replay_offset_low = replay_offset.low;
            }
        }

      FP_COMMIT_TRD(fastpath, pc->transform_index, trd);
      FP_UNLOCK_WRITE(fastpath);
    }

  return TRUE;
 fail:
  FP_RELEASE_TRD(fastpath, pc->transform_index);
  FP_UNLOCK_WRITE(fastpath);
  return FALSE;
}

/* This is called to complete the packet processing */
#ifdef SSHDIST_IPSEC_HWACCEL
/* This is also called for completion of hw accelerated transform, or
   its first part of processing the packet has otherwise been
   completed.  (Combined transform acceleration is handled separately;
   see fastpath_transform_in_finish_combined.)  If
   pc->u.flow.mac_done is TRUE, then the packet has already been
   decrypted when we get here.  When we get here, pc->u.flow.icv and
   the ICV in the packet contain the original and computed ICVs for
   the packet (either way, dependening on how we came here), and this
   function is responsible for comparing them.  */
#endif /* SSHDIST_IPSEC_HWACCEL */

void fastpath_transform_in_finish(SshInterceptorPacket pp,
#ifdef SSHDIST_IPSEC_HWACCEL
				  SshHWAccelResultCode result,
#endif /* SSHDIST_IPSEC_HWACCEL */
				  void *context)
{
  SshEnginePacketContext pc = (SshEnginePacketContext)context;
  SshFastpathTransformContext tc = pc->u.flow.tc;
  SshFastpath fastpath = pc->engine->fastpath;
  SshEngineTransformRun trr;
  unsigned char prefix[SSH_ENGINE_MAX_TRANSFORM_PREFIX];
  unsigned char *ucpw, *seg;
  SshUInt32 seq, trailer_len, prefix_ofs, i;
  size_t prefix_len, esp_ofs = 0;
#ifdef SSH_IPSEC_AH
  size_t ah_ofs = 0;
#endif /* SSH_IPSEC_AH */
  SshUInt16 cks, old_ip_len;
#ifdef SSHDIST_L2TP
  SshUInt16 bits, l2tp_ofs;
#endif /* SSHDIST_L2TP */
  unsigned char trailerhdr[2];
  size_t pad_len, seglen; 
#ifdef SSHDIST_IPSEC_NAT_TRAVERSAL
    size_t cksum_len;
#endif /* SSHDIST_IPSEC_NAT_TRAVERSAL */
  SshUInt8 ipproto, old_ipproto;
  SshUInt8 ds_outer, ds_inner, ds_inner_new; /* For ECN processing */
#ifdef SSHDIST_IPSEC_IPCOMP
#ifdef SSH_IPSEC_IPCOMP_IN_SOFTWARE
  Boolean ipcomp_present = FALSE;
  SshFastpathTransformIpcompStatus ipcomp_status;
#endif /* SSH_IPSEC_IPCOMP_IN_SOFTWARE */
#endif /* SSHDIST_IPSEC_IPCOMP */

  SSH_INTERCEPTOR_STACK_MARK();

  trr = pc->u.flow.trr;
  seq = 0;

  pc->pp = pp;

#ifdef SSHDIST_IPSEC_HWACCEL
  if (pp == NULL || result != SSH_HWACCEL_OK)
    {
      if (result & SSH_HWACCEL_ICV_FAILURE)
	{
	  trr->statflags |= SSH_ENGINE_STAT_T_MAC_FAIL;
	  pc->audit.corruption = (pc->transform & SSH_PM_IPSEC_AH)
	    ? SSH_PACKET_CORRUPTION_AH_ICV_FAILURE
	    : SSH_PACKET_CORRUPTION_ESP_ICV_FAILURE;
	}
      if (result & SSH_HWACCEL_SEQ_FAILURE)
	{
	  trr->statflags |= SSH_ENGINE_STAT_T_REPLAY;
	  SSH_ENGINE_MARK_STAT(pc, SSH_ENGINE_STAT_REPLAYDROP);
	  if (pc->transform & SSH_PM_IPSEC_AH)
	    {
	      SSH_ENGINE_MARK_STAT(pc, SSH_ENGINE_STAT_AHMACDROP);
	      pc->audit.spi = trr->myspis[SSH_PME_SPI_AH_IN];
	      pc->audit.corruption =
		SSH_PACKET_CORRUPTION_AH_SEQ_NUMBER_FAILURE;
	    }
	  if (pc->transform & SSH_PM_IPSEC_ESP)
	    {
	      SSH_ENGINE_MARK_STAT(pc, SSH_ENGINE_STAT_ESPMACDROP);
	      pc->audit.spi = trr->myspis[SSH_PME_SPI_ESP_IN];
	      pc->audit.corruption =
		SSH_PACKET_CORRUPTION_ESP_SEQ_NUMBER_FAILURE;
	    }
	  pc->tunnel_id = trr->restart_tunnel_id;
	  pc->audit.ip_option = 0;
	}
      SSH_DEBUG(SSH_D_FAIL, ("Hardware acceleration dropped packet"));
      SSH_ENGINE_MARK_STAT(pc, SSH_ENGINE_STAT_HWACCELDROP);
      goto fail;
    }
#endif /* SSHDIST_IPSEC_HWACCEL */

  /* Check the computed MAC value (assuming we have a MAC). */
  if ((pc->u.flow.mac_done & 0x02) == 0 &&
      (tc->mac ||
       (pc->transform & (SSH_PM_CRYPT_NULL_AUTH_AES_GMAC 
			 | SSH_PM_IPSEC_AH)) == 
       (SSH_PM_CRYPT_NULL_AUTH_AES_GMAC | SSH_PM_IPSEC_AH)))
    {
      if ((tc->encmac_accel || tc->mac_accel) && tc->icv_len > 0)
        /* The hardware accelerator leaves the icv in the packet so we
           must copy it out now. */
        ssh_interceptor_packet_copyout(pc->pp, pc->u.flow.mac_icv_ofs,
                                       pc->u.flow.icv, tc->icv_len);

      if (memcmp(pc->u.flow.packet_icv, pc->u.flow.icv, tc->icv_len) != 0)
        {
	icv_check_failed:















          SSH_DEBUG(SSH_D_FAIL, ("ICV check fails"));
          trr->statflags |= SSH_ENGINE_STAT_T_MAC_FAIL;
#ifdef SSH_IPSEC_AH
          if (pc->transform & SSH_PM_IPSEC_AH)
            {
              SSH_ENGINE_MARK_STAT(pc, SSH_ENGINE_STAT_AHMACDROP);
	      pc->audit.spi = trr->myspis[SSH_PME_SPI_AH_IN];
	      pc->audit.corruption = SSH_PACKET_CORRUPTION_AH_ICV_FAILURE;
            }
          else
#endif /* SSH_IPSEC_AH */
            {
              SSH_ENGINE_MARK_STAT(pc, SSH_ENGINE_STAT_ESPMACDROP);
	      pc->audit.spi = trr->myspis[SSH_PME_SPI_ESP_IN];
	      pc->audit.corruption = SSH_PACKET_CORRUPTION_ESP_ICV_FAILURE;
            }
	  /* Assing from-tunnel ID for the audit event. */
	  pc->tunnel_id = trr->restart_tunnel_id;
	  pc->audit.ip_option = 0;
          goto fail;
        }

      /* MAC successful. */
      pc->u.flow.mac_done |= 0x02;
      /* Mark that packet has had at least one MAC succesfully verified. */
      pp->flags |= SSH_PACKET_AUTHENTIC;
    }

  /* If using 64 bit sequence numbers, remove the most significant
     32 bits of the sequence number that was previously inserted to
     the packet. */
  if ((pc->transform & (SSH_PM_IPSEC_ESP | SSH_PM_IPSEC_AH)) &&
      pc->transform & SSH_PM_IPSEC_LONGSEQ)
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

  /* Check if the packet has already been decrypted.  If not, decrypt
     it now. */
  if ((tc->cipher || tc->enc_accel) && (pc->u.flow.mac_done & 0x01) == 0 &&
      (pc->transform & (SSH_PM_IPSEC_ESP)))
    {
      pp->flags |= SSH_PACKET_CONFIDENTIAL;
      pc->u.flow.mac_done |= 0x01;
#ifdef SSHDIST_IPSEC_HWACCEL
      if (tc->enc_accel)
        {
          ssh_hwaccel_perform_ipsec(tc->enc_accel, pc->pp, pc->u.flow.mac_ofs,
                                    pc->u.flow.mac_len, /* really enc len/ofs*/
                                    0, 0, 0, fastpath_transform_in_finish,
                                    (void *)pc);
          return;
        }
#endif /* SSHDIST_IPSEC_HWACCEL */
      /* Perform the decryption in software. */
      if (!ssh_ipsec_esp_transform_chain(pc->pp,
                                         tc->cipher,
                                         tc->cipher_context,
                                         tc->counter_mode,
                                         tc->cipher_nonce,
                                         tc->cipher_block_len,
                                         tc->cipher_iv_len,
                                         pc->u.flow.mac_ofs, /* enc len */
                                         pc->u.flow.mac_len)) /* enc ofs */
        goto error;
    }

  /* Check if we're using combined cipher */
  if (tc->cipher && tc->cipher->is_auth_cipher && 
      (pc->u.flow.mac_done & 0x02) == 0)
    {
      SshCryptoStatus status;
      SSH_ASSERT(tc->cipher->digest_length <= sizeof(pc->u.flow.icv));

      status = (*tc->cipher->final)(tc->cipher_context, pc->u.flow.icv);
      
      if (status != SSH_CRYPTO_OK)
        {
          SSH_DEBUG(SSH_D_FAIL, ("MAC operation failed: %d", status));
          goto fail;
        }

      if (memcmp(pc->u.flow.packet_icv, pc->u.flow.icv, tc->icv_len) != 0)
	{
	  /* Goto used here, to prevent code duplication. Unfortunately,
	     icv failure is detected with combined cipher on different
	     phase of transformation process than with standard mac. */
	  goto icv_check_failed;
	}
    }

  /* The packet has now been authenticated and decrypted.  Copy the prefix
     from the packet into a local buffer so that we don't need to worry about
     interceptor's pullup byte limit.  Note that we don't know the
     exact length of the prefix here (in particular not the length of the
     L2TP header).  Consequently, we copy up to the maximum (if the packet
     has that much data) and determine the length as we parse it. */
  if (tc->prefix_at_0)
    prefix_ofs = 0;
  else
    prefix_ofs = pc->hdrlen;
  prefix_len = pc->packet_len - prefix_ofs;
  if (prefix_len > SSH_ENGINE_MAX_TRANSFORM_PREFIX)
    prefix_len = SSH_ENGINE_MAX_TRANSFORM_PREFIX;

  /* Determine the packet prefix length and offsets to allow decapsulation
     of a packet regardless if it has or does not have UDP encapsulation.
     The offset values in tc are used for outbound transform execution. In 
     inbound transform execution the offsets need to be corrected depending 
     whether packet and tc NAT-T status match. */

  /* NAT-T packet, non NAT-T tc */
  if (pc->ipproto == SSH_IPPROTO_UDP
      && (pc->transform & SSH_PM_IPSEC_NATT) == 0)
    {
      esp_ofs = tc->esp_ofs + 8;
#ifdef SSH_IPSEC_AH
      ah_ofs = tc->ah_ofs + 8;
#endif /* SSH_IPSEC_AH */
    }
  else if (pc->ipproto != SSH_IPPROTO_UDP 
	   && (pc->transform & SSH_PM_IPSEC_NATT))
    {
      /* non NAT-T packet, NAT-T tc */
      esp_ofs = tc->esp_ofs - 8;
#ifdef SSH_IPSEC_AH
      ah_ofs = tc->ah_ofs - 8;
#endif /* SSH_IPSEC_AH */
    }
  else
    {
      /* Packet matches tc */
      esp_ofs = tc->esp_ofs;
#ifdef SSH_IPSEC_AH
      ah_ofs = tc->ah_ofs;
#endif /* SSH_IPSEC_AH */
    }
  



  ssh_interceptor_packet_copyout(pc->pp, prefix_ofs, prefix, prefix_len);

  /* Update replay prevention counters. */
#ifdef SSH_IPSEC_AH
  if (pc->transform & SSH_PM_IPSEC_AH)
    {
      ucpw = prefix + ah_ofs;
      /* This has already been checked below, so a failure here can only
         be due to a bug. */
      SSH_ASSERT(SSH_GET_32BIT(ucpw + 4) == tc->ah_spi);
      seq  = SSH_GET_32BIT(ucpw + 8);
    }
  else
#endif /* SSH_IPSEC_AH */
    if (pc->transform & SSH_PM_IPSEC_ESP)
      {
        ucpw = prefix + esp_ofs;
        /* This was already checked earlier, so a failure here can only be
           due to a bug. */
        SSH_ASSERT(SSH_GET_32BIT(ucpw) == tc->esp_spi);
        seq = SSH_GET_32BIT(ucpw + 4);
      }

  /* Update replay prevention information. */
  if (pc->transform & (SSH_PM_IPSEC_ESP | SSH_PM_IPSEC_AH))
    {
      if (!fastpath_transform_in_perform_antireplay(pc, seq))
        goto fail;
    }

  /* Delete ESP trailer.  Save next header field from ESP. */
  if (pc->transform & SSH_PM_IPSEC_ESP)
    {
      /* Read trailer len into icv [buffer reused for differnet purpose]. */
      ssh_interceptor_packet_copyout(pc->pp, pc->packet_len - tc->trailer_len,
                                     trailerhdr, 2);

      trailer_len = tc->trailer_len + trailerhdr[0];
      ipproto = trailerhdr[1];

      if (pc->packet_len < prefix_ofs + trailer_len)
        {
          SSH_DEBUG(SSH_D_NETGARB, ("Packet too short"));
          goto garbage;
        }

      /* Verify the ESP self-describing padding */
      pad_len = 0;
      ssh_interceptor_packet_reset_iteration(pp, pc->packet_len - trailer_len,
                                             trailerhdr[0]);
      while (ssh_interceptor_packet_next_iteration(pp, &seg, &seglen))
        {
          for (i = 0; i < seglen; i++)
            {
              if (seg[i] != pad_len + i + 1)
                {
                  SSH_DEBUG(SSH_D_NETGARB, ("Packet has invalid ESP padding"));
                  goto garbage;
                }
            }
          pad_len += seglen;
        }
      if (seg != NULL || (pad_len != trailerhdr[0]))
        goto fail;

      SSH_DEBUG(SSH_D_LOWOK, ("Total pad length is %d", pad_len));

      /* Delete the trailer. */
      if (!ssh_interceptor_packet_delete(pc->pp, pc->packet_len - trailer_len,
                                         trailer_len))
        {
          SSH_ENGINE_MARK_STAT(pc, SSH_ENGINE_STAT_ERRORDROP);
          goto error;
        }
      pc->packet_len -= trailer_len;
    }
  else
    {
      trailer_len = 0;
      ipproto = SSH_IPPROTO_ANY;
    }

#ifdef SSH_IPSEC_AH
  if ((pc->transform & (SSH_PM_IPSEC_AH | SSH_PM_IPSEC_ESP)) ==
       SSH_PM_IPSEC_AH)
    ipproto = prefix[ah_ofs];
#endif /* SSH_IPSEC_AH */

#ifdef SSHDIST_L2TP
  l2tp_ofs = tc->l2tp_ofs + esp_ofs - tc->esp_ofs;
#endif /* SSHDIST_L2TP */

#ifdef SSHDIST_IPSEC_IPCOMP
#ifdef SSH_IPSEC_IPCOMP_IN_SOFTWARE
  if (pc->transform & SSH_PM_IPSEC_IPCOMP)
    {
      SshUInt32 ipcomp_ofs = 
	prefix_ofs + tc->ipcomp_ofs + esp_ofs - tc->esp_ofs;
    
      /* It is quite possible that even though IPCOMP was negotiated,
         the packet was not compressed */
      if (ipproto == SSH_IPPROTO_IPPCP)
        {
          ipcomp_present = TRUE;
          ipcomp_status = 
	    ssh_fastpath_transform_ipcomp_inbound(pc, tc, ipcomp_ofs);

          switch (ipcomp_status)
            {
            case SSH_FASTPATH_IPCOMP_DROP:
              goto garbage;
            case SSH_FASTPATH_IPCOMP_NO_MEMORY:
              goto fail;
            case SSH_FASTPATH_IPCOMP_SUCCESS:
	      SSH_DEBUG(SSH_D_MY, ("Packet is decompressed"));

              ipproto = prefix[ipcomp_ofs - prefix_ofs];

              /* Copy out the prefix again since l2tp headers might
                 have been compressed and they would be seen only now.*/
	      prefix_len = pc->packet_len - prefix_ofs;
	      if (prefix_len > SSH_ENGINE_MAX_TRANSFORM_PREFIX)
		prefix_len = SSH_ENGINE_MAX_TRANSFORM_PREFIX;	      
              ssh_interceptor_packet_copyout(pc->pp, prefix_ofs,
                                             prefix, prefix_len);
              break;
            default:
              SSH_NOTREACHED;
	      goto fail;
            }
        }
      else
        {
          SSH_DEBUG(SSH_D_MY, ("Packet was not compressed"));
          ipcomp_present = FALSE;
#ifdef SSHDIST_L2TP
          /* Fix up the L2tp offset that were earlier done thinking that 
	     IPComp header was included in the prefix. */
          if (pc->transform & SSH_PM_IPSEC_L2TP)
            l2tp_ofs -= 4;
#endif /* SSHDIST_L2TP */
        }
    }
#endif /* SSH_IPSEC_IPCOMP_IN_SOFTWARE */
#endif /* SSHDIST_IPSEC_IPCOMP */

#ifdef SSHDIST_L2TP
  if (pc->transform & SSH_PM_IPSEC_L2TP)
    {
      unsigned char *hdr;

      /* Get pointer to L2TP UDP header. */
      ucpw = prefix + l2tp_ofs;
      hdr = ucpw;

      /* Sanity check the L2TP UDP header. */
      if ((trr->l2tp_remote_port
           && SSH_UDPH_SRCPORT(ucpw) != trr->l2tp_remote_port)
          || (trr->l2tp_local_port
              && SSH_UDPH_DSTPORT(ucpw) != trr->l2tp_local_port))
        {
          SSH_DEBUG(SSH_D_NETGARB,
                    ("L2TP port mismatch: src=%d(%d), dst=%d(%d)",
                     (int) SSH_UDPH_SRCPORT(ucpw),
                     (int) trr->l2tp_remote_port,
                     (int) SSH_UDPH_DSTPORT(ucpw),
                     (int) trr->l2tp_local_port));
          goto garbage;
        }
      ucpw += SSH_UDP_HEADER_LEN;
      /* Sanity check the L2TP header. */
      if (SSH_L2TPH_VERSION(ucpw) != SSH_L2TP_DATA_MESSAGE_HEADER_VERSION)
        {
          SSH_DEBUG(SSH_D_NETGARB, ("L2TP header version mismatch"));
          goto garbage;
        }
      bits = SSH_L2TPH_BITS(ucpw);
      ucpw += 2;

      /* Check for L2TP control messages.  They are passed to the
         local stack with tunnel id 1. */
      if (bits & SSH_L2TPH_F_TYPE)
        {
          size_t len;

          /* Assign SSH private AVP which tells the transform index of
             the SA protecting the L2TP traffic.  The private AVP is
             added only for non-empty control messages. */
          if ((bits & SSH_L2TPH_F_LENGTH) == 0
              || SSH_GET_16BIT(ucpw) <= 12)
            /* A message without the length field or an empty
               message. */
            goto l2tp_pass_to_local_stack;

          /* Update length field in the UDP header. */

          len = SSH_UDPH_LEN(hdr);
          SSH_UDPH_SET_LEN(hdr, len + 10);

          /* Clear UDP checksum. */
          SSH_UDPH_SET_CHECKSUM(hdr, 0);

          /* Update L2TP header length. */
          SSH_ASSERT(bits & SSH_L2TPH_F_LENGTH);
          len = SSH_GET_16BIT(ucpw);
          SSH_PUT_16BIT(ucpw, len + 10);

          /* Insert update UDP + L2TP header back to the packet. */
          if (!ssh_interceptor_packet_copyin(pc->pp,
                                             prefix_ofs + l2tp_ofs,
                                             hdr, ucpw - hdr + 2))
            {
              SSH_ENGINE_MARK_STAT(pc, SSH_ENGINE_STAT_ERRORDROP);
              goto error;
            }

          /* Insert AVP to the end of the packet. */
          ucpw = ssh_interceptor_packet_insert(pc->pp, pc->packet_len, 10);
          if (ucpw == NULL)
            goto error;

          /* The packet did grow. */
          pc->packet_len += 10;

          memset(ucpw, 0, 10);
          SSH_L2TP_AVP_SET_LENGTH(ucpw, 10);
          SSH_L2TP_AVP_SET_VENDOR_ID(ucpw, SSH_PRIVATE_ENTERPRISE_CODE);
          SSH_L2TP_AVP_SET_ATTRIBUTE_TYPE(ucpw,
                                          SSH_L2TP_SSH_AVP_TRANSFORM_INDEX);
          SSH_PUT_32BIT(ucpw + 6, pc->transform_index);

          goto l2tp_pass_to_local_stack;
        }

      if (bits & SSH_L2TPH_F_LENGTH)
        ucpw += 2; /* Skip length; IP sanity check after restart will remove
                      any trailing garbage. */

      /* Check tunnel and session IDs if they are set for the
         transform run. */
      if ((trr->l2tp_local_tunnel_id
           && SSH_GET_16BIT(ucpw) != trr->l2tp_local_tunnel_id)
          || (trr->l2tp_local_session_id
              && SSH_GET_16BIT(ucpw + 2) != trr->l2tp_local_session_id))
        {
          SSH_DEBUG(SSH_D_NETGARB, ("L2TP tunnel/session ID mismatch"));
          goto garbage;
        }
      ucpw += 4; /* skip tunnel id, session id */

      if (bits & SSH_L2TPH_F_SEQUENCE)
        {
	  SshEngineTransformData trd;

	  FP_LOCK_WRITE(fastpath);
	  trd = FP_GET_TRD(fastpath, pc->transform_index);
          if (trd)
            trd->l2tp_seq_nr = SSH_GET_16BIT(ucpw + 2);
	  FP_COMMIT_TRD(fastpath, pc->transform_index, trd);
	  FP_UNLOCK_WRITE(fastpath);
          ucpw += 4;
        }
      if (bits & SSH_L2TPH_F_OFFSET)
        {
          ucpw += 2;
        }

      /* Parse PPP header. */
      if (ucpw[0] == 0xff) /* First byte of ppp header */
        {
          /* We must have the address control field. */
          if (ucpw[1] != 0x03)
            {
              SSH_DEBUG(SSH_D_NETGARB, ("L2TP PPP address control fail"));
              goto garbage;
            }
          ucpw += 2;
        }

      /* Skip zero padding, check we still may have payload. */
      while (ucpw < (prefix + SSH_ENGINE_MAX_TRANSFORM_PREFIX) &&
             ucpw[0] == 0)
        ucpw++;
      if (ucpw == (prefix + SSH_ENGINE_MAX_TRANSFORM_PREFIX))
        {
          SSH_DEBUG(SSH_D_NETGARB, ("L2TP PPP padding too long"));
          goto garbage;
        }

      if (ucpw[0] != SSH_PPP_PROTO_IP && ucpw[0] != SSH_PPP_PROTO_IPV6)
        {
        l2tp_pass_to_local_stack:
          /* Cause the L2TP UDP header to be left in the packet, cause the
             outer IP header to be left in the packet, and cause the
             packet to be restarted with tunnel id 1. */
          prefix_ofs = pc->hdrlen;
          prefix_len = l2tp_ofs - tc->iphdrlen;
          trr->restart_tunnel_id = 1;
          ipproto = SSH_IPPROTO_UDP;
        }
      else
        {
          if (ucpw[0] == SSH_PPP_PROTO_IP)
            ipproto = SSH_IPPROTO_IPIP;
          else
            ipproto = SSH_IPPROTO_IPV6;
          prefix_len = (ucpw - prefix) + 1;
#ifdef SSHDIST_IPSEC_NAT
	  /* In the case of L2TP the internal nat is to be performed
	     only for the non-decapsulated control traffic, not the
	     PPP decapsulated IPv4/IPv6 traffic. */
	  SSH_IP_UNDEFINE(&pc->u.flow.internal_nat_ip);
#endif /* SSHDIST_IPSEC_NAT */
        }
    }
  else
#endif /* SSHDIST_L2TP */
    {
      /* Calculate correct prefix_len. Note that the length in 'tc' is for 
	 outbound transform execution and it might need to be updated 
	 depending on packet NAT-T status. See comments above, where 
	 offsets are calculated similarly. */

      if (pc->ipproto == SSH_IPPROTO_UDP 
	  && (pc->transform & SSH_PM_IPSEC_NATT) == 0)
	prefix_len = tc->prefix_len + 8;
      else if (pc->ipproto != SSH_IPPROTO_UDP 
	       && (pc->transform & SSH_PM_IPSEC_NATT))
	prefix_len = tc->prefix_len - 8;
      else
	prefix_len = tc->prefix_len;

#ifdef SSHDIST_IPSEC_IPCOMP
#ifdef SSH_IPSEC_IPCOMP_IN_SOFTWARE
      /* Account for prefix length if no IPComp header is present */
      if ((pc->transform & SSH_PM_IPSEC_IPCOMP) && !ipcomp_present)
	prefix_len -= 4;
#endif /* SSH_IPSEC_IPCOMP_IN_SOFTWARE */
#endif /* SSHDIST_IPSEC_IPCOMP */
   }

  /* Sanity check if packet is too short; perhaps headers were
     corrupt. */
  if (prefix_ofs + prefix_len > pc->packet_len)
    {
      SSH_DEBUG(SSH_D_NETGARB, ("Packet too short"));
      goto garbage;
    }

  /* Eliminate the prefix from the packet.  After this block, ipproto
     must be the next protocol */
  if (prefix_ofs == 0)
    {
      /* Tunneled packet. */
      if (!ssh_interceptor_packet_delete(pc->pp, 0, prefix_len))
        goto error;
      pc->packet_len -= prefix_len;

      /* ECN processing (1) grab information. If the inner header
	 specifies ECT(0) = 10 or ECT(1) = 01 and the outer header is
	 set to CE then set inner header DS value to CE (11) */
      if (pc->pp->protocol == SSH_PROTOCOL_IP4)
	ds_outer = SSH_IPH4_TOS(prefix);
      else
	ds_outer = SSH_IPH6_CLASS(prefix);

      /* Set pc->pp->protocol based on ipproto. */
      if (ipproto == SSH_IPPROTO_IPIP)
        pc->pp->protocol = SSH_PROTOCOL_IP4;
      else
        if (ipproto == SSH_IPPROTO_IPV6)
          pc->pp->protocol = SSH_PROTOCOL_IP6;
        else
          {
	    unsigned char ip_version;
            SSH_DEBUG(SSH_D_FAIL, ("unexpected tunnel ipproto %d",
                                   ipproto));
            /* It might make sense to drop the packet here as
               invalid.  However, following the general "strict on
               reception, permissive on reception" rule we allow
               the packet through. Set pp->protocol to the
	       address type of the decapsulated packet. */
	    ssh_interceptor_packet_copyout(pc->pp, 0, &ip_version, 1);

	   if (SSH_IPH_VERSION(&ip_version) != 4 &&
	       SSH_IPH_VERSION(&ip_version) != 6)
	     goto garbage;

	    pc->pp->protocol = (SSH_IPH_VERSION(&ip_version) == 4)
	      ? SSH_PROTOCOL_IP4 : SSH_PROTOCOL_IP6;
	  }

      /* Focus into inner protocol */
      if (pc->pp->protocol == SSH_PROTOCOL_IP6)
	{
	  if ((ucpw = ssh_interceptor_packet_pullup(pc->pp, SSH_IPH6_HDRLEN))
	      == NULL)
	    goto error;
	  ipproto = SSH_IPH6_NH(ucpw);
	}
      else
	{
	  if ((ucpw = ssh_interceptor_packet_pullup(pc->pp, SSH_IPH4_HDRLEN))
	      == NULL)
	    goto error;
	  ipproto = SSH_IPH4_PROTO(ucpw);
	}

      /* ECN processing (2); update value */
      if (pc->pp->protocol == SSH_PROTOCOL_IP4)
	ds_inner = SSH_IPH4_TOS(ucpw);
      else
	ds_inner = SSH_IPH6_CLASS(ucpw);

      /* If congestion experienced and can handle that */
      if (((ds_outer & 0x3) == 0x3)
	  && ((ds_inner & 0x3) == 0x1 || (ds_inner & 0x3) == 0x2))
	{
	  ds_inner_new = ds_inner | 0x3;

	  if (pc->pp->protocol == SSH_PROTOCOL_IP4)
	    {
	      SSH_IPH4_SET_TOS(ucpw, ds_inner_new);

	      cks = SSH_IPH4_CHECKSUM(ucpw);
	      cks = ssh_ip_cksum_update_byte(cks,
					     SSH_IPH4_OFS_TOS,
					     ds_inner, ds_inner_new);
	      SSH_IPH4_SET_CHECKSUM(ucpw, cks);
	    }
	  else
	    {
	      SSH_IPH6_SET_CLASS(ucpw, ds_inner_new);
	    }
	}
    }
  else
    {
      /* Transport mode. */
      if (!ssh_interceptor_packet_delete(pc->pp, prefix_ofs, prefix_len))
        goto error;
      pc->packet_len -= prefix_len;
      /* Update ipproto and length from the original ip header. */
      if (pc->packet_len < tc->iphdrlen)
        {
          SSH_DEBUG(SSH_D_NETGARB, ("Packet too short to contain IP hdr"));
          goto garbage;
        }
#if defined (WITH_IPV6)
      if (pc->pp->protocol == SSH_PROTOCOL_IP6)
        {
          SSH_ASSERT(pc->ipsec_offset_prevnh > 0
                     && pc->ipsec_offset_prevnh < prefix_ofs);
          /* Update packet length and next header. */
          ucpw = ssh_interceptor_packet_pullup(pc->pp, SSH_IPH6_HDRLEN);
          if (!ucpw)
            goto error;
          SSH_IPH6_SET_LEN(ucpw, pc->packet_len - SSH_IPH6_HDRLEN);
          if (pc->ipsec_offset_prevnh < SSH_IPH6_HDRLEN)
            /* A slight optimization which avoids a useless call to
               `ssh_interceptor_packet_copyin'. */
            SSH_IPH6_SET_NH(ucpw, ipproto);
          else
            if (!ssh_interceptor_packet_copyin(pc->pp,
                                               pc->ipsec_offset_prevnh,
                                               &ipproto, 1))
              goto error;
        }
      else
#endif /* WITH_IPV6 */
        {
          ucpw = ssh_interceptor_packet_pullup(pc->pp, tc->iphdrlen);
          if (!ucpw)
            goto error;
          cks = SSH_IPH4_CHECKSUM(ucpw);
          old_ipproto = SSH_IPH4_PROTO(ucpw);
          old_ip_len = SSH_IPH4_LEN(ucpw);
          SSH_IPH4_SET_LEN(ucpw, pc->packet_len);
          SSH_IPH4_SET_PROTO(ucpw, ipproto);
          cks = ssh_ip_cksum_update_byte(cks, SSH_IPH4_OFS_PROTO, old_ipproto,
                                         ipproto);
          cks = ssh_ip_cksum_update_short(cks, SSH_IPH4_OFS_LEN, old_ip_len,
                                          (SshUInt16) pc->packet_len);
          SSH_IPH4_SET_CHECKSUM(ucpw, cks);
        }
#ifdef SSHDIST_IPSEC_NAT_TRAVERSAL
      /* Update possible TCP/UDP checksum in case of NAT-T and 
	 TCP encapsulation. */
      if ((pc->ipproto == SSH_IPPROTO_UDP 
#ifdef SSH_IPSEC_TCPENCAP
	   || trr->tcp_encaps_conn_id != SSH_IPSEC_INVALID_INDEX
#endif /* SSH_IPSEC_TCPENCAP */
	   )
	  && (
#if defined (WITH_IPV6)
	      ipproto == SSH_IPPROTO_IPV6ICMP ||
#endif /* WITH_IPV6 */
	      ipproto == SSH_IPPROTO_TCP ||
	      ipproto == SSH_IPPROTO_UDP ||
	      ipproto == SSH_IPPROTO_UDPLITE))

	{
          size_t cksum_ofs = 0, header_len = 0;
          unsigned char cksum_buf[2];

          /* Fetch offsets of the protocol header. */
          if (ipproto == SSH_IPPROTO_UDP || ipproto == SSH_IPPROTO_UDPLITE)
            {
              cksum_ofs = SSH_UDPH_OFS_CHECKSUM;
              header_len = SSH_UDPH_HDRLEN;
            }
          else if (ipproto == SSH_IPPROTO_TCP)
            {
              cksum_ofs = SSH_TCPH_OFS_CHECKSUM;
              header_len = SSH_TCPH_HDRLEN;
            }
#if defined (WITH_IPV6)
          else
            {
              cksum_ofs = SSH_ICMP6H_OFS_CHECKSUM;
              header_len = SSH_ICMP6H_HDRLEN;
            }
#endif /* WITH_IPV6 */

          /* Sanity check packet length. */
          if (pc->packet_len < tc->iphdrlen + header_len)
            {
              SSH_DEBUG(SSH_D_NETGARB,
                        ("Packet too short to contain TCP/UDP header"));
              goto garbage;
            }

#if 0
          /* Check if we can update checksum incrementally.  Here we
             have two cases: we know both NAT-OA-{local,remote} or we
             know NAT-OA-remote and this end is not behind NAT. */
          if ((trr->natt_flags & SSH_ENGINE_NATT_OA_L
	       && trr->natt_flags & SSH_ENGINE_NATT_OA_R)
	      || (trr->natt_flags & SSH_ENGINE_NATT_OA_R
		  && (trr->natt_flags &
		      SSH_ENGINE_NATT_LOCAL_BEHIND_NAT) == 0))
#else






	    if (0)
#endif
	    {
#if defined (WITH_IPV6)
              unsigned char current_ip[SSH_IPH6_ADDRLEN];
#else /* WITH_IPV6 */
              unsigned char current_ip[SSH_IPH4_ADDRLEN];
#endif /* WITH_IPV6 */
              int addrlen;
              SshUInt16 old_cks;

              /* Get the original checksum. */
              ssh_interceptor_packet_copyout(pc->pp, tc->iphdrlen + cksum_ofs,
                                             cksum_buf, 2);
              cks = SSH_GET_16BIT(cksum_buf);
              old_cks = cks;

              /* Update source IP. */
              if (trr->natt_flags & SSH_ENGINE_NATT_OA_R)
                {
                  /* Store the packet's current source IP address. */
                  SSH_IP_ENCODE(&pc->src, current_ip, addrlen);

                  for (i = 0; i < addrlen; i += 4)
                    cks = ssh_ip_cksum_update_long(
                                        cks, i,
                                        SSH_GET_32BIT(trr->natt_oa_r + i),
                                        SSH_GET_32BIT(current_ip + i));
                }

              /* Update destination IP. */
              if (trr->natt_flags & SSH_ENGINE_NATT_OA_L)
                {
                  /* Store the packet's current destination IP
                     address. */
                  SSH_IP_ENCODE(&pc->dst, current_ip, addrlen);

                  for (i = 0; i < addrlen; i += 4)
                    cks = ssh_ip_cksum_update_long(
                                        cks, i,
                                        SSH_GET_32BIT(trr->natt_oa_l + i),
                                        SSH_GET_32BIT(current_ip + i));
                }

              if (old_cks || (ipproto != SSH_IPPROTO_UDP))
                {
                  /* Copy checksum back to the packet. */
                  SSH_PUT_16BIT(cksum_buf, cks);
                  if (!ssh_interceptor_packet_copyin(pc->pp,
                                                     tc->iphdrlen + cksum_ofs,
                                                     cksum_buf, 2))
                    goto error;
		}
            }
          else
            {
              /* Update the checksum by computing it over the whole
                 packet. */

              /* SSH_IP6_PSEUDOH_HDRLEN is long enough to hold also
                 TCP protocol header. */
              unsigned char pseudohdr[SSH_IP6_PSEUDOH_HDRLEN];
              size_t pseudohdrlen, len;
              SshUInt32 sum;

              /* Special checks for UDP. */
              if (ipproto == SSH_IPPROTO_UDP)
                {
                  /* Get the original checksum. */
                  ssh_interceptor_packet_copyout(pc->pp,
                                                 tc->iphdrlen + cksum_ofs,
                                                 cksum_buf, 2);
                  cks = SSH_GET_16BIT(cksum_buf);
                  if (cks == 0)
                    {
                      /* The original checksum is zero.  No need to
                         update. */
                      SSH_DEBUG(SSH_D_LOWOK,
                                ("Not updating zero UDP checksum"));
                      goto natt_local_end_compensated;
                    }
                  if (pc->transform & (SSH_PM_MAC_MASK | SSH_PM_COMBINED_MASK))
                    {
                      /* The packet is ESP authenticated.  Simply
                         clear the UPD checksum. */
                      SSH_DEBUG(SSH_D_LOWOK,
                                ("Clearing checksum of ESP authenticated "
                                 "UDP packet"));
                      memset(cksum_buf, 0, 2);
                      if (!ssh_interceptor_packet_copyin(
                                                pc->pp,
                                                tc->iphdrlen + cksum_ofs,
                                                cksum_buf, 2))
                        goto error;

                      goto natt_local_end_compensated;
                    }
                }

              /* Special checks for UDP-Lite. */
              if (ipproto == SSH_IPPROTO_UDPLITE)
		{
                  ucpw = ssh_interceptor_packet_pullup(pc->pp,
						       tc->iphdrlen + 8);
                  if (ucpw == NULL)
                    goto error;
		  ucpw += tc->iphdrlen;

		  cksum_len = SSH_UDP_LITEH_CKSUM_COVERAGE(ucpw);
		  
		  if (cksum_len > pc->packet_len - tc->iphdrlen)
		    goto error;
		}
	      else
		{
		  cksum_len = pc->packet_len - tc->iphdrlen;
		}

              SSH_DEBUG(SSH_D_LOWSTART, ("Updating protocol checksum"));

              /* The length field in the pseudo header. */
              len = pc->packet_len - tc->iphdrlen;

              /* Construct pseudo header. */
              memset(pseudohdr, 0, sizeof(pseudohdr));
#if defined (WITH_IPV6)
              if (pc->pp->protocol == SSH_PROTOCOL_IP6)
                {
                  ucpw = ssh_interceptor_packet_pullup(pc->pp,
                                                       SSH_IPH6_HDRLEN);
                  if (ucpw == NULL)
                    goto error;

                  pseudohdrlen = SSH_IP6_PSEUDOH_HDRLEN;

                  memcpy(pseudohdr + SSH_IP6_PSEUDOH_OFS_SRC,
                         ucpw + SSH_IPH6_OFS_SRC, SSH_IPH6_ADDRLEN);
                  memcpy(pseudohdr + SSH_IP6_PSEUDOH_OFS_DST,
                         ucpw + SSH_IPH6_OFS_DST, SSH_IPH6_ADDRLEN);
                  SSH_IP6_PSEUDOH_SET_LEN(pseudohdr, len);
                  SSH_IP6_PSEUDOH_SET_NH(pseudohdr, ipproto);
                }
              else
#endif /* WITH_IPV6 */
                {
                  ucpw = ssh_interceptor_packet_pullup(pc->pp, tc->iphdrlen);
                  if (ucpw == NULL)
                    goto error;

                  pseudohdrlen = SSH_TCPH_PSEUDO_HDRLEN;

                  memcpy(pseudohdr + SSH_TCPH_PSEUDO_OFS_SRC,
                         ucpw + SSH_IPH4_OFS_SRC, SSH_IPH4_ADDRLEN);
                  memcpy(pseudohdr + SSH_TCPH_PSEUDO_OFS_DST,
                         ucpw + SSH_IPH4_OFS_DST, SSH_IPH4_ADDRLEN);
                  SSH_PUT_8BIT(pseudohdr + 9, ipproto);
                  SSH_PUT_16BIT(pseudohdr + 10, len);
                }

              /* Clear checksum from the protocol header. */
              memset(cksum_buf, 0, 2);
              if (!ssh_interceptor_packet_copyin(pc->pp,
                                                 tc->iphdrlen + cksum_ofs,
                                                 cksum_buf, 2))
                goto error;

              /* Compute checksum. */
              sum = 0;
              cks = ~ssh_ip_cksum(pseudohdr, pseudohdrlen);
              sum += cks;
              cks = ~ssh_ip_cksum_packet(pc->pp, tc->iphdrlen, cksum_len);
	      sum += cks;

              /* Fold 32 bit checksum to 16 bits. */
              sum = (sum & 0xffff) + (sum >> 16);
              sum = (sum & 0xffff) + (sum >> 16);
              cks = (SshUInt16)~sum;

              /* Store the computed checksum. */
              SSH_PUT_16BIT(cksum_buf, cks);
              if (!ssh_interceptor_packet_copyin(pc->pp,
                                                 tc->iphdrlen + cksum_ofs,
                                                 cksum_buf, 2))
                goto error;
            }
        natt_local_end_compensated:
          ;
        }
#endif /* SSHDIST_IPSEC_NAT_TRAVERSAL */
    }

  SSH_ASSERT(pc->packet_len == ssh_interceptor_packet_len(pc->pp));

  /* Dummy ESP packets per rfc4303 section 2.6 are discarded
     here. Note that the same protocol are used both for IPv4 and
     IPv6. */
  if (ipproto == SSH_IPPROTO_IPV6NONXT)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Dummy ESP packet dropped"));
      goto fail;
    }

  /* If the packet TCP/UDP checksum has already been verified by 
     hardware, then we clear the flag to indicate that protocol stack
     should re-verify the checksum. */
  if (pc->pp->flags & SSH_PACKET_HWCKSUM)
    {
      SSH_DEBUG(SSH_D_LOWOK, 
		("Clearing HW cksum flag from decapsulated packet"));
      pc->pp->flags &= ~SSH_PACKET_HWCKSUM;
    }

  /* Return the packet to the transform callback for further processing. */
  ssh_fastpath_release_transform_context(fastpath, tc);
  (*pc->u.flow.tr_callback)(pc, SSH_ENGINE_RET_OK, pc->u.flow.tr_context);
  return;

 garbage:
  SSH_DEBUG(SSH_D_NETGARB, ("corrupt packet received"));
  SSH_DUMP_PACKET(SSH_D_MY + 10, "packet when corrupt:", pc->pp);
  SSH_DEBUG_HEXDUMP(10, ("prefix:"), prefix, sizeof(prefix));
  trr->statflags |= SSH_ENGINE_STAT_T_GARBAGE | SSH_ENGINE_STAT_T_DROP;
  SSH_ENGINE_MARK_STAT(pc, SSH_ENGINE_STAT_CORRUPTDROP);
  ssh_fastpath_release_transform_context(fastpath, tc);
  (*pc->u.flow.tr_callback)(pc, SSH_ENGINE_RET_FAIL, pc->u.flow.tr_context);
  return;

 fail:
  SSH_DEBUG(SSH_D_NETGARB, ("inbound transform failed"));
  trr->statflags |= SSH_ENGINE_STAT_T_DROP;
  ssh_fastpath_release_transform_context(fastpath, tc);
  (*pc->u.flow.tr_callback)(pc,
			    pc->pp
			    ? SSH_ENGINE_RET_DROP : SSH_ENGINE_RET_ERROR,
			    pc->u.flow.tr_context);
  return;

 error:
  SSH_DEBUG(SSH_D_ERROR, ("inbound transform error"));
  trr->statflags |= SSH_ENGINE_STAT_T_DROP;
  ssh_fastpath_release_transform_context(fastpath, tc);
  (*pc->u.flow.tr_callback)(pc, SSH_ENGINE_RET_ERROR, pc->u.flow.tr_context);
}

#ifdef SSHDIST_IPSEC_HWACCEL
/* This is called when "combined" transform hardware acceleration for the
   packet completes. */
void fastpath_transform_in_postprocess_combined(Boolean perform_antireplay,
						SshHWAccelResultCode result,
						SshInterceptorPacket pp,
						void *context)
{
  SshEnginePacketContext pc = (SshEnginePacketContext)context;
  SshFastpathTransformContext tc = pc->u.flow.tc;
  SshFastpath fastpath = pc->engine->fastpath;
  SshEngineTransformRun trr;
  unsigned char *ucp;
  SshUInt8 ipproto;

  trr = pc->u.flow.trr;

  /* Assign the new packet object to pc. */
  pc->pp = pp;

  /* Test if the accelerated operation was successful. */
  if (pp == NULL || result != SSH_HWACCEL_OK)
    {
      if (result & SSH_HWACCEL_ICV_FAILURE)
	{
	  trr->statflags |= SSH_ENGINE_STAT_T_MAC_FAIL;
	  pc->audit.corruption = (pc->transform & SSH_PM_IPSEC_AH)
	    ? SSH_PACKET_CORRUPTION_AH_ICV_FAILURE
	    : SSH_PACKET_CORRUPTION_ESP_ICV_FAILURE;
	}
      if (result & SSH_HWACCEL_SEQ_FAILURE)
	{
	  trr->statflags |= SSH_ENGINE_STAT_T_REPLAY;
	  SSH_ENGINE_MARK_STAT(pc, SSH_ENGINE_STAT_REPLAYDROP);
	  if (pc->transform & SSH_PM_IPSEC_AH)
	    {
	      SSH_ENGINE_MARK_STAT(pc, SSH_ENGINE_STAT_AHMACDROP);
	      pc->audit.spi = trr->myspis[SSH_PME_SPI_AH_IN];
	      pc->audit.corruption =
		SSH_PACKET_CORRUPTION_AH_SEQ_NUMBER_FAILURE;
	    }
	  if (pc->transform & SSH_PM_IPSEC_ESP)
	    {
	      SSH_ENGINE_MARK_STAT(pc, SSH_ENGINE_STAT_ESPMACDROP);
	      pc->audit.spi = trr->myspis[SSH_PME_SPI_ESP_IN];
	      pc->audit.corruption =
		SSH_PACKET_CORRUPTION_ESP_SEQ_NUMBER_FAILURE;
	    }
	  pc->tunnel_id = trr->restart_tunnel_id;
	}
      SSH_DEBUG(SSH_D_FAIL, ("Hardware acceleration failed"));
      SSH_ENGINE_MARK_STAT(pc, SSH_ENGINE_STAT_HWACCELDROP);
      goto fail;
    }

  /* Perform antireplay detection if not done by the hardware accelerator */
  if (perform_antireplay &&
      !fastpath_transform_in_perform_antireplay(pc, pc->audit.seq))
    goto fail;


  /* update the new packet_len after a combined hwaccel operation */
  pc->packet_len = ssh_interceptor_packet_len(pp);

  /* update pp->protocol after a combined hwaccel operation. We need
     to get enough information to get both version (first octet) and
     next header (at ofs=6 for ipv6 and ofs=9 - pullup ipv4hlen */
  ucp = ssh_interceptor_packet_pullup(pp, SSH_IPH4_HDRLEN);

  if (ucp == NULL)
    {
      pc->pp = NULL;
      goto fail;
    }

  SSH_DEBUG(SSH_D_LOWOK, ("Original protocol version is %d", pp->protocol));

  pp->protocol = (SSH_IPH_VERSION(ucp) == 4)
    ? SSH_PROTOCOL_IP4
    : SSH_PROTOCOL_IP6;

  SSH_DEBUG(SSH_D_LOWOK, ("Updated protocol version is %d", pp->protocol));

  ipproto = (pp->protocol == SSH_PROTOCOL_IP6)
    ? SSH_IPH6_NH(ucp)
    : SSH_IPH4_PROTO(ucp);

  /* Dummy ESP packets per rfc4303 section 2.6 are discarded
     here. Note that the same protocol are used both for IPv4 and
     IPv6. */
  if (ipproto == SSH_IPPROTO_IPV6NONXT)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Dummy ESP packet dropped"));
      goto fail;
    }

  /* Return the packet to the transform callback for further processing. */
  ssh_fastpath_release_transform_context(fastpath, tc);
  (*pc->u.flow.tr_callback)(pc, SSH_ENGINE_RET_OK, pc->u.flow.tr_context);
  
  return;

 fail:
  SSH_DEBUG(SSH_D_NETGARB, ("inbound transform error"));
  trr->statflags |= SSH_ENGINE_STAT_T_DROP;
  ssh_fastpath_release_transform_context(fastpath, tc);
  (*pc->u.flow.tr_callback)(pc,
			    pc->pp
			    ? SSH_ENGINE_RET_DROP : SSH_ENGINE_RET_ERROR,
			    pc->u.flow.tr_context);
}

void fastpath_transform_in_antireplay_combined(SshInterceptorPacket pp,
					       SshHWAccelResultCode result,
					       void *context)
{
  fastpath_transform_in_postprocess_combined(TRUE, result, pp, context);
  return;
}

void fastpath_transform_in_finish_combined(SshInterceptorPacket pp,
					   SshHWAccelResultCode result,
					   void *context)
{
  fastpath_transform_in_postprocess_combined(FALSE, result, pp, context);
  return;
}

#ifdef SSHDIST_IPSEC_NAT_TRAVERSAL
/* Remove the NAT-T header from the packet pc->pp. Returns FALSE on failure in 
 which case 'pc->pp' is already freed and set to NULL. */
Boolean
fastpath_transform_remove_natt_header(SshEnginePacketContext pc)
{
  SshUInt16 cks, old_ip_len;
  SshUInt8 old_ipproto, ipproto;
  unsigned char *ucpw;

#if defined (WITH_IPV6)
  /* Pullup IPv6 or IPv4 header as per the case */
  if (pc->pp->protocol == SSH_PROTOCOL_IP6)
      ucpw = ssh_interceptor_packet_pullup(pc->pp, SSH_IPH6_HDRLEN);
  else
#endif /* WITH_IPV6 */
    ucpw = ssh_interceptor_packet_pullup(pc->pp, pc->hdrlen);

  if (!ucpw)
    {
      SSH_DEBUG(SSH_D_FAIL, ("ucpw failed"));
      pc->pp = NULL;
      return FALSE;
    }
#if defined (WITH_IPV6)
  if (pc->pp->protocol == SSH_PROTOCOL_IP6)
    {
      SshUInt16 len;

      /* Set the new length and next header in IPv6 case. */
      len = SSH_IPH6_LEN(ucpw);
      SSH_IPH6_SET_LEN(ucpw, len - 8);
      ipproto = SSH_IPPROTO_ESP;
      SSH_IPH6_SET_NH(ucpw, ipproto);
    }
  else
    {
#endif /* WITH_IPV6 */
      /* Get checksum, protocol and length from pullup packet */
      cks = SSH_IPH4_CHECKSUM(ucpw);
      old_ipproto = SSH_IPH4_PROTO(ucpw);
      old_ip_len = SSH_IPH4_LEN(ucpw);

      /* Set new protocol,checksum,length */
      ipproto = SSH_IPPROTO_ESP;
      /* Remove the 8 bytes of NATT header */
      SSH_IPH4_SET_LEN(ucpw, old_ip_len - 8);
      SSH_IPH4_SET_PROTO(ucpw, ipproto);

      cks = ssh_ip_cksum_update_byte(cks,
				     SSH_IPH4_OFS_PROTO,
				     old_ipproto,
				     ipproto);

      cks = ssh_ip_cksum_update_short(cks,
				      SSH_IPH4_OFS_LEN,
				      old_ip_len,
				      old_ip_len - 8);
      SSH_IPH4_SET_CHECKSUM(ucpw, cks);
#if defined (WITH_IPV6)
    }
#endif /* WITH_IPV6 */

  /* Delete 8 bytes from pc->pp irrespective of IPv4 or IPv6 */
  if (!ssh_interceptor_packet_delete(pc->pp,
				     pc->pp->protocol == SSH_PROTOCOL_IP4
				     ? pc->hdrlen : SSH_IPH6_HDRLEN, 8))
    {
      pc->pp = NULL;
      return FALSE;
    }

  SSH_DUMP_PACKET(SSH_D_MY + 10, "packet after natt-decapsulation:", pc->pp);

  return TRUE;
}
#endif /* SSHDIST_IPSEC_NAT_TRAVERSAL */
#endif /* SSHDIST_IPSEC_HWACCEL */

/* Performs inbound processing for incoming IPSEC packets and ICMPs
   related to them.  Note that the definition of an IPSEC packet is
   relatively broad here; it also includes UDP-encapsulated IPSEC
   packets (NAT Traversal packets and/or L2TP packets).  Basically
   anything that needs to have IPSEC transforms performed on it comes
   here, as do error ICMPs related to such packets.  This function
   performs any required encryption and/or message authentication
   processing, as well as replay prevention (NAT Traversal, AH, ESP,
   IPCOMP, L2TP, and IP-in-IP for tunnel mode are all implemented by
   this function.  When this is called, the packet has already gone through 
   basic sanity checks, and we know that it is at least hdrlen+8 bytes long.  
   The packet should also already have gone through reassembly. */

void ssh_fastpath_transform_in(SshFastpath fastpath,
			       SshEnginePacketContext pc,
			       SshEngineTransformRun trr,
			       SshFastpathTransformCB callback,
			       void *context)
{
  SshUInt32 transform, prefix_ofs;
  size_t enc_ofs = 0, mac_ofs = 0, enc_len, mac_len;
  size_t prefix_len, esp_ofs = 0;
  SshFastpathTransformContext tc;
  unsigned char prefix[SSH_ENGINE_MAX_TRANSFORM_PREFIX];
  unsigned char *ucpw;
  SshUInt64Struct seq, mycount, max, diff;
  void (*mac_update_func)(void *context, const unsigned char *buf, size_t len);
#ifdef SSH_IPSEC_AH
  unsigned char zeroicv[32];
  size_t ah_ofs = 0;
#endif /* SSH_IPSEC_AH */
  SshCryptoStatus status;
  SshUInt8 natt_len;

  SSH_INTERCEPTOR_STACK_MARK();

  SSH_DEBUG(SSH_D_NICETOKNOW, ("Inbound transform processing entered"));

  seq.high = seq.low = 0;

  /* Check for error ICMPs related to the transform. */
  if (pc->ipproto == SSH_IPPROTO_ICMP
#if defined (WITH_IPV6)
      || pc->ipproto == SSH_IPPROTO_IPV6ICMP
#endif /* WITH_IPV6 */
      )
    {




      (*callback)(pc, SSH_ENGINE_RET_FAIL, context);
      return;
    }

  /* Save callback function for later use. */
  pc->u.flow.tr_callback = callback;
  pc->u.flow.tr_context = context;
  /* Save the transform run-time data pointer. */
  pc->u.flow.trr = trr;

  /* Obtain a transform context for the transform.  This may come from
     a cache or might be constructed here. */
  tc = ssh_fastpath_get_transform_context(fastpath, trr, pc, FALSE,
					  SSH_IP_IS6(&trr->gw_addr),
					pc->pp->protocol == SSH_PROTOCOL_IP6);
  if (tc == NULL)
    {
      /* Failed to allocate action context. */
      SSH_DEBUG(SSH_D_FAIL, ("Failed to allocate transform context"));
    fail:
      SSH_ENGINE_MARK_STAT(pc, SSH_ENGINE_STAT_TRANSFORMDROP);
      if (tc != NULL)
        ssh_fastpath_release_transform_context(fastpath, tc);
      trr->statflags |= SSH_ENGINE_STAT_T_DROP;
      (*callback)(pc, SSH_ENGINE_RET_FAIL, context);
      return;
    }
  pc->u.flow.tc = tc;

  /* Read the transform into local variable for convenient access. */
  transform = pc->transform;

  if (pc->pp->flags & SSH_ENGINE_P_ISFRAG)
    {
      pc->audit.corruption = (transform & SSH_PM_IPSEC_ESP)
	? SSH_PACKET_CORRUPTION_ESP_IP_FRAGMENT
	: ((transform & SSH_PM_IPSEC_AH)
	   ? SSH_PACKET_CORRUPTION_AH_IP_FRAGMENT
	   : SSH_PACKET_CORRUPTION_NONE);

      pc->audit.spi = trr->myspis[SSH_PME_SPI_ESP_IN];
      pc->tunnel_id = trr->restart_tunnel_id;
#ifdef SSH_IPSEC_AH
      if (transform & SSH_PM_IPSEC_AH)
	pc->audit.spi = trr->myspis[SSH_PME_SPI_AH_IN];
#endif /* SSH_IPSEC_AH */
      if (pc->audit.corruption != SSH_PACKET_CORRUPTION_NONE)
	goto fail;
    }

#ifdef SSH_IPSEC_STATISTICS
  /* Update statistics. */
  if (transform & SSH_PM_IPSEC_ESP)
    {
      SSH_ENGINE_MARK_STAT(pc, SSH_ENGINE_STAT_ESP_IN);
    }
  if (transform & SSH_PM_IPSEC_AH)
    {
      SSH_ENGINE_MARK_STAT(pc, SSH_ENGINE_STAT_AH_IN);
    }
#endif /* SSH_IPSEC_STATISTICS */

  /* Determine the offset of the packet prefix. */
  if (tc->prefix_at_0)
    prefix_ofs = 0;
  else
    prefix_ofs = pc->hdrlen;

  /* Determine the packet prefix length and offsets to allow decapsulation
     of a packet regardless if it has or does not have UDP encapsulation.
     The offset values in tc are used for outbound transform execution. In 
     inbound transform execution the offsets need to be corrected depending 
     whether packet and 'tc' NAT-T status match. */

  /* NATT packet, non-NAT-T tc */
  if (pc->ipproto == SSH_IPPROTO_UDP && (transform & SSH_PM_IPSEC_NATT) == 0)
    {
      natt_len = 8;
      prefix_len = tc->prefix_len + 8;
      esp_ofs = tc->esp_ofs + 8;
#ifdef SSH_IPSEC_AH
      ah_ofs = tc->ah_ofs + 8;
#endif /* SSH_IPSEC_AH */
    }
  else if (pc->ipproto != SSH_IPPROTO_UDP && (transform & SSH_PM_IPSEC_NATT))
    {
      /* non-NAT-T packet, NAT-T tc */
      natt_len = 0;
      prefix_len = tc->prefix_len - 8;
      esp_ofs = tc->esp_ofs - 8;
#ifdef SSH_IPSEC_AH
      ah_ofs = tc->ah_ofs - 8;
#endif /* SSH_IPSEC_AH */
    }
  else
    {
      /* Packet matches tc */
      natt_len = tc->natt_len;
      prefix_len = tc->prefix_len;
      esp_ofs = tc->esp_ofs;
#ifdef SSH_IPSEC_AH
      ah_ofs = tc->ah_ofs;
#endif /* SSH_IPSEC_AH */
    }
  
  /* Sanity check that the packet is not too short. */
  if (pc->packet_len <= prefix_ofs + prefix_len + tc->trailer_len)
    {
      SSH_DEBUG(SSH_D_NETGARB, ("Packet too short"));
    garbage:
      trr->statflags |= SSH_ENGINE_STAT_T_GARBAGE;
      SSH_ENGINE_MARK_STAT(pc, SSH_ENGINE_STAT_CORRUPTDROP);
      goto fail;
    }

  /* Copy the prefix from the packet to local buffer (so that we don't
     need to worry about interceptor's byte limit for pullup).  Note that
     the code here does not examine the L2TP header, which could be of
     variable length (possibly extending beyond tc->prefix_len).  We refetch
     a longer prefix in ssh_engine_transform_in_final before we start
     examining the L2TP header. */
  ssh_interceptor_packet_copyout(pc->pp, prefix_ofs, prefix, prefix_len);

#ifdef SSHDIST_IPSEC_HWACCEL
  /* Use "combined" transform acceleration, if available. If the hardware
     accelerator can perform antireplay detection, delegate the transform
     to hardware immediately, if not then wait until preliminary antireplay
     detection is done further below before calling the
     ssh_hwaccel_perform_combined function. */
  if (tc->transform_accel
      && !(tc->accel_unsupported_mask & SSH_HWACCEL_COMBINED_FLAG_ANTIREPLAY))
    {
#ifdef SSHDIST_IPSEC_NAT_TRAVERSAL 
      if (tc->accel_unsupported_mask & SSH_HWACCEL_COMBINED_FLAG_NATT
	  && pc->ipproto == SSH_IPPROTO_UDP)
	{
	  if (!fastpath_transform_remove_natt_header(pc))
	    goto error;
	}
#endif /* SSHDIST_IPSEC_NAT_TRAVERSAL */
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Performing combined transform with AR"));
      ssh_hwaccel_perform_combined(tc->transform_accel,
				   pc->pp,
				   fastpath_transform_in_finish_combined,
				   (void *)pc);
      return;
    }
#endif /* SSHDIST_IPSEC_HWACCEL */

  /* Determine the offsets and amounts to decrypt and authenticate, and get
     the sequence number of replay prevention. */
  enc_len = 0;
  mac_len = 0;
  if (transform & SSH_PM_IPSEC_ESP)
    {
      ucpw = prefix + esp_ofs;
      if (SSH_GET_32BIT(ucpw) != tc->esp_spi)
        {
          SSH_DEBUG(SSH_D_NETGARB, ("ESP SPI mismatch"));
          goto garbage;
        }

      seq.low = SSH_GET_32BIT(ucpw + 4);
      pc->audit.seq = seq.low;

      enc_ofs = prefix_ofs + esp_ofs + 8;
      enc_len = pc->packet_len - enc_ofs;
      if (!(transform & SSH_PM_IPSEC_AH))
        enc_len -= tc->icv_len;

      if (!tc->counter_mode && tc->cipher_block_len != 0 &&
          enc_len % tc->cipher_block_len != 0)
        {
          SSH_DEBUG(SSH_D_NETGARB, ("Encrypted not cipher block multiple"));
          goto garbage;
        }
      mac_ofs = prefix_ofs + esp_ofs;
      mac_len = pc->packet_len - mac_ofs - tc->icv_len;
      pc->u.flow.mac_icv_ofs = pc->packet_len - tc->icv_len;
      /* Copy ICV from the packet. */
      if (tc->icv_len > 0)
        ssh_interceptor_packet_copyout(pc->pp, pc->u.flow.mac_icv_ofs,
                                       pc->u.flow.packet_icv, tc->icv_len);
    }
#ifdef SSH_IPSEC_AH
  if (transform & SSH_PM_IPSEC_AH)
    {
      ucpw = prefix + ah_ofs;
      if (SSH_GET_32BIT(ucpw + 4) != tc->ah_spi)
        {
          SSH_DEBUG(SSH_D_NETGARB, ("Non-matching AH SPI"));
          goto garbage;
        }

      seq.low = SSH_GET_32BIT(ucpw + 8);
      pc->audit.seq = seq.low;

      mac_ofs = prefix_ofs + ah_ofs;
      mac_len = pc->packet_len - mac_ofs;
      pc->u.flow.mac_icv_ofs = prefix_ofs + ah_ofs + 12;
      /* Copy ICV from the packet and zero the ICV in the packet. */
      if (!tc->transform_accel && tc->icv_len > 0)
        {
          ssh_interceptor_packet_copyout(pc->pp, pc->u.flow.mac_icv_ofs,
                                         pc->u.flow.packet_icv, tc->icv_len);
          SSH_ASSERT(tc->icv_len <= sizeof(zeroicv));
          memset(zeroicv, 0, tc->icv_len);

          if (!ssh_interceptor_packet_copyin(pc->pp,
					     pc->u.flow.mac_icv_ofs,
					     zeroicv, tc->icv_len))
            goto error;
        }
    }
#endif /* SSH_IPSEC_AH */

  /* Do preliminary replay prevention screening. */
  if (transform & (SSH_PM_IPSEC_ESP | SSH_PM_IPSEC_AH))
    {
      mycount.high = trr->mycount_high;
      mycount.low = trr->mycount_low;

      if (transform & SSH_PM_IPSEC_LONGSEQ)
        {
          /* Determine seq_high from seq_low and the present position
             of the antireplay window. */
          seq.high = (seq.low >= mycount.low) ? mycount.high :
            mycount.high + 1;
        }
      else
        {
          seq.high = 0;
        }

      if (transform & SSH_PM_IPSEC_ANTIREPLAY)
        {
          /* Is seq to the left of the window? */
          if (SSH_UINT64_LE(seq, mycount))
            {
              SSH_DEBUG(SSH_D_FAIL, ("Prelim replay prevention check fail"));
              trr->statflags |= SSH_ENGINE_STAT_T_REPLAY;
              SSH_ENGINE_MARK_STAT(pc, SSH_ENGINE_STAT_REPLAYDROP);
              goto fail;
            }

          /* Check if seq lies inside the replay window */
          SSH_UINT64_ADD32(max, mycount, 32 * SSH_ENGINE_REPLAY_WINDOW_WORDS);

          if (SSH_UINT64_LE(seq, max) || SSH_UINT64_GE(mycount, max))
          {
              unsigned int bit_ofs;

              SSH_UINT64_SUB(diff, seq, mycount);
              SSH_ASSERT(diff.high == 0);
              bit_ofs = diff.low;

              SSH_ASSERT(bit_ofs < 32 * SSH_ENGINE_REPLAY_WINDOW_WORDS);
              if (trr->myreplaymask[bit_ofs / 32] &
                  ((SshUInt32) 1 << (bit_ofs & 31)))
                {
                  SSH_DEBUG(SSH_D_FAIL,
                            ("Preliminary replay prevention check fail"));
                  trr->statflags |= SSH_ENGINE_STAT_T_REPLAY;
                  SSH_ENGINE_MARK_STAT(pc, SSH_ENGINE_STAT_REPLAYDROP);
                  goto fail;
                }
            }







#ifdef SSHDIST_IPSEC_HWACCEL
          /* Use "combined" transform acceleration, if available. */
          if (tc->transform_accel)
            {                
#ifdef SSHDIST_IPSEC_NAT_TRAVERSAL 
	      if (tc->accel_unsupported_mask & SSH_HWACCEL_COMBINED_FLAG_NATT
		  && pc->ipproto == SSH_IPPROTO_UDP)
		{
		  if (!fastpath_transform_remove_natt_header(pc))
		    goto error;
		}
#endif /* SSHDIST_IPSEC_NAT_TRAVERSAL */
	      SSH_DEBUG(SSH_D_NICETOKNOW, ("Performing combined transform"));
              ssh_hwaccel_perform_combined(tc->transform_accel,
					   pc->pp,
				  fastpath_transform_in_antireplay_combined,
					   (void *)pc);
              return;
            }
#endif /* SSHDIST_IPSEC_HWACCEL */

          /* If using 64 bit sequence numbers, insert the most significant
	     32 bits of the sequence number to the packet. This gets included
	     in the ICV computation but does not get encrypted. */
	  if (transform & SSH_PM_IPSEC_LONGSEQ)
	    {
	      size_t longseq_ofs = 0;

	      if (transform & SSH_PM_IPSEC_AH)
		longseq_ofs = pc->packet_len;
	      else if (transform & SSH_PM_IPSEC_ESP)
		longseq_ofs = pc->u.flow.mac_icv_ofs;
	      else
		SSH_NOTREACHED;

	      ucpw = ssh_interceptor_packet_insert(pc->pp, longseq_ofs, 4);
	      if (!ucpw)
		goto error;

	      SSH_PUT_32BIT(ucpw, seq.high);
	      mac_len += 4;
	      pc->packet_len += 4;
	    }
	}
    }

  SSH_ASSERT(tc->icv_len <= sizeof(pc->u.flow.icv));

#ifdef SSHDIST_IPSEC_HWACCEL
  /* Perform message authentication (and decryption if encmac_accel). */
  if (tc->encmac_accel)
    { /* Use hardware acceleration to compute MAC and to perform
         decrypt.*/
      pc->u.flow.mac_done = 0x01;
      pc->pp->flags |= SSH_PACKET_CONFIDENTIAL;
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Performing hardware IPsec transform"));

      ssh_hwaccel_perform_ipsec(tc->encmac_accel, pc->pp, enc_ofs, enc_len,
                                mac_ofs, mac_len, pc->u.flow.mac_icv_ofs,
                                fastpath_transform_in_finish, (void *)pc);
      return;
    }

  /* Perform message authentication. */
  if (tc->mac_accel)
    { /* Use hardware acceleration to compute the MAC. */
      pc->u.flow.mac_done = 0x01;
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Performing hardware IPsec transform"));
      ssh_hwaccel_perform_ipsec(tc->mac_accel, pc->pp, 0, 0,
                                mac_ofs, mac_len, pc->u.flow.mac_icv_ofs,
                                fastpath_transform_in_finish, (void *)pc);
      return;
    }
#endif /* SSHDIST_IPSEC_HWACCEL */

  SSH_DEBUG(SSH_D_NICETOKNOW, ("Performing software IPsec transform"));

  /* Save enough data to continue after MAC checking in the callback. */
  pc->u.flow.mac_ofs = (SshUInt16) enc_ofs;
  pc->u.flow.mac_len = (SshUInt16) enc_len;
  pc->u.flow.mac_done = 0x00;

  /* We don't have hardware acceleration for just MAC, so we need to perform
     the MAC computation here in software.  We save the computed MAC in
     pc->u.flow.icv, and don't modify the ICV in the packet.  This is vice
     versa to the hw accelerated case, but it doesn't matter since we will
     simply compare them for equality. */
  if (tc->mac || 
      (transform & (SSH_PM_CRYPT_NULL_AUTH_AES_GMAC |
                    SSH_PM_IPSEC_AH)) == (SSH_PM_CRYPT_NULL_AUTH_AES_GMAC |
                                          SSH_PM_IPSEC_AH))
    {
      /* Start computing the MAC. */
      if (tc->mac)
        {
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
        }
      else
	{
	  (*tc->cipher->reset)(tc->cipher_context);
	  mac_update_func = tc->cipher->update;
	}

#ifdef SSH_IPSEC_AH
      /* Add IP header for AH (with adjustments). */
      if (transform & SSH_PM_IPSEC_AH)
        {
#if defined (WITH_IPV6)
          if (pc->pp->protocol == SSH_PROTOCOL_IP6)
            {
              ssh_fastpath_mac_add_ah_header6(pc, mac_update_func,
					      tc->mac_context? tc->mac_context:
					      tc->cipher_context, -natt_len,
					      SSH_IPPROTO_AH);
              if (pc->pp == NULL)
                /* AH failed, packet stolen. */
                goto garbage;
            }
          else
#endif /* WITH_IPV6 */
            ssh_fastpath_mac_add_ah_header4(pc->pp, pc->hdrlen, 
					    mac_update_func,
					    tc->mac_context? tc->mac_context:
					    tc->cipher_context, -natt_len,
					    SSH_IPPROTO_AH);
        }
#endif /* SSH_IPSEC_AH */
      /* Add the range from the packet that is to be included in MAC. */
      if (!ssh_fastpath_mac_add_range(pc->pp, mac_ofs, mac_len, 
				      mac_update_func,
				      tc->mac_context? tc->mac_context:
				      tc->cipher_context))
        {
        error:
          trr->statflags |= SSH_ENGINE_STAT_T_DROP;
          SSH_ENGINE_MARK_STAT(pc, SSH_ENGINE_STAT_ERRORDROP);
          ssh_fastpath_release_transform_context(fastpath, tc);
	  (*callback)(pc, SSH_ENGINE_RET_ERROR, context);
          return;
        }
      /* Get the resulting ICV. */
      if (tc->mac)
        if (tc->mac->hmac)
	  status = (*tc->mac->hash->final)(tc->mac_context, pc->u.flow.icv);
        else
	  status = (*tc->mac->cipher->final)(tc->mac_context, pc->u.flow.icv);
      else
        {
          /* IV for counter mode algorithm, use IPSec seq# as iv. */
          unsigned char iv[16];
	  SSH_ASSERT(tc->cipher_iv_len == 8 && tc->icv_len >= 8);
	  SSH_PUT_32BIT(iv, tc->cipher_nonce);
	  memcpy(pc->u.flow.icv, pc->u.flow.packet_icv, 8);
	  memcpy(iv + 4, pc->u.flow.icv, 8);
	  SSH_PUT_32BIT(iv + 12, 1);
          status = (*tc->cipher->transform)(tc->cipher_context, iv, iv, 0, iv);
	  if (status == SSH_CRYPTO_OK)
            status = (*tc->cipher->final)(tc->cipher_context, 
			  		  pc->u.flow.icv + 8);
        }

      if (status != SSH_CRYPTO_OK)
        {
          SSH_DEBUG(SSH_D_FAIL, ("MAC operation failed: %d", status));
          goto fail;
        }
    }
  else if (!tc->mac && !tc->mac_accel && 
	   tc->cipher && tc->cipher->is_auth_cipher)
    {
      /* If using cipher that does both authentication and confidentiality,
	 process aad now, ie. start processing icv, but do not get full value
	 calculated yet. */

      Boolean iv_in_aad = !!(transform & SSH_PM_CRYPT_NULL_AUTH_AES_GMAC);

      SSH_ASSERT(tc->counter_mode);

      /* Pass in the AAD. Notice, enc_ofs-enc_ofs+enc_len
	 MUST not be passed as AAD as it will be handled
	 in combined transform. */
      if (!ssh_ipsec_esp_process_aad(pc->pp,
				     tc->cipher,
				     tc->cipher_context,
				     mac_ofs,
				     8 + iv_in_aad * 8,
				     !!(transform & SSH_PM_IPSEC_LONGSEQ), 
				     seq.high))
      {
	SSH_DEBUG(SSH_D_FAIL, ("process_aad failed"));
	goto error;
      }
    }

  /* Continue processing from after MAC computation. */
  fastpath_transform_in_finish(pc->pp,
#ifdef SSHDIST_IPSEC_HWACCEL
			       SSH_HWACCEL_OK,
#endif /* SSHDIST_IPSEC_HWACCEL */
			       (void *)pc);
}

#endif /* SSHDIST_IPSEC_TRANSFORM */
