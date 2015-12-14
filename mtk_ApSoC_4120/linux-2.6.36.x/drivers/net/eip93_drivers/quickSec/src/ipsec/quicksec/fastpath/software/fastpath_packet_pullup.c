/*
 * 
 * fastpath_packet_pullup.c
 * 
 * Copyright:
 *       Copyright (c) 2007 SFNT Finland Oy.
 *       All rights reserved.
 *
 *  Routines for inspecting packet headers, performing
 *  sanity checks on packets and caching fields from
 *  packet headers to the SshEnginePacketContext data
 *  structure.
 *
 */

#include "sshincludes.h"
#include "engine_internal.h"

#define SSH_DEBUG_MODULE "SshEngineFastpathPacketPullup"


SSH_FASTTEXT SshEngineActionRet
fastpath_packet_context_pullup_xid(SshEngine engine, 
				   SshEnginePacketContext pc)
{
  SshInterceptorPacket pp;
  unsigned char buffer[4];
#ifdef SSHDIST_IPSEC_NAT_TRAVERSAL
  Boolean is_ike_natt;
  int i;
#endif /* SSHDIST_IPSEC_NAT_TRAVERSAL */

  pp = pc->pp;

  SSH_ASSERT(pp->protocol == SSH_PROTOCOL_IP4
             || pp->protocol == SSH_PROTOCOL_IP6);

  switch (pc->ipproto)
    {
    case SSH_IPPROTO_UDP:
#ifdef SSHDIST_IPSEC_NAT_TRAVERSAL
      is_ike_natt = FALSE;
      for (i = 0; i < engine->num_ike_ports; i++)
	{
	  if (((pc->pp->flags & SSH_PACKET_FROMADAPTER) &&
               pc->u.rule.dst_port == engine->local_ike_natt_ports[i]) ||
              ((pc->pp->flags & SSH_PACKET_FROMPROTOCOL) &&
               pc->u.rule.dst_port == engine->remote_ike_natt_ports[i]))
	    {
	      is_ike_natt = TRUE;
	      break;
	    }
	}
      
      if (is_ike_natt && (pc->packet_len == pc->hdrlen + SSH_UDPH_HDRLEN + 1))
	{
	  if (ssh_engine_ip_is_local(engine, &pc->dst))
	    {
	      SSH_DEBUG(SSH_D_LOWOK, ("Incoming NAT-T keepalive discarded"));
	      return SSH_ENGINE_RET_DROP;
	    }
	}

      if (is_ike_natt && (pc->packet_len >= pc->hdrlen + SSH_UDPH_HDRLEN + 4))
	{
	  ssh_interceptor_packet_copyout(pp, pc->hdrlen + SSH_UDPH_HDRLEN, 
					 buffer, 4);
	  pc->protocol_xid = SSH_GET_32BIT(buffer);
	  pc->flags |= SSH_ENGINE_PC_IS_IPSEC;
	}
#endif /* SSHDIST_IPSEC_NAT_TRAVERSAL */

      /* Pull-up DHCP xid */
      if (SSH_PREDICT_FALSE(pc->u.rule.dst_port == 67) ||
	  SSH_PREDICT_FALSE(pc->u.rule.dst_port == 68))
        {
          /* Fetch transaction identifier, reuse SPI in flowid */
          if (pc->hdrlen + SSH_UDPH_HDRLEN + 8 > pc->packet_len)
            return SSH_ENGINE_RET_FAIL;

          ssh_interceptor_packet_copyout(pp,
                                         pc->hdrlen + SSH_UDPH_HDRLEN + 4,
                                         buffer, 4);
          pc->protocol_xid = SSH_GET_32BIT(buffer);
        }

      break;

    default:
      break;
    }
  return SSH_ENGINE_RET_OK;
}



/* This function pulls up all necessary information into
   SshEnginePacketContext pc and SshEnginePacketData pd from the
   SshInterceptorPacket `pc->pp'. Note that this function is NOT
   intended to immediately discard all "non-good" packets. It MUST
   return all "corrupted" packets, that are sufficiently "un-corrupt"
   to be handled by the auditing code. If the packet protocol is not
   media level then 'pd' may be NULL.

   The information which has been "pulled up", is related to the
   SshInterceptorProtocol which is returned. Note that pp->protocol
   MAY have been modified in the process, and can not be used as the
   basis of a sanity check.

   Given an IP packet, this will pull up UDP, TCP, and SCTP port
   numbers, and ICMP <type,code> tuples into given packet context.

   If a packet which should not be processed further is received, then
   this function returns SSH_PROTOCOL_NUM_PROTOCOLS, and fill
   appropriate auding information into packet context. */

SSH_FASTTEXT 
SshInterceptorProtocol
fastpath_packet_context_pullup(SshEngine engine,
			       SshEnginePacketContext pc,
			       SshEnginePacketData pd)
{
  const unsigned char *ucp;
  SshUInt16 ip_len, fragoff, fragoff2;
  SshInterceptorPacket pp = pc->pp;
#ifndef SSH_IPSEC_IP_ONLY_INTERCEPTOR
  SshUInt16 ethertype = 0;
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */
#if defined (WITH_IPV6)
  SshUInt32 tcphlen;
#endif /* WITH_IPV6 */

  SSH_ASSERT(pp != NULL);

  /* Initialize basic flags */
  pc->flags &=
    (SSH_ENGINE_PC_INUSE | SSH_ENGINE_PC_RECURSED | SSH_ENGINE_PC_DONE
     | SSH_ENGINE_PC_OUTBOUND_CALL | SSH_ENGINE_PC_RESTARTED_OUT);

  /* This label starts or restarts processing of the packet.  We jump
     here when starting with the packet, and after decapsulating a
     packet from a tunnel in order to process the inner packet.
     tunnel_id will be set to 0 initially, and to some other value
     when a packet is decapsulated from a tunnel. */

  pc->packet_len = ssh_interceptor_packet_len(pp);
  pc->min_packet_size = 0;
  pc->protocol_xid = 0;
  pc->u.rule.src_port = 0;
  pc->u.rule.dst_port = 0;
  pc->u.rule.spi = 0;
  pc->u.rule.tos = 0;
  pc->hdrlen = 0;

  if (SSH_PREDICT_TRUE(pp->protocol == SSH_PROTOCOL_IP4))
    goto ssh_protocol_ip4;

  /* Strip media header if the packet has one. */
  switch (pp->protocol)
    {
#ifndef SSH_IPSEC_IP_ONLY_INTERCEPTOR
    case SSH_PROTOCOL_ETHERNET:
      SSH_DEBUG(SSH_D_LOWSTART, ("decapsulating from ethernet header"));
      SSH_ASSERT(pd != NULL);
      /* Sanity check packet length. */
      if (pc->packet_len <= SSH_ETHERH_HDRLEN)
        {
	  pc->audit.corruption = SSH_PACKET_CORRUPTION_SHORT_MEDIA_HEADER;
          SSH_DEBUG(SSH_D_FAIL, ("received too short ether packet: len=%d",
                                 (int)pc->packet_len));
           goto drop;
        }

      /* Get a pointer to the beginning of the ethernet header. */
#ifdef SSH_IPSEC_CONVERT_SNAP_TO_EII
      ucp = ssh_interceptor_packet_pullup_read(pp, SSH_SNAPH_HDRLEN);
#else /* SSH_IPSEC_CONVERT_SNAP_TO_EII */
      ucp = ssh_interceptor_packet_pullup_read(pp, SSH_ETHERH_HDRLEN);
#endif /* SSH_IPSEC_CONVERT_SNAP_TO_EII */

      if (ucp == NULL)
        goto error;

      /* Get the packet type. */
      ethertype = SSH_GET_16BIT(ucp + SSH_ETHERH_OFS_TYPE);

#ifdef SSH_IPSEC_CONVERT_SNAP_TO_EII
      SSH_DEBUG(SSH_D_LOWOK, ("Checking ethernet length %u", ethertype));
      
      if (ethertype <= 1508)
	{
	  SSH_DUMP_PACKET(SSH_D_NICETOKNOW, ("Potential SNAP packet:"), pp);

	  /* Is this SNAP packet? */
	  if ((*(ucp + 15) == 0xaa) || (*(ucp + 15) == 0xab))
	    {
              if (!ssh_interceptor_packet_delete(pp, 12, 8))
                goto error;
              
              ucp = ssh_interceptor_packet_pullup_read(pp, SSH_ETHERH_HDRLEN);
              if (ucp == NULL)
                goto error;
              
              ethertype = SSH_GET_16BIT(ucp + SSH_ETHERH_OFS_TYPE);

              SSH_DEBUG(SSH_D_NICETOKNOW, ("Converted SNAP to EII, new"
                                           " ethertype", ethertype));
            }
	}
#endif /* SSH_IPSEC_CONVERT_SNAP_TO_EII */

      /* If the packet was received using a multicast destination address,
         set a flag to that effect. */
      if (SSH_ETHER_IS_MULTICAST(ucp + SSH_ETHERH_OFS_DST))
        pp->flags |= SSH_ENGINE_P_BROADCAST;

      SSH_DEBUG(5, ("received ethernet packet flags=0x%x type=0x%x",
                    (unsigned int)pp->flags, (unsigned int)ethertype));

      /* Save the media header. */
      pd->media_hdr_len = SSH_ETHERH_HDRLEN;
      pd->min_packet_len = 60;
      pd->media_protocol = SSH_PROTOCOL_ETHERNET;
      pd->mediatype = SSH_INTERCEPTOR_MEDIA_ETHERNET;
      memcpy(pd->mediahdr, ucp, SSH_ETHERH_HDRLEN);

      /* Remove the media header. */
      if (!ssh_interceptor_packet_delete(pp, 0, SSH_ETHERH_HDRLEN))
        {
          SSH_DEBUG(SSH_D_ERROR, ("Packet delete failed, packet dropped"));
          goto error;
        }
      pc->packet_len -= SSH_ETHERH_HDRLEN;

      /* Set the pp->protocol to a new value. We might here also do some
         protocol-specific special handling. Notice that the media header
         is already removed. */
      switch (ethertype)
        {
        case SSH_ETHERTYPE_IP: /* IPv4 datagram */

#ifdef SSH_ENGINE_MEDIA_ETHER_NO_ARP_RESPONSES
          /* Take IP destination address from the packet, and add an
             arp cache entry for the IP-ether mapping.  This is only
             done for outgoing non-broadcast packets. */
          if (!(pp->flags & SSH_ENGINE_P_BROADCAST) &&
              (pp->flags & SSH_PACKET_FROMPROTOCOL))
            {
              SshIpAddrStruct ipaddr;

              if (pc->packet_len < SSH_IPH4_HDRLEN)
                {
                  SSH_DEBUG(SSH_D_FAIL,
                            ("Packet too short to contain IPv4 header"));

		  pc->hdrlen = pc->packet_len;
		  pc->audit.corruption =
		    SSH_PACKET_CORRUPTION_SHORT_IPV4_HEADER;
                  goto corrupt;
                }
              ucp = ssh_interceptor_packet_pullup_read(pp, SSH_IPH4_HDRLEN);
              if (!ucp)
                goto error;
              SSH_IP4_DECODE(&ipaddr, ucp + SSH_IPH4_OFS_DST);

              /* Update media address to existing arp cache entry.
                 Check that it is not a "0"-address. The latter is due to
                 Solaris, where inbound IP packets have to be
                 ethernet encapsulated, and the dummy addresses are just
                 six 0s. */
              ssh_engine_arp_add_kludge(engine,
					&ipaddr,
					pp->ifnum_in,
                                        pd->mediahdr + SSH_ETHERH_OFS_DST);

            }
#endif /* SSH_ENGINE_MEDIA_ETHER_NO_ARP_RESPONSES */

          /* Change to upper protocol number. */
          pp->protocol = SSH_PROTOCOL_IP4;
          break;

        case SSH_ETHERTYPE_IPv6: /* IPv6 datagram */
          /* There's no need for the
             SSH_ENGINE_MEDIA_ETHER_NO_ARP_RESPONSES here, since old
             Solarisen that need it are too old to handle IPv6 in any
             case. */
          pp->protocol = SSH_PROTOCOL_IP6;
          break;

        case SSH_ETHERTYPE_ARP:
          SSH_ENGINE_MARK_STAT(pc, SSH_ENGINE_STAT_IN_ARP);
          pp->protocol = SSH_PROTOCOL_ARP;
          break;

        default:
          pp->protocol = SSH_PROTOCOL_OTHER;
          break;
        }
      /* Restart processing of the packet, this time without the media
         header.  Note that this cannot possibly loop, because we did not
         set the pp->protocol field to any value that could again restart. */
      return SSH_PROTOCOL_ETHERNET;

    case SSH_PROTOCOL_FDDI:
      /* We currently only support ethernet media.  Drop the packet. */
      SSH_TRACE(SSH_D_FAIL, ("unsupported FDDI encapsulated packet"));
      SSH_ENGINE_MARK_STAT(pc, SSH_ENGINE_STAT_IN_OTHER);
      goto drop;

    case SSH_PROTOCOL_TOKENRING:
      SSH_TRACE(SSH_D_FAIL, ("unsupported TOKENRING encapsulated packet"));
      SSH_ENGINE_MARK_STAT(pc, SSH_ENGINE_STAT_IN_OTHER);
      goto drop;

    case SSH_PROTOCOL_ARP:
      SSH_DEBUG(SSH_D_LOWSTART, ("ARP packet received"));
      SSH_ENGINE_MARK_STAT(pc, SSH_ENGINE_STAT_IN_ARP);
      break;

#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */

    ssh_protocol_ip4:
    case SSH_PROTOCOL_IP4:
      SSH_DEBUG(SSH_D_LOWSTART, ("IPv4 packet"));
      SSH_ENGINE_MARK_STAT(pc, SSH_ENGINE_STAT_IN_IP4);

      pc->min_packet_size = SSH_IPH4_HDRLEN;

      /* Perform basic sanity checks on the packet. */
      if (SSH_PREDICT_FALSE(pc->packet_len < pc->min_packet_size))
        {
          SSH_DEBUG(SSH_D_FAIL, ("IPv4 packet shorter than IPv4 header"));
	  pc->hdrlen = (SshUInt16) pc->packet_len;
	  pc->audit.corruption = SSH_PACKET_CORRUPTION_SHORT_IPV4_HEADER;
	  goto corrupt;
        }

      /* Fetch packet header. */
      ucp = ssh_interceptor_packet_pullup_read(pp, SSH_IPH4_HDRLEN);
      if (SSH_PREDICT_FALSE(!ucp))
        {
          SSH_DEBUG(SSH_D_FAIL, ("pullup failed"));
          goto error;
        }
#ifndef SSH_IPSEC_SKIP_LINUX_SANITY_CHECKS
      /* Sanity check header version. */
      if (SSH_PREDICT_FALSE(SSH_IPH4_VERSION(ucp) != 4))
        {
          SSH_DEBUG(SSH_D_FAIL, ("IPv4 version not 4"));
	  pc->audit.corruption = SSH_PACKET_CORRUPTION_NOT_IPV4;
          goto corrupt;
        }
#endif /* SSH_IPSEC_SKIP_LINUX_SANITY_CHECKS */

      /* Sanity check header length and checksum; check IP options. */
      pc->hdrlen = 4 * SSH_IPH4_HLEN(ucp);
      ip_len = SSH_IPH4_LEN(ucp);

#ifndef SSH_IPSEC_SKIP_LINUX_SANITY_CHECKS
      if (SSH_PREDICT_FALSE(pc->hdrlen < SSH_IPH4_HDRLEN))
        {
          SSH_DEBUG(SSH_D_FAIL, ("IPv4 header short"));
	  pc->audit.corruption = SSH_PACKET_CORRUPTION_SHORT_IPV4_HEADER;
          goto corrupt;
        }
      if (SSH_PREDICT_FALSE(ip_len < pc->hdrlen))
	{
          SSH_DEBUG(SSH_D_FAIL, ("Invalid IPv4 packet short"));
	  pc->hdrlen = ip_len;
	  pc->audit.corruption = SSH_PACKET_CORRUPTION_SHORT_IPV4_HEADER;
          goto corrupt;
	}

      if (SSH_PREDICT_FALSE(pc->packet_len < ip_len))
        {
          SSH_DEBUG(SSH_D_FAIL, ("IPv4 truncated packet"));
	  pc->audit.corruption = SSH_PACKET_CORRUPTION_TRUNCATED_PACKET;
	  goto corrupt;
        }
#endif /* SSH_IPSEC_SKIP_LINUX_SANITY_CHECKS */

      /* Cache whether the packet is a fragment. */
      fragoff = SSH_IPH4_FRAGOFF(ucp);
      fragoff2 = fragoff & SSH_IPH4_FRAGOFF_OFFMASK;
      if (SSH_PREDICT_FALSE(
	    fragoff & (SSH_IPH4_FRAGOFF_OFFMASK | SSH_IPH4_FRAGOFF_MF)))
        {
          /* The packet is a fragment. */
          pp->flags |= SSH_ENGINE_P_ISFRAG;
          if ((fragoff & SSH_IPH4_FRAGOFF_OFFMASK) == 0)
            pp->flags |= SSH_ENGINE_P_FIRSTFRAG;
          if ((fragoff & SSH_IPH4_FRAGOFF_MF) == 0)
            {
              pp->flags |= SSH_ENGINE_P_LASTFRAG;
              pc->frag_packet_size = 8 * fragoff2 + ip_len - pc->hdrlen;
            }
        }

      pc->ipproto = SSH_IPH4_PROTO(ucp);
      SSH_DEBUG(SSH_D_LOWOK, ("IPv4 iproto=%d", (int) pc->ipproto));

      /* Cache the ip numbers to the packet context. */
      SSH_IPH4_SRC(&pc->src, ucp);
      SSH_IPH4_DST(&pc->dst, ucp);

      /* Cache type of service. */
      pc->u.rule.tos = SSH_IPH4_TOS(ucp);

#ifndef SSH_IPSEC_SKIP_LINUX_SANITY_CHECKS
      /* Delete extra data from end of packet. */
      if (SSH_PREDICT_FALSE(ip_len != pc->packet_len))
        {
          if (!ssh_interceptor_packet_delete(pp, ip_len,
                                             pc->packet_len - ip_len))
            {
              SSH_DEBUG(SSH_D_FAIL, ("IPv4 delete trailing junk failed"));
              goto error;
            }
          pc->packet_len = ip_len;
        }
#endif /* SSH_IPSEC_SKIP_LINUX_SANITY_CHECKS */

      /* Compute minimum packet sizes for reassembled packets */
      if (SSH_PREDICT_TRUE(fragoff2 == 0))
        {
	  SshUInt16 ulph_len;
	  unsigned const char *ulph;

          /* A restarted packet (e.g. NAT-T or L2TP) may have values
             from the previous restart, and if the new pullup
             does not override them, we must reset them. */

	  switch (pc->ipproto)
	    {
	    case SSH_IPPROTO_TCP:     ulph_len = SSH_TCPH_HDRLEN; break;
	    case SSH_IPPROTO_UDP:     ulph_len = SSH_UDPH_HDRLEN; break;
	    case SSH_IPPROTO_UDPLITE: ulph_len = SSH_UDPH_HDRLEN; break;
	    case SSH_IPPROTO_ESP:     ulph_len = SSH_ESPH_OFS_SPI + 4; break;
	    case SSH_IPPROTO_AH:      ulph_len = SSH_AHH_OFS_SPI + 4; break;
	    case SSH_IPPROTO_SCTP:    ulph_len = SSH_SCTPH_HDRLEN; break;
	    case SSH_IPPROTO_ICMP:    ulph_len = SSH_ICMP_HEADER_MINLEN; break;
	    default:                  ulph_len = 0; break;
	    }

	  pc->min_packet_size = pc->hdrlen + ulph_len;
	  if (SSH_PREDICT_TRUE(ip_len >= pc->min_packet_size))
	    {
	      if (SSH_PREDICT_FALSE((ucp =
			     ssh_interceptor_packet_pullup_read(pp,
						pc->min_packet_size))
			    == NULL))
		goto error;

	      ulph = ucp + pc->hdrlen;

	      switch (pc->ipproto)
		{
		case SSH_IPPROTO_TCP:
		  pc->u.rule.dst_port = SSH_TCPH_DSTPORT(ulph);
		  pc->u.rule.src_port = SSH_TCPH_SRCPORT(ulph);
		  break;
		case SSH_IPPROTO_UDP:
		case SSH_IPPROTO_UDPLITE:
		  pc->u.rule.dst_port = SSH_UDPH_DSTPORT(ulph);
		  pc->u.rule.src_port = SSH_UDPH_SRCPORT(ulph);
		  break;
		case SSH_IPPROTO_SCTP:
		  pc->u.rule.dst_port = SSH_SCTPH_DSTPORT(ulph);
		  pc->u.rule.src_port = SSH_SCTPH_SRCPORT(ulph);
		  break;
		case SSH_IPPROTO_ICMP:
		  pc->icmp_type = SSH_ICMPH_TYPE(ulph);
		  pc->u.rule.icmp_code = SSH_ICMPH_CODE(ulph);
		  break;
		case SSH_IPPROTO_ESP:
		  pc->u.rule.spi = SSH_GET_32BIT(ucp +
						 pc->hdrlen +
						 SSH_ESPH_OFS_SPI);
		  pc->flags |= SSH_ENGINE_PC_IS_IPSEC;
		  pc->protocol_xid = pc->u.rule.spi;
		  break;
		case SSH_IPPROTO_AH:
		  pc->u.rule.spi = SSH_GET_32BIT(ucp +
						 pc->hdrlen +
						 SSH_AHH_OFS_SPI);
		  pc->flags |= SSH_ENGINE_PC_IS_IPSEC;
		  pc->protocol_xid = pc->u.rule.spi;
		  break;
		default:
		  pc->u.rule.src_port = 0;
		  pc->u.rule.dst_port = 0;
		  pc->icmp_type = 0;
		  pc->u.rule.icmp_code = 0;
		  pc->u.rule.spi = 0;
		  break;
		}

	      /* Pull-up DHCP / NAT-T information. */
	      switch (fastpath_packet_context_pullup_xid(engine, pc))
		{
		  /* Silently drop */
		case SSH_ENGINE_RET_DROP:
		  goto drop;
		  /* Drop and audit as corrupt */
		case SSH_ENGINE_RET_FAIL:
		  pc->audit.corruption = SSH_PACKET_CORRUPTION_ERROR;
		  goto corrupt;
		case SSH_ENGINE_RET_OK:
		  break;
		default:
		  SSH_NOTREACHED;
		  goto drop;
		}
	    }
	  else
	    {
	      SSH_DEBUG(SSH_D_FAIL, ("%d %d", pc->min_packet_size, ip_len));

	      SSH_DEBUG(SSH_D_FAIL, ("truncated packet"));
	      pc->audit.corruption =
		SSH_PACKET_CORRUPTION_TOO_SMALL_FOR_NEXT_PROTOCOL;
	      goto corrupt;
	    }
	}
      break;

#if defined (WITH_IPV6)
    case SSH_PROTOCOL_IP6:
      SSH_DEBUG(SSH_D_LOWSTART, ("IPv6 packet"));
      SSH_ENGINE_MARK_STAT(pc, SSH_ENGINE_STAT_IN_IP6);

      pc->min_packet_size = SSH_IPH6_HDRLEN;

      /* Perform basic sanity checks for the IPv6 header. */
      if (pc->packet_len < pc->min_packet_size)
        {
          SSH_DEBUG(SSH_D_FAIL, ("IPv6 packet shorter than IPv6 header"));
	  pc->hdrlen = (SshUInt16) pc->packet_len;
	  pc->audit.corruption = SSH_PACKET_CORRUPTION_SHORT_IPV6_HEADER;
          goto corrupt;
        }

      pc->hdrlen = SSH_IPH6_HDRLEN;
      ucp = ssh_interceptor_packet_pullup_read(pp, SSH_IPH6_HDRLEN);
      if (!ucp)
        {
          SSH_DEBUG(SSH_D_FAIL, ("pullup failed"));
          goto error;
        }

      if (SSH_IPH6_VERSION(ucp) != 6)
        {
          SSH_DEBUG(SSH_D_FAIL, ("IPv6 version not 6"));
	  pc->audit.corruption = SSH_PACKET_CORRUPTION_NOT_IPV6;
          goto corrupt;
        }

      ip_len = SSH_IPH6_LEN(ucp) + SSH_IPH6_HDRLEN;
      if (pc->packet_len < ip_len)
        {
          SSH_DEBUG(SSH_D_FAIL, ("IPv6 truncated packet"));
	  pc->audit.corruption = SSH_PACKET_CORRUPTION_SHORT_IPV6_HEADER;
	  goto corrupt;
        }

      if (pc->packet_len != ip_len)
	{
	  SSH_ASSERT(pc->packet_len > ip_len);

          if (!ssh_interceptor_packet_delete(pp, ip_len,
                                             pc->packet_len - ip_len))
            {
              SSH_DEBUG(SSH_D_FAIL, ("IPv6 delete trailing junk failed"));
              goto error;
            }
          pc->packet_len = ip_len;
	}

      SSH_IPH6_SRC(&pc->src, ucp);
      SSH_IPH6_DST(&pc->dst, ucp);

      pc->u.rule.priority = SSH_IPH6_CLASS(ucp);
      pc->audit.flowlabel = SSH_IPH6_FLOW(ucp);

      pc->fragh_offset_prevnh
        = pc->ipsec_offset_prevnh
        = SSH_IPH6_OFS_NH;
      pc->ipproto = SSH_IPH6_NH(ucp);

      /* Next we iterate through possible IPv6 extension headers. */
      {
        Boolean have_seen_routing_header = FALSE;
         SshUInt16 payload_len = SSH_IPH6_LEN(ucp);
        SshUInt16 ext_hdr_len, ext_routing_len;
        SshUInt16 offset = SSH_IPH6_HDRLEN;
        /* The following buffer is used as temporary memory when we
           iterate over IPv6 extension headers.  Sufficient to hold
           one 16 byte IPv6 address, or 8 bytes from the extension
           header, or a TCP/UDP/SCTP/ICMP6 header's fixed part
           (20/8/12/4 bytes). */
        unsigned char buf[20];

        if (payload_len == 0)
          {
            SSH_DEBUG(SSH_D_FAIL, ("Jumbo payload option not supported"));
	    pc->audit.corruption = SSH_PACKET_CORRUPTION_FORBIDDEN_OPTION;
            goto corrupt;
          }

        if (pc->ipproto == 0)
          { /* Hop-by-hop extension header.  Must be first,
               immediately after the initial IPv6 header. */
            if (offset + SSH_IP6_EXT_HOP_BY_HOP_HDRLEN > pc->packet_len)
              {
		SSH_DEBUG(SSH_D_FAIL, ("truncated packet"));
		pc->audit.corruption =
		  SSH_PACKET_CORRUPTION_TOO_SMALL_FOR_NEXT_PROTOCOL;
                goto corrupt;
              }
            ssh_interceptor_packet_copyout(pp, offset, buf, 2);
            pc->fragh_offset_prevnh
              = pc->ipsec_offset_prevnh
              = offset + SSH_IP6_EXT_COMMON_OFS_NH;
            offset += SSH_IP6_EXT_COMMON_LENB(buf);
            pc->ipproto = SSH_IP6_EXT_COMMON_NH(buf);
          }
        pc->fragh_offset
          = pc->ipsec_offset
          = offset;

      next_extension_header:
        switch (pc->ipproto)
          {
          case 0: /* A hop-by-hop -header in wrong place. */
            SSH_DEBUG(SSH_D_NETGARB,
                      ("IPv6 hop-by-hop header in illegal place"));
            ssh_engine_send_icmp_error(engine, pc,
                                       SSH_ICMP6_TYPE_PARAMPROB,
                                       SSH_ICMP6_CODE_PARAMPROB_NH,
                                       pc->ipsec_offset_prevnh);
	    pc->audit.corruption = SSH_PACKET_CORRUPTION_FORBIDDEN_OPTION;
            goto corrupt;
            break;

          case SSH_IPPROTO_IPV6ROUTE:   /* Routing extension header. */
            if (have_seen_routing_header)
              {
                SSH_DEBUG(SSH_D_FAIL, ("Multiple IPv6 routing headers"));
		pc->audit.corruption = SSH_PACKET_CORRUPTION_FORBIDDEN_OPTION;
                goto corrupt;
              } 
	    have_seen_routing_header = TRUE;
	    
            if (pp->flags & SSH_ENGINE_P_ISFRAG)
              {
                SSH_DEBUG(SSH_D_FAIL, ("IPv6 frag hdr before routing hdr"));
		pc->audit.corruption = SSH_PACKET_CORRUPTION_FORBIDDEN_OPTION;
                goto corrupt;
              }
            if (offset + SSH_IP6_EXT_ROUTING_HDRLEN > pc->packet_len)
              {
                SSH_DEBUG(SSH_D_FAIL, ("truncated packet"));
		pc->audit.corruption =
		  SSH_PACKET_CORRUPTION_TOO_SMALL_FOR_NEXT_PROTOCOL;
                goto corrupt;
              }
	    pc->hdrlen = offset;

            ssh_interceptor_packet_copyout(pp, offset, buf,
                                           SSH_IP6_EXT_ROUTING_HDRLEN);

	    /* Drop packets with Type 0 Routing header */
            if (SSH_IP6_EXT_ROUTING_TYPE(buf) == 0)
              {
                SSH_DEBUG(SSH_D_FAIL, 
			  ("Dropping packet with Type 0 Routing header"));
		pc->audit.corruption = SSH_PACKET_CORRUPTION_FORBIDDEN_OPTION;
                goto corrupt;
              }
            ext_routing_len = SSH_IP6_EXT_ROUTING_LEN(buf);
            if (ext_routing_len & 0x1)
              {
                SSH_DEBUG(SSH_D_NETGARB, ("IPv6 routing hdr len is odd"));
                ssh_engine_send_icmp_error(
                                        engine, pc,
                                        SSH_ICMP6_TYPE_PARAMPROB,
                                        SSH_ICMP6_CODE_PARAMPROB_HEADER,
                                        offset + SSH_IP6_EXT_ROUTING_OFS_LEN);
		pc->audit.corruption = SSH_PACKET_CORRUPTION_UNALIGNED_OPTION;
                goto corrupt;
              }
            ext_hdr_len = 8 + 8 * ext_routing_len;

            pc->fragh_offset_prevnh = pc->ipsec_offset_prevnh
              = offset + SSH_IP6_EXT_COMMON_OFS_NH;
            pc->ipproto = SSH_IP6_EXT_ROUTING_NH(buf);

            offset += ext_hdr_len;
            pc->fragh_offset = pc->ipsec_offset = offset;
            goto next_extension_header;
            break;

          case SSH_IPPROTO_IPV6OPTS: /* Destination options header. */
            if (offset + SSH_IP6_EXT_DSTOPTS_HDRLEN > pc->packet_len)
              {
                SSH_DEBUG(SSH_D_FAIL, ("truncated packet"));
		pc->audit.corruption =
		  SSH_PACKET_CORRUPTION_TOO_SMALL_FOR_NEXT_PROTOCOL;
                goto corrupt;
              }
	    pc->hdrlen = offset;
            ssh_interceptor_packet_copyout(pp, offset, buf, 2);

            if (have_seen_routing_header)
              /* Increment offset, but do NOT increase
                 `pc->ipsec_offset' since the ipsec headers shall be
                 inserted before this destination options header. */
              offset += SSH_IP6_EXT_DSTOPTS_LENB(buf);
            else
              {
                pc->ipsec_offset_prevnh = offset + SSH_IP6_EXT_COMMON_OFS_NH;
                offset += SSH_IP6_EXT_DSTOPTS_LENB(buf);
                pc->ipsec_offset = offset;
              }
            pc->ipproto = SSH_IP6_EXT_DSTOPTS_NH(buf);
            goto next_extension_header;
            break;

          case SSH_IPPROTO_IPV6FRAG: /* Fragment header. */
            if (offset + SSH_IP6_EXT_FRAGMENT_HDRLEN > pc->packet_len)
              {
                SSH_DEBUG(SSH_D_FAIL, ("truncated packet"));
		pc->audit.corruption =
		  SSH_PACKET_CORRUPTION_TOO_SMALL_FOR_NEXT_PROTOCOL;
                goto corrupt;
              }
	    pc->hdrlen = offset;
            ssh_interceptor_packet_copyout(pp, offset, buf,
                                           SSH_IP6_EXT_FRAGMENT_HDRLEN);
            pc->fragment_id = SSH_IP6_EXT_FRAGMENT_ID(buf);
            pc->fragment_offset = SSH_IP6_EXT_FRAGMENT_OFFSET(buf) * 8;
            pp->flags |= SSH_ENGINE_P_ISFRAG;
            if (pc->fragment_offset == 0)
              {
                pp->flags |= SSH_ENGINE_P_FIRSTFRAG;
              }
            if (SSH_IP6_EXT_FRAGMENT_M(buf) == 0)
              {
                pp->flags |= SSH_ENGINE_P_LASTFRAG;
              }
            /* `pc->frag_packet_size' is set after traversing all the
               headers. */

            pc->fragh_offset = offset;
            pc->fragh_offset_prevnh = pc->ipsec_offset_prevnh;

            pc->ipsec_offset_prevnh = offset + SSH_IP6_EXT_FRAGMENT_OFS_NH;
            offset += SSH_IP6_EXT_FRAGMENT_HDRLEN;
            pc->ipsec_offset = offset;
            pc->ipproto = SSH_IP6_EXT_FRAGMENT_NH(buf);









            if (pp->flags & SSH_ENGINE_P_FIRSTFRAG)
              goto next_extension_header;
            break;

          case SSH_IPPROTO_TCP:
            if (pp->flags & SSH_ENGINE_P_ISFRAG
                && !(pp->flags & SSH_ENGINE_P_FIRSTFRAG))
              {
                SSH_DEBUG(SSH_D_FAIL, ("non-first frag with TCP hdr"));
		pc->audit.corruption = SSH_PACKET_CORRUPTION_FORBIDDEN_OPTION;
                goto corrupt;
              }
            if (offset + SSH_TCPH_HDRLEN > pc->packet_len)
              {
                SSH_DEBUG(SSH_D_FAIL, ("truncated packet"));
		pc->audit.corruption =
		  SSH_PACKET_CORRUPTION_TOO_SMALL_FOR_NEXT_PROTOCOL;
                goto corrupt;
              }
	    pc->hdrlen = offset;
	    ssh_interceptor_packet_copyout(pp, offset, buf, SSH_TCPH_HDRLEN);

            /* Cache src and dst port numbers in the packet context. */
            pc->u.rule.dst_port = SSH_TCPH_DSTPORT(buf);
            pc->u.rule.src_port = SSH_TCPH_SRCPORT(buf);

            /* Check that TCP header fits into first fragment */
            tcphlen = 4 * SSH_TCPH_DATAOFFSET(buf);
            if (tcphlen + offset > pc->packet_len)
              {
                SSH_DEBUG(SSH_D_NETGARB, ("TCP header fragmented"));
                pc->audit.corruption =
		  SSH_PACKET_CORRUPTION_NEXT_PROTOCOL_HEADER_FRAGMENTED;
		goto corrupt;
              }

	    /* This is here to avoid copyout and offset calculations
	       at IPv6 is-sane attribute */
	    if ((SSH_TCPH_FLAGS(buf) &
		 (SSH_TCPH_FLAG_URG|SSH_TCPH_FLAG_FIN|SSH_TCPH_FLAG_PSH))
		== (SSH_TCPH_FLAG_URG|SSH_TCPH_FLAG_FIN|SSH_TCPH_FLAG_PSH))
	      {
		SSH_DEBUG(SSH_D_FAIL, ("IPv6 Xmas attack detected"));
		pc->audit.corruption = SSH_PACKET_CORRUPTION_TCP_XMAS;
                goto corrupt;
	      }
            break;

          case SSH_IPPROTO_UDP:
          case SSH_IPPROTO_UDPLITE:
            if (pp->flags & SSH_ENGINE_P_ISFRAG
                && !(pp->flags & SSH_ENGINE_P_FIRSTFRAG))
              {
                SSH_DEBUG(SSH_D_FAIL, ("non-first frag with UDP hdr"));
		pc->audit.corruption = SSH_PACKET_CORRUPTION_FORBIDDEN_OPTION;
                goto corrupt;
              }
            if (offset + SSH_UDPH_HDRLEN > pc->packet_len)
              {
                SSH_DEBUG(SSH_D_FAIL, ("truncated packet"));
		pc->audit.corruption =
		  SSH_PACKET_CORRUPTION_TOO_SMALL_FOR_NEXT_PROTOCOL;
                goto corrupt;
              }
	    pc->hdrlen = offset;
            ssh_interceptor_packet_copyout(pp, offset, buf,
                                           SSH_UDPH_HDRLEN);

            /* Cache src and dst port numbers in the packet context. */
            pc->u.rule.dst_port = SSH_UDPH_DSTPORT(buf);
            pc->u.rule.src_port = SSH_UDPH_SRCPORT(buf);
            break;

          case SSH_IPPROTO_SCTP:
            if (pp->flags & SSH_ENGINE_P_ISFRAG
                && !(pp->flags & SSH_ENGINE_P_FIRSTFRAG))
              {
                SSH_DEBUG(SSH_D_FAIL, ("non-first frag with SCTP hdr"));
		pc->audit.corruption = SSH_PACKET_CORRUPTION_FORBIDDEN_OPTION;
                goto corrupt;
              }
            if (offset + SSH_SCTPH_HDRLEN > pc->packet_len)
              {
                SSH_DEBUG(SSH_D_FAIL, ("truncated packet"));
		pc->audit.corruption =
		  SSH_PACKET_CORRUPTION_TOO_SMALL_FOR_NEXT_PROTOCOL;
                goto corrupt;
              }
	    pc->hdrlen = offset;
            ssh_interceptor_packet_copyout(pp, offset, buf,
                                           SSH_SCTPH_HDRLEN);
            /* Cache src and dst port numbers in the packet context. */
            pc->u.rule.dst_port = SSH_SCTPH_DSTPORT(buf);
            pc->u.rule.src_port = SSH_SCTPH_SRCPORT(buf);
            break;

          case SSH_IPPROTO_AH:
            SSH_ASSERT(pc->ipsec_offset == offset);
            if (offset + SSH_AHH_OFS_SPI + 4 > pc->packet_len)
              {
                SSH_DEBUG(SSH_D_FAIL, ("truncated packet"));
		pc->audit.corruption =
		  SSH_PACKET_CORRUPTION_TOO_SMALL_FOR_NEXT_PROTOCOL;
                goto corrupt;
              }
	    pc->hdrlen = offset;
            ssh_interceptor_packet_copyout(pp, offset + SSH_AHH_OFS_SPI,
                                           buf, 4);
            pc->u.rule.spi = SSH_GET_32BIT(buf);
	    pc->flags |= SSH_ENGINE_PC_IS_IPSEC;
	    pc->protocol_xid = pc->u.rule.spi;

            break;

          case SSH_IPPROTO_ESP:
            SSH_ASSERT(pc->ipsec_offset == offset);
            if (offset + SSH_ESPH_OFS_SPI + 4 > pc->packet_len)
              {
                SSH_DEBUG(SSH_D_FAIL, ("truncated packet"));
		pc->audit.corruption = SSH_PACKET_CORRUPTION_TRUNCATED_PACKET;
                goto corrupt;
              }
	    pc->hdrlen = offset;
            ssh_interceptor_packet_copyout(pp, offset + SSH_ESPH_OFS_SPI,
                                           buf, 4);
            pc->u.rule.spi = SSH_GET_32BIT(buf);
	    pc->flags |= SSH_ENGINE_PC_IS_IPSEC;
	    pc->protocol_xid = pc->u.rule.spi;
            break;

          case SSH_IPPROTO_IPV6ICMP:
            if (offset + SSH_ICMP6H_HDRLEN > pc->packet_len)
              {
                SSH_DEBUG(SSH_D_FAIL, ("truncated packet"));
		pc->audit.corruption = SSH_PACKET_CORRUPTION_TRUNCATED_PACKET;
                goto corrupt;
              }
	    pc->hdrlen = offset;
            ssh_interceptor_packet_copyout(pp, offset, buf, SSH_ICMP6H_HDRLEN);
            pc->icmp_type = SSH_ICMP6H_TYPE(buf);
            pc->u.rule.icmp_code = SSH_ICMP6H_CODE(buf);
            break;

          default:
            pc->u.rule.src_port = 0;
            pc->u.rule.dst_port = 0;
            pc->u.rule.icmp_code = 0;
            break;
          }

        pc->hdrlen = offset;
        if (pp->flags & SSH_ENGINE_P_LASTFRAG)
          {
            SSH_ASSERT(pp->flags & SSH_ENGINE_P_ISFRAG);
            pc->frag_packet_size =
              pc->fragment_offset + pc->packet_len - pc->hdrlen;
          }

        /* Pull-up DHCP / NAT-T information. */
        switch (fastpath_packet_context_pullup_xid(engine, pc))
	  {
	    /* Silently drop */
	  case SSH_ENGINE_RET_DROP:
	    goto drop;
	    /* Drop and audit as corrupt */
	  case SSH_ENGINE_RET_FAIL:
	    pc->audit.corruption = SSH_PACKET_CORRUPTION_ERROR;
	    goto corrupt;
	  case SSH_ENGINE_RET_OK:
	    break;
	  default:
	    SSH_NOTREACHED;
	    goto drop;
	  }
	goto out;
      }
      /*NOTREACHED*/
      break;
#endif /* WITH_IPV6 */

    default:
      SSH_DEBUG(SSH_D_LOWOK, ("non-ip packet, protocol=%d - dropping",
                              (int)pp->protocol));
      SSH_ENGINE_MARK_STAT(pc, SSH_ENGINE_STAT_IN_OTHER);
      goto drop;
    }

#ifdef WITH_IPV6
 out:
#endif /* WITH_IPV6 */

  if (pc->hdrlen > pc->packet_len)
    {
      SSH_DEBUG(SSH_D_FAIL, ("truncated packet"));
      pc->audit.corruption = SSH_PACKET_CORRUPTION_TRUNCATED_PACKET;
      goto corrupt;
    }

  /* If this packet was restarted after outbound transform execution,
     then clear the SSH_ENGINE_PC_IS_IPSEC flag to avoid matching incoming
     ipsec flows in the flow lookup. */
  if (pc->flags & SSH_ENGINE_PC_RESTARTED_OUT)
    pc->flags &= ~SSH_ENGINE_PC_IS_IPSEC;

  return pp->protocol;

  /* Error handling. */

 corrupt:
  /* The packet was corrupted */
  SSH_ENGINE_MARK_STAT(pc, SSH_ENGINE_STAT_CORRUPTDROP);
  return SSH_PROTOCOL_NUM_PROTOCOLS;

 drop:
  /* The packet should be dropped.  It is not freed yet. */
  ssh_interceptor_packet_free(pc->pp);
  /* FALLTHROUGH */

 error:
  /* The packet was freed by this function.  Clear the `pp' field from
     `pc' to indicate this. */
  pc->pp = NULL;

  return SSH_PROTOCOL_NUM_PROTOCOLS;
}



/* Simple table for specifying handling of IP options */
struct SshIpOptReqsRec
{
  /* Option Id */
  SshUInt8 id;

  /* Minimum supported value for TLV encoded option.
     MUST be greater than 0 for TLV encoded options. */
  SshUInt8 min_length;

  /* Maximum supportde value for option. If 0, then
     assume the option is of the type-only encoding.
     If greater than 0, then assume option is TLV encoded. */
  SshUInt8 max_length;

  /* Require option to be aligned on a 4-byte boundary
     in packet. */
  Boolean force_alignment;

  /* Is option allowed in packet? If FALSE, then packets
     containing this option are dropped. */
  Boolean is_allowed;
};

/* Descriptions of individual IP options. Check
   http://www.iana.org/assignments/ip-options
   for a complete list. This description
   corresponds to the 2001-06-29 published/updated
   list.

   Unsupported options:
   - CIPSO (Commercial Security Option, WG terminated 95).
   - MTU Probe (IANA assignment obsolete)
   - MTU Reply (IANA assignment obsolete)
   - ZSU (Experimental Measurement, Proprietary)
   - FINN (Experimental Flow Control, Proprietary)
   - VISA (Experimental Access Control, Proprietary)
   - IMITD (IMI Traffic Descriptor, Proprietary)
   - ADDEXT (Address Extension, Proprietary)
   - SDB, NDAPA, DPS, UMP, ENCODE (Proprietary)
*/

SSH_RODATA
static const struct SshIpOptReqsRec ssh_ip_opt_reqs[] =
  {
    { 0, 0, 0, FALSE, TRUE },     /* End-Of-Options [RFC791]*/
    { 1, 0, 0, FALSE, TRUE },     /* Nop [RFC791]*/
    { 2, 3, 0xFF, FALSE, TRUE },  /* Security [RFC1108] */
    { 3, 2, 0xFF, FALSE, FALSE }, /* Loose-Source [RFC791] */
    { 5, 3, 0xFF, FALSE, TRUE },  /* Extended-Security [RFC1108] */
    { 7, 2, 0xFF, FALSE, TRUE },  /* Record-Route [RFC791] */
    { 8, 4, 4, FALSE, TRUE },     /* Stream-Id [RFC791] */
    { 9, 2, 0xFF, FALSE, FALSE }, /* Strict-Source [RFC791]  */
    {17, 2, 0xFF, FALSE, TRUE},   /* EIP [RFC1385] */
    {20, 4, 4, FALSE, TRUE },     /* Router-Alert [RFC2113] */
    {68, 2, 0xFF, TRUE, TRUE },   /* Time-Stamp [RFC791] */
    {82, 2, 0xFF, FALSE, TRUE },  /* Traceroute option [RFC1393] */
    { 0xFF, 0, 0, FALSE, FALSE }, /* Last option in the list */
    { 0, 2, 0xFF, FALSE, TRUE },  /* Unrecognized option. This
                                     MUST be after the previous
                                     "Last option" in this table. */
  };

static SshEnginePacketCorruption
fastpath_ipv4_option_is_sane(SshEngine engine,
			     SshInterceptorPacket pp,
			     const SshEnginePacketContext pc,
			     const unsigned char *ucp,
			     SshUInt32 *option_ret)
{
  SshUInt16 checksum;
  int i, j;

#ifndef SSH_IPSEC_SKIP_LINUX_SANITY_CHECKS
  if (pc->hdrlen > pc->packet_len)
    {
      SSH_DEBUG(SSH_D_FAIL, ("IPv4 HLEN > packet len"));
      return SSH_PACKET_CORRUPTION_TRUNCATED_PACKET;
    }
#endif /* SSH_IPSEC_SKIP_LINUX_SANITY_CHECKS */

  SSH_DEBUG(SSH_D_LOWOK, ("ip options present"));

  if (!(pp->flags & SSH_PACKET_IP4HDRCKSUMOK))
    {
      checksum = ssh_ip_cksum_packet(pp, 0, pc->hdrlen);
      if (checksum != 0)
	{
	  SSH_DEBUG(SSH_D_FAIL, ("IPv4 checksum mismatch(w/opt)"));
	  return SSH_PACKET_CORRUPTION_CHECKSUM_MISMATCH;
	}
    }

  for (i = 20; i < pc->hdrlen;)
    {
      /* End-Of-Options list */
      if ((ucp[i] & 0x7f) == 0x0)
	break;

      for (j = 0; ssh_ip_opt_reqs[j].id < 0xF0; j++)
	{
	  if ((ucp[i] & 0x7f) == ssh_ip_opt_reqs[j].id)
	    break;
	}

      if (ssh_ip_opt_reqs[j].id >= 0xF0)
	{
	  SSH_DEBUG(SSH_D_NETGARB,("Unknown IP option 0x%x",ucp[i]));

	  if (SSH_IPSEC_ALLOW_UNKNOWN_IPV4_OPTIONS)
	    {
	      j++; /* Skip to the next option which is the
		      "default unrecognized option */
	    }
	  else
	    {
	      *option_ret = ucp[i] & 0x7f;
	      return SSH_PACKET_CORRUPTION_UNKNOWN_IP_OPTION;
	    }
	}

      if (ssh_ip_opt_reqs[j].is_allowed == FALSE)
	{
	  SSH_DEBUG(SSH_D_NETGARB,("policy: forbidden IP option 0x%x",
				   ucp[i]));
	  *option_ret = ucp[i] & 0x7f;
	  return SSH_PACKET_CORRUPTION_FORBIDDEN_OPTION;
	}

      if (ssh_ip_opt_reqs[j].force_alignment == TRUE
	  && (i % 4) != 0)
	{
	  SSH_DEBUG(SSH_D_NETGARB,
		    ("policy: option 0x%x is not aligned as required",
		     ucp[i]));
	  *option_ret = ucp[i] & 0x7f;
	  return SSH_PACKET_CORRUPTION_UNALIGNED_OPTION;
	}

      if (ssh_ip_opt_reqs[j].max_length == 0)
	{
	  i++;
	}
      else if ((i + 1) >= pc->hdrlen)
	{
	  SSH_DEBUG(SSH_D_NETGARB,
		    ("IPv4 option 0x%x lacking required length field",
		     ucp[i]));
	  *option_ret = ucp[i] & 0x7f;
	  return SSH_PACKET_CORRUPTION_OPTION_FORMAT_INCORRECT;
	}
      else
	{
	  /* Prevent infinite loop. */
	  SSH_ASSERT(ssh_ip_opt_reqs[j].min_length > 0);

	  if ((ssh_ip_opt_reqs[j].min_length > ucp[i+1])
	      || (ssh_ip_opt_reqs[j].max_length < ucp[i+1]))
	    {
	      SSH_DEBUG(SSH_D_NETGARB,
			("IPv4 option 0x%x length does not satisfy spec",
			 ucp[i]));
	      *option_ret = ucp[i] & 0x7f;
	      return SSH_PACKET_CORRUPTION_OPTION_FORMAT_INCORRECT;
	    }
	  i += ucp[i+1];
	}
    }
  if (i > pc->hdrlen)
    {
      SSH_DEBUG(SSH_D_NETGARB,
		("IPv4 options incorrectly formatted"));
      return SSH_PACKET_CORRUPTION_OPTION_OVERFLOW;
    }

  return SSH_PACKET_CORRUPTION_NONE;
}

static SshEnginePacketCorruption
fastpath_ipv4_fragment_is_sane(SshEngine engine,
			       SshInterceptorPacket pp,
			       const SshEnginePacketContext pc,
			       SshUInt32 ip_len,
			       SshUInt16 fragoff)
{
  if (fragoff + ip_len - pc->hdrlen > 65535)
    {
      SSH_DEBUG(SSH_D_FAIL, ("IPv4 fragment goes beyond 64k"));
      return SSH_PACKET_CORRUPTION_FRAGMENT_OVERFLOW_LENGTH;
    }

  if (!(pp->flags & SSH_ENGINE_P_LASTFRAG))
    {
      if ((ip_len - pc->hdrlen) % 8 != 0)
	{ /* Non-last frag data len is not multiple of 8. */
	  SSH_DEBUG(SSH_D_NETGARB,
		    ("IPv4 non-last fragment has bad length"));
	  return SSH_PACKET_CORRUPTION_FRAGMENT_BAD_LENGTH;
	}

      /* If this is not a last fragment, then there must be a minimum
	 amount of data (in practice all links provide reasonable MTU;
	 smaller fragments are almost certainly attacks).
	 Theoretically minimum size is 8, but such fragments are never
	 sent in practice). */
      if ((ip_len < SSH_ENGINE_MIN_FIRST_FRAGMENT_V4) &&
	  (pp->flags & SSH_ENGINE_P_FIRSTFRAG))
	{
	  SSH_DEBUG(SSH_D_FAIL, ("IPv4 policy: too small fragment"));
	  return SSH_PACKET_CORRUPTION_FRAGMENT_TOO_SMALL;
	}

      if (ip_len < (pc->hdrlen + SSH_ENGINE_MIN_FRAGMENT_V4))
	{
	  SSH_DEBUG(SSH_D_FAIL, ("IPv4 policy: too small fragment"));
	  return SSH_PACKET_CORRUPTION_FRAGMENT_TOO_SMALL;
	}
    }
  /* Fragment cannot start earlier than the minimum offset. */
  if (fragoff != 0 &&
      (pc->hdrlen + fragoff < SSH_ENGINE_MIN_FIRST_FRAGMENT_V4))
    {
      SSH_DEBUG(SSH_D_FAIL, ("IPv4 policy: frag starts early"));
      return SSH_PACKET_CORRUPTION_FRAGMENT_OFFSET_TOO_SMALL;
    }
  return SSH_PACKET_CORRUPTION_NONE;
}

/* This function sanity checks a packet. */
SSH_FASTTEXT static SshEnginePacketCorruption
fastpath_context_ipv4_is_sane(SshEngine engine,
			      SshInterceptorPacket pp,
			      const SshEnginePacketContext pc,
			      SshUInt32 *option_ret)
{
  const unsigned char *ucp;
  SshUInt32 ip_len;
  SshUInt16 fragoff, fragoff2, checksum;
  SshEnginePacketCorruption corrupt;
  SshInterceptorInterface *ifp;
  
  /* Fetch packet header. */
  ucp = ssh_interceptor_packet_pullup_read(pp, pc->hdrlen);
  if (SSH_PREDICT_FALSE(!ucp))
    {
      /* Is pc->pp the same as pp, if not drop also pc->pp, since
         the packet is somehow corrupted. */
      if (pc->pp != pp)
        ssh_interceptor_packet_free(pc->pp);
      
      pc->pp = NULL;
      SSH_DEBUG(SSH_D_FAIL, ("pullup failed"));
      return SSH_PACKET_CORRUPTION_ERROR;
    }

  /* Check for traceroute TTL. */
  if (SSH_PREDICT_FALSE(SSH_IPH4_TTL(ucp) < engine->min_ttl_value))
    {
      SSH_DEBUG(SSH_D_FAIL, ("IPv4 TTL < engine->min_ttl_value"));
      return SSH_PACKET_CORRUPTION_TTL_SMALL;
    }

  /* Check for multicast/broadcast/anycast source address.
     Note that "0.0.0.0" is a valid IP source address used by
     e.g. DHCP. */
  if (SSH_PREDICT_FALSE(ucp[SSH_IPH4_OFS_SRC] >= 0xe0))
    return SSH_PACKET_CORRUPTION_MULTICAST_SOURCE;

  /* Sanity check header length and checksum; check IP options. */
  if (SSH_PREDICT_TRUE(pc->hdrlen == SSH_IPH4_HDRLEN))
    {
      if (SSH_PREDICT_FALSE(!(pp->flags & SSH_PACKET_IP4HDRCKSUMOK)))
        {
          checksum = ssh_ip_cksum(ucp, pc->hdrlen);
          if (SSH_PREDICT_FALSE(checksum != 0))
            {
              SSH_DEBUG(SSH_D_FAIL, ("IPv4 checksum mismatch"));
              return SSH_PACKET_CORRUPTION_CHECKSUM_MISMATCH;
            }
        }
    }
  else
    {
      /* Options are rare, thus have them checked on separate function
	 to have less text on fastpath */
      if ((corrupt =
	   fastpath_ipv4_option_is_sane(engine, pp, pc, ucp, option_ret))
	  != SSH_PACKET_CORRUPTION_NONE)
	{
	  return corrupt;
	}
    }

  /* Packet length already sanity checked in pullup. */
  ip_len = SSH_IPH4_LEN(ucp);

  /* Sanity check fragment information.  Cache whether the packet is a
     fragment. */
  fragoff = SSH_IPH4_FRAGOFF(ucp);
  fragoff2 = 8 * (fragoff & SSH_IPH4_FRAGOFF_OFFMASK);

  if (SSH_PREDICT_FALSE(pp->flags & SSH_ENGINE_P_ISFRAG))
    {
      /* Fragment are rare, thus have them checked on separate function. */
      if ((corrupt =
	   fastpath_ipv4_fragment_is_sane(engine, pp, pc, ip_len, fragoff2))
	  != SSH_PACKET_CORRUPTION_NONE)
	{
	  return corrupt;
	}
    }

  /* The next protocol header must be contained in the first packet if
     the protocol is UDP, TCP, ICMP or SCTP. */
  if (SSH_PREDICT_TRUE(fragoff2 == 0))
    {
      /* If the packet is not fragmented, check that the minimum
         packet size requirement is met. */
      if (SSH_PREDICT_FALSE(pc->min_packet_size > ip_len) &&
	  ((pp->flags & SSH_ENGINE_P_ISFRAG) == 0))
        {
          SSH_DEBUG(SSH_D_FAIL, ("Unfragmented packet too small (%u > %u)",
                                 (unsigned int) pc->min_packet_size,
				 (unsigned int) ip_len));
          return SSH_PACKET_CORRUPTION_TOO_SMALL_FOR_NEXT_PROTOCOL;
        }
    }

  if (SSH_PREDICT_TRUE((pp->flags & SSH_ENGINE_P_ISFRAG) == 0)
      || (pp->flags & SSH_ENGINE_P_FIRSTFRAG) != 0)
    {
      if (SSH_PREDICT_FALSE(ip_len < pc->min_packet_size))
	{
	  SSH_DEBUG(SSH_D_NETGARB, ("Next protocol header is fragmented"));
	  return SSH_PACKET_CORRUPTION_NEXT_PROTOCOL_HEADER_FRAGMENTED;
	}

      ucp = ssh_interceptor_packet_pullup_read(pp, pc->min_packet_size);
      if (SSH_PREDICT_FALSE(ucp == NULL))
	{
          /* If the pc->pp is not same as pp, drop also pc->pp, since 
             anyway the packet is corrupted. */
          if (pc->pp != pp)
            ssh_interceptor_packet_free(pc->pp);
	  pc->pp = NULL;

	  SSH_DEBUG(SSH_D_NETGARB, ("pullup of next protocol header failed"));
	  return SSH_PACKET_CORRUPTION_ERROR;
	}

      switch (pc->ipproto)
        {
        case SSH_IPPROTO_TCP:
          {
            unsigned const char *tcph;
            SshUInt32 tcphlen, urgptr;
            SshUInt16 tcp_flags;

	    tcph = ucp + pc->hdrlen;

            /* Check that TCP header fits into first fragment */
            tcphlen = 4 * SSH_TCPH_DATAOFFSET(tcph);
            if (tcphlen + pc->hdrlen > ip_len)
              {
                SSH_DEBUG(SSH_D_NETGARB, ("TCP header fragmented"));
                return SSH_PACKET_CORRUPTION_NEXT_PROTOCOL_HEADER_FRAGMENTED;
              }

	    /* Check for urgent pointer pointing outside of this
	       packets boundary */
	    urgptr = 0;
	    if (SSH_TCPH_FLAGS(tcph) & SSH_TCPH_FLAG_URG)
	      urgptr = SSH_TCPH_URGENT(tcph);
	    pc->min_packet_size = tcphlen + pc->hdrlen + urgptr;

	    if (pc->min_packet_size > ip_len)
	      {
                SSH_DEBUG(SSH_D_NETGARB, ("Winnuke attack detected"));
		return SSH_PACKET_CORRUPTION_FRAGMENT_TOO_SMALL;
	      }

            /* Check for LAND attack */
            if (SSH_IP_EQUAL(&pc->src, &pc->dst) &&
                pc->u.rule.dst_port == pc->u.rule.src_port)
              {
                SSH_DEBUG(SSH_D_NETGARB, ("LAND attack detected"));
                return SSH_PACKET_CORRUPTION_SRC_DST_SAME;
              }

	    if (pc->u.rule.src_port == 0 || pc->u.rule.dst_port == 0)
	      {
                SSH_DEBUG(SSH_D_NETGARB, ("Reserved port detected"));
                return SSH_PACKET_CORRUPTION_RESERVED_VALUE;
	      }

            /* Check for all kinds of TCP scans */
            tcp_flags = SSH_TCPH_FLAGS(tcph);
            if ((tcp_flags &
		 (SSH_TCPH_FLAG_URG|SSH_TCPH_FLAG_FIN|SSH_TCPH_FLAG_PSH))
                == (SSH_TCPH_FLAG_URG|SSH_TCPH_FLAG_FIN|SSH_TCPH_FLAG_PSH))
              return SSH_PACKET_CORRUPTION_TCP_XMAS;
          }
          break;

        case SSH_IPPROTO_UDPLITE:
	  {
            unsigned const char *udph = ucp + pc->hdrlen;

	    if (SSH_UDP_LITEH_CKSUM_COVERAGE(udph) != 0 &&
		SSH_UDP_LITEH_CKSUM_COVERAGE(udph) < 8)
	      {
                SSH_DEBUG(SSH_D_NETGARB, ("UDPLite checksum coverage field "
					  "less than 8"));
                return SSH_PACKET_CORRUPTION_CHECKSUM_COVERAGE_TOO_SMALL;
	      }
	  }
	  /* Fall-through */
        case SSH_IPPROTO_UDP:

	  if (SSH_PREDICT_FALSE(pc->u.rule.src_port == 0) ||
	      SSH_PREDICT_FALSE(pc->u.rule.dst_port == 0))
	    {
	      SSH_DEBUG(SSH_D_NETGARB, ("Reserved port detected"));
	      return SSH_PACKET_CORRUPTION_RESERVED_VALUE;
	    }
          break;

        case SSH_IPPROTO_SCTP:
	  if (pc->u.rule.src_port == 0 || pc->u.rule.dst_port == 0)
	    {
	      SSH_DEBUG(SSH_D_NETGARB, ("Reserved port detected"));
	      return SSH_PACKET_CORRUPTION_RESERVED_VALUE;
	    }
          break;
	case SSH_IPPROTO_ICMP:
	  switch (pc->icmp_type)
	    {
	    case SSH_ICMP_TYPE_UNREACH:
	    case SSH_ICMP_TYPE_SOURCEQUENCH:
	    case SSH_ICMP_TYPE_TIMXCEED:
	    case SSH_ICMP_TYPE_PARAMPROB:
	      if (pc->packet_len < pc->hdrlen + 8 + SSH_IPH4_HDRLEN + 8)
		{
		  SSH_DEBUG(SSH_D_NETGARB, ("ICMP unreachable too short"));
		  return SSH_PACKET_CORRUPTION_TOO_SMALL_FOR_NEXT_PROTOCOL;
		}
	      break;
	    case SSH_ICMP_TYPE_ECHO:
	    case SSH_ICMP_TYPE_ECHOREPLY:
	      if (!engine->broadcast_icmp)
		{
		  ssh_kernel_mutex_lock(engine->interface_lock);
		  ifp = ssh_ip_get_interface_by_broadcast(&engine->ifs,
							  &pc->dst);
		  if (ifp != NULL || SSH_IP_IS_BROADCAST(&pc->dst))
		    {
		      SSH_DEBUG(SSH_D_NETGARB,
				("ICMP broadcast pkt received"));
		      ssh_kernel_mutex_unlock(engine->interface_lock);
		      return SSH_PACKET_CORRUPTION_ICMP_BROADCAST;
		    }
		  ssh_kernel_mutex_unlock(engine->interface_lock);
		}
	      if (pc->packet_len < pc->hdrlen + 8)
		{
		  SSH_DEBUG(SSH_D_NETGARB, ("ICMP echo too short"));
		  return SSH_PACKET_CORRUPTION_TOO_SMALL_FOR_NEXT_PROTOCOL;
		}
	      break;
	    default:
	      break;
	    }
	  break;
	}
    }

  SSH_DEBUG(SSH_D_LOWOK, ("IPv4 iproto=%d packet seems sane",
                          (int)pc->ipproto));
  return SSH_PACKET_CORRUPTION_NONE;
}

#if defined (WITH_IPV6)

/* This function sanity checks a packet context. For IPv6 this means
   only sanity checks for the user protocol, as options (extension
   headers) have been checked during context pullup due to
   differencies on IPv4 and IPv6 option mechanisms. */
static SshEnginePacketCorruption
fastpath_context_ipv6_is_sane(SshEngine engine,
			      SshInterceptorPacket pp,
			      const SshEnginePacketContext pc,
			      SshUInt32 *option_ret)
{
  if ((pp->flags & SSH_ENGINE_P_ISFRAG) == 0
      || (pp->flags & SSH_ENGINE_P_FIRSTFRAG) != 0)
    {
      switch (pc->ipproto)
	{
	case SSH_IPPROTO_TCP:
	  /* Check for LAND attack */
	  if (SSH_IP_EQUAL(&pc->src, &pc->dst) &&
	      pc->u.rule.dst_port == pc->u.rule.src_port)
	    {
	      SSH_DEBUG(SSH_D_FAIL, ("IPv6 LAND attack detected"));
	      return SSH_PACKET_CORRUPTION_SRC_DST_SAME;
	    }
	  if (pc->u.rule.src_port == 0 || pc->u.rule.dst_port == 0)
	    {
	      SSH_DEBUG(SSH_D_NETGARB, ("IPv6 Reserved TCP port detected"));
	      return SSH_PACKET_CORRUPTION_RESERVED_VALUE;
	    }
	  break;
        case SSH_IPPROTO_UDPLITE:
	case SSH_IPPROTO_UDP:
	  if (pc->u.rule.src_port == 0 || pc->u.rule.dst_port == 0)
	    {
	      SSH_DEBUG(SSH_D_NETGARB, ("IPv6 Reserved UDP port detected"));
	      return SSH_PACKET_CORRUPTION_RESERVED_VALUE;
	    }
	  break;
	case SSH_IPPROTO_SCTP:
	  if (pc->u.rule.src_port == 0 || pc->u.rule.dst_port == 0)
	    {
	      SSH_DEBUG(SSH_D_NETGARB, ("IPv6 Reserved SCTP port detected"));
	      return SSH_PACKET_CORRUPTION_RESERVED_VALUE;
	    }
	  break;
	case SSH_IPPROTO_IPV6ICMP:
	  if (pc->icmp_type == SSH_ICMP6_TYPE_UNREACH)
	    {
	      if (pc->hdrlen + 8 + SSH_IPH6_HDRLEN >= pc->packet_len)
		{
		  SSH_DEBUG(SSH_D_NETGARB, ("ICMP unreachable too short"));
		  return SSH_PACKET_CORRUPTION_TOO_SMALL_FOR_NEXT_PROTOCOL;
		}
	    }
	  break;
	default:
	  break;
	}
    }
  return SSH_PACKET_CORRUPTION_NONE;
}
#endif /* WITH_IPV6 */

SSH_FASTTEXT SshEnginePacketCorruption
fastpath_packet_context_is_sane(SshEngine engine,
				SshInterceptorProtocol proto,
				SshInterceptorPacket pp,
				const SshEnginePacketContext pc,
				SshUInt32 *option_ret)
{
  *option_ret = 0;

  if (SSH_PREDICT_TRUE(proto == SSH_PROTOCOL_IP4))
    goto ssh_protocol_ip4;

  /* Strip media header if the packet has one. */
  switch (proto)
    {
#ifndef SSH_IPSEC_IP_ONLY_INTERCEPTOR
    case SSH_PROTOCOL_ETHERNET:
      return SSH_PACKET_CORRUPTION_NONE;
      break;

    case SSH_PROTOCOL_FDDI:
      /* We currently only support ethernet media.  Drop the packet. */
      SSH_TRACE(SSH_D_FAIL, ("unsupported FDDI encapsulated packet"));
      return SSH_PACKET_CORRUPTION_ERROR;

    case SSH_PROTOCOL_TOKENRING:
      SSH_TRACE(SSH_D_FAIL, ("unsupported TOKENRING encapsulated packet"));
      return SSH_PACKET_CORRUPTION_ERROR;

    case SSH_PROTOCOL_ARP:
      SSH_DEBUG(SSH_D_LOWSTART, ("ARP packet received"));
      return SSH_PACKET_CORRUPTION_NONE;
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */

    ssh_protocol_ip4:
    case SSH_PROTOCOL_IP4:
      SSH_DEBUG(SSH_D_LOWSTART, ("IPv4 packet"));
      /* Perform basic sanity checks on the packet. */
      return fastpath_context_ipv4_is_sane(engine, pp, pc, option_ret);

#if defined (WITH_IPV6)
    case SSH_PROTOCOL_IP6:
      SSH_DEBUG(SSH_D_LOWSTART, ("IPv6 packet"));
      return fastpath_context_ipv6_is_sane(engine, pp, pc, option_ret);
#endif /* WITH_IPV6 */

    default:
      SSH_DEBUG(SSH_D_LOWOK, ("non-ip packet, protocol=%d - dropping",
                              (int)proto));
      return SSH_PACKET_CORRUPTION_ERROR;
    }
  /*NOTREACHED*/
}
