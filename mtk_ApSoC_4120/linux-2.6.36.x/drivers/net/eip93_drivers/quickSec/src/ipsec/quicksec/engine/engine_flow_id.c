/*
 * engine_flow_id.c
 *
 * Copyright:
 *       Copyright (c) 2002, 2003, 2006 SFNT Finland Oy.
 *       All rights reserved.
 *
 * Code for flow id computations in the engine.
 *
 */

#include "sshincludes.h"
#include "engine_internal.h"

#define SSH_DEBUG_MODULE "SshEngineFlowId"


/* Computes the flow id for a TCP or UDP session.  This can be used to
   compute the flow id when it uses IP addresses or port numbers that
   are different from those found in the packet (as is the case when
   NAT is being performed). */
Boolean
ssh_engine_compute_tcpudp_flowid(SshEngine engine,
				 SshUInt8 ipproto,
				 SshUInt32 tunnel_id,
				 const SshIpAddr src,
				 const SshIpAddr dst,
				 SshUInt16 src_port,
				 SshUInt16 dst_port,
				 const SshUInt32 *extension,
				 unsigned char *flow_id,
				 Boolean from_adapter)
{
  SshEnginePacketContext pc;
  SshInterceptorPacket pp;
  unsigned char *ucp;
  Boolean is_ip6, is_ok;
  size_t len; 
  
  if (SSH_IP_IS6(src) || SSH_IP_IS6(dst))
    is_ip6 = TRUE;
  else
    is_ip6 = FALSE;
  
  len = (is_ip6 ? SSH_IPH6_HDRLEN : SSH_IPH4_HDRLEN) + SSH_TCPH_HDRLEN;

  /* Allocate a dummy packet for flow id computation */
  pp = ssh_interceptor_packet_alloc(engine->interceptor,
                                    from_adapter ? 
				    SSH_PACKET_FROMADAPTER :
				    SSH_PACKET_FROMPROTOCOL,
				    is_ip6 ?
				    SSH_PROTOCOL_IP6 : SSH_PROTOCOL_IP4,
                                    SSH_INTERCEPTOR_INVALID_IFNUM,
				    SSH_INTERCEPTOR_INVALID_IFNUM,
                                    len);

  if (!pp)
    return FALSE;
  ucp = ssh_interceptor_packet_pullup(pp, len);
  if (!ucp)
    return FALSE;

  memset(ucp, 0, len);
#if (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0)
  memcpy(pp->extension, extension, sizeof(pp->extension));
#endif /* (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0) */

  if (is_ip6)
    {
      SSH_IPH6_SET_VERSION(ucp, 6);
      SSH_IPH6_SET_LEN(ucp, len - SSH_IPH6_HDRLEN);
      SSH_IPH6_SET_SRC(src, ucp);
      SSH_IPH6_SET_DST(dst, ucp);
      SSH_IPH6_SET_NH(ucp, ipproto);
      /* The ports are at the same offsets for TCP and UDP */
      SSH_TCPH_SET_SRCPORT(ucp + SSH_IPH6_HDRLEN, src_port);
      SSH_TCPH_SET_DSTPORT(ucp + SSH_IPH6_HDRLEN, dst_port);
    }
  else
    {
      SSH_IPH4_SET_VERSION(ucp, 4);
      SSH_IPH4_SET_HLEN(ucp, SSH_IPH4_HDRLEN / 4);
      SSH_IPH4_SET_LEN(ucp, len);
      SSH_IPH4_SET_SRC(src, ucp);
      SSH_IPH4_SET_DST(dst, ucp);
      SSH_IPH4_SET_PROTO(ucp, ipproto);
      /* The ports are at the same offsets for TCP and UDP */
      SSH_TCPH_SET_SRCPORT(ucp + SSH_IPH4_HDRLEN, src_port);
      SSH_TCPH_SET_DSTPORT(ucp + SSH_IPH4_HDRLEN, dst_port);
    }

  SSH_DUMP_PACKET(SSH_D_MY, ("Constructed packet for flow ID"), pp);
  
  pc = ssh_engine_alloc_pc(engine);
  if (pc == NULL)
    {
      ssh_interceptor_packet_free(pp);
      return FALSE;
    }      
  if (!ssh_engine_init_and_pullup_pc(pc, engine, pp, tunnel_id, 
				     SSH_IPSEC_INVALID_INDEX))
    {
      /* pp is already freed here */
      ssh_engine_free_pc(engine, pc);
      return FALSE;
    }

  is_ok = (*engine->flow_id_hash)(engine->fastpath, pc, pp, tunnel_id,
				  flow_id);
  
  ssh_engine_free_pc(engine, pc);

  if (is_ok)
    ssh_interceptor_packet_free(pp);
  return is_ok;
}

/* Computes a flow id for incoming traffic according to the given
   transform.  This determines the outermost SPI for such traffic, and
   generates a flow id that will match with such incoming traffic.
   The generated flow id will be stored in `flow_id'. */

Boolean ssh_engine_compute_transform_flowid(SshEngine engine,
					    SshEngineTransformData trd,
					    SshIpAddr own_addr,
					    SshUInt32 outer_tunnel_id,
					    Boolean use_old_spis,
					    unsigned char *flow_id)
{
  SshEnginePacketContext pc;
  SshInterceptorPacket pp;
  unsigned char *ucp;
  SshUInt32 transform, spi;
  SshUInt8 ipproto = 0;
  Boolean is_ip6, is_ok, spi_zero;
  size_t ofs, len; 

  ssh_kernel_mutex_assert_is_locked(engine->flow_control_table_lock);
  
  is_ip6 = SSH_IP_IS6(own_addr);
  len = is_ip6 ? SSH_IPH6_HDRLEN : SSH_IPH4_HDRLEN;
  spi_zero = FALSE;
  transform = trd->transform;

  if (transform & SSH_PM_IPSEC_AH)
    {
      ipproto = SSH_IPPROTO_AH;
      len += 12;
    }
  else if (transform & SSH_PM_IPSEC_ESP)
    {
      ipproto = SSH_IPPROTO_ESP;
      len += 8;
    }
#ifdef SSHDIST_L2TP
  else if (transform & SSH_PM_IPSEC_L2TP)
    {
      ipproto = SSH_IPPROTO_UDP;
      len += 8;
    }
#endif /* SSHDIST_L2TP */
  else 
    ssh_fatal("ssh_engine_compute_transform_flowid: bad tr 0x%08lx",
	      (unsigned long) transform);
  
#ifdef SSHDIST_IPSEC_NAT_TRAVERSAL
  if (transform & SSH_PM_IPSEC_NATT)
    {
      /* ipproto gets overwritten from the previous value as the NAT-T header
	 is the outermost header. */
      ipproto = SSH_IPPROTO_UDP;
      len += 8;
    }
#endif /* SSHDIST_IPSEC_NAT_TRAVERSAL */

  /* Allocate a dummy packet for flow id computation */
  pp = ssh_interceptor_packet_alloc(engine->interceptor,
				    SSH_PACKET_FROMADAPTER,
				    is_ip6 ?
				    SSH_PROTOCOL_IP6 : SSH_PROTOCOL_IP4,
                                    SSH_INTERCEPTOR_INVALID_IFNUM,
				    SSH_INTERCEPTOR_INVALID_IFNUM,
                                    len);

  if (!pp)
    return FALSE;
  ucp = ssh_interceptor_packet_pullup(pp, len);
  if (!ucp)
    return FALSE;
  memset(ucp, 0, len);

  if (is_ip6)
    {
      SSH_IPH6_SET_VERSION(ucp, 6);
      SSH_IPH6_SET_LEN(ucp, len - SSH_IPH6_HDRLEN);
      SSH_IPH6_SET_SRC(&trd->gw_addr, ucp);
      SSH_IPH6_SET_DST(own_addr, ucp);
      SSH_IPH6_SET_NH(ucp, ipproto);
      ofs = SSH_IPH6_HDRLEN;
    }
  else
    {
      SSH_IPH4_SET_VERSION(ucp, 4);
      SSH_IPH4_SET_HLEN(ucp, SSH_IPH4_HDRLEN / 4);
      SSH_IPH4_SET_LEN(ucp, len);
      SSH_IPH4_SET_SRC(&trd->gw_addr, ucp);
      SSH_IPH4_SET_DST(own_addr, ucp);
      SSH_IPH4_SET_PROTO(ucp, ipproto);
      ofs = SSH_IPH4_HDRLEN;
    }

  /* Set the SPI value that will appear in incoming packets. */
#ifdef SSHDIST_IPSEC_NAT_TRAVERSAL
  if (transform & SSH_PM_IPSEC_NATT)
    {
      SSH_UDPH_SET_SRCPORT(ucp + ofs, trd->remote_port);
      SSH_UDPH_SET_DSTPORT(ucp + ofs, trd->local_port);
      ofs += 8;

      /* Store also the SPI to the ESP header so we can multiplex different 
	 SAs between two hosts using NAT-T. */
      SSH_ASSERT((transform & SSH_PM_IPSEC_AH) == 0);
      SSH_ASSERT(transform & SSH_PM_IPSEC_ESP);
      
      spi = use_old_spis ? trd->old_spis[SSH_PME_SPI_ESP_IN] : 
	trd->spis[SSH_PME_SPI_ESP_IN];

      if (!spi)
	spi_zero = TRUE;
      
      SSH_PUT_32BIT(ucp + ofs + SSH_ESPH_OFS_SPI, spi);
    }
  else
#endif /* SSHDIST_IPSEC_NAT_TRAVERSAL */
    {
      if (transform & SSH_PM_IPSEC_AH)
        {
	  spi = use_old_spis ? trd->old_spis[SSH_PME_SPI_AH_IN] : 
	    trd->spis[SSH_PME_SPI_AH_IN];
      
	  if (!spi)
	    spi_zero = TRUE;
	  SSH_PUT_32BIT(ucp + ofs + SSH_AHH_OFS_SPI, spi);
        }
      else
        if (transform & SSH_PM_IPSEC_ESP)
          {
	    spi = use_old_spis ? trd->old_spis[SSH_PME_SPI_ESP_IN] : 
	      trd->spis[SSH_PME_SPI_ESP_IN];
	    
	    if (!spi)
	      spi_zero = TRUE;

	    SSH_PUT_32BIT(ucp + ofs + SSH_ESPH_OFS_SPI, spi);
          }
#ifdef SSHDIST_L2TP
        else
          if (transform & SSH_PM_IPSEC_L2TP)
            {
	      SSH_UDPH_SET_SRCPORT(ucp + ofs, trd->l2tp_remote_port);
	      SSH_UDPH_SET_DSTPORT(ucp + ofs, trd->l2tp_local_port);
	    }
#endif /* SSHDIST_L2TP */
          else
            ssh_fatal("ssh_engine_compute_transform_flowid: bad tr 0x%08lx",
		      (unsigned long) transform);
    }

  SSH_DUMP_PACKET(SSH_D_MY, ("Constructed packet for transform flow ID "
			     "computation"), pp);

  pc = ssh_engine_alloc_pc(engine);
  if (pc == NULL)
    {
      ssh_interceptor_packet_free(pp);
      return FALSE;
    }      
  if (!ssh_engine_init_and_pullup_pc(pc, engine, pp, outer_tunnel_id, 
				     SSH_IPSEC_INVALID_INDEX))
    {
      /* pp is already freed here */
      ssh_engine_free_pc(engine, pc);
      return FALSE;
    }

  if (spi_zero == TRUE)
    {
      /* No valid SPI is defined. Leave flow id as zero.  */
      memset(flow_id, 0, SSH_ENGINE_FLOW_ID_SIZE);
      is_ok = TRUE;
    }
  else
    {
      is_ok = (*engine->flow_id_hash)(engine->fastpath, pc, pp, 
				      outer_tunnel_id, flow_id);
    } 

  ssh_engine_free_pc(engine, pc);
  
  if (is_ok)
    ssh_interceptor_packet_free(pp);
  return is_ok;
}

/* The ssh_engine_flow_compute_flow_id_from_flow() function
   attempts to compute the flow id of a flow that corresponds
   to the current flow parameters. If 'is_forward' is TRUE, then
   the forward flow id is computed. If 'is_forward' is FALSE, then
   the reverse flow id is computed. The result is placed in the
   buffer 'flow_id'. If the engine state does not allow for
   computation of the flow id, then FALSE is returned. */
Boolean
ssh_engine_flow_compute_flow_id_from_flow(SshEngine engine,
                                          SshUInt32 flow_index,
					  SshEngineFlowData d_flow,
                                          Boolean is_forward,
                                          unsigned char *flow_id)
{
  SshEnginePacketContext pc;
  SshInterceptorPacket pp;
  unsigned char *ucp;
  SshEngineFlowControl c_flow;
  SshEngineTransformControl c_trd;
  SshEngineTransformData d_trd;
  SshEnginePolicyRule rule;
  Boolean forward_local, reverse_local, ret;
  SshIpAddr src_ip, dst_ip;
  SshUInt16 src_port, dst_port;
  unsigned char icmp_identifier[2] = {0};
  SshUInt32 tunnel_id;
  Boolean from_adapter;
  Boolean is_ip6, is_ok;
  size_t ofs, len; 
#ifndef SSH_IPSEC_IP_ONLY_INTERCEPTOR
  SshEngineNextHopData nh;
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */

  SSH_INTERCEPTOR_STACK_MARK();

  ssh_kernel_mutex_assert_is_locked(engine->flow_control_table_lock);

  SSH_ASSERT(flow_index != SSH_IPSEC_INVALID_INDEX);
  c_flow = SSH_ENGINE_GET_FLOW(engine, flow_index);
  SSH_ASSERT(c_flow != NULL);

  rule = SSH_ENGINE_GET_RULE(engine, c_flow->rule_index);
  SSH_ASSERT(rule != NULL);

  memset(flow_id, 0, SSH_ENGINE_FLOW_ID_SIZE);
  ret = TRUE;

  if (c_flow->control_flags & SSH_ENGINE_FLOW_C_IPSECINCOMING)
    {
      SshIpAddrStruct dst_ip_struct;

      if (d_flow->forward_transform_index != SSH_IPSEC_INVALID_INDEX)
        {
          c_trd = SSH_ENGINE_GET_TRD(engine,
				     d_flow->forward_transform_index);
          if (c_trd == NULL)
            {
              SSH_DEBUG(SSH_D_FAIL,
                        ("Unable to re-compute ipsec incoming "
                         "flow id: transform invalidated."));
              return FALSE;
            }
          d_trd = FASTPATH_GET_READ_ONLY_TRD(engine->fastpath,
					     d_flow->forward_transform_index);

          dst_ip_struct = d_trd->own_addr;

#ifdef SSHDIST_IPSEC_SCTP_MULTIHOME
          if (rule->flags & SSH_ENGINE_RULE_SCTP_MULTIHOME)
            {
              if (rule->protocol == SSH_PROTOCOL_IP4)
                SSH_IP_DECODE(&dst_ip_struct, rule->src_ip_low, 4);
              else
                SSH_IP_DECODE(&dst_ip_struct, rule->src_ip_low, 16);
            }
#endif /* SSHDIST_IPSEC_SCTP_MULTIHOME */

          /* If is_forward == FALSE compute flow-id for freshest SPI.
             If is_forward == TRUE compute flow-id for pre-rekey SPI. */
#ifdef SSH_IPSEC_MULTICAST
          /* For transforms having multicast gw IP, multicast gw IP 
           * should be used to calculate flow id. */
          if (SSH_IP_IS_MULTICAST(&(d_trd->gw_addr)))
	    {
	      SSH_DEBUG(SSH_D_LOWOK,
			("Transform has multicast peer IP, thus using"
			 " multicast peer IP for flow id calculations."));
	      ret = ssh_engine_compute_transform_flowid(engine, d_trd,
							&(d_trd->gw_addr),
							c_trd->outer_tunnel_id,
							is_forward, flow_id);
	    }
          else
#endif /* SSH_IPSEC_MULTICAST */
	    ret = ssh_engine_compute_transform_flowid(engine, d_trd, 
						      &dst_ip_struct,
						      c_trd->outer_tunnel_id,
						      is_forward, flow_id);
	  
	  FASTPATH_RELEASE_TRD(engine->fastpath,
			       d_flow->forward_transform_index);
        }
      return ret;
    }
  else
    {
      reverse_local = forward_local = FALSE;
#ifndef SSH_IPSEC_IP_ONLY_INTERCEPTOR
      if (d_flow->reverse_nh_index != SSH_IPSEC_INVALID_INDEX)
        {
          nh = FASTPATH_GET_NH(engine->fastpath, d_flow->reverse_nh_index);
          if (nh->flags & SSH_ENGINE_NH_LOCAL)
            reverse_local = TRUE;
          FASTPATH_RELEASE_NH(engine->fastpath, d_flow->reverse_nh_index);
        }

      if (d_flow->forward_nh_index != SSH_IPSEC_INVALID_INDEX)
        {
          nh = FASTPATH_GET_NH(engine->fastpath, d_flow->forward_nh_index);
          if (nh->flags & SSH_ENGINE_NH_LOCAL)
            forward_local = TRUE;
          FASTPATH_RELEASE_NH(engine->fastpath, d_flow->forward_nh_index);
        }
#else /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */
      forward_local = d_flow->forward_local;
      reverse_local = d_flow->reverse_local;
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */

      if (is_forward)
	from_adapter = reverse_local ? FALSE : TRUE;
      else
	from_adapter = forward_local ? FALSE : TRUE;

      tunnel_id = 0;
      if (is_forward == TRUE)
        {
          /* Only assume tunnels for non-"magic unroutable" endpoints.
             Using the rule->tunnel_id assures that we also get
             'magic' system internal tunnel id's correct. */
          if (c_flow->control_flags & SSH_ENGINE_FLOW_C_REROUTE_I)
            tunnel_id = rule->tunnel_id;
        }
      else if (c_flow->control_flags & SSH_ENGINE_FLOW_C_REROUTE_R)
        {
          /* is_forward == FALSE */
          if (d_flow->forward_transform_index != SSH_IPSEC_INVALID_INDEX)
            {
              c_trd = SSH_ENGINE_GET_TRD(engine,
					 d_flow->forward_transform_index);
              if (c_trd == NULL)
                {
                  SSH_DEBUG(SSH_D_FAIL,
                            ("Unable to resolve transform of flow"));
                  return FALSE;
                }
	      d_trd = 
		FASTPATH_GET_READ_ONLY_TRD(engine->fastpath,
					   d_flow->forward_transform_index);

              /* Note that this will work incorrectly, if
		 'magic' tunnel id 1 packets are involved. */
              tunnel_id = d_trd->inbound_tunnel_id;
	      FASTPATH_RELEASE_TRD(engine->fastpath,
				   d_flow->forward_transform_index);
	    }
        }

      /* Select and encode IP addresses and ports */
      if (is_forward)
        {
          src_port = d_flow->src_port;
          dst_port = d_flow->dst_port;
	  src_ip = &d_flow->src_ip;
	  dst_ip = &d_flow->dst_ip;
        }
      else
        {
#ifdef SSHDIST_IPSEC_NAT
	  src_ip = &d_flow->nat_dst_ip;
	  dst_ip = &d_flow->nat_src_ip;
          src_port = d_flow->nat_dst_port;
          dst_port = d_flow->nat_src_port;
#else /* SSHDIST_IPSEC_NAT */
	  src_ip = &d_flow->dst_ip;
	  dst_ip = &d_flow->src_ip;
          src_port = d_flow->dst_port;
          dst_port = d_flow->src_port;
#endif /* SSHDIST_IPSEC_NAT */
        }

      if (SSH_IP_IS6(src_ip) || SSH_IP_IS6(dst_ip))
	is_ip6 = TRUE;
      else
	is_ip6 = FALSE;

      /* For ICMP flows extract the Identifier from the flow */
      if (d_flow->ipproto == SSH_IPPROTO_ICMP
          || d_flow->ipproto == SSH_IPPROTO_IPV6ICMP)
        {
#ifdef SSHDIST_IPSEC_NAT
          /* ICMP identifier is stored in nat_src */
          if (is_forward)
            {
              icmp_identifier[0] = (d_flow->src_port >> 8) & 0xff;
              icmp_identifier[1] = (d_flow->src_port & 0xff);
            }
          else
            {
              icmp_identifier[0] = (d_flow->nat_src_port >> 8) & 0xff;
              icmp_identifier[1] = (d_flow->nat_src_port & 0xff);

            }
#else /* SSHDIST_IPSEC_NAT */
          icmp_identifier[0] = (d_flow->src_port >> 8) & 0xff;
          icmp_identifier[1] = (d_flow->src_port & 0xff);
#endif /* SSHDIST_IPSEC_NAT */
	}

      /* Allocate 20 bytes to contain the upper layer protocol headers.
	 The maximum required is for TCP packets. */
      len = (is_ip6 ? SSH_IPH6_HDRLEN : SSH_IPH4_HDRLEN) + SSH_TCPH_HDRLEN;

      /* Allocate a dummy packet for flow id computation */
      pp = ssh_interceptor_packet_alloc(engine->interceptor,
					from_adapter ? 
					SSH_PACKET_FROMADAPTER :
					SSH_PACKET_FROMPROTOCOL,
					is_ip6 ?
					SSH_PROTOCOL_IP6 : SSH_PROTOCOL_IP4,
					SSH_INTERCEPTOR_INVALID_IFNUM,
					SSH_INTERCEPTOR_INVALID_IFNUM,
					len);
      
      if (!pp)
	return FALSE;
      ucp = ssh_interceptor_packet_pullup(pp, len);
      if (!ucp)
	return FALSE;
      memset(ucp, 0, len);

      if (is_ip6)
	{
	  SSH_IPH6_SET_VERSION(ucp, 6);
	  SSH_IPH6_SET_LEN(ucp, len - SSH_IPH6_HDRLEN);
	  SSH_IPH6_SET_SRC(src_ip, ucp);
	  SSH_IPH6_SET_DST(dst_ip, ucp);
	  SSH_IPH6_SET_NH(ucp, d_flow->ipproto);
	  ofs = SSH_IPH6_HDRLEN;
	}
      else
	{
	  SSH_IPH4_SET_VERSION(ucp, 4);
	  SSH_IPH4_SET_HLEN(ucp, SSH_IPH4_HDRLEN / 4);
	  SSH_IPH4_SET_LEN(ucp, len);
	  SSH_IPH4_SET_SRC(src_ip, ucp);
	  SSH_IPH4_SET_DST(dst_ip, ucp);
	  SSH_IPH4_SET_PROTO(ucp, d_flow->ipproto);
	  ofs = SSH_IPH4_HDRLEN;
	}

      switch (d_flow->ipproto)
	{
	case SSH_IPPROTO_TCP:
	  SSH_TCPH_SET_SRCPORT(ucp + ofs, src_port);
	  SSH_TCPH_SET_DSTPORT(ucp + ofs, dst_port);
	  break;
      
	case SSH_IPPROTO_UDP:
	case SSH_IPPROTO_UDPLITE:
	  SSH_UDPH_SET_SRCPORT(ucp + ofs, src_port);
	  SSH_UDPH_SET_DSTPORT(ucp + ofs, dst_port);

	  /* For DHCP flows set the Transaction ID from protocol_xid . */
          if (dst_port == 67 || dst_port == 68 || dst_port == 546 || 
              dst_port == 547)
	    SSH_PUT_32BIT(ucp + ofs + 12, d_flow->protocol_xid);
	  break;
      
	case SSH_IPPROTO_SCTP:
	  SSH_SCTPH_SET_SRCPORT(ucp + ofs, src_port);
	  SSH_SCTPH_SET_DSTPORT(ucp + ofs, dst_port);
	  break;
      
	case SSH_IPPROTO_ICMP:
	  SSH_ICMPH_SET_TYPE(ucp + ofs, (d_flow->dst_port >> 8));
	  SSH_ICMPH_SET_CODE(ucp + ofs, (d_flow->dst_port & 0xff));

	  ofs += 4;
	  SSH_PUT_8BIT(ucp + ofs, icmp_identifier[0]);
	  SSH_PUT_8BIT(ucp + ofs + 1, icmp_identifier[1]);
	  break;

	case SSH_IPPROTO_IPV6ICMP:
	  SSH_ICMP6H_SET_TYPE(ucp + ofs, (d_flow->dst_port >> 8));
	  SSH_ICMP6H_SET_CODE(ucp + ofs, (d_flow->dst_port & 0xff));

	  ofs += 4;
	  SSH_PUT_8BIT(ucp + ofs, icmp_identifier[0]);
	  SSH_PUT_8BIT(ucp + ofs + 1, icmp_identifier[1]);
	  break;
      
	case SSH_IPPROTO_ESP:
	  SSH_PUT_32BIT(ucp + ofs + SSH_ESPH_OFS_SPI, d_flow->protocol_xid);
	  break;

	case SSH_IPPROTO_AH:
	  SSH_PUT_32BIT(ucp + ofs + SSH_AHH_OFS_SPI, d_flow->protocol_xid);
	  break;
	}

#if (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0)
      memcpy(pp->extension, d_flow->extension, sizeof(pp->extension));
#endif /* (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0) */
      
      SSH_DUMP_PACKET(SSH_D_MY, ("Constructed packet for flow ID from flow "
				 "computation"), pp);

      pc = ssh_engine_alloc_pc(engine);
      if (pc == NULL)
	{
	  ssh_interceptor_packet_free(pp);
	  return FALSE;
	}      
      if (!ssh_engine_init_and_pullup_pc(pc, engine, pp, tunnel_id, 
					 SSH_IPSEC_INVALID_INDEX))
	{
	  /* pp is already freed here */
	  ssh_engine_free_pc(engine, pc);
	  return FALSE;
	}

      /* If this is not an incoming IPsec flow then clear the PC_IS_IPSEC 
	 flag of pc. This is required for correct flow id computation of 
	 IPsec packets which should not be decapsulated by this implemetation
	 (i.e. IPsec packets not directed to this host or directed to a 
	 coexisting IPsec stack on this host.) */
      if (!(c_flow->control_flags & SSH_ENGINE_FLOW_C_IPSECINCOMING))
	pc->flags &= ~SSH_ENGINE_PC_IS_IPSEC;      
      
      is_ok = (*engine->flow_id_hash)(engine->fastpath, pc, pp, tunnel_id, 
				      flow_id);
      
      ssh_engine_free_pc(engine, pc);

      if (is_ok)
	ssh_interceptor_packet_free(pp);
      return is_ok;
    }
}


SshInterceptorPacket 
ssh_engine_icmp_get_inner_packet(SshEngine engine, SshInterceptorPacket pp)
     
{
  SshEnginePacketContext pc;
  SshInterceptorPacket pp_ret;
  size_t ip_len;
  size_t inner_hdrlen, len, ofs;
  unsigned char *ucp;
  SshIpAddrStruct src, dst;
  SshUInt16 src_port = 0, dst_port = 0;
  unsigned char icmp_identifier[2] = {0};
  SshUInt32 spi = 0;
  SshInetIPProtocolID ipproto = 0;
  SshUInt8 icmp_type = 0, icmp_code = 0;
  Boolean is_ipv6, from_adapter;
  int i;
  
  pc = ssh_engine_alloc_pc(engine);
  if (pc == NULL)
    {
      ssh_interceptor_packet_free(pp);
      return FALSE;
    }      

  if (!ssh_engine_init_and_pullup_pc(pc, engine, pp, 0, 
				     SSH_IPSEC_INVALID_INDEX))
    goto drop;

  if (pc->ipproto != SSH_IPPROTO_ICMP 
#if defined (WITH_IPV6)
      && pc->ipproto != SSH_IPPROTO_IPV6ICMP
#endif /* WITH_IPV6 */
      )
    {
      SSH_DEBUG(SSH_D_FAIL, ("Packet not ICMP, dropping"));
      goto drop;
    }

  ip_len = pc->packet_len;

  /* Process the ICMP according to its type. */  
  if (pc->ipproto == SSH_IPPROTO_ICMP)
    {
      unsigned char buf[8 + SSH_IPH4_MAX_HEADER_LEN];

      if (pc->icmp_type != SSH_ICMP_TYPE_UNREACH &&
	  pc->icmp_type != SSH_ICMP_TYPE_SOURCEQUENCH &&
	  pc->icmp_type != SSH_ICMP_TYPE_TIMXCEED &&
	  pc->icmp_type != SSH_ICMP_TYPE_PARAMPROB)
	{
	  SSH_DEBUG(SSH_D_FAIL, 
		    ("Packet not an ICMP error message, dropping"));
	  goto drop;
	}

      /* Check for truncated ICMPv4 packet. Must have at least
	 IPv4 header inside. */
      if (ip_len < pc->hdrlen + 8 + SSH_IPH4_HDRLEN)
	{
	  SSH_DEBUG(SSH_D_NETGARB, ("ICMP; truncated error"));
	  goto drop;
	}
      
      /* Copy out the offending IPv4 header without options to
	 check for header length and inner protocol. */
      ssh_interceptor_packet_copyout(pc->pp,
				     pc->hdrlen + 8,
				     buf,
				     SSH_IPH4_HDRLEN);
      
      /* Get and check the inner IPv4 header length. Needs to be
	 at least std header and not beyond packet boundary. */
      inner_hdrlen = 4 * SSH_IPH4_HLEN(buf);
      if (inner_hdrlen < SSH_IPH4_HDRLEN
	  || ip_len < pc->hdrlen + 8 + inner_hdrlen)
	{
	  SSH_DEBUG(SSH_D_NETGARB, ("ICMP; Bad offending header"));
	  goto drop;
	}
      
      /* Take src,dst IP, ipproto.  Note that the ICMP packet is
	 going in the direction OPPOSITE to the original packet,
	 and will get routed to the SOURCE of the original packet.
	 Consequently, normal and reverse directions must be
	 REVERSED for ICMP errors to get correct routing
	 information for the packets. */
      SSH_IP_DECODE(&src, buf + SSH_IPH4_OFS_DST, 4); 
      SSH_IP_DECODE(&dst, buf + SSH_IPH4_OFS_SRC, 4); 
      ipproto = SSH_IPH4_PROTO(buf);
      





      if (ipproto == SSH_IPPROTO_ICMP
	  || ipproto == SSH_IPPROTO_UDP
	  || ipproto == SSH_IPPROTO_UDPLITE
	  || ipproto == SSH_IPPROTO_TCP
	  || ipproto == SSH_IPPROTO_SCTP)
	{
	  /* A. We should have more data (rest of ip hdr + ports) */
	  if (ip_len < pc->hdrlen + 8 + inner_hdrlen + 8)
	    {
	      SSH_DEBUG(SSH_D_NETGARB,
			("ICMP; missing offending payload data"));
	      goto drop;
	    }
	  
	  SSH_ASSERT(inner_hdrlen >= SSH_IPH4_HDRLEN);
	  
	  /* Copy from the remaining data (from end of offending ipv4
	     header, the options and 8 octets) to buf */
	  ssh_interceptor_packet_copyout(pc->pp,
					 (pc->hdrlen + 8)
					 + SSH_IPH4_HDRLEN,
					 buf + SSH_IPH4_HDRLEN,
					 (inner_hdrlen - SSH_IPH4_HDRLEN)
					 + 8);
	  
	  /* Then take src,dst port from original (inner) packet that
	     triggered the ICMP. */
	  switch (ipproto)
	    {
	    case SSH_IPPROTO_TCP:
	      src_port = SSH_TCPH_DSTPORT(buf + inner_hdrlen);
	      dst_port = SSH_TCPH_SRCPORT(buf + inner_hdrlen);
	      break;
	    case SSH_IPPROTO_UDP:
	    case SSH_IPPROTO_UDPLITE:
	      src_port = SSH_UDPH_DSTPORT(buf + inner_hdrlen);
	      dst_port = SSH_UDPH_SRCPORT(buf + inner_hdrlen);
	      break;
	    case SSH_IPPROTO_SCTP:
	      src_port = SSH_SCTPH_DSTPORT(buf + inner_hdrlen);
	      dst_port = SSH_SCTPH_SRCPORT(buf + inner_hdrlen);
	      break;
	    case SSH_IPPROTO_ICMP:
	      icmp_type = SSH_ICMPH_TYPE(buf + inner_hdrlen);
	      icmp_code = SSH_ICMPH_CODE(buf + inner_hdrlen);
	      
	      if (icmp_type == SSH_ICMP_TYPE_ECHO ||
		  icmp_type == SSH_ICMP_TYPE_ECHOREPLY)
		memcpy(icmp_identifier, buf + inner_hdrlen + 4, 2);
	      break;
	    default:
	      SSH_NOTREACHED;
	      goto drop;
	    }
	}
    }
#if defined (WITH_IPV6)
  else if (pc->ipproto == SSH_IPPROTO_IPV6ICMP)
    {
      unsigned char buf[SSH_IPH6_HDRLEN];
      unsigned char src_buf[16];
      SshUInt32 offset, x, ext_hdr_len;

      if (pc->icmp_type != SSH_ICMP6_TYPE_UNREACH &&
	  pc->icmp_type != SSH_ICMP6_TYPE_TOOBIG &&
	  pc->icmp_type != SSH_ICMP6_TYPE_TIMXCEED &&
	  pc->icmp_type != SSH_ICMP6_TYPE_PARAMPROB)
	{
	  SSH_DEBUG(SSH_D_FAIL, 
		    ("Packet not an ICMP error message, dropping"));
	  goto drop;
	}
      
      offset = pc->hdrlen + 8;
      if (offset + SSH_IPH6_HDRLEN >= ip_len)
	goto drop;
      ssh_interceptor_packet_copyout(pp, offset, buf, SSH_IPH6_HDRLEN);
      /* See comments for the IPv4 case for the logic behind
	 these. */
      SSH_IP_DECODE(&dst, buf + SSH_IPH6_OFS_SRC, 16);
      SSH_IP_DECODE(&src, buf + SSH_IPH6_OFS_DST, 16);
      
      ipproto = SSH_IPH6_NH(buf);
      offset += SSH_IPH6_HDRLEN;

      /* The following part iterates through extension headers
	 to find out ipproto and possibly port numbers.  If the
	 packet is too short to contain the offending packet's
	 payload so that it can be meaningfully parsed, then
	 drop the packet. */
    next_header:
      switch (ipproto)
	{
	case 0:           /* Hop-by-hop header. */
	  if (offset + SSH_IP6_EXT_HOP_BY_HOP_HDRLEN >= ip_len)
	    goto drop;
	  ssh_interceptor_packet_copyout(pp, offset, buf, 2);
	  ipproto = SSH_IP6_EXT_COMMON_NH(buf);
	  offset += SSH_IP6_EXT_COMMON_LENB(buf);
	  goto next_header;
	  break;
	  
	case SSH_IPPROTO_IPV6ROUTE: /* Routing header. */
	  if (offset + SSH_IP6_EXT_ROUTING_HDRLEN >= ip_len)
	    goto drop;
	  ssh_interceptor_packet_copyout(pc->pp, offset, buf,
					 SSH_IP6_EXT_ROUTING_HDRLEN);
	  if (SSH_IP6_EXT_ROUTING_TYPE(buf) != 0)
	    goto drop;
	  ipproto = SSH_IP6_EXT_ROUTING_NH(buf);
	  x = SSH_IP6_EXT_ROUTING_LEN(buf);
	  if (x & 0x1)
	    goto drop;
	  ext_hdr_len = 8 + 8 * x;
	  if (x != 0)
	    {
	      SshUInt32 n_addrs = x >> 1;
	      SshUInt32 n_segs = SSH_IP6_EXT_ROUTING_SEGMENTS(buf);

	      if (n_segs > n_addrs)
		goto drop;

	      if (offset + 8 + n_addrs * 16 > ip_len)
		goto drop;
	      ssh_interceptor_packet_copyout(pp,
					     offset + n_addrs * 16 - 8,
					     src_buf, 16);
	      SSH_IP_DECODE(&src, src_buf, 16);
	    }
	  offset += ext_hdr_len;
	  goto next_header;
	  break;

	case SSH_IPPROTO_IPV6OPTS: /* Destination options header. */
	  if (offset + SSH_IP6_EXT_DSTOPTS_HDRLEN > ip_len)
	    goto drop;
	  ssh_interceptor_packet_copyout(pc->pp, offset, buf, 2);
	  offset += SSH_IP6_EXT_DSTOPTS_LENB(buf);
	  ipproto = SSH_IP6_EXT_DSTOPTS_NH(buf);
	  goto next_header;
	  break;

	case SSH_IPPROTO_IPV6FRAG: /* Fragment header. */
	  if (offset + SSH_IP6_EXT_FRAGMENT_HDRLEN > ip_len)
	    goto drop;
	  ssh_interceptor_packet_copyout(pc->pp, offset, buf,
					 SSH_IP6_EXT_FRAGMENT_HDRLEN);
	  if (SSH_IP6_EXT_FRAGMENT_OFFSET(buf) != 0)
	    /* Drop non-first fragments, since we can't find their
	       flow since we don't know their ipproto and ports. */
	    goto drop;
	  offset += SSH_IP6_EXT_FRAGMENT_HDRLEN;
	  ipproto = SSH_IP6_EXT_FRAGMENT_NH(buf);
	  goto next_header;
	  break;

	  /* Dig out the port numbers of TCP, UDP and SCTP
	     packets. */
	case SSH_IPPROTO_TCP:
	  if (offset + SSH_TCPH_HDRLEN > ip_len)
	    goto drop;
	  ssh_interceptor_packet_copyout(pc->pp, offset, buf,
					 SSH_TCPH_HDRLEN);
             
	  src_port = SSH_TCPH_DSTPORT(buf);
	  dst_port = SSH_TCPH_SRCPORT(buf);
	  break;
		
	case SSH_IPPROTO_UDP:
	case SSH_IPPROTO_UDPLITE:
	  if (offset + SSH_UDPH_HDRLEN > ip_len)
	    goto drop;
	  ssh_interceptor_packet_copyout(pc->pp, offset, buf,
					 SSH_UDPH_HDRLEN);

	  src_port = SSH_UDPH_DSTPORT(buf);
	  dst_port = SSH_UDPH_SRCPORT(buf);
	  break;

	case SSH_IPPROTO_SCTP:
	  if (offset + SSH_SCTPH_HDRLEN > ip_len)
	    goto drop;
	  ssh_interceptor_packet_copyout(pc->pp, offset, buf,
					 SSH_SCTPH_HDRLEN);

	  dst_port = SSH_SCTPH_SRCPORT(buf);
	  src_port = SSH_SCTPH_DSTPORT(buf);
	  break;

	  /* Dig out the SPI from AH and ESP headers. */
	case SSH_IPPROTO_AH:
	  if (offset + SSH_AHH_OFS_SPI + 4 > ip_len)
	    goto drop;
	  ssh_interceptor_packet_copyout(pc->pp, 
					 offset + SSH_AHH_OFS_SPI,
					 buf, 4);
	  spi = SSH_GET_32BIT(buf);
	  break;

	case SSH_IPPROTO_ESP:
	  if (offset + SSH_ESPH_OFS_SPI + 4 > ip_len)
	    goto drop;
	  ssh_interceptor_packet_copyout(pc->pp, 
					 offset + SSH_ESPH_OFS_SPI,
					 buf, 4);
	  spi = SSH_GET_32BIT(buf);
	  break;

	case SSH_IPPROTO_IPV6ICMP:
	  /* Dig out the ICMP identifier code from ICMP echo and
	     reply packets. */
	  if (offset + 4 > ip_len)
	    goto drop;
	  ssh_interceptor_packet_copyout(pc->pp, offset, buf, 4);
	  icmp_type = SSH_ICMP6H_TYPE(buf);
	  icmp_code = SSH_ICMP6H_CODE(buf);
	  
	  if (icmp_type == SSH_ICMP6_TYPE_ECHOREQUEST ||
	      icmp_type == SSH_ICMP6_TYPE_ECHOREPLY)
	    {
	      /* Take identification and IP addresses. */
	      if (offset + 8 > ip_len)
		goto drop;
	      ssh_interceptor_packet_copyout(pc->pp, offset + 4,
					     icmp_identifier, 2);
	    }
	  break;

	default:
	  break;
	}
    }
#endif /* WITH_IPV6 */
  else
    {
      SSH_NOTREACHED;
      goto drop;
    }

  is_ipv6 = SSH_IP_IS6(&src);

  /* Allocate 20 bytes to contain the upper layer protocol headers.
     The maximum required is for TCP packets. */
  len = (is_ipv6 ? SSH_IPH6_HDRLEN : SSH_IPH4_HDRLEN) + SSH_TCPH_HDRLEN;

  from_adapter = (pc->pp->flags & SSH_PACKET_FROMADAPTER) ? TRUE : FALSE;

  /* Allocate a dummy packet for flow id computation */
  pp_ret = ssh_interceptor_packet_alloc(pc->engine->interceptor,
					from_adapter ? 
					SSH_PACKET_FROMADAPTER :
					SSH_PACKET_FROMPROTOCOL,
					is_ipv6 ?
					SSH_PROTOCOL_IP6 : SSH_PROTOCOL_IP4,
					SSH_INTERCEPTOR_INVALID_IFNUM,
					SSH_INTERCEPTOR_INVALID_IFNUM,
					len);
  
  if (!pp_ret)
    goto drop;

  ucp = ssh_interceptor_packet_pullup(pp_ret, len);
  if (!ucp)
    goto drop;
  memset(ucp, 0, len);

#if (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0)
  for (i = 0; i < SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS; i++)
    pp_ret->extension[i] = pp->extension[i];
#endif /* SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0 */

  if (is_ipv6)
    {
      SSH_IPH6_SET_VERSION(ucp, 6);
      SSH_IPH6_SET_LEN(ucp, len - SSH_IPH6_HDRLEN);
      SSH_IPH6_SET_SRC(&src, ucp);
      SSH_IPH6_SET_DST(&dst, ucp);
      SSH_IPH6_SET_NH(ucp, ipproto);
      ofs = SSH_IPH6_HDRLEN;
    }
  else
    {
      SSH_IPH4_SET_VERSION(ucp, 4);
      SSH_IPH4_SET_HLEN(ucp, SSH_IPH4_HDRLEN / 4);
      SSH_IPH4_SET_LEN(ucp, len);
      SSH_IPH4_SET_SRC(&src, ucp);
      SSH_IPH4_SET_DST(&dst, ucp);
      SSH_IPH4_SET_PROTO(ucp, ipproto);
      ofs = SSH_IPH4_HDRLEN;
    }
 
  switch (ipproto)
    {
    case SSH_IPPROTO_TCP:
      SSH_TCPH_SET_SRCPORT(ucp + ofs, src_port);
      SSH_TCPH_SET_DSTPORT(ucp + ofs, dst_port);
      break;
     
    case SSH_IPPROTO_UDP:
    case SSH_IPPROTO_UDPLITE:
      SSH_UDPH_SET_SRCPORT(ucp + ofs, src_port);
      SSH_UDPH_SET_DSTPORT(ucp + ofs, dst_port);
      break;
     
    case SSH_IPPROTO_SCTP:
      SSH_SCTPH_SET_SRCPORT(ucp + ofs, src_port);
      SSH_SCTPH_SET_DSTPORT(ucp + ofs, dst_port);
      break;
     
    case SSH_IPPROTO_ICMP:
      SSH_ICMPH_SET_TYPE(ucp + ofs, icmp_type);
      SSH_ICMPH_SET_CODE(ucp + ofs, icmp_code);
     
      ofs += 4;
      SSH_PUT_8BIT(ucp + ofs, icmp_identifier[0]);
      SSH_PUT_8BIT(ucp + ofs + 1, icmp_identifier[1]);
      break;

    case SSH_IPPROTO_IPV6ICMP:
      SSH_ICMP6H_SET_TYPE(ucp + ofs, icmp_type);
      SSH_ICMP6H_SET_CODE(ucp + ofs, icmp_code);

      ofs += 4;
      SSH_PUT_8BIT(ucp + ofs, icmp_identifier[0]);
      SSH_PUT_8BIT(ucp + ofs + 1, icmp_identifier[1]);
      break;
     
    case SSH_IPPROTO_ESP:
      SSH_PUT_32BIT(ucp + ofs + SSH_ESPH_OFS_SPI, spi);
      break;
     
    case SSH_IPPROTO_AH:
      SSH_PUT_32BIT(ucp + ofs + SSH_AHH_OFS_SPI, spi);
      break;

    default:
      break;
    }

  SSH_DUMP_PACKET(SSH_D_MY, ("original ICMP error packet"), pp);

  SSH_DUMP_PACKET(SSH_D_MY, ("Constructed inner packet"), pp_ret);
 
  ssh_engine_free_pc(engine, pc);
  return pp_ret;
 
 drop:
  SSH_DEBUG(SSH_D_FAIL, ("Could not construct inner packet from purported "
			 "ICMP error message"));
  if (pc->pp)
    ssh_interceptor_packet_free(pc->pp);
  pc->pp = NULL;
  ssh_engine_free_pc(engine, pc);
  return NULL;
}     

