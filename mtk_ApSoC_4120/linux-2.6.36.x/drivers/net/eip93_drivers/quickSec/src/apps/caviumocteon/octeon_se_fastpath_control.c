/*
  octeon_se_fastpath.c

  Copyright:
           Copyright (c) 2008 SFNT Finland Oy.
     All rights reserved.

  Description:
     Control tool for Cavium Octeon Simple Executive fastpath.
*/

#include "stdio.h"
#include "stdlib.h"
#include "string.h"
#include "octeon_se_fastpath_control_internal.h"
#include "cvmx-sysinfo.h"

/** Sends enable/disable/stop command to SE fastpath. This should never be
    called when quicksec.ko is loaded in to the kernel. */
static int
octeon_se_fastpath_control_send_cmd(uint8_t command)
{
  cvmx_wqe_t *wqe;
  SeFastpathControlCmd cmd;

  wqe = cvmx_fpa_alloc(CVMX_FPA_WQE_POOL);
  if (wqe == NULL)
    return -1;

  memset(wqe, 0, sizeof(*wqe));
  wqe->grp = OCTEON_SE_FASTPATH_CONTROL_GROUP;

  cmd = (SeFastpathControlCmd) wqe->packet_data;
  cmd->cmd = command;

  cvmx_pow_work_submit(wqe, 0, CVMX_POW_TAG_TYPE_ATOMIC, 0, 
		       OCTEON_SE_FASTPATH_CONTROL_GROUP);

  return 0;
}

/** Set MAC address for port and configure port to receive only frames to
    configured MAC address, to MAC broadcast and to any MAC multicast. This
    should never be called when cavium-ethernet.ko is loaded in to the kernel.
*/
static int
octeon_se_fastpath_control_set_mac(int iface, int index, uint64_t mac)
{
  cvmx_gmxx_prtx_cfg_t gmx_port_cfg;
  cvmx_gmxx_rxx_adr_cam_en_t gmx_cam_cfg; 
  cvmx_gmxx_rxx_adr_ctl_t gmx_ctrl_cfg;

  /* Disable link */
  gmx_port_cfg.u64 = cvmx_read_csr(CVMX_GMXX_PRTX_CFG(index, iface));  
  gmx_port_cfg.s.en = 0;
  cvmx_write_csr(CVMX_GMXX_PRTX_CFG(index, iface), gmx_port_cfg.u64);

  /* Set MAC for ethernet PAUSE frames */
  cvmx_write_csr(CVMX_GMXX_SMACX(index, iface), mac);

  /* Write MAC to CAM table */
  cvmx_write_csr(CVMX_GMXX_RXX_ADR_CAM0(index, iface), (mac >> 40) & 0xff);
  cvmx_write_csr(CVMX_GMXX_RXX_ADR_CAM1(index, iface), (mac >> 32) & 0xff);
  cvmx_write_csr(CVMX_GMXX_RXX_ADR_CAM2(index, iface), (mac >> 24) & 0xff);
  cvmx_write_csr(CVMX_GMXX_RXX_ADR_CAM3(index, iface), (mac >> 16) & 0xff);
  cvmx_write_csr(CVMX_GMXX_RXX_ADR_CAM4(index, iface), (mac >> 8) & 0xff);
  cvmx_write_csr(CVMX_GMXX_RXX_ADR_CAM5(index, iface), (mac) & 0xff);

  /* Configure CAM mode */
  gmx_ctrl_cfg.u64 = 0;
  gmx_ctrl_cfg.s.cam_mode = 1; /* accept the packet on DMAC address match */
  gmx_ctrl_cfg.s.mcst = 2; /* 2 = Force accept all multicast packets */
  gmx_ctrl_cfg.s.bcst = 1; /* Accept All Broadcast Packets */
  cvmx_write_csr(CVMX_GMXX_RXX_ADR_CTL(index, iface), gmx_ctrl_cfg.u64);

  /* Enable CAM filter */
  gmx_cam_cfg.u64 = 0;
  gmx_cam_cfg.s.en = 1;
  cvmx_write_csr(CVMX_GMXX_RXX_ADR_CAM_EN(index, iface), gmx_cam_cfg.u64);

  /* Enable link */
  gmx_port_cfg.s.en = 1;
  cvmx_write_csr(CVMX_GMXX_PRTX_CFG(index, iface), gmx_port_cfg.u64);

  return 0;
}

/** Performs global hw initialization. This should never be called if 
    cavium-ethernet.ko is loaded in to the kernel. */
static int
octeon_se_fastpath_control_init_hw(uint64_t mac_base)
{
  extern CVMX_SHARED __cvmx_cmd_queue_all_state_t *__cvmx_cmd_queue_state_ptr;
  int result;
  int i, j;
  cvmx_pip_port_cfg_t port_cfg;
  cvmx_pip_port_tag_cfg_t port_tag_cfg;
  int num_interfaces, num_ports, port;
  uint64_t mac;




  result = cvmx_helper_initialize_fpa(1000, 1000,
                                      CVMX_PKO_MAX_OUTPUT_QUEUES * 4, 0, 0);
  if (result != 0)
    return result;

  result = cvmx_helper_initialize_packet_io_global();
  if (result != 0)
    return result;

  result = cvmx_helper_initialize_packet_io_local();
  if (result != 0)
    return result;  

  /* Initialize ports */
  num_interfaces = cvmx_helper_get_number_of_interfaces();
  for (i = 0; i < num_interfaces; i++)
    {
      num_ports = cvmx_helper_ports_on_interface(i);
      for (j = 0; j < num_ports; j++)
	{
	  port = cvmx_helper_get_ipd_port(i, j);
	  if (port >= 0)
	    {
	      /* Configure MAC address */
	      mac = (mac_base & 0x0000ffffffffff00) | port;
	      
	      if (octeon_se_fastpath_control_set_mac(i, j, mac))
		{
		  fprintf(stderr, "Could not set MAC address for port %d\n",
			  port);
		}
	      else
		{
		  fprintf(stderr, 
			  "Port %d MAC %02x:%02x:%02x:%02x:%02x:%02x\n",
			  port, 
			  (uint8_t) ((mac >> 40) & 0xff), 
			  (uint8_t) ((mac >> 32) & 0xff), 
			  (uint8_t) ((mac >> 24) & 0xff), 
			  (uint8_t) ((mac >> 16) & 0xff), 
			  (uint8_t) ((mac >> 8) & 0xff), 
			  (uint8_t) ((mac) & 0xff));
		}
		
	      /* Configure recv mode and recv pow group and pi ptag. */

	      port_cfg.u64 = cvmx_read_csr(CVMX_PIP_PRT_CFGX(port));
	      port_cfg.s.mode = CVMX_PIP_PORT_CFG_MODE_SKIPL2;	      
	      
	      port_tag_cfg.u64 = cvmx_read_csr(CVMX_PIP_PRT_TAGX(port));
	      port_tag_cfg.s.grp = OCTEON_SE_FASTPATH_PKT_GROUP;
	      port_tag_cfg.s.ip6_src_flag  = 1;
	      port_tag_cfg.s.ip6_dst_flag  = 1;
	      port_tag_cfg.s.ip6_sprt_flag = 1;
	      port_tag_cfg.s.ip6_dprt_flag = 1;
	      port_tag_cfg.s.ip6_nxth_flag = 1;
	      port_tag_cfg.s.ip4_src_flag  = 1;
	      port_tag_cfg.s.ip4_dst_flag  = 1;
	      port_tag_cfg.s.ip4_sprt_flag = 1;
	      port_tag_cfg.s.ip4_dprt_flag = 1;
	      port_tag_cfg.s.ip4_pctl_flag = 1;
	      port_tag_cfg.s.inc_prt_flag  = 1;
	      port_tag_cfg.s.tcp6_tag_type = CVMX_POW_TAG_TYPE_ORDERED;
	      port_tag_cfg.s.tcp4_tag_type = CVMX_POW_TAG_TYPE_ORDERED;
	      port_tag_cfg.s.ip6_tag_type = CVMX_POW_TAG_TYPE_ORDERED;
	      port_tag_cfg.s.ip4_tag_type = CVMX_POW_TAG_TYPE_ORDERED;
	      port_tag_cfg.s.non_tag_type = CVMX_POW_TAG_TYPE_ORDERED;
	      
	      cvmx_pip_config_port(port, port_cfg, port_tag_cfg);
	    }
	}
    }

  /* Receive only slowpath packets on this core. */
  cvmx_pow_set_group_mask(cvmx_get_core_num(),
			  (1 << OCTEON_SE_FASTPATH_SLOWPATH_GROUP));

  return result;
}

/** Returns pointer to shared fastpath object. This can be called when
    quicksec.ko is loaded in to the kernel. */
static SeFastpath
octeon_se_fastpath_control_get_fastpath()
{
  cvmx_bootmem_named_block_desc_t *bootmem_block;
  
  /* Fetch shared fastpath object from shared memory. */
  bootmem_block =
    cvmx_bootmem_find_named_block(OCTEON_SE_FASTPATH_BOOTMEM_BLOCK);
  if (bootmem_block == NULL)
    goto error;

  if (bootmem_block->size < sizeof(SeFastpathStruct))
    goto error;
  
  return (SeFastpath) cvmx_phys_to_ptr(bootmem_block->base_addr);

 error:
  fprintf(stderr, "Cannot access SE fastpath\n");
  return NULL;
}

/** Initializes shared SE fastpath object. This should never be used when
    quicksec.ko is loaded in to the kernel. */
static int
octeon_se_fastpath_control_init_fastpath()
{
  SeFastpath fastpath;
  uint32_t i, j;
  SeFastpathFlowData se_flow;
  SeFastpathTransformData se_trd;
  SeFastpathNextHopData se_nh;

  /* Allocate named memory block from shared memory. */
  fastpath = cvmx_bootmem_alloc_named(sizeof(*fastpath), 16,
				 OCTEON_SE_FASTPATH_BOOTMEM_BLOCK);

  if (fastpath == NULL)
    {
      fprintf(stderr, "Could not allocate %d byte bootmem block at \"%s\"",
	      (int) sizeof(*fastpath), OCTEON_SE_FASTPATH_BOOTMEM_BLOCK);
      return -1;
    }
  
  /* Initialize shared fastpath object */
  memset(fastpath, 0, sizeof(*fastpath));
  
  /* Allocate flow hash locks */
  for (i = 0; i < OCTEON_SE_FASTPATH_NUM_FLOW_HASH_LOCKS; i++)
    cvmx_rwlock_wp_init(&fastpath->flow_hash_lock[i].lock);

  /* Initialize flow hash table */
  for (i = 0; i < OCTEON_SE_FASTPATH_FLOW_ID_HASH_SIZE; i++)
    {
      fastpath->flow_id_hash[i].fwd_flow_index =
	OCTEON_SE_FASTPATH_INVALID_INDEX;
      fastpath->flow_id_hash[i].rev_flow_index =
        OCTEON_SE_FASTPATH_INVALID_INDEX;
      fastpath->flow_id_hash[i].lock =
        &fastpath->
        flow_hash_lock[i % OCTEON_SE_FASTPATH_NUM_FLOW_HASH_LOCKS].lock;
    }

  /* Initialize flow table */
  for (i = 0; i < OCTEON_SE_FASTPATH_FLOW_TABLE_SIZE; i++)
    {
      se_flow = OCTEON_SE_FASTPATH_FLOW(fastpath, i);
      OCTEON_SE_FASTPATH_FLOW_LOCK_INIT(se_flow->lock);
      se_flow->fwd_flow_index_next = OCTEON_SE_FASTPATH_INVALID_INDEX;
      se_flow->rev_flow_index_next = OCTEON_SE_FASTPATH_INVALID_INDEX;
      se_flow->fwd_transform_index = OCTEON_SE_FASTPATH_INVALID_INDEX;
      se_flow->rev_transform_index = OCTEON_SE_FASTPATH_INVALID_INDEX;
      se_flow->fwd_nh_index = OCTEON_SE_FASTPATH_INVALID_INDEX;
      se_flow->rev_nh_index = OCTEON_SE_FASTPATH_INVALID_INDEX;
      for (j = 0; j < OCTEON_SE_FASTPATH_NUM_RX_TRANSFORMS; j++)
	{
	  se_flow->fwd_rx_transform_index[i] = 
	    OCTEON_SE_FASTPATH_INVALID_INDEX;
	  se_flow->rev_rx_transform_index[i] = 
	    OCTEON_SE_FASTPATH_INVALID_INDEX;
	}
      se_flow->fwd_iport = OCTEON_SE_FASTPATH_INVALID_PORT;
      se_flow->rev_iport = OCTEON_SE_FASTPATH_INVALID_PORT;
    }

  /* Initialize trd table */
  for (i = 0; i < OCTEON_SE_FASTPATH_TRD_TABLE_SIZE; i++)
    {
      se_trd = OCTEON_SE_FASTPATH_TRD(fastpath, i);
      cvmx_rwlock_wp_init(se_trd->lock);
      se_trd->port = OCTEON_SE_FASTPATH_INVALID_PORT;
    }

  /* Initialize nexthop table */
  for (i = 0; i < OCTEON_SE_FASTPATH_NH_TABLE_SIZE; i++)
    {
      se_nh = OCTEON_SE_FASTPATH_NH(fastpath, i);
      cvmx_rwlock_wp_init(se_nh->lock);
      se_nh->port = OCTEON_SE_FASTPATH_INVALID_PORT;
    }

  fprintf(stderr, "Allocated SE fastpath %p, size %d bytes",
	  fastpath, (int) sizeof(*fastpath));

  return 0;
}

/** Installs a flow to SE fastpath. This should never be used when
    quicksec.ko is loaded in to the kernel, as there is a risk of deadlocking.
*/
static int
octeon_se_fastpath_control_install_flow(uint32_t flow_index,
					uint64_t src_ip_high,
					uint64_t src_ip_low,
					uint64_t dst_ip_high,
					uint64_t dst_ip_low,
					uint8_t ipproto,
					uint16_t src_port,
					uint16_t dst_port,
					uint32_t tunnel_id,
					uint32_t fwd_nh_index,
					uint32_t rev_nh_index,
					uint8_t fwd_iport,
					uint8_t rev_iport)
{
  SeFastpath fastpath;
  SeFastpathFlowData se_flow;
  int i;
  uint8_t flags = OCTEON_SE_FASTPATH_FLOW_ID_FLAG_FROMADAPTER;
  uint32_t fwd_hash_bucket, rev_hash_bucket;

  fastpath = octeon_se_fastpath_control_get_fastpath();
  if (fastpath == NULL)
    return -1;

  if (flow_index == OCTEON_SE_FASTPATH_INVALID_INDEX
      || flow_index >= OCTEON_SE_FASTPATH_FLOW_TABLE_SIZE)
    {
      fprintf(stderr, "Invalid flow index %d\n", flow_index);
      return -1;
    }
  
  if ((ipproto != 6 && ipproto != 17) || src_port == 0 || dst_port == 0
      || fwd_nh_index == OCTEON_SE_FASTPATH_INVALID_INDEX
      || rev_nh_index == OCTEON_SE_FASTPATH_INVALID_INDEX)
    {
      fprintf(stderr, "Invalid flow parameters\n");
      return -1;
    }

  se_flow = OCTEON_SE_FASTPATH_FLOW(fastpath, flow_index);

  OCTEON_SE_FASTPATH_FLOW_WRITE_LOCK(fastpath, flow_index, se_flow);
  
  if (se_flow->flag_in_use == 1)
    {
      OCTEON_SE_FASTPATH_FLOW_WRITE_UNLOCK(fastpath, flow_index, se_flow);
      fprintf(stderr, "Flow %d is already in use\n", flow_index);
      return -1;
    }

  se_flow->flag_in_use = 1;

  se_flow->src_ip_high = src_ip_high;
  se_flow->src_ip_low = src_ip_low;
  se_flow->dst_ip_high = dst_ip_high;
  se_flow->dst_ip_low = dst_ip_low;
  
  if (src_ip_high != 0 && dst_ip_high != 0)
    {
      flags |= OCTEON_SE_FASTPATH_FLOW_ID_FLAG_IP6;
      se_flow->flag_ip_version_6 = 1;
    }

  se_flow->ipproto = ipproto;
  se_flow->src_port = src_port;
  se_flow->dst_port = dst_port;
  se_flow->tunnel_id = tunnel_id;
  
  se_flow->fwd_nh_index = fwd_nh_index;
  se_flow->rev_nh_index = rev_nh_index;

  se_flow->fwd_iport = fwd_iport;
  se_flow->rev_iport = rev_iport;
  if (fwd_iport == OCTEON_SE_FASTPATH_INVALID_PORT
      || rev_iport == OCTEON_SE_FASTPATH_INVALID_PORT)
    se_flow->flag_ignore_iport = 1;  
  
  se_flow->fwd_transform_index = OCTEON_SE_FASTPATH_INVALID_INDEX;
  se_flow->rev_transform_index = OCTEON_SE_FASTPATH_INVALID_INDEX;
   
   for (i = 0; i < OCTEON_SE_FASTPATH_NUM_RX_TRANSFORMS; i++)
     {
       se_flow->fwd_rx_transform_index[i] = OCTEON_SE_FASTPATH_INVALID_INDEX;
       se_flow->rev_rx_transform_index[i] = OCTEON_SE_FASTPATH_INVALID_INDEX;
     }
   
   octeon_se_fastpath_flow_id_hash(&se_flow->fwd_flow_id,
				   fastpath->salt,
                                   se_flow->tunnel_id, se_flow->src_port,
                                   se_flow->dst_port, se_flow->ipproto,
                                   flags,
                                   se_flow->src_ip_high, se_flow->src_ip_low,
                                   se_flow->dst_ip_high, se_flow->dst_ip_low);
   fwd_hash_bucket = OCTEON_SE_FASTPATH_FLOW_HASH_BUCKET(fastpath,
							 se_flow->
							 fwd_flow_id.id.
							 hash_id);

   octeon_se_fastpath_flow_id_hash(&se_flow->rev_flow_id,
				   fastpath->salt,
                                   se_flow->tunnel_id, se_flow->dst_port,
                                   se_flow->src_port, se_flow->ipproto,
                                   flags,
                                   se_flow->dst_ip_high, se_flow->dst_ip_low,
                                   se_flow->src_ip_high, se_flow->src_ip_low);
   rev_hash_bucket = OCTEON_SE_FASTPATH_FLOW_HASH_BUCKET(fastpath,
							 se_flow->
							 rev_flow_id.id.
							 hash_id);
   
   OCTEON_SE_FASTPATH_FLOW_WRITE_UNLOCK(fastpath, flow_index, se_flow);
   
   OCTEON_SE_FASTPATH_FLOW_HASH_WRITE_LOCK(fastpath, fwd_hash_bucket);
   se_flow->fwd_flow_index_next =
     fastpath->flow_id_hash[fwd_hash_bucket].fwd_flow_index;
   fastpath->flow_id_hash[fwd_hash_bucket].fwd_flow_index = flow_index;
   se_flow->in_fwd_hash = 1;
   OCTEON_SE_FASTPATH_FLOW_HASH_WRITE_UNLOCK(fastpath, fwd_hash_bucket);
   
   OCTEON_SE_FASTPATH_FLOW_HASH_WRITE_LOCK(fastpath, rev_hash_bucket);
   se_flow->rev_flow_index_next =
     fastpath->flow_id_hash[rev_hash_bucket].rev_flow_index;
   fastpath->flow_id_hash[rev_hash_bucket].rev_flow_index = flow_index;
   se_flow->in_rev_hash = 1;
   OCTEON_SE_FASTPATH_FLOW_HASH_WRITE_UNLOCK(fastpath, rev_hash_bucket);

   return 0;
}

/** Dumps SE flow content. */
static void
octeon_se_fastpath_control_print_flow(SeFastpathFlowData se_flow,
				      uint32_t flow_index)
{
  printf("SE Flow %d:\n"
	 "Fwd flow ID 0x%016lx 0x%016lx\n"
	 "Rev flow ID 0x%016lx 0x%016lx\n",
	 flow_index, se_flow->fwd_flow_id.raw[0], se_flow->fwd_flow_id.raw[1],
	 se_flow->rev_flow_id.raw[0], se_flow->rev_flow_id.raw[1]);

  if (se_flow->flag_ip_version_6 == 1)
    {
      printf("Src %016lx %016lx\n"
	     "Dst %016lx %016lx\n",
	     se_flow->src_ip_high, se_flow->src_ip_low,
	     se_flow->dst_ip_high, se_flow->dst_ip_low);
    }
  else
    {
      printf("Src %08lx\n"
	     "Dst %08lx\n",
	     se_flow->src_ip_low,
	     se_flow->dst_ip_low);
    }
  
  switch (se_flow->ipproto)
    {
    case 17:  /* UDP */
    case 6:   /* TCP */
      printf("IP protocol %d src port %d dst port %d\n",
	     se_flow->ipproto, se_flow->src_port, se_flow->dst_port);
      break;
      
    case 1:   /* ICMP */
    case 58:  /* ICMPv6 */
      printf("IP protocol %d code %d type %d id %d\n",
	     se_flow->ipproto, 
	     se_flow->u.icmp.code, se_flow->u.icmp.type, se_flow->u.icmp.id);
      break;
      
    case 50:  /* ESP */
    case 51:  /* AH */
      printf("IP protocol %d spi %d\n",
	     se_flow->ipproto, se_flow->u.spi);
      break;

    default:
      printf("IP protocol %d xid 0x%x\n",
	     se_flow->ipproto, se_flow->u.protocol_xid);
      break;
    }

  printf("Iport fwd %d rev %d NextHop fwd %d rev %d\n"
	 "Tunnel ID %d Transform fwd 0x%x (%d) rev 0x%x (%d)\n"
	 "Last packet %d\n"
	 "Flags [%s%s%s%s%s%s%s%s]\n",
	 se_flow->fwd_iport, se_flow->rev_iport,
	 se_flow->fwd_nh_index, se_flow->rev_nh_index,
	 se_flow->tunnel_id,
	 se_flow->fwd_transform_index, se_flow->fwd_transform_index & 0xffffff,
	 se_flow->rev_transform_index, se_flow->rev_transform_index & 0xffffff,
	 se_flow->last_packet_time,
	 (se_flow->in_fwd_hash ? "in_fwd_hash " : ""),
	 (se_flow->in_rev_hash ? "in_rev_hash " : ""),
	 (se_flow->flag_ip_version_6 ? "ip_version_6 " : ""),
	 (se_flow->flag_invalid ? "invalid " : ""),
	 (se_flow->flag_in_use ? "in_use " : ""),
	 (se_flow->flag_slow ? "slow " : ""),
	 (se_flow->flag_ignore_iport ? "ignore_iport " : ""),
	 (se_flow->flag_ipsec_incoming ? "ipsec_incoming " : ""));

#ifdef OCTEON_SE_FASTPATH_STATISTICS
  printf("Stats\n"
	 "\tForward packets %ld octets %ld\n"
	 "\tReverse packets %ld octets %ld\n"
	 "\tDropped packets %ld\n",
	 se_flow->fwd_packets, se_flow->fwd_octets, 
	 se_flow->rev_packets, se_flow->rev_octets, 
	 se_flow->dropped_packets);
#endif /* OCTEON_SE_FASTPATH_STATISTICS */
}

/** Dumps SE flow at flow_index. It is safe to call this when quicksec.ko
    is loaded in to the kernel. This does not take a lock on flow so there
    is a risk that the flow data is inconsistent. */
static int
octeon_se_fastpath_control_dump_flow(uint32_t flow_index)
{
  SeFastpathFlowData se_flowp;
  SeFastpathFlowDataStruct se_flow;
  SeFastpath fastpath;

  fastpath = octeon_se_fastpath_control_get_fastpath();
  if (fastpath == NULL)
    return -1;
  
  if (flow_index == OCTEON_SE_FASTPATH_INVALID_INDEX
      || flow_index >= OCTEON_SE_FASTPATH_FLOW_TABLE_SIZE)
    {
      fprintf(stderr, "Invalid flow index %d\n", flow_index);
      return -1;
    }

  /* Copy flow data. Note that no lock is taken here, so data might out
     of sync. */
  se_flowp = OCTEON_SE_FASTPATH_FLOW(fastpath, flow_index);
  se_flow = *se_flowp;
  
  octeon_se_fastpath_control_print_flow(&se_flow, flow_index);
	 
  return 0;
}

/** Dumps all non-slow valid flows. It is safe to call this when quicksec.ko
    is loaded in to the kernel. This does not take a lock on flows so there
    is a risk that the flow data is inconsistent.  */
static int
octeon_se_fastpath_control_dump_fast_flow()
{
  SeFastpathFlowData se_flowp;
  SeFastpathFlowDataStruct se_flow;
  SeFastpath fastpath;
  uint32_t flow_index;
  
  fastpath = octeon_se_fastpath_control_get_fastpath();
  if (fastpath == NULL)
    return -1;
  
  for (flow_index = 0;
       flow_index < OCTEON_SE_FASTPATH_FLOW_TABLE_SIZE;
       flow_index++)
    {
      /* Copy flow data. Note that no lock is taken here, so data might out
	 of sync. */
      se_flowp = OCTEON_SE_FASTPATH_FLOW(fastpath, flow_index);
      se_flow = *se_flowp;

      /* Print only flows that are valid and not slow. */
      if (se_flow.flag_slow == 0 && se_flow.flag_invalid == 0
	  && se_flow.flag_in_use == 1)
	octeon_se_fastpath_control_print_flow(&se_flow, flow_index);
    }
  
  return 0;
}

/** Dumps SE transform at trd_index. It is safe to call this when quicksec.ko
    is loaded in to the kernel. This does not take a lock on trd so there
    is a risk that the trd data is inconsistent.  */
static int
octeon_se_fastpath_control_dump_trd(uint32_t trd_index)
{
  SeFastpathTransformData se_trdp;
  SeFastpathTransformDataStruct se_trd;
  SeFastpath fastpath;
  int i;

  fastpath = octeon_se_fastpath_control_get_fastpath();
  if (fastpath == NULL)
    return -1;
  
  if (trd_index == OCTEON_SE_FASTPATH_INVALID_INDEX
      || trd_index >= OCTEON_SE_FASTPATH_TRD_TABLE_SIZE)
    {
      fprintf(stderr, "Invalid transform index %d\n", trd_index);
      return -1;
    }

  /* Copy transform data. Note that no lock is taken here, so data might out
     of sync. */
  se_trdp = OCTEON_SE_FASTPATH_TRD(fastpath, trd_index);
  se_trd = *se_trdp;
  
  printf("SE Transform %d:\n"
	 "Transform 0x%x [%s%s%s]\n"
	 "SPI out %x in %x old in %x\n"
	 "SEQ %ld Port %d\n",
	 trd_index, se_trd.transform,
	 (se_trd.tunnel_mode ? "tunnel " : "transport "),
	 (se_trd.nh == SSH_IPPROTO_ESP ? "esp " : "ah "),
	 (se_trd.is_special ? "special" : ""),
	 se_trd.spi_out, se_trd.spi_in, se_trd.old_spi_in,
	 se_trd.seq, se_trd.port);
  
  if (se_trd.ip_version_6 == 1)
    {
      printf("Gw  %016lx %016lx\n"
	     "Own %016lx %016lx\n",
	     se_trd.gw_addr_high, se_trd.gw_addr_low,
	     se_trd.own_addr_high, se_trd.own_addr_low);
    }
  else
    {
      printf("Gw  %08lx\n"
	     "Own %08lx\n",
	     se_trd.gw_addr_low,
	     se_trd.own_addr_low);
    }

  printf("Cipher keys, len %d bytes\n", se_trd.cipher_key_size);
  printf("IN:\n");
  for (i = 0; i < se_trd.cipher_key_size; i++)
    {
      printf("%02x ", se_trd.keymat[i]);
      if ((i % 8) == 7)
	printf("\n");
    }
  if (se_trd.cipher_nonce_size > 0)
    {
      printf("Nonce:\n");
      for (i = 0; i < se_trd.cipher_nonce_size; i++)
	{
	  printf("%02x ", se_trd.keymat[i + se_trd.cipher_key_size]);
	  if ((i % 8) == 7)
	    printf("\n");
	}
    }
  printf("\n");

  printf("OUT:\n");
  for (i = 0; i < se_trd.cipher_key_size; i++)
    {
      printf("%02x ", se_trd.keymat[i + (OCTEON_MAX_KEYMAT_LEN/2)]);
      if ((i % 8) == 7)
	printf("\n");
    }

  if (se_trd.cipher_nonce_size > 0)
    {
      printf("Nonce:\n");
      for (i = 0; i < se_trd.cipher_nonce_size; i++)
	{
	  printf("%02x ", se_trd.keymat[i + (OCTEON_MAX_KEYMAT_LEN/2) 
					+ se_trd.cipher_key_size]);
	  if ((i % 8) == 7)
	    printf("\n");
	}
    }
  printf("\n");

  printf("Mac keys, len %d bytes\n", se_trd.mac_key_size);
  printf("IN:\n");
  for (i = 0; i < se_trd.mac_key_size; i++)
    {
      printf("%02x ", se_trd.keymat[i + (OCTEON_MAX_ESP_KEY_BITS/8)]);
      if ((i % 8) == 7)
	printf("\n");
    }
  printf("\n");

  printf("OUT:\n");
  for (i = 0; i < se_trd.mac_key_size; i++)
    {
      printf("%02x ", se_trd.keymat[i + (OCTEON_MAX_KEYMAT_LEN/2)
				    + (OCTEON_MAX_ESP_KEY_BITS/8)]);
      if ((i % 8) == 7)
	printf("\n");
    }
  printf("\n");

  printf("Last packet in %d out %d\n",
	 se_trd.last_in_packet_time, se_trd.last_out_packet_time);

#ifdef OCTEON_SE_FASTPATH_STATISTICS
  printf("Stats\n"
	 "\tOut packets %ld octets %ld\n"
	 "\tIn packets %ld octets %ld\n"
	 "\tDropped packets %ld\n"
	 "\tNum mac fails %ld\n",
	 se_trd.out_packets, se_trd.out_octets,
	 se_trd.in_packets, se_trd.in_octets,
	 se_trd.drop_packets, se_trd.num_mac_fails);
#endif /* OCTEON_SE_FASTPATH_STATISTICS */
	 
  return 0;
}


/** Install a nexthop to SE fastpath. This should never be called when 
    quicksec.ko is loaded in to the kernel, as this could cause a deadlock. */
static int
octeon_se_fastpath_control_install_nh(uint32_t nh_index,
				      uint8_t media_len, 
				      uint64_t dst_mac,
				      uint64_t src_mac,
				      uint16_t ether_type,
				      uint8_t port,
				      uint16_t mtu,
				      uint16_t min_len)
{
  SeFastpath fastpath;
  SeFastpathNextHopData se_nh;
  int i;

  fastpath = octeon_se_fastpath_control_get_fastpath();
  if (fastpath == NULL)
    return -1;

  if (nh_index == OCTEON_SE_FASTPATH_INVALID_INDEX
      || nh_index >= OCTEON_SE_FASTPATH_NH_TABLE_SIZE)
    {
      fprintf(stderr, "Invalid nexthop index %d\n", nh_index);
      return -1;
    }
  
  if (media_len != 14 || port == OCTEON_SE_FASTPATH_INVALID_PORT
      || (src_mac & 0xffff000000000000) != 0
      || (dst_mac & 0xffff000000000000) != 0)
    {
      fprintf(stderr, "Invalid nexthop parameters\n");
      return -1;
    }

  se_nh = OCTEON_SE_FASTPATH_NH(fastpath, nh_index);

  OCTEON_SE_FASTPATH_NH_WRITE_LOCK(fastpath, nh_index, se_nh);

  se_nh->mtu = mtu;
  se_nh->min_packet_len = min_len;
  se_nh->port = port;
  se_nh->media_hdrlen = media_len;
  
  for (i = 0; i < 6; i++)
    se_nh->media_hdr.data[i] = (dst_mac >> ((5 - i) * 8)) & 0xff;
  for (i = 0; i < 6; i++)
    se_nh->media_hdr.data[i+6] = (src_mac >> ((5 - i) * 8)) & 0xff;  
  se_nh->media_hdr.data[12] = (ether_type >> 8) & 0xff;
  se_nh->media_hdr.data[13] = (ether_type) & 0xff;

  OCTEON_SE_FASTPATH_NH_WRITE_UNLOCK(fastpath, nh_index, se_nh);

  return 0;
}

/** Dumps nexthop at nh_index. It is safe to call this when quicksec.ko
    is loaded in to the kernel. This does not take a lock on nh so there
    is a risk that the nh data is inconsistent. */
static int
octeon_se_fastpath_control_dump_nh(uint32_t nh_index)
{
  SeFastpathNextHopData se_nhp;
  SeFastpathNextHopDataStruct se_nh;
  SeFastpath fastpath;
  uint8_t i;

  fastpath = octeon_se_fastpath_control_get_fastpath();
  if (fastpath == NULL)
    return -1;
  
  if (nh_index == OCTEON_SE_FASTPATH_INVALID_INDEX
      || nh_index >= OCTEON_SE_FASTPATH_NH_TABLE_SIZE)
    {
      fprintf(stderr, "Invalid nexthop index %d\n", nh_index);
      return -1;
    }

  /* Copy nexthop data. Note that no lock is taken here, so data might out
     of sync. */
  se_nhp = OCTEON_SE_FASTPATH_NH(fastpath, nh_index);
  se_nh = *se_nhp;
  
  printf("SE nexthop %d:\n"
	 "Media header len %d 0x",
	 nh_index, se_nh.media_hdrlen);
  
  for (i = 0; i < se_nh.media_hdrlen && i < sizeof(se_nh.media_hdr); i++)
    printf("%02x ", se_nh.media_hdr.data[i]);

  printf("\n"
	 "Mtu %d min packet len %d port %d\n",
	 se_nh.mtu, se_nh.min_packet_len, se_nh.port);

  return 0;
}


/** Flushes/dumps packets in the slowpath queues. This should never be called
    when quicksec.ko is installed in to the kernel. */
static int
octeon_se_fastpath_control_flush_queue(int dump)
{
  cvmx_wqe_t *wqe;
  cvmx_pow_tag_req_t cur_tag;
  int count = 0;
  SeFastpathControlCmd cmd;

  while (1)
    {
      wqe = cvmx_pow_work_request_sync(CVMX_POW_WAIT);
      if (wqe == NULL)
	break;

      if (dump)
	{
	  cmd = (SeFastpathControlCmd) wqe->packet_data;
	  printf("Packet %d: tunnel_id %d prev_transform_index %x\n",
		 count, cmd->tunnel_id, cmd->prev_transform_index);
	  cvmx_helper_dump_packet(wqe);
	}

      cur_tag = cvmx_pow_get_current_tag();
      cvmx_pow_tag_sw(cur_tag.s.tag, CVMX_POW_TAG_TYPE_ORDERED);
      cvmx_helper_free_packet_data(wqe);
      cvmx_fpa_free(wqe, CVMX_FPA_WQE_POOL, 0);

      count++;
    }

  printf("Flushed %d slowpath work queue entries\n", count);

  return 0;
}

/** Dumps flow hash table. It is safe to call this when quicksec.ko
    is loaded in to the kernel. This does not take a lock on flow hash so 
    there is a risk that the flow hash data is inconsistent. */
static int
octeon_se_fastpath_control_dump_hash(uint32_t obj_index)
{
  SeFastpath fastpath;
  uint32_t start, end;
  int num_buckets_populated = 0;

  fastpath = octeon_se_fastpath_control_get_fastpath();
  if (fastpath == NULL)
    return -1;
  
  if (obj_index == OCTEON_SE_FASTPATH_INVALID_INDEX)
    {
      start = 0;
      end = OCTEON_SE_FASTPATH_FLOW_ID_HASH_SIZE;
    }
  else if (obj_index < OCTEON_SE_FASTPATH_FLOW_ID_HASH_SIZE)
    {
      start = obj_index;
      end = obj_index;
    }
  else
    {
      fprintf(stderr, "Invalid flow hash bucket %d\n", obj_index);
      return -1;
    }

  printf("Flow hash table:\n");  
  do
    {
      if (obj_index != OCTEON_SE_FASTPATH_INVALID_INDEX
	  || (fastpath->flow_id_hash[start].fwd_flow_index
	      != OCTEON_SE_FASTPATH_INVALID_INDEX)
	  || (fastpath->flow_id_hash[start].rev_flow_index
	      != OCTEON_SE_FASTPATH_INVALID_INDEX))
	{
	  printf("Bucket %d: fwd %d rev %d\n",
		 start,
		 fastpath->flow_id_hash[start].fwd_flow_index,
		 fastpath->flow_id_hash[start].rev_flow_index);
	  num_buckets_populated++;
	}
      start++;
    } while (start < end);
  
  if (obj_index == OCTEON_SE_FASTPATH_INVALID_INDEX)
    printf("%d hash buckets populated\n", num_buckets_populated);

  return 0;
}

/** Dumps per core statistics. It is safe to call this when quicksec.ko
    is loaded in to the kernel. */
static int
octeon_se_fastpath_control_core_stats(uint32_t obj_index)
{
  SeFastpath fastpath;
  int i = 0;
  uint64_t total_rx = 0;
  uint64_t total_tx = 0;
  uint64_t total_drop = 0;
  uint64_t total_slow = 0;
  uint64_t total_desched = 0;
  uint64_t total_resched = 0;

  if (obj_index != OCTEON_SE_FASTPATH_INVALID_INDEX
      && obj_index >= (OCTEON_SE_FASTPATH_MAX_NUM_CPUS * CVMX_MAX_CORES))
    {
      fprintf(stderr, "Invalid core number %d\n", obj_index);
      return -1;
    }

  if (obj_index != OCTEON_SE_FASTPATH_INVALID_INDEX)
    i = obj_index;

  fastpath = octeon_se_fastpath_control_get_fastpath();
  if (fastpath == NULL)
    return -1;

  printf("Core statistics:\n");
  printf("Core        Rx        Tx      Drop      Slow   Desched   Resched\n");
  /*     "   1 000000000 000000000 000000000 000000000 000000000 000000000" */
  do
    {
      printf("%4d %9ld %9ld %9ld %9ld %9ld %9ld\n",
	     i,
	     fastpath->core_stats[i].s.pkt_rx,
	     fastpath->core_stats[i].s.pkt_tx,
	     fastpath->core_stats[i].s.pkt_drop,
	     fastpath->core_stats[i].s.pkt_slow,
	     fastpath->core_stats[i].s.pkt_desched,
	     fastpath->core_stats[i].s.pkt_resched);
      if (obj_index != OCTEON_SE_FASTPATH_INVALID_INDEX)
	break;
      
      total_rx += fastpath->core_stats[i].s.pkt_rx;
      total_tx += fastpath->core_stats[i].s.pkt_tx;
      total_drop += fastpath->core_stats[i].s.pkt_drop;
      total_slow += fastpath->core_stats[i].s.pkt_slow;
      total_desched += fastpath->core_stats[i].s.pkt_desched;
      total_resched += fastpath->core_stats[i].s.pkt_resched;

      i++;
    }
  while (i < (OCTEON_SE_FASTPATH_MAX_NUM_CPUS * CVMX_MAX_CORES));
  
  if (total_rx != 0)
    printf(" Tot %9ld %9ld %9ld %9ld %9ld %9ld\n",
	   total_rx, total_tx, total_drop, total_slow,
	   total_desched, total_resched);

  return 0;
}

/** Dumps the length of each POW input queue. It is safe to call this when 
    quicksec.ko is loaded in to the kernel. */
static int
octeon_se_fastpath_control_queue_len(uint32_t obj_index)
{
  int i = 0;
  cvmx_pow_iq_cntx_t pow_iq_cntx;

  if (obj_index != OCTEON_SE_FASTPATH_INVALID_INDEX
      && obj_index >= 8)
    {
      fprintf(stderr, "Invalid queue number %d\n", obj_index);
      return -1;
    }

  if (obj_index != OCTEON_SE_FASTPATH_INVALID_INDEX)
    i = obj_index;

  printf("Input queue length:\n");
  printf("Queue\tLength\n");
  do
    {
      pow_iq_cntx.u64 = cvmx_read_csr(CVMX_POW_IQ_CNTX(i));
      printf("%5d\t%6d\n", i, pow_iq_cntx.s.iq_cnt);

      if (obj_index != OCTEON_SE_FASTPATH_INVALID_INDEX)
	break;
      i++;
    }
  while (i < 8);
  
  return 0;
}


#define INIT_FASTPATH   128
#define INIT_HW         129
#define DUMP_FLOW       130
#define INSTALL_FLOW    131
#define DUMP_TRD        132
#define INSTALL_TRD     133
#define DUMP_NH         133
#define INSTALL_NH      134
#define FLUSH_QUEUE     135
#define DUMP_QUEUE      136
#define DUMP_HASH       137
#define CORE_STATS      138
#define QUEUE_LEN       139
#define DUMP_FAST_FLOW  140

static void usage(char *prog)
{
  fprintf(stderr, 
	  "Usage:\n"
	  "%s dumphash [bucket]   \tDump flow hash table\n"
	  "%s dumpflow flow_index \tDump SE flow at flow_index\n"
	  "%s dumpfastflows       \tDump all fast SE flows\n"
	  "%s dumptrd trd_index   \tDump SE transform at trd_index\n"
	  "%s dumpnh nh_index     \tDump SE nexthop at nh_index\n"
	  "\n"
	  "%s corestats [core]    \tDisplay core per statistics\n"
	  "%s queuelen [queue]    \tDisplay input queue length\n"
	  "\n"
	  "%s installflow ...     \tInstall SE flow\n"
	  "%s installtrd ...      \tInstall SE transform\n"
	  "%s installnh ...       \tInstall SE nexthop\n"
	  "%s enable|disable      \tEnable/disable SE fastpath\n"
	  "%s stop                \tStop SE fastpath\n"
	  "%s initfastpath ...    \tPerform SE fastpath initialization\n"
	  "%s inithw [mac_base]   \tPerform HW initialization\n"
	  "%s flushqueue          \tFlush slowpath work queue\n"
	  "%s dumpqueue           \tDump and flush slowpath work queue\n"
	  "%s help command        \tGet more help for command\n",
	  prog, prog, prog, prog, prog, prog, prog, prog, prog, prog, prog, 
	  prog, prog, prog, prog, prog, prog);
}

static void detailed_usage(char *prog, char *command)
{
  if (strncmp(command, "enable", strlen("enable")) == 0
      || strncmp(command, "disable", strlen("disable")) == 0)
    {
      fprintf(stderr,
	      "Usage:\n"
	      "%s enable|disable\n\n"
	      "Enables/disables SE fastpath packet processing. When the\n"
	      "fastpath is disabled, all inbound packets are queued in POW\n"
	      "and are processed when the fastpath is enabled.\n", prog);
    }
  else if (strncmp(command, "stop", strlen("stop")) == 0)
    {
      fprintf(stderr,
	      "Usage:\n"
	      "%s stop\n\n"
	      "Stops SE fastpath. This causes the SE to exit and leave the\n"
	      "cores idle. The fastpath cannot be restarted after it is \n"
	      "stopped\n", prog);
    }
  else if (strncmp(command, "initfastpath", strlen("initfastpath")) == 0)
    {
      fprintf(stderr,
	      "Usage:\n"
	      "%s initfastpath \n\n"
	      "Initializes the shared fastpath object\n", prog);
    }
  else if (strncmp(command, "inithw", strlen("inithw")) == 0)
    {
      fprintf(stderr,
	      "Usage:\n"
	      "%s inithw [mac_base]\n\n"
	      "Initializes octeon hardware modules. This sets the MAC\n"
	      "addresses and the rx mode on all ports, configures the\n"
	      "inbound packet tagging and groups, and initializes FPA,\n"
	      "PIP/IPD and PKO modules. The optional parameter 'mac_base'\n"
	      "specifies the prefix for MAC addresses\n", prog);
    }
  else if (strncmp(command, "dumpflow", strlen("dumpflow")) == 0
	   || strncmp(command, "dumptrd", strlen("dumptrd")) == 0
	   || strncmp(command, "dumpnh", strlen("dumpnh")) == 0)
    {
      fprintf(stderr,
	      "Usage:\n"
	      "%s dumpflow|dumptrd|dumpnh index\n\n"
	      "Dumps the flow/trd/nexthop at index 'index'\n", prog);
    }
  else if (strncmp(command, "dumpfastflow", strlen("dumpfastflow")) == 0)
    {
      fprintf(stderr,
	      "Usage:\n"
	      "%s dumpfastflow\n\n"
	      "Dumps all flows that are processed on the SE fastpath.\n",
	      prog);
    }
  else if (strncmp(command, "installflow", strlen("installflow")) == 0)
    {
      fprintf(stderr,
	      "Usage:\n"
	      "%s installflow index src_ip_high src_ip_low \\\n"
	      "\tdst_ip_high dst_ip_low ipproto src_port dst_port \\\n"
	      "\ttunnel_id fwd_nh_index rev_nh_index [fwd_iport rev_iport]\n\n"
	      "Installs a flow to SE fastpath. For IPv4 flows the parameters\n"
	      "'src_ip_high' and 'dst_ip_high' must be zero. If the\n"
	      "parameters 'fwd_iport' and 'rev_iport' are not given then\n"
	      "ingress port filtering is disabled for the flow.\n", prog);
    }
  else if (strncmp(command, "installtrd", strlen("installtrd")) == 0)
    {
      fprintf(stderr,
	      "Usage:\n"
	      "%s installtrd index\n\n"
	      "Installs a transform to SE fastpath. Not implemented yet.\n",
	      prog);
    }
  else if (strncmp(command, "installnh", strlen("installnh")) == 0)
    {
      fprintf(stderr,
	      "Usage:\n"
	      "%s installnh index media_len dst_mac src_mac ether_type \\\n"
	      "\tport [mtu min_packet_len]\n\n"
	      "Installs a nexthop to SE fastpath.\n", prog);
    }
  else if (strncmp(command, "flushqueue", strlen("flushqueue")) == 0
	   || strncmp(command, "dumpqueue", strlen("dumpqueue")) == 0)
    {
      fprintf(stderr,
	      "Usage:\n"
	      "%s flushqueue|dumpqueue\n\n"
	      "Flushes the slowpath packet queue. The command 'dumpqueue'\n"
	      "additionally dumps packets in the queue before flushing them\n",
	      prog);
    }
  else if (strncmp(command, "dumphash", strlen("dumphash")) == 0)
    {
      fprintf(stderr,
	      "Usage:\n"
	      "%s dumphash [bucket]\n\n"
	      "Dumps flow hash table. If optional parameter 'bucket' is\n"
	      "given then only the flow hash bucket is dumped.\n", prog);
    }
  else if (strncmp(command, "corestats", strlen("corestats")) == 0)
    {
      fprintf(stderr,
	      "Usage:\n"
	      "%s corestats [core]\n\n"
	      "Displays the core statistics counters. If optional parameter\n"
	      "'core' is given then only the statistics are only shown for\n"
	      "that core.\n", prog);
    }
  else if (strncmp(command, "queuelen", strlen("queuelen")) == 0)
    {
      fprintf(stderr,
	      "Usage:\n"
	      "%s queuelen [queue]\n\n"
	      "Displays queue lengths for input queues. If optional\n"
	      "parameter 'queue' is given then only the queue length is\n"
	      "only shown for that input queue.\n", prog);
    }
  else
    {
      fprintf(stderr, "Unknown command %s\n", command);
    }
}

int appmain(int argc, char **argv)
{
  cvmx_sysinfo_t *sysinfo;
  int i;
  uint8_t command;
  uint32_t obj_index;
  uint64_t src_ip_high, src_ip_low, dst_ip_high, dst_ip_low;
  uint32_t fwd_nh_index, rev_nh_index, tunnel_id;
  uint16_t src_port, dst_port;
  uint8_t ipproto, fwd_iport, rev_iport;
  uint64_t src_mac, dst_mac;
  uint8_t media_len, port;
  uint16_t mtu, min_len, ether_type;
  uint64_t mac_base;

  sysinfo = cvmx_sysinfo_get();
  if (sysinfo == NULL || !cvmx_coremask_first_core(sysinfo->core_mask))
    exit(0);

  if (argc <= 1)
    {
      usage(argv[0]);
      exit(-1);
    }

  command = 0;
  obj_index = OCTEON_SE_FASTPATH_INVALID_INDEX;

  src_ip_high = src_ip_low = 0;
  dst_ip_high = dst_ip_low = 0;
  ipproto = 0;
  src_port = 0;
  dst_port = 0;
  tunnel_id = 0;
  fwd_nh_index = OCTEON_SE_FASTPATH_INVALID_INDEX;
  rev_nh_index = OCTEON_SE_FASTPATH_INVALID_INDEX;
  fwd_iport = OCTEON_SE_FASTPATH_INVALID_PORT;
  rev_iport = OCTEON_SE_FASTPATH_INVALID_PORT;

  src_mac = dst_mac = 0;
  media_len = 0;
  port = OCTEON_SE_FASTPATH_INVALID_PORT;
  mtu = 1500;
  min_len = 64;
  ether_type = 0;

  mac_base = 0x000fb7000000;

  for (i = 1; i < argc; i++)
    {
      if (strncmp(argv[i], "enable", strlen("enable")) == 0)
	command = OCTEON_SE_FASTPATH_CONTROL_CMD_ENABLE;
      else if (strncmp(argv[i], "disable", strlen("disable")) == 0)
	command = OCTEON_SE_FASTPATH_CONTROL_CMD_DISABLE;
      else if (strncmp(argv[i], "stop", strlen("stop")) == 0)
	command = OCTEON_SE_FASTPATH_CONTROL_CMD_STOP;
      else if (strncmp(argv[i], "initfastpath", strlen("initfastpath")) == 0)
	{
	  command = INIT_FASTPATH;
	}
      else if (strncmp(argv[i], "inithw", strlen("inithw")) == 0)
	{
	  command = INIT_HW;
	  if ((i + 1) < argc)
	    {
	      mac_base = strtol(argv[i+1], NULL, 0);
	      i++;
	    }
	}
      else if (strncmp(argv[i], "dumpflow", strlen("dumpflow")) == 0
	       && (i + 1) < argc)
	{
	  obj_index = strtol(argv[i+1], NULL, 0);
	  command = DUMP_FLOW;
	  i++;
	}
      else if (strncmp(argv[i], "dumpfastflow", strlen("dumpfastflow")) == 0)
	{
	  command = DUMP_FAST_FLOW;
	  i++;
	}
      else if (strncmp(argv[i], "installflow", strlen("installflow")) == 0
	       && (i + 11) < argc)
	{
	  command = INSTALL_FLOW;
	  obj_index = strtol(argv[i+1], NULL, 0);
	  src_ip_high = strtol(argv[i+2], NULL, 0);
	  src_ip_low = strtol(argv[i+3], NULL, 0);
	  dst_ip_high = strtol(argv[i+4], NULL, 0);
	  dst_ip_low = strtol(argv[i+5], NULL, 0);
	  ipproto = strtol(argv[i+6], NULL, 0);
	  src_port = strtol(argv[i+7], NULL, 0);
	  dst_port = strtol(argv[i+8], NULL, 0);
	  tunnel_id = strtol(argv[i+9], NULL, 0);
	  fwd_nh_index = strtol(argv[i+10], NULL, 0);
	  rev_nh_index = strtol(argv[i+11], NULL, 0);
	  i += 11;
	  if ((i + 1) < argc)
	    {
	      fwd_iport = strtol(argv[i+1], NULL, 0);
	      i++;
	    }
	  if ((i + 1) < argc)
	    {
	      i++;
	      rev_iport = strtol(argv[i+1], NULL, 0);
	    }
	}
      else if (strncmp(argv[i], "dumptrd", strlen("dumptrd")) == 0
	       && (i + 1) < argc)
	{
	  obj_index = strtol(argv[i+1], NULL, 0);
	  command = DUMP_TRD;
	  i++;
	}
      else if (strncmp(argv[i], "dumpnh", strlen("dumpnh")) == 0
	       && (i + 1) < argc)
	{
	  obj_index = strtol(argv[i+1], NULL, 0);
	  command = DUMP_NH;
	  i++;
	}
      else if (strncmp(argv[i], "installnh", strlen("installnh")) == 0
	       && (i + 6) < argc)
	{
	  command = INSTALL_NH;
	  obj_index = strtol(argv[i+1], NULL, 0);
	  media_len = strtol(argv[i+2], NULL, 0);
	  dst_mac= strtol(argv[i+3], NULL, 0);
	  src_mac = strtol(argv[i+4], NULL, 0);
	  ether_type = strtol(argv[i+5], NULL, 0);
	  port = strtol(argv[i+6], NULL, 0);
	  i += 6;
	  if ((i + 1) < argc)
	    {
	      mtu = strtol(argv[i+1], NULL, 0);
	      i++;
	    }
	  if ((i + 1) < argc)
	    {
	      min_len = strtol(argv[i+1], NULL, 0);
	      i++;
	    }
	}
      else if (strncmp(argv[i], "flushqueue", strlen("flushqueue")) == 0)
	{
	  command = FLUSH_QUEUE;
	}
      else if (strncmp(argv[i], "dumpqueue", strlen("dumpqueue")) == 0)
	{
	  command = DUMP_QUEUE;
	}
      else if (strncmp(argv[i], "dumphash", strlen("dumphash")) == 0)
	{	  
	  command = DUMP_HASH;
	  if ((i + 1) < argc)
	    {
	      obj_index = strtol(argv[i+1], NULL, 0);
	      i++;
	    }
	}      
      else if (strncmp(argv[i], "corestats", strlen("corestats")) == 0)
	{	  
	  command = CORE_STATS;
	  if ((i + 1) < argc)
	    {
	      obj_index = strtol(argv[i+1], NULL, 0);
	      i++;
	    }
	}      
      else if (strncmp(argv[i], "queuelen", strlen("queuelen")) == 0)
	{	  
	  command = QUEUE_LEN;
	  if ((i + 1) < argc)
	    {
	      obj_index = strtol(argv[i+1], NULL, 0);
	      i++;
	    }
	}      
      else if (strncmp(argv[i], "help", strlen("help")) == 0)
	{
	  if ((i + 1) < argc)
	    {
	      detailed_usage(argv[0], argv[i+1]);
	      exit(0);
	    }
	  else
	    {
	      usage(argv[0]);
	      exit(-1);
	    }
	}
      else
	{
	  usage(argv[0]);
	  exit(-1);
	}
    }
  
  if (cvmx_user_app_init())
    {
      fprintf(stderr, "User app init failed\n");
      exit(-1);
    }

  switch (command)
    {
    case OCTEON_SE_FASTPATH_CONTROL_CMD_ENABLE:
    case OCTEON_SE_FASTPATH_CONTROL_CMD_DISABLE:
    case OCTEON_SE_FASTPATH_CONTROL_CMD_STOP:
      if (octeon_se_fastpath_control_send_cmd(command))
	{
	  fprintf(stderr, "Command send failed\n");
	  exit(-1);
	}
      break;

    case INIT_FASTPATH:
      if (octeon_se_fastpath_control_init_fastpath())
	{
	  fprintf(stderr, "SE fastpath init failed\n");
	  exit(-1);
	}
      break;

    case INIT_HW:
      if (octeon_se_fastpath_control_init_hw(mac_base))
	{
	  fprintf(stderr, "HW init failed\n");
	  exit(-1);
	}
      break;

    case DUMP_FLOW:
      if (octeon_se_fastpath_control_dump_flow(obj_index))
	{
	  fprintf(stderr, "Flow dump failed\n");
	  exit(-1);
	}
      break;

    case DUMP_FAST_FLOW:
      if (octeon_se_fastpath_control_dump_fast_flow())
	{
	  fprintf(stderr, "Fast flow dump failed\n");
	  exit(-1);
	}
      break;

    case INSTALL_FLOW:
      if (octeon_se_fastpath_control_install_flow(obj_index,
						  src_ip_high, src_ip_low,
						  dst_ip_high, dst_ip_low,
						  ipproto, src_port, dst_port,
						  tunnel_id, fwd_nh_index, 
						  rev_nh_index, fwd_iport,
						  rev_iport))
	{
	  fprintf(stderr, "Flow install failed\n");
	  exit(-1);	  
	}
      break;

    case DUMP_TRD:
      if (octeon_se_fastpath_control_dump_trd(obj_index))
	{
	  fprintf(stderr, "Transform dump failed\n");
	  exit(-1);
	}
      break;

    case DUMP_NH:
      if (octeon_se_fastpath_control_dump_nh(obj_index))
	{
	  fprintf(stderr, "NextHop dump failed\n");
	  exit(-1);
	}
      break;

    case INSTALL_NH:
      if (octeon_se_fastpath_control_install_nh(obj_index, media_len, 
						dst_mac, src_mac, ether_type,
						port, mtu, min_len))
	{
	  fprintf(stderr, "NextHop install failed\n");
	  exit(-1);
	}
      break;
      
    case FLUSH_QUEUE:
    case DUMP_QUEUE:
      if (octeon_se_fastpath_control_flush_queue(command==DUMP_QUEUE?1:0))
	{
	  fprintf(stderr, "Slowpath work queue flush failed\n");
	  exit(-1);	  
	}
      break;

    case DUMP_HASH:
      if (octeon_se_fastpath_control_dump_hash(obj_index))
	{
	  fprintf(stderr, "Flow hash table dump failed\n");
	  exit(-1);
	}
      break;

    case CORE_STATS:
      if (octeon_se_fastpath_control_core_stats(obj_index))
	{
	  fprintf(stderr, "Core statistics dump failed\n");
	  exit(-1);
	}
      break;

    case QUEUE_LEN:
      if (octeon_se_fastpath_control_queue_len(obj_index))
	{
	  fprintf(stderr, "Input queue length dump failed\n");
	  exit(-1);
	}
      break;

    default:
      fprintf(stderr, "Unknown command\n");
      exit(-1);
    }

  exit(0);
}
