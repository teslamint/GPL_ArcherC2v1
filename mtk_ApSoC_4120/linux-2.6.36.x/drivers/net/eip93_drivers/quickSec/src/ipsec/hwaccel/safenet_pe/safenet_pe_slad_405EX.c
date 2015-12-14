/*

  safenet_pe_slad_405EX.c

  Copyright:
  Copyright (c) 2007 - 2007 SFNT Vught.
  All rights reserved.
	
  Safenet Look-Aside Accelerator Packet Engine Interface 
  implementation specifics for 405EX Chips with the use
  of the SLAD driver.
*/


#include "safenet_pe.h"
#include "safenet_pe_slad_platform.h"
#include "safenet_pe_utils.h"

#include "sshincludes.h"

#include "slad.h"
#include "initblk.h"

/* Size of the PDR descriptor ring */
#define SSH_SAFENET_NR_PDR_ENTRIES (SSH_SAFENET_MAX_QUEUED_OPERATIONS + 10)

/* Size of the CGX descriptor ring (unused) */
#define SSH_SAFENET_NR_CDR_ENTRIES 0


#define SSH_DEBUG_MODULE "SshSafenet1x41"
#define SSH_TRACE_ENABLED(level)  (level <= 10)


#ifdef SSH_SAFENET_PE_SA_CACHING
static SLAD_SA* prev_sa = NULL;
#endif /* SSH_SAFENET_PE_SA_CACHING */


/******** Packet descriptor handling **********/

void safenet_pe_pkt_from_slad_pkt(SLAD_PKT_BITS *pktb, PE_PKT_DESCRIPTOR* pkt)
{
  SLAD_PKT* p = (SLAD_PKT*)pktb;

  memset(pkt, 0, sizeof(*pkt));

  dma_unmap_single (NULL, p->src_bus_addr, p->dst_len, DMA_BIDIRECTIONAL);

  pkt->next_header = pktb->next_header;
  
  pkt->src = p->src;
  pkt->dst = p->dst;
  
  pkt->sa_data = pktb->sa;
  pkt->sa_data_len = pktb->sa_len;
  
  pkt->src_len = pktb->len;
  pkt->user_handle = p->user_handle;
  pkt->dst_len = p->dst_len;
  pkt->flags = p->flags;
  
  pkt->status = PE_PKT_STATUS_OK;
  if (pktb->status)
    {
      pkt->status = PE_PKT_STATUS_FAILURE;
      if (pktb->status & 0x01)
	{
	  pkt->status = PE_PKT_STATUS_ICV_FAILURE;
	}
      if (pktb->status & 0x02)
	{
	  pkt->status = PE_PKT_STATUS_PAD_FAILURE;
	}
      if (pktb->status & 0x08)
	{
	  pkt->status = PE_PKT_STATUS_FAILURE;
	}
      if (pktb->status & 0x04)
	{
	  pkt->status = PE_PKT_STATUS_SEQ_FAILURE;
	}
	
      printk("Safenet Crypto EIP-94 PKTGET status: %x\n",pktb->status);
  
    }
  /*    
	SSH_DEBUG(SSH_D_MY, ("copy_pad value is 1"));
	SSH_DEBUG(SSH_D_LOWOK,
	("Stripping padding from packet len=%d, pad_len=%d",
	pkt->len, pkt->pad_control));

	if (pkt->len < pkt->pad_control)
	pkt->status = PE_PKT_STATUS_PAD_FAILURE;

	pkt->len -= pkt->pad_control;
  */
}


void safenet_pe_pkt_to_slad_pkt(PE_PKT_DESCRIPTOR* pkt, SLAD_PKT_BITS *pktb)
{ 
  PE_SLAD_SA_ADAPTER* pslad_sa_adapter = (PE_SLAD_SA_ADAPTER*)pkt->sa_data;
  SLAD_PKT* p = (SLAD_PKT*)pktb;
  
  memset(p, 0, sizeof(*p));
  
  pktb->next_header = pkt->next_header;
  p->src = pkt->src;
  p->dst = pkt->dst;
  pktb->len = pkt->src_len;
  p->dst_len = pkt->dst_len;
  p->user_handle = pkt->user_handle;
  p->sa = pslad_sa_adapter->sa;
  p->srec = pslad_sa_adapter->srec;
  p->src_bus_addr = p->dst_bus_addr = 
    dma_map_single (NULL, p->src, pkt->dst_len, DMA_BIDIRECTIONAL);
#ifdef SAFENET_DEBUG
  if (!p->src_bus_addr)
    printk("\nsafenet_pe_pkt_to_slad_pkt: dma_map_single failed!\n");
#endif /* SAFENET_DEBUG */

  p->flags = pkt->flags;
  pktb->hash_final = 1;
  pktb->bypass_offset = 0;
  pktb->pad_control = (pkt->flags & PE_FLAGS_AES) ? 0x8 : 0;

  pktb->sa_busid = SLAD_BUSID_HOST;

#ifdef SSH_SAFENET_PE_SA_CACHING
  if ((prev_sa == p->sa) && (NULL != p->sa))
    {
      pktb->chain_sa_cache = 1;

    }
  else
    {
      pktb->chain_sa_cache = 0;

    }
  prev_sa = p->sa;
#endif /* SSH_SAFENET_PE_SA_CACHING */    
}


/******** SLAD driver init block initializing **********/

BOOL safenet_pe_setup_init_block(UINT32 device_num, OSAL_NOTIFY* pdr_notify,
				 BOOL pci_swap,
				 INIT_BLOCK *iblk)
{
  UINT16 pdr_poll_delay, pdr_delay_after;
  UINT32 pdr_int_count;
  int sg_flag = 0;
  int status;


  /* EIP94v2.2 AMCC values */
  pdr_poll_delay =30; /* appxomately 30*0.7 = 21 microseconds */
  pdr_delay_after=30;
  pdr_int_count = SSH_SAFENET_PDR_ENTRIES_PER_INTERRUPT;



  memset ((void *) iblk, 0, sizeof (INIT_BLOCK));
  /*This function is for auto-generation as part of driver */
  status = slad_get_initblk (device_num, iblk, &sg_flag);

  if (status == SLAD_DRVSTAT_SUCCESS)
    {
      SSH_DEBUG(SSH_D_FAIL, ("\n Initialized the INIT_BLOCK \n"));
    }
  else
    {
#ifdef SAFENET_DEBUG
      printk("\nFailed to initialize the INIT_BLOCK\n");
#endif /* SAFENET_DEBUG */
      return FALSE;
    }
  iblk->pdr_notify = pdr_notify;
  iblk->cdr_notify = pdr_notify;
  iblk->part_src_addr = 0;
  iblk->part_dst_addr = 0;

              
#ifdef SSH_SAFENET_MIN_BYTE_SWAP
  /* PDR automatic swap only */
  iblk->pe_dma_config &= ~PE_DMA_CFG_ENDIAN_SWAP_SA; 
#else
  /* PDR + SA automatic swap only */
  iblk->pe_dma_config |= PE_DMA_CFG_ENDIAN_SWAP_SA; 
#endif
  
  iblk->dma_config |= 0x300; /*  high priority for PLB access */
  
  iblk->enable_dynamic_sa = false;

  iblk->pdr_entries = SSH_SAFENET_NR_PDR_ENTRIES;
  iblk->pdr_int_count = pdr_int_count;
  iblk->pdr_poll_delay = pdr_poll_delay;
  iblk->pdr_delay_after = pdr_delay_after;
  SSH_DEBUG(SSH_D_NICETOKNOW, ("\nSA caching disabled.\n"));
  return TRUE;

#if 0

  memset((void *)iblk, 0, sizeof (INIT_BLOCK));
  
  /* EIP94 AMCC values */
  pdr_poll_delay = 0x8;
  pdr_delay_after = 0x8;
  pdr_int_count = SSH_SAFENET_PDR_ENTRIES_PER_INTERRUPT;

  iblk->cdr_busid = SLAD_BUSID_HOST;
  iblk->cdr_addr  = 0;
  iblk->cdr_entries = SSH_SAFENET_NR_CDR_ENTRIES;
  iblk->cdr_int_count = 1;
  iblk->cdr_int_type = 0x0100;
  iblk->cdr_poll_delay = 8;
  iblk->cdr_delay_after = 1;
  iblk->pdr_addr = 0;
  iblk->pdrr_addr = 0;
  iblk->pdr_entries = SSH_SAFENET_NR_PDR_ENTRIES;
  iblk->pdr_int_count = pdr_int_count;
  iblk->pdr_poll_delay = pdr_poll_delay;
  iblk->pdr_delay_after = pdr_delay_after;

  /* SAs are in host memory, created and managed by host. */
  iblk->sa_config = 0;
  iblk->sa_busid = SLAD_BUSID_HOST;
  iblk->sa_addr = 0;
  iblk->sa_entries = 0;

  iblk->dma_config = 0x00180006;
  iblk->pe_dma_config =   PE_DMA_CFG_PE_MODE
    | PE_DMA_CFG_PDR_BUSID_HOST
    | PE_DMA_CFG_GATH_BUSID_HOST
    | PE_DMA_CFG_SCAT_BUSID_HOST
    | PE_DMA_CFG_ENABLE_FAILSAFE;

  /* Not using scatter/gather. */
  iblk->part_src_addr = 0;
  iblk->part_dst_addr = 0;
  iblk->part_config = 0;
  iblk->part_src_entries = 0;
  iblk->part_dst_entries = 0;

  iblk->int_config = 0;

#ifdef SSH_SAFENET_TARGET_REQUIRES_SWAP
  iblk->target_endian_mode	= 0xe41b;
#else /* SSH_SAFENET_TARGET_REQUIRES_SWAP */
  iblk->target_endian_mode	= pci_swap ? 0xe41b : 0xe4e4;
#endif /* SSH_SAFENET_TARGET_REQUIRES_SWAP */

#ifdef SLAD_BIG_ENDIAN
  iblk->pe_endian_mode = 0xe41b;
#else
  iblk->pe_endian_mode = 0xe4e4;
#endif

  if (pci_swap)
    {
      iblk->pe_dma_config
	|= PE_DMA_CFG_ENDIAN_SWAP_DESC
	| PE_DMA_CFG_ENDIAN_SWAP_SA
	| PE_DMA_CFG_ENDIAN_SWAP_PART;
    }
  else
    {
      iblk->pe_dma_config |= PE_DMA_CFG_ENDIAN_SWAP_PKT;
    }

#if 0
  iblk->pdr_offset = (int) (sizeof(SLAD_PD_REV1) / sizeof(UINT32));
#endif

#ifdef SSH_SAFENET_OCM_SA
  if (ocm_sa_conf_ok == TRUE)
    {
      iblk->pdr_offset = 5;
    }
  else
    {
#ifdef SSH_SAFENET_NOT_COHERENT_CACHE
      iblk->pdr_offset = 5;
#else
      iblk->pdr_offset = 8;
#endif
    }
#else /* SSH_SAFENET_OCM_SA */
#ifdef SSH_SAFENET_NOT_COHERENT_CACHE
  iblk->pdr_offset = 5;
#else
  iblk->pdr_offset = 8;
#endif
#endif /* SSH_SAFENET_OCM_SA */

  iblk->pe_dma_input_threshold = 0x0008;
  iblk->pe_dma_output_threshold = 0x0008;
  iblk->pe_dma_config |= PE_DMA_CFG_ENABLE_FAILSAFE;
  iblk->intsrc_mailbox_busid = SLAD_BUSID_HOST;
  iblk->intsrc_mailbox_addr = 0;
  iblk->token_busid = SLAD_BUSID_DISABLED;
  iblk->token_addr = 0;
  iblk->software_timer_busid = SLAD_BUSID_DISABLED;
  iblk->software_timer_addr = 0;
  iblk->online_int_type = 0x8100;
  iblk->fatalerror_int_type = 0x8100;
  iblk->resetack_int_type = 0x8100;
  iblk->pf_active_low_int = 0;
  iblk->reserved = 0;
  iblk->max_cgx_pci_burst = 32;
  iblk->target_read_count = 1;
  iblk->ext_map = 0x00000000;
  iblk->dram_config    = 0x00000022;
  iblk->ext_memcfg     = 0x00000000;
  iblk->refresh_timer  = 0x00000490;
  iblk->ext_mem_wait   = 0x00000011;
  iblk->dsp_pmdmiom_wait = 0x00000000;
  iblk->cdr_notify = NULL;
  iblk->pdr_notify = pdr_notify;
  iblk->exp0_notify = NULL;
  iblk->exp2_notify = NULL;
  iblk->pkcp_notify = NULL;
  iblk->user_boot_control = 0;
  iblk->user_boot_interrupt_to_force	= 0;
  iblk->user_boot_signblock_busid = SLAD_BUSID_DISABLED;
  iblk->user_boot_signblock_addr = 0;
#endif
}



/******** SA data initializing **********/
BOOL safenet_pe_populate_sa (PE_SA_TYPE type, 
			     PE_FLAGS flags, 
			     SLAD_SA *sa,
			     UINT32 spi,
			     UINT32 seq,
			     int hash_alg,
			     int ciph_alg,
			     const unsigned char *ciph_key,
			     size_t ciph_key_len)
{
  UINT32 aes_key_len = 0;

  /* Set parameters common for AH and ESP operations */
  if (type == PE_SA_TYPE_AH)
    {
      if (flags & PE_FLAGS_OUTBOUND)
	sa->rev1.opcode = SA_OPCODE_AH_OUTBOUND;
      else
	sa->rev1.opcode = SA_OPCODE_AH_INBOUND;
    }
  sa->rev1.crypto_pad = SA_PAD_IPSEC;
  sa->rev1.hash_algo = hash_alg;
  sa->rev1.crypto_algo = SA_CRYPTO_NULL;
  sa->rev1.ext_pad = 0; /* See crypto_pad also: 
			   ext_pad|crypto_pad = 000. No padding 
			   for stream ciphers like ARC4 and AES-CTR */
  sa->rev1.stream_cipher_pad = 0;
  sa->rev1.digest_len = 3; /*  Digest Length. The length of the 
			       (truncated) Hash Digest, in words.
			       Now it is set to standard IPSEC */
  sa->rev1.hash_loading = SA_HASH_SA;
  sa->rev1.use_red_keys = 0;
  sa->rev1.save_hash = 1;
  sa->rev1.spi = (UINT32)spi;
  sa->rev1.seq = (UINT32)seq;
  
  sa->rev1.copy_header = 1;
  sa->rev1.copy_payload = 1;
  /* Copy the pad for the 1141 device types to avoid a lockup problem
     that occurs if there is no output data from certain operations. */
  SSH_DEBUG(SSH_D_LOWOK, ("copy_pad is %d, device type is %d",
			  1, SLAD_DEVICETYPE_EIP9422));
  sa->rev1.copy_pad = 0;
  sa->rev1.ipv6 = (flags & PE_FLAGS_IPV6) ? 1 : 0;
  sa->rev1.header_proc = 1;
  sa->rev1.mutable_bits = 0;/* Set to 0 to enable mutable bit handling */
  sa->rev1.ext_seq_num = 0;  /* 32-bit sequence numbers (vs. 64-bit) */
  sa->rev1.seq_num_mask = 1; /* 64-bit sequence number mask 
				(vs. 128-bit) */
  sa->rev1.hmac = 0;
  /* SA revision */
  sa->rev1.rev = 2; /* binary 10 - rev.1, binary 01 - rev.2*/
  
  /* Set ESP specific operation data */
  if (type == PE_SA_TYPE_ESP)  
    {
      sa->rev1.opcode = (flags & PE_FLAGS_OUTBOUND)
	? SA_OPCODE_ESP_OUTBOUND : SA_OPCODE_ESP_INBOUND;
      sa->rev1.iv_loading = (flags & PE_FLAGS_OUTBOUND) ?
	SA_IV_REUSE : SA_IV_INPUT;
      sa->rev1.crypto_algo = ciph_alg;
      sa->rev1.header_proc = 1;    

      if (ciph_alg == PE_CIPHER_ALG_AES)
	{
	  if (ciph_key_len == 16)
	    aes_key_len = 2;
	  else if (ciph_key_len == 24)
	    aes_key_len = 3;
	  else if (ciph_key_len == 32)
	    aes_key_len = 4;
	  else
	    return FALSE;
	}
    
      /* Set ESP parameters */
      sa->rev1.use_red_keys = 0;
      sa->rev1.save_hash = 0;
      sa->rev1.copy_header = 0;
      sa->rev1.copy_payload = 0;
      sa->rev1.save_iv = 0      ;
      /* Set to 1 disables mutable bit handling */
      sa->rev1.mutable_bits = 1;
      /* We not always use CBC mode of encryption */
      if (hash_alg == PE_HASH_ALG_GCM)
	{
	  /* We select AES-CTR (AES Counter Mode (CTR) for 
	     IPSec using a 32-bit counter) */
	  sa->rev1.crypto_mode = SA_CRYPTO_MODE_ECB;
	  sa->rev1.aes_ctr_mode = 1;
	}
      else
	{
	  sa->rev1.crypto_mode = SA_CRYPTO_MODE_CBC;
	  sa->rev1.aes_ctr_mode = 0;
	}
      sa->rev1.crypto_feedback = SA_CRYPTO_FEEDBACK_8;
      sa->rev1.hmac = 1;
  
      if (ciph_alg == PE_CIPHER_ALG_AES)
	sa->rev1.arc4_aes_key_len = aes_key_len;
    }

}
