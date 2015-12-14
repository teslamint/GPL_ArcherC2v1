/*

  safenet_pe_slad_platform.h

  Copyright:
  Copyright (c) 2007 - 2007 SFNT Vught.
  All rights reserved.

  Platform-specific interface for using in
  Safenet Look-Aside Accelerator Packet Engine Interface implementation 
  for chips with the use of the SLAD driver.
*/

#ifndef SAFENET_PE_SLAD_PLATFORM_H
#define SAFENET_PE_SLAD_PLATFORM_H

#include "slad.h"
#include "initblk.h"
#include "safenet_pe.h"
/* adapter type for the SLAD format of the SA data */
typedef struct
{
  sa_handle sa;   /*  pointer to the SA in SLAD format */
  sa_handle srec; /* pointer to the State record in SLAD format */
}
  PE_SLAD_SA_ADAPTER;


void safenet_pe_pkt_to_slad_pkt(PE_PKT_DESCRIPTOR* pkt, SLAD_PKT_BITS *pktb);

void safenet_pe_pkt_from_slad_pkt(SLAD_PKT_BITS *pktb, PE_PKT_DESCRIPTOR* pkt);

BOOL safenet_pe_setup_init_block(UINT32 device_num, 
				 OSAL_NOTIFY* pdr_notify,
				 BOOL pci_swap,INIT_BLOCK *iblk);

BOOL safenet_pe_populate_sa (PE_SA_TYPE type, 
			     PE_FLAGS flags, 
			     SLAD_SA *sa,
			     UINT32 spi,
			     UINT32 seq,
			     int hash_alg,
			     int ciph_alg,
			     const unsigned char *ciph_key,
			     size_t ciph_key_len);


#endif /* SAFENET_PE_SLAD_PLATFORM_H */
