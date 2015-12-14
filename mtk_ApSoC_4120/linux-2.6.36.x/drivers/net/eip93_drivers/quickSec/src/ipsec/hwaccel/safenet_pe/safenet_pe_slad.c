/*

  safenet_pe_slad.c

  Copyright:
  Copyright (c) 2007 - 2007 SFNT Vught.
  All rights reserved.

  Safenet Look-Aside Accelerator Packet Engine Interface implementation 
  for chips with the use of the SLAD driver.
*/

#include "safenet_la_params.h"
#include "safenet_pe.h"
#include "safenet_pe_slad_platform.h"

#include "sshincludes.h"

#ifdef KERNEL
#ifdef __linux__
#include "linux_internal.h"

#include <linux/time.h>
#include <linux/timer.h>
#include <linux/bitops.h>
#include <linux/interrupt.h>

#include <linux/sched.h>

#include <linux/kernel.h>
#ifdef SSH_SAFENET_NOT_COHERENT_CACHE
#include <linux/dma-mapping.h>
#endif /* SSH_SAFENET_NOT_COHERENT_CACHE */

#endif /* __linux__ */
#endif /* KERNEL */

#include "kernel_alloc.h"

#include "safenet_pe_utils.h"

#include "slad.h"
#include "initblk.h"

#define SSH_DEBUG_MODULE "SshSafenet1x41"
#define SSH_TRACE_ENABLED(level)  (level <= 10)

static slad_app_id_type  app_id;

static SLAD_PKT slad_pkt[PE_MAX_DEVICES][SSH_SAFENET_PDR_GET_COUNT];

static SLAD_PKT slad_pktput[PE_MAX_DEVICES][SSH_SAFENET_PDR_GET_COUNT];

static OSAL_NOTIFY slad_callbacks[PE_MAX_DEVICES];

#ifndef KERNEL
#undef SSH_SAFENET_PACKET_IS_DMA
#define ssh_kernel_alloc(a,b) ssh_malloc(a)
#define ssh_kernel_free ssh_free
#define printk printf
#endif /* KERNEL */

#undef KERN_NOTICE
#define KERN_NOTICE ".. "


#ifdef __linux__
/* If SSH_SAFENET_NOT_COHERENT_CACHE is defined we don't need
   SSH_SAFENET_SA_CACHE_ALIGN */
   
#if defined(SSH_SAFENET_NOT_COHERENT_CACHE)
#undef SSH_SAFENET_SA_CACHE_ALIGN
static inline void * 
safenet_alloc_coherent(size_t size, int flag, unsigned long *p_addr)
{
  dma_addr_t dma_handle = 0;
  void *p;
  p = dma_alloc_coherent(NULL, size, &dma_handle, GFP_ATOMIC|GFP_DMA);
  if (NULL == p)
    {
#ifdef SAFENET_DEBUG
      printk ("dma_alloc_coherent failed.\n");
#endif /* SAFENET_DEBUG */         
      return NULL;
    }
  else
    {
      if (p_addr)
	*p_addr = dma_handle;
      return p;
    }
  return NULL;
}
static inline void safenet_free_coherent(void *vaddr, size_t size)
{
  dma_free_coherent(NULL,size, vaddr,0);
}
#define ssh_kernel_alloc_sa(a,b,c) safenet_alloc_coherent(a,b,c)
#define ssh_kernel_free_sa(a,b) safenet_free_coherent(a,b)

#else /*SSH_SAFENET_NOT_COHERENT_CACHE*/
#define ssh_kernel_alloc_sa(a,b,c) ssh_kernel_alloc(a,b)
#define ssh_kernel_free_sa(a,b) ssh_kernel_free(a)
#endif /*SSH_SAFENET_NOT_COHERENT_CACHE*/

#else /* __linux__ */
#define ssh_kernel_alloc_sa(a,b,c) ssh_kernel_alloc(a,b)
#define ssh_kernel_free_sa(a,b) ssh_kernel_free(a)
#endif /* __linux__ */

#ifdef  SSH_SAFENET_OCM_SA
static unsigned long ocm_sa_pool_handle = 0;
static Boolean ocm_sa_conf_ok = FALSE;
#endif


/******** LOCAL FUNCTIONS ***********/

static void* safenet_alloc_sa(unsigned long* p_addr_sa, size_t sa_size);
static void safenet_free_sa(const void* sa_data, size_t sa_size);
static const char *ssh_safenet_get_printable_status(int driver_status);
static Boolean safenet_is_pci_swapping(int device_num, 
				       const SLAD_DEVICEINFO* device_info);
static Boolean ssh_safenet_device_init(OSAL_NOTIFY* pdr_callback,
				       UINT32 device_num,
				       const SLAD_DEVICEINFO* device_info);

#ifdef SAFENET_DEBUG
static void print_safenet_device_info(int device_number, SLAD_DEVICEINFO info);
#endif /* SAFENET_DEBUG */

#ifdef SAFENET_DEBUG_HEAVY
static void print_safenet_pkt(SLAD_PKT *pkt);
static void print_safenet_sa(SLAD_SA *sa);
static void print_safenet_srec(SLAD_STATE_RECORD *srec);
#endif /* SAFENET_DEBUG_HEAVY */



/******** PE INIT/DEINIT **********/

/* Accelerator-specific de-initialization function. */
void  safenet_pe_uninit(UINT32 device_num)
{
#ifdef SSH_SAFENET_OCM_SA
  if (ocm_sa_conf_ok ==TRUE)
    { 
      int status = udm_free_pool_region(&ocm_sa_pool_handle);
      if (status != UDM_MEM_POOL_OK)
	{
	  SSH_DEBUG(SSH_D_FAIL,
		    ("Could not free OCM SA region from pool, status: %d",status));
	}

      status = udm_free_pool(ocm_sa_pool_handle);
      if (status != UDM_MEM_POOL_OK)
	{
	  SSH_DEBUG(SSH_D_FAIL,("Could not free OCM SA pool, status: %d",status));
	}
    }
#endif /* SSH_SAFENET_OCM_SA */
  slad_pe_uninit (app_id, device_num);
}


/* Accelerator-specific initialization function. Finds all accelerators,
   builds corresponding init blocks and initializes the driver
   
   device_callbacks - an array of glue layer callback functions, which 
   should be called when packets are processed by the Packet Engine and 
   ready to be received.
   
   device_count - as input is an expected number of accelerator devices 
   and the size of the device_callbacks[],this value should be big enough
   to possibly provide callbacks for a maximum number of devices.
   
   device_count - as output is a number of actually found accelerator devices.
*/
BOOL safenet_pe_init(PE_DEVICE_INIT device_init[], UINT32* device_count)
{
  Boolean found = FALSE;
  int status;
  UINT32 vers;
  UINT32 count;
  int i;
  SLAD_DEVICEINFO device_info;

  SSH_ASSERT(*device_count<=PE_MAX_DEVICES);

  memset(slad_pkt, 0, 
	 sizeof(SLAD_PKT)*PE_MAX_DEVICES*SSH_SAFENET_PDR_GET_COUNT);
  memset(slad_pktput, 0, 
	 sizeof(SLAD_PKT)*PE_MAX_DEVICES*SSH_SAFENET_PDR_GET_COUNT);
  
  for (i=0; i<*device_count; i++)
    { 
    
      device_init[i].found = FALSE;
      device_init[i].device_number = 0;
      slad_callbacks[i].process_id = device_init[i].device_callback.process_id;
      slad_callbacks[i].signal_number = 
	device_init[i].device_callback.signal_number;
      slad_callbacks[i].callback = 
	device_init[i].device_callback.callback;
    }

  /* Get driver version. */
  status = slad_driver_version (&vers);

  if (status != SLAD_DRVSTAT_SUCCESS)
    {
#ifdef SAFENET_DEBUG
      printk(KERN_NOTICE "Cannot determine the SLAD driver version %s\n",
             ssh_safenet_get_printable_status(status));
#endif /* SAFENET_DEBUG */

      return FALSE;
    }

#ifdef SAFENET_DEBUG
  printk(KERN_NOTICE  "SLAD version %x.%02x\n",
         (vers >> 24) & 0xff, (vers >> 16) &0xff);
#endif /* SAFENET_DEBUG */

  /*  prepare supported devices list */

  /* Get device info and store the number of devices */
  count = 0;
  for (i = 0 ; i < *device_count; i++)
    {
      status = slad_device_info (i, &device_info);

      if (status != SLAD_DRVSTAT_SUCCESS)
	{
#ifdef SAFENET_DEBUG
	  printk(KERN_NOTICE "Cannot get the device info driver version: %s\n",
		 ssh_safenet_get_printable_status(status));
#endif /* SAFENET_DEBUG */
	  continue;
	}

      found = TRUE;
      
      if (!ssh_safenet_device_init(&slad_callbacks[i], i, &device_info))
	{
#ifdef SAFENET_DEBUG
	  printk(KERN_NOTICE "Device init failed\n");
#endif /* SAFENET_DEBUG */
          return FALSE;
	}

      device_init[i].found = TRUE;
      device_init[i].device_number = i;
      count++;
       
#ifdef SAFENET_DEBUG
      print_safenet_device_info(i, device_info);
#endif /* SAFENET_DEBUG */
    }
  *device_count = count;
    
#ifdef SSH_SAFENET_OCM_SA
  {
    unsigned long  vaddr, paddr;
    int stat;

    paddr  = SSH_SAFENET_OCM_BASE + SSH_SAFENET_OCM_PDR_SIZE;

    stat = udm_map_n_pool_memory(&ocm_sa_pool_handle, 
				 &vaddr, paddr, SSH_SAFENET_OCM_SA_SIZE);
    if (stat == UDM_MEM_POOL_OK)
      {

        stat = 
	  udm_reserve_pool_region(&ocm_sa_pool_handle, 
				  sizeof(UDM_SA)+sizeof(UDM_STATE_RECORD),
				  SSH_SAFENET_OCM_SA_SIZE/(sizeof(UDM_SA)+sizeof(UDM_STATE_RECORD)),
				  0);
        if (stat == UDM_MEM_POOL_OK)
	  {
	    ocm_sa_conf_ok = TRUE;
	  }
      }
    if (ocm_sa_conf_ok != TRUE)
      {
	SSH_DEBUG(SSH_D_FAIL, 
		  ("Cannot allocate SA memory pool in OCM, off-chip memory will be used!"));
	status = stat;
      }
  }
#endif /* SSH_SAFENET_OCM_SA */
    

#ifdef SAFENET_DEBUG
  printk(KERN_NOTICE "The SLAD_SA size is %d bytes and the SLAD_STATE_RECORD "
	 "size is %d bytes\n", sizeof(SLAD_SA), sizeof(SLAD_STATE_RECORD));
#endif /* SAFENET_DEBUG */

  return found;
}



static Boolean ssh_safenet_device_init(OSAL_NOTIFY* pdr_callback, 
				       UINT32 device_num,
				       const SLAD_DEVICEINFO* device_info)
{
  INIT_BLOCK initblock;
  Boolean pci_swap;
  int status;
  
  /* Uninitialize the deivce before testing for PCI swapping */
  /*  udm_device_uninit(device->device_number);*/
  slad_pe_uninit (app_id, device_num);
  pci_swap = safenet_is_pci_swapping(device_num, device_info);

  /* Setup the initialization block */
  safenet_pe_setup_init_block(device_num, pdr_callback, pci_swap, &initblock);

  /* Initialize */
  status = slad_pe_init (&app_id, device_num, &initblock);


#ifdef SAFENET_DEBUG
  if (status != SLAD_DRVSTAT_SUCCESS)
    {
      printk(KERN_NOTICE "Cannot initialize the slad driver: %s\n",
             ssh_safenet_get_printable_status(status));
    }
#endif /* SAFENET_DEBUG */
  return (status == SLAD_DRVSTAT_SUCCESS);
}


/* Determine if data is being swapped across the PCI bus */
static Boolean safenet_is_pci_swapping(int device_num, 
				       const SLAD_DEVICEINFO* device_info)
{
  int swap = FALSE;

  return FALSE;

#ifdef SLAD_BIG_ENDIAN
  UINT32 d = 0;

  /* Set device's endian config register to disable all endian adjustment. */
  d = 0xe4e4e4e4;
  slad_bus_write (device_num, &d, 0xe0, sizeof(UINT32));

  /* Read the vendor/device id register. */
  slad_bus_read (device_num, &d, 0x84, sizeof(UINT32));

  /* If we did not get what we expected, assume swapping is
     ocurring over the PCI bus. */
  if (d != ((device_info->vendor_id << 16) |
            device_info->device_id))
    {
      swap = TRUE;
    }

#ifdef SAFENET_DEBUG
  printk(KERN_NOTICE "is pci swapping; d=0x%08x, swap=%d\n", d, swap);
#endif /* SAFENET_DEBUG */

#else /* SLAD_BIG_ENDIAN */

#ifdef SAFENET_DEBUG
  printk(KERN_NOTICE " no pci swapping \n");
#endif /* SAFENET_DEBUG */
#endif /* SLAD_BIG_ENDIAN */
  return swap;
}



/******** SA ALLOC API **********/


/* Allocates memory and builds SAs and related data for AH or ESP transforms
   type	    - in: for which transforms to build the SA (AH, ESP)
   flags     - in: transform options for building the SA
   sa_params - in: parameters for building the SA 
   (algorithms, keys,other items), 
   see PE_SA_PARAMS
   sa_data   - out: pointer to a memory block with initialized SA data
*/
BOOL safenet_pe_build_sa(int device_num, PE_SA_TYPE type, PE_FLAGS flags, 
			 PE_SA_PARAMS sa_params, void** sa_data)
{
  unsigned char inner[20]; /* inner precompute for HMAC */
  unsigned char outer[20]; /* outer precompute for HMAC */
  SLAD_STATE_RECORD srec;
  SLAD_SA sa;
  
  unsigned long p_addr_sa = 0;
  unsigned long p_addr_sa_stat = 0;
  void* mem_block;
  PE_SLAD_SA_ADAPTER* pslad_sa_adapter;
  SLAD_SA* psa;
  SLAD_STATE_RECORD* psrec;
  
  memset(inner, 0, 20);
  memset(outer, 0, 20);
  memset(&srec, 0, sizeof(srec));
  memset(&sa, 0, sizeof(sa));
  
  *sa_data = NULL;
  
  /***** Hash digest handling. ********/
  /* NOTE: Maybe it is a good idea to make it also platform-dependent, 
     sort of safenet_pe_populate_hmac() (see safenet_pe_populate_sa() below) */
  
  /* Compute the inner and outer hmac precomputes */
  if (sa_params.hash_alg != PE_HASH_ALG_NULL)
    if (!ssh_safenet_compute_hmac_precomputes(sa_params.hash_alg ==
					      PE_HASH_ALG_SHA1,
					      sa_params.mac_key,
					      sa_params.mac_key_len,
					      inner, outer))
      return FALSE;

  SSH_DEBUG_HEXDUMP(10, ("Inner HMAC digest"), inner, sizeof(inner));
  SSH_DEBUG_HEXDUMP(10, ("Outer HMAC digest"), outer, sizeof(outer));
 
  size_t digest_len = 0;

  /* Set the hash digest length */
  if (sa_params.hash_alg == PE_HASH_ALG_SHA1)
    digest_len = 20;
  else if (sa_params.hash_alg == PE_HASH_ALG_MD5)
    digest_len = 16;
  else if (type == PE_SA_TYPE_AH)
    return FALSE;

  /* Set the state record hash digest*/
  if (sa_params.hash_alg != PE_HASH_ALG_NULL)
    safenet_copy_key_material((BYTE *)srec.rev1.inner, inner, digest_len);
  srec.rev1.hash_count = 0;

  /* Set the SA hash digest */
  if (sa_params.hash_alg != PE_HASH_ALG_NULL)
    {
      /* Copy the hash digests. */
      safenet_copy_key_material(sa.rev1.inner, inner, digest_len);
      safenet_copy_key_material(sa.rev1.outer, outer, digest_len);
    }
 
  /****** Cipher key handling ********/
  /* Check the cipher key size */
  if (type == PE_SA_TYPE_ESP)
    {
      if (sa_params.ciph_alg == PE_CIPHER_ALG_DES &&
	  sa_params.ciph_key_len != 8)
	return FALSE;
      if (sa_params.ciph_alg == PE_CIPHER_ALG_TDES && 
	  sa_params.ciph_key_len != 24)
	return FALSE;
      if (sa_params.ciph_alg != PE_CIPHER_ALG_NULL)
	safenet_copy_key_material((BYTE *)sa.rev1.key1, 
				  sa_params.ciph_key, sa_params.ciph_key_len);
    }
  
  /******* SA content handling *********/ 
  if (!safenet_pe_populate_sa (type, flags, &sa,
			       sa_params.spi,
			       sa_params.seq,
			       sa_params.hash_alg,
			       sa_params.ciph_alg,
			       sa_params.ciph_key,
			       sa_params.ciph_key_len)
      )
    return FALSE;

  sa.rev1.srec = (UINT32)&srec;
  
  /********* Allocate an SA memory block *******/
  psa = safenet_alloc_sa(&p_addr_sa, sizeof(sa));
  if (!psa)
    return FALSE;

  psrec = safenet_alloc_sa(&p_addr_sa_stat, sizeof(srec));
  if (!psrec)
    return FALSE;

  pslad_sa_adapter = ssh_kernel_alloc(sizeof(PE_SLAD_SA_ADAPTER),
				      SSH_KERNEL_ALLOC_NOWAIT);
  if (!pslad_sa_adapter)
    return FALSE;
    
  *sa_data = pslad_sa_adapter;

                               
  /* Copy new SA into the allocated memory block */
  memcpy(psa, &sa, sizeof(sa));
  memcpy(psrec, &srec, sizeof(srec));
   
  /* Prepare SA and State record addresses in SLAD format */
  if (SLAD_SUCCESS != slad_register_sa (&pslad_sa_adapter->sa,
					psa, p_addr_sa, 
					sizeof(sa), 1))
    {
#ifdef SAFENET_DEBUG
      printk ("safenet_pe_build_sa(): slad_register_sa() for SA failed!\n");
#endif /*SAFENET_DEBUG*/
      return FALSE;
    }
  /*    
	#ifdef SSH_SAFENET_MIN_BYTE_SWAP
	ssh_swap_endian_w(&p_addr_sa_stat, 1);
	#endif /* SSH_SAFENET_MIN_BYTE_SWAP */
    
  pslad_sa_adapter->srec = NULL;
  if (SLAD_SUCCESS != slad_register_srec (device_num, 
					  &pslad_sa_adapter->sa, 
					  psrec, p_addr_sa_stat, 
					  sizeof (srec), 1))
    {
#ifdef SAFENET_DEBUG
      printk("safenet_pe_build_sa(): slad_register_srec() \
for State Record failed!\n");
#endif /*SAFENET_DEBUG*/
      return FALSE;
    }
  
  SSH_DEBUG(SSH_D_MIDOK,("SA bus addr=%x, SA virt addr=%x, \
SRec bus addr=%x, SRec virt addr=%x\n",
			 p_addr_sa,psa,p_addr_sa_stat,psrec));

#ifdef SAFENET_DEBUG_HEAVY
  print_safenet_sa(&sa);
  print_safenet_srec(&srec);
#endif /* SAFENET_DEBUG_HEAVY */


#ifdef SSH_SAFENET_MIN_BYTE_SWAP
  ssh_swap_endian_w((UINT32 *)psa, sizeof (SLAD_SA) / 4);
  ssh_swap_endian_w((UINT32 *)psrec, sizeof(SLAD_STATE_RECORD) / 4);
#endif /* SSH_SAFENET_MIN_BYTE_SWAP */



  return TRUE;
}



static void* safenet_alloc_sa(unsigned long* p_addr_sa, size_t sa_size)
{
  void *psa = NULL;

#ifdef SSH_SAFENET_SA_CACHE_ALIGN
  sa_size += (sizeof(void*) + (2 * L1_CACHE_BYTES));
#endif /* SSH_SAFENET_SA_CACHE_ALIGN */

#ifdef SSH_SAFENET_OCM_SA
  if (ocm_sa_conf_ok == TRUE)
    {
      unsigned long paddr;
      int stat = udm_get_blk_from_pool_region(ocm_sa_pool_handle,
					      (unsigned long*)&psa,&paddr) ;
      if (stat != 0)
	{
	  SSH_DEBUG(SSH_D_FAIL,("Could not get blocks from OCM \
SA memory pool, status: %d",stat));
	  psa = ssh_kernel_alloc_sa(sa_size, SSH_KERNEL_ALLOC_DMA);
	  if (psa == NULL)
	    return FALSE;
	}
    }
  else
    {
      psa = ssh_kernel_alloc_sa(sa_size, SSH_KERNEL_ALLOC_DMA);
      if (psa == NULL)
	return FALSE;
    }
#else
  psa = ssh_kernel_alloc_sa(sa_size, SSH_KERNEL_ALLOC_DMA, p_addr_sa);
  if (psa == NULL)
    return FALSE;
#endif /* SSH_SAFENET_OCM_SA */

#ifdef SSH_SAFENET_SA_CACHE_ALIGN
  {
    void**tmp;
    void *aligned_psa;
     
    /* orig-sa-address, |alignment boundary|, sa-address, srec */
    aligned_psa = (void *) L1_CACHE_ALIGN((int)psa);
    if ((unsigned int)(aligned_psa - psa) < sizeof(void *))
      {
	/* If there is not enough space to store the
	   non-cache-aligned A buffer address, shift SA buffer
	   by one cache line to make space in front of it */
        aligned_psa = (void *)
	  ((unsigned char *)aligned_psa + L1_CACHE_BYTES);
      }
    /* Store the original potentially non aligned address in
       front of aligned sa record */
    tmp = (void**)
      ((unsigned char *)aligned_psa - sizeof(void *));
    *tmp = psa;
    psa = aligned_psa;
  }
#endif /* SSH_SAFENET_SA_CACHE_ALIGN */
  return psa;
}



/* Frees any memory allocated with safenet_pe_build_sa for SAs and 
   related data for AH or ESP transforms
   sa_data   - in: pointer to a memory block with SA data
*/
void safenet_pe_destroy_sa(const void* sa_data)
{
  if (!sa_data)
    return;
  PE_SLAD_SA_ADAPTER* pslad_sa_adapter = (PE_SLAD_SA_ADAPTER*)sa_data;
  safenet_free_sa(pslad_sa_adapter->sa->sa_dma_obj.virt_addr, sizeof(SLAD_SA));
  safenet_free_sa(pslad_sa_adapter->sa->srec_dma_obj.virt_addr,
		  sizeof(SLAD_STATE_RECORD));
  ssh_kernel_free(pslad_sa_adapter);
}

static void safenet_free_sa(const void* sa_data, size_t sa_size)
{
  if (!sa_data)
    return;
#ifdef SSH_SAFENET_SA_CACHE_ALIGN
  sa_data = *(void **) ((unsigned char *)sa_data - sizeof(void *));
#endif
#ifdef SSH_SAFENET_OCM_SA
  if (ocm_sa_conf_ok == TRUE)
    {
      int stat = udm_put_blk_to_pool_region(ocm_sa_pool_handle,
					    (unsigned long)sa_data);
      if (stat == UDM_MEM_POOL_INVALID_VADDR)
	{
	  ssh_kernel_free_sa(sa_data, sa_size);
	}
      else if (stat != UDM_MEM_POOL_INVALID_VADDR && stat != UDM_MEM_POOL_OK)
	{
	  SSH_DEBUG(SSH_D_FAIL,("Cannot free OCM SA buffer, status: %d",stat));
	}
    }
  else
    {
      ssh_kernel_free_sa(sa_data, sa_size);
    }
#else
  ssh_kernel_free_sa(sa_data, sa_size);
#endif /* SSH_SAFENET_OSM_SA */
}



/******** PKTGET/PKTPUT API **********/

/* Use this to put a packet to be processed to the Packet Engine
   pkt is a points to a PE_PKT_DESCRIPTOR object for the packet
   to be sent to the Packet Engine for processing.
   Returns TRUE if the packet was sucessfully sent to the Packet Engine
*/
BOOL safenet_pe_pktput(int device_num, PE_PKT_DESCRIPTOR pkt[], UINT32 count)
{
  int status;
  SLAD_PKT slad_pkt1;
  UINT32 i;
  UINT32 fact_count;

  for(i=0; i<count; i++)
    {
      safenet_pe_pkt_to_slad_pkt(&pkt[i], &slad_pktput[device_num][i]);
    }
#ifdef SAFENET_DEBUG_HEAVY
  SSH_DEBUG(10, ("Before combined transform"));
  print_safenet_pkt(&slad_pkt1);
  print_safenet_sa((SLAD_SA *)((sa_handle)slad_pkt1.sa)->virt_addr);
  print_safenet_srec((SLAD_STATE_RECORD *)
		     ((sa_handle)slad_pkt1.srec)->virt_addr);
#endif /* SAFENET_DEBUG_HEAVY */

  fact_count = count;
  status = slad_pkt_put (app_id, device_num, 
			 slad_pktput[device_num], &fact_count);

  if (unlikely(status != SLAD_DRVSTAT_SUCCESS || fact_count != count))
    { 
      printk("slad pkt put failed, status %d\n", status);
      SSH_DEBUG(SSH_D_FAIL, ("slad pkt put failed, status %d", status));
      return FALSE;
    }
    
  return TRUE;
 
}



/* Use this to get completed packets from the Packet Engine
   The function returns PE_PKT_DESCRIPTOR objects in pkt if the 
   packets were successfully processed by the Packet Engine and 
   available for receiving.
   pcount is an output parameter and is the number of packets received.
   Returns FALSE if the packets cannot be received because of 
   the Packet Engine error.
*/
inline BOOL safenet_pe_pktget(int device_num, 
			      PE_PKT_DESCRIPTOR pkt[], UINT32* pcount)
{
  int status;
  UINT32 i;
  SLAD_PKT_BITS* pkt_bits;
  
  *pcount = SSH_SAFENET_PDR_GET_COUNT;
  status = slad_pkt_get (app_id, device_num, slad_pkt[device_num], pcount);
   
  /* Check status is ok */
    
  if (unlikely(status != SLAD_DRVSTAT_SUCCESS))
    {
      printk("Cannot retrieve packets from the pdr ring, status= %d\n", 
	     status);
      SSH_DEBUG(SSH_D_FAIL,
		("Cannot retrieve packets from the pdr ring, status= %d", 
		 status));
      return FALSE;
    }
    
  for(i=0; i<*pcount; i++)
    {
      pkt_bits = (SLAD_PKT_BITS*)&slad_pkt[device_num][i]; 
      safenet_pe_pkt_from_slad_pkt(&slad_pkt[device_num][i], &pkt[i]);

#ifdef SAFENET_DEBUG_HEAVY
      SSH_DEBUG(10, ("After combined transform"));
      print_safenet_pkt(&slad_pkt[device_num][i]);
      print_safenet_sa((SLAD_SA *)
		       ((sa_handle)slad_pkt[device_num][i].sa)->virt_addr);
      print_safenet_srec((SLAD_STATE_RECORD *)
			 ((sa_handle)slad_pkt[device_num][i].srec)->virt_addr);
#endif /* SAFENET_DEBUG_HEAVY */

      SSH_DEBUG(SSH_D_NICETOKNOW,
		("return len=%d, pad control=%d, next header=%d",
		 pkt_bits->len, pkt_bits->pad_control, pkt_bits->next_header));

    }
  return TRUE;
}

        
/************** Debugging help funtions *************************/

static const char *ssh_safenet_get_printable_status(int driver_status)
{
  switch (driver_status)
    {
    case SLAD_DRVSTAT_SUCCESS:
      return "The operation was successful";
    case SLAD_DRVSTAT_COMMAND_INVALID:
      return "The command was invalid";
    case SLAD_DRVSTAT_DEVICE_INVALID :
      return "Invalid device number specified";
    case SLAD_DRVSTAT_DEVICE_NOT_FOUND :
      return "Device not found";
    case SLAD_DRVSTAT_DEVICE_NOT_INIT :
      return "Device not initialized";
    case SLAD_DRVSTAT_CDR_FULL :
      return "CDR queue full";
    case SLAD_DRVSTAT_PDR_FULL :
      return "PDR command queue full";
    case SLAD_DRVSTAT_MALLOC_ERR :
      return "No memory available";
    case SLAD_DRVSTAT_UPLOAD_ERR :
      return "Device upload error";
    case SLAD_DRVSTAT_INIT_FAIL :
      return "Device initialization failed";
    case SLAD_DRVSTAT_CDR_EMPTY :
      return "CDR queue empty";
    case SLAD_DRVSTAT_PDR_EMPTY :
      return "PDR queue  empty";
    case SLAD_DRVSTAT_GDR_FULL :
      return "GDR queue full";
    case SLAD_DRVSTAT_IOCTL_ERR :
      return "IOCTL error";
    case SLAD_DRVSTAT_USERMODE_API_ERR :
      return "Usermode API error";
    case SLAD_DRVSTAT_BAD_PARAM_PDR_BUSID :
      return "Bad PDR busid";
    case SLAD_DRVSTAT_BAD_PARAM_PDR_ENTRIES :
      return "Bad number of PDR entries";
    case SLAD_DRVSTAT_BAD_PARAM_PDR_POLL_DELAY :
      return "Bad PDR poll delay";
    case SLAD_DRVSTAT_BAD_PARAM_PDR_DELAY_AFTER :
      return "Bad PDR delay after parameter";
    case SLAD_DRVSTAT_BAD_PARAM_PDR_INT_COUNT :
      return "Bad PDR int count parameter";
    case SLAD_DRVSTAT_BAD_PARAM_PDR_OFFSET :
      return "Bad PDR offset";
    case SLAD_DRVSTAT_BAD_PARAM_SA_BUSID :
      return "Bad SA busid";
    case SLAD_DRVSTAT_BAD_PARAM_SA_ENTRIES :
      return "Bad number of SA entries";
    case SLAD_DRVSTAT_BAD_PARAM_SA_CONFIG :
      return "Bad SA configuration parameter";
    case SLAD_DRVSTAT_BAD_PARAM_PAR_SRC_BUSID :
      return "Bad PAR source busid";
    case SLAD_DRVSTAT_BAD_PARAM_PAR_SRC_SIZE :
      return "Bad PAR source size";
    case SLAD_DRVSTAT_BAD_PARAM_PAR_DST_BUSID :
      return "Bad PAR desitination busid";
    case SLAD_DRVSTAT_BAD_PARAM_PAR_DST_SIZE :
      return "Bad PAR destination size";
    case SLAD_DRVSTAT_BAD_PARAM_PAR_CONFIG :
      return "Bad configuration parameter";
    case SLAD_DRVSTAT_INTERNAL_ERR :
      return "Internal error";
    default:
      return "Unknown Status";
    }
}


#ifdef SAFENET_DEBUG
static void print_safenet_device_info(int device_number, SLAD_DEVICEINFO info)
{
  printk(KERN_NOTICE " Printing Device Info for device %d....\n",
         device_number);

  printk(KERN_NOTICE " Device number:    %d\n", info.device_num);
  printk(KERN_NOTICE " Device type:      %x\n", info.device_type);
  printk(KERN_NOTICE " Base address:     %x\n", info.base_addr);
  printk(KERN_NOTICE " Address length:   %x\n", info.addr_len);
  printk(KERN_NOTICE " Vendor id:        %x\n", info.vendor_id);
  printk(KERN_NOTICE " Device id:        %x\n", info.device_id);

  if (info.features & DEVICEINFO_FEATURES_PE)
    printk(KERN_NOTICE "Packet engine is present\n");

  if (info.features & DEVICEINFO_FEATURES_HE)
    printk(KERN_NOTICE "Hash /Encrypt engine is present\n");

  if (info.features & DEVICEINFO_FEATURES_RNG)
    printk(KERN_NOTICE "RNG is present\n");

  if (info.features & DEVICEINFO_FEATURES_PKCP)
    printk(KERN_NOTICE "Public key coprocessor is present\n");

  if (info.features & DEVICEINFO_FEATURES_KMR)
    printk(KERN_NOTICE "Key management ring is present\n");

  if (info.features & DEVICEINFO_FEATURES_KCR)
    printk(KERN_NOTICE "KCR is present\n");

  if (info.features & DEVICEINFO_FEATURES_PKCP_PKE)
    printk(KERN_NOTICE "Public key accelerator present\n");

  if (info.features & DEVICEINFO_FEATURES_PKCP_PKECRT)
    printk(KERN_NOTICE "CRT algorithm is present\n");

  if (info.crypto_algs & DEVICEINFO_CRYPTO_ALGS_TDES)
    printk(KERN_NOTICE "TDES crypto algorithm is supported\n");

  if (info.crypto_algs & DEVICEINFO_CRYPTO_ALGS_DES)
    printk(KERN_NOTICE "DES crypto algorithm is supported\n");

  if (info.crypto_algs & DEVICEINFO_CRYPTO_ALGS_AES)
    printk(KERN_NOTICE "AES crypto algorithm is supported\n");

  if (info.crypto_algs & DEVICEINFO_CRYPTO_ALGS_ARCFOUR)
    printk(KERN_NOTICE "ARCFOUR crypto algorithm is supported\n");

  if (info.crypto_algs & DEVICEINFO_CRYPTO_ALGS_RC5)
    printk(KERN_NOTICE "RC5 crypto algorithm is supported\n");

  if (info.hash_algs & DEVICEINFO_HASH_ALGS_SHA1)
    printk(KERN_NOTICE "SHA1 hash algorithm is supported\n");

  if (info.hash_algs & DEVICEINFO_HASH_ALGS_MD5)
    printk(KERN_NOTICE "MD5 hash algorithm is supported\n");

  if (info.hash_algs & DEVICEINFO_HASH_ALGS_MD2)
    printk(KERN_NOTICE "MD2 hash algorithm is supported\n");

  if (info.hash_algs & DEVICEINFO_HASH_ALGS_RIPEMD128)
    printk(KERN_NOTICE "Ripemd128 hash algorithm is supported\n");

  if (info.hash_algs & DEVICEINFO_HASH_ALGS_RIPEMD160)
    printk(KERN_NOTICE "Ripemd160 hash algorithm is supported\n");

  if (info.comp_algs & DEVICEINFO_COMP_ALGS_DEFLATE)
    printk(KERN_NOTICE "Deflate compression algorithm is supported\n");

  if (info.pkt_ops & DEVICEINFO_PKT_OPS_ESP)
    printk(KERN_NOTICE "ESP transform is supported\n");

  if (info.pkt_ops & DEVICEINFO_PKT_OPS_AH)
    printk(KERN_NOTICE "AH transform is supported\n");

  if (info.pkt_ops & DEVICEINFO_PKT_OPS_IPCOMP)
    printk(KERN_NOTICE "IPComp transform is supported\n");

  return;
}
#endif /* SAFENET_DEBUG */


#ifdef SAFENET_DEBUG_HEAVY

static const char *opcode_text(UINT32 idx)
{
  switch (idx)
    {
    case SA_OPCODE_ENCRYPT: return "ENCRYPT";
    case SA_OPCODE_ENCRYPT_HASH: return "ENCRYPT-HASH";
    case SA_OPCODE_HASH: return "HASH";
    case SA_OPCODE_DECRYPT: return "DECRYPT";
    case SA_OPCODE_HASH_DECRYPT: return "HASH-DECRYPT";
    case SA_OPCODE_ESP_OUTBOUND: return "ESP-OUTBOUND";
    case SA_OPCODE_AH_OUTBOUND: return "AH-OUTBOUND";
    case SA_OPCODE_ESP_INBOUND: return "ESP-INBOUND";
    case SA_OPCODE_AH_INBOUND: return "AH-INBOUND";
    default:
      return "reserved";
    }
};

static const char *crypto_algo_text(UINT32 idx)
{
  switch (idx)
    {
    case SA_CRYPTO_DES:  return "DES";
    case SA_CRYPTO_TDES: return "3DES";
    case SA_CRYPTO_ARC4: return "ARC4";
    case SA_CRYPTO_AES:  return "AES";
    case SA_CRYPTO_NULL: return "NULL";
    default:
      return "reserved";
    }
};

static const char *hash_algo_text(UINT32 idx)
{
  switch (idx)
    {
    case SA_HASH_SHA1: return "SHA1";
    case SA_HASH_MD5:  return "MD5";
    case SA_HASH_NULL:  return "NULL";
    default:
      return "reserved";
    }
};

static const char *crypto_mode_text(UINT32 idx)
{
  switch (idx)
    {
    case SA_CRYPTO_MODE_ECB: return "ECB";
    case SA_CRYPTO_MODE_CBC: return "CBC";
    case SA_CRYPTO_MODE_OFB: return "OFB";
    case SA_CRYPTO_MODE_CFB: return "CFB";
    default:
      return "reserved";
    }
};

static const char *crypto_feedback_text(UINT32 idx)
{
  switch (idx)
    {
    case SA_CRYPTO_FEEDBACK_64: return "64-bit";
    case SA_CRYPTO_FEEDBACK_8:  return "8-bit";
    case SA_CRYPTO_FEEDBACK_1:  return "1-bit";
    default:
      return "reserved";
    }
};

static const char *crypto_pad_text(UINT32 idx)
{
  switch (idx)
    {
    case SA_PAD_IPSEC:    return "IPSEC";
    case SA_PAD_CONSTANT: return "CONSTANT";
    case SA_PAD_ZERO:     return "ZERO";
    default:
      return "reserved";
    }
};

static const char *iv_loading_text(UINT32 idx)
{
  switch (idx)
    {
    case SA_IV_REUSE: return "REUSE";
    case SA_IV_INPUT: return "INPUT";
    case SA_IV_STATE: return "STATE";
    default:
      return "reserved";
    }
};

static const char *hash_loading_text(UINT32 idx)
{
  switch (idx)
    {
    case SA_HASH_SA:      return "SA";
    case SA_HASH_STATE:   return "STATE";
    case SA_HASH_NO_LOAD: return "NO LOAD";
    default:
      return "reserved";
    }
};

static void print_safenet_pkt(SLAD_PKT *pkt)
{
  SLAD_PKT_BITS *pktb = (SLAD_PKT_BITS *)pkt;

  SSH_DEBUG(10, ("print_safenet_pkt; pkt = 0x%p", pkt));
  SSH_DEBUG(10, ("src = 0x%p", pkt->src));
  SSH_DEBUG(10, ("dst = 0x%p", pkt->dst));
  SSH_DEBUG(10, ("sa = 0x%p", pkt->sa));
  SSH_DEBUG(10, ("srec = 0x%p", pkt->srec));
  SSH_DEBUG(10, ("user_handle = 0x%p", pkt->user_handle));
  SSH_DEBUG(10, ("ready/done 1 = %d/%d", pktb->ready1, pktb->done1));
  SSH_DEBUG(10, ("pad_control = %x", pktb->pad_control));
  SSH_DEBUG(10, ("load_sa_digests = %d", pktb->load_sa_digests));
  SSH_DEBUG(10, ("hash_final = %d", pktb->hash_final));
  SSH_DEBUG(10, ("status = 0x%02x", pktb->status));
  SSH_DEBUG(10, ("len = %d", pktb->len));
  SSH_DEBUG(10, ("ready/done 2 = %d/%d", pktb->ready2, pktb->done2));
  SSH_DEBUG(10, ("bypass_offset = %d", pktb->bypass_offset));
  SSH_DEBUG(10, ("\n"));
}

static void print_safenet_sa(SLAD_SA *sa)
{
  SSH_DEBUG(10, ("print_safenet_sa; sa=0x%08x", (int)sa));
  SSH_DEBUG(10, ("opcode = 0x%02x(%s)",
		 sa->rev1.opcode, opcode_text(sa->rev1.opcode)));
  SSH_DEBUG(10, ("crypto_pad = 0x%02x(%s)",
                 sa->rev1.crypto_pad, crypto_pad_text(sa->rev1.crypto_pad)));
  SSH_DEBUG(10, ("crypto_algo = 0x%02x(%s)",
                 sa->rev1.crypto_algo,
                 crypto_algo_text(sa->rev1.crypto_algo)));
  SSH_DEBUG(10, ("hash_algo = 0x%02x(%s)",
                 sa->rev1.hash_algo, hash_algo_text(sa->rev1.hash_algo)));
  SSH_DEBUG(10, ("header_proc = %d", sa->rev1.header_proc));
  SSH_DEBUG(10, ("iv_loading = 0x%02x(%s)",
                 sa->rev1.iv_loading, iv_loading_text(sa->rev1.iv_loading)));
  SSH_DEBUG(10, ("hash_loading = 0x%02x(%s)",
                 sa->rev1.hash_loading,
                 hash_loading_text(sa->rev1.hash_loading)));
  SSH_DEBUG(10, ("save_iv/hash = %d/%d",
                 sa->rev1.save_iv, sa->rev1.save_hash));
  SSH_DEBUG(10, ("copy_header/payload/pad = %d/%d/%d",
                 sa->rev1.copy_header, sa->rev1.copy_payload,
                 sa->rev1.copy_pad));
  SSH_DEBUG(10, ("mutable_bits = %d", sa->rev1.mutable_bits));
  SSH_DEBUG(10, ("crypto_mode = 0x%02x(%s)",
                 sa->rev1.crypto_mode,
                 crypto_mode_text(sa->rev1.crypto_mode)));
  SSH_DEBUG(10, ("crypto_feedback = 0x%02x(%s)",
                 sa->rev1.crypto_feedback,
                 crypto_feedback_text(sa->rev1.crypto_feedback)));
  SSH_DEBUG(10, ("hmac = %d", sa->rev1.hmac));
  SSH_DEBUG(10, ("aes_decrypt_key = %d", sa->rev1.aes_decrypt_key));
  SSH_DEBUG(10, ("aes_key_len = %d", sa->rev1.arc4_aes_key_len));
  SSH_DEBUG(10, ("rev = %d", sa->rev1.rev));
  SSH_DEBUG(10, ("offset = %d", sa->rev1.offset));
  SSH_DEBUG(10, ("spi = 0x%08x", sa->rev1.spi));
  SSH_DEBUG(10, ("seq = 0x%08x", sa->rev1.seq));
  SSH_DEBUG(10, ("srec = 0x%08x", (int)sa->rev1.srec));
  SSH_DEBUG_HEXDUMP(10, ("key1 = "), sa->rev1.key1, sizeof (sa->rev1.key1));
  SSH_DEBUG_HEXDUMP(10, ("key2 = "), sa->rev1.key2, sizeof (sa->rev1.key2));
  SSH_DEBUG_HEXDUMP(10, ("key3 = "), sa->rev1.key3, sizeof (sa->rev1.key3));
  SSH_DEBUG_HEXDUMP(10, ("key4 = "), sa->rev1.key4, sizeof (sa->rev1.key4));
  SSH_DEBUG_HEXDUMP(10, ("inner = "), sa->rev1.inner, sizeof (sa->rev1.inner));
  SSH_DEBUG_HEXDUMP(10, ("outer = "), sa->rev1.outer, sizeof (sa->rev1.outer));
  SSH_DEBUG(10, ("\n"));
}

static void print_safenet_srec(SLAD_STATE_RECORD *srec)
{
  SSH_DEBUG(10, ("print_safenet_srec(); srec=0x%08x", (int)srec));
  SSH_DEBUG(10, ("hash_count = %d", srec->rev1.hash_count));

  SSH_DEBUG_HEXDUMP(10, ("srec IV"),
                    (unsigned char *)srec->rev1.iv,
                    sizeof(srec->rev1.iv));

  SSH_DEBUG_HEXDUMP(10, ("srec inner digest"),
                    (unsigned char *)srec->rev1.inner,
                    sizeof(srec->rev1.inner));
  SSH_DEBUG(10, ("\n"));
}
#endif /* SAFENET_DEBUG_HEAVY */

