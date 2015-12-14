/*

  safenet_la_utils.c

  Copyright:
 	Copyright (c) 2007 - 2009 SFNT Vught.
        All rights reserved.

        Safenet Look-Aside Accelerator Packet Engine utilities
        for chips with the use of the driver.
*/

#include "safenet_pe_utils.h" /* API we implement */

#include "ip_cksum.h"
#include "sshcrypt.h"
#include "sshhash.h"
#include "sshhash_i.h"
#include "sha.h"
#include "sha256.h"
#include "sha512.h"
#include "md5.h"

#include "rijndael.h"

#include "basic_defs.h" 

#include "safenet_la_params.h"

#define SSH_DEBUG_MODULE "SshSafenet1x41"

/* Linux specific includes we use for
   kernel-mode memory allocation routines */
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
/* there is no automatically coherent I/O */
	    #if (LINUX_VERSION_CODE >= KERNEL_VERSION (2,6,0))
		    #include <linux/dma-mapping.h>
		#else
		    #include <linux/pci.h>
		#endif
	#endif /* SSH_SAFENET_NOT_COHERENT_CACHE */

    #endif /* __linux__ */
#endif /* KERNEL */


/******** API of utility functions for glue layer ***********/

/* The Safenet device requires as input the HMAC inner and outer precomputes
   when creating SA's and not the usual HMAC key.
   This function computes the HMAC precomputes for SHA-2 from the HMAC key. */
Boolean
ssh_safenet_compute_sha2_precomputes(
        const PE_HASH_ALG algo,
        const unsigned char * key,
        const size_t keylen,
        unsigned char * inner,
        unsigned char * outer,
        const unsigned int inner_outer_limit,
        unsigned int * const DigestLen_p)
{
    #define SAFENET_LA_UTILS_MAX_SHA2_BLOCKSIZE 128
    Boolean res = FALSE;
    unsigned char authdata[SAFENET_LA_UTILS_MAX_SHA2_BLOCKSIZE];    
    unsigned int i=0;
    unsigned int blocksize = 64; 
    /* cannot be greater than SAFENET_LA_UTILS_MAX_SHA2_BLOCKSIZE */
    void* ctx =  NULL;
    size_t ctx_size = 0;
    unsigned int wordSwap = 0; 
    /* whether word swap is required for SHA512 and SHA384 algorithms */
    
    SSH_ASSERT(DigestLen_p != NULL);
    SSH_ASSERT(inner != NULL);
    SSH_ASSERT(outer != NULL);
    SSH_ASSERT(key != NULL);

    *DigestLen_p = 0;
    
    switch (algo)
    {
      case PE_HASH_ALG_SHA256:
        ctx_size =  ssh_sha256_ctxsize();
        *DigestLen_p = 32;
        blocksize = 64;
        break;
      case PE_HASH_ALG_SHA512:
        ctx_size =  ssh_sha512_ctxsize();
        *DigestLen_p = 64;
        blocksize = 128;
#ifdef PE_REQUIRES_SWAP
        wordSwap = 0;
#else
        wordSwap = 1;
#endif
        break;
      case PE_HASH_ALG_SHA384:
        ctx_size =  ssh_sha512_ctxsize();
        *DigestLen_p = 64;
        blocksize = 128;
#ifdef PE_REQUIRES_SWAP
        wordSwap = 0;
#else
        wordSwap = 1;
#endif
        break;
      default:
        SSH_DEBUG(SSH_D_FAIL, (": "
                  "Unknown hash algorithm specified - %d\n",
                  algo));
        goto DONE;
    }    
    
    SSH_ASSERT(blocksize <= SAFENET_LA_UTILS_MAX_SHA2_BLOCKSIZE);
    
    if (*DigestLen_p > inner_outer_limit)
    {
        SSH_DEBUG(SSH_D_FAIL, (": "
                  "Not enough space provided for Inner and Outer digest "
		  "- %d, need at least %d bytes\n",
                  inner_outer_limit, *DigestLen_p));
        goto DONE;
    }
    
    if (keylen > blocksize)
    {
        SSH_DEBUG(SSH_D_FAIL, (": "
                  "Key length (%d) is greater than the Block size (%d)\n",
                  keylen, blocksize));
        return FALSE;
    }
    
    ctx = ssh_kernel_alloc(ctx_size,
                         SSH_KERNEL_ALLOC_NOWAIT);
    if (ctx == NULL)
    {
        goto DONE;
    }
    /* prepare context for inner digest */
    memset(ctx, 0, ctx_size);
    switch (algo)
    {
      case PE_HASH_ALG_SHA256:
        ssh_sha256_reset_context(ctx);
        break;
      case PE_HASH_ALG_SHA512:
        ssh_sha512_reset_context(ctx);
        break;      
      case PE_HASH_ALG_SHA384:
        ssh_sha384_reset_context(ctx);
        break;
      default:
        goto DONE;
    }

    /* inner digest */
    memcpy(authdata, key, keylen);
    memset(authdata+keylen, 0, blocksize - keylen);

    for (i=0; i < blocksize; i++) 
        authdata[i] ^= 0x36;

    #ifdef SAFENET_DEBUG_HEAVY
      SSH_DEBUG_HEXDUMP(SSH_D_LOWOK, ("authdata for inner digest"), 
			authdata, blocksize);
    #endif    

    switch (algo)
    {
      case PE_HASH_ALG_SHA256:
        ssh_sha256_update(ctx, authdata, blocksize);
        break;
      case PE_HASH_ALG_SHA512:
      case PE_HASH_ALG_SHA384:      
        ssh_sha512_update(ctx, authdata, blocksize);
        break;
      default:
        goto DONE;
    }
    
    
    for (i = 0; i < *DigestLen_p/4; i++)
    {
      unsigned int srcIndex = (i & 1) ? (i - wordSwap) : (i + wordSwap);
      SSH_PUT_32BIT_LSB_FIRST(inner + i*4, ((SshUInt32*)ctx)[srcIndex]);
    }
    
    
    /* prepare context for outer digest */
    memset(ctx, 0, ctx_size);
    switch (algo)
    {
      case PE_HASH_ALG_SHA256:
        ssh_sha256_reset_context(ctx);
        break;
      case PE_HASH_ALG_SHA512:
        ssh_sha512_reset_context(ctx);
        break;      
      case PE_HASH_ALG_SHA384:
        ssh_sha384_reset_context(ctx);
        break;
      default:
        goto DONE;
    }

    /* outer digest */
    memcpy(authdata, key, keylen);
    memset(authdata+keylen, 0, blocksize - keylen);

    for (i=0; i < blocksize; i++) 
        authdata[i] ^= 0x5c;

    #ifdef SAFENET_DEBUG_HEAVY
      SSH_DEBUG_HEXDUMP(SSH_D_LOWOK, ("authdata for outer digest"), 
			authdata, blocksize);
    #endif    
    
    switch (algo)
    {
      case PE_HASH_ALG_SHA256:
        ssh_sha256_update(ctx, authdata, blocksize);
        break;
      case PE_HASH_ALG_SHA512:
      case PE_HASH_ALG_SHA384:      
        ssh_sha512_update(ctx, authdata, blocksize);
        break;
      default:
        goto DONE;
    }
    
      
    for (i = 0; i < *DigestLen_p/4; i++)
    {
      unsigned int srcIndex = (i & 1) ? (i - wordSwap) : (i + wordSwap);
      SSH_PUT_32BIT_LSB_FIRST(outer + i*4, ((SshUInt32*)ctx)[srcIndex]);
    }
    

    res = TRUE;

    #ifdef SAFENET_DEBUG_HEAVY
      SSH_DEBUG_HEXDUMP(SSH_D_LOWOK, ("Key"), key, keylen);
      SSH_DEBUG_HEXDUMP(SSH_D_LOWOK, ("Inner digest"), inner, *DigestLen_p);
      SSH_DEBUG_HEXDUMP(SSH_D_LOWOK, ("Outer digest"), outer, *DigestLen_p);
    #endif

DONE:
    if (ctx)
        ssh_kernel_free(ctx);
    return res;
}



/* The Safenet device requires as input the GHash key
   when creating SA's for AES_GCM transform.
   This function computes the GHash key using the AES Cipher key.
   GHash key is a block of 16 '0' bytes encrypted with AES.
*/
Boolean
ssh_safenet_compute_gcm_hashkey(
        const unsigned char *key,
        const size_t keylen,
        unsigned char hash_key[16])
{
    SshCryptoStatus status = SSH_CRYPTO_OK;
    Boolean res = FALSE;
    unsigned char dummy_iv[16];
    
    void* ctx = 
        ssh_kernel_alloc(ssh_rijndael_ctxsize(),
                         SSH_KERNEL_ALLOC_NOWAIT);
    if (ctx == NULL)
    {
        goto DONE;
    }

    status = ssh_aes_init(ctx,
                          key,
                          keylen,
                          TRUE);
    if (status != SSH_CRYPTO_OK)
    {
        goto DONE;
    }

    memset(hash_key, 0, 16 ); /* 128 bit */
    memset(dummy_iv, 0, sizeof(dummy_iv));

    /* Encryption and decryption in electronic codebook mode */
    status = ssh_rijndael_ecb(ctx,
                              hash_key, /* unsigned char *dest */
			      hash_key, /* const unsigned char *src */
			      16,       /* size_t len, in bytes */
			      dummy_iv);/* unsigned char *iv */
    if (status != SSH_CRYPTO_OK)
    {    
        goto DONE;
    }

    res = TRUE;

    #ifdef SAFENET_DEBUG_HEAVY
      SSH_DEBUG_HEXDUMP(SSH_D_LOWOK, ("Key"), key, keylen);
      SSH_DEBUG_HEXDUMP(SSH_D_LOWOK, ("GCM hash key"), hash_key, 16);
    #endif

DONE:
    if (ctx)
        ssh_kernel_free(ctx);
    return res;
}



/* The Safenet device requires as input the HMAC inner and outer precomputes
   when creating SA's and not the usual HMAC key. This computes the HMAC
   precomputes from the HMAC key. */
Boolean
ssh_safenet_compute_hmac_precomputes(Boolean sha_hash,
                                     const unsigned char *key,
                                     size_t keylen,
                                     unsigned char inner[20],
                                     unsigned char outer[20])
{
  unsigned char ipad[64];
  unsigned char opad[64];
  SshUInt32 buf[5];
  int i;

  buf[0] = 0x67452301L;
  buf[1] = 0xefcdab89L;
  buf[2] = 0x98badcfeL;
  buf[3] = 0x10325476L;
  buf[4] = 0xc3d2e1f0L;

  for (i = 0; i < 64; i++)
    {
      ipad[i] = 0x36;
      opad[i] = 0x5c;
    }

  if (keylen > 64)
    return FALSE;

  for (i = 0; i < keylen; i++)
    {
      ipad[i] ^= key[i];
      opad[i] ^= key[i];
    }

  if (sha_hash)
    ssh_sha_transform(buf, ipad);
  else
    ssh_md5_transform(buf, ipad);

  SSH_PUT_32BIT_LSB_FIRST(inner, buf[0]);
  SSH_PUT_32BIT_LSB_FIRST(inner + 4, buf[1]);
  SSH_PUT_32BIT_LSB_FIRST(inner + 8, buf[2]);
  SSH_PUT_32BIT_LSB_FIRST(inner + 12, buf[3]);
  SSH_PUT_32BIT_LSB_FIRST(inner + 16, buf[4]);

  buf[0] = 0x67452301L;
  buf[1] = 0xefcdab89L;
  buf[2] = 0x98badcfeL;
  buf[3] = 0x10325476L;
  buf[4] = 0xc3d2e1f0L;

  if (sha_hash)
    ssh_sha_transform(buf, opad);
  else
    ssh_md5_transform(buf, opad);

  SSH_PUT_32BIT_LSB_FIRST(outer, buf[0]);
  SSH_PUT_32BIT_LSB_FIRST(outer + 4, buf[1]);
  SSH_PUT_32BIT_LSB_FIRST(outer + 8, buf[2]);
  SSH_PUT_32BIT_LSB_FIRST(outer + 12, buf[3]);
  SSH_PUT_32BIT_LSB_FIRST(outer + 16, buf[4]);

  #ifdef SAFENET_DEBUG_HEAVY
      SSH_DEBUG_HEXDUMP(SSH_D_LOWOK, ("Key"), key, keylen);
      SSH_DEBUG_HEXDUMP(SSH_D_LOWOK, ("Inner digest"), inner, 20);
      SSH_DEBUG_HEXDUMP(SSH_D_LOWOK, ("Outer digest"), outer, 20);
  #endif
  return TRUE;
}


void
safenet_copy_key_material(
        unsigned char *dst,
        const unsigned char *src,
        int len)
{
	#ifdef PE_REQUIRES_SWAP
	  int i;
	
	  /* Swap byte order of each 4 bytes. */
	  for (i = 0; i < len; i += 4)
	    {
	      dst[i + 0] = src[i + 3];
	      dst[i + 1] = src[i + 2];
	      dst[i + 2] = src[i + 1];
	      dst[i + 3] = src[i + 0];
	    }
	#else
	  /* No endian issues, just a regular copy. */
	  memcpy(dst, src, len);
	#endif
}


#ifdef SSH_SAFENET_MIN_BYTE_SWAP
static void st_le32(uint32_t *a)
{
	uint32_t tmp;

	tmp = 0;
	tmp |= (*a)<<24 && ~(0x00ffffff) ;
	tmp |= (*a)>>24 && ~(0xffffff00) ;
	tmp |= (*a)<<8 && ~(0xff00ffff) ;
	tmp |= (*a)>>8 && ~(0xffff00ff) ;
	*a = tmp;
}

void ssh_swap_endian_w (void * buf, size_t num_of_words)
{
   int i = 0;
   for (i = 0; i < num_of_words; i++)
   {
      //st_le32( (uint32_t *)buf + i, *((uint32_t *)buf + i));
	  st_le32( (uint32_t *)buf + i);
   }
}
#endif /* SSH_SAFENET_MIN_BYTE_SWAP */



/******** SA buffer allocation API ***********/

/* 1. Useful memory allocation macros
   for Linux kernel-mode memory allocation  */
#ifdef __linux__
    
    #if defined(SSH_SAFENET_NOT_COHERENT_CACHE)
/* there is no automatically coherent I/O */

        #if (LINUX_VERSION_CODE >= KERNEL_VERSION (2,6,0))
	    /* Only for Linux 2.6: */
	        
	    /*If SSH_SAFENET_NOT_COHERENT_CACHE is defined we don't need
	      SSH_SAFENET_SA_CACHE_ALIGN */
			#undef SSH_SAFENET_SA_CACHE_ALIGN
			
			static inline void*
			safenet_alloc_coherent(
			        size_t size,
			        int flag,
			        unsigned long *p_addr)
			{
				dma_addr_t dma_handle = 0;
				void *p;
				p = dma_alloc_coherent(NULL, 
                                    size, &dma_handle, GFP_ATOMIC|GFP_DMA);
			        if (NULL == p)
			        {
			          #ifdef SAFENET_DEBUG
				  SSH_DEBUG(SSH_D_FAIL, 
                                            ("dma_alloc_coherent failed."));
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
			
			static inline void
			safenet_free_coherent(
			        void *vaddr,
			        size_t size)
			{
				dma_free_coherent(NULL,size, vaddr,0);
			}
			
	    #else
	    /* Only for Linux 2.4: */
	
			/*SSH_SAFENET_SA_CACHE_ALIGN must be defined -
			   cache alignment is required because Linux 2.4 
			   does not guarantee cache coherency */
			#define SSH_SAFENET_SA_CACHE_ALIGN
	
			static inline void*
			safenet_alloc_coherent(
			        size_t size,
			        int flag,
			        unsigned long *p_addr)
			{
				dma_addr_t bus_addr = 0;
				void *p;
				
				p = pci_alloc_consistent(NULL, 
                                                         size, &bus_addr);
			    if (NULL == p)
			    {
			          #ifdef SAFENET_DEBUG
			      SSH_DEBUG (SSH_D_FAIL, 
                                          ("pci_alloc_consistent failed.\n"));
			          #endif /* SAFENET_DEBUG */         
			          return NULL;
			    }
			    else
			    {
					if (p_addr)
			  	    	*p_addr = bus_addr;
				  	 return p;
				}
				return NULL;
			}
			
			static inline void
			safenet_free_coherent(
			        void *vaddr,
			        size_t size)
			{
				pci_free_consistent(NULL,size, vaddr,0);
			}
	
	    #endif /* LINUX_VERSION_CODE >= KERNEL_VERSION (2,6,0) */
#define ssh_kernel_alloc_sa(a,b,c) safenet_alloc_coherent(a,b,c)
#define ssh_kernel_free_sa(a,b) safenet_free_coherent(a,b)

    #else /*SSH_SAFENET_NOT_COHERENT_CACHE*/
/* Platform I/O is automatically cache coherent,
   so we don't need to worry about allocation of cache-coherent memory
   We use defaults provided by Quicksec */

#define ssh_kernel_alloc_sa(a,b,c) ssh_kernel_alloc(a,b)
#define ssh_kernel_free_sa(a,b) ssh_kernel_free(a)

    #endif /*SSH_SAFENET_NOT_COHERENT_CACHE*/

#else /* __linux__ */
/* For non-Linux we use defaults provided by Quicksec */

    #define ssh_kernel_alloc_sa(a,b,c) ssh_kernel_alloc(a,b)
    #define ssh_kernel_free_sa(a,b) ssh_kernel_free(a)
    
#endif /* __linux__ */



/* SA buffer allocation routines */

#ifdef SSH_SAFENET_OCM_SA
  #define SSH_SAFENET_OCM_BASE          0xe0010000UL            
/* 440EPx/GRx On Chip Memory base address */
  #define SSH_SAFENET_OCM_SIZE          0x4000UL                
/* 440EPx/GRx OCM size, 16 KB */
  #define SSH_SAFENET_PD_LEN            0x14UL                  
/* Packet decriptor length in bytes in 440EPx/GRx OCM */
  #define SSH_SAFENET_OCM_PDR_SIZE  \
    ((unsigned long)SSH_SAFENET_NR_PDR_ENTRIES*SSH_SAFENET_PD_LEN) 
/* PDR size in 440EPx/GRx OCM */
  #define SSH_SAFENET_OCM_SA_SIZE   \
    (SSH_SAFENET_OCM_SIZE-(unsigned long)SSH_SAFENET_OCM_PDR_SIZE) 
/* SA area size in 440EPx/GRx OCM */
#endif


#ifdef  SSH_SAFENET_OCM_SA
  static unsigned long ocm_sa_pool_handle = 0;
  static Boolean ocm_sa_conf_ok = FALSE;
#endif

int
safenet_alloc_sa_init(
        void* params)
{
  #ifdef SSH_SAFENET_OCM_SA
  {
     unsigned long  vaddr, paddr;
     int stat;

     paddr  = SSH_SAFENET_OCM_BASE + SSH_SAFENET_OCM_PDR_SIZE;

     stat = udm_map_n_pool_memory(&ocm_sa_pool_handle, 
				  &vaddr, paddr, SSH_SAFENET_OCM_SA_SIZE);
     if (stat == UDM_MEM_POOL_OK)
     {

        stat = udm_reserve_pool_region(&ocm_sa_pool_handle,
				       sizeof(UDM_SA)+sizeof(UDM_STATE_RECORD),
	 SSH_SAFENET_OCM_SA_SIZE/(sizeof(UDM_SA)+sizeof(UDM_STATE_RECORD)),0);
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
  
  return TRUE;

}


void*
safenet_alloc_sa(
        unsigned long* p_addr_sa,
        size_t sa_size)
{
	void *psa = NULL;

    #ifdef SSH_SAFENET_SA_CACHE_ALIGN
	    sa_size += (sizeof(void*) + (2 * L1_CACHE_BYTES));
    #endif /* SSH_SAFENET_SA_CACHE_ALIGN */

    #ifdef SSH_SAFENET_OCM_SA
	          /*accel->ah.sa_len = sa_size;*/
	   if (ocm_sa_conf_ok == TRUE)
	   {
	     unsigned long paddr;
	     int stat = udm_get_blk_from_pool_region(ocm_sa_pool_handle,
	                                             (unsigned long*)&psa,
	                                             &paddr);
	     if (stat != 0)
	     {
	       SSH_DEBUG(SSH_D_FAIL,
          ("Could not get blocks from OCM SA memory pool, status: %d",stat));
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
	   /*accel->ah.sa_len = sa_size;*/
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
	     *p_addr_sa += aligned_psa - psa;
	     
         SSH_DEBUG(SSH_D_NICETOKNOW,
             ("new phys SA addr %x, aligned_psa - psa = %x", 
	      *p_addr_sa, aligned_psa - psa));
         
	     psa = aligned_psa;
	   }
    #endif /* SSH_SAFENET_SA_CACHE_ALIGN */
    return psa;
}



void
safenet_free_sa(
        const void* sa_data,
        size_t sa_size)
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
    ssh_kernel_free_sa((void *)sa_data, sa_size);
#endif /* SSH_SAFENET_OSM_SA */
}

void
safenet_alloc_sa_uninit(
        void)
{
    return;
}

