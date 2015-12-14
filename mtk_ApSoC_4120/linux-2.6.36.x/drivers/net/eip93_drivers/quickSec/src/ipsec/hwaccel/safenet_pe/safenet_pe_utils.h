/*

  safenet_pe_utils.h

  Copyright:
 	Copyright (c) 2007 - 2007 SFNT Vught.
        All rights reserved.

        Safenet Packet Engine Interface general utilities.
*/

#ifndef SAFENET_PE_UTILS_H
#define SAFENET_PE_UTILS_H

#include "safenet_pe.h"            /* PE API */
#include "sshincludes.h"           /* Useful Quicksec tools */
#include "kernel_alloc.h"          /* Quicksec kernel-mode memory allocation */


/******** API of utility functions for glue layer ***********/

void
safenet_copy_key_material(
        unsigned char *dst,
        const unsigned char *src,
        int len);

void
safenet_copy_key_material_uint32(
        uint32_t * dst,
        const unsigned char *src,
        int len);

Boolean
ssh_safenet_compute_hmac_precomputes(
        Boolean sha_hash,
        const unsigned char *key,
        size_t keylen,
        unsigned char inner[20],
        unsigned char outer[20]);

Boolean
ssh_safenet_compute_gcm_hashkey(
        const unsigned char *key,
        const size_t keylen,
        unsigned char hash_key[16]);
        
Boolean
ssh_safenet_compute_sha2_precomputes(
        const PE_HASH_ALG algo,
        const unsigned char * key,
        const size_t keylen,
        unsigned char * inner,
        unsigned char * outer,
        const unsigned int inner_outer_limit,
        unsigned int * const DigestLen_p);
        
#ifdef SSH_SAFENET_MIN_BYTE_SWAP
void
ssh_swap_endian_w (
        void * buf, 
        size_t num_of_words);
#endif /* SSH_SAFENET_MIN_BYTE_SWAP */


/******** SA buffer allocation API ***********/


/* Initialization of SA allocation API
   Returns implementation specific status
*/
int
safenet_alloc_sa_init(
        void* params);

/* Allocates SA data block
*/
void*
safenet_alloc_sa(
        unsigned long* p_addr_sa,
        const size_t sa_size);

/* Frees SA data block
*/
void
safenet_free_sa(
        const void* sa_data,
        const size_t sa_size);

void
safenet_alloc_sa_uninit(
        void);


/******** User-mode memory allocation routines ***********/

#ifndef KERNEL
	#undef SSH_SAFENET_PACKET_IS_DMA
	#define ssh_kernel_alloc(a,b) ssh_malloc(a)
	#define ssh_kernel_free ssh_free
#endif /* KERNEL */

        
#endif /* SAFENET_PE_UTILS_H */
