/*
  safenet1x41_params.h

  Copyright:
 	Copyright (c) 2007 SFNT Finland Oy.
        All rights reserved.

       Tunable configuration parameters for safenet1x41.c 
*/

#ifndef SAFENET1X41_PARAMS_H
#define SAFENET1X41_PARAMS_H


/* How many UDM_PKT's to retrieve when calling udm_pkt_get. */
#ifdef SSH_SAFENET_AMCC_SUPPORT 
#define SSH_SAFENET_PDR_GET_COUNT 48
#else
#define SSH_SAFENET_PDR_GET_COUNT 10
#endif /* SSH_SAFENET_AMCC_SUPPORT */

/* The maximum number of operations allowed in the PDR queue ring. */
#define SSH_SAFENET_MAX_QUEUED_OPERATIONS 390

/* POLLING: Depending on the system properties it may be advisable to
   poll for results instead of receiving them from interrupts. This is
   true especially for the low CPU systems. */
#ifdef SSH_SAFENET_AMCC_SUPPORT
#define SSH_SAFENET_POLLING
#else
/* #define SSH_SAFENET_POLLING */
#endif /* SSH_SAFENET_AMCC_SUPPORT */

/* CACHE ALIGNMENT: Some systems get considerable performance gain if
   the SA record is cache aligned so that UDM does not have to do
   this. Currently this only works for LINUX. */

#ifdef SSH_SAFENET_AMCC_SUPPORT
/* Allocate non-cacheable memory buffers for SA records. This would
 *    remove data inconsistency between main memory and D-cache. */
#define SSH_SAFENET_NOT_COHERENT_CACHE 
#endif /* SSH_SAFENET_AMCC_SUPPORT */

/* The buffer for an SA passed to the SafeNet device driver will be allocated
   in memory cache-aligned and padded so that no other data resides
   in the same cache line. 
   This can be defined together with UDM_NO_CACHE_ALIGN_CHECK in device
   driver which will prevent the driver from allocating bounce buffers. 
   CAUTION: If defined application (Ethernet driver) should also supply 
   properly allocated packet buffers for udm_pkt_put() call! */

/*
#if defined(L1_CACHE_LINE_SIZE) && defined(L1_CACHE_ALIGN)
#define SSH_SAFENET_SA_CACHE_ALIGN
#endif
*/

/* Minimize the byte swapping performed by the driver for big endian
   CPUs with little endian packet engine that cannot perform endianness 
   conversion in HW such as AMCC 440EPx with EIP94 v1.2 PLB */
#ifdef SSH_SAFENET_AMCC_SUPPORT
#define SSH_SAFENET_MIN_BYTE_SWAP
#else
/* #define SSH_SAFENET_MIN_BYTE_SWAP */
#endif /* SSH_SAFENET_AMCC_SUPPORT */
#ifdef SSH_SAFENET_AMCC_SUPPORT
/* Utilize the internal SA cache of the packet engine. Packet engine must
 *    support this functionality before it can be enabled */
#define SSH_SAFENET_PE_SA_CACHING 
#endif /* SSH_SAFENET_AMCC_SUPPORT */

/* Perform zero-copying handling of packet data if possible. This define 
   should only be enabled on environments where packet data can be assumed 
   to be from DMA'able memory. This parameter cannot be enabled on non-Linux 
   platforms. */  
#undef SSH_SAFENET_PACKET_IS_DMA
#ifdef __linux__
#define SSH_SAFENET_PACKET_IS_DMA
#endif /* __linux__ */


/* Define this if you want to force the use of SA's in EMI memory. This 
   parameter is only relevant for 1840, 1841 and 1842 devices. This define 
   should normally be enabled by the configure option --enable-emi-memory.
   The user should not need to touch this define. */
/* #define SSH_SAFENET_USE_EMI_MEMORY 1 */

/* DEBUGGING: Displays profiling information, like the throughput and
   packet processing statistics. Do not use in production code, only
   for debugging purposes. */
#define SSH_SAFENET_PROFILING
#undef  SSH_SAFENET_PROFILING

/* DEBUGGING: Profiling rate in seconds if SSH_SAFENET_PROFILING is
   defined, 0 = never display. */
#define SSH_SAFENET_PROFILING_RATE_SEC 4

/* Define this to enable some extra debugging. No not enable in production 
   systems.  */
#define SAFENET_DEBUG
#undef  SAFENET_DEBUG

/* Define this to enable some extra heavy debugging. No not enable in 
   production systems. */
#define SAFENET_DEBUG_HEAVY
#undef  SAFENET_DEBUG_HEAVY

#endif /* SAFENET1X41_PARAMS_H */
