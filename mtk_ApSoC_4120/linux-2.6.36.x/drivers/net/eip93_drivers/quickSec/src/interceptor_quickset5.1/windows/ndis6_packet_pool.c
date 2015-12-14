/*
  ndis6_packet_pool.c

  Copyright:
          Copyright (c) 2006 - 2009 SFNT Finland Oy.
  All rights reserved.

  This file contains the (NDIS 6.0) packet pool creation and destruction
  functions. The actual packet manipulation functions are inlined to 
  packet processing paths from ndis_packet_pool.h (doesn't make any 
  sense to have extra function calls there).
  
*/

/*--------------------------------------------------------------------------
  INCLUDE FILES
  ------------------------------------------------------------------------*/

#include "sshincludes.h"
#include "interceptor_i.h"

/*--------------------------------------------------------------------------
  DEFINITIONS
  --------------------------------------------------------------------------*/
#define SSH_DEBUG_MODULE          "SshInterceptorPacketPool"

static void
ssh_init_net_buffer(PNET_BUFFER nb)
{
  nb->stDataLength = 0;
  NdisZeroMemory(&nb->ProtocolReserved, sizeof(nb->ProtocolReserved));
  NdisZeroMemory(&nb->MiniportReserved, sizeof(nb->MiniportReserved));
  NdisZeroMemory(&nb->DataPhysicalAddress, sizeof(nb->DataPhysicalAddress));
}


/*--------------------------------------------------------------------------
  EXPORTED FUNCTIONS
  --------------------------------------------------------------------------*/

Boolean
ssh_packet_pools_create(SshInterceptor interceptor)
{
  SshCpuContext cpu_ctx;
  SshPacketPool pool;
  SshNdisPacket packet;
  int i;
  NDIS_HANDLE nbl_pool_handle;
  NDIS_HANDLE nb_pool_handle;
  NET_BUFFER_LIST_POOL_PARAMETERS nbl_pool_params;
  NET_BUFFER_POOL_PARAMETERS nb_pool_params;
  SshUInt16 context_size;

  SSH_ASSERT(interceptor != NULL);
  SSH_ASSERT(interceptor->processor_count > 0);

  context_size = (sizeof(*packet) / MEMORY_ALLOCATION_ALIGNMENT);
  if (sizeof(*packet) % MEMORY_ALLOCATION_ALIGNMENT)
    context_size++;
  context_size *= MEMORY_ALLOCATION_ALIGNMENT;

  NdisZeroMemory(&nbl_pool_params, sizeof(nbl_pool_params));
  nbl_pool_params.ContextSize = context_size;
  nbl_pool_params.ProtocolId = NDIS_PROTOCOL_ID_DEFAULT;
  nbl_pool_params.fAllocateNetBuffer = 0;
  nbl_pool_params.DataSize = 0;
  nbl_pool_params.Header.Type = NDIS_OBJECT_TYPE_DEFAULT;
  nbl_pool_params.Header.Size = 
    NDIS_SIZEOF_NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1;
  nbl_pool_params.Header.Revision = 
    NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1;
  nbl_pool_params.PoolTag = 'KPNS'; /* "SafeNet PacKet" */

  nbl_pool_handle = NdisAllocateNetBufferListPool(NULL, &nbl_pool_params);
  if (nbl_pool_handle == NULL)
    goto failed;

  NdisZeroMemory(&nb_pool_params, sizeof(nb_pool_params));
  nb_pool_params.Header.Type = NDIS_OBJECT_TYPE_DEFAULT;
  nb_pool_params.Header.Size = 
    NDIS_SIZEOF_NET_BUFFER_POOL_PARAMETERS_REVISION_1;
  nb_pool_params.Header.Revision = NET_BUFFER_POOL_PARAMETERS_REVISION_1;
  nb_pool_params.DataSize = 0;
  nb_pool_params.PoolTag = 'FBNS'; /* "SafeNet BufFer" */

  nb_pool_handle = NdisAllocateNetBufferPool(NULL, &nb_pool_params);
  if (nb_pool_handle == NULL)
    {
      NdisFreeNetBufferListPool(nbl_pool_handle);
      goto failed;
    }

  for (i = 0; i < interceptor->processor_count; i++)
    {
      cpu_ctx = &interceptor->cpu_ctx[i];
      pool = &cpu_ctx->global_packet_pool;

      ssh_kernel_mutex_init(&cpu_ctx->global_packet_pool_lock);
      
      InitializeListHead(&pool->free_packet_list);
      InitializeListHead(&pool->free_buffer_list);






      pool->cpu_index = i;
      pool->packet_list_size = 0;
      pool->buffer_list_size = 0;
      pool->packet_count = 0;
      pool->buffer_count = 0;
      pool->packet_list_context = nbl_pool_handle;
      pool->buffer_list_context = nb_pool_handle;
    }

  for (i = 0; i < interceptor->processor_count; i++)
    {
      unsigned int j;

      cpu_ctx = &interceptor->cpu_ctx[i];
      pool = &cpu_ctx->packet_pool;

      InitializeListHead(&pool->free_packet_list);
      InitializeListHead(&pool->free_buffer_list);        





      
      pool->cpu_index = i;
      pool->packet_list_size = 0;
      pool->buffer_list_size = 0;
      pool->packet_count = 0;
      pool->buffer_count = 0;
      pool->packet_list_context = nbl_pool_handle;
      pool->buffer_list_context = nb_pool_handle;

      for (j = 0; j < SSH_INTERCEPTOR_PER_CPU_PACKET_POOL_SIZE; j++)
        {
          NET_BUFFER_LIST *nbl;
          int k;

          nbl = NdisAllocateNetBufferList(nbl_pool_handle, 
                                          context_size, 
                                          (USHORT)0);
          if (nbl == NULL)
            goto failed;

          NdisZeroMemory(&nbl->MiniportReserved, 
                         sizeof(nbl->MiniportReserved));
          NdisZeroMemory(&nbl->ProtocolReserved,
                         sizeof(nbl->ProtocolReserved));

          packet = SSH_PACKET_CTX(nbl);
          packet->np = nbl;
          packet->pool = pool;

#ifdef DEBUG_LIGHT
          packet->f.flags.in_free_list = 1;
#endif /* DEBUG_LIGHT */
          pool->packet_list_size++;
          pool->packet_count++;
          InsertTailList(&pool->free_packet_list, &packet->list_entry);

          for (k = 0; k < SSH_CLONE_BUF_DESCRIPTORS_PER_PACKET; k++) 
            {
              SshNdisBufferHeader header = &packet->clone_buffers[k];
              header->nb = NdisAllocateNetBuffer(nb_pool_handle, NULL, 0, 0);
              if (header->nb == NULL)
                goto failed;

              ssh_init_net_buffer(header->nb);

              header->plain_header = 1;
            }
        }

      for (j = 0; j < SSH_INTERCEPTOR_PER_CPU_BUFFER_POOL_SIZE; j++)
        {
          SshNdisBuffer buffer = ssh_calloc(1, sizeof(*buffer));

          if (buffer == NULL)
            goto failed;

          buffer->copy.mdl = IoAllocateMdl(buffer->copy.buffer, 
                                           sizeof(buffer->copy.buffer), 
                                           FALSE, FALSE, NULL);
          if (buffer->copy.mdl == NULL)
            {
              ssh_free(buffer);
              goto failed;
            }

          MmBuildMdlForNonPagedPool(buffer->copy.mdl);
          buffer->copy.orig_mdl = *buffer->copy.mdl;






          buffer->nb = NdisAllocateNetBuffer(nb_pool_handle, NULL, 0, 0);
          if (buffer->nb == NULL)
            {
              IoFreeMdl(buffer->copy.mdl);
              ssh_free(buffer);
              goto failed;
            }

          ssh_init_net_buffer(buffer->nb);

          SSH_RESET_BUFFER((SshNetDataBuffer)buffer, 0);

          buffer->pool = pool;
#ifdef DEBUG_LIGHT
          buffer->in_free_list = 1;
#endif /* DEBUG_LIGHT */
          pool->buffer_list_size++;
          pool->buffer_count++;
          InsertTailList(&pool->free_buffer_list, &buffer->list_entry);
        }
    }

  return TRUE;

 failed:

  ssh_log_event(SSH_LOGFACILITY_LOCAL0,
                SSH_LOG_CRITICAL,
                ("Failed to create Packet pool!"));
  ssh_packet_pools_destroy(interceptor);

  return FALSE;
}


void
ssh_packet_pools_destroy(SshInterceptor interceptor)
{
  int i, j;
  NDIS_HANDLE pool_handle;
  SshCpuContext cpu_ctx;

  SSH_ASSERT(interceptor != NULL);
  SSH_ASSERT(interceptor->processor_count > 0);

  for (j = 0; j < 2; j++)
    {
      for (i = 0; i < interceptor->processor_count; i++)
        {
          SshPacketPool pool;
          PLIST_ENTRY entry;

          cpu_ctx = &interceptor->cpu_ctx[i];
          if (j == 0)
            {
              pool = &cpu_ctx->global_packet_pool;

              ssh_kernel_mutex_uninit(&cpu_ctx->global_packet_pool_lock);
            }
          else
            {
              pool = &cpu_ctx->packet_pool;
            }

          while (!IsListEmpty(&pool->free_packet_list))
            {
              SshNdisPacket packet;
              int k;

#ifdef DEBUG_LIGHT
              SSH_ASSERT(pool->packet_count > 0);
              pool->packet_count--;
#endif /* DEBUG_LIGHT */
              entry = RemoveHeadList(&pool->free_packet_list);

              packet = CONTAINING_RECORD(entry, 
                                         SshNdisPacketStruct, 
                                         list_entry);

              for (k = 0; k < SSH_CLONE_BUF_DESCRIPTORS_PER_PACKET; k++)
                {
                  SshNdisBufferHeader header = &packet->clone_buffers[k];

                  if (header->nb)
                    NdisFreeNetBuffer(header->nb);
                }

              if (packet->np)
                NdisFreeNetBufferList(packet->np);
            }

          while (!IsListEmpty(&pool->free_buffer_list))
            {
              SshNdisBuffer buffer;

#ifdef DEBUG_LIGHT
              SSH_ASSERT(pool->buffer_count > 0);
              pool->buffer_count--;
#endif /* DEBUG_LIGHT */
              entry = RemoveHeadList(&pool->free_buffer_list);

              buffer = CONTAINING_RECORD(entry, 
                                         SshNdisBufferStruct, 
                                         list_entry);

              SSH_ASSERT(buffer->nb != NULL);
              NdisFreeNetBuffer(buffer->nb);

              SSH_ASSERT(buffer->copy.mdl != NULL);
              IoFreeMdl(buffer->copy.mdl);






              ssh_free(buffer);
            }
        }
    }

  cpu_ctx = &interceptor->cpu_ctx[0];

  pool_handle = cpu_ctx->global_packet_pool.buffer_list_context;
  if (pool_handle)
    NdisFreeNetBufferPool(pool_handle);

  pool_handle = cpu_ctx->global_packet_pool.packet_list_context;
  if (pool_handle)
    NdisFreeNetBufferListPool(pool_handle);
}

#ifndef SSH_PACKET_POOL_USE_INLINE_FUNCTIONS
#include "packet_pool_common.c"
#include "ndis6_packet_pool_impl.c"
#endif /* SSH_PACKET_POOL_USE_INLINE_FUNCTIONS */
