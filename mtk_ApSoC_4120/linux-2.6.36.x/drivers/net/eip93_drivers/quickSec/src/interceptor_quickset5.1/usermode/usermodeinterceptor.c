/*

 usermodeinterceptor.c

  Copyright:
          Copyright (c) 2002, 2003 SFNT Finland Oy.
              All rights reserved.

This file implements a user-mode packet interceptor that talks to the
forwarder engine in the kernel.  This interceptor is used by programs
needing the interceptor services on the user level.

*/

#include "sshincludes.h"
#include "sshmutex.h"
#include "sshcondition.h"
#include "sshthreadedmbox.h"
#include "usermodeinterceptor.h"
#ifndef INTERCEPTOR_PROVIDES_MACSEC
#include "ip_cksum.h"
#endif /* not INTERCEPTOR_PROVIDES_MACSEC */
#include "sshfdstream.h"


/* Notice about memory allocation:

   Though we *know* this module is executed in user context, we still
   program this module as it was in kernel mode (since semantically
   that is where it is), thus using ssh_k*alloc routines and checking
   their return values --- even if we know they're really ssh_x*alloc
   versions and would never return a NULL value.

   Except the packet manipulation routines use ssh_x* versions,
   because they have their own allocation failure points.
 */


#define SSH_DEBUG_MODULE "SshUserModeInterceptor"




#define SSH_DUMP_PACKET(level, str, pp)                                 \
  {                                                                     \
      size_t packet_len, len; const unsigned char *seg;                 \
      packet_len = ssh_interceptor_packet_len(pp);                      \
      SSH_DEBUG((level), ("%s (len=%ld flags=0x%lx)",                   \
                          (str), (long)packet_len,                      \
                          (long)pp->flags));                            \
      ssh_interceptor_packet_reset_iteration(pp, 0, packet_len);        \
      while                                                             \
        (ssh_interceptor_packet_next_iteration_read(pp, &seg, &len))    \
          SSH_DEBUG_HEXDUMP((level),                                    \
                            ("seg len %lx:", (long)len), seg, len);     \
      if (seg != NULL) ssh_fatal("SSH_DUMP_PACKET freed the packet");   \
  }

/* This is an ugly kludge to allow initialization of the engine without
   being in thread_mbox "thread context.  */ 





#ifdef SSH_ASSERT_THREAD
#undef SSH_ASSERT_THREAD
#define SSH_ASSERT_THREAD()
#endif /* SSH_ASSERT_THREAD */

/* Pointer to the interceptor object.  Only one interceptor is supported by
   this implementation. */
SshInterceptor ssh_usermode_interceptor = NULL;

/* Pointer to timeouts object. This is initialized and uninitialized
   in _init and _uninit routines, eg. before interceptor_open and
   ssh_usermode_interceptor variable init */
SshInterceptorTimeouts ssh_usermode_timeouts = NULL;

/* Flags for the usermode interceptor.  These can be used to cause it
   to generate fake errors at random. */
SshUInt32 ssh_usermode_interceptor_flags = SSH_USERMODE_DEFAULT_FLAGS;

/* Maximum MTU for any interface shown to the engine.  If this is zero,
   there is no limit. */
SshUInt32 ssh_usermode_interceptor_max_mtu = 0;

/* Thread-boundary mbox. */
SshThreadedMbox thread_mbox = NULL;

/* This routine is invoked through the mbox in the thread context */
static void packet_recv(void *ctx)
{
  SshInterceptorPacket pp = (SshInterceptorPacket)ctx;
  SshInterceptor interceptor = ssh_usermode_interceptor;

  SSH_ASSERT_THREAD();

  SSH_DUMP_PACKET(SSH_D_PCKDMP, "interceptor receive", pp);

  (*interceptor->packet_cb)(pp, interceptor->packet_cb_context);

  ssh_mutex_lock(interceptor->mutex);
  interceptor->num_outcalls--;
  SSH_DEBUG(9, ("outcalls-- -> %d.", (int) interceptor->num_outcalls));
  ssh_mutex_unlock(interceptor->mutex);
}

/* Process a network packet message received from the kernel. Called
   in eloop context. */
void ssh_kernel_receive_packet(SshInterceptor interceptor,
                               const unsigned char *data, size_t len)
{
  SshUInt32 flags, ifnum_in, ifnum_out, protocol;
#if (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0)
  unsigned char extbuf[SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS * 4];
#endif /* (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0) */
  unsigned char *packet_ptr, *internal_ptr;
  size_t packet_len, internal_len;
  SshInterceptorPacket pp;

  SSH_ASSERT_ELOOP();

  SSH_DEBUG(SSH_D_MIDSTART, ("receive packet"));

  /* Decode the packet from the kernel. */
  if (ssh_decode_array(data, len,
                       SSH_FORMAT_UINT32, &flags,
                       SSH_FORMAT_UINT32, &ifnum_in,
                       SSH_FORMAT_UINT32, &ifnum_out,
                       SSH_FORMAT_UINT32, &protocol,
                       SSH_FORMAT_UINT32, NULL,
                       SSH_FORMAT_UINT32_STR_NOCOPY, &packet_ptr, &packet_len,
                       SSH_FORMAT_UINT32_STR_NOCOPY,
                        &internal_ptr, &internal_len,
#if (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0)
                       SSH_FORMAT_DATA, extbuf, sizeof(extbuf),
#endif /* (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0) */
                       SSH_FORMAT_END) != len)
    {
      SSH_DEBUG_HEXDUMP(0, ("bad packet"), data, len);
      return;
    }

  /* Assert that the interface numbers fit into SshInterceptorIfnum. */
  SSH_ASSERT(((SshUInt32)ifnum_in) <= ((SshUInt32)SSH_INTERCEPTOR_MAX_IFNUM));
  SSH_ASSERT(((SshUInt32)ifnum_out) <= ((SshUInt32)SSH_INTERCEPTOR_MAX_IFNUM));

  /* Allocate a packet object. */
  pp = ssh_interceptor_packet_alloc(interceptor,
                                    flags & (SSH_PACKET_FROMADAPTER
                                             | SSH_PACKET_FROMPROTOCOL),
                                    protocol, ifnum_in, ifnum_out,
                                    packet_len);
  if (pp == NULL)
    {
      return;
    }

  /* Copy all interceptor flags to packet apart from
     SSH_PACKET_FROMADAPTER and SSH_PACKET_FROMPROTOCOL which were
     already given to ssh_interceptor_packet_alloc. */
  pp->flags |= (flags & 0x000000ff)
    & ~(SSH_PACKET_FROMADAPTER | SSH_PACKET_FROMPROTOCOL);

  /* Copy the data from the kernel into the packet object. */
  if (!ssh_interceptor_packet_copyin(pp, 0, packet_ptr, packet_len))
    {
      SSH_DEBUG(SSH_D_ERROR, ("copyin failed, dropping packet"));
      return;
    }

  if (!ssh_interceptor_packet_import_internal_data(pp, internal_ptr,
                                                   internal_len))
    {
      SSH_DEBUG(SSH_D_ERROR, ("import failed, dropping packet"));
      return;
    }

  /* Pass the packet to the packet callback. */
  if (interceptor->packet_cb)
    {
      ssh_mutex_lock(interceptor->mutex);
      interceptor->num_outcalls++;
      SSH_DEBUG(9, ("outcalls++ -> %d.", (int) interceptor->num_outcalls));
      ssh_mutex_unlock(interceptor->mutex);

      if (!ssh_threaded_mbox_send_to_thread(thread_mbox, packet_recv, pp))
        {
          ssh_mutex_lock(interceptor->mutex);
          interceptor->num_outcalls--;
          SSH_DEBUG(9, ("outcalls-- -> %d.", (int) interceptor->num_outcalls));
          ssh_mutex_unlock(interceptor->mutex);
          ssh_interceptor_packet_free(pp);
        }
    }
  else
    ssh_interceptor_packet_free(pp);
}


#ifdef INTERCEPTOR_PROVIDES_IP_ROUTING

typedef struct SshInterceptorRouteWrapRec {
  SshUInt32 reachable, ifnum, mtu;
  Boolean next_hop_ok;
  SshIpAddrStruct next_hop_gw;
  SshInterceptorRouteOp operations;
} *SshInterceptorRouteWrap, SshInterceptorRouteWrapStruct;

/* This runs in thread context. */
static void wrapper_route(void *ctx)
{
  SshInterceptorRouteWrap wrap = (SshInterceptorRouteWrap)ctx;
  SshInterceptorRouteOp op, completed;
  SshIpAddrStruct *next_hop_ret;
  SshUInt32 reachable, ifnum, mtu;
  SshInterceptor interceptor = ssh_usermode_interceptor;

  SSH_ASSERT_THREAD();

  completed = wrap->operations;
  reachable = wrap->reachable;
  ifnum = wrap->ifnum;
  mtu = wrap->mtu;

  if (wrap->next_hop_ok)
    next_hop_ret = &wrap->next_hop_gw;
  else
    next_hop_ret = NULL;

  /* Complete entries. */
  for (op = completed; op; op = completed)
    {
      completed = op->next;

      /* Call the completion function, passing it the routing data
         from the kernel. */
      (*op->cb.completion)(reachable, next_hop_ret, ifnum, mtu,
			   op->context);

      /* Free the entry. */
      memset(op, 'F', sizeof(*op));
      ssh_free(op);
    }

  ssh_xfree(wrap);

  ssh_mutex_lock(interceptor->mutex);
  interceptor->num_outcalls--;
  SSH_DEBUG(9, ("outcalls-- -> %d.", (int) interceptor->num_outcalls));
  ssh_mutex_unlock(interceptor->mutex);
}

/* Process a route reply message from the kernel. Run in eloop context. */
void ssh_kernel_receive_routereply(SshInterceptor interceptor,
                                   const unsigned char *data, size_t len)
{
  SshUInt32 id, reachable, ifnum, mtu;
  unsigned char *next_hop_ptr;
  size_t next_hop_len;
  SshIpAddrStruct next_hop_gw, *next_hop_ret;
  SshInterceptorRouteOp op, prev;
  SshInterceptorRouteWrap wrap;

  SSH_ASSERT_ELOOP();

  SSH_DEBUG(SSH_D_MIDSTART, ("route reply"));

  ssh_mutex_lock(interceptor->mutex);

  /* Decode the message. */
  if (ssh_decode_array(data, len,
                       SSH_FORMAT_UINT32, &id,
                       SSH_FORMAT_UINT32, &reachable,
                       SSH_FORMAT_UINT32, &ifnum,
                       SSH_FORMAT_UINT32, &mtu,
                       SSH_FORMAT_UINT32_STR_NOCOPY,
                         &next_hop_ptr, &next_hop_len,
                       SSH_FORMAT_END) != len)
    {
      SSH_DEBUG_HEXDUMP(0, ("bad routereply"), data, len);
      ssh_mutex_unlock(interceptor->mutex);
      return;
    }

  /* Convert the next hop gateway address to a properly aligned address
     object or NULL. */
  if (!ssh_decode_ipaddr_array(next_hop_ptr, next_hop_len, &next_hop_gw))
    {
      SSH_DEBUG_HEXDUMP(0, ("bad ipaddr encode"),
                        next_hop_ptr, next_hop_len);
      next_hop_ret = NULL;
    }
  else
    next_hop_ret = &next_hop_gw;

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("Route reply id %d reachable %d ifnum %d mtu %d",
             (int) id, (int) reachable, (int) ifnum, (int) mtu));

  if (next_hop_ret)
    SSH_DEBUG(SSH_D_NICETOKNOW,
              ("Route reply next_hop %@",
               ssh_ipaddr_render, next_hop_ret));

  /* Find the corresponding entry from the list. */
  for (prev = NULL, op = interceptor->route_operations;
       op != NULL;
       prev = op, op = op->next)
    {
      /* Check if the identifiers match. */
      if (op->id == id)
	break;
    }

  if (op == NULL)
    {
      SSH_DEBUG(SSH_D_ERROR,
                ("Received route reply for unknown id 0x%lx",
                 (unsigned long) id));

      for (op = interceptor->route_operations; op; op = op->next)
        SSH_DEBUG(SSH_D_ERROR,
                  ("id=0x%lx, dst=%@",
                   op->id, ssh_ipaddr_render, &op->destination));
      
      ssh_mutex_unlock(interceptor->mutex);
      return;
    }

  if (prev)
    prev->next = op->next;
  else
    interceptor->route_operations = op->next;
  op->next = NULL;

  interceptor->num_outcalls--;
  SSH_DEBUG(9, ("outcalls-- -> %d.", (int) interceptor->num_outcalls));

  ssh_mutex_unlock(interceptor->mutex);

  /* Wrap the completion callback handling and push it through the
     mbox to thread side */
  wrap = ssh_xmalloc(sizeof(*wrap));

  if (next_hop_ret == NULL)
    wrap->next_hop_ok = FALSE;
  else
    {
      wrap->next_hop_ok = TRUE;
      wrap->next_hop_gw = *next_hop_ret;
    }

  wrap->reachable = reachable;
  wrap->ifnum = ifnum;
  wrap->mtu = mtu;
  wrap->operations = op;

  ssh_mutex_lock(interceptor->mutex);
  interceptor->num_outcalls++;
  SSH_DEBUG(9, ("outcalls++ -> %d.", (int) interceptor->num_outcalls));
  ssh_mutex_unlock(interceptor->mutex);

  if (!ssh_threaded_mbox_send_to_thread(thread_mbox, wrapper_route, wrap))
    {
      ssh_mutex_lock(interceptor->mutex);
      interceptor->num_outcalls--;
      SSH_DEBUG(9, ("outcalls-- -> %d.", (int) interceptor->num_outcalls));
      ssh_mutex_unlock(interceptor->mutex);

      while (wrap->operations)
        {
          SshInterceptorRouteOp next = wrap->operations->next;
          ssh_free(wrap->operations);
          wrap->operations = next;
        }
      ssh_xfree(wrap);
    }
}

typedef struct SshInterceptorRouteSuccessWrapRec {
  SshInterceptorRouteError error;
  SshInterceptorRouteOp op;
} *SshInterceptorRouteSuccessWrap, SshInterceptorRouteSuccessWrapStruct;

/* This runs in thread context. */
static void wrapper_route_success(void *ctx)
{
  SshInterceptorRouteSuccessWrap wrap = (SshInterceptorRouteSuccessWrap) ctx;
  SshInterceptor interceptor = ssh_usermode_interceptor;

  SSH_ASSERT_THREAD();

  if (wrap->op->cb.success)
    (*wrap->op->cb.success)(wrap->error, wrap->op->context);
  
  ssh_free(wrap->op);
  ssh_free(wrap);

  ssh_mutex_lock(interceptor->mutex);
  interceptor->num_outcalls--;
  SSH_DEBUG(9, ("outcalls-- -> %d.", (int) interceptor->num_outcalls));
  ssh_mutex_unlock(interceptor->mutex);
}

/* Process a routing table modification success callback. */
static void 
ssh_kernel_receive_route_success(SshInterceptor interceptor,
				 const unsigned char *data, size_t len)
{
  SshInterceptorRouteSuccessWrap wrap;
  SshInterceptorRouteOp op, prev;
  SshUInt32 id, error;

  SSH_ASSERT_ELOOP();

  SSH_DEBUG(SSH_D_MIDSTART, ("route modification success"));

  ssh_mutex_lock(interceptor->mutex);

  /* Decode the message. */
  if (ssh_decode_array(data, len,
                       SSH_FORMAT_UINT32, &id,
                       SSH_FORMAT_UINT32, &error,
                       SSH_FORMAT_END) != len)
    {
      SSH_DEBUG_HEXDUMP(0, ("bad routereply"), data, len);
      ssh_mutex_unlock(interceptor->mutex);
      return;
    }
  
  /* Find the corresponding entry from the list. */
  op = NULL;
  for (prev = NULL, op = interceptor->route_operations; 
       op != NULL; 
       prev = op, op = op->next)
    {
      /* Check if the identifiers match. */
      if (op->id == id)
	break;
    }

  if (op == NULL)
    {
      SSH_DEBUG(SSH_D_ERROR,
                ("Received route reply for unknown id 0x%lx",
                 (unsigned long) id));

      for (op = interceptor->route_operations; op; op = op->next)
        SSH_DEBUG(SSH_D_ERROR, ("id=0x%lx", op->id));
      
      ssh_mutex_unlock(interceptor->mutex);
      return;
    }

  /* Remove op from the list. */
  if (prev)
    prev->next = op->next;
  else
    interceptor->route_operations = op->next;
  op->next = NULL;

  interceptor->num_outcalls--;
  SSH_DEBUG(9, ("outcalls-- -> %d.", (int) interceptor->num_outcalls));

  ssh_mutex_unlock(interceptor->mutex);

  /* Wrap the completion callback handling and push it through the
     mbox to thread side */
  wrap = ssh_xmalloc(sizeof(*wrap));
  wrap->error = (SshInterceptorRouteError) error;
  wrap->op = op;

  ssh_mutex_lock(interceptor->mutex);
  interceptor->num_outcalls++;
  SSH_DEBUG(9, ("outcalls++ -> %d.", (int) interceptor->num_outcalls));
  ssh_mutex_unlock(interceptor->mutex);

  if (!ssh_threaded_mbox_send_to_thread(thread_mbox, 
					wrapper_route_success, wrap))
    {
      ssh_mutex_lock(interceptor->mutex);
      interceptor->num_outcalls--;
      SSH_DEBUG(9, ("outcalls-- -> %d.", (int) interceptor->num_outcalls));
      ssh_mutex_unlock(interceptor->mutex);
      ssh_free(wrap->op);
      ssh_xfree(wrap);
    }
}

/* This is called in thread context. */
static void wrapper_routechange(void *ctx)
{
  SshInterceptor interceptor = ssh_usermode_interceptor;

  SSH_ASSERT_THREAD();

  (*interceptor->route_change_cb)(interceptor->context);

  ssh_mutex_lock(interceptor->mutex);
  interceptor->num_outcalls--;
  SSH_DEBUG(9, ("outcalls-- -> %d.", (int) interceptor->num_outcalls));
  ssh_mutex_unlock(interceptor->mutex);
}

/* Process a route change message from the kernel. Run in eloop context. */
void ssh_kernel_receive_routechange(SshInterceptor interceptor,
                                    const unsigned char *data, size_t len)
{
  SSH_DEBUG(SSH_D_MIDSTART, ("route change"));

  SSH_ASSERT_ELOOP();

  /* Make sure there is no extra data in the message. */
  if (len != 0)
    {
      SSH_DEBUG_HEXDUMP(0, ("bad routechange"), data, len);
      return;
    }

  /* Call the route change callback. */
  if (interceptor->route_change_cb)
    {
      ssh_mutex_lock(interceptor->mutex);
      interceptor->num_outcalls++;
      SSH_DEBUG(9, ("outcalls++ -> %d.", (int) interceptor->num_outcalls));
      ssh_mutex_unlock(interceptor->mutex);

      if (!ssh_threaded_mbox_send_to_thread(thread_mbox,
                                            wrapper_routechange, NULL))
        {
          ssh_mutex_lock(interceptor->mutex);
          interceptor->num_outcalls--;
          SSH_DEBUG(9, ("outcalls-- -> %d.", (int) interceptor->num_outcalls));
          ssh_mutex_unlock(interceptor->mutex);
        }
    }
}
#endif /* INTERCEPTOR_PROVIDES_IP_ROUTING */


#ifdef INTERCEPTOR_PROVIDES_INTERFACE_INFORMATION

typedef struct SshInterceptorInterfacesWrapRec
{
  SshInterceptor interceptor;
  SshUInt32 num_interfaces;
  SshInterceptorInterface *ifs;
} *SshInterceptorInterfacesWrap, SshInterceptorInterfacesWrapStruct;

static void wrapper_interfaces(void *ctx)
{
  SshInterceptorInterfacesWrap wrap = (SshInterceptorInterfacesWrap)ctx;
  SshInterceptor interceptor = wrap->interceptor;
  SshUInt32 num_interfaces;
  SshInterceptorInterface *ifs;
  int i;

  SSH_ASSERT_THREAD();

  num_interfaces = wrap->num_interfaces;
  ifs = wrap->ifs;

  /* Pass the interfaces array to the callback. */
  if (interceptor->interfaces_cb)
    (*interceptor->interfaces_cb)(num_interfaces, ifs, interceptor->context);

  /* Free the interfaces array. */
  for (i = 0; i < num_interfaces; i++)
    ssh_free(ifs[i].addrs);
  ssh_free(ifs);
  ssh_xfree(wrap);

  ssh_mutex_lock(interceptor->mutex);
  interceptor->num_outcalls--;
  SSH_DEBUG(9, ("outcalls-- -> %d.", (int) interceptor->num_outcalls));
  ssh_mutex_unlock(interceptor->mutex);
}

static void
ssh_usermode_interceptor_send_interfaces(void *context)
{
  SshInterceptor interceptor = (SshInterceptor) context;
  SshInterceptorInterfacesWrap wrap;
  SshInterceptorInterface *ifs;
  SshUInt32 num_ifs, i;

  /* Allocate a copy of the interfaces. */

  ssh_mutex_lock(interceptor->mutex);

  num_ifs = interceptor->num_ifs;
  ifs = ssh_xcalloc(num_ifs, sizeof(ifs[0]));

  memcpy(ifs, interceptor->ifs, num_ifs * sizeof(ifs[0]));

  for (i = 0; i < num_ifs; i++)
    ifs[i].addrs = ssh_xmemdup(interceptor->ifs[i].addrs,
                               ifs[i].num_addrs * sizeof(ifs[i].addrs[0]));


  /* Move the actual callback to the thread side through mbox */
  wrap = ssh_xmalloc(sizeof(*wrap));
  wrap->interceptor = interceptor;
  wrap->num_interfaces = num_ifs;
  wrap->ifs = ifs;

  interceptor->num_outcalls++;
  SSH_DEBUG(9, ("outcalls++ -> %d.", (int) interceptor->num_outcalls));
  ssh_mutex_unlock(interceptor->mutex);

  if (!ssh_threaded_mbox_send_to_thread(thread_mbox, wrapper_interfaces, wrap))
    {
      ssh_mutex_lock(interceptor->mutex);
      interceptor->num_outcalls--;
      SSH_DEBUG(9, ("outcalls-- -> %d.", (int) interceptor->num_outcalls));
      ssh_mutex_unlock(interceptor->mutex);

      for (i = 0; i < wrap->num_interfaces; i++)
        ssh_xfree(wrap->ifs[i].addrs);
      ssh_xfree(wrap->ifs);
      ssh_xfree(wrap);
    }
}

/* Process an interfaces message received from the kernel. Run in
   eloop context. */
void ssh_kernel_receive_interfaces(SshInterceptor interceptor,
                                   const unsigned char *data, size_t len)
{
  size_t bytes, name_len, ma_len;
  unsigned char *name_ptr, *ma_ptr;
  SshUInt32 num_interfaces, num_addrs;
  SshUInt32 protocol_media, protocol_flags;
  SshUInt32 protocol_mtu_ipv4;
  SshUInt32 adapter_media, adapter_flags;
  SshUInt32 adapter_mtu_ipv4;
#ifdef WITH_IPV6
  SshUInt32 adapter_mtu_ipv6, protocol_mtu_ipv6;
#endif /* WITH_IPV6 */
  SshUInt32 ifnum, flags;
  SshInterceptorInterface *ifs;
  SshUInt32 i, k;

  SSH_ASSERT_ELOOP();

  SSH_DEBUG(SSH_D_MIDSTART, ("interfaces callback"));

  /* Parse number of interfaces from the message. */
  bytes = ssh_decode_array(data, len,
                           SSH_FORMAT_UINT32, &num_interfaces,
                           SSH_FORMAT_END);
  if (bytes == 0)
    {
      SSH_DEBUG_HEXDUMP(0, ("bad interfaces (num_interfaces)"), data, len);
      return;
    }
  data += bytes;
  len -= bytes;

  /* Allocate the data structure for the interfaces and parse each
     interface. Notice: We use non-failing allocators here, since the
     logic is like this:

     - If the (real) interceptor fails to allocate memory to pass
     structures to the engine, it can always try again. We cannot,
     since we rely on the message from the (real) kernel interceptor,
     which means the interfaces message might not be resent.

     - If the engine fails to allocate memory, it is not interceptor's
     problem.

     So, to keep a sort-of-natural semantics, we want to avoid showing
     effects of memory allocation failures in this routine to the
     engine, thus non-failing allocators. */

  ifs = ssh_xcalloc(num_interfaces, sizeof(ifs[0]));
  if (!ifs)
    return;
  for (i = 0; i < num_interfaces; i++)
    {
      /* Parse fixed part of the interface. */
      bytes = ssh_decode_array(data, len,
                               SSH_FORMAT_UINT32, &protocol_media,
                               SSH_FORMAT_UINT32, &protocol_flags,
                               SSH_FORMAT_UINT32, &protocol_mtu_ipv4,
#ifdef WITH_IPV6
                               SSH_FORMAT_UINT32, &protocol_mtu_ipv6,
#endif /* WITH_IPV6 */
                               SSH_FORMAT_UINT32, &adapter_media,
                               SSH_FORMAT_UINT32, &adapter_flags,
                               SSH_FORMAT_UINT32, &adapter_mtu_ipv4,
#ifdef WITH_IPV6
                               SSH_FORMAT_UINT32, &adapter_mtu_ipv6,
#endif /* WITH_IPV6 */
                               SSH_FORMAT_UINT32_STR_NOCOPY,
                                 &ma_ptr, &ma_len,
                               SSH_FORMAT_UINT32, &ifnum,
                               SSH_FORMAT_UINT32, &flags,
                               SSH_FORMAT_UINT32_STR_NOCOPY,
                                 &name_ptr, &name_len,
                               SSH_FORMAT_UINT32, &num_addrs,
                               SSH_FORMAT_END);
      if (bytes == 0)
        {
          SSH_DEBUG_HEXDUMP(0, ("bad interfaces (i=%d)", (int)i), data, len);
          return;
        }
      data += bytes;
      len -= bytes;

      /* Initialize the interface structure. */
      ifs[i].ifnum = ifnum;
      ifs[i].flags = flags;
      ifs[i].to_protocol.media = protocol_media;
      ifs[i].to_adapter.media = adapter_media;
      if (protocol_media == SSH_INTERCEPTOR_MEDIA_NONEXISTENT)
        continue;

      ifs[i].to_protocol.flags = protocol_flags;
      ifs[i].to_adapter.flags = adapter_flags;

      if (ssh_usermode_interceptor_max_mtu != 0
          && protocol_mtu_ipv4 > ssh_usermode_interceptor_max_mtu)
        protocol_mtu_ipv4 = ssh_usermode_interceptor_max_mtu;
      ifs[i].to_protocol.mtu_ipv4 = protocol_mtu_ipv4;

      if (ssh_usermode_interceptor_max_mtu != 0
          && adapter_mtu_ipv4 > ssh_usermode_interceptor_max_mtu)
        adapter_mtu_ipv4 = ssh_usermode_interceptor_max_mtu;
      ifs[i].to_adapter.mtu_ipv4 = adapter_mtu_ipv4;

#ifdef WITH_IPV6
      if (ssh_usermode_interceptor_max_mtu != 0
          && protocol_mtu_ipv6 > ssh_usermode_interceptor_max_mtu)
        protocol_mtu_ipv6 = ssh_usermode_interceptor_max_mtu;
      ifs[i].to_protocol.mtu_ipv6 = protocol_mtu_ipv6;

      if (ssh_usermode_interceptor_max_mtu != 0
          && adapter_mtu_ipv6 > ssh_usermode_interceptor_max_mtu)
        adapter_mtu_ipv6 = ssh_usermode_interceptor_max_mtu;
      ifs[i].to_adapter.mtu_ipv6 = adapter_mtu_ipv6;
#endif /* WITH_IPV6 */

      if (name_len > sizeof(ifs[i].name) - 1)
        name_len = sizeof(ifs[i].name) - 1;
      memcpy(ifs[i].name, name_ptr, name_len);
      ifs[i].name[name_len] = '\0';

      /* Allocate and initialize address information. */
      ifs[i].num_addrs = num_addrs;
      ifs[i].addrs = ssh_xcalloc(num_addrs, sizeof(*ifs[i].addrs));

      if (!ifs[i].addrs)
        ssh_fatal("alloc failed");

      /* Decode addresses */
      for (k = 0; k < num_addrs; k++)
        {
          unsigned char *ip, *mask, *bcast, *addr;
          size_t ip_size, mask_size, bcast_size, addrlen;
          SshUInt32 proto;

          bytes = ssh_decode_array(data, len,
                                   SSH_FORMAT_UINT32, &proto,
                                   SSH_FORMAT_UINT32_STR_NOCOPY,
                                   &addr, &addrlen,
                                   SSH_FORMAT_END);

          data += bytes;
          len -= bytes;

          /* Here we handle only IPv4 and IPv6 addresses. This needs
             to be modified to support usermode engine for *
             non-IPv4/IPv6 interface addresses (IPX, AppleTalk) */

          SSH_ASSERT(proto == SSH_PROTOCOL_IP4 || proto == SSH_PROTOCOL_IP6);

          ifs[i].addrs[k].protocol = proto;

          ssh_decode_array(addr, addrlen,
                           SSH_FORMAT_UINT32_STR_NOCOPY, &ip, &ip_size,
                           SSH_FORMAT_UINT32_STR_NOCOPY, &mask, &mask_size,
                           SSH_FORMAT_UINT32_STR_NOCOPY, &bcast, &bcast_size,
                           SSH_FORMAT_END);

          ssh_decode_ipaddr_array(ip, ip_size,
                                  &ifs[i].addrs[k].addr.ip.ip);

          ssh_decode_ipaddr_array(mask, mask_size,
                                  &ifs[i].addrs[k].addr.ip.mask);

          ssh_decode_ipaddr_array(bcast, bcast_size,
                                  &ifs[i].addrs[k].addr.ip.broadcast);
        }

      /* Initialize media address. */
      if (ma_len > sizeof(ifs[i].media_addr))
        ma_len = sizeof(ifs[i].media_addr);
      memcpy(ifs[i].media_addr, ma_ptr, ma_len);
      ifs[i].media_addr_len = ma_len;
    }

  /* Free possible old interface information from the interceptor. */
  for (i = 0; i < interceptor->num_ifs; i++)
    ssh_free(interceptor->ifs[i].addrs);
  ssh_free(interceptor->ifs);

  /* And store the new information. */
  interceptor->ifs = ifs;
  interceptor->num_ifs = num_interfaces;

  /* Send the interface information. */
  ssh_usermode_interceptor_send_interfaces(interceptor);
}
#endif /* INTERCEPTOR_PROVIDES_INTERFACE_INFORMATION */


/* Process a version string received from the kernel. Run in eloop context. */
void ssh_kernel_receive_version(SshInterceptor interceptor,
                                const unsigned char *data, size_t len)
{
  char *version;

  SSH_ASSERT_ELOOP();

  SSH_DEBUG(SSH_D_MIDSTART, ("receive version"));

  /* Parse the message. */
  if (ssh_decode_array(data, len,
                       SSH_FORMAT_UINT32_STR, &version, NULL,
                       SSH_FORMAT_END) != len)
    {
      SSH_DEBUG_HEXDUMP(0, ("bad receive version"), data, len);
      return;
    }

  /* Display the version and warn about this being a user mode
     implementation. */
  ssh_warning("User mode interceptor, kernel module: %s", version);
  ssh_free(version);
}

/* Processes a received debug message from the kernel. Run in eloop context. */
void ssh_kernel_receive_debug(SshInterceptor ic,
                              const unsigned char *data, size_t len)
{
  char *str;

  SSH_ASSERT_ELOOP();

  /* Decode the message. */
  if (ssh_decode_array(data, len,
                       SSH_FORMAT_UINT32_STR, &str, NULL,
                       SSH_FORMAT_END) != len)
    {
      SSH_DEBUG_HEXDUMP(0, ("bad debug message received"), data, len);
      return;
    }

  /* Display the debug message here. */
  ssh_debug("%s", str);
  ssh_free(str);
}

/* Processes a received warning message from the kernel. Run in eloop
   context. */
void ssh_kernel_receive_warning(SshInterceptor ic,
                                const unsigned char *data, size_t len)
{
  char *str;

  SSH_ASSERT_ELOOP();

  /* Decode the message. */
  if (ssh_decode_array(data, len,
                       SSH_FORMAT_UINT32_STR, &str, NULL,
                       SSH_FORMAT_END) != len)
    {
      SSH_DEBUG_HEXDUMP(0, ("bad warning message received"), data, len);
      return;
    }

  /* Display the warning message here. */
  ssh_warning("%s", str);
  ssh_free(str);
}
















































































































/* Process a message received from the kernel.  This dispatches the message
   to the appropriate handler function. Run in eloop context. */
void ssh_kernel_receive(SshPacketType type,
                        const unsigned char *data, size_t len,
                        void *context)
{
  SshInterceptor interceptor = (SshInterceptor)context;

  SSH_ASSERT_ELOOP();

  SSH_DEBUG(SSH_D_MIDSTART, ("packet type %d from kernel", (int)type));

  ssh_mutex_lock(interceptor->mutex);
  if (interceptor->stopped)
    {
      SSH_DEBUG(9, ("stopped - not processing."));
      ssh_mutex_unlock(interceptor->mutex);
      return;
    }
  interceptor->num_outcalls++;
  SSH_DEBUG(9, ("outcalls++ -> %d.", (int) interceptor->num_outcalls));
  ssh_mutex_unlock(interceptor->mutex);

  /* Dispatch the message to a handler function. */
  switch (type)
    {
    case SSH_ENGINE_IPM_FORWARDER_PACKET:
      if (!interceptor->stopping)
	ssh_kernel_receive_packet(interceptor, data, len);
      break;

#ifdef INTERCEPTOR_PROVIDES_IP_ROUTING
    case SSH_ENGINE_IPM_FORWARDER_ROUTEREPLY:
      ssh_kernel_receive_routereply(interceptor, data, len);
      break;

    case SSH_ENGINE_IPM_FORWARDER_ROUTE_SUCCESS:
      ssh_kernel_receive_route_success(interceptor, data, len);
      break;

    case SSH_ENGINE_IPM_FORWARDER_ROUTECHANGE:
      if (!interceptor->stopping)
	ssh_kernel_receive_routechange(interceptor, data, len);
      break;
#endif /* INTERCEPTOR_PROVIDES_IP_ROUTING */

#ifdef INTERCEPTOR_PROVIDES_INTERFACE_INFORMATION
    case SSH_ENGINE_IPM_FORWARDER_INTERFACES:
      if (!interceptor->stopping)
	ssh_kernel_receive_interfaces(interceptor, data, len);
      break;
#endif /* INTERCEPTOR_PROVIDES_INTERFACE_INFORMATION */

    case SSH_ENGINE_IPM_FORWARDER_VERSION:
      if (!interceptor->stopping)
	ssh_kernel_receive_version(interceptor, data, len);
      break;

    case SSH_ENGINE_IPM_FORWARDER_DEBUG:
      if (!interceptor->stopping)
	ssh_kernel_receive_debug(interceptor, data, len);
      break;

    case SSH_ENGINE_IPM_FORWARDER_WARNING:
      if (!interceptor->stopping)
	ssh_kernel_receive_warning(interceptor, data, len);
      break;

#ifdef SSHDIST_IPSEC_VIRTUAL_ADAPTERS
#ifdef INTERCEPTOR_PROVIDES_VIRTUAL_ADAPTERS
    case SSH_ENGINE_IPM_FORWARDER_VIRTUAL_ADAPTER_SEND:
    case SSH_ENGINE_IPM_FORWARDER_VIRTUAL_ADAPTER_ATTACH:
    case SSH_ENGINE_IPM_FORWARDER_VIRTUAL_ADAPTER_DETACH:
    case SSH_ENGINE_IPM_FORWARDER_VIRTUAL_ADAPTER_CONFIGURE:
    case SSH_ENGINE_IPM_FORWARDER_VIRTUAL_ADAPTER_GET_STATUS:
    case SSH_ENGINE_IPM_FORWARDER_VIRTUAL_ADAPTER_STATUS_CB:
    case SSH_ENGINE_IPM_FORWARDER_VIRTUAL_ADAPTER_PACKET_CB:
      ssh_kernel_receive_virtual_adapter(type, data, len);
      break;
#endif /* INTERCEPTOR_PROVIDES_VIRTUAL_ADAPTERS */
#endif /* SSHDIST_IPSEC_VIRTUAL_ADAPTERS */









    default:
        SSH_DEBUG(SSH_D_ERROR,
                  ("unknown packet type %d from kernel", (int) type));
        break;
    }

  ssh_mutex_lock(interceptor->mutex);
  interceptor->num_outcalls--;
  SSH_DEBUG(9, ("outcalls-- -> %d.", (int) interceptor->num_outcalls));
  ssh_mutex_unlock(interceptor->mutex);
}

/* Process EOF from the kernel device.  This should never happen. */

void ssh_kernel_eof(void *context)
{
  SSH_ASSERT_ELOOP();
  ssh_warning("EOF received from kernel module, strage...");
}

/* Process a notification about being able to send to the kernel again. */

void ssh_kernel_can_send(void *context)
{
  SSH_ASSERT_ELOOP();
  /* Do nothing. */
}

/* ZZZ: notice: Watchdogs are always initialized and canceled from
   withing eloop context. Creation is from
   main->engine_start->interceptor_open and cancel from
   eloop->ipm_eof->engine_stop->interceptor_close */

/* Send watchdog reset packets */
void watchdog_reset(void *ctx)
{
  SshInterceptor interceptor = ctx;

  SSH_ASSERT_ELOOP();

  ssh_usermode_interceptor_send_encode(interceptor,
				       SSH_ENGINE_IPM_WATCHDOG_RESET,
				       SSH_FORMAT_UINT32, (SshUInt32) 3,
				       SSH_FORMAT_END);
  
  ssh_xregister_timeout(1, 0, watchdog_reset, (void *) interceptor);
}

typedef struct SshInterceptorOpenWrapRec {
  SshInterceptor interceptor;
  SshMutex mutex;
  SshCondition cond;
  const char *devname;
  SshPacketWrapper wrapper;
  Boolean done;
} *SshInterceptorOpenWrap, SshInterceptorOpenWrapStruct;

Boolean ssh_interceptor_create(void *machine_context,
			       SshInterceptor *interceptor_return)
{
  *interceptor_return = ssh_usermode_interceptor;  
  return TRUE;
}

Boolean ssh_interceptor_set_packet_cb(SshInterceptor interceptor,
				      SshInterceptorPacketCB packet_cb,
				      void *context)
{
  if (interceptor == NULL)
    return FALSE;

  interceptor->packet_cb = packet_cb;
  interceptor->packet_cb_context = context;

  return TRUE;
}

/* Opens the interceptor.  This initializes data structures, opens the
   connection to the kernel module, and prepares for communication. */
Boolean ssh_interceptor_open(SshInterceptor interceptor,
                             SshInterceptorPacketCB packet_cb,
                             SshInterceptorInterfacesCB interfaces_cb,
                             SshInterceptorRouteChangeCB route_change_cb,
                             void *context)
{
  SSH_ASSERT_THREAD();

  if (interceptor == NULL)
    return FALSE;

  SSH_TRACE(1, ("usermode interceptor open"));

  if (packet_cb != NULL_FNPTR)
    {
      interceptor->packet_cb = packet_cb;
      interceptor->packet_cb_context = context;
    }
  SSH_ASSERT(interceptor->packet_cb != NULL_FNPTR);
#ifdef INTERCEPTOR_PROVIDES_INTERFACE_INFORMATION
  interceptor->interfaces_cb = interfaces_cb;
#endif /* INTERCEPTOR_PROVIDES_INTERFACE_INFORMATION */
#ifdef INTERCEPTOR_PROVIDES_IP_ROUTING
  interceptor->route_change_cb = route_change_cb;
#endif /* INTERCEPTOR_PROVIDES_IP_ROUTING */
  interceptor->context = context;

#ifdef INTERCEPTOR_PROVIDES_INTERFACE_INFORMATION
  /* Register a timeout to send interface information. */
  ssh_xregister_timeout(0, 100000, ssh_usermode_interceptor_send_interfaces,
                        interceptor);
#endif /* INTERCEPTOR_PROVIDES_INTERFACE_INFORMATION */

  return TRUE;
}

Boolean ssh_interceptor_init(void *machine_context)
{
  SshInterceptorTimeouts timeouts;
  SshInterceptor interceptor;
  SshStream devstream =(SshStream) machine_context;

  thread_mbox = ssh_threaded_mbox_create(0);
  if (thread_mbox == NULL)
    {
      ssh_warning("Could not create create threaded mbox\n");
      return FALSE;
    }

  SSH_ASSERT_ELOOP();

  SSH_DEBUG(1, ("usermode interceptor init"));

  if (!machine_context)
    {
      ssh_warning("device opening failed");
      return FALSE;
    }




  SSH_ASSERT(ssh_usermode_timeouts == NULL);
  timeouts = ssh_malloc(sizeof(*timeouts));

  if (!timeouts)
    {
      ssh_stream_destroy(devstream);
      return FALSE;
    }

  timeouts->mutex = ssh_mutex_create("timeouts", 0);

  if (!timeouts->mutex)
    {
      ssh_free(timeouts);
      ssh_stream_destroy(devstream);
      return FALSE;
    }

  timeouts->timeouts = NULL;

  ssh_usermode_timeouts = timeouts;

  /* Sanity check: only one instance of this interceptor can be open. */
  SSH_ASSERT(ssh_usermode_interceptor == NULL);

  interceptor = ssh_interceptor_alloc(machine_context);
  if (!interceptor)
    {
      ssh_stream_destroy(devstream);
      return FALSE;
    }

  /* Wrap the kernel device into a packet stream. */
  interceptor->wrapper = ssh_packet_wrap(devstream,
                                         ssh_kernel_receive,
                                         ssh_kernel_eof,
                                         ssh_kernel_can_send,
                                         (void *)interceptor);

  if (interceptor->wrapper == NULL)
    {
      ssh_interceptor_free(interceptor);
      ssh_stream_destroy(devstream);
      return FALSE;
    }

  ssh_usermode_interceptor = interceptor;

#if 0
  /* Start the watchdog reseter (run pretty soon) */
  ssh_xregister_timeout(1, 0, watchdog_reset, (void*) interceptor);
#endif

  return TRUE;
}

/* Sends a packet out.  This just sends the packet to the kernel. */
void ssh_interceptor_send(SshInterceptor interceptor,
                          SshInterceptorPacket pp,
                          size_t media_header_len)
{
#if (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0)
  unsigned char extbuf[SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS * 4];
  SshUInt32 i;
#endif /* (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0) */
  unsigned char *packetbuf, *internalbuf;
  size_t packet_len, internal_len;

  SSH_ASSERT_THREAD();

  /* Encode extension selectors into linear memory. */
#if (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0)
  for (i = 0; i < SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS; i++)
    {
      SSH_PUT_32BIT(extbuf + 4 * i, pp->extension[i]);
    }
#endif /* (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0) */

  /* Convert the packet into linear memory for convenience.  This is not
     nearly as fast as this could be, but is easy and simple.  The user-mode
     interceptor is intended for debugging only, so performance does not
     matter too much here. */
  packet_len = ssh_interceptor_packet_len(pp);
  packetbuf = ssh_malloc(packet_len);
  if (!packetbuf)
    {
      SSH_DEBUG(SSH_D_ERROR, ("allocation failed"));
      ssh_interceptor_packet_free(pp);
      return;
    }
  
#ifndef INTERCEPTOR_PROVIDES_MACSEC
  /* Insert the correct upper level checksum to the packet. This is required 
     for packets which expect the checksum to be computed by the NIC. */
  if (pp->flags & SSH_PACKET_HWCKSUM)
    {
      unsigned char *ucp;
      SshUInt16 ethertype = 0;
      size_t ip_header_len;

      /* Unfortunately we don't have access to pc->hdrlen here and we 
	 don't know the real IP header length so we need to reparse the 
	 packet. */
      
      /* Check the frame type. */
      ucp = ssh_interceptor_packet_pullup(pp, media_header_len + 1);
      if (ucp == NULL)
	{
	  SSH_DEBUG(SSH_D_ERROR, ("pullup failed"));
	  ssh_free(packetbuf);
	  return;
	}
      
      if (pp->protocol == SSH_PROTOCOL_ETHERNET)
	{
	  ethertype = SSH_ETHERH_TYPE(ucp);
	  if (ethertype == SSH_ETHERTYPE_VLAN)
	    ethertype = SSH_VLANH_TYPE((ucp + SSH_ETHERH_HDRLEN));
	}
      else if (pp->protocol == SSH_PROTOCOL_IP4)
	{
	  ethertype = SSH_ETHERTYPE_IP;
	}
      else if (pp->protocol == SSH_PROTOCOL_IP6)
	{
	  ethertype = SSH_ETHERTYPE_IPv6;
	}

      /* Handle only IPv4 and IPv6 frames. */
      if (ethertype == SSH_ETHERTYPE_IP || ethertype == SSH_ETHERTYPE_IPv6)
	{
	  /* Get the IP version */
	  ucp += media_header_len;
	  if (SSH_IPH4_VERSION(ucp) != 4 && SSH_IPH6_VERSION(ucp) != 6)
	    {
	      SSH_DEBUG(SSH_D_ERROR, ("Bad IP version"));
	      ssh_interceptor_packet_free(pp);
	      ssh_free(packetbuf);
	      return;
	    }
	  
	  /* If you're an IPv6 enthusiast, feel free to fix this to work 
	     in the nightmare case of extension headers. And some people 
	     claim IPv6 is a good protocol. */
	  if (SSH_IPH4_VERSION(ucp) == 6)
	    ip_header_len = SSH_IPH6_HDRLEN;
	  else
	    ip_header_len =  4 * SSH_IPH4_HLEN(ucp);
	  
	  SSH_DEBUG(SSH_D_LOWOK, ("Computing TCP/UDP checksum"));
	  if (!ssh_ip_cksum_packet_compute(pp, media_header_len, 
					   ip_header_len))
	    {
	      SSH_DEBUG(SSH_D_ERROR,
			("Cannot compute checksum, dropping packet"));
	      ssh_free(packetbuf);
	      return;
	    }
	  pp->flags &= ~SSH_PACKET_HWCKSUM;
	}
    }
#endif /* not INTERCEPTOR_PROVIDES_MACSEC */  

  ssh_interceptor_packet_copyout(pp, 0, packetbuf, packet_len);

  if (!ssh_interceptor_packet_export_internal_data(pp, &internalbuf,
                                                   &internal_len))
    {
      SSH_DEBUG(SSH_D_ERROR, ("export failed, dropping packet"));
      ssh_free(packetbuf);
      return;
    }


  SSH_DUMP_PACKET(SSH_D_PCKDMP, "interceptor send", pp);
  /* Send the packet to the kernel forwarder module. */
  ssh_usermode_interceptor_send_encode(interceptor,
                                 SSH_ENGINE_IPM_FORWARDER_PACKET,
                                 SSH_FORMAT_UINT32, (SshUInt32) pp->flags,
                                 SSH_FORMAT_UINT32, (SshUInt32) pp->ifnum_in,
                                 SSH_FORMAT_UINT32, (SshUInt32) pp->ifnum_out,
                                 SSH_FORMAT_UINT32,
                                   (SshUInt32) pp->protocol,
                                 SSH_FORMAT_UINT32,
                                   (SshUInt32) media_header_len,
                                 SSH_FORMAT_UINT32_STR,
                                   packetbuf, packet_len,
                                 SSH_FORMAT_UINT32_STR,
                                   internalbuf, internal_len,
#if (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0)
                                 SSH_FORMAT_DATA, extbuf, sizeof(extbuf),
#endif /* (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0) */
                                 SSH_FORMAT_END);

  /* Free the linearized packet. */
  ssh_free(packetbuf);

  /* Free the internal data representation */
  ssh_free(internalbuf);

  /* Free the original packet object. */
  ssh_interceptor_packet_free(pp);
}

typedef struct SshInterceptorMessageWrapRec {
  SshPacketType type;
  unsigned char *data;
  size_t len;
} *SshInterceptorMessageWrap, SshInterceptorMessageWrapStruct;

static void wrapper_send(void *ctx)
{
  SshInterceptorMessageWrap wrap = (SshInterceptorMessageWrap)ctx;
  SshInterceptor interceptor = ssh_usermode_interceptor;
  SshPacketType type;
  const unsigned char *data;
  size_t len;

  SSH_ASSERT_ELOOP();

  type = wrap->type;
  data = wrap->data;
  len = wrap->len;

  if (!ssh_packet_wrapper_can_send(interceptor->wrapper))
    {
      SSH_DEBUG(0, ("cannot send packet, wrapper queue full"));
    }
  else
    {
      ssh_packet_wrapper_send(interceptor->wrapper, type, data, len);
    }

  ssh_xfree(wrap->data);
  ssh_xfree(wrap);
}

/* Send already-formatted packet to the interceptor. This might be
   called in both eloop and thread context. */
Boolean ssh_usermode_interceptor_send(SshInterceptor interceptor,
                                      SshPacketType type,
                                      const unsigned char * data, size_t len)
{
  SshInterceptorMessageWrap wrap;

  wrap = ssh_xmalloc(sizeof(*wrap));
  wrap->type = type;
  wrap->data = ssh_xmemdup(data, len);
  wrap->len = len;

  ssh_threaded_mbox_send_to_eloop(thread_mbox, wrapper_send, wrap);

  return TRUE;
}

/* Encode a message and put into the kernel interceptor side. This can
   be called in both thread and eloop context. */
Boolean ssh_usermode_interceptor_send_encode(SshInterceptor interceptor,
                                             SshPacketType type, ...)
{
  va_list va;
  SshBufferStruct buffer;
  size_t len;
  Boolean status;

  ssh_buffer_init(&buffer);

  va_start(va, type);
  len = ssh_encode_buffer_va(&buffer, va);
  va_end(va);

  if (len)
    {
      SSH_ASSERT(ssh_buffer_len(&buffer) == len);
      status = ssh_usermode_interceptor_send(interceptor, type,
                                             ssh_buffer_ptr(&buffer), len);
    }
  else
    status = FALSE;

  ssh_buffer_uninit(&buffer);

  return status;
}

/* Stops the interceptor.  This should be called repeatedly until this
   returns TRUE. It is important that this routine does not cause any
   blocking calls to eloop. */

Boolean ssh_interceptor_stop(SshInterceptor interceptor)
{
  Boolean done = FALSE;

  SSH_ASSERT_THREAD();

  ssh_mutex_lock(interceptor->mutex);

  interceptor->stopping = TRUE;

  if (interceptor->num_outcalls != 0)
    SSH_DEBUG(SSH_D_NICETOKNOW, ("%d outcalls remaining", 
				 interceptor->num_outcalls)); 
  else if (interceptor->num_packets != 0)
    SSH_DEBUG(SSH_D_NICETOKNOW, ("%d packets active", 
				 interceptor->num_packets)); 

#ifdef INTERCEPTOR_PROVIDES_IP_ROUTING
  else if (interceptor->route_operations != NULL)
    SSH_DEBUG(SSH_D_NICETOKNOW, ("Route operations active"));
#endif /* INTERCEPTOR_PROVIDES_IP_ROUTING */

#ifdef SSHDIST_IPSEC_VIRTUAL_ADAPTERS
#ifdef INTERCEPTOR_PROVIDES_VIRTUAL_ADAPTERS
  else if (interceptor->virtual_adapter_operations != NULL)
    SSH_DEBUG(SSH_D_NICETOKNOW, ("Virtual adapter operations active"));
#endif /* INTERCEPTOR_PROVIDES_VIRTUAL_ADAPTERS */
#endif /* SSHDIST_IPSEC_VIRTUAL_ADAPTERS */

  else
    {
      interceptor->stopped = TRUE;
      SSH_DEBUG(SSH_D_NICETOKNOW, ("successfully stopped."));
      done = TRUE;
    }

  ssh_mutex_unlock(interceptor->mutex);

  return done;
}

static void wrapper_close(void *ctx)
{
  SshInterceptor interceptor = ssh_usermode_interceptor;

  SSH_ASSERT_ELOOP();
  SSH_ASSERT(interceptor != NULL);

  ssh_mutex_lock(interceptor->mutex);

  /* Cancel any timeouts related to the interceptor (watchdog reset). */
  ssh_cancel_timeouts(SSH_ALL_CALLBACKS, (void *)interceptor);

  /* Destroy the packet wrapper for the device.  This also destroys the
     contained device stream. */
  ssh_packet_wrapper_destroy(interceptor->wrapper);
  interceptor->wrapper = NULL;

  ssh_mutex_unlock(interceptor->mutex);
}

/* Closes the interceptor.  This closes the connection to the kernel
   device and frees data structures.  ssh_interceptor_stop must have
   returned TRUE before calling this. This routine must not cause any
   blocking calls to eloop side.*/
void ssh_interceptor_close(SshInterceptor interceptor)
{
  SSH_TRACE(1, ("usermode interceptor close"));
  SSH_ASSERT(interceptor != NULL && interceptor == ssh_usermode_interceptor);

  SSH_ASSERT_THREAD();

#ifdef WITH_PURIFY
  /*purify_all_leaks();*/
#endif

  SSH_ASSERT(interceptor->stopped);
  SSH_ASSERT(interceptor->num_packets == 0);
  SSH_ASSERT(interceptor->num_outcalls == 0);

#ifdef INTERCEPTOR_PROVIDES_IP_ROUTING
  SSH_ASSERT(interceptor->route_operations == NULL);
#endif /* INTERCEPTOR_PROVIDES_IP_ROUTING */

#ifdef SSHDIST_IPSEC_VIRTUAL_ADAPTERS
#ifdef INTERCEPTOR_PROVIDES_VIRTUAL_ADAPTERS
  SSH_ASSERT(interceptor->virtual_adapter_operations == NULL);
#endif /* INTERCEPTOR_PROVIDES_VIRTUAL_ADAPTERS */
#endif /* SSHDIST_IPSEC_VIRTUAL_ADAPTERS */

  /* We need to remove the eloop context, kernel ipm connection
     etc. too. But those don't have to be synchronized.. */
  ssh_threaded_mbox_send_to_eloop(thread_mbox, wrapper_close, interceptor);
}

void ssh_interceptor_uninit(void)
{
  SshInterceptorTimeouts timeouts = ssh_usermode_timeouts;
  SshInterceptor interceptor = ssh_usermode_interceptor;

  SSH_ASSERT(timeouts != NULL && timeouts->timeouts == NULL);
  SSH_ASSERT(interceptor != NULL);

  ssh_threaded_mbox_destroy(thread_mbox);

  if (!interceptor->stopped)
    wrapper_close(interceptor);

#ifdef INTERCEPTOR_PROVIDES_INTERFACE_INFORMATION
 {
   int i;

  /* Free any cached interface information. */
  for (i = 0; i < interceptor->num_ifs; i++)
    ssh_free(interceptor->ifs[i].addrs);
  ssh_free(interceptor->ifs);
 }
#endif /* INTERCEPTOR_PROVIDES_INTERFACE_INFORMATION */

  /* Free the interceptor data structure. */
  ssh_interceptor_free(interceptor);

  /* Mark that we have no interceptor open. */
  ssh_usermode_interceptor = NULL;

  /* Destroy timeouts */
  ssh_mutex_destroy(timeouts->mutex);

  ssh_free(timeouts);

  ssh_usermode_timeouts = NULL;

  SSH_DEBUG(SSH_D_LOWOK, ("uninit done."));
}


#ifdef INTERCEPTOR_PROVIDES_IP_ROUTING

/* Looks up routing information from the kernel, and calls the
   completion function when done. This is called in thread context by
   the engine. */
void ssh_interceptor_route(SshInterceptor interceptor,
                           SshInterceptorRouteKey key,
                           SshInterceptorRouteCompletion completion,
                           void *context)
{
  SshInterceptorRouteOp op;
  unsigned char *key_dst, *key_src;
  size_t key_dst_len, key_src_len;
#if (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0)
  unsigned char key_ext[SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS * 4];
  SshUInt32 i;
#endif /* (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0) */
  SshIpAddrStruct src;
  Boolean success;

  SSH_ASSERT_THREAD();

  ssh_mutex_lock(interceptor->mutex);

  /* Prepare a route entry data structure.  This structure is used when a
     reply to the routing request is received from the kernel. */
  op = ssh_calloc(1, sizeof(*op));

  if (op == NULL)
    {
    lookup_failure:
      ssh_mutex_unlock(interceptor->mutex);
      (*completion)(FALSE, NULL, 0, 0, context);
      return;
    }

  op->id = interceptor->next_route_id++;
  op->destination = key->dst;
  op->cb.completion = completion;
  op->context = context;

  /* Encode the destination address */
  SSH_ASSERT(SSH_IP_DEFINED(&key->dst));
  if (!(key_dst_len = ssh_encode_ipaddr_array_alloc(&key_dst, &key->dst)))
    {
      ssh_free(op);
      
      ssh_warning("Failed to encode ipaddr %@",
		  ssh_ipaddr_render, &key->dst);
      goto lookup_failure;
    }
  
  /* Encode the source address */      
  if (key->selector & SSH_INTERCEPTOR_ROUTE_KEY_SRC)
    {
      key_src_len = ssh_encode_ipaddr_array_alloc(&key_src, &key->src);
    }
  else
    {
      SSH_IP_UNDEFINE(&src);
      key_src_len = ssh_encode_ipaddr_array_alloc(&key_src, &src);
    }
  
  if (key_src_len == 0)
    {
      ssh_free(key_dst);
      ssh_free(op);
      
      ssh_warning("Failed to encode ipaddr %@",
		  ssh_ipaddr_render, &key->src);
      goto lookup_failure;
    }
  
  /* Encode extension selectors into linear memory. */
#if (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0)
  for (i = 0; i < SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS; i++)
    {
      SSH_PUT_32BIT(key_ext + 4 * i, key->extension[i]);
    }
#endif /* (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0) */      
  
  /* Put the entry on the list of routing entries. */
  op->next = interceptor->route_operations;
  interceptor->route_operations = op;

  SSH_DEBUG(SSH_D_NICETOKNOW,
	    ("Sending route request for %@ id %d",
	     ssh_ipaddr_render, &key->dst, (int) op->id));
  
  /* Count the pending routing request as a call from the
     interceptor.  This means that ssh_interceptor_stop cannot
     return TRUE until the routing request has completed. */
  
  interceptor->num_outcalls++;
  SSH_DEBUG(9, ("outcalls++ -> %d.", (int) interceptor->num_outcalls));
  ssh_mutex_unlock(interceptor->mutex);
  
  /* Send the request to the kernel. */
  success = ssh_usermode_interceptor_send_encode(
                                interceptor,
                                SSH_ENGINE_IPM_FORWARDER_ROUTEREQ,
                                SSH_FORMAT_UINT32, (SshUInt32) op->id,
				SSH_FORMAT_UINT32_STR, key_dst, key_dst_len,
				SSH_FORMAT_UINT32_STR, key_src, key_src_len,
				SSH_FORMAT_UINT32, (SshUInt32) key->ipproto,
				SSH_FORMAT_UINT32, (SshUInt32) key->ifnum,
				SSH_FORMAT_DATA, 
				key->nh.raw, sizeof(key->nh.raw),
				SSH_FORMAT_DATA, 
				key->th.raw, sizeof(key->th.raw),
#if (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0)
				SSH_FORMAT_DATA, key_ext, sizeof(key_ext),
#endif /* (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0) */
                                SSH_FORMAT_UINT32, (SshUInt32) key->selector,
                                SSH_FORMAT_END);
  ssh_free(key_dst);
  ssh_free(key_src);
  ssh_mutex_lock(interceptor->mutex);
  
  if (!success)
    {
      SshInterceptorRouteOp op_ptr, prev;
      
      /* Remove the entry from the list. It won't ever get any
	 callbacks from the engine. */      
      for (prev = NULL, op_ptr = interceptor->route_operations;
	   op_ptr != NULL && op_ptr != op;
	   prev = op_ptr, op_ptr = op_ptr->next)
	;
      SSH_ASSERT(op_ptr != NULL);
      SSH_ASSERT(op_ptr == op);
      if (prev)
	prev->next = op_ptr->next;
      else
	interceptor->route_operations = op_ptr->next;

      /* Cleanup. */
      ssh_free(op);
      interceptor->num_outcalls--;
      SSH_DEBUG(9, ("outcalls-- -> %d.", (int) interceptor->num_outcalls));

      goto lookup_failure;
    }
  
  ssh_mutex_unlock(interceptor->mutex);
}


static void
ssh_interceptor_modify_route(SshInterceptor interceptor,
			     Boolean add,
			     SshInterceptorRouteKey key,
			     SshIpAddr gateway,
			     SshInterceptorIfnum ifnum,
			     SshRoutePrecedence precedence,
			     SshUInt32 flags,
			     SshInterceptorRouteSuccessCB success_cb,
			     void *success_cb_context)
{
  SshInterceptorRouteOp op;
  unsigned char *dst_buf, *src_buf, *gw_buf;
  size_t dst_len, src_len, gw_len;
#if (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0)
  unsigned char extbuf[SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS * 4];
  SshUInt32 i;
#endif /* (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0) */
  SshIpAddrStruct src;
  Boolean success;
  SshPacketType operation_type;

  SSH_ASSERT_THREAD();

  ssh_mutex_lock(interceptor->mutex);

  /* Prepare a route entry data structure. This structure is used when a
     reply to the routing operation is received from the kernel. */
  op = ssh_calloc(1, sizeof(*op));

  if (!op)
    {
    failure:
      ssh_mutex_unlock(interceptor->mutex);
      (*success_cb)(FALSE, success_cb_context);
      return;
    }

  op->id = interceptor->next_route_id++;
  op->destination = key->dst;
  op->cb.success = success_cb;
  op->context = success_cb_context;

  /* Encode the destination address */
  SSH_ASSERT(SSH_IP_DEFINED(&key->dst));
  if (!(dst_len = ssh_encode_ipaddr_array_alloc(&dst_buf, &key->dst)))
    {
      ssh_free(op);      
      ssh_warning("Failed to encode ipaddr %@",
		  ssh_ipaddr_render, &key->dst);
      goto failure;
    }
  
  /* Encode the source address */      
  if (key->selector & SSH_INTERCEPTOR_ROUTE_KEY_SRC)
    {
      src_len = ssh_encode_ipaddr_array_alloc(&src_buf, &key->src);
    }
  else
    {
      SSH_IP_UNDEFINE(&src);
      src_len = ssh_encode_ipaddr_array_alloc(&src_buf, &src);
    }
  
  if (src_len == 0)
    {
      ssh_free(dst_buf);
      ssh_free(op);
      
      ssh_warning("Failed to encode ipaddr %@",
		  ssh_ipaddr_render, &key->src);
      goto failure;
    }
  
  /* Encode extension selectors into linear memory. */
#if (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0)
  for (i = 0; i < SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS; i++)
    {
      SSH_PUT_32BIT(extbuf + 4 * i, key->extension[i]);
    }
#endif /* (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0) */      
  
  /* Encode gateway address */
  if (!(gw_len = ssh_encode_ipaddr_array_alloc(&gw_buf, gateway)))
    {
      ssh_free(dst_buf);
      ssh_free(src_buf);
      ssh_free(op);
      
      ssh_warning("Failed to encode ipaddr %@",
		  ssh_ipaddr_render, gateway);
      goto failure;
    }

  /* Put the entry on the list of routing entries. */
  op->next = interceptor->route_operations;
  interceptor->route_operations = op;

  SSH_DEBUG(SSH_D_NICETOKNOW,
	    ("Sending route %s request for %@ id %d",
	     (add ? "add" : "remove"),
	     ssh_ipaddr_render, &key->dst,
	     (int) op->id));

  /* Count the pending routing operations as a call from the
     interceptor.  This means that ssh_interceptor_stop cannot
     return TRUE until the routing operation has completed. */

  interceptor->num_outcalls++;
  SSH_DEBUG(9, ("outcalls++ -> %d.", (int) interceptor->num_outcalls));
  ssh_mutex_unlock(interceptor->mutex);

  operation_type = SSH_ENGINE_IPM_FORWARDER_REMOVE_ROUTE;
  if (add)
    operation_type = SSH_ENGINE_IPM_FORWARDER_ADD_ROUTE;

  /* Send the request to the kernel. */
  success = ssh_usermode_interceptor_send_encode(
                                interceptor,
				operation_type,
                                SSH_FORMAT_UINT32, (SshUInt32) op->id,
				SSH_FORMAT_UINT32_STR, dst_buf, dst_len,
				SSH_FORMAT_UINT32_STR, src_buf, src_len,
				SSH_FORMAT_UINT32, (SshUInt32) key->ipproto,
				SSH_FORMAT_UINT32, (SshUInt32) key->ifnum,
				SSH_FORMAT_DATA, 
				key->nh.raw, sizeof(key->nh.raw),
				SSH_FORMAT_DATA, 
				key->th.raw, sizeof(key->th.raw),
#if (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0)
				SSH_FORMAT_DATA, extbuf, sizeof(extbuf),
#endif /* (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0) */
                                SSH_FORMAT_UINT32, (SshUInt32) key->selector,
				SSH_FORMAT_UINT32_STR, gw_buf, gw_len,
				SSH_FORMAT_UINT32, (SshUInt32) ifnum,
				SSH_FORMAT_UINT32, (SshUInt32) precedence,
				SSH_FORMAT_UINT32, flags,
                                SSH_FORMAT_END);
  ssh_free(dst_buf);
  ssh_free(src_buf);
  ssh_free(gw_buf);
  ssh_mutex_lock(interceptor->mutex);
  
  if (!success)
    {
      SshInterceptorRouteOp prev, op_ptr;
      
      /* Remove the entry from the list. It won't ever get any
	 callbacks from the engine. */
      for (prev = NULL, op_ptr = interceptor->route_operations;
	   op_ptr != NULL && op_ptr != op;
	   prev = op_ptr, op_ptr = op_ptr->next)
	;
      SSH_ASSERT(op_ptr != NULL);
      SSH_ASSERT(op_ptr == op);
      if (prev)
	prev->next = op_ptr->next;
      else
	interceptor->route_operations = op_ptr->next;

      /* Cleanup. */
      ssh_free(op);
      interceptor->num_outcalls--;
      SSH_DEBUG(9, ("outcalls-- -> %d.", (int) interceptor->num_outcalls));

      goto failure;
    }

  ssh_mutex_unlock(interceptor->mutex);
}

void
ssh_interceptor_add_route(SshInterceptor interceptor,
			  SshInterceptorRouteKey key,
			  SshIpAddr gateway,
			  SshInterceptorIfnum ifnum,
			  SshRoutePrecedence precedence,
			  SshUInt32 flags,
			  SshInterceptorRouteSuccessCB success_cb,
			  void *success_cb_context)
{
  ssh_interceptor_modify_route(interceptor, 
			       TRUE, key, gateway, ifnum, precedence, flags,
			       success_cb, success_cb_context);
}

void
ssh_interceptor_remove_route(SshInterceptor interceptor,
			     SshInterceptorRouteKey key,
                             SshIpAddr gateway,
			     SshInterceptorIfnum ifnum,
			     SshRoutePrecedence precedence,
			     SshUInt32 flags,
                             SshInterceptorRouteSuccessCB success_cb,
                             void *success_cb_context)
{
  ssh_interceptor_modify_route(interceptor, 
			       FALSE, key, gateway, ifnum, precedence, flags,
			       success_cb, success_cb_context);
}
#endif /* INTERCEPTOR_PROVIDES_IP_ROUTING */

/* The wrapper has three functionalities: it is used to pass
   information about with the callbacks, and while a timeout exists,
   it is in a linked list to be perused. It is also used as a
   non-linked entity in the cancellation process. */

typedef struct SshInterceptorTimeoutWrapRec {
  /* Timeout parameters */
  SshUInt32 seconds, microseconds;
  SshKernelTimeoutCallback callback;
  void *context;

  /* True if the timeout has been registered (by the eloop timeout
     routine!) */
  Boolean registered;

  /* True if the timeout is currently running */
  Boolean running;

  /* Chain next */
  struct SshInterceptorTimeoutWrapRec *next;

  /* Only used for timeout cancellation, otherwise uninitialized */
  SshCondition cond;
} *SshInterceptorTimeoutWrap, SshInterceptorTimeoutWrapStruct;

/* This is finally run in thread context. */
static void wrapper_timeout3(void *ctx)
{
  SshInterceptorTimeoutWrap *wrapp, wrap = (SshInterceptorTimeoutWrap)ctx;
  SshInterceptorTimeouts timeouts = ssh_usermode_timeouts;

  SSH_ASSERT_THREAD();

  SSH_DEBUG(13, ("wrap %p thread timeout, callback %p, context %p",
                wrap, wrap->callback, wrap->context));

  (*wrap->callback)(wrap->context);

  /* Now remove the timeout from the list */
  ssh_mutex_lock(timeouts->mutex);
  for (wrapp = &timeouts->timeouts; *wrapp; )
    {
      if (*wrapp == wrap)
        {
          *wrapp = (*wrapp)->next;
          ssh_mutex_unlock(timeouts->mutex);
          ssh_xfree(wrap);
          return;
        }

      wrapp = &(*wrapp)->next;
    }
  ssh_mutex_unlock(timeouts->mutex);

  SSH_NOTREACHED;
}

/* This is run in eloop context in response to eloop timeout. We have
   to move the actual callback invocation back to thread context. */
static void wrapper_timeout2(void *ctx)
{
  SshInterceptorTimeoutWrap wrap2, wrap = (SshInterceptorTimeoutWrap)ctx;
  SshInterceptorTimeouts timeouts = ssh_usermode_timeouts;

  SSH_ASSERT_ELOOP();

  ssh_mutex_lock(timeouts->mutex);

  /* Look for ourselves in the timeouts list. If *not* found, we've
     apparently been cancelled. */
  for (wrap2 = timeouts->timeouts; wrap2; wrap2 = wrap2->next)
    {
      if (wrap2 == wrap)
        break;
    }

  if (wrap2 == NULL)
    {
      ssh_mutex_unlock(timeouts->mutex);
      SSH_DEBUG(12, ("wrap %p cancelled before running", wrap));
      return;
    }

  wrap->running = TRUE;
  ssh_mutex_unlock(timeouts->mutex);

  SSH_DEBUG(13, ("wrap %p timeout, moving to thread", wrap));

  ssh_threaded_mbox_send_to_thread(thread_mbox, wrapper_timeout3, wrap);
}

/* This is run in eloop context. */
static void wrapper_timeout(void *ctx)
{
  SshInterceptorTimeoutWrap wrap2, wrap = (SshInterceptorTimeoutWrap)ctx;
  SshUInt32 seconds, microseconds;
  SshInterceptorTimeouts timeouts = ssh_usermode_timeouts;

  SSH_ASSERT_ELOOP();

  ssh_mutex_lock(timeouts->mutex);

  /* Look for ourselves in the timeouts list. If *not* found, we've
     apparently been cancelled. */
  for (wrap2 = timeouts->timeouts; wrap2; wrap2 = wrap2->next)
    {
      if (wrap2 == wrap)
        break;
    }

  if (wrap2 == NULL)
    {
      ssh_mutex_unlock(timeouts->mutex);
      SSH_DEBUG(12, ("wrap %p cancelled before registering", wrap));
      return;
    }

  seconds = wrap->seconds;
  microseconds = wrap->microseconds;

  ssh_xregister_timeout(seconds, microseconds, wrapper_timeout2, wrap);
  wrap->registered = TRUE;
  ssh_mutex_unlock(timeouts->mutex);
}

/* Implement kernel timeouts using normal timeouts.  This function registers
   a timeout. This is called in thread context. */
void ssh_kernel_timeout_register(SshUInt32 seconds, SshUInt32 microseconds,
                                 SshKernelTimeoutCallback callback,
                                 void *context)
{
  SshInterceptorTimeoutWrap wrap;
  SshInterceptorTimeouts timeouts = ssh_usermode_timeouts;

  SSH_ASSERT_THREAD();

  wrap = ssh_xmalloc(sizeof(*wrap));
  wrap->seconds = seconds;
  wrap->microseconds = microseconds;
  wrap->callback = callback;
  wrap->context = context;
  wrap->running = wrap->registered = FALSE;

  ssh_mutex_lock(timeouts->mutex);
  wrap->next = timeouts->timeouts;
  timeouts->timeouts = wrap;
  ssh_mutex_unlock(timeouts->mutex);

  ssh_threaded_mbox_send_to_eloop(thread_mbox, wrapper_timeout, wrap);
}

/* Cancellation of timeouts. This runs in eloop contetxt. */
static void wrapper_cancel(void *ctx)
{
  SshInterceptorTimeoutWrap *wrapp, current,
    wrap = (SshInterceptorTimeoutWrap)ctx;
  SshInterceptorTimeouts timeouts = ssh_usermode_timeouts;
  SshKernelTimeoutCallback callback;
  void *context;
  Boolean again;

  SSH_ASSERT_ELOOP();

  callback = wrap->callback;
  context = wrap->context;

  /* First, look to all matching timeouts and use cancel to cancel
     them. */

  ssh_mutex_lock(timeouts->mutex);
  for (again = FALSE, wrapp = &timeouts->timeouts; *wrapp; )
    {
      /* Check if the conditions match */
      if ((callback == (*wrapp)->callback ||
           callback == SSH_KERNEL_ALL_CALLBACKS) &&
          (context == (*wrapp)->context ||
           context == SSH_KERNEL_ALL_CONTEXTS))
        {
          if ((*wrapp)->running)
            {
              SSH_DEBUG(12, ("wrap %p running, pending", *wrapp));
              again = TRUE;
              wrapp = &(*wrapp)->next;
            }
          else
            {
              SSH_DEBUG(13, ("wrap %p cancelling (%p vs %p, %p vs %p)",
                            *wrapp, wrap->callback, (*wrapp)->callback,
                            wrap->context, (*wrapp)->context));

              /* we could also use wrapper_timeout2 as the callback */
              ssh_cancel_timeouts(SSH_ALL_CALLBACKS, *wrapp);

              current = *wrapp;
              *wrapp = (*wrapp)->next;
              ssh_xfree(current);
            }
        }
      else
        {
          wrapp = &(*wrapp)->next;
        }
    }

  if (again)
    {
      ssh_mutex_unlock(timeouts->mutex);

      /* we could do this also with a timeout.. it might be safer? */
      ssh_threaded_mbox_send_to_eloop(thread_mbox, wrapper_cancel, wrap);
      return;
    }

  wrap->running = FALSE;
  ssh_mutex_unlock(timeouts->mutex);
  ssh_condition_signal(wrap->cond);
}

/* Implement kernel timeouts using normal timeouts.  This function
   cancels a timeout. Runs in thread context. */
void ssh_kernel_timeout_cancel(SshKernelTimeoutCallback callback,
                               void *context)
{
  SshInterceptorTimeoutWrap wrap;
  SshInterceptorTimeouts timeouts = ssh_usermode_timeouts;

  SSH_ASSERT_THREAD();

  wrap = ssh_xmalloc(sizeof(*wrap));
  wrap->callback = callback;
  wrap->context = context;
  wrap->running = TRUE;
  wrap->cond = ssh_condition_create("timeout_cancel", 0);
  if (!wrap->cond)
    ssh_fatal(" ssh_kernel_timeout_cancel: Cannot create condition");
  
  SSH_DEBUG(13, ("canceling callback %p context %p", callback, context));

  ssh_threaded_mbox_send_to_eloop(thread_mbox, wrapper_cancel, wrap);

  ssh_mutex_lock(timeouts->mutex);
  while (wrap->running)
    ssh_condition_wait(wrap->cond, timeouts->mutex);
  ssh_mutex_unlock(timeouts->mutex);

  ssh_condition_destroy(wrap->cond);
  ssh_xfree(wrap);

  SSH_DEBUG(12, ("callback %p context %p cancelled", callback, context));
}
















































































































































































































#if 0
/* For now these are off, we do not prefer ssh* versions any more. */
#ifdef sun

#undef atoi
#undef strcasecmp
#undef strncasecmp
#undef strrchr

/* Can't include <string.h>, since that'll cause macro problems */
extern int strcasecmp(const char *, const char *);
extern int strncasecmp(const char *, const char *, size_t);

/* Some functions needed for Solaris usermode interceptor. */

int ssh_atoi(const char *input)
{
  return atoi(input);
}

int ssh_strcasecmp(const char *s1, const char *s2)
{
  return strcasecmp(s1, s2);
}

int ssh_strncasecmp(const char *s1, const char *s2, int n)
{
  return strncasecmp(s1, s2, n);
}

char *ssh_strrchr(const char *s, int c)
{
  return strrchr(s, c);
}

#undef memmove
#undef memcpy
#undef memset
#undef memcmp
#undef memchr

extern void *memmove(void *, const void *, size_t);
extern void *memcpy(void *, const void *, size_t);
extern void *memset(void *, int, size_t);
extern int memcmp(const void *, const void *, size_t);
extern void *memchr(const void *, int, size_t);

void *ssh_memmove(void *t, const void *s, size_t n)
{
  return memmove(t, s, n);
}

void *ssh_memcpy(void *t, const void *s, size_t n)
{
  return memcpy(t, s, n);
}

void *ssh_memset(void *t, int c, size_t n)
{
  return memset(t, c, n);
}

int ssh_memcmp(const void *s1, const void *s2, size_t n)
{
  return memcmp(s1, s2, n);
}

void *ssh_memchr(const void *s, int c, size_t n)
{
  return memchr(s, c, n);
}

void ssh_exit(int value)
{
  exit(value);
}

#endif /* __sun__ */
#endif /* 0 */

#if defined(__linux__) && !defined(__i386__)
void *ssh_memchr(const void *s, int c, size_t n)
{
  return memchr(s, c, n);
}
#endif /* __linux__ && !__i386__ */

void ssh_interceptor_get_time(SshTime *seconds, SshUInt32 *useconds)
{
  struct timeval now;

  gettimeofday(&now, NULL);

  if (seconds)
    *seconds = (SshTime)now.tv_sec;
  if (useconds)
    *useconds = (SshUInt32)now.tv_usec;
}

#ifdef INTERCEPTOR_SUPPORTS_MAPPED_MEMORY

/* If the underlying platform supports mapped memory, we'll have to
   provide stub functions. Since the policy manager will never succeed
   with mmap on the usermode engine socket, we should never actually
   see any mmaped pages, thus the asserts */

void ssh_interceptor_mmap_ref(SshInterceptor icept, SshKernelMemoryMap map)
{
  ssh_fatal("Should not happen.");
}

void ssh_interceptor_mmap_unref(SshInterceptor icept, SshKernelMemoryMap map)
{
  ssh_fatal("Should not happen.");
}

/* This just warns instead of doing fatal, and returns failure. */
SshKernelMemoryMap ssh_interceptor_mmap_by_user_address(SshInterceptor icept,
                                                  SshUInt64 user_address)
{
  ssh_warning("Should not happen.");
  return NULL;
}

void * ssh_interceptor_mmap_kernel_address(SshInterceptor icept,
                                           SshKernelMemoryMap map)
{
  ssh_fatal("Should not happen.");
  return NULL;
}

size_t ssh_interceptor_mmap_size(SshInterceptor icept,
                                 SshKernelMemoryMap map)
{
  ssh_fatal("Should not happen.");
  return 0;
}


#endif /* INTERCEPTOR_SUPPORTS_MAPPED_MEMORY */
