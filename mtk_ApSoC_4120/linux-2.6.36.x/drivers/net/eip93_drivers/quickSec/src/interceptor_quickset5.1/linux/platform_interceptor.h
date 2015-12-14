/*

  platform_interceptor.h

  Author: Lauri Tarkkala <ltarkkal@ssh.com>

  Copyright:
          Copyright (c) 2002, 2003 SFNT Finland Oy.
  All rights reserved

  Additional platform-dependent thinngs. This file is included from
  engine-interface/interceptor.h, provided that autoconfig has set
  INTERCEPTOR_HAS_PLATFOMR_INCLUDE preprocessor macro.
*/

#ifndef SSH_PLATFORM_INTERCEPTOR_H

#define SSH_PLATFORM_INTERCEPTOR_H 1

#ifdef KERNEL
#ifndef KERNEL_INTERCEPTOR_USE_FUNCTIONS

#include "linux_params.h"
#include "linux_packet_internal.h"

/* Define macros to access packet data directly. Currently netfilter
   linearizes all packets before they hit the netfilter hooks, so we
   can assume that the full packet data is available unfragmented. */

#define ssh_interceptor_packet_len(pp) \
  ((size_t)((SshInterceptorInternalPacket)(pp))->skb->len)

#define ssh_interceptor_packet_pullup(pp, len) \
  ((unsigned char *)((SshInterceptorInternalPacket)(pp))->skb->data)

#define ssh_interceptor_packet_pullup_read(pp, len) \
  ((unsigned char *)((SshInterceptorInternalPacket)(pp))->skb->data)

#endif /* KERNEL_INTERCEPTOR_USE_FUNCTIONS */
#endif /* KERNEL */

#ifdef SSHDIST_IPSEC_HWACCEL_OCTEON
#ifdef PLATFORM_OCTEON_LINUX
#include "linux_octeon_interceptor.h"
#endif /* PLATFORM_OCTEON_LINUX */
#endif /* SSHDIST_IPSEC_HWACCEL_OCTEON */

#endif /* SSH_PLATFORM_INTERCEPTOR_H */
