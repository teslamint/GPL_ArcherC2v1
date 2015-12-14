#ifndef SSHCONF_H
#define SSHCONF_H
@TOP@

/* Package name. */
#undef PACKAGE

/* Package version. */
#undef VERSION

/* EFENCE memory debugger */
#undef EFENCE

/* Use replacement memcmp, may be slower but works properly */
#undef WITH_REPLACEMENT_MEMCMP

/* Global variable emulation, see lib/sshutil/sshcore/sshglobals.h. */
#undef SSH_GLOBALS_EMULATION

/* Light debugging */
#undef DEBUG_LIGHT

/* Heavy debugging */
#undef DEBUG_HEAVY

/* Minimal stack */
#undef MINIMAL_STACK

/* Inet addr is broken on this system */
#undef BROKEN_INET_ADDR

/* Sizes of usermode basic types */
#undef USERMODE_SIZEOF_INT
#undef USERMODE_SIZEOF_LONG
#undef USERMODE_SIZEOF_LONG_LONG
#undef USERMODE_SIZEOF_SHORT
#undef USERMODE_SIZEOF_VOID_P

/* "Have" for the usermode types */
#undef HAVE_USERMODE_INT
#undef HAVE_USERMODE_LONG
#undef HAVE_USERMODE_LONG_LONG
#undef HAVE_USERMODE_SHORT
#undef HAVE_USERMODE_VOID_P

/* Is this source tree compiled with purify? */
#undef WITH_PURIFY

/* How large data and insn caches do we have, in kB. */
#undef SSH_DATA_CACHE_SIZE
#undef SSH_INSN_CACHE_SIZE

/* PCSC libraries */
#undef HAVE_PCSC

/* Define this for Hi/Fn 6500 support */
#undef WITH_HIFN6500

/* ENABLE_HIFN_HSP */
#undef ENABLE_HIFN_HSP

/* ENABLE_OCF_SP */
#undef ENABLE_OCF_SP

/* Cavium Octeon. */
#undef PLATFORM_OCTEON_LINUX

/* Define this if you are using HP-UX.  HP-UX uses non-standard shared
   memory communication for X, which seems to be enabled by the display name
   matching that of the local host.  This circumvents it by using the IP
   address instead of the host name in DISPLAY. */
#undef HPUX_NONSTANDARD_X11_KLUDGE

/* SSH Distribution name ("quicksec-complete") */
#undef SSH_DIST_NAME

/* SSH base distribution name (truncate to first -) ("quicksec") */
#undef SSH_DIST_BASENAME

/* Compile a minimal engine */
#undef SSH_IPSEC_SMALL

/* Kludge for platforms where no arp packets can be received. */
#undef SSH_ENGINE_MEDIA_ETHER_NO_ARP_RESPONSES
#ifdef SSHDIST_PLATFORM_NETBSD
/* The NetBSD version number. */
#undef SSH_NetBSD
#endif /* SSHDIST_PLATFORM_NETBSD */



















#ifdef SSHDIST_PLATFORM_LINUX
/* Need to specify extra tags when linking ASM optimized code. */
#undef NEED_ASM_LINKAGE

/* Does kernel support RTM_SETLINK. */
#undef LINUX_HAS_RTM_SETLINK
#endif /* SSHDIST_PLATFORM_LINUX */





/* Define this to the canonical name of your host type (e.g.,
   "sparc-sun-sunos4.0.3"). */
#undef HOSTTYPE

/* Need defines for readonly versions of pullup and iteration packet
   routines */
#undef NEED_PACKET_READONLY_DEFINES

/* Interceptor has its own version of
   ssh_interceptor_packet_alloc_and_copy_ext_data */
#undef INTERCEPTOR_HAS_PACKET_ALLOC_AND_COPY_EXT_DATA

/* Interceptor has its own version of ssh_interceptor_packet_copy */
#undef INTERCEPTOR_HAS_PACKET_COPY

/* Interceptor has its own version of ssh_interceptor_packet_copyin */
#undef INTERCEPTOR_HAS_PACKET_COPYIN

/* Interceptor has its own version of ssh_interceptor_mark() function */
#undef INTERCEPTOR_HAS_MARK_FUNC

/* Interceptor has its own version of ssh_interceptor_packet_copyout */
#undef INTERCEPTOR_HAS_PACKET_COPYOUT

/* Interceptor has its own versions of
   ssh_interceptor_export_internal_data and
   ssh_interceptor_import_internal_data */
#undef INTERCEPTOR_HAS_PACKET_INTERNAL_DATA_ROUTINES

/* Interceptor has its own version of ssh_interceptor_has_packet_detach() */
#undef INTERCEPTOR_HAS_PACKET_DETACH

/* Intercepor has its own version of ssh_interceptor_packet_cache() */
#undef INTERCEPTOR_HAS_PACKET_CACHE

/* Interceptor has "platform_interceptor.h" include file
   to be included by interceptor.h. */
#undef INTERCEPTOR_HAS_PLATFORM_INCLUDE

/* Interceptor sees and sets the SSH_PACKET_FORWARDED flag */
#undef INTERCEPTOR_SETS_IP_FORWARDING

/* Interceptor handles loopback packets and never passes them to the
   packet callback */
#undef INTERCEPTOR_HANDLES_LOOPBACK_PACKETS

/* Does the interceptor have virtual adapters */
#undef INTERCEPTOR_HAS_VIRTUAL_ADAPTERS

/* Does the interceptor implement kernel level virtual adapter configure */
#undef INTERCEPTOR_IMPLEMENTS_VIRTUAL_ADAPTER_CONFIGURE

/* Does the interceptor implement kernel level routing table modification */
#undef INTERCEPTOR_IMPLEMENTS_ROUTE_MODIFY

/* Does the interceptor support memory mapped files (on the IPM
   device) interface? */
#undef INTERCEPTOR_SUPPORTS_MAPPED_MEMORY

/* Should the interceptor align the IP header of packets to word boundary 
   when sending to the network or stack? */
#undef INTERCEPTOR_IP_ALIGNS_PACKETS

/* Sizes of kernel basic types */
#undef KERNEL_SIZEOF_INT
#undef KERNEL_SIZEOF_LONG
#undef KERNEL_SIZEOF_LONG_LONG
#undef KERNEL_SIZEOF_SHORT
#undef KERNEL_SIZEOF_VOID_P

/* "Have" for kernel basic types */
#undef HAVE_KERNEL_INT
#undef HAVE_KERNEL_LONG
#undef HAVE_KERNEL_LONG_LONG
#undef HAVE_KERNEL_SHORT
#undef HAVE_KERNEL_VOID_P

/* Different evaluator types (_DUMMY is a true dummy to get around an
   autoheader (mis)feature) */
#undef SSH_FCE_VM__DUMMY
#undef SSH_FCE_VM_APFVM
#undef SSH_FCE_VM_BASSET
#undef SSH_FCE_VM_SIMPLE




#undef RXP_PLATFORM_NAME

#undef RXP_PLATFORM_LINUX
#undef RXP_PLATFORM_VXWORKS
#undef RXP_PLATFORM_SOLARIS

/* This is defined if /var/run exists. */
#undef HAVE_VAR_RUN

/* Define this to enable setting TCP_NODELAY for tcp sockets. */
#undef ENABLE_TCP_NODELAY

/* Define this if connect(2) system call fails with nonblocking sockets. */
#undef NO_NONBLOCKING_CONNECT

/* Define this if S_IFSOCK is defined */
#undef HAVE_S_IFSOCK

/* Support for Secure RPC */
#undef SECURE_RPC

/* Support for Secure NFS */
#undef SECURE_NFS

/* Does struct tm have tm_gmtoff member? */
#undef HAVE_TM_GMTOFF_IN_STRUCT_TM

/* Does struct tm have __tm_gmtoff__ member? (older Linux distributions) */
#undef HAVE_OLD_TM_GMTOFF_IN_STRUCT_TM

/* Does struct tm have tm_isdst member? */
#undef HAVE_TM_ISDST_IN_STRUCT_TM

/* Does system keep gmt offset in external variable "timezone"? */
#undef HAVE_EXTERNAL_TIMEZONE

/* Should sshtime routines avoid using system provided gmtime(3)
   and localtime(3) functions? */
#undef USE_SSH_INTERNAL_LOCALTIME

/* Do we have socklen_t defined in sys/socket.h. */
#undef HAVE_SOCKLEN_T

/* Do we have threads? */
#undef HAVE_THREADS

/* Do we have posix threads */
#undef HAVE_PTHREADS

/* Do we have IPv6 socket structures */
#undef HAVE_SOCKADDR_IN6_STRUCT

/* Does IPv6 have the RFC2533 defined "sin6_scope_id" field? */
#undef HAVE_SOCKADDR_IN6_SCOPE_ID

/* Whether termios.h needs modem.h to also be included in
   sshserialstream. */
#undef TERMIOS_H_NEEDS_MODEM_H

/* Define this to enable IPv6 support. */
#undef WITH_IPV6

/* Whether we can use __attribute__ ((weak)) with GCC */
#undef HAVE_GCC_ATTRIBUTE_WEAK

/* Prefer select() over poll() ? */
#undef ENABLE_SELECT

/* Are development time memory leak checks enabled? */
#undef MEMORY_LEAK_CHECKS

/* Stack trace support for memory leaks? */
#undef MEMORY_LEAK_STACK_TRACE

/* Ssh_encode failure support */
#undef SSH_ENCODE_FAIL

/* Are development time debugging malloc enabled? */
#undef SSH_DISABLE_DEBUG_MALLOC

/* Do we want to use system resolver */
#undef ENABLE_SYSTEM_DNS_RESOLVER

/* Do we have __libc_stack_end */
#undef HAVE_LIBC_STACK_END

/* The size in bytes of the global UDP datagram buffer.*/
#undef SSH_UDP_DATAGRAM_BUFFER_SIZE

/* What is the size of the size_t */
#undef USERMODE_SIZEOF_SIZE_T

/* "Have" for the size_t */
#undef HAVE_USERMODE_SIZE_T

/* Do we support __attribute__ ((format (printf, x, y))) with %@? */
#undef HAVE_ATTRIBUTE_FORMAT_PRINTF_SSH
/* Define this to use assembler routines in sshmath library. */
#undef SSHMATH_ASSEMBLER_SUBROUTINES

/* Define this to use assembler macros in sshmath library. */
#undef SSHMATH_ASSEMBLER_MACROS

/* Define this to use i386 assembler routines in sshmath library. */
#undef SSHMATH_I386

/* Define this to use alpha assembler routines in sshmath library. */
#undef SSHMATH_ALPHA

/* Define this to use Digital CC V5.3 assembler inline macros in sshmath
library. */
#undef SSHMATH_ALPHA_DEC_CC_ASM

/* Define this to obtain a minimal implementation of the mathematics library. 
   No library initialization is performed and modular exponentation assumes 
   an odd modulus. Routines which only are used for elliptic curves are 
   omitted. 
*/
#undef SSHMATH_MINIMAL

/* Up to what bit size do we use static memory for MP integers? */
#undef SSH_MP_INTEGER_BIT_SIZE_STATIC
/* NFAST driver */
#undef HAVE_NFAST

#undef SSH_SAFENET_USE_1840_DEVICE
#undef SSH_SAFENET_USE_1841_DEVICE
#undef SSH_SAFENET_USE_1842_DEVICE

/* Cavium Nitrox driver */
#undef ENABLE_CAVIUM_NITROX

/* Safenet UDM driver */
#undef HAVE_SAFENET

/* SCP 51X0 driver */
#undef HAVE_SCP51X0


/* Cavium Octeon driver */
#undef ENABLE_CAVIUM_OCTEON

/* Enable the I386 assembler optimizations. */
#undef QUICKSEC_ASM_I386

/* Enable Anti-virus ALG support */
#undef WITH_AV_ALG

/* Defined if a hardware accelerator has been configured. */
#undef SSH_IPSEC_HWACCEL_CONFIGURED

/* Defined if we are using transform (combined) level hardware acceleration */
#undef SSH_IPSEC_HWACCEL_USE_COMBINED_TRANSFORM

/* Defined if the transform (combined) level hardware acceleration performs 
   antireplay detection. */
#undef SSH_IPSEC_HWACCEL_DOES_ANTIREPLAY

#undef SSH_IPSEC_HWACCEL_NAME

/* Use EMI memory for Safenet 184x chips */
#undef SSH_SAFENET_USE_EMI_MEMORY

/* Enable the AMCC support */
#undef SSH_SAFENET_AMCC_SUPPORT

/* Target mode ops require endian swapping for Safenet chips */
#undef SSH_SAFENET_TARGET_REQUIRES_SWAP

/* Enable Intel Tolapai support */
#undef HAVE_INTEL_TOLAPAI

/* Hardware acceleration for TLS */
#undef SSH_IPSEC_HWACCEL_SUPPORT_TLS

/* Enable SafeNet hwaccelerator devices support */
#undef HAVE_SAFENET
#undef SSH_SAFENET_USE_1840_DEVICE
#undef SSH_SAFENET_USE_1841_DEVICE
#undef SSH_SAFENET_USE_1842_DEVICE
#undef HAVE_GETPASS/* Enable the IDEA cipher. */
#undef WITH_IDEA

/* Enable the RSA code. */
#undef WITH_RSA

/* Enable the assembler crypt code. */
#undef WITH_CRYPT_ASM

/* Assember code for Blowfish included. */
#undef ASM_BLOWFISH

/* Assembler code for DES included. */
#undef ASM_DES

/* Assembler code for ARCFOUR included. */
#undef ASM_ARCFOUR

/* Assembler code for MD5 included. */
#undef ASM_MD5

/* Assembler code for Octeon included. */
#undef ASM_PLATFORM_OCTEON

/* Have the DES cipher. */
#undef HAVE_DES

/* Have the 3 DES cipher. */
#undef HAVE_3DES

/* Have the AES cipher. */
#undef HAVE_AES

/* Have the SHA1 hash. */
#undef HAVE_SHA

/* Have the MD5 hash. */
#undef HAVE_MD5


/* Defined if compiled symbols are _not_ prepended with underscore `_' */
#undef HAVE_NO_SYMBOL_UNDERSCORE
/* Define this to use the ANSI X9.17 Random Number Generator */
#undef WITH_ANSI_RNG
/* Defined if the SCP 51X0 fastpath is used. */
#undef FASTPATH_IS_SCP51X0

/* Defined if the Octeon fastpath is used. */
#undef FASTPATH_IS_OCTEON

/* Defined if a fastpath accelerator has been configured. */
#undef FASTPATH_ACCELERATOR_CONFIGURED

/* Defined if the fastpath provides LRU flow lists. */
#undef FASTPATH_PROVIDES_LRU_FLOWS

/* Defined if flows are managed by the fastpath */
#undef FASTPATH_PROVIDES_FLOW

/* Defined if transforms are managed by the fastpath */
#undef FASTPATH_PROVIDES_TRD

/* Defined if next hop objects are managed by the fastpath */
#undef FASTPATH_PROVIDES_NH

/* Defined if a non-software fastpath has been configured. */
#undef FASTPATH_CONFIGURED@BOTTOM@
#endif /* SSHCONF_H */
