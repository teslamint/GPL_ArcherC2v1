/**
   
   @copyright
   Copyright (c) 2008 - 2010, AuthenTec Oy.  All rights reserved.
    
       linux_versions.h
    
   	This file defines some parameters that have changed between
   	various linux kernel versions. If you are using other than
   	"vanilla" kernels from http://www.kernel.org/ and have
   	these changes included in earlier or later kernel versions
   	you have to modify this file.
   
   	When adding support for new kernel versions, add the define
   	block to the bottom of the file. The new kernel version will
   	inherit all features of the previous kernel version. Create 
   	new defines for new features and undefine defines for features
   	that have disappeared from the new kernel version.
    
*/

#ifndef LINUX_VERSION_H
#define LINUX_VERSION_H

#include <linux/version.h>

#ifndef KERNEL_VERSION
#define KERNEL_VERSION(a,b,c) (((a) << 16) + ((b) << 8) + (c))
#endif /* KERNEL_VERSION */

/* 2.6.37 is the highest version currently supported */
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,37)
#error "Kernel versions after 2.6.37 are not supported"
#endif /* LINUX_VERSION_CODE > KERNEL_VERSION(2,6,37) */

/* 2.4 is no longer supported */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
#error "Kernel versions pre 2.6.0 are not supported"
#endif /* LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0) */

/* 2.6 series specific things */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
#define LINUX_MUST_USE_ALLMULTI 1
#define LINUX_HAS_SKB_SECURITY 1
#define LINUX_HAS_SKB_STAMP 1
#define LINUX_HAS_SKB_NFCACHE 1
#define LINUX_HAS_SKB_NFDEBUG 1
#define LINUX_SKB_LINEARIZE_NEEDS_FLAGS 1
#define LINUX_HAS_DEV_IOCTL 1
#define LINUX_INODE_OPERATION_PERMISSION_HAS_NAMEIDATA 1
#define LINUX_HAS_NET_DEVICE_PRIV 1
#define LINUX_HAS_PROC_DIR_ENTRY_OWNER 1
#endif /* >= 2.6.0 */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,2)
#define LINUX_HAS_CPU_POSSIBLE_MAP 1
#endif /* >= 2.6.2 */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,4)
#define LINUX_HAS_SKB_MAC_LEN 1
#endif /* >= 2.6.4 */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,9)
#define LINUX_HAS_ETH_HDR 1
/* Prefer dev_set_mtu */
#undef LINUX_HAS_DEV_IOCTL
#endif /* >= 2.6.9 */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,10)
/* Linux developers, please make up your minds. */
#ifdef MONTAVISTA_4
/* No montavista 4 specific feature flags. */
#endif /* MONTAVISTA_4 */
#endif /* >= 2.6.10 */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,12) 
#define LINUX_HAS_DST_MTU 1
#define LINUX_HAS_DEV_GET_FLAGS 1
#endif /* >= 2.6.12 */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,13)
#undef LINUX_HAS_SKB_SECURITY
#undef LINUX_HAS_SKB_STAMP
#undef LINUX_HAS_SKB_NFCACHE
#undef LINUX_HAS_SKB_NFDEBUG
#endif /* >= 2.6.13 */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,14)
#define LINUX_PACKET_TYPE_FUNC_HAS_ORIG_DEV 1
#endif /* >= 2.6.14 */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,15)
#define LINUX_HAS_NET_NETLINK_H 1
#endif /* >= 2.6.15 */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,16)
#define LINUX_HAS_IP6CB_NHOFF 1
#define LINUX_FRAGMENTATION_AFTER_NF_POST_ROUTING 1
#endif /* >= 2.6.16 */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,17)
#define LINUX_HAS_FOR_EACH_POSSIBLE_CPU 1
#endif /* >= 2.6.17 */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,18)
#undef LINUX_SKB_LINEARIZE_NEEDS_FLAGS
#endif /* >= 2.6.18 */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,19)
#define LINUX_HAS_NEW_CHECKSUM_FLAGS 1
#define LINUX_NEED_IF_ADDR_H 1
#define LINUX_HAS_IRQ_RETURN_T 1
#endif /* >= 2.6.19 */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,20)
#define LINUX_HAS_SKB_MARK 1
#define LINUX_HAS_SKB_CSUM_OFFSET 1
#endif /* >= 2.6.20 */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,22)
#define LINUX_HAS_NETDEVICE_ACCESSORS 1 
#define LINUX_HAS_SKB_DATA_ACCESSORS 1
#define LINUX_HAS_SKB_CSUM_START 1
#endif /* >= 2.6.22 */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,23)
#undef LINUX_MUST_USE_ALLMULTI 
#define LINUX_HAS_SKB_CLONE_WRITABLE 1
#endif /* >= 2.6.23 */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,24)
#define LINUX_NET_DEVICE_HAS_ARGUMENT 1
#define LINUX_NF_HOOK_SKB_IS_POINTER  1
#define LINUX_HAS_NETDEVICE_HEADER_OPS 1
#endif /* >= 2.6.24 */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,25)
#define LINUX_MODULE_DEPENDS_HAS_USED_ATTRIBUTE 1
#define LINUX_NF_INET_HOOKNUMS 1
#define LINUX_IP_ROUTE_OUTPUT_KEY_HAS_NET_ARGUMENT 1
#endif /* >= 2.6.25 */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,26)
#define LINUX_IP6_ROUTE_OUTPUT_KEY_HAS_NET_ARGUMENT 1
#endif /* >= 2.6.26 */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,27)
#undef LINUX_INODE_OPERATION_PERMISSION_HAS_NAMEIDATA
#endif /* >= 2.6.27 */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,28)
#define LINUX_HAS_NFPROTO_ARP 1
#endif /* >= 2.6.28 */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,29)
#undef LINUX_HAS_NET_DEVICE_PRIV
#define LINUX_HAS_TASK_CRED_STRUCT 1
#endif /* >= 2.6.29 */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,30)
#undef LINUX_HAS_PROC_DIR_ENTRY_OWNER
#define LINUX_HAS_IRQRETURN_T_ENUM
#endif /* >= 2.6.30 */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,31)
#define LINUX_HAS_SKB_DST_FUNCTIONS 1
#endif /* >= 2.6.31 */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,32)
#define LINUX_IN6_DEV_GET_NEEDS_IPV6_ADDRESS 1
#endif /* >= 2.6.32 */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,33)
/* New notifier type value NETDEV_UNREGISTER_BATCH was introduced. */
#endif /* >= 2.6.33 */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,34)
#define LINUX_HAS_NETDEV_NDO_CHANGE_RX_FLAGS 1
#define LINUX_HAS_NETDEV_NDO_SET_RX_MODE 1
#define LINUX_HAS_NETDEV_NDO_SET_MULTICAST_LIST 1
#endif /* >= 2.6.34 */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,35)
#define LINUX_HAS_INET6_IFADDR_LIST_HEAD 1
#define LINUX_DST_POP_IS_SKB_DST_POP 1
#define LINUX_FRAGMENTATION_AFTER_NF6_POST_ROUTING 1
#define LINUX_IP_ONLY_PASSTHROUGH_NDISC 1
#endif /* >= 2.6.35 */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,36)
#define LINUX_RT_DST_IS_NOT_IN_UNION 1
#define LINUX_DEV_GET_STATS_HAS_STATS_ARGUMENT 1
#endif /* >= 2.6.36 */

#endif /* LINUX_VERSION_H */
