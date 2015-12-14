.set project_name kernel
.set project_type drvlib
.set project_platforms
.set project_guid 50484C19-F1AF-3AF3-8400-0D821ED393D2
.set project_dir ipsec\\quicksec\\kernel
.set project_dir_inverse ..\\..\\..
.set project_incdirs \
	ipsec\\hwaccel \
	ipsec\\util \
	ipsec \
	ipsec\\include \
	ipsec\\quicksec \
	interceptor\\include \
	ipsec\\quicksec\\engine \
	include \
	lib\\sshcrypto \
	lib\\sshcrypto\\sshcipher \
	lib\\sshcrypto\\sshhash \
	lib\\sshcrypto\\sshmac \
	lib\\zlib \
	interceptor\\windows \
	ipsec\\quicksec\\fastpath\\software \
	ipsec\\quicksec\\fastpath \
	interceptor\\libkernelutil \
	ipsec\\quicksec\\kernel \
	.
.set project_defs \
	SSH_BUILD_IPSEC \
	HAVE_CONFIG_H
.set project_cflags
.set project_rcflags
.set project_libdirs
.set project_ldflags
.set project_libs
.set project_dependencies
.set outdir .
.set srcs \
	kernel_alloc.c \
	kernel_encode.c \
	packet_utils.c \
	sshdebug.c \
	sshenum.c \
	sshfatal.c \
	sshmatch.c \
	sshmemcmp.c \
	sshrand.c \
	sshsnprintf.c \
	sshustr.c \
	sshinetbits.c \
	sshinetencode.c \
	sshinetether.c \
	sshinethash.c \
	sshinetmapped.c \
	sshinetmask.c \
	sshinetmerge.c \
	sshinetprint.c \
	sshinetproto.c \
	sshinetrender.c \
	sshencodetypes.c \
	ip_cksum.c \
	ip_cksum_packet.c \
	ip_interfaces.c \
	virtual_adapter_arp.c \
	virtual_adapter_misc.c \
	virtual_adapter_util.c
.set dir_kernel_alloc.c interceptor\\libkernelutil 
.set dir_kernel_encode.c interceptor\\libkernelutil 
.set dir_packet_utils.c interceptor\\libkernelutil 
.set dir_sshdebug.c lib\\sshutil\\sshcore 
.set dir_sshenum.c lib\\sshutil\\sshcore 
.set dir_sshfatal.c lib\\sshutil\\sshcore 
.set dir_sshmatch.c lib\\sshutil\\sshcore 
.set dir_sshmemcmp.c lib\\sshutil\\sshcore 
.set dir_sshrand.c lib\\sshutil\\sshcore 
.set dir_sshsnprintf.c lib\\sshutil\\sshcore 
.set dir_sshustr.c lib\\sshutil\\sshcore 
.set dir_sshinetbits.c lib\\sshutil\\sshnet 
.set dir_sshinetencode.c lib\\sshutil\\sshnet 
.set dir_sshinetether.c lib\\sshutil\\sshnet 
.set dir_sshinethash.c lib\\sshutil\\sshnet 
.set dir_sshinetmapped.c lib\\sshutil\\sshnet 
.set dir_sshinetmask.c lib\\sshutil\\sshnet 
.set dir_sshinetmerge.c lib\\sshutil\\sshnet 
.set dir_sshinetprint.c lib\\sshutil\\sshnet 
.set dir_sshinetproto.c lib\\sshutil\\sshnet 
.set dir_sshinetrender.c lib\\sshutil\\sshnet 
.set dir_sshencodetypes.c lib\\sshutil\\sshstrutil 
.set dir_ip_cksum.c ipsec\\util 
.set dir_ip_cksum_packet.c ipsec\\util 
.set dir_ip_interfaces.c ipsec\\util 
.set dir_virtual_adapter_arp.c ipsec\\util 
.set dir_virtual_adapter_misc.c ipsec\\util 
.set dir_virtual_adapter_util.c ipsec\\util 
.set custom_tags
.set rsrcs
.set hdrs \
	kernel_encode.h \
	ip_cksum.h \
	ip_interfaces.h \
	virtual_adapter_internal.h
.set dir_kernel_encode.h interceptor\\libkernelutil 
.set dir_ip_cksum.h ipsec\\util 
.set dir_ip_interfaces.h ipsec\\util 
.set dir_virtual_adapter_internal.h ipsec\\util 
