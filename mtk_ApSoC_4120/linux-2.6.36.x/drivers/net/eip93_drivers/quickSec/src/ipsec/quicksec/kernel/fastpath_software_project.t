.set project_name fastpath_software
.set project_type drvlib
.set project_platforms
.set project_guid D33B296A-4E6E-32E5-8600-A1207148D39A
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
	blowfish.c \
	des.c \
	mode-gcm.c \
	mscapi-cipher.c \
	octeon-cipher.c \
	rijndael.c \
	md5.c \
	mscapi-hash.c \
	octeon-hash.c \
	sha.c \
	sha256.c \
	sha512.c \
	hmac.c \
	xcbc-mac.c \
	adler32.c \
	deflate.c \
	infblock.c \
	infcodes.c \
	inffast.c \
	inflate.c \
	inftrees.c \
	infutil.c \
	trees.c \
	zutil.c \
	engine_fastpath.c \
	engine_fastpath_impl.c \
	engine_fragment.c \
	engine_tcp_encaps.c \
	engine_transform_in.c \
	engine_transform_ipcomp.c \
	engine_transform_nat.c \
	engine_transform_out.c \
	engine_transform_utils.c \
	fastpath_alloc.c \
	fastpath_flow_id.c \
	fastpath_flows.c \
	fastpath_fragmagic.c \
	fastpath_icmp.c \
	fastpath_init.c \
	fastpath_mediatypes.c \
	fastpath_packet_pullup.c \
	fastpath_tcp.c \
	fastpath_udp.c \
	fastpath_utils.c
.set dir_blowfish.c lib\\sshcrypto\\sshcipher 
.set dir_des.c lib\\sshcrypto\\sshcipher 
.set dir_mode-gcm.c lib\\sshcrypto\\sshcipher 
.set dir_mscapi-cipher.c lib\\sshcrypto\\sshcipher 
.set dir_octeon-cipher.c lib\\sshcrypto\\sshcipher 
.set dir_rijndael.c lib\\sshcrypto\\sshcipher 
.set dir_md5.c lib\\sshcrypto\\sshhash 
.set dir_mscapi-hash.c lib\\sshcrypto\\sshhash 
.set dir_octeon-hash.c lib\\sshcrypto\\sshhash 
.set dir_sha.c lib\\sshcrypto\\sshhash 
.set dir_sha256.c lib\\sshcrypto\\sshhash 
.set dir_sha512.c lib\\sshcrypto\\sshhash 
.set dir_hmac.c lib\\sshcrypto\\sshmac 
.set dir_xcbc-mac.c lib\\sshcrypto\\sshmac 
.set dir_adler32.c lib\\zlib 
.set dir_deflate.c lib\\zlib 
.set dir_infblock.c lib\\zlib 
.set dir_infcodes.c lib\\zlib 
.set dir_inffast.c lib\\zlib 
.set dir_inflate.c lib\\zlib 
.set dir_inftrees.c lib\\zlib 
.set dir_infutil.c lib\\zlib 
.set dir_trees.c lib\\zlib 
.set dir_zutil.c lib\\zlib 
.set dir_engine_fastpath.c ipsec\\quicksec\\fastpath\\software 
.set dir_engine_fastpath_impl.c ipsec\\quicksec\\fastpath\\software 
.set dir_engine_fragment.c ipsec\\quicksec\\fastpath\\software 
.set dir_engine_tcp_encaps.c ipsec\\quicksec\\fastpath\\software 
.set dir_engine_transform_in.c ipsec\\quicksec\\fastpath\\software 
.set dir_engine_transform_ipcomp.c ipsec\\quicksec\\fastpath\\software 
.set dir_engine_transform_nat.c ipsec\\quicksec\\fastpath\\software 
.set dir_engine_transform_out.c ipsec\\quicksec\\fastpath\\software 
.set dir_engine_transform_utils.c ipsec\\quicksec\\fastpath\\software 
.set dir_fastpath_alloc.c ipsec\\quicksec\\fastpath\\software 
.set dir_fastpath_flow_id.c ipsec\\quicksec\\fastpath\\software 
.set dir_fastpath_flows.c ipsec\\quicksec\\fastpath\\software 
.set dir_fastpath_fragmagic.c ipsec\\quicksec\\fastpath\\software 
.set dir_fastpath_icmp.c ipsec\\quicksec\\fastpath\\software 
.set dir_fastpath_init.c ipsec\\quicksec\\fastpath\\software 
.set dir_fastpath_mediatypes.c ipsec\\quicksec\\fastpath\\software 
.set dir_fastpath_packet_pullup.c ipsec\\quicksec\\fastpath\\software 
.set dir_fastpath_tcp.c ipsec\\quicksec\\fastpath\\software 
.set dir_fastpath_udp.c ipsec\\quicksec\\fastpath\\software 
.set dir_fastpath_utils.c ipsec\\quicksec\\fastpath\\software 
.set custom_tags
.set rsrcs
.set hdrs \
	engine_fastpath_impl.h \
	engine_ipcomp_glue.h \
	engine_tcp_encaps.h \
	fastpath_swi.h
.set dir_engine_fastpath_impl.h ipsec\\quicksec\\fastpath\\software 
.set dir_engine_ipcomp_glue.h ipsec\\quicksec\\fastpath\\software 
.set dir_engine_tcp_encaps.h ipsec\\quicksec\\fastpath\\software 
.set dir_fastpath_swi.h ipsec\\quicksec\\fastpath\\software 
