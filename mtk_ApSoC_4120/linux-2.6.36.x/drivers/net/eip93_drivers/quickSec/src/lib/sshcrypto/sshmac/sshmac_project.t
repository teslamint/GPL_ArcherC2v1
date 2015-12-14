.set project_name sshmac
.set project_type applib
.set project_platforms
.set project_guid 73D9175D-C510-3681-8100-9508EF1F5752
.set project_dir lib\\sshcrypto\\sshmac
.set project_dir_inverse ..\\..\\..
.set project_incdirs \
	lib\\sshcrypto \
	. \
	lib\\sshutil\\sshcore \
	lib\\sshutil\\sshadt \
	lib\\sshutil\\ssheloop \
	lib\\sshutil\\sshstrutil \
	lib\\sshutil\\sshfsm \
	lib\\sshutil\\sshstream \
	lib\\sshutil\\sshsysutil \
	lib\\sshutil\\sshnet \
	lib\\sshutil\\sshmisc \
	lib\\sshutil\\sshaudit \
	lib\\sshutil\\sshpacketstream \
	lib\\sshutil\\sshtestutil \
	lib\\sshutil \
	lib\\zlib \
	lib\\sshmath \
	lib\\sshasn1 \
	lib\\sshcrypto\\sshcipher \
	lib\\sshcrypto\\sshhash \
	lib\\sshcrypto\\sshrandom \
	lib\\sshcrypto\\sshcryptocore \
	lib\\sshcrypto\\sshmac
.set project_defs \
	HAVE_CONFIG_H
.set project_cflags
.set project_rcflags
.set project_libdirs
.set project_ldflags
.set project_libs
.set project_dependencies
.set outdir .
.set srcs \
	genmac.c \
	hmac.c \
	macs.c \
	ssl3mac.c \
	xcbc-mac.c
.set dir_genmac.c lib\\sshcrypto\\sshmac 
.set dir_hmac.c lib\\sshcrypto\\sshmac 
.set dir_macs.c lib\\sshcrypto\\sshmac 
.set dir_ssl3mac.c lib\\sshcrypto\\sshmac 
.set dir_xcbc-mac.c lib\\sshcrypto\\sshmac 
.set custom_tags
.set rsrcs
.set hdrs \
	hmac.h \
	macs.h \
	sshmac_i.h \
	ssl3mac.h \
	xcbc-mac.h
.set dir_hmac.h lib\\sshcrypto\\sshmac 
.set dir_macs.h lib\\sshcrypto\\sshmac 
.set dir_sshmac_i.h lib\\sshcrypto\\sshmac 
.set dir_ssl3mac.h lib\\sshcrypto\\sshmac 
.set dir_xcbc-mac.h lib\\sshcrypto\\sshmac 
