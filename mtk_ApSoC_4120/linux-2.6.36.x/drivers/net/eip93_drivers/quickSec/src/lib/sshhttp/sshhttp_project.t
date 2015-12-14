.set project_name sshhttp
.set project_type applib
.set project_platforms
.set project_guid 8B592B00-A042-3CE0-9C00-C53EB335755F
.set project_dir lib\\sshhttp
.set project_dir_inverse ..\\..
.set project_incdirs \
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
	lib\\sshcrypto\\sshmac \
	lib\\sshcrypto\\sshpk \
	lib\\sshcrypto \
	lib\\sshcryptoaux \
	lib\\sshradius \
	lib\\sshldap \
	lib\\sshhttp
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
	sshhttpclient.c \
	sshhttpserver.c \
	sshhttputils.c
.set dir_sshhttpclient.c lib\\sshhttp 
.set dir_sshhttpserver.c lib\\sshhttp 
.set dir_sshhttputils.c lib\\sshhttp 
.set custom_tags
.set rsrcs
.set hdrs \
	sshhttp.h \
	sshhttp_status.h \
	sshhttpi.h
.set dir_sshhttp.h lib\\sshhttp 
.set dir_sshhttp_status.h lib\\sshhttp 
.set dir_sshhttpi.h lib\\sshhttp 
