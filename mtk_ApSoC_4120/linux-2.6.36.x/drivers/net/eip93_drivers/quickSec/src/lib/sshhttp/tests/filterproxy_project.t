.set project_name filterproxy
.set project_type console
.set project_platforms
.set project_guid 4EC6EB95-CF06-337A-9500-D88568687376
.set project_dir lib\\sshhttp\\tests
.set project_dir_inverse ..\\..\\..
.set project_incdirs \
	lib\\sshhttp \
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
	lib\\sshhttp\\tests
.set project_defs \
	HAVE_CONFIG_H
.set project_cflags
.set project_rcflags
.set project_libdirs
.set project_ldflags
.set project_libs
.set project_dependencies \
	..\\..\\..\\lib\\sshldap\\libsshldap \
	..\\..\\..\\lib\\sshradius\\libsshradius \
	..\\..\\..\\lib\\sshcryptoaux\\libsshcryptoaux \
	..\\..\\..\\lib\\sshcrypto\\libsshcrypto \
	..\\..\\..\\lib\\sshasn1\\libsshasn1 \
	..\\..\\..\\lib\\sshmath\\libsshmath \
	..\\..\\..\\lib\\zlib\\libz \
	..\\..\\..\\lib\\sshutil\\libsshutil \
	..\\..\\..\\lib\\sshhttp\\libsshhttp \
	..\\..\\..\\lib\\sshutil\\libsshutil
.set outdir .
.set srcs \
	filterproxy.c \
	sshcopystream.c
.set dir_filterproxy.c lib\\sshhttp\\tests 
.set dir_sshcopystream.c lib\\sshhttp\\tests 
.set custom_tags
.set rsrcs
.set hdrs \
	sshcopystream.h
.set dir_sshcopystream.h lib\\sshhttp\\tests 
