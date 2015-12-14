.set project_name http-benchmark
.set project_type console
.set project_platforms
.set project_guid BBFF4EF5-0A76-3BB4-9300-2357188798C8
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
	http-benchmark.c
.set dir_http-benchmark.c lib\\sshhttp\\tests 
.set custom_tags
.set rsrcs
.set hdrs \
	sshcopystream.h
.set dir_sshcopystream.h lib\\sshhttp\\tests 
