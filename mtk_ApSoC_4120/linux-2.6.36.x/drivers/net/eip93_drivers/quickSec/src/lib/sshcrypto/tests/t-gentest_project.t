.set project_name t-gentest
.set project_type console
.set project_platforms
.set project_guid 7C69AD23-BDA3-31EE-9C00-A1CEA9F434E2
.set project_dir lib\\sshcrypto\\tests
.set project_dir_inverse ..\\..\\..
.set project_incdirs \
	lib\\sshcrypto \
	lib\\sshcrypto\\sshcipher \
	lib\\sshcrypto\\sshcryptocore \
	lib\\sshcrypto\\sshhash \
	lib\\sshcrypto\\sshmac \
	lib\\sshcrypto\\sshpk \
	lib\\sshcrypto\\sshrandom \
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
	lib\\sshapputil \
	lib\\sshcrypto\\tests
.set project_defs \
	HAVE_CONFIG_H
.set project_cflags
.set project_rcflags
.set project_libdirs
.set project_ldflags
.set project_libs
.set project_dependencies \
	..\\libsshcrypto \
	..\\..\\..\\lib\\sshasn1\\libsshasn1 \
	..\\..\\..\\lib\\sshmath\\libsshmath \
	..\\..\\..\\lib\\zlib\\libz \
	..\\..\\..\\lib\\sshutil\\libsshutil
.set outdir .
.set srcs \
	cipher-test.c \
	hash-test.c \
	mac-test.c \
	misc-test.c \
	parser.c \
	pkcs-static-import-export.c \
	pkcs-static-test.c \
	pkcs-test.c \
	readfile.c \
	rnd-test.c \
	t-gentest.c
.set dir_cipher-test.c lib\\sshcrypto\\tests 
.set dir_hash-test.c lib\\sshcrypto\\tests 
.set dir_mac-test.c lib\\sshcrypto\\tests 
.set dir_misc-test.c lib\\sshcrypto\\tests 
.set dir_parser.c lib\\sshcrypto\\tests 
.set dir_pkcs-static-import-export.c lib\\sshcrypto\\tests 
.set dir_pkcs-static-test.c lib\\sshcrypto\\tests 
.set dir_pkcs-test.c lib\\sshcrypto\\tests 
.set dir_readfile.c lib\\sshcrypto\\tests 
.set dir_rnd-test.c lib\\sshcrypto\\tests 
.set dir_t-gentest.c lib\\sshcrypto\\tests 
.set custom_tags
.set rsrcs
.set hdrs \
	parser.h \
	readfile.h \
	t-gentest.h
.set dir_parser.h lib\\sshcrypto\\tests 
.set dir_readfile.h lib\\sshcrypto\\tests 
.set dir_t-gentest.h lib\\sshcrypto\\tests 
