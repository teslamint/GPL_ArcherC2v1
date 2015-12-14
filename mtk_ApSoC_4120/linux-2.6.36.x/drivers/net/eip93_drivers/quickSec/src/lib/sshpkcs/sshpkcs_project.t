.set project_name sshpkcs
.set project_type applib
.set project_platforms
.set project_guid E09EB275-BD4B-39EB-9F00-2D2892CEADFC
.set project_dir lib\\sshpkcs
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
	lib\\sshhttp \
	lib\\sshxml \
	lib\\sshcert \
	lib\\sshpkcs
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
	pkcs1-formats.c \
	pkcs12-conv.c \
	pkcs12.c \
	pkcs5.c \
	pkcs6-cert.c \
	pkcs6.c \
	pkcs7-common.c \
	pkcs7-create-sync.c \
	pkcs7-create.c \
	pkcs7-decode.c \
	pkcs7-encode.c \
	pkcs7-receive-sync.c \
	pkcs7-receive.c \
	pkcs8.c
.set dir_pkcs1-formats.c lib\\sshpkcs 
.set dir_pkcs12-conv.c lib\\sshpkcs 
.set dir_pkcs12.c lib\\sshpkcs 
.set dir_pkcs5.c lib\\sshpkcs 
.set dir_pkcs6-cert.c lib\\sshpkcs 
.set dir_pkcs6.c lib\\sshpkcs 
.set dir_pkcs7-common.c lib\\sshpkcs 
.set dir_pkcs7-create-sync.c lib\\sshpkcs 
.set dir_pkcs7-create.c lib\\sshpkcs 
.set dir_pkcs7-decode.c lib\\sshpkcs 
.set dir_pkcs7-encode.c lib\\sshpkcs 
.set dir_pkcs7-receive-sync.c lib\\sshpkcs 
.set dir_pkcs7-receive.c lib\\sshpkcs 
.set dir_pkcs8.c lib\\sshpkcs 
.set custom_tags
.set rsrcs
.set hdrs \
	pkcs6.h \
	pkcs7-internal.h \
	sshpkcs1.h \
	sshpkcs12-conv.h \
	sshpkcs12.h \
	sshpkcs5.h \
	sshpkcs7.h \
	sshpkcs8.h
.set dir_pkcs6.h lib\\sshpkcs 
.set dir_pkcs7-internal.h lib\\sshpkcs 
.set dir_sshpkcs1.h lib\\sshpkcs 
.set dir_sshpkcs12-conv.h lib\\sshpkcs 
.set dir_sshpkcs12.h lib\\sshpkcs 
.set dir_sshpkcs5.h lib\\sshpkcs 
.set dir_sshpkcs7.h lib\\sshpkcs 
.set dir_sshpkcs8.h lib\\sshpkcs 
