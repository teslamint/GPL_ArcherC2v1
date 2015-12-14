.set project_name sshcryptoaux
.set project_type applib
.set project_platforms
.set project_guid 745975F2-C747-344D-9000-4C5C9776BF09
.set project_dir lib\\sshcryptoaux
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
	lib\\sshcryptoaux
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
	aes_keywrap.c \
	bufhash.c \
	bufzip.c \
	genauxmp.c \
	keyexpand.c \
	oldimportapi.c \
	pkcs1_pad.c \
	sshcipheralias.c \
	sshrandompoll.c
.set dir_aes_keywrap.c lib\\sshcryptoaux 
.set dir_bufhash.c lib\\sshcryptoaux 
.set dir_bufzip.c lib\\sshcryptoaux 
.set dir_genauxmp.c lib\\sshcryptoaux 
.set dir_keyexpand.c lib\\sshcryptoaux 
.set dir_oldimportapi.c lib\\sshcryptoaux 
.set dir_pkcs1_pad.c lib\\sshcryptoaux 
.set dir_sshcipheralias.c lib\\sshcryptoaux 
.set dir_sshrandompoll.c lib\\sshcryptoaux 
.set custom_tags
.set rsrcs
.set hdrs \
	aes_keywrap.h \
	bufzip.h \
	pkcs1_pad.h \
	sshcryptoaux.h
.set dir_aes_keywrap.h lib\\sshcryptoaux 
.set dir_bufzip.h lib\\sshcryptoaux 
.set dir_pkcs1_pad.h lib\\sshcryptoaux 
.set dir_sshcryptoaux.h lib\\sshcryptoaux 
