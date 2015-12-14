.set project_name sshcryptocore
.set project_type applib
.set project_platforms
.set project_guid EA82B6D4-7FCC-3EDD-8000-8FF0D0B54A21
.set project_dir lib\\sshcrypto\\sshcryptocore
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
	lib\\sshcrypto\\sshcryptocore
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
	crypto_init.c \
	crypto_tests.c \
	genaux.c \
	namelist.c
.set dir_crypto_init.c lib\\sshcrypto\\sshcryptocore 
.set dir_crypto_tests.c lib\\sshcrypto\\sshcryptocore 
.set dir_genaux.c lib\\sshcrypto\\sshcryptocore 
.set dir_namelist.c lib\\sshcrypto\\sshcryptocore 
.set custom_tags
.set rsrcs
.set hdrs \
	crypto_tests.h \
	namelist.h
.set dir_crypto_tests.h lib\\sshcrypto\\sshcryptocore 
.set dir_namelist.h lib\\sshcrypto\\sshcryptocore 
