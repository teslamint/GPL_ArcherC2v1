.set project_name sshcipher
.set project_type applib
.set project_platforms
.set project_guid 57F6AD89-D599-38E6-9700-08B93A10F0BC
.set project_dir lib\\sshcrypto\\sshcipher
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
	lib\\sshcrypto\\sshcipher
.set project_defs \
	HAVE_CONFIG_H
.set project_cflags
.set project_rcflags
.set project_libdirs
.set project_ldflags
.set project_libs
.set project_dependencies \
	@SSHCIPHER_CONF_OBJS@
.set outdir .
.set srcs \
	arcfour.c \
	blowfish.c \
	des.c \
	genciph.c \
	mode-gcm.c \
	mscapi-cipher.c \
	nociph.c \
	octeon-cipher.c \
	rc2.c \
	rijndael.c
.set dir_arcfour.c lib\\sshcrypto\\sshcipher 
.set dir_blowfish.c lib\\sshcrypto\\sshcipher 
.set dir_des.c lib\\sshcrypto\\sshcipher 
.set dir_genciph.c lib\\sshcrypto\\sshcipher 
.set dir_mode-gcm.c lib\\sshcrypto\\sshcipher 
.set dir_mscapi-cipher.c lib\\sshcrypto\\sshcipher 
.set dir_nociph.c lib\\sshcrypto\\sshcipher 
.set dir_octeon-cipher.c lib\\sshcrypto\\sshcipher 
.set dir_rc2.c lib\\sshcrypto\\sshcipher 
.set dir_rijndael.c lib\\sshcrypto\\sshcipher 
.set custom_tags
.set rsrcs
.set hdrs \
	arcfour.h \
	blowfish.h \
	des.h \
	mode-gcm.h \
	nociph.h \
	octeon-cipher.h \
	rc2.h \
	rijndael.h \
	sshcipher_i.h \
	sshrotate.h
.set dir_arcfour.h lib\\sshcrypto\\sshcipher 
.set dir_blowfish.h lib\\sshcrypto\\sshcipher 
.set dir_des.h lib\\sshcrypto\\sshcipher 
.set dir_mode-gcm.h lib\\sshcrypto\\sshcipher 
.set dir_nociph.h lib\\sshcrypto\\sshcipher 
.set dir_octeon-cipher.h lib\\sshcrypto\\sshcipher 
.set dir_rc2.h lib\\sshcrypto\\sshcipher 
.set dir_rijndael.h lib\\sshcrypto\\sshcipher 
.set dir_sshcipher_i.h lib\\sshcrypto\\sshcipher 
.set dir_sshrotate.h lib\\sshcrypto\\sshcipher 
