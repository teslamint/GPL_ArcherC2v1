.set project_name sshhash
.set project_type applib
.set project_platforms
.set project_guid 638F2924-DF11-3358-8800-753E18476A64
.set project_dir lib\\sshcrypto\\sshhash
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
	lib\\sshcrypto\\sshhash
.set project_defs \
	HAVE_CONFIG_H
.set project_cflags
.set project_rcflags
.set project_libdirs
.set project_ldflags
.set project_libs
.set project_dependencies \
	@SSHHASH_CONF_OBJS@
.set outdir .
.set srcs \
	genhash.c \
	md2.c \
	md4.c \
	md5.c \
	mscapi-hash.c \
	octeon-hash.c \
	sha.c \
	sha256.c \
	sha512.c
.set dir_genhash.c lib\\sshcrypto\\sshhash 
.set dir_md2.c lib\\sshcrypto\\sshhash 
.set dir_md4.c lib\\sshcrypto\\sshhash 
.set dir_md5.c lib\\sshcrypto\\sshhash 
.set dir_mscapi-hash.c lib\\sshcrypto\\sshhash 
.set dir_octeon-hash.c lib\\sshcrypto\\sshhash 
.set dir_sha.c lib\\sshcrypto\\sshhash 
.set dir_sha256.c lib\\sshcrypto\\sshhash 
.set dir_sha512.c lib\\sshcrypto\\sshhash 
.set custom_tags
.set rsrcs
.set hdrs \
	md2.h \
	md4.h \
	md5.h \
	sha.h \
	sha256.h \
	sha512.h \
	sshhash_i.h
.set dir_md2.h lib\\sshcrypto\\sshhash 
.set dir_md4.h lib\\sshcrypto\\sshhash 
.set dir_md5.h lib\\sshcrypto\\sshhash 
.set dir_sha.h lib\\sshcrypto\\sshhash 
.set dir_sha256.h lib\\sshcrypto\\sshhash 
.set dir_sha512.h lib\\sshcrypto\\sshhash 
.set dir_sshhash_i.h lib\\sshcrypto\\sshhash 
