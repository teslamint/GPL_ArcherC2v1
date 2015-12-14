.set project_name sshpk
.set project_type applib
.set project_platforms
.set project_guid A3B0C9DB-08E9-3493-8E00-1AB82B0261D9
.set project_dir lib\\sshcrypto\\sshpk
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
	lib\\sshcrypto\\sshmac \
	lib\\sshcrypto\\sshpk
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
	dl-dh.c \
	dl-dsa.c \
	dl-generate.c \
	dl-stack.c \
	dl-utility.c \
	dlfix.c \
	dsa-maker.c \
	dsa-user.c \
	ecp-maker.c \
	ecp-user.c \
	ecpfix.c \
	ecpglue.c \
	genmp-integer.c \
	genmp-prime.c \
	genpkcs.c \
	genpkcs_dh.c \
	genpkcs_private.c \
	genpkcs_public.c \
	libmonitor.c \
	pkcs1.c \
	rsa-generate.c \
	rsa-maker.c \
	rsa-operation.c \
	rsa-user.c \
	rsa-utility.c \
	ssh-pk-export.c \
	ssh-pk-group.c \
	ssh-pk-prv-def.c \
	ssh-pk-prv-gen.c \
	sshproxykey.c \
	sshrgf-mgf1.c \
	sshrgf-oaep.c \
	sshrgf-pss.c \
	sshrgf.c
.set dir_dl-dh.c lib\\sshcrypto\\sshpk 
.set dir_dl-dsa.c lib\\sshcrypto\\sshpk 
.set dir_dl-generate.c lib\\sshcrypto\\sshpk 
.set dir_dl-stack.c lib\\sshcrypto\\sshpk 
.set dir_dl-utility.c lib\\sshcrypto\\sshpk 
.set dir_dlfix.c lib\\sshcrypto\\sshpk 
.set dir_dsa-maker.c lib\\sshcrypto\\sshpk 
.set dir_dsa-user.c lib\\sshcrypto\\sshpk 
.set dir_ecp-maker.c lib\\sshcrypto\\sshpk 
.set dir_ecp-user.c lib\\sshcrypto\\sshpk 
.set dir_ecpfix.c lib\\sshcrypto\\sshpk 
.set dir_ecpglue.c lib\\sshcrypto\\sshpk 
.set dir_genmp-integer.c lib\\sshcrypto\\sshpk 
.set dir_genmp-prime.c lib\\sshcrypto\\sshpk 
.set dir_genpkcs.c lib\\sshcrypto\\sshpk 
.set dir_genpkcs_dh.c lib\\sshcrypto\\sshpk 
.set dir_genpkcs_private.c lib\\sshcrypto\\sshpk 
.set dir_genpkcs_public.c lib\\sshcrypto\\sshpk 
.set dir_libmonitor.c lib\\sshcrypto\\sshpk 
.set dir_pkcs1.c lib\\sshcrypto\\sshpk 
.set dir_rsa-generate.c lib\\sshcrypto\\sshpk 
.set dir_rsa-maker.c lib\\sshcrypto\\sshpk 
.set dir_rsa-operation.c lib\\sshcrypto\\sshpk 
.set dir_rsa-user.c lib\\sshcrypto\\sshpk 
.set dir_rsa-utility.c lib\\sshcrypto\\sshpk 
.set dir_ssh-pk-export.c lib\\sshcrypto\\sshpk 
.set dir_ssh-pk-group.c lib\\sshcrypto\\sshpk 
.set dir_ssh-pk-prv-def.c lib\\sshcrypto\\sshpk 
.set dir_ssh-pk-prv-gen.c lib\\sshcrypto\\sshpk 
.set dir_sshproxykey.c lib\\sshcrypto\\sshpk 
.set dir_sshrgf-mgf1.c lib\\sshcrypto\\sshpk 
.set dir_sshrgf-oaep.c lib\\sshcrypto\\sshpk 
.set dir_sshrgf-pss.c lib\\sshcrypto\\sshpk 
.set dir_sshrgf.c lib\\sshcrypto\\sshpk 
.set custom_tags
.set rsrcs
.set hdrs \
	dl-internal.h \
	dl-stack.h \
	dlfix.h \
	dlglue.h \
	ecpfix.h \
	ecpglue.h \
	libmonitor.h \
	pkcs1.h \
	rsa.h \
	sshgenmp.h \
	sshpk_i.h \
	sshrgf-internal.h \
	sshrgf.h
.set dir_dl-internal.h lib\\sshcrypto\\sshpk 
.set dir_dl-stack.h lib\\sshcrypto\\sshpk 
.set dir_dlfix.h lib\\sshcrypto\\sshpk 
.set dir_dlglue.h lib\\sshcrypto\\sshpk 
.set dir_ecpfix.h lib\\sshcrypto\\sshpk 
.set dir_ecpglue.h lib\\sshcrypto\\sshpk 
.set dir_libmonitor.h lib\\sshcrypto\\sshpk 
.set dir_pkcs1.h lib\\sshcrypto\\sshpk 
.set dir_rsa.h lib\\sshcrypto\\sshpk 
.set dir_sshgenmp.h lib\\sshcrypto\\sshpk 
.set dir_sshpk_i.h lib\\sshcrypto\\sshpk 
.set dir_sshrgf-internal.h lib\\sshcrypto\\sshpk 
.set dir_sshrgf.h lib\\sshcrypto\\sshpk 
