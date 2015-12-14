.set project_name sshexternalkey
.set project_type applib
.set project_platforms
.set project_guid 21B86D89-3195-351B-8E00-EA53596D85D2
.set project_dir lib\\sshexternalkey
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
	lib\\sshpkcs \
	lib\\sshenroll \
	lib\\sshvalidator \
	lib\\sshtls \
	lib\\sshapputil \
	lib\\sshexternalkey
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
	@OCTEON_SRCS@ \
	@SAFENET_UDM_SRCS@ \
	dummyacc.c \
	dummyprov.c \
	extkeyprov.c \
	genaccdevice.c \
	genaccprovider.c \
	msprovider.c \
	ocf_acc.c \
	octeon_acc.c \
	octeon_acci.c \
	safenet_acc.c \
	softacc.c \
	softprovider.c \
	sshexternalkey.c \
	sshsoftkey.c
.set dir_@OCTEON_SRCS@ lib\\sshexternalkey 
.set dir_@SAFENET_UDM_SRCS@ lib\\sshexternalkey 
.set dir_dummyacc.c lib\\sshexternalkey 
.set dir_dummyprov.c lib\\sshexternalkey 
.set dir_extkeyprov.c lib\\sshexternalkey 
.set dir_genaccdevice.c lib\\sshexternalkey 
.set dir_genaccprovider.c lib\\sshexternalkey 
.set dir_msprovider.c lib\\sshexternalkey 
.set dir_ocf_acc.c lib\\sshexternalkey 
.set dir_octeon_acc.c lib\\sshexternalkey 
.set dir_octeon_acci.c lib\\sshexternalkey 
.set dir_safenet_acc.c lib\\sshexternalkey 
.set dir_softacc.c lib\\sshexternalkey 
.set dir_softprovider.c lib\\sshexternalkey 
.set dir_sshexternalkey.c lib\\sshexternalkey 
.set dir_sshsoftkey.c lib\\sshexternalkey 
.set custom_tags
.set rsrcs
.set hdrs \
	dummyacc.h \
	dummyprov.h \
	extkeyprov.h \
	genaccdevicei.h \
	genaccprov.h \
	genaccprovider.h \
	genaccprovideri.h \
	msprovider.h \
	ocf_acc.h \
	octeon_acc.h \
	octeon_acci.h \
	safenet_acc.h \
	softacc.h \
	softprovider.h \
	softprovideri.h \
	sshexternalkey.h \
	sshmsprov_util.h \
	sshsoftkey.h
.set dir_dummyacc.h lib\\sshexternalkey 
.set dir_dummyprov.h lib\\sshexternalkey 
.set dir_extkeyprov.h lib\\sshexternalkey 
.set dir_genaccdevicei.h lib\\sshexternalkey 
.set dir_genaccprov.h lib\\sshexternalkey 
.set dir_genaccprovider.h lib\\sshexternalkey 
.set dir_genaccprovideri.h lib\\sshexternalkey 
.set dir_msprovider.h lib\\sshexternalkey 
.set dir_ocf_acc.h lib\\sshexternalkey 
.set dir_octeon_acc.h lib\\sshexternalkey 
.set dir_octeon_acci.h lib\\sshexternalkey 
.set dir_safenet_acc.h lib\\sshexternalkey 
.set dir_softacc.h lib\\sshexternalkey 
.set dir_softprovider.h lib\\sshexternalkey 
.set dir_softprovideri.h lib\\sshexternalkey 
.set dir_sshexternalkey.h lib\\sshexternalkey 
.set dir_sshmsprov_util.h lib\\sshexternalkey 
.set dir_sshsoftkey.h lib\\sshexternalkey 
