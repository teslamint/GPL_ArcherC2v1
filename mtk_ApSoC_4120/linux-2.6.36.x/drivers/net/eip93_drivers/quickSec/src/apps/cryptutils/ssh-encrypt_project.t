.set project_name ssh-encrypt
.set project_type console
.set project_platforms \
	win32 \
	x64 \
	win32vista \
	x64vista \
	win32win7 \
	x64win7
.set project_guid DFED8357-38AA-3E73-8200-3524E1272197
.set project_dir apps\\cryptutils
.set project_dir_inverse ..\\..
.set project_incdirs \
	apps\\cryptutils \
	. \
	include
.set project_defs \
	HAVE_CONFIG_H
.set project_cflags
.set project_rcflags
.set project_libdirs
.set project_ldflags
.set project_libs
.set project_dependencies \
	..\\..\\lib\\sshcrypto\\libsshcrypto \
	..\\..\\lib\\sshutil\\libsshutil \
	..\\..\\lib\\sshmath\\libsshmath
.set outdir .
.set srcs \
	ssh-encrypt.c
.set dir_ssh-encrypt.c apps\\cryptutils 
.set custom_tags
.set rsrcs
.set hdrs
