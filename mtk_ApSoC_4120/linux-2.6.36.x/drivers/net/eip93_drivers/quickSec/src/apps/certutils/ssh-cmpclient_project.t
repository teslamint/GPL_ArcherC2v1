.set project_name ssh-cmpclient
.set project_type console
.set project_platforms \
	win32 \
	x64 \
	win32vista \
	x64vista \
	win32win7 \
	x64win7
.set project_guid 3BD39BE3-CCFC-3E0D-9900-EDA9345C9697
.set project_dir apps\\certutils
.set project_dir_inverse ..\\..
.set project_incdirs \
	apps\\certutils \
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
	..\\..\\lib\\libssh
.set outdir .
.set srcs \
	au-ek.c \
	dump-ber.c \
	dump-cert.c \
	dump-key.c \
	ec-cmp.c \
	iprintf.c \
	ssh-cmpclient.c
.set dir_au-ek.c apps\\certutils 
.set dir_dump-ber.c apps\\certutils 
.set dir_dump-cert.c apps\\certutils 
.set dir_dump-key.c apps\\certutils 
.set dir_ec-cmp.c apps\\certutils 
.set dir_iprintf.c apps\\certutils 
.set dir_ssh-cmpclient.c apps\\certutils 
.set custom_tags
.set rsrcs
.set hdrs \
	au-ek.h \
	ec-cep.h \
	ec-cmp.h \
	iprintf.h \
	parse-x509-forms.h
.set dir_au-ek.h apps\\certutils 
.set dir_ec-cep.h apps\\certutils 
.set dir_ec-cmp.h apps\\certutils 
.set dir_iprintf.h apps\\certutils 
.set dir_parse-x509-forms.h apps\\certutils 
