.set project_name ssh-keytool
.set project_type console
.set project_platforms \
	win32 \
	x64 \
	win32vista \
	x64vista \
	win32win7 \
	x64win7
.set project_guid 6CCD8039-22A2-3367-9500-7AE576546C1B
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
	dump-key.c \
	iprintf.c \
	ssh-keytool.c
.set dir_dump-key.c apps\\certutils 
.set dir_iprintf.c apps\\certutils 
.set dir_ssh-keytool.c apps\\certutils 
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
