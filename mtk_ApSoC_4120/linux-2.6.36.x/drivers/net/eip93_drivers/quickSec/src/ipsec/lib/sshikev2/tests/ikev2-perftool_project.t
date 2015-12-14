.set project_name ikev2-perftool
.set project_type console
.set project_platforms
.set project_guid D039474E-8089-39E1-9100-171E881D4D48
.set project_dir ipsec\\lib\\sshikev2\\tests
.set project_dir_inverse ..\\..\\..\\..
.set project_incdirs \
	ipsec\\lib\\sshikev2 \
	ipsec \
	. \
	include \
	ipsec\\lib\\sshisakmp \
	ipsec\\lib\\sshikev2\\tests
.set project_defs \
	SSH_BUILD_IPSEC \
	HAVE_CONFIG_H
.set project_cflags
.set project_rcflags
.set project_libdirs
.set project_ldflags
.set project_libs
.set project_dependencies \
	..\\libsshikev2 \
	ssh-certmake
.set outdir .
.set srcs \
	dummy-if.c \
	ikev2-perftool.c \
	pad-dummy.c \
	pad-eap-dummy.c \
	pm_ike_confutils.c \
	pm_ike_sautils.c \
	pm_ike_tsutils.c \
	sad-dummy.c \
	spd-dummy.c
.set dir_dummy-if.c ipsec\\lib\\sshikev2\\tests 
.set dir_ikev2-perftool.c ipsec\\lib\\sshikev2\\tests 
.set dir_pad-dummy.c ipsec\\lib\\sshikev2\\tests 
.set dir_pad-eap-dummy.c ipsec\\lib\\sshikev2\\tests 
.set dir_pm_ike_confutils.c ipsec\\lib\\sshikev2\\tests 
.set dir_pm_ike_sautils.c ipsec\\lib\\sshikev2\\tests 
.set dir_pm_ike_tsutils.c ipsec\\lib\\sshikev2\\tests 
.set dir_sad-dummy.c ipsec\\lib\\sshikev2\\tests 
.set dir_spd-dummy.c ipsec\\lib\\sshikev2\\tests 
.set custom_input_0 {srctop}\\ipsec\\lib\\sshikev2\\tests\\test.x509
.set custom_output_0 test-ca-1.ca
.set custom_command_0 ..\\..\\..\\..\\apps\\certutils\\$(OutDir)\\ssh-certmake {srctop}\\ipsec\\lib\\sshikev2\\tests\\test.x509
.set custom_platforms_0 win32 x64 win32vista x64vista win32win7 x64win7
.set custom_tags \
	0
.set rsrcs
.set hdrs \
	dummy-if.h \
	pad-dummy.h \
	pm_ike_sad.h \
	sad-dummy.h \
	spd-dummy.h
.set dir_dummy-if.h ipsec\\lib\\sshikev2\\tests 
.set dir_pad-dummy.h ipsec\\lib\\sshikev2\\tests 
.set dir_pm_ike_sad.h ipsec\\lib\\sshikev2\\tests 
.set dir_sad-dummy.h ipsec\\lib\\sshikev2\\tests 
.set dir_spd-dummy.h ipsec\\lib\\sshikev2\\tests 
