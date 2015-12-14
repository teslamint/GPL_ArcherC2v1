.set project_name qsvnic5
.set project_type driver
.set project_platforms \
	win32 \
	x64 \
	win32vistandis5 \
	x64vistandis5 \
	win32win7ndis5 \
	x64win7ndis5 \
	std500armv4i \
	std500x86 \
	std500sh4 \
	std500mipsii \
	std500mipsii_fp \
	std500mipsiv \
	std500mipsiv_fp \
	ppc50armv4i \
	sp50armv4i \
	wm6std \
	wm6pro
.set project_guid F84D3031-B58E-3D7E-8000-4B322B316491
.set project_dir ipsec\\interceptor\\windows\\vnic\\ndis5_0
.set project_dir_inverse ..\\..\\..\\..\\..
.set project_incdirs \
	ipsec \
	ipsec\\engine \
	interceptor\\include \
	lib\\sshutil \
	lib\\sshutil\\sshcore \
	lib\\sshutil\\sshnet \
	ipsec\\interceptor\\windows\\vnic\\ndis5_0 \
	.
.set project_defs \
	SSH_BUILD_IPSEC \
	HAVE_CONFIG_H
.set project_cflags
.set project_rcflags
.set project_libdirs
.set project_ldflags
.set project_libs
.set project_dependencies
.set outdir .
.set srcs \
	sshvnic.c
.set dir_sshvnic.c interceptor\\windows\\vnic 
.set custom_tags
.set rsrcs \
	sshvnic5.rc
.set dir_sshvnic5.rc interceptor\\windows\\vnic\\ndis5_0 
.set hdrs \
	resource.h \
	sshvnic.h \
	sshvnic_def.h \
	sshvnicdbg.h
.set dir_resource.h interceptor\\windows\\vnic\\ndis5_0 
.set dir_sshvnic.h interceptor\\windows\\vnic 
.set dir_sshvnic_def.h interceptor\\windows\\vnic 
.set dir_sshvnicdbg.h interceptor\\windows\\vnic 
