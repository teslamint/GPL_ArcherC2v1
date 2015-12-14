.set project_name qsinfo
.set project_type windows
.set project_platforms \
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
.set project_guid 0F2DB0A4-90A8-3DA0-9700-E8BEE27A266D
.set project_dir apps\\winceutils
.set project_dir_inverse ..\\..
.set project_incdirs \
	apps\\winceutils \
	.
.set project_defs \
	QS_SETUP_EXPORTS \
	HAVE_CONFIG_H
.set project_cflags
.set project_rcflags
.set project_libdirs
.set project_ldflags
.set project_libs
.set project_dependencies
.set outdir .
.set srcs \
	qsinfo.c
.set dir_qsinfo.c apps\\winceutils 
.set custom_tags
.set rsrcs \
	qsinfo.rc
.set dir_qsinfo.rc apps\\winceutils 
.set hdrs \
	qsinfo.h
.set dir_qsinfo.h apps\\winceutils 
