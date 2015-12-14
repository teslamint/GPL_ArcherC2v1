.set project_name qssetup
.set project_type appdll
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
.set project_guid E7292501-09E5-3E3B-8600-943B6C129F43
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
	qssetup.c
.set dir_qssetup.c apps\\winceutils 
.set custom_tags
.set rsrcs \
	qssetup.rc
.set dir_qssetup.rc apps\\winceutils 
.set hdrs \
	qssetup.h
.set dir_qssetup.h apps\\winceutils 
