.set project_name sshpacketstream
.set project_type applib
.set project_platforms
.set project_guid D3F312E3-B689-32DA-8500-B2A045D86CF3
.set project_dir lib\\sshutil\\sshpacketstream
.set project_dir_inverse ..\\..\\..
.set project_incdirs \
	lib\\sshutil \
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
	lib\\sshutil\\sshpacketstream
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
	sshpacketimpl.c \
	sshpacketstream.c \
	sshpacketwrapper.c
.set dir_sshpacketimpl.c lib\\sshutil\\sshpacketstream 
.set dir_sshpacketstream.c lib\\sshutil\\sshpacketstream 
.set dir_sshpacketwrapper.c lib\\sshutil\\sshpacketstream 
.set custom_tags
.set rsrcs
.set hdrs \
	sshpacketint.h \
	sshpacketstream.h
.set dir_sshpacketint.h lib\\sshutil\\sshpacketstream 
.set dir_sshpacketstream.h lib\\sshutil\\sshpacketstream 
