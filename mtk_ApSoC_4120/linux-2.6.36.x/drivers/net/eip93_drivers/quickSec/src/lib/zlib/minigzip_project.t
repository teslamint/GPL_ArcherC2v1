.set project_name minigzip
.set project_type console
.set project_platforms \
	win32 \
	x64 \
	win32vista \
	x64vista \
	win32win7 \
	x64win7
.set project_guid C8752B55-00FA-3F35-8D00-207A7ACA6527
.set project_dir lib\\zlib
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
	lib\\zlib
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
	crc32.c \
	gzio.c \
	minigzip.c
.set dir_crc32.c lib\\zlib 
.set dir_gzio.c lib\\zlib 
.set dir_minigzip.c lib\\zlib 
.set custom_tags
.set rsrcs
.set hdrs \
	deflate.h \
	infblock.h \
	infcodes.h \
	inffast.h \
	inftrees.h \
	infutil.h \
	sshzlibrename.h \
	zconf.h \
	zlib.h \
	zutil.h
.set dir_deflate.h lib\\zlib 
.set dir_infblock.h lib\\zlib 
.set dir_infcodes.h lib\\zlib 
.set dir_inffast.h lib\\zlib 
.set dir_inftrees.h lib\\zlib 
.set dir_infutil.h lib\\zlib 
.set dir_sshzlibrename.h lib\\zlib 
.set dir_zconf.h lib\\zlib 
.set dir_zlib.h lib\\zlib 
.set dir_zutil.h lib\\zlib 
