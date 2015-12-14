.set project_name ssheloop
.set project_type applib
.set project_platforms
.set project_guid 6E65EAF3-0803-31A1-9400-C85DB357FF80
.set project_dir lib\\sshutil\\ssheloop
.set project_dir_inverse ..\\..\\..
.set project_incdirs \
	lib\\sshutil \
	. \
	lib\\sshutil\\sshcore \
	lib\\sshutil\\sshadt \
	lib\\sshutil\\ssheloop
.set project_defs \
	HAVE_CONFIG_H
.set project_cflags
.set project_rcflags
.set project_libdirs
.set project_ldflags
.set project_libs
.set project_dependencies \
	@THREAD_SYSTEM_OBJS@
.set outdir .
.set srcs \
	sshasyncop.c \
	sshnothreads.c \
	sshoperation.c \
	sshthreadpool.c \
	sshtimeouts.c \
	sshcondition.c \
	ssheloop.c \
	sshmutex.c \
	sshthread.c \
	sshthreadedtimeout.c \
	sshwineloop.c
.set dir_sshasyncop.c lib\\sshutil\\ssheloop 
.set dir_sshnothreads.c lib\\sshutil\\ssheloop 
.set dir_sshoperation.c lib\\sshutil\\ssheloop 
.set dir_sshthreadpool.c lib\\sshutil\\ssheloop 
.set dir_sshtimeouts.c lib\\sshutil\\ssheloop 
.set dir_sshcondition.c lib\\sshutil\\ssheloop\\win32 
.set dir_ssheloop.c lib\\sshutil\\ssheloop\\win32 
.set dir_sshmutex.c lib\\sshutil\\ssheloop\\win32 
.set dir_sshthread.c lib\\sshutil\\ssheloop\\win32 
.set dir_sshthreadedtimeout.c lib\\sshutil\\ssheloop\\win32 
.set dir_sshwineloop.c lib\\sshutil\\ssheloop\\win32 
.set custom_tags
.set rsrcs
.set hdrs \
	sshasyncop.h \
	sshcondition.h \
	ssheloop.h \
	sshmutex.h \
	sshoperation.h \
	sshthread.h \
	sshthreadpool.h \
	sshtimeouts.h \
	sshtimeoutsi.h
.set dir_sshasyncop.h lib\\sshutil\\ssheloop 
.set dir_sshcondition.h lib\\sshutil\\ssheloop 
.set dir_ssheloop.h lib\\sshutil\\ssheloop 
.set dir_sshmutex.h lib\\sshutil\\ssheloop 
.set dir_sshoperation.h lib\\sshutil\\ssheloop 
.set dir_sshthread.h lib\\sshutil\\ssheloop 
.set dir_sshthreadpool.h lib\\sshutil\\ssheloop 
.set dir_sshtimeouts.h lib\\sshutil\\ssheloop 
.set dir_sshtimeoutsi.h lib\\sshutil\\ssheloop 
