
# Added by filter_add_makefile_libextra_stuff
# To keep automake silent about public and private headers
# not been set when something is added to them

public_headers =
private_headers =

#
# sshutil/libssheloop.a Makefile.am.raw
#
# Author: Antti Huima <huima@ssh.fi>
#
#  Copyright:
#          Copyright (c) 2002, 2003 SFNT Finland Oy.
# All rights reserved
#

AUTOMAKE_OPTIONS = 1.0 foreign dist-zip no-dependencies
INCLUDES = -I$(srcdir)/.. -I$(top_srcdir)  -I$(top_srcdir)/lib/sshutil/sshcore  -I$(top_srcdir)/lib/sshutil/sshadt 
LDADD = $(top_builddir)/lib/sshutil/sshadt/libsshadt.a $(top_builddir)/lib/sshutil/sshcore/libsshcore.a 

WINCONF_OPTIONS = maintainer=kivinen@ssh.fi,kukkonen@ssh.fi

noinst_LIBRARIES = libssheloop.a

THREAD_SYSTEM_OBJS = @THREAD_SYSTEM_OBJS@

EXTRA_DIST = \
	win32/sshcondition.c \
        win32/ssheloop.c \
	win32/sshwineloop.c \
	win32/sshmutex.c \
	win32/sshthreadedtimeout.c \
	win32/sshthread.c \
     sshmt_pthreads.c sshmt_timeouts.c



libssheloop_a_SOURCES = \
	sshthreadedtimeout.c \
	sshtimeouts.c \
	sshthreadpool.c \
	sshnothreads.c \
	sshoperation.c \
	sshasyncop.c \
	sshunixeloop.c





libssheloop_a_DEPENDENCIES = $(THREAD_SYSTEM_OBJS)

libssheloop_a_SOURCES_windelta = \
	-sshthreadedtimeout.c \
	-sshunixeloop.c

libssheloop_a_LIBADD_windelta = \
	-$(THREAD_SYSTEM_OBJS)	\
        +win32/sshcondition.o \
        +win32/ssheloop.o \
	+win32/sshwineloop.o \
	+win32/sshmutex.o \
	+win32/sshthread.o \
	+win32/sshthreadedtimeout.o

public_headers += \
	sshtimeouts.h \
	sshmutex.h \
	sshcondition.h \
	ssheloop.h \
	sshthread.h \
	sshthreadpool.h \
	sshoperation.h \
	sshasyncop.h



private_headers += sshtimeoutsi.h


ADD_INCLUDES_windelta = +-I$(srcdir)/../sshmisc/win32/


GRANDLIB_OBJECTS = $(libssheloop_a_OBJECTS) $(libssheloop_a_LIBADD) $(THREAD_SYSTEM_OBJS)

include $(top_srcdir)/Makefile.libextra
include $(top_srcdir)/Makefile.grandlib_provider

# EOF
