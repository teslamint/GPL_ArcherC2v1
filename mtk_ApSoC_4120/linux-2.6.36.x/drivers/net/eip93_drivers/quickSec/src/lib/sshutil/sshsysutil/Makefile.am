
# Added by filter_add_makefile_libextra_stuff
# To keep automake silent about public and private headers
# not been set when something is added to them

public_headers =
private_headers =

#
# sshutil/libsshsysutil.a Makefile.am.raw
#
# Author: Antti Huima <huima@ssh.fi>
#
#  Copyright:
#          Copyright (c) 2002, 2003 SFNT Finland Oy.
#               All rights reserved
#

AUTOMAKE_OPTIONS = 1.0 foreign dist-zip no-dependencies
INCLUDES = -I$(srcdir)/.. -I$(top_srcdir)  -I$(top_srcdir)/lib/sshutil/sshcore  -I$(top_srcdir)/lib/sshutil/sshadt  -I$(top_srcdir)/lib/sshutil/ssheloop  -I$(top_srcdir)/lib/sshutil/sshstrutil  -I$(top_srcdir)/lib/sshutil/sshfsm  -I$(top_srcdir)/lib/sshutil/sshstream 
LDADD = $(top_builddir)/lib/sshutil/sshstream/libsshstream.a $(top_builddir)/lib/sshutil/sshfsm/libsshfsm.a $(top_builddir)/lib/sshutil/sshstrutil/libsshstrutil.a $(top_builddir)/lib/sshutil/ssheloop/libssheloop.a $(top_builddir)/lib/sshutil/sshadt/libsshadt.a $(top_builddir)/lib/sshutil/sshcore/libsshcore.a 

WINCONF_OPTIONS = maintainer=mtr@ssh.com,kivinen@ssh.com

noinst_LIBRARIES=libsshsysutil.a


libsshsysutil_a_SOURCES = \
	sshunixfdstream.c \
	sshmallocspare.c	\
	sshdlib.c \
	sshthreadedmbox.c \
	sshfilebuffer.c \
	sshfileio.c \
	sshsignals.c \
	sshunixdevicestream.c \
	sshunixdirectory.c 


















libsshsysutil_a_SOURCES_windelta = \
	-sshunixserial.c \
	-sshunixdevicestream.c \
	-sshunixfdstream.c \
	-sshunixdirectory.c \
	-sshsignals.c

libsshsysutil_a_LIBADD_windelta = \
	+win32/sshfdstream.o \
	+win32/sshwinstdiostream.o \
	+win32/sshdevicestream.o \
	+win32/sshwindirectory.o






public_headers += \
	sshfilebuffer.h \
	sshfileio.h \
	sshfdstream.h \
	sshsignals.h \
	sshdevicestream.h \
	sshdirectory.h \
	sshdlib.h \
	sshthreadedmbox.h 
















EXTRA_DIST = \
	win32/sshfdstream.c \
	win32/sshwinstdiostream.c \
	win32/sshdevicestream.c \
	win32/sshwindirectory.c \
	sshdlib.c 







GRANDLIB_OBJECTS = $(libsshsysutil_a_OBJECTS) $(libsshsysutil_a_LIBADD)

include $(top_srcdir)/Makefile.libextra
include $(top_srcdir)/Makefile.grandlib_provider
# EOF
