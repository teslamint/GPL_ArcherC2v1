
# Added by filter_add_makefile_libextra_stuff
# To keep automake silent about public and private headers
# not been set when something is added to them

public_headers =
private_headers =

## Process this file with automake to produce Makefile.in

#
# lib/sshutil Makefile.am
#
# Author: Tatu Ylonen <ylo@ssh.fi>
#
#  Copyright:
#          Copyright (c) 2002, 2003 SFNT Finland Oy.
#                    All rights reserved
#

AUTOMAKE_OPTIONS = 1.0 foreign dist-zip no-dependencies
INCLUDES = -I$(top_srcdir)  -I$(top_srcdir)/lib/sshutil/sshcore  -I$(top_srcdir)/lib/sshutil/sshadt  -I$(top_srcdir)/lib/sshutil/ssheloop  -I$(top_srcdir)/lib/sshutil/sshstrutil  -I$(top_srcdir)/lib/sshutil/sshfsm  -I$(top_srcdir)/lib/sshutil/sshstream  -I$(top_srcdir)/lib/sshutil/sshsysutil  -I$(top_srcdir)/lib/sshutil/sshnet  -I$(top_srcdir)/lib/sshutil/sshmisc  -I$(top_srcdir)/lib/sshutil/sshaudit  -I$(top_srcdir)/lib/sshutil/sshpacketstream  -I$(top_srcdir)/lib/sshutil/sshtestutil 
LDADD = $(top_builddir)/lib/sshutil/sshtestutil/libsshtestutil.a $(top_builddir)/lib/sshutil/sshpacketstream/libsshpacketstream.a $(top_builddir)/lib/sshutil/sshaudit/libsshaudit.a $(top_builddir)/lib/sshutil/sshmisc/libsshmisc.a $(top_builddir)/lib/sshutil/sshnet/libsshnet.a $(top_builddir)/lib/sshutil/sshsysutil/libsshsysutil.a $(top_builddir)/lib/sshutil/sshstream/libsshstream.a $(top_builddir)/lib/sshutil/sshfsm/libsshfsm.a $(top_builddir)/lib/sshutil/sshstrutil/libsshstrutil.a $(top_builddir)/lib/sshutil/ssheloop/libssheloop.a $(top_builddir)/lib/sshutil/sshadt/libsshadt.a $(top_builddir)/lib/sshutil/sshcore/libsshcore.a 

SUBDIRS = \
	sshcore \
	sshadt \
	ssheloop \
	sshstrutil \
	sshfsm \
	sshstream \
	sshsysutil \
	sshnet \
	sshmisc \
	sshaudit \
	sshpacketstream \
	sshtestutil \
	tests














# CONFOBJS = @LIBOBJS@

WINCONF_OPTIONS = maintainer=mtr@ssh.com,kivinen@ssh.com,tmo@ssh.fi

# noinst_LIBRARIES = libsshutil.a

public_headers +=               \
        sshincludes.h           \
        sshtypes.h              \
        kernel_includes.h       \
        sshincludes_unix.h      \
        sshincludes_vxworks.h   





public_headers_windelta = \
	-sshincludes_unix.h \
	+sshincludes_win32.h    \
	+sshwinconf.h           \
	+sshincludes_ntddk.h




EXTRA_DIST = \
	sshwinconf.h		\
	sshincludes_win32.h	\
	sshincludes_ntddk.h	\
	sshincludes_vxworks.h   














GRANDLIB = libsshutil.a


libsshutil_a_SUBLIBRARIES =			\
	sshcore/libsshcore.a			\
	sshadt/libsshadt.a			\
	sshstrutil/libsshstrutil.a		\
	ssheloop/libssheloop.a			\
	sshfsm/libsshfsm.a			\
	sshstream/libsshstream.a		\
	sshsysutil/libsshsysutil.a		\
	sshnet/libsshnet.a			\
	sshaudit/libsshaudit.a			\
	sshmisc/libsshmisc.a			\
	sshpacketstream/libsshpacketstream.a	\
	sshtestutil/libsshtestutil.a            












include $(top_srcdir)/Makefile.grandlib_maker
include $(top_srcdir)/Makefile.libextra

# EOF
