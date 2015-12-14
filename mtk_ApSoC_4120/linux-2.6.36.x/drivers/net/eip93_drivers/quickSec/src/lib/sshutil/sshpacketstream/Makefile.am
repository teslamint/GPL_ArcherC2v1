
# Added by filter_add_makefile_libextra_stuff
# To keep automake silent about public and private headers
# not been set when something is added to them

public_headers =
private_headers =

#
# sshutil/libsshpacketstream.a Makefile.am.raw
#
# Author: Antti Huima <huima@ssh.fi>
#
#  Copyright:
#          Copyright (c) 2002, 2003 SFNT Finland Oy.
# All rights reserved
#

AUTOMAKE_OPTIONS = 1.0 foreign dist-zip no-dependencies
INCLUDES = -I$(srcdir)/.. -I$(top_srcdir)  -I$(top_srcdir)/lib/sshutil/sshcore  -I$(top_srcdir)/lib/sshutil/sshadt  -I$(top_srcdir)/lib/sshutil/ssheloop  -I$(top_srcdir)/lib/sshutil/sshstrutil  -I$(top_srcdir)/lib/sshutil/sshfsm  -I$(top_srcdir)/lib/sshutil/sshstream  -I$(top_srcdir)/lib/sshutil/sshsysutil  -I$(top_srcdir)/lib/sshutil/sshnet  -I$(top_srcdir)/lib/sshutil/sshmisc  -I$(top_srcdir)/lib/sshutil/sshaudit 
LDADD = $(top_builddir)/lib/sshutil/sshaudit/libsshaudit.a $(top_builddir)/lib/sshutil/sshmisc/libsshmisc.a $(top_builddir)/lib/sshutil/sshnet/libsshnet.a $(top_builddir)/lib/sshutil/sshsysutil/libsshsysutil.a $(top_builddir)/lib/sshutil/sshstream/libsshstream.a $(top_builddir)/lib/sshutil/sshfsm/libsshfsm.a $(top_builddir)/lib/sshutil/sshstrutil/libsshstrutil.a $(top_builddir)/lib/sshutil/ssheloop/libssheloop.a $(top_builddir)/lib/sshutil/sshadt/libsshadt.a $(top_builddir)/lib/sshutil/sshcore/libsshcore.a 

WINCONF_OPTIONS = maintainer=ylo@ssh.fi,kivinen@ssh.fi

noinst_LIBRARIES=libsshpacketstream.a

EXTRA_DIST = 

libsshpacketstream_a_SOURCES = \
	sshpacketwrapper.c \
	sshpacketstream.c \
	sshpacketimpl.c

public_headers += \
	sshpacketstream.h

private_headers += \
	sshpacketint.h

GRANDLIB_OBJECTS = $(libsshpacketstream_a_OBJECTS)

include $(top_srcdir)/Makefile.libextra
include $(top_srcdir)/Makefile.grandlib_provider
# EOF
