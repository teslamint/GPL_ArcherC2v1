
# Added by filter_add_makefile_libextra_stuff
# To keep automake silent about public and private headers
# not been set when something is added to them

public_headers =
private_headers =

#
# sshutil/libsshtestutil.a Makefile.am.raw
#
# Author: Antti Huima <huima@ssh.fi>
#
#  Copyright:
#          Copyright (c) 2002, 2003 SFNT Finland Oy.
# All rights reserved
#

AUTOMAKE_OPTIONS = 1.0 foreign dist-zip no-dependencies
WINCONF_OPTIONS = maintainer=tmo@ssh.fi


INCLUDES = -I$(srcdir)/.. -I$(top_srcdir)  -I$(top_srcdir)/lib/sshutil/sshcore  -I$(top_srcdir)/lib/sshutil/sshadt  -I$(top_srcdir)/lib/sshutil/ssheloop  -I$(top_srcdir)/lib/sshutil/sshstrutil  -I$(top_srcdir)/lib/sshutil/sshfsm  -I$(top_srcdir)/lib/sshutil/sshstream  -I$(top_srcdir)/lib/sshutil/sshsysutil  -I$(top_srcdir)/lib/sshutil/sshnet  -I$(top_srcdir)/lib/sshutil/sshmisc  -I$(top_srcdir)/lib/sshutil/sshaudit  -I$(top_srcdir)/lib/sshutil/sshpacketstream 
LDADD = $(top_builddir)/lib/sshutil/sshpacketstream/libsshpacketstream.a $(top_builddir)/lib/sshutil/sshaudit/libsshaudit.a $(top_builddir)/lib/sshutil/sshmisc/libsshmisc.a $(top_builddir)/lib/sshutil/sshnet/libsshnet.a $(top_builddir)/lib/sshutil/sshsysutil/libsshsysutil.a $(top_builddir)/lib/sshutil/sshstream/libsshstream.a $(top_builddir)/lib/sshutil/sshfsm/libsshfsm.a $(top_builddir)/lib/sshutil/sshstrutil/libsshstrutil.a $(top_builddir)/lib/sshutil/ssheloop/libssheloop.a $(top_builddir)/lib/sshutil/sshadt/libsshadt.a $(top_builddir)/lib/sshutil/sshcore/libsshcore.a 

EXTRA_DIST = 

noinst_LIBRARIES = libsshtestutil.a

libsshtestutil_a_SOURCES = sshregression.c 

public_headers += sshregression.h sshticks.h sshape_mark.h

GRANDLIB_OBJECTS = $(libsshtestutil_a_OBJECTS)


include $(top_srcdir)/Makefile.libextra
include $(top_srcdir)/Makefile.grandlib_provider

# EOF
