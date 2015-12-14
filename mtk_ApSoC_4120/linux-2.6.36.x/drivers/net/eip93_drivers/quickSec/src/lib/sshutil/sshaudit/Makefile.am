
# Added by filter_add_makefile_libextra_stuff
# To keep automake silent about public and private headers
# not been set when something is added to them

public_headers =
private_headers =

#
# sshutil/libsshaudit.a Makefile.am.raw
#
# Author: Markku Rossi <mtr@ssh.fi>
#
#  Copyright:
#          Copyright (c) 2002, 2003 SFNT Finland Oy.
# All rights reserved
#

AUTOMAKE_OPTIONS = 1.0 foreign dist-zip no-dependencies
INCLUDES = -I$(srcdir)/.. -I$(top_srcdir)  -I$(top_srcdir)/lib/sshutil/sshcore  -I$(top_srcdir)/lib/sshutil/sshadt  -I$(top_srcdir)/lib/sshutil/ssheloop  -I$(top_srcdir)/lib/sshutil/sshstrutil  -I$(top_srcdir)/lib/sshutil/sshfsm  -I$(top_srcdir)/lib/sshutil/sshstream  -I$(top_srcdir)/lib/sshutil/sshsysutil  -I$(top_srcdir)/lib/sshutil/sshnet  -I$(top_srcdir)/lib/sshutil/sshmisc 
LDADD = $(top_builddir)/lib/sshutil/sshmisc/libsshmisc.a $(top_builddir)/lib/sshutil/sshnet/libsshnet.a $(top_builddir)/lib/sshutil/sshsysutil/libsshsysutil.a $(top_builddir)/lib/sshutil/sshstream/libsshstream.a $(top_builddir)/lib/sshutil/sshfsm/libsshfsm.a $(top_builddir)/lib/sshutil/sshstrutil/libsshstrutil.a $(top_builddir)/lib/sshutil/ssheloop/libssheloop.a $(top_builddir)/lib/sshutil/sshadt/libsshadt.a $(top_builddir)/lib/sshutil/sshcore/libsshcore.a 

WINCONF_OPTIONS = maintainer=mtr@ssh.fi

noinst_LIBRARIES = libsshaudit.a

libsshaudit_a_SOURCES = sshaudit.c        \
			sshaudit_tables.c \
			sshaudit_util.c	  \
			sshaudit_file.c   \
			sshaudit_syslog.c



libsshaudit_a_SOURCES_windelta = +sshaudit_winsyslog.c

public_headers += sshaudit.h sshaudit_file.h sshaudit_syslog.h
public_headers_windelta = +sshaudit_winsyslog.h

private_headers +=                \
		sshaudit_util.h




EXTRA_DIST = sshaudit_winsyslog.c sshaudit_winsyslog.h

GRANDLIB_OBJECTS = $(libsshaudit_a_OBJECTS)

include $(top_srcdir)/Makefile.libextra
include $(top_srcdir)/Makefile.grandlib_provider
