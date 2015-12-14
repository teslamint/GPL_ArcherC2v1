
# Added by filter_add_makefile_libextra_stuff
# To keep automake silent about public and private headers
# not been set when something is added to them

public_headers =
private_headers =

#
# sshutil/libsshfsm.a Makefile.am.raw
#
# Author: Antti Huima <huima@ssh.fi>
#
#  Copyright:
#          Copyright (c) 2002, 2003 SFNT Finland Oy.
# All rights reserved
#

AUTOMAKE_OPTIONS = 1.0 foreign dist-zip no-dependencies
INCLUDES = -I$(srcdir)/.. -I$(top_srcdir)  -I$(top_srcdir)/lib/sshutil/sshcore  -I$(top_srcdir)/lib/sshutil/sshadt  -I$(top_srcdir)/lib/sshutil/ssheloop  -I$(top_srcdir)/lib/sshutil/sshstrutil 
LDADD = $(top_builddir)/lib/sshutil/sshstrutil/libsshstrutil.a $(top_builddir)/lib/sshutil/ssheloop/libssheloop.a $(top_builddir)/lib/sshutil/sshadt/libsshadt.a $(top_builddir)/lib/sshutil/sshcore/libsshcore.a 

WINCONF_OPTIONS = maintainer=mtr@ssh.fi

noinst_LIBRARIES=libsshfsm.a

SUBDIRS = tutorial

EXTRA_DIST =

libsshfsm_a_SOURCES =   \
        sshfsm.c        




public_headers +=               \
        sshfsm.h                \
        sshfsm_internal.h       




GRANDLIB_OBJECTS = $(libsshfsm_a_OBJECTS)

include $(top_srcdir)/Makefile.libextra
include $(top_srcdir)/Makefile.grandlib_provider
# EOF
