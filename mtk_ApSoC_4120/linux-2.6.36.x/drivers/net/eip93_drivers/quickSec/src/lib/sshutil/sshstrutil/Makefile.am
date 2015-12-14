
# Added by filter_add_makefile_libextra_stuff
# To keep automake silent about public and private headers
# not been set when something is added to them

public_headers =
private_headers =

#
# sshutil/libsshstrutil.a Makefile.am.raw
#
# Copyright:
# 	Copyright (c) 2002, 2003 SFNT Finland Oy.
#       All rights reserved.
#

AUTOMAKE_OPTIONS = 1.0 foreign dist-zip no-dependencies
INCLUDES = -I$(srcdir)/.. -I$(top_srcdir)  -I$(top_srcdir)/lib/sshutil/sshcore  -I$(top_srcdir)/lib/sshutil/sshadt  -I$(top_srcdir)/lib/sshutil/ssheloop 
LDADD = $(top_builddir)/lib/sshutil/ssheloop/libssheloop.a $(top_builddir)/lib/sshutil/sshadt/libsshadt.a $(top_builddir)/lib/sshutil/sshcore/libsshcore.a 

WINCONF_OPTIONS = kivinen@safenet-inc.com

EXTRA_DIST = REGEX-SYNTAX \
	     sshregexsyn_egrep.c \
	     sshregexsyn_ssh.c \
	     sshregexsyn_zsh.c

noinst_LIBRARIES=libsshstrutil.a

libsshstrutil_a_SOURCES = \
	sshencode.c \
	sshencodetypes.c \
	sshutf8.c \
	sshbase64.c \
	sshbase16.c \
	sshregex.c \
	sshstr.c \
	sshfingerprint.c \
	sshmiscstring.c \
	sshbitvector.c 














public_headers += \
	sshencode.h \
	sshutf8.h \
	sshbase64.h \
	sshbase16.h \
	sshregex.h sshdlex.h \
	sshstr.h \
	sshfingerprint.h \
	sshmiscstring.h \
	sshbitvector.h 














GRANDLIB_OBJECTS = $(libsshstrutil_a_OBJECTS)

include $(top_srcdir)/Makefile.libextra
include $(top_srcdir)/Makefile.grandlib_provider
# EOF
