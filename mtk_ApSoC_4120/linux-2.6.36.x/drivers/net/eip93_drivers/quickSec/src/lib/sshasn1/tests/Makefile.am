
# Added by filter_add_makefile_libextra_stuff
# To keep automake silent about public and private headers
# not been set when something is added to them

public_headers =
private_headers =

## Process this file with automake to produce Makefile.in

#
# lib/sshasn1/tests Makefile.am
#
# Author: Tero Kivinen <kivinen@ssh.fi>
#
#  Copyright:
#          Copyright (c) 2002, 2003 SFNT Finland Oy.
#                    All rights reserved
#

AUTOMAKE_OPTIONS = 1.0 foreign dist-zip no-dependencies
WINCONF_OPTIONS = maintainer=mtr@ssh.com,kivinen@ssh.com



INCLUDES = -I$(srcdir)/.. -I$(top_srcdir)  -I$(top_srcdir)/lib/sshutil/sshcore  -I$(top_srcdir)/lib/sshutil/sshadt  -I$(top_srcdir)/lib/sshutil/ssheloop  -I$(top_srcdir)/lib/sshutil/sshstrutil  -I$(top_srcdir)/lib/sshutil/sshfsm  -I$(top_srcdir)/lib/sshutil/sshstream  -I$(top_srcdir)/lib/sshutil/sshsysutil  -I$(top_srcdir)/lib/sshutil/sshnet  -I$(top_srcdir)/lib/sshutil/sshmisc  -I$(top_srcdir)/lib/sshutil/sshaudit  -I$(top_srcdir)/lib/sshutil/sshpacketstream  -I$(top_srcdir)/lib/sshutil/sshtestutil  -I$(top_srcdir)/lib/sshutil  -I$(top_srcdir)/lib/zlib  -I$(top_srcdir)/lib/sshmath 
LDADD = ../libsshasn1.a $(top_builddir)/lib/sshmath/libsshmath.a $(top_builddir)/lib/zlib/libz.a $(top_builddir)/lib/sshutil/libsshutil.a 

TESTS_LIGHT = t-asn1

TESTS = $(TESTS_LIGHT)

EXTRA_PROGRAMS = $(TESTS) t-decode

EXTRA_DIST =

t_decode_SOURCES = t-decode.c
t_decode_DEPENDENCIES = $(LDADD)
t_asn1_SOURCES = t-asn1.c
t_asn1_DEPENDENCIES = $(LDADD)

grandlib:
	@if test ! -f grandlib_objs; then touch grandlib_objs; fi



include $(top_srcdir)/Makefile.libextra
include $(top_srcdir)/Makefile.grandlib_provider

# EOF
