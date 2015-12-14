
# Added by filter_add_makefile_libextra_stuff
# To keep automake silent about public and private headers
# not been set when something is added to them

public_headers =
private_headers =

## Process this file with automake to produce Makefile.in

#
# lib/sshldap/tests Makefile.am
# Author: Tero Kivinen <kivinen@ssh.fi>
#
#  Copyright:
#          Copyright (c) 2002, 2003, 2004, 2005 SFNT Finland Oy.
#            All rights reserved
#
# This directory contains only interactive test programs.
#
AUTOMAKE_OPTIONS = 1.0 foreign dist-zip no-dependencies
WINCONF_OPTIONS  = maintainer=kivinen@ssh.fi

INCLUDES   = -I$(srcdir)/.. -I$(top_srcdir)  -I$(top_srcdir)/lib/sshutil/sshcore  -I$(top_srcdir)/lib/sshutil/sshadt  -I$(top_srcdir)/lib/sshutil/ssheloop  -I$(top_srcdir)/lib/sshutil/sshstrutil  -I$(top_srcdir)/lib/sshutil/sshfsm  -I$(top_srcdir)/lib/sshutil/sshstream  -I$(top_srcdir)/lib/sshutil/sshsysutil  -I$(top_srcdir)/lib/sshutil/sshnet  -I$(top_srcdir)/lib/sshutil/sshmisc  -I$(top_srcdir)/lib/sshutil/sshaudit  -I$(top_srcdir)/lib/sshutil/sshpacketstream  -I$(top_srcdir)/lib/sshutil/sshtestutil  -I$(top_srcdir)/lib/sshutil  -I$(top_srcdir)/lib/zlib  -I$(top_srcdir)/lib/sshmath  -I$(top_srcdir)/lib/sshasn1  -I$(top_srcdir)/lib/sshcrypto/sshcipher  -I$(top_srcdir)/lib/sshcrypto/sshhash  -I$(top_srcdir)/lib/sshcrypto/sshrandom  -I$(top_srcdir)/lib/sshcrypto/sshcryptocore  -I$(top_srcdir)/lib/sshcrypto/sshmac  -I$(top_srcdir)/lib/sshcrypto/sshpk  -I$(top_srcdir)/lib/sshcrypto  -I$(top_srcdir)/lib/sshcryptoaux  -I$(top_srcdir)/lib/sshradius 
LDADD      = ../libsshldap.a $(top_builddir)/lib/sshradius/libsshradius.a $(top_builddir)/lib/sshcryptoaux/libsshcryptoaux.a $(top_builddir)/lib/sshcrypto/libsshcrypto.a $(top_builddir)/lib/sshasn1/libsshasn1.a $(top_builddir)/lib/sshmath/libsshmath.a $(top_builddir)/lib/zlib/libz.a $(top_builddir)/lib/sshutil/libsshutil.a 
EXTRA_DIST =
CLEANFILES =


TESTS_LIGHT      = t-dummy t-ldapfilter
TESTS = $(TESTS_LIGHT)
TESTS_LIGHT_windelta = -t-dummy

EXTRA_PROGRAMS = t-ldap t-ldapconv t-dummy t-ldapfilter
EXTRA_PROGRAMS_windelta = -t-dummy

t_dummy_SOURCES = t-dummy.c
t_dummy_DEPENDENCIES = $(LDADD)

t_ldapfilter_SOURCES = t-ldapfilter.c
t_ldapfilter_DEPENDENCIES = $(LDADD)

t_ldap_SOURCES = t-ldap.c
t_ldap_DEPENDENCIES = $(LDADD)

t_ldapconv_SOURCES = t-ldapconv.c
t_ldapconv_DEPENDENCIES = $(LDADD)

include $(top_srcdir)/Makefile.libextra
include $(top_srcdir)/Makefile.grandlib_provider

# EOF
