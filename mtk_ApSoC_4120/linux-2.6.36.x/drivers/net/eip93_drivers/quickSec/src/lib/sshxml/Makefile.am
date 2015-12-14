
# Added by filter_add_makefile_libextra_stuff
# To keep automake silent about public and private headers
# not been set when something is added to them

public_headers =
private_headers =

#
# Makefile.am.raw
#
# Copyright:
# 	Copyright (c) 2002-2004 SFNT Finland Oy.
#       All rights reserved.
#
# Automakefile for XML parser library.
#

AUTOMAKE_OPTIONS = 1.0 foreign dist-zip no-dependencies
INCLUDES = -I$(top_srcdir)  -I$(top_srcdir)/lib/sshutil/sshcore  -I$(top_srcdir)/lib/sshutil/sshadt  -I$(top_srcdir)/lib/sshutil/ssheloop  -I$(top_srcdir)/lib/sshutil/sshstrutil  -I$(top_srcdir)/lib/sshutil/sshfsm  -I$(top_srcdir)/lib/sshutil/sshstream  -I$(top_srcdir)/lib/sshutil/sshsysutil  -I$(top_srcdir)/lib/sshutil/sshnet  -I$(top_srcdir)/lib/sshutil/sshmisc  -I$(top_srcdir)/lib/sshutil/sshaudit  -I$(top_srcdir)/lib/sshutil/sshpacketstream  -I$(top_srcdir)/lib/sshutil/sshtestutil  -I$(top_srcdir)/lib/sshutil  -I$(top_srcdir)/lib/zlib  -I$(top_srcdir)/lib/sshmath  -I$(top_srcdir)/lib/sshasn1  -I$(top_srcdir)/lib/sshcrypto/sshcipher  -I$(top_srcdir)/lib/sshcrypto/sshhash  -I$(top_srcdir)/lib/sshcrypto/sshrandom  -I$(top_srcdir)/lib/sshcrypto/sshcryptocore  -I$(top_srcdir)/lib/sshcrypto/sshmac  -I$(top_srcdir)/lib/sshcrypto/sshpk  -I$(top_srcdir)/lib/sshcrypto  -I$(top_srcdir)/lib/sshcryptoaux  -I$(top_srcdir)/lib/sshradius  -I$(top_srcdir)/lib/sshldap  -I$(top_srcdir)/lib/sshhttp 
LDADD = libsshxml.a $(top_builddir)/lib/sshhttp/libsshhttp.a $(top_builddir)/lib/sshldap/libsshldap.a $(top_builddir)/lib/sshradius/libsshradius.a $(top_builddir)/lib/sshcryptoaux/libsshcryptoaux.a $(top_builddir)/lib/sshcrypto/libsshcrypto.a $(top_builddir)/lib/sshasn1/libsshasn1.a $(top_builddir)/lib/sshmath/libsshmath.a $(top_builddir)/lib/zlib/libz.a $(top_builddir)/lib/sshutil/libsshutil.a 

WINCONF_OPTIONS = maintainer=tmononen@safenet-inc.com

SUBDIRS = tests

noinst_LIBRARIES = libsshxml.a

libsshxml_a_SOURCES = sshxml_parser.c sshxml_verifier.c			\
sshxml_verifier_dfa.c sshxml_accessors.c sshxml_chain.c			\
sshxml_tables.c sshxml_input_file.c sshxml_input_data.c sshxml_dom.c

public_headers += sshxml.h sshxml_chain.h sshxml_structs.h	\
sshxml_dom.h
private_headers += sshxml_internal.h

bin_PROGRAMS = xml-tool xmlconf dtd-compress

GRANDLIB_OBJECTS =  $(libsshxml_a_OBJECTS)









include $(top_srcdir)/Makefile.libextra
include $(top_srcdir)/Makefile.grandlib_provider
