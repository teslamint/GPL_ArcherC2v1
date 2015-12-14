
# Added by filter_add_makefile_libextra_stuff
# To keep automake silent about public and private headers
# not been set when something is added to them

public_headers =
private_headers =

## Process this file with automake to produce Makefile.in

#
# lib/sshpkcs Makefile.am
#
#  Copyright:
#          Copyright (c) 2002, 2003 SFNT Finland Oy.
#               All rights reserved
#

AUTOMAKE_OPTIONS = 1.0 foreign dist-zip no-dependencies
INCLUDES = -I$(top_srcdir)  -I$(top_srcdir)/lib/sshutil/sshcore  -I$(top_srcdir)/lib/sshutil/sshadt  -I$(top_srcdir)/lib/sshutil/ssheloop  -I$(top_srcdir)/lib/sshutil/sshstrutil  -I$(top_srcdir)/lib/sshutil/sshfsm  -I$(top_srcdir)/lib/sshutil/sshstream  -I$(top_srcdir)/lib/sshutil/sshsysutil  -I$(top_srcdir)/lib/sshutil/sshnet  -I$(top_srcdir)/lib/sshutil/sshmisc  -I$(top_srcdir)/lib/sshutil/sshaudit  -I$(top_srcdir)/lib/sshutil/sshpacketstream  -I$(top_srcdir)/lib/sshutil/sshtestutil  -I$(top_srcdir)/lib/sshutil  -I$(top_srcdir)/lib/zlib  -I$(top_srcdir)/lib/sshmath  -I$(top_srcdir)/lib/sshasn1  -I$(top_srcdir)/lib/sshcrypto/sshcipher  -I$(top_srcdir)/lib/sshcrypto/sshhash  -I$(top_srcdir)/lib/sshcrypto/sshrandom  -I$(top_srcdir)/lib/sshcrypto/sshcryptocore  -I$(top_srcdir)/lib/sshcrypto/sshmac  -I$(top_srcdir)/lib/sshcrypto/sshpk  -I$(top_srcdir)/lib/sshcrypto  -I$(top_srcdir)/lib/sshcryptoaux  -I$(top_srcdir)/lib/sshradius  -I$(top_srcdir)/lib/sshldap  -I$(top_srcdir)/lib/sshhttp  -I$(top_srcdir)/lib/sshxml  -I$(top_srcdir)/lib/sshcert 
LDADD = $(top_builddir)/lib/sshcert/libsshcert.a $(top_builddir)/lib/sshxml/libsshxml.a $(top_builddir)/lib/sshhttp/libsshhttp.a $(top_builddir)/lib/sshldap/libsshldap.a $(top_builddir)/lib/sshradius/libsshradius.a $(top_builddir)/lib/sshcryptoaux/libsshcryptoaux.a $(top_builddir)/lib/sshcrypto/libsshcrypto.a $(top_builddir)/lib/sshasn1/libsshasn1.a $(top_builddir)/lib/sshmath/libsshmath.a $(top_builddir)/lib/zlib/libz.a $(top_builddir)/lib/sshutil/libsshutil.a 

WINCONF_OPTIONS = maintainer=tmo@ssh.fi

SUBDIRS = tests

noinst_LIBRARIES = libsshpkcs.a

libsshpkcs_a_SOURCES = \
   pkcs1-formats.c \
   pkcs5.c \
   pkcs6.c \
   pkcs7-common.c \
   pkcs7-decode.c \
   pkcs7-receive.c \
   pkcs7-encode.c \
   pkcs7-create.c \
   pkcs6-cert.c \
   pkcs7-receive-sync.c \
   pkcs7-create-sync.c \
   pkcs8.c \
   pkcs12.c \
   pkcs12-conv.c



GRANDLIB_OBJECTS =  $(libsshpkcs_a_OBJECTS) $(libsshpkcs_a_LIBADD)

public_headers += \
   sshpkcs1.h \
   sshpkcs5.h \
   sshpkcs7.h \
   sshpkcs8.h \
   sshpkcs12.h \
   sshpkcs12-conv.h

private_headers += \
   pkcs6.h \
   pkcs7-internal.h

include $(top_srcdir)/Makefile.libextra
include $(top_srcdir)/Makefile.grandlib_provider
