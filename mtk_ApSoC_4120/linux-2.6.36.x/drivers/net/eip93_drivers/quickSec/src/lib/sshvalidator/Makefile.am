
# Added by filter_add_makefile_libextra_stuff
# To keep automake silent about public and private headers
# not been set when something is added to them

public_headers =
private_headers =

#
# lib/sshvalidator Makefile.am
#
# Copyright:
# 	Copyright (c) 2002, 2003, 2005 SFNT Finland Oy.
# 	All rights reserved
#

AUTOMAKE_OPTIONS = 1.0 foreign dist-zip no-dependencies
INCLUDES = -I$(top_srcdir)  -I$(top_srcdir)/lib/sshutil/sshcore  -I$(top_srcdir)/lib/sshutil/sshadt  -I$(top_srcdir)/lib/sshutil/ssheloop  -I$(top_srcdir)/lib/sshutil/sshstrutil  -I$(top_srcdir)/lib/sshutil/sshfsm  -I$(top_srcdir)/lib/sshutil/sshstream  -I$(top_srcdir)/lib/sshutil/sshsysutil  -I$(top_srcdir)/lib/sshutil/sshnet  -I$(top_srcdir)/lib/sshutil/sshmisc  -I$(top_srcdir)/lib/sshutil/sshaudit  -I$(top_srcdir)/lib/sshutil/sshpacketstream  -I$(top_srcdir)/lib/sshutil/sshtestutil  -I$(top_srcdir)/lib/sshutil  -I$(top_srcdir)/lib/zlib  -I$(top_srcdir)/lib/sshmath  -I$(top_srcdir)/lib/sshasn1  -I$(top_srcdir)/lib/sshcrypto/sshcipher  -I$(top_srcdir)/lib/sshcrypto/sshhash  -I$(top_srcdir)/lib/sshcrypto/sshrandom  -I$(top_srcdir)/lib/sshcrypto/sshcryptocore  -I$(top_srcdir)/lib/sshcrypto/sshmac  -I$(top_srcdir)/lib/sshcrypto/sshpk  -I$(top_srcdir)/lib/sshcrypto  -I$(top_srcdir)/lib/sshcryptoaux  -I$(top_srcdir)/lib/sshradius  -I$(top_srcdir)/lib/sshldap  -I$(top_srcdir)/lib/sshhttp  -I$(top_srcdir)/lib/sshxml  -I$(top_srcdir)/lib/sshcert  -I$(top_srcdir)/lib/sshpkcs  -I$(top_srcdir)/lib/sshenroll 
LDADD = $(top_builddir)/lib/sshenroll/libsshenroll.a $(top_builddir)/lib/sshpkcs/libsshpkcs.a $(top_builddir)/lib/sshcert/libsshcert.a $(top_builddir)/lib/sshxml/libsshxml.a $(top_builddir)/lib/sshhttp/libsshhttp.a $(top_builddir)/lib/sshldap/libsshldap.a $(top_builddir)/lib/sshradius/libsshradius.a $(top_builddir)/lib/sshcryptoaux/libsshcryptoaux.a $(top_builddir)/lib/sshcrypto/libsshcrypto.a $(top_builddir)/lib/sshasn1/libsshasn1.a $(top_builddir)/lib/sshmath/libsshmath.a $(top_builddir)/lib/zlib/libz.a $(top_builddir)/lib/sshutil/libsshutil.a 

WINCONF_OPTIONS = maintainer=tmononen@safenet-inc.com

SUBDIRS = tests

noinst_LIBRARIES = libsshvalidator.a

libsshvalidator_a_SOURCES = \
   cert-db.c 	\
   cmi.c 	\
   cmi-pcnst.c 	\
   cmi-config.c \
   cmi-key.c 	\
   cmi-key-pk.c \
   cmi-cert.c 	\
   cmi-crl.c 	\
   cmi-trust.c 	\
   cmi-list.c 	\
   cmi-edb.c 	\
   cmi-map.c 	\
   cmi-pkcs7.c 	\
   cmi-ldap.c 	\
   cmi-http.c 	\
   cmi-ocsp.c	\
   cmi-debug.c









GRANDLIB_OBJECTS =  $(libsshvalidator_a_OBJECTS) $(libsshvalidator_a_LIBADD)

cmi-key.c: cert-db.h
cmi.c: cmi-internal.h cmi.h cert-db.h

public_headers += \
   cmi.h \
   cmi-edb.h

private_headers += \
   cmi-internal.h \
   cmi-debug.h \
   cmi-map.h \
   cert-db.h

include $(top_srcdir)/Makefile.libextra
include $(top_srcdir)/Makefile.grandlib_provider
