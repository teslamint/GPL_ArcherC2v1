
# Added by filter_add_makefile_libextra_stuff
# To keep automake silent about public and private headers
# not been set when something is added to them

public_headers =
private_headers =

#
# lib/sshcert Makefile.am
#
# Copyright:
# 	Copyright (c) 2002, 2003, 2005 SFNT Finland Oy.
# 	All rights reserved
#

AUTOMAKE_OPTIONS = 1.0 foreign dist-zip no-dependencies
INCLUDES = -I$(top_srcdir)  -I$(top_srcdir)/lib/sshutil/sshcore  -I$(top_srcdir)/lib/sshutil/sshadt  -I$(top_srcdir)/lib/sshutil/ssheloop  -I$(top_srcdir)/lib/sshutil/sshstrutil  -I$(top_srcdir)/lib/sshutil/sshfsm  -I$(top_srcdir)/lib/sshutil/sshstream  -I$(top_srcdir)/lib/sshutil/sshsysutil  -I$(top_srcdir)/lib/sshutil/sshnet  -I$(top_srcdir)/lib/sshutil/sshmisc  -I$(top_srcdir)/lib/sshutil/sshaudit  -I$(top_srcdir)/lib/sshutil/sshpacketstream  -I$(top_srcdir)/lib/sshutil/sshtestutil  -I$(top_srcdir)/lib/sshutil  -I$(top_srcdir)/lib/zlib  -I$(top_srcdir)/lib/sshmath  -I$(top_srcdir)/lib/sshasn1  -I$(top_srcdir)/lib/sshcrypto/sshcipher  -I$(top_srcdir)/lib/sshcrypto/sshhash  -I$(top_srcdir)/lib/sshcrypto/sshrandom  -I$(top_srcdir)/lib/sshcrypto/sshcryptocore  -I$(top_srcdir)/lib/sshcrypto/sshmac  -I$(top_srcdir)/lib/sshcrypto/sshpk  -I$(top_srcdir)/lib/sshcrypto  -I$(top_srcdir)/lib/sshcryptoaux  -I$(top_srcdir)/lib/sshradius  -I$(top_srcdir)/lib/sshldap  -I$(top_srcdir)/lib/sshhttp  -I$(top_srcdir)/lib/sshxml 
LDADD = $(top_builddir)/lib/sshxml/libsshxml.a $(top_builddir)/lib/sshhttp/libsshhttp.a $(top_builddir)/lib/sshldap/libsshldap.a $(top_builddir)/lib/sshradius/libsshradius.a $(top_builddir)/lib/sshcryptoaux/libsshcryptoaux.a $(top_builddir)/lib/sshcrypto/libsshcrypto.a $(top_builddir)/lib/sshasn1/libsshasn1.a $(top_builddir)/lib/sshmath/libsshmath.a $(top_builddir)/lib/zlib/libz.a $(top_builddir)/lib/sshutil/libsshutil.a 

WINCONF_OPTIONS = maintainer=tmononen@safenet-inc.com

SUBDIRS = tests

noinst_LIBRARIES = libsshcert.a

libsshcert_a_SOURCES = \
   x509.c \
   x509init.c \
   x509cert.c \
   x509name_encode.c \
   x509name_decode.c \
   x509cert_decode.c \
   x509cert_encode.c \
   x509crl.c \
   x509crl_decode.c \
   x509crl_encode.c \
   x509get.c \
   x509set.c \
   x509ext_decode.c \
   x509ext_encode.c \
   x509private.c \
   x509public_encode.c \
   x509public_decode.c \
   x509signature.c \
   x509req_decode.c \
   x509req_encode.c \
   sshpswbmac.c \
   x509crmf_encode.c \
   x509crmf_decode.c \
   x509crmf_value.c \
   ocsp_common.c \
   ocsp_client.c \
   ocsp_http.c \
   oid.c  \
   x509cert_sync.c \
   x509crl_sync.c \
   eckeys.c \
   dn-util.c \
   dn-der.c \
   dn-ldap.c \
   sshglist.c

















GRANDLIB_OBJECTS =  $(libsshcert_a_OBJECTS) $(libsshcert_a_LIBADD)

public_headers += \
   x509.h \
   sshocsp.h \
   sshocsphttp.h \
   sshocspclient.h \
   sshocspresponder.h \
   sshpswbmac.h \
   x509spkac.h \
   dn.h   \
   eckeys.h  \
   oid.h  \
   sshglist.h





private_headers += \
   ocsp_internal.h \
   x509internal.h



EXTRA_DIST =

SUFFIXES = .S .s
CLEANFILES = tmp-*.s

.s.o:
	$(CC) -c $(CFLAGS) $(SFLAGS) $<

.S.o:
	$(CPP) $(CPPFLAGS) $(INCLUDES) $(DEFS) $< | grep -v '^#' >tmp-$*.s
	$(CC) $(CFLAGS) $(SFLAGS) -c tmp-$*.s
	mv tmp-$*.o $@
	rm -f tmp-$*.s

include $(top_srcdir)/Makefile.libextra
include $(top_srcdir)/Makefile.grandlib_provider
