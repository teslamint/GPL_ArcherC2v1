
# Added by filter_add_makefile_libextra_stuff
# To keep automake silent about public and private headers
# not been set when something is added to them

public_headers =
private_headers =

## Process this file with automake to produce Makefile.in
#
# lib/sshtls Makefile.am
#
#  Copyright:
#          Copyright 2002-2007, SafeNet Inc. All rights reserved.
# All rights reserved
#

AUTOMAKE_OPTIONS = 1.0 foreign dist-zip no-dependencies
INCLUDES = -I$(top_srcdir)  -I$(top_srcdir)/lib/sshutil/sshcore  -I$(top_srcdir)/lib/sshutil/sshadt  -I$(top_srcdir)/lib/sshutil/ssheloop  -I$(top_srcdir)/lib/sshutil/sshstrutil  -I$(top_srcdir)/lib/sshutil/sshfsm  -I$(top_srcdir)/lib/sshutil/sshstream  -I$(top_srcdir)/lib/sshutil/sshsysutil  -I$(top_srcdir)/lib/sshutil/sshnet  -I$(top_srcdir)/lib/sshutil/sshmisc  -I$(top_srcdir)/lib/sshutil/sshaudit  -I$(top_srcdir)/lib/sshutil/sshpacketstream  -I$(top_srcdir)/lib/sshutil/sshtestutil  -I$(top_srcdir)/lib/sshutil  -I$(top_srcdir)/lib/zlib  -I$(top_srcdir)/lib/sshmath  -I$(top_srcdir)/lib/sshasn1  -I$(top_srcdir)/lib/sshcrypto/sshcipher  -I$(top_srcdir)/lib/sshcrypto/sshhash  -I$(top_srcdir)/lib/sshcrypto/sshrandom  -I$(top_srcdir)/lib/sshcrypto/sshcryptocore  -I$(top_srcdir)/lib/sshcrypto/sshmac  -I$(top_srcdir)/lib/sshcrypto/sshpk  -I$(top_srcdir)/lib/sshcrypto  -I$(top_srcdir)/lib/sshcryptoaux  -I$(top_srcdir)/lib/sshradius  -I$(top_srcdir)/lib/sshldap  -I$(top_srcdir)/lib/sshhttp  -I$(top_srcdir)/lib/sshxml  -I$(top_srcdir)/lib/sshcert  -I$(top_srcdir)/lib/sshpkcs  -I$(top_srcdir)/lib/sshenroll  -I$(top_srcdir)/lib/sshvalidator  \
-I$(top_srcdir)/ipsec/hwaccel/safenet1x41 \
-I$(top_srcdir)/lib/sshexternalkey 





LDADD = $(top_builddir)/lib/sshvalidator/libsshvalidator.a $(top_builddir)/lib/sshenroll/libsshenroll.a $(top_builddir)/lib/sshpkcs/libsshpkcs.a $(top_builddir)/lib/sshcert/libsshcert.a $(top_builddir)/lib/sshxml/libsshxml.a $(top_builddir)/lib/sshhttp/libsshhttp.a $(top_builddir)/lib/sshldap/libsshldap.a $(top_builddir)/lib/sshradius/libsshradius.a $(top_builddir)/lib/sshcryptoaux/libsshcryptoaux.a $(top_builddir)/lib/sshcrypto/libsshcrypto.a $(top_builddir)/lib/sshasn1/libsshasn1.a $(top_builddir)/lib/sshmath/libsshmath.a $(top_builddir)/lib/zlib/libz.a $(top_builddir)/lib/sshutil/libsshutil.a 

WINCONF_OPTIONS = maintainer=toka@ssh.fi


EXTRA_DIST = README.QUICKSEC





noinst_LIBRARIES = libsshtls.a

libsshtls_a_SOURCES = 	\
	tls_alert.c     \
	tls_downstream.c\
	tls_kextrans.c  \
	tls_record.c	\
	tls_appstream.c \
	tls_kex.c      	\
	tls_main.c      \
	tls_suites.c	\
	tls_crypto.c    \
	tls_tempkey.c   \
	tls_multihash.c \
	tls_cache.c 	\
	tls_extra.c	\
	tls_async.c	\
	tls_util.c 	\
	tls_kt_RCertificate.c 		\
	tls_kt_RCertificateRequest.c 	\
	tls_kt_RCertificateVerify.c 	\
	tls_kt_RChangeCipher.c 		\
	tls_kt_RClientHello.c 		\
	tls_kt_RClientKeyExchange.c 	\
	tls_kt_RFinished.c 		\
	tls_kt_RServerHello.c 		\
	tls_kt_RServerHelloDone.c 	\
	tls_kt_RServerKeyExchance.c 	\
	tls_kt_WCertificate.c 		\
	tls_kt_WCertificateRequest.c 	\
	tls_kt_WCertificateVerify.c 	\
	tls_kt_WChangeCipher.c 		\
	tls_kt_WClientHello.c 		\
	tls_kt_WClientKeyExchance.c 	\
	tls_kt_WFinished.c 		\
	tls_kt_WHelloRequest.c 		\
	tls_kt_WServerHello.c 		\
	tls_kt_WServerHelloDone.c 	\
	tls_kt_WServerKeyExchance.c 	\
	tls_kt_cont_funcs.c \
	tls_accel.c

public_headers += sshtls.h
private_headers += sshtlsi.h sshtlsextra.h sshtlskextrans.h tls_multihash.h tls_accel.h






GRANDLIB_OBJECTS =  $(libsshtls_a_OBJECTS) $(libsshtls_a_LIBADD)

SUBDIRS = tests

include $(top_srcdir)/Makefile.libextra
include $(top_srcdir)/Makefile.grandlib_provider
