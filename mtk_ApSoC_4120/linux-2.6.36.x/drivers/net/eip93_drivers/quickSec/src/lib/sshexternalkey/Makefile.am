
# Added by filter_add_makefile_libextra_stuff
# To keep automake silent about public and private headers
# not been set when something is added to them

public_headers =
private_headers =

## Process this file with automake to produce Makefile.in

#
# lib/sshexternalkey Makefile.am
#
# Copyright (c) 2002, 2003, 2004, 2005 SFNT Finland Oy.
# All rights reserved
#

AUTOMAKE_OPTIONS = 1.0 foreign dist-zip no-dependencies
WINCONF_OPTIONS = maintainer=pirwin@safenet-inc.com

VPATH 	 = $(srcdir):@SAFENET_UDM_VPATH@:@SCP51X0_VPATH@:@OCTEON_VPATH@

INCLUDES = -I$(top_srcdir)  -I$(top_srcdir)/lib/sshutil/sshcore  -I$(top_srcdir)/lib/sshutil/sshadt  -I$(top_srcdir)/lib/sshutil/ssheloop  -I$(top_srcdir)/lib/sshutil/sshstrutil  -I$(top_srcdir)/lib/sshutil/sshfsm  -I$(top_srcdir)/lib/sshutil/sshstream  -I$(top_srcdir)/lib/sshutil/sshsysutil  -I$(top_srcdir)/lib/sshutil/sshnet  -I$(top_srcdir)/lib/sshutil/sshmisc  -I$(top_srcdir)/lib/sshutil/sshaudit  -I$(top_srcdir)/lib/sshutil/sshpacketstream  -I$(top_srcdir)/lib/sshutil/sshtestutil  -I$(top_srcdir)/lib/sshutil  -I$(top_srcdir)/lib/zlib  -I$(top_srcdir)/lib/sshmath  -I$(top_srcdir)/lib/sshasn1  -I$(top_srcdir)/lib/sshcrypto/sshcipher  -I$(top_srcdir)/lib/sshcrypto/sshhash  -I$(top_srcdir)/lib/sshcrypto/sshrandom  -I$(top_srcdir)/lib/sshcrypto/sshcryptocore  -I$(top_srcdir)/lib/sshcrypto/sshmac  -I$(top_srcdir)/lib/sshcrypto/sshpk  -I$(top_srcdir)/lib/sshcrypto  -I$(top_srcdir)/lib/sshcryptoaux  -I$(top_srcdir)/lib/sshradius  -I$(top_srcdir)/lib/sshldap  -I$(top_srcdir)/lib/sshhttp  -I$(top_srcdir)/lib/sshxml  -I$(top_srcdir)/lib/sshcert  -I$(top_srcdir)/lib/sshpkcs  -I$(top_srcdir)/lib/sshenroll  -I$(top_srcdir)/lib/sshvalidator  -I$(top_srcdir)/lib/sshtls  -I$(top_srcdir)/lib/sshapputil  




LDADD = $(top_builddir)/lib/sshapputil/libsshapputil.a $(top_builddir)/lib/sshtls/libsshtls.a $(top_builddir)/lib/sshvalidator/libsshvalidator.a $(top_builddir)/lib/sshenroll/libsshenroll.a $(top_builddir)/lib/sshpkcs/libsshpkcs.a $(top_builddir)/lib/sshcert/libsshcert.a $(top_builddir)/lib/sshxml/libsshxml.a $(top_builddir)/lib/sshhttp/libsshhttp.a $(top_builddir)/lib/sshldap/libsshldap.a $(top_builddir)/lib/sshradius/libsshradius.a $(top_builddir)/lib/sshcryptoaux/libsshcryptoaux.a $(top_builddir)/lib/sshcrypto/libsshcrypto.a $(top_builddir)/lib/sshasn1/libsshasn1.a $(top_builddir)/lib/sshmath/libsshmath.a $(top_builddir)/lib/zlib/libz.a $(top_builddir)/lib/sshutil/libsshutil.a 

noinst_LIBRARIES = libsshexternalkey.a

libsshexternalkey_a_SOURCES = \
	sshexternalkey.c \
	genaccdevice.c \
	genaccprovider.c \
        dummyprov.c \
        dummyacc.c \
        softacc.c \
	octeon_acc.c \
	octeon_acci.c \
	@OCTEON_SRCS@ \
        safenet_acc.c \
	@SAFENET_UDM_SRCS@ \
       ocf_acc.c \
	softprovider.c \
	sshsoftkey.c \
	extkeyprov.c




































libsshexternalkey_a_SOURCES_windelta = \
	+msprovider.c 



GRANDLIB_OBJECTS =  \
	$(libsshexternalkey_a_OBJECTS) \
	$(libsshexternalkey_a_LIBADD)

libsshexternalkey_a_LIBADD = \
	@SAFENET_UDM_OBJS@ \
	@OCTEON_OBJS@        








libsshexternalkey_a_DEPENDENCIES = \
	@SAFENET_UDM_OBJS@   \
	@OCTEON_OBJS@        








SUBDIRS = tests

public_headers += \
	genaccprovider.h \
        sshsoftkey.h \
	genaccprov.h \
	sshexternalkey.h










public_headers_windelta = \
	+sshmsprov_util.h 



private_headers += \
	genaccdevicei.h \
	genaccprovideri.h \
        dummyprov.h \
        dummyacc.h \
        softacc.h \
	octeon_acc.h \
	octeon_acci.h \
        ocf_acc.h \
        safenet_acc.h \
	softprovider.h \
	softprovideri.h \
	extkeyprov.h





































private_headers_windelta =       \
        +msprovider.h           



EXTRA_DIST = \
	sshmsprov_util.h \
	msprovider.c \
	msprovider.h \
	cavium_cryptlib.patch 














include $(top_srcdir)/Makefile.libextra
include $(top_srcdir)/Makefile.grandlib_provider

