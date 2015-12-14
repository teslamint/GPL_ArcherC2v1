
# Added by filter_add_makefile_libextra_stuff
# To keep automake silent about public and private headers
# not been set when something is added to them

public_headers =
private_headers =

## Process this file with automake to produce Makefile.in

#
# lib/sshapputil Makefile.am
#
# Author: Timo J. Rinne <tri@ssh.fi>
#
#  Copyright:
#          Copyright (c) 2002, 2003, 2005 SFNT Finland Oy.
#                    All rights reserved
#

AUTOMAKE_OPTIONS = 1.0 foreign dist-zip no-dependencies
INCLUDES = -I$(top_srcdir)  -I$(top_srcdir)/lib/sshutil/sshcore  -I$(top_srcdir)/lib/sshutil/sshadt  -I$(top_srcdir)/lib/sshutil/ssheloop  -I$(top_srcdir)/lib/sshutil/sshstrutil  -I$(top_srcdir)/lib/sshutil/sshfsm  -I$(top_srcdir)/lib/sshutil/sshstream  -I$(top_srcdir)/lib/sshutil/sshsysutil  -I$(top_srcdir)/lib/sshutil/sshnet  -I$(top_srcdir)/lib/sshutil/sshmisc  -I$(top_srcdir)/lib/sshutil/sshaudit  -I$(top_srcdir)/lib/sshutil/sshpacketstream  -I$(top_srcdir)/lib/sshutil/sshtestutil  -I$(top_srcdir)/lib/sshutil  -I$(top_srcdir)/lib/zlib  -I$(top_srcdir)/lib/sshmath  -I$(top_srcdir)/lib/sshasn1  -I$(top_srcdir)/lib/sshcrypto/sshcipher  -I$(top_srcdir)/lib/sshcrypto/sshhash  -I$(top_srcdir)/lib/sshcrypto/sshrandom  -I$(top_srcdir)/lib/sshcrypto/sshcryptocore  -I$(top_srcdir)/lib/sshcrypto/sshmac  -I$(top_srcdir)/lib/sshcrypto/sshpk  -I$(top_srcdir)/lib/sshcrypto  -I$(top_srcdir)/lib/sshcryptoaux  -I$(top_srcdir)/lib/sshradius  -I$(top_srcdir)/lib/sshldap  -I$(top_srcdir)/lib/sshhttp  -I$(top_srcdir)/lib/sshxml  -I$(top_srcdir)/lib/sshcert  -I$(top_srcdir)/lib/sshpkcs  -I$(top_srcdir)/lib/sshenroll  -I$(top_srcdir)/lib/sshvalidator  -I$(top_srcdir)/lib/sshtls  




LDADD = $(top_builddir)/lib/sshtls/libsshtls.a $(top_builddir)/lib/sshvalidator/libsshvalidator.a $(top_builddir)/lib/sshenroll/libsshenroll.a $(top_builddir)/lib/sshpkcs/libsshpkcs.a $(top_builddir)/lib/sshcert/libsshcert.a $(top_builddir)/lib/sshxml/libsshxml.a $(top_builddir)/lib/sshhttp/libsshhttp.a $(top_builddir)/lib/sshldap/libsshldap.a $(top_builddir)/lib/sshradius/libsshradius.a $(top_builddir)/lib/sshcryptoaux/libsshcryptoaux.a $(top_builddir)/lib/sshcrypto/libsshcrypto.a $(top_builddir)/lib/sshasn1/libsshasn1.a $(top_builddir)/lib/sshmath/libsshmath.a $(top_builddir)/lib/zlib/libz.a $(top_builddir)/lib/sshutil/libsshutil.a 
INCLUDES_windelta = -@ssh2_toolkit_includes@

WINCONF_OPTIONS = maintainer=toka@ssh.com,tomi@ssh.com,sjl@ssh.com,tmo@ssh.fi

SUBDIRS = tests

noinst_LIBRARIES = libsshapputil.a

libsshapputil_a_SOURCES = \
	sshprvkey.c		\
	sshpubkey.c		\
	sshkeyblob2.c		\
	ssh2pubkeyencode.c	\
	sshcipherlist.c		\
	sshkeyblob1.c		\
	ssh1encode.c		\
	sshpsystem.c 		\
	pem-format.c		\
	sshsnlist.c		

























EXTRA_DIST =   \
	tests/test-file.mc		



GRANDLIB_OBJECTS =  $(libsshapputil_a_OBJECTS) $(libsshapputil_a_LIBADD)

public_headers += \
	sshpsystem.h 		\
	sshkeyblob1.h		\
	sshkeyblob2.h		\
	sshprvkey.h             \
	sshpubkey.h		\
	ssh2pubkeyencode.h	\
	sshcipherlist.h		\
	ssh1encode.h		\
        sshpem.h                \
	sshsnlist.h

























private_headers += \
	sshpemi.h		



include $(top_srcdir)/Makefile.libextra
include $(top_srcdir)/Makefile.grandlib_provider
