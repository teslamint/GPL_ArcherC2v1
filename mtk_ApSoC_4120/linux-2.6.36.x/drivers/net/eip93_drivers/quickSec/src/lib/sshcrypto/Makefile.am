
# Added by filter_add_makefile_libextra_stuff
# To keep automake silent about public and private headers
# not been set when something is added to them

public_headers =
private_headers =

## Process this file with automake to produce Makefile.in

#
# lib/sshcrypto Makefile.am
#
# Copyright:
# 	Copyright (c) 2002, 2003, 2005 SFNT Finland Oy.
# 	All rights reserved
#

AUTOMAKE_OPTIONS = 1.0 foreign dist-zip no-dependencies
WINCONF_OPTIONS = maintainer=pirwin@safenet-inc.com

INCLUDES = -I$(top_srcdir)  -I$(top_srcdir)/lib/sshutil/sshcore  -I$(top_srcdir)/lib/sshutil/sshadt  -I$(top_srcdir)/lib/sshutil/ssheloop  -I$(top_srcdir)/lib/sshutil/sshstrutil  -I$(top_srcdir)/lib/sshutil/sshfsm  -I$(top_srcdir)/lib/sshutil/sshstream  -I$(top_srcdir)/lib/sshutil/sshsysutil  -I$(top_srcdir)/lib/sshutil/sshnet  -I$(top_srcdir)/lib/sshutil/sshmisc  -I$(top_srcdir)/lib/sshutil/sshaudit  -I$(top_srcdir)/lib/sshutil/sshpacketstream  -I$(top_srcdir)/lib/sshutil/sshtestutil  -I$(top_srcdir)/lib/sshutil  -I$(top_srcdir)/lib/zlib  -I$(top_srcdir)/lib/sshmath  -I$(top_srcdir)/lib/sshasn1  -I$(top_srcdir)/lib/sshcrypto/sshcipher  -I$(top_srcdir)/lib/sshcrypto/sshhash  -I$(top_srcdir)/lib/sshcrypto/sshrandom  -I$(top_srcdir)/lib/sshcrypto/sshcryptocore  -I$(top_srcdir)/lib/sshcrypto/sshmac  -I$(top_srcdir)/lib/sshcrypto/sshpk  -I$(srcdir)/sshcipher
LDADD = $(top_builddir)/lib/sshcrypto/sshpk/libsshpk.a $(top_builddir)/lib/sshcrypto/sshmac/libsshmac.a $(top_builddir)/lib/sshcrypto/sshcryptocore/libsshcryptocore.a $(top_builddir)/lib/sshcrypto/sshrandom/libsshrandom.a $(top_builddir)/lib/sshcrypto/sshhash/libsshhash.a $(top_builddir)/lib/sshcrypto/sshcipher/libsshcipher.a $(top_builddir)/lib/sshasn1/libsshasn1.a $(top_builddir)/lib/sshmath/libsshmath.a $(top_builddir)/lib/zlib/libz.a $(top_builddir)/lib/sshutil/libsshutil.a 

public_headers += 	\
	sshcrypt.h	\
	sshrandom.h	\
	sshcipher.h	\
	sshhash.h	\
	sshmac.h	\
	sshpk.h		\
	sshproxykey.h 	


























SUBDIRS = 					\
	tests					\
	sshcipher				\
	sshhash					\
	sshrandom				\
	sshcryptocore				\
	sshmac					\
	sshpk					




















libsshcrypto_a_SUBLIBRARIES =			\
	sshcipher/libsshcipher.a		\
	sshhash/libsshhash.a			\
	sshrandom/libsshrandom.a		\
	sshcryptocore/libsshcryptocore.a	\
	sshmac/libsshmac.a			\
	sshpk/libsshpk.a                        
















private_headers += \
	octeon-asm.h \
	sshcrypt_i.h





EXTRA_DIST = 




































GRANDLIB = libsshcrypto.a



include $(top_srcdir)/Makefile.grandlib_maker
include $(top_srcdir)/Makefile.libextra

# EOF
