
# Added by filter_add_makefile_libextra_stuff
# To keep automake silent about public and private headers
# not been set when something is added to them

public_headers =
private_headers =

## Process this file with automake to produce Makefile.in

#
# lib/sshcrypto/sshpk/Makefile.am
#
#  Copyright:
#          Copyright (c) 2002, 2003, 2005 SFNT Finland Oy.
#               All rights reserved
#

AUTOMAKE_OPTIONS = 1.0 foreign dist-zip no-dependencies
INCLUDES = \
	-I$(srcdir)/..  -I$(top_srcdir)  -I$(top_srcdir)/lib/sshutil/sshcore  -I$(top_srcdir)/lib/sshutil/sshadt  -I$(top_srcdir)/lib/sshutil/ssheloop  -I$(top_srcdir)/lib/sshutil/sshstrutil  -I$(top_srcdir)/lib/sshutil/sshfsm  -I$(top_srcdir)/lib/sshutil/sshstream  -I$(top_srcdir)/lib/sshutil/sshsysutil  -I$(top_srcdir)/lib/sshutil/sshnet  -I$(top_srcdir)/lib/sshutil/sshmisc  -I$(top_srcdir)/lib/sshutil/sshaudit  -I$(top_srcdir)/lib/sshutil/sshpacketstream  -I$(top_srcdir)/lib/sshutil/sshtestutil  -I$(top_srcdir)/lib/sshutil  -I$(top_srcdir)/lib/zlib  -I$(top_srcdir)/lib/sshmath  -I$(top_srcdir)/lib/sshasn1  -I$(top_srcdir)/lib/sshcrypto/sshcipher  -I$(top_srcdir)/lib/sshcrypto/sshhash  -I$(top_srcdir)/lib/sshcrypto/sshrandom  -I$(top_srcdir)/lib/sshcrypto/sshcryptocore  -I$(top_srcdir)/lib/sshcrypto/sshmac  










LDADD = $(top_builddir)/lib/sshcrypto/sshmac/libsshmac.a $(top_builddir)/lib/sshcrypto/sshcryptocore/libsshcryptocore.a $(top_builddir)/lib/sshcrypto/sshrandom/libsshrandom.a $(top_builddir)/lib/sshcrypto/sshhash/libsshhash.a $(top_builddir)/lib/sshcrypto/sshcipher/libsshcipher.a $(top_builddir)/lib/sshasn1/libsshasn1.a $(top_builddir)/lib/sshmath/libsshmath.a $(top_builddir)/lib/zlib/libz.a $(top_builddir)/lib/sshutil/libsshutil.a 

WINCONF_OPTIONS = maintainer=pirwin@safenet-inc.com

SUBDIRS =

EXTRA_DIST = ssh-pk-prv.c

noinst_LIBRARIES = 	\
	libsshpk.a






libsshpk_a_SOURCES = \
        pkcs1.c \
	rsa-utility.c	\
	rsa-generate.c	\
	rsa-operation.c \
	rsa-user.c	\
	rsa-maker.c	\
	libmonitor.c	\
	dl-utility.c	\
	dl-stack.c	\
	dl-generate.c	\
	dl-dh.c		\
	dl-dsa.c	\
	dlfix.c 	\
	dsa-user.c	\
	dsa-maker.c	\
	ecpfix.c 	\
	ecpglue.c 	\
	ecp-user.c	\
	ecp-maker.c	\
	genpkcs.c 	\
	genpkcs_dh.c 	\
	genpkcs_public.c \
	genpkcs_private.c \
	genmp-prime.c 	\
	genmp-integer.c	\
	sshrgf.c 	\
	sshrgf-mgf1.c	\
	sshrgf-pss.c 	\
	sshrgf-oaep.c 	\
	ssh-pk-group.c	\
	ssh-pk-export.c \
	sshproxykey.c 	\
	ssh-pk-prv-def.c \
	ssh-pk-prv-gen.c



































libsshpk_a_DEPENDENCIES = $(libsshpk_a_LIBADD)








GRANDLIB_OBJECTS =  $(libsshpk_a_OBJECTS) $(libsshpk_a_LIBADD)

public_headers += \
	sshgenmp.h 	\
	sshrgf.h 	



private_headers += \
	sshpk_i.h           \
	sshrgf-internal.h \
	pkcs1.h		  \
	rsa.h 		  \
	ecpfix.h 	  \
	ecpglue.h 	  \
	dlglue.h 	  \
	dlfix.h           \
	dl-internal.h	  \
	dl-stack.h	  \
	libmonitor.h

















include $(top_srcdir)/Makefile.libextra
include $(top_srcdir)/Makefile.grandlib_provider
