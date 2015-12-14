
# Added by filter_add_makefile_libextra_stuff
# To keep automake silent about public and private headers
# not been set when something is added to them

public_headers =
private_headers =

## Process this file with automake to produce Makefile.in

#
# lib/ssexternalkey/tests Makefile.am.raw
#
# Author: Vesa Suontama <vsuontam@ssh.fi>
#
#  Copyright:
#          Copyright (c) 2002, 2003 SFNT Finland Oy.
#                    All rights reserved
#

AUTOMAKE_OPTIONS = 1.0 foreign dist-zip no-dependencies
WINCONF_OPTIONS = maintainer=pirwin@safenet-inc.com



INCLUDES = -I$(srcdir)/.. -I$(top_srcdir)  -I$(top_srcdir)/lib/sshutil/sshcore  -I$(top_srcdir)/lib/sshutil/sshadt  -I$(top_srcdir)/lib/sshutil/ssheloop  -I$(top_srcdir)/lib/sshutil/sshstrutil  -I$(top_srcdir)/lib/sshutil/sshfsm  -I$(top_srcdir)/lib/sshutil/sshstream  -I$(top_srcdir)/lib/sshutil/sshsysutil  -I$(top_srcdir)/lib/sshutil/sshnet  -I$(top_srcdir)/lib/sshutil/sshmisc  -I$(top_srcdir)/lib/sshutil/sshaudit  -I$(top_srcdir)/lib/sshutil/sshpacketstream  -I$(top_srcdir)/lib/sshutil/sshtestutil  -I$(top_srcdir)/lib/sshutil  -I$(top_srcdir)/lib/zlib  -I$(top_srcdir)/lib/sshmath  -I$(top_srcdir)/lib/sshasn1  -I$(top_srcdir)/lib/sshcrypto/sshcipher  -I$(top_srcdir)/lib/sshcrypto/sshhash  -I$(top_srcdir)/lib/sshcrypto/sshrandom  -I$(top_srcdir)/lib/sshcrypto/sshcryptocore  -I$(top_srcdir)/lib/sshcrypto/sshmac  -I$(top_srcdir)/lib/sshcrypto/sshpk  -I$(top_srcdir)/lib/sshcrypto  -I$(top_srcdir)/lib/sshcryptoaux  -I$(top_srcdir)/lib/sshradius  -I$(top_srcdir)/lib/sshldap  -I$(top_srcdir)/lib/sshhttp  -I$(top_srcdir)/lib/sshxml  -I$(top_srcdir)/lib/sshcert  -I$(top_srcdir)/lib/sshpkcs  -I$(top_srcdir)/lib/sshenroll  -I$(top_srcdir)/lib/sshvalidator  -I$(top_srcdir)/lib/sshtls  -I$(top_srcdir)/lib/sshapputil 
LDADD = ../libsshexternalkey.a $(top_builddir)/lib/sshapputil/libsshapputil.a $(top_builddir)/lib/sshtls/libsshtls.a $(top_builddir)/lib/sshvalidator/libsshvalidator.a $(top_builddir)/lib/sshenroll/libsshenroll.a $(top_builddir)/lib/sshpkcs/libsshpkcs.a $(top_builddir)/lib/sshcert/libsshcert.a $(top_builddir)/lib/sshxml/libsshxml.a $(top_builddir)/lib/sshhttp/libsshhttp.a $(top_builddir)/lib/sshldap/libsshldap.a $(top_builddir)/lib/sshradius/libsshradius.a $(top_builddir)/lib/sshcryptoaux/libsshcryptoaux.a $(top_builddir)/lib/sshcrypto/libsshcrypto.a $(top_builddir)/lib/sshasn1/libsshasn1.a $(top_builddir)/lib/sshmath/libsshmath.a $(top_builddir)/lib/zlib/libz.a $(top_builddir)/lib/sshutil/libsshutil.a 


TESTS_LIGHT = t-softprovider t-genacc_rsacrt
TESTS = $(TESTS_LIGHT) t-genacc

EXTRA_PROGRAMS = \
	t-softprovider \
	t-genacc \
	t-genacc-speed \
	t-genacc_rsacrt \
	t-externalkey \
	t-simple_externalkey \
	t-accelerator \
	t-makereq \
	t-externalcert





# XXX: Nobody has modified these after API changes; removed from daily Windows
# build until somebody fixes these.
EXTRA_PROGRAMS_windelta = 




EXTRA_DIST = accelerator-test.prv

t_externalkey_SOURCES = t-externalkey.c
t_externalkey_DEPENDENCIES = $(LDADD)

t_softprovider_SOURCES = t-softprovider.c
t_softprovider_DEPENDENCIES = $(LDADD)

t_accelerator_SOURCES = t-accelerator.c
t_accelerator_DEPENDENCIES = $(LDADD)

t_genacc_SOURCES = t-genacc.c
t_genacc_DEPENDENCIES = $(LDADD)

t_genacc_speed_SOURCES = t-genacc-speed.c
t_genacc_speed_DEPENDENCIES = $(LDADD)

t_genacc_rsacrt_SOURCES = t-genacc_rsacrt.c
t_genacc_rsacrt_DEPENDENCIES = $(LDADD)

t_simple_externalkey_SOURCES = t-simple_externalkey.c
t_simple_externalkey_DEPENDENCIES = $(LDADD)









t_makereq_SOURCES = t-makereq.c
t_makereq_DEPENDENCIES = $(LDADD)

t_externalcert_SOURCES = t-externalcert.c
t_externalcert_DEPENDENCIES = $(LDADD)



include $(top_srcdir)/Makefile.libextra
include $(top_srcdir)/Makefile.grandlib_provider

# EOF
