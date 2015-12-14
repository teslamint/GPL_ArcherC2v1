
# Added by filter_add_makefile_libextra_stuff
# To keep automake silent about public and private headers
# not been set when something is added to them

public_headers =
private_headers =

#
# ipsec/lib/ssheap/tests Makefile.am.raw
#
#  Copyright:
#          Copyright (c) 2002, 2003 SFNT Finland Oy.
# All rights reserved.
#

AUTOMAKE_OPTIONS = 1.0 foreign dist-zip no-dependencies
WINCONF_OPTIONS = maintainer=pirwin@safenet-inc.com



INCLUDES = -I$(srcdir)/.. -I$(top_srcdir)  -I$(top_srcdir)/lib/sshutil/sshcore  -I$(top_srcdir)/lib/sshutil/sshadt  -I$(top_srcdir)/lib/sshutil/ssheloop  -I$(top_srcdir)/lib/sshutil/sshstrutil  -I$(top_srcdir)/lib/sshutil/sshfsm  -I$(top_srcdir)/lib/sshutil/sshstream  -I$(top_srcdir)/lib/sshutil/sshsysutil  -I$(top_srcdir)/lib/sshutil/sshnet  -I$(top_srcdir)/lib/sshutil/sshmisc  -I$(top_srcdir)/lib/sshutil/sshaudit  -I$(top_srcdir)/lib/sshutil/sshpacketstream  -I$(top_srcdir)/lib/sshutil/sshtestutil  -I$(top_srcdir)/lib/sshutil  -I$(top_srcdir)/lib/zlib  -I$(top_srcdir)/lib/sshmath  -I$(top_srcdir)/lib/sshasn1  -I$(top_srcdir)/lib/sshcrypto/sshcipher  -I$(top_srcdir)/lib/sshcrypto/sshhash  -I$(top_srcdir)/lib/sshcrypto/sshrandom  -I$(top_srcdir)/lib/sshcrypto/sshcryptocore  -I$(top_srcdir)/lib/sshcrypto/sshmac  -I$(top_srcdir)/lib/sshcrypto/sshpk  -I$(top_srcdir)/lib/sshcrypto  -I$(top_srcdir)/lib/sshcryptoaux  -I$(top_srcdir)/lib/sshradius  -I$(top_srcdir)/lib/sshldap  -I$(top_srcdir)/lib/sshhttp  -I$(top_srcdir)/lib/sshxml  -I$(top_srcdir)/lib/sshcert  -I$(top_srcdir)/lib/sshpkcs  -I$(top_srcdir)/lib/sshenroll  -I$(top_srcdir)/lib/sshvalidator  -I$(top_srcdir)/lib/sshtls  -I$(top_srcdir)/lib/sshapputil  -I$(top_srcdir)/lib/sshexternalkey 
LDADD = ../libssheap.a $(top_builddir)/lib/sshexternalkey/libsshexternalkey.a $(top_builddir)/lib/sshapputil/libsshapputil.a $(top_builddir)/lib/sshtls/libsshtls.a $(top_builddir)/lib/sshvalidator/libsshvalidator.a $(top_builddir)/lib/sshenroll/libsshenroll.a $(top_builddir)/lib/sshpkcs/libsshpkcs.a $(top_builddir)/lib/sshcert/libsshcert.a $(top_builddir)/lib/sshxml/libsshxml.a $(top_builddir)/lib/sshhttp/libsshhttp.a $(top_builddir)/lib/sshldap/libsshldap.a $(top_builddir)/lib/sshradius/libsshradius.a $(top_builddir)/lib/sshcryptoaux/libsshcryptoaux.a $(top_builddir)/lib/sshcrypto/libsshcrypto.a $(top_builddir)/lib/sshasn1/libsshasn1.a $(top_builddir)/lib/sshmath/libsshmath.a $(top_builddir)/lib/zlib/libz.a $(top_builddir)/lib/sshutil/libsshutil.a 


TESTS_LIGHT = t-eap-md5 \
	t-eap-sim \
	t-eap-aka \
	t-eap-aka-dash 













TESTS = $(TESTS_LIGHT)


t_eap_sim_DEPENDENCIES = ../libssheap.a sim_keys



t_eap_aka_DEPENDENCIES = ../libssheap.a aka_keys



t_eap_aka_dash_DEPENDENCIES = ../libssheap.a akadash_keys







sim_keys: 	sim_keys.dat
	if test ! -e \
	$(top_builddir)/lib/ssheap/tests/aka_keys.dat; then \
		cp $(srcdir)/sim_keys.dat  \
		$(top_builddir)/lib/ssheap/tests/sim_keys.dat; \
	fi	



aka_keys: 	aka_keys.dat
	if test ! -e \
	$(top_builddir)/lib/ssheap/tests/aka_keys.dat; then \
		cp $(srcdir)/aka_keys.dat  \
		$(top_builddir)/lib/ssheap/tests/aka_keys.dat; \
	fi



akadash_keys:        akadash_keys.dat
	if test ! -e \
	$(top_builddir)/lib/ssheap/tests/akadash_keys.dat; then \
		cp $(srcdir)/akadash_keys.dat  \
		$(top_builddir)/lib/ssheap/tests/akadash_keys.dat; \
	fi











TESTS_LIGHT_windelta = -t-eap-md5 -t-eap-sim -t-eap-aka -t-eap-aka-dash -t-eap-tls -t-eap-srp

EXTRA_DIST =                                                   \
             sim_keys.dat                                      \
             aka_keys.dat                                      \
             akadash_keys.dat










EXTRA_PROGRAMS = $(TESTS)

GENERIC_TEST_SOURCES = t-eap.c

t_eap_md5_SOURCES = $(GENERIC_TEST_SOURCES) t-eap-md5.c

t_eap_sim_SOURCES = $(GENERIC_TEST_SOURCES) t-eap-files.c t-eap-sim.c


t_eap_aka_SOURCES = $(GENERIC_TEST_SOURCES) t-eap-files.c t-eap-aka.c


t_eap_aka_dash_SOURCES = $(GENERIC_TEST_SOURCES) t-eap-files.c t-eap-aka-dash.c








private_headers         += t-eap-files.h t-eap.h



include $(top_srcdir)/Makefile.libextra
include $(top_srcdir)/Makefile.grandlib_provider


# EOF
