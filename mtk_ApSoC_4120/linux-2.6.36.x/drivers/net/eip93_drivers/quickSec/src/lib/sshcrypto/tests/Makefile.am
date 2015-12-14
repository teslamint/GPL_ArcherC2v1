
# Added by filter_add_makefile_libextra_stuff
# To keep automake silent about public and private headers
# not been set when something is added to them

public_headers =
private_headers =

## Process this file with automake to produce Makefile.in

#
# lib/sshcrypt/tests Makefile.am
#
# Author: Tatu Ylonen <ylo@ssh.fi>
#
#  Copyright:
#          Copyright (c) 2002 - 2008 SFNT Finland Oy.
#                    All rights reserved
#

AUTOMAKE_OPTIONS = 1.0 foreign dist-zip no-dependencies
WINCONF_OPTIONS = maintainer=pirwin@safenet-inc.com

INCLUDES = -I$(srcdir)/.. \
	-I$(srcdir)/../sshcipher \
	-I$(srcdir)/../sshcryptocore \
	-I$(srcdir)/../sshhash \
	-I$(srcdir)/../sshmac \
	-I$(srcdir)/../sshpk \
	-I$(srcdir)/../sshrandom \
	-I$(top_srcdir)  -I$(top_srcdir)/lib/sshutil/sshcore  -I$(top_srcdir)/lib/sshutil/sshadt  -I$(top_srcdir)/lib/sshutil/ssheloop  -I$(top_srcdir)/lib/sshutil/sshstrutil  -I$(top_srcdir)/lib/sshutil/sshfsm  -I$(top_srcdir)/lib/sshutil/sshstream  -I$(top_srcdir)/lib/sshutil/sshsysutil  -I$(top_srcdir)/lib/sshutil/sshnet  -I$(top_srcdir)/lib/sshutil/sshmisc  -I$(top_srcdir)/lib/sshutil/sshaudit  -I$(top_srcdir)/lib/sshutil/sshpacketstream  -I$(top_srcdir)/lib/sshutil/sshtestutil  -I$(top_srcdir)/lib/sshutil  -I$(top_srcdir)/lib/zlib  -I$(top_srcdir)/lib/sshmath  -I$(top_srcdir)/lib/sshasn1 



LDADD = ../libsshcrypto.a $(top_builddir)/lib/sshasn1/libsshasn1.a $(top_builddir)/lib/sshmath/libsshmath.a $(top_builddir)/lib/zlib/libz.a $(top_builddir)/lib/sshutil/libsshutil.a 


INCLUDES_windelta = \
	+-I$(srcdir)/../../sshapputil

TESTS_LIGHT = \
	t-proxykey \
	t-combined-modes \
	t-pkcs1implicit \
	t-namelist \
	t-modetest







TESTS = $(TESTS_LIGHT) \
	t-gentest \
	t-dh 











#  t-arcfour t-blowfish t-des t-idea t-md5 t-safer t-seal t-sha \
#  t-genhash t-genrand t-gencrypt \
#  t-genmp


EXTRA_PROGRAMS = \
	$(TESTS) \
	t-hdt    \
	t-combined-speed \
	t-cipher-vs-mac-speed \
	t-cryptest \
	t-random 

























EXTRA_PROGRAMS_windelta = -keytool \
			  -t-speed

EXTRA_DIST = \
	NBS-data-full 	\
	cryptest.desc 	\
	hash.tests 	\
	mac.tests 	\
	cipher.tests	\
	pkcs.tests	\
	import-export.tests \
	t-gentest.h

private_headers += readfile.h t-gentest.h parser.h
# timeit.h


t_gentest_SOURCES = t-gentest.c readfile.c rnd-test.c \
	hash-test.c cipher-test.c mac-test.c \
	pkcs-test.c pkcs-static-test.c pkcs-static-import-export.c \
	misc-test.c parser.c
t_gentest_DEPENDENCIES = $(LDADD)




t_cryptest_SOURCES = t-cryptest.c
t_cryptest_LDADD = ../../sshapputil/libsshapputil.a $(LDADD)
t_cryptest_DEPENDENCIES = ../../sshapputil/libsshapputil.a $(LDADD)
t_cryptest_DEPENDENCIES_windelta = \
  +../../libsshapputil.a



t_hdt_SOURCES = t-hdt.c
t_hdt_DEPENDENCIES = $(LDADD)
t_hdt_PLATFORMS = win32 x64 win32vista x64vista win32win7 x64win7



t_namelist_SOURCES = t-namelist.c
t_namelist_DEPENDENCIES = $(LDADD)




t_modetest_SOURCES = t-modetest.c
t_modetest_DEPENDENCIES = $(LDADD)









t_dh_SOURCES = t-dh.c
t_dh_DEPENDENCIES = $(LDADD)




t_proxykey_SOURCES = t-proxykey.c
t_proxykey_DEPENDENCIES = $(LDADD)







t_combined_modes_SOURCES = t-combined-modes.c
t_combined_modes_DEPENDENCIES = $(LDADD)


t_combined_speed_SOURCES = t-combined-speed.c
t_combined_speed_DEPENDENCIES = $(LDADD)



t_pkcs1implicit_SOURCES = t-pkcs1implicit.c
t_pkcs1implicit_DEPENDENCIES = $(LDADD)





t_cipher_vs_mac_speed_SOURCES = t-cipher-vs-mac-speed.c
t_cipher_vs_mac_speed_DEPENDENCIES = $(LDADD)
































t_random_SOURCES = t-random.c fft.c fft.h
t_random_LDADD = $(LDADD) -lm
t_random_LDADD_windelta = --lm
t_random_DEPENDENCIES = $(LDADD)






include $(top_srcdir)/Makefile.libextra
include $(top_srcdir)/Makefile.grandlib_provider

# EOF
