
# Added by filter_add_makefile_libextra_stuff
# To keep automake silent about public and private headers
# not been set when something is added to them

public_headers =
private_headers =

## Process this file with automake to produce Makefile.in

#
# lib/sshhttp/tests Makefile.am
#
# Author: Markku Rossi <mtr@ssh.fi>
#
#  Copyright:
#          Copyright (c) 2002, 2003 SFNT Finland Oy.
#               All rights reserved
#

AUTOMAKE_OPTIONS = 1.0 foreign dist-zip no-dependencies
WINCONF_OPTIONS = maintainer=mtr@ssh.fi



TESTS_LIGHT = t-http-kvhash
TESTS = $(TESTS_LIGHT) t-http

INCLUDES = -I$(srcdir)/.. -I$(top_srcdir)  -I$(top_srcdir)/lib/sshutil/sshcore  -I$(top_srcdir)/lib/sshutil/sshadt  -I$(top_srcdir)/lib/sshutil/ssheloop  -I$(top_srcdir)/lib/sshutil/sshstrutil  -I$(top_srcdir)/lib/sshutil/sshfsm  -I$(top_srcdir)/lib/sshutil/sshstream  -I$(top_srcdir)/lib/sshutil/sshsysutil  -I$(top_srcdir)/lib/sshutil/sshnet  -I$(top_srcdir)/lib/sshutil/sshmisc  -I$(top_srcdir)/lib/sshutil/sshaudit  -I$(top_srcdir)/lib/sshutil/sshpacketstream  -I$(top_srcdir)/lib/sshutil/sshtestutil  -I$(top_srcdir)/lib/sshutil  -I$(top_srcdir)/lib/zlib  -I$(top_srcdir)/lib/sshmath  -I$(top_srcdir)/lib/sshasn1  -I$(top_srcdir)/lib/sshcrypto/sshcipher  -I$(top_srcdir)/lib/sshcrypto/sshhash  -I$(top_srcdir)/lib/sshcrypto/sshrandom  -I$(top_srcdir)/lib/sshcrypto/sshcryptocore  -I$(top_srcdir)/lib/sshcrypto/sshmac  -I$(top_srcdir)/lib/sshcrypto/sshpk  -I$(top_srcdir)/lib/sshcrypto  -I$(top_srcdir)/lib/sshcryptoaux  -I$(top_srcdir)/lib/sshradius  -I$(top_srcdir)/lib/sshldap  





EXTRA_DIST =

EXTRA_PROGRAMS =        \
        $(TESTS)        \
        httpclient      \
        httpserver      \
        http-benchmark  \
        filterproxy     




LDADD =                                                           \
        $(top_builddir)/lib/sshldap/libsshldap.a $(top_builddir)/lib/sshradius/libsshradius.a $(top_builddir)/lib/sshcryptoaux/libsshcryptoaux.a $(top_builddir)/lib/sshcrypto/libsshcrypto.a $(top_builddir)/lib/sshasn1/libsshasn1.a $(top_builddir)/lib/sshmath/libsshmath.a $(top_builddir)/lib/zlib/libz.a $(top_builddir)/lib/sshutil/libsshutil.a                                       \
        $(top_builddir)/lib/sshhttp/libsshhttp.a                  \
        $(top_builddir)/lib/sshutil/libsshutil.a





httpclient_PLATFORMS = win32 x64 win32vista x64vista win32win7 x64win7
httpserver_PLATFORMS = win32 x64 win32vista x64vista win32win7 x64win7

httpserver_SOURCES = httpserver.c





filterproxy_SOURCES = filterproxy.c sshcopystream.c
filterproxy_DEPENDENCIES = $(LDADD)

http_benchmark_SOURCES = http-benchmark.c
http_benchmark_DEPENDENCIES = $(LDADD)


private_headers += sshcopystream.h



include $(top_srcdir)/Makefile.libextra
include $(top_srcdir)/Makefile.grandlib_provider

# EOF
