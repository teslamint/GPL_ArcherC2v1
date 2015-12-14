
# Added by filter_add_makefile_libextra_stuff
# To keep automake silent about public and private headers
# not been set when something is added to them

public_headers =
private_headers =

## Process this file with automake to produce Makefile.in

#
# lib/sshutil/tests Makefile.am
#
# Author: Tatu Ylonen <ylo@ssh.fi>
#
#  Copyright:
#          Copyright (c) 2002, 2003, 2006 SFNT Finland Oy.
#               All rights reserved
#

AUTOMAKE_OPTIONS = 1.0 foreign dist-zip no-dependencies
WINCONF_OPTIONS = maintainer=mtr@ssh.com,kivinen@ssh.com



INCLUDES = -I$(srcdir)/..               \
        -I$(top_srcdir)/lib/zlib        \
        -I$(top_srcdir)/lib/sshcrypto   \
	-I$(top_srcdir)  -I$(top_srcdir)/lib/sshutil/sshcore  -I$(top_srcdir)/lib/sshutil/sshadt  -I$(top_srcdir)/lib/sshutil/ssheloop  -I$(top_srcdir)/lib/sshutil/sshstrutil  -I$(top_srcdir)/lib/sshutil/sshfsm  -I$(top_srcdir)/lib/sshutil/sshstream  -I$(top_srcdir)/lib/sshutil/sshsysutil  -I$(top_srcdir)/lib/sshutil/sshnet  -I$(top_srcdir)/lib/sshutil/sshmisc  -I$(top_srcdir)/lib/sshutil/sshaudit  -I$(top_srcdir)/lib/sshutil/sshpacketstream  -I$(top_srcdir)/lib/sshutil/sshtestutil 



LDADD = ../libsshutil.a         \
        ../../zlib/libz.a       \
	$(top_builddir)/lib/sshutil/sshtestutil/libsshtestutil.a $(top_builddir)/lib/sshutil/sshpacketstream/libsshpacketstream.a $(top_builddir)/lib/sshutil/sshaudit/libsshaudit.a $(top_builddir)/lib/sshutil/sshmisc/libsshmisc.a $(top_builddir)/lib/sshutil/sshnet/libsshnet.a $(top_builddir)/lib/sshutil/sshsysutil/libsshsysutil.a $(top_builddir)/lib/sshutil/sshstream/libsshstream.a $(top_builddir)/lib/sshutil/sshfsm/libsshfsm.a $(top_builddir)/lib/sshutil/sshstrutil/libsshstrutil.a $(top_builddir)/lib/sshutil/ssheloop/libssheloop.a $(top_builddir)/lib/sshutil/sshadt/libsshadt.a $(top_builddir)/lib/sshutil/sshcore/libsshcore.a 



EXTRA_DIST = \
	t-packet-test1.c	\
	t-packet-test2.c	\
	t-packet-test3.c	\
	t-packet-test4.c	



TESTS_LIGHT =           \
	t-globals	\
	t-malloc	\
	t-sshstr	\
        t-time          \
        t-addr          \
        t-addrencode    \
        t-debugwrite    \
        t-dsprintf      \
        t-encode        \
        t-eprintf       \
        t-esnprintf     \
        t-eventloop     \
        t-fsm           \
        t-getput        \
        t-inet_ntoa     \
        t-replace       \
        t-snprintf      \
        t-snprintf2     \
	t-renderer	\
        t-sshutf8       \
        t-threads       \
        t-threadedmbox  \
        t-url           \
	t-audit		\
        t-regex         \
        t-fingerprint   \
        t-udp           \
        t-crc32         \
        t-buffer        \
        t-miscstring    \
        t-streampair    \
        t-socks         \
        t-localstream   \
	t-icmp-util     \
	t-netconfig



































TESTS = $(TESTS_LIGHT)  \
	t-adt		\
	t-timeout       \
        t-operation     \
	t-packet	\
	t-dns           \
	t-resolver	\
        t-stream        \
        t-timemeasure   \
	t-obstack















TESTS_LIGHT_windelta =	\
	-t-malloc	\
	-t-udp		\
	-t-replace	\
	-t-inet_ntoa    \
	-t-globals      \
	-t-netconfig

EXTRA_PROGRAMS =                \
        t-decay                 \
        t-base64                \
        t-debug                 \
        t-c64                   \
        t-ipaddr-print          \
        t-zlib                  \
        t-tcpc                  \
        t-udpc                  \
        t-localstreamclient     \
        t-localstreamserver     \
        t-l2tp                  \
        t-randspeed             \
	t-messenger		\
	t-audit-format		\
	t-netevent              \
	t-netmac                \
	$(TESTS)














EXTRA_PROGRAMS_windelta = \
	-t-l2tp           \
	-t-netevent       \
	-t-netmac

t_debugwrite_PLATFORMS = win32 x64 win32vista x64vista win32win7 x64win7


t_localstream_PLATFORMS = win32 x64 win32vista x64vista win32win7 x64win7
t_localstreamclient_PLATFORMS = win32 x64 win32vista x64vista win32win7 x64win7
t_localstreamserver_PLATFORMS = win32 x64 win32vista x64vista win32win7 x64win7


t_eventloop_SOURCES = t-eventloop.c eventloop_perf.c



grandlib:
	@if test ! -f grandlib_objs; then touch grandlib_objs; fi

include $(top_srcdir)/Makefile.libextra
include $(top_srcdir)/Makefile.grandlib_provider

# EOF
