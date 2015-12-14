
# Added by filter_add_makefile_libextra_stuff
# To keep automake silent about public and private headers
# not been set when something is added to them

public_headers =
private_headers =

#
# sshutil/libsshnet Makefile.am.raw
#
# Copyright:
#       Copyright (c) 2002, 2003, 2004 SFNT Finland Oy.
# 	All rights reserved
#

AUTOMAKE_OPTIONS = 1.0 foreign dist-zip no-dependencies
INCLUDES = -I$(srcdir)/.. -I$(top_srcdir)  -I$(top_srcdir)/lib/sshutil/sshcore  -I$(top_srcdir)/lib/sshutil/sshadt  -I$(top_srcdir)/lib/sshutil/ssheloop  -I$(top_srcdir)/lib/sshutil/sshstrutil  -I$(top_srcdir)/lib/sshutil/sshfsm  -I$(top_srcdir)/lib/sshutil/sshstream  -I$(top_srcdir)/lib/sshutil/sshsysutil 
LDADD = $(top_builddir)/lib/sshutil/sshsysutil/libsshsysutil.a $(top_builddir)/lib/sshutil/sshstream/libsshstream.a $(top_builddir)/lib/sshutil/sshfsm/libsshfsm.a $(top_builddir)/lib/sshutil/sshstrutil/libsshstrutil.a $(top_builddir)/lib/sshutil/ssheloop/libssheloop.a $(top_builddir)/lib/sshutil/sshadt/libsshadt.a $(top_builddir)/lib/sshutil/sshcore/libsshcore.a 

WINCONF_OPTIONS = maintainer=tmononen@safenet-inc.com

INCLUDES_windelta = +-I$(srcdir)/win32

noinst_LIBRARIES=libsshnet.a

libsshnet_a_SOURCES =           \
        sshurl.c                \
        sshinet.c               \
        sshinetbits.c           \
        sshinetcalc.c           \
        sshinetcompare.c        \
        sshinetether.c          \
        sshinethash.c           \
        sshinetmapped.c         \
        sshinetmask.c           \
        sshinetnetmask.c        \
        sshinetmerge.c          \
        sshinetparse.c          \
        sshinetprint.c          \
        sshinetproto.c          \
        sshinetrender.c         \
        sshinetscope.c          \
        sshinetstrtobin.c       \
        sshinetencode.c         \
        sshudp-ip.c             \
        sshudp-str.c            \
        sshtcp.c                \
        sshnameserver.c         \
        sshsocks.c              \
	sshdnstransport.c	\
	sshdnstransportudp.c	\
	sshdnstransporttcp.c	\
	sshdnsnameserver.c	\
	sshdnsquery.c		\
	sshdnsrrsetcache.c	\
	sshdnsresolver.c	\
	sshdnspacket.c		\
	sshdnspacketrender.c	\
	sshdnserror.c		\
	sshdnsrender.c		\
	sshdnsrrsetrender.c	\
	sshdnsrrtype.c		\
	sshdnsrrdataprint.c	\
        sshunixlocalstream.c    \
        sshunixtcplocalstream.c \
        sshunixudp.c            \
        sshunixtcp.c            \
	sshnetconfig.c          \
	sshlinuxnetconfig.c     \
	sshlinuxnetevent.c      \
	sshlinuxnetmac.c        \
	sshvxworksnetconfig.c   \
	sshvxworksnetevent.c    \
	sshvxworksnetmac.c      \
	sshicmp-util.c	        



















libsshnet_a_SOURCES_windelta =          \
        -sshunixlocalstream.c           \
        -sshunixtcplocalstream.c        \
        -sshunixudp.c                   \
        -sshunixtcp.c                   \
	-sshlinuxnetconfig.c            \
	-sshlinuxnetevent.c             \
	-sshlinuxnetmac.c               \
	-sshvxworksnetconfig.c          \
	-sshvxworksnetevent.c           \
	-sshvxworksnetmac.c             














libsshnet_a_LIBADD_windelta =           \
        +win32/sshwinutil2.o            \
        +win32/sshwinlocalstream.o      \
        +win32/sshwinudp2.o             \
        +win32/sshwintcp2.o             












public_headers +=               \
        sshurl.h                \
        sshinet.h               \
        sshether.h              \
        sshinetencode.h         \
        sshudp.h                \
	sshdns.h		\
	sshdnstransport.h	\
	sshdnstransportimpl.h	\
	sshdnsnameserver.h	\
	sshdnsquery.h		\
	sshdnsrrsetcache.h	\
	sshdnsresolver.h	\
	sshdnspacket.h		\
        sshtcp.h                \
        sshnameserver.h         \
        sshsocks.h              \
        sshlocalstream.h        \
	sshicmp-util.h          \
	sshlinuxnetconfig_i.h   \
	sshnetconfig.h          \
	sshnetevent.h           \
	sshnetmac.h












EXTRA_DIST = \
	win32/sshwinutil2.c \
	win32/sshwinutil2.h \
	win32/sshwinlocalstream.c \
	win32/sshwinudp2.c \
	win32/sshwintcp2.c 













GRANDLIB_OBJECTS = $(libsshnet_a_OBJECTS) $(libsshnet_a_LIBADD)

include $(top_srcdir)/Makefile.libextra
include $(top_srcdir)/Makefile.grandlib_provider
# EOF
