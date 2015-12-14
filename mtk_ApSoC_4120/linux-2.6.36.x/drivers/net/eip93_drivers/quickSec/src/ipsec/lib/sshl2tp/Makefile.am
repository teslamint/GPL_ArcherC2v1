
# Added by filter_add_makefile_libextra_stuff
# To keep automake silent about public and private headers
# not been set when something is added to them

public_headers =
private_headers =

#
# ipsec/lib/sshl2tp Makefile.am
#
#  Copyright:
#          Copyright (c) 2002, 2003 SFNT Finland Oy.
# All rights reserved

AUTOMAKE_OPTIONS	= 1.0 foreign dist-zip no-dependencies
DEFS = -DSSH_BUILD_IPSEC

INCLUDES = -I$(top_srcdir)/ipsec -I$(top_srcdir) -I$(top_builddir)/include -I$(top_srcdir)/ipsec/lib/sshisakmp  -I$(top_srcdir)/ipsec/lib/sshikev2  -I$(top_srcdir)/ipsec/lib/sshppp 
LDADD = $(top_builddir)/ipsec/lib/sshppp/libsshppp.a $(top_builddir)/ipsec/lib/sshikev2/libsshikev2.a $(top_builddir)/ipsec/lib/sshisakmp/libsshisakmp.a 

WINCONF_OPTIONS		= maintainer=tuomas.siren@ssh.com,mtr@ssh.fi

SUBDIRS			= tests

noinst_LIBRARIES	= libsshl2tp.a

EXTRA_DIST =

libsshl2tp_a_SOURCES =                  \
        sshl2tp_internal.h              \
        sshl2tp.c                       \
        sshl2tp_message.c               \
        sshl2tp_st_cc_initiator.h       \
        sshl2tp_st_cc_initiator.c       \
        sshl2tp_st_cc_responder.h       \
        sshl2tp_st_cc_responder.c       \
        sshl2tp_st_lac_ic.h             \
        sshl2tp_st_lac_ic.c             \
        sshl2tp_st_lac_oc.h             \
        sshl2tp_st_lac_oc.c             \
        sshl2tp_st_lns_ic.h             \
        sshl2tp_st_lns_ic.c             \
        sshl2tp_st_lns_oc.h             \
        sshl2tp_st_lns_oc.c             \
        sshl2tp_st_session.h            \
        sshl2tp_st_session.c            \
        sshl2tp_st_tunnel.h             \
        sshl2tp_st_tunnel.c             \
        sshl2tp_tables.c                \
        sshl2tp_transport.h             \
        sshl2tp_transport.c             \
        sshl2tp_util.c

public_headers += sshl2tp.h sshl2tp_parse.h

enscript:
	enscript -G2rE -pfoo.ps \
	sshl2tp.h sshl2tp_parse.h $(libsshl2tp_a_SOURCES)

GRANDLIB_OBJECTS = $(libsshl2tp_a_OBJECTS) $(libsshl2tp_a_LIBADD)

include $(top_srcdir)/Makefile.grandlib_provider
include $(top_srcdir)/Makefile.libextra
