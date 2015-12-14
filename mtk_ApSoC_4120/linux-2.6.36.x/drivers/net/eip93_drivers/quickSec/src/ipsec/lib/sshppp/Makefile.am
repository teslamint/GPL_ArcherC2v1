
# Added by filter_add_makefile_libextra_stuff
# To keep automake silent about public and private headers
# not been set when something is added to them

public_headers =
private_headers =

#
# ipsec/lib/sshppp Makefile.am
#
#  Copyright:
#          Copyright (c) 2002, 2003 SFNT Finland Oy.
# All rights reserved

AUTOMAKE_OPTIONS	= 1.0 foreign dist-zip no-dependencies
DEFS = -DSSH_BUILD_IPSEC

INCLUDES = -I$(top_srcdir)/ipsec -I$(top_srcdir) -I$(top_builddir)/include -I$(top_srcdir)/ipsec/lib/sshisakmp  -I$(top_srcdir)/ipsec/lib/sshikev2 
LDADD = $(top_builddir)/ipsec/lib/sshikev2/libsshikev2.a $(top_builddir)/ipsec/lib/sshisakmp/libsshisakmp.a 

SUBDIRS = tests

WINCONF_OPTIONS		= maintainer=ltarkkal@ssh.com

EXTRA_DIST =

noinst_LIBRARIES	= libsshppp.a
libsshppp_a_SOURCES	= sshppp_setup.c sshppp_fsm.c sshppp_io_stream.c \
			  sshppp_fcs.c sshppp_lcp.c \
			  sshppp_linkpkt.c sshppp_lcp_config.c \
			  sshppp_events.c sshppp_timer.c sshppp_flush.c \
			  sshppp_chap.c sshppp_chap_fsm.c sshppp_protocol.c \
			  sshppp_protocol_fsm.c sshppp_config.c \
			  sshppp_ipcp.c sshppp_ipcp_config.c sshppp_thread.c \
			  sshppp_auth.c sshppp_pap_fsm.c \
			  sshppp_eap_fsm.c \
                         sshppp_radius.c 





private_headers		+= sshppp_fcs.h sshppp_ipcp.h sshppp_linkpkt.h \
			  sshppp_chap.h sshppp_flush.h sshppp_ipcp_config.h \
			  sshppp_config.h sshppp_internal.h \
			  sshppp_lcp.h sshppp_protocol.h sshppp_events.h \
			  sshppp_io_stream.h sshppp_lcp_config.h \
			  sshppp_timer.h sshppp_thread.h \
			  sshppp_auth.h sshppp_pap.h \
			  sshppp_eap.h 



public_headers += sshppp.h

GRANDLIB_OBJECTS = $(libsshppp_a_OBJECTS) $(libsshppp_a_LIBADD)

include $(top_srcdir)/Makefile.grandlib_provider
include $(top_srcdir)/Makefile.libextra
