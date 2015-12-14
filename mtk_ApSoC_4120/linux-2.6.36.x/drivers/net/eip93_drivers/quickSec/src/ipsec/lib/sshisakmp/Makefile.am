
# Added by filter_add_makefile_libextra_stuff
# To keep automake silent about public and private headers
# not been set when something is added to them

public_headers =
private_headers =

#
# ipsec/lib/sshisakmp Makefile.am
#
#  Copyright:
#          Copyright (c) 2002, 2003 SFNT Finland Oy.
# All rights reserved
#

AUTOMAKE_OPTIONS = 1.0 foreign dist-zip no-dependencies
DEFS = -DSSH_BUILD_IPSEC

# This library does not depend on any other ipsec/lib library, thus
# autodist_ipsec_lib stuff is not needed
INCLUDES = -I$(top_srcdir) -I$(top_builddir)/include -I$(top_srcdir)/ipsec

WINCONF_OPTIONS = maintainer=kivinen@ssh.fi

noinst_LIBRARIES = libsshisakmp.a

libsshisakmp_a_SOURCES = \
	isakmp.c \
	isakmp_attrs.c \
	isakmp_cookie.c \
	isakmp_crypt.c \
	isakmp_da.c \
	isakmp_finalize.c \
	isakmp_groups.c \
	isakmp_id.c \
	isakmp_init.c \
	isakmp_input.c \
	isakmp_linearize.c \
	isakmp_misc.c \
	isakmp_output.c \
	isakmp_packet.c \
	isakmp_reply.c \
	isakmp_sa.c \
	isakmp_stat.c \
	isakmp_state.c \
	isakmp_tables.c \
	isakmp_udp.c \
	isakmp_util.c

EXTRA_DIST = FEATURES DOC

SUBDIRS = tests

public_headers += \
	isakmp.h \
	isakmp_policy.h \
	isakmp_defaults.h \
	isakmp_util.h \
	isakmp_notify.h \
	isakmp_linearize.h \
	isakmp_doi.h

private_headers += \
	isakmp_internal.h \
	isakmp_state.h

GRANDLIB_OBJECTS = $(libsshisakmp_a_OBJECTS) $(libsshisakmp_a_LIBADD)

include $(top_srcdir)/Makefile.grandlib_provider
include $(top_srcdir)/Makefile.libextra
