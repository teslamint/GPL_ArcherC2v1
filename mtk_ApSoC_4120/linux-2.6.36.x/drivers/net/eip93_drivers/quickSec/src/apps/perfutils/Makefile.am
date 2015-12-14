# Makefile.am.raw
#
#
#  Copyright:
#          Copyright (c) 2002-2005 SFNT Finland Oy.
#               All rights reserved.
#
#

AUTOMAKE_OPTIONS = 1.0 foreign dist-zip no-dependencies
EXTRA_PROGRAMS = udp-send udp-recv ubenchmark ubenchmark-multiport tbenchmark

INCLUDES = -I. -I$(srcdir) \
	-I$(top_builddir) -I$(top_srcdir) \
	-I$(top_builddir)/include

LDADD = -L$(top_builddir)/lib -lssh

DEPENDENCIES = $(top_builddir)/lib/libssh.a

includes:
