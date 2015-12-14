## Process this file with automake to produce Makefile.in

#
# ssh2 Makefile.am
#
# Author: Timo J. Rinne <tri@ssh.fi>
#
#  Copyright:
#          Copyright (c) 2002, 2003 SFNT Finland Oy.
#                    All rights reserved
#

AUTOMAKE_OPTIONS = 1.0 foreign dist-zip no-dependencies
WINCONF_OPTIONS = maintainer=kivinen@ssh.fi

bin_PROGRAMS = ssh-ldapadd ssh-ldapclient

man_MANS = ssh-ldapadd.1 ssh-ldapclient.1

INCLUDES = -I. -I$(srcdir) \
	   -I$(top_builddir) -I$(top_srcdir) \
	   -I$(top_builddir)/include







LDADD = -L../../lib -lssh


EXTRA_DIST = \
	ssh-ldapadd.1 ssh-ldapclient.1

DEPENDENCIES = $(top_builddir)/lib/libssh.a

ssh_ldapadd_SOURCES = ssh-ldapadd.c
ssh_ldapadd_DEPENDENCIES = $(DEPENDENCIES)
ssh_ldapclient_SOURCES = ssh-ldapclient.c
ssh_ldapclient_DEPENDENCIES = $(DEPENDENCIES)

includes:
