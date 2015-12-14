
# Added by filter_add_makefile_libextra_stuff
# To keep automake silent about public and private headers
# not been set when something is added to them

public_headers =
private_headers =

#
# ipsec/lib/sshl2tp/tests Makefile.am
#
#  Copyright:
#          Copyright (c) 2002, 2003 SFNT Finland Oy.
# All rights reserved

AUTOMAKE_OPTIONS	= 1.0 foreign dist-zip no-dependencies
WINCONF_OPTIONS		= maintainer=tuomas.siren@ssh.com,mtr@ssh.fi

DEFS = -DSSH_BUILD_IPSEC



INCLUDES = -I$(srcdir)/.. -I$(top_srcdir)/ipsec -I$(top_srcdir) -I$(top_builddir)/include -I$(top_srcdir)/ipsec/lib/sshisakmp  -I$(top_srcdir)/ipsec/lib/sshikev2  -I$(top_srcdir)/ipsec/lib/sshppp 
LDADD = ../libsshl2tp.a \
	$(top_builddir)/ipsec/lib/sshppp/libsshppp.a $(top_builddir)/ipsec/lib/sshikev2/libsshikev2.a $(top_builddir)/ipsec/lib/sshisakmp/libsshisakmp.a  \
	-L$(top_builddir)/lib -lssh

TESTS_LIGHT			= t-l2tp-seq t-l2tp
TESTS = $(TESTS_LIGHT)

EXTRA_DIST =

EXTRA_PROGRAMS		= ssh-l2tp $(TESTS)



include $(top_srcdir)/Makefile.libextra
