
# Added by filter_add_makefile_libextra_stuff
# To keep automake silent about public and private headers
# not been set when something is added to them

public_headers =
private_headers =

#
# ipsec/lib/sshppp/tests Makefile.am
#
#  Copyright:
#          Copyright (c) 2002, 2003 SFNT Finland Oy.
# All rights reserved

AUTOMAKE_OPTIONS		= 1.0 foreign dist-zip no-dependencies
WINCONF_OPTIONS			= maintainer=ltarkkal@ssh.com

DEFS = -DSSH_BUILD_IPSEC



INCLUDES = -I$(srcdir)/.. -I$(top_srcdir)/ipsec -I$(top_srcdir) -I$(top_builddir)/include -I$(top_srcdir)/ipsec/lib/sshisakmp  -I$(top_srcdir)/ipsec/lib/sshikev2 
LDADD = ../libsshppp.a $(top_builddir)/ipsec/lib/sshikev2/libsshikev2.a $(top_builddir)/ipsec/lib/sshisakmp/libsshisakmp.a  -L$(top_builddir)/lib -lssh

TESTS				= t-dummy
TESTS_windelta                  = -t-dummy

EXTRA_DIST =

EXTRA_PROGRAMS			= t-pppd t-mschap $(TESTS)

EXTRA_PROGRAMS_windelta         = -t-pppd

# t_sshppp_fcs_SOURCES		= t-sshppp_fcs.c
# t_sshppp_fcs_DEPENDENCIES	= $(LDADD)

t_pppd_SOURCES          = t-pppd.c
t_pppd_DEPENDENCIES     = ../libsshppp.a

t_pppd_SOURCES_windelta = -t-pppd.c
t_pppd_DEPENDENCIES_windelta = -../libsshppp.a

t_mschap_SOURCES        =  t-mschap.c
t_mschap_DEPENDENCIES   = ../libsshppp.a



include $(top_srcdir)/Makefile.libextra
