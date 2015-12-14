
# Added by filter_add_makefile_libextra_stuff
# To keep automake silent about public and private headers
# not been set when something is added to them

public_headers =
private_headers =

## Process this file with automake to produce Makefile.in

#
# lib/sshmath/tests Makefile.am
#
# Author: Tatu Ylonen <ylo@ssh.fi>
#
#  Copyright:
#          Copyright (c) 2002, 2003 SFNT Finland Oy.
#                    All rights reserved
#

AUTOMAKE_OPTIONS = 1.0 foreign dist-zip no-dependencies
WINCONF_OPTIONS = maintainer=tmo@ssh.fi



INCLUDES = -I$(srcdir)/.. -I$(top_srcdir)  -I$(top_srcdir)/lib/sshutil/sshcore  -I$(top_srcdir)/lib/sshutil/sshadt  -I$(top_srcdir)/lib/sshutil/ssheloop  -I$(top_srcdir)/lib/sshutil/sshstrutil  -I$(top_srcdir)/lib/sshutil/sshfsm  -I$(top_srcdir)/lib/sshutil/sshstream  -I$(top_srcdir)/lib/sshutil/sshsysutil  -I$(top_srcdir)/lib/sshutil/sshnet  -I$(top_srcdir)/lib/sshutil/sshmisc  -I$(top_srcdir)/lib/sshutil/sshaudit  -I$(top_srcdir)/lib/sshutil/sshpacketstream  -I$(top_srcdir)/lib/sshutil/sshtestutil  -I$(top_srcdir)/lib/sshutil  -I$(top_srcdir)/lib/zlib 
LDADD = ../libsshmath.a $(top_builddir)/lib/zlib/libz.a $(top_builddir)/lib/sshutil/libsshutil.a 

TESTS_LIGHT = t-xuint           \
              t-xuint2          \
	t-mathtest 		\
	t-sophie-germain 	\
	t-montgomery








TESTS = $(TESTS_LIGHT) \
	t-mathspeed 		









# t-2adic-agm

EXTRA_PROGRAMS = factor $(TESTS)

EXTRA_DIST = \
        pollard.h


t_mathtest_SOURCES = \
	t-mathtest.c




t_mathtest_DEPENDENCIES = $(LDADD)








t_mathspeed_SOURCES = t-mathspeed.c
t_mathspeed_DEPENDENCIES = $(LDADD)


t_montgomery_SOURCES = t-montgomery.c
t_montgomery_DEPENDENCIES = $(LDADD)

#t_2adic_agm_SOURCES = t-2adic-agm.c
#t_2adic_agm_DEPENDENCIES = $(LDADD)












t_sophie_germain_SOURCES = t-sophie-germain.c
t_sophie_germain_DEPENDENCIES = $(LDADD)


factor_SOURCES = factor.c pollard.c
factor_DEPENDENCIES = $(LDADD)



include $(top_srcdir)/Makefile.libextra
include $(top_srcdir)/Makefile.grandlib_provider

# EOF
