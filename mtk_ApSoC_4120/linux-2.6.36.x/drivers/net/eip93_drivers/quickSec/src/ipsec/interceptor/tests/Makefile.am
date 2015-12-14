
# Added by filter_add_makefile_libextra_stuff
# To keep automake silent about public and private headers
# not been set when something is added to them

public_headers =
private_headers =

## Process this file with automake to produce Makefile.in

#
# ipsec/interceptor/tests Makefile.am
#
#  Copyright:
#          Copyright (c) 2002, 2003 SFNT Finland Oy.
#                    All rights reserved
#

AUTOMAKE_OPTIONS = 1.0 foreign dist-zip no-dependencies
WINCONF_OPTIONS = maintainer=tas@ssh.fi

DEFS = -DSSH_BUILD_IPSEC



TESTS = t-icept-attach
TESTS_windelta = -t-icept-attach

t_icept_attach_SOURCES = t-icept-attach.c
t_icept_attach_LINKOBJS = icept_attach_i386.o
t_icept_attach_LDADD = $(t_icept_attach_LINKOBJS) $(LDADD)
t_icept_attach_DEPENDENCIES = $(DEPLIBS) $(t_icept_attach_LINKOBJS)

EXTRA_PROGRAMS = $(TESTS)






















LDADD = -L../../../lib -lssh
DEPLIBS = ../../../lib/libssh.a

INCLUDES = -I. -I$(srcdir) -I../ -I$(srcdir)/.. \
	   -I$(top_builddir) -I$(top_srcdir) \
	   -I$(top_builddir)/include \
	   -I../../engine -I$(srcdir)/../../engine \
	   -I../@SSH_INTERCEPTOR_MACHINE_DIR@ \
	   -I$(srcdir)/../@SSH_INTERCEPTOR_MACHINE_DIR@ \
	   -I../bsd -I$(srcdir)/../bsd

icept_attach_i386.o: $(srcdir)/../bsd/icept_attach_i386.c
	rm -f icept_attach_i386.c
	$(LN_S) $(srcdir)/../bsd/icept_attach_i386.c .
	$(COMPILE) -c icept_attach_i386.c

EXTRA_DIST = \
	$(INTERCEPTOR_TESTER_SRCS) \
	Makefile.fragment




includes:


include $(top_srcdir)/ipsec/interceptor/tests/Makefile.fragment
include $(top_srcdir)/Makefile.libextra
