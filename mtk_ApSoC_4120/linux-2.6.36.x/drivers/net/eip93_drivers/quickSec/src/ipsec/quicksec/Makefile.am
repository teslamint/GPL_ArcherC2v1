#
# ipsec/quicksec/Makefile.am.raw
#
# Copyright:
#       Copyright (c) 2002-2005 SFNT Finland Oy.
#       All rights reserved
#

AUTOMAKE_OPTIONS = 1.0 foreign dist-zip no-dependencies
SUBDIRS = \
	engine fastpath policymanager apps appgw \
        unified-kernel kernel \
	unified-usermode \
 	samples \
	usermode \
	tests






INCLUDES = \
	-I$(top_builddir)/ipsec/include \
	-I$(top_builddir)/include \
	-I$(top_builddir)/ipsec

EXTRA_DIST = \
	make-vendor-id.c \
	version.h \
	versioni.h 




EXTRA_PROGRAMS = make-vendor-id
make_vendor_id_LDADD = -L$(top_builddir)/lib -lssh

compiled-dtds: $(top_builddir)/lib/sshxml/dtd-compress
	$(top_builddir)/lib/sshxml/dtd-compress -b quicksec_dtd -o apps/quicksec_dtd.c $(srcdir)/apps/quicksec.dtd

includes:
