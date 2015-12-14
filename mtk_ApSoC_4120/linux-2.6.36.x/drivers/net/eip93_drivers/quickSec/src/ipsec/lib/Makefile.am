
# Added by filter_add_makefile_libextra_stuff
# To keep automake silent about public and private headers
# not been set when something is added to them

public_headers =
private_headers =

#
# File: ipsec/lib/Makefile.am
#
# Copyright:
#       Copyright (c) 2002-2004 SFNT Finland Oy.
# 	All rights reserved
#

AUTOMAKE_OPTIONS = 1.0 foreign dist-zip no-dependencies
SUBDIRS =                       \
          sshisakmp             \
          sshikev2              \
          sshppp                \
          sshl2tp               

















GRANDLIB = libsshipsec.a

libsshipsec_a_SUBLIBRARIES =     \
	sshl2tp/libsshl2tp.a     \
	sshppp/libsshppp.a       \
	sshisakmp/libsshisakmp.a \
	sshikev2/libsshikev2.a  















include $(top_srcdir)/Makefile.grandlib_maker
include $(top_srcdir)/Makefile.libextra
