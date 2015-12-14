# Process this file with automake to produce Makefile.in
#
# lib Makefile.am
#
#  Copyright:
#          Copyright (c) 2002, 2003, 2005 SFNT Finland Oy.
#          All rights reserved
#

AUTOMAKE_OPTIONS = 1.0 foreign dist-zip no-dependencies
SUBDIRS =                       \
          sshutil               \
          zlib                  \
          sshmath               \
          sshasn1               \
          sshcrypto             \
	  sshcryptoaux          \
          sshradius             \
          sshldap               \
          sshhttp               \
	  sshxml                \
          sshcert               \
          sshpkcs               \
          sshenroll             \
          sshvalidator          \
          sshtls                \
          sshapputil            \
          sshexternalkey        \
          ssheap                \
          sshsim                

























































# sshtest testsuite

all-local: local-includes

local-includes:

includes: local-includes
	for d in $(SUBDIRS); do (cd $$d && $(MAKE) includes); done

clean-local:
	rm -rf tmpdir-*

TAGS:
	etags `find $(SUBDIRS) -name '*.[ch]' -print`

stripped-library :
	@echo "Copying objects to stripped/"
	-rm -rf stripped/
	mkdir stripped/
	$(MAKE) grandlib
	for i in `cat grandlib_objs`; \
	do \
	  echo "Copying $$i..."; \
	  cp $$i stripped/`echo $$i | sed 's!/!_!g'`; \
	done
	cd stripped; for i in *.o; do echo Stripping $$i...; strip -d $$i; done
	-rm -f libssh.a
	$(AR) cq libssh.a stripped/*.o
	$(RANLIB) libssh.a

EXTRA_DIST = 











































GRANDLIB = libssh.a












# The `object_SUBLIBRARIES' variables are used on the Windows to
# expand the original library `object' with the listed sublibraries at
# the link step.

libssh_a_SUBLIBRARIES = $(top_builddir)/lib/sshsim/libsshsim.a $(top_builddir)/lib/ssheap/libssheap.a $(top_builddir)/lib/sshexternalkey/libsshexternalkey.a $(top_builddir)/lib/sshapputil/libsshapputil.a $(top_builddir)/lib/sshtls/libsshtls.a $(top_builddir)/lib/sshvalidator/libsshvalidator.a $(top_builddir)/lib/sshenroll/libsshenroll.a $(top_builddir)/lib/sshpkcs/libsshpkcs.a $(top_builddir)/lib/sshcert/libsshcert.a $(top_builddir)/lib/sshxml/libsshxml.a $(top_builddir)/lib/sshhttp/libsshhttp.a $(top_builddir)/lib/sshldap/libsshldap.a $(top_builddir)/lib/sshradius/libsshradius.a $(top_builddir)/lib/sshcryptoaux/libsshcryptoaux.a $(top_builddir)/lib/sshcrypto/libsshcrypto.a $(top_builddir)/lib/sshasn1/libsshasn1.a $(top_builddir)/lib/sshmath/libsshmath.a $(top_builddir)/lib/zlib/libz.a $(top_builddir)/lib/sshutil/libsshutil.a 

include $(top_srcdir)/Makefile.grandlib_maker
