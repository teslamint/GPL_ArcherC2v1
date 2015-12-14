## Process this file with automake to produce Makefile.in

#
# top-level Makefile.am
#
# Copyright:
#       Copyright (c) 2002, 2003 SFNT Finland Oy.
#       All rights reserved
#

public_headers =
private_headers =

AUTOMAKE_OPTIONS = 1.0 foreign dist-zip no-dependencies
PACKAGE = ssh-src
VERSION = 0.0

SUBDIRS = \
	lib \
	include \
	build \
	ipsec \
	apps \
	filter_distdefs \
	interceptor
























INCLUDES_SUBDIRS = \
	lib \
	include \
	build \
	ipsec \
	apps \
	winconf \
	filter_distdefs \
	interceptor













































public_headers += sshdistdefs.h  sshparams.h




EXTRA_DIST = \
	sshparams.h \
	sshwinconf_defs.h \
	mobilinux-conf-arm \
	octeon-conf-sdk-1.9.0    \
	octeon-conf-sdk-1.8.1    \
	filter_distdefs.pl \
	config.sub config.guess install-sh missing mkinstalldirs \
	copy_include Makefile.grandlib.pre Makefile.grandlib_final.pre.in \
	Makefile.grandlib_maker Makefile.grandlib_provider Makefile.libextra





















BUILT_SOURCES = sshdistdefs.h





# all-local: includes
includes:
	-if test '!' -d include; then mkdir include; fi
	$(COPY_INCLUDE) sshconf.h include/sshconf.h sshconf.h
	-if test -n "$(public_headers)"; then \
	  $(SHELL) -c 'for file in $(public_headers); do \
	     $(COPY_INCLUDE) $(srcdir)/$$file include/`basename $$file` $$file; \
	  done' ; \
	fi
	-for dir in $(SUBDIRS); do \
		( cd $$dir && $(MAKE) includes) ; \
	done

run_unit_tests_flags=--log-build --log-run --remove-and-make
unit-test:
	@if test -x $(top_srcdir)/test/run_unit_tests ; then             \
	    $(top_srcdir)/test/run_unit_tests $(run_unit_tests_flags) ;  \
	else                                                             \
	    echo No $(top_srcdir)/test/run_unit_tests available ;        \
	    false ;                                                      \
	fi

html-unit-test:
	@if test -x $(top_srcdir)/test/run_unit_tests ; then             \
	    $(top_srcdir)/test/run_unit_tests $(run_unit_tests_flags) --html;  \
	else                                                             \
	    echo No $(top_srcdir)/test/run_unit_tests available ;        \
	    false ;                                                      \
	fi

autocompile-test:
	@if test -x $(top_srcdir)/test/run_unit_tests ; then             \
	    $(top_srcdir)/test/run_unit_tests $(run_unit_tests_flags)    \
		--html --tar-logs; 					 \
	else                                                             \
	    echo No $(top_srcdir)/test/run_unit_tests available ;        \
	    false ;                                                      \
	fi

autocompile-test-3rd:
	@if test -x $(top_srcdir)/test/run_unit_tests ; then             \
	    $(top_srcdir)/test/run_unit_tests $(run_unit_tests_flags)    \
		--html --tar-logs --memdebug=3rd;			 \
	else                                                             \
	    echo No $(top_srcdir)/test/run_unit_tests available ;        \
	    false ;                                                      \
	fi

# eof

noinst_HEADERS = $(public_headers) $(private_headers)
