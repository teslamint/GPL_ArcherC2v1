## Process this file with automake to produce Makefile.in

#
# src/ipsec/interceptor/Makefile.am.raw
#
#  Copyright:
#          Copyright (c) 2002, 2003 SFNT Finland Oy.
#               All rights reserved
#
# This file works closely with the configure.in.inc file in directory
# above. The interceptor source files need to be configured for each
# platform in the configure.  All source files must be listed in
# EXTRA_DIST to be included in distributions.
#

AUTOMAKE_OPTIONS = 1.0 foreign dist-zip no-dependencies
SUBDIRS = @SSH_INTERCEPTOR_MACHINE_DIR@
SUBDIRS_windelta = +windows

INCLUDES_SUBDIRS =      \
	tests           \
	bsd             \
	windows         \
	windows/winim   \
	windows/ndisfilter   \
	linux           \
	caviumocteon



















CLEANFILES = 





includes:
	  for dir in $(SUBDIRS) .nosuch; \
	  do \
	    if [ -d $$dir ]; then \
		( cd $$dir && $(MAKE) includes) ; \
	    fi \
	  done

TAGS:
	etags `find $(SUBDIRS) -name '*.[ch]' -print`
