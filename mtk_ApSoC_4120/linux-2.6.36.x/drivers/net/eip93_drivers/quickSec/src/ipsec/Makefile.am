#
# src/ipsec/Makefile.am.raw
#
#  Copyright:
#          Copyright (c) 2002, 2003, 2005 SFNT Finland Oy.
# All rights reserved
#

AUTOMAKE_OPTIONS = 1.0 foreign dist-zip no-dependencies
LDADD =

SUBDIRS =                       \
	include			\
	lib			\
        quicksec                \
        hwaccel                 \
        interceptor             \
        util













EXTRA_DIST =                    \
        ipsec_params.h          \
	ipsec_params_small.h    \
	README.ipsec_over_tcp   






includes:
	-for dir in $(SUBDIRS); do \
		( cd $$dir && $(MAKE) includes) ; \
	done

TAGS:
	etags `find $(SUBDIRS) -name '*.[ch]' -print` kernel/*.[ch]
