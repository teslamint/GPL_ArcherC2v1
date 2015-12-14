# src/apps/caviumocteon/Makefile.am.raw
#
# Copyright:
# 	Copyright (c) 2008 SFNT Finland Oy.
# 	All rights reserved
#

AUTOMAKE_OPTIONS = 1.0 foreign dist-zip no-dependencies
AUTODIST_OPTIONS = lnsrcs

OCTEON_FASTPATH_CONTROL_SRC= \
	octeon_se_fastpath_control.c \
	octeon_se_fastpath_control_internal.h

EXTRA_DIST = \
	Makefile.cavium.fragment \
	$(OCTEON_FASTPATH_CONTROL_SRC)

.PHONY: cavium_ln_srcs

all-local: cavium_ln_srcs makefile.cavium
	$(MAKE) -f makefile.cavium OCTEON_TARGET=linux_64

cavium_ln_srcs: $(top_srcdir)/apps/caviumocteon/Makefile.cavium.fragment
	$(MAKE) -f $(top_srcdir)/apps/caviumocteon/Makefile.cavium.fragment ln_srcs

makefile.cavium: $(top_srcdir)/apps/caviumocteon/Makefile.cavium.fragment
	$(MAKE) -f $(top_srcdir)/apps/caviumocteon/Makefile.cavium.fragment makefile

clean: $(top_srcdir)/apps/caviumocteon/makefile.cavium
	$(MAKE) -f makefile.cavium OCTEON_TARGET=linux_64 clean

includes:


include $(top_srcdir)/ipsec/quicksec/fastpath/caviumocteon/Makefile.fragment

