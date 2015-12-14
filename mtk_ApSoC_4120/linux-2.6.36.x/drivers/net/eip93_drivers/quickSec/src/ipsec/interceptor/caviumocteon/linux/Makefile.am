# src/ipsec/interceptor/caviumocteon/linux/Makefile.am.raw
#
# Copyright:
#       Copyright (c) 2008 SFNT Finland Oy.
#       All rights reserved
#

AUTOMAKE_OPTIONS = 1.0 foreign dist-zip no-dependencies
AUTODIST_OPTIONS = lnsrcs

EXTRA_DIST = \
	Makefile.kbuild.fragment 

.PHONY:	kbuild_ln_srcs

all-local: kbuild_ln_srcs kbuild/Makefile
	cd kbuild && $(MAKE)

kbuild_ln_srcs: $(top_srcdir)/ipsec/interceptor/caviumocteon/linux/Makefile.kbuild.fragment
	$(MAKE)  -f $(top_srcdir)/ipsec/interceptor/caviumocteon/linux/Makefile.kbuild.fragment ln_srcs

kbuild/Makefile: $(top_srcdir)/ipsec/interceptor/caviumocteon/linux/Makefile.kbuild.fragment
	$(MAKE) -f $(top_srcdir)/ipsec/interceptor/caviumocteon/linux/Makefile.kbuild.fragment make-kbuild

clean: kbuild/Makefile
	cd kbuild && $(MAKE) clean

includes:

tags:

