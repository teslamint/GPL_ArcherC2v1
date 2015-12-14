# src/ipsec/interceptor/caviumocteon/se/Makefile.am.raw
#
# Copyright:
# 	Copyright (c) 2008 SFNT Finland Oy.
# 	All rights reserved
#

AUTOMAKE_OPTIONS = 1.0 foreign dist-zip no-dependencies
AUTODIST_OPTIONS = lnsrcs


EXTRA_DIST = \
	Makefile.cavium.fragment

.PHONY: cavium_ln_srcs

all-local: cavium_ln_srcs makefile.cavium app
	$(MAKE) -f makefile.cavium

cavium_ln_srcs: $(top_srcdir)/ipsec/interceptor/caviumocteon/se/Makefile.cavium.fragment
	$(MAKE) -f $(top_srcdir)/ipsec/interceptor/caviumocteon/se/Makefile.cavium.fragment ln_srcs

makefile.cavium: $(top_srcdir)/ipsec/interceptor/caviumocteon/se/Makefile.cavium.fragment
	$(MAKE) -f $(top_srcdir)/ipsec/interceptor/caviumocteon/se/Makefile.cavium.fragment makefile

app: $(top_srcdir)/ipsec/interceptor/caviumocteon/se/makefile.cavium 
	$(MAKE) -f makefile.cavium

clean:$(top_srcdir)/ipsec/interceptor/caviumocteon/se/makefile.cavium
	$(MAKE) -f makefile.cavium clean

include $(top_srcdir)/ipsec/quicksec/fastpath/caviumocteon/Makefile.fragment

