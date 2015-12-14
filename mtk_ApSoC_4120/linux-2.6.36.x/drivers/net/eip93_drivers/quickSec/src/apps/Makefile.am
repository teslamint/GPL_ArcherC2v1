## Process this file with automake to produce Makefile.in

#
# apps Makefile.am
#
# Author: Tero Kivinen <kivinen@ssh.fi>
#
#  Copyright:
#          Copyright (c) 2002, 2003 SFNT Finland Oy.
#                    All rights reserved
#

AUTOMAKE_OPTIONS = 1.0 foreign dist-zip no-dependencies
SUBDIRS = \
	certutils			\
	ldaputils			\
	cryptutils			\
	perfutils			\
	caviumocteon			









































SUBDIRS_windelta = \
	+winceutils



INCLUDES_SUBDIRS = \
	$(SUBDIRS) \
	winceutils



includes:
	-for dir in $(SUBDIRS); do \
	  (cd $$dir && $(MAKE) includes); \
	done
