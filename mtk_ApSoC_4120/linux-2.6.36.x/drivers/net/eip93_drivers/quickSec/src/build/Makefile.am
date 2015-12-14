## Process this file with automake to produce Makefile.in
#
# build/Makefile.am
#
# Author: Lauri Tarkkala <ltarkkal@ssh.com>
#
#  Copyright:
#          Copyright (c) 2002, 2003 SFNT Finland Oy.
# All rights reserved
#

AUTOMAKE_OPTIONS = 1.0 foreign dist-zip no-dependencies
SUBDIRS = xml-compress

includes:
	-if test -n "$(SUBDIRS)" ; then     \
	  for dir in "$(SUBDIRS)"; do       \
	    (cd $$dir && $(MAKE) includes); \
	  done                              \
	fi
