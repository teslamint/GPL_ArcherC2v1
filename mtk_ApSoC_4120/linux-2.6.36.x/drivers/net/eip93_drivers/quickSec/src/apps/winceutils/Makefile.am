## Process this file with automake to produce Makefile.in

#
# Makefile.am
#
#  Copyright:
#          Copyright (c) 2006, 2007 SFNT Finland Oy.
#                    All rights reserved
#

AUTOMAKE_OPTIONS = 1.0 foreign dist-zip no-dependencies
WINCONF_OPTIONS = \
        vpath=../../ipsec/quicksec/ims

# VPATH must not contain extra spaces
VPATH 	 = $(top_srcdir)/ipsec/quicksec/ims

bin_PROGRAMS =		\
	qsconsole	\
	qssetup 	\
	qsinfo




ce_platforms =		\
	std500armv4i	\
	std500x86	\
	std500sh4	\
	std500mipsii	\
	std500mipsii_fp	\
	std500mipsiv	\
	std500mipsiv_fp	\
	ppc50armv4i	\
	sp50armv4i	\
	wm6std		\
	wm6pro

qsconsole_PLATFORMS = $(ce_platforms)
qsconsole_winconf = template=windows-app

qssetup_PLATFORMS = $(ce_platforms)
qssetup_winconf = template=dll






qsinfo_PLATFORMS = $(ce_platforms)
qsinfo_winconf = template=windows-app

qsconsole_SOURCES = 	\
	qsconsole.c	\
	qsconsole.h	\
	qsconsole.rc

qssetup_SOURCES = 	\
	qssetup.c	\
	qssetup.h	\
	qssetup.rc
	
qsinfo_SOURCES = 	\
	qsinfo.c	\
	qsinfo.h	\
	qsinfo.rc


INCLUDES =  \
          -DQS_SETUP_EXPORTS 





































includes:

