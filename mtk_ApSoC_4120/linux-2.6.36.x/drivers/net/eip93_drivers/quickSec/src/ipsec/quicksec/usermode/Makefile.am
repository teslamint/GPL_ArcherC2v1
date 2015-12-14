#
# ipsec/quicksec/usermode/Makefile.am.raw
#
# Copyright:
# 	Copyright (c) 2002-2004 SFNT Finland Oy.
#       All rights reserved.
#
# Automakefile for QuickSec user-mode policy manager built directory
#

AUTODIST_OPTIONS = lnsrcs

AUTOMAKE_OPTIONS = 1.0 foreign dist-zip no-dependencies
WINCONF_OPTIONS = \
	no-dsw \
        vpath=..;../apps;../policymanager;../apps;../appgw;../ims;../engine;../../util

# VPATH must not contain extra spaces
VPATH 	 = $(top_srcdir)/ipsec/quicksec/apps:$(top_srcdir)/ipsec/quicksec/policymanager:$(top_srcdir)/ipsec/quicksec/appgw:$(top_srcdir)/ipsec/quicksec/ims:$(top_srcdir)/ipsec/quicksec/engine:$(top_srcdir)/interceptor/libkernelutil:$(top_srcdir)/ipsec/util

if SSH_QS_BUILD_USERMODE

DEFS = -DQUICKSEC -DSSH_BUILD_IPSEC

noinst_LIBRARIES = \
                   libappgw.a \
		   libpmconf.a \
		   libipsecpm.a











libipsecpm_a_SOURCES =       \
	$(PM_LIB_SRCS)

bin_PROGRAMS = \
	quicksecpm


































































































libappgw_a_SOURCES = $(APPGW_LIB_SRCS)



libpmconf_a_SOURCES = $(QUICKSECPM_CONF_LIB_SRCS)


quicksecpm_DEPENDENCIES =  libipsecpm.a \
                           libpmconf.a \
	                   libappgw.a





quicksecpm_LDADD = \
        $(top_builddir)/ipsec/quicksec/usermode/libpmconf.a \
        $(top_builddir)/ipsec/quicksec/usermode/libipsecpm.a \
        $(top_builddir)/ipsec/quicksec/usermode/libappgw.a \
        $(top_builddir)/ipsec/lib/libsshipsec.a \
	@AV_ALG_LIBS@ \
        $(top_builddir)/lib/libssh.a









quicksecpm_SOURCES =            \
	quicksecpm.c 		\
	quicksecpm_unix.c 	\
        quicksec_dtd.c          \
	eng_pm_api_pm.c	        \
	engine_pm_api_util.c 	\
	virtual_adapter_util.c  \
	ip_interfaces.c





quicksecpm_SOURCES_windelta = \
	-quicksecpm_unix.c 	\
	+quicksecpm_windows.c 	


EXTRA_PROGRAMS = tinypm 	\
		clientpm	




tinypm_SOURCES = \
	tinypm.c		\
	eng_pm_api_pm.c	        \
	engine_pm_api_util.c 	\
	virtual_adapter_util.c  \
	ip_interfaces.c



tinypm_PLATFORMS = win32 x64 win32vista x64vista win32win7 x64win7


clientpm_SOURCES = \
	clientpm.c		\
	eng_pm_api_pm.c	        \
	engine_pm_api_util.c 	\
	virtual_adapter_util.c  \
	ip_interfaces.c



clientpm_PLATFORMS = win32 x64 win32vista x64vista win32win7 x64win7




endif

LDADD = \
        $(top_builddir)/ipsec/quicksec/usermode/libipsecpm.a \
        $(top_builddir)/ipsec/lib/libsshipsec.a \
        $(top_builddir)/ipsec/quicksec/usermode/libpmconf.a \
        $(top_builddir)/ipsec/quicksec/usermode/libappgw.a \
	@AV_ALG_LIBS@ \
        $(top_builddir)/lib/libssh.a














INCLUDES = \
	$(PM_LIB_INCLUDES) $(APPGW_LIB_INCLUDES) \
	$(IMS_LIB_INCLUDES) $(IPSEC_UTIL_INCLUDES) \
	$(KERNEL_UTIL_INCLUDES)


# Include lists of source files
include $(top_srcdir)/interceptor/libkernelutil/Makefile.fragment
include $(top_srcdir)/ipsec/util/Makefile.fragment
include $(top_srcdir)/ipsec/quicksec/policymanager/Makefile.fragment

include $(top_srcdir)/ipsec/quicksec/apps/Makefile.fragment
include $(top_srcdir)/ipsec/quicksec/appgw/Makefile.fragment





