#
# Makefile.am.raw
#
# Copyright:
#       Copyright (c) 2002-2004 SFNT Finland Oy.
#       All rights reserved.
#
# Automakefile for unified (kernel mode) QuickSec.
#

AUTODIST_OPTIONS = lnsrcs
AUTOMAKE_OPTIONS = 1.0 foreign dist-zip no-dependencies
DEFS = -DSSH_BUILD_IPSEC

CPPFLAGS = $(SSH_INTERCEPTOR_CPPFLAGS)

CC = $(KERN_CC)
CFLAGS = $(KERN_CFLAGS) -DSSHMALLOC_H
VPATH 	 = $(top_srcdir)/ipsec/quicksec/engine:$(top_srcdir)/ipsec/quicksec/fastpath/@QS_FASTPATH@:$(top_srcdir)/interceptor/libkernelutil:$(top_srcdir)/ipsec/util:$(top_srcdir)/ipsec/hwaccel/@HWACCEL_CONFIGURED_DIRECTORY@:$(top_srcdir)/ipsec/quicksec/policymanager:$(top_srcdir)/ipsec/quicksec/apps:$(top_srcdir)/ipsec/quicksec/appgw:$(HWACCEL_VPATH)

if SSH_QS_BUILD_UNIFIED_KERNEL

noinst_LIBRARIES = libengine.a libipsecpm.a libappgw.a libpmconf.a \
	libfastpath-software.a \
	libaccelerator.a \
	libkernel.a

libengine_a_SOURCES =           \
	$(ENGINE_IMPL_SRCS)     \
	$(ROUTE_SRCS)

libfastpath_software_a_LIBADD = @QS_FASTPATH_CRYPTO_ASM_OBJS@
libfastpath_software_a_DEPENDENCIES = @QS_FASTPATH_CRYPTO_ASM_OBJS@
libfastpath_software_a_SOURCES = $(FASTPATH_SOFTWARE_SRCS)

libaccelerator_a_SOURCES =
libaccelerator_a_LIBADD = @HWACCEL_CONFIGURED_OBJS@
libaccelerator_a_DEPENDENCIES = @HWACCEL_CONFIGURED_OBJS@
HWACCEL_INCLUDES = @HWACCEL_CONFIGURED_INCLUDES@

libkernel_a_SOURCES = \
	$(VIRTUAL_ADAPTER_SRCS) \
	$(IPSEC_UTIL_SRCS) $(PLATFORM_UTILITY_LNSRCS) \
	$(KERNEL_UTIL_SRCS)

libipsecpm_a_SOURCES = \
        $(PM_LIB_SRCS)
libappgw_a_SOURCES = $(APPGW_LIB_SRCS)
libpmconf_a_SOURCES = $(QUICKSECPM_CONF_LIB_SRCS) quicksec_dtd.o \
	quicksecpm.c quicksecpm_vxworks.c \
	engine_pm_api_util.c engine_pm_api_engine.c

endif

INCLUDES = \
	-DSSH_IPSEC_UNIFIED_ADDRESS_SPACE -DSSH_IPSEC_UNIFIED_KERNEL \
	$(PM_LIB_INCLUDES) $(APPGW_LIB_INCLUDES) \
	$(HWACCEL_INCLUDES) \
	$(VIRTUAL_ADAPTER_INCLUDES) $(IPSEC_UTIL_INCLUDES) \
	$(ENGINE_INCLUDES) $(FASTPATH_INCLUDES) \
	$(ROUTE_INCLUDES) $(KERNEL_UTIL_INCLUDES)

# Include lists of source files
include $(top_srcdir)/ipsec/hwaccel/Makefile.fragment
include $(top_srcdir)/interceptor/libkernelutil/Makefile.fragment
include $(top_srcdir)/ipsec/util/Makefile.fragment
include $(top_srcdir)/ipsec/quicksec/engine/Makefile.fragment
include $(top_srcdir)/ipsec/quicksec/fastpath/Makefile.fragment
include $(top_srcdir)/ipsec/quicksec/policymanager/Makefile.fragment
include $(top_srcdir)/ipsec/quicksec/apps/Makefile.fragment
include $(top_srcdir)/ipsec/quicksec/appgw/Makefile.fragment

