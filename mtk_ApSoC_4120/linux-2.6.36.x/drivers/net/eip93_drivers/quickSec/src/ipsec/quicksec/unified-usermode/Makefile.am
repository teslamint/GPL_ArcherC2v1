#
# Makefile.am.raw
#
# Copyright:
#       Copyright (c) 2002-2004 SFNT Finland Oy.
#       All rights reserved.
#
# Automakefile for QuickSec combined user-mode engine and policy manager
#

AUTODIST_OPTIONS = lnsrcs
AUTOMAKE_OPTIONS = 1.0 foreign dist-zip no-dependencies
WINCONF_OPTIONS = \
	  vpath=..;../engine;../fastpath;../fastpath/scp51x0;../fastpath/caviumocteon;../fastpath/software;../policymanager;../apps;../appgw;../../../interceptor/libkernelutil;../../util;../../hwaccel/none;../../../interceptor/usermode

# VPATH must not contain extra spaces
VPATH 	 = $(top_srcdir)/ipsec/quicksec/engine:$(top_srcdir)/ipsec/quicksec/fastpath/@QS_FASTPATH@:$(top_srcdir)/ipsec/quicksec/fastpath/software:$(top_srcdir)/ipsec/quicksec/policymanager:$(top_srcdir)/ipsec/quicksec/apps:$(top_srcdir)/ipsec/quicksec/appgw:$(top_srcdir)/interceptor/libkernelutil:$(top_srcdir)/ipsec/util:$(top_srcdir)/ipsec/hwaccel/none:$(top_srcdir)/ipsec/hwaccel/@HWACCEL_CONFIGURED_DIRECTORY@:$(top_srcdir)/interceptor/usermode

if SSH_QS_BUILD_UNIFIED_USERMODE

DEFS = -DQUICKSEC -DSSH_BUILD_IPSEC

noinst_LIBRARIES = libengine.a \
	           libfastpath-software.a \
		   libfastpath.a libkernel.a \
        	   libaccelerator.a \
		   libipsecpm.a \
		   libpmconf.a \
		   libappgw.a 





libengine_a_SOURCES =       \
	$(ENGINE_IMPL_SRCS) \
	$(ROUTE_SRCS)       

libfastpath_software_a_SOURCES = $(FASTPATH_SOFTWARE_SRCS)

# Fastpath alternative implementations
libfastpath_a_SOURCES = 
libfastpath_a_LIBADD = @FASTPATH_CONFIGURED_OBJS@
libfastpath_a_DEPENDENCIES = @FASTPATH_CONFIGURED_OBJS@


libkernel_a_SOURCES = \
	$(VIRTUAL_ADAPTER_SRCS) \
        virtual_adapter.c               \
        ip_cksum.c                      \
        ip_cksum.h                      \
        ip_cksum_packet.c               \
        ip_interfaces.c                 \
        ip_interfaces.h                 \
        packet_utils.c



libipsecpm_a_SOURCES = \
	$(PM_LIB_SRCS)



libappgw_a_SOURCES = $(APPGW_LIB_SRCS)



libpmconf_a_SOURCES = $(QUICKSECPM_CONF_LIB_SRCS)







libaccelerator_a_SOURCES = $(HWACCEL_NONE_SRCS)
libaccelerator_a_LIBADD =
libaccelerator_a_DEPENDENCIES =




bin_PROGRAMS = quicksecpm

quicksecpm_SOURCES = \
	quicksecpm.c 		\
        quicksecpm_i.h 		\
	quicksecpm_unix.c 	\
	eng_pm_api_pm.c	        \
	engine_pm_api_util.c 	\
	ip_interfaces.c 	\
        quicksec_dtd.c 		\
	usermodeinterceptor.c   \
	usermode_packet.c       \
	usermode_util.c



quicksecpm_SOURCES_windelta = \
	-quicksecpm_unix.c 	\
	+quicksecpm_windows.c 	

quicksecpm_DEPENDENCIES = libengine.a \
			  libfastpath-software.a \
			  libkernel.a \
        		  libaccelerator.a \
			  libipsecpm.a \
			  libfastpath.a \
			  libpmconf.a \
			  libappgw.a





quicksecpm_LDADD = \
       $(top_builddir)/ipsec/quicksec/unified-usermode/libpmconf.a \
       $(top_builddir)/ipsec/quicksec/unified-usermode/libappgw.a \
       $(top_builddir)/ipsec/quicksec/unified-usermode/libipsecpm.a \
       $(top_builddir)/ipsec/quicksec/unified-usermode/libengine.a \
       $(top_builddir)/ipsec/quicksec/unified-usermode/libipsecpm.a \
       $(top_builddir)/ipsec/quicksec/unified-usermode/libfastpath-software.a \
       $(top_builddir)/ipsec/quicksec/unified-usermode/libfastpath.a \
       $(top_builddir)/ipsec/quicksec/unified-usermode/libkernel.a \
       $(top_builddir)/ipsec/quicksec/unified-usermode/libaccelerator.a \
       $(top_builddir)/ipsec/lib/libsshipsec.a \
       @AV_ALG_LIBS@ \
       $(top_builddir)/lib/libssh.a









EXTRA_PROGRAMS = tinypm 	\
		clientpm



tinypm_SOURCES = \
	tinypm.c		\
	eng_pm_api_pm.c	\
	engine_pm_api_util.c 	\
	ip_interfaces.c 	\
	usermodeinterceptor.c   \
	usermode_packet.c       \
	usermode_util.c

tinypm_DEPENDENCIES = $(noinst_QUICKSECPM_LIBRARIES)


clientpm_SOURCES = \
	clientpm.c		\
	eng_pm_api_pm.c	\
	engine_pm_api_util.c 	\
	ip_interfaces.c 	\
	usermodeinterceptor.c   \
	usermode_packet.c       \
	usermode_util.c

clientpm_DEPENDENCIES = $(noinst_QUICKSECPM_LIBRARIES)


endif

LDADD = \
       $(top_builddir)/ipsec/quicksec/unified-usermode/libpmconf.a \
       $(top_builddir)/ipsec/quicksec/unified-usermode/libappgw.a \
       $(top_builddir)/ipsec/quicksec/unified-usermode/libipsecpm.a \
       $(top_builddir)/ipsec/quicksec/unified-usermode/libengine.a \
       $(top_builddir)/ipsec/quicksec/unified-usermode/libipsecpm.a \
       $(top_builddir)/ipsec/quicksec/unified-usermode/libfastpath-software.a \
      $(top_builddir)/ipsec/quicksec/unified-usermode/libfastpath.a \
       $(top_builddir)/ipsec/quicksec/unified-usermode/libkernel.a \
       $(top_builddir)/ipsec/quicksec/unified-usermode/libaccelerator.a \
       $(top_builddir)/ipsec/lib/libsshipsec.a \
       @AV_ALG_LIBS@ \
       $(top_builddir)/lib/libssh.a










HWACCEL_INCLUDES = @HWACCEL_CONFIGURED_INCLUDES@

HWACCEL_INCLUDES_windelta = -@HWACCEL_CONFIGURED_INCLUDES@

INCLUDES = \
	-DUSERMODE_ENGINE \
	-DSSH_IPSEC_UNIFIED_ADDRESS_SPACE \
	-DINTERCEPTOR_PROVIDES_INTERFACE_INFORMATION \
	-DINTERCEPTOR_PROVIDES_IP_ROUTING \
	-DINTERCEPTOR_PROVIDES_VIRTUAL_ADAPTERS \
	$(USERMODE_INTERCEPTOR_INCLUDES) \
	$(PM_LIB_INCLUDES) $(APPGW_LIB_INCLUDES) \
	$(HWACCEL_INCLUDES) $(HWACCEL_NONE_INCLUDES) \
	$(VIRTUAL_ADAPTER_INCLUDES) $(IPSEC_UTIL_INCLUDES) \
	$(ENGINE_INCLUDES) $(FASTPATH_INCLUDES) \
	$(ROUTE_INCLUDES) $(KERNEL_UTIL_INCLUDES)

# Include lists of source files
include $(top_srcdir)/ipsec/hwaccel/Makefile.fragment
include $(top_srcdir)/interceptor/libkernelutil/Makefile.fragment
include $(top_srcdir)/interceptor/usermode/Makefile.fragment
include $(top_srcdir)/ipsec/util/Makefile.fragment
include $(top_srcdir)/ipsec/quicksec/engine/Makefile.fragment
include $(top_srcdir)/ipsec/quicksec/fastpath/Makefile.fragment
include $(top_srcdir)/ipsec/quicksec/policymanager/Makefile.fragment
include $(top_srcdir)/ipsec/quicksec/apps/Makefile.fragment
include $(top_srcdir)/ipsec/quicksec/appgw/Makefile.fragment

