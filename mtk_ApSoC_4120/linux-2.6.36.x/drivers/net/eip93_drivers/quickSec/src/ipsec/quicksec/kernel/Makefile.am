#
# Makefile.am.raw
#
# Copyright:
#       Copyright (c) 2002-2004 SFNT Finland Oy.
#       All rights reserved.
#
# Automakefile for QuickSec kernel-mode engine.
#
# This makefile produces the following libraries:
#

AUTODIST_OPTIONS = lnsrcs
AUTOMAKE_OPTIONS = 1.0 foreign dist-zip no-dependencies
WINCONF_OPTIONS  = \
	no-dsw \
	vpath=.;..;../engine;../fastpath;../fastpath/scp51x0;../fastpath/caviumocteon;../fastpath/software;../../../interceptor/libkernelutil;../../util;../../hwaccel/none;../../../lib/sshcrypto/sshcipher;../../../lib/sshcrypto/sshhash;../../../lib/sshcrypto/sshmac;../../../lib/sshutil/sshcore;../../../lib/sshutil/sshaudit;../../../lib/sshutil/sshnet;../../../lib/sshutil/sshstrutil;../../lib/sshdhcp;../../../lib/sshcryptoaux;../../../lib/zlib;../../../lib/sshmath

DEFS = -DSSH_BUILD_IPSEC

# -DSSHMALLOC_H is needed to prevent sshmalloc.h from being included
CC 	 = $(KERN_CC)
CFLAGS 	 = $(KERN_CFLAGS) -DSSHMALLOC_H -DQUICKSEC
CPPFLAGS = $(SSH_INTERCEPTOR_CPPFLAGS)

# VPATH must not contain extra spaces
VPATH = $(top_srcdir)/ipsec/quicksec/engine:$(top_srcdir)/ipsec/quicksec/fastpath:$(top_srcdir)/ipsec/quicksec/fastpath/@QS_FASTPATH@:$(top_srcdir)/ipsec/quicksec/fastpath/software:$(top_srcdir)/interceptor/libkernelutil:$(top_srcdir)/ipsec/util:$(top_srcdir)/ipsec/hwaccel/@HWACCEL_CONFIGURED_DIRECTORY@:$(top_srcdir)/ipsec/hwaccel/none:$(HWACCEL_VPATH):

if SSH_QS_BUILD_KERNEL

noinst_LIBRARIES = \
	libkernel.a 		\
	libengine.a 		\
	libfastpath-software.a 	\
	libfastpath.a \
	libaccelerator-none.a   \
	libaccelerator.a

noinst_LIBRARIES_windelta = \
	-libkernel.a 		\
	-libengine.a 		\
	-libfastpath-software.a \
	-libfastpath.a \
	-libaccelerator-none.a  \
	-libaccelerator.a       \
	+libkernel.a            \
	+libengine.a            \
	+libfastpath_software.a \
	+libaccelerator_none.a



# Kernel utility library
libkernel_a_SOURCES = \
	$(VIRTUAL_ADAPTER_SRCS) \
	$(IPSEC_UTIL_SRCS) $(PLATFORM_UTILITY_LNSRCS) \
	$(KERNEL_UTIL_SRCS)

# Engine implementation
libengine_a_SOURCES =        \
	$(ENGINE_SRCS)       \
	$(ROUTE_SRCS)

# Software Fastpath implementation
libfastpath_software_a_LIBADD = @QS_FASTPATH_CRYPTO_ASM_OBJS@
libfastpath_software_a_DEPENDENCIES = @QS_FASTPATH_CRYPTO_ASM_OBJS@
libfastpath_software_a_SOURCES = $(FASTPATH_SOFTWARE_SRCS)

# Fastpath alternative implementations
libfastpath_a_SOURCES = 
libfastpath_a_LIBADD = @FASTPATH_CONFIGURED_OBJS@
libfastpath_a_DEPENDENCIES = @FASTPATH_CONFIGURED_OBJS@

# Accelerators
libaccelerator_a_SOURCES =
libaccelerator_a_LIBADD = @HWACCEL_CONFIGURED_OBJS@
libaccelerator_a_DEPENDENCIES = @HWACCEL_CONFIGURED_OBJS@

# Accelerators
libaccelerator_none_a_SOURCES =  $(HWACCEL_NONE_SRCS)
libaccelerator_none_a_LIBADD =
libaccelerator_none_a_DEPENDENCIES =

endif

HWACCEL_INCLUDES = @HWACCEL_CONFIGURED_INCLUDES@
INCLUDES =                                                 \
	$(HWACCEL_INCLUDES)                                \
        $(HWACCEL_NONE_INCLUDES)                           \
	$(VIRTUAL_ADAPTER_INCLUDES) $(IPSEC_UTIL_INCLUDES) \
	$(ENGINE_INCLUDES) $(FASTPATH_INCLUDES)            \
	$(ROUTE_INCLUDES) $(KERNEL_UTIL_INCLUDES)

libkernel_a_SOURCES_windelta = @+(libkernel_a_SOURCES)
libkernel_a_winconf = template=driver-lib

libengine_a_SOURCES_windelta = @+(libengine_a_SOURCES)
libengine_a_winconf = template=driver-lib

libfastpath_software_a_SOURCES_windelta = \
	@+(libfastpath_software_a_SOURCES)
libfastpath_software_a_winconf = template=driver-lib

libaccelerator_none_a_SOURCES_windelta = \
	@+(libaccelerator_none_a_SOURCES)
libaccelerator_none_a_winconf = template=driver-lib

EXTRA_DIST =

# Include lists of source files
include $(top_srcdir)/ipsec/hwaccel/Makefile.fragment
include $(top_srcdir)/interceptor/libkernelutil/Makefile.fragment
include $(top_srcdir)/ipsec/util/Makefile.fragment
include $(top_srcdir)/ipsec/quicksec/engine/Makefile.fragment
include $(top_srcdir)/ipsec/quicksec/fastpath/Makefile.fragment

