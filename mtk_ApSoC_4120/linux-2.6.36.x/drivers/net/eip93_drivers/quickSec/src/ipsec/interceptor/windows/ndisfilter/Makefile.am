## Process this file with automake to produce Makefile.in
#
# src/ipsec/interceptor/windows/ndisfilter/Makefile.am.raw
#
#  Copyright:
#          Copyright (c) 2007 SFNT Finland Oy.
#               All rights reserved
#

WINCONF_OPTIONS = maintainer=ttuunanen@safenet-inc.com \
                  dsw-name=qsfilter

DEFS = -DSSH_BUILD_IPSEC

FILTER_SRCDIR = $(top_srcdir)/interceptor/windows/ndisfilter
COMMON_WIN_SRCDIR = $(top_srcdir)/interceptor/windows

WINCONF_CUSTOM_BUILD_0_INPUT = $(COMMON_WIN_SRCDIR)/event_log_msg.mc
WINCONF_CUSTOM_BUILD_0_COMMAND = mc -v -c _INPUT_
WINCONF_CUSTOM_BUILD_0_OUTPUT = event_log_msg.h
WINCONF_CUSTOM_BUILD_0_PLATFORMS = win32vista x64vista win32win7 x64win7

SUBDIRS =

INCLUDES_SUBDIRS =

INCLUDES = \
        -I$(top_srcdir)/interceptor/windows/vnic \
        -I$(top_srcdir)/interceptor/windows/ndisfilter \
        -I$(top_srcdir)/interceptor/windows \
        -I$(top_srcdir)/ipsec/interceptor \
        -I$(top_srcdir)/ipsec/engine \
        -I$(top_srcdir)/interceptor/include \
        -I$(top_srcdir)/interceptor/libkernelutil \
        -I$(top_srcdir)/ipsec/util \
        -I$(top_srcdir)/ipsec/lib/sshdhcp \
        -I$(top_srcdir)/ipsec \
        -I$(top_srcdir)/lib/sshcrypto \
        -I$(top_srcdir)/lib/sshutil \
        -I$(top_srcdir)/lib/sshutil/sshfsm \
        -I$(top_srcdir)/lib/sshutil/sshadt \
        -I$(top_srcdir)/lib/sshutil/sshcore \
        -I$(top_srcdir)/lib/sshutil/ssheloop \
        -I$(top_srcdir)/lib/sshutil/sshnet \
        -I$(top_srcdir)/lib/sshutil/sshstrutil





#-----------------------------------------------------------
# SafeNet IPSEC driver
#-----------------------------------------------------------
#
lib_LIBRARIES_windelta = \
        +qsfilter.sys

qsfilter_sys_PLATFORMS = win32vista x64vista win32win7 x64win7

qsfilter_sys_winconf = template=driver custom-object

#-----------------------------------------------------------
# NDIS filter driver specific source files
#-----------------------------------------------------------
#
ndisfilter_sources = \
        $(FILTER_SRCDIR)/ndisfilter_main.c \
        $(FILTER_SRCDIR)/ndisfilter_adapter.c \
        $(FILTER_SRCDIR)/ndisfilter_icept_api.c \
        $(FILTER_SRCDIR)/qsfilter.rc \
        $(FILTER_SRCDIR)/interceptor_i.h \
        $(FILTER_SRCDIR)/resource.h

#-----------------------------------------------------------
# Common Windows interceptor files  
#-----------------------------------------------------------
#
win_common_sources = \
        $(COMMON_WIN_SRCDIR)/adapter_common.c \
        $(COMMON_WIN_SRCDIR)/alloc.c \
        $(COMMON_WIN_SRCDIR)/event.c \
        $(COMMON_WIN_SRCDIR)/event_log.c \
        $(COMMON_WIN_SRCDIR)/interceptor_i_common.c \
        $(COMMON_WIN_SRCDIR)/icept_api_common.c \
        $(COMMON_WIN_SRCDIR)/iodevice.c \
        $(COMMON_WIN_SRCDIR)/ipdevice.c \
        $(COMMON_WIN_SRCDIR)/mutex.c \
        $(COMMON_WIN_SRCDIR)/ndis6_packet_pool.c \
        $(COMMON_WIN_SRCDIR)/pktizer.c \
        $(COMMON_WIN_SRCDIR)/registry.c \
        $(COMMON_WIN_SRCDIR)/secsys.c \
        $(COMMON_WIN_SRCDIR)/task.c \
        $(COMMON_WIN_SRCDIR)/timeout.c \
        $(COMMON_WIN_SRCDIR)/debug_trace.c \
        $(COMMON_WIN_SRCDIR)/ndis_render.c \
        $(COMMON_WIN_SRCDIR)/winnt_file_io.c \
        $(COMMON_WIN_SRCDIR)/winnt_device_io.c \
        $(COMMON_WIN_SRCDIR)/virtual_adapter.c \
        $(COMMON_WIN_SRCDIR)/virtual_adapter_private.c \
        $(COMMON_WIN_SRCDIR)/wan_interface.c \
        $(COMMON_WIN_SRCDIR)/win_ip_interface.c \
        $(COMMON_WIN_SRCDIR)/win_ip_route.c \
        $(COMMON_WIN_SRCDIR)/winnt6_ipdevice.c \
        $(COMMON_WIN_SRCDIR)/wrkqueue.c \
        $(COMMON_WIN_SRCDIR)/adapter_common.h \
        $(COMMON_WIN_SRCDIR)/event.h \
        $(COMMON_WIN_SRCDIR)/event_log.h \
        $(COMMON_WIN_SRCDIR)/interceptor_i_common.h \
        $(COMMON_WIN_SRCDIR)/iodevice.h \
        $(COMMON_WIN_SRCDIR)/ipdevice.h \
        $(COMMON_WIN_SRCDIR)/ipdevice_internal.h \
        $(COMMON_WIN_SRCDIR)/packet_pool_common.h \
        $(COMMON_WIN_SRCDIR)/ndis6_packet_pool.h \
        $(COMMON_WIN_SRCDIR)/pktizer.h \
        $(COMMON_WIN_SRCDIR)/registry.h \
        $(COMMON_WIN_SRCDIR)/secsys.h \
        $(COMMON_WIN_SRCDIR)/task.h \
        $(COMMON_WIN_SRCDIR)/debug_trace.h \
        $(COMMON_WIN_SRCDIR)/ndis_render.h \
        $(COMMON_WIN_SRCDIR)/file_io.h \
        $(COMMON_WIN_SRCDIR)/device_io.h \
        $(COMMON_WIN_SRCDIR)/virtual_adapter_private.h \
        $(COMMON_WIN_SRCDIR)/wan_interface.h \
        $(COMMON_WIN_SRCDIR)/win_ip_interface.h \
        $(COMMON_WIN_SRCDIR)/win_ip_route.h \
        $(COMMON_WIN_SRCDIR)/win_os_version.h \
        $(COMMON_WIN_SRCDIR)/wrkqueue.h





qsfilter_sys_SOURCES_windelta = \
        @+(ndisfilter_sources) \
        @+(win_common_sources)

#-----------------------------------------------------------
# Dependencies to other components
#-----------------------------------------------------------
#

qsfilter_sys_DEPENDENCIES_windelta = \
        +libaccelerator_none.a  \
        +libkernel.a            \
        +libfastpath_software.a \
        +libengine.a

#-----------------------------------------------------------
# Miscallenious files
#-----------------------------------------------------------
#
EXTRA_DIST = \
        readme_qs.txt \
        qsfilter.inf 

