## Process this file with automake to produce Makefile.in
#
# src/ipsec/interceptor/windows/winim/Makefile.am.raw
#
#  Copyright:
#          Copyright (c) 2002 - 2006 SFNT Finland Oy.
#               All rights reserved
#

WINCONF_OPTIONS = maintainer=ttuunanen@safenet-inc.com \
                  dsw-name=quicksec

DEFS = -DSSH_BUILD_IPSEC

WINIM_SRCDIR = $(top_srcdir)/interceptor/windows/winim
COMMON_WIN_SRCDIR = $(top_srcdir)/interceptor/windows

WINCONF_CUSTOM_BUILD_0_INPUT = $(COMMON_WIN_SRCDIR)/event_log_msg.mc
WINCONF_CUSTOM_BUILD_0_COMMAND = mc -v -c _INPUT_
WINCONF_CUSTOM_BUILD_0_OUTPUT = event_log_msg.h
WINCONF_CUSTOM_BUILD_0_PLATFORMS = win32 x64

SUBDIRS =
SUBDIRS_windelta = +install

INCLUDES_SUBDIRS = install

INCLUDES = \
        -I$(top_srcdir)/interceptor/windows/vnic \
        -I$(top_srcdir)/interceptor/windows/winim \
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
        +quicksec.sys

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

quicksec_sys_PLATFORMS = win32 x64 $(ce_platforms)

quicksec_sys_winconf = template=driver custom-object

#-----------------------------------------------------------
# NDIS intermediate driver specific source files
#-----------------------------------------------------------
#
win_im_sources = \
        $(WINIM_SRCDIR)/main.c \
        $(WINIM_SRCDIR)/interceptor.c	\
        $(WINIM_SRCDIR)/interceptor_i.c \
        $(WINIM_SRCDIR)/upper_edge.c \
        $(WINIM_SRCDIR)/lower_edge.c \
        $(WINIM_SRCDIR)/adapter.c \
        $(WINIM_SRCDIR)/interceptor_i.h \
        $(WINIM_SRCDIR)/upper_edge.h \
        $(WINIM_SRCDIR)/lower_edge.h \
        $(WINIM_SRCDIR)/adapter.h \
        $(WINIM_SRCDIR)/wince_wan_interface.c \
        $(WINIM_SRCDIR)/wince_wan_interface.h \
        $(WINIM_SRCDIR)/quicksec.rc \
        $(WINIM_SRCDIR)/resource.h



#-----------------------------------------------------------
# Common Windows interceptor files  
#-----------------------------------------------------------
#
win_common_sources = \
        $(COMMON_WIN_SRCDIR)/interceptor_i_common.h  \
        $(COMMON_WIN_SRCDIR)/interceptor_i_common.c  \
        $(COMMON_WIN_SRCDIR)/icept_api_common.c      \
        $(COMMON_WIN_SRCDIR)/adapter_common.h        \
        $(COMMON_WIN_SRCDIR)/adapter_common.c        \
        $(COMMON_WIN_SRCDIR)/packet_pool_common.h    \
        $(COMMON_WIN_SRCDIR)/ndis5_packet_pool.h     \
        $(COMMON_WIN_SRCDIR)/ndis5_packet_pool.c     \
        $(COMMON_WIN_SRCDIR)/virtual_adapter.c         \
        $(COMMON_WIN_SRCDIR)/virtual_adapter_private.c \
        $(COMMON_WIN_SRCDIR)/virtual_adapter_private.h \
        $(COMMON_WIN_SRCDIR)/task.c          \
        $(COMMON_WIN_SRCDIR)/task.h          \
        $(COMMON_WIN_SRCDIR)/timeout.c       \
        $(COMMON_WIN_SRCDIR)/event.c         \
        $(COMMON_WIN_SRCDIR)/event.h         \
        $(COMMON_WIN_SRCDIR)/mutex.c         \
        $(COMMON_WIN_SRCDIR)/wan_interface.c \
        $(COMMON_WIN_SRCDIR)/wan_interface.h \
        $(COMMON_WIN_SRCDIR)/win_ip_interface.c \
        $(COMMON_WIN_SRCDIR)/win_ip_interface.h \
        $(COMMON_WIN_SRCDIR)/win_ip_route.c     \
        $(COMMON_WIN_SRCDIR)/win_ip_route.h     \
        $(COMMON_WIN_SRCDIR)/win_ip_route_ce.c  \
        $(COMMON_WIN_SRCDIR)/win_os_version.h   \
        $(COMMON_WIN_SRCDIR)/wrkqueue.c      \
        $(COMMON_WIN_SRCDIR)/wrkqueue.h      \
        $(COMMON_WIN_SRCDIR)/event_log.c     \
        $(COMMON_WIN_SRCDIR)/event_log.h     \
        $(COMMON_WIN_SRCDIR)/debug_trace.h   \
        $(COMMON_WIN_SRCDIR)/debug_trace.c   \
        $(COMMON_WIN_SRCDIR)/file_io.h       \
        $(COMMON_WIN_SRCDIR)/winnt_file_io.c \
        $(COMMON_WIN_SRCDIR)/device_io.h     \
        $(COMMON_WIN_SRCDIR)/winnt_device_io.c \
        $(COMMON_WIN_SRCDIR)/ndis_render.c   \
        $(COMMON_WIN_SRCDIR)/ndis_render.h   \
        $(COMMON_WIN_SRCDIR)/ipdevice.c      \
        $(COMMON_WIN_SRCDIR)/ipdevice.h      \
        $(COMMON_WIN_SRCDIR)/ipdevice_internal.h \
        $(COMMON_WIN_SRCDIR)/winnt_ipdevice.c    \
        $(COMMON_WIN_SRCDIR)/wince_event_log.c   \
        $(COMMON_WIN_SRCDIR)/wince_file_io.c     \
        $(COMMON_WIN_SRCDIR)/wince_ipdevice.c    \
        $(COMMON_WIN_SRCDIR)/wince_iodevice.c    \
        $(COMMON_WIN_SRCDIR)/secsys.c        \
        $(COMMON_WIN_SRCDIR)/secsys.h        \
        $(COMMON_WIN_SRCDIR)/alloc.c         \
        $(COMMON_WIN_SRCDIR)/pktizer.c       \
        $(COMMON_WIN_SRCDIR)/pktizer.h       \
        $(COMMON_WIN_SRCDIR)/registry.c      \
        $(COMMON_WIN_SRCDIR)/registry.h      \
        $(COMMON_WIN_SRCDIR)/iodevice.c      \
        $(COMMON_WIN_SRCDIR)/iodevice.h 





quicksec_sys_SOURCES_windelta = \
        @+(win_im_sources) \
        @+(win_common_sources)

#-----------------------------------------------------------
# Dependencies to other components
#-----------------------------------------------------------
#

quicksec_sys_DEPENDENCIES_windelta = \
        +libaccelerator_none.a  \
        +libkernel.a            \
        +libfastpath_software.a \
	+libengine.a

#-----------------------------------------------------------
# Miscallenious files
#-----------------------------------------------------------
#
EXTRA_DIST = \
        install/winnt/quicksec.inf \
        install/winnt/qs-setup.inf 
