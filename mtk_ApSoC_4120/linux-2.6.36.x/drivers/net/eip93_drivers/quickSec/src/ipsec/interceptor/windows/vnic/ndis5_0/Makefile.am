## Process this file with automake to produce Makefile.in
#
# src/ipsec/interceptor/windows/vnic/ndis5_0/Makefile.am.raw
#
# Author: Timo Tuunanen <tunskitj@ssh.com>
#
#  Copyright:
#          Copyright (c) 2002, 2003 SFNT Finland Oy.
#               All rights reserved
#

WINCONF_OPTIONS = maintainer=tunskitj@ssh.com dsw-name=qsvnic5

DEFS = -DSSH_BUILD_IPSEC

INCLUDES = \
        -I$(top_srcdir)/ipsec                   \
        -I$(top_srcdir)/ipsec/engine            \
        -I$(top_srcdir)/interceptor/include     \
        -I$(top_srcdir)/lib/sshutil             \
        -I$(top_srcdir)/lib/sshutil/sshcore	\
        -I$(top_srcdir)/lib/sshutil/sshnet	

lib_LIBRARIES_windelta = +qsvnic5.sys

VNIC_SRCDIR=$(top_srcdir)/interceptor/windows/vnic
VNIC50_SRCDIR=$(top_srcdir)/interceptor/windows/vnic/ndis5_0

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

qsvnic5_sys_PLATFORMS = win32 x64 win32vistandis5 x64vistandis5 \
        win32win7ndis5 x64win7ndis5 $(ce_platforms)

qsvnic5_sys_winconf = template=driver custom-object 

sshvnic_sys_common_sources =	\
        $(VNIC_SRCDIR)/sshvnic.c          \
        $(VNIC_SRCDIR)/sshvnic.h          \
        $(VNIC_SRCDIR)/sshvnic_def.h      \
        $(VNIC_SRCDIR)/sshvnicdbg.h

sshvnic_sys_ndis5_sources = \
        $(VNIC50_SRCDIR)/resource.h      \
        $(VNIC50_SRCDIR)/sshvnic5.rc     

qsvnic5_sys_SOURCES_windelta = \
	@+(sshvnic_sys_common_sources) \
	@+(sshvnic_sys_ndis5_sources)	

EXTRA_DIST = \
        $(sshvnic_sys_ndis5_sources) \
        netvnic.inf \ 
        qsvnic5.cat 
