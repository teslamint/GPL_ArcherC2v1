# Process this file with automake to produce Makefile.in

#
# src/ipsec/interceptor/bsd/Makefile.am.raw
#
# Copyright:
#       Copyright (c) 2002-2006 SFNT Finland Oy.
#       All rights reserved
#
# This file works closely with the configure.in.inc file in directory
# above. The interceptor source files need to be configured for each
# platform in the configure.  All source files must be listed in
# EXTRA_DIST to be included in distributions.
#
# Interceptor sources are linked against quicksec/kernel/libengine and
# quicksec/kernel/libkernel. The first provides quicksec engine and
# the latter kernel utilities.

AUTOMAKE_OPTIONS = 1.0 foreign dist-zip no-dependencies
WINCONF_OPTIONS  = ignore

DEFS = -DSSH_BUILD_IPSEC

VPATH = $(srcdir):$(srcdir)/..:$(top_srcdir)/interceptor/usermode:$(top_srcdir)/ipsec/interceptor/@SSH_INTERCEPTOR_MACHINE_DIR@/@SSH_INTERCEPTOR_MACHINE_SUBDIR@:$(top_srcdir)/ipsec/interceptor/tests

CLEANFILES =                            \
	$(cleanfiles) 			\
        $(SSH_INTERCEPTOR_TARGETS)      \
	*.o

LDFLAGS  = $(KERN_LDFLAGS)
LIBS     = $(KERN_LIBS)
CFLAGS   = $(INCLUDES) $(KERN_CFLAGS) $(CPPFLAGS)
CPPFLAGS = $(SSH_INTERCEPTOR_CPPFLAGS) \
	-DINTERCEPTOR_PROVIDES_INTERFACE_INFORMATION \
	-DINTERCEPTOR_PROVIDES_IP_ROUTING \
	-DINTERCEPTOR_PROVIDES_VIRTUAL_ADAPTERS

######################################################################
# NetBSD, FreeBSD and VxWorks

I386_OBJS= icept_attach_i386.o
PPC_OBJS = icept_attach_ppc.o

# Common BSD interceptor source files
BSD_OBJS =                              \
	icept_virtual_adapter.o		\
        icept_chardev_bsd.o             \
        icept_kernel_interceptor_bsd.o  \
        icept_kernel_main.o             \
        icept_kernel_mutex.o            \
        icept_kernel_stubs_bsd.o


# configure.in.inc sets SSH_INTERCEPTOR_NONETHER_OBJS and
# SSH_INTERCEPTOR_ETHER_OBJS to refer to these.

FREEBSD_NONETHER_OBJS=icept_subst_freebsd.o
FREEBSD_ETHER_OBJS=icept_subst_freebsd_mediahdr.o
NETBSD_NONETHER_OBJS=icept_subst_netbsd.o
NETBSD_ETHER_OBJS=icept_subst_netbsd_mediahdr.o


VXWORKS_OBJS=                           \
        icept_kernel_interceptor_bsd.o  \
        icept_kernel_stubs_vxworks.o    \
        icept_attach_vxworks.o          \
        icept_chardev_vxworks.o         \
        icept_route_vxworks.o           \
        icept_virtual_adapter_vxworks.o \
        vxworks_pcihw.o                 









######################################################################

noinst_PROGRAMS = $(SSH_INTERCEPTOR_TARGETS)

EXTRA_PROGRAMS = sshipsec_tester.o interceptor_tester

INCLUDES = -I. -I$(srcdir) \
           -I$(top_builddir) -I$(top_srcdir) \
           -I$(top_builddir)/include \
           -I$(top_srcdir)/ipsec/quicksec \
           -I$(top_srcdir)/interceptor/include \
           -I$(top_srcdir)/interceptor/libkernelutil \
           -I$(top_srcdir)/ipsec \
           -I$(top_srcdir)/ipsec/util \
	   -I$(top_srcdir)/ipsec/hwaccel \
	   -I$(top_srcdir)/ipsec/interceptor/@SSH_INTERCEPTOR_MACHINE_DIR@/@SSH_INTERCEPTOR_MACHINE_SUBDIR@

LIBENGINE = \
 $(top_builddir)/ipsec/quicksec/@QS_ADDRSPACE@/libengine.a \
 $(top_builddir)/ipsec/quicksec/@QS_ADDRSPACE@/libfastpath-@QS_FASTPATH@.a \
 $(top_builddir)/ipsec/quicksec/@QS_ADDRSPACE@/libaccelerator.a

LIBKERNEL = \
 $(top_builddir)/ipsec/quicksec/@QS_ADDRSPACE@/libaccelerator.a \
 $(top_builddir)/ipsec/quicksec/@QS_ADDRSPACE@/libkernel.a

QS_ENGINE_LIBS = $(LIBENGINE) $(LIBKERNEL) @QS_EXTRALIBS@

QS_PM_LIBS = \
 $(top_builddir)/ipsec/quicksec/@QS_ADDRSPACE@/libpmconf.a \
 $(top_builddir)/ipsec/quicksec/@QS_ADDRSPACE@/libappgw.a \
 $(top_builddir)/ipsec/quicksec/@QS_ADDRSPACE@/libipsecpm.a

SUFFIXES = .o .c

#
# Create QuickSec engine.
#
quicksec.o: $(SSH_INTERCEPTOR_OBJS) $(SSH_INTERCEPTOR_NONETHER_OBJS) \
	      $(QS_ENGINE_LIBS)
	rm -f tmpquicksec.o quicksec.o
	$(LD) $(LDFLAGS) -r -o tmpquicksec.o \
	      $(SSH_INTERCEPTOR_OBJS) $(SSH_INTERCEPTOR_NONETHER_OBJS) \
	      $(QS_ENGINE_LIBS)
	mv tmpquicksec.o quicksec.o


quicksecpm.o: $(SSH_INTERCEPTOR_OBJS) $(SSH_INTERCEPTOR_NONETHER_OBJS) \
	       $(QS_PM_LIBS) $(QS_ENGINE_LIBS)
	rm -f tmpquicksec.o quicksec.o
	$(LD) $(LDFLAGS) -r -o tmpquicksec.o \
		  $(SSH_INTERCEPTOR_OBJS) $(SSH_INTERCEPTOR_NONETHER_OBJS) \
		  $(QS_PM_LIBS) \
		  $(QS_ENGINE_LIBS) \
		  $(QS_PM_LIBS)
	mv tmpquicksec.o quicksec.o


#
# Create QuickSec engine for media level.
#
quicksec_ether.o: $(SSH_INTERCEPTOR_OBJS) $(SSH_INTERCEPTOR_ETHER_OBJS) \
	              $(QS_ENGINE_LIBS)
	rm -f tmpquicksec_ether.o quicksec_ether.o
	$(LD) $(LDFLAGS) -r -o tmpquicksec_ether.o \
	      $(SSH_INTERCEPTOR_OBJS) $(SSH_INTERCEPTOR_ETHER_OBJS) \
	      $(QS_ENGINE_LIBS)
	mv tmpquicksec_ether.o quicksec_ether.o

#
# Object files we need for user-mode forwarder and for other similar
# stripped-down interceptors.
#
NETBSD_USERMODE_FORWARDER_OBJS =        \
        $(BSD_OBJS)                     \
	usermodeforwarder.o		\
	icept_lkm_bsd.o

# Create IPSEC forwarder for usermode engine with IP binding
quicksec_usermode.o: $(NETBSD_USERMODE_FORWARDER_OBJS) $(SSH_INTERCEPTOR_NONETHER_OBJS) \
	$(LIBKERNEL)
	rm -f tmpipsec_usermode.o quicksec_usermode.o
	$(LD) $(LDFLAGS) -r -o tmpipsec_usermode.o \
	  $(NETBSD_USERMODE_FORWARDER_OBJS) $(SSH_INTERCEPTOR_NONETHER_OBJS) \
	  $(LIBKERNEL)
	mv tmpipsec_usermode.o quicksec_usermode.o

# Create IPSEC forwarder for usermode engine with ether binding
quicksec_usermode_ether.o: $(NETBSD_USERMODE_FORWARDER_OBJS) $(SSH_INTERCEPTOR_ETHER_OBJS) \
	$(LIBKERNEL)
	rm -f tmpipsec_usermode_ether.o quicksec_usermode_ether.o
	$(LD) $(LDFLAGS) -r -o tmpipsec_usermode_ether.o \
	  $(NETBSD_USERMODE_FORWARDER_OBJS) $(SSH_INTERCEPTOR_ETHER_OBJS) \
	  $(LIBKERNEL)
	mv tmpipsec_usermode_ether.o quicksec_usermode_ether.o

interceptor_tester: interceptor_tester_ipm.o ../../../lib/libssh.a
	$(CC) $(LDFLAGS) -o interceptor_tester interceptor_tester_ipm.o \
	  -L../../../lib -lssh

sshipsec_tester.o: interceptor_tester.o \
		   $(SSH_INTERCEPTOR_NONETHER_OBJS) $(LIBKERNEL)
	rm -f tmpipsec_tester.o sshipsec_tester.o
	$(LD) $(LDFLAGS) -r -o tmpipsec_tester.o interceptor_tester.o \
	      $(SSH_INTERCEPTOR_NONETHER_OBJS) $(LIBKERNEL)
	mv tmpipsec_tester.o sshipsec_tester.o

######################################################################












































######################################################################
EXTRA_DIST =                                                    \
        icept_attach.h                                          \
        icept_attach_i386.c                                     \
        icept_attach_ppc.c                                      \
        icept_chardev.h                                         \
        icept_chardev_bsd.c                                     \
        icept_internal.h                                        \
        icept_kernel_interceptor_bsd.c                          \
        icept_kernel_main.c                                     \
        icept_kernel_main.c                                     \
        icept_kernel_mutex.c                                    \
        icept_kernel_stubs_bsd.c                                \
        icept_lkm_bsd.c                                         \
	\
	\
        netbsd132/lib/libkern/libkern.h                         \
        netbsd132/hwaccel_async_sw.c                            \
        netbsd132/icept_subst_netbsd.c                          \
        netbsd132/icept_subst_netbsd_mediahdr.c                 \
        netbsd132/lib/libkern/libkern.h                         \
        netbsd133/icept_subst_netbsd.c                          \
        netbsd133/icept_subst_netbsd_mediahdr.c                 \
        netbsd140/lib/libkern/libkern.h                         \
        netbsd140/icept_subst_netbsd.c                          \
        netbsd150/lib/libkern/libkern.h                         \
        netbsd150/icept_subst_netbsd.c                          \
        netbsd150/icept_subst_netbsd_mediahdr.c                 \
        netbsd160/lib/libkern/libkern.h                         \
        netbsd160/icept_subst_netbsd.c                          \
        netbsd160/icept_subst_netbsd_mediahdr.c                 \
	netbsd200/icept_subst_netbsd.c                          \
        netbsd200/icept_subst_netbsd_mediahdr.c                 \
	netbsd200/lib/libkern/libkern.h                         \
	netbsd200/machine/pic.h		                        \
	netbsd200/sys/kernel.h                         		\
	netbsd-pfil/icept_subst_netbsd.c			\
	netbsd-pfil/machine/pic.h		                \
	\
        vxworks54/icept_virtual_adapter_vxworks.c               \
        vxworks54/icept_attach_vxworks.c                        \
        vxworks54/icept_route_vxworks.c                         \
        vxworks54/icept_chardev_vxworks.c                       \
        vxworks54/icept_kernel_stubs_vxworks.c                  \
        vxworks54/icept_mbuf_vxworks.h                          \
        vxworks54/icept_vxworks.h                               \
        vxworks54/icept_mutex_vxworks.h                         \
        vxworks54/usrTime.c                                     \
        vxworks54/ds12887Rtc.c                                  \
        vxworks54/Makefile.default                              \
        vxworks54/vxworks_pcihw.c                               \
	\
        platform_kernel_alloc.h                                 \
        platform_kernel_mutex.h


























includes:
	@for d in . $(SUBDIRS); \
        do \
	  if test "$$d" != "."; \
          then \
	    (cd $$d && $(MAKE) includes); \
          fi; \
        done

TAGS:
	etags `find $(SUBDIRS) -name '*.[ch]' -print`

print-vpath:
	@echo $(VPATH)
