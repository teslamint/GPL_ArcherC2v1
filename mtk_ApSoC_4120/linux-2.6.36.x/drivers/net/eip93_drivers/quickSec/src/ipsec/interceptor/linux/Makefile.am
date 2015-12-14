#
# src/ipsec/interceptor/linux/Makefile.am.raw
#
# Copyright:
#       Copyright (c) 2002-2004 SFNT Finland Oy.
#       All rights reserved
#

AUTOMAKE_OPTIONS = 1.0 foreign dist-zip no-dependencies
AUTODIST_OPTIONS = lnsrcs
WINCONF_OPTIONS = ignore maintainer=sponkanen@safenet-inc.com

DEFS = 	-DSSH_BUILD_IPSEC \
	-DINTERCEPTOR_PROVIDES_INTERFACE_INFORMATION \
	-DINTERCEPTOR_PROVIDES_IP_ROUTING \
	-DINTERCEPTOR_PROVIDES_VIRTUAL_ADAPTERS

CFLAGS = $(KERN_CFLAGS) $(SSH_INTERCEPTOR_CPPFLAGS)
LIBS   = 
CC     = $(KERN_CC) -o $@

LIBENGINE = \
 $(top_builddir)/ipsec/quicksec/@QS_ADDRSPACE@/libengine.a \
 $(top_builddir)/ipsec/quicksec/@QS_ADDRSPACE@/libfastpath-software.a \
 $(top_builddir)/ipsec/quicksec/@QS_ADDRSPACE@/libfastpath.a

LIBKERNEL = \
 $(top_builddir)/ipsec/quicksec/@QS_ADDRSPACE@/libaccelerator.a \
 $(top_builddir)/ipsec/quicksec/@QS_ADDRSPACE@/libkernel.a

LIBKERNEL_NONE = \
 $(top_builddir)/ipsec/quicksec/@QS_ADDRSPACE@/libaccelerator-none.a \
 $(top_builddir)/ipsec/quicksec/@QS_ADDRSPACE@/libkernel.a

QS_ENGINE_LIBS = $(LIBENGINE) $(LIBKERNEL) @QS_EXTRALIBS@


INCLUDES = \
	-I. -I$(srcdir) \
	-I$(top_builddir) -I$(top_srcdir) \
	-I$(top_builddir)/include \
	-I$(top_srcdir)/interceptor/include \
	-I$(top_srcdir)/interceptor/linux \
	-I$(top_srcdir)/interceptor/libkernelutil \
	-I$(top_srcdir)/interceptor/usermode \
	-I$(top_srcdir)/interceptor \
	-I$(top_srcdir)/ipsec \
	-I$(top_srcdir)/ipsec/hwaccel \
	$(INTERCEPTOR_TESTER_INCLUDES) 




CLEANFILES = $(cleanfiles) $(SSH_INTERCEPTOR_TARGETS) */*.o

DISTCLEANFILES=$(shell find -P . -name \*.[chS] -and -type l) \
		kbuild/Makefile kbuild/.*.cmd \
		./kbuild/Module.markers ./kbuild/*.ko \
		./kbuild/quicksec.mod.c \
		./kbuild/quicksec_usermode.mod.c \
		./kbuild/Module.symvers \
		./kbuild/modules.order

distclean: extra-dist-clean

.PHONY: extra-dist-clean

extra-dist-clean:
	rm -fr kbuild/.deps kbuild/.tmp_versions 

icept_kernel_ldflags = -nodefaultlibs -nostdlib -nostartfiles -Wl,-r

EXTRA_PROGRAMS =                \
        quicksec.o              \
        sshipsec_tester.o       \
	sshipsec_tester_ipm     \
	quicksec_usermode.o





quicksec_o_SOURCES = $(LINUX_IPSEC_COMMON_LNSRCS)

quicksec_o_LDADD =           \
        $(QS_ENGINE_LIBS)

quicksec_o_LDFLAGS = $(icept_kernel_ldflags)
quicksec_o_DEPENDENCIES = $(quicksec_o_LDADD)

sshipsec_tester_o_SOURCES =   \
        $(LINUX_IPSEC_COMMON_LNSRCS)  \
        $(INTERCEPTOR_TESTER_LNSRCS)

sshipsec_tester_o_LDADD = $(LIBKERNEL)
sshipsec_tester_o_LDFLAGS = $(icept_kernel_ldflags)
sshipsec_tester_o_DEPENDENCIES = $(sshipsec_tester_o_LDADD)

sshipsec_tester_ipm_SOURCES = $(INTERCEPTOR_TESTER_IPM_LNSRCS)
sshipsec_tester_ipm_LDFLAGS = @LIBS@
sshipsec_tester_ipm_LDADD = -L../../../lib -lssh













quicksec_usermode_o_SOURCES = \
	$(LINUX_IPSEC_COMMON_LNSRCS) \
	$(USERMODE_INTERCEPTOR_KERNEL_LNSRCS)

quicksec_usermode_o_LDADD = $(LIBKERNEL_NONE)
quicksec_usermode_o_LDFLAGS = $(icept_kernel_ldflags)
quicksec_usermode_o_DEPENDENCIES = $(quicksec_usermode_o_LDADD)

all-local: $(SSH_INTERCEPTOR_TARGETS) kbuild/Makefile
	${MAKE} -C kbuild

quicksec_usermode.ko: quicksec_usermode.o
	rm -f quicksec_usermode.ko
	cp quicksec_usermode.o quicksec_usermode.ko

quicksec.ko: quicksec.o
	rm -f quicksec.ko
	cp quicksec.o quicksec.ko

sshipsec_tester.ko: sshipsec_tester.o
	rm -f sshipsec_tester.ko
	cp sshipsec_tester.o sshipsec_tester.ko

LINUX_IPSEC_COMMON_LNSRCS=      \
        linux_debug.c           \
        linux_iface.c           \
        linux_ipm.c             \
        linux_kernel_alloc.c    \
        linux_main.c            \
        linux_misc.c            \
        linux_mutex.c           \
        linux_packet.c          \
        linux_procfs.c          \
        linux_route.c           \
        linux_timeout.c         \
        linux_ip_glue.c         \
        linux_hook_magic.c      \
	linux_octeon_intercept.c \
        linux_pcihw.c           \
        linux_virtual_adapter.c 







EXTRA_DIST =                             \
        README INSTALL                   \
	kbuild/Makefile.kbuild.fragment

kbuild_srcdir=$(shell (cd $(srcdir)/kbuild/; pwd))

kbuild/Makefile: $(kbuild_srcdir)/Makefile.kbuild.fragment
	install -d kbuild
	cd kbuild && $(MAKE) -f $^

includes:

tags:


include $(top_srcdir)/interceptor/libkernelutil/Makefile.fragment
include $(top_srcdir)/interceptor/usermode/Makefile.fragment
include $(top_srcdir)/ipsec/interceptor/tests/Makefile.fragment
linux_debug.c linux_iface.c linux_ipm.c linux_kernel_alloc.c linux_main.c linux_misc.c linux_mutex.c linux_packet.c linux_procfs.c linux_route.c linux_timeout.c linux_ip_glue.c linux_hook_magic.c linux_octeon_intercept.c linux_pcihw.c linux_virtual_adapter.c:
	-rm -f $@
	$(LN_S) $(top_srcdir)/interceptor/linux/$@ .

