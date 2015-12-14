
# Added by filter_add_makefile_libextra_stuff
# To keep automake silent about public and private headers
# not been set when something is added to them

public_headers =
private_headers =

## Process this file with automake to produce Makefile.in

#
# lib/sshmath Makefile.am
#
# Author: Tatu Ylonen <ylo@ssh.fi>
#
#  Copyright:
#          Copyright (c) 2002, 2003 SFNT Finland Oy.
#                    All rights reserved
#

AUTOMAKE_OPTIONS = 1.0 foreign dist-zip no-dependencies
INCLUDES = -I$(top_srcdir)  -I$(top_srcdir)/lib/sshutil/sshcore  -I$(top_srcdir)/lib/sshutil/sshadt  -I$(top_srcdir)/lib/sshutil/ssheloop  -I$(top_srcdir)/lib/sshutil/sshstrutil  -I$(top_srcdir)/lib/sshutil/sshfsm  -I$(top_srcdir)/lib/sshutil/sshstream  -I$(top_srcdir)/lib/sshutil/sshsysutil  -I$(top_srcdir)/lib/sshutil/sshnet  -I$(top_srcdir)/lib/sshutil/sshmisc  -I$(top_srcdir)/lib/sshutil/sshaudit  -I$(top_srcdir)/lib/sshutil/sshpacketstream  -I$(top_srcdir)/lib/sshutil/sshtestutil  -I$(top_srcdir)/lib/sshutil  -I$(top_srcdir)/lib/zlib  




LDADD = $(top_builddir)/lib/zlib/libz.a $(top_builddir)/lib/sshutil/libsshutil.a 

WINCONF_OPTIONS = maintainer=pirwin@safenet-inc.com

SUBDIRS = tests

noinst_LIBRARIES = libsshmath.a

libsshmath_a_SOURCES =	 \
sshmp-init.c		 \
sshmp-tests.c		 \
sshmp-kernel.c		 \
sshmp-xuint.c            \
sshmp-integer-core.c     \
sshmp-integer-misc.c     \
sshmp-convabs.c          \
sshmp-arithmetic.c       \
sshmp-arithmetic-extra.c \
sshmp-2adic.c            \
sshmp-montgomery.c       \
sshmp-intmod.c           \
sshmp-powm.c             \
sshmp-ecp.c              \
sshmp-naf.c              \
sshsieve.c               








































GRANDLIB_OBJECTS =  $(libsshmath_a_OBJECTS) $(libsshmath_a_LIBADD)

math_headers =	\
sshmp.h			\
sshmp-types.h           \
sshmp-kernel.h          \
sshmp-convabs.h         \
sshmp-integer.h		\
sshmp-xuint.h           \
sshmp-arithmetic.h      \
sshmp-2adic.h           \
sshmp-montgomery.h      \
sshmp-intmod.h          \
sshmp-powm.h            \
sshmp-ecp.h             \
sshmp-naf.h             \
sshsieve.h              









































public_headers += \
		  $(math_headers)



private_headers += 




libsshmath_a_LIBADD = @MATH_CONF_OBJS@
libsshmath_a_LIBADD_windelta = -@MATH_CONF_OBJS@
libsshmath_a_DEPENDENCIES = @MATH_CONF_OBJS@

EXTRA_DIST = \
	sshmp-asmopt_i386-att.S 





SUFFIXES = .S .s
CLEANFILES = tmp-*.s











.s.o:
	$(CC) -c $(CFLAGS) $(SFLAGS) $<

.S.o:
	$(CPP) $(CPPFLAGS) $(INCLUDES) $(DEFS) $< | grep -v '^#' >tmp-$*.s
	$(CC) $(CFLAGS) $(SFLAGS) -c tmp-$*.s
	mv tmp-$*.o $@
	rm -f tmp-$*.s


include $(top_srcdir)/Makefile.libextra
include $(top_srcdir)/Makefile.grandlib_provider
