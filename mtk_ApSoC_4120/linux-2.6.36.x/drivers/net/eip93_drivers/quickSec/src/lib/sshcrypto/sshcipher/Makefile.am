
# Added by filter_add_makefile_libextra_stuff
# To keep automake silent about public and private headers
# not been set when something is added to them

public_headers =
private_headers =

## Process this file with automake to produce Makefile.in

#
# lib/sshcrypt/sshcipher/Makefile.am
#
#  Copyright:
#          Copyright (c) 2002, 2003 SFNT Finland Oy.
#           All rights reserved
#

AUTOMAKE_OPTIONS = 1.0 foreign dist-zip no-dependencies
WINCONF_OPTIONS = maintainer=pirwin@safenet-inc.com

INCLUDES = -I$(srcdir)/..  -I$(top_srcdir)  -I$(top_srcdir)/lib/sshutil/sshcore  -I$(top_srcdir)/lib/sshutil/sshadt  -I$(top_srcdir)/lib/sshutil/ssheloop  -I$(top_srcdir)/lib/sshutil/sshstrutil  -I$(top_srcdir)/lib/sshutil/sshfsm  -I$(top_srcdir)/lib/sshutil/sshstream  -I$(top_srcdir)/lib/sshutil/sshsysutil  -I$(top_srcdir)/lib/sshutil/sshnet  -I$(top_srcdir)/lib/sshutil/sshmisc  -I$(top_srcdir)/lib/sshutil/sshaudit  -I$(top_srcdir)/lib/sshutil/sshpacketstream  -I$(top_srcdir)/lib/sshutil/sshtestutil  -I$(top_srcdir)/lib/sshutil  -I$(top_srcdir)/lib/zlib  -I$(top_srcdir)/lib/sshmath  -I$(top_srcdir)/lib/sshasn1 
LDADD = $(top_builddir)/lib/sshasn1/libsshasn1.a $(top_builddir)/lib/sshmath/libsshmath.a $(top_builddir)/lib/zlib/libz.a $(top_builddir)/lib/sshutil/libsshutil.a 

SUBDIRS =

noinst_LIBRARIES = libsshcipher.a

libsshcipher_a_SOURCES = \
  nociph.c  \
  des.c \
  blowfish.c \
  arcfour.c \
  rc2.c \
  rijndael.c \
  mode-gcm.c \
	octeon-cipher.c \
	mscapi-cipher.c \
  genciph.c
























































GRANDLIB_OBJECTS =  $(libsshcipher_a_OBJECTS) $(libsshcipher_a_LIBADD)

private_headers += \
	sshcipher_i.h	\
  nociph.h      \
  des.h 	\
  blowfish.h 	\
  arcfour.h 	\
  rc2.h 	\
  rijndael.h 	\
  mode-gcm.h \
  octeon-cipher.h \
  sshrotate.h





















































libsshcipher_a_LIBADD = @SSHCIPHER_CONF_OBJS@
libsshcipher_a_LIBADD_windelta = -@SSHCIPHER_CONF_OBJS@
libsshcipher_a_DEPENDENCIES = @SSHCIPHER_CONF_OBJS@

EXTRA_DIST = \
  des386.S \
  blowfish386.S \
  arcfour_386.S 












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
