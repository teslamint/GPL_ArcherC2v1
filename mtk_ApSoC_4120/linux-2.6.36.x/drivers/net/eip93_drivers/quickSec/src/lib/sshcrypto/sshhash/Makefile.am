
# Added by filter_add_makefile_libextra_stuff
# To keep automake silent about public and private headers
# not been set when something is added to them

public_headers =
private_headers =

## Process this file with automake to produce Makefile.in

#
# lib/sshcrypto/sshash/Makefile.am
#
#  Copyright:
#          Copyright (c) 2002, 2003 SFNT Finland Oy.
#               All rights reserved
#

AUTOMAKE_OPTIONS = 1.0 foreign dist-zip no-dependencies
INCLUDES = -I$(srcdir)/.. -I$(top_srcdir)  -I$(top_srcdir)/lib/sshutil/sshcore  -I$(top_srcdir)/lib/sshutil/sshadt  -I$(top_srcdir)/lib/sshutil/ssheloop  -I$(top_srcdir)/lib/sshutil/sshstrutil  -I$(top_srcdir)/lib/sshutil/sshfsm  -I$(top_srcdir)/lib/sshutil/sshstream  -I$(top_srcdir)/lib/sshutil/sshsysutil  -I$(top_srcdir)/lib/sshutil/sshnet  -I$(top_srcdir)/lib/sshutil/sshmisc  -I$(top_srcdir)/lib/sshutil/sshaudit  -I$(top_srcdir)/lib/sshutil/sshpacketstream  -I$(top_srcdir)/lib/sshutil/sshtestutil  -I$(top_srcdir)/lib/sshutil  -I$(top_srcdir)/lib/zlib  -I$(top_srcdir)/lib/sshmath  -I$(top_srcdir)/lib/sshasn1  -I$(top_srcdir)/lib/sshcrypto/sshcipher 
LDADD = $(top_builddir)/lib/sshcrypto/sshcipher/libsshcipher.a $(top_builddir)/lib/sshasn1/libsshasn1.a $(top_builddir)/lib/sshmath/libsshmath.a $(top_builddir)/lib/zlib/libz.a $(top_builddir)/lib/sshutil/libsshutil.a 

WINCONF_OPTIONS = pirwin@safenet-inc.com

SUBDIRS =

noinst_LIBRARIES = libsshhash.a

libsshhash_a_SOURCES = \
	genhash.c 	\
	md5.c 		\
	md2.c 		\
	md4.c 		\
	sha.c 		\
	sha256.c 	\
        sha512.c        \
	octeon-hash.c \
	mscapi-hash.c 


























GRANDLIB_OBJECTS =  $(libsshhash_a_OBJECTS) $(libsshhash_a_LIBADD)

private_headers += 	\
	sshhash_i.h       \
	sha.h 		\
	sha256.h 	\
	sha512.h 	\
	md5.h 		\
	md4.h 		\
	md2.h 		






















libsshhash_a_LIBADD = @SSHHASH_CONF_OBJS@
libsshhash_a_LIBADD_windelta = -@SSHHASH_CONF_OBJS@
libsshhash_a_DEPENDENCIES = @SSHHASH_CONF_OBJS@

EXTRA_DIST = \
	md5_386.S 	





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
