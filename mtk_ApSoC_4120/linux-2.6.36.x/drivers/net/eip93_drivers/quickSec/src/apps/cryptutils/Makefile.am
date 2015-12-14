## Process this file with automake to produce Makefile.in

#
# ssh2 Makefile.am
#
# Author: Timo J. Rinne <tri@ssh.fi>
#
#  Copyright:
#          Copyright (c) 2002, 2003 SFNT Finland Oy.
#                    All rights reserved
#

AUTOMAKE_OPTIONS = 1.0 foreign dist-zip no-dependencies
WINCONF_OPTIONS = maintainer=tmo@ssh.fi

bin_PROGRAMS = \
	ssh-hash \
	ssh-encrypt




man_MANS = \
	ssh-hash.1 \
	ssh-encrypt.1




INCLUDES = -I. -I$(srcdir) \
	   -I$(top_builddir) -I$(top_srcdir) \
	   -I$(top_builddir)/include







LDADD = -L../../lib -lssh


EXTRA_DIST = \
	ssh-encrypt.1 \
	ssh-hash.1

DEPENDENCIES = 	$(top_builddir)/lib/sshcrypto/libsshcrypto.a 	\
		$(top_builddir)/lib/sshutil/libsshutil.a 	\
		$(top_builddir)/lib/sshmath/libsshmath.a


ssh_hash_SOURCES = ssh-hash.c
ssh_hash_DEPENDENCIES = $(DEPENDENCIES)






ssh_encrypt_SOURCES = ssh-encrypt.c
ssh_encrypt_DEPENDENCIES = $(DEPENDENCIES)
ssh_encrypt_PLATFORMS = win32 x64 win32vista x64vista win32win7 x64win7

includes:
