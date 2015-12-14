#
# Makefile.am.raw
#
# Author: Markku Rossi <mtr@ssh.fi>
#
#  Copyright:
#          Copyright (c) 2002, 2003 SFNT Finland Oy.
#               All rights reserved.
#
# Automakefile for FSM tutorial.
#

AUTOMAKE_OPTIONS = 1.0 foreign dist-zip no-dependencies
WINCONF_OPTIONS = maintainer=mtr@ssh.fi

INCLUDES = -I$(top_srcdir)/lib/sshutil -I$(srcdir)/.. -I$(top_srcdir)  -I$(top_srcdir)/lib/sshutil/sshcore  -I$(top_srcdir)/lib/sshutil/sshadt  -I$(top_srcdir)/lib/sshutil/ssheloop  -I$(top_srcdir)/lib/sshutil/sshstrutil 
LDADD = $(top_builddir)/lib/sshutil/sshstrutil/libsshstrutil.a $(top_builddir)/lib/sshutil/ssheloop/libssheloop.a $(top_builddir)/lib/sshutil/sshadt/libsshadt.a $(top_builddir)/lib/sshutil/sshcore/libsshcore.a  $(top_builddir)/lib/sshutil/sshfsm/libsshfsm.a

EXTRA_PROGRAMS = hello hello2 yield producer-consumer timeout

includes:
