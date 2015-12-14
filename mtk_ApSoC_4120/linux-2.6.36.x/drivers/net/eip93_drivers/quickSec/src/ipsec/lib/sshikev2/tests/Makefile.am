
# Added by filter_add_makefile_libextra_stuff
# To keep automake silent about public and private headers
# not been set when something is added to them

public_headers =
private_headers =

#
# ipsec/lib/sshikev2/tests/Makefile.am
#
#  Copyright:
#          Copyright (c) 2004, 2005 SFNT Finland Oy.
# All rights reserved
#

AUTOMAKE_OPTIONS = 1.0 foreign dist-zip no-dependencies
WINCONF_OPTIONS = maintainer=kivinen@safenet-inc.com

DEFS = -DSSH_BUILD_IPSEC



X509_CREATE = $(top_builddir)/apps/certutils/ssh-certmake

INCLUDES = -I$(srcdir)/.. -I$(top_srcdir)/ipsec \
	-I$(top_srcdir) -I$(top_builddir)/include -I$(top_srcdir)/ipsec/lib/sshisakmp 

LDADD =../libsshikev2.a \
	$(top_builddir)/ipsec/lib/sshisakmp/libsshisakmp.a  \
	-L$(top_builddir)/lib -lssh


TESTS_LIGHT = \
	t-ikev2 \
	t-fb-util \
        t-multiauth \
        t-ts-util




TESTS = $(TESTS_LIGHT)

noinst_MANS = t-ikev2.1
private_headers += dummy-if.h pad-dummy.h sad-dummy.h spd-dummy.h pm_ike_sad.h

EXTRA_DIST = $(noinst_MANS) test.x509 certificates.config

EXTRA_PROGRAMS = $(TESTS) ikev2-perftool

t_ts_util_SOURCES = t-ts-util.c pm_ike_tsutils.c

ikev2_perftool_SOURCES = \
	pm_ike_tsutils.c dummy-if.c sad-dummy.c pad-dummy.c \
	spd-dummy.c pm_ike_confutils.c pm_ike_sautils.c \
	pad-eap-dummy.c \
	ikev2-perftool.c





ikev2_perftool_DEPENDENCIES = test-ca-1.ca ../libsshikev2.a	
ikev2_perftool_DEPENDENCIES_windelta = -test-ca-1.ca +ssh-certmake


t_fb_util_SOURCES = t-fb-util.c \
	pm_ike_confutils.c pm_ike_sautils.c pm_ike_tsutils.c


t_ikev2_SOURCES = \
	dummy-if.c sad-dummy.c pad-dummy.c spd-dummy.c \
	pm_ike_confutils.c pm_ike_sautils.c pm_ike_tsutils.c \
	pad-eap-dummy.c \
	t-ikev2.c





t_multiauth_SOURCES = \
	dummy-if.c sad-dummy.c pad-dummy.c spd-dummy.c \
	pm_ike_confutils.c pm_ike_sautils.c pm_ike_tsutils.c \
	pad-eap-dummy.c \
	t-multiauth.c








# This is not completely correct, as now t-ikev2 is rebuild when
# test.x509 changes, and that is not neccessary.
t_ikev2_DEPENDENCIES = test-ca-1.ca ../libsshikev2.a
t_ikev2_DEPENDENCIES_windelta = -test-ca-1.ca +ssh-certmake


t_multiauth_DEPENDENCIES = test-ca-1.ca ../libsshikev2.a
t_multiauth_DEPENDENCIES_windelta = -test-ca-1.ca +ssh-certmake

test-ca-1.ca: $(srcdir)/test.x509 $(X509_CREATE)
	(cd $(srcdir); $(M4) < test.x509 ) | \
		$(X509_CREATE) -

WINCONF_X509_CREATE = $(top_builddir)/apps/certutils/$$(OutDir)/ssh-certmake
WINCONF_CUSTOM_BUILD_0_INPUT = test.x509
WINCONF_CUSTOM_BUILD_0_COMMAND = $(WINCONF_X509_CREATE) _INPUT_
WINCONF_CUSTOM_BUILD_0_OUTPUT = test-ca-1.ca
WINCONF_CUSTOM_BUILD_0_PLATFORMS = win32 x64 win32vista x64vista win32win7 x64win7 

$(X509_CREATE):
	(cd $(top_builddir)/apps/certutils && make ssh-certmake)



include $(top_srcdir)/Makefile.libextra

# EOF
