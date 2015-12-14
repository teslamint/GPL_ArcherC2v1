
# Added by filter_add_makefile_libextra_stuff
# To keep automake silent about public and private headers
# not been set when something is added to them

public_headers =
private_headers =

#
# ipsec/lib/sshisakmp/tests Makefile.am
#
#  Copyright:
#          Copyright (c) 2002, 2003 SFNT Finland Oy.
# All rights reserved
#

AUTOMAKE_OPTIONS = 1.0 foreign dist-zip no-dependencies
WINCONF_OPTIONS = maintainer=kivinen@ssh.fi

DEFS = -DSSH_BUILD_IPSEC

INCLUDES = -I$(srcdir)/.. -I$(top_srcdir)/ipsec -I$(top_srcdir) -I$(top_builddir)/include

LDADD = ../libsshisakmp.a $(top_builddir)/lib/libssh.a

EXTRA_DIST = certificates.config test.x509 top.m4

TESTS_LIGHT = t-da t-id 
TESTS = $(TESTS_LIGHT) t-isakmp
EXTRA_PROGRAMS = t-id t-da t-isakmp

EXTRA_PROGRAMS_windelta = \
	-t-isakmp

private_headers += \
	xauth_demo.h \
	test_policy.h



LDAP_SERVER = ryijy.sfnt.local
# LDAP_SERVER = 2001:670:83:109:2d0:b7ff:fe6a:d95c
LDAP_USERNAME = cn=root, o=example, c=FI
LDAP_PASSWORD = kukkuuRESET
X509_CREATE = $(top_builddir)/apps/certutils/ssh-certmake
LDAP_ADD = $(top_builddir)/apps/ldaputils/ssh-ldapadd
CRL_TTL=00:30
HOSTNAME=`uname -n`

CLEANFILES = \
	master.certconf






t_da_SOURCES = t-da.c
t_da_DEPENDENCIES = $(LDADD)

t_id_SOURCES = t-id.c \
	xauth_demo.c \
	cert_policy.c \
	test_policy.c


t_id_DEPENDENCIES = $(LDADD)

t_isakmp_SOURCES = t-isakmp.c \
	xauth_demo.c \
	cert_policy.c \
	test_policy.c


t_isakmp_DEPENDENCIES = $(LDADD) \
	master.certconf







t-isakmp-pre: crl

master.certconf: $(srcdir)/certificates.config
	ln -s $(srcdir)/certificates.config master.certconf

ssh-test-ca.bin: $(srcdir)/test.x509 $(X509_CREATE) $(LDAP_ADD)
	(cd $(srcdir); $(M4) -DIP_NUMBER="127.0.0.1" -DCRL_TTL=$(CRL_TTL) \
		< test.x509 ) | \
		$(X509_CREATE) -
	rm -f ssh-test-ca.bin ssh-test-ca.prv ssh-test-ca.crl
	rm -f ssh-test-dsa.bin ssh-test-dsa.prv
	rm -f ssh-test-rsa.bin ssh-test-rsa.prv
	ln -s ssh-test-ca-$(HOSTNAME).bin ssh-test-ca.bin
	ln -s ssh-test-ca-$(HOSTNAME).prv ssh-test-ca.prv
	ln -s ssh-test-ca-$(HOSTNAME).crl ssh-test-ca.crl
	ln -s ssh-test-rsa-$(HOSTNAME).bin ssh-test-rsa.bin
	ln -s ssh-test-rsa-$(HOSTNAME).prv ssh-test-rsa.prv
	ln -s ssh-test-dsa-$(HOSTNAME).bin ssh-test-dsa.bin
	ln -s ssh-test-dsa-$(HOSTNAME).prv ssh-test-dsa.prv
	$(LDAP_ADD) -u "$(LDAP_USERNAME)" -P "$(LDAP_PASSWORD)" \
		-s $(LDAP_SERVER) -r -b \
		"CN=Test ca-$(HOSTNAME), O=Example, C=FI" \
		"cn=Test ca-$(HOSTNAME)" \
		"certificateRevocationList;binary"=:b:ssh-test-ca.crl \
		objectclass=cRLDistributionPoint \
		"userCertificate;binary"=:b:ssh-test-ca.bin \
		objectclass=strongAuthenticationUser

crl:	force-crl-create-time crl-create-time

force-crl-create-time:
	rm -f crl-create-time







check-crl: force-crl-test-time crl-create-time

force-crl-test-time:
	rm -f crl-test-time

crl-test-time:
	touch crl-test-time

crl-create-time: crl-test-time $(X509_CREATE) $(LDAP_ADD)
	(cd $(srcdir); $(M4) -DNO_KEYS=1 -DNO_CAS=1 \
		-DIP_NUMBER="127.0.0.1" -DCRL_TTL=$(CRL_TTL) \
		< test.x509 ) | \
		$(X509_CREATE) -
	rm -f ssh-test-ca.bin ssh-test-ca.prv ssh-test-ca.crl
	rm -f ssh-test-dsa.bin ssh-test-dsa.prv
	rm -f ssh-test-rsa.bin ssh-test-rsa.prv
	ln -s ssh-test-ca-$(HOSTNAME).bin ssh-test-ca.bin
	ln -s ssh-test-ca-$(HOSTNAME).prv ssh-test-ca.prv
	ln -s ssh-test-ca-$(HOSTNAME).crl ssh-test-ca.crl
	ln -s ssh-test-rsa-$(HOSTNAME).bin ssh-test-rsa.bin
	ln -s ssh-test-rsa-$(HOSTNAME).prv ssh-test-rsa.prv
	ln -s ssh-test-dsa-$(HOSTNAME).bin ssh-test-dsa.bin
	ln -s ssh-test-dsa-$(HOSTNAME).prv ssh-test-dsa.prv
	$(LDAP_ADD) -u "$(LDAP_USERNAME)" -P "$(LDAP_PASSWORD)" \
		-s $(LDAP_SERVER) -r -b \
		"CN=Test ca-$(HOSTNAME), O=Example, C=FI" \
		"cn=Test ca-$(HOSTNAME)" \
		"certificateRevocationList;binary"=:b:ssh-test-ca.crl \
		objectclass=cRLDistributionPoint \
		"userCertificate;binary"=:b:ssh-test-ca.bin \
		objectclass=strongAuthenticationUser
	TZ=GMT-00:00 touch -t `TZ=GMT-$(CRL_TTL) date +%Y%m%d%H%M` crl-create-time

revoke: $(X509_CREATE) $(LDAP_ADD)
	(cd $(srcdir); $(M4) -DNO_KEYS=1  -DNO_CAS=1 -DREVOKE_CERTS=1 \
		-DIP_NUMBER="127.0.0.1" -DCRL_TTL=$(CRL_TTL) \
		< test.x509 ) | \
		$(X509_CREATE) -
	rm -f ssh-test-ca.bin ssh-test-ca.prv ssh-test-ca.crl
	rm -f ssh-test-dsa.bin ssh-test-dsa.prv
	rm -f ssh-test-rsa.bin ssh-test-rsa.prv
	ln -s ssh-test-ca-$(HOSTNAME).bin ssh-test-ca.bin
	ln -s ssh-test-ca-$(HOSTNAME).prv ssh-test-ca.prv
	ln -s ssh-test-ca-$(HOSTNAME).crl ssh-test-ca.crl
	ln -s ssh-test-rsa-$(HOSTNAME).bin ssh-test-rsa.bin
	ln -s ssh-test-rsa-$(HOSTNAME).prv ssh-test-rsa.prv
	ln -s ssh-test-dsa-$(HOSTNAME).bin ssh-test-dsa.bin
	ln -s ssh-test-dsa-$(HOSTNAME).prv ssh-test-dsa.prv
	$(LDAP_ADD) -u "$(LDAP_USERNAME)" -P "$(LDAP_PASSWORD)" \
		-s $(LDAP_SERVER) -r -b \
		"CN=Test ca-$(HOSTNAME), O=Example, C=FI" \
		"cn=Test ca-$(HOSTNAME)" \
		"certificateRevocationList;binary"=:b:ssh-test-ca.crl \
		objectclass=cRLDistributionPoint \
		"userCertificate;binary"=:b:ssh-test-ca.bin \
		objectclass=strongAuthenticationUser

net-gen: $(X509_CREATE)
	(cd $(srcdir); $(M4) -DCRL_TTL=$(CRL_TTL) \
		< test-net.x509 ) | \
		$(X509_CREATE) -

net-crl: $(X509_CREATE) $(LDAP_ADD)
	(cd $(srcdir); $(M4) -DNO_KEYS=1 -DNO_CAS=1 -DCRL_TTL=$(CRL_TTL) \
		< test-net.x509 ) | \
		$(X509_CREATE) -
	$(srcdir)/upload-crls.sh $(LDAP_SERVER)

net-revoke: $(X509_CREATE) $(LDAP_ADD)
	(cd $(srcdir); $(M4) -DNO_KEYS=1 -DNO_CAS=1 \
		-DCRL_TTL=$(CRL_TTL) -DREVOKE_CERTS=1 \
		< test-net.x509 ) | \
		$(X509_CREATE) -
	$(srcdir)/upload-crls.sh $(LDAP_SERVER)

$(X509_CREATE):
	(cd $(top_builddir)/apps/certutils && make ssh-certmake)

$(LDAP_ADD):
	(cd $(top_builddir)/apps/ldaputils && make ssh-ldapadd)

include $(top_srcdir)/Makefile.libextra

# EOF
