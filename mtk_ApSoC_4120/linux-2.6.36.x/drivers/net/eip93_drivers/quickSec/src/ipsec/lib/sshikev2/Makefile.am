
# Added by filter_add_makefile_libextra_stuff
# To keep automake silent about public and private headers
# not been set when something is added to them

public_headers =
private_headers =

#
# ipsec/lib/sshikev2 Makefile.am
#
# Copyright:
#       Copyright (c) 2004, 2005 SFNT Finland Oy.
# 	All rights reserved
#

AUTOMAKE_OPTIONS = 1.0 foreign dist-zip no-dependencies
DEFS = -DSSH_BUILD_IPSEC

# This library does not depend on any other ipsec/lib library, thus
# autodist_ipsec_lib stuff is not needed
INCLUDES = \
	-I$(top_srcdir) 			\
	-I$(top_builddir)/include 		\
	-I$(top_srcdir)/ipsec 			\
	-I$(top_srcdir)/ipsec/lib/sshisakmp 	



WINCONF_OPTIONS = maintainer=kivinen@safenet-inc.com,tmononen@safenet-inc.com

noinst_LIBRARIES = libsshikev2.a

libsshikev2_a_SOURCES = \
	ikev2-auth-init-in.c \
	ikev2-auth-init-out.c \
	ikev2-auth-resp-in.c \
	ikev2-auth-resp-out.c \
	ikev2-child-init-in.c \
	ikev2-child-init-out.c \
	ikev2-child-resp-in.c \
	ikev2-child-resp-out.c \
	ikev2-confutil.c \
	ikev2-common-info.c \
	ikev2-crypto.c \
	ikev2-decode.c \
	ikev2-eap-auth.c \
	ikev2-mobike.c \
	ikev2-encode.c \
	ikev2-groups.c \
	ikev2-init.c \
	ikev2-ike-rekey-init-in.c \
	ikev2-ike-rekey-init-out.c \
	ikev2-ike-rekey-resp-in.c \
	ikev2-ike-rekey-resp-out.c \
	ikev2-info-init-in.c \
	ikev2-info-init-out.c \
	ikev2-info-resp-in.c \
	ikev2-info-resp-out.c \
	ikev2-init-ike-sa.c \
	ikev2-init-info-sa.c \
	ikev2-init-ipsec-sa.c \
	ikev2-ke-error-out.c \
	ikev2-multiple-auth.c \
	ikev2-auth2-init-in.c \
	ikev2-auth2-init-out.c \
	ikev2-auth2-resp-in.c \
	ikev2-auth2-resp-out.c \
	ikev2-nat-t.c \
	ikev2-packet-decode.c \
	ikev2-packet-encode.c \
	ikev2-pk-auth.c \
	ikev2-prfplus.c \
	ikev2-state.c	\
	ikev2-window.c \
	ikev2-send.c \
	ikev2-shared-key-auth.c \
	ikev2-recv.c \
	ikev2-rekey-ike.c \
	ikev2-render-ike-spi.c \
	ikev2-render-payload.c \
	ikev2-request-cookie-out.c \
	ikev2-sa-init-init-in.c \
	ikev2-sa-init-init-out.c \
	ikev2-sa-init-resp-in.c \
	ikev2-sa-init-resp-out.c \
	ikev2-sa-init-error.c \
	ikev2-sautil.c \
	ikev2-state-common.c \
	ikev2-string-attribute-type.c \
	ikev2-string-auth-method.c \
	ikev2-string-cert-encoding.c \
	ikev2-string-id.c \
	ikev2-string-notify.c \
	ikev2-string-protocol.c \
	ikev2-string-transform.c \
	ikev2-string-payload.c \
	ikev2-tables.c \
	ikev2-tsutil.c \
	ikev2-linearize.c \
	ikev2-fb-init.c \
	ikev2-fb-util.c \
	ikev2-fb-conv.c \
	ikev2-fb-ts-conv.c \
	ikev2-fb-id-conv.c \
	ikev2-fb-sa-conv.c \
	ikev2-fb-init-info.c \
	ikev2-fb-init-p1.c \
	ikev2-fb-init-qm.c \
	ikev2-fb-policy-p1.c \
	ikev2-fb-policy-p2.c \
	ikev2-fb-policy-qm.c \
	ikev2-fb-policy-certs.c \
	ikev2-fb-cfgmode.c \
	ikev2-fb-cfgmode-conv.c \
	ikev2-fb-nat-t.c \
	ikev2-fb-xauth.c 















EXTRA_DIST =


SUBDIRS = tests


public_headers += \
	sshsad.h \
	sshikev2-initiator.h \
	sshikev2-exchange.h \
	sshikev2-sad.h \
	sshikev2-pad.h \
	sshikev2-spd.h \
	sshikev2-payloads.h \
	sshikev2-util.h	\
	sshikev2-fallback.h



private_headers += \
	ikev2-internal.h \
	ikev2-fb.h \
	ikev2-fb-st.h



GRANDLIB_OBJECTS = $(libsshikev2_a_OBJECTS) $(libsshikev2_a_LIBADD)

include $(top_srcdir)/Makefile.grandlib_provider
include $(top_srcdir)/Makefile.libextra

SUFFIXES = .dot .ps .pdf

.dot.ps:
	dot -Tps $< | $(top_srcdir)/scripts/change-to-a3.pl -c > $*.ps

.dot.pdf:
	sed 's/page=\".*\";/page="20,45";/g;s/orientation=land;//g;' $< | \
	dot -Tps | \
	$(top_srcdir)/scripts/change-to-a3.pl -s "1440 3240" | \
	ps2pdf - $*.pdf


ike-state-init.dot: $(libsshikev2_a_SOURCES) $(srcdir)/fsmdoc-settings.pl
	-rm -f ike-state-init.dot
	$(top_srcdir)/scripts/fsmdoc.pl \
		--settings $(srcdir)/fsmdoc-settings.pl \
		$(srcdir)/ikev2-init-ike-sa.c \
		$(srcdir)/ikev2-ke-error-out.c \
		$(srcdir)/ikev2-request-cookie-out.c \
		$(srcdir)/ikev2-sa-init-init-in.c \
		$(srcdir)/ikev2-sa-init-init-out.c \
		$(srcdir)/ikev2-sa-init-resp-in.c \
		$(srcdir)/ikev2-sa-init-resp-out.c \
		$(srcdir)/ikev2-sa-init-error.c \
		$(srcdir)/ikev2-state.c > ike-state-init.dot

ike-state-auth.dot: $(libsshikev2_a_SOURCES) $(srcdir)/fsmdoc-settings.pl
	-rm -f ike-state-auth.dot
	$(top_srcdir)/scripts/fsmdoc.pl \
		--settings $(srcdir)/fsmdoc-settings.pl \
		$(srcdir)/ikev2-auth-init-in.c \
		$(srcdir)/ikev2-auth-init-out.c \
		$(srcdir)/ikev2-auth-resp-in.c \
		$(srcdir)/ikev2-auth-resp-out.c \
		$(srcdir)/ikev2-auth2-init-in.c \
		$(srcdir)/ikev2-auth2-init-out.c \
		$(srcdir)/ikev2-auth2-resp-in.c \
		$(srcdir)/ikev2-auth2-resp-out.c \
		$(srcdir)/ikev2-state.c > ike-state-auth.dot

ike-state-child.dot: $(libsshikev2_a_SOURCES) $(srcdir)/fsmdoc-settings.pl
	-rm -f ike-state-child.dot
	$(top_srcdir)/scripts/fsmdoc.pl \
		--settings $(srcdir)/fsmdoc-settings.pl \
		$(srcdir)/ikev2-init-ike-sa.c \
		$(srcdir)/ikev2-child-init-in.c \
		$(srcdir)/ikev2-child-init-out.c \
		$(srcdir)/ikev2-child-resp-in.c \
		$(srcdir)/ikev2-child-resp-out.c \
		$(srcdir)/ikev2-state.c > ike-state-child.dot

ike-state-rekey.dot: $(libsshikev2_a_SOURCES) $(srcdir)/fsmdoc-settings.pl
	-rm -f ike-state-rekey.dot
	$(top_srcdir)/scripts/fsmdoc.pl \
		--settings $(srcdir)/fsmdoc-settings.pl \
		$(srcdir)/ikev2-init-ike-sa.c \
		$(srcdir)/ikev2-ike-rekey-init-in.c \
		$(srcdir)/ikev2-ike-rekey-init-out.c \
		$(srcdir)/ikev2-ike-rekey-resp-in.c \
		$(srcdir)/ikev2-ike-rekey-resp-out.c \
		$(srcdir)/ikev2-state.c > ike-state-rekey.dot

ike-state-info.dot: $(libsshikev2_a_SOURCES) $(srcdir)/fsmdoc-settings.pl
	-rm -f ike-state-info.dot
	$(top_srcdir)/scripts/fsmdoc.pl \
		--settings $(srcdir)/fsmdoc-settings.pl \
		$(srcdir)/ikev2-init-ike-sa.c \
		$(srcdir)/ikev2-info-init-in.c \
		$(srcdir)/ikev2-info-init-out.c \
		$(srcdir)/ikev2-info-resp-in.c \
		$(srcdir)/ikev2-info-resp-out.c \
		$(srcdir)/ikev2-state.c > ike-state-info.dot


ike-state-all.dot: $(libsshikev2_a_SOURCES) \
	$(srcdir)/fsmdoc-settings.pl $(srcdir)/fsmdoc-settings-all.pl
	-rm -f ike-state-all.dot
	$(top_srcdir)/scripts/fsmdoc.pl \
		--settings $(srcdir)/fsmdoc-settings.pl \
		--settings $(srcdir)/fsmdoc-settings-all.pl \
		$(srcdir)/ikev2-auth-init-in.c \
		$(srcdir)/ikev2-auth-init-out.c \
		$(srcdir)/ikev2-auth-resp-in.c \
		$(srcdir)/ikev2-auth-resp-out.c \
		$(srcdir)/ikev2-auth2-init-in.c \
		$(srcdir)/ikev2-auth2-init-out.c \
		$(srcdir)/ikev2-auth2-resp-in.c \
		$(srcdir)/ikev2-auth2-resp-out.c \
		$(srcdir)/ikev2-child-init-in.c \
		$(srcdir)/ikev2-child-init-out.c \
		$(srcdir)/ikev2-child-resp-in.c \
		$(srcdir)/ikev2-child-resp-out.c \
		$(srcdir)/ikev2-common-info.c \
		$(srcdir)/ikev2-confutil.c \
		$(srcdir)/ikev2-crypto.c \
		$(srcdir)/ikev2-decode.c \
		$(srcdir)/ikev2-eap-auth.c \
		$(srcdir)/ikev2-encode.c \
		$(srcdir)/ikev2-groups.c \
		$(srcdir)/ikev2-ike-rekey-init-in.c \
		$(srcdir)/ikev2-ike-rekey-init-out.c \
		$(srcdir)/ikev2-ike-rekey-resp-in.c \
		$(srcdir)/ikev2-ike-rekey-resp-out.c \
		$(srcdir)/ikev2-info-init-in.c \
		$(srcdir)/ikev2-info-init-out.c \
		$(srcdir)/ikev2-info-resp-in.c \
		$(srcdir)/ikev2-info-resp-out.c \
		$(srcdir)/ikev2-init-ike-sa.c \
		$(srcdir)/ikev2-init-info-sa.c \
		$(srcdir)/ikev2-init-ipsec-sa.c \
		$(srcdir)/ikev2-init.c \
		$(srcdir)/ikev2-ke-error-out.c \
		$(srcdir)/ikev2-linearize.c \
		$(srcdir)/ikev2-mobike.c \
		$(srcdir)/ikev2-multiple-auth.c \
		$(srcdir)/ikev2-nat-t.c \
		$(srcdir)/ikev2-packet-decode.c \
		$(srcdir)/ikev2-packet-encode.c \
		$(srcdir)/ikev2-pk-auth.c \
		$(srcdir)/ikev2-prfplus.c \
		$(srcdir)/ikev2-recv.c \
		$(srcdir)/ikev2-rekey-ike.c \
		$(srcdir)/ikev2-render-ike-spi.c \
		$(srcdir)/ikev2-render-payload.c \
		$(srcdir)/ikev2-request-cookie-out.c \
		$(srcdir)/ikev2-sa-init-init-in.c \
		$(srcdir)/ikev2-sa-init-init-out.c \
		$(srcdir)/ikev2-sa-init-resp-in.c \
		$(srcdir)/ikev2-sa-init-resp-out.c \
		$(srcdir)/ikev2-sa-init-error.c \
		$(srcdir)/ikev2-sautil.c \
		$(srcdir)/ikev2-send.c \
		$(srcdir)/ikev2-shared-key-auth.c \
		$(srcdir)/ikev2-state-common.c \
		$(srcdir)/ikev2-state.c \
		$(srcdir)/ikev2-string-attribute-type.c \
		$(srcdir)/ikev2-string-auth-method.c \
		$(srcdir)/ikev2-string-cert-encoding.c \
		$(srcdir)/ikev2-string-id.c \
		$(srcdir)/ikev2-string-notify.c \
		$(srcdir)/ikev2-string-payload.c \
		$(srcdir)/ikev2-string-protocol.c \
		$(srcdir)/ikev2-string-transform.c \
		$(srcdir)/ikev2-tables.c \
		$(srcdir)/ikev2-tsutil.c \
		$(srcdir)/ikev2-window.c \
		  > ike-state-all.dot

ike-state-init.ps: ike-state-init.dot
ike-state-init.pdf: ike-state-init.dot
ike-state-auth.ps: ike-state-auth.dot
ike-state-auth.pdf: ike-state-auth.dot
ike-state-child.ps: ike-state-child.dot
ike-state-child.pdf: ike-state-child.dot
ike-state-rekey.ps: ike-state-rekey.dot
ike-state-rekey.pdf: ike-state-rekey.dot
ike-state-info.ps: ike-state-info.dot
ike-state-info.pdf: ike-state-info.dot
ike-state-all.ps: ike-state-all.dot
ike-state-all.pdf: ike-state-all.dot

all-ps: ike-state-init.ps ike-state-auth.ps \
	ike-state-child.ps ike-state-rekey.ps ike-state-info.ps

all-pdf: ike-state-init.pdf ike-state-auth.pdf \
	ike-state-child.pdf ike-state-rekey.pdf ike-state-info.pdf
