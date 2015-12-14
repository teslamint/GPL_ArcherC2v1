#  Copyright:
#          Copyright (c) 2002, 2003 SFNT Finland Oy.
# All rights reserved

AUTOMAKE_OPTIONS = 1.0 foreign dist-zip no-dependencies
WINCONF_OPTIONS = maintainer=tmo@ssh.fi

bin_PROGRAMS =		\
	ssh-certview 	\
	ssh-berdump 	\
	ssh-certmake 	\
	ssh-keytool 	\
	ssh-p12make 	\
	ssh-scepclient 	\
	ssh-cmpclient 	






































TESTS =			\
	ssh-certmake



INCLUDES = -I. -I$(srcdir) \
	   -I$(top_builddir) -I$(top_srcdir) \
	   -I$(top_builddir)/include

private_headers = 		\
        iprintf.h		\
	parse-x509-forms.h	\
	au-ek.h 		\
	ec-cmp.h		\
	au-ek.h 		\
	ec-cep.h		

















LDADD = -L../../lib -lssh





DEPENDENCIES = $(top_builddir)/lib/libssh.a



ssh_berdump_SOURCES = ssh-berdump.c dump-ber.c iprintf.c
ssh_berdump_DEPENDENCIES = $(DEPENDENCIES)



ssh_certview_SOURCES = \
	ssh-certview.c \
	dump-key.c dump-cert.c dump-crl.c dump-other.c \
	iprintf.c dump-ber.c
ssh_certview_DEPENDENCIES = $(DEPENDENCIES)



ssh_keytool_SOURCES = ssh-keytool.c dump-key.c iprintf.c
ssh_keytool_DEPENDENCIES = $(DEPENDENCIES)
ssh_keytool_PLATFORMS = win32 x64 win32vista x64vista win32win7 x64win7



ssh_p12make_SOURCES = ssh-p12make.c
ssh_p12make_DEPENDENCIES = $(DEPENDENCIES)




ssh_certmake_SOURCES = ssh-certmake.c parse-x509-forms.c dump-key.c iprintf.c
ssh_certmake_DEPENDENCIES = $(DEPENDENCIES)















































ssh_cmpclient_SOURCES = ssh-cmpclient.c au-ek.c ec-cmp.c \
	dump-cert.c dump-key.c dump-ber.c iprintf.c

ssh_cmpclient_DEPENDENCIES = $(DEPENDENCIES)

ssh_cmpclient_PLATFORMS = win32 x64 win32vista x64vista win32win7 x64win7




















ssh_scepclient_SOURCES = ssh-scepclient.c \
	au-ek.c ec-cep.c dump-cert.c dump-ber.c dump-key.c iprintf.c
ssh_scepclient_DEPENDENCIES = $(DEPENDENCIES)






















includes:

EXTRA_DIST = \
        test.x509

public_headers += 
private_headers += 
noinst_HEADERS = $(public_headers) $(private_headers)
