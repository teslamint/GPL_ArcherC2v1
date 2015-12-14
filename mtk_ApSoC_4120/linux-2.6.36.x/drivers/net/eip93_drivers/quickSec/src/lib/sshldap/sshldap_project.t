.set project_name sshldap
.set project_type applib
.set project_platforms
.set project_guid 7B7D73E9-5B07-3D40-8D00-63516C15F9EA
.set project_dir lib\\sshldap
.set project_dir_inverse ..\\..
.set project_incdirs \
	. \
	lib\\sshutil\\sshcore \
	lib\\sshutil\\sshadt \
	lib\\sshutil\\ssheloop \
	lib\\sshutil\\sshstrutil \
	lib\\sshutil\\sshfsm \
	lib\\sshutil\\sshstream \
	lib\\sshutil\\sshsysutil \
	lib\\sshutil\\sshnet \
	lib\\sshutil\\sshmisc \
	lib\\sshutil\\sshaudit \
	lib\\sshutil\\sshpacketstream \
	lib\\sshutil\\sshtestutil \
	lib\\sshutil \
	lib\\zlib \
	lib\\sshmath \
	lib\\sshasn1 \
	lib\\sshcrypto\\sshcipher \
	lib\\sshcrypto\\sshhash \
	lib\\sshcrypto\\sshrandom \
	lib\\sshcrypto\\sshcryptocore \
	lib\\sshcrypto\\sshmac \
	lib\\sshcrypto\\sshpk \
	lib\\sshcrypto \
	lib\\sshcryptoaux \
	lib\\sshradius \
	lib\\sshldap
.set project_defs \
	HAVE_CONFIG_H
.set project_cflags
.set project_rcflags
.set project_libdirs
.set project_ldflags
.set project_libs
.set project_dependencies
.set outdir .
.set srcs \
	ldap-bind.c \
	ldap-connect.c \
	ldap-conv.c \
	ldap-ext.c \
	ldap-filtertostr.c \
	ldap-init.c \
	ldap-input.c \
	ldap-modify.c \
	ldap-object.c \
	ldap-output.c \
	ldap-search.c \
	ldap-strtofilter.c
.set dir_ldap-bind.c lib\\sshldap 
.set dir_ldap-connect.c lib\\sshldap 
.set dir_ldap-conv.c lib\\sshldap 
.set dir_ldap-ext.c lib\\sshldap 
.set dir_ldap-filtertostr.c lib\\sshldap 
.set dir_ldap-init.c lib\\sshldap 
.set dir_ldap-input.c lib\\sshldap 
.set dir_ldap-modify.c lib\\sshldap 
.set dir_ldap-object.c lib\\sshldap 
.set dir_ldap-output.c lib\\sshldap 
.set dir_ldap-search.c lib\\sshldap 
.set dir_ldap-strtofilter.c lib\\sshldap 
.set custom_tags
.set rsrcs
.set hdrs \
	ldap-internal.h \
	sshldap.h
.set dir_ldap-internal.h lib\\sshldap 
.set dir_sshldap.h lib\\sshldap 
