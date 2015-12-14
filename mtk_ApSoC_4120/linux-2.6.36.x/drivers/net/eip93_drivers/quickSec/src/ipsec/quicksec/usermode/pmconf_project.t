.set project_name pmconf
.set project_type applib
.set project_platforms
.set project_guid ABBF46E2-638B-34D6-8400-788D0F6A7F40
.set project_dir ipsec\\quicksec\\usermode
.set project_dir_inverse ..\\..\\..
.set project_incdirs \
	ipsec\\quicksec\\policymanager \
	ipsec\\quicksec\\engine \
	ipsec\\quicksec \
	interceptor\\include \
	ipsec\\include \
	ipsec \
	include \
	ipsec\\quicksec\\appgw \
	ipsec\\util \
	interceptor\\libkernelutil \
	ipsec\\quicksec\\usermode \
	.
.set project_defs \
	QUICKSEC \
	SSH_BUILD_IPSEC \
	HAVE_CONFIG_H
.set project_cflags
.set project_rcflags
.set project_libdirs
.set project_ldflags
.set project_libs
.set project_dependencies
.set outdir .
.set srcs \
	quicksec.dtd \
	quicksec_dtd.c \
	quicksecpm_audit.c \
	quicksecpm_xmlconf.c \
	quicksecpm_xmlconf_alg.c \
	quicksecpm_xmlconf_http.c
.set dir_quicksec.dtd ipsec\\quicksec\\apps 
.set dir_quicksec_dtd.c ipsec\\quicksec\\apps 
.set dir_quicksecpm_audit.c ipsec\\quicksec\\apps 
.set dir_quicksecpm_xmlconf.c ipsec\\quicksec\\apps 
.set dir_quicksecpm_xmlconf_alg.c ipsec\\quicksec\\apps 
.set dir_quicksecpm_xmlconf_http.c ipsec\\quicksec\\apps 
.set custom_tags
.set rsrcs
.set hdrs \
	quicksecpm_audit.h \
	quicksecpm_xmlconf.h \
	quicksecpm_xmlconf_i.h
.set dir_quicksecpm_audit.h ipsec\\quicksec\\apps 
.set dir_quicksecpm_xmlconf.h ipsec\\quicksec\\apps 
.set dir_quicksecpm_xmlconf_i.h ipsec\\quicksec\\apps 
