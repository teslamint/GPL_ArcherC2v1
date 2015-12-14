.set project_name quicksecpm
.set project_type console
.set project_platforms
.set project_guid F15618FC-74AC-31F0-9300-8EA7B5F900EA
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
.set project_dependencies \
	ipsecpm \
	pmconf \
	appgw
.set outdir .
.set srcs \
	ip_interfaces.c \
	virtual_adapter_util.c \
	quicksec_dtd.c \
	quicksecpm.c \
	quicksecpm_windows.c \
	engine_pm_api_util.c \
	eng_pm_api_pm.c
.set dir_ip_interfaces.c ipsec\\util 
.set dir_virtual_adapter_util.c ipsec\\util 
.set dir_quicksec_dtd.c ipsec\\quicksec\\apps 
.set dir_quicksecpm.c ipsec\\quicksec\\apps 
.set dir_quicksecpm_windows.c ipsec\\quicksec\\apps 
.set dir_engine_pm_api_util.c ipsec\\quicksec\\engine 
.set dir_eng_pm_api_pm.c ipsec\\quicksec\\policymanager 
.set custom_tags
.set rsrcs
.set hdrs
