.set project_name appgw
.set project_type applib
.set project_platforms
.set project_guid F5ED03E4-ACB0-31EE-9600-045A403170BF
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
	appgw_av.c \
	appgw_cifs.c \
	appgw_cifs_st_msds.c \
	appgw_cifs_st_nbt.c \
	appgw_cifs_st_parser.c \
	appgw_cifs_st_request.c \
	appgw_cifs_st_response.c \
	appgw_dns.c \
	appgw_dns_config.c \
	appgw_ftp.c \
	appgw_http.c \
	appgw_http_config.c \
	appgw_http_state.c \
	appgw_netbios_dgm.c \
	appgw_pass_through_tcp.c \
	appgw_sip.c \
	appgw_sip_config.c \
	appgw_sip_packet.c \
	appgw_sip_ports.c \
	appgw_socksify.c \
	appgw_wins.c \
	dce_rpc_pdu.c \
	wins_packet.c
.set dir_appgw_av.c ipsec\\quicksec\\appgw 
.set dir_appgw_cifs.c ipsec\\quicksec\\appgw 
.set dir_appgw_cifs_st_msds.c ipsec\\quicksec\\appgw 
.set dir_appgw_cifs_st_nbt.c ipsec\\quicksec\\appgw 
.set dir_appgw_cifs_st_parser.c ipsec\\quicksec\\appgw 
.set dir_appgw_cifs_st_request.c ipsec\\quicksec\\appgw 
.set dir_appgw_cifs_st_response.c ipsec\\quicksec\\appgw 
.set dir_appgw_dns.c ipsec\\quicksec\\appgw 
.set dir_appgw_dns_config.c ipsec\\quicksec\\appgw 
.set dir_appgw_ftp.c ipsec\\quicksec\\appgw 
.set dir_appgw_http.c ipsec\\quicksec\\appgw 
.set dir_appgw_http_config.c ipsec\\quicksec\\appgw 
.set dir_appgw_http_state.c ipsec\\quicksec\\appgw 
.set dir_appgw_netbios_dgm.c ipsec\\quicksec\\appgw 
.set dir_appgw_pass_through_tcp.c ipsec\\quicksec\\appgw 
.set dir_appgw_sip.c ipsec\\quicksec\\appgw 
.set dir_appgw_sip_config.c ipsec\\quicksec\\appgw 
.set dir_appgw_sip_packet.c ipsec\\quicksec\\appgw 
.set dir_appgw_sip_ports.c ipsec\\quicksec\\appgw 
.set dir_appgw_socksify.c ipsec\\quicksec\\appgw 
.set dir_appgw_wins.c ipsec\\quicksec\\appgw 
.set dir_dce_rpc_pdu.c ipsec\\quicksec\\appgw 
.set dir_wins_packet.c ipsec\\quicksec\\appgw 
.set custom_tags
.set rsrcs
.set hdrs \
	appgw_av.h \
	appgw_cifs_internal.h \
	appgw_dns.h \
	appgw_ftp.h \
	appgw_http.h \
	appgw_http_internal.h \
	appgw_pass_through_tcp.h \
	appgw_sip.h \
	appgw_socksify.h \
	appgw_wins_internal.h \
	dce_rpc_pdu.h \
	wins_packet.h
.set dir_appgw_av.h ipsec\\quicksec\\appgw 
.set dir_appgw_cifs_internal.h ipsec\\quicksec\\appgw 
.set dir_appgw_dns.h ipsec\\quicksec\\appgw 
.set dir_appgw_ftp.h ipsec\\quicksec\\appgw 
.set dir_appgw_http.h ipsec\\quicksec\\appgw 
.set dir_appgw_http_internal.h ipsec\\quicksec\\appgw 
.set dir_appgw_pass_through_tcp.h ipsec\\quicksec\\appgw 
.set dir_appgw_sip.h ipsec\\quicksec\\appgw 
.set dir_appgw_socksify.h ipsec\\quicksec\\appgw 
.set dir_appgw_wins_internal.h ipsec\\quicksec\\appgw 
.set dir_dce_rpc_pdu.h ipsec\\quicksec\\appgw 
.set dir_wins_packet.h ipsec\\quicksec\\appgw 
