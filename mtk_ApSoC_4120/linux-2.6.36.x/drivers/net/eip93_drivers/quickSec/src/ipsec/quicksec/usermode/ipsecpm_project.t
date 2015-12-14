.set project_name ipsecpm
.set project_type applib
.set project_platforms
.set project_guid F5C5E4F9-2A8F-37A8-9A00-8F5CDE484702
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
	appgw.c \
	appgw_st.c \
	eng_pm_api_pm.c \
	eng_rules.c \
	eng_upcall.c \
	pad_auth_domain.c \
	pad_auth_passwd.c \
	pad_auth_radius.c \
	pad_authorization.c \
	pad_authorization_local.c \
	pad_ike.c \
	pad_ike_certs.c \
	pad_ike_certs_mscapi.c \
	pad_ike_eap.c \
	rac_virtual_ip.c \
	rac_virtual_ip_cfgmode_st.c \
	rac_virtual_ip_l2tp_st.c \
	rac_virtual_ip_st.c \
	ras.c \
	ras_addrpool.c \
	ras_cfgmode_client_store.c \
	ras_legacy_auth_server.c \
	sad_ike.c \
	sad_ike_common_st.c \
	sad_ike_i_negotiation_st.c \
	sad_ike_initiator_st.c \
	sad_ike_spis.c \
	sad_mobike.c \
	sad_mobike_st.c \
	sad_sa_handler.c \
	sad_sa_handler_manual.c \
	sad_sa_handler_st.c \
	spd_batch_st.c \
	spd_config_st.c \
	spd_iface_st.c \
	spd_ike.c \
	spd_ike_delete.c \
	spd_ike_init.c \
	spd_ike_psk.c \
	spd_main.c \
	spd_main_st.c \
	spd_rule_lookup.c \
	spd_rules.c \
	spd_services.c \
	spd_shutdown_st.c \
	spd_tunnels.c \
	spd_tunnels_ike.c \
	util.c \
	util_algorithms.c \
	util_alloc.c \
	util_asyncop.c \
	util_audit.c \
	util_cm.c \
	util_cm_access.c \
	util_cm_notify.c \
	util_compat.c \
	util_connection.c \
	util_dnsresolver.c \
	util_dpd.c \
	util_ek.c \
	util_ek_st.c \
	util_ike_certs.c \
	util_ike_cfgmode.c \
	util_ike_confutils.c \
	util_ike_id.c \
	util_ike_ipsec.c \
	util_ike_sautils.c \
	util_ike_spis.c \
	util_ike_tsutils.c \
	util_ipsec.c \
	util_l2tp.c \
	util_l2tp_lns_st.c \
	util_linearize.c \
	util_mscapi.c \
	util_nameserver.c \
	util_peer.c \
	util_render.c \
	util_servers.c \
	util_statistics.c \
	util_tables.c \
	util_tcpencap.c \
	util_unknown_spis.c \
	util_virtual_adapter.c
.set dir_appgw.c ipsec\\quicksec\\policymanager 
.set dir_appgw_st.c ipsec\\quicksec\\policymanager 
.set dir_eng_pm_api_pm.c ipsec\\quicksec\\policymanager 
.set dir_eng_rules.c ipsec\\quicksec\\policymanager 
.set dir_eng_upcall.c ipsec\\quicksec\\policymanager 
.set dir_pad_auth_domain.c ipsec\\quicksec\\policymanager 
.set dir_pad_auth_passwd.c ipsec\\quicksec\\policymanager 
.set dir_pad_auth_radius.c ipsec\\quicksec\\policymanager 
.set dir_pad_authorization.c ipsec\\quicksec\\policymanager 
.set dir_pad_authorization_local.c ipsec\\quicksec\\policymanager 
.set dir_pad_ike.c ipsec\\quicksec\\policymanager 
.set dir_pad_ike_certs.c ipsec\\quicksec\\policymanager 
.set dir_pad_ike_certs_mscapi.c ipsec\\quicksec\\policymanager 
.set dir_pad_ike_eap.c ipsec\\quicksec\\policymanager 
.set dir_rac_virtual_ip.c ipsec\\quicksec\\policymanager 
.set dir_rac_virtual_ip_cfgmode_st.c ipsec\\quicksec\\policymanager 
.set dir_rac_virtual_ip_l2tp_st.c ipsec\\quicksec\\policymanager 
.set dir_rac_virtual_ip_st.c ipsec\\quicksec\\policymanager 
.set dir_ras.c ipsec\\quicksec\\policymanager 
.set dir_ras_addrpool.c ipsec\\quicksec\\policymanager 
.set dir_ras_cfgmode_client_store.c ipsec\\quicksec\\policymanager 
.set dir_ras_legacy_auth_server.c ipsec\\quicksec\\policymanager 
.set dir_sad_ike.c ipsec\\quicksec\\policymanager 
.set dir_sad_ike_common_st.c ipsec\\quicksec\\policymanager 
.set dir_sad_ike_i_negotiation_st.c ipsec\\quicksec\\policymanager 
.set dir_sad_ike_initiator_st.c ipsec\\quicksec\\policymanager 
.set dir_sad_ike_spis.c ipsec\\quicksec\\policymanager 
.set dir_sad_mobike.c ipsec\\quicksec\\policymanager 
.set dir_sad_mobike_st.c ipsec\\quicksec\\policymanager 
.set dir_sad_sa_handler.c ipsec\\quicksec\\policymanager 
.set dir_sad_sa_handler_manual.c ipsec\\quicksec\\policymanager 
.set dir_sad_sa_handler_st.c ipsec\\quicksec\\policymanager 
.set dir_spd_batch_st.c ipsec\\quicksec\\policymanager 
.set dir_spd_config_st.c ipsec\\quicksec\\policymanager 
.set dir_spd_iface_st.c ipsec\\quicksec\\policymanager 
.set dir_spd_ike.c ipsec\\quicksec\\policymanager 
.set dir_spd_ike_delete.c ipsec\\quicksec\\policymanager 
.set dir_spd_ike_init.c ipsec\\quicksec\\policymanager 
.set dir_spd_ike_psk.c ipsec\\quicksec\\policymanager 
.set dir_spd_main.c ipsec\\quicksec\\policymanager 
.set dir_spd_main_st.c ipsec\\quicksec\\policymanager 
.set dir_spd_rule_lookup.c ipsec\\quicksec\\policymanager 
.set dir_spd_rules.c ipsec\\quicksec\\policymanager 
.set dir_spd_services.c ipsec\\quicksec\\policymanager 
.set dir_spd_shutdown_st.c ipsec\\quicksec\\policymanager 
.set dir_spd_tunnels.c ipsec\\quicksec\\policymanager 
.set dir_spd_tunnels_ike.c ipsec\\quicksec\\policymanager 
.set dir_util.c ipsec\\quicksec\\policymanager 
.set dir_util_algorithms.c ipsec\\quicksec\\policymanager 
.set dir_util_alloc.c ipsec\\quicksec\\policymanager 
.set dir_util_asyncop.c ipsec\\quicksec\\policymanager 
.set dir_util_audit.c ipsec\\quicksec\\policymanager 
.set dir_util_cm.c ipsec\\quicksec\\policymanager 
.set dir_util_cm_access.c ipsec\\quicksec\\policymanager 
.set dir_util_cm_notify.c ipsec\\quicksec\\policymanager 
.set dir_util_compat.c ipsec\\quicksec\\policymanager 
.set dir_util_connection.c ipsec\\quicksec\\policymanager 
.set dir_util_dnsresolver.c ipsec\\quicksec\\policymanager 
.set dir_util_dpd.c ipsec\\quicksec\\policymanager 
.set dir_util_ek.c ipsec\\quicksec\\policymanager 
.set dir_util_ek_st.c ipsec\\quicksec\\policymanager 
.set dir_util_ike_certs.c ipsec\\quicksec\\policymanager 
.set dir_util_ike_cfgmode.c ipsec\\quicksec\\policymanager 
.set dir_util_ike_confutils.c ipsec\\quicksec\\policymanager 
.set dir_util_ike_id.c ipsec\\quicksec\\policymanager 
.set dir_util_ike_ipsec.c ipsec\\quicksec\\policymanager 
.set dir_util_ike_sautils.c ipsec\\quicksec\\policymanager 
.set dir_util_ike_spis.c ipsec\\quicksec\\policymanager 
.set dir_util_ike_tsutils.c ipsec\\quicksec\\policymanager 
.set dir_util_ipsec.c ipsec\\quicksec\\policymanager 
.set dir_util_l2tp.c ipsec\\quicksec\\policymanager 
.set dir_util_l2tp_lns_st.c ipsec\\quicksec\\policymanager 
.set dir_util_linearize.c ipsec\\quicksec\\policymanager 
.set dir_util_mscapi.c ipsec\\quicksec\\policymanager 
.set dir_util_nameserver.c ipsec\\quicksec\\policymanager 
.set dir_util_peer.c ipsec\\quicksec\\policymanager 
.set dir_util_render.c ipsec\\quicksec\\policymanager 
.set dir_util_servers.c ipsec\\quicksec\\policymanager 
.set dir_util_statistics.c ipsec\\quicksec\\policymanager 
.set dir_util_tables.c ipsec\\quicksec\\policymanager 
.set dir_util_tcpencap.c ipsec\\quicksec\\policymanager 
.set dir_util_unknown_spis.c ipsec\\quicksec\\policymanager 
.set dir_util_virtual_adapter.c ipsec\\quicksec\\policymanager 
.set custom_tags
.set rsrcs
.set hdrs \
	core_pm_shared.h \
	ipsec_pm_shared.h \
	quicksec_pm_shared.h \
	appgw_api.h \
	core_pm.h \
	eng_pm_api_pm.h \
	firewall_internal.h \
	firewall_pm.h \
	ipsec_internal.h \
	ipsec_pm.h \
	ipsec_pm_low.h \
	nat_internal.h \
	pad_auth_domain.h \
	pad_auth_passwd.h \
	pad_auth_radius.h \
	pad_authorization_local.h \
	quicksec_pm.h \
	quicksec_pm_low.h \
	quicksecpm_internal.h \
	rac_virtual_ip_internal.h \
	ras_addrpool.h \
	ras_internal.h \
	sad_ike.h \
	spd_internal.h \
	spd_main_st.h \
	util_algorithms_internal.h \
	util_cm.h \
	util_connection.h \
	util_dnsresolver.h \
	util_internal.h \
	util_mscapi.h \
	util_nameserver.h \
	util_tcpencap.h
.set dir_core_pm_shared.h ipsec\\quicksec\\engine 
.set dir_ipsec_pm_shared.h ipsec\\quicksec\\engine 
.set dir_quicksec_pm_shared.h ipsec\\quicksec\\engine 
.set dir_appgw_api.h ipsec\\quicksec\\policymanager 
.set dir_core_pm.h ipsec\\quicksec\\policymanager 
.set dir_eng_pm_api_pm.h ipsec\\quicksec\\policymanager 
.set dir_firewall_internal.h ipsec\\quicksec\\policymanager 
.set dir_firewall_pm.h ipsec\\quicksec\\policymanager 
.set dir_ipsec_internal.h ipsec\\quicksec\\policymanager 
.set dir_ipsec_pm.h ipsec\\quicksec\\policymanager 
.set dir_ipsec_pm_low.h ipsec\\quicksec\\policymanager 
.set dir_nat_internal.h ipsec\\quicksec\\policymanager 
.set dir_pad_auth_domain.h ipsec\\quicksec\\policymanager 
.set dir_pad_auth_passwd.h ipsec\\quicksec\\policymanager 
.set dir_pad_auth_radius.h ipsec\\quicksec\\policymanager 
.set dir_pad_authorization_local.h ipsec\\quicksec\\policymanager 
.set dir_quicksec_pm.h ipsec\\quicksec\\policymanager 
.set dir_quicksec_pm_low.h ipsec\\quicksec\\policymanager 
.set dir_quicksecpm_internal.h ipsec\\quicksec\\policymanager 
.set dir_rac_virtual_ip_internal.h ipsec\\quicksec\\policymanager 
.set dir_ras_addrpool.h ipsec\\quicksec\\policymanager 
.set dir_ras_internal.h ipsec\\quicksec\\policymanager 
.set dir_sad_ike.h ipsec\\quicksec\\policymanager 
.set dir_spd_internal.h ipsec\\quicksec\\policymanager 
.set dir_spd_main_st.h ipsec\\quicksec\\policymanager 
.set dir_util_algorithms_internal.h ipsec\\quicksec\\policymanager 
.set dir_util_cm.h ipsec\\quicksec\\policymanager 
.set dir_util_connection.h ipsec\\quicksec\\policymanager 
.set dir_util_dnsresolver.h ipsec\\quicksec\\policymanager 
.set dir_util_internal.h ipsec\\quicksec\\policymanager 
.set dir_util_mscapi.h ipsec\\quicksec\\policymanager 
.set dir_util_nameserver.h ipsec\\quicksec\\policymanager 
.set dir_util_tcpencap.h ipsec\\quicksec\\policymanager 
