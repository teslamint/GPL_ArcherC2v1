.set project_name engine
.set project_type drvlib
.set project_platforms
.set project_guid AD1943A9-FD6D-3D7E-8100-AF41A5B0D3E7
.set project_dir ipsec\\quicksec\\kernel
.set project_dir_inverse ..\\..\\..
.set project_incdirs \
	ipsec\\hwaccel \
	ipsec\\util \
	ipsec \
	ipsec\\include \
	ipsec\\quicksec \
	interceptor\\include \
	ipsec\\quicksec\\engine \
	include \
	lib\\sshcrypto \
	lib\\sshcrypto\\sshcipher \
	lib\\sshcrypto\\sshhash \
	lib\\sshcrypto\\sshmac \
	lib\\zlib \
	interceptor\\windows \
	ipsec\\quicksec\\fastpath\\software \
	ipsec\\quicksec\\fastpath \
	interceptor\\libkernelutil \
	ipsec\\quicksec\\kernel \
	.
.set project_defs \
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
	sshmp-xuint.c \
	sshaudit.c \
	sshinetcalc.c \
	engine_alloc.c \
	engine_arp.c \
	engine_asyncop.c \
	engine_audit.c \
	engine_audit_pkt.c \
	engine_flow_id.c \
	engine_flows.c \
	engine_icmp.c \
	engine_init.c \
	engine_interfaces.c \
	engine_mediatypes.c \
	engine_nat.c \
	engine_natt_keepalive.c \
	engine_next_hop.c \
	engine_packet_handler.c \
	engine_pm_api_engine.c \
	engine_pm_api_tcp_encaps.c \
	engine_pm_api_util.c \
	engine_pme.c \
	engine_pmtu.c \
	engine_random.c \
	engine_rate_limit.c \
	engine_route.c \
	engine_rule_execute.c \
	engine_rule_lookup.c \
	engine_rule_lookup_list.c \
	engine_rule_lookup_tree.c \
	engine_rules.c \
	engine_tcp.c \
	engine_tcp_rst.c \
	engine_timeout.c \
	engine_transform.c \
	engine_trigger.c \
	engine_udp.c
.set dir_sshmp-xuint.c lib\\sshmath 
.set dir_sshaudit.c lib\\sshutil\\sshaudit 
.set dir_sshinetcalc.c lib\\sshutil\\sshnet 
.set dir_engine_alloc.c ipsec\\quicksec\\engine 
.set dir_engine_arp.c ipsec\\quicksec\\engine 
.set dir_engine_asyncop.c ipsec\\quicksec\\engine 
.set dir_engine_audit.c ipsec\\quicksec\\engine 
.set dir_engine_audit_pkt.c ipsec\\quicksec\\engine 
.set dir_engine_flow_id.c ipsec\\quicksec\\engine 
.set dir_engine_flows.c ipsec\\quicksec\\engine 
.set dir_engine_icmp.c ipsec\\quicksec\\engine 
.set dir_engine_init.c ipsec\\quicksec\\engine 
.set dir_engine_interfaces.c ipsec\\quicksec\\engine 
.set dir_engine_mediatypes.c ipsec\\quicksec\\engine 
.set dir_engine_nat.c ipsec\\quicksec\\engine 
.set dir_engine_natt_keepalive.c ipsec\\quicksec\\engine 
.set dir_engine_next_hop.c ipsec\\quicksec\\engine 
.set dir_engine_packet_handler.c ipsec\\quicksec\\engine 
.set dir_engine_pm_api_engine.c ipsec\\quicksec\\engine 
.set dir_engine_pm_api_tcp_encaps.c ipsec\\quicksec\\engine 
.set dir_engine_pm_api_util.c ipsec\\quicksec\\engine 
.set dir_engine_pme.c ipsec\\quicksec\\engine 
.set dir_engine_pmtu.c ipsec\\quicksec\\engine 
.set dir_engine_random.c ipsec\\quicksec\\engine 
.set dir_engine_rate_limit.c ipsec\\quicksec\\engine 
.set dir_engine_route.c ipsec\\quicksec\\engine 
.set dir_engine_rule_execute.c ipsec\\quicksec\\engine 
.set dir_engine_rule_lookup.c ipsec\\quicksec\\engine 
.set dir_engine_rule_lookup_list.c ipsec\\quicksec\\engine 
.set dir_engine_rule_lookup_tree.c ipsec\\quicksec\\engine 
.set dir_engine_rules.c ipsec\\quicksec\\engine 
.set dir_engine_tcp.c ipsec\\quicksec\\engine 
.set dir_engine_tcp_rst.c ipsec\\quicksec\\engine 
.set dir_engine_timeout.c ipsec\\quicksec\\engine 
.set dir_engine_transform.c ipsec\\quicksec\\engine 
.set dir_engine_trigger.c ipsec\\quicksec\\engine 
.set dir_engine_udp.c ipsec\\quicksec\\engine 
.set custom_tags
.set rsrcs
.set hdrs \
	core_pm_shared.h \
	engine_arp.h \
	engine_fastpath.h \
	engine_fastpath_types.h \
	engine_fastpath_util.h \
	engine_icmp.h \
	engine_internal.h \
	engine_pm_api.h \
	engine_pm_api_marshal.h \
	engine_pm_api_tcp_encaps.h \
	engine_pme.h \
	engine_rule_lookup.h \
	engine_tcp.h \
	engine_udp.h \
	ipsec_pm_shared.h \
	quicksec_pm_shared.h \
	version.h \
	versioni.h
.set dir_core_pm_shared.h ipsec\\quicksec\\engine 
.set dir_engine_arp.h ipsec\\quicksec\\engine 
.set dir_engine_fastpath.h ipsec\\quicksec\\engine 
.set dir_engine_fastpath_types.h ipsec\\quicksec\\engine 
.set dir_engine_fastpath_util.h ipsec\\quicksec\\engine 
.set dir_engine_icmp.h ipsec\\quicksec\\engine 
.set dir_engine_internal.h ipsec\\quicksec\\engine 
.set dir_engine_pm_api.h ipsec\\quicksec\\engine 
.set dir_engine_pm_api_marshal.h ipsec\\quicksec\\engine 
.set dir_engine_pm_api_tcp_encaps.h ipsec\\quicksec\\engine 
.set dir_engine_pme.h ipsec\\quicksec\\engine 
.set dir_engine_rule_lookup.h ipsec\\quicksec\\engine 
.set dir_engine_tcp.h ipsec\\quicksec\\engine 
.set dir_engine_udp.h ipsec\\quicksec\\engine 
.set dir_ipsec_pm_shared.h ipsec\\quicksec\\engine 
.set dir_quicksec_pm_shared.h ipsec\\quicksec\\engine 
.set dir_version.h ipsec\\quicksec 
.set dir_versioni.h ipsec\\quicksec 
