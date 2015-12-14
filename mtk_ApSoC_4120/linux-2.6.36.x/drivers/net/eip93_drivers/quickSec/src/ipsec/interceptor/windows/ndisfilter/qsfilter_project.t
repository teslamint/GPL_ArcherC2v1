.set project_name qsfilter
.set project_type driver
.set project_platforms \
	win32vista \
	x64vista \
	win32win7 \
	x64win7
.set project_guid F81E770B-852D-33EA-9200-6548240F9F34
.set project_dir ipsec\\interceptor\\windows\\ndisfilter
.set project_dir_inverse ..\\..\\..\\..
.set project_incdirs \
	interceptor\\windows\\vnic \
	interceptor\\windows\\ndisfilter \
	interceptor\\windows \
	ipsec\\interceptor \
	ipsec\\engine \
	interceptor\\include \
	interceptor\\libkernelutil \
	ipsec\\util \
	ipsec\\lib\\sshdhcp \
	ipsec \
	lib\\sshcrypto \
	lib\\sshutil \
	lib\\sshutil\\sshfsm \
	lib\\sshutil\\sshadt \
	lib\\sshutil\\sshcore \
	lib\\sshutil\\ssheloop \
	lib\\sshutil\\sshnet \
	lib\\sshutil\\sshstrutil \
	ipsec\\interceptor\\windows\\ndisfilter \
	.
.set project_defs \
	SSH_BUILD_IPSEC \
	HAVE_CONFIG_H
.set project_cflags
.set project_rcflags
.set project_libdirs
.set project_ldflags
.set project_libs
.set project_dependencies \
	accelerator_none \
	kernel \
	fastpath_software \
	engine
.set outdir .
.set srcs \
	adapter_common.c \
	alloc.c \
	debug_trace.c \
	event.c \
	event_log.c \
	icept_api_common.c \
	interceptor_i_common.c \
	iodevice.c \
	ipdevice.c \
	mutex.c \
	ndis6_packet_pool.c \
	ndis_render.c \
	ndisfilter_adapter.c \
	ndisfilter_icept_api.c \
	ndisfilter_main.c \
	pktizer.c \
	registry.c \
	secsys.c \
	task.c \
	timeout.c \
	virtual_adapter.c \
	virtual_adapter_private.c \
	wan_interface.c \
	win_ip_interface.c \
	win_ip_route.c \
	winnt6_ipdevice.c \
	winnt_device_io.c \
	winnt_file_io.c \
	wrkqueue.c
.set dir_adapter_common.c interceptor\\windows 
.set dir_alloc.c interceptor\\windows 
.set dir_debug_trace.c interceptor\\windows 
.set dir_event.c interceptor\\windows 
.set dir_event_log.c interceptor\\windows 
.set dir_icept_api_common.c interceptor\\windows 
.set dir_interceptor_i_common.c interceptor\\windows 
.set dir_iodevice.c interceptor\\windows 
.set dir_ipdevice.c interceptor\\windows 
.set dir_mutex.c interceptor\\windows 
.set dir_ndis6_packet_pool.c interceptor\\windows 
.set dir_ndis_render.c interceptor\\windows 
.set dir_ndisfilter_adapter.c interceptor\\windows\\ndisfilter 
.set dir_ndisfilter_icept_api.c interceptor\\windows\\ndisfilter 
.set dir_ndisfilter_main.c interceptor\\windows\\ndisfilter 
.set dir_pktizer.c interceptor\\windows 
.set dir_registry.c interceptor\\windows 
.set dir_secsys.c interceptor\\windows 
.set dir_task.c interceptor\\windows 
.set dir_timeout.c interceptor\\windows 
.set dir_virtual_adapter.c interceptor\\windows 
.set dir_virtual_adapter_private.c interceptor\\windows 
.set dir_wan_interface.c interceptor\\windows 
.set dir_win_ip_interface.c interceptor\\windows 
.set dir_win_ip_route.c interceptor\\windows 
.set dir_winnt6_ipdevice.c interceptor\\windows 
.set dir_winnt_device_io.c interceptor\\windows 
.set dir_winnt_file_io.c interceptor\\windows 
.set dir_wrkqueue.c interceptor\\windows 
.set custom_input_0 {srctop}\\interceptor\\windows\\event_log_msg.mc
.set custom_output_0 event_log_msg.h
.set custom_command_0 mc -v -c {srctop}\\interceptor\\windows\\event_log_msg.mc
.set custom_platforms_0 win32vista x64vista win32win7 x64win7
.set custom_tags \
	0
.set rsrcs \
	qsfilter.rc
.set dir_qsfilter.rc interceptor\\windows\\ndisfilter 
.set hdrs \
	adapter_common.h \
	debug_trace.h \
	device_io.h \
	event.h \
	event_log.h \
	file_io.h \
	interceptor_i_common.h \
	iodevice.h \
	ipdevice.h \
	ipdevice_internal.h \
	ndis6_packet_pool.h \
	ndis_render.h \
	interceptor_i.h \
	resource.h \
	packet_pool_common.h \
	pktizer.h \
	registry.h \
	secsys.h \
	task.h \
	virtual_adapter_private.h \
	wan_interface.h \
	win_ip_interface.h \
	win_ip_route.h \
	win_os_version.h \
	wrkqueue.h
.set dir_adapter_common.h interceptor\\windows 
.set dir_debug_trace.h interceptor\\windows 
.set dir_device_io.h interceptor\\windows 
.set dir_event.h interceptor\\windows 
.set dir_event_log.h interceptor\\windows 
.set dir_file_io.h interceptor\\windows 
.set dir_interceptor_i_common.h interceptor\\windows 
.set dir_iodevice.h interceptor\\windows 
.set dir_ipdevice.h interceptor\\windows 
.set dir_ipdevice_internal.h interceptor\\windows 
.set dir_ndis6_packet_pool.h interceptor\\windows 
.set dir_ndis_render.h interceptor\\windows 
.set dir_interceptor_i.h interceptor\\windows\\ndisfilter 
.set dir_resource.h interceptor\\windows\\ndisfilter 
.set dir_packet_pool_common.h interceptor\\windows 
.set dir_pktizer.h interceptor\\windows 
.set dir_registry.h interceptor\\windows 
.set dir_secsys.h interceptor\\windows 
.set dir_task.h interceptor\\windows 
.set dir_virtual_adapter_private.h interceptor\\windows 
.set dir_wan_interface.h interceptor\\windows 
.set dir_win_ip_interface.h interceptor\\windows 
.set dir_win_ip_route.h interceptor\\windows 
.set dir_win_os_version.h interceptor\\windows 
.set dir_wrkqueue.h interceptor\\windows 
