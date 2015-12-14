.set workspace_name interceptor
.set guid_quicksec EBD56545-3884-340C-9D00-2C58E54D769B
.set file_quicksec windows\\winim\\quicksec.vcproj
.set dependencies_quicksec \
	accelerator_none \
	engine \
	fastpath_software \
	include \
	kernel
.set platforms_quicksec \
	win32 \
	x64 \
	std500armv4i \
	std500x86 \
	std500sh4 \
	std500mipsii \
	std500mipsii_fp \
	std500mipsiv \
	std500mipsiv_fp \
	ppc50armv4i \
	sp50armv4i \
	wm6std \
	wm6pro
.set build_quicksec yes
.set guid_qsfilter F81E770B-852D-33EA-9200-6548240F9F34
.set file_qsfilter windows\\ndisfilter\\qsfilter.vcproj
.set dependencies_qsfilter \
	accelerator_none \
	engine \
	fastpath_software \
	include \
	kernel
.set platforms_qsfilter \
	win32vista \
	x64vista \
	win32win7 \
	x64win7
.set build_qsfilter yes
.set guid_qsvnic5 F84D3031-B58E-3D7E-8000-4B322B316491
.set file_qsvnic5 windows\\vnic\\ndis5_0\\qsvnic5.vcproj
.set dependencies_qsvnic5 \
	include
.set platforms_qsvnic5 \
	win32 \
	x64 \
	win32vistandis5 \
	x64vistandis5 \
	win32win7ndis5 \
	x64win7ndis5 \
	std500armv4i \
	std500x86 \
	std500sh4 \
	std500mipsii \
	std500mipsii_fp \
	std500mipsiv \
	std500mipsiv_fp \
	ppc50armv4i \
	sp50armv4i \
	wm6std \
	wm6pro
.set build_qsvnic5 yes
.set guid_accelerator_none E2B0E928-1111-3EFE-9A00-F07EE44B4C6A
.set file_accelerator_none ..\\..\\ipsec\\quicksec\\kernel\\accelerator_none.vcproj
.set dependencies_accelerator_none \
	include
.set platforms_accelerator_none
.set build_accelerator_none yes
.set guid_kernel 50484C19-F1AF-3AF3-8400-0D821ED393D2
.set file_kernel ..\\..\\ipsec\\quicksec\\kernel\\kernel.vcproj
.set dependencies_kernel \
	include
.set platforms_kernel
.set build_kernel yes
.set guid_fastpath_software D33B296A-4E6E-32E5-8600-A1207148D39A
.set file_fastpath_software ..\\..\\ipsec\\quicksec\\kernel\\fastpath_software.vcproj
.set dependencies_fastpath_software \
	include
.set platforms_fastpath_software
.set build_fastpath_software yes
.set guid_engine AD1943A9-FD6D-3D7E-8100-AF41A5B0D3E7
.set file_engine ..\\..\\ipsec\\quicksec\\kernel\\engine.vcproj
.set dependencies_engine \
	include
.set platforms_engine
.set build_engine yes
.set guid_include D436EB0F-D9DE-30B5-8A00-8CE6435F7E81
.set file_include ..\\..\\include\\include.vcproj
.set dependencies_include
.set platforms_include
.set build_include yes
.set projects \
	quicksec \
	qsfilter \
	qsvnic5 \
	accelerator_none \
	kernel \
	fastpath_software \
	engine \
	include
