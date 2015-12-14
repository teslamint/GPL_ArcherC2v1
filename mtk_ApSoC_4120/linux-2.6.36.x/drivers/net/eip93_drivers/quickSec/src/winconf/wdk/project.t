.rem
.rem project.t
.rem
.rem Copyright:
.rem          Copyright (c) 2008 SFNT Finland Oy.
.rem               All rights reserved
.rem
.rem Windows Driver Kit build file template.
.rem
.rem Consider drivers, driver libraries and header files only.
.rem ---------------------------------------------------------
.rem
.set target_is_driver
.set target_is_drvlib
.set target_is_include
.set target_is_{project_type} yes
.set target_is_{project_name} yes
.set enable
.for dummy {target_is_driver}
.set prefix drv
.set enable yes
.rof
.for dummy {target_is_drvlib}
.set prefix drv
.set enable yes
.rof
.for dummy {target_is_include}
.set prefix drv
.set enable yes
.rof
.for dummy0 {enable}
.rem
.rem WDK platforms.
.rem --------------
.rem
.set wdk_platforms \
	w2k \
	wxp \
	wnet \
	wlh \
	win7 \
        wlhndis5 \
        win7ndis5
.rem
.set ddk_target_os_w2k            Win2K
.set ddk_target_os_wxp            WinXP
.set ddk_target_os_wnet           WinNET
.set ddk_target_os_wlh            WinLH
.set ddk_target_os_win7           Win7
.set ddk_target_os_wlhndis5       WinLH
.set ddk_target_os_win7ndis5      Win7
.rem
.rem WDK architectures.
.rem ------------------
.set wdk_architectures \
	x86 \
	x64 \
	ia64
.rem
.set buildarch_x86         x86
.set buildarch_x64         AMD64
.set buildarch_ia64        IA64
.rem
.rem WDK environments.
.rem -----------------
.rem
.set wdk_environments \
	debug \
	release
.rem
.set ddkbuildenv_debug   chk
.set ddkbuildenv_release fre
.rem
.rem C preprocessor options for all objects.
.rem ---------------------------------------
.rem
.rem Values for each platform.
.rem
.set any_defs_w2k \
	_WIN32_WINNT=0x0500 \
	WINVER=0x0500 \
	NTDDI_VERSION=0x05000400
.set any_defs_wxp \
	_WIN32_WINNT=0x0501 \
	WINVER=0x0501 \
	NTDDI_VERSION=0x05010000
.set any_defs_wnet \
	_WIN32_WINNT=0x0502 \
	WINVER=0x0502 \
	NTDDI_VERSION=0x05020000
.set any_defs_wlh \
	_WIN32_WINNT=0x0600 \
	WINVER=0x0600 \
	NTDDI_VERSION=0x06000000
.set any_defs_win7 \
	_WIN32_WINNT=0x0601 \
	WINVER=0x0601 \
	NTDDI_VERSION=0x06010000
.set any_defs_wlhndis5 
.set any_defs_win7ndis5 
.rem
.rem C compiler options for all objects.
.rem ---------------------------------------
.rem
.rem All targets.
.rem
.set any_cflags \
	/wd4018
.rem
.rem Additional libraries for all executables.
.rem -----------------------------------------
.rem
.rem All targets.
.rem
.set any_libs
.rem
.rem C preprocessor options for application objects.
.rem -----------------------------------------------
.rem
.rem All targets.
.rem
.set app_defs \
	WINDOWS \
	WIN32
.rem
.rem Values for each platform.
.rem
.set app_defs_w2k {any_defs_w2k} {app_defs}
.set app_defs_wxp {any_defs_wxp} {app_defs}
.set app_defs_wnet {any_defs_wnet} {app_defs}
.set app_defs_wlh {any_defs_wlh} {app_defs}
.set app_defs_win7 {any_defs_win7} {app_defs}
.set app_defs_wlhndis5 {any_defs_wlhndis5} {app_defs}
.set app_defs_win7ndis5 {any_defs_win7ndis5} {app_defs}
.rem
.rem Debug/optimization options.
.rem
.set app_defs_dbg \
	_DEBUG \
	DEBUG_LIGHT
.set app_defs_rel \
	NDEBUG
.rem
.rem Values for each platform/configuration combination.
.rem
.set app_defs_w2k_debug             {app_defs_w2k} {app_defs_dbg}
.set app_defs_w2k_release           {app_defs_w2k} {app_defs_rel}
.set app_defs_wxp_debug             {app_defs_wxp} {app_defs_dbg}
.set app_defs_wxp_release           {app_defs_wxp} {app_defs_rel}
.set app_defs_wnet_debug            {app_defs_wnet} {app_defs_dbg}
.set app_defs_wnet_release          {app_defs_wnet} {app_defs_rel}
.set app_defs_wlh_debug             {app_defs_wlh} {app_defs_dbg}
.set app_defs_wlh_release           {app_defs_wlh} {app_defs_rel}
.set app_defs_win7_debug            {app_defs_win7} {app_defs_dbg}
.set app_defs_win7_release          {app_defs_win7} {app_defs_rel}
.set app_defs_wlhndis5_debug        {app_defs_wlhndis5} {app_defs_dbg}
.set app_defs_wlhndis5_release      {app_defs_wlhndis5} {app_defs_rel}
.set app_defs_win7ndis5_debug       {app_defs_win7ndis5} {app_defs_dbg}
.set app_defs_win7ndis5_release     {app_defs_win7ndis5} {app_defs_rel}
.rem
.rem C compiler options for application objects.
.rem -------------------------------------------
.rem
.rem Values for each platform/configuration combination.
.rem
.set app_cflags_w2k_debug             {any_cflags}
.set app_cflags_w2k_release           {any_cflags}
.set app_cflags_wxp_debug             {any_cflags}
.set app_cflags_wxp_release           {any_cflags}
.set app_cflags_wnet_debug            {any_cflags}
.set app_cflags_wnet_release          {any_cflags}
.set app_cflags_wlh_debug             {any_cflags}
.set app_cflags_wlh_release           {any_cflags}
.set app_cflags_win7_debug            {any_cflags}
.set app_cflags_win7_release          {any_cflags}
.set app_cflags_wlhndis5_debug        {any_cflags}
.set app_cflags_wlhndis5_release      {any_cflags}
.set app_cflags_win7ndis5_debug       {any_cflags}
.set app_cflags_win7ndis5_release     {any_cflags}
.rem
.rem Additional libraries for applications.
.rem --------------------------------------
.rem
.rem All targets.
.rem
.set app_libs {any_libs} ws2_32.lib
.rem
.rem Values for each platform.
.rem
.set app_libs_w2k             {app_libs}
.set app_libs_wxp             {app_libs}
.set app_libs_wnet            {app_libs}
.set app_libs_wlh             {app_libs}
.set app_libs_win7            {app_libs}
.set app_libs_wlhndis5        {app_libs}
.set app_libs_win7ndis5       {app_libs}
.rem
.rem C preprocessor options for driver objects.
.rem ------------------------------------------
.rem
.rem All targets.
.rem
.set drv_defs \
	WINDOWS \
	KERNEL \
	WIN32 \
	WINNT \
	BINARY_COMPATIBLE=0 \
	INTERCEPTOR_HAS_PACKET_COPYIN \
	INTERCEPTOR_HAS_PACKET_COPYOUT \
        INTERCEPTOR_HAS_PACKET_DETACH \
	INTERCEPTOR_IMPLEMENTS_VIRTUAL_ADAPTER_CONFIGURE \
	INTERCEPTOR_IMPLEMENTS_ROUTE_MODIFY
.rem
.rem NDIS 5 options
.rem
.set drv_defs_ndis5 \
	NDIS_MINIPORT_DRIVER=1 \
	NDIS50=1 \
	NDIS50_MINIPORT=1
.rem
.rem NDIS 6 options
.rem
.set drv_defs_ndis6 \
	NDIS_MINIPORT_DRIVER \
	NDIS60 \
	NDIS60_MINIPORT \
	NDIS_SUPPORT_NDIS6=1 \
	NDIS61 \
	NDIS_SUPPORT_NDIS61=1 \
	NDIS620 \
	NDIS_SUPPORT_NDIS620=1
.rem
.rem Values for each platform.
.rem
.set drv_defs_w2k {any_defs_w2k} {drv_defs} {drv_defs_ndis5} \
	_WIN2K_COMPAT_SLIST_USAGE
.set drv_defs_wxp {any_defs_wxp} {drv_defs} {drv_defs_ndis5}
.set drv_defs_wnet {any_defs_wnet} {drv_defs} {drv_defs_ndis5}
.set drv_defs_wlh {any_defs_wlh} {drv_defs} {drv_defs_ndis6}
.set drv_defs_win7 {any_defs_win7} {drv_defs} {drv_defs_ndis6}
.set drv_defs_wlhndis5 {any_defs_wlhndis5} {drv_defs} {drv_defs_ndis5}
.set drv_defs_win7ndis5 {any_defs_win7ndis5} {drv_defs} {drv_defs_ndis5}
.rem
.rem Debug/optimization options.
.rem
.set drv_defs_dbg \
	DBG \
	DEBUG_LIGHT
.set drv_defs_rel
.rem
.rem Values for each platform/configuration combination.
.rem
.set drv_defs_w2k_debug             {drv_defs_w2k} {drv_defs_dbg}
.set drv_defs_w2k_release           {drv_defs_w2k} {drv_defs_rel}
.set drv_defs_wxp_debug             {drv_defs_wxp} {drv_defs_dbg}
.set drv_defs_wxp_release           {drv_defs_wxp} {drv_defs_rel}
.set drv_defs_wnet_debug            {drv_defs_wnet} {drv_defs_dbg}
.set drv_defs_wnet_release          {drv_defs_wnet} {drv_defs_rel}
.set drv_defs_wlh_debug             {drv_defs_wlh} {drv_defs_dbg}
.set drv_defs_wlh_release           {drv_defs_wlh} {drv_defs_rel}
.set drv_defs_win7_debug            {drv_defs_win7} {drv_defs_dbg}
.set drv_defs_win7_release          {drv_defs_win7} {drv_defs_rel}
.set drv_defs_wlhndis5_debug       {drv_defs_wlhndis5} {drv_defs_dbg}
.set drv_defs_wlhndis5_release     {drv_defs_wlhndis5} {drv_defs_rel}
.set drv_defs_win7ndis5_debug      {drv_defs_win7ndis5} {drv_defs_dbg}
.set drv_defs_win7ndis5_release    {drv_defs_win7ndis5} {drv_defs_rel}
.rem
.rem C compiler options for application objects.
.rem -------------------------------------------
.rem
.rem Values for each platform/configuration combination.
.rem
.set drv_cflags_w2k_debug             {any_cflags}
.set drv_cflags_w2k_release           {any_cflags}
.set drv_cflags_wxp_debug             {any_cflags}
.set drv_cflags_wxp_release           {any_cflags}
.set drv_cflags_wnet_debug            {any_cflags}
.set drv_cflags_wnet_release          {any_cflags}
.set drv_cflags_wlh_debug             {any_cflags}
.set drv_cflags_wlh_release           {any_cflags}
.set drv_cflags_win7_debug            {any_cflags}
.set drv_cflags_win7_release          {any_cflags}
.set drv_cflags_wlhndis5_debug       {any_cflags}
.set drv_cflags_wlhndis5_release     {any_cflags}
.set drv_cflags_win7ndis5_debug      {any_cflags}
.set drv_cflags_win7ndis5_release    {any_cflags}
.rem
.rem Additional libraries for drivers.
.rem ---------------------------------
.rem
.rem All targets.
.rem
.set drv_libs {any_libs} \
	BufferOverflowK.lib \
	ntoskrnl.lib \
	hal.lib \
	wmilib.lib \
	ndis.lib
.rem
.rem Values for each platform.
.rem
.set drv_libs_w2k {drv_libs} \
	sehupd.lib \
	tdi.lib
.set drv_libs_wxp {drv_libs} \
	sehupd.lib \
	tdi.lib
.set drv_libs_wnet {drv_libs} \
	sehupd.lib \
	tdi.lib
.set drv_libs_wlh {drv_libs} \
	netio.lib
.set drv_libs_win7 {drv_libs} \
	netio.lib
.set drv_libs_wlhndis5 {drv_libs} \
	tdi.lib
.set drv_libs_win7ndis5 {drv_libs} \
	tdi.lib
.rem
.rem WDK target types.
.rem -----------------
.rem
.set targettype_driver   DRIVER
.set targettype_drvlib   DRIVER_LIBRARY
.set targettype_custom   NOTARGET
.rem
.rem Calculate build platforms.
.rem --------------------------
.rem
.rem Set project platforms to given platforms if empty.
.rem
.set project_platforms_empty yes
.for platform {project_platforms}
.set project_platforms_empty
.rof
.for dummy {project_platforms_empty}
.set project_platforms {platforms}
.rof
.rem Calculate intersection of given platforms and project platforms.
.rem
.for platform {project_platforms}
.set platform_{platform}
.rof
.for platform {platforms}
.set platform_{platform} yes
.rof
.set build_platforms
.for platform {project_platforms}
.for dummy {platform_{platform}}
.set build_platforms {build_platforms} {platform}
.rof
.rof
.rem Init conversion to WDK platforms.
.rem
.for platform {platforms}
.set wplatforms_{platform}
.rof
.for platform {project_platforms}
.set wplatforms_{platform}
.rof
.set wplatforms_all              w2k wxp wnet wlh win7 wlhndis5 win7ndis5
.set wplatforms_win32            w2k wxp wnet
.set wplatforms_x64              wnet
.set wplatforms_win32vista       wlh
.set wplatforms_x64vista         wlh
.set wplatforms_win32win7        win7
.set wplatforms_x64win7          win7
.set wplatforms_win32vistandis5  wlhndis5
.set wplatforms_x64vistandis5    wlhndis5
.set wplatforms_win32win7ndis5   win7ndis5
.set wplatforms_x64win7ndis5     win7ndis5
.rem
.rem Convert to WDK platforms.
.rem
.for wplatform {wplatforms_all}
.set enabled_{wplatform}
.rof
.for platform {build_platforms}
.for wplatform {wplatforms_{platform}}
.set enabled_{wplatform} yes
.rof
.rof
.set build_wplatforms
.for wplatform {wplatforms_all}
.for dummy {enabled_{wplatform}}
.set build_wplatforms {build_wplatforms} {wplatform}
.rof
.rof
.rem Set up build options for each platform and configuration.
.rem ---------------------------------------------------------
.rem
.for wplatform {build_wplatforms}
.for configuration {configurations}
.set defs_{wplatform}_{configuration} \
	{{prefix}_defs_{wplatform}_{configuration}} \
	{project_defs}
.set cflags_{wplatform}_{configuration} \
	{{prefix}_cflags_{wplatform}_{configuration}} \
	{project_cflags}
.set libs_{wplatform}_{configuration} \
	{{prefix}_libs_{wplatform}} \
	{project_libs}
.rof
.rof
.rem Begin `makefile'.
.rem -----------------
.rem
.out {blddir}\\{project_name}\\makefile
.rem
.rem Include system makefile for supported platforms.
.rem

!IF 0\
.for wplatform {build_wplatforms}
.for configuration {configurations}
 \\
	|| ("$(DDK_TARGET_OS)"=="{ddk_target_os_{wplatform}}" && \\
	    "$(DDKBUILDENV)"=="{ddkbuildenv_{configuration}}")\
.rof
.rof
.rem The following empty line is significant.


SRCTOP = {srctop}

!INCLUDE $(NTMAKEENV)\\makefile.def

!ELSE

!MESSAGE This target is not enabled in this build environment.

!ENDIF

.rem End `makefile'.
.rem -------------------
.tuo
.rem Begin `sources' file.
.rem ----------------------
.rem
.out {blddir}\\{project_name}\\sources
.rem
TARGETNAME={project_name}

TARGETTYPE={targettype_{project_type}}

!IF ("$(DDK_TARGET_OS)"!="Win7")
TARGETPATH=obj
!ENDIF

NTTARGETFILE0=generated_files

INCLUDES=\\
\..\\include\
.for incdir {project_incdirs}
;\\
$(SRCTOP)\\{incdir}\
.rof
.rem The following empty line is significant.


SOURCES=\
.for src {srcs}
 \\
	{src}\
.rof
.for rsrc {rsrcs}
 \\
	{rsrc}\
.rof
.rem The following empty line is significant.


TARGETLIBS=\
.for dependency {project_dependencies}
 \\
	\..\\{dependency}\\obj$(BUILD_ALT_DIR)\\$(TARGET_DIRECTORY)\\{dependency}.lib\
.rof
.rem The following empty line is significant.


.for wplatform {build_wplatforms}
.for configuration {configurations}
!IF "$(DDK_TARGET_OS)"=="{ddk_target_os_{wplatform}}"
!IF "$(DDKBUILDENV)"=="{ddkbuildenv_{configuration}}"

C_DEFINES =\
.for def {defs_{wplatform}_{configuration}}
 \\
	/D{def}\
.rof
.for cflag {cflags_{wplatform}_{configuration}}
 \\
	{cflag}\
.rof
.rem The following empty line is significant.


TARGETLIBS= \\
	$(TARGETLIBS)\
.for lib {libs_{wplatform}_{configuration}}
 \\
	$(DDK_LIB_PATH)\\{lib}\
.rof
.rem The following empty line is significant.


!ENDIF
!ENDIF

.rof
.rof

.rem
.rem End `sources' file.
.rem -------------------
.tuo
.rem Begin `makefile.inc'.
.rem -----------------
.rem
.out {blddir}\\{project_name}\\makefile.inc
.rem
GENERATED_FILES =

.rem Source copy rules.
.rem
.for src {srcs}
GENERATED_FILES = $(GENERATED_FILES) {src}

{src}: $(SRCTOP)\\{dir_{src}}\\{src}
	copy "$(SRCTOP)\\{dir_{src}}\\{src}" {src}

.rof
.rem Source copy rules.
.rem
.for rsrc {rsrcs}
GENERATED_FILES = $(GENERATED_FILES) {rsrc}

{rsrc}: $(SRCTOP)\\{dir_{rsrc}}\\{rsrc}
	copy "$(SRCTOP)\\{dir_{rsrc}}\\{rsrc}" {rsrc}

.rof
.rem Header copy rules.
.rem
.for hdr {hdrs}
GENERATED_FILES = $(GENERATED_FILES) {hdr}

{hdr}: $(SRCTOP)\\{dir_{hdr}}\\{hdr}
	copy "$(SRCTOP)\\{dir_{hdr}}\\{hdr}" {hdr}

.rof
.rem
.rem Iterate custom commands.
.rem
.for tag {custom_tags}
.rem
.rem Check if platform restrictions apply for this tag.
.rem
.set custom_platforms_nonempty
.for platform {custom_platforms_{tag}}
.set custom_platforms_nonempty yes
.rof
.rem Convert platform restrictions to WDK platforms.
.rem
.for wplatform {wplatforms_all}
.set enabled_{wplatform}
.rof
.for platform {custom_platforms_{tag}}
.for wplatform {wplatforms_{platform}}
.set enabled_{wplatform} yes
.rof
.rof
.set custom_wplatforms
.for wplatform {wplatforms_all}
.for dummy {enabled_{wplatform}}
.set custom_wplatforms {custom_wplatforms} {wplatform}
.rof
.rof
.rem Output platform restrictions, if any.
.rem
.for dummy {custom_platforms_nonempty}
.for wplatform {build_wplatforms}
.set enabled_{wplatform}
.rof
.for wplatform {custom_wplatforms}
.set enabled_{wplatform} yes
.rof
!IF 0\
.for wplatform {build_wplatforms}
.for dummy2 {enabled_{wplatform}}
 \\
	|| "$(DDK_TARGET_OS)"=="{ddk_target_os_{wplatform}}"\
.rof
.rof
.rem The following empty line is significant.


.rof
GENERATED_FILES = $(GENERATED_FILES) {custom_output_{tag}}

.rem Output rule.
.rem
{custom_output_{tag}}: {custom_input_{tag}}
	{custom_command_{tag}}

.rem
.rem Close platform restrictions, if any.
.rem
.for dummy {custom_platforms_nonempty}
.for wplatform {build_wplatforms}
.for dummy2 {enabled_{wplatform}}
.rof
.rof
!ENDIF

.rof
.rem End iterating custom commands.
.rof
generated_files: $(GENERATED_FILES)
	echo >generated_files

.rem End `makefile.inc'.
.rem -------------------
.tuo
.rem End.
.rem ----
.rof
