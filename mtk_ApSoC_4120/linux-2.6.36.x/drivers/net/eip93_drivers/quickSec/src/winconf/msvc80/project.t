.rem
.rem project.t
.rem
.rem Copyright:
.rem          Copyright (c) 2007-2008 SFNT Finland Oy.
.rem               All rights reserved
.rem
.rem Visual Studio 2005 project file template.
.rem
.rem
.rem Platform names used in this file.
.rem ---------------------------------
.rem
.rem win32
.rem x64
.rem win32vista
.rem x64vista
.rem std500armv4i
.rem std500x86
.rem std500sh4
.rem std500mipsii
.rem std500mipsii_fp
.rem std500mipsiv
.rem std500mipsiv_fp
.rem ppc50armv4i
.rem sp50armv4i
.rem wm6std
.rem wm6pro
.rem
.rem Configuration names used in this file.
.rem --------------------------------------
.rem
.rem debug
.rem release
.rem
.rem Visual Studio 2005 names for platforms.
.rem ---------------------------------------
.rem
.set name_win32            Win32
.set name_x64              x64
.set name_win32vista       Win32
.set name_x64vista         x64
.set name_std500armv4i     STANDARDSDK_500 (ARMV4I)
.set name_std500x86        STANDARDSDK_500 (x86)
.set name_std500sh4        STANDARDSDK_500 (SH4)
.set name_std500mipsii     STANDARDSDK_500 (MIPSII)
.set name_std500mipsii_fp  STANDARDSDK_500 (MIPSII_FP)
.set name_std500mipsiv     STANDARDSDK_500 (MIPSIV)
.set name_std500mipsiv_fp  STANDARDSDK_500 (MIPSIV_FP)
.set name_ppc50armv4i      Windows Mobile 5.0 Pocket PC SDK (ARMV4I)
.set name_sp50armv4i       Windows Mobile 5.0 Smartphone SDK (ARMV4I)
.set name_wm6std           Windows Mobile 6 Standard SDK (ARMV4I)
.set name_wm6pro           Windows Mobile 6 Professional SDK (ARMV4I)
.rem
.rem Visual Studio 2005 names for configurations.
.rem --------------------------------------------
.rem
.set name_debug   Debug
.set name_release Release
.rem
.rem Header directories for all objects.
.rem -----------------------------------
.rem
.rem All targets.
.rem
.set any_incdirs
.rem
.rem Pre-vista desktop targets.
.rem
.set any_incdirs_dtv5 {any_incdirs}
.rem
.rem Vista desktop targets.
.rem
.set any_incdirs_dtv6 {any_incdirs}
.rem
.rem Mobile targets based on CE 5.0.
.rem
.set any_incdirs_ce5 {any_incdirs} \
	$(_ACP_INCLUDE) \
	$(WINCE500)\\PUBLIC\\COMMON\\SDK\\INC \
	$(WINCE500)\\PUBLIC\\COMMON\\DDK\\INC \
	$(WINCE500)\\PUBLIC\\COMMON\\OAK\\INC
.rem
.rem Mobile targets based on CE 6.0.
.rem
.set any_incdirs_ce6 {any_incdirs} \
	$(_ACP_INCLUDE) \
	$(WINCE600)\\PUBLIC\\COMMON\\SDK\\INC \
	$(WINCE600)\\PUBLIC\\COMMON\\DDK\\INC \
	$(WINCE600)\\PUBLIC\\COMMON\\OAK\\INC
.rem
.rem C Preprocessor options for all objects.
.rem ---------------------------------------
.rem
.rem All targets.
.rem
.set any_defs
.rem
.rem 32-bit pre-Vista desktop targets.
.rem
.set any_defs_dt32v5 \
	_WIN32_WINNT=0x0501 \
	WINVER=0x0501 \
	NTDDI_VERSION=0x05010000
.rem
.rem 64-bit pre-Vista desktop targets.
.rem
.set any_defs_dt64v5 \
	_WIN32_WINNT=0x0502 \
	WINVER=0x0502 \
	NTDDI_VERSION=0x05020000
.rem
.rem 32-bit Vista desktop targets.
.rem
.set any_defs_dt32v6 \
	_WIN32_WINNT=0x0600 \
	WINVER=0x0600 \
	NTDDI_VERSION=0x06000000
.rem
.rem 64-bit Vista desktop targets.
.rem
.set any_defs_dt64v6 \
	_WIN32_WINNT=0x0600 \
	WINVER=0x0600 \
	NTDDI_VERSION=0x06000000
.rem
.rem Mobile targets.
.rem
.set any_defs_ce \
	_WIN32_WCE=$(CEVER) \
	UNDER_CE \
	WINCE \
	$(ARCHFAM) \
	$(_ARCHFAM_) \
	UNICODE \
	_UNICODE
.rem
.rem C Compiler options for all objects.
.rem -----------------------------------
.rem
.rem All targets.
.rem
.set any_cflags \
	/TC \
	/Gm \
	/W3 \
	/Zi \
	/wd4018 \
	/wd4267 \
	/wd4996 \
	/wd4244 \
	/wd4312 \
	/wd4311
.rem
.rem Desktop targets.
.rem
.set any_cflags_dt {any_cflags} \
	/Wp64
.rem
.rem Mobile targets.
.rem
.set any_cflags_ce {any_cflags} \
	/GS-
.rem
.rem Debug/optimization options.
.rem
.set any_cflags_dbg
.set any_cflags_rel
.rem
.rem Library directories for all executables.
.rem ----------------------------------------
.rem
.rem All targets.
.rem
.set any_libdirs
.rem
.rem Values for each platform/configuration combination.
.rem
.set any_libdirs_win32_debug               {any_libdirs}
.set any_libdirs_win32_release             {any_libdirs}
.set any_libdirs_x64_debug                 {any_libdirs}
.set any_libdirs_x64_release               {any_libdirs}
.set any_libdirs_win32vista_debug          {any_libdirs}
.set any_libdirs_win32vista_release        {any_libdirs}
.set any_libdirs_x64vista_debug            {any_libdirs}
.set any_libdirs_x64vista_release          {any_libdirs}
.set any_libdirs_std500armv4i_debug        {any_libdirs} \
	$(_ACP_LIB) \
	$(WINCE500)\\PUBLIC\\COMMON\\OAK\\LIB\\ARMV4I\\DEBUG
.set any_libdirs_std500armv4i_release      {any_libdirs} \
	$(_ACP_LIB) \
	$(WINCE500)\\PUBLIC\\COMMON\\OAK\\LIB\\ARMV4I\\RETAIL
.set any_libdirs_std500x86_debug           {any_libdirs} \
	$(_ACP_LIB) \
	$(WINCE500)\\PUBLIC\\COMMON\\OAK\\LIB\\X86\\DEBUG
.set any_libdirs_std500x86_release         {any_libdirs} \
	$(_ACP_LIB) \
	$(WINCE500)\\PUBLIC\\COMMON\\OAK\\LIB\\X86\\RETAIL
.set any_libdirs_std500sh4_debug           {any_libdirs} \
	$(_ACP_LIB) \
	$(WINCE500)\\PUBLIC\\COMMON\\OAK\\LIB\\SH4\\DEBUG
.set any_libdirs_std500sh4_release         {any_libdirs} \
	$(_ACP_LIB) \
	$(WINCE500)\\PUBLIC\\COMMON\\OAK\\LIB\\SH4\\RETAIL
.set any_libdirs_std500mipsii_debug        {any_libdirs} \
	$(_ACP_LIB) \
	$(WINCE500)\\PUBLIC\\COMMON\\OAK\\LIB\\MIPSII\\DEBUG
.set any_libdirs_std500mipsii_release      {any_libdirs} \
	$(_ACP_LIB) \
	$(WINCE500)\\PUBLIC\\COMMON\\OAK\\LIB\\MIPSII\\RETAIL
.set any_libdirs_std500mipsii_fp_debug     {any_libdirs} \
	$(_ACP_LIB) \
	$(WINCE500)\\PUBLIC\\COMMON\\OAK\\LIB\\MIPSII_FP\\DEBUG
.set any_libdirs_std500mipsii_fp_release   {any_libdirs} \
	$(_ACP_LIB) \
	$(WINCE500)\\PUBLIC\\COMMON\\OAK\\LIB\\MIPSII_FP\\RETAIL
.set any_libdirs_std500mipsiv_debug        {any_libdirs} \
	$(_ACP_LIB) \
	$(WINCE500)\\PUBLIC\\COMMON\\OAK\\LIB\\MIPSIV\\DEBUG
.set any_libdirs_std500mipsiv_release      {any_libdirs} \
	$(_ACP_LIB) \
	$(WINCE500)\\PUBLIC\\COMMON\\OAK\\LIB\\MIPSIV\\RETAIL
.set any_libdirs_std500mipsiv_fp_debug     {any_libdirs} \
	$(_ACP_LIB) \
	$(WINCE500)\\PUBLIC\\COMMON\\OAK\\LIB\\MIPSIV_FP\\DEBUG
.set any_libdirs_std500mipsiv_fp_release   {any_libdirs} \
	$(_ACP_LIB) \
	$(WINCE500)\\PUBLIC\\COMMON\\OAK\\LIB\\MIPSIV_FP\\RETAIL
.set any_libdirs_ppc50armv4i_debug         {any_libdirs} \
	$(_ACP_LIB) \
	$(WINCE500)\\PUBLIC\\COMMON\\OAK\\LIB\\ARMV4I\\DEBUG
.set any_libdirs_ppc50armv4i_release       {any_libdirs} \
	$(_ACP_LIB) \
	$(WINCE500)\\PUBLIC\\COMMON\\OAK\\LIB\\ARMV4I\\RETAIL
.set any_libdirs_sp50armv4i_debug          {any_libdirs} \
	$(_ACP_LIB) \
	$(WINCE500)\\PUBLIC\\COMMON\\OAK\\LIB\\ARMV4I\\DEBUG
.set any_libdirs_sp50armv4i_release        {any_libdirs} \
	$(_ACP_LIB) \
	$(WINCE500)\\PUBLIC\\COMMON\\OAK\\LIB\\ARMV4I\\RETAIL
.set any_libdirs_wm6std_debug              {any_libdirs} \
	$(_ACP_LIB) \
	$(WINCE500)\\PUBLIC\\COMMON\\OAK\\LIB\\ARMV4I\\DEBUG
.set any_libdirs_wm6std_release            {any_libdirs} \
	$(_ACP_LIB) \
	$(WINCE500)\\PUBLIC\\COMMON\\OAK\\LIB\\ARMV4I\\RETAIL
.set any_libdirs_wm6pro_debug              {any_libdirs} \
	$(_ACP_LIB) \
	$(WINCE500)\\PUBLIC\\COMMON\\OAK\\LIB\\ARMV4I\\DEBUG
.set any_libdirs_wm6pro_release            {any_libdirs} \
	$(_ACP_LIB) \
	$(WINCE500)\\PUBLIC\\COMMON\\OAK\\LIB\\ARMV4I\\RETAIL
.rem
.rem Linker options for all executables.
.rem -----------------------------------
.rem
.rem All targets.
.rem
.set any_ldflags
.rem
.rem 32-bit pre-Vista desktop targets.
.rem
.set any_ldflags_dt32v5 {any_ldflags} \
	/MACHINE:X86
.rem
.rem 64-bit pre-Vista desktop targets.
.rem
.set any_ldflags_dt64v5 {any_ldflags} \
	/MACHINE:X64
.rem
.rem 32-bit Vista desktop targets.
.rem
.set any_ldflags_dt32v6 {any_ldflags} \
	/MACHINE:X86
.rem
.rem 64-bit Vista desktop targets.
.rem
.set any_ldflags_dt64v6 {any_ldflags} \
	/MACHINE:X64
.rem
.rem Mobile targets based on CE 5.0.
.rem
.set any_ldflags_ce5 {any_ldflags} \
	/SUBSYSTEM:WINDOWSCE,5.00
.rem
.rem Mobile targets based on Windows Mobile 5.0.
.rem
.set any_ldflags_wm5 {any_ldflags} \
	/SUBSYSTEM:WINDOWSCE,5.01
.rem
.rem Mobile targets based on Windows Mobile 6.
.rem
.set any_ldflags_wm6 {any_ldflags} \
	/SUBSYSTEM:WINDOWSCE,5.02
.rem
.rem Debug/optimization options.
.rem
.set any_ldflags_dbg
.set any_ldflags_rel
.rem
.rem Additional libraries for all executables.
.rem -----------------------------------------
.rem
.rem All targets.
.rem
.set any_libs
.rem
.rem Header directories for application objects.
.rem -------------------------------------------
.rem
.rem Pre-vista desktop targets.
.rem
.set app_incdirs_dtv5 {any_incdirs_dtv5}
.rem
.rem Vista desktop targets.
.rem
.set app_incdirs_dtv6 {any_incdirs_dtv6}
.rem
.rem Mobile targets based on CE 5.0.
.rem
.set app_incdirs_ce5 {any_incdirs_ce5}
.rem
.rem Mobile targets based on CE 6.0.
.rem
.set app_incdirs_ce6 {any_incdirs_ce6}
.rem
.rem Values for each platform.
.rem
.set app_incdirs_win32             {app_incdirs_dtv5}
.set app_incdirs_x64               {app_incdirs_dtv5}
.set app_incdirs_win32vista        {app_incdirs_dtv6}
.set app_incdirs_x64vista          {app_incdirs_dtv6}
.set app_incdirs_std500armv4i      {app_incdirs_ce5}
.set app_incdirs_std500x86         {app_incdirs_ce5}
.set app_incdirs_std500sh4         {app_incdirs_ce5}
.set app_incdirs_std500mipsii      {app_incdirs_ce5}
.set app_incdirs_std500mipsii_fp   {app_incdirs_ce5}
.set app_incdirs_std500mipsiv      {app_incdirs_ce5}
.set app_incdirs_std500mipsiv_fp   {app_incdirs_ce5}
.set app_incdirs_ppc50armv4i       {app_incdirs_ce5}
.set app_incdirs_sp50armv4i        {app_incdirs_ce5}
.set app_incdirs_wm6std            {app_incdirs_ce5}
.set app_incdirs_wm6pro            {app_incdirs_ce5}
.rem
.rem C preprocessor options for application objects.
.rem -----------------------------------------------
.rem
.rem All targets.
.rem
.set app_defs \
	WINDOWS \
	WIN32 \
	INTERCEPTOR_IMPLEMENTS_VIRTUAL_ADAPTER_CONFIGURE \
	INTERCEPTOR_IMPLEMENTS_ROUTE_MODIFY
.rem
.rem 32-bit pre-Vista desktop targets.
.rem
.set app_defs_dt32v5 {any_defs_dt32v5} {app_defs}
.rem
.rem 64-bit pre-Vista desktop targets.
.rem
.set app_defs_dt64v5 {any_defs_dt64v5} {app_defs}
.rem
.rem 32-bit Vista desktop targets.
.rem
.set app_defs_dt32v6 {any_defs_dt32v6} {app_defs}
.rem
.rem 64-bit Vista desktop targets.
.rem
.set app_defs_dt64v6 {any_defs_dt64v6} {app_defs}
.rem
.rem Mobile targets.
.rem
.set app_defs_ce {any_defs_ce} {app_defs}
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
.set app_defs_win32_debug             {app_defs_dt32v5} {app_defs_dbg}
.set app_defs_win32_release           {app_defs_dt32v5} {app_defs_rel}
.set app_defs_x64_debug               {app_defs_dt64v5} {app_defs_dbg}
.set app_defs_x64_release             {app_defs_dt64v5} {app_defs_rel}
.set app_defs_win32vista_debug        {app_defs_dt32v6} {app_defs_dbg}
.set app_defs_win32vista_release      {app_defs_dt32v6} {app_defs_rel}
.set app_defs_x64vista_debug          {app_defs_dt64v6} {app_defs_dbg}
.set app_defs_x64vista_release        {app_defs_dt64v6} {app_defs_rel}
.set app_defs_std500armv4i_debug      {app_defs_ce} {app_defs_dbg}
.set app_defs_std500armv4i_release    {app_defs_ce} {app_defs_rel}
.set app_defs_std500x86_debug         {app_defs_ce} {app_defs_dbg}
.set app_defs_std500x86_release       {app_defs_ce} {app_defs_rel}
.set app_defs_std500sh4_debug         {app_defs_ce} {app_defs_dbg}
.set app_defs_std500sh4_release       {app_defs_ce} {app_defs_rel}
.set app_defs_std500mipsii_debug      {app_defs_ce} {app_defs_dbg}
.set app_defs_std500mipsii_release    {app_defs_ce} {app_defs_rel}
.set app_defs_std500mipsii_fp_debug   {app_defs_ce} {app_defs_dbg}
.set app_defs_std500mipsii_fp_release {app_defs_ce} {app_defs_rel}
.set app_defs_std500mipsiv_debug      {app_defs_ce} {app_defs_dbg}
.set app_defs_std500mipsiv_release    {app_defs_ce} {app_defs_rel}
.set app_defs_std500mipsiv_fp_debug   {app_defs_ce} {app_defs_dbg}
.set app_defs_std500mipsiv_fp_release {app_defs_ce} {app_defs_rel}
.set app_defs_ppc50armv4i_debug       {app_defs_ce} {app_defs_dbg} \
	$(PLATFORMDEFINES)
.set app_defs_ppc50armv4i_release     {app_defs_ce} {app_defs_rel} \
	$(PLATFORMDEFINES)
.set app_defs_sp50armv4i_debug        {app_defs_ce} {app_defs_dbg} \
	$(PLATFORMDEFINES)
.set app_defs_sp50armv4i_release      {app_defs_ce} {app_defs_rel} \
	$(PLATFORMDEFINES)
.set app_defs_wm6std_debug            {app_defs_ce} {app_defs_dbg} \
	$(PLATFORMDEFINES)
.set app_defs_wm6std_release          {app_defs_ce} {app_defs_rel} \
	$(PLATFORMDEFINES)
.set app_defs_wm6pro_debug            {app_defs_ce} {app_defs_dbg} \
	$(PLATFORMDEFINES)
.set app_defs_wm6pro_release          {app_defs_ce} {app_defs_rel} \
	$(PLATFORMDEFINES)
.rem
.rem C compiler options for application objects.
.rem -------------------------------------------
.rem
.rem Desktop targets.
.rem
.set app_cflags_dt {any_cflags_dt}
.rem
.rem Mobile targets.
.rem
.set app_cflags_ce {any_cflags_ce}
.rem
.rem Desktop debug/optimization options.
.rem
.set app_cflags_dtdbg {any_cflags_dbg} \
	/RTC1 \
	/Od
.set app_cflags_dtrel {any_cflags_rel} \
	/O2
.rem
.rem Mobile debug/optimization options.
.rem
.set app_cflags_cedbg {any_cflags_dbg} \
	/Od
.set app_cflags_cerel {any_cflags_rel} \
	/Od
.rem
.rem Values for each platform/configuration combination.
.rem
.set app_cflags_win32_debug             {app_cflags_dt} {app_cflags_dtdbg}
.set app_cflags_win32_release           {app_cflags_dt} {app_cflags_dtrel}
.set app_cflags_x64_debug               {app_cflags_dt} {app_cflags_dtdbg}
.set app_cflags_x64_release             {app_cflags_dt} {app_cflags_dtrel}
.set app_cflags_win32vista_debug        {app_cflags_dt} {app_cflags_dtdbg}
.set app_cflags_win32vista_release      {app_cflags_dt} {app_cflags_dtrel}
.set app_cflags_x64vista_debug          {app_cflags_dt} {app_cflags_dtdbg}
.set app_cflags_x64vista_release        {app_cflags_dt} {app_cflags_dtrel}
.set app_cflags_std500armv4i_debug      {app_cflags_ce} {app_cflags_cedbg}
.set app_cflags_std500armv4i_release    {app_cflags_ce} {app_cflags_cerel} \
	/QRthumb
.set app_cflags_std500x86_debug         {app_cflags_ce} {app_cflags_cedbg}
.set app_cflags_std500x86_release       {app_cflags_ce} {app_cflags_cerel}
.set app_cflags_std500sh4_debug         {app_cflags_ce} {app_cflags_cedbg}
.set app_cflags_std500sh4_release       {app_cflags_ce} {app_cflags_cerel}
.set app_cflags_std500mipsii_debug      {app_cflags_ce} {app_cflags_cedbg}
.set app_cflags_std500mipsii_release    {app_cflags_ce} {app_cflags_cerel}
.set app_cflags_std500mipsii_fp_debug   {app_cflags_ce} {app_cflags_cedbg}
.set app_cflags_std500mipsii_fp_release {app_cflags_ce} {app_cflags_cerel}
.set app_cflags_std500mipsiv_debug      {app_cflags_ce} {app_cflags_cedbg}
.set app_cflags_std500mipsiv_release    {app_cflags_ce} {app_cflags_cerel}
.set app_cflags_std500mipsiv_fp_debug   {app_cflags_ce} {app_cflags_cedbg}
.set app_cflags_std500mipsiv_fp_release {app_cflags_ce} {app_cflags_cerel}
.set app_cflags_ppc50armv4i_debug       {app_cflags_ce} {app_cflags_cedbg}
.set app_cflags_ppc50armv4i_release     {app_cflags_ce} {app_cflags_cerel} \
	/QRthumb
.set app_cflags_sp50armv4i_debug        {app_cflags_ce} {app_cflags_cedbg}
.set app_cflags_sp50armv4i_release      {app_cflags_ce} {app_cflags_cerel} \
	/QRthumb
.set app_cflags_wm6std_debug            {app_cflags_ce} {app_cflags_cedbg}
.set app_cflags_wm6std_release          {app_cflags_ce} {app_cflags_cerel} \
	/QRthumb
.set app_cflags_wm6pro_debug            {app_cflags_ce} {app_cflags_cedbg}
.set app_cflags_wm6pro_release          {app_cflags_ce} {app_cflags_cerel} \
	/QRthumb
.rem
.rem Library directories for applications.
.rem -------------------------------------
.rem
.rem All targets.
.rem
.set app_libdirs {any_libdirs}
.rem
.rem Values for each platform/configuration combination.
.rem
.set app_libdirs_win32_debug \
	{any_libdirs_win32_debug} {app_libdirs}
.set app_libdirs_win32_release \
	{any_libdirs_win32_release} {app_libdirs}
.set app_libdirs_x64_debug \
	{any_libdirs_x64_debug} {app_libdirs}
.set app_libdirs_x64_release \
	{any_libdirs_x64_release} {app_libdirs}
.set app_libdirs_win32vista_debug \
	{any_libdirs_win32vista_debug} {app_libdirs}
.set app_libdirs_win32vista_release \
	{any_libdirs_win32vista_release} {app_libdirs}
.set app_libdirs_x64vista_debug \
	{any_libdirs_x64vista_debug} {app_libdirs}
.set app_libdirs_x64vista_release \
	{any_libdirs_x64vista_release} {app_libdirs}
.set app_libdirs_std500armv4i_debug \
	{any_libdirs_std500armv4i_debug} {app_libdirs}
.set app_libdirs_std500armv4i_release \
	{any_libdirs_std500armv4i_release} {app_libdirs}
.set app_libdirs_std500x86_debug \
	{any_libdirs_std500x86_debug} {app_libdirs}
.set app_libdirs_std500x86_release \
	{any_libdirs_std500x86_release} {app_libdirs}
.set app_libdirs_std500sh4_debug \
	{any_libdirs_std500sh4_debug} {app_libdirs}
.set app_libdirs_std500sh4_release \
	{any_libdirs_std500sh4_release} {app_libdirs}
.set app_libdirs_std500mipsii_debug \
	{any_libdirs_std500mipsii_debug} {app_libdirs}
.set app_libdirs_std500mipsii_release \
	{any_libdirs_std500mipsii_release} {app_libdirs}
.set app_libdirs_std500mipsii_fp_debug \
	{any_libdirs_std500mipsii_fp_debug} {app_libdirs}
.set app_libdirs_std500mipsii_fp_release \
	{any_libdirs_std500mipsii_fp_release} {app_libdirs}
.set app_libdirs_std500mipsiv_debug \
	{any_libdirs_std500mipsiv_debug} {app_libdirs}
.set app_libdirs_std500mipsiv_release \
	{any_libdirs_std500mipsiv_release} {app_libdirs}
.set app_libdirs_std500mipsiv_fp_debug \
	{any_libdirs_std500mipsiv_fp_debug} {app_libdirs}
.set app_libdirs_std500mipsiv_fp_release \
	{any_libdirs_std500mipsiv_fp_release} {app_libdirs}
.set app_libdirs_ppc50armv4i_debug \
	{any_libdirs_ppc50armv4i_debug} {app_libdirs}
.set app_libdirs_ppc50armv4i_release \
	{any_libdirs_ppc50armv4i_release} {app_libdirs}
.set app_libdirs_sp50armv4i_debug \
	{any_libdirs_sp50armv4i_debug} {app_libdirs}
.set app_libdirs_sp50armv4i_release \
	{any_libdirs_sp50armv4i_release} {app_libdirs}
.set app_libdirs_wm6std_debug \
	{any_libdirs_wm6std_debug} {app_libdirs}
.set app_libdirs_wm6std_release \
	{any_libdirs_wm6std_release} {app_libdirs}
.set app_libdirs_wm6pro_debug \
	{any_libdirs_wm6pro_debug} {app_libdirs}
.set app_libdirs_wm6pro_release \
	{any_libdirs_wm6pro_release} {app_libdirs}
.rem
.rem Linker options for applications.
.rem --------------------------------
.rem
.rem Desktop targets.
.rem
.set app_ldflags_dt
.rem
.rem 32-bit pre-Vista desktop targets.
.rem
.set app_ldflags_dt32v5 {any_ldflags_dt32v5} {app_ldflags_dt}
.rem
.rem 64-bit pre-Vista desktop targets.
.rem
.set app_ldflags_dt64v5 {any_ldflags_dt64v5} {app_ldflags_dt}
.rem
.rem 32-bit Vista desktop targets.
.rem
.set app_ldflags_dt32v6 {any_ldflags_dt32v6} {app_ldflags_dt}
.rem
.rem 64-bit Vista desktop targets.
.rem
.set app_ldflags_dt64v6 {any_ldflags_dt64v6} {app_ldflags_dt}
.rem
.rem Mobile targets.
.rem
.set app_ldflags_ce \
	/NODEFAULTLIB:libc.lib \
	/NODEFAULTLIB:libcd.lib \
	/NODEFAULTLIB:msvcrt.lib \
	/NODEFAULTLIB:libcmtd.lib
.rem
.rem Mobile targets based on CE 5.0.
.rem
.set app_ldflags_ce5 {any_ldflags_ce5} {app_ldflags_ce}
.rem
.rem Mobile targets based on Windows Mobile 5.0.
.rem
.set app_ldflags_wm5 {any_ldflags_wm5} {app_ldflags_ce}
.rem
.rem Mobile targets based on Windows Mobile 6.
.rem
.set app_ldflags_wm6 {any_ldflags_wm6} {app_ldflags_ce}
.rem
.rem Debug/optimization options.
.rem
.set app_ldflags_dbg {any_ldflags_dbg} \
	/INCREMENTAL \
	/DEBUG
.set app_ldflags_rel {any_ldflags_rel} \
	/INCREMENTAL:NO \
	/OPT:REF \
	/OPT:ICF
.rem
.rem Values for each platform/configuration combination.
.rem
.set app_ldflags_win32_debug             {app_ldflags_dt32v5} {app_ldflags_dbg}
.set app_ldflags_win32_release           {app_ldflags_dt32v5} {app_ldflags_rel}
.set app_ldflags_x64_debug               {app_ldflags_dt64v5} {app_ldflags_dbg}
.set app_ldflags_x64_release             {app_ldflags_dt64v5} {app_ldflags_rel}
.set app_ldflags_win32vista_debug        {app_ldflags_dt32v6} {app_ldflags_dbg}
.set app_ldflags_win32vista_release      {app_ldflags_dt32v6} {app_ldflags_rel}
.set app_ldflags_x64vista_debug          {app_ldflags_dt64v6} {app_ldflags_dbg}
.set app_ldflags_x64vista_release        {app_ldflags_dt64v6} {app_ldflags_rel}
.set app_ldflags_std500armv4i_debug      {app_ldflags_ce5} {app_ldflags_dbg}
.set app_ldflags_std500armv4i_release    {app_ldflags_ce5} {app_ldflags_rel}
.set app_ldflags_std500x86_debug         {app_ldflags_ce5} {app_ldflags_dbg}
.set app_ldflags_std500x86_release       {app_ldflags_ce5} {app_ldflags_rel}
.set app_ldflags_std500sh4_debug         {app_ldflags_ce5} {app_ldflags_dbg}
.set app_ldflags_std500sh4_release       {app_ldflags_ce5} {app_ldflags_rel}
.set app_ldflags_std500mipsii_debug      {app_ldflags_ce5} {app_ldflags_dbg}
.set app_ldflags_std500mipsii_release    {app_ldflags_ce5} {app_ldflags_rel}
.set app_ldflags_std500mipsii_fp_debug   {app_ldflags_ce5} {app_ldflags_dbg}
.set app_ldflags_std500mipsii_fp_release {app_ldflags_ce5} {app_ldflags_rel}
.set app_ldflags_std500mipsiv_debug      {app_ldflags_ce5} {app_ldflags_dbg}
.set app_ldflags_std500mipsiv_release    {app_ldflags_ce5} {app_ldflags_rel}
.set app_ldflags_std500mipsiv_fp_debug   {app_ldflags_ce5} {app_ldflags_dbg}
.set app_ldflags_std500mipsiv_fp_release {app_ldflags_ce5} {app_ldflags_rel}
.set app_ldflags_ppc50armv4i_debug       {app_ldflags_wm5} {app_ldflags_dbg}
.set app_ldflags_ppc50armv4i_release     {app_ldflags_wm5} {app_ldflags_rel}
.set app_ldflags_sp50armv4i_debug        {app_ldflags_wm5} {app_ldflags_dbg}
.set app_ldflags_sp50armv4i_release      {app_ldflags_wm5} {app_ldflags_rel}
.set app_ldflags_wm6std_debug            {app_ldflags_wm6} {app_ldflags_dbg}
.set app_ldflags_wm6std_release          {app_ldflags_wm6} {app_ldflags_rel}
.set app_ldflags_wm6pro_debug            {app_ldflags_wm6} {app_ldflags_dbg}
.set app_ldflags_wm6pro_release          {app_ldflags_wm6} {app_ldflags_rel}
.rem
.rem Additional libraries for applications.
.rem --------------------------------------
.rem
.rem Desktop targets.
.rem
.set app_libs_dt {any_libs} ws2_32.lib
.rem
.rem Mobile targets.
.rem
.set app_libs_ce {any_libs} ws2.lib
.rem
.rem Values for each platform.
.rem
.set app_libs_win32             {app_libs_dt}
.set app_libs_x64               {app_libs_dt}
.set app_libs_win32vista        {app_libs_dt}
.set app_libs_x64vista          {app_libs_dt}
.set app_libs_std500armv4i      {app_libs_ce}
.set app_libs_std500x86         {app_libs_ce}
.set app_libs_std500sh4         {app_libs_ce}
.set app_libs_std500mipsii      {app_libs_ce}
.set app_libs_std500mipsii_fp   {app_libs_ce}
.set app_libs_std500mipsiv      {app_libs_ce}
.set app_libs_std500mipsiv_fp   {app_libs_ce}
.set app_libs_ppc50armv4i       {app_libs_ce}
.set app_libs_sp50armv4i        {app_libs_ce}
.set app_libs_wm6std            {app_libs_ce}
.set app_libs_wm6pro            {app_libs_ce}
.rem
.rem Header directories for driver objects.
.rem --------------------------------------
.rem
.rem 32-bit pre-Vista desktop targets.
.rem
.set drv_incdirs_dt32v5 {any_incdirs_dtv5} \
	$(WINDDK)\\inc\\api \
	$(WINDDK)\\inc\\ddk \
	$(WINDDK)\\inc\\crt
.rem
.rem 64-bit pre-Vista desktop targets.
.rem
.set drv_incdirs_dt64v5 {any_incdirs_dtv5} \
	$(WINDDK)\\inc\\api \
	$(WINDDK)\\inc\\ddk \
	$(WINDDK)\\inc\\wnet \
	$(WINDDK)\\inc\\ddk\\wnet \
	$(WINDDK)\\inc\\ddk\\wdm\\wnet \
	$(WINDDK)\\inc\\crt
.rem
.rem 32-bit Vista desktop targets.
.rem
.set drv_incdirs_dt32v6 {any_incdirs_dtv6} \
	$(WINDDK)\\inc\\api \
	$(WINDDK)\\inc\\ddk
.rem
.rem 64-bit Vista desktop targets.
.rem
.set drv_incdirs_dt64v6 {any_incdirs_dtv6} \
	$(WINDDK)\\inc\\api \
	$(WINDDK)\\inc\\ddk
.rem
.rem Mobile targets based on Windows CE 5.0.
.rem
.set drv_incdirs_ce5 {any_incdirs_ce5}
.rem
.rem Mobile targets based on Windows CE 6.0.
.rem
.set drv_incdirs_ce6 {any_incdirs_ce6}
.rem
.rem Values for each platform.
.rem
.set drv_incdirs_win32             {drv_incdirs_dt32v5}
.set drv_incdirs_x64               {drv_incdirs_dt64v5}
.set drv_incdirs_win32vista        {drv_incdirs_dt32v6}
.set drv_incdirs_x64vista          {drv_incdirs_dt64v6}
.set drv_incdirs_std500armv4i      {drv_incdirs_ce5}
.set drv_incdirs_std500x86         {drv_incdirs_ce5}
.set drv_incdirs_std500sh4         {drv_incdirs_ce5}
.set drv_incdirs_std500mipsii      {drv_incdirs_ce5}
.set drv_incdirs_std500mipsii_fp   {drv_incdirs_ce5}
.set drv_incdirs_std500mipsiv      {drv_incdirs_ce5}
.set drv_incdirs_std500mipsiv_fp   {drv_incdirs_ce5}
.set drv_incdirs_ppc50armv4i       {drv_incdirs_ce5}
.set drv_incdirs_sp50armv4i        {drv_incdirs_ce5}
.set drv_incdirs_wm6std            {drv_incdirs_ce5}
.set drv_incdirs_wm6pro            {drv_incdirs_ce5}
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
	NDIS_MINIPORT_DRIVER \
	NDIS50 \
	NDIS50_MINIPORT
.rem
.rem NDIS 6 options
.rem
.set drv_defs_ndis6 \
	NDIS_MINIPORT_DRIVER \
	NDIS60 \
	NDIS60_MINIPORT \
	NDIS_SUPPORT_NDIS6=1 \
        NDIS_SUPPORT_NDIS61=1
.rem
.rem Desktop targets.
.rem
.set drv_defs_dt {drv_defs} \
	CONDITION_HANDLING=1 \
	NT_INST=0 \
	_NT1X_=100 \
	WIN32_LEAN_AND_MEAN=1 \
	DEVL=1 \
	__BUILDMACHINE__=WinDDK \
	_DLL=1
.rem
.rem 32-bit desktop targets.
.rem
.set drv_defs_dt32 {drv_defs_dt} \
	_X86_=1 \
	i386=1 \
	STD_CALL \
	FPO=0
.rem
.rem 64-bit desktop targets.
.rem
.set drv_defs_dt64 {drv_defs_dt} \
	_WIN64 \
	_AMD64_ \
	AMD64 \
	_AMD64_SIMULATOR_PERF_ \
	_SKIP_IF_SIMULATOR_ \
	_AMD64_SIMULATOR_ \
	_AMD64_WORKAROUND_
.rem
.rem 32-bit pre-Vista desktop targets.
.rem
.set drv_defs_dt32v5 {any_defs_dt32v5} {drv_defs_dt32} {drv_defs_ndis5}
.rem
.rem 64-bit pre-Vista desktop targets.
.rem
.set drv_defs_dt64v5 {any_defs_dt64v5} {drv_defs_dt64} {drv_defs_ndis5}
.rem
.rem 32-bit Vista desktop targets.
.rem
.set drv_defs_dt32v6 {any_defs_dt32v6} {drv_defs_dt32} {drv_defs_ndis6}
.rem
.rem 64-bit Vista desktop targets.
.rem
.set drv_defs_dt64v6 {any_defs_dt64v6} {drv_defs_dt64} {drv_defs_ndis6}
.rem
.rem Mobile targets.
.rem
.set drv_defs_ce {any_defs_ce} {drv_defs} {drv_defs_ndis5} \
	USE_WCE_STUBS \
	_USRDLL \
	{project_name}_EXPORTS
.rem
.rem Mobile targets based on Windows CE 5.0.
.rem
.set drv_defs_ce5 {drv_defs_ce}
.rem
.rem Mobile targets based on Windows CE 6.0.
.rem
.set drv_defs_ce6 {drv_defs_ce} \
	IN_KERNEL
.rem
.rem Desktop debug/optimization options.
.rem
.set drv_defs_dtdbg \
	DBG \
	DEBUG_LIGHT
.set drv_defs_dtrel
.rem
.rem Mobile debug/optimization options.
.rem
.set drv_defs_cedbg \
	_DEBUG \
	DEBUG \
	DEBUG_LIGHT
.set drv_defs_cerel \
	NDEBUG
.rem
.rem Values for each platform/configuration combination.
.rem
.set drv_defs_win32_debug             {drv_defs_dt32v5} {drv_defs_dtdbg}
.set drv_defs_win32_release           {drv_defs_dt32v5} {drv_defs_dtrel}
.set drv_defs_x64_debug               {drv_defs_dt64v5} {drv_defs_dtdbg}
.set drv_defs_x64_release             {drv_defs_dt64v5} {drv_defs_dtrel}
.set drv_defs_win32vista_debug        {drv_defs_dt32v6} {drv_defs_dtdbg}
.set drv_defs_win32vista_release      {drv_defs_dt32v6} {drv_defs_dtrel}
.set drv_defs_x64vista_debug          {drv_defs_dt64v6} {drv_defs_dtdbg}
.set drv_defs_x64vista_release        {drv_defs_dt64v6} {drv_defs_dtrel}
.set drv_defs_std500armv4i_debug      {drv_defs_ce5} {drv_defs_cedbg}
.set drv_defs_std500armv4i_release    {drv_defs_ce5} {drv_defs_cerel}
.set drv_defs_std500x86_debug         {drv_defs_ce5} {drv_defs_cedbg}
.set drv_defs_std500x86_release       {drv_defs_ce5} {drv_defs_cerel}
.set drv_defs_std500sh4_debug         {drv_defs_ce5} {drv_defs_cedbg}
.set drv_defs_std500sh4_release       {drv_defs_ce5} {drv_defs_cerel}
.set drv_defs_std500mipsii_debug      {drv_defs_ce5} {drv_defs_cedbg}
.set drv_defs_std500mipsii_release    {drv_defs_ce5} {drv_defs_cerel}
.set drv_defs_std500mipsii_fp_debug   {drv_defs_ce5} {drv_defs_cedbg}
.set drv_defs_std500mipsii_fp_release {drv_defs_ce5} {drv_defs_cerel}
.set drv_defs_std500mipsiv_debug      {drv_defs_ce5} {drv_defs_cedbg}
.set drv_defs_std500mipsiv_release    {drv_defs_ce5} {drv_defs_cerel}
.set drv_defs_std500mipsiv_fp_debug   {drv_defs_ce5} {drv_defs_cedbg}
.set drv_defs_std500mipsiv_fp_release {drv_defs_ce5} {drv_defs_cerel}
.set drv_defs_ppc50armv4i_debug       {drv_defs_ce5} {drv_defs_cedbg}
.set drv_defs_ppc50armv4i_release     {drv_defs_ce5} {drv_defs_cerel}
.set drv_defs_sp50armv4i_debug        {drv_defs_ce5} {drv_defs_cedbg}
.set drv_defs_sp50armv4i_release      {drv_defs_ce5} {drv_defs_cerel}
.set drv_defs_wm6std_debug            {drv_defs_ce5} {drv_defs_cedbg}
.set drv_defs_wm6std_release          {drv_defs_ce5} {drv_defs_cerel}
.set drv_defs_wm6pro_debug            {drv_defs_ce5} {drv_defs_cedbg}
.set drv_defs_wm6pro_release          {drv_defs_ce5} {drv_defs_cerel}
.rem
.rem C compiler options for driver objects.
.rem --------------------------------------
.rem
.rem All targets.
.rem
.set drv_cflags /Zl /Zp8 /Gy /Gm- /GF /Oy- /Oi
.rem
.rem Desktop targets.
.rem
.set drv_cflags_dt {any_cflags_dt} {drv_cflags} \
	/GS- \
	/Gz
.rem
.rem 32-bit desktop targets.
.rem
.set drv_cflags_dt32 {drv_cflags_dt} \
	/hotpatch
.rem
.rem 64-bit desktop targets.
.rem
.set drv_cflags_dt64 {drv_cflags_dt}
.rem
.rem Mobile targets.
.rem
.set drv_cflags_ce {any_cflags_ce} {drv_cflags}
.rem
.rem Desktop debug/optimization options.
.rem
.set drv_cflags_dtdbg {any_cflags_dbg} \
	/Od
.set drv_cflags_dtrel {any_cflags_rel} \
	/O2
.rem
.rem Mobile debug/optimization options.
.rem
.set drv_cflags_cedbg {any_cflags_dbg} \
	/Od
.set drv_cflags_cerel {any_cflags_rel} \
	/Od
.rem
.rem Values for each platform/configuration combination.
.rem
.set drv_cflags_win32_debug             {drv_cflags_dt32} {drv_cflags_dtdbg}
.set drv_cflags_win32_release           {drv_cflags_dt32} {drv_cflags_dtrel}
.set drv_cflags_x64_debug               {drv_cflags_dt64} {drv_cflags_dtdbg}
.set drv_cflags_x64_release             {drv_cflags_dt64} {drv_cflags_dtrel}
.set drv_cflags_win32vista_debug        {drv_cflags_dt32} {drv_cflags_dtdbg}
.set drv_cflags_win32vista_release      {drv_cflags_dt32} {drv_cflags_dtrel}
.set drv_cflags_x64vista_debug          {drv_cflags_dt64} {drv_cflags_dtdbg}
.set drv_cflags_x64vista_release        {drv_cflags_dt64} {drv_cflags_dtrel}
.set drv_cflags_std500armv4i_debug      {drv_cflags_ce} {drv_cflags_cedbg}
.set drv_cflags_std500armv4i_release    {drv_cflags_ce} {drv_cflags_cerel} \
	/QRthumb
.set drv_cflags_std500x86_debug         {drv_cflags_ce} {drv_cflags_cedbg}
.set drv_cflags_std500x86_release       {drv_cflags_ce} {drv_cflags_cerel}
.set drv_cflags_std500sh4_debug         {drv_cflags_ce} {drv_cflags_cedbg}
.set drv_cflags_std500sh4_release       {drv_cflags_ce} {drv_cflags_cerel}
.set drv_cflags_std500mipsii_debug      {drv_cflags_ce} {drv_cflags_cedbg}
.set drv_cflags_std500mipsii_release    {drv_cflags_ce} {drv_cflags_cerel}
.set drv_cflags_std500mipsii_fp_debug   {drv_cflags_ce} {drv_cflags_cedbg}
.set drv_cflags_std500mipsii_fp_release {drv_cflags_ce} {drv_cflags_cerel}
.set drv_cflags_std500mipsiv_debug      {drv_cflags_ce} {drv_cflags_cedbg}
.set drv_cflags_std500mipsiv_release    {drv_cflags_ce} {drv_cflags_cerel}
.set drv_cflags_std500mipsiv_fp_debug   {drv_cflags_ce} {drv_cflags_cedbg}
.set drv_cflags_std500mipsiv_fp_release {drv_cflags_ce} {drv_cflags_cerel}
.set drv_cflags_ppc50armv4i_debug       {drv_cflags_ce} {drv_cflags_cedbg}
.set drv_cflags_ppc50armv4i_release     {drv_cflags_ce} {drv_cflags_cerel} \
	/QRthumb
.set drv_cflags_sp50armv4i_debug        {drv_cflags_ce} {drv_cflags_cedbg}
.set drv_cflags_sp50armv4i_release      {drv_cflags_ce} {drv_cflags_cerel} \
	/QRthumb
.set drv_cflags_wm6std_debug            {drv_cflags_ce} {drv_cflags_cedbg}
.set drv_cflags_wm6std_release          {drv_cflags_ce} {drv_cflags_cerel} \
	/QRthumb
.set drv_cflags_wm6pro_debug            {drv_cflags_ce} {drv_cflags_cedbg}
.set drv_cflags_wm6pro_release          {drv_cflags_ce} {drv_cflags_cerel} \
	/QRthumb
.rem
.rem Library directories for drivers.
.rem --------------------------------
.rem
.rem 32-bit pre-Vista desktop targets.
.rem
.set drv_libdirs_dt32v5 {any_libdirs} \
	$(WINDDK)\\lib\\wxp\\i386
.rem
.rem 64-bit pre-Vista desktop targets.
.rem
.set drv_libdirs_dt64v5 {any_libdirs} \
	$(WINDDK)\\lib\\wnet\\amd64
.rem
.rem 32-bit Vista desktop targets.
.rem
.set drv_libdirs_dt32v6 {any_libdirs} \
	$(WINDDK)\\lib\\wlh\\i386
.rem
.rem 64-bit Vista desktop targets.
.rem
.set drv_libdirs_dt64v6 {any_libdirs} \
	$(WINDDK)\\lib\\wlh\\amd64
.rem
.rem Mobile targets.
.rem
.set drv_libdirs_ce {any_libdirs}
.rem
.rem Values for each platform/configuration combination.
.rem
.set drv_libdirs_win32_debug \
	{any_libdirs_win32_debug} {drv_libdirs_dt32v5}
.set drv_libdirs_win32_release \
	{any_libdirs_win32_release} {drv_libdirs_dt32v5}
.set drv_libdirs_x64_debug \
	{any_libdirs_x64_debug} {drv_libdirs_dt64v5}
.set drv_libdirs_x64_release \
	{any_libdirs_x64_release} {drv_libdirs_dt64v5}
.set drv_libdirs_win32vista_debug \
	{any_libdirs_win32vista_debug} {drv_libdirs_dt32v6}
.set drv_libdirs_win32vista_release \
	{any_libdirs_win32vista_release} {drv_libdirs_dt32v6}
.set drv_libdirs_x64vista_debug \
	{any_libdirs_x64vista_debug} {drv_libdirs_dt64v6}
.set drv_libdirs_x64vista_release \
	{any_libdirs_x64vista_release} {drv_libdirs_dt64v6}
.set drv_libdirs_std500armv4i_debug \
	{any_libdirs_std500armv4i_debug} {drv_libdirs_ce}
.set drv_libdirs_std500armv4i_release \
	{any_libdirs_std500armv4i_release} {drv_libdirs_ce}
.set drv_libdirs_std500x86_debug \
	{any_libdirs_std500x86_debug} {drv_libdirs_ce}
.set drv_libdirs_std500x86_release \
	{any_libdirs_std500x86_release} {drv_libdirs_ce}
.set drv_libdirs_std500sh4_debug \
	{any_libdirs_std500sh4_debug} {drv_libdirs_ce}
.set drv_libdirs_std500sh4_release \
	{any_libdirs_std500sh4_release} {drv_libdirs_ce}
.set drv_libdirs_std500mipsii_debug \
	{any_libdirs_std500mipsii_debug} {drv_libdirs_ce}
.set drv_libdirs_std500mipsii_release \
	{any_libdirs_std500mipsii_release} {drv_libdirs_ce}
.set drv_libdirs_std500mipsii_fp_debug \
	{any_libdirs_std500mipsii_fp_debug} {drv_libdirs_ce}
.set drv_libdirs_std500mipsii_fp_release \
	{any_libdirs_std500mipsii_fp_release} {drv_libdirs_ce}
.set drv_libdirs_std500mipsiv_debug \
	{any_libdirs_std500mipsiv_debug} {drv_libdirs_ce}
.set drv_libdirs_std500mipsiv_release \
	{any_libdirs_std500mipsiv_release} {drv_libdirs_ce}
.set drv_libdirs_std500mipsiv_fp_debug \
	{any_libdirs_std500mipsiv_fp_debug} {drv_libdirs_ce}
.set drv_libdirs_std500mipsiv_fp_release \
	{any_libdirs_std500mipsiv_fp_release} {drv_libdirs_ce}
.set drv_libdirs_ppc50armv4i_debug \
	{any_libdirs_ppc50armv4i_debug} {drv_libdirs_ce}
.set drv_libdirs_ppc50armv4i_release \
	{any_libdirs_ppc50armv4i_release} {drv_libdirs_ce}
.set drv_libdirs_sp50armv4i_debug \
	{any_libdirs_sp50armv4i_debug} {drv_libdirs_ce}
.set drv_libdirs_sp50armv4i_release \
	{any_libdirs_sp50armv4i_release} {drv_libdirs_ce}
.set drv_libdirs_wm6std_debug \
	{any_libdirs_wm6std_debug} {drv_libdirs_ce}
.set drv_libdirs_wm6std_release \
	{any_libdirs_wm6std_release} {drv_libdirs_ce}
.set drv_libdirs_wm6pro_debug \
	{any_libdirs_wm6pro_debug} {drv_libdirs_ce}
.set drv_libdirs_wm6pro_release \
	{any_libdirs_wm6pro_release} {drv_libdirs_ce}
.rem
.rem Linker options for drivers.
.rem ---------------------------
.rem
.rem All targets.
.rem
.set drv_ldflags \
	/NODEFAULTLIB \
	/INCREMENTAL:NO
.rem
.rem Desktop targets.
.rem
.set drv_ldflags_dt {drv_ldflags} \
	/MERGE:_PAGE=PAGE \
	/MERGE:_TEXT=.text \
	/SECTION:INIT,d \
	/IGNORE:4078,4198,4010,4037,4039,4065,4070,4087,4089,4221 \
	/FULLBUILD \
	/WX \
	/PDBCOMPRESS \
	/DRIVER \
	/STACK:0x40000,0x1000 \
	/BASE:0x10000 \
	/ALIGN:0x80
.rem
.rem 32-bit pre-Vista desktop targets.
.rem
.set drv_ldflags_dt32v5 {any_ldflags_dt32v5} {drv_ldflags_dt} \
	/VERSION:5.0 \
	/OSVERSION:5.0 \
	/FUNCTIONPADMIN:5 \
	/SUBSYSTEM:NATIVE,5.00 \
	/ENTRY:DriverEntry@8
.rem
.rem 64-bit pre-Vista desktop targets.
.rem
.set drv_ldflags_dt64v5 {any_ldflags_dt64v5} {drv_ldflags_dt} \
	/VERSION:5.2 \
	/OSVERSION:5.2 \
	/FUNCTIONPADMIN:6 \
	/SUBSYSTEM:NATIVE,5.02 \
	 /OPT:nowin98 \
	$(WINDDK)\\lib\\wnet\\amd64\\hotpatch.obj \
	/ENTRY:DriverEntry
.rem
.rem 32-bit Vista desktop targets.
.rem
.set drv_ldflags_dt32v6 {any_ldflags_dt32v6} {drv_ldflags_dt} \
	/VERSION:5.0 \
	/OSVERSION:5.0 \
	/FUNCTIONPADMIN:5 \
	/SUBSYSTEM:NATIVE,5.00 \
	/ENTRY:DriverEntry@8
.rem
.rem 64-bit Vista desktop targets.
.rem
.set drv_ldflags_dt64v6 {any_ldflags_dt64v6} {drv_ldflags_dt} \
	/VERSION:5.2 \
	/OSVERSION:5.2 \
	/FUNCTIONPADMIN:6 \
	/SUBSYSTEM:NATIVE,5.02 \
	 /OPT:nowin98 \
	$(WINDDK)\\lib\\wnet\\amd64\\hotpatch.obj \
	/ENTRY:DriverEntry
.rem
.rem Mobile targets.
.rem
.set drv_ldflags_ce {drv_ldflags} \
	/IGNORE:4078,4001,4070,4086,4089,4096,4099,4108,4229 \
	/ENTRY:_DllMainCRTStartup
.rem
.rem Mobile targets based on CE 5.0.
.rem
.set drv_ldflags_ce5 {any_ldflags_ce5} {drv_ldflags_ce}
.rem
.rem Mobile targets based on Windows Mobile 5.0.
.rem
.set drv_ldflags_wm5 {any_ldflags_wm5} {drv_ldflags_ce}
.rem
.rem Mobile targets based on Windows Mobile 6.
.rem
.set drv_ldflags_wm6 {any_ldflags_wm6} {drv_ldflags_ce}
.rem
.rem Debug/optimization options.
.rem
.set drv_ldflags_dbg {any_ldflags_dbg} \
	/DEBUG
.set drv_ldflags_rel {any_ldflags_rel} \
	/OPT:REF \
	/OPT:ICF
.rem
.rem Values for each platform/configuration combination.
.rem
.set drv_ldflags_win32_debug             {drv_ldflags_dt32v5} {drv_ldflags_dbg}
.set drv_ldflags_win32_release           {drv_ldflags_dt32v5} {drv_ldflags_rel}
.set drv_ldflags_x64_debug               {drv_ldflags_dt64v5} {drv_ldflags_dbg}
.set drv_ldflags_x64_release             {drv_ldflags_dt64v5} {drv_ldflags_rel}
.set drv_ldflags_win32vista_debug        {drv_ldflags_dt32v6} {drv_ldflags_dbg}
.set drv_ldflags_win32vista_release      {drv_ldflags_dt32v6} {drv_ldflags_rel}
.set drv_ldflags_x64vista_debug          {drv_ldflags_dt64v6} {drv_ldflags_dbg}
.set drv_ldflags_x64vista_release        {drv_ldflags_dt64v6} {drv_ldflags_rel}
.set drv_ldflags_std500armv4i_debug      {drv_ldflags_ce5} {drv_ldflags_dbg}
.set drv_ldflags_std500armv4i_release    {drv_ldflags_ce5} {drv_ldflags_rel}
.set drv_ldflags_std500x86_debug         {drv_ldflags_ce5} {drv_ldflags_dbg}
.set drv_ldflags_std500x86_release       {drv_ldflags_ce5} {drv_ldflags_rel}
.set drv_ldflags_std500sh4_debug         {drv_ldflags_ce5} {drv_ldflags_dbg}
.set drv_ldflags_std500sh4_release       {drv_ldflags_ce5} {drv_ldflags_rel}
.set drv_ldflags_std500mipsii_debug      {drv_ldflags_ce5} {drv_ldflags_dbg}
.set drv_ldflags_std500mipsii_release    {drv_ldflags_ce5} {drv_ldflags_rel}
.set drv_ldflags_std500mipsii_fp_debug   {drv_ldflags_ce5} {drv_ldflags_dbg}
.set drv_ldflags_std500mipsii_fp_release {drv_ldflags_ce5} {drv_ldflags_rel}
.set drv_ldflags_std500mipsiv_debug      {drv_ldflags_ce5} {drv_ldflags_dbg}
.set drv_ldflags_std500mipsiv_release    {drv_ldflags_ce5} {drv_ldflags_rel}
.set drv_ldflags_std500mipsiv_fp_debug   {drv_ldflags_ce5} {drv_ldflags_dbg}
.set drv_ldflags_std500mipsiv_fp_release {drv_ldflags_ce5} {drv_ldflags_rel}
.set drv_ldflags_ppc50armv4i_debug       {drv_ldflags_wm5} {drv_ldflags_dbg}
.set drv_ldflags_ppc50armv4i_release     {drv_ldflags_wm5} {drv_ldflags_rel}
.set drv_ldflags_sp50armv4i_debug        {drv_ldflags_wm5} {drv_ldflags_dbg}
.set drv_ldflags_sp50armv4i_release      {drv_ldflags_wm5} {drv_ldflags_rel}
.set drv_ldflags_wm6std_debug            {drv_ldflags_wm6} {drv_ldflags_dbg}
.set drv_ldflags_wm6std_release          {drv_ldflags_wm6} {drv_ldflags_rel}
.set drv_ldflags_wm6pro_debug            {drv_ldflags_wm6} {drv_ldflags_dbg}
.set drv_ldflags_wm6pro_release          {drv_ldflags_wm6} {drv_ldflags_rel}
.rem
.rem Additional libraries for drivers.
.rem ---------------------------------
.rem
.rem Desktop targets.
.rem
.set drv_libs_dt {any_libs} \
	ntoskrnl.lib \
	hal.lib \
	wmilib.lib \
	ndis.lib
.rem
.rem 32-bit pre-Vista desktop targets.
.rem
.set drv_libs_dt32v5 {drv_libs_dt} \
	sehupd.lib \
	tdi.lib
.rem
.rem 64-bit pre-Vista desktop targets.
.rem
.set drv_libs_dt64v5 {drv_libs_dt} \
	tdi.lib
.rem
.rem 32-bit Vista desktop targets.
.rem
.set drv_libs_dt32v6 {drv_libs_dt} \
	netio.lib
.rem
.rem 64-bit Vista desktop targets.
.rem
.set drv_libs_dt64v6 {drv_libs_dt} \
	netio.lib
.rem
.rem Mobile targets.
.rem
.set drv_libs_ce {any_libs} \
	iphlpapi.lib \
	cxport.lib \
	ntcompat.lib \
	ndis.lib
.rem
.rem Values for each platform.
.rem
.set drv_libs_win32             {drv_libs_dt32v5}
.set drv_libs_x64               {drv_libs_dt64v5}
.set drv_libs_win32vista        {drv_libs_dt32v6}
.set drv_libs_x64vista          {drv_libs_dt64v6}
.set drv_libs_std500armv4i      {drv_libs_ce}
.set drv_libs_std500x86         {drv_libs_ce}
.set drv_libs_std500sh4         {drv_libs_ce}
.set drv_libs_std500mipsii      {drv_libs_ce}
.set drv_libs_std500mipsii_fp   {drv_libs_ce}
.set drv_libs_std500mipsiv      {drv_libs_ce}
.set drv_libs_std500mipsiv_fp   {drv_libs_ce}
.set drv_libs_ppc50armv4i       {drv_libs_ce}
.set drv_libs_sp50armv4i        {drv_libs_ce}
.set drv_libs_wm6std            {drv_libs_ce}
.set drv_libs_wm6pro            {drv_libs_ce}
.rem
.rem Suffix for drivers.
.rem -------------------
.rem
.rem Desktop targets.
.rem
.set drv_suffix_dt .sys
.rem
.rem Mobile targets.
.rem
.set drv_suffix_ce .dll
.rem
.rem Values for each platform.
.rem
.set drv_suffix_win32           {drv_suffix_dt}
.set drv_suffix_x64             {drv_suffix_dt}
.set drv_suffix_win32vista      {drv_suffix_dt}
.set drv_suffix_x64vista        {drv_suffix_dt}
.set drv_suffix_std500armv4i    {drv_suffix_ce}
.set drv_suffix_std500x86       {drv_suffix_ce}
.set drv_suffix_std500sh4       {drv_suffix_ce}
.set drv_suffix_std500mipsii    {drv_suffix_ce}
.set drv_suffix_std500mipsii_fp {drv_suffix_ce}
.set drv_suffix_std500mipsiv    {drv_suffix_ce}
.set drv_suffix_std500mipsiv_fp {drv_suffix_ce}
.set drv_suffix_ppc50armv4i     {drv_suffix_ce}
.set drv_suffix_sp50armv4i      {drv_suffix_ce}
.set drv_suffix_wm6std          {drv_suffix_ce}
.set drv_suffix_wm6pro          {drv_suffix_ce}
.rem
.rem Visual Studio 2005 configuration type number for drivers.
.rem ---------------------------------------------------------
.rem
.rem Desktop targets.
.rem
.set drv_cfgnum_dt 1
.rem
.rem Mobile targets.
.rem
.set drv_cfgnum_ce 2
.rem
.rem Values for each platform/configuration combination.
.rem
.set drv_cfgnum_win32             {drv_cfgnum_dt}
.set drv_cfgnum_x64               {drv_cfgnum_dt}
.set drv_cfgnum_win32vista        {drv_cfgnum_dt}
.set drv_cfgnum_x64vista          {drv_cfgnum_dt}
.set drv_cfgnum_std500armv4i      {drv_cfgnum_ce}
.set drv_cfgnum_std500x86         {drv_cfgnum_ce}
.set drv_cfgnum_std500sh4         {drv_cfgnum_ce}
.set drv_cfgnum_std500mipsii      {drv_cfgnum_ce}
.set drv_cfgnum_std500mipsii_fp   {drv_cfgnum_ce}
.set drv_cfgnum_std500mipsiv      {drv_cfgnum_ce}
.set drv_cfgnum_std500mipsiv_fp   {drv_cfgnum_ce}
.set drv_cfgnum_ppc50armv4i       {drv_cfgnum_ce}
.set drv_cfgnum_sp50armv4i        {drv_cfgnum_ce}
.set drv_cfgnum_wm6std            {drv_cfgnum_ce}
.set drv_cfgnum_wm6pro            {drv_cfgnum_ce}
.rem
.rem Linker options for console applications.
.rem ----------------------------------------
.rem
.rem Desktop targets.
.rem
.set con_ldflags_dt \
	/SUBSYSTEM:CONSOLE
.rem
.rem Mobile targets.
.rem
.set con_ldflags_ce \
	/ENTRY:mainWCRTStartup
.rem
.rem Values for each platform/configuration combination.
.rem
.set con_ldflags_win32             {con_ldflags_dt}
.set con_ldflags_x64               {con_ldflags_dt}
.set con_ldflags_win32vista        {con_ldflags_dt}
.set con_ldflags_x64vista          {con_ldflags_dt}
.set con_ldflags_std500armv4i      {con_ldflags_ce}
.set con_ldflags_std500x86         {con_ldflags_ce}
.set con_ldflags_std500sh4         {con_ldflags_ce}
.set con_ldflags_std500mipsii      {con_ldflags_ce}
.set con_ldflags_std500mipsii_fp   {con_ldflags_ce}
.set con_ldflags_std500mipsiv      {con_ldflags_ce}
.set con_ldflags_std500mipsiv_fp   {con_ldflags_ce}
.set con_ldflags_ppc50armv4i       {con_ldflags_ce}
.set con_ldflags_sp50armv4i        {con_ldflags_ce}
.set con_ldflags_wm6std            {con_ldflags_ce}
.set con_ldflags_wm6pro            {con_ldflags_ce}
.rem
.rem Visual Studio 2005 runtime library number for each configuration.
.rem -----------------------------------------------------------------
.rem
.rem 0 = Multi-threaded (/MT)
.rem 1 = Multi-threaded Debug (/MTd)
.rem 2 = Multi-threaded DLL (/MD)
.rem 3 = Multi-threaded Debug DLL (/MDd)
.rem
.set rtlnum_debug   1
.set rtlnum_release 0
.rem
.rem Resource compiler flags.
.rem ------------------------
.rem
.set rcflags -l 409 -n
.rem
.rem Set target type flag.
.rem ---------------------
.rem
.set console_defined
.set windows_defined
.set appdll_defined
.set driver_defined
.set applib_defined
.set drvlib_defined
.set custom_defined
.rem
.set {project_type}_defined yes
.rem
.rem Begin .vsprops file.
.rem --------------------
.rem
.out {project_name}.vsprops
.rem
<?xml version="1.0" encoding="Windows-1252"?>
<VisualStudioPropertySheet
	ProjectType="Visual C++"
	Version="8.00"
	Name="UserMacros"
	>
	<UserMacro
		Name="SRCTOP"
		Value="{project_dir_inverse}"
	/>
</VisualStudioPropertySheet>
.rem End .vsprops file.
.rem -----------------
.tuo
.rem Begin .vcproj file.
.rem -------------------
.rem
.out {project_name}.vcproj
.rem
<?xml version="1.0" encoding="Windows-1252"?>
<VisualStudioProject
	ProjectType="Visual C++"
	Version="8.00"
	Name="{project_name}"
	ProjectGUID="\{{project_guid}\}"
	RootNamespace="{project_name}"
	>
	<Platforms>
.rem
.rem Declare platforms
.rem
.for platform {platforms}
		<Platform
			Name="{name_{platform}}"
		/>
.rof
	</Platforms>
	<ToolFiles>
	</ToolFiles>
	<Configurations>
.rem
.rem Iterate the configuration template part for each platform/configuration
.rem combination.
.rem
.for platform {platforms}
.for configuration {configurations}
.rem
.rem Set runtime library number based on configuration.
.rem
.set rtlnum {rtlnum_{configuration}}
.rem
.rem Set build options based on target type.
.rem
.for dummy {console_defined}
.set cfgnum 1
.set incdirs {app_incdirs_{platform}}
.set defs {app_defs_{platform}_{configuration}} {project_defs}
.set cflags {app_cflags_{platform}_{configuration}} {project_cflags}
.set libdirs {project_libdirs} {app_libdirs_{platform}_{configuration}}
.set ldflags {app_ldflags_{platform}_{configuration}} {project_ldflags} \
	{con_ldflags_{platform}}
.set libs {app_libs_{platform}} {project_libs}
.set is_cprogram yes
.set is_library
.set is_executable yes
.set suffix .exe
.rof
.for dummy {windows_defined}
.set cfgnum 1
.set incdirs {app_incdirs_{platform}}
.set defs {app_defs_{platform}_{configuration}} {project_defs}
.set cflags {app_cflags_{platform}_{configuration}} {project_cflags}
.set libdirs {project_libdirs} {app_libdirs_{platform}_{configuration}}
.set ldflags {app_ldflags_{platform}_{configuration}} {project_ldflags}
.set libs {app_libs_{platform}} {project_libs}
.set is_cprogram yes
.set is_library
.set is_executable yes
.set suffix .exe
.rof
.for dummy {appdll_defined}
.set cfgnum 2
.set incdirs {app_incdirs_{platform}}
.set defs {app_defs_{platform}_{configuration}} {project_defs} \
	_USRDLL \
	{project_name}_EXPORTS
.set cflags {app_cflags_{platform}_{configuration}} {project_cflags}
.set libdirs {project_libdirs} {app_libdirs_{platform}_{configuration}}
.set ldflags {app_ldflags_{platform}_{configuration}} {project_ldflags}
.set libs {app_libs_{platform}} {project_libs}
.set is_cprogram yes
.set is_library
.set is_executable yes
.set suffix .dll
.rof
.for dummy {driver_defined}
.set cfgnum {drv_cfgnum_{platform}}
.set incdirs {drv_incdirs_{platform}}
.set defs {drv_defs_{platform}_{configuration}} {project_defs}
.set cflags {drv_cflags_{platform}_{configuration}} {project_cflags}
.set libdirs {project_libdirs} {drv_libdirs_{platform}_{configuration}}
.set ldflags {drv_ldflags_{platform}_{configuration}} {project_ldflags}
.set libs {drv_libs_{platform}} {project_libs}
.set is_cprogram yes
.set is_library
.set is_executable yes
.set suffix {drv_suffix_{platform}}
.rof
.for dummy {applib_defined}
.set cfgnum 4
.set incdirs {app_incdirs_{platform}}
.set defs {app_defs_{platform}_{configuration}} {project_defs}
.set cflags {app_cflags_{platform}_{configuration}} {project_cflags}
.set libdirs {project_libdirs} {app_libdirs_{platform}_{configuration}}
.set ldflags {app_ldflags_{platform}_{configuration}} {project_ldflags}
.set libs {app_libs_{platform}} {project_libs}
.set is_cprogram yes
.set is_library yes
.set is_executable
.set suffix .lib
.rof
.for dummy {drvlib_defined}
.set cfgnum 4
.set incdirs {drv_incdirs_{platform}}
.set defs {drv_defs_{platform}_{configuration}} {project_defs}
.set cflags {drv_cflags_{platform}_{configuration}} {project_cflags}
.set libdirs {project_libdirs} {drv_libdirs_{platform}_{configuration}}
.set ldflags {drv_ldflags_{platform}_{configuration}} {project_ldflags}
.set libs {drv_libs_{platform}} {project_libs}
.set is_cprogram yes
.set is_library yes
.set is_executable
.set suffix .lib
.rof
.for dummy {custom_defined}
.set cfgnum 1
.set is_cprogram
.set is_library
.set is_executable
.rof
		<Configuration
			Name="{name_{configuration}}|{name_{platform}}"
			OutputDirectory="{outdir}\\$(PlatformName)\\$(ConfigurationName)"
			IntermediateDirectory="{outdir}\\$(PlatformName)\\$(ConfigurationName)"
			ConfigurationType="{cfgnum}"
			InheritedPropertySheets="{project_name}.vsprops"
			CharacterSet="0"
			>
			<Tool
				Name="VCPreBuildEventTool"
			/>
			<Tool
				Name="VCCustomBuildTool"
			/>
			<Tool
				Name="VCXMLDataGeneratorTool"
			/>
			<Tool
				Name="VCWebServiceProxyGeneratorTool"
			/>
			<Tool
				Name="VCMIDLTool"
			/>
.for dummy {is_cprogram}
			<Tool
				Name="VCCLCompilerTool"
				RuntimeLibrary="{rtlnum}"
				Optimization="4"
				AdditionalIncludeDirectories="\
.for incdir {project_incdirs}
{srctop}\\{incdir};\
.rof
.for incdir {incdirs}
{incdir};\
.rof
"
				PreprocessorDefinitions="\
.for def {defs}
{def};\
.rof
"
				AdditionalOptions="{cflags}"
				ProgramDataBaseFileName="$(OutDir)\\{project_name}.pdb"
				CompileAs="1"
			/>
.rof
			<Tool
				Name="VCManagedResourceCompilerTool"
			/>
.for dummy {is_cprogram}
			<Tool
				Name="VCResourceCompilerTool"
				AdditionalIncludeDirectories="\
.for incdir {project_incdirs}
{srctop}\\{incdir};\
.rof
.for incdir {incdirs}
{incdir};\
.rof
"
				PreprocessorDefinitions="\
.for def {defs}
{def};\
.rof
"
				AdditionalOptions="{rcflags}"
			/>
.rof
			<Tool
				Name="VCPreLinkEventTool"
			/>
.for dummy {is_library}
			<Tool
				Name="VCLibrarianTool"
				LinkLibraryDependencies="true"
				OutputFile="$(OutDir)\\{project_name}{suffix}"
			/>
.rof
.for dummy {is_executable}
			<Tool
				Name="VCLinkerTool"
				AdditionalDependencies="{libs}"
				AdditionalLibraryDirectories="\
.for libdir {libdirs}
{libdir};\
.rof
"
				AdditionalOptions="{ldflags}"
				OutputFile="$(OutDir)\\{project_name}{suffix}"
			/>
.rof
			<Tool
				Name="VCALinkTool"
			/>
			<Tool
				Name="VCManifestTool"
			/>
			<Tool
				Name="VCXDCMakeTool"
			/>
			<Tool
				Name="VCBscMakeTool"
			/>
			<Tool
				Name="VCFxCopTool"
			/>
			<Tool
				Name="VCAppVerifierTool"
			/>
			<Tool
				Name="VCWebDeploymentTool"
			/>
			<Tool
				Name="VCPostBuildEventTool"
			/>
		</Configuration>
.rof
.rof
	</Configurations>
	<References>
	</References>
	<Files>
		<Filter
			Name="Source Files"
			Filter="cpp;c;cc;cxx;def;odl;idl;hpj;bat;asm;asmx"
			UniqueIdentifier="\{4FC737F1-C7A5-4376-A066-2A32D752A2FF\}"
			>
.for src {srcs}
			<File
				RelativePath="{srctop}\\{dir_{src}}\\{src}"
				>
			</File>
.rof
.rem
.rem Clear platform flags for custom commands.
.rem
.for platform {platforms}
.set custom_defined_{platform}
.rof
.rem Iterate custom commands.
.rem
.for tag {custom_tags}
.rem
.rem If no platform restrictions apply for this tags then enable all
.rem platforms available in this project.
.rem
.set custom_noplatforms yes
.for platform {custom_platforms_{tag}}
.set custom_noplatforms
.rof
.for dummy {custom_noplatforms}
.set custom_platforms_{tag} {platforms}
.rof
.rem Iterate platforms for this custom command.
.rem
.for platform {custom_platforms_{tag}}
.rem
.rem Set platform flag.
.rem
.set custom_defined_{platform} yes
.rof
			<File
				RelativePath="{custom_input_{tag}}"
				>
.rem
.rem Iterate all project platforms and output custom command for those
.rem platforms that are enabled for the command.
.rem
.for platform {platforms}
.for dummy {custom_defined_{platform}}
.for configuration {configurations}
				<FileConfiguration
					Name="{name_{configuration}}|{name_{platform}}"
					>
					<Tool
						Name="VCCustomBuildTool"
						CommandLine="{custom_command_{tag}}"
						Outputs="{custom_output_{tag}}"
					/>
				</FileConfiguration>
.rof
.rof
.rof
			</File>
.rem
.rem Clear platform flag.
.rem
.for platform {custom_platforms_{tag}}
.set custom_defined_{platform}
.rof
.rof
		</Filter>
		<Filter
			Name="Header Files"
			Filter="h;hpp;hxx;hm;inl;inc;xsd"
			UniqueIdentifier="\{93995380-89BD-4b04-88EB-625FBE52EBFB\}"
			>
.for hdr {hdrs}
			<File
				RelativePath="{srctop}\\{dir_{hdr}}\\{hdr}"
				>
			</File>
.rof
		</Filter>
		<Filter
			Name="Resource Files"
			Filter="rc;ico;cur;bmp;dlg;rc2;rct;bin;rgs;gif;jpg;jpeg;jpe;resx;tiff;tif;png;wav"
			UniqueIdentifier="\{67DA6AB6-F800-4c08-8B7A-83BB121AAD01\}"
			>
.for rsrc {rsrcs}
			<File
				RelativePath="{srctop}\\{dir_{rsrc}}\\{rsrc}"
				>
			</File>
.rof
		</Filter>
	</Files>
	<Globals>
	</Globals>
</VisualStudioProject>
.rem
.rem End .vcproj file.
.rem -----------------
.tuo
