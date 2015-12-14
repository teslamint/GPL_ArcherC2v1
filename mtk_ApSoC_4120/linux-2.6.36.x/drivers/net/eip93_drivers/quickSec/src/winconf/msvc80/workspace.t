.rem
.rem workspace.t
.rem
.rem Copyright:
.rem          Copyright (c) 2007-2008 SFNT Finland Oy.
.rem               All rights reserved
.rem
.rem Visual Studio 2005 solution file template.
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
.rem Beginning of output.
.rem --------------------
.rem
.out {workspace_name}.sln
﻿
Microsoft Visual Studio Solution File, Format Version 9.00
# Visual Studio 2005
.for project {projects}
Project("\{8BC9CEB8-8B4A-11D0-8D11-00A0C91BC942\}") = "{project}", "{file_{project}}", "\{{guid_{project}}\}"
	ProjectSection(ProjectDependencies) = postProject
.for dependency {dependencies_{project}}
		\{{guid_{dependency}}\} = \{{guid_{dependency}}\}
.rof
	EndProjectSection
EndProject
.rof
Global
	GlobalSection(SolutionConfigurationPlatforms) = preSolution
.for platform {platforms}
.for configuration {configurations}
		{name_{configuration}}|{name_{platform}} = {name_{configuration}}|{name_{platform}}
.rof
.rof
	EndGlobalSection
	GlobalSection(ProjectConfigurationPlatforms) = postSolution
.for project {projects}
.rem
.rem Clear per-platform build flags.
.rem
.for platform {platforms}
.set build_{platform}
.rof
.rem If no platform restrictions apply for this project then enable all
.rem solution platforms.
.rem
.set no_project_platforms yes
.for dummy {platforms_{project}}
.set no_project_platforms
.rof
.for dummy {no_project_platforms}
.set platforms_{project} {platforms}
.rof
.rem Set per-platform build flags.
.rem 
.for platform {platforms_{project}}
.set build_{platform} yes
.rof
.rem Iterate all platforms but output the Build.0 line only if corresponding
.rem per-platform build flag is set.
.rem
.for platform {platforms}
.for configuration {configurations}
		\{{guid_{project}}\}.{name_{configuration}}|{name_{platform}}.ActiveCfg = {name_{configuration}}|{name_{platform}}
.for dummy {build_{platform}}
		\{{guid_{project}}\}.{name_{configuration}}|{name_{platform}}.Build.0 = {name_{configuration}}|{name_{platform}}
.rof
.rem
.rem
.rof
.rof
.rof
	EndGlobalSection
	GlobalSection(SolutionProperties) = preSolution
		HideSolutionNode = FALSE
	EndGlobalSection
EndGlobal
.rem
.rem End of output.
.rem --------------
.tuo
