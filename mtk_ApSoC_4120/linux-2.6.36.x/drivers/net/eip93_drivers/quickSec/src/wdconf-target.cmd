@echo off

setlocal

echo processing %~1

set t=%~n1
set t=%t:_project=%

set d=%blddir%\%t%

if not exist "%d%" mkdir "%d%"
if errorlevel 1 goto end

winconf\substitute -cr wdconf-settings.t %1 winconf\wdk\project.t

if exist "%d%\makefile" echo 	%t% \ >>"%blddir%\dirs"
if not exist "%d%\makefile" rmdir "%d%"

:end
