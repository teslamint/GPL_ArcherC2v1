@echo off

setlocal

set platforms=%~1
set configurations=%~2
set profile=%~3

if "%platforms%"=="" goto usage

if "%platforms%"=="nt5" goto nt5
if "%platforms%"=="nt6" goto nt6
if "%platforms%"=="ce5" goto ce5
if "%platforms%"=="wm6" goto wm6

if "%configurations%"=="" goto usage
goto profile

:nt5
set profile=%configurations%
set platforms=win32 x64
set configurations=debug release
goto profile

:nt6
set profile=%configurations%
set platforms=win32vista x64vista
set configurations=debug release
goto profile

:ce5
set profile=%configurations%
set platforms=std500armv4i std500x86
set configurations=debug release
goto profile

:wm6
set profile=%configurations%
set platforms=wm6std wm6pro
set configurations=debug release
goto profile

:profile
if not "%profile%"=="" goto profile2
if exist sshdistdefs.h goto configure
echo.
echo Cannot find sshdistdefs.h and build profile not specified.
echo.
goto end

:profile2
if exist sshdistdefs-%profile%.h goto profile3
echo.
echo Cannot find sshdistdefs-%profile%.h.
echo.
goto end

:profile3
if not exist sshdistdefs.h goto profile4
fc sshdistdefs.h sshdistdefs-%profile%.h >nul
if not errorlevel 1 goto configure
del sshdistdefs.h

:profile4
type sshdistdefs-%profile%.h >sshdistdefs.h

:configure
echo .set platforms %platforms% >vsconf-settings.t
echo .set configurations %configurations% >>vsconf-settings.t
echo .set profile %profile% >>vsconf-settings.t
echo .set srctop $(SRCTOP) >>vsconf-settings.t
echo wrote vsconf-settings.t

set sub=%CD%\winconf\substitute.exe
set cfg=%CD%\vsconf-settings.t
set dir=%CD%\winconf\msvc80

for /d /r build %%d in (*) do @call vsconf-dir "%%d" "%sub%" "%cfg%" "%dir%"
for /d /r include %%d in (*) do @call vsconf-dir "%%d" "%sub%" "%cfg%" "%dir%"
for /d /r lib %%d in (*) do @call vsconf-dir "%%d" "%sub%" "%cfg%" "%dir%"
for /d /r ipsec %%d in (*) do @call vsconf-dir "%%d" "%sub%" "%cfg%" "%dir%"
for /d /r macsec %%d in (*) do @call vsconf-dir "%%d" "%sub%" "%cfg%" "%dir%"
for /d /r apps %%d in (*) do @call vsconf-dir "%%d" "%sub%" "%cfg%" "%dir%"
call vsconf-dir build "%sub%" "%cfg%" "%dir%"
call vsconf-dir include "%sub%" "%cfg%" "%dir%"
call vsconf-dir lib "%sub%" "%cfg%" "%dir%"
call vsconf-dir ipsec "%sub%" "%cfg%" "%dir%"
call vsconf-dir macsec "%sub%" "%cfg%" "%dir%"
call vsconf-dir apps "%sub%" "%cfg%" "%dir%"
call vsconf-dir . "%sub%" "%cfg%" "%dir%"

goto end

:usage
echo.
echo Usage:
echo.
echo   vsconf PLATFORMS CONFIGURATIONS [PROFILE]
echo.
echo where PLATFORMS is a space-separated list of words from the
echo following list:
echo.
echo   win32
echo   x64
echo   win32vista
echo   x64vista
echo   std500armv4i
echo   std500x86
echo   wm6std
echo   wm6pro
echo.
echo and CONFIGURATIONS is a space-separated list of words from the
echo following list:
echo.
echo   debug
echo   release
echo.
echo and PROFILE is one of the following:
echo.
echo   quicksec-client
echo   quicksec-server
echo.
echo If PLATFORMS or CONFIGURATONS contains multiple words surround
echo it with double quotes. If PROFILE is not specified the previously
echo configured build profile remains in effect.
echo.
echo Note: win32 and win32vista can not be used simultaneously. Also,
echo x64 and x64vista can not be used simultaneously.
echo.
echo Note: platform and configuration names are case-sensitive.
echo.
echo Instead of PLATFORMS and CONFIGURATIONS a single shortcut symbol
echo may be specified as follows:
echo.
echo   vsconf nt5 [PROFILE] (pre-Vista desktop Windows, Debug/Release)
echo   vsconf nt6 [PROFILE] (Windows Vista/Windows 7, Debug/Release)
echo   vsconf ce5 [PROFILE] (Windows CE 5.0 on ARM/x86 , Debug/Release)
echo   vsconf wm6 [PROFILE] (Windows Mobile 6, Debug/Release)
echo.

:end
