@echo off

setlocal

if "%~1"=="/?" goto usage
if "%~1"=="-?" goto usage
if "%~1"=="-h" goto usage

set profile=%~1
set blddir=%~2
set ERRORLEVEL=0

:profile
if not "%profile%"=="" goto profile2
if exist sshdistdefs.h goto endprofile
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
if not errorlevel 1 goto endprofile
del sshdistdefs.h

:profile4
type sshdistdefs-%profile%.h >sshdistdefs.h

:endprofile

:builddir
if not "%blddir%"=="" goto builddir2
set blddir=%CD%\wdbuild
if not exist "%blddir%" mkdir "%blddir%"
if errorlevel 1 goto end
set srctop=..\..
goto endbuilddir

:builddir2
if not exist "%blddir%" mkdir "%blddir%"
if errorlevel 1 goto end
pushd "%blddir%"
if errorlevel 1 goto end
set blddir=%CD%
popd
set srctop=%CD%

:endbuilddir

:configure
set platforms=win32 x64 win32vista x64vista win32win7 x64win7
set platforms=%platforms% win32vistandis5 x64vistandis5 win32win7ndis5 
set platforms=%platforms% x64win7ndis5
set configurations=debug release
echo .set platforms %platforms% >wdconf-settings.t
echo .set configurations %configurations% >>wdconf-settings.t
echo .set srctop %srctop:\=\\% >>wdconf-settings.t
echo .set blddir %blddir:\=\\% >>wdconf-settings.t
echo wrote wdconf-settings.t

echo DIRS = \ >"%blddir%\dirs"

for /r build %%t in (*_project.t) do @call wdconf-target "%%t"
for /r include %%t in (*_project.t) do @call wdconf-target "%%t"
for /r lib %%t in (*_project.t) do @call wdconf-target "%%t"
for /r ipsec %%t in (*_project.t) do @call wdconf-target "%%t"
for /r macsec %%t in (*_project.t) do @call wdconf-target "%%t"
for /r apps %%t in (*_project.t) do @call wdconf-target "%%t"

echo. >>"%blddir%\dirs"

goto end

:usage
echo.
echo Usage:
echo.
echo   wdconf [PROFILE [BUILDDIR]]
echo.
echo where PROFILE is one of the following:
echo.
echo   quicksec-client
echo   quicksec-server
echo.
echo BUILDDIR specifies the directory into which build files will be
echo placed. The default is to create a subdirectory `wdbuild' in the
echo current directory. Note that if BUILDDIR is specified then references
echo to the source tree from the build files will be absolute. Note also
echo that the full path to BUILDDIR (either the default or explicitly
echo specified) must not contain spaces.
echo.

:end
