echo off

setlocal

goto start

:usage

echo.
echo Usage: quicksec platform config
echo.
echo   `platform' is one of the following:
echo.
echo     ce5        Windows CE 5.0 Standard (ARMV4I)
echo     ce5pc      Windows CE 5.0 Standard (x86)
echo     wm6pro     Windows Mobile 6 Professional
echo     wm6std     Windows Mobile 6 Standard
echo.
echo   `config' is one of the following:
echo.
echo     debug      Debug build
echo     release    Release build
echo.

goto end

:start

set vs8=C:\Program Files\Microsoft Visual Studio 8
set sdktools=%vs8%\SmartDevices\SDK\SDKTools
set sdkbin=%vs8%\SDK\v2.0\Bin

set wm6tools=C:\Program Files\Windows Mobile 6 SDK\Tools
set wm6certs=%wm6tools%\Security\SDK Development Certificates

set signtool=%sdkbin%\signtool.exe

set wm=
if "%1"=="wm6pro" set wm=6
if "%1"=="wm6std" set wm=6

set cabwiz=%sdktools%\cabwiz.exe

if "%wm%"=="6" set cabwiz=%wm6tools%\CabWiz\cabwiz.exe
if "%wm%"=="6" set pfx=%wm6certs%\SamplePrivDeveloper.pfx

set ce5=STANDARDSDK_500 (ARMV4I)
set ce5pc=STANDARDSDK_500 (x86)
set wm6pro=Windows Mobile 6 Professional SDK (ARMV4I)
set wm6std=Windows Mobile 6 Standard SDK (ARMV4I)

set platform=
if "%1"=="ce5" set platform=%ce5%
if "%1"=="ce5pc" set platform=%ce5pc%
if "%1"=="wm6pro" set platform=%wm6pro%
if "%1"=="wm6std" set platform=%wm6std%
if "%platform%"=="" goto usage

set config=
if "%2"=="debug" set config=Debug
if "%2"=="release" set config=Release
if "%config%"=="" goto usage

if "%1"=="ce5" set cpu=CE5.ARMV4I.%config%
if "%1"=="ce5pc" set cpu=CE5PC.x86.%config%
if "%1"=="wm6pro" set cpu=WM6PRO.ARMV4I.%config%
if "%1"=="wm6std" set cpu=WM6STD.ARMV4I.%config%

set subdir=%platform%\%config%

set pmexe=..\..\..\..\..\quicksec\usermode\%subdir%\quicksecpm.exe
set pmpdb=..\..\..\..\..\quicksec\usermode\%subdir%\quicksecpm.pdb
set icdll=..\..\%subdir%\quicksec.dll
set icpdb=..\..\%subdir%\quicksec.pdb
set vadll=..\..\..\vnic\ndis5_0\%subdir%\qsvnic5.dll
set vapdb=..\..\..\vnic\ndis5_0\%subdir%\qsvnic5.pdb
set qsxml=quicksec.xml
set qcexe=..\..\..\..\..\..\apps\winceutils\%subdir%\qsconsole.exe
set qcpdb=..\..\..\..\..\..\apps\winceutils\%subdir%\qsconsole.pdb
set qssetupdll=..\..\..\..\..\..\apps\winceutils\%subdir%\qssetup.dll
set qssetuppdb=..\..\..\..\..\..\apps\winceutils\%subdir%\qssetup.pdb

if exist "%pmexe%" goto pmexe
echo Cannot find %pmexe%
set error=yes
:pmexe

if exist "%icdll%" goto icdll
echo Cannot find %icdll%
set error=yes
:icdll

if exist "%vadll%" goto vadll
echo Cannot find %vadll%
set error=yes
:vadll

if exist "%qsxml%" goto qsxml
echo Cannot find %qsxml%
set error=yes
:qsxml

if exist "%qcexe%" goto  qcexe
echo Cannot find %qcexe%
set error=yes
:qcexe

if exist "%qssetupdll%" goto  qssetupdll
echo Cannot find %qssetupdll%
set error=yes
:qssetupdll

if "%1"=="ce5" goto signtool
if "%1"=="ce5pc" goto signtool
if exist "%signtool%" goto signtool
echo Cannot find %signtool%
set error=yes
:signtool

if "%1"=="ce5" goto pfx
if "%1"=="ce5pc" goto pfx
if exist "%pfx%" goto pfx
echo Cannot find %pfx%
set error=yes
:pfx

if exist "%cabwiz%" goto cabwiz
echo Cannot find %cabwiz%
set error=yes
:cabwiz

if not "%error%"=="" goto end

echo *** Copying binaries
if not exist "%subdir%" mkdir "%subdir%"
copy "%pmexe%" "%subdir%"\quicksecpm.exe
copy "%icdll%" "%subdir%"\quicksec.dll
copy "%vadll%" "%subdir%"\qsvnic5.dll
copy "%qsxml%" "%subdir%"\quicksec.xml
copy "%qcexe%" "%subdir%"\QSConsole.exe
copy "%qssetupdll%" "%subdir%"\qssetup.dll
if exist "%pmpdb%" copy "%pmpdb%" "%subdir%"\quicksecpm.pdb
if exist "%icpdb%" copy "%icpdb%" "%subdir%"\quicksec.pdb
if exist "%vapdb%" copy "%vapdb%" "%subdir%"\qsvnic5.pdb
if exist "%qcpdb%" copy "%qcpdb%" "%subdir%"\QSConsole.pdb
if exist "%qssetuppdb%" copy "%qssetuppdb%" "%subdir%"\qssetup.pdb

if "%1"=="ce5" goto nosign
if "%1"=="ce5pc" goto nosign
echo *** Signing binaries
"%signtool%" sign /f "%pfx%" "%subdir%"\quicksecpm.exe
"%signtool%" sign /f "%pfx%" "%subdir%"\quicksec.dll
"%signtool%" sign /f "%pfx%" "%subdir%"\qsvnic5.dll
"%signtool%" sign /f "%pfx%" "%subdir%"\QSConsole.exe
"%signtool%" sign /f "%pfx%" "%subdir%"\qssetup.dll
:nosign

echo *** Creating CAB file
"%cabwiz%" QuickSec.inf /cpu "%cpu%"

if "%1"=="ce5" goto nosigncab
if "%1"=="ce5pc" goto nosigncab
echo *** Signing CAB file
"%signtool%" sign /f "%pfx%" quicksec."%cpu%".cab
:nosigncab

if errorlevel 1 goto end

echo *** Created quicksec.%cpu%.cab succesfully
echo *** Binaries left in %subdir%

goto end

:end
