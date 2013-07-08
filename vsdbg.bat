@echo off

setlocal

rem %DevEnvDir% environment variable should be defined
if not defined DevEnvDir goto nodevenv

rem Ensure local vars are undefined
set cmdline=
set pincmd=

:getarg

if "%1" == "" goto endarg
if "%1" == "--" goto startapparg

if defined cmdline set cmdline=%cmdline% %1
if not defined cmdline set cmdline=%1

shift /1
goto getarg

:startapparg

rem Build Pin command line for debugged process
set pincmd=""%~dp0ia32\bin\pin.exe"" -p32 ""%~dp0ia32\bin\pin.exe"" -p64 ""%~dp0intel64\bin\pin.exe"" %cmdline%
rem Clear for application command line
set cmdline=
shift /1
goto getarg

:endarg

if not defined pincmd goto noapp
if not defined cmdline goto noapp

echo "%~dp0ia32\bin\pin.exe" -p32 "%~dp0ia32\bin\pin.exe" -p64 "%~dp0intel64\bin\pin.exe" -xyzzy -late_injection 1 -follow_execv -t64 "%~dp0intel64\bin\vsdbg.dll" -t "%~dp0ia32\bin\vsdbg.dll" -pin_args "%pincmd%" -- "%DevEnvDir%\devenv.exe" /debugexe "%cmdline%"
"%~dp0ia32\bin\pin.exe" -p32 "%~dp0ia32\bin\pin.exe" -p64 "%~dp0intel64\bin\pin.exe" -xyzzy -late_injection 1 -follow_execv -t64 "%~dp0intel64\bin\vsdbg.dll" -t "%~dp0ia32\bin\vsdbg.dll" -pin_args "%pincmd%" -- "%DevEnvDir%\devenv.exe" /debugexe "%cmdline%"
goto end

:nodevenv
echo "Error: DevEnvDir environment variable is not defined. Visual Studio product is not found.
exit /b 1

:noapp
echo "Error: application to debug is not specified"
exit /b 2

:end
endlocal
