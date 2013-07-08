@echo off
rem echo "Expand first parameter to a fully qualified path name and add -p32 and -p64 flags"
"%~dp0\ia32\bin\pin.exe" -p32 "%~dp0\ia32\bin\pin.exe" -p64 "%~dp0\intel64\bin\pin.exe" %*

pause