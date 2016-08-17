@echo off
setlocal

call :main || goto :failed
exit /b 0

:failed
echo Build failed
exit /b 1


:::::::::::::::::::::::::::::::::::::::
:: main routine

:main
set Unix2Dos=C:\cygwin64\bin\unix2dos.exe
set ProjectRoot=%~dp0..
set ProjectRootMix=%ProjectRoot:\=/%
cd "%ProjectRoot%"
rmdir /s/q out 2>NUL
set /p Version=<VERSION.txt

"%WINDIR%\System32\bash.exe" -c "make -C backend && strip out/wslbridge-backend"    || exit /b 1
"%WINDIR%\System32\bash.exe" -c "g++ --version > out/WslGccVersion.txt"             || exit /b 1
%Unix2Dos% out/WslGccVersion.txt                                                    || exit /b 1

call :makeFrontend "cygwin32" "C:\cygwin\bin"       "cygwin1.dll"   || exit /b 1
call :makeFrontend "cygwin64" "C:\cygwin64\bin"     "cygwin1.dll"   || exit /b 1
call :makeFrontend "msys32"   "C:\msys32\usr\bin"   "msys-2.0.dll"  || exit /b 1
call :makeFrontend "msys64"   "C:\msys64\usr\bin"   "msys-2.0.dll"  || exit /b 1

exit /b 0


:::::::::::::::::::::::::::::::::::::::
:: makeFrontend subroutine

:makeFrontend

set PackageName=wslbridge-%Version%-%1
set PackageDir=out\%PackageName%
mkdir %PackageDir% || exit /b 1

del out\wslbridge.exe 2>NUL
%2\bash.exe -l -c "cd '%ProjectRootMix%' && make -C frontend && strip out/wslbridge.exe"            || exit /b 1
%2\bash.exe -l -c "cd '%ProjectRootMix%' && g++ --version > out/CygGccVersion.txt"                  || exit /b 1
%Unix2Dos% out/CygGccVersion.txt                                                                    || exit /b 1

copy out\wslbridge.exe     %PackageDir% || exit /b 1
copy out\wslbridge-backend %PackageDir% || exit /b 1

powershell "[System.Diagnostics.FileVersionInfo]::GetVersionInfo(\"%2\" + \"\\\" + \"%3\") | Set-Content -Encoding ASCII out\CygDllVersion.txt" || exit /b 1

copy README.md                     %PackageDir%                 || exit /b 1
copy LICENSE.txt                   %PackageDir%                 || exit /b 1
type out\CygDllVersion.txt      >> %PackageDir%\BuildInfo.txt   || exit /b 1
type out\CygGccVersion.txt      >> %PackageDir%\BuildInfo.txt   || exit /b 1
type out\WslGccVersion.txt      >> %PackageDir%\BuildInfo.txt   || exit /b 1

del %PackageDir%.zip 2>NUL
"C:\Program Files\7-Zip\7z.exe" a %PackageDir%.zip .\%PackageDir%\* || exit /b 1

exit /b 0
