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
setlocal

set Unix2Dos=C:\cygwin64\bin\unix2dos.exe
set ProjectRoot=%~dp0..
set ProjectRootM=%ProjectRoot:\=/%
cd "%ProjectRoot%"
rmdir /s/q out 2>NUL
mkdir out\packages || exit /b 1
set /p Version=<VERSION.txt

"%WINDIR%\System32\bash.exe" -c "make -C backend && strip out/wslbridge-backend"    || exit /b 1
"%WINDIR%\System32\bash.exe" -c "g++ --version > out/WslGccVersion.txt"             || exit /b 1
%Unix2Dos% out/WslGccVersion.txt                                                    || exit /b 1

call :makeFrontend "cygwin32" "C:\cygwin\bin"       "cygwin1.dll"   || exit /b 1
call :makeFrontend "cygwin64" "C:\cygwin64\bin"     "cygwin1.dll"   || exit /b 1
call :makeFrontend "msys32"   "C:\msys32\usr\bin"   "msys-2.0.dll"  || exit /b 1
call :makeFrontend "msys64"   "C:\msys64\usr\bin"   "msys-2.0.dll"  || exit /b 1

echo ============= TAR FILES =============
set PATH=C:\cygwin64\bin;%PATH%
C:\cygwin64\bin\bash.exe -c "for p in out/packages/*; do printf '\n'$p'\n'; tar tfv $p; done"

exit /b 0


:::::::::::::::::::::::::::::::::::::::
:: makeFrontend subroutine

:makeFrontend
setlocal

set PackageName=wslbridge-%Version%-%1
set PackageDir=out\%PackageName%
set PackageDirM=out/%PackageName%
mkdir %PackageDir% || exit /b 1

del out\wslbridge.exe 2>NUL
%2\bash.exe -l -c "cd '%ProjectRootM%' && make -C frontend && strip out/wslbridge.exe"  || exit /b 1
%2\bash.exe -l -c "cd '%ProjectRootM%' && g++ --version > out/CygGccVersion.txt"        || exit /b 1
%Unix2Dos% out/CygGccVersion.txt                                                        || exit /b 1

copy out\wslbridge.exe     %PackageDir% || exit /b 1
copy out\wslbridge-backend %PackageDir% || exit /b 1

powershell "[System.Diagnostics.FileVersionInfo]::GetVersionInfo(\"%2\" + \"\\\" + \"%3\") | Set-Content -Encoding ASCII out\CygDllVersion.txt" || exit /b 1

:: Always use Cygwin tar to package the binary.  The MSYS2 tar will mark the
:: backend executable because its POSIX emulation uses filetype to determine
:: executability.  Cygwin, on the other hand, uses NTFS ACL entries.  If the
:: MSYS2 package were then extracted using Cygwin tar, the backend file would
:: have non-executable ACL entries, and WSL would refuse to run it.
::
:: Use bash.exe to copy files so the execute bit is left unset.
set DistSavedPath=%PATH%
set PATH=C:\cygwin64\bin;%PATH%
C:\cygwin64\bin\bash.exe -c "cat README.md      | unix2dos  > %PackageDirM%/README.md"          || exit /b 1
C:\cygwin64\bin\bash.exe -c "cat LICENSE.txt    | unix2dos  > %PackageDirM%/LICENSE.txt"        || exit /b 1
C:\cygwin64\bin\bash.exe -c "cat out/CygDllVersion.txt out/CygGccVersion.txt out/WslGccVersion.txt | unix2dos.exe > %PackageDirM%/BuildInfo.txt" || exit /b 1
C:\cygwin64\bin\tar.exe cfz out/packages/%PackageName%.tar.gz --numeric-owner --owner=0 --group=0 -C out %PackageName%  || exit /b 1
set PATH=%DistSavedPath%

exit /b 0
