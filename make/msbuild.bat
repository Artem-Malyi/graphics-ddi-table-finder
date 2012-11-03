@echo off
rem +--------------------------------------------------------------------------------------------------------------------+
rem | Set WINDDK environment variable here.                                                                              |
rem +--------------------------------------------------------------------------------------------------------------------+


call "C:\Program Files (x86)\Microsoft Visual Studio 8\VC\vcvarsall.bat" x86_amd64

set WINDDK=C:\WinDDK\3790.1830

rem set latin encoding
chcp 850

if "%1"=="" (
    msbuild.exe offset-finder.proj
) else (
    msbuild.exe "%1"
)

pause