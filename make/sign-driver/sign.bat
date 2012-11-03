@echo off

if "%1" == "" (
echo Usage: %0 file_to_sign
goto :eof
) else (
goto StartSigning
)

:StartSigning
rem set SIGNTOOLS=%WDKPATH%\bin\amd64
rem set FILEPATH=$(TargetDir)$(TargetName)
rem set CERTPATH=$(TargetDir)TestCert.cer

set SIGNTOOLS=.
set FILEPATH=%~f1
set CERTPATH=TestCert.cer
set CERTNAME="Hewlett-Packard"
set STORENAME="Hewlett-Packard Test Store"

if not exist %FILEPATH% (
echo File %1 does not exist. Exiting.
goto :eof
)

goto SignTool

:MakeCert
echo Generating test certificate file...
"%SIGNTOOLS%\MakeCert.exe" -r -pe -ss %STORENAME% -n "CN=%CERTNAME%" "%CERTPATH%"

:SignTool
rem echo Signing the file with generated certificate...
"%SIGNTOOLS%\SignTool.exe" sign /v /s %STORENAME% /n "%CERTNAME%" "%FILEPATH%"

if errorlevel == 1 goto MakeCert