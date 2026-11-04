@echo off
setlocal EnableExtensions EnableDelayedExpansion

set "source=%~1"
set "destination=%~2"
set "versionFile=%~3"
if not defined source set "source=%~dp0Uhara.dll"
if not defined destination set "destination=%~dp0"
for %%I in ("!source!") do set "source=%%~fI"
for %%I in ("!destination!") do set "destination=%%~fI"
if "!destination:~-1!"=="\" set "destination=!destination:~0,-1!"

if not exist "!source!" (
    echo Source DLL not found: "!source!" 1>&2
    endlocal & exit /b 1
)

if not exist "!destination!" mkdir "!destination!" >nul 2>&1
if not exist "!destination!\" (
    echo Destination directory could not be created: "!destination!" 1>&2
    endlocal & exit /b 1
)

set "log=!destination!\post_build.log"
set "now=%DATE% %TIME%"
>>"!log!" echo !now! - post_build started

if not defined versionFile call :find_version_file
if defined versionFile call :parse_version
if not defined version call :next_version
call :copy_output
set "result=%errorlevel%"
endlocal & exit /b %result%

:find_version_file
if exist "%~dp0Code\Interface\Main\Main.cs" (
    set "versionFile=%~dp0Code\Interface\Main\Main.cs"
    exit /b 0
)
set "search=%~dp0"
for /L %%I in (1,1,8) do (
    if exist "!search!..\Code\Interface\Main\Main.cs" (
        set "versionFile=!search!..\Code\Interface\Main\Main.cs"
        goto :version_file_found
    )
    set "search=!search!..\"
)
:version_file_found
exit /b 0

:parse_version
set "version="
if not exist "!versionFile!" exit /b 0
set "line="
for /f "usebackq delims=" %%L in (`findstr /I /R /C:"LIB_VERSION[ ]*=" "!versionFile!" 2^>nul`) do (
    set "line=%%L"
    goto :version_line_found
)
:version_line_found
if not defined line exit /b 0
for /f "tokens=1* delims==" %%A in ("!line!") do set "version=%%B"
if not defined version exit /b 0
set "version=!version: =!"
set "version=!version:"=!"
set "version=!version:;=!"
set "versionCheck=!version!"
for /f "delims=0123456789" %%A in ("!versionCheck!") do set "versionCheck="
if not defined versionCheck set "version="
exit /b 0

:next_version
set "version=1"
:next_version_loop
if exist "!destination!\uhara!version!" (
    set /a version+=1
    goto :next_version_loop
)
exit /b 0

:copy_output
set "target=!destination!\uhara!version!"
>>"!log!" echo !now! - Packaging "!source!" as "!target!"
copy /Y /B "!source!" "!target!" >nul
if errorlevel 1 (
    >>"!log!" echo !now! - Copy failed with errorlevel !errorlevel!
    echo Copy failed: "!target!" 1>&2
    endlocal & exit /b 1
)
>>"!log!" echo !now! - Created "!target!"
echo Created "!target!"
exit /b 0
