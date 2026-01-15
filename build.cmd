@echo off
setlocal EnableExtensions

rem ------------------------------------------------------------------
rem  Cleanup previous build artifacts
rem ------------------------------------------------------------------
call :CleanupArtifacts >nul 2>&1

if exist "%~dp0memclean_default-only.exe" (
    del /f /q "%~dp0memclean_default-only.exe" >nul 2>&1
)

timeout /t 1 /nobreak >nul

rem ------------------------------------------------------------------
rem  Initialize Microsoft Visual C++ Build Environment
rem ------------------------------------------------------------------
echo Initializing Microsoft Visual C++ build environment...

set "VCVARS_PATH=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"

if exist "%VCVARS_PATH%" (
    call "%VCVARS_PATH%"
) else (
    echo ERROR: Visual Studio Build Tools not found.
    exit /b 1
)

echo.
echo Compiling project sources...

rem ------------------------------------------------------------------
rem  Build command
rem ------------------------------------------------------------------
cl.exe ^
    /EHsc ^
    /O2 ^
    /MD ^
    /W4 ^
    /std:c++20 ^
    /Fe:memclean_default-only.exe ^
    memclean_default-only.cpp ^
    /link ^
    /MANIFEST:EMBED ^
    /MANIFESTUAC:level='requireAdministrator'

rem ------------------------------------------------------------------
rem  Post-build cleanup
rem ------------------------------------------------------------------
call :CleanupArtifacts >nul 2>&1

timeout /t 1 /nobreak >nul
echo.
pause
exit /b 0


:CleanupArtifacts
for /r %%F in (*.xml *.tmp *.bak *.obj *.res *.lib *.exp *.manifest *.pdb *.ilk) do (
    del /f /q "%%F" >nul 2>&1
)
goto :eof
