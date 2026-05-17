@echo off
REM TriCord Build Script for Windows
REM Requires: devkitARM (via MSYS2/devkitPro), 3ds-curl, 3ds-mbedtls, 3ds-zlib, bannertool, makerom
setlocal enabledelayedexpansion

set "TOOLS_DIR=%~dp0"
if "%TOOLS_DIR:~-1%"=="\" set "TOOLS_DIR=%TOOLS_DIR:~0,-1%"

set "ROOT_DIR=%TOOLS_DIR%\.."
cd /d "%ROOT_DIR%"

set "PATH=%TOOLS_DIR%;%PATH%"

REM Check devkitARM
if not defined DEVKITARM (
    if exist "C:\devkitPro\devkitARM" (
        set "DEVKITPRO=C:\devkitPro"
        set "DEVKITARM=C:\devkitPro\devkitARM"
        set "PATH=!DEVKITARM!\bin;!DEVKITPRO!\tools\bin;!DEVKITPRO!\msys2\usr\bin;%PATH%"
    ) else (
        echo ERROR: devkitARM not found.
        echo Install it from https://devkitpro.org/wiki/Getting_Started
        echo Or set DEVKITARM environment variable manually.
        pause
        exit /b 1
    )
) else (
    set "PATH=!DEVKITPRO!\msys2\usr\bin;%PATH%"
)

echo === devkitARM: %DEVKITARM% ===

REM Check makerom
where makerom >nul 2>&1
if errorlevel 1 (
    echo ERROR: makerom.exe not found.
    echo Download it from: https://github.com/3DSGuy/Project_CTR/releases
    echo Place makerom.exe in the tools\ folder.
    pause
    exit /b 1
)
echo === makerom OK ===

REM Check bannertool
where bannertool >nul 2>&1
if errorlevel 1 (
    echo ERROR: bannertool.exe not found.
    echo Download it from: https://github.com/carstene1ns/3ds-bannertool/releases
    echo Place bannertool.exe in the tools\ folder.
    pause
    exit /b 1
)
echo === bannertool OK ===

REM Check make
where make >nul 2>&1
if errorlevel 1 (
    echo ERROR: make.exe not found.
    echo Ensure MSYS2 is installed in devkitPro.
    pause
    exit /b 1
)

REM Build using MSYS2 make from devkitPro
echo === Building TriCord ===
make
if errorlevel 1 (
    echo.
    echo === BUILD FAILED ===
    pause
    exit /b 1
)

echo.
echo === Build complete! ===
if exist "TriCord.3dsx" (echo   TriCord.3dsx OK) else (echo   TriCord.3dsx MISSING)
if exist "TriCord.cia" (echo   TriCord.cia  OK) else (echo   TriCord.cia  MISSING)

pause
endlocal
