@echo off
title Build Dhanyah Crypto Utility Installer
echo =========================================================
echo Building Windows Setup Installer using Inno Setup
echo Author: CA Akash J. Bhayani (https://ca-akash.in)
echo =========================================================
echo.

set "ISCC=C:\Program Files\Inno Setup 7\ISCC.exe"
if not exist "%ISCC%" (
    set "ISCC=C:\Program Files (x86)\Inno Setup 7\ISCC.exe"
)
if not exist "%ISCC%" (
    set "ISCC=C:\Program Files\Inno Setup 6\ISCC.exe"
)
if not exist "%ISCC%" (
    set "ISCC=C:\Program Files (x86)\Inno Setup 6\ISCC.exe"
)
if not exist "%ISCC%" (
    where iscc >nul 2>&1
    if %ERRORLEVEL% equ 0 (
        set "ISCC=iscc"
    ) else (
        echo ERROR: Inno Setup compiler ISCC.exe was not found!
        echo Please ensure Inno Setup is installed.
        pause
        exit /b 1
    )
)

if not exist "dist\DhanyahCryptoUtility\DhanyahCryptoUtility.exe" (
    echo Executable not found in dist! Building with PyInstaller first...
    call build_exe.bat
)

echo Compiling installer with: "%ISCC%"
"%ISCC%" "installer.iss"

if %ERRORLEVEL% equ 0 (
    echo.
    echo SUCCESS: Installer generated successfully in dist_installer\
    echo Output: dist_installer\DhanyahCryptoUtility_Setup_v1.1.3.exe
    if not exist "releases" mkdir "releases"
    copy /y "dist_installer\DhanyahCryptoUtility_Setup_v1.1.3.exe" "releases\DhanyahCryptoUtility_Setup_v1.1.3.exe" >nul
    echo Copied installer to releases\DhanyahCryptoUtility_Setup_v1.1.3.exe
    echo =========================================================
) else (
    echo.
    echo ERROR: Inno Setup compilation failed!
)

echo.
pause
