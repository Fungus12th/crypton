@echo off
title Crypton - Windows Executable Builder
echo ===================================================
echo   Building Crypton Standalone Windows Executable
echo ===================================================
echo.

if exist "%~dp0crypton_project\crypton-windows.spec" (
    cd /d "%~dp0crypton_project"
) else (
    cd /d "%~dp0"
)

echo [1/3] Checking Python installation...
python --version
if %errorlevel% neq 0 (
    echo [ERROR] Python is not installed or not in PATH!
    echo Please install Python 3.9+ from python.org and check "Add to PATH".
    pause
    exit /b 1
)

echo.
echo [2/3] Installing dependencies...
python -m pip install --upgrade pip
python -m pip install -e . pyinstaller customtkinter pillow argon2-cffi cryptography typer rich google-api-python-client google-auth-oauthlib google-auth-httplib2

echo.
echo [3/3] Compiling standalone Windows binary with PyInstaller...
python -m PyInstaller crypton-windows.spec --noconfirm

if %errorlevel% equ 0 (
    echo.
    echo ===================================================
    echo  SUCCESS! Updating Crypton.exe on USB...
    echo ===================================================
    if exist "dist\crypton-windows.exe" (
        copy /y "dist\crypton-windows.exe" "..\Crypton.exe"
        if exist "..\crypton-windows.exe" del /f /q "..\crypton-windows.exe"
    )
    echo.
    echo Done! You can now double-click Crypton.exe on Windows.
) else (
    echo.
    echo [ERROR] Build failed! Check the output above.
)

pause
